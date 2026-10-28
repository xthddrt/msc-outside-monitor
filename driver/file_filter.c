#include <fltKernel.h>
#include "msmon.h"

#define MSMON_POOL_TAG 'noSM'
/* Volume results are small (FILE_FS_*_INFORMATION); cap what is copied out. */
#define MSMON_VOLUME_MAX_BYTES 1024u

static PFLT_FILTER gFilter;

static ULONG MsMonFileCategory(PCUNICODE_STRING Path)
{
    UNICODE_STRING namedPipe;
    RtlInitUnicodeString(&namedPipe, L"\\Device\\NamedPipe");
    if (Path != NULL && Path->Length >= namedPipe.Length &&
        RtlPrefixUnicodeString(&namedPipe, Path, TRUE)) return MsMonCategoryIpc;
    return MsMonCategoryUnknown;
}

static ULONG MsMonEventType(UCHAR MajorFunction)
{
    switch (MajorFunction) {
    case IRP_MJ_READ: return MsMonFileRead;
    case IRP_MJ_WRITE: return MsMonFileWrite;
    case IRP_MJ_SET_INFORMATION: return MsMonFileSetInformation;
    case IRP_MJ_QUERY_INFORMATION: return MsMonFileQueryInformation;
    case IRP_MJ_DIRECTORY_CONTROL: return MsMonFileDirectoryControl;
    case IRP_MJ_CLEANUP: return MsMonFileCleanup;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL: return MsMonFileDeviceControl;
    case IRP_MJ_FILE_SYSTEM_CONTROL: return MsMonFileSystemControl;
    case IRP_MJ_QUERY_VOLUME_INFORMATION: return MsMonFileQueryVolumeInformation;
    default: return MsMonCoverage;
    }
}

static ULONGLONG MsMonEventValue(PFLT_CALLBACK_DATA Data, BOOLEAN Second)
{
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_READ:
        return Second ? (ULONGLONG)Data->Iopb->Parameters.Read.ByteOffset.QuadPart : Data->Iopb->Parameters.Read.Length;
    case IRP_MJ_WRITE:
        return Second ? (ULONGLONG)Data->Iopb->Parameters.Write.ByteOffset.QuadPart : Data->Iopb->Parameters.Write.Length;
    case IRP_MJ_SET_INFORMATION:
        return Second ? 0 : Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    case IRP_MJ_QUERY_INFORMATION:
        return Second ? 0 : Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
    case IRP_MJ_DIRECTORY_CONTROL:
        if (Second) return 0;
        if (Data->Iopb->MinorFunction == IRP_MN_QUERY_DIRECTORY) {
            return Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
        }
        return Data->Iopb->MinorFunction;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        return Second ? Data->Iopb->Parameters.DeviceIoControl.Common.InputBufferLength :
                        Data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        return Second ? Data->Iopb->Parameters.FileSystemControl.Common.InputBufferLength :
                        Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        return Second ? 0 : Data->Iopb->Parameters.QueryVolumeInformation.FsInformationClass;
    default:
        return 0;
    }
}

static PFLT_FILE_NAME_INFORMATION MsMonAcquireName(PFLT_CALLBACK_DATA Data, ULONG QueryFlags)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    /*
     * FltGetFileNameInformation is documented for IRQL <= APC_LEVEL. Paging
     * I/O and some cleanup paths can reach a minifilter above that, so refuse
     * instead of letting the filter manager query the file system at a raised
     * IRQL.
     */
    if (KeGetCurrentIrql() > APC_LEVEL) return NULL;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | QueryFlags, &nameInfo))) {
        return NULL;
    }
    return nameInfo;
}

static FLT_PREOP_CALLBACK_STATUS MsMonPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0) && !MsMonCurrentIsBlackCat()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    /*
     * Resolve the name in the pre-create path, which is the documented safe
     * place for a file-system name query. Post-create used to query the name
     * itself, which can recurse into the file system and is not valid when the
     * create failed.
     */
    *CompletionContext = MsMonAcquireName(Data, FLT_FILE_NAME_QUERY_DEFAULT);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS MsMonPreOperation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0) && !MsMonCurrentIsBlackCat()) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /*
     * Cache first, file system second, but only when the filter manager judges
     * it safe. The recorded session lost 7.4% of file paths with a cache-only
     * lookup (45% of query-information events), which is too much to analyse.
     */
    *CompletionContext = MsMonAcquireName(Data, FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static VOID MsMonVolumeUnavailable(
    PFLT_CALLBACK_DATA Data, PCUNICODE_STRING Path, PCWSTR Reason
)
{
    UNICODE_STRING detail;
    ULONG category = MsMonEventValue(Data, FALSE) == 1 ? MsMonCategoryHardwareIdentity : MsMonFileCategory(Path);
    RtlInitUnicodeString(&detail, Reason);
    (VOID)MsMonLogEvent(MsMonFileQueryVolumeInformation, PsGetCurrentProcessId(), NULL,
                        PsGetCurrentThreadId(), NULL, 0, MsMonFlagPayloadUnavailable,
                        Data->IoStatus.Status, 0, category, MsMonEventValue(Data, FALSE),
                        0, Path, &detail);
}

static VOID MsMonCaptureVolume(PFLT_CALLBACK_DATA Data, PCUNICODE_STRING Path)
{
    ULONG category = MsMonEventValue(Data, FALSE) == 1 ? MsMonCategoryHardwareIdentity : MsMonFileCategory(Path);
    PVOID buffer = Data->Iopb->Parameters.QueryVolumeInformation.VolumeBuffer;
    ULONG length = Data->Iopb->Parameters.QueryVolumeInformation.Length;
    ULONG information = (ULONG)Data->IoStatus.Information;
    UCHAR local[MSMON_VOLUME_MAX_BYTES];
    BOOLEAN copied = FALSE;

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        if (Data->IoStatus.Status == STATUS_BUFFER_OVERFLOW ||
            Data->IoStatus.Status == STATUS_BUFFER_TOO_SMALL) {
            /*
             * Two-pass probe: the caller asked with a short buffer and repeats
             * the request with the correct size. No value is available yet, so
             * this is metadata, not an unavailable payload.
             */
            UNICODE_STRING detail;
            RtlInitUnicodeString(&detail, L"two_pass_probe");
            (VOID)MsMonLogEvent(MsMonFileQueryVolumeInformation, PsGetCurrentProcessId(), NULL,
                                PsGetCurrentThreadId(), NULL, 0, 0, Data->IoStatus.Status, 0,
                                category, MsMonEventValue(Data, FALSE), 0, Path, &detail);
        } else {
            MsMonVolumeUnavailable(Data, Path, L"volume_query_failed");
        }
        return;
    }
    if (buffer == NULL) {
        MsMonVolumeUnavailable(Data, Path, L"missing_volume_buffer");
        return;
    }
    if (information == 0 || information > length) {
        MsMonVolumeUnavailable(Data, Path, L"invalid_volume_result");
        return;
    }
    if (information > MSMON_VOLUME_MAX_BYTES) {
        MsMonVolumeUnavailable(Data, Path, L"volume_result_too_large");
        return;
    }
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        MsMonVolumeUnavailable(Data, Path, L"unsafe_irql");
        return;
    }
    /*
     * The buffer is either a filter-manager system buffer or the caller's user
     * buffer. Only read the user case in the requesting process context, and
     * never without a probe: a post-operation callback can run in an arbitrary
     * thread, where a user address belongs to another address space.
     */
    if (FltGetRequestorProcessId(Data) != HandleToUlong(PsGetCurrentProcessId()) &&
        (ULONG_PTR)buffer < (ULONG_PTR)MmUserProbeAddress) {
        MsMonVolumeUnavailable(Data, Path, L"foreign_process_context");
        return;
    }
    __try {
        if ((ULONG_PTR)buffer < (ULONG_PTR)MmUserProbeAddress) {
            ProbeForRead(buffer, information, sizeof(UCHAR));
        }
        RtlCopyMemory(local, buffer, information);
        copied = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        copied = FALSE;
    }
    if (!copied) {
        MsMonVolumeUnavailable(Data, Path, L"unsafe_result_buffer");
        return;
    }
    (VOID)MsMonLogPayloadSeries(MsMonFileQueryVolumeInformation, PsGetCurrentProcessId(),
                                PsGetCurrentThreadId(), 0, Data->IoStatus.Status, category,
                                MsMonEventValue(Data, FALSE), 0, Path, NULL,
                                MsMonPayloadVolumeInformation, MsMonNextOperationId(),
                                information, local, information);
}

static FLT_POSTOP_CALLBACK_STATUS MsMonPostOperation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = (PFLT_FILE_NAME_INFORMATION)CompletionContext;
    PCUNICODE_STRING path = nameInfo != NULL ? &nameInfo->Name : NULL;
    UNREFERENCED_PARAMETER(FltObjects);
    if ((Flags & FLTFL_POST_OPERATION_DRAINING) == 0 &&
        (MsMonIsTracked(PsGetCurrentProcessId(), 0) || MsMonCurrentIsBlackCat())) {
        if (Data->Iopb->MajorFunction == IRP_MJ_QUERY_VOLUME_INFORMATION && MsMonPayloadEnabled()) {
            MsMonCaptureVolume(Data, path);
        } else {
            (VOID)MsMonLogEvent(MsMonEventType(Data->Iopb->MajorFunction),
                                PsGetCurrentProcessId(), NULL, PsGetCurrentThreadId(), NULL, 0,
                                path == NULL ? MsMonFlagMissingPath : 0, Data->IoStatus.Status, 0,
                                MsMonFileCategory(path), MsMonEventValue(Data, FALSE),
                                MsMonEventValue(Data, TRUE), path, NULL);
        }
    }
    if (nameInfo != NULL) FltReleaseFileNameInformation(nameInfo);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_POSTOP_CALLBACK_STATUS MsMonPostCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = (PFLT_FILE_NAME_INFORMATION)CompletionContext;
    PFLT_FILE_NAME_INFORMATION tunneled = NULL;
    PCUNICODE_STRING path = nameInfo != NULL ? &nameInfo->Name : NULL;
    ULONG desiredAccess = 0;
    UNREFERENCED_PARAMETER(FltObjects);
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        if (nameInfo != NULL) FltReleaseFileNameInformation(nameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0) && !MsMonCurrentIsBlackCat()) {
        if (nameInfo != NULL) FltReleaseFileNameInformation(nameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    /*
     * A normalized name obtained in pre-create can be invalidated by name
     * tunneling; FltGetTunneledName returns the name that was actually used.
     */
    if (nameInfo != NULL && KeGetCurrentIrql() == PASSIVE_LEVEL &&
        NT_SUCCESS(FltGetTunneledName(Data, nameInfo, &tunneled)) && tunneled != NULL) {
        path = &tunneled->Name;
    }
    /*
     * SecurityContext belongs to the create request. Only trust it when the
     * create itself succeeded.
     */
    if (NT_SUCCESS(Data->IoStatus.Status) &&
        Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    (VOID)MsMonLogEvent(MsMonFileCreate, PsGetCurrentProcessId(), NULL, PsGetCurrentThreadId(),
                        NULL, 0, path == NULL ? MsMonFlagMissingPath : 0, Data->IoStatus.Status,
                        desiredAccess,
                        MsMonFileCategory(path),
                        Data->Iopb->Parameters.Create.Options, Data->IoStatus.Information, path, NULL);
    if (tunneled != NULL) FltReleaseFileNameInformation(tunneled);
    if (nameInfo != NULL) FltReleaseFileNameInformation(nameInfo);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static const FLT_OPERATION_REGISTRATION gOperations[] = {
    { IRP_MJ_CREATE, 0, MsMonPreCreate, MsMonPostCreate, NULL },
    { IRP_MJ_READ, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_SET_INFORMATION, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_QUERY_INFORMATION, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_CLEANUP, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_DEVICE_CONTROL, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_INTERNAL_DEVICE_CONTROL, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_QUERY_VOLUME_INFORMATION, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_OPERATION_END, 0, NULL, NULL, NULL }
};

static NTSTATUS FLTAPI MsMonFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    MsMonRecordStatus(L"FilterUnloadCallback", STATUS_FLT_DO_NOT_DETACH);
    /*
     * This filter shares its driver image with the control device and the other
     * callbacks. It cannot be detached on its own, so refuse and let the driver
     * unload path call FltUnregisterFilter exactly once.
     */
    return STATUS_FLT_DO_NOT_DETACH;
}

static const FLT_REGISTRATION gFilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, gOperations,
    MsMonFilterUnload, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS MsMonFileFilterInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = FltRegisterFilter(DriverObject, &gFilterRegistration, &gFilter);
    if (!NT_SUCCESS(status)) return status;
    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return status;
}

VOID MsMonFileFilterUninitialize(VOID)
{
    if (gFilter != NULL) {
        FltUnregisterFilter(gFilter);
        MsMonRecordStatus(L"FltUnregisterComplete", STATUS_SUCCESS);
        gFilter = NULL;
    }
}
