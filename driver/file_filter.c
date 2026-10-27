#include <fltKernel.h>
#include "../include/msmon_protocol.h"

#define MSMON_POOL_TAG 'noSM'

BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime);
BOOLEAN MsMonCurrentIsBlackCat(VOID);
NTSTATUS MsMonLogEvent(ULONG Type, HANDLE ProcessId, HANDLE ParentProcessId, HANDLE ThreadId,
                       HANDLE TargetProcessId, LONGLONG TargetProcessStartTime, ULONG Flags,
                       NTSTATUS Status, ULONG DesiredAccess, ULONG Category,
                       ULONGLONG Value0, ULONGLONG Value1,
                       PCUNICODE_STRING Text, PCUNICODE_STRING Detail);
NTSTATUS MsMonLogPayloadSeries(ULONG Type, HANDLE ProcessId, HANDLE ThreadId, ULONG Flags,
                               NTSTATUS Status, ULONG Category, ULONGLONG Value0, ULONGLONG Value1,
                               PCUNICODE_STRING Text, PCUNICODE_STRING Detail,
                               ULONG PayloadKind, ULONGLONG OperationId, ULONGLONG TotalBytes,
                               const VOID* Payload, ULONG AvailableBytes);
BOOLEAN MsMonPayloadEnabled(VOID);
ULONGLONG MsMonNextOperationId(VOID);

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

static FLT_PREOP_CALLBACK_STATUS MsMonPreOperation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0) && !MsMonCurrentIsBlackCat()) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    (VOID)FltGetFileNameInformation(Data,
                                    FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_CACHE_ONLY,
                                    &nameInfo);
    *CompletionContext = nameInfo;
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
    PMDL* mdlAddress = NULL;
    PVOID* buffer = NULL;
    PULONG length = NULL;
    LOCK_OPERATION desiredAccess;
    NTSTATUS status;
    PVOID address = NULL;
    ULONG category = MsMonEventValue(Data, FALSE) == 1 ? MsMonCategoryHardwareIdentity : MsMonFileCategory(Path);

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        MsMonVolumeUnavailable(Data, Path, L"volume_query_failed");
        return;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        MsMonVolumeUnavailable(Data, Path, L"unsafe_irql");
        return;
    }
    status = FltDecodeParameters(Data, &mdlAddress, &buffer, &length, &desiredAccess);
    if (!NT_SUCCESS(status) || length == NULL || Data->IoStatus.Information == 0 ||
        Data->IoStatus.Information > (ULONGLONG)*length) {
        MsMonVolumeUnavailable(Data, Path, L"invalid_volume_result");
        return;
    }
    status = FltLockUserBuffer(Data);
    if (!NT_SUCCESS(status)) {
        MsMonVolumeUnavailable(Data, Path, L"buffer_lock_failed");
        return;
    }
    if (mdlAddress != NULL && *mdlAddress != NULL) {
        address = MmGetSystemAddressForMdlSafe(*mdlAddress, NormalPagePriority);
    } else if (buffer != NULL) {
        address = *buffer;
    }
    if (address == NULL) {
        MsMonVolumeUnavailable(Data, Path, L"buffer_mapping_failed");
        return;
    }
    (VOID)MsMonLogPayloadSeries(MsMonFileQueryVolumeInformation, PsGetCurrentProcessId(),
                                PsGetCurrentThreadId(), 0, Data->IoStatus.Status, category,
                                MsMonEventValue(Data, FALSE), 0, Path, NULL,
                                MsMonPayloadVolumeInformation, MsMonNextOperationId(),
                                Data->IoStatus.Information, address, (ULONG)Data->IoStatus.Information);
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
    UNREFERENCED_PARAMETER(Flags);
    if (MsMonIsTracked(PsGetCurrentProcessId(), 0) || MsMonCurrentIsBlackCat()) {
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
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PCUNICODE_STRING path = NULL;
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0) && !MsMonCurrentIsBlackCat()) return FLT_POSTOP_FINISHED_PROCESSING;
    if (NT_SUCCESS(FltGetFileNameInformation(Data,
                                             FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                             &nameInfo))) path = &nameInfo->Name;
    (VOID)MsMonLogEvent(MsMonFileCreate, PsGetCurrentProcessId(), NULL, PsGetCurrentThreadId(),
                        NULL, 0, path == NULL ? MsMonFlagMissingPath : 0, Data->IoStatus.Status,
                        Data->Iopb->Parameters.Create.SecurityContext != NULL ?
                            Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess : 0,
                        MsMonFileCategory(path),
                        Data->Iopb->Parameters.Create.Options, Data->IoStatus.Information, path, NULL);
    if (nameInfo != NULL) FltReleaseFileNameInformation(nameInfo);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static const FLT_OPERATION_REGISTRATION gOperations[] = {
    { IRP_MJ_CREATE, 0, NULL, MsMonPostCreate, NULL },
    { IRP_MJ_READ, 0, MsMonPreOperation, MsMonPostOperation, NULL },
    { IRP_MJ_WRITE, 0, MsMonPreOperation, MsMonPostOperation, NULL },
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

static const FLT_REGISTRATION gFilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, gOperations,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
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
        gFilter = NULL;
    }
}
