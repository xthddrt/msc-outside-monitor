#include <fltKernel.h>
#include "../include/msmon_protocol.h"

#define MSMON_POOL_TAG 'noSM'

BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime);
NTSTATUS MsMonLogEvent(ULONG Type, HANDLE ProcessId, HANDLE ParentProcessId, HANDLE ThreadId,
                       HANDLE TargetProcessId, LONGLONG TargetProcessStartTime, ULONG Flags,
                       NTSTATUS Status, ULONG DesiredAccess, ULONG Category,
                       ULONGLONG Value0, ULONGLONG Value1,
                       PCUNICODE_STRING Text, PCUNICODE_STRING Detail);

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
    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    (VOID)FltGetFileNameInformation(Data,
                                    FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_CACHE_ONLY,
                                    &nameInfo);
    *CompletionContext = nameInfo;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
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
    if (MsMonIsTracked(PsGetCurrentProcessId(), 0)) {
        (VOID)MsMonLogEvent(MsMonEventType(Data->Iopb->MajorFunction),
                            PsGetCurrentProcessId(), NULL, PsGetCurrentThreadId(), NULL, 0,
                            path == NULL ? MsMonFlagMissingPath : 0, Data->IoStatus.Status, 0,
                            MsMonFileCategory(path), MsMonEventValue(Data, FALSE),
                            MsMonEventValue(Data, TRUE), path, NULL);
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
    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0)) return FLT_POSTOP_FINISHED_PROCESSING;
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
