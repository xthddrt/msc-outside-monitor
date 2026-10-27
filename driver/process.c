#include "msmon.h"

typedef struct _MSMON_PROCESS_ENTRY {
    LIST_ENTRY Link;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    LONGLONG StartTime;
    ULONG Flags;
} MSMON_PROCESS_ENTRY, *PMSMON_PROCESS_ENTRY;

static LIST_ENTRY gProcesses;
static KSPIN_LOCK gProcessLock;
static volatile LONG gProcessCount;
static UNICODE_STRING gClientRoot;
static KMUTEX gRootMutex;
static BOOLEAN gSessionActive;
static BOOLEAN gProcessNotifyEx;

static BOOLEAN MsMonImageMatches(PCUNICODE_STRING ImageFileName, PCWSTR RelativePath)
{
    UNICODE_STRING relative;
    UNICODE_STRING candidate;
    if (!gSessionActive || gClientRoot.Buffer == NULL || ImageFileName == NULL || ImageFileName->Buffer == NULL) {
        return FALSE;
    }
    RtlInitUnicodeString(&relative, RelativePath);
    if (ImageFileName->Length != gClientRoot.Length + relative.Length) return FALSE;
    if (ImageFileName->Length < gClientRoot.Length ||
        !RtlPrefixUnicodeString(&gClientRoot, ImageFileName, TRUE)) return FALSE;
    candidate.Buffer = (PWSTR)((PUCHAR)ImageFileName->Buffer + gClientRoot.Length);
    candidate.Length = relative.Length;
    candidate.MaximumLength = relative.Length;
    return RtlEqualUnicodeString(&candidate, &relative, TRUE);
}

static BOOLEAN MsMonKnownImage(PCUNICODE_STRING ImageFileName)
{
    BOOLEAN result;
    (VOID)KeWaitForSingleObject(&gRootMutex, Executive, KernelMode, FALSE, NULL);
    result = MsMonImageMatches(ImageFileName, L"\\MapleStory.exe") ||
             MsMonImageMatches(ImageFileName, L"\\grap\\NGService.exe") ||
             MsMonImageMatches(ImageFileName, L"\\NxOverlay\\DwarfAxe.exe") ||
             MsMonImageMatches(ImageFileName, L"\\CrashReportClient.exe");
    KeReleaseMutex(&gRootMutex, FALSE);
    return result;
}

static VOID MsMonClearProcesses(VOID)
{
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    while (!IsListEmpty(&gProcesses)) {
        entry = RemoveHeadList(&gProcesses);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, MSMON_PROCESS_ENTRY, Link), MSMON_POOL_TAG);
    }
    gProcessCount = 0;
    KeReleaseSpinLock(&gProcessLock, oldIrql);
}

NTSTATUS MsMonProcessStartSession(PCUNICODE_STRING ClientRoot)
{
    PWSTR buffer;
    PWSTR oldBuffer;
    UNICODE_STRING normalized;
    USHORT length;

    if (ClientRoot == NULL || ClientRoot->Buffer == NULL || ClientRoot->Length == 0 ||
        ClientRoot->Length >= MSMON_CLIENT_PATH_CHARS * sizeof(WCHAR)) return STATUS_INVALID_PARAMETER;
    length = ClientRoot->Length;
    while (length > 3 * sizeof(WCHAR) && ClientRoot->Buffer[length / sizeof(WCHAR) - 1] == L'\\') {
        length -= sizeof(WCHAR);
    }
    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)length + sizeof(WCHAR), MSMON_POOL_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(buffer, ClientRoot->Buffer, length);
    buffer[length / sizeof(WCHAR)] = L'\0';
    RtlInitUnicodeString(&normalized, buffer);
    normalized.Length = length;
    normalized.MaximumLength = length + sizeof(WCHAR);

    MsMonClearProcesses();
    (VOID)KeWaitForSingleObject(&gRootMutex, Executive, KernelMode, FALSE, NULL);
    oldBuffer = gClientRoot.Buffer;
    gClientRoot = normalized;
    gSessionActive = TRUE;
    KeReleaseMutex(&gRootMutex, FALSE);
    if (oldBuffer != NULL) ExFreePoolWithTag(oldBuffer, MSMON_POOL_TAG);
    return STATUS_SUCCESS;
}

VOID MsMonProcessStopSession(VOID)
{
    PWSTR buffer;
    (VOID)KeWaitForSingleObject(&gRootMutex, Executive, KernelMode, FALSE, NULL);
    gSessionActive = FALSE;
    buffer = gClientRoot.Buffer;
    gClientRoot.Buffer = NULL;
    gClientRoot.Length = 0;
    gClientRoot.MaximumLength = 0;
    KeReleaseMutex(&gRootMutex, FALSE);
    if (buffer != NULL) ExFreePoolWithTag(buffer, MSMON_POOL_TAG);
    MsMonClearProcesses();
}

NTSTATUS MsMonTrackProcess(HANDLE ProcessId, ULONG Flags)
{
    PMSMON_PROCESS_ENTRY entry;
    PMSMON_PROCESS_ENTRY existing;
    PMSMON_PROCESS_ENTRY stale = NULL;
    PLIST_ENTRY link;
    PEPROCESS process = NULL;
    KIRQL oldIrql;
    BOOLEAN duplicate = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    (VOID)KeWaitForSingleObject(&gRootMutex, Executive, KernelMode, FALSE, NULL);
    if (!gSessionActive) {
        KeReleaseMutex(&gRootMutex, FALSE);
        return STATUS_DEVICE_NOT_READY;
    }
    entry = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*entry), MSMON_POOL_TAG);
    if (entry == NULL) {
        KeReleaseMutex(&gRootMutex, FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(entry, sizeof(*entry));
    entry->ProcessId = ProcessId;
    entry->Flags = Flags;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        entry->StartTime = PsGetProcessCreateTimeQuadPart(process);
        entry->ParentProcessId = NULL;
        ObDereferenceObject(process);
    } else {
        ExFreePoolWithTag(entry, MSMON_POOL_TAG);
        KeReleaseMutex(&gRootMutex, FALSE);
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        existing = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (existing->ProcessId == ProcessId) {
            if (existing->StartTime == entry->StartTime) {
                duplicate = TRUE;
            } else {
                RemoveEntryList(&existing->Link);
                stale = existing;
                InterlockedDecrement(&gProcessCount);
            }
            break;
        }
    }
    if (!duplicate) {
        InsertTailList(&gProcesses, &entry->Link);
        InterlockedIncrement(&gProcessCount);
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);
    KeReleaseMutex(&gRootMutex, FALSE);
    if (stale != NULL) ExFreePoolWithTag(stale, MSMON_POOL_TAG);
    if (duplicate) ExFreePoolWithTag(entry, MSMON_POOL_TAG);
    return status;
}

BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime)
{
    PLIST_ENTRY link;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        PMSMON_PROCESS_ENTRY entry = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (entry->ProcessId == ProcessId &&
            (StartTime == 0 || entry->StartTime == 0 || entry->StartTime == StartTime)) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);
    return found;
}

LONGLONG MsMonProcessStartTime(HANDLE ProcessId)
{
    PLIST_ENTRY link;
    KIRQL oldIrql;
    LONGLONG startTime = 0;
    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        PMSMON_PROCESS_ENTRY entry = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (entry->ProcessId == ProcessId) {
            startTime = entry->StartTime;
            break;
        }
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);
    return startTime;
}

ULONG MsMonTrackedProcessCount(VOID)
{
    return (ULONG)gProcessCount;
}

static VOID MsMonForgetProcess(HANDLE ProcessId, LONGLONG StartTime)
{
    PLIST_ENTRY link;
    KIRQL oldIrql;
    PMSMON_PROCESS_ENTRY removed = NULL;
    KeAcquireSpinLock(&gProcessLock, &oldIrql);
    for (link = gProcesses.Flink; link != &gProcesses; link = link->Flink) {
        PMSMON_PROCESS_ENTRY entry = CONTAINING_RECORD(link, MSMON_PROCESS_ENTRY, Link);
        if (entry->ProcessId == ProcessId && entry->StartTime == StartTime) {
            RemoveEntryList(&entry->Link);
            removed = entry;
            InterlockedDecrement(&gProcessCount);
            break;
        }
    }
    KeReleaseSpinLock(&gProcessLock, oldIrql);
    if (removed != NULL) ExFreePoolWithTag(removed, MSMON_POOL_TAG);
}

static VOID MsMonProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    LONGLONG startTime = PsGetProcessCreateTimeQuadPart(Process);
    ULONG flags;
    NTSTATUS status;

    if (CreateInfo == NULL) {
        BOOLEAN tracked = MsMonIsTracked(ProcessId, startTime);
        if (tracked || MsMonCurrentIsBlackCat()) {
            (VOID)MsMonLogEvent(MsMonProcessExit, ProcessId, NULL, NULL, NULL, 0, 0,
                                STATUS_SUCCESS, 0, MsMonCategoryExternalProcess,
                                (ULONGLONG)startTime, 0, NULL, NULL);
        }
        if (tracked) MsMonForgetProcess(ProcessId, startTime);
        return;
    }
    if (MsMonIsTracked(CreateInfo->ParentProcessId, 0)) {
        flags = MsMonFlagInheritedTrack;
    } else if (MsMonKnownImage(CreateInfo->ImageFileName)) {
        flags = MsMonFlagExplicitTrack;
    } else if (MsMonCurrentIsBlackCat()) {
        (VOID)MsMonLogEvent(MsMonProcessStart, ProcessId, CreateInfo->ParentProcessId, NULL, NULL, 0,
                            MsMonFlagExplicitTrack, STATUS_SUCCESS, 0, MsMonCategoryExternalProcess,
                            (ULONGLONG)startTime, 0, CreateInfo->ImageFileName, CreateInfo->CommandLine);
        return;
    } else {
        return;
    }
    status = MsMonTrackProcess(ProcessId, flags);
    if (!NT_SUCCESS(status)) return;
    (VOID)MsMonLogEvent(MsMonProcessStart, ProcessId, CreateInfo->ParentProcessId, NULL, NULL, 0,
                        flags, STATUS_SUCCESS, 0, MsMonCategoryExternalProcess,
                        (ULONGLONG)startTime, 0, CreateInfo->ImageFileName, CreateInfo->CommandLine);
}

static VOID MsMonThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    if (!MsMonIsTracked(ProcessId, 0) && !MsMonCurrentIsBlackCat()) return;
    (VOID)MsMonLogEvent(Create ? MsMonThreadStart : MsMonThreadExit,
                        ProcessId, NULL, ThreadId, NULL, 0, 0, STATUS_SUCCESS, 0,
                        MsMonCategoryUnknown, 0, 0, NULL, NULL);
}

static VOID MsMonImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if (!MsMonIsTracked(ProcessId, 0) && !MsMonCurrentIsBlackCat()) return;
    (VOID)MsMonLogEvent(MsMonImageLoad, ProcessId, NULL, NULL, NULL, 0, 0,
                        STATUS_SUCCESS, 0, MsMonCategoryUnknown,
                        (ULONGLONG)ImageInfo->ImageBase, ImageInfo->ImageSize, FullImageName, NULL);
}

static VOID MsMonProcessNotifyLegacy(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) return;
    if (Create) {
        PUNICODE_STRING imageName = NULL;
        if (NT_SUCCESS(SeLocateProcessImageName(process, &imageName))) {
            PS_CREATE_NOTIFY_INFO info;
            RtlZeroMemory(&info, sizeof(info));
            info.ParentProcessId = ParentId;
            info.ImageFileName = imageName;
            MsMonProcessNotify(process, ProcessId, &info);
            ExFreePool(imageName);
        } else {
            MsMonProcessNotify(process, ProcessId, NULL);
        }
    } else {
        MsMonProcessNotify(process, ProcessId, NULL);
    }
    ObDereferenceObject(process);
}

static VOID MsMonRemoveProcessNotify(VOID)
{
    if (gProcessNotifyEx) {
        (VOID)PsSetCreateProcessNotifyRoutineEx(MsMonProcessNotify, TRUE);
    } else {
        (VOID)PsSetCreateProcessNotifyRoutine(MsMonProcessNotifyLegacy, TRUE);
    }
}

NTSTATUS MsMonProcessInitialize(VOID)
{
    NTSTATUS status;
    InitializeListHead(&gProcesses);
    KeInitializeSpinLock(&gProcessLock);
    KeInitializeMutex(&gRootMutex, 0);
    gProcessCount = 0;
    gClientRoot.Buffer = NULL;
    gSessionActive = FALSE;
    gProcessNotifyEx = FALSE;
    status = PsSetCreateProcessNotifyRoutineEx(MsMonProcessNotify, FALSE);
    if (NT_SUCCESS(status)) {
        gProcessNotifyEx = TRUE;
    } else {
        status = PsSetCreateProcessNotifyRoutine(MsMonProcessNotifyLegacy, FALSE);
        if (!NT_SUCCESS(status)) return status;
    }
    status = PsSetCreateThreadNotifyRoutine(MsMonThreadNotify);
    if (!NT_SUCCESS(status)) {
        MsMonRemoveProcessNotify();
        return status;
    }
    status = PsSetLoadImageNotifyRoutine(MsMonImageNotify);
    if (!NT_SUCCESS(status)) {
        (VOID)PsRemoveCreateThreadNotifyRoutine(MsMonThreadNotify);
        MsMonRemoveProcessNotify();
    }
    return status;
}

VOID MsMonProcessUninitialize(VOID)
{
    (VOID)PsSetLoadImageNotifyRoutine(MsMonImageNotify);
    (VOID)PsRemoveCreateThreadNotifyRoutine(MsMonThreadNotify);
    MsMonRemoveProcessNotify();
    MsMonProcessStopSession();
}
