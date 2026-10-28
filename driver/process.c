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
static BOOLEAN gProcessNotifyRegistered;
static BOOLEAN gThreadNotifyRegistered;
static BOOLEAN gImageNotifyRegistered;
static BOOLEAN gCallbackRundownInitialized;
static BOOLEAN gProcessInitialized;
static EX_RUNDOWN_REF gCallbackRundown;

VOID MsMonRecordStatus(PCWSTR Name, NTSTATUS Status)
{
    UNICODE_STRING path;
    UNICODE_STRING valueName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE key = NULL;
    RtlInitUnicodeString(&path, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\msmon");
    InitializeObjectAttributes(&attributes, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_SET_VALUE, &attributes))) return;
    RtlInitUnicodeString(&valueName, Name);
    (VOID)ZwSetValueKey(key, &valueName, 0, REG_DWORD, &Status, sizeof(Status));
    (VOID)ZwClose(key);
}

/*
 * Track any executable image beneath the configured client root, not a
 * hard-coded list.  The installation contains PE payloads with non-.exe
 * extensions (for example the GRAP .aes images) and private-server builds
 * may rename helpers.  The root is the appdata scope chosen by the agent;
 * descendants are still inherited separately.
 */
static BOOLEAN MsMonImageUnderRoot(PCUNICODE_STRING ImageFileName)
{
    BOOLEAN result = FALSE;
    USHORT offset;
    WCHAR boundary;
    if (!gSessionActive || gClientRoot.Buffer == NULL || ImageFileName == NULL || ImageFileName->Buffer == NULL) {
        return FALSE;
    }
    (VOID)KeWaitForSingleObject(&gRootMutex, Executive, KernelMode, FALSE, NULL);
    if (gSessionActive && gClientRoot.Buffer != NULL &&
        ImageFileName->Length > gClientRoot.Length &&
        RtlPrefixUnicodeString(&gClientRoot, ImageFileName, TRUE)) {
        offset = gClientRoot.Length;
        boundary = ImageFileName->Buffer[offset / sizeof(WCHAR)];
        result = (boundary == L'\\');
    }
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

static VOID MsMonProcessNotifyInner(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    LONGLONG startTime = PsGetProcessCreateTimeQuadPart(Process);
    ULONG flags;
    NTSTATUS status;

    MsMonCoverageEnter(MSMON_SENSOR_PROCESS_NOTIFY);
    if (CreateInfo == NULL) {
        BOOLEAN tracked = MsMonIsTracked(ProcessId, startTime);
        if (tracked || MsMonCurrentIsBlackCat()) {
            (VOID)MsMonLogEvent(MsMonProcessExit, ProcessId, NULL, NULL, NULL, 0, 0,
                                STATUS_SUCCESS, 0, MsMonCategoryExternalProcess,
                                (ULONGLONG)startTime, 0, NULL, NULL);
            MsMonCoverageLogged(MSMON_SENSOR_PROCESS_NOTIFY);
        }
        if (tracked) MsMonForgetProcess(ProcessId, startTime);
        return;
    }
    if (MsMonIsTracked(CreateInfo->ParentProcessId, 0)) {
        flags = MsMonFlagInheritedTrack;
    } else if (MsMonImageUnderRoot(CreateInfo->ImageFileName)) {
        flags = MsMonFlagExplicitTrack;
    } else if (MsMonCurrentIsBlackCat()) {
        /*
         * A process created by BlackCat is part of the observed application
         * tree.  Log it and add it to the tracked set so its later file,
         * registry, network, and handle events are not lost.
         */
        flags = MsMonFlagExplicitTrack;
        status = MsMonTrackProcess(ProcessId, flags);
        if (!NT_SUCCESS(status)) {
            MsMonCoverageSkip(MSMON_SKIP_TRACK);
            MsMonEventsNoteDropped();
            return;
        }
        (VOID)MsMonLogEvent(MsMonProcessStart, ProcessId, CreateInfo->ParentProcessId, NULL, NULL, 0,
                            flags, STATUS_SUCCESS, 0, MsMonCategoryExternalProcess,
                            (ULONGLONG)startTime, 0, CreateInfo->ImageFileName, CreateInfo->CommandLine);
        MsMonCoverageLogged(MSMON_SENSOR_PROCESS_NOTIFY);
        return;
    } else {
        return;
    }
    status = MsMonTrackProcess(ProcessId, flags);
    if (!NT_SUCCESS(status)) {
        MsMonCoverageSkip(MSMON_SKIP_TRACK);
        MsMonEventsNoteDropped();
        return;
    }
    (VOID)MsMonLogEvent(MsMonProcessStart, ProcessId, CreateInfo->ParentProcessId, NULL, NULL, 0,
                        flags, STATUS_SUCCESS, 0, MsMonCategoryExternalProcess,
                        (ULONGLONG)startTime, 0, CreateInfo->ImageFileName, CreateInfo->CommandLine);
    MsMonCoverageLogged(MSMON_SENSOR_PROCESS_NOTIFY);
}

static VOID MsMonProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (!ExAcquireRundownProtection(&gCallbackRundown)) return;
    MsMonProcessNotifyInner(Process, ProcessId, CreateInfo);
    ExReleaseRundownProtection(&gCallbackRundown);
}

static VOID MsMonThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    if (!ExAcquireRundownProtection(&gCallbackRundown)) return;
    MsMonCoverageEnter(MSMON_SENSOR_THREAD_NOTIFY);
    if (MsMonIsTracked(ProcessId, 0) || MsMonCurrentIsBlackCat()) {
        (VOID)MsMonLogEvent(Create ? MsMonThreadStart : MsMonThreadExit,
                            ProcessId, NULL, ThreadId, NULL, 0, 0, STATUS_SUCCESS, 0,
                            MsMonCategoryUnknown, 0, 0, NULL, NULL);
        MsMonCoverageLogged(MSMON_SENSOR_THREAD_NOTIFY);
    }
    ExReleaseRundownProtection(&gCallbackRundown);
}

static VOID MsMonImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if (!ExAcquireRundownProtection(&gCallbackRundown)) return;
    MsMonCoverageEnter(MSMON_SENSOR_IMAGE_NOTIFY);
    if (MsMonIsTracked(ProcessId, 0) || MsMonCurrentIsBlackCat()) {
        (VOID)MsMonLogEvent(MsMonImageLoad, ProcessId, NULL, NULL, NULL, 0, 0,
                            STATUS_SUCCESS, 0, MsMonCategoryUnknown,
                            (ULONGLONG)ImageInfo->ImageBase, ImageInfo->ImageSize, FullImageName, NULL);
        MsMonCoverageLogged(MSMON_SENSOR_IMAGE_NOTIFY);
    }
    ExReleaseRundownProtection(&gCallbackRundown);
}

static VOID MsMonProcessNotifyLegacy(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    PEPROCESS process = NULL;
    if (!ExAcquireRundownProtection(&gCallbackRundown)) return;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        if (Create) {
            PUNICODE_STRING imageName = NULL;
            if (NT_SUCCESS(SeLocateProcessImageName(process, &imageName))) {
                PS_CREATE_NOTIFY_INFO info;
                RtlZeroMemory(&info, sizeof(info));
                info.ParentProcessId = ParentId;
                info.ImageFileName = imageName;
                MsMonProcessNotifyInner(process, ProcessId, &info);
                ExFreePool(imageName);
            } else {
                MsMonProcessNotifyInner(process, ProcessId, NULL);
            }
        } else {
            MsMonProcessNotifyInner(process, ProcessId, NULL);
        }
        ObDereferenceObject(process);
    }
    ExReleaseRundownProtection(&gCallbackRundown);
}

static VOID MsMonRemoveProcessNotify(VOID)
{
    if (!gProcessNotifyRegistered) return;
    if (gProcessNotifyEx) {
        (VOID)PsSetCreateProcessNotifyRoutineEx(MsMonProcessNotify, TRUE);
    } else {
        (VOID)PsSetCreateProcessNotifyRoutine(MsMonProcessNotifyLegacy, TRUE);
    }
    gProcessNotifyRegistered = FALSE;
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
    gProcessNotifyRegistered = FALSE;
    gThreadNotifyRegistered = FALSE;
    gImageNotifyRegistered = FALSE;
    gCallbackRundownInitialized = TRUE;
    gProcessInitialized = TRUE;
    ExInitializeRundownProtection(&gCallbackRundown);
    status = PsSetCreateProcessNotifyRoutineEx(MsMonProcessNotify, FALSE);
    if (NT_SUCCESS(status)) {
        gProcessNotifyEx = TRUE;
        gProcessNotifyRegistered = TRUE;
    } else {
        status = PsSetCreateProcessNotifyRoutine(MsMonProcessNotifyLegacy, FALSE);
        if (!NT_SUCCESS(status)) {
            MsMonCoverageRegister(MSMON_SENSOR_REG_PROCESS_NOTIFY, status);
            return status;
        }
        gProcessNotifyRegistered = TRUE;
    }
    MsMonCoverageRegister(MSMON_SENSOR_REG_PROCESS_NOTIFY, status);
    status = PsSetCreateThreadNotifyRoutine(MsMonThreadNotify);
    if (!NT_SUCCESS(status)) {
        MsMonCoverageRegister(MSMON_SENSOR_REG_THREAD_NOTIFY, status);
        MsMonRemoveProcessNotify();
        return status;
    }
    MsMonCoverageRegister(MSMON_SENSOR_REG_THREAD_NOTIFY, status);
    gThreadNotifyRegistered = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS MsMonImageInitialize(VOID)
{
    NTSTATUS status = PsSetLoadImageNotifyRoutine(MsMonImageNotify);
    gImageNotifyRegistered = NT_SUCCESS(status);
    MsMonCoverageRegister(MSMON_SENSOR_REG_IMAGE_NOTIFY, status);
    MsMonRecordStatus(L"ImageRegisterStatus", status);
    return status;
}

VOID MsMonProcessUninitialize(VOID)
{
    /*
     * MsMonProcessInitialize may never have run if an earlier driver
     * initialisation step failed; the list, mutex and spin lock would still be
     * zeroed memory and must not be touched.
     */
    if (!gProcessInitialized) return;
    MsMonRecordStatus(L"ProcessUninitializeStart", STATUS_SUCCESS);
    if (gImageNotifyRegistered) {
        /*
         * Image-notify routines are removed with PsRemoveLoadImageNotifyRoutine.
         * The previous code called PsSetLoadImageNotifyRoutine again, which only
         * fails (the routine is already registered) and leaves a pointer to this
         * driver in the kernel's notify list after the image is unloaded. The
         * next image load anywhere in the system then jumps into unmapped code
         * and bugchecks.
         */
        NTSTATUS removeStatus = PsRemoveLoadImageNotifyRoutine(MsMonImageNotify);
        gImageNotifyRegistered = FALSE;
        MsMonRecordStatus(L"ImageRemoveStatus", removeStatus);
    } else {
        MsMonRecordStatus(L"ImageRemoveStatus", STATUS_PROCEDURE_NOT_FOUND);
    }
    if (gThreadNotifyRegistered) {
        (VOID)PsRemoveCreateThreadNotifyRoutine(MsMonThreadNotify);
        gThreadNotifyRegistered = FALSE;
    }
    MsMonRemoveProcessNotify();
    if (gCallbackRundownInitialized) {
        /*
         * The wait refuses new callback acquisitions and drains the callbacks
         * already running; ExRundownCompleted must follow it and only then is
         * the rundown state final.
         */
        ExWaitForRundownProtectionRelease(&gCallbackRundown);
        ExRundownCompleted(&gCallbackRundown);
        gCallbackRundownInitialized = FALSE;
    }
    MsMonRecordStatus(L"RundownComplete", STATUS_SUCCESS);
    MsMonProcessStopSession();
}
