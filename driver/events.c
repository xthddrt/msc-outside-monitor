#include "msmon.h"

typedef struct _MSMON_EVENT_BLOCK {
    LIST_ENTRY Link;
    MSMON_EVENT_HEADER Event;
} MSMON_EVENT_BLOCK, *PMSMON_EVENT_BLOCK;

typedef struct _MSMON_EVENT_QUEUE {
    KSPIN_LOCK Lock;
    LIST_ENTRY Head;
    KEVENT DataAvailable;
    ULONGLONG Sequence;
    ULONGLONG SessionId;
    volatile LONG64 Dropped;
    volatile LONG Queued;
    volatile LONG64 QueuedBytes;
    ULONG QueueRecordLimit;
    ULONG QueueByteLimit;
} MSMON_EVENT_QUEUE;

static MSMON_EVENT_QUEUE gQueue;

static USHORT MsMonStringBytes(PCUNICODE_STRING Value, PBOOLEAN Truncated)
{
    if (Value == NULL || Value->Buffer == NULL || Value->Length == 0) {
        return 0;
    }
    if (Value->Length > MSMON_MAX_EVENT_STRING_BYTES) {
        *Truncated = TRUE;
        return MSMON_MAX_EVENT_STRING_BYTES;
    }
    return Value->Length;
}

static VOID MsMonClearQueueLocked(VOID)
{
    while (!IsListEmpty(&gQueue.Head)) {
        PLIST_ENTRY entry = RemoveHeadList(&gQueue.Head);
        PMSMON_EVENT_BLOCK block = CONTAINING_RECORD(entry, MSMON_EVENT_BLOCK, Link);
        ExFreePoolWithTag(block, MSMON_POOL_TAG);
    }
    gQueue.Queued = 0;
    gQueue.QueuedBytes = 0;
    KeResetEvent(&gQueue.DataAvailable);
}

NTSTATUS MsMonEventsInitialize(VOID)
{
    KeInitializeSpinLock(&gQueue.Lock);
    InitializeListHead(&gQueue.Head);
    KeInitializeEvent(&gQueue.DataAvailable, SynchronizationEvent, FALSE);
    gQueue.Sequence = 0;
    gQueue.SessionId = 0;
    gQueue.Dropped = 0;
    gQueue.Queued = 0;
    gQueue.QueuedBytes = 0;
    gQueue.QueueRecordLimit = MSMON_DEFAULT_QUEUE_RECORDS;
    gQueue.QueueByteLimit = MSMON_DEFAULT_QUEUE_BYTES;
    return STATUS_SUCCESS;
}

NTSTATUS MsMonEventsStart(ULONGLONG SessionId, ULONG QueueRecords, ULONG QueueBytes)
{
    KIRQL oldIrql;
    if (SessionId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (QueueRecords == 0) QueueRecords = MSMON_DEFAULT_QUEUE_RECORDS;
    if (QueueBytes == 0) QueueBytes = MSMON_DEFAULT_QUEUE_BYTES;
    QueueRecords = min(QueueRecords, MSMON_MAX_QUEUE_RECORDS);
    QueueBytes = min(QueueBytes, MSMON_MAX_QUEUE_BYTES);
    QueueBytes = max(QueueBytes, MSMON_MAX_EVENT_RECORD_BYTES * 2u);

    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    MsMonClearQueueLocked();
    gQueue.Sequence = 0;
    gQueue.Dropped = 0;
    gQueue.SessionId = SessionId;
    gQueue.QueueRecordLimit = QueueRecords;
    gQueue.QueueByteLimit = QueueBytes;
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    return STATUS_SUCCESS;
}

VOID MsMonEventsStop(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    gQueue.SessionId = 0;
    MsMonClearQueueLocked();
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
}

VOID MsMonEventsUninitialize(VOID)
{
    MsMonEventsStop();
}

NTSTATUS MsMonLogEvent(
    ULONG Type,
    HANDLE ProcessId,
    HANDLE ParentProcessId,
    HANDLE ThreadId,
    HANDLE TargetProcessId,
    LONGLONG TargetProcessStartTime,
    ULONG Flags,
    NTSTATUS Status,
    ULONG DesiredAccess,
    ULONG Category,
    ULONGLONG Value0,
    ULONGLONG Value1,
    PCUNICODE_STRING Text,
    PCUNICODE_STRING Detail
)
{
    PMSMON_EVENT_BLOCK block;
    LARGE_INTEGER timestamp;
    KIRQL oldIrql;
    BOOLEAN truncated = FALSE;
    USHORT textBytes = MsMonStringBytes(Text, &truncated);
    USHORT detailBytes = MsMonStringBytes(Detail, &truncated);
    ULONG textOffset = (sizeof(MSMON_EVENT_HEADER) + 7u) & ~7u;
    ULONG detailOffset = (textOffset + textBytes + (textBytes != 0 ? 2u : 0u) + 7u) & ~7u;
    ULONG recordBytes = detailOffset + detailBytes + (detailBytes != 0 ? 2u : 0u);
    ULONG allocationBytes = sizeof(LIST_ENTRY) + recordBytes;
    PWSTR destination;

    if (recordBytes > MSMON_MAX_EVENT_RECORD_BYTES) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    block = ExAllocatePool2(POOL_FLAG_NON_PAGED, allocationBytes, MSMON_POOL_TAG);
    if (block == NULL) {
        KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
        if (gQueue.SessionId != 0) gQueue.Sequence++;
        InterlockedIncrement64(&gQueue.Dropped);
        KeReleaseSpinLock(&gQueue.Lock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(block, allocationBytes);
    block->Event.Size = recordBytes;
    block->Event.Version = MSMON_PROTOCOL_VERSION;
    block->Event.Type = Type;
    block->Event.Flags = Flags | (truncated ? MsMonFlagTruncatedPath : 0);
    block->Event.ProcessId = HandleToULong(ProcessId);
    block->Event.ParentProcessId = HandleToULong(ParentProcessId);
    block->Event.ThreadId = HandleToULong(ThreadId);
    block->Event.TargetProcessId = HandleToULong(TargetProcessId);
    block->Event.ProcessStartTime = (ULONGLONG)MsMonProcessStartTime(ProcessId);
    block->Event.TargetProcessStartTime = (ULONGLONG)TargetProcessStartTime;
    block->Event.Status = Status;
    block->Event.DesiredAccess = DesiredAccess;
    block->Event.Category = Category;
    block->Event.Attribution = MsMonAttributionProcessOnly;
    block->Event.Value0 = Value0;
    block->Event.Value1 = Value1;
    KeQuerySystemTime(&timestamp);
    block->Event.Timestamp = (ULONGLONG)timestamp.QuadPart;

    if (textBytes != 0) {
        block->Event.TextOffset = (USHORT)textOffset;
        block->Event.TextBytes = textBytes;
        destination = (PWSTR)((PUCHAR)&block->Event + textOffset);
        RtlCopyMemory(destination, Text->Buffer, textBytes);
        destination[textBytes / sizeof(WCHAR)] = L'\0';
    }
    if (detailBytes != 0) {
        block->Event.DetailOffset = (USHORT)detailOffset;
        block->Event.DetailBytes = detailBytes;
        destination = (PWSTR)((PUCHAR)&block->Event + detailOffset);
        RtlCopyMemory(destination, Detail->Buffer, detailBytes);
        destination[detailBytes / sizeof(WCHAR)] = L'\0';
    }

    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    if (gQueue.SessionId == 0) {
        KeReleaseSpinLock(&gQueue.Lock, oldIrql);
        ExFreePoolWithTag(block, MSMON_POOL_TAG);
        return STATUS_DEVICE_NOT_READY;
    }
    block->Event.SessionId = gQueue.SessionId;
    block->Event.Sequence = ++gQueue.Sequence;
    if ((ULONG)gQueue.Queued >= gQueue.QueueRecordLimit ||
        (ULONGLONG)gQueue.QueuedBytes + recordBytes > gQueue.QueueByteLimit) {
        InterlockedIncrement64(&gQueue.Dropped);
        KeReleaseSpinLock(&gQueue.Lock, oldIrql);
        ExFreePoolWithTag(block, MSMON_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }
    InsertTailList(&gQueue.Head, &block->Link);
    InterlockedIncrement(&gQueue.Queued);
    InterlockedAdd64(&gQueue.QueuedBytes, recordBytes);
    KeSetEvent(&gQueue.DataAvailable, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS MsMonReadEvents(PVOID Output, ULONG MaximumBytes, ULONG TimeoutMilliseconds, PULONG BytesRead)
{
    ULONG count = 0;
    LARGE_INTEGER timeout;
    KIRQL oldIrql;

    *BytesRead = 0;
    if (Output == NULL || MaximumBytes < MSMON_MAX_EVENT_RECORD_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    if (IsListEmpty(&gQueue.Head)) KeResetEvent(&gQueue.DataAvailable);
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);

    timeout.QuadPart = -((LONGLONG)TimeoutMilliseconds * 10000LL);
    if (TimeoutMilliseconds != 0) {
        (VOID)KeWaitForSingleObject(&gQueue.DataAvailable, Executive, KernelMode, FALSE, &timeout);
    }

    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    while (!IsListEmpty(&gQueue.Head)) {
        PLIST_ENTRY entry = gQueue.Head.Flink;
        PMSMON_EVENT_BLOCK block = CONTAINING_RECORD(entry, MSMON_EVENT_BLOCK, Link);
        ULONG recordBytes = block->Event.Size;
        if (recordBytes > MaximumBytes - count) break;
        RemoveEntryList(entry);
        RtlCopyMemory((PUCHAR)Output + count, &block->Event, recordBytes);
        ExFreePoolWithTag(block, MSMON_POOL_TAG);
        InterlockedDecrement(&gQueue.Queued);
        InterlockedAdd64(&gQueue.QueuedBytes, -(LONG64)recordBytes);
        count += recordBytes;
    }
    if (IsListEmpty(&gQueue.Head)) KeResetEvent(&gQueue.DataAvailable);
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    *BytesRead = count;
    return STATUS_SUCCESS;
}

VOID MsMonGetStatistics(PMSMON_STATISTICS Statistics)
{
    KIRQL oldIrql;
    RtlZeroMemory(Statistics, sizeof(*Statistics));
    KeAcquireSpinLock(&gQueue.Lock, &oldIrql);
    Statistics->SessionId = gQueue.SessionId;
    Statistics->QueuedEvents = (ULONGLONG)gQueue.Queued;
    Statistics->QueuedBytes = (ULONGLONG)gQueue.QueuedBytes;
    Statistics->DroppedEvents = (ULONGLONG)gQueue.Dropped;
    Statistics->QueueRecordLimit = gQueue.QueueRecordLimit;
    Statistics->QueueByteLimit = gQueue.QueueByteLimit;
    KeReleaseSpinLock(&gQueue.Lock, oldIrql);
    Statistics->TrackedProcesses = MsMonTrackedProcessCount();
}
