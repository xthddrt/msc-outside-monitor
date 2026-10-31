#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define MSMON_DEVICE_NAME L"\\Device\\MsMon"
#define MSMON_DOS_DEVICE_NAME L"\\DosDevices\\MsMon"
#define MSMON_USER_DEVICE_PATH "\\\\.\\MsMon"
#define MSMON_PROTOCOL_VERSION 4u
#define MSMON_MAX_EVENT_RECORD_BYTES 16384u
#define MSMON_MAX_EVENT_STRING_BYTES 2048u
#define MSMON_PAYLOAD_CHUNK_BYTES 8192u
#define MSMON_MAX_PAYLOAD_TOTAL_BYTES (8u * 1024u * 1024u)
#define MSMON_READ_MAX_BYTES (1024u * 1024u)
#define MSMON_DEFAULT_QUEUE_RECORDS 16384u
/* The byte limit bounds nonpaged memory; the record limit only has to exceed what it admits. */
#define MSMON_MAX_QUEUE_RECORDS 131072u
#define MSMON_DEFAULT_QUEUE_BYTES (64u * 1024u * 1024u)
#define MSMON_MAX_QUEUE_BYTES (128u * 1024u * 1024u)
#define MSMON_CLIENT_PATH_CHARS 260u
#define MSMON_EXTRA_ROOTS 3u
#define MSMON_MAX_STACK_FRAMES 24u

typedef enum _MSMON_EVENT_TYPE {
    MsMonProcessStart = 1,
    MsMonProcessExit = 2,
    MsMonThreadStart = 3,
    MsMonThreadExit = 4,
    MsMonImageLoad = 5,
    MsMonProcessHandle = 6,
    MsMonThreadHandle = 7,
    MsMonFileCreate = 10,
    MsMonFileRead = 11,
    MsMonFileWrite = 12,
    MsMonFileSetInformation = 13,
    MsMonFileDirectoryControl = 14,
    MsMonFileCleanup = 15,
    MsMonFileDeviceControl = 16,
    MsMonFileSystemControl = 17,
    MsMonFileQueryVolumeInformation = 18,
    MsMonFileQueryInformation = 19,
    MsMonRegistryOpen = 20,
    MsMonRegistryCreate = 21,
    MsMonRegistrySetValue = 22,
    MsMonRegistryDelete = 23,
    MsMonRegistryRename = 24,
    MsMonRegistryQuery = 25,
    MsMonRegistryEnumerate = 26,
    MsMonNetworkConnect = 30,
    MsMonNetworkAccept = 31,
    MsMonNetworkFlowEstablished = 32,
    MsMonNetworkFlowClose = 33,
    MsMonFileSection = 34,
    MsMonFileClose = 35,
    MsMonFileFlush = 36,
    MsMonFileQuerySecurity = 37,
    MsMonFileSetSecurity = 38,
    MsMonFileQueryEa = 39,
    MsMonFileSetEa = 40,
    MsMonEtwWmi = 100,
    MsMonEtwDns = 101,
    MsMonEtwRpc = 102,
    MsMonEtwUnattributed = 103,
    MsMonEtwTcp = 104,
    MsMonEtwCodeIntegrity = 105,
    MsMonCoverage = 110,
    MsMonCoverageUsage = 111,
    MsMonKfilterDecision = 120
} MSMON_EVENT_TYPE;

typedef enum _MSMON_EVENT_FLAGS {
    MsMonFlagExplicitTrack = 0x00000001u,
    MsMonFlagInheritedTrack = 0x00000002u,
    MsMonFlagTruncatedPath = 0x00000004u,
    MsMonFlagMissingPath = 0x00000008u,
    MsMonFlagServiceCorrelated = 0x00000010u,
    MsMonFlagObserverRecord = 0x00000020u,
    MsMonFlagPayloadPresent = 0x00000040u,
    MsMonFlagPayloadUnavailable = 0x00000080u,
    MsMonFlagPayloadFinalChunk = 0x00000100u,
    MsMonFlagPayloadInput = 0x00000200u,
    MsMonFlagPayloadPartial = 0x00000400u
} MSMON_EVENT_FLAGS;

typedef enum _MSMON_PAYLOAD_KIND {
    MsMonPayloadNone = 0,
    MsMonPayloadRegistryValue = 1,
    MsMonPayloadVolumeInformation = 2
} MSMON_PAYLOAD_KIND;

typedef enum _MSMON_CATEGORY {
    MsMonCategoryUnknown = 0,
    MsMonCategoryClientData = 1,
    MsMonCategoryWindowsRuntime = 2,
    MsMonCategoryExternalProcess = 3,
    MsMonCategoryBrowserInteraction = 4,
    MsMonCategoryHardwareIdentity = 5,
    MsMonCategoryUserData = 6,
    MsMonCategoryRegistry = 7,
    MsMonCategoryNetwork = 8,
    MsMonCategoryIpc = 9
} MSMON_CATEGORY;

typedef enum _MSMON_ATTRIBUTION {
    MsMonAttributionUnknown = 0,
    MsMonAttributionProcessOnly = 1,
    MsMonAttributionStackResolved = 2,
    MsMonAttributionServiceCorrelated = 3,
    MsMonAttributionStaticEvidence = 4
} MSMON_ATTRIBUTION;

#pragma pack(push, 8)
typedef struct _MSMON_EVENT_HEADER {
    unsigned long Size;
    unsigned long Version;
    unsigned long Type;
    unsigned long Flags;
    unsigned __int64 Sequence;
    unsigned __int64 Timestamp;
    unsigned __int64 SessionId;
    unsigned long ProcessId;
    unsigned long ParentProcessId;
    unsigned long ThreadId;
    unsigned long TargetProcessId;
    unsigned __int64 ProcessStartTime;
    unsigned __int64 TargetProcessStartTime;
    long Status;
    unsigned long DesiredAccess;
    unsigned long Category;
    unsigned long Attribution;
    unsigned short TextOffset;
    unsigned short TextBytes;
    unsigned short DetailOffset;
    unsigned short DetailBytes;
    unsigned short ComponentOffset;
    unsigned short ComponentBytes;
    unsigned __int64 Value0;
    unsigned __int64 Value1;
    unsigned __int64 OperationId;
    unsigned __int64 PayloadTotalBytes;
    unsigned __int64 PayloadByteOffset;
    unsigned long PayloadChunkIndex;
    unsigned long PayloadChunkCount;
    unsigned long PayloadKind;
    unsigned long PayloadOffset;
    unsigned long PayloadBytes;
    /*
     * User-mode return addresses of the requesting thread, one unsigned
     * __int64 each, at StackOffset; both zero when no stack was captured.
     * These two fields were a zeroed Reserved ULONG, so the layout is unchanged.
     */
    unsigned short StackOffset;
    unsigned short StackFrames;
} MSMON_EVENT_HEADER;

typedef struct _MSMON_PAYLOAD {
    unsigned __int64 OperationId;
    unsigned __int64 TotalBytes;
    unsigned __int64 ByteOffset;
    unsigned long ChunkIndex;
    unsigned long ChunkCount;
    unsigned long Kind;
    const VOID* Data;
    unsigned long ByteCount;
} MSMON_PAYLOAD;

typedef struct _MSMON_SESSION_CONFIG {
    unsigned __int64 SessionId;
    unsigned long QueueRecords;
    unsigned long QueueBytes;
    unsigned long PayloadMode;
    unsigned long Reserved;
    wchar_t ClientRoot[MSMON_CLIENT_PATH_CHARS];
    /*
     * Further device-path roots tracked like ClientRoot; empty entries are
     * unused.  Drivers accept the shorter structure that ends at ClientRoot.
     */
    wchar_t ExtraRoots[MSMON_EXTRA_ROOTS][MSMON_CLIENT_PATH_CHARS];
} MSMON_SESSION_CONFIG;

typedef struct _MSMON_TRACK_REQUEST {
    unsigned long ProcessId;
    unsigned long Flags;
    unsigned __int64 ProcessStartTime;
} MSMON_TRACK_REQUEST;

typedef struct _MSMON_READ_REQUEST {
    unsigned long TimeoutMilliseconds;
    unsigned long MaximumBytes;
} MSMON_READ_REQUEST;

typedef struct _MSMON_STATISTICS {
    unsigned __int64 SessionId;
    unsigned __int64 QueuedEvents;
    unsigned __int64 QueuedBytes;
    unsigned __int64 DroppedEvents;
    unsigned __int64 TrackedProcesses;
    unsigned __int64 QueueRecordLimit;
    unsigned __int64 QueueByteLimit;
} MSMON_STATISTICS;
#pragma pack(pop)

typedef MSMON_EVENT_HEADER* PMSMON_EVENT_HEADER;
typedef MSMON_SESSION_CONFIG* PMSMON_SESSION_CONFIG;
typedef MSMON_TRACK_REQUEST* PMSMON_TRACK_REQUEST;
typedef MSMON_READ_REQUEST* PMSMON_READ_REQUEST;
typedef MSMON_STATISTICS* PMSMON_STATISTICS;

#define MSMON_IOCTL_START_SESSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_STOP_SESSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_TRACK_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_READ_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
#define MSMON_IOCTL_STATISTICS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS)
#define MSMON_IOCTL_STOP_TRACKING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_REFRESH_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MSMON_IOCTL_COVERAGE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS)

#ifdef __cplusplus
}
#endif
