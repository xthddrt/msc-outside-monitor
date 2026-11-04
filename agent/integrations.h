#pragma once

#include "telemetry.h"

#define KFILTER_ABI_VERSION_5 5u
#define KFILTER_MAX_NAME_4 512u
#define KFILTER_EVENT_FLAG_WOULD_DENY_4 0x00000001u

/* kfilterd's Linux layout uses 32-bit fields where Windows has ULONG (64-bit on LP64). */
#ifdef _WIN32
typedef unsigned long KF4_ULONG;
typedef long KF4_LONG;
#else
typedef uint32_t KF4_ULONG;
typedef int32_t KF4_LONG;
#endif

#pragma pack(push, 8)
typedef struct _KFILTER_EVENT_4 {
    uint64_t Timestamp;
    KF4_ULONG ProcessId;
    KF4_ULONG Target;
    KF4_ULONG Action;
    KF4_ULONG Flags;
    KF4_LONG Status;
    KF4_ULONG Value;
    KF4_ULONG RuleId;
    KF4_ULONG Generation;
    wchar_t Path[KFILTER_MAX_NAME_4];
} KFILTER_EVENT_4;

typedef struct _KFILTER_STATUS_4 {
    KF4_ULONG AbiVersion;
    KF4_ULONG Mode;
    KF4_ULONG Flags;
    KF4_ULONG RuleCount;
    KF4_ULONG ProtectedCount;
    KF4_ULONG NetworkRuleCount;
    KF4_ULONG TrackedProcesses;
    KF4_ULONG Allowed;
    KF4_ULONG Denied;
    KF4_ULONG Audited;
    KF4_ULONG WouldDeny;
    KF4_ULONG NameFailures;
    KF4_ULONG MissingContexts;
    KF4_ULONG DroppedEvents;
    KF4_ULONG Registered;
    KF4_ULONG PolicyGeneration;
    KF4_ULONG SidFailures;
    KF4_ULONG Degraded;
    uint64_t SessionTag;
} KFILTER_STATUS_4;

typedef struct _KFILTER_READ_REQUEST_4 {
    KF4_ULONG MaximumEvents;
    KF4_ULONG Reserved;
} KFILTER_READ_REQUEST_4;
#pragma pack(pop)

/* sequence is required: every decision must carry a non-zero per-source sequence. */
TelemetryEvent KFilterDecisionEvent(const KFILTER_EVENT_4& event, uint64_t sessionId, uint64_t sequence);
std::wstring KFilterStatusDetail(const KFILTER_STATUS_4& status, const KFILTER_STATUS_4* start);
std::wstring IntegrationCoverageState(bool etwEnabled, const std::wstring& kfilterState);

/* The ring survives across agent runs: only decisions stamped at or after the session start
 * belong to this session. Events at the boundary are included. */
bool KFilterDecisionInSession(const KFILTER_EVENT_4& event, uint64_t sessionStart);

class KFilterReader {
public:
    KFilterReader(uint64_t sessionId, uint64_t sessionStart);
    ~KFilterReader();

    bool Open(KFILTER_STATUS_4& status, std::wstring& state, std::wstring& detail);
    bool Drain(std::vector<TelemetryEvent>& events, std::wstring& error);
    /* Visible so the offline regression can exercise the session filter and numbering. */
    void ConvertBatch(const KFILTER_EVENT_4* batch, unsigned count, std::vector<TelemetryEvent>& events);
    bool Status(KFILTER_STATUS_4& status, std::wstring& error);
    void Close();

private:
    uint64_t sessionId_;
    uint64_t sessionStart_;
    uint64_t sequence_ = 0;
#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
    /* Request/reply over KFILTER_SOCKET_PATH; one connection per request, see integrations.cpp. */
    bool Call(uint32_t code, const void* input, uint32_t inputLength, void* output, uint32_t capacity,
              uint32_t& bytes, std::wstring& error);
    bool open_ = false;
#endif
};
