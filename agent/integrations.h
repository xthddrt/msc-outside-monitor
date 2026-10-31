#pragma once

#include "telemetry.h"

#define KFILTER_ABI_VERSION_4 4u
#define KFILTER_MAX_NAME_4 512u
#define KFILTER_EVENT_FLAG_WOULD_DENY_4 0x00000001u

#pragma pack(push, 8)
typedef struct _KFILTER_EVENT_4 {
    unsigned __int64 Timestamp;
    unsigned long ProcessId;
    unsigned long Target;
    unsigned long Action;
    unsigned long Flags;
    long Status;
    unsigned long Value;
    unsigned long RuleId;
    unsigned long Generation;
    wchar_t Path[KFILTER_MAX_NAME_4];
} KFILTER_EVENT_4;

typedef struct _KFILTER_STATUS_4 {
    unsigned long AbiVersion;
    unsigned long Mode;
    unsigned long Flags;
    unsigned long RuleCount;
    unsigned long ProtectedCount;
    unsigned long NetworkRuleCount;
    unsigned long TrackedProcesses;
    unsigned long Allowed;
    unsigned long Denied;
    unsigned long Audited;
    unsigned long WouldDeny;
    unsigned long NameFailures;
    unsigned long MissingContexts;
    unsigned long DroppedEvents;
    unsigned long Registered;
    unsigned long PolicyGeneration;
    unsigned long SidFailures;
    unsigned long Degraded;
    unsigned __int64 SessionTag;
} KFILTER_STATUS_4;

typedef struct _KFILTER_READ_REQUEST_4 {
    unsigned long MaximumEvents;
    unsigned long Reserved;
} KFILTER_READ_REQUEST_4;
#pragma pack(pop)

/* sequence is required: every decision must carry a non-zero per-source sequence. */
TelemetryEvent KFilterDecisionEvent(const KFILTER_EVENT_4& event, uint64_t sessionId, uint64_t sequence);
std::wstring KFilterStatusDetail(const KFILTER_STATUS_4& status, const KFILTER_STATUS_4* start);
std::wstring IntegrationCoverageState(bool etwEnabled, const std::wstring& kfilterState);

class KFilterReader {
public:
    explicit KFilterReader(uint64_t sessionId);
    ~KFilterReader();

    bool Open(KFILTER_STATUS_4& status, std::wstring& state, std::wstring& detail);
    bool Drain(std::vector<TelemetryEvent>& events, std::wstring& error);
    bool Status(KFILTER_STATUS_4& status, std::wstring& error);
    void Close();

private:
    uint64_t sessionId_;
    uint64_t sequence_ = 0;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};
