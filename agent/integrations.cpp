#include "integrations.h"
#include <sstream>

#define KFILTER_IOCTL_GET_STATUS_4 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define KFILTER_IOCTL_READ_EVENTS_4 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

static std::wstring HexValue(unsigned long value)
{
    wchar_t buffer[16];
    swprintf_s(buffer, L"0x%08lX", value);
    return buffer;
}

static const wchar_t* KFilterTargetName(unsigned long target)
{
    switch (target) {
    case 0x00000001u: return L"file";
    case 0x00000002u: return L"dir";
    case 0x00000004u: return L"registry";
    case 0x00000008u: return L"process";
    case 0x00000010u: return L"volume";
    case 0x00000020u: return L"device";
    case 0x00000040u: return L"pipe";
    case 0x00000080u: return L"network";
    default: return L"unknown";
    }
}

static const wchar_t* KFilterActionName(unsigned long action)
{
    switch (action) {
    case 1u: return L"audit";
    case 2u: return L"allow";
    case 3u: return L"deny";
    default: return L"unknown";
    }
}

TelemetryEvent KFilterDecisionEvent(const KFILTER_EVENT_4& source, uint64_t sessionId, uint64_t sequence)
{
    TelemetryEvent event;
    event.source = "agent";
    event.header.Size = sizeof(event.header);
    event.header.Version = MSMON_PROTOCOL_VERSION;
    event.header.Type = MsMonKfilterDecision;
    event.header.Flags = MsMonFlagObserverRecord;
    event.header.Sequence = sequence;
    event.header.Timestamp = source.Timestamp;
    event.header.SessionId = sessionId;
    event.header.ProcessId = source.ProcessId;
    event.header.Status = source.Status;
    event.header.DesiredAccess = source.Value;
    event.header.Attribution = MsMonAttributionUnknown;
    event.header.Value0 = source.Target;
    event.header.Value1 = source.RuleId;
    event.component = L"kfilter.sys";
    event.text.assign(source.Path, wcsnlen(source.Path, KFILTER_MAX_NAME_4));

    const bool wouldDeny = (source.Flags & KFILTER_EVENT_FLAG_WOULD_DENY_4) != 0;
    std::wstring detail = L"target=" + std::wstring(KFilterTargetName(source.Target)) +
                          L";action=" + KFilterActionName(source.Action) +
                          L";decision=" + (wouldDeny ? L"would_deny" : KFilterActionName(source.Action)) +
                          L";target_id=" + std::to_wstring(source.Target) +
                          L";action_id=" + std::to_wstring(source.Action) +
                          L";flags=" + HexValue(source.Flags) +
                          L";rights=" + HexValue(source.Value) +
                          L";rule_id=" + std::to_wstring(source.RuleId) +
                          L";generation=" + std::to_wstring(source.Generation);
    event.detail = std::move(detail);
    return event;
}

std::wstring KFilterStatusDetail(const KFILTER_STATUS_4& status, const KFILTER_STATUS_4* start)
{
    const wchar_t* mode = status.Mode == 0 ? L"off" : status.Mode == 1 ? L"audit" :
                          status.Mode == 2 ? L"block" : L"unknown";
    const uint64_t droppedDelta = start != nullptr && status.DroppedEvents >= start->DroppedEvents ?
        status.DroppedEvents - start->DroppedEvents : 0;
    std::wstring detail = L"abi=" + std::to_wstring(status.AbiVersion) +
                          L";mode=" + mode +
                          L";mode_id=" + std::to_wstring(status.Mode) +
                          L";flags=" + HexValue(status.Flags) +
                          L";rules=" + std::to_wstring(status.RuleCount) +
                          L";protected=" + std::to_wstring(status.ProtectedCount) +
                          L";tracked=" + std::to_wstring(status.TrackedProcesses) +
                          L";policy_generation=" + std::to_wstring(status.PolicyGeneration) +
                          L";session_tag=" + std::to_wstring(status.SessionTag) +
                          L";allowed=" + std::to_wstring(status.Allowed) +
                          L";denied=" + std::to_wstring(status.Denied) +
                          L";audited=" + std::to_wstring(status.Audited) +
                          L";would_deny=" + std::to_wstring(status.WouldDeny) +
                          L";dropped_events=" + std::to_wstring(status.DroppedEvents) +
                          L";dropped_delta=" + std::to_wstring(droppedDelta) +
                          L";registered=" + HexValue(status.Registered) +
                          L";degraded=" + HexValue(status.Degraded);
    return detail;
}

std::wstring IntegrationCoverageState(bool etwEnabled, const std::wstring& kfilterState)
{
    return std::wstring(etwEnabled ? L"etw=wmi,dns,rpc,tcp,codeintegrity" : L"etw=disabled") +
           L";kfilter=" + kfilterState +
           L";wdac=" + (etwEnabled ? L"etw" : L"disabled");
}

bool KFilterDecisionInSession(const KFILTER_EVENT_4& event, uint64_t sessionStart)
{
    return event.Timestamp >= sessionStart;
}

KFilterReader::KFilterReader(uint64_t sessionId, uint64_t sessionStart)
    : sessionId_(sessionId), sessionStart_(sessionStart) {}

KFilterReader::~KFilterReader()
{
    Close();
}

void KFilterReader::Close()
{
    if (handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
}

bool KFilterReader::Status(KFILTER_STATUS_4& status, std::wstring& error)
{
    DWORD bytes = 0;
    status = {};
    if (handle_ == INVALID_HANDLE_VALUE ||
        !DeviceIoControl(handle_, KFILTER_IOCTL_GET_STATUS_4, nullptr, 0,
                         &status, sizeof(status), &bytes, nullptr)) {
        error = L"Win32 " + std::to_wstring(GetLastError());
        return false;
    }
    if (bytes != sizeof(status)) {
        error = L"short status response";
        return false;
    }
    return true;
}

bool KFilterReader::Open(KFILTER_STATUS_4& status, std::wstring& state, std::wstring& detail)
{
    handle_ = CreateFileW(L"\\\\.\\KFilter", GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle_ == INVALID_HANDLE_VALUE) {
        state = L"kfilter_unavailable";
        detail = L"Win32 " + std::to_wstring(GetLastError());
        return false;
    }
    std::wstring error;
    if (!Status(status, error)) {
        state = L"kfilter_unavailable";
        detail = std::move(error);
        Close();
        return false;
    }
    if (status.AbiVersion != KFILTER_ABI_VERSION_4) {
        state = L"kfilter_unsupported";
        detail = L"abi=" + std::to_wstring(status.AbiVersion) + L";required=4";
        Close();
        return false;
    }
    state = L"kfilter_available";
    detail = KFilterStatusDetail(status, nullptr);
    return true;
}

void KFilterReader::ConvertBatch(const KFILTER_EVENT_4* batch, unsigned count,
                                 std::vector<TelemetryEvent>& events)
{
    for (unsigned index = 0; index < count; index++) {
        /* Stale decisions from an earlier run are neither written nor numbered. */
        if (!KFilterDecisionInSession(batch[index], sessionStart_)) continue;
        events.push_back(KFilterDecisionEvent(batch[index], sessionId_, ++sequence_));
    }
}

bool KFilterReader::Drain(std::vector<TelemetryEvent>& events, std::wstring& error)
{
    KFILTER_EVENT_4 buffer[128];
    unsigned total = 0;
    for (;;) {
        KFILTER_READ_REQUEST_4 request{};
        request.MaximumEvents = static_cast<unsigned long>(std::size(buffer));
        DWORD bytes = 0;
        if (!DeviceIoControl(handle_, KFILTER_IOCTL_READ_EVENTS_4, &request, sizeof(request),
                             buffer, sizeof(buffer), &bytes, nullptr)) {
            error = L"Win32 " + std::to_wstring(GetLastError());
            return false;
        }
        if (bytes % sizeof(KFILTER_EVENT_4) != 0) {
            error = L"invalid event response size";
            return false;
        }
        const unsigned count = bytes / sizeof(KFILTER_EVENT_4);
        ConvertBatch(buffer, count, events);
        total += count;
        if (count < std::size(buffer) || total >= 2048) return true;
    }
}
