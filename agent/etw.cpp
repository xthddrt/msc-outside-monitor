#include "etw.h"
#include <tdh.h>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <sstream>

#ifndef TRACE_LEVEL_VERBOSE
#define TRACE_LEVEL_VERBOSE 5
#endif

static const GUID WMI_ACTIVITY = { 0x1418ef04, 0xb0b4, 0x4623, { 0xbf, 0x7e, 0xd7, 0x4a, 0xb4, 0x7b, 0xbd, 0xaa } };
static const GUID DNS_CLIENT = { 0x1c95126e, 0x7eea, 0x49a9, { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d } };
static const GUID RPC_EVENTS = { 0x6ad52b32, 0xd609, 0x4be9, { 0xae, 0x07, 0xce, 0x8d, 0xae, 0x93, 0x7e, 0x39 } };

static const ULONG ETW_PENDING_LIMIT = 4096;
static const ULONG ETW_PENDING_MILLISECONDS = 5000;

/*
 * Deferring every untracked PID would turn the log into a system-wide WMI/DNS/
 * RPC feed: on a normal machine thousands of unrelated events would expire into
 * `etw_unattributed` records.  The race this queue actually fixes is narrow --
 * an ETW event from a client process that started moments before the driver's
 * process-start record reaches the agent.  Only defer events from processes
 * whose creation time is inside that same window.
 */
static bool ProcessStartedWithin(DWORD pid, uint64_t nowFileTime, uint64_t window)
{
    HANDLE process;
    FILETIME creation{}, exitTime{}, kernelTime{}, userTime{};
    ULARGE_INTEGER created;
    bool ok;

    if (pid == 0 || pid == 4) return false;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL) return false;
    ok = GetProcessTimes(process, &creation, &exitTime, &kernelTime, &userTime) != 0;
    CloseHandle(process);
    if (!ok) return false;
    created.LowPart = creation.dwLowDateTime;
    created.HighPart = creation.dwHighDateTime;
    return created.QuadPart != 0 && nowFileTime >= created.QuadPart &&
           nowFileTime - created.QuadPart <= window;
}

static const EVENT_PROPERTY_INFO* FindProperty(const TRACE_EVENT_INFO* info, const std::wstring& name)
{
    for (ULONG index = 0; index < info->TopLevelPropertyCount; index++) {
        const auto& property = info->EventPropertyInfoArray[index];
        const wchar_t* propertyName = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const BYTE*>(info) + property.NameOffset);
        if (name == propertyName) return &property;
    }
    return nullptr;
}

static bool PropertyData(PEVENT_RECORD record, const TRACE_EVENT_INFO* info,
                         const std::wstring& name, std::vector<BYTE>& data)
{
    if (FindProperty(info, name) == nullptr) return false;
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(const_cast<wchar_t*>(name.c_str()));
    descriptor.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size == 0) {
        return false;
    }
    data.resize(size);
    return TdhGetProperty(record, 0, nullptr, 1, &descriptor, size, data.data()) == ERROR_SUCCESS;
}

static bool PropertyString(PEVENT_RECORD record, const TRACE_EVENT_INFO* info,
                           const std::wstring& name, std::wstring& output)
{
    const auto* property = FindProperty(info, name);
    std::vector<BYTE> data;
    if (property == nullptr || (property->Flags & PropertyStruct) != 0 ||
        !PropertyData(record, info, name, data)) return false;
    USHORT type = property->nonStructType.InType;
    if (type == TDH_INTYPE_UNICODESTRING) {
        size_t characters = data.size() / sizeof(wchar_t);
        const wchar_t* value = reinterpret_cast<const wchar_t*>(data.data());
        while (characters != 0 && value[characters - 1] == L'\0') characters--;
        output.assign(value, value + characters);
        return true;
    }
    if (type == TDH_INTYPE_ANSISTRING) {
        size_t length = data.size();
        while (length != 0 && data[length - 1] == 0) length--;
        if (length == 0) {
            output.clear();
            return true;
        }
        int wide = MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(data.data()),
                                       static_cast<int>(length), nullptr, 0);
        if (wide <= 0) return false;
        output.resize(static_cast<size_t>(wide));
        MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(data.data()),
                            static_cast<int>(length), output.data(), wide);
        return true;
    }
    return false;
}

static bool PropertyNumber(PEVENT_RECORD record, const TRACE_EVENT_INFO* info,
                           const std::wstring& name, uint64_t& output)
{
    std::vector<BYTE> data;
    if (!PropertyData(record, info, name, data)) return false;
    output = 0;
    size_t size = data.size();
    if (size != 1 && size != 2 && size != 4 && size != 8) return false;
    std::memcpy(&output, data.data(), size);
    return true;
}

static std::wstring SanitizeQuery(const std::wstring& query)
{
    std::wstring output;
    output.reserve(query.size());
    wchar_t quote = 0;
    bool redacted = false;
    bool number = false;
    auto identifier = [](wchar_t c) {
        return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || c == L'_';
    };
    for (size_t index = 0; index < query.size(); index++) {
        wchar_t c = query[index];
        if (quote != 0) {
            if (c == quote) {
                output.push_back(c);
                quote = 0;
            } else if (!redacted) {
                output.push_back(L'?');
                redacted = true;
            }
            continue;
        }
        if (c == L'\'' || c == L'\"') {
            output.push_back(c);
            quote = c;
            redacted = false;
            number = false;
        } else if (c >= L'0' && c <= L'9') {
            bool partOfIdentifier = (index != 0 && identifier(query[index - 1])) ||
                                    (index + 1 < query.size() && identifier(query[index + 1]));
            if (partOfIdentifier) {
                output.push_back(c);
            } else if (!number) {
                output.push_back(L'#');
            }
            number = !partOfIdentifier;
        } else {
            output.push_back(c);
            number = false;
        }
    }
    if (output.size() > 1800) output.resize(1800);
    return output;
}

static void AppendField(std::wstring& target, const std::wstring& name, const std::wstring& value)
{
    if (value.empty()) return;
    if (!target.empty()) target += L";";
    target += name + L"=" + value;
}

EtwCollector::EtwCollector(ProcessScope& scope, EventQueue& queue, uint64_t sessionId, bool capturePayloads)
    : scope_(scope), queue_(queue), sessionId_(sessionId), capturePayloads_(capturePayloads) {}

EtwCollector::~EtwCollector()
{
    Stop();
}

ULONG WINAPI EtwCollector::BufferCallback(PEVENT_TRACE_LOGFILEW logfile)
{
    if (logfile != nullptr && logfile->Context != nullptr) {
        auto* self = static_cast<EtwCollector*>(logfile->Context);
        uint64_t lost = logfile->LogfileHeader.EventsLost;
        uint64_t current = self->lostEvents_.load();
        while (lost > current &&
               !self->lostEvents_.compare_exchange_weak(current, lost)) {
        }
    }
    return TRUE;
}

void EtwCollector::EnableProvider(const GUID& provider, const std::wstring& name)
{
    ENABLE_TRACE_PARAMETERS parameters{};
    parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    parameters.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;

    /*
     * Verbose with no keyword mask asks the provider for all events it can
     * produce.  Some useful providers emit events at verbose level or with a
     * zero keyword mask; the previous Information/all-bits request silently
     * excluded those.  The agent-side PID filter still limits what is written.
     */
    ULONG status = EnableTraceEx2(session_, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                  TRACE_LEVEL_VERBOSE, 0, 0, 0, &parameters);
    if (status != ERROR_SUCCESS) {
        parameters.EnableProperty = 0;
        status = EnableTraceEx2(session_, &provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_VERBOSE, 0, 0, 0, &parameters);
    }
    if (status != ERROR_SUCCESS) {
        warnings_.push_back(L"ETW provider unavailable: " + name + L" (Win32 " + std::to_wstring(status) + L")");
    }
}

bool EtwCollector::Start(std::string& error)
{
    loggerName_ = L"MsMon-Outside-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                  std::to_wstring(GetTickCount64());
    properties_.resize(sizeof(EVENT_TRACE_PROPERTIES) + (loggerName_.size() + 1) * sizeof(wchar_t));
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(properties_.size());
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 2;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ULONG status = StartTraceW(&session_, loggerName_.c_str(), properties);
    if (status != ERROR_SUCCESS) {
        error = "StartTrace failed with Win32 " + std::to_string(status);
        return false;
    }
    started_ = true;
    EnableProvider(WMI_ACTIVITY, L"Microsoft-Windows-WMI-Activity");
    EnableProvider(DNS_CLIENT, L"Microsoft-Windows-DNS-Client");
    EnableProvider(RPC_EVENTS, L"Microsoft-Windows-RPC");

    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = loggerName_.data();
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = [](PEVENT_RECORD record) {
        static_cast<EtwCollector*>(record->UserContext)->OnRecord(record);
    };
    log.BufferCallback = EtwCollector::BufferCallback;
    log.Context = this;
    trace_ = OpenTraceW(&log);
    if (trace_ == INVALID_PROCESSTRACE_HANDLE) {
        error = "OpenTrace failed with Win32 " + std::to_string(GetLastError());
        Stop();
        return false;
    }
    worker_ = std::thread([this] {
        (void)ProcessTrace(&trace_, 1, nullptr, nullptr);
    });
    return true;
}

void EtwCollector::Stop()
{
    if (started_) {
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
        (void)ControlTraceW(session_, loggerName_.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
        started_ = false;
    }
    if (worker_.joinable()) worker_.join();
    if (trace_ != 0 && trace_ != INVALID_PROCESSTRACE_HANDLE) {
        (void)CloseTrace(trace_);
        trace_ = 0;
    }
    session_ = 0;
}

void EtwCollector::Emit(TelemetryEvent&& event)
{
    if (!event.stackAddresses.empty() && event.stackPid != 0) {
        event.modules = scope_.ResolveStack(event.stackPid, event.stackAddresses.data(),
                                            event.stackAddresses.size());
        if (!event.modules.empty()) event.header.Attribution = MsMonAttributionStackResolved;
    }
    /*
     * OnRecord runs on the ETW worker, while ReplayProcess/ExpirePending run
     * on the collector thread.  Assigning the sequence and pushing must be
     * one ordered operation, otherwise the writer can observe sequence 2
     * before sequence 1 and abort.
     */
    std::lock_guard<std::mutex> lock(emitMutex_);
    event.header.Sequence = sequence_.fetch_add(1) + 1;
    queue_.Push(std::move(event));
}

void EtwCollector::OnRecord(PEVENT_RECORD record)
{
    ULONG type;
    if (IsEqualGUID(record->EventHeader.ProviderId, WMI_ACTIVITY)) {
        type = MsMonEtwWmi;
    } else if (IsEqualGUID(record->EventHeader.ProviderId, DNS_CLIENT)) {
        type = MsMonEtwDns;
    } else if (IsEqualGUID(record->EventHeader.ProviderId, RPC_EVENTS)) {
        type = MsMonEtwRpc;
    } else {
        return;
    }

    ULONG infoSize = 0;
    (void)TdhGetEventInformation(record, 0, nullptr, nullptr, &infoSize);
    if (infoSize == 0) {
        parseFailures_.fetch_add(1);
        return;
    }
    std::vector<BYTE> infoBuffer(infoSize);
    auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(infoBuffer.data());
    if (TdhGetEventInformation(record, 0, nullptr, info, &infoSize) != ERROR_SUCCESS) {
        parseFailures_.fetch_add(1);
        return;
    }

    DWORD nativePid = record->EventHeader.ProcessId;
    DWORD attributedPid = nativePid;
    uint64_t number = 0;
    if (type != MsMonEtwDns && PropertyNumber(record, info, L"ClientProcessId", number) && number <= MAXDWORD) {
        attributedPid = static_cast<DWORD>(number);
    }

    TelemetryEvent event;
    event.source = "etw";
    event.header.Size = sizeof(event.header);
    event.header.Version = MSMON_PROTOCOL_VERSION;
    event.header.Type = type;
    event.header.Flags = MsMonFlagObserverRecord;
    event.header.Timestamp = static_cast<uint64_t>(record->EventHeader.TimeStamp.QuadPart);
    event.header.SessionId = sessionId_;
    event.header.ProcessId = attributedPid;
    event.header.ProcessStartTime = 0;
    event.header.ThreadId = record->EventHeader.ThreadId;
    event.header.Attribution = MsMonAttributionProcessOnly;
    event.header.Value0 = record->EventHeader.EventDescriptor.Id;
    if (nativePid != attributedPid) {
        event.header.Flags |= MsMonFlagServiceCorrelated;
        event.header.Attribution = MsMonAttributionServiceCorrelated;
    }

    std::wstring value;
    if (type == MsMonEtwWmi) {
        PropertyString(record, info, L"NamespaceName", event.text);
        if (event.text.empty()) PropertyString(record, info, L"ProviderName", event.text);
        if (PropertyString(record, info, L"Operation", value)) AppendField(event.detail, L"operation", value);
        if (PropertyString(record, info, L"Query", value)) {
            AppendField(event.detail, L"query", capturePayloads_ ? value : SanitizeQuery(value));
        }
        if (PropertyString(record, info, L"QueryLanguage", value)) AppendField(event.detail, L"language", value);
        if (PropertyNumber(record, info, L"OperationId", number)) event.header.Value1 = number;
        if (PropertyNumber(record, info, L"StatusCode", number)) event.header.Status = static_cast<LONG>(number);
    } else if (type == MsMonEtwDns) {
        PropertyString(record, info, L"QueryName", event.text);
        if (PropertyNumber(record, info, L"QueryType", number)) {
            AppendField(event.detail, L"query_type", std::to_wstring(number));
        }
        if (PropertyNumber(record, info, L"QueryOptions", number)) {
            AppendField(event.detail, L"query_options", std::to_wstring(number));
        }
    } else {
        PropertyString(record, info, L"Endpoint", event.text);
        if (event.text.empty()) PropertyString(record, info, L"Protocol", event.text);
        if (PropertyNumber(record, info, L"OperationNum", number)) {
            AppendField(event.detail, L"operation", std::to_wstring(number));
        }
        if (PropertyString(record, info, L"InterfaceUuid", value)) AppendField(event.detail, L"interface", value);
    }

    /*
     * Retain raw stack addresses rather than resolving immediately.  If the
     * event is deferred until its process-start record arrives, image-load
     * records may also arrive in that window and make the stack resolvable.
     */
    for (USHORT index = 0; index < record->ExtendedDataCount; index++) {
        const auto& extended = record->ExtendedData[index];
        if (extended.DataSize < sizeof(uint64_t)) continue;
        if (extended.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
            const auto* stack = reinterpret_cast<const EVENT_EXTENDED_ITEM_STACK_TRACE64*>(extended.DataPtr);
            size_t count = (extended.DataSize - sizeof(uint64_t)) / sizeof(uint64_t);
            if (count > 256) count = 256;
            event.stackPid = nativePid;
            event.stackAddresses.assign(stack->Address, stack->Address + count);
        } else if (extended.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32) {
            const auto* stack = reinterpret_cast<const EVENT_EXTENDED_ITEM_STACK_TRACE32*>(extended.DataPtr);
            size_t count = (extended.DataSize - sizeof(uint64_t)) / sizeof(uint32_t);
            if (count > 256) count = 256;
            event.stackPid = nativePid;
            event.stackAddresses.reserve(count);
            for (size_t frame = 0; frame < count; frame++) {
                event.stackAddresses.push_back(stack->Address[frame]);
            }
        }
    }

    if (!scope_.IsTracked(attributedPid)) {
        FILETIME nowFileTime;
        ULARGE_INTEGER now;
        GetSystemTimeAsFileTime(&nowFileTime);
        now.LowPart = nowFileTime.dwLowDateTime;
        now.HighPart = nowFileTime.dwHighDateTime;
        if (!ProcessStartedWithin(attributedPid, now.QuadPart,
                                  static_cast<uint64_t>(ETW_PENDING_MILLISECONDS) * 10000ULL)) {
            /* Long-running, unrelated process: out of scope, as before. */
            return;
        }
        const uint64_t deadline = GetTickCount64() + ETW_PENDING_MILLISECONDS;
        std::lock_guard<std::mutex> lock(pendingMutex_);
        if (pending_.size() >= ETW_PENDING_LIMIT) {
            pending_.pop_front();
            pendingOverflow_.fetch_add(1);
        }
        pending_.push_back({ std::move(event), deadline });
        return;
    }

    event.header.ProcessStartTime = scope_.StartTime(attributedPid);
    Emit(std::move(event));
}

void EtwCollector::ReplayProcess(DWORD pid)
{
    std::vector<TelemetryEvent> ready;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (it->event.header.ProcessId == pid) {
                ready.push_back(std::move(it->event));
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& event : ready) {
        if (event.header.ProcessStartTime == 0) {
            event.header.ProcessStartTime = scope_.StartTime(pid);
        }
        Emit(std::move(event));
    }
}

void EtwCollector::ExpirePending(uint64_t nowTick)
{
    std::vector<TelemetryEvent> expired;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (it->deadline <= nowTick) {
                expired.push_back(std::move(it->event));
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& original : expired) {
        TelemetryEvent event;
        event.source = "etw";
        event.header.Size = sizeof(event.header);
        event.header.Version = MSMON_PROTOCOL_VERSION;
        event.header.Type = MsMonEtwUnattributed;
        event.header.Flags = MsMonFlagObserverRecord;
        event.header.Timestamp = original.header.Timestamp;
        event.header.SessionId = sessionId_;
        event.header.ProcessId = original.header.ProcessId;
        event.header.ThreadId = original.header.ThreadId;
        event.header.Value0 = original.header.Type;
        event.header.Value1 = original.header.Value0;
        event.header.Attribution = MsMonAttributionUnknown;
        event.text = ProviderName(original.header.Type);
        event.detail = L"reason=no_process_start;event_id=" + std::to_wstring(original.header.Value0) +
                       L";original_pid=" + std::to_wstring(original.header.ProcessId);
        event.outsideClient = true;
        Emit(std::move(event));
        unattributed_.fetch_add(1);
    }
}

uint64_t EtwCollector::PendingCount() const
{
    std::lock_guard<std::mutex> lock(pendingMutex_);
    return static_cast<uint64_t>(pending_.size());
}

std::wstring EtwCollector::ProviderName(unsigned long type) const
{
    switch (type) {
    case MsMonEtwWmi: return L"Microsoft-Windows-WMI-Activity";
    case MsMonEtwDns: return L"Microsoft-Windows-DNS-Client";
    case MsMonEtwRpc: return L"Microsoft-Windows-RPC";
    default: return L"unknown";
    }
}
