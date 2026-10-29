#include "classify.h"
#include <algorithm>
#include <cwctype>
#include <sstream>

static std::wstring Normalize(std::wstring value)
{
    std::replace(value.begin(), value.end(), L'/', L'\\');
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return value;
}

static bool StartsWith(const std::wstring& value, const std::wstring& prefix)
{
    if (prefix.empty() || value.size() < prefix.size() ||
        value.compare(0, prefix.size(), prefix) != 0) return false;
    return value.size() == prefix.size() || prefix.back() == L'\\' ||
           value[prefix.size()] == L'\\';
}

static bool ContainsAny(const std::wstring& value, const std::vector<std::wstring>& terms)
{
    for (const auto& term : terms) {
        if (value.find(term) != std::wstring::npos) return true;
    }
    return false;
}

OutsideClassifier::OutsideClassifier(std::wstring clientDos, std::wstring clientNt,
                                     std::wstring windowsDos, std::wstring windowsNt)
    : clientDos_(Normalize(clientDos)), clientNt_(Normalize(clientNt)),
      windowsDos_(Normalize(windowsDos)), windowsNt_(Normalize(windowsNt)) {}

void OutsideClassifier::Classify(TelemetryEvent& event) const
{
    std::wstring text = Normalize(event.text);
    std::wstring detail = Normalize(event.detail);
    std::wstring combined = text + L"\n" + detail;
    ULONG type = event.header.Type;

    if (type == MsMonProcessHandle || type == MsMonThreadHandle) {
        bool browser = ContainsAny(text, {L"chrome.exe", L"msedge.exe", L"firefox.exe",
                                         L"iexplore.exe", L"brave.exe", L"opera.exe"});
        event.header.Category = browser ? MsMonCategoryBrowserInteraction : MsMonCategoryExternalProcess;
    } else if (type == MsMonProcessStart || type == MsMonProcessExit) {
        event.header.Category = MsMonCategoryExternalProcess;
    } else if (type == MsMonEtwWmi) {
        event.header.Category = ContainsAny(combined, {
            L"win32_bios", L"win32_baseboard", L"win32_computersystem", L"win32_processor",
            L"win32_diskdrive", L"win32_physicalmedia", L"win32_networkadapter",
            L"win32_systemenclosure", L"uuid", L"serialnumber", L"macaddress", L"smbios"
        }) ? MsMonCategoryHardwareIdentity : MsMonCategoryWindowsRuntime;
    } else if (type == MsMonEtwDns || type == MsMonEtwTcp) {
        event.header.Category = MsMonCategoryNetwork;
    } else if (type == MsMonEtwRpc) {
        event.header.Category = MsMonCategoryIpc;
    } else if (type >= MsMonNetworkConnect && type <= MsMonNetworkFlowClose) {
        event.header.Category = MsMonCategoryNetwork;
    } else if (type == MsMonFileQueryVolumeInformation) {
        event.header.Category = event.header.Value0 == 1 ?
            MsMonCategoryHardwareIdentity : MsMonCategoryUnknown;
    } else if (type >= MsMonRegistryOpen && type <= MsMonRegistryEnumerate) {
        bool hardware = ContainsAny(combined, {
            L"machineguid", L"hardware\\description", L"hardware config", L"computername",
            L"system\\currentcontrolset\\control\\systeminformation", L"hardwareid",
            L"serialnumber", L"smbios", L"uuid", L"macaddress", L"networkadapter",
            L"diskdrive", L"physicalmedia", L"baseboard", L"bios"
        });
        event.header.Category = hardware ? MsMonCategoryHardwareIdentity : MsMonCategoryRegistry;
    } else if (type == MsMonFileDeviceControl || type == MsMonFileSystemControl) {
        event.header.Category = ContainsAny(text, {
            L"harddisk", L"physicaldrive", L"scsi", L"nvme", L"volume{", L"mounteddevice"
        }) ? MsMonCategoryHardwareIdentity : event.header.Category;
    }

    if (event.header.Category == MsMonCategoryUnknown || event.header.Category == MsMonCategoryIpc) {
        if (StartsWith(text, clientDos_) || StartsWith(text, clientNt_)) {
            event.header.Category = MsMonCategoryClientData;
        } else if (StartsWith(text, windowsDos_) || StartsWith(text, windowsNt_)) {
            event.header.Category = MsMonCategoryWindowsRuntime;
        } else if (ContainsAny(text, {L"\\users\\", L"\\documents and settings\\"})) {
            event.header.Category = MsMonCategoryUserData;
        }
    }
    event.outsideClient = event.header.Category != MsMonCategoryClientData;
}

void SessionSummary::Add(const TelemetryEvent& event)
{
    events_++;
    if (event.source == "driver" && event.header.Type == MsMonProcessStart) trackedStarts_++;
    /* The driver reports the loaded image's real name: BlackCat1.sys, BlackCat64.sys, ... */
    if (event.component.size() >= 8 && _wcsnicmp(event.component.c_str(), L"blackcat", 8) == 0) blackCatEvents_++;
    if (event.outsideClient) outsideEvents_++;
    if (event.header.Category == MsMonCategoryHardwareIdentity) hardwareEvents_++;
    if ((event.header.Flags & MsMonFlagPayloadUnavailable) != 0) payloadUnavailable_++;
    if ((event.header.Flags & MsMonFlagPayloadPresent) != 0) {
        payloadBytes_ += event.header.PayloadBytes;
        auto& operation = payloadOperations_[event.header.OperationId];
        if (operation.chunkCount == 0) operation.chunkCount = event.header.PayloadChunkCount;
        if (operation.chunkCount != event.header.PayloadChunkCount) operation.invalid = true;
        if (!operation.chunks.emplace(event.header.PayloadChunkIndex, true).second) {
            operation.invalid = true;
            payloadDuplicateChunks_++;
        }
    }
    categories_[CategoryName(event.header.Category)]++;
    processes_[event.header.ProcessId]++;
    if (event.header.TargetProcessId != 0) targets_[event.header.TargetProcessId]++;
    for (const auto& module : event.modules) modules_[module]++;
}

std::string SessionSummary::Json(const MSMON_STATISTICS& statistics, uint64_t etwDropped,
                                 uint64_t driverGaps, uint64_t etwGaps) const
{
    uint64_t completePayloads = 0;
    for (const auto& item : payloadOperations_) {
        const auto& operation = item.second;
        if (!operation.invalid && operation.chunkCount != 0 &&
            operation.chunks.size() == operation.chunkCount &&
            operation.chunks.begin()->first == 0 &&
            operation.chunks.rbegin()->first == operation.chunkCount - 1) completePayloads++;
    }
    std::ostringstream json;
    json << "{\"type\":\"observer_summary\",\"session_id\":" << statistics.SessionId
         << ",\"events\":" << events_ << ",\"outside_client_events\":" << outsideEvents_
         << ",\"hardware_identity_events\":" << hardwareEvents_
         << ",\"blackcat_events\":" << blackCatEvents_
         << ",\"payload_bytes\":" << payloadBytes_
         << ",\"payload_operations\":" << payloadOperations_.size()
         << ",\"complete_payload_operations\":" << completePayloads
         << ",\"incomplete_payload_operations\":" << (payloadOperations_.size() - completePayloads)
         << ",\"payload_unavailable_events\":" << payloadUnavailable_
         << ",\"payload_duplicate_chunks\":" << payloadDuplicateChunks_
         << ",\"driver_dropped_events\":" << statistics.DroppedEvents
         << ",\"driver_queued_events\":" << statistics.QueuedEvents
         << ",\"driver_queued_bytes\":" << statistics.QueuedBytes
         << ",\"etw_dropped_events\":" << etwDropped
         << ",\"driver_sequence_gaps\":" << driverGaps
         << ",\"etw_sequence_gaps\":" << etwGaps
         << ",\"tracked_at_start\":" << initiallyTracked_
         << ",\"tracked_process_starts\":" << trackedStarts_
         << ",\"tracked_processes_at_end\":" << statistics.TrackedProcesses << ",\"by_category\":{";
    bool first = true;
    for (const auto& item : categories_) {
        if (!first) json << ',';
        first = false;
        json << '\"' << JsonEscape(item.first) << "\":" << item.second;
    }
    json << "},\"by_process\":{";
    first = true;
    for (const auto& item : processes_) {
        if (!first) json << ',';
        first = false;
        json << '\"' << item.first << "\":" << item.second;
    }
    json << "},\"by_target_process\":{";
    first = true;
    for (const auto& item : targets_) {
        if (!first) json << ',';
        first = false;
        json << '\"' << item.first << "\":" << item.second;
    }
    json << "},\"by_module\":{";
    first = true;
    for (const auto& item : modules_) {
        if (!first) json << ',';
        first = false;
        json << '\"' << JsonEscape(WideToUtf8(item.first)) << "\":" << item.second;
    }
    json << "}}";
    return json.str();
}
