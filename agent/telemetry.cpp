#include "telemetry.h"
#include <bcrypt.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <set>
#include <sstream>

void ProcessScope::AddProcess(DWORD pid, uint64_t startTime, const std::wstring& path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto& process = processes_[pid];
    if (process.startTime != startTime) process.modules.clear();
    process.startTime = startTime;
    if (!path.empty()) process.path = path;
}

void ProcessScope::RemoveProcess(DWORD pid, uint64_t startTime)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = processes_.find(pid);
    if (found != processes_.end() &&
        (startTime == 0 || found->second.startTime == 0 || found->second.startTime == startTime)) {
        processes_.erase(found);
    }
}

void ProcessScope::AddImage(DWORD pid, uint64_t base, uint64_t size, const std::wstring& path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = processes_.find(pid);
    if (found == processes_.end() || base == 0 || size == 0) return;
    auto& modules = found->second.modules;
    auto duplicate = std::find_if(modules.begin(), modules.end(), [&](const ModuleRange& module) {
        return module.base == base;
    });
    if (duplicate != modules.end()) modules.erase(duplicate);
    modules.push_back({base, size, path});
    std::sort(modules.begin(), modules.end(), [](const ModuleRange& left, const ModuleRange& right) {
        return left.base < right.base;
    });
}

bool ProcessScope::IsTracked(DWORD pid) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return processes_.find(pid) != processes_.end();
}

uint64_t ProcessScope::StartTime(DWORD pid) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = processes_.find(pid);
    return found == processes_.end() ? 0 : found->second.startTime;
}

std::vector<std::wstring> ProcessScope::ResolveStack(DWORD pid, const uint64_t* addresses, size_t count) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::wstring> result;
    auto found = processes_.find(pid);
    if (found == processes_.end() || addresses == nullptr) return result;
    std::set<std::wstring> seen;
    for (size_t index = 0; index < count; index++) {
        uint64_t address = addresses[index];
        for (const auto& module : found->second.modules) {
            if (address >= module.base && address - module.base < module.size) {
                if (seen.insert(module.path).second) result.push_back(module.path);
                break;
            }
        }
        if (result.size() == 8) break;
    }
    return result;
}

bool EventQueue::Push(TelemetryEvent&& event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (events_.size() >= capacity_) {
        dropped_.fetch_add(1);
        return false;
    }
    events_.push_back(std::move(event));
    return true;
}

size_t EventQueue::Drain(std::vector<TelemetryEvent>& output, size_t maximum)
{
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    while (count < maximum && !events_.empty()) {
        output.push_back(std::move(events_.front()));
        events_.pop_front();
        count++;
    }
    return count;
}

static std::string WideToUtf8(const wchar_t* value, size_t length)
{
    if (value == nullptr || length == 0) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, value, static_cast<int>(length),
                                   nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, static_cast<int>(length),
                        result.data(), size, nullptr, nullptr);
    return result;
}

std::string WideToUtf8(const std::wstring& value)
{
    return WideToUtf8(value.data(), value.size());
}

std::string JsonEscape(const std::string& value)
{
    std::ostringstream output;
    for (unsigned char c : value) {
        switch (c) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (c < 0x20) {
                output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                       << static_cast<unsigned>(c) << std::dec << std::setfill(' ');
            } else {
                output << static_cast<char>(c);
            }
        }
    }
    return output.str();
}

std::string EventTypeName(unsigned long type)
{
    switch (type) {
    case MsMonProcessStart: return "process_start";
    case MsMonProcessExit: return "process_exit";
    case MsMonThreadStart: return "thread_start";
    case MsMonThreadExit: return "thread_exit";
    case MsMonImageLoad: return "image_load";
    case MsMonProcessHandle: return "process_handle";
    case MsMonThreadHandle: return "thread_handle";
    case MsMonFileCreate: return "file_create";
    case MsMonFileRead: return "file_read";
    case MsMonFileWrite: return "file_write";
    case MsMonFileSetInformation: return "file_set_information";
    case MsMonFileDirectoryControl: return "file_directory_control";
    case MsMonFileCleanup: return "file_cleanup";
    case MsMonFileDeviceControl: return "file_device_control";
    case MsMonFileSystemControl: return "file_system_control";
    case MsMonFileQueryVolumeInformation: return "file_query_volume_information";
    case MsMonFileQueryInformation: return "file_query_information";
    case MsMonRegistryOpen: return "registry_open";
    case MsMonRegistryCreate: return "registry_create";
    case MsMonRegistrySetValue: return "registry_set_value";
    case MsMonRegistryDelete: return "registry_delete";
    case MsMonRegistryRename: return "registry_rename";
    case MsMonRegistryQuery: return "registry_query";
    case MsMonRegistryEnumerate: return "registry_enumerate";
    case MsMonNetworkConnect: return "network_connect";
    case MsMonNetworkAccept: return "network_accept";
    case MsMonNetworkFlowEstablished: return "network_flow_established";
    case MsMonNetworkFlowClose: return "network_flow_close";
    case MsMonEtwWmi: return "etw_wmi";
    case MsMonEtwDns: return "etw_dns";
    case MsMonEtwRpc: return "etw_rpc";
    case MsMonCoverage: return "coverage";
    default: return "unknown";
    }
}

std::string CategoryName(unsigned long category)
{
    switch (category) {
    case MsMonCategoryClientData: return "client_data";
    case MsMonCategoryWindowsRuntime: return "windows_runtime";
    case MsMonCategoryExternalProcess: return "external_process";
    case MsMonCategoryBrowserInteraction: return "browser_interaction";
    case MsMonCategoryHardwareIdentity: return "hardware_identity";
    case MsMonCategoryUserData: return "user_data";
    case MsMonCategoryRegistry: return "registry";
    case MsMonCategoryNetwork: return "network";
    case MsMonCategoryIpc: return "ipc";
    default: return "unknown";
    }
}

std::string AttributionName(unsigned long attribution)
{
    switch (attribution) {
    case MsMonAttributionProcessOnly: return "process_only";
    case MsMonAttributionStackResolved: return "stack_resolved";
    case MsMonAttributionServiceCorrelated: return "service_correlated";
    case MsMonAttributionStaticEvidence: return "static_evidence";
    default: return "unknown";
    }
}

std::string Timestamp(uint64_t value)
{
    FILETIME fileTime{};
    SYSTEMTIME systemTime{};
    fileTime.dwLowDateTime = static_cast<DWORD>(value & 0xffffffff);
    fileTime.dwHighDateTime = static_cast<DWORD>(value >> 32);
    if (!FileTimeToSystemTime(&fileTime, &systemTime)) return {};
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
             systemTime.wYear, systemTime.wMonth, systemTime.wDay,
             systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds);
    return buffer;
}

std::string Sha256(const std::string& input)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD resultSize = 0;
    std::vector<unsigned char> object;
    unsigned char digest[32];
    std::ostringstream hex;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
                          sizeof(objectSize), &resultSize, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }
    object.resize(objectSize);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) != 0 ||
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                       static_cast<ULONG>(input.size()), 0) != 0 ||
        BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0) {
        if (hash != nullptr) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    hex << std::hex << std::setfill('0');
    for (unsigned char byte : digest) hex << std::setw(2) << static_cast<unsigned>(byte);
    return hex.str();
}

JsonlWriter::JsonlWriter(std::filesystem::path basePath, uint64_t maximumBytes)
    : basePath_(std::move(basePath)), maximumBytes_(maximumBytes), chain_(64, '0') {}

bool JsonlWriter::Open()
{
    stream_.open(basePath_, std::ios::binary | std::ios::trunc);
    bytes_ = 0;
    return static_cast<bool>(stream_);
}

bool JsonlWriter::Write(const std::string& json)
{
    if (json.empty() || json.back() != '}') return false;
    if (maximumBytes_ != 0 && bytes_ != 0 && bytes_ >= maximumBytes_) {
        stream_.close();
        std::filesystem::path rotated = basePath_;
        rotated += L"." + std::to_wstring(++part_);
        stream_.open(rotated, std::ios::binary | std::ios::trunc);
        if (!stream_) return false;
        bytes_ = 0;
    }
    std::string indexed = json.substr(0, json.size() - 1) +
                          ",\"record_index\":" + std::to_string(++recordIndex_) + "}";
    chain_ = Sha256(chain_ + indexed);
    if (chain_.empty()) return false;
    std::string line = indexed.substr(0, indexed.size() - 1) + ",\"chain\":\"" + chain_ + "\"}\n";
    stream_.write(line.data(), static_cast<std::streamsize>(line.size()));
    stream_.flush();
    bytes_ += line.size();
    return static_cast<bool>(stream_);
}

std::string TelemetryJson(const TelemetryEvent& event)
{
    const auto& header = event.header;
    std::ostringstream json;
    json << "{\"protocol\":" << header.Version
         << ",\"source\":\"" << JsonEscape(event.source)
         << "\",\"sequence\":" << header.Sequence
         << ",\"timestamp\":\"" << Timestamp(header.Timestamp)
         << "\",\"session_id\":" << header.SessionId
         << ",\"type\":\"" << EventTypeName(header.Type)
         << "\",\"type_id\":" << header.Type
         << ",\"process_id\":" << header.ProcessId
         << ",\"process_start_time\":" << header.ProcessStartTime
         << ",\"parent_process_id\":" << header.ParentProcessId
         << ",\"thread_id\":" << header.ThreadId
         << ",\"target_process_id\":" << header.TargetProcessId
         << ",\"target_process_start_time\":" << header.TargetProcessStartTime
         << ",\"flags\":" << header.Flags
         << ",\"status\":" << static_cast<int32_t>(header.Status)
         << ",\"desired_access\":" << header.DesiredAccess
         << ",\"category\":\"" << CategoryName(header.Category)
         << "\",\"outside_client\":" << (event.outsideClient ? "true" : "false")
         << ",\"attribution\":\"" << AttributionName(header.Attribution)
         << "\",\"value0\":" << header.Value0
         << ",\"value1\":" << header.Value1
         << ",\"text\":\"" << JsonEscape(WideToUtf8(event.text))
         << "\",\"detail\":\"" << JsonEscape(WideToUtf8(event.detail))
         << "\",\"modules\":[";
    for (size_t index = 0; index < event.modules.size(); index++) {
        if (index != 0) json << ',';
        json << '\"' << JsonEscape(WideToUtf8(event.modules[index])) << '\"';
    }
    json << "]}";
    return json.str();
}

bool DecodeDriverEvent(const BYTE* data, DWORD available, TelemetryEvent& event,
                       DWORD& consumed, std::string& error)
{
    consumed = 0;
    if (data == nullptr || available < sizeof(MSMON_EVENT_HEADER)) {
        error = "partial event header";
        return false;
    }
    std::memcpy(&event.header, data, sizeof(event.header));
    const auto& header = event.header;
    if (header.Version != MSMON_PROTOCOL_VERSION) {
        error = "protocol version mismatch";
        return false;
    }
    if (header.Size < sizeof(header) || header.Size > MSMON_MAX_EVENT_RECORD_BYTES || header.Size > available) {
        error = "invalid or partial event record size";
        return false;
    }
    auto validString = [&](unsigned short offset, unsigned short bytes) {
        if (offset == 0 && bytes == 0) return true;
        return offset >= sizeof(header) && (bytes % sizeof(wchar_t)) == 0 &&
               offset <= header.Size && bytes <= header.Size - offset;
    };
    if (!validString(header.TextOffset, header.TextBytes) ||
        !validString(header.DetailOffset, header.DetailBytes)) {
        error = "invalid event string bounds";
        return false;
    }
    if (header.TextBytes != 0) {
        const wchar_t* text = reinterpret_cast<const wchar_t*>(data + header.TextOffset);
        event.text.assign(text, text + header.TextBytes / sizeof(wchar_t));
    }
    if (header.DetailBytes != 0) {
        const wchar_t* detail = reinterpret_cast<const wchar_t*>(data + header.DetailOffset);
        event.detail.assign(detail, detail + header.DetailBytes / sizeof(wchar_t));
    }
    event.source = "driver";
    consumed = header.Size;
    return true;
}
