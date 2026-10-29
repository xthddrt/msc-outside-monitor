#include "telemetry.h"
#include "classify.h"
#include "etw.h"
#include "../include/msmon_coverage.h"
#include <tlhelp32.h>
#include <bcrypt.h>
#include <winver.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <wchar.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>

#pragma comment(lib, "version.lib")

static std::atomic<bool> gStop(false);

static BOOL WINAPI ConsoleHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        gStop.store(true);
        return TRUE;
    }
    return FALSE;
}

static uint64_t FileTimeValue(const FILETIME& value)
{
    return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

static uint64_t Now()
{
    FILETIME value;
    GetSystemTimeAsFileTime(&value);
    return FileTimeValue(value);
}

static std::wstring UtcStamp(uint64_t fileTime)
{
    FILETIME value{static_cast<DWORD>(fileTime & 0xffffffff), static_cast<DWORD>(fileTime >> 32)};
    SYSTEMTIME time{};
    if (!FileTimeToSystemTime(&value, &time)) return L"unknown";
    wchar_t buffer[40];
    swprintf_s(buffer, L"%04u%02u%02uT%02u%02u%02uZ", time.wYear, time.wMonth, time.wDay,
               time.wHour, time.wMinute, time.wSecond);
    return buffer;
}

static std::wstring SanitizeLabel(const std::wstring& input, const wchar_t* fallback)
{
    std::wstring output;
    for (wchar_t c : input) {
        bool allowed = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                       (c >= L'0' && c <= L'9') || c == L'-' || c == L'_' || c == L'.';
        if (allowed) {
            output.push_back(c);
        } else if (output.empty() || output.back() != L'-') {
            output.push_back(L'-');
        }
    }
    while (!output.empty() && (output.back() == L'-' || output.back() == L'.')) output.pop_back();
    if (output.size() > 64) output.resize(64);
    return output.empty() ? std::wstring(fallback) : output;
}

static bool AllowedLabel(const std::wstring& value, std::initializer_list<const wchar_t*> values)
{
    for (const wchar_t* item : values) {
        if (value == item) return true;
    }
    return false;
}

static std::wstring Utf8ToWide(const std::string& value)
{
    if (value.empty()) return {};
    int length = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) return {};
    std::wstring output(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), output.data(), length);
    return output;
}

static std::wstring MachineLabel()
{
    wchar_t name[256];
    DWORD size = static_cast<DWORD>(std::size(name));
    if (GetComputerNameW(name, &size) == 0) return L"unknown";
    return SanitizeLabel(name, L"unknown");
}

static std::string MachineIdHash()
{
    std::string material;
    wchar_t guid[128];
    DWORD bytes = sizeof(guid);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                     RRF_RT_REG_SZ, nullptr, guid, &bytes) == ERROR_SUCCESS) {
        material += WideToUtf8(guid);
    }
    DWORD serial = 0;
    wchar_t volume[256];
    wchar_t filesystem[32];
    if (GetVolumeInformationW(L"C:\\", volume, static_cast<DWORD>(std::size(volume)), &serial,
                              nullptr, nullptr, filesystem, static_cast<DWORD>(std::size(filesystem)))) {
        material += ":" + std::to_string(serial);
    }
    return material.empty() ? std::string() : "sha256:" + Sha256(material);
}

static std::string ClientVersion(const std::wstring& path)
{
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (size == 0) return {};
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) return {};
    VS_FIXEDFILEINFO* info = nullptr;
    UINT length = 0;
    if (!VerQueryValueW(data.data(), L"\\", reinterpret_cast<LPVOID*>(&info), &length) ||
        info == nullptr || length < sizeof(*info)) return {};
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
             HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS),
             HIWORD(info->dwFileVersionLS), LOWORD(info->dwFileVersionLS));
    return buffer;
}

static std::wstring ExecutablePath()
{
    std::vector<wchar_t> path(32768);
    DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (size == 0 || size >= path.size()) return {};
    return std::wstring(path.data(), size);
}

static std::wstring DriverFilePath()
{
    wchar_t system[32768];
    UINT size = GetSystemDirectoryW(system, static_cast<UINT>(std::size(system)));
    if (size == 0 || size >= std::size(system)) return {};
    return std::wstring(system, size) + L"\\drivers\\msmon.sys";
}

static bool ReadTextFile(const std::filesystem::path& path, std::string& output)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    std::ostringstream buffer;
    buffer << file.rdbuf();
    output = buffer.str();
    return true;
}

static std::string JsonField(const std::string& text, const std::string& key)
{
    const std::string needle = "\"" + key + "\"";
    size_t position = text.find(needle);
    if (position == std::string::npos) return {};
    position = text.find(':', position + needle.size());
    if (position == std::string::npos) return {};
    position = text.find('"', position + 1);
    if (position == std::string::npos) return {};
    size_t end = position + 1;
    while (end < text.size() && text[end] != '"') {
        if (text[end] == '\\') end++;
        end++;
    }
    if (end >= text.size()) return {};
    return text.substr(position + 1, end - position - 1);
}

static bool ReadBuildInfo(std::string& text, std::string& hash)
{
    std::wstring executable = ExecutablePath();
    std::error_code error;
    std::vector<std::filesystem::path> candidates;
    if (!executable.empty()) {
        std::filesystem::path directory = std::filesystem::path(executable).parent_path();
        candidates.push_back(directory / L".." / L".." / L"build-info.json");
        candidates.push_back(directory / L"build-info.json");
    }
    candidates.push_back(std::filesystem::current_path(error) / L"build" / L"build-info.json");
    candidates.push_back(std::filesystem::current_path(error) / L"build-info.json");
    for (const auto& candidate : candidates) {
        if (ReadTextFile(candidate, text)) {
            hash = Sha256(text);
            return true;
        }
    }
    return false;
}

static void WriteTextFile(const std::filesystem::path& path, const std::string& content)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (file) file << content;
}

static bool GenerateUuid(std::wstring& uuid, std::wstring& shortId, uint64_t& numericId)
{
    BYTE bytes[16]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return false;
    bytes[6] = static_cast<BYTE>((bytes[6] & 0x0F) | 0x40);
    bytes[8] = static_cast<BYTE>((bytes[8] & 0x3F) | 0x80);
    wchar_t buffer[40];
    swprintf_s(buffer, L"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
               bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    uuid = buffer;
    shortId = uuid.substr(0, 8);
    numericId = 0;
    for (int index = 0; index < 8; index++) numericId = (numericId << 8) | bytes[index];
    if (numericId == 0) numericId = 1;
    return true;
}

struct SessionLabels {
    std::wstring uuid;
    std::wstring uuidShort;
    uint64_t id = 0;
    std::wstring label;
    std::wstring testId;
    std::wstring scenario;
    std::wstring phase;
    std::wstring machine;
    std::string machineHash;
    uint64_t iteration = 1;
    std::wstring started;
};

struct SessionBinaryInfo {
    std::string agentHash;
    std::string driverHash;
    std::string buildInfoHash;
    std::string buildCommit;
    std::string clientVersion;
    std::string clientHash;
    bool buildInfoPresent = false;
    std::string buildInfoRaw;
};

static std::string BuildCoverageJson(
    const MSMON_COVERAGE& coverage, const MSMON_COVERAGE* start, bool supported, const EtwCollector* etw,
    uint64_t queueDrops, unsigned parts, uint64_t bytes, const std::wstring& sessionUuid,
    const std::unordered_map<unsigned long, uint64_t>& eventCounts)
{
    auto delta = [&](unsigned __int64 end, unsigned __int64 begin) { return end - begin; };
    std::ostringstream json;
    json << "{\"schema_version\":1,\"session_uuid\":\"" << WideToUtf8(sessionUuid) << "\""
         << ",\"driver_supported\":" << (supported ? "true" : "false")
         << ",\"driver\":{\"version\":" << coverage.Version
         << ",\"registration_ok\":" << coverage.RegistrationOk
         << ",\"registration_failed\":" << coverage.RegistrationFailed
         << ",\"event_attempted\":[";
    for (unsigned index = 0; index < MSMON_EVENT_SLOTS; index++) {
        if (index != 0) json << ',';
        json << delta(coverage.EventAttempted[index], start ? start->EventAttempted[index] : 0);
    }
    json << "],\"event_dropped\":[";
    for (unsigned index = 0; index < MSMON_EVENT_SLOTS; index++) {
        if (index != 0) json << ',';
        json << delta(coverage.EventDropped[index], start ? start->EventDropped[index] : 0);
    }
    json << "],\"sensor_entered\":[";
    for (unsigned index = 0; index < MSMON_SENSOR_SLOTS; index++) {
        if (index != 0) json << ',';
        json << delta(coverage.SensorEntered[index], start ? start->SensorEntered[index] : 0);
    }
    json << "],\"sensor_logged\":[";
    for (unsigned index = 0; index < MSMON_SENSOR_SLOTS; index++) {
        if (index != 0) json << ',';
        json << delta(coverage.SensorLogged[index], start ? start->SensorLogged[index] : 0);
    }
    json << "],\"registration_status\":[";
    for (unsigned index = 0; index < MSMON_SENSOR_SLOTS; index++) {
        if (index != 0) json << ',';
        json << coverage.RegistrationStatus[index];
    }
    json << "],\"skip_untracked\":" << delta(coverage.SkipUntracked, start ? start->SkipUntracked : 0)
         << ",\"skip_irql\":" << delta(coverage.SkipIrql, start ? start->SkipIrql : 0)
         << ",\"skip_no_name\":" << delta(coverage.SkipNoName, start ? start->SkipNoName : 0)
         << ",\"alloc_failures\":" << delta(coverage.AllocFailures, start ? start->AllocFailures : 0)
         << ",\"track_failures\":" << delta(coverage.TrackFailures, start ? start->TrackFailures : 0)
         << ",\"queue_drops\":" << delta(coverage.QueueDrops, start ? start->QueueDrops : 0)
         << ",\"blackcat_matches\":" << delta(coverage.BlackCatMatches, start ? start->BlackCatMatches : 0)
         << ",\"payload_captured\":[";
    for (size_t index = 0; index < std::size(coverage.PayloadCaptured); index++) {
        if (index != 0) json << ',';
        json << delta(coverage.PayloadCaptured[index], start ? start->PayloadCaptured[index] : 0);
    }
    json << "]}"
         << ",\"agent\":{\"writer_parts\":" << parts
         << ",\"writer_bytes\":" << bytes
         << ",\"etw_queue_drops\":" << queueDrops;
    if (etw != nullptr) {
        static const char* providers[3] = {"wmi", "dns", "rpc"};
        json << ",\"etw_lost\":" << etw->LostEvents()
             << ",\"etw_parse_failures\":" << etw->ParseFailures()
             << ",\"etw_unattributed\":" << etw->UnattributedCount()
             << ",\"etw_pending_overflow\":" << etw->PendingOverflow()
             << ",\"etw_providers\":[";
        for (int index = 0; index < 3; index++) {
            if (index != 0) json << ',';
            json << "{\"name\":\"" << providers[index] << "\""
                 << ",\"received\":" << etw->Received(index)
                 << ",\"parsed\":" << etw->Parsed(index)
                 << ",\"emitted\":" << etw->Emitted(index)
                 << ",\"deferred\":" << etw->Deferred(index)
                 << ",\"expired\":" << etw->Expired(index) << "}";
        }
        json << "]";
    } else {
        json << ",\"etw_lost\":0,\"etw_parse_failures\":0,\"etw_unattributed\":0"
             << ",\"etw_pending_overflow\":0,\"etw_providers\":[]";
    }
    json << ",\"event_counts\":{";
    bool firstCount = true;
    for (const auto& item : eventCounts) {
        if (!firstCount) json << ',';
        firstCount = false;
        json << "\"" << item.first << "\":" << item.second;
    }
    json << "}}}";
    return json.str();
}

static std::string BuildSessionMeta(
    const SessionLabels& labels, const SessionBinaryInfo& binaries,
    const std::wstring& clientRoot, const std::wstring& scopeRoot,
    bool payload, bool etw, uint64_t queueRecords, uint64_t queueBytes,
    const std::wstring& outcome, const std::wstring& ended,
    uint64_t events, uint64_t dropped, uint64_t driverGaps, uint64_t etwGaps,
    uint64_t records, uint64_t bytes, unsigned parts)
{
    std::ostringstream json;
    json << "{\"schema_version\":1"
         << ",\"session_uuid\":\"" << WideToUtf8(labels.uuid) << "\""
         << ",\"session_id\":" << labels.id
         << ",\"session_label\":\"" << JsonEscape(WideToUtf8(labels.label)) << "\""
         << ",\"test_id\":\"" << JsonEscape(WideToUtf8(labels.testId)) << "\""
         << ",\"scenario\":\"" << WideToUtf8(labels.scenario) << "\""
         << ",\"phase\":\"" << WideToUtf8(labels.phase) << "\""
         << ",\"iteration\":" << labels.iteration
         << ",\"machine_label\":\"" << WideToUtf8(labels.machine) << "\""
         << ",\"machine_id_hash\":\"" << labels.machineHash << "\""
         << ",\"started_utc\":\"" << WideToUtf8(labels.started) << "\""
         << ",\"ended_utc\":\"" << WideToUtf8(ended) << "\""
         << ",\"outcome\":\"" << WideToUtf8(outcome) << "\""
         << ",\"client_root\":\"" << JsonEscape(WideToUtf8(clientRoot)) << "\""
         << ",\"scope_root\":\"" << JsonEscape(WideToUtf8(scopeRoot)) << "\""
         << ",\"client_version\":\"" << binaries.clientVersion << "\""
         << ",\"client_sha256\":\"" << binaries.clientHash << "\""
         << ",\"agent_sha256\":\"" << binaries.agentHash << "\""
         << ",\"driver_sha256\":\"" << binaries.driverHash << "\""
         << ",\"build_info_present\":" << (binaries.buildInfoPresent ? "true" : "false")
         << ",\"build_info_sha256\":\"" << binaries.buildInfoHash << "\""
         << ",\"build_commit\":\"" << JsonEscape(binaries.buildCommit) << "\""
         << ",\"config\":{\"payload_mode\":\"" << (payload ? "full" : "metadata") << "\""
         << ",\"etw\":" << (etw ? "true" : "false")
         << ",\"queue_records\":" << queueRecords
         << ",\"queue_bytes\":" << queueBytes << "}"
         << ",\"events\":" << events
         << ",\"driver_dropped_events\":" << dropped
         << ",\"driver_sequence_gaps\":" << driverGaps
         << ",\"etw_sequence_gaps\":" << etwGaps
         << ",\"record_count\":" << records
         << ",\"raw_bytes\":" << bytes
         << ",\"part_count\":" << parts;
    if (binaries.buildInfoPresent) {
        json << ",\"build_info_raw\":\"" << JsonEscape(binaries.buildInfoRaw) << "\"";
    }
    json << "}";
    return json.str();
}

static std::wstring FullPath(const std::wstring& input)
{
    DWORD needed = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
    if (needed == 0) return {};
    std::wstring output(needed, L'\0');
    if (GetFullPathNameW(input.c_str(), needed, output.data(), nullptr) == 0) return {};
    output.resize(std::wcslen(output.c_str()));
    while (output.size() > 3 && output.back() == L'\\') output.pop_back();
    return output;
}

static bool DevicePath(const std::wstring& dosPath, std::wstring& devicePath, std::string& error)
{
    if (dosPath.size() < 3 || dosPath[1] != L':') {
        error = "Only local drive-letter client paths are supported";
        return false;
    }
    wchar_t drive[3] = {dosPath[0], L':', L'\0'};
    wchar_t device[32768];
    DWORD length = QueryDosDeviceW(drive, device, static_cast<DWORD>(std::size(device)));
    if (length == 0) {
        error = "QueryDosDevice failed with Win32 " + std::to_string(GetLastError());
        return false;
    }
    devicePath = device + dosPath.substr(2);
    return true;
}

static bool ProcessIdentity(DWORD pid, std::wstring& path, uint64_t& startTime)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return false;
    DWORD size = 32768;
    path.resize(size);
    BOOL ok = QueryFullProcessImageNameW(process, 0, path.data(), &size);
    FILETIME created{}, exited{}, kernel{}, user{};
    if (ok) {
        path.resize(size);
        ok = GetProcessTimes(process, &created, &exited, &kernel, &user);
        if (ok) startTime = FileTimeValue(created);
    }
    CloseHandle(process);
    return ok != 0;
}

class DeviceSession {
public:
    ~DeviceSession()
    {
        if (started_) {
            DWORD bytes = 0;
            (void)DeviceIoControl(handle_, MSMON_IOCTL_STOP_SESSION, nullptr, 0, nullptr, 0, &bytes, nullptr);
        }
        if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    }

    bool Open()
    {
        handle_ = CreateFileA(MSMON_USER_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return handle_ != INVALID_HANDLE_VALUE;
    }

    bool Start(MSMON_SESSION_CONFIG& config)
    {
        DWORD bytes = 0;
        started_ = DeviceIoControl(handle_, MSMON_IOCTL_START_SESSION, &config, sizeof(config),
                                   nullptr, 0, &bytes, nullptr) != 0;
        return started_;
    }

    bool Track(DWORD pid, uint64_t startTime, ULONG flags)
    {
        MSMON_TRACK_REQUEST request{pid, flags, startTime};
        DWORD bytes = 0;
        return DeviceIoControl(handle_, MSMON_IOCTL_TRACK_PID, &request, sizeof(request),
                               nullptr, 0, &bytes, nullptr) != 0;
    }

    bool Read(DWORD waitMs, std::vector<BYTE>& buffer, DWORD& bytes)
    {
        MSMON_READ_REQUEST request{waitMs, static_cast<ULONG>(buffer.size())};
        bytes = 0;
        return DeviceIoControl(handle_, MSMON_IOCTL_READ_EVENTS, &request, sizeof(request),
                               buffer.data(), static_cast<DWORD>(buffer.size()), &bytes, nullptr) != 0;
    }

    bool RefreshModules()
    {
        DWORD bytes = 0;
        return DeviceIoControl(handle_, MSMON_IOCTL_REFRESH_MODULES, nullptr, 0,
                               nullptr, 0, &bytes, nullptr) != 0;
    }

    bool StopTracking()
    {
        DWORD bytes = 0;
        return DeviceIoControl(handle_, MSMON_IOCTL_STOP_TRACKING, nullptr, 0,
                               nullptr, 0, &bytes, nullptr) != 0;
    }

    bool Statistics(MSMON_STATISTICS& statistics)
    {
        DWORD bytes = 0;
        return DeviceIoControl(handle_, MSMON_IOCTL_STATISTICS, nullptr, 0,
                               &statistics, sizeof(statistics), &bytes, nullptr) != 0;
    }

    bool Coverage(MSMON_COVERAGE& coverage)
    {
        DWORD bytes = 0;
        std::memset(&coverage, 0, sizeof(coverage));
        return DeviceIoControl(handle_, MSMON_IOCTL_COVERAGE, nullptr, 0,
                               &coverage, sizeof(coverage), &bytes, nullptr) != 0 &&
               bytes >= sizeof(coverage);
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    bool started_ = false;
};

static bool IsUnderRoot(const std::wstring& root, const std::wstring& path)
{
    if (path.size() <= root.size()) return false;
    if (_wcsnicmp(path.c_str(), root.c_str(), root.size()) != 0) return false;
    return path[root.size()] == L'\\';
}

static unsigned TrackExisting(DeviceSession& device, const std::wstring& scopeRoot,
                              ProcessScope& scope)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    std::vector<PROCESSENTRY32W> processes;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            processes.push_back(entry);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    std::set<DWORD> tracked;
    unsigned count = 0;
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& process : processes) {
            if (tracked.count(process.th32ProcessID) != 0) continue;
            if (process.th32ProcessID == GetCurrentProcessId()) continue;
            bool inherited = tracked.count(process.th32ParentProcessID) != 0;
            std::wstring path;
            uint64_t startTime = 0;
            if (!ProcessIdentity(process.th32ProcessID, path, startTime)) continue;
            if (!inherited && !IsUnderRoot(scopeRoot, path)) continue;
            ULONG flags = inherited ? MsMonFlagInheritedTrack : MsMonFlagExplicitTrack;
            if (device.Track(process.th32ProcessID, startTime, flags)) {
                tracked.insert(process.th32ProcessID);
                scope.AddProcess(process.th32ProcessID, startTime, path);
                count++;
                changed = true;
            }
        }
    }
    return count;
}

static std::wstring DefaultOutputPath()
{
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t path[128];
    swprintf_s(path, L"msmon-%04u%02u%02u-%02u%02u%02u.jsonl",
               time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
    return path;
}

static void Usage()
{
    std::cout << "Usage: msmon-agent [--client DIRECTORY] [--scope-root DIRECTORY] [--output FILE] [--pid PID] "
                 "[--log-dir DIR] [--session-label LABEL] [--test-id ID] [--scenario NAME] [--phase NAME] "
                 "[--iteration N] [--machine-label NAME] [--outcome-override NAME] [--compact] "
                 "[--wait-ms N] [--max-file-mb N] [--queue-records N] [--queue-mb N] "
                 "[--stop-file FILE] [--no-etw] [--no-payloads] [--once]\n";
}

static bool ParseNumber(const wchar_t* text, uint64_t& value)
{
    wchar_t* end = nullptr;
    value = std::wcstoull(text, &end, 10);
    return end != text && end != nullptr && *end == L'\0';
}

int wmain(int argc, wchar_t** argv)
{
    std::wstring clientRoot = L"C:\\Nexon\\Library\\maplestorycw";
    std::wstring scopeRootArg;
    std::wstring output = DefaultOutputPath();
    std::wstring logDir;
    std::wstring sessionLabel;
    std::wstring testId;
    std::wstring scenario = L"mixed";
    std::wstring phase = L"steady";
    std::wstring machineLabelArg;
    std::wstring outcomeOverride;
    uint64_t iteration = 1;
    bool compact = false;
    bool outputSet = false;
    uint64_t waitMs = 100;
    uint64_t maxFileBytes = 64ull * 1024ull * 1024ull;
    uint64_t queueRecords = MSMON_DEFAULT_QUEUE_RECORDS;
    uint64_t queueBytes = MSMON_DEFAULT_QUEUE_BYTES;
    bool once = false;
    bool enableEtw = true;
    bool capturePayloads = true;
    std::filesystem::path stopFile;
    bool stopFileEnabled = false;
    std::vector<DWORD> explicitPids;

    for (int index = 1; index < argc; index++) {
        std::wstring argument = argv[index];
        uint64_t value = 0;
        if (argument == L"--help" || argument == L"-h") {
            Usage();
            return 0;
        } else if (argument == L"--once") {
            once = true;
        } else if (argument == L"--no-etw") {
            enableEtw = false;
        } else if (argument == L"--no-payloads") {
            capturePayloads = false;
        } else if (index + 1 < argc && argument == L"--client") {
            clientRoot = argv[++index];
        } else if (index + 1 < argc && argument == L"--scope-root") {
            scopeRootArg = argv[++index];
        } else if (index + 1 < argc && argument == L"--output") {
            output = argv[++index];
            outputSet = true;
        } else if (index + 1 < argc && (argument == L"--log-dir" || argument == L"--session-dir")) {
            logDir = argv[++index];
        } else if (index + 1 < argc && argument == L"--session-label") {
            sessionLabel = argv[++index];
        } else if (index + 1 < argc && argument == L"--test-id") {
            testId = argv[++index];
        } else if (index + 1 < argc && argument == L"--scenario") {
            scenario = argv[++index];
        } else if (index + 1 < argc && argument == L"--phase") {
            phase = argv[++index];
        } else if (index + 1 < argc && argument == L"--machine-label") {
            machineLabelArg = argv[++index];
        } else if (index + 1 < argc && argument == L"--outcome-override") {
            outcomeOverride = argv[++index];
        } else if (index + 1 < argc && argument == L"--iteration" && ParseNumber(argv[index + 1], value)) {
            iteration = value;
            index++;
        } else if (argument == L"--compact") {
            compact = true;
        } else if (index + 1 < argc && argument == L"--stop-file") {
            stopFile = argv[++index];
            stopFileEnabled = true;
        } else if (index + 1 < argc && argument == L"--wait-ms" && ParseNumber(argv[index + 1], value)) {
            waitMs = value;
            index++;
        } else if (index + 1 < argc && argument == L"--max-file-mb" && ParseNumber(argv[index + 1], value)) {
            maxFileBytes = value * 1024ull * 1024ull;
            index++;
        } else if (index + 1 < argc && argument == L"--queue-records" && ParseNumber(argv[index + 1], value)) {
            queueRecords = value;
            index++;
        } else if (index + 1 < argc && argument == L"--queue-mb" && ParseNumber(argv[index + 1], value)) {
            queueBytes = value * 1024ull * 1024ull;
            index++;
        } else if (index + 1 < argc && argument == L"--pid" && ParseNumber(argv[index + 1], value) && value <= MAXDWORD) {
            explicitPids.push_back(static_cast<DWORD>(value));
            index++;
        } else {
            Usage();
            return 2;
        }
    }

    if (!AllowedLabel(scenario, {L"startup", L"login", L"gameplay", L"cash_shop", L"file_io",
                                 L"registry", L"wmi", L"dns", L"rpc", L"network", L"ipc",
                                 L"idle", L"shutdown", L"mixed", L"other"})) {
        std::cerr << "Invalid --scenario value.\n";
        return 2;
    }
    if (!AllowedLabel(phase, {L"startup", L"steady", L"shutdown"})) {
        std::cerr << "Invalid --phase value.\n";
        return 2;
    }
    if (!outcomeOverride.empty() &&
        !AllowedLabel(outcomeOverride, {L"completed", L"agent_stopped", L"agent_killed",
                                        L"driver_stopped", L"crash", L"timeout", L"unknown"})) {
        std::cerr << "Invalid --outcome-override value.\n";
        return 2;
    }
    if (iteration == 0) iteration = 1;
    SetDecodedFields(!compact);
    std::wstring sessionUuid;
    std::wstring uuidShort;
    uint64_t sessionId = 0;
    if (!GenerateUuid(sessionUuid, uuidShort, sessionId)) {
        std::cerr << "Could not generate a session UUID.\n";
        return 1;
    }
    if (sessionLabel.empty()) sessionLabel = scenario;
    sessionLabel = SanitizeLabel(sessionLabel, L"session");
    machineLabelArg = machineLabelArg.empty() ? MachineLabel() : SanitizeLabel(machineLabelArg, L"unknown");

    clientRoot = FullPath(clientRoot);
    if (clientRoot.empty()) {
        std::cerr << "Could not resolve the client root.\n";
        return 1;
    }

    /*
     * The folder the user names and the folder containing the executable are
     * not always the same.  The installation root is ...\maplestorycw, while
     * the game and its helpers live in ...\maplestorycw\appdata.  Keep the
     * classification root at the named folder, but auto-detect appdata for
     * the process scope.  An explicit --scope-root always wins.
     */
    std::wstring scopeRoot = scopeRootArg.empty() ? clientRoot : FullPath(scopeRootArg);
    if (scopeRoot.empty()) {
        std::cerr << "Could not resolve the scope root.\n";
        return 1;
    }
    std::error_code fsError;
    if (scopeRootArg.empty() &&
        !std::filesystem::exists(std::filesystem::path(scopeRoot) / L"MapleStory.exe", fsError) &&
        std::filesystem::exists(std::filesystem::path(scopeRoot) / L"appdata" / L"MapleStory.exe", fsError)) {
        scopeRoot = (std::filesystem::path(scopeRoot) / L"appdata").wstring();
    }
    if (!std::filesystem::exists(std::filesystem::path(scopeRoot) / L"MapleStory.exe", fsError) &&
        explicitPids.empty()) {
        std::cerr << "No MapleStory.exe was found under scope root:\n  " << WideToUtf8(scopeRoot)
                  << "\nUse --scope-root to point at the folder containing the executable, or --pid for an already running process.\n";
        return 1;
    }

    std::wstring scopeNt;
    std::wstring clientNt;
    std::string error;
    if (!DevicePath(scopeRoot, scopeNt, error)) {
        std::cerr << "Scope root: " << error << "\n";
        return 1;
    }
    if (!DevicePath(clientRoot, clientNt, error)) {
        std::cerr << "Client root: " << error << "\n";
        return 1;
    }
    wchar_t windowsBuffer[32768];
    if (GetWindowsDirectoryW(windowsBuffer, static_cast<UINT>(std::size(windowsBuffer))) == 0) {
        std::cerr << "Could not resolve the Windows directory.\n";
        return 1;
    }
    std::wstring windowsDos = windowsBuffer;
    std::wstring windowsNt;
    if (!DevicePath(windowsDos, windowsNt, error)) {
        std::cerr << error << "\n";
        return 1;
    }

    std::wstring startedUtc = UtcStamp(Now());
    std::wstring resolvedTestId = testId.empty() ? std::wstring() : SanitizeLabel(testId, L"session");
    wchar_t iterationText[8];
    swprintf_s(iterationText, L"%02llu", static_cast<unsigned long long>(iteration));
    std::filesystem::path sessionDir;
    if (!logDir.empty()) {
        if (outputSet) {
            std::cerr << "Use either --output or --log-dir, not both.\n";
            return 2;
        }
        std::wstring base = FullPath(logDir);
        if (base.empty()) {
            std::cerr << "Could not resolve --log-dir.\n";
            return 1;
        }
        if (resolvedTestId.empty()) {
            resolvedTestId = startedUtc + L"__" + machineLabelArg + L"__" + scenario +
                             L"__iter" + iterationText + L"__" + uuidShort;
        }
        sessionDir = std::filesystem::path(base) / resolvedTestId;
        std::error_code createError;
        std::filesystem::create_directories(sessionDir, createError);
        if (createError) {
            std::cerr << "Could not create the session directory: " << createError.message() << "\n";
            return 1;
        }
        output = (sessionDir / L"events.jsonl").wstring();
    } else if (resolvedTestId.empty()) {
        resolvedTestId = startedUtc + L"__" + machineLabelArg + L"__" + scenario +
                         L"__iter" + iterationText + L"__" + uuidShort;
    }

    SessionLabels labels;
    labels.uuid = sessionUuid;
    labels.uuidShort = uuidShort;
    labels.id = sessionId;
    labels.label = sessionLabel;
    labels.testId = resolvedTestId;
    labels.scenario = scenario;
    labels.phase = phase;
    labels.machine = machineLabelArg;
    labels.machineHash = MachineIdHash();
    labels.iteration = iteration;
    labels.started = startedUtc;

    SessionBinaryInfo binaries;
    std::string buildText;
    std::string buildHash;
    binaries.buildInfoPresent = ReadBuildInfo(buildText, buildHash);
    binaries.buildInfoRaw = buildText;
    binaries.buildInfoHash = buildHash;
    binaries.buildCommit = JsonField(buildText, "commit");
    if (binaries.buildCommit.empty()) binaries.buildCommit = "unknown";
    binaries.agentHash = Sha256File(ExecutablePath());
    binaries.driverHash = Sha256File(DriverFilePath());
    std::filesystem::path clientExe = std::filesystem::path(scopeRoot) / L"MapleStory.exe";
    std::error_code clientError;
    if (std::filesystem::exists(clientExe, clientError)) {
        binaries.clientVersion = ClientVersion(clientExe.wstring());
        binaries.clientHash = Sha256File(clientExe.wstring());
    }

    if (!sessionDir.empty()) {
        WriteTextFile(sessionDir / L"session_meta.json",
                      BuildSessionMeta(labels, binaries, clientRoot, scopeRoot, capturePayloads,
                                       enableEtw, queueRecords, queueBytes, L"in_progress", L"",
                                       0, 0, 0, 0, 0, 0, 0));
    }

    MSMON_SESSION_CONFIG config{};
    config.SessionId = sessionId;
    config.QueueRecords = static_cast<ULONG>(queueRecords);
    config.QueueBytes = static_cast<ULONG>(queueBytes);
    config.PayloadMode = capturePayloads ? 1u : 0u;
    if (scopeNt.size() >= MSMON_CLIENT_PATH_CHARS) {
        std::cerr << "The scope NT path is too long for the session configuration.\n";
        return 1;
    }
    wcscpy_s(config.ClientRoot, MSMON_CLIENT_PATH_CHARS, scopeNt.c_str());

    DeviceSession device;
    if (!device.Open()) {
        std::cerr << "Cannot open " MSMON_USER_DEVICE_PATH ": Win32 error " << GetLastError()
                  << ". Use a properly signed driver in an isolated test VM.\n";
        return 1;
    }
    if (!device.Start(config)) {
        std::cerr << "Could not start the driver session: Win32 error " << GetLastError() << "\n";
        return 1;
    }
    if (!device.RefreshModules()) {
        std::cerr << "Could not refresh kernel module attribution: Win32 error " << GetLastError() << "\n";
        return 1;
    }
    MSMON_COVERAGE startCoverage{};
    bool startCoverageSupported = device.Coverage(startCoverage);

    ProcessScope scope;
    unsigned registered = TrackExisting(device, scopeRoot, scope);
    for (DWORD pid : explicitPids) {
        std::wstring path;
        uint64_t startTime = 0;
        if (ProcessIdentity(pid, path, startTime) && device.Track(pid, startTime, MsMonFlagExplicitTrack)) {
            scope.AddProcess(pid, startTime, path);
            registered++;
        } else {
            std::cerr << "Could not track explicit PID " << pid << ".\n";
        }
    }
    std::cout << "Registered " << registered << " client/helper/descendant processes.\n";
    if (registered == 0) {
        std::cout << "No client process is running yet; waiting for a tracked image to start.\n";
    }

    JsonlWriter writer(output, maxFileBytes);
    if (!writer.Open()) {
        std::cerr << "Cannot open output log.\n";
        return 1;
    }
    OutsideClassifier classifier(clientRoot, clientNt, windowsDos, windowsNt);
    SessionSummary summary;
    EventQueue etwQueue;
    std::unique_ptr<EtwCollector> etw;

    auto writeCoverage = [&](const std::wstring& text, const std::wstring& detail,
                             ULONG attribution = MsMonAttributionUnknown) {
        TelemetryEvent event;
        event.source = "agent";
        event.header.Size = sizeof(event.header);
        event.header.Version = MSMON_PROTOCOL_VERSION;
        event.header.Type = MsMonCoverage;
        event.header.Flags = MsMonFlagObserverRecord;
        event.header.Timestamp = Now();
        event.header.SessionId = sessionId;
        event.header.Attribution = attribution;
        event.text = text;
        event.detail = detail;
        event.outsideClient = false;
        return writer.Write(TelemetryJson(event));
    };

    if (!writeCoverage(L"session_start", L"client_root=" + clientRoot + L";scope_root=" + scopeRoot)) return 1;
    {
        std::wstring context = L"schema_version=1;session_uuid=" + sessionUuid +
                               L";session_label=" + sessionLabel +
                               L";test_id=" + resolvedTestId +
                               L";scenario=" + scenario +
                               L";phase=" + phase +
                               L";iteration=" + std::to_wstring(iteration) +
                               L";machine_label=" + machineLabelArg +
                               L";machine_id_hash=" + Utf8ToWide(labels.machineHash) +
                               L";started_utc=" + startedUtc +
                               L";client_version=" + Utf8ToWide(binaries.clientVersion) +
                               L";client_sha256=" + Utf8ToWide(binaries.clientHash) +
                               L";agent_sha256=" + Utf8ToWide(binaries.agentHash) +
                               L";driver_sha256=" + Utf8ToWide(binaries.driverHash) +
                               L";build_commit=" + Utf8ToWide(binaries.buildCommit) +
                               L";build_info_present=" + (binaries.buildInfoPresent ? L"true" : L"false");
        if (!writeCoverage(L"session_context", context)) return 1;
    }
    {
        std::wstring manifest = L"scope_root=" + scopeRoot +
                                L";inside_root=" + clientRoot +
                                L";driver_callbacks=process,thread,image,object_process,object_thread,file,file_section,file_security,file_ea,registry,wfp" +
                                L";minifilter_npfs=true;file_section_acquire=true;registry_enum_names=true;memory=false;ui=false;hardware_direct=false" +
                                L";etw=";
        manifest += (enableEtw ? L"wmi,dns,rpc" : L"disabled");
        manifest += L";etw_level=verbose;payload_mode=";
        manifest += capturePayloads ? L"full" : L"metadata";
        manifest += L";blind_spots=per_page_mmap_io,named_pipe_payload,memory_ops,ui_clipboard_input,hardware_direct,brokered_actions,tls_plaintext";
        if (!writeCoverage(L"coverage_manifest", manifest)) return 1;
    }
    if (!writeCoverage(capturePayloads ? L"payload_capture_enabled" : L"payload_capture_disabled",
                       capturePayloads ?
                           L"Exact registry values and volume information will be logged; logs may contain hardware identifiers and registry secrets. Registry values are capped at 64 KiB; WMI result rows, direct adapter-API results, file contents, and network contents remain unavailable" :
                           L"Metadata-only mode; no registry value or volume payload capture")) return 1;
    if (!writeCoverage(L"coverage_limit",
                       L"Handle-less process/window snapshots, per-page mapped I/O, named-pipe/ALPC/COM payloads, brokered existing-browser launches, direct adapter/firmware APIs, protected processes, pre-start activity, and dropped events are not guaranteed")) return 1;
    if (!writeCoverage(L"static_hardware_boundary",
                       L"MachineIdLib.dll imports process/window enumeration, GetVolumeInformationA, and GetAdaptersInfo; static imports do not prove runtime invocation",
                       MsMonAttributionStaticEvidence)) return 1;
    {
        DWORD required = QueryDosDeviceW(nullptr, nullptr, 0);
        unsigned discovered = 0;
        if (required != 0) {
            std::vector<wchar_t> devices(required);
            DWORD length = QueryDosDeviceW(nullptr, devices.data(), required);
            if (length != 0) {
                for (const wchar_t* cursor = devices.data(); *cursor != L'\0'; cursor += std::wcslen(cursor) + 1) {
                    std::wstring name = cursor;
                    if (name.find(L"BlackCat") == std::wstring::npos &&
                        name.find(L"blackcat") == std::wstring::npos &&
                        name.find(L"NGS") == std::wstring::npos &&
                        name.find(L"ngs") == std::wstring::npos) continue;
                    wchar_t targetBuffer[32768];
                    DWORD targetLength = QueryDosDeviceW(name.c_str(), targetBuffer,
                                                         static_cast<DWORD>(std::size(targetBuffer)));
                    std::wstring target = targetLength != 0 ? targetBuffer : L"<unavailable>";
                    discovered++;
                    if (!writeCoverage(L"blackcat_device_discovered", name + L" -> " + target)) return 1;
                }
            }
        }
        if (!writeCoverage(L"blackcat_device_discovery",
                           L"matches=" + std::to_wstring(discovered))) return 1;
    }
    if (enableEtw) {
        etw = std::make_unique<EtwCollector>(scope, etwQueue, sessionId, capturePayloads);
        if (!etw->Start(error)) {
            if (!writeCoverage(L"etw_unavailable", std::wstring(error.begin(), error.end()))) return 1;
            etw.reset();
        } else {
            for (const auto& warning : etw->Warnings()) {
                if (!writeCoverage(L"etw_provider_coverage", warning)) return 1;
            }
        }
    } else if (!writeCoverage(L"etw_disabled", L"Started with --no-etw")) {
        return 1;
    }

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    std::cout << "Writing " << WideToUtf8(output) << "\n";
    std::vector<BYTE> buffer(MSMON_READ_MAX_BYTES);
    uint64_t previousDriverSequence = 0;
    uint64_t previousEtwSequence = 0;
    uint64_t driverGaps = 0;
    uint64_t etwGaps = 0;
    uint64_t totalEvents = 0;
    std::unordered_map<unsigned long, uint64_t> eventCounts;
    uint64_t nextModuleRefresh = GetTickCount64() + 1000;
    uint64_t nextStatistics = GetTickCount64() + 30000;
    bool moduleRefreshWarning = false;
    int result = 0;

    auto writeGap = [&](const std::string& source, uint64_t after, uint64_t before) {
        std::ostringstream json;
        json << "{\"type\":\"observer_sequence_gap\",\"source\":\"" << source
             << "\",\"after_sequence\":" << after << ",\"before_sequence\":" << before
             << ",\"missing_events\":" << (before - after - 1) << "}";
        return writer.Write(json.str());
    };

    auto writeEvent = [&](TelemetryEvent& event) {
        if (event.source == "etw") {
            if (event.header.Sequence > previousEtwSequence + 1) {
                uint64_t gap = event.header.Sequence - previousEtwSequence - 1;
                etwGaps += gap;
                if (!writeGap("etw", previousEtwSequence, event.header.Sequence)) return false;
            }
            previousEtwSequence = event.header.Sequence;
        }
        if (event.processPath.empty() && event.header.ProcessId != 0) {
            uint64_t start = scope.StartTime(event.header.ProcessId);
            if (event.header.ProcessStartTime == 0 || start == 0 || start == event.header.ProcessStartTime) {
                event.processPath = scope.Path(event.header.ProcessId);
            }
        }
        classifier.Classify(event);
        summary.Add(event);
        totalEvents++;
        eventCounts[event.header.Type]++;
        return writer.Write(TelemetryJson(event));
    };

    auto drainEtw = [&]() {
        std::vector<TelemetryEvent> events;
        for (;;) {
            events.clear();
            size_t count = etwQueue.Drain(events, 8192);
            if (count == 0) break;
            for (auto& event : events) {
                if (!writeEvent(event)) return false;
            }
        }
        return true;
    };

    DWORD bytes = 0;
    bool draining = false;
    std::wstring outcome = once ? L"completed" : L"unknown";
    do {
        std::error_code stopError;
        bool stopFileRequested = stopFileEnabled && std::filesystem::exists(stopFile, stopError);
        if (!once && !draining && (gStop.load() || stopFileRequested)) {
            outcome = gStop.load() ? L"agent_stopped" : L"completed";
            if (!device.StopTracking()) {
                std::cerr << "Could not stop driver tracking: Win32 error " << GetLastError() << "\n";
                result = 1;
                break;
            }
            draining = true;
        }
        if (!device.Read(draining ? 0 : static_cast<DWORD>(waitMs), buffer, bytes)) {
            std::cerr << "Driver read failed: Win32 error " << GetLastError() << "\n";
            outcome = L"driver_stopped";
            result = 1;
            break;
        }
        if (bytes > buffer.size()) {
            std::cerr << "Driver returned an invalid byte count.\n";
            result = 1;
            break;
        }
        DWORD offset = 0;
        while (offset < bytes) {
            TelemetryEvent event;
            DWORD consumed = 0;
            if (!DecodeDriverEvent(buffer.data() + offset, bytes - offset, event, consumed, error) || consumed == 0) {
                std::cerr << "Invalid driver event: " << error << "\n";
                result = 1;
                break;
            }
            offset += consumed;
            if (event.header.SessionId != sessionId) {
                std::cerr << "Driver returned an event from another session.\n";
                result = 1;
                break;
            }
            if (previousDriverSequence != 0 && event.header.Sequence <= previousDriverSequence) {
                std::cerr << "Driver sequence is not increasing.\n";
                result = 1;
                break;
            }
            if (event.header.Sequence > previousDriverSequence + 1) {
                uint64_t gap = event.header.Sequence - previousDriverSequence - 1;
                driverGaps += gap;
                if (!writeGap("driver", previousDriverSequence, event.header.Sequence)) {
                    result = 1;
                    break;
                }
            }
            previousDriverSequence = event.header.Sequence;
            if (event.header.Type == MsMonProcessStart) {
                uint64_t start = event.header.ProcessStartTime != 0 ? event.header.ProcessStartTime : event.header.Value0;
                scope.AddProcess(event.header.ProcessId, start, event.text);
                if (etw) etw->ReplayProcess(event.header.ProcessId);
            } else if (event.header.Type == MsMonProcessExit) {
                event.processPath = scope.Path(event.header.ProcessId);
                scope.RemoveProcess(event.header.ProcessId, event.header.ProcessStartTime);
            } else if (event.header.Type == MsMonImageLoad) {
                scope.AddImage(event.header.ProcessId, event.header.Value0, event.header.Value1, event.text);
            }
            if (!writeEvent(event)) {
                std::cerr << "Could not write the event log.\n";
                result = 1;
                break;
            }
        }
        if (etw) etw->ExpirePending(GetTickCount64());
        if (result != 0 || !drainEtw()) {
            result = 1;
            break;
        }
        if (!draining && GetTickCount64() >= nextModuleRefresh) {
            if (!device.RefreshModules() && !moduleRefreshWarning) {
                if (!writeCoverage(L"module_refresh_failed",
                                   L"BlackCat image mapping could not be refreshed; direct stack attribution may be incomplete")) {
                    result = 1;
                    break;
                }
                moduleRefreshWarning = true;
            }
            nextModuleRefresh = GetTickCount64() + 1000;
        }
        if (!draining && GetTickCount64() >= nextStatistics) {
            /*
             * Periodic statistics keep drop and queue pressure visible even if
             * the session ends abruptly (bugcheck, kill, power loss), where the
             * final summary is never written.
             */
            MSMON_STATISTICS statistics{};
            if (device.Statistics(statistics)) {
                TelemetryEvent event;
                event.source = "agent";
                event.header.Size = sizeof(event.header);
                event.header.Version = MSMON_PROTOCOL_VERSION;
                event.header.Type = MsMonCoverage;
                event.header.Flags = MsMonFlagObserverRecord;
                event.header.Timestamp = Now();
                event.header.SessionId = sessionId;
                event.header.Value0 = statistics.DroppedEvents;
                event.header.Value1 = statistics.QueuedEvents;
                event.text = L"driver_statistics";
                event.detail = L"queued=" + std::to_wstring(statistics.QueuedEvents) +
                               L";queued_bytes=" + std::to_wstring(statistics.QueuedBytes) +
                               L";dropped=" + std::to_wstring(statistics.DroppedEvents) +
                               L";tracked=" + std::to_wstring(statistics.TrackedProcesses) +
                               L";queue_record_limit=" + std::to_wstring(statistics.QueueRecordLimit) +
                               L";queue_byte_limit=" + std::to_wstring(statistics.QueueByteLimit);
                event.outsideClient = false;
                if (!writeEvent(event)) {
                    result = 1;
                    break;
                }
            }
            nextStatistics = GetTickCount64() + 30000;
        }
    } while (!once && (!draining || bytes != 0));

    if (etw != nullptr) {
        /*
         * The session is ending: any event still waiting for a process-start
         * record is now permanently unattributed.  Emit those coverage
         * records before stopping the session so they are not lost.
         */
        etw->ExpirePending(~0ull);
        etw->Stop();
        /* Stop joins the ETW worker; expire anything it queued in the race. */
        etw->ExpirePending(~0ull);
    }
    if (!drainEtw()) result = 1;
    if (etw != nullptr) {
        if (!writeCoverage(L"etw_accounting",
                           L"unattributed=" + std::to_wstring(etw->UnattributedCount()) +
                           L";pending_overflow=" + std::to_wstring(etw->PendingOverflow()) +
                           L";pending_after=" + std::to_wstring(etw->PendingCount()) +
                           L";lost_events=" + std::to_wstring(etw->LostEvents()) +
                           L";parse_failures=" + std::to_wstring(etw->ParseFailures()) +
                           L";queue_drops=" + std::to_wstring(etwQueue.Dropped()))) {
            result = 1;
        }
    }
    MSMON_COVERAGE coverage{};
    bool coverageSupported = device.Coverage(coverage);
    const MSMON_COVERAGE* startCoveragePtr =
        (startCoverageSupported && coverageSupported) ? &startCoverage : nullptr;
    if (!coverageSupported) {
        (VOID)writeCoverage(L"coverage_unsupported",
                            L"The driver does not expose MSMON_IOCTL_COVERAGE; sensor counters are unavailable");
    }
    uint64_t coverageAttempted = 0;
    uint64_t coverageDropped = 0;
    uint64_t coverageEntered = 0;
    uint64_t coverageLogged = 0;
    for (unsigned index = 0; index < MSMON_EVENT_SLOTS; index++) {
        coverageAttempted += coverage.EventAttempted[index] -
                             (startCoveragePtr ? startCoveragePtr->EventAttempted[index] : 0);
        coverageDropped += coverage.EventDropped[index] -
                           (startCoveragePtr ? startCoveragePtr->EventDropped[index] : 0);
    }
    for (unsigned index = 0; index < MSMON_SENSOR_SLOTS; index++) {
        coverageEntered += coverage.SensorEntered[index] -
                           (startCoveragePtr ? startCoveragePtr->SensorEntered[index] : 0);
        coverageLogged += coverage.SensorLogged[index] -
                          (startCoveragePtr ? startCoveragePtr->SensorLogged[index] : 0);
    }
    if (!sessionDir.empty()) {
        WriteTextFile(sessionDir / L"coverage.json",
                      BuildCoverageJson(coverage, startCoveragePtr, coverageSupported, etw.get(),
                                        etwQueue.Dropped(), writer.PartCount(), writer.TotalBytes(),
                                        sessionUuid, eventCounts));
    }
    {
        std::wstring detail = L"schema_version=1;driver_supported=" +
                              std::wstring(coverageSupported ? L"true" : L"false") +
                              L";event_attempted=" + std::to_wstring(coverageAttempted) +
                              L";event_dropped=" + std::to_wstring(coverageDropped) +
                              L";sensor_entered=" + std::to_wstring(coverageEntered) +
                              L";sensor_logged=" + std::to_wstring(coverageLogged) +
                              L";registration_failed=" + std::to_wstring(coverage.RegistrationFailed) +
                              L";blackcat_matches=" + std::to_wstring(coverage.BlackCatMatches) +
                              L";etw_unattributed=" + std::to_wstring(etw ? etw->UnattributedCount() : 0) +
                              L";etw_queue_drops=" + std::to_wstring(etwQueue.Dropped());
        TelemetryEvent event;
        event.source = "agent";
        event.header.Size = sizeof(event.header);
        event.header.Version = MSMON_PROTOCOL_VERSION;
        event.header.Type = MsMonCoverageUsage;
        event.header.Flags = MsMonFlagObserverRecord;
        event.header.Timestamp = Now();
        event.header.SessionId = sessionId;
        event.header.Value0 = coverageDropped;
        event.header.Value1 = coverageAttempted;
        event.header.Attribution = MsMonAttributionUnknown;
        event.text = L"coverage_usage";
        event.detail = detail;
        event.outsideClient = false;
        if (!writeEvent(event)) result = 1;
    }
    MSMON_STATISTICS statistics{};
    if (!device.Statistics(statistics)) {
        std::cerr << "Could not read final driver statistics.\n";
        result = 1;
    } else {
        std::string summaryJson = summary.Json(statistics, etwQueue.Dropped(), driverGaps, etwGaps);
        if (!writer.Write(summaryJson)) result = 1;
        if (!sessionDir.empty()) {
            WriteTextFile(sessionDir / L"summary.json", summaryJson);
        }
        std::cout << "Events written: " << totalEvents << "; driver gaps: " << driverGaps
                  << "; ETW gaps: " << etwGaps << "; driver drops: " << statistics.DroppedEvents
                  << "; ETW queue drops: " << etwQueue.Dropped() << "\n";
    }
    if (outcome == L"unknown" && once) outcome = L"completed";
    if (!outcomeOverride.empty()) outcome = outcomeOverride;
    if (!sessionDir.empty()) {
        WriteTextFile(sessionDir / L"session_meta.json",
                      BuildSessionMeta(labels, binaries, clientRoot, scopeRoot, capturePayloads,
                                       enableEtw, queueRecords, queueBytes, outcome, UtcStamp(Now()),
                                       totalEvents, statistics.DroppedEvents, driverGaps, etwGaps,
                                       writer.RecordCount(), writer.TotalBytes(), writer.PartCount()));
        std::cout << "Session bundle: " << WideToUtf8(sessionDir.wstring()) << "\n";
    }
    if (!writer.Close()) result = 1;
    SetConsoleCtrlHandler(ConsoleHandler, FALSE);
    return result;
}
