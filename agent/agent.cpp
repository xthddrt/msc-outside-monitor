#include "telemetry.h"
#include "classify.h"
#include "etw.h"
#include <tlhelp32.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>

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

static bool EqualPath(const std::wstring& left, const std::wstring& right)
{
    return _wcsicmp(left.c_str(), right.c_str()) == 0;
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

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    bool started_ = false;
};

static bool KnownClientImage(const std::wstring& root, const std::wstring& image)
{
    static const wchar_t* relative[] = {
        L"\\MapleStory.exe", L"\\grap\\NGService.exe",
        L"\\NxOverlay\\DwarfAxe.exe", L"\\CrashReportClient.exe"
    };
    for (const auto* suffix : relative) {
        if (EqualPath(image, root + suffix)) return true;
    }
    return false;
}

static unsigned TrackExisting(DeviceSession& device, const std::wstring& clientRoot,
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
            bool inherited = tracked.count(process.th32ParentProcessID) != 0;
            std::wstring path;
            uint64_t startTime = 0;
            if (!ProcessIdentity(process.th32ProcessID, path, startTime)) continue;
            if (!inherited && !KnownClientImage(clientRoot, path)) continue;
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
    std::cout << "Usage: msmon-agent [--client DIRECTORY] [--output FILE] [--pid PID] "
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
    std::wstring clientRoot = L"C:\\Nexon\\Library\\maplestorycw\\appdata";
    std::wstring output = DefaultOutputPath();
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
        } else if (index + 1 < argc && argument == L"--output") {
            output = argv[++index];
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

    clientRoot = FullPath(clientRoot);
    if (clientRoot.empty()) {
        std::cerr << "Could not resolve the client root.\n";
        return 1;
    }
    std::wstring clientNt;
    std::string error;
    if (!DevicePath(clientRoot, clientNt, error)) {
        std::cerr << error << "\n";
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

    uint64_t sessionId = Now() ^ (static_cast<uint64_t>(GetCurrentProcessId()) << 32) ^ GetTickCount64();
    if (sessionId == 0) sessionId = 1;
    MSMON_SESSION_CONFIG config{};
    config.SessionId = sessionId;
    config.QueueRecords = static_cast<ULONG>(queueRecords);
    config.QueueBytes = static_cast<ULONG>(queueBytes);
    config.PayloadMode = capturePayloads ? 1u : 0u;
    if (clientNt.size() >= MSMON_CLIENT_PATH_CHARS) {
        std::cerr << "The client NT path is too long for the session configuration.\n";
        return 1;
    }
    wcscpy_s(config.ClientRoot, MSMON_CLIENT_PATH_CHARS, clientNt.c_str());

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

    ProcessScope scope;
    unsigned registered = TrackExisting(device, clientRoot, scope);
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

    if (!writeCoverage(L"session_start", L"client_root=" + clientRoot)) return 1;
    if (!writeCoverage(capturePayloads ? L"payload_capture_enabled" : L"payload_capture_disabled",
                       capturePayloads ?
                           L"Exact registry values and volume information will be logged; logs may contain hardware identifiers and registry secrets. WMI result rows, direct adapter-API results, file contents, and network contents remain unavailable" :
                           L"Metadata-only mode; no registry value or volume payload capture")) return 1;
    if (!writeCoverage(L"coverage_limit",
                       L"Handle-less process/window snapshots, ALPC/COM payloads, brokered existing-browser launches, direct adapter APIs, protected processes, pre-start activity, and dropped events are not guaranteed")) return 1;
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
        classifier.Classify(event);
        summary.Add(event);
        totalEvents++;
        return writer.Write(TelemetryJson(event));
    };

    auto drainEtw = [&]() {
        std::vector<TelemetryEvent> events;
        etwQueue.Drain(events, 8192);
        for (auto& event : events) {
            if (!writeEvent(event)) return false;
        }
        return true;
    };

    DWORD bytes = 0;
    bool draining = false;
    do {
        std::error_code stopError;
        bool stopFileRequested = stopFileEnabled && std::filesystem::exists(stopFile, stopError);
        if (!once && !draining && (gStop.load() || stopFileRequested)) {
            if (!device.StopTracking()) {
                std::cerr << "Could not stop driver tracking: Win32 error " << GetLastError() << "\n";
                result = 1;
                break;
            }
            draining = true;
        }
        if (!device.Read(draining ? 0 : static_cast<DWORD>(waitMs), buffer, bytes)) {
            std::cerr << "Driver read failed: Win32 error " << GetLastError() << "\n";
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
            } else if (event.header.Type == MsMonProcessExit) {
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

    if (etw != nullptr) etw->Stop();
    if (!drainEtw()) result = 1;
    MSMON_STATISTICS statistics{};
    if (!device.Statistics(statistics)) {
        std::cerr << "Could not read final driver statistics.\n";
        result = 1;
    } else {
        if (!writer.Write(summary.Json(statistics, etwQueue.Dropped(), driverGaps, etwGaps))) result = 1;
        std::cout << "Events written: " << totalEvents << "; driver gaps: " << driverGaps
                  << "; ETW gaps: " << etwGaps << "; driver drops: " << statistics.DroppedEvents
                  << "; ETW queue drops: " << etwQueue.Dropped() << "\n";
    }
    if (!writer.Close()) result = 1;
    SetConsoleCtrlHandler(ConsoleHandler, FALSE);
    return result;
}
