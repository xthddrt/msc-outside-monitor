#pragma once

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "../include/msmon_protocol.h"

struct TelemetryEvent {
    MSMON_EVENT_HEADER header{};
    std::wstring text;
    std::wstring detail;
    std::wstring component;
    std::wstring processPath;
    std::vector<std::wstring> modules;
    std::vector<BYTE> payload;
    /* Raw ETW stack, retained until the event is emitted so late image loads
     * can still be resolved.  Never written to JSON. */
    DWORD stackPid = 0;
    std::vector<uint64_t> stackAddresses;
    std::string source = "driver";
    bool outsideClient = true;
};

struct ModuleRange {
    uint64_t base = 0;
    uint64_t size = 0;
    std::wstring path;
};

struct ProcessInfo {
    uint64_t startTime = 0;
    std::wstring path;
    std::vector<ModuleRange> modules;
};

class ProcessScope {
public:
    void AddProcess(DWORD pid, uint64_t startTime, const std::wstring& path);
    void RemoveProcess(DWORD pid, uint64_t startTime);
    void AddImage(DWORD pid, uint64_t base, uint64_t size, const std::wstring& path);
    bool IsTracked(DWORD pid) const;
    uint64_t StartTime(DWORD pid) const;
    std::wstring Path(DWORD pid) const;
    std::vector<std::wstring> ResolveStack(DWORD pid, const uint64_t* addresses, size_t count) const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<DWORD, ProcessInfo> processes_;
};

class EventQueue {
public:
    explicit EventQueue(size_t capacity = 32768) : capacity_(capacity) {}
    bool Push(TelemetryEvent&& event);
    size_t Drain(std::vector<TelemetryEvent>& output, size_t maximum);
    uint64_t Dropped() const { return dropped_.load(); }

private:
    size_t capacity_;
    mutable std::mutex mutex_;
    std::deque<TelemetryEvent> events_;
    std::atomic<uint64_t> dropped_{0};
};

class JsonlWriter {
public:
    JsonlWriter(std::filesystem::path basePath, uint64_t maximumBytes);
    bool Open();
    bool Write(const std::string& json);
    bool Close();
    uint64_t RecordCount() const { return recordIndex_; }

private:
    std::filesystem::path basePath_;
    uint64_t maximumBytes_;
    uint64_t bytes_ = 0;
    uint64_t recordIndex_ = 0;
    unsigned part_ = 0;
    std::ofstream stream_;
    std::string chain_;
};

std::string WideToUtf8(const std::wstring& value);
std::string JsonEscape(const std::string& value);
std::string Timestamp(uint64_t value);
std::string EventTypeName(unsigned long type);
std::string CategoryName(unsigned long category);
std::string AttributionName(unsigned long attribution);
std::string Sha256(const std::string& input);
std::string TelemetryJson(const TelemetryEvent& event);
bool DecodeDriverEvent(const BYTE* data, DWORD available, TelemetryEvent& event,
                       DWORD& consumed, std::string& error);
