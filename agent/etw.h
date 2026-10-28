#pragma once

#include "telemetry.h"
#include <evntrace.h>
#include <evntcons.h>
#include <deque>
#include <mutex>
#include <thread>

class EtwCollector {
public:
    EtwCollector(ProcessScope& scope, EventQueue& queue, uint64_t sessionId, bool capturePayloads);
    ~EtwCollector();
    bool Start(std::string& error);
    void Stop();
    const std::vector<std::wstring>& Warnings() const { return warnings_; }

    /* Re-emit events that arrived before the driver's process-start record. */
    void ReplayProcess(DWORD pid);
    /* Expire unmatched events and emit an etw_unattributed coverage record. */
    void ExpirePending(uint64_t nowTick);
    uint64_t PendingCount() const;
    uint64_t UnattributedCount() const { return unattributed_.load(); }
    uint64_t PendingOverflow() const { return pendingOverflow_.load(); }
    uint64_t LostEvents() const { return lostEvents_.load(); }
    uint64_t ParseFailures() const { return parseFailures_.load(); }
    uint64_t Received(int index) const { return index >= 0 && index < 3 ? received_[index].load() : 0; }
    uint64_t Parsed(int index) const { return index >= 0 && index < 3 ? parsed_[index].load() : 0; }
    uint64_t Emitted(int index) const { return index >= 0 && index < 3 ? emitted_[index].load() : 0; }
    uint64_t Deferred(int index) const { return index >= 0 && index < 3 ? deferred_[index].load() : 0; }
    uint64_t Expired(int index) const { return index >= 0 && index < 3 ? expired_[index].load() : 0; }

private:
    static ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW logfile);
    void OnRecord(PEVENT_RECORD record);
    void EnableProvider(const GUID& provider, const std::wstring& name);
    void Emit(TelemetryEvent&& event);
    std::wstring ProviderName(unsigned long type) const;

    struct PendingEvent {
        TelemetryEvent event;
        uint64_t deadline = 0;
    };

    ProcessScope& scope_;
    EventQueue& queue_;
    uint64_t sessionId_;
    bool capturePayloads_ = true;
    TRACEHANDLE session_ = 0;
    TRACEHANDLE trace_ = 0;
    std::wstring loggerName_;
    std::vector<BYTE> properties_;
    std::thread worker_;
    std::atomic<uint64_t> sequence_{0};
    std::atomic<uint64_t> unattributed_{0};
    std::atomic<uint64_t> pendingOverflow_{0};
    std::atomic<uint64_t> lostEvents_{0};
    std::atomic<uint64_t> parseFailures_{0};
    std::atomic<uint64_t> received_[3]{};
    std::atomic<uint64_t> parsed_[3]{};
    std::atomic<uint64_t> emitted_[3]{};
    std::atomic<uint64_t> deferred_[3]{};
    std::atomic<uint64_t> expired_[3]{};
    mutable std::mutex pendingMutex_;
    std::mutex emitMutex_;
    std::deque<PendingEvent> pending_;
    std::vector<std::wstring> warnings_;
    bool started_ = false;
};
