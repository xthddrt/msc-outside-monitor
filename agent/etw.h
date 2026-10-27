#pragma once

#include "telemetry.h"
#include <evntrace.h>
#include <evntcons.h>
#include <thread>

class EtwCollector {
public:
    EtwCollector(ProcessScope& scope, EventQueue& queue, uint64_t sessionId);
    ~EtwCollector();
    bool Start(std::string& error);
    void Stop();
    const std::vector<std::wstring>& Warnings() const { return warnings_; }

private:
    void OnRecord(PEVENT_RECORD record);
    void EnableProvider(const GUID& provider, const std::wstring& name);

    ProcessScope& scope_;
    EventQueue& queue_;
    uint64_t sessionId_;
    TRACEHANDLE session_ = 0;
    TRACEHANDLE trace_ = 0;
    std::wstring loggerName_;
    std::vector<BYTE> properties_;
    std::thread worker_;
    std::atomic<uint64_t> sequence_{0};
    std::vector<std::wstring> warnings_;
    bool started_ = false;
};
