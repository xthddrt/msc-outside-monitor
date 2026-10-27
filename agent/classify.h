#pragma once

#include "telemetry.h"
#include <map>

class OutsideClassifier {
public:
    OutsideClassifier(std::wstring clientDos, std::wstring clientNt,
                      std::wstring windowsDos, std::wstring windowsNt);
    void Classify(TelemetryEvent& event) const;

private:
    std::wstring clientDos_;
    std::wstring clientNt_;
    std::wstring windowsDos_;
    std::wstring windowsNt_;
};

class SessionSummary {
public:
    void Add(const TelemetryEvent& event);
    std::string Json(const MSMON_STATISTICS& statistics, uint64_t etwDropped,
                     uint64_t driverGaps, uint64_t etwGaps) const;

private:
    uint64_t events_ = 0;
    uint64_t outsideEvents_ = 0;
    uint64_t hardwareEvents_ = 0;
    std::map<std::string, uint64_t> categories_;
    std::map<DWORD, uint64_t> processes_;
    std::map<DWORD, uint64_t> targets_;
    std::map<std::wstring, uint64_t> modules_;
};
