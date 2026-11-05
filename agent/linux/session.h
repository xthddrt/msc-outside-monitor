#pragma once

#include "../telemetry.h"
#include "../../include/msmon_coverage.h"
#include <condition_variable>
#include <thread>
#include <utility>

/* One record with every header field a sensor can fill (Log fills the common ones). */
struct LinuxRecord {
    unsigned sensor = MSMON_SENSOR_SLOTS;
    ULONG type = 0;
    DWORD pid = 0;
    DWORD tid = 0;
    DWORD parent = 0;
    DWORD target = 0;
    uint64_t start = 0;
    uint64_t timestamp = 0;   /* FILETIME; 0 = now */
    ULONG flags = 0;
    long status = 0;
    uint64_t value0 = 0;
    uint64_t value1 = 0;
    std::wstring text;
    std::wstring detail;
    std::vector<uint64_t> stack;
};

/* Set before LinuxSession::Start; false keeps the eBPF sensors off (--no-ebpf). */
void LinuxSessionUseEbpf(bool enabled);

/*
 * In-process stand-in for the Windows driver.  The Linux sensors log records here in
 * the driver's wire format (MSMON_EVENT_HEADER + strings), with one sequence and one
 * bounded queue, so agent.cpp reads, gap-checks and accounts them unchanged.
 */
class LinuxSession {
public:
    static LinuxSession& Instance();
    bool Start(const MSMON_SESSION_CONFIG& config);
    void Stop();
    bool Track(DWORD pid, uint64_t expectedStart, ULONG flags);
    void StopTracking();
    bool Read(DWORD waitMs, std::vector<BYTE>& buffer, DWORD& bytes);
    void Statistics(MSMON_STATISTICS& statistics);
    void Coverage(MSMON_COVERAGE& coverage);
    /* Coverage records (text, detail) the agent writes at session start. */
    std::vector<std::pair<std::wstring, std::wstring>> Notes();

    /* Sensor side. */
    bool Stopping() const { return stopping_.load(); }
    bool Tracked(DWORD pid, uint64_t& start, ULONG& flags) const;
    std::vector<std::pair<DWORD, uint64_t>> TrackedProcesses() const;
    /* Track without logging; false once tracking has stopped. */
    bool Admit(DWORD pid, uint64_t start, ULONG flags);
    void Forget(DWORD pid, uint64_t start);
    bool UnderRoot(const std::wstring& path) const;
    void Log(unsigned sensor, ULONG type, DWORD pid, uint64_t start, ULONG flags, uint64_t value0, uint64_t value1,
             const std::wstring& text, const std::wstring& detail = {}, DWORD parent = 0);
    void Write(const LinuxRecord& record);
    void Enter(unsigned sensor);
    void SkipUntracked();
    /* A source lost events it cannot name: burn a sequence number so the agent logs a gap. */
    void NoteDropped();

private:
    void Registered(unsigned slot, int error);
    void PollLoop();

    mutable std::mutex mutex_;
    std::condition_variable data_;
    std::condition_variable wake_;
    std::deque<std::vector<BYTE>> queue_;
    uint64_t queuedBytes_ = 0;
    uint64_t queueRecords_ = 0;
    uint64_t queueBytesLimit_ = 0;
    uint64_t sequence_ = 0;
    uint64_t dropped_ = 0;
    uint64_t sessionId_ = 0;
    MSMON_COVERAGE coverage_{};
    struct TrackedProcess {
        uint64_t start = 0;
        ULONG flags = 0;
    };
    std::unordered_map<DWORD, TrackedProcess> tracked_;
    std::vector<std::wstring> roots_;
    std::vector<std::pair<std::wstring, std::wstring>> notes_;
    std::vector<std::thread> threads_;
    std::atomic<bool> stopping_{false};
    bool running_ = false;
    bool tracking_ = false;
    bool ebpf_ = false;
    bool pollNet_ = true;
};

/* The agent's driver handle, backed by LinuxSession. */
class DeviceSession {
public:
    ~DeviceSession()
    {
        if (started_) LinuxSession::Instance().Stop();
    }
    bool Open() { return true; }
    bool Start(MSMON_SESSION_CONFIG& config)
    {
        started_ = LinuxSession::Instance().Start(config);
        return started_;
    }
    bool Track(DWORD pid, uint64_t startTime, ULONG flags) { return LinuxSession::Instance().Track(pid, startTime, flags); }
    bool Read(DWORD waitMs, std::vector<BYTE>& buffer, DWORD& bytes)
    {
        return LinuxSession::Instance().Read(waitMs, buffer, bytes);
    }
    bool RefreshModules() { return true; }
    bool StopTracking()
    {
        LinuxSession::Instance().StopTracking();
        return true;
    }
    bool Statistics(MSMON_STATISTICS& statistics)
    {
        LinuxSession::Instance().Statistics(statistics);
        return true;
    }
    bool Coverage(MSMON_COVERAGE& coverage)
    {
        LinuxSession::Instance().Coverage(coverage);
        return true;
    }
    std::vector<std::pair<std::wstring, std::wstring>> Notes() { return LinuxSession::Instance().Notes(); }

private:
    bool started_ = false;
};

/* Sensors (one file each).  Open returns 0 or an errno and fills detail. */
int FanotifyOpen(std::wstring& detail);
void FanotifyRun(LinuxSession& session);
void FanotifyClose();
int ProcConnectorOpen(std::wstring& detail);
void ProcConnectorRun(LinuxSession& session);
void ProcConnectorClose();
void ImagesScan(LinuxSession& session, DWORD pid, uint64_t start);
void ImagesForget(DWORD pid);
void ImagesReset();
void NetPoll(LinuxSession& session);
void NetReset();
/* eBPF sensors (bpf.cpp).  BpfOpen returns 0 or an errno and sets bit (slot - 48) of
 * Registered for each MSMON_SENSOR_LINUX_EBPF_* sensor that attached; Root is the scope
 * root an untracked process's executable mapping is matched against. */
int BpfOpen(std::wstring& detail, const std::wstring& root, unsigned& registered);
void BpfRun(LinuxSession& session);
void BpfClose();
void BpfTrack(DWORD pid, uint64_t start, ULONG flags);
void BpfForget(DWORD pid);
void BpfClear();
/* "/proc/<pid>/cmdline" with NUL separators as spaces, as the Windows command line. */
std::wstring ProcessCommandLine(DWORD pid);
