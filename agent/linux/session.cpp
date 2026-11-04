#include "session.h"
#include <algorithm>
#include <fstream>
#include <iterator>

/* Longest string kept per field; bounds a record below MSMON_MAX_EVENT_RECORD_BYTES. */
static const size_t MAX_STRING_CHARS = 1024;
static const unsigned NO_SENSOR = MSMON_SENSOR_SLOTS;
static bool gUseEbpf = true;

void LinuxSessionUseEbpf(bool enabled)
{
    gUseEbpf = enabled;
}

LinuxSession& LinuxSession::Instance()
{
    static LinuxSession session;
    return session;
}

static uint64_t Now()
{
    FILETIME value;
    GetSystemTimeAsFileTime(&value);
    return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

static std::wstring ErrnoName(int error)
{
    const char* name = strerrorname_np(error);
    return std::to_wstring(error) + (name != nullptr ? L" " + LinuxWide(name) : L"");
}

bool LinuxSession::Start(const MSMON_SESSION_CONFIG& config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) return false;
    sessionId_ = config.SessionId;
    queueRecords_ = config.QueueRecords;
    queueBytesLimit_ = config.QueueBytes;
    queue_.clear();
    queuedBytes_ = 0;
    sequence_ = 0;
    dropped_ = 0;
    coverage_ = {};
    tracked_.clear();
    notes_.clear();
    roots_.clear();
    roots_.emplace_back(config.ClientRoot, wcsnlen(config.ClientRoot, MSMON_CLIENT_PATH_CHARS));
    for (const auto& root : config.ExtraRoots) {
        if (root[0] != L'\0') roots_.emplace_back(root, wcsnlen(root, MSMON_CLIENT_PATH_CHARS));
    }
    ImagesReset();
    NetReset();
    stopping_.store(false);
    running_ = true;
    tracking_ = true;

    /* The Windows driver's callbacks have no Linux equivalent here; say so per slot. */
    for (unsigned slot = MSMON_SENSOR_REG_PROCESS_NOTIFY; slot <= MSMON_SENSOR_REG_ATTRIBUTION; slot++) {
        coverage_.RegistrationFailed |= 1ull << slot;
        coverage_.RegistrationStatus[slot] = ENOSYS;
    }
    /* The kernel sensors own a class when they attached; its user-space source is then
     * not started, so records are not duplicated.  --no-ebpf keeps the old sources. */
    std::wstring detail;
    unsigned ebpf = 0;
    int error = ENOTSUP;
    if (gUseEbpf) {
        error = BpfOpen(detail, roots_.empty() ? std::wstring() : roots_.front(), ebpf);
        for (unsigned index = 0; index < 6; index++) {
            const bool attached = error == 0 && (ebpf & (1u << index)) != 0;
            Registered(MSMON_SENSOR_REG_LINUX_EBPF_PROCESS + index, attached ? 0 : (error != 0 ? error : EOPNOTSUPP));
        }
        if (error == 0) {
            notes_.push_back({L"ebpf_active", detail});
        } else {
            notes_.push_back({L"bpf_unavailable", L"errno=" + ErrnoName(error) + L";" + detail +
                              L";the fanotify, proc connector and polling sensors are used instead"});
        }
    } else {
        notes_.push_back({L"bpf_unavailable", L"errno=0;disabled with --no-ebpf"});
    }
    ebpf_ = error == 0;
    auto owns = [&](unsigned sensor) { return ebpf_ && (ebpf & (1u << (sensor - MSMON_SENSOR_LINUX_EBPF_PROCESS))) != 0; };
    const bool fileOwned = owns(MSMON_SENSOR_LINUX_EBPF_FILE);
    const bool processOwned = owns(MSMON_SENSOR_LINUX_EBPF_PROCESS);
    const bool netOwned = owns(MSMON_SENSOR_LINUX_EBPF_NET);
    /* The maps poll always runs: it is the only source of image_load for Wine PE modules,
     * which are mapped without PROT_EXEC and made executable with mprotect later. */
    pollNet_ = !netOwned;

    detail.clear();
    error = fileOwned ? 0 : FanotifyOpen(detail);
    const bool fanotify = !fileOwned && error == 0;
    if (fileOwned) {
        notes_.push_back({L"fanotify_superseded", L"file records come from linux.ebpf_file"});
    } else {
        Registered(MSMON_SENSOR_REG_LINUX_FANOTIFY, error);
        if (fanotify) {
            notes_.push_back({L"fanotify_active", detail});
        } else {
            notes_.push_back({L"fanotify_unavailable", L"errno=" + ErrnoName(error) + L";" + detail +
                              L";file_create, file_read, file_write, file_close and unlink/rename records are not produced"
                              L" (needs CAP_SYS_ADMIN)"});
        }
    }
    detail.clear();
    error = processOwned ? 0 : ProcConnectorOpen(detail);
    const bool procConnector = !processOwned && error == 0;
    if (processOwned) {
        notes_.push_back({L"proc_connector_superseded", L"process and thread records come from linux.ebpf_process"});
    } else {
        Registered(MSMON_SENSOR_REG_LINUX_PROC_CONNECTOR, error);
        if (!procConnector) {
            notes_.push_back({L"proc_connector_unavailable", L"errno=" + ErrnoName(error) + L";" + detail +
                              L";forks, execs and exits after start are not seen; only processes running at start and"
                              L" --pid are tracked (needs CAP_NET_ADMIN)"});
        }
    }
    const int mapsError = access("/proc/self/maps", R_OK) == 0 ? 0 : errno;
    Registered(MSMON_SENSOR_REG_LINUX_MAPS_POLL, mapsError);
    if (pollNet_) {
        const int netError = access("/proc/net/tcp", R_OK) == 0 ? 0 : errno;
        Registered(MSMON_SENSOR_REG_LINUX_NET_POLL, netError);
    } else {
        notes_.push_back({L"net_poll_superseded", L"socket records come from linux.ebpf_net and linux.ebpf_ipc"});
    }
    notes_.push_back({L"registry_unavailable",
                      L"Wine keeps its registry in wineserver: no key-level registry_* events; the prefix's *.reg files"
                      L" are recorded as file events and snapshotted when written"});
    notes_.push_back({L"blackcat_not_applicable",
                      L"BlackCat is a Windows kernel driver: no device discovery, kernel-module attribution or"
                      L" BlackCat-initiated tracking"});
    if (ebpf_) threads_.emplace_back([this] { BpfRun(*this); });
    if (fanotify) threads_.emplace_back([this] { FanotifyRun(*this); });
    if (procConnector) threads_.emplace_back([this] { ProcConnectorRun(*this); });
    threads_.emplace_back([this] { PollLoop(); });
    return true;
}

void LinuxSession::Registered(unsigned slot, int error)
{
    if (error == 0) {
        coverage_.RegistrationOk |= 1ull << slot;
    } else {
        coverage_.RegistrationFailed |= 1ull << slot;
    }
    coverage_.RegistrationStatus[slot] = error;
}

void LinuxSession::Stop()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) return;
        tracking_ = false;
        stopping_.store(true);
    }
    wake_.notify_all();
    for (auto& thread : threads_) {
        if (thread.joinable()) thread.join();
    }
    threads_.clear();
    FanotifyClose();
    ProcConnectorClose();
    if (ebpf_) BpfClose();
    std::lock_guard<std::mutex> lock(mutex_);
    running_ = false;
    ebpf_ = false;
    data_.notify_all();
}

/* Images every two seconds, sockets every second; see the coverage_limit note. */
void LinuxSession::PollLoop()
{
    for (unsigned tick = 0;; tick++) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (tick != 0) wake_.wait_for(lock, std::chrono::seconds(1), [this] { return stopping_.load(); });
            if (stopping_.load()) return;
            if (!tracking_) continue;
        }
        if (tick % 2 == 0) {
            for (const auto& process : TrackedProcesses()) ImagesScan(*this, process.first, process.second);
        }
        if (pollNet_) NetPoll(*this);
    }
}

bool LinuxSession::Track(DWORD pid, uint64_t expectedStart, ULONG flags)
{
    std::wstring path;
    uint64_t start = 0;
    if (!LinuxProcessIdentity(pid, path, start) || !MsMonTrackAdmitsStart(expectedStart, start)) {
        errno = ESRCH;
        return false;
    }
    if (flags == 0) flags = MsMonFlagExplicitTrack;
    if (!Admit(pid, start, flags)) {
        errno = EINVAL;
        return false;
    }
    /* As the driver does: log what was admitted, with no image text (the agent already knows it). */
    Log(NO_SENSOR, MsMonProcessStart, pid, start, flags, start, 0, {});
    ImagesScan(*this, pid, start);
    return true;
}

void LinuxSession::StopTracking()
{
    std::lock_guard<std::mutex> lock(mutex_);
    tracking_ = false;
    tracked_.clear();
    if (ebpf_) BpfClear();
}

bool LinuxSession::Read(DWORD waitMs, std::vector<BYTE>& buffer, DWORD& bytes)
{
    std::unique_lock<std::mutex> lock(mutex_);
    bytes = 0;
    data_.wait_for(lock, std::chrono::milliseconds(std::min<DWORD>(waitMs, 1000)),
                   [this] { return !queue_.empty(); });
    while (!queue_.empty() && bytes + queue_.front().size() <= buffer.size()) {
        const auto& record = queue_.front();
        std::memcpy(buffer.data() + bytes, record.data(), record.size());
        bytes += static_cast<DWORD>(record.size());
        queuedBytes_ -= record.size();
        queue_.pop_front();
    }
    return true;
}

void LinuxSession::Statistics(MSMON_STATISTICS& statistics)
{
    std::lock_guard<std::mutex> lock(mutex_);
    statistics = {};
    statistics.SessionId = sessionId_;
    statistics.QueuedEvents = queue_.size();
    statistics.QueuedBytes = queuedBytes_;
    statistics.DroppedEvents = dropped_;
    statistics.TrackedProcesses = tracked_.size();
    statistics.QueueRecordLimit = queueRecords_;
    statistics.QueueByteLimit = queueBytesLimit_;
}

void LinuxSession::Coverage(MSMON_COVERAGE& coverage)
{
    std::lock_guard<std::mutex> lock(mutex_);
    coverage = coverage_;
    coverage.Version = MSMON_COVERAGE_VERSION;
    coverage.Size = sizeof(coverage);
    coverage.SessionId = sessionId_;
}

std::vector<std::pair<std::wstring, std::wstring>> LinuxSession::Notes()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return notes_;
}

bool LinuxSession::Tracked(DWORD pid, uint64_t& start, ULONG& flags) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = tracked_.find(pid);
    if (found == tracked_.end()) return false;
    start = found->second.start;
    flags = found->second.flags;
    return true;
}

std::vector<std::pair<DWORD, uint64_t>> LinuxSession::TrackedProcesses() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<DWORD, uint64_t>> result;
    for (const auto& item : tracked_) result.emplace_back(item.first, item.second.start);
    return result;
}

bool LinuxSession::Admit(DWORD pid, uint64_t start, ULONG flags)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!tracking_) return false;
    tracked_[pid] = {start, flags};
    if (ebpf_) BpfTrack(pid, start, flags);
    return true;
}

void LinuxSession::Forget(DWORD pid, uint64_t start)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = tracked_.find(pid);
    if (found != tracked_.end() && found->second.start == start) {
        tracked_.erase(found);
        if (ebpf_) BpfForget(pid);
    }
}

bool LinuxSession::UnderRoot(const std::wstring& path) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& root : roots_) {
        if (!root.empty() && path.size() > root.size() && path.compare(0, root.size(), root) == 0 &&
            (root.back() == L'/' || path[root.size()] == L'/')) {
            return true;
        }
    }
    return false;
}

static void AppendString(std::vector<BYTE>& record, const std::wstring& value,
                         unsigned short& offset, unsigned short& bytes, bool& truncated)
{
    if (value.empty()) return;
    const size_t characters = std::min(value.size(), MAX_STRING_CHARS);
    truncated = characters < value.size();
    offset = static_cast<unsigned short>(record.size());
    bytes = static_cast<unsigned short>(characters * sizeof(wchar_t));
    const BYTE* data = reinterpret_cast<const BYTE*>(value.data());
    record.insert(record.end(), data, data + bytes);
}

void LinuxSession::Log(unsigned sensor, ULONG type, DWORD pid, uint64_t start, ULONG flags, uint64_t value0,
                       uint64_t value1, const std::wstring& text, const std::wstring& detail, DWORD parent)
{
    LinuxRecord record;
    record.sensor = sensor;
    record.type = type;
    record.pid = pid;
    record.start = start;
    record.flags = flags;
    record.value0 = value0;
    record.value1 = value1;
    record.text = text;
    record.detail = detail;
    record.parent = parent;
    Write(record);
}

void LinuxSession::Write(const LinuxRecord& input)
{
    MSMON_EVENT_HEADER header{};
    header.Version = MSMON_PROTOCOL_VERSION;
    header.Type = input.type;
    header.Flags = input.flags;
    header.Timestamp = input.timestamp != 0 ? input.timestamp : Now();
    header.ProcessId = input.pid;
    header.ParentProcessId = input.parent;
    header.ThreadId = input.tid;
    header.TargetProcessId = input.target;
    header.ProcessStartTime = input.start;
    header.Status = input.status;
    header.Category = MsMonCategoryUnknown;
    header.Attribution = MsMonAttributionProcessOnly;
    header.Value0 = input.value0;
    header.Value1 = input.value1;
    std::vector<BYTE> record(sizeof(header));
    bool textTruncated = false;
    bool detailTruncated = false;
    AppendString(record, input.text, header.TextOffset, header.TextBytes, textTruncated);
    AppendString(record, input.detail, header.DetailOffset, header.DetailBytes, detailTruncated);
    if (textTruncated) header.Flags |= MsMonFlagTruncatedPath;
    if (!input.stack.empty()) {
        record.resize((record.size() + 7) & ~size_t(7));
        const size_t frames = std::min<size_t>(input.stack.size(), MSMON_MAX_STACK_FRAMES);
        header.StackOffset = static_cast<unsigned short>(record.size());
        header.StackFrames = static_cast<unsigned short>(frames);
        const BYTE* data = reinterpret_cast<const BYTE*>(input.stack.data());
        record.insert(record.end(), data, data + frames * sizeof(uint64_t));
    }
    /* Keep every record 8-byte aligned so the next header and its strings stay aligned. */
    record.resize((record.size() + 7) & ~size_t(7));
    header.Size = static_cast<unsigned long>(record.size());

    const unsigned sensor = input.sensor;
    const ULONG type = input.type;
    std::lock_guard<std::mutex> lock(mutex_);
    /* After StopTracking nothing is tracked, as in the driver; this also drops records a sensor
     * computed just before (a socket poll would otherwise report every flow closed). */
    if (!running_ || !tracking_) return;
    header.SessionId = sessionId_;
    header.Sequence = ++sequence_;
    if (type < MSMON_EVENT_SLOTS) coverage_.EventAttempted[type]++;
    if (queue_.size() >= queueRecords_ || queuedBytes_ + record.size() > queueBytesLimit_) {
        dropped_++;
        coverage_.QueueDrops++;
        if (type < MSMON_EVENT_SLOTS) coverage_.EventDropped[type]++;
        return;
    }
    std::memcpy(record.data(), &header, sizeof(header));
    queuedBytes_ += record.size();
    queue_.push_back(std::move(record));
    if (sensor < MSMON_SENSOR_SLOTS) coverage_.SensorLogged[sensor]++;
    data_.notify_one();
}

void LinuxSession::Enter(unsigned sensor)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (sensor < MSMON_SENSOR_SLOTS) coverage_.SensorEntered[sensor]++;
}

void LinuxSession::SkipUntracked()
{
    std::lock_guard<std::mutex> lock(mutex_);
    coverage_.SkipUntracked++;
}

void LinuxSession::NoteDropped()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_) return;
    sequence_++;
    dropped_++;
}

std::wstring ProcessCommandLine(DWORD pid)
{
    std::ifstream file("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    while (!text.empty() && text.back() == '\0') text.pop_back();
    for (char& c : text) {
        if (c == '\0') c = ' ';
    }
    return LinuxWide(text);
}
