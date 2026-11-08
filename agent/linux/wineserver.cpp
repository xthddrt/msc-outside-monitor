#include "wineserver.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string_view>

/*
 * Protocol 930 (wine-11.0 include/wine/server_protocol.h, server/protocol.def). Every number and
 * offset of the protocol lives in this file only; ws.bpf.h gets what it needs through ws_cfg.
 * Requests are decoded when their reply arrives (the record carries the reply's status), or without
 * it (detail ";no_reply") when the thread sends another request or the process ends first.
 */

namespace {

enum Request : uint32_t {
    NewProcess = 0, CloseHandleReq = 21, DupHandle = 23, OpenProcess = 27, OpenThread = 28, CreateFile = 44, OpenFileObject = 45,
    GetVolumeInfo = 52, CreateMapping = 63, OpenMapping = 64, ListProcesses = 76, DebugProcess = 82,
    ReadProcessMemory = 84, WriteProcessMemory = 85, CreateKey = 86, OpenKey = 87, DeleteKey = 88,
    EnumKey = 90, SetKeyValue = 91, GetKeyValue = 92, EnumKeyValue = 93, DeleteKeyValue = 94, RenameKey = 99,
    Ioctl = 138, CreateNamedPipe = 140, GetWindowList = 151, GetWindowTree = 154,
    GetWindowText = 157, GetSystemHandles = 234, GetTcpConnections = 235, GetUdpEndpoints = 236,
    GetNextProcess = 293,
};

struct Name {
    uint32_t request;
    const char* name;
    bool replyData;   /* the decoder reads the reply data */
};
const Name kRequests[] = {
    {NewProcess, "wineserver:new_process", false},     /* handle table only, no record */
    {CloseHandleReq, "wineserver:close_handle", false},   /* handle table only, no record */
    {DupHandle, "wineserver:dup_handle", false},
    {OpenProcess, "wineserver:open_process", false},
    {OpenThread, "wineserver:open_thread", false},
    {CreateFile, "wineserver:create_file", false},
    {OpenFileObject, "wineserver:open_file_object", false},
    {GetVolumeInfo, "wineserver:get_volume_info", true},
    {CreateMapping, "wineserver:create_mapping", false},
    {OpenMapping, "wineserver:open_mapping", false},
    {ListProcesses, "wineserver:list_processes", false},
    {DebugProcess, "wineserver:debug_process", false},
    {ReadProcessMemory, "wineserver:read_process_memory", false},
    {WriteProcessMemory, "wineserver:write_process_memory", false},
    {CreateKey, "wineserver:create_key", false},
    {OpenKey, "wineserver:open_key", false},
    {DeleteKey, "wineserver:delete_key", false},
    {EnumKey, "wineserver:enum_key", true},
    {SetKeyValue, "wineserver:set_key_value", false},
    {GetKeyValue, "wineserver:get_key_value", true},
    {EnumKeyValue, "wineserver:enum_key_value", true},
    {DeleteKeyValue, "wineserver:delete_key_value", false},
    {RenameKey, "wineserver:rename_key", false},
    {Ioctl, "wineserver:ioctl", false},
    {CreateNamedPipe, "wineserver:create_named_pipe", false},
    {GetWindowList, "wineserver:get_window_list", false},
    {GetWindowTree, "wineserver:get_window_tree", false},
    {GetWindowText, "wineserver:get_window_text", true},
    {GetSystemHandles, "wineserver:get_system_handles", false},
    {GetTcpConnections, "wineserver:get_tcp_connections", false},
    {GetUdpEndpoints, "wineserver:get_udp_endpoints", false},
    {GetNextProcess, "wineserver:get_next_process", false},
};

/* include/wine/afd.h: CTL_CODE(FILE_DEVICE_BEEP = 1, 0x800/0x802, METHOD_NEITHER, 0) and
 * WINE_AFD_IOC(n) = CTL_CODE(FILE_DEVICE_NETWORK = 0x12, n, METHOD_BUFFERED, 0). */
constexpr uint32_t kAfdBind = 0x12003, kAfdListen = 0x1200b, kAfdAccept = 0x120324, kAfdAcceptInto = 0x120328,
                   kAfdConnect = 0x12032c;

constexpr uint32_t kCurrentProcess = 0xffffffff;   /* GetCurrentProcess() pseudo handle */
constexpr uint32_t kStatusPending = 0x103;

uint32_t U32(const uint8_t* bytes, size_t offset)
{
    uint32_t value;
    std::memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

uint64_t U64(const uint8_t* bytes, size_t offset)
{
    uint64_t value;
    std::memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

std::wstring Hex(uint64_t value)
{
    wchar_t text[24];
    swprintf(text, 24, L"0x%llx", static_cast<unsigned long long>(value));
    return text;
}

std::wstring Num(uint64_t value) { return std::to_wstring(value); }

/* UTF-16LE (no NUL) as UTF-32; an unpaired surrogate becomes U+FFFD. */
std::wstring Utf16(const uint8_t* bytes, size_t length)
{
    std::wstring text;
    for (size_t index = 0; index + 1 < length; index += 2) {
        uint32_t unit = bytes[index] | (bytes[index + 1] << 8);
        if (unit >= 0xd800 && unit < 0xdc00 && index + 3 < length) {
            const uint32_t low = bytes[index + 2] | (bytes[index + 3] << 8);
            if (low >= 0xdc00 && low < 0xe000) {
                text += static_cast<wchar_t>(0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00));
                index += 2;
                continue;
            }
        }
        text += static_cast<wchar_t>(unit >= 0xd800 && unit < 0xe000 ? 0xfffd : unit);
    }
    return text;
}

/* VARARG(objattr,object_attributes): u32 rootdir, attributes, sd_len, name_len, the security descriptor,
 * the UTF-16 name. Returns the bytes it takes (what follows is the next vararg), 0 if malformed. */
size_t ObjectAttributes(const uint8_t* data, size_t length, uint32_t& rootdir, std::wstring& name)
{
    if (length < 16) return 0;
    rootdir = U32(data, 0);
    const uint32_t sd = U32(data, 8), nameBytes = U32(data, 12);
    if (16ull + sd + nameBytes > length) {
        /* Captured cut inside the name: keep what arrived. */
        if (16ull + sd < length) name = Utf16(data + 16 + sd, length - 16 - sd);
        return length;
    }
    name = Utf16(data + 16 + sd, nameBytes);
    return std::min<size_t>(length, (16ull + (sd & ~1u) + (nameBytes & ~1u) + 3) & ~3ull);
}

/* A Windows sockaddr (ws2def.h: AF_INET 2, AF_INET6 23) as "a.b.c.d:port" / "[v6]:port"; Family and
 * Port get the Linux family number (2, 10) and the host-order port. */
std::wstring Endpoint(const uint8_t* address, size_t length, unsigned& family, uint16_t& port)
{
    family = 0;
    port = 0;
    if (length < 4) return {};
    const uint16_t windowsFamily = static_cast<uint16_t>(address[0] | (address[1] << 8));
    port = static_cast<uint16_t>((address[2] << 8) | address[3]);
    wchar_t text[64];
    if (windowsFamily == 2 && length >= 8) {
        family = 2;
        swprintf(text, 64, L"%u.%u.%u.%u:%u", address[4], address[5], address[6], address[7], port);
        return text;
    }
    if (windowsFamily == 23 && length >= 24) {
        family = 10;
        std::wstring out = L"[";
        for (int group = 0; group < 8; group++) {
            swprintf(text, 64, L"%s%x", group ? L":" : L"", (address[8 + group * 2] << 8) | address[9 + group * 2]);
            out += text;
        }
        return out + L"]:" + Num(port);
    }
    family = windowsFamily;
    return L"family=" + Num(windowsFamily);
}

bool Failed(uint32_t status) { return static_cast<int32_t>(status) < 0; }

}  // namespace

const char* WsRequestName(uint32_t request)
{
    for (const Name& name : kRequests) {
        if (name.request == request) return name.name;
    }
    return "wineserver:unknown";
}

mm_ws_config WsCaptureConfig()
{
    mm_ws_config config{};
    for (const Name& name : kRequests) {
        config.want[name.request >> 6] |= 1ull << (name.request & 63);
        if (name.replyData) config.data[name.request >> 6] |= 1ull << (name.request & 63);
    }
    config.ioctl_req = Ioctl;
    const uint32_t codes[] = {kAfdBind, kAfdListen, kAfdAccept, kAfdAcceptInto, kAfdConnect};
    std::copy(std::begin(codes), std::end(codes), config.ioctl_codes);
    return config;
}

unsigned WsProtocolForBuild(const std::string& build)
{
    /* Wine refuses a server of any other version, so the client's build names the protocol. */
    return build == "wine-11.0" ? kWsProtocol : 0;
}

namespace {
std::unordered_map<std::string, std::string> gBuilds;   /* ntdll.so path -> build string */
}

void WsNtdllReset() { gBuilds.clear(); }

std::string WsNtdllBuild(uint32_t pid, std::string& path)
{
    path.clear();
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line, range;
    while (std::getline(maps, line)) {
        const size_t slash = line.find('/');
        if (slash == std::string::npos || line.size() < 9 || line.compare(line.size() - 9, 9, "/ntdll.so") != 0) continue;
        path = line.substr(slash);
        range = line.substr(0, line.find(' '));
        break;
    }
    if (path.empty()) return {};
    auto cached = gBuilds.find(path);
    if (cached != gBuilds.end()) return cached->second;
    /* map_files reaches the file the process mapped even in another mount namespace (root only). */
    int fd = open(("/proc/" + std::to_string(pid) + "/map_files/" + range).c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    std::string build;
    struct stat info {};
    constexpr off_t kMaxBytes = 64 << 20;
    if (fd >= 0 && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_size <= kMaxBytes) {
        std::string bytes(static_cast<size_t>(info.st_size), '\0');
        size_t done = 0;
        while (done < bytes.size()) {
            const ssize_t got = read(fd, &bytes[done], bytes.size() - done);
            if (got <= 0) break;
            done += static_cast<size_t>(got);
        }
        bytes.resize(done);
        /* wine_get_build_id(): "wine-<version>" as a NUL-terminated string. */
        static const char kKnown[] = "wine-11.0";
        if (bytes.find(std::string(kKnown, sizeof(kKnown))) != std::string::npos) build = kKnown;
        else if (bytes.find("wine-") != std::string::npos) build = "wine-other";
    }
    if (fd >= 0) close(fd);
    gBuilds[path] = build;
    return build;
}

void WsDecoder::Reset()
{
    pending_.clear();
    processes_.clear();
    winPids_.clear();
    winTids_.clear();
}

std::wstring WsDecoder::KeyPath(uint32_t tgid, uint32_t handle)
{
    const auto& keys = processes_[tgid].keys;
    auto known = keys.find(handle);
    /* shortcut: keys opened before the agent watched (or duplicated) are named by handle; copy the
     * name on a dup_handle within the process if that matters. */
    return known != keys.end() ? known->second : L"hkey:" + Hex(handle);
}

void WsDecoder::Target(uint32_t winPid, WsRecord& out)
{
    auto known = winPids_.find(winPid);
    if (known != winPids_.end()) out.record.target = known->second.tgid;
}

void WsDecoder::Emit(WsRecord& record, const WsSink& sink)
{
    record.record.sensor = MSMON_SENSOR_LINUX_EBPF_WINESERVER;
    sink(record);
}

void WsDecoder::Event(const mm_ws_event& event, const WsSink& sink)
{
    if (event.kind == MM_WS_REQUEST) {
        if (event.win_pid != 0) winPids_[event.win_pid] = {event.tgid, event.start_ns};
        if (event.win_tid != 0) winTids_[event.win_tid] = {event.tgid, event.start_ns};
        auto& slot = pending_[event.tid];
        if (slot.event) Decode(slot, nullptr, sink);   /* its reply never came (or was not read whole) */
        if (!slot.event) slot.event = std::make_unique<mm_ws_event>();
        std::memcpy(slot.event.get(), &event, offsetof(mm_ws_event, data) + std::min<uint32_t>(event.data_len, MM_WS_DATA));
        Resolve(slot);
        return;
    }
    auto found = pending_.find(event.tid);
    if (found == pending_.end() || !found->second.event || found->second.event->req != event.req) return;
    Pending request = std::move(found->second);
    pending_.erase(found);
    Decode(request, &event, sink);
}

void WsDecoder::Resolve(Pending& pending)
{
    /* At request time wineserver has not read the request yet, so a handle it closes cannot have been given
     * out again, and a handle it uses still names what it named. New handles (open_process, open_key,
     * create_key, new_process) are mapped when their reply arrives. */
    const mm_ws_event& request = *pending.event;
    const uint8_t* q = request.fixed;
    Process& process = processes_[request.tgid];
    auto pid = [&](uint32_t handle) {
        const auto known = process.processes.find(handle);
        return known != process.processes.end() ? known->second : 0;
    };
    pending.winPid = 0;
    pending.key.clear();
    switch (request.req) {
    case CloseHandleReq:
        process.Handed(U32(q, 12));
        break;
    case DupHandle: {
        const uint32_t source = U32(q, 12);
        pending.winPid = pid(source != kCurrentProcess ? source : U32(q, 20));
        if (source == kCurrentProcess && (U32(q, 32) & 1)) process.Handed(U32(q, 16));   /* DUPLICATE_CLOSE_SOURCE */
        break;
    }
    case ReadProcessMemory:
    case WriteProcessMemory:
    case DebugProcess:
        pending.winPid = pid(U32(q, 12));
        break;
    case CreateKey: {   /* the parent is the objattr rootdir */
        const uint32_t parent = std::min<uint32_t>(request.data_len, MM_WS_DATA) >= 16 ? U32(request.data, 0) : 0;
        if (parent != 0) pending.key = KeyPath(request.tgid, parent);
        break;
    }
    case OpenKey:
        if (U32(q, 12) != 0) pending.key = KeyPath(request.tgid, U32(q, 12));
        break;
    case DeleteKey:
    case DeleteKeyValue:
    case RenameKey:
    case SetKeyValue:
    case GetKeyValue:
    case EnumKey:
    case EnumKeyValue:
        pending.key = KeyPath(request.tgid, U32(q, 12));
        break;
    default:
        break;
    }
}

void WsDecoder::Forget(uint32_t tgid, const WsSink& sink)
{
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (!it->second.event || it->second.event->tgid != tgid) {
            ++it;
            continue;
        }
        Decode(it->second, nullptr, sink);
        it = pending_.erase(it);
    }
    processes_.erase(tgid);
    for (auto* map : {&winPids_, &winTids_}) {
        for (auto it = map->begin(); it != map->end();) it = it->second.tgid == tgid ? map->erase(it) : std::next(it);
    }
}

void WsDecoder::Decode(const Pending& pending, const mm_ws_event* reply, const WsSink& sink)
{
    const mm_ws_event& request = *pending.event;
    const uint8_t* q = request.fixed;
    const uint8_t* data = request.data;
    const size_t length = std::min<uint32_t>(request.data_len, MM_WS_DATA);
    const uint8_t* r = reply != nullptr ? reply->fixed : nullptr;
    const uint8_t* replyData = reply != nullptr ? reply->data : nullptr;
    const size_t replyLength = reply != nullptr ? std::min<uint32_t>(reply->data_len, MM_WS_DATA) : 0;
    const uint32_t status = r != nullptr ? U32(r, 0) : 0;
    const bool ok = r != nullptr && !Failed(status);
    const uint32_t tgid = request.tgid;
    Process& process = processes_[tgid];

    WsRecord out;
    out.request = &request;
    out.tsNs = reply != nullptr ? reply->ts_ns : request.ts_ns;
    LinuxRecord& record = out.record;
    record.status = static_cast<int32_t>(status);
    const std::wstring tail = reply != nullptr ? L"" : L";no_reply";
    std::wstring valueName;   /* the registry value a payload belongs to */
    /* wineserver answers a client buffer (reply_size, +8) smaller than the value with success, the value's
     * size and what fits; ntdll turns that into STATUS_BUFFER_OVERFLOW. A size probe (or a
     * KeyValueBasicInformation query): no payload, and not payload_truncated. */
    const bool probe = ok && (request.req == GetKeyValue || request.req == EnumKeyValue) && U32(q, 8) < U32(r, 12);
    const std::wstring buffer = probe ? L";buffer=" + Num(U32(q, 8)) : L"";
    /* wineserver gives out the lowest free handle: a handle closed or given out again no longer names
     * the key or process it named before (unknown beats a wrong target). */
    auto handed = [&](uint32_t handle) { process.Handed(handle); };

    /* Payload of a registry value or volume information (as MsMonLogRegistryValue / MsMonRegistryUnavailable
     * on Windows): Captured bytes of a value of Total bytes. */
    auto payload = [&](ULONG kind, uint64_t total, const uint8_t* bytes, size_t captured, const wchar_t* failure) {
        if (!payloads_ || r == nullptr) return;
        auto unavailable = [&](const wchar_t* reason) {
            record.flags |= MsMonFlagPayloadUnavailable;
            record.detail = std::wstring(reason) + L";value=" + valueName;
        };
        if (Failed(status)) {
            if (failure != nullptr) unavailable(failure);
            return;
        }
        if (total > MSMON_MAX_PAYLOAD_TOTAL_BYTES) return unavailable(L"payload_too_large");
        /* shortcut: values longer than about 8 KiB minus the name are payload_truncated for set_key_value
         * and enum_key_value (one MM_WS_DATA chunk is captured); upgrade by capturing more. */
        if (captured >= total) {
            out.bytes.assign(bytes, bytes + total);
        } else if (captured >= MSMON_PAYLOAD_CHUNK_BYTES) {
            out.bytes.assign(bytes, bytes + MSMON_PAYLOAD_CHUNK_BYTES);   /* chunk 0 of N: a partial series */
        } else {
            return unavailable(L"payload_truncated");
        }
        out.payload = true;
        out.payloadKind = kind;
        out.payloadTotal = total;
    };

    switch (request.req) {
    case CloseHandleReq:   /* applied by Resolve when it was sent */
        return;
    case NewProcess:   /* reply: info handle +8, Windows pid +12, process handle +16 */
        if (ok) {
            handed(U32(r, 8));
            handed(U32(r, 16));
            process.processes[U32(r, 16)] = U32(r, 12);
        }
        return;
    case OpenKey:
    case CreateKey: {
        std::wstring path;
        uint32_t parent = 0;
        if (request.req == OpenKey) {
            parent = U32(q, 12);
            path = Utf16(data, length);
            record.desiredAccess = U32(q, 16);
        } else {
            ObjectAttributes(data, length, parent, path);
            record.desiredAccess = U32(q, 12);
            record.value0 = U32(q, 16);   /* create options */
        }
        /* parent 0: an absolute name (\Registry\Machine\...). */
        if (parent != 0) path = path.empty() ? pending.key : pending.key + L"\\" + path;
        if (ok) {
            handed(U32(r, 8));
            process.keys[U32(r, 8)] = path;
        }
        record.type = request.req == OpenKey ? MsMonRegistryOpen : MsMonRegistryCreate;
        record.text = path;
        record.detail = tail.empty() ? L"" : tail.substr(1);
        out.collapse = request.req == OpenKey;
        out.repeatKey = record.desiredAccess;
        break;
    }
    case DeleteKey:
        record.type = MsMonRegistryDelete;
        record.text = pending.key;
        record.detail = tail.empty() ? L"" : tail.substr(1);
        break;
    case DeleteKeyValue:
    case RenameKey:
        record.type = request.req == RenameKey ? MsMonRegistryRename : MsMonRegistryDelete;
        record.text = pending.key;
        record.detail = Utf16(data, length) + tail;
        break;
    case SetKeyValue: {
        const uint32_t nameBytes = std::min<uint32_t>(U32(q, 20), static_cast<uint32_t>(length));
        const uint64_t total = request.total >= U32(q, 20) ? request.total - U32(q, 20) : 0;
        record.type = MsMonRegistrySetValue;
        record.text = pending.key;
        valueName = Utf16(data, nameBytes);
        record.detail = valueName + tail;
        record.value0 = total;
        record.value1 = U32(q, 16);
        record.flags |= MsMonFlagPayloadInput;
        payload(MsMonPayloadRegistryValue, total, data + nameBytes, length - nameBytes, nullptr);
        if (!out.payload && (record.flags & MsMonFlagPayloadUnavailable) == 0) record.flags &= ~MsMonFlagPayloadInput;
        break;
    }
    case GetKeyValue:
        record.type = MsMonRegistryQuery;
        record.text = pending.key;
        valueName = Utf16(data, length);
        record.detail = valueName + tail + buffer;
        /* value0: the information class is applied by ntdll, wineserver never sees it (0). */
        if (r != nullptr) {
            record.value1 = U32(r, 8);
            if (!probe) payload(MsMonPayloadRegistryValue, U32(r, 12), replyData, replyLength, L"query_failed");
        }
        out.collapse = true;
        /* The value bytes and the probe bit are in the key: the read after a size probe, or a changed
         * value, is never counted as a repeat. */
        out.repeatKey = std::hash<std::wstring>()(valueName) ^
                        (std::hash<std::string_view>()(std::string_view(reinterpret_cast<const char*>(out.bytes.data()),
                                                                        out.bytes.size())) << 1) ^
                        (probe ? 1 : 0);
        break;
    case EnumKey:
    case EnumKeyValue:
        record.type = MsMonRegistryEnumerate;
        record.text = pending.key;
        record.value0 = U32(q, 16);   /* index */
        record.value1 = U32(q, 20);   /* information class */
        if (ok && request.req == EnumKey) {
            valueName = Utf16(replyData, std::min<size_t>(U32(r, 44), replyLength));
        } else if (ok) {
            const uint32_t nameBytes = std::min<uint32_t>(U32(r, 16), static_cast<uint32_t>(replyLength));
            const uint32_t infoClass = U32(q, 20);   /* 0 basic (name), 1 full (name + data), 2 partial (data) */
            valueName = Utf16(replyData, nameBytes);
            record.value1 = U32(r, 8);   /* value type */
            if ((infoClass == 1 || infoClass == 2) && !probe) {
                const uint64_t total = infoClass == 1 && U32(r, 12) >= nameBytes ? U32(r, 12) - nameBytes : U32(r, 12);
                payload(MsMonPayloadRegistryValue, total, replyData + nameBytes, replyLength - nameBytes, nullptr);
            }
        }
        if ((record.flags & MsMonFlagPayloadUnavailable) == 0) record.detail = valueName + tail + buffer;
        break;
    case OpenProcess:
    case OpenThread: {
        const uint32_t id = U32(q, 12);
        record.type = request.req == OpenProcess ? MsMonProcessHandle : MsMonThreadHandle;
        record.desiredAccess = U32(q, 16);
        record.value0 = 1;   /* a handle create, as OB_OPERATION_HANDLE_CREATE */
        record.value1 = ok ? record.desiredAccess : 0;
        if (request.req == OpenProcess) {
            Target(id, out);
            if (ok) {
                handed(U32(r, 8));
                process.processes[U32(r, 8)] = id;
            }
        } else {
            auto known = winTids_.find(id);
            if (known != winTids_.end()) record.target = known->second.tgid;
        }
        record.detail = (request.req == OpenProcess ? L"open_process;win_pid=" : L"open_thread;win_tid=") + Num(id) +
                        (ok ? L";handle=" + Hex(U32(r, 8)) : L"") + tail;
        out.collapse = true;
        out.repeatKey = (static_cast<uint64_t>(record.desiredAccess) << 32) | id;   /* a stronger open is logged */
        break;
    }
    case ReadProcessMemory:
    case WriteProcessMemory: {
        const uint32_t handle = U32(q, 12);
        const uint32_t winPid = handle == kCurrentProcess ? request.win_pid : pending.winPid;
        record.type = MsMonProcessHandle;
        record.value0 = request.req == ReadProcessMemory ? 1 : 2;
        record.value1 = request.req == ReadProcessMemory ? U32(q, 8) : request.total;   /* bytes asked for */
        Target(winPid, out);
        record.detail = std::wstring(request.req == ReadProcessMemory ? L"read_process_memory" : L"write_process_memory") +
                        L";handle=" + Hex(handle) + (winPid ? L";win_pid=" + Num(winPid) : L"") +
                        L";address=" + Hex(U64(q, 16)) + tail;
        out.collapse = true;
        out.repeatKey = handle;
        break;
    }
    case DupHandle: {
        const uint32_t source = U32(q, 12), destination = U32(q, 20);
        if (ok && destination == kCurrentProcess) handed(U32(r, 8));          /* the copy: target not tracked */
        if (source == kCurrentProcess && destination == kCurrentProcess) return;   /* within the process */
        record.type = MsMonProcessHandle;
        record.desiredAccess = U32(q, 24);
        record.value0 = 2;   /* a duplicate, as OB_OPERATION_HANDLE_DUPLICATE */
        record.value1 = U32(q, 32);   /* options */
        Target(pending.winPid, out);
        record.detail = L"dup_handle;src_process=" + Hex(source) + L";src_handle=" + Hex(U32(q, 16)) +
                        L";dst_process=" + Hex(destination) +
                        (pending.winPid ? L";win_pid=" + Num(pending.winPid) : L"") + tail;
        break;
    }
    case DebugProcess: {
        record.type = MsMonProcessHandle;
        record.value1 = U32(q, 20);   /* attach */
        Target(pending.winPid, out);
        record.detail = L"debug_process;handle=" + Hex(U32(q, 12)) + L";attach=" + Num(U32(q, 20)) + tail;
        break;
    }
    case GetNextProcess:
        if (ok) handed(U32(r, 8));   /* its Windows pid is not in the reply */
        record.type = MsMonProcessHandle;
        record.desiredAccess = U32(q, 16);
        record.value0 = 1;
        record.detail = L"get_next_process;last=" + Hex(U32(q, 12)) + (ok ? L";handle=" + Hex(U32(r, 8)) : L"") + tail;
        out.collapse = true;
        break;
    case CreateFile: {
        uint32_t root = 0;
        std::wstring nt;
        const size_t used = ObjectAttributes(data, length, root, nt);
        const std::string unixPath(reinterpret_cast<const char*>(data) + used, length - used);
        record.type = MsMonFileCreate;
        record.text = !unixPath.empty() ? LinuxWide(unixPath) : nt;
        record.desiredAccess = U32(q, 12);
        record.value0 = (static_cast<uint64_t>(U32(q, 20)) << 24) | U32(q, 24);   /* disposition << 24 | options */
        record.value1 = ok ? U32(r, 8) : 0;   /* the handle */
        if (record.text.empty()) record.flags |= MsMonFlagMissingPath;
        if (request.total > length) record.flags |= MsMonFlagTruncatedPath;
        record.detail = L"create_file;nt=" + nt + L";sharing=" + Hex(U32(q, 16)) + L";attrs=" + Hex(U32(q, 28)) + tail;
        out.collapse = true;
        out.repeatKey = record.value0;
        break;
    }
    case OpenFileObject: {
        const uint32_t root = U32(q, 20);
        record.type = MsMonFileCreate;
        record.text = (root ? L"handle:" + Hex(root) + L"\\" : L"") + Utf16(data, length);
        record.desiredAccess = U32(q, 12);
        record.value0 = U32(q, 28);
        record.value1 = ok ? U32(r, 8) : 0;
        record.detail = L"open_file_object;rootdir=" + Hex(root) + L";sharing=" + Hex(U32(q, 24)) + tail;
        out.collapse = true;
        out.repeatKey = record.value0;
        break;
    }
    case CreateNamedPipe: {
        uint32_t root = 0;
        std::wstring name;
        ObjectAttributes(data, length, root, name);
        record.type = MsMonFileCreate;
        record.text = name;
        record.desiredAccess = U32(q, 12);
        record.value0 = (static_cast<uint64_t>(U32(q, 24)) << 24) | U32(q, 16);
        record.value1 = ok ? U32(r, 8) : 0;
        if (name.empty()) record.flags |= MsMonFlagMissingPath;
        record.detail = L"create_named_pipe;rootdir=" + Hex(root) + L";sharing=" + Hex(U32(q, 20)) +
                        L";max_instances=" + Num(U32(q, 28)) + tail;
        break;
    }
    case CreateMapping:
    case OpenMapping: {
        uint32_t root = 0;
        std::wstring name;
        if (request.req == CreateMapping) {
            ObjectAttributes(data, length, root, name);
            if (name.empty()) return;   /* an unnamed section: not shared by name */
            record.value0 = U32(q, 16);   /* SEC_* flags */
            /* +20 is file_access (FILE_READ_DATA [| FILE_WRITE_DATA]) ntdll derives from the page
             * protection, not the protection itself: detail only, value1 stays 0. */
            record.detail = L"create_mapping;size=" + Num(U64(q, 24)) + L";file_handle=" + Hex(U32(q, 32)) +
                            L";file_access=" + Hex(U32(q, 20));
        } else {
            root = U32(q, 20);
            name = Utf16(data, length);
            record.detail = L"open_mapping";
        }
        record.type = MsMonFileSection;
        record.text = (root ? L"handle:" + Hex(root) + L"\\" : L"") + name;
        record.desiredAccess = U32(q, 12);
        record.detail += L";rootdir=" + Hex(root) + tail;
        break;
    }
    case GetVolumeInfo:
        record.type = MsMonFileQueryVolumeInformation;
        record.text = L"handle:" + Hex(U32(q, 12));
        record.value0 = U32(q, 56);   /* FS_INFORMATION_CLASS */
        record.detail = L"get_volume_info" + tail;
        valueName = L"get_volume_info";
        if (reply != nullptr) payload(MsMonPayloadVolumeInformation, reply->total, replyData, replyLength, nullptr);
        break;
    case ListProcesses:
    case GetSystemHandles:
    case GetWindowList:
    case GetWindowTree:
    case GetWindowText:
    case GetTcpConnections:
    case GetUdpEndpoints: {
        /* Enumerations, as the eBPF sensor's system:<call> records: value0 the request, value1 the count
         * (get_window_text: the text length; get_window_tree: 0, it returns no count). */
        const char* name = WsRequestName(request.req) + std::strlen("wineserver:");
        record.type = MsMonFileQueryInformation;
        record.text = L"system:" + LinuxWide(name);
        record.value0 = request.req;
        record.detail = L"ws=" + LinuxWide(name);
        if (request.req == GetWindowList || request.req == GetWindowTree || request.req == GetWindowText) {
            out.repeatKey = U32(q, request.req == GetWindowList ? 16 : 12);
            record.detail += L";handle=" + Hex(out.repeatKey);
        }
        if (ok) {
            if (request.req == GetWindowTree) record.detail += L";parent=" + Hex(U32(r, 8));   /* +8 is parent, not a count */
            else record.value1 = U32(r, request.req == ListProcesses ? 12 : 8);
            /* Another application's window title is content: only with payloads on. */
            if (request.req == GetWindowText)
                record.detail += payloads_ ? L";text=" + Utf16(replyData, replyLength) : L";text_bytes=" + Num(replyLength);
        }
        record.detail += tail;
        out.collapse = true;
        break;
    }
    case Ioctl: {
        /* AFD socket ioctls (ws2_32 -> ntdll unix/socket.c -> server/sock.c): the request that makes
         * wineserver bind/listen/connect/accept for the client. async.handle (+16) is the socket. */
        const uint32_t code = U32(q, 12), socket = U32(q, 16);
        unsigned family = 0;
        uint16_t port = 0;
        std::wstring what;
        record.type = MsMonNetworkAccept;
        if (code == kAfdConnect) {
            record.type = MsMonNetworkConnect;
            if (length >= 8) record.text = Endpoint(data + 8, std::min<size_t>(U32(data, 0), length - 8), family, port);
            what = L"connect;family=" + Num(family) + L";ws=ioctl;afd=connect;synchronous=" +
                   Num(length >= 8 ? U32(data, 4) : 0);
        } else if (code == kAfdBind) {
            if (length >= 4) record.text = Endpoint(data + 4, length - 4, family, port);
            what = L"bind;family=" + Num(family) + L";ws=ioctl;afd=bind";
        } else if (code == kAfdListen) {
            port = length >= 8 ? static_cast<uint16_t>(U32(data, 4)) : 0;   /* backlog */
            what = L"listen;ws=ioctl;afd=listen;backlog=" + Num(port);
        } else if (code == kAfdAccept || code == kAfdAcceptInto) {
            what = L"accept;ws=ioctl;afd=accept";
            if (code == kAfdAcceptInto && length >= 4) what += L";accept_handle=" + Hex(U32(data, 0));
        } else {
            return;
        }
        record.value1 = port;   /* value0 0: the flow is the syscall record's (wineserver's) */
        if (record.text.empty() && code != kAfdListen && code != kAfdAccept && code != kAfdAcceptInto)
            record.flags |= MsMonFlagMissingPath;
        /* A pending connect completes through an APC_ASYNC_IO in a select reply (no get_async_result:
         * it has no output data), so the record carries the ioctl's status; netattr's
         * network_flow_established gives the outcome. */
        record.detail = what + L";socket=" + Hex(socket) + L";ioctl=" + Hex(code) +
                        (status == kStatusPending && r != nullptr ? L";pending" : L"") + tail;
        break;
    }
    default:
        return;
    }
    Emit(out, sink);
}
