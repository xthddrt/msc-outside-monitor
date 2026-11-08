/* Wineserver requests (wineserver upgrade): bpf.cpp's hooks for ws.bpf.h. The ring records go to the
 * pure decoder in wineserver.cpp; what it returns is written here as records of the requesting
 * process and thread (docs/LINUX.md "Wineserver requests"). */
#include "wineserver.h"

namespace {

struct WsState {
    WsDecoder decoder;
    struct Process {
        uint64_t startNs = 0;
        bool active = false;
    };
    std::unordered_map<uint32_t, Process> processes;   /* tgid -> decoder gate */
    std::string lastBuild, lastPath;                     /* the last ntdll.so read from a live process */
    bool attached = false;
};
WsState gWs;

void WsConfigure(bpf_object* object)
{
    gWs.decoder.SetPayloads(gBpf.payloads);
    bpf_map* map = bpf_object__find_map_by_name(object, "ws_cfg");
    if (map == nullptr) return;
    const mm_ws_config config = WsCaptureConfig();
    const uint32_t zero = 0;
    bpf_map_update_elem(bpf_map__fd(map), &zero, &config, BPF_ANY);
}

int WsOpened(std::wstring& detail, unsigned& registered)
{
    gWs.attached = Attached("mm_ws_enter") && Attached("mm_ws_exit");
    if (gWs.attached) {
        registered |= 1u << (MSMON_SENSOR_LINUX_EBPF_WINESERVER - MSMON_SENSOR_LINUX_EBPF_PROCESS);
        detail += L";wineserver=on";
        return 0;
    }
    const Group* group = FindGroup("wineserver");
    detail += L";wineserver=off(" +
              (group->state == 0    ? std::wstring(L"attach_failed")
               : group->state == -1 ? std::wstring(L"off")
                                    : L"load_failed:" + std::to_wstring(group->state)) +
              L")";
    return 0;
}

/* One decoded record: identity and stack from its request, then collapsed or written. */
void WsWrite(WsRecord& out)
{
    const mm_ws_event& request = *out.request;
    LinuxRecord& record = out.record;
    record.pid = request.tgid;
    record.tid = request.tid;
    record.start = HertzTicksToFileTime(request.start_ns);
    record.timestamp = BootToFileTime(out.tsNs);
    if (out.collapse) {
        /* Repeated's key: the pseudo syscall 1000 + request, the status, the target text and RepeatKey. */
        mm_event shell{};
        shell.tgid = request.tgid;
        shell.tid = request.tid;
        shell.start_ns = request.start_ns;
        shell.ts_ns = out.tsNs;
        shell.nr = 1000 + request.req;
        shell.ret = record.status;
        if (Repeated(shell, WsRequestName(request.req), record.sensor, record.type, record.text, out.repeatKey, false,
                     record.detail))
            return;
    }
    uint64_t targetStart = 0;
    ULONG targetFlags = 0;
    if (record.target != 0 && gBpf.session->Tracked(record.target, targetStart, targetFlags)) record.targetStart = targetStart;
    PeFrames(request.pe, request.tgid, record.start, request.stack, std::min<uint32_t>(request.frames, MM_FRAMES), record);
    if (out.payload) {
        gBpf.session->WritePayloadSeries(record, out.payloadKind, out.payloadTotal, out.bytes);
    } else {
        gBpf.session->Write(record);
    }
}

/* The decoder runs only for a client whose ntdll.so is a build it has the protocol of; the first event
 * of each process writes the wineserver_decoder record that says so. */
bool WsActive(const mm_ws_event& event)
{
    WsState::Process& process = gWs.processes[event.tgid];
    if (process.startNs == event.start_ns) return process.active;
    std::string path;
    std::string build = WsNtdllBuild(event.tgid, path);
    /* The ring is drained after the request: a short-lived client may be gone (maps empty). Only a
     * Wine thread (TEB, pipe fd) produces these events, so assume the last ntdll.so seen. */
    const bool assumed = path.empty() && !gWs.lastPath.empty();
    if (assumed) {
        build = gWs.lastBuild;
        path = gWs.lastPath;
    } else if (!path.empty()) {
        gWs.lastBuild = build;
        gWs.lastPath = path;
    }
    const unsigned protocol = WsProtocolForBuild(build);
    process = {event.start_ns, protocol == kWsProtocol};
    LinuxRecord record;
    record.sensor = MSMON_SENSOR_LINUX_EBPF_WINESERVER;
    record.type = MsMonCoverage;
    record.flags = MsMonFlagObserverRecord;
    record.pid = event.tgid;
    record.tid = event.tid;
    record.start = HertzTicksToFileTime(event.start_ns);
    record.text = L"wineserver_decoder";
    record.detail = L"active=" + std::to_wstring(process.active ? 1 : 0) + L";build=" + LinuxWide(build.empty() ? "unknown" : build) +
                    L";protocol=" + std::to_wstring(protocol) + L";ntdll=" + LinuxWide(path) + (assumed ? L";assumed=1" : L"");
    gBpf.session->Write(record);
    return process.active;
}

void WsRing(const void* data, size_t size)
{
    constexpr size_t head = offsetof(mm_ws_event, data);
    if (size < head) return;
    static mm_ws_event event;   /* about 17 KB: not on the stack per record */
    std::memcpy(&event, data, std::min(size, sizeof(event)));
    event.data_len = std::min<uint32_t>({event.data_len, static_cast<uint32_t>(std::min<size_t>(size - head, MM_WS_DATA)),
                                         MM_WS_DATA});
    LinuxSession& session = *gBpf.session;
    session.Enter(MSMON_SENSOR_LINUX_EBPF_WINESERVER);
    uint64_t start = 0;
    ULONG flags = 0;
    if (!session.Tracked(event.tgid, start, flags)) return;
    if (!WsActive(event)) return;
    gWs.decoder.Event(event, WsWrite);
}

void WsForget(const mm_event& e)
{
    gWs.decoder.Forget(e.tgid, WsWrite);
    gWs.processes.erase(e.tgid);
}

void WsClose()
{
    gWs.decoder.Reset();
    gWs.processes.clear();
    gWs.lastBuild.clear();
    gWs.lastPath.clear();
    gWs.attached = false;
    WsNtdllReset();
}

void WsNotes(Notes& notes)
{
    if (GroupOn("wineserver") && gWs.attached) {
        notes.emplace_back(
            L"wineserver_requests",
            L"protocol=" + std::to_wstring(kWsProtocol) +
                L";builds=wine-11.0;records=registry,process_handle,thread_handle,file_create,file_section,"
                L"file_query_volume_information,file_query_information,network_connect,network_accept;payloads=" +
                (gBpf.payloads ? L"on" : L"off") + L";request_bytes=" + std::to_wstring(MM_WS_DATA) +
                L";reply_bytes=" + std::to_wstring(MM_WS_DATA) + L";gate=ntdll_build");
        return;
    }
    const Group* group = FindGroup("wineserver");
    notes.emplace_back(L"wineserver_requests_unavailable",
                       group->state == 0    ? std::wstring(L"attach_failed")
                       : group->state == -1 ? std::wstring(L"group_off")
                                            : L"load_failed:" + std::to_wstring(group->state));
}

}  // namespace
