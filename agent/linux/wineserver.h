#pragma once
/*
 * Decoder of a Wine client's wineserver requests (protocol 930 = wine-11.0), captured by
 * agent/linux/bpf/ws.bpf.h as MM_WS_REQUEST / MM_WS_REPLY records. Pure: no BPF, no session; bpf_ws.inc
 * feeds it ring records and writes what it returns. tests/wineserver_test.cpp drives it with synthetic
 * buffers. docs/LINUX.md "Wineserver requests" lists the records.
 */
#include "session.h"
#include "bpf/monitor_bpf.h"
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

constexpr unsigned kWsProtocol = 930;   /* SERVER_PROTOCOL_VERSION the tables below are for */

/* ws_cfg for protocol 930: the wanted requests, their reply data and the AFD ioctls. */
mm_ws_config WsCaptureConfig();
/* The wineserver protocol of an ntdll.so build string ("wine-11.0" -> 930); 0 = not decoded. */
unsigned WsProtocolForBuild(const std::string& build);
/* The build string of the ntdll.so process Pid maps (via /proc/<pid>/map_files, else the path), or "";
 * Path is set to the mapping's path. Results are cached by path. */
std::string WsNtdllBuild(uint32_t pid, std::string& path);
void WsNtdllReset();
/* "wineserver:<request>" for a protocol-930 request number (a static string). */
const char* WsRequestName(uint32_t request);

/* One decoded record: Record is complete apart from pid/tid/start/timestamp/stack, which the caller takes
 * from Request (and TsNs). */
struct WsRecord {
    LinuxRecord record;
    const mm_ws_event* request = nullptr;   /* the request it decodes (identity, stack, PE context) */
    uint64_t tsNs = 0;                      /* CLOCK_BOOTTIME of the reply (or of the request) */
    bool collapse = false;                  /* may be collapsed by Repeated (key: text + repeatKey) */
    uint64_t repeatKey = 0;
    bool payload = false;                   /* write Bytes as a payload series of PayloadKind */
    ULONG payloadKind = 0;
    uint64_t payloadTotal = 0;
    std::vector<BYTE> bytes;
};

using WsSink = std::function<void(WsRecord&)>;

class WsDecoder {
public:
    /* Payloads false (--no-payloads): registry and volume records keep their metadata only. */
    void SetPayloads(bool payloads) { payloads_ = payloads; }
    /* One ring record (data_len already clamped to the bytes received). */
    void Event(const mm_ws_event& event, const WsSink& sink);
    /* The process exited or exec'd: its unanswered requests are written, its state dropped. */
    void Forget(uint32_t tgid, const WsSink& sink);
    void Reset();

private:
    struct Process {
        std::unordered_map<uint32_t, std::wstring> keys;   /* registry handle -> key path */
        std::unordered_map<uint32_t, uint32_t> processes;  /* process handle -> Windows pid */
        void Handed(uint32_t handle)
        {
            keys.erase(handle);
            processes.erase(handle);
        }
    };
    /* A request awaiting its reply. Its handles are resolved when it is sent: replies of different threads
     * reach the ring in scheduling order, not in the order wineserver handled them, so by the reply the
     * handle may already be closed and given out again. */
    struct Pending {
        std::unique_ptr<mm_ws_event> event;
        uint32_t winPid = 0;   /* Windows pid the request's process handle named (0 unknown) */
        std::wstring key;      /* path of the request's registry key (or parent) handle, "" if none */
    };
    struct Unix {
        uint32_t tgid = 0;
        uint64_t startNs = 0;
    };
    void Resolve(Pending& pending);
    void Decode(const Pending& pending, const mm_ws_event* reply, const WsSink& sink);
    void Emit(WsRecord& record, const WsSink& sink);
    std::wstring KeyPath(uint32_t tgid, uint32_t handle);
    void Target(uint32_t winPid, WsRecord& out);

    bool payloads_ = true;
    std::unordered_map<uint32_t, Pending> pending_;                         /* tid -> request awaiting reply */
    std::unordered_map<uint32_t, Process> processes_;                      /* tgid -> handles */
    std::unordered_map<uint32_t, Unix> winPids_;                            /* Windows pid -> unix process */
    /* shortcut: winTids_ (and the pending_ entry of a thread that dies mid-request) live until the process
     * exits or execs, a few dozen bytes per Windows thread; drop them on MM_THREAD_EXIT if a client churns
     * through millions of threads. */
    std::unordered_map<uint32_t, Unix> winTids_;                            /* Windows tid -> unix process */
};
