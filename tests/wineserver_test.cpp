/* Self-test of the wineserver request decoder (agent/linux/wineserver.cpp) with synthetic protocol-930
 * request/reply records, as ws.bpf.h sends them. Run by build.sh; no root, no BPF. */
#include "../agent/linux/wineserver.h"
#include <fcntl.h>
#include <algorithm>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <memory>

namespace {

int failures = 0;
#define CHECK(what, condition)                                         \
    do {                                                               \
        if (!(condition)) {                                            \
            std::fprintf(stderr, "[fail] %s: %s\n", what, #condition); \
            failures++;                                                \
        }                                                              \
    } while (0)

constexpr uint32_t kTgid = 4242, kTid = 4243, kWinPid = 0x20;
uint64_t gClock = 1000000000ull;

std::unique_ptr<mm_ws_event> Event(uint32_t kind, uint32_t req, const std::vector<uint8_t>& data, uint32_t total)
{
    auto e = std::make_unique<mm_ws_event>();
    e->kind = kind;
    e->tgid = kTgid;
    e->tid = kTid;
    e->req = req;
    e->total = total;
    e->data_len = static_cast<uint32_t>(std::min<size_t>(data.size(), MM_WS_DATA));
    e->win_pid = kind == MM_WS_REQUEST ? kWinPid : 0;
    e->win_tid = kind == MM_WS_REQUEST ? kWinPid + 4 : 0;
    e->start_ns = 77;
    e->ts_ns = gClock += 1000;
    std::memcpy(e->data, data.data(), e->data_len);
    if (kind == MM_WS_REQUEST) {
        std::memcpy(e->fixed, &req, 4);
        std::memcpy(e->fixed + 4, &total, 4);
    }
    return e;
}

void Put32(mm_ws_event& e, size_t offset, uint32_t value) { std::memcpy(e.fixed + offset, &value, 4); }
void Put64(mm_ws_event& e, size_t offset, uint64_t value) { std::memcpy(e.fixed + offset, &value, 8); }

std::vector<uint8_t> U16(const char* text)
{
    std::vector<uint8_t> out;
    for (; *text; text++) {
        out.push_back(static_cast<uint8_t>(*text));
        out.push_back(0);
    }
    return out;
}

std::vector<uint8_t> Cat(std::vector<uint8_t> a, const std::vector<uint8_t>& b)
{
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

std::vector<uint8_t> Le32(uint32_t value) { return {uint8_t(value), uint8_t(value >> 8), uint8_t(value >> 16), uint8_t(value >> 24)}; }

/* objattr: rootdir, attributes, sd_len 0, name_len, name, padded to 4. */
std::vector<uint8_t> ObjAttr(uint32_t root, const char* name)
{
    const std::vector<uint8_t> text = U16(name);
    std::vector<uint8_t> out = Cat(Cat(Cat(Le32(root), Le32(0x40)), Cat(Le32(0), Le32(static_cast<uint32_t>(text.size())))), text);
    out.resize((out.size() + 3) & ~size_t(3));
    return out;
}

struct Harness {
    WsDecoder decoder;
    std::vector<WsRecord> out;
    WsSink sink = [this](WsRecord& record) { out.push_back(record); };

    /* One request and (unless reply is null) its reply; returns the records written by it. */
    std::vector<WsRecord> Run(mm_ws_event& request, mm_ws_event* reply)
    {
        out.clear();
        decoder.Event(request, sink);
        if (reply != nullptr) decoder.Event(*reply, sink);
        return out;
    }
};

std::unique_ptr<mm_ws_event> Reply(uint32_t req, uint32_t status, const std::vector<uint8_t>& data = {}, uint32_t total = 0)
{
    auto e = Event(MM_WS_REPLY, req, data, total ? total : static_cast<uint32_t>(data.size()));
    Put32(*e, 0, status);
    Put32(*e, 4, e->total);
    return e;
}

std::string Narrow(const std::wstring& text) { return std::string(text.begin(), text.end()); }

}  // namespace

int main()
{
    Harness h;
    const std::wstring root = L"\\Registry\\Machine\\Software\\MsmonProbe";

    /* (a) capture config: wanted requests, reply data, AFD codes; hot requests off. */
    const mm_ws_config config = WsCaptureConfig();
    CHECK("a", config.want[87 >> 6] & (1ull << (87 & 63)));
    CHECK("a", !(config.want[29 >> 6] & (1ull << (29 & 63))));    /* select */
    CHECK("a", !(config.want[122 >> 6] & (1ull << (122 & 63))));  /* get_message */
    CHECK("a", config.data[92 >> 6] & (1ull << (92 & 63)));
    CHECK("a", !(config.data[84 >> 6] & (1ull << (84 & 63))));   /* read_process_memory bytes are not kept */
    CHECK("a", config.ioctl_req == 138 && !(config.want[134 >> 6] & (1ull << (134 & 63))));   /* no get_async_result */
    CHECK("a", std::count(std::begin(config.ioctl_codes), std::end(config.ioctl_codes), 0x12032cu) == 1);
    CHECK("a", WsProtocolForBuild("wine-11.0") == 930 && WsProtocolForBuild("wine-10.0") == 0);

    /* (b) open_key: absolute, then relative to the returned handle. */
    {
        auto q = Event(MM_WS_REQUEST, 87, U16("\\Registry\\Machine\\Software\\MsmonProbe"), 0);
        q->total = q->data_len;
        Put32(*q, 12, 0);
        Put32(*q, 16, 0x20019);
        auto r = Reply(87, 0);
        Put32(*r, 8, 0x10);
        auto got = h.Run(*q, r.get());
        CHECK("b", got.size() == 1 && got[0].record.type == MsMonRegistryOpen && got[0].record.text == root);
        CHECK("b", got.size() == 1 && got[0].record.desiredAccess == 0x20019 && got[0].record.status == 0);
        CHECK("b", got.size() == 1 && got[0].record.sensor == MSMON_SENSOR_LINUX_EBPF_WINESERVER && got[0].collapse);
        auto q2 = Event(MM_WS_REQUEST, 87, U16("Sub"), 6);
        Put32(*q2, 12, 0x10);
        auto r2 = Reply(87, 0);
        Put32(*r2, 8, 0x14);
        got = h.Run(*q2, r2.get());
        CHECK("b", got.size() == 1 && got[0].record.text == root + L"\\Sub");
    }
    /* (c) create_key with objattr rootdir; an unknown parent handle is named. */
    {
        const auto attr = ObjAttr(0x10, "New");
        auto q = Event(MM_WS_REQUEST, 86, attr, static_cast<uint32_t>(attr.size()));
        Put32(*q, 12, 0xf003f);
        auto r = Reply(86, 0);
        Put32(*r, 8, 0x18);
        auto got = h.Run(*q, r.get());
        CHECK("c", got.size() == 1 && got[0].record.type == MsMonRegistryCreate && got[0].record.text == root + L"\\New");
        const auto lost = ObjAttr(0x99, "X");
        auto q2 = Event(MM_WS_REQUEST, 86, lost, static_cast<uint32_t>(lost.size()));
        got = h.Run(*q2, Reply(86, 0).get());
        CHECK("c", got.size() == 1 && got[0].record.text == L"hkey:0x99\\X");
    }
    const auto hello = U16("hello");
    /* (d) set_key_value REG_SZ "hello": input payload, value0 size, value1 type, detail the name. */
    {
        const auto name = U16("Probe");
        auto q = Event(MM_WS_REQUEST, 91, Cat(name, hello), 20);
        Put32(*q, 12, 0x10);
        Put32(*q, 16, 1);
        Put32(*q, 20, 10);
        auto got = h.Run(*q, Reply(91, 0).get());
        CHECK("d", got.size() == 1 && got[0].record.type == MsMonRegistrySetValue && got[0].record.detail == L"Probe");
        CHECK("d", got.size() == 1 && got[0].record.value0 == 10 && got[0].record.value1 == 1 && got[0].payload);
        CHECK("d", got.size() == 1 && got[0].bytes == hello && got[0].payloadTotal == 10 &&
                       (got[0].record.flags & MsMonFlagPayloadInput) && got[0].payloadKind == MsMonPayloadRegistryValue);
    }
    /* (e) get_key_value as RegQueryValueEx does it: a size probe (reply_size 0; wineserver answers success
     * with the total) has no payload and no unavailable flag; the read that follows is one complete chunk
     * and is not a repeat of the probe. */
    {
        auto q = Event(MM_WS_REQUEST, 92, U16("Probe"), 10);
        Put32(*q, 12, 0x10);
        auto r = Reply(92, 0);
        Put32(*r, 8, 1);
        Put32(*r, 12, 10);
        auto got = h.Run(*q, r.get());
        CHECK("e", got.size() == 1 && got[0].record.type == MsMonRegistryQuery && got[0].record.text == root);
        CHECK("e", got.size() == 1 && !got[0].payload && !(got[0].record.flags & MsMonFlagPayloadUnavailable) &&
                       got[0].record.detail == L"Probe;buffer=0");
        const uint64_t probeKey = got.size() == 1 ? got[0].repeatKey : 0;
        auto q2 = Event(MM_WS_REQUEST, 92, U16("Probe"), 10);
        Put32(*q2, 8, 10);
        Put32(*q2, 12, 0x10);
        auto r2 = Reply(92, 0, hello);
        Put32(*r2, 8, 1);
        Put32(*r2, 12, 10);
        got = h.Run(*q2, r2.get());
        CHECK("e", got.size() == 1 && got[0].record.detail == L"Probe" && got[0].record.value1 == 1);
        CHECK("e", got.size() == 1 && got[0].payload && got[0].bytes == hello && got[0].payloadTotal == 10);
        CHECK("e", got.size() == 1 && got[0].collapse && got[0].repeatKey != probeKey);
    }
    /* (f) a failed query: payload_unavailable with the reason first. */
    {
        auto q = Event(MM_WS_REQUEST, 92, U16("Gone"), 8);
        Put32(*q, 12, 0x10);
        auto got = h.Run(*q, Reply(92, 0xC0000034).get());
        CHECK("f", got.size() == 1 && (got[0].record.flags & MsMonFlagPayloadUnavailable) &&
                       got[0].record.detail == L"query_failed;value=Gone" && got[0].record.status == (int32_t)0xC0000034);
    }
    /* (g) enum_key_value (full): the name in the detail, the data as the payload; enum_key's name. */
    {
        auto q = Event(MM_WS_REQUEST, 93, {}, 0);
        Put32(*q, 8, 20);
        Put32(*q, 12, 0x10);
        Put32(*q, 16, 3);
        Put32(*q, 20, 1);
        auto r = Reply(93, 0, Cat(U16("Probe"), hello));
        Put32(*r, 8, 1);
        Put32(*r, 12, 20);
        Put32(*r, 16, 10);
        auto got = h.Run(*q, r.get());
        CHECK("g", got.size() == 1 && got[0].record.type == MsMonRegistryEnumerate && got[0].record.detail == L"Probe");
        CHECK("g", got.size() == 1 && got[0].record.value0 == 3 && got[0].bytes == hello && got[0].payloadTotal == 10);
        auto q2 = Event(MM_WS_REQUEST, 90, {}, 0);
        Put32(*q2, 12, 0x10);
        auto r2 = Reply(90, 0, U16("Sub"));
        Put32(*r2, 44, 6);
        got = h.Run(*q2, r2.get());
        CHECK("g", got.size() == 1 && got[0].record.detail == L"Sub" && !got[0].payload);
    }
    /* (h) open_process: the Windows pid of another tracked client maps to its unix pid. */
    {
        auto other = Event(MM_WS_REQUEST, 87, U16("\\Registry\\Machine"), 34);
        other->tgid = 5000;
        other->tid = 5000;
        other->win_pid = 2457;
        h.Run(*other, nullptr);
        auto q = Event(MM_WS_REQUEST, 27, {}, 0);
        Put32(*q, 12, 2457);
        Put32(*q, 16, 0x10);
        auto r = Reply(27, 0);
        Put32(*r, 8, 0x20);
        auto got = h.Run(*q, r.get());
        CHECK("h", got.size() == 1 && got[0].record.type == MsMonProcessHandle && got[0].record.target == 5000);
        CHECK("h", got.size() == 1 && got[0].record.desiredAccess == 0x10 && got[0].record.value1 == 0x10);
        CHECK("h", got.size() == 1 && got[0].record.detail == L"open_process;win_pid=2457;handle=0x20");
        /* A stronger open of the same process is not a repeat of the weaker one. */
        auto q2 = Event(MM_WS_REQUEST, 27, {}, 0);
        Put32(*q2, 12, 2457);
        Put32(*q2, 16, 0x38);
        auto got2 = h.Run(*q2, Reply(27, 0).get());
        CHECK("h", got.size() == 1 && got2.size() == 1 && got2[0].repeatKey != got[0].repeatKey);
    }
    /* (i) read_process_memory through that handle: value0 1, value1 the length, the target. */
    {
        auto q = Event(MM_WS_REQUEST, 84, {}, 0);
        Put32(*q, 8, 16);
        Put32(*q, 12, 0x20);
        Put64(*q, 16, 0x401000);
        auto got = h.Run(*q, Reply(84, 0).get());
        CHECK("i", got.size() == 1 && got[0].record.value0 == 1 && got[0].record.value1 == 16 && got[0].record.target == 5000);
        CHECK("i", got.size() == 1 && Narrow(got[0].record.detail).rfind("read_process_memory;handle=0x20;win_pid=2457;address=0x401000", 0) == 0);
    }
    /* (i2) Wine reuses the lowest free handle: after close_handle, new_process gets 0x20 for a child. */
    {
        auto close = Event(MM_WS_REQUEST, 21, {}, 0);
        Put32(*close, 12, 0x20);
        CHECK("i2", h.Run(*close, Reply(21, 0).get()).empty());
        auto spawn = Event(MM_WS_REQUEST, 0, {}, 0);
        auto spawned = Reply(0, 0);
        Put32(*spawned, 8, 0x1c);
        Put32(*spawned, 12, 3000);
        Put32(*spawned, 16, 0x20);
        CHECK("i2", h.Run(*spawn, spawned.get()).empty());
        auto q = Event(MM_WS_REQUEST, 85, {}, 4);
        Put32(*q, 12, 0x20);
        auto got = h.Run(*q, Reply(85, 0).get());
        CHECK("i2", got.size() == 1 && got[0].record.target == 0 &&
                        Narrow(got[0].record.detail).find(";win_pid=3000;") != std::string::npos);
        /* get_next_process hands out 0x20 again: its pid is unknown, so no win_pid. */
        auto next = Event(MM_WS_REQUEST, 293, {}, 0);
        auto nextReply = Reply(293, 0);
        Put32(*nextReply, 8, 0x20);
        h.Run(*next, nextReply.get());
        got = h.Run(*q, Reply(85, 0).get());
        CHECK("i2", got.size() == 1 && Narrow(got[0].record.detail).find("win_pid") == std::string::npos);
        /* get_window_tree: +8 is the parent window, not a count. */
        auto tree = Event(MM_WS_REQUEST, 154, {}, 0);
        Put32(*tree, 12, 0x10020);
        auto treeReply = Reply(154, 0);
        Put32(*treeReply, 8, 0x10010);
        got = h.Run(*tree, treeReply.get());
        CHECK("i2", got.size() == 1 && got[0].record.value1 == 0 &&
                        Narrow(got[0].record.detail).find(";parent=0x10010") != std::string::npos);
    }
    /* (i3) Replies of two threads arrive out of wineserver's order: handles are resolved at request time. */
    {
        constexpr uint32_t kTidA = kTid + 10, kTidB = kTid + 11;
        auto y = Event(MM_WS_REQUEST, 1, {}, 0);   /* process Y (tgid 6000, Windows pid 3100) is known */
        y->tgid = y->tid = 6000;
        y->win_pid = 3100;
        h.Run(*y, nullptr);
        auto as = [](std::unique_ptr<mm_ws_event> e, uint32_t tid) { e->tid = tid; return e; };
        auto open = [&](uint32_t tid, uint32_t winPid, uint32_t handle) {
            auto q = as(Event(MM_WS_REQUEST, 27, {}, 0), tid);
            Put32(*q, 12, winPid);
            auto r = as(Reply(27, 0), tid);
            Put32(*r, 8, handle);
            return std::make_pair(std::move(q), std::move(r));
        };
        auto memory = [&](uint32_t tid) {
            auto q = as(Event(MM_WS_REQUEST, 84, {}, 0), tid);
            Put32(*q, 12, 0x48);
            return q;
        };
        auto close = as(Event(MM_WS_REQUEST, 21, {}, 0), kTidA);
        Put32(*close, 12, 0x48);
        auto closed = as(Reply(21, 0), kTidA);
        auto x = open(kTidA, 2457, 0x48);   /* 0x48 names X (tgid 5000) */
        h.Run(*x.first, x.second.get());
        /* (1) A close request, B open request (gets 0x48), B reply, A reply: 0x48 names Y. */
        auto b = open(kTidB, 3100, 0x48);
        h.Run(*close, nullptr);
        h.Run(*b.first, b.second.get());
        h.Run(*closed, nullptr);
        auto got = h.Run(*memory(kTidB), as(Reply(84, 0), kTidB).get());
        CHECK("i3", got.size() == 1 && got[0].record.target == 6000);
        /* (2) A reads through 0x48 (Y); B closes it and opens X into 0x48, both replying first: A's record names Y. */
        auto read = memory(kTidA);
        h.Run(*read, nullptr);
        close->tid = closed->tid = kTidB;
        h.Run(*close, closed.get());
        auto bx = open(kTidB, 2457, 0x48);
        h.Run(*bx.first, bx.second.get());
        got = h.Run(*as(Reply(84, 0), kTidA), nullptr);
        CHECK("i3", got.size() == 1 && got[0].record.target == 6000 &&
                        Narrow(got[0].record.detail).find(";win_pid=3100;") != std::string::npos);
        got = h.Run(*memory(kTidB), as(Reply(84, 0), kTidB).get());
        CHECK("i3", got.size() == 1 && got[0].record.target == 5000);
    }
    /* (j) create_file: the unix path as text, the NT name in the detail, disposition << 24 | options. */
    {
        const std::string unixPath = "/tmp/msmon-probe.txt";
        const auto data = Cat(ObjAttr(0, "\\??\\unix\\tmp\\msmon-probe.txt"), std::vector<uint8_t>(unixPath.begin(), unixPath.end()));
        auto q = Event(MM_WS_REQUEST, 44, data, static_cast<uint32_t>(data.size()));
        Put32(*q, 12, 0x80100080);
        Put32(*q, 20, 3);
        Put32(*q, 24, 0x60);
        auto r = Reply(44, 0);
        Put32(*r, 8, 0x24);
        auto got = h.Run(*q, r.get());
        CHECK("j", got.size() == 1 && got[0].record.type == MsMonFileCreate && got[0].record.text == L"/tmp/msmon-probe.txt");
        CHECK("j", got.size() == 1 && got[0].record.value0 == ((3ull << 24) | 0x60) && got[0].record.value1 == 0x24);
        CHECK("j", got.size() == 1 && Narrow(got[0].record.detail).rfind("create_file;nt=\\??\\unix\\tmp\\msmon-probe.txt;", 0) == 0);
    }
    /* (k) AFD connect: network_connect with the endpoint; IPv6 too. */
    {
        std::vector<uint8_t> in = Cat(Le32(16), Le32(1));
        const uint8_t sin[16] = {2, 0, 0, 9, 127, 0, 0, 1};
        in.insert(in.end(), sin, sin + 16);
        auto q = Event(MM_WS_REQUEST, 138, in, static_cast<uint32_t>(in.size()));
        Put32(*q, 12, 0x12032c);
        Put32(*q, 16, 0x28);
        auto got = h.Run(*q, Reply(138, 0).get());
        CHECK("k", got.size() == 1 && got[0].record.type == MsMonNetworkConnect && got[0].record.text == L"127.0.0.1:9");
        CHECK("k", got.size() == 1 && got[0].record.value0 == 0 && got[0].record.value1 == 9);
        CHECK("k", got.size() == 1 && Narrow(got[0].record.detail).rfind("connect;family=2;ws=ioctl;afd=connect;", 0) == 0);
        std::vector<uint8_t> in6 = Cat(Le32(28), Le32(0));
        uint8_t sin6[28] = {23, 0, 1, 0xbb};
        sin6[23] = 1;
        in6.insert(in6.end(), sin6, sin6 + 28);
        auto q2 = Event(MM_WS_REQUEST, 138, in6, static_cast<uint32_t>(in6.size()));
        Put32(*q2, 12, 0x12032c);
        got = h.Run(*q2, Reply(138, 0).get());
        CHECK("k", got.size() == 1 && got[0].record.text == L"[0:0:0:0:0:0:0:1]:443" &&
                       Narrow(got[0].record.detail).rfind("connect;family=10;", 0) == 0);
        std::vector<uint8_t> bind = Le32(0);
        bind.insert(bind.end(), sin, sin + 16);
        auto q3 = Event(MM_WS_REQUEST, 138, bind, static_cast<uint32_t>(bind.size()));
        Put32(*q3, 12, 0x12003);
        got = h.Run(*q3, Reply(138, 0).get());
        CHECK("k", got.size() == 1 && got[0].record.type == MsMonNetworkAccept && got[0].record.text == L"127.0.0.1:9" &&
                       Narrow(got[0].record.detail).rfind("bind;family=2;ws=ioctl;afd=bind", 0) == 0);
    }
    /* (l) a pending connect is written at once with STATUS_PENDING (Wine completes it by APC, not get_async_result). */
    {
        std::vector<uint8_t> in = Cat(Le32(16), Le32(0));
        const uint8_t sin[16] = {2, 0, 0x1f, 0x90, 10, 0, 0, 2};
        in.insert(in.end(), sin, sin + 16);
        auto q = Event(MM_WS_REQUEST, 138, in, static_cast<uint32_t>(in.size()));
        Put32(*q, 12, 0x12032c);
        auto got = h.Run(*q, Reply(138, 0x103).get());
        CHECK("l", got.size() == 1 && got[0].record.text == L"10.0.0.2:8080" && got[0].record.status == 0x103 &&
                       Narrow(got[0].record.detail).find(";pending") != std::string::npos);
    }
    /* (m) a request without its reply is written when the process goes. */
    {
        auto q = Event(MM_WS_REQUEST, 88, {}, 0);
        Put32(*q, 12, 0x10);
        h.Run(*q, nullptr);
        CHECK("m", h.out.empty());
        h.out.clear();
        h.decoder.Forget(kTgid, h.sink);
        CHECK("m", h.out.size() == 1 && h.out[0].record.type == MsMonRegistryDelete && h.out[0].record.detail == L"no_reply");
        /* Forget dropped the handle table. */
        auto q2 = Event(MM_WS_REQUEST, 88, {}, 0);
        Put32(*q2, 12, 0x10);
        auto got = h.Run(*q2, Reply(88, 0).get());
        CHECK("m", got.size() == 1 && got[0].record.text == L"hkey:0x10");
    }
    /* (n) create_mapping: unnamed sections are skipped, named ones are file_section. */
    {
        const auto unnamed = ObjAttr(0, "");
        auto q = Event(MM_WS_REQUEST, 63, unnamed, static_cast<uint32_t>(unnamed.size()));
        CHECK("n", h.Run(*q, Reply(63, 0).get()).empty());
        const auto named = ObjAttr(0x30, "MsmonShared");
        auto q2 = Event(MM_WS_REQUEST, 63, named, static_cast<uint32_t>(named.size()));
        Put32(*q2, 20, 3);   /* file_access: FILE_READ_DATA | FILE_WRITE_DATA (PAGE_READWRITE) */
        auto got = h.Run(*q2, Reply(63, 0).get());
        CHECK("n", got.size() == 1 && got[0].record.type == MsMonFileSection && got[0].record.text == L"handle:0x30\\MsmonShared" &&
                       got[0].record.value1 == 0 && Narrow(got[0].record.detail).find(";file_access=0x3;") != std::string::npos);
    }
    /* (o) list_processes: file_query_information system:list_processes with the count. */
    {
        auto q = Event(MM_WS_REQUEST, 76, {}, 0);
        auto r = Reply(76, 0);
        Put32(*r, 12, 57);
        auto got = h.Run(*q, r.get());
        CHECK("o", got.size() == 1 && got[0].record.type == MsMonFileQueryInformation &&
                       got[0].record.text == L"system:list_processes" && got[0].record.value1 == 57 && got[0].collapse);
    }
    /* (p) a 10000-byte value captured at 8192: chunk 0 of 2, partial (whole first chunk), not final. */
    {
        auto q = Event(MM_WS_REQUEST, 92, U16("Big"), 6);
        Put32(*q, 8, 10000);   /* the client's buffer holds the whole value */
        Put32(*q, 12, 0x10);
        auto r = Reply(92, 0, std::vector<uint8_t>(10000, 0x41));
        Put32(*r, 8, 3);
        Put32(*r, 12, 10000);
        auto got = h.Run(*q, r.get());
        const bool ok = got.size() == 1 && got[0].payload;
        CHECK("p", ok && got[0].bytes.size() == MSMON_PAYLOAD_CHUNK_BYTES && got[0].payloadTotal == 10000);
        CHECK("p", ok && (got[0].payloadTotal + MSMON_PAYLOAD_CHUNK_BYTES - 1) / MSMON_PAYLOAD_CHUNK_BYTES == 2 &&
                       got[0].bytes.size() < got[0].payloadTotal);
    }
    /* (q) set_key_value of 9000 bytes with a 10-byte name: only 8182 value bytes arrive -> truncated. */
    {
        auto q = Event(MM_WS_REQUEST, 91, Cat(U16("Probe"), std::vector<uint8_t>(9000, 1)), 9010);
        Put32(*q, 12, 0x10);
        Put32(*q, 16, 3);
        Put32(*q, 20, 10);
        auto got = h.Run(*q, Reply(91, 0).get());
        CHECK("q", got.size() == 1 && !got[0].payload && (got[0].record.flags & MsMonFlagPayloadUnavailable) &&
                       got[0].record.detail == L"payload_truncated;value=Probe" && got[0].record.value0 == 9000);
    }
    /* (r) --no-payloads: the same records, no payload and no unavailable flag. */
    {
        h.decoder.SetPayloads(false);
        auto q = Event(MM_WS_REQUEST, 91, Cat(U16("Probe"), hello), 20);
        Put32(*q, 20, 10);
        auto got = h.Run(*q, Reply(91, 0).get());
        CHECK("r", got.size() == 1 && !got[0].payload && got[0].record.flags == 0 && got[0].record.detail == L"Probe");
        /* Window titles are content: their length only. */
        auto q2 = Event(MM_WS_REQUEST, 157, {}, 0);
        Put32(*q2, 12, 0x1234);
        got = h.Run(*q2, Reply(157, 0, U16("Secret")).get());
        CHECK("r", got.size() == 1 && Narrow(got[0].record.detail).find("text=") == std::string::npos &&
                       Narrow(got[0].record.detail).find(";text_bytes=12") != std::string::npos);
        h.decoder.SetPayloads(true);
    }
    /* (s) the gate: the build string of the ntdll.so this process maps. */
    {
        mkdir("build/tests/ws", 0755);
        mkdir("build/tests/ws/x86_64-unix", 0755);
        const char* path = "build/tests/ws/x86_64-unix/ntdll.so";
        const int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        static const char content[] = "FAKE\0wine-11.0\0";
        CHECK("s", fd >= 0 && write(fd, content, sizeof(content)) == static_cast<ssize_t>(sizeof(content)));
        void* map = fd >= 0 ? mmap(nullptr, sizeof(content), PROT_READ, MAP_PRIVATE, fd, 0) : MAP_FAILED;
        std::string where;
        CHECK("s", map != MAP_FAILED && WsNtdllBuild(static_cast<uint32_t>(getpid()), where) == "wine-11.0");
        CHECK("s", where.size() > 9 && where.compare(where.size() - 9, 9, "/ntdll.so") == 0);
        if (map != MAP_FAILED) munmap(map, sizeof(content));
        if (fd >= 0) close(fd);
        WsNtdllReset();
        CHECK("s", WsNtdllBuild(static_cast<uint32_t>(getpid()), where) == "" && where.empty());
    }

    if (failures != 0) {
        std::fprintf(stderr, "wineserver decoder self-test: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("wineserver decoder self-test passed\n");
    return 0;
}
