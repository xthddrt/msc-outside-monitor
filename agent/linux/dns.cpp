#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

/*
 * DNS wire format (RFC 1035) for the etw_dns records the eBPF sensor writes from the client's own
 * port-53 traffic (bpf.cpp). Pure functions over untrusted bytes: every read is bounds-checked,
 * compression pointers must point backwards (so a name always ends), and counts are capped.
 * build.sh compiles this file alone with MSMON_DNS_SELF_TEST and runs the self-test at its end.
 */

namespace {

uint16_t Be16(const uint8_t* p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

/* A label byte as presentation text: letters, digits, '-' and '_' as they are, anything else
 * (including '.', ';', '|', '=' and spaces) as \DDD, so a name cannot break the detail fields. */
void AppendLabel(std::wstring& out, const uint8_t* label, size_t length)
{
    for (size_t index = 0; index < length; index++) {
        const uint8_t c = label[index];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
            out += static_cast<wchar_t>(c);
        } else {
            wchar_t escaped[8];
            swprintf(escaped, 8, L"\\%03u", static_cast<unsigned>(c));
            out += escaped;
        }
    }
}

/* The (possibly compressed) name at Offset; Next is the offset after it in the message. */
bool ReadName(const uint8_t* data, size_t size, size_t offset, std::wstring& name, size_t& next)
{
    name.clear();
    next = 0;
    size_t position = offset;
    size_t wire = 0;
    for (unsigned labels = 0; labels < 128; labels++) {
        if (position >= size) return false;
        const uint8_t length = data[position];
        if ((length & 0xC0) == 0xC0) {
            if (position + 1 >= size) return false;
            const size_t target = static_cast<size_t>(((length & 0x3F) << 8) | data[position + 1]);
            if (target >= position) return false;   /* only backwards: no loops */
            if (next == 0) next = position + 2;
            position = target;
            continue;
        }
        if ((length & 0xC0) != 0) return false;     /* extended label types are not used */
        if (length == 0) {
            if (next == 0) next = position + 1;
            if (name.empty()) name = L".";
            return true;
        }
        if (position + 1 + length > size || (wire += length + 1) > 255) return false;
        if (!name.empty()) name += L'.';
        AppendLabel(name, data + position + 1, length);
        position += 1 + length;
    }
    return false;
}

const wchar_t* TypeName(uint16_t type)
{
    switch (type) {
    case 1: return L"A";
    case 2: return L"NS";
    case 5: return L"CNAME";
    case 12: return L"PTR";
    case 28: return L"AAAA";
    default: return nullptr;
    }
}

}  // namespace

/* One DNS message as the etw_dns record carries it: Name is the first question's name;
 * Detail is "query_type=N;dns_id=N", and for a response also ";rcode=N" and, when it has
 * answers, ";answers=TYPE value|..." (A/AAAA addresses, NS/CNAME/PTR names, TYPEnn for other
 * types). False when Data is not a well-formed message with a question. */
bool DnsDescribe(const uint8_t* data, size_t size, std::wstring& name, std::wstring& detail, bool& response)
{
    name.clear();
    detail.clear();
    response = false;
    if (data == nullptr || size < 12) return false;
    const uint16_t id = Be16(data);
    const uint16_t flags = Be16(data + 2);
    const unsigned questions = Be16(data + 4);
    const unsigned answers = Be16(data + 6);
    if (questions == 0 || questions > 16) return false;
    size_t position = 12;
    uint16_t queryType = 0;
    for (unsigned index = 0; index < questions; index++) {
        std::wstring questionName;
        size_t next = 0;
        if (!ReadName(data, size, position, questionName, next) || next + 4 > size) return false;
        if (index == 0) {
            name = questionName;
            queryType = Be16(data + next);
        }
        position = next + 4;
    }
    response = (flags & 0x8000) != 0;
    detail = L"query_type=" + std::to_wstring(queryType) + L";dns_id=" + std::to_wstring(id);
    if (!response) return true;
    detail += L";rcode=" + std::to_wstring(flags & 0xF);
    std::wstring list;
    for (unsigned index = 0; index < answers && index < 32; index++) {
        std::wstring owner;
        size_t next = 0;
        if (!ReadName(data, size, position, owner, next) || next + 10 > size) break;
        const uint16_t type = Be16(data + next);
        const size_t length = Be16(data + next + 8);
        const size_t rdata = next + 10;
        if (rdata + length > size) break;
        position = rdata + length;
        const wchar_t* typeName = TypeName(type);
        std::wstring value;
        if ((type == 1 && length == 4) || (type == 28 && length == 16)) {
            char text[INET6_ADDRSTRLEN] = {};
            inet_ntop(type == 1 ? AF_INET : AF_INET6, data + rdata, text, sizeof(text));
            value.assign(text, text + strnlen(text, sizeof(text)));
        } else if (type == 2 || type == 5 || type == 12) {
            size_t ignored = 0;
            if (!ReadName(data, size, rdata, value, ignored)) continue;
        } else {
            typeName = nullptr;
        }
        if (!list.empty()) list += L'|';
        list += typeName != nullptr ? std::wstring(typeName) + L" " + value : L"TYPE" + std::to_wstring(type);
    }
    if (!list.empty()) detail += L";answers=" + list;
    return true;
}

/* DNS over TCP: appends Bytes to Stream (one direction of one socket) and returns the complete
 * messages it now holds; each is framed by a 2-byte big-endian length (RFC 1035 4.2.2). */
std::vector<std::string> DnsTcpTake(std::string& stream, const uint8_t* bytes, size_t size)
{
    std::vector<std::string> messages;
    stream.append(reinterpret_cast<const char*>(bytes), size);
    while (stream.size() >= 2) {
        const size_t length = Be16(reinterpret_cast<const uint8_t*>(stream.data()));
        if (stream.size() < 2 + length) break;
        messages.push_back(stream.substr(2, length));
        stream.erase(0, 2 + length);
    }
    return messages;
}

#ifdef MSMON_DNS_SELF_TEST
int main()
{
    int failures = 0;
    auto check = [&](bool ok, const char* what) {
        if (!ok) {
            std::fprintf(stderr, "dns self-test FAILED: %s\n", what);
            failures++;
        }
    };
    /* The query tests/fixtures/linux_ebpf_probe.c sends: id 0x4d53, RD, msmon-probe.example A. */
    const uint8_t query[] = {0x4d, 0x53, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                             11, 'm', 's', 'm', 'o', 'n', '-', 'p', 'r', 'o', 'b', 'e',
                             7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1};
    std::wstring name, detail;
    bool response = true;
    check(DnsDescribe(query, sizeof(query), name, detail, response) && !response &&
              name == L"msmon-probe.example" && detail == L"query_type=1;dns_id=19795",
          "a query names its question, type and id");

    /* Response: CNAME (compressed to the question) then an A and an AAAA for the CNAME target. */
    std::vector<uint8_t> answer = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0,
                                   3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
                                   0, 1, 0, 1};
    const uint8_t cname[] = {0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 7, 4, 'e', 'd', 'g', 'e', 0xC0, 16};
    answer.insert(answer.end(), cname, cname + sizeof(cname));   /* edge.example.com, target at 45 */
    const uint8_t a[] = {0xC0, 45, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34};
    answer.insert(answer.end(), a, a + sizeof(a));
    const uint8_t aaaa[] = {0xC0, 45, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 0x26, 0x06, 0x28, 0, 0x02, 0x20, 0, 1,
                            0, 0, 0, 0, 0, 0, 0, 1};
    answer.insert(answer.end(), aaaa, aaaa + sizeof(aaaa));
    check(DnsDescribe(answer.data(), answer.size(), name, detail, response) && response &&
              name == L"www.example.com" &&
              detail == L"query_type=1;dns_id=4660;rcode=0;answers=CNAME edge.example.com|A 93.184.216.34|"
                        L"AAAA 2606:2800:220:1::1",
          "a response lists CNAME, A and AAAA answers");

    std::vector<uint8_t> nxdomain(answer.begin(), answer.begin() + 33);
    nxdomain[3] = 0x83;   /* rcode 3 */
    nxdomain[7] = 0;      /* no answers */
    check(DnsDescribe(nxdomain.data(), nxdomain.size(), name, detail, response) && response &&
              detail == L"query_type=1;dns_id=4660;rcode=3",
          "NXDOMAIN keeps its rcode and has no answers field");

    const uint8_t odd[] = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'a', ';', 'b', 0, 0, 16, 0, 1};
    check(DnsDescribe(odd, sizeof(odd), name, detail, response) && name == L"a\\059b",
          "a label byte that would break the detail is escaped");

    check(!DnsDescribe(query, 11, name, detail, response), "a short header is refused");
    std::vector<uint8_t> noQuestion(query, query + sizeof(query));
    noQuestion[5] = 0;
    check(!DnsDescribe(noQuestion.data(), noQuestion.size(), name, detail, response), "no question is refused");
    std::vector<uint8_t> truncated(query, query + sizeof(query) - 3);
    check(!DnsDescribe(truncated.data(), truncated.size(), name, detail, response), "a truncated question is refused");
    const uint8_t loop[] = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1};
    check(!DnsDescribe(loop, sizeof(loop), name, detail, response), "a pointer to itself is refused");
    const uint8_t forward[] = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 14, 1, 'a', 0, 0, 1, 0, 1};
    check(!DnsDescribe(forward, sizeof(forward), name, detail, response), "a forward pointer is refused");
    const uint8_t overlong[] = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 64, 'a', 0};
    check(!DnsDescribe(overlong, sizeof(overlong), name, detail, response), "a label over 63 bytes is refused");

    /* TCP framing: a length split from its body across calls, then two messages in one call. */
    std::string stream;
    const uint8_t length[] = {0, sizeof(query)};
    check(DnsTcpTake(stream, length, 1).empty() && DnsTcpTake(stream, length + 1, 1).empty(),
          "a length alone is no message");
    check(DnsTcpTake(stream, query, 20).empty(), "half a message is no message");
    std::vector<std::string> taken = DnsTcpTake(stream, query + 20, sizeof(query) - 20);
    check(taken.size() == 1 && taken[0] == std::string(reinterpret_cast<const char*>(query), sizeof(query)) &&
              stream.empty(),
          "the message completes across three calls");
    std::string two;
    for (int copy = 0; copy < 2; copy++) {
        two.append(reinterpret_cast<const char*>(length), 2);
        two.append(reinterpret_cast<const char*>(query), sizeof(query));
    }
    taken = DnsTcpTake(stream, reinterpret_cast<const uint8_t*>(two.data()), two.size() - 1);
    check(taken.size() == 1 && stream.size() == sizeof(query) + 1, "a second, unfinished message waits");

    if (failures == 0) std::puts("dns self-test passed");
    return failures == 0 ? 0 : 1;
}
#endif
