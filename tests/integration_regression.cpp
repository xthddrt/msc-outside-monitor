#include "../agent/integrations.h"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static bool Check(bool condition, const char* message)
{
    if (!condition) std::cerr << "FAIL: " << message << "\n";
    return condition;
}

int main()
{
    bool ok = true;
    ok &= Check(sizeof(KFILTER_EVENT_4) == 1064 && sizeof(KFILTER_STATUS_4) == 80 &&
                sizeof(KFILTER_READ_REQUEST_4) == 8, "ABI 4 layouts");
    KFILTER_EVENT_4 source{};
    source.Timestamp = 123456789;
    source.ProcessId = 42;
    source.Target = 4;
    source.Action = 3;
    source.Flags = KFILTER_EVENT_FLAG_WOULD_DENY_4;
    source.Status = static_cast<long>(0xC0000022);
    source.Value = 0x81;
    source.RuleId = 17;
    source.Generation = 9;
    wcscpy_s(source.Path, L"\\REGISTRY\\MACHINE\\Synthetic");

    TelemetryEvent event = KFilterDecisionEvent(source, 77, 1);
    TelemetryEvent second = KFilterDecisionEvent(source, 77, 2);
    ok &= Check(event.header.Sequence == 1 && second.header.Sequence == 2,
                "decisions are numbered from 1");
    ok &= Check(event.header.Sequence != 0 && second.header.Sequence != 0,
                "a decision sequence is never zero");
    ok &= Check(event.header.Sequence != second.header.Sequence,
                "decision identities are unique");
    ok &= Check(event.header.Type == MsMonKfilterDecision, "decision event type");
    ok &= Check(event.header.SessionId == 77 && event.header.ProcessId == 42, "session and PID");
    ok &= Check(event.header.Timestamp == source.Timestamp && event.header.Status == source.Status,
                "timestamp and status");
    ok &= Check(event.header.DesiredAccess == source.Value && event.header.Value0 == source.Target &&
                event.header.Value1 == source.RuleId, "rights, target, and rule");
    ok &= Check(event.text == source.Path && event.component == L"kfilter.sys", "path and component");
    ok &= Check(event.detail.find(L"decision=would_deny") != std::wstring::npos,
                "audit denial is would_deny");
    ok &= Check(event.detail.find(L"rule_id=17") != std::wstring::npos &&
                event.detail.find(L"generation=9") != std::wstring::npos, "rule metadata");

    source.Flags = 0;
    event = KFilterDecisionEvent(source, 77, 3);
    ok &= Check(event.detail.find(L"decision=deny") != std::wstring::npos &&
                event.detail.find(L"would_deny") == std::wstring::npos,
                "enforced denial is deny");

    source.Action = 1;
    event = KFilterDecisionEvent(source, 77, 4);
    ok &= Check(event.detail.find(L"decision=audit") != std::wstring::npos,
                "explicit audit rule stays audit");

    KFILTER_STATUS_4 start{};
    start.DroppedEvents = 3;
    KFILTER_STATUS_4 end = start;
    end.AbiVersion = 4;
    end.Mode = 2;
    end.DroppedEvents = 8;
    const std::wstring status = KFilterStatusDetail(end, &start);
    ok &= Check(status.find(L"mode=block") != std::wstring::npos &&
                status.find(L"dropped_delta=5") != std::wstring::npos, "status and drop delta");
    ok &= Check(EventTypeName(MsMonEtwCodeIntegrity) == "etw_code_integrity" &&
                EventTypeName(MsMonKfilterDecision) == "kfilter_decision", "JSON event names");

    TelemetryEvent integrity;
    integrity.source = "etw";
    integrity.header.Size = sizeof(integrity.header);
    integrity.header.Version = MSMON_PROTOCOL_VERSION;
    integrity.header.Type = MsMonEtwCodeIntegrity;
    integrity.header.Flags = MsMonFlagObserverRecord;
    integrity.header.Sequence = 1;
    integrity.header.Timestamp = source.Timestamp;
    integrity.header.SessionId = 77;
    integrity.header.ProcessId = 4;
    integrity.header.Value0 = 3077;
    integrity.component = L"WDAC";
    integrity.text = L"C:\\Synthetic\\BlackCat64.sys";
    integrity.detail = L"decision=blocked;event_id=3077";

    TelemetryEvent firstDecision = KFilterDecisionEvent(source, 77, 1);
    TelemetryEvent secondDecision = KFilterDecisionEvent(source, 77, 2);

    JsonlWriter writer(L"build\\tests\\integration-events.jsonl", 0);
    ok &= Check(writer.Open(), "open JSONL output");
    ok &= Check(writer.Write(TelemetryJson(firstDecision)), "write first KFilter JSON");
    ok &= Check(writer.Write(TelemetryJson(secondDecision)), "write second KFilter JSON");
    ok &= Check(writer.Write(TelemetryJson(integrity)), "write CodeIntegrity JSON");
    ok &= Check(writer.Close(), "close JSONL output");

    /* verify_log.py keys written events on (source, sequence); zero would hide them. */
    std::ifstream written(L"build\\tests\\integration-events.jsonl");
    std::vector<std::string> sequences;
    std::string line;
    while (std::getline(written, line)) {
        if (line.find("\"type\":\"kfilter_decision\"") == std::string::npos) continue;
        const size_t at = line.find("\"sequence\":");
        ok &= Check(at != std::string::npos, "written decision carries a sequence");
        if (at == std::string::npos) continue;
        size_t stop = line.find_first_of(",}", at);
        if (stop == std::string::npos) stop = line.size();
        sequences.push_back(line.substr(at + 11, stop - at - 11));
    }
    ok &= Check(sequences.size() == 2, "two decisions were written");
    ok &= Check(sequences.size() == 2 && sequences[0] != "0" && sequences[1] != "0" &&
                sequences[0] != sequences[1],
                "written decisions are numbered and distinct");

    const std::wstring manifestOn = IntegrationCoverageState(true, L"kfilter_available");
    ok &= Check(manifestOn.find(L"etw=wmi,dns,rpc,tcp,codeintegrity") != std::wstring::npos,
                "manifest lists the CodeIntegrity provider");
    ok &= Check(manifestOn.find(L"kfilter=kfilter_available") != std::wstring::npos,
                "manifest reports the KFilter state");
    ok &= Check(manifestOn.find(L"wdac=etw") != std::wstring::npos,
                "manifest reports WDAC ingestion");
    const std::wstring manifestOff = IntegrationCoverageState(false, L"kfilter_unavailable");
    ok &= Check(manifestOff.find(L"etw=disabled") != std::wstring::npos,
                "manifest shows ETW disabled");
    ok &= Check(manifestOff.find(L"wdac=disabled") != std::wstring::npos,
                "manifest shows WDAC disabled");

    if (!ok) return 1;
    std::cout << "integration regression passed\n";
    return 0;
}
