#include "../agent/integrations.h"
#include <iostream>

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

    TelemetryEvent event = KFilterDecisionEvent(source, 77);
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
    event = KFilterDecisionEvent(source, 77);
    ok &= Check(event.detail.find(L"decision=deny") != std::wstring::npos &&
                event.detail.find(L"would_deny") == std::wstring::npos,
                "enforced denial is deny");

    source.Action = 1;
    event = KFilterDecisionEvent(source, 77);
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

    JsonlWriter writer(L"build\\tests\\integration-events.jsonl", 0);
    ok &= Check(writer.Open(), "open JSONL output");
    ok &= Check(writer.Write(TelemetryJson(event)), "write KFilter JSON");
    ok &= Check(writer.Write(TelemetryJson(integrity)), "write CodeIntegrity JSON");
    ok &= Check(writer.Close(), "close JSONL output");

    if (!ok) return 1;
    std::cout << "integration regression passed\n";
    return 0;
}
