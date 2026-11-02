#include "../agent/integrations.h"
#include "../agent/classify.h"
#include "../agent/etw.h"
#include "../agent/rpc_names.h"
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
    ProcessScope processScope;
    processScope.AddProcess(41, 100, L"C:\\client.exe");
    ok &= Check(processScope.IsTracked(41, 100), "tracked PID accepts its process incarnation");
    ok &= Check(!processScope.IsTracked(41, 101), "tracked PID rejects a reused incarnation");
    ok &= Check(!processScope.IsTracked(42, 100), "unknown PID is not tracked");
    ok &= Check(processScope.Path(41, 100) == L"C:\\client.exe",
                "a process path is borrowed only for the exact incarnation");
    ok &= Check(processScope.Path(41, 0).empty() && processScope.Path(41, 101).empty(),
                "start-less and mismatched records cannot borrow a process path");
    processScope.AddProcess(41, 200, L"C:\\new-client.exe");
    ok &= Check(processScope.Path(41, 100).empty() && processScope.Path(41, 200) == L"C:\\new-client.exe",
                "a reused PID cannot lend its new path to the old incarnation");
    /* #76: the exit record was dropped, so 42@100 is still known when Windows
     * reuses the PID for an incarnation whose start carries no image name. */
    {
        ProcessScope reused;
        reused.AddProcess(42, 100, L"C:\\old.exe");
        reused.AddProcess(42, 200, L"");
        ok &= Check(reused.Path(42, 200).empty() && reused.Path(42, 100).empty(),
                    "an empty process-start text cannot inherit the old incarnation's path");
        reused.AddProcess(42, 200, L"C:\\new.exe");
        reused.AddProcess(42, 200, L"");
        ok &= Check(reused.Path(42, 200) == L"C:\\new.exe",
                    "a repeated start record keeps its own incarnation's path");
    }
    ok &= Check(ProcessScope::ValidParentIncarnation(100, 100, 100),
                "snapshot inheritance accepts the exact parent incarnation");
    ok &= Check(!ProcessScope::ValidParentIncarnation(100, 101, 100) &&
                !ProcessScope::ValidParentIncarnation(101, 101, 100) &&
                !ProcessScope::ValidParentIncarnation(100, 100, 99),
                "snapshot inheritance rejects reused, later, and older-parent identities");

    /* #55: an explicit track names the incarnation the caller resolved. */
    ok &= Check(MsMonTrackAdmitsStart(0, 123456), "an unspecified start admits the live process");
    ok &= Check(MsMonTrackAdmitsStart(100, 100), "the requested incarnation is admitted");
    ok &= Check(!MsMonTrackAdmitsStart(100, 101), "a reused PID is refused, not tracked");

    {
        ProcessScope early;
        const uint64_t address = 0x1000;
        early.AddImage(42, 100, address, 0x200, L"C:\\old.dll");
        early.AddProcess(42, 101, L"C:\\client.exe");
        ok &= Check(early.ResolveStack(42, &address, 1).empty(),
                    "early images do not cross into a reused process incarnation");
        early.AddImage(42, 100, address, 0x200, L"C:\\client.dll");
        early.AddProcess(42, 100, L"C:\\client.exe");
        auto modules = early.ResolveStack(42, &address, 1);
        ok &= Check(modules.size() == 1 && modules[0] == L"C:\\client.dll",
                    "early images merge for the captured incarnation");
        early.AddImage(43, 100, address, 0x200, L"C:\\old.dll");
        early.RemoveProcess(43, 100);
        early.AddProcess(43, 100, L"C:\\client.exe");
        ok &= Check(early.ResolveStack(43, &address, 1).empty(),
                    "process exit discards unmatched early images");
    }

    /*
     * A deferred ETW event belongs to the incarnation it was captured for: a
     * reused PID must not release it, and an unknown identity never does.
     */
    {
        EventQueue queue;
        ProcessScope scope;
        EtwCollector collector(scope, queue, 1, true, {});
        TelemetryEvent deferred;
        deferred.source = "etw";
        deferred.header.Size = sizeof(deferred.header);
        deferred.header.Version = MSMON_PROTOCOL_VERSION;
        deferred.header.Type = MsMonEtwWmi;
        deferred.header.ProcessId = 42;
        collector.Defer(TelemetryEvent(deferred), 100);
        scope.AddProcess(42, 101, L"C:\\client.exe");
        ok &= Check(collector.ReplayProcess(42) == 0,
                    "a reused PID does not release another incarnation's deferred event");
        ok &= Check(collector.PendingCount() == 1, "the mismatched event stays pending to expire");
        scope.AddProcess(42, 100, L"C:\\client.exe");
        ok &= Check(collector.ReplayProcess(42) == 1, "the deferred event is released for its incarnation");
        ok &= Check(collector.PendingCount() == 0, "a released event leaves the pending queue");
        std::vector<TelemetryEvent> emitted;
        ok &= Check(queue.Drain(emitted, 1) == 1 && emitted[0].header.ProcessStartTime == 100,
                    "a replayed event keeps its captured incarnation");
        collector.Defer(TelemetryEvent(deferred), 0);
        ok &= Check(collector.ReplayProcess(42) == 0, "an event with no known identity never replays");
        ok &= Check(collector.PendingCount() == 1, "an unidentified event is left to expire");
    }

    /*
     * TCP attribution: a connection's cached owner is only usable while that
     * exact incarnation is tracked; a reused PID is not the old owner.
     */
    {
        EventQueue queue;
        ProcessScope scope;
        EtwCollector collector(scope, queue, 1, true, {});
        scope.AddProcess(42, 100, L"C:\\client.exe");
        ok &= Check(!collector.RememberTcpOwner(9, 42, 101, L"192.0.2.1:443"),
                    "a stale incarnation is not cached as a connection owner");
        ok &= Check(!collector.RememberTcpOwner(9, 42, 0, L"192.0.2.1:443"),
                    "an unknown identity is not cached as a connection owner");
        ok &= Check(collector.RememberTcpOwner(9, 42, 100, L"192.0.2.1:443"),
                    "the live owner is cached");
        DWORD owner = 0;
        uint64_t ownerStart = 0;
        std::wstring ownerEndpoints;
        ProcessFacts stale;
        stale.ok = true;
        stale.created = 101;
        ok &= Check(!collector.ResolveTcpOwner(10, 42, stale, ownerEndpoints, owner, ownerStart),
                    "a direct TCP owner must match the tracked incarnation");
        ProcessFacts live;
        live.ok = true;
        live.created = 100;
        ok &= Check(collector.ResolveTcpOwner(10, 42, live, ownerEndpoints, owner, ownerStart) &&
                        owner == 42 && ownerStart == 100,
                    "a direct TCP owner returns its validated incarnation");
        ProcessFacts unknown;
        ok &= Check(collector.ResolveTcpOwner(9, 0, unknown, ownerEndpoints, owner, ownerStart) &&
                        owner == 42 && ownerStart == 100 && ownerEndpoints == L"192.0.2.1:443",
                    "a cached TCP owner returns its captured incarnation");
        collector.ForgetTcpOwner(9);
        ok &= Check(!collector.ResolveTcpOwner(9, 0, unknown, ownerEndpoints, owner, ownerStart),
                    "a closed connection cannot lend its owner to a reused TCB");
        ok &= Check(collector.RememberTcpOwner(9, 42, 100, L"192.0.2.1:443"),
                    "the current connection can be cached after eviction");
        /* A record that names a live non-client process must not borrow the cache. */
        ProcessFacts unrelated;
        unrelated.ok = true;
        unrelated.created = 500;
        ok &= Check(!collector.ResolveTcpOwner(9, 43, unrelated, ownerEndpoints, owner, ownerStart),
                    "a named non-client process does not inherit a cached TCP owner");
        ok &= Check(!collector.ResolveTcpOwner(9, 0, unknown, ownerEndpoints, owner, ownerStart),
                    "the stale TCB entry is dropped when a foreign process reuses it");
        ok &= Check(collector.RememberTcpOwner(9, 42, 100, L"192.0.2.1:443"),
                    "the client can cache the connection again after a foreign reuse");
        scope.AddProcess(42, 101, L"C:\\client.exe");
        ok &= Check(ownerStart == 100, "TCP attribution does not re-read a reused PID's start time");
        ok &= Check(!collector.ResolveTcpOwner(9, 0, unknown, ownerEndpoints, owner, ownerStart),
                    "a reused PID no longer owns the cached connection");
    }
    const auto& opnumProperties = RpcOpnumProperties();
    ok &= Check(opnumProperties.size() == 3 && opnumProperties[0] == L"ProcNum" &&
                opnumProperties[1] == L"OpNum" && opnumProperties[2] == L"OperationNum",
                "RPC opnum property aliases");
    GUID wkssvc{ 0x6bffd098, 0xa112, 0x3610,
                 { 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a } };
    ok &= Check(RpcGuidText(wkssvc) == L"6bffd098-a112-3610-9833-46c3f87e345a",
                "RPC GUID decoding");
    std::wstring service;
    std::wstring method;
    ok &= Check(RpcOperationName(L"{6BFFD098-A112-3610-9833-46C3F87E345A}", 0, service, method) &&
                service == L"Wkssvc" && method == L"NetrWkstaGetInfo", "Wkssvc operation name");
    ok &= Check(RpcOperationName(L"484809d6-4239-471b-b5bc-61df8c23ac48", 5, service, method) &&
                service == L"WTS/TermSrvSession" && method == L"RpcGetUserName", "WTS operation name");
    ok &= Check(!RpcOperationName(L"5ca4a760-ebb1-11cf-8611-00a0245420ed", 5, service, method),
                "Legacy WTS operation is not mislabeled");
    ok &= Check(RpcOperationName(L"12345778-1234-abcd-ef00-0123456789ab", 7, service, method) &&
                service == L"LSA/lsarpc" && method == L"LsarQueryInformationPolicy", "LSA operation name");
    ok &= Check(RpcOperationName(L"12345778-1234-abcd-ef00-0123456789ac", 17, service, method) &&
                service == L"SAMR" && method == L"SamrLookupNamesInDomain", "SAMR operation name");
    ok &= Check(!RpcOperationName(L"12345778-1234-abcd-ef00-0123456789ac", 999, service, method),
                "unknown RPC operation stays raw");
    ok &= Check(MsMonNetworkUnregisterComplete(0) != 0, "callout unregister success is complete");
    ok &= Check(MsMonNetworkUnregisterComplete(static_cast<long>(0xC0220001)) != 0,
                "callout already absent is complete");
    ok &= Check(MsMonNetworkUnregisterComplete(static_cast<long>(0xC022000A)) == 0,
                "callout in use is not complete");
    ok &= Check(MsMonNetworkUnregisterComplete(static_cast<long>(0x80000011)) == 0,
                "busy callout is not complete");
    ok &= Check(MsMonNetworkUnregisterComplete(static_cast<long>(0xC0000001)) == 0,
                "ordinary unregister failure is not complete");
    /*
     * Flow removal has its own terminal set: STATUS_SUCCESS (flowDeleteFn already ran
     * synchronously) and STATUS_UNSUCCESSFUL (no context associated). STATUS_PENDING is
     * success-valued but the asynchronous flowDeleteFn is still to come, so freeing the
     * context there frees memory the engine still references.
     */
    ok &= Check(MsMonFlowRemoveComplete(0) != 0, "flow removal success is complete");
    ok &= Check(MsMonFlowRemoveComplete(static_cast<long>(0xC0000001)) != 0,
                "already-removed flow is complete");
    ok &= Check(MsMonFlowRemoveComplete(0x00000103) == 0, "pending flow removal is not complete");
    ok &= Check(MsMonFlowRemoveComplete(static_cast<long>(0xC0000225)) == 0,
                "generic not-found flow removal is not complete");
    ok &= Check(MsMonFlowRemoveComplete(static_cast<long>(0xC0000022)) == 0,
                "an ordinary flow removal failure is not complete");

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
    source.Action = 4;
    event = KFilterDecisionEvent(source, 77, 5);
    ok &= Check(event.detail.find(L"decision=RISK") != std::wstring::npos &&
                event.detail.find(L"action=RISK") != std::wstring::npos,
                "risk rule use is decoded");
    source.Action = 1;
    source.Target = 0x20;
    source.Value = 0x006D0008;
    event = KFilterDecisionEvent(source, 77, 6);
    ok &= Check(event.detail.find(L"target=device") != std::wstring::npos &&
                event.detail.find(L"ioctl=0x006D0008") != std::wstring::npos &&
                event.detail.find(L"rights=") == std::wstring::npos,
                "device decisions expose the IOCTL");
    source.Target = 4;
    source.Value = 0x81;

    /* ABI 5 outside-process targets keep their names and the rights= label. */
    {
        struct TargetCase { unsigned long value; const wchar_t* name; };
        const TargetCase targets[] = {
            { 0x00000100u, L"handle" }, { 0x00000200u, L"launch" },
            { 0x00000400u, L"open" }, { 0x00000800u, L"thread-handle" },
            { 0x00001000u, L"thread-open" }
        };
        for (const auto& target : targets) {
            source.Target = target.value;
            event = KFilterDecisionEvent(source, 77, 6);
            const std::wstring prefix = L"target=" + std::wstring(target.name) + L";";
            ok &= Check(event.detail.find(prefix) != std::wstring::npos,
                        "an ABI 5 target is decoded by name");
            ok &= Check(event.detail.find(L"target=unknown") == std::wstring::npos &&
                        event.detail.find(L"target_id=" + std::to_wstring(target.value)) != std::wstring::npos,
                        "an ABI 5 target keeps its numeric id");
        }
        source.Target = 4;
    }

    /* The decision ring survives across runs: only events from this session may be written. */
    ok &= Check(!KFilterDecisionInSession(source, source.Timestamp + 1),
                "a decision from before the session start is excluded");
    ok &= Check(KFilterDecisionInSession(source, source.Timestamp),
                "a decision at the session boundary is included");
    ok &= Check(KFilterDecisionInSession(source, source.Timestamp - 1),
                "a decision after the session start is included");
    ok &= Check(KFilterDecisionEvent(source, 77, 1).header.Sequence == 1,
                "the first accepted decision keeps sequence 1");

    KFILTER_EVENT_4 staleEvent = source;
    staleEvent.Timestamp = source.Timestamp - 1;
    KFilterReader sessionReader(77, source.Timestamp);
    std::vector<TelemetryEvent> converted;
    sessionReader.ConvertBatch(&staleEvent, 1, converted);
    ok &= Check(converted.empty(), "a pre-session decision is not converted");
    sessionReader.ConvertBatch(&source, 1, converted);
    ok &= Check(converted.size() == 1 && converted.front().header.Sequence == 1,
                "accepted decisions are numbered from 1");
    sessionReader.ConvertBatch(&source, 1, converted);
    ok &= Check(converted.size() == 2 && converted.back().header.Sequence == 2,
                "numbering continues across batches");

    KFILTER_STATUS_4 start{};
    start.DroppedEvents = 3;
    KFILTER_STATUS_4 end = start;
    end.AbiVersion = 5;
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

    /* Observer coverage carries sequence 0 and must not inflate the event totals. */
    TelemetryEvent coverage;
    coverage.source = "agent";
    coverage.header.Size = sizeof(coverage.header);
    coverage.header.Version = MSMON_PROTOCOL_VERSION;
    coverage.header.Type = MsMonCoverageUsage;
    coverage.header.Flags = MsMonFlagObserverRecord;
    coverage.header.Sequence = 0;
    coverage.header.Timestamp = source.Timestamp;
    coverage.header.SessionId = 77;
    coverage.text = L"coverage_usage";
    ok &= Check(!CountsAsSessionEvent(coverage), "a sequence-0 coverage record is not an event");
    ok &= Check(CountsAsSessionEvent(firstDecision), "a numbered decision is an event");

    MSMON_STATISTICS statistics{};
    SessionSummary summary;
    summary.Add(coverage);
    ok &= Check(summary.Json(statistics, 0, 0, 0).find("\"events\":0") != std::string::npos,
                "coverage alone is not counted as an event");
    summary.Add(firstDecision);
    summary.Add(secondDecision);
    summary.Add(integrity);
    ok &= Check(summary.Json(statistics, 0, 0, 0).find("\"events\":3") != std::string::npos,
                "observer_summary counts only identified events");

    /* Payload bookkeeping is bounded, and a completed series retains no chunks. */
    {
        SessionSummary payloads;
        for (unsigned index = 0; index < 5000; index++) {
            TelemetryEvent payload;
            payload.header.Sequence = index + 1;
            payload.header.Type = MsMonRegistryQuery;
            payload.header.Flags = MsMonFlagPayloadPresent;
            payload.header.OperationId = index + 1;
            payload.header.PayloadChunkCount = 1;
            payload.header.PayloadChunkIndex = 0;
            payload.header.PayloadTotalBytes = 4;
            payload.header.PayloadBytes = 4;
            payload.payload = { 1, 2, 3, 4 };
            payloads.Add(payload);
        }
        const std::string json = payloads.Json(statistics, 0, 0, 0);
        ok &= Check(json.find("\"payload_operations\":5000") != std::string::npos,
                    "every payload operation is counted");
        ok &= Check(json.find("\"complete_payload_operations\":5000") != std::string::npos,
                    "a completed payload series counts once");
        ok &= Check(json.find("\"incomplete_payload_operations\":0") != std::string::npos,
                    "a completed payload series leaves no incomplete entry");
        ok &= Check(json.find("\"payload_operations_pending\":0") != std::string::npos,
                    "completed payload series retain no chunk bookkeeping");
    }

    /*
     * #53/#57: a late, lower OperationId must survive the insert that evicts the
     * oldest pending series. 4096 incomplete series fill the table; inserting id
     * 1 raises it to 4097 and evicts one of them, and must not free the node it
     * just inserted; finishing id 1 then removes exactly one entry.
     */
    {
        SessionSummary late;
        TelemetryEvent payload;
        payload.source = "driver";
        payload.header.Type = MsMonRegistryQuery;
        payload.header.Flags = MsMonFlagPayloadPresent;
        payload.header.PayloadChunkCount = 2;
        payload.header.PayloadTotalBytes = 8;
        payload.header.PayloadBytes = 4;
        payload.payload = { 1, 2, 3, 4 };
        for (unsigned index = 0; index < 4096; index++) {
            payload.header.Sequence = index + 1;
            payload.header.OperationId = 1000 + index;
            payload.header.PayloadChunkIndex = 0;
            late.Add(payload);
        }
        payload.header.OperationId = 1;
        payload.header.PayloadChunkIndex = 0;
        late.Add(payload);
        payload.header.PayloadChunkIndex = 1;
        late.Add(payload);
        const std::string json = late.Json(statistics, 0, 0, 0);
        ok &= Check(json.find("\"payload_operations\":4097") != std::string::npos,
                    "the late operation survives its own eviction");
        ok &= Check(json.find("\"complete_payload_operations\":1") != std::string::npos,
                    "the late operation completes after eviction");
        ok &= Check(json.find("\"incomplete_payload_operations\":4096") != std::string::npos,
                    "the evicted series stays counted as incomplete");
        ok &= Check(json.find("\"payload_operations_pending\":4095") != std::string::npos,
                    "one series is evicted and the late one is released on completion");
    }

    /*
     * The unit the agent uses for session_meta.json and coverage.json: the summary, the total
     * and the per-type counts must come from one decision, or the counts drift from verify_log.
     */
    SessionSummary accounted;
    uint64_t accountedTotal = 0;
    std::unordered_map<unsigned long, uint64_t> accountedCounts;
    AccountSessionEvent(accounted, coverage, accountedTotal, accountedCounts);
    AccountSessionEvent(accounted, firstDecision, accountedTotal, accountedCounts);
    AccountSessionEvent(accounted, secondDecision, accountedTotal, accountedCounts);
    AccountSessionEvent(accounted, integrity, accountedTotal, accountedCounts);
    ok &= Check(accountedTotal == 3, "session_meta event total matches the verifier");
    ok &= Check(accounted.Json(statistics, 0, 0, 0).find("\"events\":3") != std::string::npos,
                "accounted summary matches the session total");
    ok &= Check(accountedCounts.size() == 2 &&
                accountedCounts.count(MsMonCoverage) == 0 &&
                accountedCounts.count(MsMonCoverageUsage) == 0,
                "coverage records stay out of event_counts");

    JsonlWriter writer(L"build\\tests\\integration-events.jsonl", 0);
    ok &= Check(writer.Open(), "open JSONL output");
    ok &= Check(writer.Write(TelemetryJson(firstDecision)), "write first KFilter JSON");
    ok &= Check(writer.Write(TelemetryJson(secondDecision)), "write second KFilter JSON");
    ok &= Check(writer.Write(TelemetryJson(coverage)), "write coverage JSON");
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
    ok &= Check(sequences.size() == 2 && sequences[0] == "1" && sequences[1] == "2",
                "written decisions are numbered 1..N");

    /* The fixture must be the record class production writes at shutdown (type 111). */
    std::ifstream serialized(L"build\\tests\\integration-events.jsonl");
    unsigned coverageUsageRecords = 0;
    while (std::getline(serialized, line)) {
        if (line.find("\"type\":\"coverage_usage\"") == std::string::npos) continue;
        coverageUsageRecords++;
        ok &= Check(line.find("\"type_id\":111") != std::string::npos,
                    "serialized coverage record has the production type id");
        ok &= Check(line.find("\"sequence\":0") != std::string::npos,
                    "serialized coverage record stays a non-event");
    }
    ok &= Check(coverageUsageRecords == 1, "exactly one coverage_usage record was written");

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
