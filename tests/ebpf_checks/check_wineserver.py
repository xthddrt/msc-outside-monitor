"""Wineserver upgrade checks (tests/linux_ebpf_test.sh check()): the fake Wine clients of wineserver.sh
must be decoded into Windows-parity records (ebpf), the same without payloads (nopayloads), and nothing
may come from the decoder under --no-ebpf (fallback)."""
import base64
import os


def check(mode, path, events, mine, pids, coverage, problems):
    if mode == "fallback":
        if coverage & {"wineserver_requests", "wineserver_decoder"}:
            problems.append("wineserver: decoder coverage records under --no-ebpf")
        if any(";ws=ioctl;" in e.get("detail", "") for e in events):
            problems.append("wineserver: request records under --no-ebpf")
        return
    active = [e.get("detail", "") for e in events if e["type"] == "coverage" and e["text"] == "ebpf_active"]
    if "wineserver_requests" not in coverage:
        problems.append("wineserver: no wineserver_requests coverage note (ebpf_active: %s)" % active)
    names = ["ws_fake_client"] + (["ws_fake_client32"] if os.path.exists("build/linux/ws_fake_client32") else [])
    for name in names:
        ids = {e.get("process_id") for e in events if e["type"] == "process_start" and e.get("text", "").endswith("/" + name)}
        if not ids:
            problems.append("wineserver: %s was not tracked" % name)
            continue
        recs = [e for e in events if e.get("process_id") in ids]

        def has(kind, test, what):
            if not any(e["type"] == kind and test(e) for e in recs):
                problems.append("wineserver: %s: no %s %s" % (name, kind, what))

        def value(e):
            """The payload as text, or None (no payload)."""
            if "payload" not in e:
                return None
            return base64.b64decode(e["payload"]["data"]).decode("utf-16-le", "replace")

        def payload_ok(e):
            if mode == "ebpf":
                return value(e) == "hello" and e["payload"]["final_chunk"] and e.get("decoded_value") == "hello"
            return "payload" not in e and not e.get("payload_unavailable")

        has("coverage", lambda e: e["text"] == "wineserver_decoder" and "active=1" in e["detail"] and
            "protocol=930" in e["detail"], "wineserver_decoder active=1")
        has("registry_open", lambda e: e["text"] == "\\Registry\\Machine\\Software\\MsmonProbe" and
            e["desired_access"] == 0x20019 and e["status"] == 0, "of \\Registry\\Machine\\Software\\MsmonProbe")
        has("registry_set_value", lambda e: e["text"].endswith("\\MsmonProbe") and e["detail"] == "Probe" and
            e["value0"] == 10 and e["value1"] == 1 and payload_ok(e), "of Probe = hello (%s)" % mode)
        has("registry_query", lambda e: e["text"].endswith("\\MsmonProbe") and e["detail"] == "Probe" and payload_ok(e),
            "of Probe = hello (%s)" % mode)
        has("process_handle", lambda e: "open_process;win_pid=2457" in e["detail"] and e["desired_access"] == 16,
            "open_process of win_pid=2457 with desired_access 16")
        has("process_handle", lambda e: e["detail"].startswith("read_process_memory;") and e["value0"] == 1 and
            e["value1"] == 16, "read_process_memory of 16 bytes")
        has("file_create", lambda e: e["text"] == "/tmp/msmon-probe.txt" and "nt=\\??\\unix\\tmp\\msmon-probe.txt" in e["detail"],
            "of /tmp/msmon-probe.txt with nt=")
        has("network_connect", lambda e: e["text"] == "127.0.0.1:9" and e["detail"].startswith("connect;family=2;ws=ioctl;afd=connect") and
            ";pending" in e["detail"] and e["status"] == 0x103 and e["value0"] == 0, "to 127.0.0.1:9 (STATUS_PENDING)")
