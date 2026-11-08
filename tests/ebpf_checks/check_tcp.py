"""TCP lifecycle (tcp upgrade): etw_tcp records of tests/fixtures/probe_tcp.h's loopback pairs and refused
connect, attributed to the probe (the sockets' maker). Called by tests/linux_ebpf_test.sh check()."""


def check(mode, path, events, mine, pids, coverage, problems):
    if mode not in ("ebpf", "nopayloads"):
        return
    tcp = [e for e in mine if e["type"] == "etw_tcp"]

    def tcp_event(name, test=lambda e: True):
        return [e for e in tcp if e["detail"].startswith("event=" + name + ";") and test(e)]

    for name, number in (("connect_completed", 1033), ("accept_completed", 1017), ("close_issued", 1038),
                         ("fin_received", 1176), ("disconnect_completed", 1043), ("abort_issued", 1039)):
        if not tcp_event(name, lambda e: e["value0"] == number and e["value1"] != 0 and e["text"].startswith("127.0.0.1:")):
            problems.append("no etw_tcp " + name)
    if not tcp_event("reset_sent", lambda e: "reason=TCP_ABORT_ON_CLOSE" in e["detail"]):
        problems.append("no etw_tcp reset_sent for the close with unread data")
    if not tcp_event("reset_received", lambda e: "state=SYN_SENT" in e["detail"]):
        problems.append("no etw_tcp reset_received for the connect to a closed port")
    if not tcp_event("connect_failed", lambda e: e["status"] == -111):
        problems.append("no etw_tcp connect_failed with ECONNREFUSED")
    connected = {e["value1"] for e in tcp_event("connect_completed")}
    if not any(e["value1"] in connected for e in tcp_event("close_issued")):
        problems.append("no close_issued on a connection whose connect_completed was logged (value1: socket cookie)")
    if not any(e["type"] == "coverage" and e["text"] == "ebpf_active" and "tcp:on" in e["detail"] and
               "tcp_lifecycle=on" in e["detail"] for e in events):
        problems.append("ebpf_active does not say tcp:on and tcp_lifecycle=on")
    if "tcp_lifecycle" not in coverage:
        problems.append("no tcp_lifecycle coverage record")
