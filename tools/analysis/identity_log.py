#!/usr/bin/env python3
"""Append identity-relevant events from an msmon session bundle to a Markdown log."""

import argparse
import datetime
import fnmatch
import hashlib
import json
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import iter_events  # noqa: E402

CHANNELS_HEADING = "## Channels no rule can reach"
CHANNELS = [
    ("CPUID/MSR", "CPU model, features and IDs; no OS call for kfilter to intercept"),
    ("Firmware tables", "SMBIOS/BIOS, board and system serials through system queries"),
    ("Machine SID", "Machine and account identifiers already present in the process token"),
    ("GPU adapter APIs", "Adapter and device identifiers outside file/registry filtering"),
    ("Process/module lists", "System and window enumeration without another process handle"),
    ("Service-side RPC/WMI", "Services answer with user, computer, domain and hardware data"),
    ("Kernel anti-cheat", "Kernel code can bypass or remove user and kernel callbacks"),
]
RISK_MODULES = {
    "wbemprox.dll", "fastprox.dll", "wbemcomn.dll", "wbemsvc.dll", "rpcrt4.dll",
    "iphlpapi.dll", "hid.dll", "pdh.dll", "wtsapi32.dll", "netapi32.dll", "sspicli.dll",
    "grap64.dll", "grap-core64.aes", "grap-updater.aes", "blackcat64.sys",
    "machineidlib.dll", "tbs.dll", "nvapi64.dll", "atiadlxx.dll", "setupapi.dll",
    "cfgmgr32.dll", "wlanapi.dll", "dhcpcsvc.dll",
}
IDENTITY_TEXT = re.compile(
    r"machineguid|computername|tcpip|networklist|hardware\\description|hardware\\acpi|"
    r"hardware\\devicemap|\\enum(?:\\|$)|mounteddevices|idconfigdb|systeminformation|"
    r"winlogon|networkcards|windowsupdate|diagtrack|mountpoints2|valve|blizzard|battle\.net|"
    r"epic games|riot games|electronic arts|ubisoft|xboxlive|productid|profilelist|"
    r"shell folders|volatile environment|identitycrl|susclientid|defaultusername|defaultdomainname",
    re.I,
)
CONNECTIONS = {"network_connect", "network_accept", "network_flow_established",
               "network_flow_close", "etw_tcp"}
DIRECT = {"etw_wmi", "etw_dns", "etw_rpc"}


def markdown(value):
    return str(value or "?").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def detail_field(detail, name):
    for part in detail.split(";"):
        key, _, value = part.partition("=")
        if key == name:
            return value
    return ""


def denied_by(path, pattern):
    """The rule's path covers the object: kfilter's prefix match, case-insensitive, * spans separators."""
    path, pattern = path.lower(), pattern.lower().replace("[", "[[]")
    return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path, pattern + "\\*")


def identity_event(event, deny_rules=None):
    kind = event.get("type")
    text = event.get("text") or ""
    detail = event.get("detail") or ""
    if kind == "kfilter_decision" and detail_field(detail, "target") == "device":
        return True
    if kind == "kfilter_decision" and detail_field(detail, "action") == "deny":
        # An explicit deny rule (the identity block list) or the network-adapter filter;
        # default-deny denials (rule 0) are not identity evidence. The rule's path must
        # cover the object, so a policy edited since the run cannot misattribute a denial.
        rule_id = detail_field(detail, "rule_id")
        pattern = (deny_rules or {}).get(int(rule_id)) if rule_id.isdigit() else None
        return (pattern is not None and denied_by(text, pattern)) or text.lower() == "\\device\\nsi"
    if kind in DIRECT or kind in CONNECTIONS or event.get("category") == "hardware_identity":
        return True
    if kind == "image_load":
        name = text.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        return name.endswith(".sys") or name in RISK_MODULES
    if kind == "coverage" and text == "blackcat_loaded":
        return True
    if kind == "kfilter_decision" and ("action=RISK" in detail or "decision=RISK" in detail):
        return True
    return kind in {"file_create", "registry_open", "registry_create", "registry_query",
                    "registry_enumerate"} and IDENTITY_TEXT.search(text + "\\" + detail) is not None


def policy_rules(policy_path):
    """risk= rules, and explicit deny rules' paths by rule ID (kfilterctl numbers non-network rules 1, 2, ...)."""
    rules = []
    deny_rules = {}
    rule_id = 0
    with open(policy_path, encoding="utf-8-sig") as stream:
        for line in stream:
            fields = line.strip().split("|")
            if len(fields) < 3 or fields[0] not in ("allow", "audit", "deny"):
                continue
            if fields[1] != "network":
                rule_id += 1
                if fields[0] == "deny":
                    deny_rules[rule_id] = fields[2]
            risks = [field[5:] for field in fields[3:] if field.startswith("risk=") and len(field) > 5]
            if risks:
                rules.append((fields[1], fields[2], risks[0]))
    return rules, deny_rules


def append_identity_log(bundle, policy, output):
    bundle = pathlib.Path(bundle)
    output = pathlib.Path(output)
    summary_path = bundle / "summary.json"
    summary = {}
    if summary_path.exists():
        with open(summary_path, encoding="utf-8") as stream:
            summary = json.load(stream)
    rules, deny_rules = policy_rules(policy)
    events = [event for event in iter_events(bundle) if identity_event(event, deny_rules)]
    existing = output.read_text(encoding="utf-8") if output.exists() else ""
    # The full risk= table is written only when it differs from the last one in the log.
    table = "".join(f"| {markdown(target)} | {markdown(path)} | {markdown(risk)} |\n"
                    for target, path, risk in rules)
    marker = f"<!-- risk-rules sha256={hashlib.sha256(table.encode('utf-8')).hexdigest()} -->"
    markers = re.findall(r"<!-- risk-rules sha256=[0-9a-f]{64} -->", existing)
    unchanged = bool(markers) and markers[-1] == marker
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with open(output, "a", encoding="utf-8", newline="\n") as stream:
        if CHANNELS_HEADING not in existing:
            stream.write(f"\n{CHANNELS_HEADING}\n\n| Channel | Residual risk |\n|---|---|\n")
            for name, reason in CHANNELS:
                stream.write(f"| {name} | {reason} |\n")
        stream.write(f"\n## Run {now} {markdown(bundle.name)}\n\n")
        stream.write(
            "Capture: "
            f"events={summary.get('events', '?')}, "
            f"driver_dropped={summary.get('driver_dropped_events', '?')}, "
            f"etw_dropped={summary.get('etw_dropped_events', '?')}, "
            f"driver_gaps={summary.get('driver_sequence_gaps', '?')}, "
            f"etw_gaps={summary.get('etw_sequence_gaps', '?')}.\n\n"
        )
        stream.write("### Identity-relevant events\n\n")
        if events:
            stream.write("| Timestamp | PID | Type | Text | Detail |\n|---|---:|---|---|---|\n")
            for event in events:
                stream.write(
                    f"| {markdown(event.get('timestamp'))} | {event.get('process_id') or 0} | "
                    f"{markdown(event.get('type'))} | {markdown(event.get('text'))} | "
                    f"{markdown(event.get('detail'))} |\n"
                )
        else:
            stream.write("No identity-relevant events captured; this is not proof none occurred.\n")
        stream.write("\n### risk= rules in the loaded policy\n\n")
        if unchanged:
            stream.write(f"Unchanged since the last run ({len(rules)} rules).\n")
        else:
            stream.write(marker + "\n\n")
            if rules:
                stream.write("| Target | Path | Risk |\n|---|---|---|\n" + table)
            else:
                stream.write("None.\n")
    return len(events), len(rules)


def self_test():
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        bundle = root / "session"
        bundle.mkdir()
        records = [
            {"type": "etw_wmi", "timestamp": "t1", "process_id": 7, "text": "ROOT\\CIMV2", "detail": "query=Win32_ComputerSystemProduct"},
            {"type": "etw_dns", "timestamp": "t2", "process_id": 7, "text": "login.example"},
            {"type": "etw_rpc", "timestamp": "t3", "process_id": 7, "detail": "interface=SAMR;operation=SamrLookupNamesInDomain"},
            {"type": "kfilter_decision", "timestamp": "t4", "process_id": 7, "detail": "action=RISK;rule_id=4"},
            {"type": "registry_query", "timestamp": "t5", "process_id": 7, "text": "\\REGISTRY\\USER\\S-1-5-21\\Software\\Valve"},
            {"type": "network_flow_close", "timestamp": "t7", "process_id": 8,
             "text": "10.0.0.5:52000 -> 203.0.113.10:443", "detail": "flow=17;state=closed"},
            {"type": "file_read", "timestamp": "t6", "process_id": 7, "text": "ordinary.txt"},
            # Rule 2 is the policy's explicit deny (the network rule is not numbered).
            {"type": "kfilter_decision", "timestamp": "t8", "process_id": 7,
             "text": "\\REGISTRY\\MACHINE\\DenyKey\\IdentityDenied", "detail": "action=deny;rule_id=2"},
            {"type": "kfilter_decision", "timestamp": "t9", "process_id": 7,
             "text": "\\REGISTRY\\MACHINE\\DefaultDenied", "detail": "action=deny;rule_id=0"},
            # Same rule ID, but the deny rule's path does not cover it (another policy's rule 2).
            {"type": "kfilter_decision", "timestamp": "t11", "process_id": 7,
             "text": "\\Device\\HarddiskVolume3\\SpentAllow.exe", "detail": "action=deny;rule_id=2"},
            {"type": "kfilter_decision", "timestamp": "t10", "process_id": 7,
             "text": "\\Device\\Nsi", "detail": "action=deny;rule_id=0;rights=0x0012001b"},
            {"type": "kfilter_decision", "timestamp": "t12", "process_id": 7,
             "text": "\\Device\\DeviceAllow", "detail": "target=device;action=allow;ioctl=0x006D0008"},
            {"type": "kfilter_decision", "timestamp": "t13", "process_id": 7,
             "text": "\\Device\\DeviceDeny", "detail": "target=device;action=deny;ioctl=0x004D100C"},
            {"type": "kfilter_decision", "timestamp": "t14", "process_id": 7,
             "text": "\\Device\\DeviceAudit", "detail": "target=device;action=audit;ioctl=0x00170001"},
            {"type": "kfilter_decision", "timestamp": "t15", "process_id": 7,
             "text": "\\Device\\DeviceRisk", "detail": "target=device;action=RISK;ioctl=0x002D1400"},
        ]
        with open(bundle / "events.jsonl", "w", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record) + "\n")
        with open(bundle / "summary.json", "w", encoding="utf-8") as stream:
            json.dump({"events": 7, "driver_dropped_events": 2}, stream)
        policy = root / "policy.txt"
        policy.write_text(
            "allow|network|ip=192.0.2.1/32|port=443|proto=tcp|rights=connect|uses=1|risk=login-endpoint\n"
            "audit|registry|\\REGISTRY\\MACHINE\\AuditKey|rights=read|risk=audit-reason\n"
            "deny|registry|\\REGISTRY\\MACHINE\\DenyKey|rights=read|risk=deny-reason\n",
            encoding="utf-8")
        output = root / "identity.md"
        counts = append_identity_log(bundle, policy, output)
        assert counts == (12, 3), counts
        text = output.read_text(encoding="utf-8")
        for expected in ("Win32_ComputerSystemProduct", "login.example", "SamrLookupNamesInDomain",
                         "action=RISK", "Software\\Valve", "login-endpoint", "CPUID/MSR", "Machine SID",
                         "driver_dropped=2", "10.0.0.5:52000 -> 203.0.113.10:443",
                         "audit-reason", "deny-reason", "\\REGISTRY\\MACHINE\\AuditKey",
                         "\\REGISTRY\\MACHINE\\DenyKey", "IdentityDenied", "\\Device\\Nsi",
                         "DeviceAllow", "DeviceDeny", "DeviceAudit", "DeviceRisk", "0x006D0008"):
            assert expected in text, expected
        for unexpected in ("ordinary.txt", "DefaultDenied", "SpentAllow"):
            assert unexpected not in text, unexpected
        append_identity_log(bundle, policy, output)
        text = output.read_text(encoding="utf-8")
        assert text.count(CHANNELS_HEADING) == 1
        assert text.count("| deny-reason |") == 1 and "Unchanged since the last run (3 rules)." in text
        with open(policy, "a", encoding="utf-8") as stream:
            stream.write("allow|file|\\Device\\HarddiskVolume3\\x\\hid.dll|rights=read|risk=device-id\n")
        append_identity_log(bundle, policy, output)
        text = output.read_text(encoding="utf-8")
        assert text.count("| deny-reason |") == 2 and "| device-id |" in text
    print("identity_log self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle")
    parser.add_argument("--policy")
    parser.add_argument("--out")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.bundle or not args.policy or not args.out:
        parser.error("--bundle, --policy and --out are required")
    events, rules = append_identity_log(args.bundle, args.policy, args.out)
    print(f"appended {events} identity events and {rules} risk rules to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
