#!/usr/bin/env python3
"""Generate coverage/sensor-map.json from the protocol and telemetry names."""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "include" / "msmon_protocol.h"
TELEMETRY = ROOT / "agent" / "telemetry.cpp"
OUTPUT = ROOT / "coverage" / "sensor-map.json"

CALLBACKS = [
    (0, "process.notify", "driver/process.c::MsMonProcessNotifyInner", "process_start,process_exit", "startup,gameplay"),
    (1, "thread.notify", "driver/process.c::MsMonThreadNotify", "thread_start,thread_exit", "startup,gameplay"),
    (2, "image.notify", "driver/process.c::MsMonImageNotify", "image_load", "startup,gameplay"),
    (3, "object.process", "driver/object.c::MsMonObjectPre", "process_handle", "gameplay"),
    (4, "object.thread", "driver/object.c::MsMonObjectPre", "thread_handle", "gameplay"),
    (5, "file.pre_create", "driver/file_filter.c::MsMonPreCreate", "file_create", "file_io,gameplay"),
    (6, "file.post_create", "driver/file_filter.c::MsMonPostCreate", "file_create", "file_io,gameplay"),
    (7, "file.pre_op", "driver/file_filter.c::MsMonPreOperation", "file_read,file_write", "file_io,gameplay"),
    (8, "file.post_op", "driver/file_filter.c::MsMonPostOperation", "file_read,file_write", "file_io,gameplay"),
    (9, "registry.callback", "driver/registry.c::MsMonRegistryCallback", "registry_open,registry_query", "registry,gameplay"),
    (10, "wfp.classify", "driver/network.c::MsMonWfpClassify", "network_connect,network_accept", "network,gameplay"),
    (11, "wfp.notify", "driver/network.c::MsMonWfpNotify", "", "network,gameplay"),
    (12, "blackcat.check", "driver/attribution.c::MsMonCurrentIsBlackCat", "", "gameplay"),
    (13, "ioctl.dispatch", "driver/driver.c::MsMonDeviceControl", "", "startup,shutdown"),
]

REGISTRATIONS = {
    20: "process.notify",
    21: "thread.notify",
    22: "image.notify",
    23: "object.process",
    24: "object.thread",
    25: "filter.register",
    26: "filter.start",
    27: "registry.callback",
    28: "wfp.callout0",
    29: "wfp.callout1",
    30: "wfp.callout2",
    31: "wfp.callout3",
    32: "wfp.callout4",
    33: "wfp.callout5",
    34: "wfp.engine",
    38: "attribution",
}


def expected_for(name):
    if name.startswith(("process_", "thread_", "image_")):
        return ["startup", "gameplay"]
    if name.startswith("file_"):
        return ["file_io", "gameplay"]
    if name.startswith("registry_"):
        return ["registry", "gameplay"]
    if name.startswith("network_"):
        return ["network", "gameplay"]
    if name == "etw_wmi":
        return ["wmi", "gameplay"]
    if name == "etw_dns":
        return ["dns", "gameplay"]
    if name == "etw_rpc":
        return ["rpc", "gameplay"]
    if name == "etw_tcp":
        return ["network", "gameplay"]
    return ["startup", "shutdown"]


def main():
    protocol = PROTOCOL.read_text(encoding="utf-8")
    telemetry = TELEMETRY.read_text(encoding="utf-8")
    names = dict(re.findall(r"case (MsMon\w+): return \"([^\"]+)\";", telemetry))
    block = re.search(r"typedef enum _MSMON_EVENT_TYPE \{(.*?)\} MSMON_EVENT_TYPE;", protocol, re.S)
    if not block:
        print("event enum not found", file=sys.stderr)
        return 1
    ids = {name: int(value) for name, value in re.findall(r"^\s*(MsMon\w+) = (\d+)", block.group(1), re.M)}
    sensors = []
    for name, type_id in sorted(ids.items(), key=lambda item: item[1]):
        event_name = names.get(name)
        if not event_name:
            continue
        sensors.append({
            "sensor_id": "event." + event_name,
            "kind": "event",
            "event_type": event_name,
            "type_id": type_id,
            "implementation": "driver event " + name,
            "expected_in": expected_for(event_name),
            "status": "active",
        })
    for slot, sensor_id, implementation, events, expected in CALLBACKS:
        sensors.append({
            "sensor_id": sensor_id,
            "kind": "callback",
            "slot": slot,
            "implementation": implementation,
            "event_types": [item for item in events.split(",") if item],
            "expected_in": expected.split(","),
            "status": "active",
        })
    for slot, sensor_id in REGISTRATIONS.items():
        sensors.append({
            "sensor_id": "registration." + sensor_id,
            "kind": "registration",
            "slot": slot,
            "implementation": "driver registration call",
            "expected_in": ["startup"],
            "status": "active",
        })
    for index, name in enumerate(("wmi", "dns", "rpc")):
        sensors.append({
            "sensor_id": "etw." + name,
            "kind": "agent",
            "provider": name,
            "implementation": "agent/etw.cpp",
            "expected_in": [name, "gameplay"],
            "status": "active",
        })
    for name, implementation in (
        ("per_page_mmap", "section acquire only; no page-fault callbacks"),
        ("memory_ops", "no process-memory/APC/remote-thread callbacks"),
        ("ui_clipboard_input", "no UI/clipboard/input sensor"),
        ("broker_com", "no broker/COM/DPAPI correlation"),
        ("tls_plaintext", "no TLS plaintext"),
        ("direct_hardware", "no direct firmware/port/MSR sensor"),
    ):
        sensors.append({
            "sensor_id": "blind_spot." + name,
            "kind": "blind_spot",
            "implementation": implementation,
            "expected_in": [],
            "status": "blind_spot",
        })
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps({"schema_version": 1, "sensors": sensors}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT} with {len(sensors)} sensors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
