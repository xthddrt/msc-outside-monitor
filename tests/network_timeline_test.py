#!/usr/bin/env python3
"""network_timeline must pair flow-established/close events by the driver's flow ID (value0)."""

import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "analysis" / "network_timeline.py"
PACKED_PORTS = 25342781883  # identical protocol/local/remote ports for both flows


def main():
    with tempfile.TemporaryDirectory() as temporary:
        bundle = pathlib.Path(temporary)
        events = [
            {"type": "network_flow_established", "timestamp": "2026-11-01T10:00:01.000Z",
             "process_id": 7, "text": "10.0.0.5:52000 -> 203.0.113.10:443",
             "detail": "protocol/local/remote", "value0": 101, "value1": PACKED_PORTS},
            {"type": "network_flow_close", "timestamp": "2026-11-01T10:00:02.000Z",
             "process_id": 7, "text": "10.0.0.5:52000 -> 203.0.113.10:443",
             "detail": "protocol/local/remote", "value0": 101, "value1": PACKED_PORTS},
            {"type": "network_flow_established", "timestamp": "2026-11-01T10:00:03.000Z",
             "process_id": 7, "text": "10.0.0.5:52000 -> 203.0.113.11:443",
             "detail": "protocol/local/remote", "value0": 102, "value1": PACKED_PORTS},
            {"type": "process_start", "process_id": 42, "process_start_time": 100,
             "process_path": r"C:\old.exe", "text": r"C:\old.exe", "timestamp": "2026-11-01T10:00:04.000Z"},
            {"type": "network_flow_established", "process_id": 42, "process_start_time": 100,
             "process_path": r"C:\old.exe", "text": "10.0.0.5:52000 -> 203.0.113.12:443",
             "value0": 103, "timestamp": "2026-11-01T10:00:05.000Z"},
            {"type": "process_exit", "process_id": 42, "process_start_time": 100,
             "text": "", "timestamp": "2026-11-01T10:00:06.000Z"},
            {"type": "process_start", "process_id": 42, "process_start_time": 200,
             "process_path": r"C:\new.exe", "text": r"C:\new.exe", "timestamp": "2026-11-01T10:00:07.000Z"},
            {"type": "network_flow_close", "process_id": 42, "process_start_time": 200,
             "process_path": r"C:\new.exe", "text": "10.0.0.5:52000 -> 203.0.113.12:443",
             "value0": 103, "timestamp": "2026-11-01T10:00:08.000Z"},
        ]
        with open(bundle / "events.jsonl", "w", encoding="utf-8", newline="\n") as stream:
            for event in events:
                stream.write(json.dumps(event, separators=(",", ":")) + "\n")
        result = subprocess.run([sys.executable, str(TOOL), str(bundle)],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit(f"network_timeline failed: {result.stderr}")
        output = result.stdout
        assert "flow=101" in output, "the first flow id is not shown"
        assert "flow=102" in output, "the second flow id is not shown"
        assert "10:00:01.000 -> 10:00:02.000" in output, "the first flow lost its close time"
        assert "10:00:03.000 -> open at stop" in output, "the second flow is missing"
        assert "old.exe" in output, "PID reuse relabeled the old process and its flow"
        old_start = next(line for line in output.splitlines() if "START" in line and r"C:\old.exe" in line)
        old_flow = next(line for line in output.splitlines() if "flow=103" in line and "->" in line)
        new_start = next(line for line in output.splitlines() if "START" in line and r"C:\new.exe" in line)
        assert "old.exe" in old_start and "new.exe" not in old_start, output
        assert "old.exe" in old_flow and "new.exe" not in old_flow, output
        assert "new.exe" in new_start and "old.exe" not in new_start, output
        assert "10:00:05.000 -> 10:00:08.000" in output, output

    # #75: the flow is logged before its process_start arrives. The row and the
    # flow entry must keep the incarnation and be labelled old.exe once the
    # delayed start has been read, and a later reuse of PID 42 must not relabel it.
    with tempfile.TemporaryDirectory() as temporary:
        bundle = pathlib.Path(temporary)
        delayed = [
            {"type": "network_flow_established", "process_id": 42, "process_start_time": 100,
             "text": "10.0.0.5:52001 -> 203.0.113.13:443", "value0": 900,
             "timestamp": "2026-11-01T10:00:00.000Z"},
            {"type": "process_start", "process_id": 42, "process_start_time": 100,
             "process_path": r"C:\old.exe", "text": r"C:\old.exe",
             "timestamp": "2026-11-01T10:00:01.000Z"},
            {"type": "process_start", "process_id": 42, "process_start_time": 200,
             "process_path": r"C:\new.exe", "text": r"C:\new.exe",
             "timestamp": "2026-11-01T10:00:02.000Z"},
        ]
        with open(bundle / "events.jsonl", "w", encoding="utf-8", newline="\n") as stream:
            for event in delayed:
                stream.write(json.dumps(event, separators=(",", ":")) + "\n")
        result = subprocess.run([sys.executable, str(TOOL), str(bundle)],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit(f"network_timeline failed: {result.stderr}")
        output = result.stdout
        rows, _, flows = output.partition("== flows (established -> closed, UTC)")
        named = {}
        for line in rows.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                named[parts[0]] = parts[1]
        assert named.get("10:00:00.000") == "old.exe", (named, output)
        assert named.get("10:00:01.000") == "old.exe", (named, output)
        assert named.get("10:00:02.000") == "new.exe", (named, output)
        assert "10:00:00.000 -> open at stop  old.exe" in flows, flows
        assert "-> open at stop  42" not in flows, flows
    print("network timeline regression passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
