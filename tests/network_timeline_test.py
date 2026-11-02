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
    print("network timeline regression passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
