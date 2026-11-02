#!/usr/bin/env python3
"""time_window must include the whole second named by a fractionless end."""

import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "analysis" / "time_window.py"
IMAGE = "\\Device\\HarddiskVolume3\\x\\MapleStory.exe"


def run(bundle, start, end):
    result = subprocess.run([sys.executable, str(TOOL), str(bundle), start, end],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"time_window failed: {result.stderr}")
    return result.stdout


def main():
    with tempfile.TemporaryDirectory() as temporary:
        bundle = pathlib.Path(temporary)
        events = [
            ("10:00:20.100", "a.txt"),
            ("10:00:21.000", "b.txt"),
            ("10:00:21.900", "c.txt"),
        ]
        with open(bundle / "events.jsonl", "w", encoding="utf-8", newline="\n") as stream:
            for stamp, name in events:
                stream.write(json.dumps({
                    "type": "file_create", "timestamp": f"2026-11-01T{stamp}Z",
                    "process_id": 7, "process_path": IMAGE,
                    "text": f"\\Device\\HarddiskVolume3\\x\\{name}",
                    "status_name": "STATUS_SUCCESS",
                }, separators=(",", ":")) + "\n")

        whole = run(bundle, "10:00:20", "10:00:21")
        for name in ("a.txt", "b.txt", "c.txt"):
            assert name in whole, f"{name} was outside the requested window"

        fractional = run(bundle, "10:00:20", "10:00:21.5")
        assert "b.txt" in fractional, "an event at 21.000 was excluded by an end of 21.5"
        assert "c.txt" not in fractional, "an event at 21.900 was included by an end of 21.5"
    print("time window regression passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
