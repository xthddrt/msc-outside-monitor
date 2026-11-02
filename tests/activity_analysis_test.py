#!/usr/bin/env python3
"""Process incarnations and registry creates must keep their real identities."""

import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ANALYSIS = ROOT / "tools" / "analysis"
sys.path.insert(0, str(ANALYSIS))
import session_activity  # noqa: E402


def event(kind, pid, created, text, timestamp, **extra):
    record = {
        "type": kind,
        "process_id": pid,
        "process_start_time": created,
        "timestamp": timestamp,
        "text": text,
        "status": 0,
    }
    record.update(extra)
    return record


def main():
    new_key = r"\REGISTRY\MACHINE\SOFTWARE\Nexon\NewKey"
    failed_key = r"\REGISTRY\MACHINE\SOFTWARE\Nexon\FailedKey"
    records = [
        event("process_start", 42, 100, r"C:\old.exe", "2026-01-01T00:00:00.000Z"),
        event("file_read", 42, 100, r"C:\old.dat", "2026-01-01T00:00:00.500Z"),
        event("process_exit", 42, 100, "", "2026-01-01T00:00:01.000Z"),
        event("process_start", 42, 200, r"C:\new.exe", "2026-01-01T00:00:02.000Z"),
        event("file_read", 42, 200, r"C:\new.dat", "2026-01-01T00:00:02.500Z"),
        event("process_start", 9, 50, r"C:\parent-old.exe", "2026-01-01T00:00:00.000Z"),
        event("process_start", 9, 60, r"C:\parent-new.exe", "2026-01-01T00:00:01.500Z"),
        event("process_start", 300, 70, r"C:\child.exe", "2026-01-01T00:00:03.000Z", parent_process_id=9),
        event("registry_create", 42, 200, new_key, "2026-01-01T00:00:03.500Z", value0=0),
        event("registry_create", 42, 200, failed_key, "2026-01-01T00:00:04.000Z", value0=0, status=-1),
    ]
    with tempfile.TemporaryDirectory() as temporary:
        bundle = pathlib.Path(temporary)
        with open(bundle / "events.jsonl", "w", encoding="utf-8", newline="\n") as stream:
            for record in records:
                stream.write(json.dumps(record, separators=(",", ":")) + "\n")

        report = session_activity.report(session_activity.collect(bundle), bundle, 40)
        rows = {(row["pid"], row["process_start_time"]): row for row in report["processes"]}
        assert set(rows) == {(42, 100), (42, 200), (9, 50), (9, 60), (300, 70)}, rows.keys()
        old, new = rows[(42, 100)], rows[(42, 200)]
        assert old["image"] == "old.exe" and new["image"] == "new.exe"
        assert old["start"] == "2026-01-01T00:00:00.000Z"
        assert old["end"] == "2026-01-01T00:00:01.000Z"
        assert new["start"] == "2026-01-01T00:00:02.000Z" and new["end"] is None
        assert old["start"] <= old["end"]
        assert old["events"] == 3 and new["events"] == 4
        assert "old.dat" not in str(new["reads_outside_client"])
        assert "new.dat" not in str(old["reads_outside_client"])
        assert rows[(300, 70)]["parent_image"] == "parent-new.exe", rows[(300, 70)]

        writes = new["registry_writes"]
        assert any(item[0][0] == "create" and "NewKey" in item[0][1] for item in writes), writes
        assert "FailedKey" not in str(writes), writes
        assert "NewKey" not in str(new["registry_read_prefixes"]), new["registry_read_prefixes"]
        assert "NewKey" not in str(new.get("registry_identity_reads", [])), new.get("registry_identity_reads")

        shown = subprocess.run(
            [sys.executable, str(ANALYSIS / "session_activity.py"), str(bundle), "--show", "42"],
            capture_output=True, text=True, check=False,
        )
        assert shown.returncode == 0, shown.stderr
        assert "old.exe" in shown.stdout and "new.exe" in shown.stdout, shown.stdout

        outside = subprocess.run(
            [sys.executable, str(ANALYSIS / "outside_activity.py"), str(bundle)],
            capture_output=True, text=True, check=False,
        )
        assert outside.returncode == 0, outside.stderr
        assert "NewKey" in outside.stdout and "create" in outside.stdout, outside.stdout

    print("activity analysis regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
