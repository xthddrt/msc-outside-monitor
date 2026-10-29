#!/usr/bin/env python3
"""Create a redacted derived bundle.  The raw bundle is never modified."""

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "tools" / "session_pack.py"


def redact_detail(detail):
    parts = []
    for field in detail.split(";"):
        if field.startswith("query="):
            parts.append("query=<redacted>")
        else:
            parts.append(field)
    return ";".join(parts)


def redact_record(record, keep_paths, keep_commands):
    had_payload = "payload" in record
    record.pop("payload", None)
    if had_payload:
        record["payload_redacted"] = True
    if record.get("type") == "etw_wmi":
        record["detail"] = redact_detail(record.get("detail", ""))
    elif record.get("type") == "etw_dns":
        record["text"] = "<redacted-dns>"
    if not keep_paths:
        record["process_path"] = ""
    if not keep_commands and record.get("type") == "process_start":
        record["detail"] = "<redacted-command-line>"
    return record


def rewrite(parts, destination, keep_paths, keep_commands):
    chain = "0" * 64
    index = 0
    for part in parts:
        output = destination / part.name
        with open(part, "r", encoding="utf-8") as source, open(output, "w", encoding="utf-8") as target:
            for line in source:
                line = line.strip()
                if not line:
                    continue
                record = redact_record(json.loads(line), keep_paths, keep_commands)
                record.pop("chain", None)
                index += 1
                record["record_index"] = index
                original = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
                chain = hashlib.sha256((chain + original).encode("utf-8")).hexdigest()
                target.write(original[:-1] + ',"chain":"' + chain + '"}\n')
    return chain, index


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("session_dir")
    parser.add_argument("--output", default=None)
    parser.add_argument("--keep-paths", action="store_true")
    parser.add_argument("--keep-commands", action="store_true")
    parser.add_argument("--no-compress", action="store_true")
    args = parser.parse_args()

    source = pathlib.Path(args.session_dir).resolve()
    destination = pathlib.Path(args.output).resolve() if args.output else source.with_name(source.name + "-redacted")
    if destination.exists():
        print(f"refusing to overwrite {destination}", file=sys.stderr)
        return 1
    destination.mkdir(parents=True)

    parts = []
    for path in source.glob("events.jsonl*"):
        suffix = path.name[len("events.jsonl"):]
        order = int(suffix[1:]) if suffix.startswith(".") and suffix[1:].isdigit() else 0
        parts.append((order, path))
    parts = [path for _, path in sorted(parts)]

    chain, count = rewrite(parts, destination, args.keep_paths, args.keep_commands)
    for name in ("session_meta.json", "summary.json", "coverage.json", "sensor-usage.json", "scenario_results.json"):
        path = source / name
        if path.exists():
            shutil.copy2(path, destination / name)
    meta_path = destination / "session_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["redacted"] = True
    meta["redaction_mode"] = "metadata"
    meta["events"] = count
    meta["record_count"] = count
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    command = [sys.executable, str(PACK), str(destination)]
    if args.no_compress:
        command.append("--no-compress")
    result = subprocess.run(command)
    if result.returncode != 0:
        return result.returncode
    print(f"redacted bundle: {destination}")
    print(f"chain_head {chain} records {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
