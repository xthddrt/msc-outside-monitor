#!/usr/bin/env python3
"""redact_session_test.py - a redacted bundle must not keep the payload's decoded copy.

The agent writes a friendly decoded_value beside a registry or volume payload
(agent/telemetry.cpp AppendDecodedValue). Removing only the Base64 payload left
the same MachineGuid, registry secret, volume serial or label in the "redacted"
bundle, so this drives the production redact_record through rewrite().
"""

import json
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import redact_session  # noqa: E402

DECODED_SECRET = "machine-guid-4f1c9e2a"
VOLUME_LABEL = "SYSTEM-RESTORE"
VOLUME_SERIAL_HEX = "3A2B1C0F"


def check(condition, name):
    if not condition:
        raise SystemExit(f"FAIL: {name}")


def records():
    return [
        {
            "type": "registry_set_value", "timestamp": "t1", "process_id": 7,
            "text": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
            "detail": "value MachineGuid", "operation_id": 3,
            "payload": {"kind": "registry_value", "encoding": "base64", "data": "QQBCAEMA",
                        "operation_id": 3, "total_bytes": 6, "byte_offset": 0,
                        "chunk_index": 0, "chunk_count": 1, "final_chunk": True},
            "decoded_value": DECODED_SECRET,
        },
        {
            "type": "file_query_volume_information", "timestamp": "t2", "process_id": 7,
            "text": "\\Device\\HarddiskVolume3", "operation_id": 4,
            "payload": {"kind": "volume_information", "encoding": "base64", "data": "AAAA",
                        "operation_id": 4, "total_bytes": 3, "byte_offset": 0,
                        "chunk_index": 0, "chunk_count": 1, "final_chunk": True},
            "decoded_value": {"volume_serial_number": 975903759,
                              "volume_serial_hex": VOLUME_SERIAL_HEX,
                              "volume_creation_time": "2026-10-01T00:00:00.000Z",
                              "volume_label": VOLUME_LABEL},
        },
        {
            "type": "process_start", "timestamp": "t3", "process_id": 7,
            "text": "C:\\client.exe", "detail": "client.exe -play",
        },
    ]


def main():
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        source = root / "session"
        source.mkdir()
        destination = root / "redacted"
        destination.mkdir()
        with open(source / "events.jsonl", "w", encoding="utf-8") as stream:
            for record in records():
                stream.write(json.dumps(record) + "\n")

        chain, count = redact_session.rewrite([source / "events.jsonl"], destination, False, False)
        check(count == len(records()), f"all records are rewritten (got {count})")
        check(re.fullmatch(r"[0-9a-f]{64}", chain) is not None, "the rewrite returns a chain head")

        text = (destination / "events.jsonl").read_text(encoding="utf-8")
        lines = [line for line in text.splitlines() if line.strip()]
        check(len(lines) == count, "one output line per input record")
        for name in ('"payload"', '"decoded_value"', DECODED_SECRET, VOLUME_SERIAL_HEX, VOLUME_LABEL):
            check(name not in text, f"the redacted bundle no longer contains {name}")

        redacted = [json.loads(line) for line in lines]
        check(redacted[0]["text"] == "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography" and
              redacted[0]["process_id"] == 7 and redacted[0]["payload_redacted"] is True,
              "the registry record keeps its metadata and says the payload was dropped")
        check(redacted[1]["type"] == "file_query_volume_information" and
              redacted[1]["payload_redacted"] is True,
              "the volume record keeps its metadata and says the payload was dropped")
        check(redacted[2]["text"] == "C:\\client.exe" and redacted[2].get("payload_redacted") is None,
              "a record without a payload is otherwise unchanged")
        check([record["record_index"] for record in redacted] == [1, 2, 3],
              "records are renumbered in write order")
        check(all(re.fullmatch(r"[0-9a-f]{64}", record["chain"]) for record in redacted),
              "every output record carries the new chain")

    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        source = root / "session"
        source.mkdir()
        destination = root / "redacted"
        destination.mkdir()
        identifying = [
            {"type": "file_read", "timestamp": "t1", "process_id": 7,
             "text": "\\Device\\HarddiskVolume3\\Users\\alice\\Documents\\notes.txt",
             "detail": "read"},
            {"type": "registry_query", "timestamp": "t2", "process_id": 7,
             "text": "\\REGISTRY\\USER\\S-1-5-21-111-222-333-1001\\Software",
             "detail": "value"},
            {"type": "network_connect", "timestamp": "t3", "process_id": 7,
             "text": "10.0.0.5:52000 -> 1.2.3.4:443",
             "detail": "tcp"},
        ]
        with open(source / "events.jsonl", "w", encoding="utf-8") as stream:
            for record in identifying:
                stream.write(json.dumps(record) + "\n")

        redact_session.rewrite([source / "events.jsonl"], destination, False, False)
        text = (destination / "events.jsonl").read_text(encoding="utf-8")
        for secret in ("Users", "S-1-5-21-", "10.0.0.5", "1.2.3.4"):
            check(secret not in text, f"the redacted bundle still contains {secret}")
        redacted = [json.loads(line) for line in text.splitlines() if line.strip()]
        check(redacted[0]["text"] == "<redacted-path>", "a profile path is replaced")
        check(redacted[1]["text"] == "<redacted-path>", "a user SID path is replaced")
        check(redacted[2]["text"] == "<redacted-ip>:52000 -> <redacted-ip>:443",
              "network endpoints are replaced")

        kept = root / "kept"
        kept.mkdir()
        redact_session.rewrite([source / "events.jsonl"], kept, True, False)
        kept_text = (kept / "events.jsonl").read_text(encoding="utf-8")
        kept_records = [json.loads(line) for line in kept_text.splitlines() if line.strip()]
        check(kept_records[0]["text"] == identifying[0]["text"] and
              kept_records[1]["text"] == identifying[1]["text"] and
              kept_records[2]["text"] == identifying[2]["text"],
              "--keep-paths leaves paths and endpoints intact")
    print("redact_session regression passed")


if __name__ == "__main__":
    main()
