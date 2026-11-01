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
    print("redact_session regression passed")


if __name__ == "__main__":
    main()
