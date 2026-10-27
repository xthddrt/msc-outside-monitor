#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path


def verify(paths):
    previous = "0" * 64
    lines = 0
    events = 0
    gaps = 0
    last_sequences = {}
    for path in paths:
        with path.open("r", encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                raw = line.rstrip("\r\n")
                record = json.loads(raw)
                chain = record.get("chain")
                if not isinstance(chain, str) or len(chain) != 64:
                    raise ValueError(f"{path}:{number}: missing SHA-256 chain")
                marker = f',"chain":"{chain}"}}'
                if not raw.endswith(marker):
                    raise ValueError(f"{path}:{number}: chain is not the final property")
                original = raw[:-len(marker)] + "}"
                expected = hashlib.sha256((previous + original).encode("utf-8")).hexdigest()
                if chain != expected:
                    raise ValueError(f"{path}:{number}: hash-chain mismatch")
                if record.get("protocol", 1) not in {1, 2}:
                    raise ValueError(f"{path}:{number}: unsupported protocol")
                if "record_index" in record and record["record_index"] != lines + 1:
                    raise ValueError(f"{path}:{number}: non-consecutive record index")
                if "outside_client" in record and not isinstance(record["outside_client"], bool):
                    raise ValueError(f"{path}:{number}: outside_client must be Boolean")
                previous = chain
                lines += 1
                if record.get("type") == "observer_sequence_gap":
                    missing = int(record["missing_events"])
                    if missing <= 0:
                        raise ValueError(f"{path}:{number}: invalid sequence gap")
                    gaps += missing
                elif "sequence" in record:
                    sequence = int(record["sequence"])
                    if sequence < 0:
                        raise ValueError(f"{path}:{number}: negative event sequence")
                    if sequence == 0:
                        continue
                    source = record.get("source", "driver")
                    last_sequence = last_sequences.get(source)
                    if last_sequence is not None and sequence <= last_sequence:
                        raise ValueError(f"{path}:{number}: non-increasing {source} sequence")
                    last_sequences[source] = sequence
                    events += 1
    return {"files": len(paths), "lines": lines, "events": events, "missing_events": gaps, "final_chain": previous}


def main():
    parser = argparse.ArgumentParser(description="Validate ms-monitor JSONL and its SHA-256 hash chain.")
    parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.logs), indent=2))


if __name__ == "__main__":
    main()
