#!/usr/bin/env python3
"""compare_sessions_test.py - the manifest every compared value comes from is verified.

session_pack.py excludes manifest.json from checksums['parts'] and binds it with
checksums['bundle_sha256'] (manifest hash plus every part hash). compare_sessions
only hashed the parts, so an edited manifest was reported as verified data.
"""

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "compare_sessions.py"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_bundle(directory, record_count, text):
    directory.mkdir()
    events = directory / "events.jsonl"
    events.write_text(json.dumps({"type": "file_create", "text": text}) + "\n", encoding="utf-8")
    parts = [{"name": "events.jsonl", "bytes": events.stat().st_size,
              "sha256": sha256_file(events)}]
    manifest = {
        "schema_version": 1,
        "test_id": directory.name,
        "session_uuid": directory.name,
        "record_count": record_count,
        "parts": parts,
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    material = sha256_file(directory / "manifest.json") + "".join(part["sha256"] for part in parts)
    checksums = {
        "schema_version": 1,
        "parts": parts,
        "bundle_sha256": hashlib.sha256(material.encode("ascii")).hexdigest(),
    }
    (directory / "checksums.json").write_text(json.dumps(checksums), encoding="utf-8")


def run(*sessions):
    return subprocess.run([sys.executable, str(TOOL), *map(str, sessions)],
                          capture_output=True, text=True)


def check(condition, name, detail=""):
    if not condition:
        raise SystemExit(f"FAIL: {name} {detail}".rstrip())


def main():
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        first = root / "first"
        second = root / "second"
        write_bundle(first, 10, "\\Device\\HarddiskVolume3\\first.exe")
        write_bundle(second, 20, "\\Device\\HarddiskVolume3\\second.exe")

        result = run(first, second)
        check(result.returncode == 0, "intact bundles compare", result.stderr)

        manifest = json.loads((second / "manifest.json").read_text(encoding="utf-8"))
        manifest["record_count"] = 999999
        manifest["outcome"] = "crash"
        (second / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        result = run(first, second)
        check(result.returncode != 0, "an edited manifest is rejected")
        check("manifest" in result.stderr.lower(), "the manifest mismatch is reported", result.stderr)

        third = root / "third"
        fourth = root / "fourth"
        write_bundle(third, 30, "third")
        write_bundle(fourth, 40, "fourth")
        checksums = json.loads((fourth / "checksums.json").read_text(encoding="utf-8"))
        del checksums["bundle_sha256"]
        (fourth / "checksums.json").write_text(json.dumps(checksums), encoding="utf-8")
        result = run(third, fourth)
        check(result.returncode != 0, "a missing bundle_sha256 is rejected")
        check("bundle_sha256" in result.stderr, "the missing hash is reported", result.stderr)

    print("compare sessions regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
