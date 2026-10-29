#!/usr/bin/env python3
"""Chronological network timeline: process starts/exits, DNS, WFP connections, TCP close reasons, snapshots."""

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import hhmmss, iter_events, short_image  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session_dir")
    parser.add_argument("--no-loopback", action="store_true", help="hide 127.0.0.1 connections")
    args = parser.parse_args()

    images, rows, flows = {}, [], {}
    for line_event in iter_events(args.session_dir):
        kind = line_event.get("type")
        text = line_event.get("text") or ""
        if not (kind and (kind.startswith(("network_", "etw_dns", "etw_tcp"))
                          or kind in ("process_start", "process_exit")
                          or text in ("blackcat_loaded", "file_snapshot", "file_snapshot_missed"))):
            continue
        pid = line_event.get("process_id")
        if line_event.get("process_path"):
            images.setdefault(pid, short_image(line_event["process_path"]))
        if args.no_loopback and "127.0.0.1" in text:
            continue
        when = hhmmss(line_event.get("timestamp"))
        if kind == "process_start":
            images[pid] = short_image(text)
            rows.append((when, pid, "START", text[-60:]))
        elif kind == "process_exit":
            rows.append((when, pid, "EXIT", ""))
        elif kind == "coverage":
            rows.append((when, pid, text.upper(), (line_event.get("detail") or "")[:100]))
        elif kind == "etw_dns":
            rows.append((when, pid, "DNS", text))
        elif kind == "etw_tcp":
            reason = line_event.get("status_name") or ""
            rows.append((when, pid, "TCP", f"{line_event.get('detail', '')}  {text}  {reason}"))
        else:
            flow = line_event.get("value1")
            rows.append((when, pid, kind.replace("network_", "").upper(), f"{text}  flow={flow}"))
            if kind == "network_flow_established":
                flows[flow] = [when, None, pid, text]
            elif kind == "network_flow_close" and flow in flows:
                flows[flow][1] = when
    rows.sort()
    for when, pid, kind, info in rows:
        print(f"{when}  {images.get(pid, pid)!s:18} {kind:16} {info}")
    print("\n== flows (established -> closed, UTC)")
    for start, end, pid, text in sorted(flows.values(), key=lambda flow: flow[0]):
        if "127.0.0.1" not in text:
            print(f"   {start} -> {end or 'open at stop'}  {images.get(pid, pid)!s:16} {text}")
    print("\nReading TCP events on one connection: fin_received before the client's close_issued = the remote "
          "closed; reset_received = the remote reset; close/abort with neither = the client closed; "
          "*_timeout = traffic stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
