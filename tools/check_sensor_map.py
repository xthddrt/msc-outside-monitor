#!/usr/bin/env python3
"""Validate coverage/sensor-map.json against the protocol and coverage slots."""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAP = ROOT / "coverage" / "sensor-map.json"
PROTOCOL = ROOT / "include" / "msmon_protocol.h"
COVERAGE = ROOT / "include" / "msmon_coverage.h"


def main():
    data = json.loads(MAP.read_text(encoding="utf-8"))
    sensors = data.get("sensors", [])
    errors = []
    ids = set()
    callback_slots = set()
    registration_slots = set()
    by_event = {}

    protocol = PROTOCOL.read_text(encoding="utf-8")
    block = re.search(r"typedef enum _MSMON_EVENT_TYPE \{(.*?)\} MSMON_EVENT_TYPE;", protocol, re.S)
    if not block:
        print("event enum not found", file=sys.stderr)
        return 1
    event_ids = {name: int(value) for name, value in re.findall(r"^\s*(MsMon\w+) = (\d+)", block.group(1), re.M)}
    # Telemetry spells enum members as snake_case without the MsMon prefix.
    event_names = {value: re.sub(r"(?<!^)(?=[A-Z])", "_", name.removeprefix("MsMon")).lower()
                   for name, value in event_ids.items()}

    for item in sensors:
        sensor_id = item.get("sensor_id")
        if not sensor_id:
            errors.append("sensor without sensor_id")
            continue
        if sensor_id in ids:
            errors.append(f"duplicate sensor_id {sensor_id}")
        ids.add(sensor_id)
        kind = item.get("kind")
        if kind == "event":
            type_id = item.get("type_id")
            event_type = item.get("event_type")
            if not isinstance(type_id, int) or not (0 <= type_id < 128):
                errors.append(f"{sensor_id}: invalid type_id")
            elif type_id in by_event:
                errors.append(f"{sensor_id}: duplicate type_id {type_id} (also used by {by_event[type_id]})")
            elif event_names.get(type_id) != event_type:
                errors.append(f"{sensor_id}: event_type {event_type!r} does not match type_id {type_id}")
            by_event[type_id] = sensor_id
        elif kind == "callback":
            slot = item.get("slot")
            if not isinstance(slot, int) or not (0 <= slot < 64):
                errors.append(f"{sensor_id}: invalid callback slot")
            elif slot in callback_slots:
                errors.append(f"{sensor_id}: duplicate callback slot {slot}")
            callback_slots.add(slot)
        elif kind == "registration":
            slot = item.get("slot")
            if not isinstance(slot, int) or not (20 <= slot < 64):
                errors.append(f"{sensor_id}: invalid registration slot")
            elif slot in registration_slots:
                errors.append(f"{sensor_id}: duplicate registration slot {slot}")
            registration_slots.add(slot)
        elif kind == "agent":
            if item.get("provider") not in ("wmi", "dns", "rpc", "codeintegrity"):
                errors.append(f"{sensor_id}: invalid provider")
        elif kind == "blind_spot":
            if item.get("status") != "blind_spot":
                errors.append(f"{sensor_id}: blind spot must have status blind_spot")
        else:
            errors.append(f"{sensor_id}: unknown kind {kind}")

    for name, value in event_ids.items():
        if value not in by_event:
            errors.append(f"event type {name}={value} has no sensor entry")
    for slot in range(14):
        if slot not in callback_slots:
            errors.append(f"callback slot {slot} missing")
    for slot in list(range(20, 35)) + [38]:
        if slot not in registration_slots:
            errors.append(f"registration slot {slot} missing")

    coverage = COVERAGE.read_text(encoding="utf-8")
    slots = [int(value) for value in re.findall(r"MSMON_SENSOR_\w+ = (\d+)", coverage)]
    if slots and max(slots) >= 64:
        errors.append("sensor enum exceeds MSMON_SENSOR_SLOTS")

    print(f"sensors={len(sensors)} events={len(by_event)} callbacks={len(callback_slots)} "
          f"registrations={len(registration_slots)}")
    for error in errors[:100]:
        print(error, file=sys.stderr)
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
