# Log schema (v1)

This is the human-readable contract for `events.jsonl`, the session bundle, and the derived files. The machine-readable form is `schema/event-v1.json` plus `schema/session-v1.json`, `schema/checksums-v1.json`, and `schema/sensor-usage-v1.json`. `tools/validate_schema.py` implements the documented subset of JSON Schema used here.

The raw JSONL chain is authoritative. Manifest, catalog, reports, and redacted bundles are derived.

## 1. Record envelope

Every line is one JSON object. Telemetry records carry the common fields below; chained `observer_sequence_gap` and `observer_summary` records carry only `type`, `record_index`, `chain`, and their control/summary fields.

| Field | Meaning |
|---|---|
| `protocol` | Binary/event protocol version (currently 4). |
| `schema_version` | JSON schema version (1). |
| `source` | `driver`, `etw`, or `agent`. |
| `sequence` | Per-source sequence. Gaps are reported as `observer_sequence_gap`. |
| `timestamp` | UTC string decoded from FILETIME. |
| `session_id` | Random 64-bit numeric session ID (binary field). |
| `type` / `type_id` | Event name and numeric ID. |
| `process_id`, `process_start_time`, `process_path` | Requesting process identity. |
| `parent_process_id`, `thread_id` | Parent and thread identity. |
| `target_process_id`, `target_process_start_time` | Handle/network target identity. |
| `flags` / `flags_names` | Bitmask and decoded names. |
| `status` / `status_name` / `status_hex` | NTSTATUS value, decoded name, hex. |
| `desired_access` / `desired_access_hex` | Access mask and hex. |
| `category` | `unknown`, `client_data`, `windows_runtime`, `external_process`, `browser_interaction`, `hardware_identity`, `user_data`, `registry`, `network`, `ipc`. |
| `outside_client` | Classification heuristic, not proof. |
| `attribution` | `unknown`, `process_only`, `stack_resolved`, `service_correlated`, `static_evidence`. |
| `value0`, `value1` | Type-specific integers (below). |
| `operation_id` | Links payload chunks. |
| `text`, `detail`, `component` | Type-specific strings, detail fields, resolved component. |
| `modules` | Resolved image paths (up to 8). |
| `payload` | Optional Base64 chunk (below). |
| `payload_unavailable` | Payload could not be captured safely. |
| `record_index` | Writer order across rotated parts. |
| `chain` | SHA-256 chain over the previous chain and this record without `chain`. |

The session UUID is **not** repeated on every line. It lives in `manifest.json` and the `session_context` coverage record; join via `session_id`.

## 2. Event types

### Process, thread, image

| ID | Type | `text` | `detail` | `value0` / `value1` |
|---|---|---|---|---|
| 1 | `process_start` | image path | command line | start time |
| 2 | `process_exit` | — | — | start time |
| 3 | `thread_start` | — | — | — |
| 4 | `thread_exit` | — | — | — |
| 5 | `image_load` | image path | — | base address / size |
| 6 | `process_handle` | target image | — | operation / granted access |
| 7 | `thread_handle` | target image | — | operation / granted access |

### Files and devices

`text` is the NT path unless missing. `status` is the operation result.

| ID | Type | `value0` | `value1` |
|---|---|---|---|
| 10 | `file_create` | create options | returned information |
| 11 | `file_read` | length | byte offset |
| 12 | `file_write` | length | byte offset |
| 13 | `file_set_information` | information class | — |
| 14 | `file_directory_control` | information class | minor function |
| 15 | `file_cleanup` | — | — |
| 16 | `file_device_control` | IOCTL code | input length |
| 17 | `file_system_control` | FSCTL code | input length |
| 18 | `file_query_volume_information` | information class | — |
| 19 | `file_query_information` | information class | — |
| 34 | `file_section` | sync type | page protection |
| 35 | `file_close` | — | — |
| 36 | `file_flush` | — | — |
| 37 | `file_query_security` | security information mask | — |
| 38 | `file_set_security` | security information mask | — |
| 39 | `file_query_ea` | — | — |
| 40 | `file_set_ea` | — | — |

Volume information may carry a `volume_information` payload. File contents and per-page mapped I/O are not captured.

### Registry

`text` is the key path; `detail` is the value name when available.

| ID | Type | `value0` | `value1` |
|---|---|---|---|
| 20 | `registry_open` | — | — |
| 21 | `registry_create` | — | — |
| 22 | `registry_set_value` | data size | value type |
| 23 | `registry_delete` | — | — |
| 24 | `registry_rename` | — | — |
| 25 | `registry_query` | value index/class | value type |
| 26 | `registry_enumerate` | index/class | value type |

Set/query values may carry a `registry_value` payload. Enumerated names come from the post-operation result where the layout is known.

### Network

| ID | Type | `text` | `detail` | `value0` / `value1` |
|---|---|---|---|---|
| 30 | `network_connect` | endpoints | protocol/local/remote | flow ID / packed ports |
| 31 | `network_accept` | endpoints | protocol/local/remote | flow ID / packed ports |
| 32 | `network_flow_established` | endpoints | protocol/local/remote | flow ID / packed ports |
| 33 | `network_flow_close` | endpoints | protocol/local/remote | flow ID / packed ports |

No packet bytes or TLS plaintext.

### ETW

| ID | Type | `text` | `detail` | `value0` / `value1` |
|---|---|---|---|---|
| 100 | `etw_wmi` | namespace/provider | operation/query/language | provider event ID / operation ID |
| 101 | `etw_dns` | query name | query type/options | provider event ID |
| 102 | `etw_rpc` | endpoint/protocol | operation/interface | provider event ID |
| 103 | `etw_unattributed` | provider name | reason/event ID/PID | original type / original event ID |

WMI query text is preserved in full-payload mode; `--no-payloads` sanitizes it. Result rows are unavailable.

### Coverage

| ID | Type | Meaning |
|---|---|---|
| 110 | `coverage` | `text` is the record name (`session_context`, `coverage_manifest`, `session_start`, `etw_accounting`, etc.); `detail` is `key=value` fields or a message. |
| 111 | `coverage_usage` | Driver and agent sensor counters (Phase 3). |

## 3. Flags

| Bit | Name | Meaning |
|---|---|---|
| 0x00000001 | `explicit_track` | Registered explicitly or by image match. |
| 0x00000002 | `inherited_track` | Child of a tracked process. |
| 0x00000004 | `truncated_path` | Path was truncated. |
| 0x00000008 | `missing_path` | Name unavailable at this IRQL/context. |
| 0x00000010 | `service_correlated` | ETW client PID differs from the native service. |
| 0x00000020 | `observer_record` | Agent/ETW record. |
| 0x00000040 | `payload_present` | Payload chunk follows. |
| 0x00000080 | `payload_unavailable` | Payload could not be captured. |
| 0x00000100 | `payload_final_chunk` | Final chunk of an operation. |
| 0x00000200 | `payload_input` | Captured input (e.g., set-value). |
| 0x00000400 | `payload_partial` | More bytes exist than this chunk. |

## 4. Payloads

Payloads are Base64, chunked at 8 KiB. Fields: `kind`, `encoding`, `data`, `operation_id`, `total_bytes`, `byte_offset`, `chunk_index`, `chunk_count`, `final_chunk`. Kinds: `registry_value`, `volume_information`. Values above the 8-MiB protocol limit are marked unavailable; values above 64 KiB are partial.

Reconstruct by grouping `operation_id`, sorting `byte_offset`, and concatenating `data` until `total_bytes` is reached. A complete operation has contiguous chunks from 0 to `chunk_count - 1`.

## 5. Session labels

| Field | Values |
|---|---|
| `session_uuid` | Random 128-bit UUID string (manifest/context only). |
| `session_id` | Random 64-bit numeric binary session ID. |
| `session_label` | Operator label, sanitized. |
| `test_id` | Unique directory/test label. |
| `scenario` | `startup`, `login`, `gameplay`, `cash_shop`, `file_io`, `registry`, `wmi`, `dns`, `rpc`, `network`, `ipc`, `idle`, `shutdown`, `mixed`, `other`. |
| `phase` | `startup`, `steady`, `shutdown`. |
| `outcome` | `completed`, `agent_stopped`, `agent_killed`, `driver_stopped`, `crash`, `timeout`, `unknown`. Packer maps `in_progress` to `incomplete`. |
| `machine_label` | Operator/host name, sanitized. |
| `machine_id_hash` | SHA-256 of MachineGuid + system volume serial (raw values never stored). |
| `sensitivity` | `metadata`, `payload`, `secrets`. |

## 6. Compatibility and legacy

- Telemetry `schema_version` is 1. Records without it are legacy v4 logs; `validate_schema.py --allow-legacy` skips them. Observer control/summary records are part of schema v1 without carrying the full telemetry envelope.
- Existing fields are preserved. New fields are additive.
- The binary event header is unchanged: `session_id` stays 64-bit.
- The event identity is `(session_uuid, source, sequence)`.

## 7. Known blind spots

Per-page mapped I/O, file/pipe/mailslot payloads, memory/APC/remote-thread operations, UI/clipboard/input, direct hardware/firmware APIs, broker/COM/DPAPI correlation, TLS plaintext, pre-start activity, and events lost under overload. A zero event count is not proof that an operation did not happen.

## 8. Derived files

- `manifest.json` — labels, client/build fingerprints, configuration, sensitivity, parts, record count, chain head (`schema/session-v1.json`).
- `checksums.json` — per-part SHA-256, chain head, bundle hash (`schema/checksums-v1.json`).
- `coverage.json` — driver per-type/per-sensor counters and agent ETW/writer counters (`schema/coverage-v1.json`).
- `sensor-usage.json` — activity/health/verification per sensor (`schema/sensor-usage-v1.json`).
- `derived/census.json` — event/source/category/status/process counts.
- `environment.json`, `notes.md` — context for the session.
- `scenario_results.json` — expected/observed/failing/unexpected fixture results.

All of these are derived from the raw chain and may be rebuilt. `manifest.json` and `checksums.json` are the bundle's integrity source of truth.
