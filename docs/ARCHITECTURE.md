# Architecture and coverage

## Data path

Protocol v4 uses self-delimiting `MSMON_EVENT_HEADER` records with bounded UTF-16 metadata, an optional source component, and optional raw payloads. Each text field is capped at 2,048 bytes, each record at 16,384 bytes, and each payload chunk at 8,192 bytes. Payload records include an operation ID, total byte length, byte offset, and chunk index/count. The collector validates all sizes, offsets, versions, session IDs, string/payload bounds, and source sequences.

The driver assigns session, source-sequence, and operation IDs and queues records in a bounded nonpaged list. Defaults are 16,384 records and 64 MiB, with maxima of 32,768 records and 128 MiB. The collector drains up to 1 MiB per IOCTL. ETW uses a separate bounded queue and source sequence. Allocation failure or a full queue increments drop counters; missing chunks make payload operations incomplete. On Ctrl+C, the collector stops new driver tracking and drains the remaining queue before final statistics. This is not lossless capture.

A single agent writer assigns consecutive record indexes and chains every JSON object with SHA-256. Rotated files continue the chain. Payloads are Base64 encoded, and complete operations can be reconstructed in chunk order. Friendly decodings are provided only when the entire value is present in one chunk. The chain detects later modification only when the trusted final hash is retained separately.

## Process scope and identity

The collector translates the configured DOS client root to an NT device path. The driver automatically recognizes only these exact images beneath it:

- `MapleStory.exe`
- `grap\NGService.exe`
- `NxOverlay\DwarfAxe.exe`
- `CrashReportClient.exe`

Children of tracked processes inherit tracking. At startup, the collector resolves full image paths and creation times, then registers matching processes and descendants iteratively. Explicit `--pid` scope is separate. PID + creation time is the intended process key; PID-only metadata still has weaker identity during PID reuse.

Root configuration and registration use a passive-level mutex. Event-time process lookups use a spin lock and bounded nonpaged entries. Basename matching alone is not treated as publisher identity, and no Authenticode claim is made for the modified private-server installation.

## Event sources

### Object access

`ObRegisterCallbacks` observes process and thread handle creation/duplication for tracked source processes. Events include target PID, target creation time/image where available, original desired access, granted access, and completion status. A handle-open event does not prove a later `ReadProcessMemory`, and handles opened before monitoring or through protected/brokered paths may be missed. No access bits are stripped.

### Files and devices

The minifilter logs create results and uses pre-operation cached name references for post-operation read/write, query/set information, directory control, cleanup, file-system control, device control, and volume-information results. Cache-only lookup avoids unsafe filesystem name queries; missing cache entries produce `MsMonFlagMissingPath`.

Named-pipe device paths are classified as IPC, but generic file and named-pipe contents are not captured in this Pareto-scoped version. Arbitrary non-filesystem device IOCTLs are not all visible to a minifilter.

For `FileFsVolumeInformation`, the driver uses Filter Manager buffer decoding/locking at APC_LEVEL or below. It records the raw returned buffer when valid and the collector decodes `FILE_FS_VOLUME_INFORMATION`, including the exact volume serial number, creation time, and label. Failed queries, invalid lengths, and unsafe-IRQL cases produce `payload_unavailable` instead of unsafe access or fabricated values.

### Registry

Pre-operation callbacks copy bounded key/value metadata into nonpaged call contexts. Set-value input bytes are captured during their valid pre-operation window and linked to final status through an operation ID. Post-operation callbacks emit actual status and free contexts.

Successful value queries and enumeration support Partial, Full, Align64, and multi-value layouts with checked offsets and lengths. Exact value bytes and types are retained. Failed, partial, unsupported, or unsafe results are marked unavailable rather than read beyond valid output. The collector adds friendly decoding for common string, multi-string, DWORD, and QWORD types while retaining Base64 for every value.

### Network

WFP callouts cover ALE connect and receive/accept plus flow-established IPv4/IPv6 layers. Events carry flow IDs, endpoints, protocol, and packed ports. Associated flow contexts produce close events and are removed during teardown. Callouts permit traffic and do not capture packet payloads or decrypt TLS.

### BlackCat kernel attribution

`driver/attribution.c` uses Auxiliary Kernel Library module enumeration at PASSIVE_LEVEL to record BlackCat's image base and size. The map refreshes at session start and through a once-per-second agent IOCTL. Event-time checks use `RtlCaptureStackBackTrace` and accept only a direct address within that image. Direct matches produce component `BlackCat64.sys` and `stack_resolved`; unrelated system activity does not inherit the component.

This is intentionally limited to direct evidence in existing process, object, file, and registry callbacks. There is no thread-lineage map, completion-context redesign, network expansion, or BlackCat device-stack attachment. Queued work items, DPCs on shared worker threads, protected code, and BlackCat device IRPs outside those callbacks remain uncovered. A BlackCat frame proves BlackCat participation, not MapleStory-to-BlackCat causality.

### ETW and attribution

The collector creates a uniquely named private real-time trace session. It enables WMI Activity, DNS Client, and RPC providers when available and records provider failures as coverage warnings. It does not stop or modify other trace sessions.

WMI can be correlated through `ClientProcessId` even when the event arrives from a service. Full-payload mode preserves the original query text; `--no-payloads` restores literal sanitization. WMI Activity does not supply result rows, and RPC/ALPC payloads are not available through these providers. DNS names and RPC endpoint metadata remain potentially sensitive.

Where ETW supplies supported stack extended data, the collector resolves addresses against image-load ranges and records up to eight module paths. Attribution is labeled `stack_resolved`, `service_correlated`, `process_only`, or `unknown`. Kernel callback context alone does not identify the calling DLL, and module resolution is not symbol or subroutine resolution.

## Classification and summaries

The classifier preserves raw metadata and adds `outside_client`, a category, and attribution. Hardware-related rules cover selected WMI classes/properties, registry key/value names, volume-information operations, and storage/device paths. Exact registry/volume values show what Windows returned, but still do not prove retention or transmission. Other hardware categories remain heuristics, and unknown remains unknown.

The final observer summary groups events by category, PID, target PID, and resolved module. It includes source drops/gaps, payload bytes, complete and incomplete payload operations, unavailable events, and duplicate chunks. It is evidence for a later policy tool, not an enforcement policy or proof of exfiltration.

## What full capture cannot mean

The monitor does not capture every CPU instruction, function call, in-memory transition, process/window enumeration without a handle, UI intent, or game-state semantic. It does not capture generic file contents, named-pipe payloads, ALPC/COM payloads, all RPC associations, all browser-broker activity, packet payloads, WMI result rows, direct adapter-API return buffers, activity before monitor startup, or events lost under overload. Pre-existing browser interaction through Explorer or another broker may remain unattributed.

Protected components and direct user-mode hardware APIs can lack a supported attributable event. Adding injection, SSDT hooks, client patching, or GRAP bypass is outside this project. Server-side code is not needed to build the monitor, but server-dependent gameplay paths cannot be certified without a runnable environment.

## Reliability requirements

The deliverable is a compiled development prototype. It has not been installed or runtime-tested. Before production use it needs isolated VM load/unload testing, Driver Verifier, payload and queue stress tests, buffer-failure tests, PID-reuse testing, WFP/minifilter coexistence checks, formal IRQL and lifetime review, independent security review, and a proper production signing/deployment process.
