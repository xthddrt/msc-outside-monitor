# Architecture and coverage

## Data path

Protocol v2 uses self-delimiting `MSMON_EVENT_HEADER` records with bounded UTF-16 strings. Each string is capped at 2,048 bytes and each record at 8,192 bytes; truncation and missing-path flags are explicit. The collector rejects invalid sizes, versions, session IDs, string bounds, partial records, and non-increasing source sequences.

The driver assigns a session ID and source sequence and queues records in a bounded nonpaged list. Defaults are 16,384 records and 64 MiB, with maxima of 32,768 records and 128 MiB. The collector drains up to 1 MiB per IOCTL. ETW uses a separate bounded 32,768-record queue and source sequence. Allocation failure or a full queue increments drop counters; source gaps identify lost sequence ranges where possible. On Ctrl+C, the collector stops new driver tracking and drains the remaining queue before final statistics. This is not lossless capture.

A single agent writer assigns consecutive record indexes and chains every JSON object with SHA-256. Rotated files continue the chain. The chain detects later modification only when the trusted final hash is retained separately; it does not stop a privileged attacker from rewriting the whole log.

## Process scope and identity

The collector translates the configured DOS client root to an NT device path. The driver automatically recognizes only these exact images beneath it:

- `MapleStory.exe`
- `grap\NGService.exe`
- `NxOverlay\DwarfAxe.exe`
- `CrashReportClient.exe`

Children of tracked processes inherit tracking. At startup, the collector resolves full image paths and creation times, then registers matching processes and their descendants iteratively. Explicit `--pid` scope is separate. PID + creation time is the intended process key; metadata sources that provide only a PID still have weaker identity during PID reuse.

Root configuration and registration use a passive-level mutex. Event-time process lookups use a spin lock and bounded nonpaged entries. Basename matching alone is not treated as publisher identity, and no Authenticode claim is made for the modified private-server installation.

## Event sources

### Object access

`ObRegisterCallbacks` observes process and thread handle creation/duplication for tracked source processes. Events include target PID, target creation time/image where available, original desired access, granted access, and completion status. Self-handle noise is skipped. A handle-open event does not prove a later `ReadProcessMemory`, and handles opened before monitoring or through protected/brokered paths may be missed. No access bits are stripped.

### Files and devices

The minifilter logs create results and uses pre-operation cached name references for post-operation read/write, query/set information, directory control, cleanup, file-system control, device control, and volume-information results. Cache-only lookup avoids unsafe filesystem name queries in completion callbacks; a missing cache entry produces `MsMonFlagMissingPath` instead of a fabricated path.

Named-pipe device paths are classified as IPC. Volume-information and selected storage/device paths feed hardware-related classification. Arbitrary non-filesystem device IOCTLs are not all visible to a minifilter. No data buffers, file contents, volume serial values, or named-pipe payloads are copied.

### Registry

Pre-operation callbacks copy bounded key/value metadata into nonpaged call contexts. Post-operation callbacks emit the actual status and free those contexts. Set events include value type and data size; query/set events do not include value data. The callback covers open/create, query, multi-value query metadata, enumerate, set, delete, and rename operations registered by the configuration manager.

### Network

WFP callouts cover ALE connect and receive/accept plus flow-established IPv4/IPv6 layers. Explicit field IDs select local/remote addresses, ports, and protocol; the implementation does not assume those fields are adjacent. Events carry flow IDs and packed protocol/ports. Associated flow contexts produce close events and are removed during teardown. Callouts permit traffic and never inspect packets or TLS plaintext.

### ETW and attribution

The collector creates a uniquely named private real-time trace session with system-time timestamps. It enables WMI Activity, DNS Client, and RPC providers when available, and records coverage warnings for provider failures. It does not stop or modify other trace sessions.

WMI can be correlated through `ClientProcessId` even when the event arrives from a service. Query string literals and numeric literals are redacted before logging. DNS query names and RPC endpoint/operation metadata remain potentially sensitive. RPC events without defensible client correlation are ignored.

Where ETW supplies supported stack extended data, the collector resolves addresses against image-load ranges and records up to eight module paths. Attribution is labeled:

- `stack_resolved`: at least one frame resolved to a module;
- `service_correlated`: a service event names a tracked client PID;
- `process_only`: only process identity is known;
- `unknown`: no reliable attribution.

Kernel callback context by itself does not identify the calling DLL. Module resolution is not symbol resolution and does not recover subroutine names.

## Classification and summaries

The classifier preserves raw metadata and adds `outside_client`, a category, and attribution. Hardware-related rules cover selected WMI classes/properties, registry key/value names, volume-information operations, and storage/device paths. These are heuristics: they identify a query surface, not the returned value or proof of exfiltration. Unknown remains unknown rather than being treated as safe.

The final observer summary groups events by category, PID, target PID, and resolved module, and includes source drops/gaps. It is intended as evidence for a later policy tool, not as an enforcement policy by itself.

## What full capture cannot mean

The monitor does not capture every CPU instruction, function call, in-memory transition, process/window enumeration that does not open a handle, UI intent, or game-state semantic. It does not capture ALPC/COM payloads, all RPC associations, all browser-broker activity, raw packets, file/registry values, hardware-ID values, activity before monitor startup, or events lost under overload. Pre-existing browser interaction through Explorer or another broker may remain process-only or unattributed.

Protected components and direct user-mode hardware APIs can lack a supported attributable event. Adding injection, SSDT hooks, client patching, or GRAP bypass would change the risk model and is outside this project. Server-side code is not needed to build the monitor, but server-dependent gameplay paths cannot be certified without a runnable environment.

## Reliability requirements

The deliverable is a compiled development prototype. It has not been installed or runtime-tested. Before production use it needs isolated VM load/unload testing, Driver Verifier, stress and PID-reuse testing, WFP/minifilter coexistence checks, formal IRQL and lifetime review, independent security review, and a proper production signing/deployment process.
