# msc-outside-monitor

Application-scoped Windows telemetry for the MapleStoryCW client, with a WDM kernel/minifilter driver, an elevated Win32 collector, ETW correlation, chained JSONL output, and a static inventory of the supplied installation.

The monitor observes an exact client installation, its descendants, and configured Nexon helpers. It does not inject code, hook SSDTs, patch the client, bypass GRAP/Nexon security, disable driver signing, or decrypt network traffic. By default it records exact registry values and volume-information results; these payloads can contain hardware identifiers and registry secrets. Generic file contents and network payloads are not captured.

## What it captures

| Source | Events |
|---|---|
| Process/thread/image callbacks | start/exit, PID and creation time, ancestry, image path, command line when available, module base/size |
| Object callbacks | process/thread handle creation and duplication, target PID/image, requested and granted access, result |
| Filesystem minifilter | create, read/write, query/set information, directory control, cleanup, visible FS/device controls, volume-information results |
| Registry callbacks | open/create, query/enumerate, set/delete/rename, key/value names, type/size, operation result, and exact value bytes |
| Windows Filtering Platform | IPv4/IPv6 connect/accept and flow establish/close, flow ID, endpoints, protocol, ports, PID |
| WMI Activity ETW | correlated client PID, namespace/provider/operation, and original query text in full-payload mode |
| DNS Client ETW | correlated query name and query metadata |
| RPC ETW | correlated endpoint/operation metadata where client attribution is available |

Registry values are emitted as Base64 bytes with friendly decoding for common string, multi-string, DWORD, and QWORD types. Volume results include raw bytes plus the exact serial number, creation time, and label when the returned structure is valid. Large values use linked 8-KiB chunks.

Records are classified as client data, Windows runtime, external process, browser interaction, hardware identity, user data, registry, network, IPC, or unknown. Capturing a request or returned value does not prove that MapleStory retained or transmitted it. This is broad OS telemetry, not a guarantee of every instruction, function call, service-mediated action, or hardware read.

## Build

Requirements: Visual Studio 2022 with MSVC and the Windows Kernel Mode Driver toolset, plus Windows SDK 10.0.26100.

```bat
build.cmd
```

Outputs:

- `build\Release\driver\msmon.sys`
- `build\Release\driver\msmon.inf`
- `build\Release\agent\msmon-agent.exe`

The default build is unsigned development output. Do not load it on a production machine. Use the isolated test-VM procedure in `docs/TEST_VM.md`. The current code has been compiled but has not been installed or runtime-tested.

## Collect

Run elevated in the test VM after properly signing and starting the driver. Start the collector before launching the game:

```bat
msmon-agent.exe --client "C:\Nexon\Library\maplestorycw\appdata" --output session.jsonl
```

Options:

- `--pid PID` explicitly tracks another existing process;
- `--wait-ms N` sets the empty-queue wait, capped by the driver at one second;
- `--max-file-mb N` rotates output after the threshold with a continuing hash chain;
- `--queue-records N` and `--queue-mb N` adjust bounded driver buffering;
- `--no-etw` disables the private ETW session and records a coverage warning;
- `--no-payloads` disables exact registry/volume payloads and restores sanitized WMI queries;
- `--once` reads one driver batch and exits.

The default root is `C:\Nexon\Library\maplestorycw\appdata`. Local drive-letter paths are translated to the NT device paths seen by kernel process callbacks. The configured root contains `MapleStory.exe`, `grap\NGService.exe`, `NxOverlay\DwarfAxe.exe`, and `CrashReportClient.exe`; descendants inherit tracking. Existing unrelated browsers and services are logged as interaction targets, not monitored wholesale.

Every output line has a consecutive record index and a SHA-256 chain. Driver and ETW sequence numbers remain independent; gaps and queue drops are visible. Validate rotated logs in order:

```bat
python tools\verify_log.py session.jsonl session.jsonl.1
```

The verifier checks the chain, Base64 payloads, chunk ordering/completeness, and friendly decoded values. The final observer summary groups events by category, process, target process, and resolved module and reports complete and incomplete payload operations. Keep the final chain separately if later modification detection matters.

## Static client inventory

The analysis script requires Python and `pefile`:

```bat
python tools\analyze_client.py C:\Nexon\Library\maplestorycw analysis\pe-inventory.json
```

The committed inventory covers all 391 supplied files and 46 PE images, including PE-formatted GRAP `.aes` payloads. No proprietary client binaries are included here. The installation contains no original C/C++ source or symbols; import analysis is not a complete decompilation.

## Safety and privacy

Use only on systems and software you are authorized to inspect. Logs can contain exact hardware identifiers, registry secrets, command lines, paths, process relationships, network endpoints, DNS names, and original WMI queries. Use synthetic data in tests, restrict log access, define a retention period, and never commit real payload logs. The control device is administrator-only, and the driver is not hidden or hardened against tampering.
