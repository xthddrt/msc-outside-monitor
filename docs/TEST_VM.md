# Isolated test-VM procedure

The driver compiles cleanly with WDK 10.0.26100 (`/W4 /WX`) but has **not been installed or runtime-tested** on this host. Do not first load it on a production host or alongside an active game session.

## Prepare

1. Use a disposable Windows x64 VM with a current snapshot, no production accounts, and no sensitive data. Keep networking disabled until basic load/unload testing succeeds.
2. Install Visual Studio 2022, MSVC, the WDK, and matching Windows SDK 10.0.26100. Build with `build.cmd` (main monitor only; add `--with-compat` only if testing the legacy subsystem).
3. Copy `msmon.sys`, `msmon.inf`, and `msmon-agent.exe` into a test directory. Enable Windows test-signing mode using the VM's normal administrative boot configuration and reboot. Do not disable Secure Boot or third-party security software.
4. Create a test certificate, stage the package with the WDK's `Inf2Cat`, and sign the driver/catalog with `signtool` using SHA-256. Record the certificate only in the test VM's trusted store. Do not commit certificates or private keys.
5. Install the signed INF through Windows SetupAPI, or use the driver's test service entry. Confirm minifilter altitude `370030` and registry/object callback altitudes do not conflict. If `ObRegisterCallbacks` rejects the development signature, stop and use the correct signing process rather than bypassing it.

Example service management after signed installation:

```bat
sc.exe start msmon
sc.exe query msmon
msmon-agent.exe --client "C:\Nexon\Library\maplestorycw" --output C:\msmon-logs\session.jsonl
sc.exe stop msmon
```

The agent auto-detects `appdata` as the process scope when `--client` names the installation root; use `--scope-root` to test an explicit scope. Full registry/volume payload capture is enabled by default. Add `--no-payloads` for metadata-only collection and sanitized WMI queries. Stop the collector with Ctrl+C before stopping the driver so it can stop new tracking, drain queued records, and write final statistics. The log should contain a `coverage_manifest` at start and an `etw_accounting` record at stop.

## Validation checklist

- Install the INF with `ServiceType=2`, `Dependencies=FltMgr`, and the configured altitude. Confirm `fltmc` shows the filter at the expected altitude.
- Start the collector with `--client C:\Nexon\Library\maplestorycw` and again with the `appdata` path. Confirm `appdata` auto-detection, the `coverage_manifest` roots, descendant inheritance, PID + creation-time identity, and no tracking of an unrelated same-named executable.
- Confirm a scope root without `MapleStory.exe` fails before opening a session, while a valid root with no running game prints a waiting message and continues.
- Confirm process/thread start/exit, image paths, module bases/sizes, and command lines when available. Confirm a helper with a non-`.exe` extension under the scope root is tracked.
- Verify BlackCat load detection and direct-stack component attribution. Confirm `BlackCat64.sys` appears only on direct matches and unrelated system activity is not labeled. Do not treat a BlackCat frame as proof that MapleStory requested the operation.
- From a controlled tracked process, open and duplicate handles to another process/thread. Verify target PID/image, requested/granted access, and result without changing access.
- Perform controlled synchronous and overlapped file reads/writes, directory enumeration, rename/set-information, section mapping/acquire, close/flush, security/EA, named-pipe, mailslot, and visible device-control operations. Verify paths, status, lengths/offsets, section protection, and missing-path flags. Confirm async operations are attributed to the requestor PID/TID, not the completion context.
- Confirm named-pipe and mailslot creates and subsequent read/write events appear with IPC category (`FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS`). Per-page mapped I/O and paging I/O are **not covered**; do not treat a clean log as proof of no mapped-file activity. The session `coverage_manifest` records `minifilter_npfs=true` and the remaining blind spots.
- Generic file, named-pipe, and mailslot contents are intentionally not captured in this version.
- Use synthetic registry strings, multi-strings, DWORD/QWORD values, binary data, and values larger than 8 KiB and 64 KiB. Verify Base64 bytes, friendly decoded values, enumerated key/value names, explicit partial/unavailable markers, chunk ordering, and final operation status. Compare the values with the known inputs, not with real credentials or production identifiers.
- Test failed, partial, unsupported, and over-8-MiB registry queries and set-value inputs. Confirm they produce `payload_unavailable` or partial records without flooding the queue and never claim complete values.
- Issue a controlled volume-information request. Compare the logged raw result, exact serial number, creation time, and label with the VM's known values. Test buffer failures and confirm unavailable reasons.
- Issue controlled WMI hardware and non-hardware queries. Verify original query text in full mode, sanitization with `--no-payloads`, client correlation, and module attribution. Confirm the log explicitly notes that WMI result rows are unavailable.
- Start a controlled child and issue WMI/DNS/RPC immediately, before the driver process-start record is drained. Confirm the ETW event is replayed rather than dropped, or that an `etw_unattributed` record is emitted after the timeout. Then generate WMI/DNS/RPC activity from a long-running unrelated process and confirm it is **not** deferred or emitted (the queue only accepts processes created within the 5-second window).
- Enable an isolated network and verify IPv4/IPv6 connect/accept and flow establish/close correlation. Packet payloads and TLS plaintext remain outside this version's coverage.
- Launch an external URL/browser through the client or a controlled descendant. Distinguish direct child creation, handle access, and brokered/RPC evidence.
- Start/stop the collector and driver repeatedly, including with pending reads and active flows. Check for hangs, stale sessions, leaked contexts, and bugchecks.
- Specifically: run the agent, then `sc stop msmon` while the agent is still collecting. The unload must wake the pending read and complete without a bugcheck.
- Attempt `fltmc unload msmon`; the filter must refuse with `STATUS_FLT_DO_NOT_DETACH` and remain attached. Then stop the driver normally.
- Run Driver Verifier with `/standard /all` (plus `/em` for the test-signed build) from load through unload, and confirm no "driver unloaded without cancelling" reports for notification routines, WFP callouts, or minifilter registrations.
- Run the agent with `--log-dir`, `--scenario file_io`, `--machine-label`, and `--iteration`; stop it normally. Run `tools\session_pack.py`, `tools\validate_schema.py --session`, and `tools\sensor_report.py --write`. Confirm `manifest.json`, `chain_head`, `sensor-usage.json`, and `coverage.json` exist, and the bundle verifies after copying to another PC.
- Build and run `build.cmd --with-fixtures`, then `build\fixtures\sensor_probe.exe file` (also `registry`, `ipc`, `network`, `handles`) under the matching scenario. Confirm expected sensors are `verified`, a disabled ETW session is `disabled` rather than `failing`, and a registration failure reports `registration_failed` with a status code.
- Export a Procmon CSV for the fixture PID and run `tools\oracle_diff.py`; confirm known blind spots appear as missing classes only when they are genuinely outside coverage.
- Check that `coverage.json` counters reset per session and that `coverage_usage` appears once in the log. A zero event count must not be reported as dead code.
- Run Driver Verifier and controlled stress tests. Exceed record and byte queue limits; verify that queue drops create a driver sequence gap, that periodic/final drop counters agree, and that `etw_accounting` reports unattributed/pending/lost events. Test multi-megabyte values and unsafe-IRQL paths without using sensitive payloads.
- Exercise PID reuse and protected-process cases; review zero creation times and unknown attribution rather than treating them as strong identity.
- Validate logs with `python tools\verify_log.py <parts-in-order>`. Confirm malformed Base64, duplicate/missing/out-of-order chunks, incorrect decoded values, and hash-chain tampering are rejected or reported.
- Review logs for exact registry values, hardware identifiers, paths, command lines, DNS names, and original WMI queries before sharing them. Never commit real payload logs.

## Legacy compatibility subsystem

`build\compat\msmon-legacy.sys` and `msmon-legacyctl.exe` are **not part of the default build**. Build them with `build.cmd --with-compat` only. They contain the legacy capability set; inline kernel hooks are compiled in for `trace.c` but disabled by the runtime gate. Do not enable them expecting PatchGuard stability. The build never installs either driver, and compat is not a coverage substitute for the main monitor.

- Verify the compatibility device rejects access from a non-administrator test account and allows the intended elevated account.
- Confirm status reports unsafe functionality as implemented but disabled, with no inline patch installed and no PatchGuard/security setting changed.
- Test supported process/thread notifications and handle events, including actual post-operation status and granted access.
- Test legacy process-notification fallback when the extended registration API is refused, without treating reduced signing support as a reason to bypass signing requirements.
- Use two different programs accessing the same resource and confirm summary/folding keys keep their events separate by PID.
- Test guard audit/enforce only with synthetic targets and resources. File/registry/memory detours remain disabled with their inline hooks.
- Exercise ring overflow and confirm drops are reported; do not treat `mon collect` as a lossless-capture guarantee.

A successful compile is not evidence that kernel runtime behavior is safe. Production use requires the full checklist, independent driver review, and a production signing process. Without a runnable server environment, server-dependent gameplay behavior remains uncertified.
