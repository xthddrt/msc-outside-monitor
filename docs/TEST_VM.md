# Isolated test-VM procedure

The driver has been compiled but **not installed or runtime-tested**. Do not first load it on a production host or alongside an active game session.

## Prepare

1. Use a disposable Windows x64 VM with a current snapshot, no production accounts, and no sensitive data. Keep networking disabled until basic load/unload testing succeeds.
2. Install Visual Studio 2022, MSVC, the WDK, and matching Windows SDK 10.0.26100. Build with `build.cmd`.
3. Copy `msmon.sys`, `msmon.inf`, and `msmon-agent.exe` into a test directory. Enable Windows test-signing mode using the VM's normal administrative boot configuration and reboot. Do not disable Secure Boot or third-party security software.
4. Create a test certificate, stage the package with the WDK's `Inf2Cat`, and sign the driver/catalog with `signtool` using SHA-256. Record the certificate only in the test VM's trusted store. Do not commit certificates or private keys.
5. Install the signed INF through Windows SetupAPI, or use the driver's test service entry. Confirm minifilter altitude `370030` and registry/object callback altitudes do not conflict. If `ObRegisterCallbacks` rejects the development signature, stop and use the correct signing process rather than bypassing it.

Example service management after signed installation:

```bat
sc.exe start msmon
sc.exe query msmon
msmon-agent.exe --client "C:\Nexon\Library\maplestorycw\appdata" --output C:\msmon-logs\session.jsonl
sc.exe stop msmon
```

Stop the collector with Ctrl+C before stopping the driver. The collector stops new driver tracking, drains queued driver records, stops its private ETW session, writes final statistics, and ends the driver session during normal shutdown.

## Validation checklist

- Start the collector before the game. Verify exact-path root/helper registration, descendant inheritance, PID + creation-time identity, and no tracking of an unrelated same-named executable.
- Confirm process/thread start/exit, image paths, module bases/sizes, and command lines when available.
- From a controlled tracked process, open and duplicate handles to another process/thread. Verify target PID/image, requested/granted access, and result. Confirm the monitor does not change access.
- Perform controlled file reads/writes, directory enumeration, rename/set-information, named-pipe, volume-information, and visible device-control operations. Verify paths, status, lengths/offsets, and missing-path flags. Do not use sensitive payloads.
- Perform registry open/create/query/enumerate/set/delete/rename operations. Verify key/value names, type/size, and post-operation status without value-data capture.
- Issue controlled WMI hardware and non-hardware queries. Verify client correlation, query-literal redaction, category, and any supported stack/module attribution. Confirm actual hardware-ID values are absent from the log.
- Enable an isolated network and verify IPv4/IPv6 connect/accept and flow establish/close correlation. Confirm endpoints use the correct local/remote fields and the monitor does not change connection policy.
- Launch an external URL/browser through the client or a controlled descendant. Distinguish direct child creation, handle access, and brokered/RPC evidence; do not assume an existing browser is wholly monitored.
- Start/stop the collector and driver repeatedly, including with pending reads and active flows. Check for hangs, stale sessions, leaked flow contexts, and bugchecks.
- Run Driver Verifier and controlled stress tests. Exceed both record and byte queue limits; verify source gaps and final drop statistics. Confirm ETW queue drops are also visible.
- Exercise PID reuse and protected-process cases; review events with zero creation time or unknown attribution rather than treating them as strongly identified.
- Validate logs with `python tools\verify_log.py <parts-in-order>` and retain the final chain separately as evidence.
- Review logs for sensitive paths, command lines, DNS names, registry metadata, and sanitized WMI queries before sharing them.

A successful compile is not evidence that kernel runtime behavior is safe. Production use requires the full checklist, independent driver review, and a production signing process. Without a runnable server environment, launch and local-access paths can be tested, but server-dependent gameplay behavior remains uncertified.
