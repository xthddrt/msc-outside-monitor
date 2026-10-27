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

Full registry/volume payload capture is enabled by default. Add `--no-payloads` for metadata-only collection and sanitized WMI queries. Stop the collector with Ctrl+C before stopping the driver so it can stop new tracking, drain queued records, and write final statistics.

## Validation checklist

- Start the collector before the game. Verify exact-path root/helper registration, descendant inheritance, PID + creation-time identity, and no tracking of an unrelated same-named executable.
- Confirm process/thread start/exit, image paths, module bases/sizes, and command lines when available.
- From a controlled tracked process, open and duplicate handles to another process/thread. Verify target PID/image, requested/granted access, and result without changing access.
- Perform controlled file reads/writes, directory enumeration, rename/set-information, named-pipe, and visible device-control operations. Verify paths, status, lengths/offsets, and missing-path flags. Generic file and named-pipe contents are intentionally not captured in this version.
- Use synthetic registry strings, multi-strings, DWORD/QWORD values, binary data, and values larger than 8 KiB. Verify exact Base64 bytes, friendly decoded values, chunk ordering, and final operation status. Compare the values with the known inputs, not with real credentials or production identifiers.
- Test failed, partial, and unsupported registry queries. Confirm they produce `payload_unavailable` and never claim complete values.
- Issue a controlled volume-information request. Compare the logged raw result, exact serial number, creation time, and label with the VM's known values. Test buffer failures and confirm unavailable reasons.
- Issue controlled WMI hardware and non-hardware queries. Verify original query text in full mode, sanitization with `--no-payloads`, client correlation, and module attribution. Confirm the log explicitly notes that WMI result rows are unavailable.
- Enable an isolated network and verify IPv4/IPv6 connect/accept and flow establish/close correlation. Packet payloads and TLS plaintext remain outside this version's coverage.
- Launch an external URL/browser through the client or a controlled descendant. Distinguish direct child creation, handle access, and brokered/RPC evidence.
- Start/stop the collector and driver repeatedly, including with pending reads and active flows. Check for hangs, stale sessions, leaked contexts, and bugchecks.
- Run Driver Verifier and controlled stress tests. Exceed record and byte queue limits; verify source gaps, incomplete payload operations, and final drop statistics. Test multi-megabyte values and unsafe-IRQL paths without using sensitive payloads.
- Exercise PID reuse and protected-process cases; review zero creation times and unknown attribution rather than treating them as strong identity.
- Validate logs with `python tools\verify_log.py <parts-in-order>`. Confirm malformed Base64, duplicate/missing/out-of-order chunks, incorrect decoded values, and hash-chain tampering are rejected or reported.
- Review logs for exact registry values, hardware identifiers, paths, command lines, DNS names, and original WMI queries before sharing them. Never commit real payload logs.

A successful compile is not evidence that kernel runtime behavior is safe. Production use requires the full checklist, independent driver review, and a production signing process. Without a runnable server environment, server-dependent gameplay behavior remains uncertified.
