# Legacy monitor compatibility subsystem

This directory contains the complete monitoring-related implementation reviewed from `sysinfo-monitor`, built as a separate driver and control tool. It is not installed or loaded by our build.

- Driver: `build\compat\msmon-legacy.sys` (`SysInfoMon` service/device)
- Control tool: `build\compat\msmon-legacyctl.exe`
- Policy template: `policy\example.txt`

The main `msmon.sys` driver and agent remain independent. This subsystem exists so the complete legacy capability set is available without forcing our safer implementation to adopt inline kernel hooks.

## Capability state

| Capability | Default state |
|---|---|
| Image/process/thread notifications | Implemented through supported callbacks |
| Process/thread handle monitoring | Supported object callbacks when registration is permitted, with actual status/access |
| File, registry, directory, device, memory, system-information, APC, context, callback, and device-registration hooks | **Implemented but disabled** |
| User/kernel caller attribution | Supported paths plus heuristic legacy paths that depend on unsafe hooks |
| Summary and continuous collection | Active, with visible ring-drop and summary-overflow counters |
| Guard file/registry/process-handle/memory enforcement | Guard framework present; file/registry/memory detours are disabled with their hooks |
| Inline kernel-text patching, CR0.WP changes, PatchGuard bypasses | **Not enabled and not claimed to be stable** |

`SYSINFO_ENABLE_HANDLE_HOOKS` and `SYSINFO_ENABLE_TRACE_HOOKS` both default to `0` in the compat sources. The separate runtime gate, `UnsafeHooksEnabled` in `SYSINFO_MON_CONFIG`, is also `0` by default. Inline kernel hooks therefore require a deliberate rebuild with the compile-time switch plus a deliberate runtime opt-in (`mon on [unsafe]`). Several implemented detours are also absent from the installation table, so opting in would not activate everything advertised. Do not treat any of these paths as PatchGuard-safe, and do not load this driver for normal coverage work.

## High-value fixes in this copy

- Administrator-only secure control device.
- Corrected duplicate trampoline indices for `NtDuplicateObject` and `NtQueryDirectoryFile`.
- PID included in summary and ring-fold keys to avoid merging different programs.
- Actual post-operation handle status and granted access.
- Legacy process-notification fallback when the extended API is refused.
- Corrected control-tool string types and format strings.
- No automatic signing, security disabling, or driver installation.

The identity-spoofing functionality from the separate `sysinfo` project is not added here. Its commands may remain in the shared control tool, but this monitor device does not serve them.

## Build

From the repository root:

```bat
build.cmd
```

This builds our main driver/agent and this compatibility subsystem with the installed VS2022/WDK. No signing script is run.

## Use and limits

`msmon-legacyctl.exe` supports `status`, `preflight`, `mon on`, `mon off`, `mon summary`, `mon dump`, `mon watch`, `mon collect`, and `guard` commands. Use only in an isolated signed-driver VM. Do not install this driver on a production host or enable inline hooks expecting stability.

The ring has 8192 events and drops the oldest on overflow. The summary has 8192 slots and reports overflow. `mon collect` drains continuously but **cannot guarantee lossless capture**; check the drop counters.

See `COVERAGE.md` for the capability matrix and `..\docs\TEST_VM.md` for the required validation procedure.
