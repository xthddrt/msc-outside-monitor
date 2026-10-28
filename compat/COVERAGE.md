# Compatibility coverage

## Implemented through supported paths

- Image loads with base information, including kernel images.
- Process and thread creation/exit, with legacy process-notification fallback.
- Process/thread handle creation and duplication through object callbacks when registration is permitted, with post-operation status and granted access.
- Administrator-only control device, summary counts, ring drops, and summary overflow.

## Implemented but disabled by default

These paths use inline kernel-text hooks and are not PatchGuard-safe. Both compile-time and runtime activation gates are off:

- File open/create/write/rename/delete and directory queries.
- Registry open/create/read/write/delete/enumeration.
- Device IOCTL metadata. The input-payload selection helpers are not wired into the detour and do not capture bytes.
- Process/thread handles through inline open hooks.
- Memory read/write/protect/map/create-section and process-memory copies.
- `NtQuerySystemInformation` classes.
- Handle duplication through inline hooks.
- APC queue and thread-context changes.
- Kernel callback and device registration.
- Caller attribution that depends on inline trap-frame/PEB scanning.

`MmCopyVirtualMemory` and `KeStackAttachProcess` have no stable activation path in this copy and must remain disabled. Do not enable the inline implementation on a production host.

## Not covered by the legacy monitor

- Network peers, packet bytes, or DNS; use our main driver's WFP and ETW coverage instead.
- ALPC ports and full IPC payloads.
- `CPUID`, MSR, port I/O, direct MMIO, and direct SMBIOS reads.
- IOCTL payload capture; the legacy helpers are not connected to the detour. Registry payloads are limited to 8 bytes in the legacy hooks. The main driver provides bounded registry and volume payloads instead.
- Window/input semantics.

## Storage and accuracy

The ring holds 8192 events and drops the oldest on overflow. The summary holds 8192 distinct entries and reports overflow. Summary and folding keys include PID so different programs are not merged. `mon collect` drains continuously but cannot guarantee lossless capture; always inspect drop counters.
