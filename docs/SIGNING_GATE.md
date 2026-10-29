# Callback registration findings (measured)

Measured 2026-10-29 on Windows 11 build 26200, Secure Boot off, `TESTSIGNING` on.
The test-signed driver loaded and attached as a minifilter at altitude 370030.
These limited registration measurements are not a full runtime certification.

## Object-callback signing gate

| Registration | Sensor slot | NTSTATUS | Meaning |
|---|---|---|---|
| `ObRegisterCallbacks` (process) | 23 | `0xC0000022` | `STATUS_ACCESS_DENIED` |
| `ObRegisterCallbacks` (thread) | 24 | `0xC0000022` | `STATUS_ACCESS_DENIED` |
| process/thread/image notify, minifilter, registry | 20-27 | `0x00000000` | success |

Both object slots receive the status from the single `ObRegisterCallbacks` call in
`driver/object.c`. While that call fails, `process_handle` and `thread_handle` events
are unavailable. The failure is disclosed as `registration_failed` rather than
silently treated as no activity.

| Attempt | Result |
|---|---|
| Test-signed (Code Signing EKU only), `TESTSIGNING` on | `0xC0000022` |
| Self-signed with Code Signing **and** `1.3.6.1.4.1.311.61.1.1` (Kernel Mode Code Signing) EKU, `TESTSIGNING` on | `0xC0000022` |

The results are consistent with the documented signing requirement for
`ObRegisterCallbacks`: `TESTSIGNING` and these self-signed certificates did not
satisfy it. Microsoft attestation or WHQL signing is the next route to test; it has
not been verified here.

## WFP result: layer-registration defect, not signing evidence

The initial run also returned `0xC0220004` for all six WFP layer slots (28-33),
while `FwpmEngineOpen` succeeded. That status is `STATUS_FWP_LAYER_NOT_FOUND`,
not a signing error.

The cause was in `MsMonAddCallout`: `FWPM_CALLOUT.applicableLayer` was zeroed but
never assigned before `FwpmCalloutAdd`. The driver now assigns the layer GUID passed
to that function. The initial `0xC0220004` results must not be used as evidence for
a WFP signing gate. The corrected WFP registration path still needs an isolated
runtime retest; success must not be inferred from compilation.

Repro: `tools/windows-test/probe-signing-gate.ps1` verifies the build hash, signs and
deploys that exact build, runs a uniquely identified agent session, and prints the
registration slots. The object slots are expected to report `0xC0000022` on the
test-signed build. A WFP failure should be decoded and investigated on its own rather
than automatically attributed to signing.

## Interim options

1. **Microsoft attestation signing** (Partner Center; requires an EV certificate).
   This is the route to test for the object-callback restriction. It cannot correct
   an invalid WFP callout definition.
2. **Sysmon** (`tools/windows-test/sysmon/`) can supplement process-handle access and
   connect/DNS telemetry. Its `ProcessAccess` event was observed with source image,
   target image, and granted access mask. It is not a replacement for the driver's
   thread-handle, duplication, accept, flow-lifetime, or BlackCat attribution events.
3. Patching kernel code integrity is out of scope and is not implemented here.

## Consequence for coverage claims

Do not read an empty `network_*` class or a missing `process_handle` class in a log as
"the client did not do it". Check the registration entries in `sensor-usage.json` and
`coverage.json`. The `coverage_manifest` derives its callback list from the driver's
registration bitmask when the coverage IOCTL is available, including individual WFP
layers; with an older driver it reports registration as unknown.
