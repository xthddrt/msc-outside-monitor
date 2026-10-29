# Callback registration findings (measured)

Measured 2026-10-29 on Windows 11 build 26200, Secure Boot off, `TESTSIGNING` on.
The test-signed driver loaded and attached as a minifilter at altitude 370030.
These limited registration measurements are not a full runtime certification.

## Object callbacks: image was not linked with `/INTEGRITYCHECK`

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

Both measured builds were linked without `/INTEGRITYCHECK`, so the image did not carry
`IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` (`0x0080`). `ObRegisterCallbacks` returns
`STATUS_ACCESS_DENIED` for callbacks in an image without that flag regardless of the
certificate, which matches the EKU change having no effect. These results are not
evidence that a Microsoft-issued signature is required.

`driver/msmon.vcxproj` now links with `/INTEGRITYCHECK`, and `build.cmd` records the
flag as `driver_force_integrity` in `build/build-info.json`. With the flag set, the
kernel validates the signature at load; under `TESTSIGNING` a test-signed build is
expected to load and register object callbacks. **Not yet verified on the test host:**
rerun `probe-signing-gate.ps1` and replace this paragraph with the measured slot 23/24
status. If those slots still report `0xC0000022` on a build with
`driver_force_integrity: true`, Microsoft attestation signing is the next route to test.

## WFP result: layer-registration defect, not signing evidence

The initial run also returned `0xC0220004` for all six WFP layer slots (28-33),
while `FwpmEngineOpen` succeeded. That status is `STATUS_FWP_LAYER_NOT_FOUND`,
not a signing error.

The cause was in `MsMonAddCallout`: `FWPM_CALLOUT.applicableLayer` was zeroed but
never assigned before `FwpmCalloutAdd`. The driver now assigns the layer GUID passed
to that function. The initial `0xC0220004` results must not be used as evidence for
a WFP signing gate. The corrected WFP registration path still needs an isolated
runtime retest; success must not be inferred from compilation.

## Repro

`tools/windows-test/probe-signing-gate.ps1` refuses a build whose hash does not match
`build-info.json` or whose `driver_force_integrity` is not `true`, then signs and deploys
that exact build, runs a uniquely identified agent session, and prints the registration
slots. On a `/INTEGRITYCHECK` build all object and WFP slots are expected to report
`0x00000000`; any failure should be decoded and investigated on its own rather than
attributed to signing.

## Interim options

1. **Rebuild with `/INTEGRITYCHECK` and rerun the probe.** This is the expected fix for
   the object-callback denial and keeps everything inside this driver.
2. **Microsoft attestation signing** (Partner Center; requires an EV certificate), only
   if option 1 still reports `0xC0000022`. It cannot correct an invalid WFP callout
   definition.
3. **Sysmon** (`tools/windows-test/sysmon/`) can supplement process-handle access and
   connect/DNS telemetry while the driver result is unverified. Its `ProcessAccess`
   event was observed with source image, target image, and granted access mask. It is
   not a replacement for the driver's thread-handle, duplication, accept, flow-lifetime,
   or BlackCat attribution events.
4. Patching kernel code integrity is out of scope and is not implemented here.

## Consequence for coverage claims

Do not read an empty `network_*` class or a missing `process_handle` class in a log as
"the client did not do it". Check the registration entries in `sensor-usage.json` and
`coverage.json`. The `coverage_manifest` derives its callback list from the driver's
registration bitmask when the coverage IOCTL is available, including individual WFP
layers; with an older driver it reports registration as unknown.
