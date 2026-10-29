# Callback registration gate (measured)

Measured 2026-10-29 on Windows 11 build 26200, Secure Boot off, `TESTSIGNING` on,
driver otherwise loading and attaching normally as a minifilter at altitude 370030.

## Result

| Registration | Sensor slot | NTSTATUS | Meaning |
|---|---|---|---|
| `ObRegisterCallbacks` (process) | 23 | `0xC0000022` | `STATUS_ACCESS_DENIED` |
| `ObRegisterCallbacks` (thread) | 24 | `0xC0000022` | `STATUS_ACCESS_DENIED` |
| `FwpsCalloutRegister3`/`FwpmCalloutAdd` x6 | 28-33 | `0xC0220004` | undecoded; all six fail identically |
| `FwpmEngineOpen` | 34 | `0x00000000` | success |
| process/thread/image notify, minifilter, registry | 20-27 | `0x00000000` | success |

Consequence: `process_handle`, `thread_handle`, `network_connect`, `network_accept`,
`network_flow_established`, `network_flow_close` are never emitted. The driver
otherwise works; the failure is disclosed in `sensor-usage.json` as
`registration_failed`, so it is visible rather than silent.

The registration code in `driver/object.c` is correct: `OB_FLT_REGISTRATION_VERSION`,
both object types, handle create + duplicate, altitude `380011`, and zeroed
structures. The failure is a policy gate, not a parameter error.

## What does and does not clear the gate

| Attempt | Result |
|---|---|
| Test-signed (Code Signing EKU only), `TESTSIGNING` on | `0xC0000022` |
| Self-signed with Code Signing **and** `1.3.6.1.4.1.311.61.1.1` (Kernel Mode Code Signing) EKU, `TESTSIGNING` on | `0xC0000022` |

`TESTSIGNING` does not satisfy the check. Microsoft's documentation states
`ObRegisterCallbacks` returns `STATUS_ACCESS_DENIED` when the callback is not in a
signed kernel binary image, and the practical requirement is a **Microsoft-issued**
signature (attestation or WHQL), not a self-signed one.

Repro: `tools/windows-test/probe-signing-gate.ps1` creates the EKU cert, signs the
current build, restarts the driver, runs a short agent session, and prints the
registration slots above. It is expected to report `0xC0000022` on an unsigned/test-signed
build.

## Options

1. **Microsoft attestation signing** (Partner Center; requires an EV certificate).
   Expected to clear both gates; not verified here. This is the only route that keeps
   everything inside this driver.
2. **Sysmon** (`tools/windows-test/sysmon/`) covers process-handle access and
   connect/DNS on the same machine today. Verified working: `ProcessAccess` emitted
   source image, target image and granted access mask.
3. Patching kernel code integrity is out of scope and is not implemented here.

## Consequence for coverage claims

Do not read an empty `network_*` class or a missing `process_handle` class in a log as
"the client did not do it". Check `sensor-usage.json` first; those sensors report
`registration_failed` and the `coverage_manifest` record lists the callbacks that were
actually registered.
