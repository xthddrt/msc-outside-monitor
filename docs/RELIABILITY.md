# Reliability audit

This document records the defects found in the driver while investigating host
bugchecks, and what was changed. It is an audit trail, not a claim that the
driver is production ready. Every item below still needs the VM procedure in
`TEST_VM.md`, ideally under Driver Verifier with `/standard /all`, plus
`/em` applied to non-Microsoft drivers when the build is test-signed.

## Fatal on driver stop / unload

### 1. Load-image notification was never removed

`MsMonProcessUninitialize` called `PsSetLoadImageNotifyRoutine(MsMonImageNotify)`
a second time to "unregister" the callback. The removal API is
`PsRemoveLoadImageNotifyRoutine`. Windows rejects a duplicate registration, so
the routine stayed in the kernel's notification list, pointing into a driver
image that was about to be unmapped.

Effect: the next image load anywhere on the system (any DLL in any process)
jumps into unmapped code. This shows up as a fault in an unloaded module
(`PAGE_FAULT_IN_NONPAGED_AREA`, `IRQL_NOT_LESS_OR_EQUAL`), or under Driver
Verifier as `0xC4` with the "driver unloaded without cancelling a notification
routine" subcode.

Fixed in `driver/process.c`.

### 2. Unload while a collector was blocked in `MSMON_IOCTL_READ_EVENTS`

The read IOCTL sleeps up to one second waiting for events. Nothing made
`DriverUnload` wait for that in-flight IRP or wake it, so the device object was
deleted while a dispatch routine was still executing, and teardown raced with a
live `gQueue`. This is `0xCE` `DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS`,
the signature reported for this driver.

Fixed with an `EX_RUNDOWN_REF` around every dispatch plus an explicit wake:
after waking readers, unload calls `ExWaitForRundownProtectionRelease` (which
refuses new acquisitions and blocks until the in-flight IRPs finish) and only
then `ExRundownCompleted`, which is the documented order
(`driver/driver.c`, `driver/events.c`). Session stop also wakes readers.

### 3. Minifilter could be detached twice

`MsMonFilterUnload` returned `STATUS_SUCCESS`, so `fltmc unload` detached the
filter while the driver kept running. The later `FltUnregisterFilter` in
`DriverUnload` then operated on an already-unregistered filter. The filter is
part of a multi-purpose legacy driver and cannot be detached alone, so the
callback now returns `STATUS_FLT_DO_NOT_DETACH`.

## Runtime stability

### 4. WFP call made while holding a spin lock

`MsMonAssociateFlow` called `FwpsFlowAssociateContext0` with `gFlowLock` held.
The flow-delete callback (`MsMonWfpFlowDelete`) is invoked by WFP holding its
own internal flow lock and takes `gFlowLock`. The two lock orders are opposite,
which is a hard deadlock at `DISPATCH_LEVEL` (typically `CLOCK_WATCHDOG_TIMEOUT`
or a frozen machine) whenever a flow is torn down while another is being
associated.

WFP is now called without the lock, and the context is linked afterwards.

### 5. WFP teardown order and ignored unregister status

Flow contexts were freed after `FwpmEngineClose`, and
`FwpsCalloutUnregisterById` failures were ignored while the driver cleared its
own bookkeeping. A callout that fails to unregister still points at the driver
image after unload.

Flow contexts are now removed before the engine closes, and the registered flag
is cleared only when unregistration actually succeeds (failure is reported with
`DbgPrint`). The `...ById0` variant is used with the `FWPS_CALLOUT3`
registration.

### 6. Unchecked WFP field indexing

The callout indexed `InFixedValues->incomingValue[]` with hard-coded layer field
ids. It now verifies every field id against `valueCount` before use, and checks
`Filter`, `InFixedValues`, `InMetaValues`, `ClassifyOut` for `NULL`.

### 7. File-name queries at unsafe IRQL and in post-create

* `FltGetFileNameInformation` is documented for `IRQL <= APC_LEVEL`. Paging I/O
  and some cleanup paths can reach a minifilter above that, so every call is now
  IRQL guarded.
* Create names were queried from the post-operation callback with
  `FLT_FILE_NAME_QUERY_DEFAULT`, which may issue file-system I/O from a
  post-create path and is not valid when the create failed. Names are now
  resolved in a pre-create callback (the documented place) and the post-create
  path only reads the cached result, applies `FltGetTunneledName`, and releases
  it. `Parameters.Create.SecurityContext` is read only when the create
  succeeded.
* `IRP_MJ_READ` / `IRP_MJ_WRITE` registrations now set
  `FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO`; a telemetry filter has no
  reason to observe paging I/O, and that path is both the highest risk and the
  highest volume.
* Post-operation callbacks skip all work when
  `FLTFL_POST_OPERATION_DRAINING` is set.

### 8. Volume-information capture used unsupported buffer APIs

`IRP_MJ_QUERY_VOLUME_INFORMATION` is not one of the operations
`FltLockUserBuffer` supports, and the code called it (and
`FltDecodeParameters`) from a post-operation callback, then dereferenced the
result as a kernel pointer. For a user-mode requestor the buffer is a user
address, and a post-operation callback can run in a different process context,
so that was a wild kernel read.

The capture now reads `Parameters.QueryVolumeInformation.VolumeBuffer`
directly, requires `IRQL == PASSIVE_LEVEL`, requires the requesting process to
be the current process for user addresses, probes user addresses, guards the
copy with `SEH`, caps the copy at 1 KiB, and records `payload_unavailable` with
a reason otherwise.

## Bounds and teardown hardening

### 9. Unbounded payload chunking

One registry value could turn into thousands of 8 KiB records of nonpaged pool
(and a stalled registry callback). Registry values are captured up to 64 KiB
and larger values are reported as incomplete (`MsMonFlagPayloadPartial`);
`MsMonLogPayloadSeries` rejects operations above 8 MiB / 1024 chunks.

### 10. Teardown of uninitialised subsystems

If an early `DriverEntry` step failed, the cleanup path still called teardown
for the process tracker and the event queue, which used an uninitialised
`KMUTEX` and list head. Both now have an initialised flag and return early.

### 11. Missing NULL checks in the object post-operation callback

`OB_POST_OPERATION_INFORMATION.Parameters` and `Object` are now checked before
use, and the allocated call context is freed on every path.

## Not changed

* Full-payload registry and volume capture is still the default; logs still
  contain identifiers and secrets.
* `MsMonCurrentIsBlackCat` still walks the kernel stack for every event while a
  BlackCat image is loaded. That is a deliberate accuracy/cost trade-off; it is
  expensive under heavy file I/O and shows up as throughput loss, not as a
  crash.
* The `compat/` legacy driver is untouched. Its inline hooks remain disabled.
* No packet payload, file content, or TLS capture is added.

## Suggested verification

1. Load, start the agent, then `sc stop msmon` **while the agent is still
   running**. No bugcheck, no hung unload.
2. Repeat start/stop ten times, including with `fltmc unload msmon` attempted
   (it must fail with `FLT_DO_NOT_DETACH`).
3. Exercise the game's connect/accept path heavily and stop the driver while
   flows are open.
4. Query volume information from a tracked process and from an unrelated
   process; confirm the payload matches and that the foreign-context case is
   recorded as unavailable.
5. Run Driver Verifier with `/standard /all` and `/em` for `msmon.sys` through
   the checklist in `TEST_VM.md`.