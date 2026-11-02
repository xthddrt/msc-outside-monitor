$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$hooks = Get-Content (Join-Path $root 'driver\hooks.c') -Raw
$trace = Get-Content (Join-Path $root 'driver\trace.c') -Raw
$monitor = Get-Content (Join-Path $root 'driver\monitor.c') -Raw

function Body([string]$text, [string]$start, [string]$end) {
    $a = $text.IndexOf($start)
    if ($a -lt 0) { throw "missing $start" }
    if ([string]::IsNullOrEmpty($end)) { $b = $text.Length }
    else { $b = $text.IndexOf($end, $a) }
    if ($b -lt 0) { throw "missing $end" }
    return $text.Substring($a, $b - $a)
}

$quiesce = Body $hooks 'HookQuiesce(VOID)' 'SysinfoPatchMethod'
if ($quiesce.Contains('while (g_InHook != 0)')) {
    throw 'detour quiesce still waits for the caller''s own detour'
}
if (-not $quiesce.Contains('while (HookCountedFrames() > ownDepth)')) {
    throw 'detour quiesce does not exclude own depth and parked control callers'
}
$counted = Body $hooks 'HookCountedFrames(VOID)' 'HookDrainAll(VOID)'
if (-not $counted.Contains('g_InHook') -or -not $counted.Contains('g_HookParkedFrames') -or
    $counted.Contains('g_HookControlWaiters') -or
    $counted.IndexOf('g_InHook') -gt $counted.IndexOf('g_HookParkedFrames')) {
    throw 'quiesce does not subtract actual parked detour frames from the drain'
}
$parked = Body $hooks 'HookParkedFrames(_In_ BOOLEAN Enter)' 'HookControlWaitEnter(VOID)'
if (-not $parked.Contains('KeGetCurrentThread()') -or -not $parked.Contains('g_HookThreadLock') -or
    -not $parked.Contains('record->Depth') -or -not $parked.Contains('record->ParkedFrames') -or
    -not $parked.Contains('record->ParkedFrames = 0;')) {
    throw 'parked accounting does not capture and clear the current thread detour depth'
}
$waitEnter = Body $hooks 'HookControlWaitEnter(VOID)' 'HookControlWaitLeave(VOID)'
$waitLeave = Body $hooks 'HookControlWaitLeave(VOID)' 'HookCountedFrames(VOID)'
if (-not $waitEnter.Contains('HookParkedFrames(TRUE)') -or
    -not $waitEnter.Contains('InterlockedAdd(&g_HookParkedFrames, frames)') -or
    -not $waitLeave.Contains('HookParkedFrames(FALSE)') -or
    -not $waitLeave.Contains('InterlockedAdd(&g_HookParkedFrames, -frames)')) {
    throw 'control waiters do not add and subtract their exact parked depth'
}
if ($hooks.Contains('g_HookControlWaiters')) {
    throw 'the unconditional one-per-control-waiter accounting remains'
}
if ($quiesce.Contains('maxMilliseconds')) {
    throw 'detour quiesce is not unbounded'
}
$config = Body $monitor 'MonConfigure(_In_ const SYSINFO_MON_CONFIG *config)' 'MonQuery('
$park = $config.IndexOf('HookControlWaitEnter()')
$mutex = $config.IndexOf('KeWaitForSingleObject(&g_MonConfigMutex')
$unpark = $config.IndexOf('HookControlWaitLeave()')
$disable = $config.IndexOf('TraceSetUnsafeHooksEnabled(0)')
if ($park -lt 0 -or $mutex -lt $park -or $unpark -lt $mutex -or $disable -lt $unpark) {
    throw 'MON_CONFIG does not exempt itself only while parked on the config mutex'
}
$enter = Body $hooks 'HookEnter(VOID)' 'HookLeave(VOID)'
$leave = Body $hooks 'HookLeave(VOID)' 'HookQuiesce(VOID)'
if (-not $enter.Contains('KeGetCurrentThread()') -or -not $enter.Contains('Depth') -or
    -not $leave.Contains('KeGetCurrentThread()') -or -not $leave.Contains('Depth')) {
    throw 'detour enter/leave does not maintain a per-thread depth'
}
if (-not $enter.Contains('InterlockedIncrement(&g_InHook)') -or
    -not $leave.Contains('InterlockedDecrement(&g_InHook)')) {
    throw 'detour enter/leave does not balance the global count'
}
# One allocation per thread, not one per detour, and a counted fallback when it fails.
if ([regex]::Matches($enter, 'ExAllocatePool2\(').Count -ne 1) {
    throw 'detour entry allocates a depth record on every call instead of once per thread'
}
if (-not $enter.Contains('record->ParkedFrames = 0;')) {
    throw 'a new detour depth record does not initialize its parked depth'
}
if (-not $enter.Contains('InterlockedIncrement(&g_HookThreadsUntracked)')) {
    throw 'a missing depth record is not counted as untracked'
}
if (-not $quiesce.Contains('g_HookThreadsUntracked, 0, 0) != 0') -or
    -not $quiesce.Contains('return FALSE;')) {
    throw 'quiesce waits or frees when the caller''s depth is unknown'
}
if (-not $hooks.Contains('HookInitialize(VOID)') -or
    -not $hooks.Contains('KeInitializeSpinLock(&g_HookThreadLock')) {
    throw 'the per-thread depth lock is not initialized'
}
$remove = Body $hooks 'HookRemove(_Inout_ PHOOK hook)' 'HookFree(_Inout_ PHOOK hook)'
if ($hooks -notmatch 'NTSTATUS\s+HookRemove\(_Inout_ PHOOK hook\)' -or $remove.Contains('return;')) {
    throw 'prologue restoration failure is not propagated'
}
if ($remove.Contains('ExFreePoolWithTag')) {
    throw 'HookRemove frees the trampoline before the detour drain'
}
$main = Get-Content (Join-Path $root 'driver\main.c') -Raw
$stop = Body $main 'MonitorStopHooks(VOID)' 'DispatchShutdown('
$restore = $stop.IndexOf('TraceShutdown(')
$drain = $stop.IndexOf('HookQuiesce()')
$drainAll = $stop.IndexOf('HookDrainAll()')
$free = $stop.IndexOf('TraceFreeTrampolines()')
if ($restore -lt 0 -or $drain -lt $restore -or $drainAll -lt $drain -or $free -lt $drainAll) {
    throw 'unload does not restore, drain, then free the trampolines'
}
$enable = Body $trace 'TraceSetUnsafeHooksEnabled(_In_ ULONG enabled)' 'TraceUnsafeHooksEnabled'
$restore = $enable.IndexOf('TraceShutdown()')
$drain = $enable.IndexOf('HookQuiesce()')
$free = $enable.IndexOf('TraceFreeTrampolines()')
if ($restore -lt 0 -or $drain -lt $restore -or $free -lt $drain) {
    throw 'mon off does not restore, drain, then free the trampolines'
}
$shutdown = Body $trace 'TraceShutdown(VOID)' 'TraceHookCount'
if (-not $shutdown.Contains('while (g_Hooks[i].Installed)')) {
    throw 'failed prologue restoration is not retried'
}
$moninit = Body $monitor 'MonInit(VOID)' 'MonShutdown(VOID)'
if (-not $moninit.Contains('HookInitialize()')) {
    throw 'MonInit does not initialize the detour depth table'
}
$config = Body $monitor 'MonConfigure(_In_ const SYSINFO_MON_CONFIG *config)' 'MonQuery('
if (-not $config.Contains('KeWaitForSingleObject(&g_MonConfigMutex') -or
    -not $config.Contains('KeReleaseMutex(&g_MonConfigMutex')) {
    throw 'MON_CONFIG is not serialized'
}
$early = $config.IndexOf('if (config->Enable == 0)')
$disable = $config.IndexOf('TraceSetUnsafeHooksEnabled(0)')
if ($early -lt 0 -or $disable -lt 0 -or $disable -gt $early -or $config.Contains('if (!config->Enable)')) {
    throw 'mon off does not disable unsafe hooks'
}
# --- #92: the kernel-image flag lives in Type, where the consumers read it ---
$image = Body $monitor 'ImageNotify(_In_opt_ PUNICODE_STRING fullImageName' 'ProcessNotifyEx(_In_ PEPROCESS Process'
if (-not $image.Contains('type |= SYSINFO_MON_KERNEL;') -or $image.Contains('op |= SYSINFO_MON_KERNEL')) {
    throw 'a kernel image is not marked in the event Type'
}
$toolSource = Get-Content (Join-Path $root 'tools\sysinfoctl.c') -Raw
if ([regex]::Matches($toolSource, 'e->Type & SYSINFO_MON_KERNEL').Count -lt 3) {
    throw 'the kernel-image consumers no longer read the flag from Type'
}
# --- #93: a caller-supplied length pointer is probed and read under a handler
$sysinfo = Body $trace 'HookNtQuerySystemInformation(' 'LogCallback('
if (-not $sysinfo.Contains('__try') -or -not $sysinfo.Contains('ProbeForRead(ReturnLength') -or
    $sysinfo.Contains('? *ReturnLength :')) {
    throw 'the NtQuerySystemInformation length pointer is read without a probe and handler'
}
if ($sysinfo.IndexOf('ProbeForRead(ReturnLength') -gt $sysinfo.IndexOf('reported = *ReturnLength')) {
    throw 'ReturnLength is read before it is probed'
}
$summary = Body $monitor 'MonSummary(_In_reads_bytes_' '/* pid/tid of 0 means'
$take = $summary.IndexOf('KeAcquireSpinLock(&g_SumLock')
$copy = $summary.IndexOf('entries[count++] = g_Sum[i]')
$give = $summary.IndexOf('KeReleaseSpinLock(&g_SumLock')
if ($take -lt 0 -or $copy -lt $take -or $give -lt $copy) {
    throw 'summary is not copied under g_SumLock'
}
$publish = $config.IndexOf('g_Ring = ring;')
$capacity = $config.IndexOf('g_Cap = MON_RING_EVENTS;')
$head = $config.IndexOf('g_Head = 0;')
$tail = $config.IndexOf('g_Tail = 0;')
if ($publish -lt 0 -or $capacity -lt 0 -or $head -lt 0 -or $tail -lt 0 -or
    $capacity -gt $publish -or $head -gt $publish -or $tail -gt $publish) {
    throw 'ring is published before its capacity and cursors'
}
# --- #101: the installed protection detour is accounted before fallible work ---
$protect = Body $trace 'HookNtProtectVirtualMemory(' 'HookNtMapViewOfSection('
$entered = $protect.IndexOf('HookEnter();')
$previousMode = $protect.IndexOf('ExGetPreviousMode()')
$probe = $protect.IndexOf('ProbeForRead(')
if ($entered -lt 0 -or $previousMode -lt $entered -or $probe -lt $entered) {
    throw 'NtProtectVirtualMemory touches caller state before entering detour accounting'
}
if ([regex]::Matches($protect, 'HookEnter\(\);').Count -ne 1) {
    throw 'NtProtectVirtualMemory does not have exactly one detour entry'
}
# --- #102: a failed build cannot leave a freed trampoline for a second cleanup ---
$failedBuild = Body $hooks 'status = BuildTrampoline(hook, build, &built);' 'if (hook->PoolTramp) {'
if (-not $failedBuild.Contains('HookFree(hook);') -or
    $failedBuild.Contains('ExFreePoolWithTag(hook->PoolBase')) {
    throw 'a failed trampoline build does not clear its pool allocation exactly once'
}
$freeHook = Body $hooks 'HookFree(_Inout_ PHOOK hook)' 'HookResetTrampolinePool'
if (-not $freeHook.Contains('hook->PoolBase = NULL;') -or
    -not $freeHook.Contains('hook->PoolTramp = FALSE;')) {
    throw 'HookFree leaves a freed trampoline published for another free'
}
# --- #116: no detour may read its trampoline before entering accounting ---
$detours = [regex]::Matches($trace, 'static\s+(?:NTSTATUS|VOID)\s+NTAPI\s+(\w+)\s*\(')
for ($index = 0; $index -lt $detours.Count; $index++) {
    $start = $detours[$index].Index
    $end = if ($index + 1 -lt $detours.Count) { $detours[$index + 1].Index } else { $trace.Length }
    $body = $trace.Substring($start, $end - $start)
    if (-not $body.Contains('g_Hooks[')) { continue }
    $entered = $body.IndexOf('HookEnter();')
    $trampoline = $body.IndexOf('g_Hooks[')
    if ($entered -lt 0 -or $trampoline -lt $entered) {
        throw "$($detours[$index].Groups[1].Value) reads its trampoline before HookEnter"
    }
    if ([regex]::Matches($body, 'HookEnter\(\);').Count -ne 1 -or
        [regex]::Matches($body, 'HookLeave\(\);').Count -lt 1) {
        throw "$($detours[$index].Groups[1].Value) does not balance detour accounting"
    }
}
foreach ($name in 'OpenProcessHook', 'OpenThreadHook') {
    $end = if ($name -eq 'OpenThreadHook') { '/* Legacy routine:' } else { 'typedef NTSTATUS (NTAPI *PFN_' }
    $body = Body $monitor "$name(" $end
    $entered = $body.IndexOf('HookEnter();')
    $trampoline = $body.IndexOf('.Trampoline')
    if ($entered -lt 0 -or $trampoline -lt $entered) {
        throw "$name reads its trampoline before HookEnter"
    }
}
Write-Host 'monitor lifetime regression passed'
