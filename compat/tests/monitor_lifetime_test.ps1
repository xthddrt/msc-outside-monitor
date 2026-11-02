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
if (-not $quiesce.Contains('while (g_InHook != 0)') -or $quiesce.Contains('maxMilliseconds')) {
    throw 'detour quiesce is not unbounded'
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
$free = $stop.IndexOf('TraceFreeTrampolines()')
if ($restore -lt 0 -or $drain -lt $restore -or $free -lt $drain) {
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
Write-Host 'monitor lifetime regression passed'
