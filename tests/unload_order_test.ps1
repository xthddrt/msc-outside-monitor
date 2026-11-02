# unload_order_test.ps1 - the control plane must be drained before any sensor is
# torn down.
#
# MsMonDriverUnload cannot be driven from user mode, so this guards the source
# facts #24 depends on: the reader blocked in MSMON_IOCTL_READ_EVENTS is woken
# first, and gIoRundown is waited on (and then completed) before the first
# sensor uninitialize runs.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path

function Body([string] $text, [string] $startMarker, [string] $endMarker, [string] $what) {
    $start = $text.IndexOf($startMarker)
    if ($start -lt 0) { throw "$what not found" }
    $end = $text.IndexOf($endMarker, $start)
    if ($end -lt 0) { $end = $text.Length }
    return $text.Substring($start, $end - $start)
}

$driver = Get-Content (Join-Path $root 'driver\driver.c') -Raw
$unload = Body $driver 'VOID MsMonDriverUnload(' 'NTSTATUS DriverEntry(' 'MsMonDriverUnload'

$wake = $unload.IndexOf('MsMonEventsWakeAll();')
$wait = $unload.IndexOf('ExWaitForRundownProtectionRelease(&gIoRundown)')
$completed = $unload.IndexOf('ExRundownCompleted(&gIoRundown)')
if ($wake -lt 0) { throw 'MsMonDriverUnload no longer wakes a blocked event reader' }
if ($wait -lt 0) { throw 'MsMonDriverUnload no longer drains gIoRundown' }
if ($completed -lt 0) { throw 'MsMonDriverUnload no longer completes the rundown' }
if ($wake -gt $wait) {
    throw 'MsMonDriverUnload drains the control plane before waking the blocked reader'
}
if ($completed -lt $wait) {
    throw 'MsMonDriverUnload completes the rundown before waiting for in-flight control IRPs'
}

foreach ($teardown in @('MsMonNetworkUninitialize();', 'MsMonRegistryUninitialize();',
                        'MsMonFileFilterUninitialize();', 'MsMonObjectUninitialize();',
                        'MsMonProcessUninitialize();', 'MsMonAttributionStop();',
                        'MsMonEventsUninitialize();')) {
    $index = $unload.IndexOf($teardown)
    if ($index -lt 0) { throw "MsMonDriverUnload no longer calls $teardown" }
    if ($index -lt $wait) {
        throw "MsMonDriverUnload runs $teardown before draining in-flight control IRPs"
    }
}

Write-Host 'unload order regression passed'
