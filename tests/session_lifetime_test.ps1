$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$driver = Get-Content (Join-Path $root 'driver\driver.c') -Raw

$from = $driver.IndexOf('static NTSTATUS MsMonStartSession(')
$to = if ($from -ge 0) { $driver.IndexOf('static NTSTATUS MsMonDeviceControl(', $from) } else { -1 }
if ($from -lt 0 -or $to -le $from) { throw 'MsMonStartSession not found' }
$start = $driver.Substring($from, $to - $from)
$take = $start.IndexOf('KeWaitForSingleObject(&gSessionMutex')
$stop = $start.IndexOf('MsMonProcessStopSession()')
$give = $start.LastIndexOf('KeReleaseMutex(&gSessionMutex')
if (-not $driver.Contains('static KMUTEX gSessionMutex;') -or
    -not $driver.Contains('KeInitializeMutex(&gSessionMutex, 0);')) {
    throw 'session mutex is not initialized'
}
if ($take -lt 0 -or $stop -lt $take -or $give -lt $stop -or
    $give -gt $start.LastIndexOf('return status;')) {
    throw 'session start is not covered by the session mutex'
}
if ($start.Contains('return STATUS_INVALID_PARAMETER;') -or
    $start.Contains('if (!NT_SUCCESS(status)) return status;')) {
    throw 'a session start exit bypasses the session mutex release'
}
foreach ($case in @('case MSMON_IOCTL_STOP_SESSION:', 'case MSMON_IOCTL_STOP_TRACKING:')) {
    $from = $driver.IndexOf($case)
    $to = if ($from -ge 0) { $driver.IndexOf('case MSMON_IOCTL_', $from + $case.Length) } else { -1 }
    if ($from -lt 0 -or $to -le $from) { throw "$case not found" }
    $body = $driver.Substring($from, $to - $from)
    if (-not $body.Contains('KeWaitForSingleObject(&gSessionMutex') -or
        -not $body.Contains('KeReleaseMutex(&gSessionMutex')) {
        throw "$case is not serialized with session start"
    }
}
Write-Host 'session lifetime regression passed'
