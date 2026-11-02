$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$source = Get-Content (Join-Path $root 'driver\main.c') -Raw

function Once([string] $text, [string] $marker) {
    $at = $text.IndexOf($marker)
    if ($at -lt 0) { throw "missing $marker" }
    return $at
}

# The control device may only accept IOCTLs after the state DispatchControl
# uses (guard policy, monitor ring/mutex, hooks) has been initialized.
$guard = Once $source 'GuardInit();'
$mon = Once $source 'MonInit();'
$trace = Once $source 'TraceInit();'
$publish = Once $source 'Flags &= ~DO_DEVICE_INITIALIZING;'
$shutdown = Once $source 'IoRegisterShutdownNotification(g_Device)'

if ($publish -lt $guard -or $publish -lt $mon -or $publish -lt $trace -or
    $shutdown -lt $guard -or $shutdown -lt $mon -or $shutdown -lt $trace) {
    throw 'the control device is published before guard/monitor/trace initialization'
}

Write-Host 'init order regression passed'
