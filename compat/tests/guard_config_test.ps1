$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$source = Get-Content (Join-Path $root 'driver\guard.c') -Raw

function Body([string] $text, [string] $startMarker, [string] $endMarker, [string] $what) {
    $start = $text.IndexOf($startMarker)
    if ($start -lt 0) { throw "$what not found" }
    $end = $text.IndexOf($endMarker, $start)
    if ($end -lt 0) { $end = $text.Length }
    return $text.Substring($start, $end - $start)
}

# A reload fills the inactive buffer and swaps the pointer under the lock, so a
# reader never sees a zeroed or half-copied policy.
if (-not $source.Contains('g_ConfigStore[2]') -or
    -not $source.Contains('g_Config = &g_ConfigStore[0]') -or
    -not $source.Contains('KeInitializeSpinLock(&g_ConfigLock)')) {
    throw 'the guard policy is not a double-buffered, locked snapshot'
}
if ($source.Contains('SYSINFO_GUARD_CONFIG updated')) {
    throw 'the reload keeps a whole guard config on the kernel stack'
}

$configure = Body $source 'GuardConfigure(_In_' 'GuardGetStatus(' 'GuardConfigure'
$acquire = $configure.IndexOf('KeAcquireSpinLock(&g_ConfigLock')
$copy = $configure.IndexOf('RtlCopyMemory(next, g_Config')
$swap = $configure.IndexOf('g_Config = next')
$release = $configure.IndexOf('KeReleaseSpinLock(&g_ConfigLock')
if ($acquire -lt 0 -or $copy -lt 0 -or $swap -lt 0 -or $release -lt 0) {
    throw 'GuardConfigure does not build and publish the inactive buffer under the lock'
}
if ($acquire -gt $copy -or $release -lt $swap) {
    throw 'GuardConfigure copies or publishes outside the lock'
}
if ($configure.Contains('CopyAscii(g_Config.') -or $configure.Contains('CopyWide(g_Config.')) {
    throw 'GuardConfigure still rewrites the published policy in place'
}

$readers = @(
    @('GuardGetStatus(_Out_', 'GuardIsTargetProcess(', 'GuardGetStatus'),
    @('GuardIsTargetProcess(VOID)', 'GuardFileBlocked(', 'GuardIsTargetProcess'),
    @('GuardFileBlocked(_In_', 'GuardRegistryBlocked(', 'GuardFileBlocked'),
    @('GuardRegistryBlocked(_In_', 'GuardProcessHandleBlocked(_In_', 'GuardRegistryBlocked'),
    @('GuardProcessHandleBlocked(_In_', 'GuardMemoryBlocked(', 'GuardProcessHandleBlocked'),
    @('GuardPreHandle(_Inout_', 'NO_SUCH_MARKER(', 'GuardPreHandle')
)
$logging = @('LogEvent(', 'DbgPrint(', 'HandleAction(', 'MsMonLogEvent(')
foreach ($reader in $readers) {
    $body = Body $source $reader[0] $reader[1] $reader[2]
    $firstRead = $body.IndexOf('g_Config->')
    $take = $body.IndexOf('KeAcquireSpinLock(&g_ConfigLock')
    $give = $body.IndexOf('KeReleaseSpinLock(&g_ConfigLock')
    if ($take -lt 0 -or $give -lt 0 -or $take -gt $give) {
        throw "$($reader[2]) does not bracket its policy read with g_ConfigLock"
    }
    if ($firstRead -ge 0 -and $firstRead -lt $take) {
        throw "$($reader[2]) reads the policy before taking g_ConfigLock"
    }
    $held = $body.Substring($take, $give - $take)
    foreach ($call in $logging) {
        if ($held.Contains($call)) { throw "$($reader[2]) logs or emits inside g_ConfigLock" }
    }
    foreach ($call in @('PsGetProcessImageFileName(', 'ProtectedProcessImage(')) {
        if ($held.Contains($call)) { throw "$($reader[2]) looks up a process image inside g_ConfigLock" }
    }
}

# The handle guards resolve the target image before they take the lock.
foreach ($name in @('GuardProcessHandleBlocked(_In_', 'GuardPreHandle(_Inout_')) {
    $body = Body $source $name 'NO_SUCH_MARKER(' $name
    $lookup = $body.IndexOf('PsGetProcessImageFileName(')
    $take = $body.IndexOf('KeAcquireSpinLock(&g_ConfigLock')
    if ($lookup -lt 0 -or $take -lt 0 -or $lookup -gt $take) {
        throw "$name does not capture the target image before g_ConfigLock"
    }
}

Write-Host 'guard config source regression passed'
