$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$events = Get-Content (Join-Path $root 'driver\events.c') -Raw
if (-not $events.Contains('block->Event.ProcessStartTime = (ULONGLONG)ProcessStartTime;') -or
    $events.Contains('block->Event.ProcessStartTime = (ULONGLONG)MsMonProcessStartTime(ProcessId);')) {
    throw 'event emission re-reads the requestor incarnation'
}
foreach ($item in @(
    @('driver\file_filter.c', 'context->ProcessStartTime = MsMonProcessStartTime(requestor);'),
    @('driver\registry.c', 'context->ProcessStartTime = MsMonProcessStartTime(context->ProcessId);'),
    @('driver\object.c', 'context->ProcessStartTime = MsMonProcessStartTime(source);'),
    @('driver\network.c', 'context->ProcessStartTime = MsMonProcessStartTime(context->ProcessId);')
)) {
    $source = Get-Content (Join-Path $root $item[0]) -Raw
    if (-not $source.Contains($item[1])) { throw "$($item[0]) does not capture request start time" }
    if (-not $source.Contains('ProcessStartTime,')) { throw "$($item[0]) does not propagate request start time" }
}
Write-Host 'event identity regression passed'
