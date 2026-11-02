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

# --- #44: the first image must carry the incarnation that callback admitted ---
# MsMonProcessStartTime only knows processes already in the tracked list, so a
# read taken before MsMonTrackClientAtFirstImage admits the client is 0, and the
# agent's early-image merge then discards the module.
$process = Get-Content (Join-Path $root 'driver\process.c') -Raw
$from = $process.IndexOf('MsMonImageNotify(PUNICODE_STRING FullImageName')
$to = if ($from -ge 0) { $process.IndexOf('static VOID MsMonProcessNotifyLegacy(', $from) } else { -1 }
if ($from -lt 0 -or $to -le $from) { throw 'MsMonImageNotify not found' }
$notify = $process.Substring($from, $to - $from)
if ($notify.Contains('LONGLONG startTime = MsMonProcessStartTime(ProcessId);')) {
    throw 'image notification reads the requestor start time before admitting the client'
}
if (-not $notify.Contains('MsMonImageLoad, ProcessId, MsMonProcessStartTime(ProcessId)')) {
    throw 'the image-load event does not carry the admitted incarnation'
}
$admit = $notify.IndexOf('MsMonTrackClientAtFirstImage(')
$readStart = $notify.IndexOf('MsMonProcessStartTime(')
if ($admit -lt 0 -or $readStart -lt 0 -or $readStart -lt $admit) {
    throw 'the image-load start time is read before the first-image admission'
}
Write-Host 'event identity regression passed'
