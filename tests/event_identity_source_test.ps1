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
# --- #55: TRACK_PID must admit only the incarnation the caller resolved ------
$driver = Get-Content (Join-Path $root 'driver\driver.c') -Raw
$from = $driver.IndexOf('case MSMON_IOCTL_TRACK_PID:')
$to = if ($from -ge 0) { $driver.IndexOf('case MSMON_IOCTL_READ_EVENTS:', $from) } else { -1 }
if ($from -lt 0 -or $to -le $from) { throw 'MSMON_IOCTL_TRACK_PID not found' }
$track = $driver.Substring($from, $to - $from)
if (-not $track.Contains('(LONGLONG)request->ProcessStartTime')) {
    throw 'TRACK_PID does not pass the expected incarnation into MsMonTrackProcess'
}
if (-not $track.Contains('MsMonProcessStartTime(') -or
    $track.Contains('MsMonCategoryExternalProcess, request->ProcessStartTime')) {
    throw 'TRACK_PID logs the caller start instead of the validated stored start'
}
if (-not $process.Contains('NTSTATUS MsMonTrackProcess(HANDLE ProcessId, ULONG Flags, LONGLONG ExpectedStartTime)') -or
    -not $process.Contains('MsMonTrackAdmitsStart(')) {
    throw 'MsMonTrackProcess does not validate the expected incarnation'
}
$check = $process.IndexOf('MsMonTrackAdmitsStart(')
$insert = $process.IndexOf('InsertTailList(&gProcesses', $check)
if ($check -lt 0 -or $insert -lt 0) {
    throw 'the incarnation check does not precede the tracked-list insertion'
}
# --- #91: a legacy create/image failure must not take the exit path ----------
$from = $process.IndexOf('static VOID MsMonProcessNotifyLegacy(')
$to = if ($from -ge 0) { $process.IndexOf('static VOID MsMonRemoveProcessNotify(', $from) } else { -1 }
if ($from -lt 0 -or $to -le $from) { throw 'MsMonProcessNotifyLegacy not found' }
$legacy = $process.Substring($from, $to - $from)
$nullCalls = [regex]::Matches($legacy, [regex]::Escape('MsMonProcessNotifyInner(process, ProcessId, NULL);'))
if ($nullCalls.Count -ne 1) {
    throw 'a legacy create/image failure can still be reported as process exit'
}
$createElse = $legacy.IndexOf('} else {')
$nullCall = $legacy.IndexOf('MsMonProcessNotifyInner(process, ProcessId, NULL);')
if ($createElse -lt 0 -or $nullCall -lt $createElse -or
    -not $legacy.Contains('info.ParentProcessId = ParentId;') -or
    -not $legacy.Contains('MsMonProcessNotifyInner(process, ProcessId, &info);')) {
    throw 'the legacy image-failure branch does not preserve create semantics with a null image name'
}
Write-Host 'event identity regression passed'
