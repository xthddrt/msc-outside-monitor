$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$source = Get-Content (Join-Path $root 'agent\etw.cpp') -Raw

function Body([string] $text, [string] $startMarker, [string] $endMarker, [string] $what) {
    $start = $text.IndexOf($startMarker)
    if ($start -lt 0) { throw "$what not found" }
    $end = $text.IndexOf($endMarker, $start)
    if ($end -lt 0) { throw "$what end not found" }
    return $text.Substring($start, $end - $start)
}

$onTcp = Body $source 'void EtwCollector::OnTcpRecord(' 'void EtwCollector::OnCodeIntegrityRecord(' 'OnTcpRecord'
if (-not $onTcp.Contains('ResolveTcpOwner(') -or
    -not $onTcp.Contains('ProcessStartTime = ownerStart') -or
    $onTcp.Contains('scope_.StartTime(') -or $onTcp.Contains('scope_.IsTracked(pid)')) {
    throw 'OnTcpRecord does not use the owner incarnation validated by ResolveTcpOwner'
}

$onRecord = Body $source 'void EtwCollector::OnRecord(' 'static std::wstring FormatSocketAddress(' 'OnRecord'
if (-not $onRecord.Contains('ProcessStartTime = current.created') -or
    $onRecord.Contains('scope_.StartTime(')) {
    throw 'OnRecord does not retain the validated current incarnation'
}

Write-Host 'ETW owner source regression passed'
