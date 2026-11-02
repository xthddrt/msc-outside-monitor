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
    -not $onTcp.Contains('QueryProcessFacts(pid)') -or
    $onTcp.Contains('FactsForPid(') -or
    $onTcp.Contains('scope_.StartTime(') -or $onTcp.Contains('scope_.IsTracked(pid)')) {
    throw 'OnTcpRecord does not use the owner incarnation validated from a fresh identity query'
}

$onRecord = Body $source 'void EtwCollector::OnRecord(' 'static std::wstring FormatSocketAddress(' 'OnRecord'
if (-not $onRecord.Contains('ProcessStartTime = current.created') -or
    -not $onRecord.Contains('QueryProcessFacts(attributedPid)') -or
    $onRecord.Contains('FactsForPid(') -or
    $onRecord.Contains('scope_.StartTime(')) {
    throw 'OnRecord does not retain the validated current incarnation from a fresh identity query'
}

# The one-second cache may only feed the candidate heuristic (MayBelongToClient).
# A cached fact must never authorize an immediate emit: a PID reused inside the
# TTL would otherwise be attributed to the previous client incarnation.
$factsDefinition = Body $source 'ProcessFacts EtwCollector::FactsForPid(' 'bool EtwCollector::MayBelongToClient(' 'FactsForPid'
$mayBelong = Body $source 'bool EtwCollector::MayBelongToClient(' 'EtwCollector::~EtwCollector(' 'MayBelongToClient'
$rest = $source.Replace($factsDefinition, '').Replace($mayBelong, '')
if ($rest.Contains('FactsForPid(')) {
    throw 'a cached PID fact is still used outside MayBelongToClient'
}

Write-Host 'ETW owner source regression passed'
