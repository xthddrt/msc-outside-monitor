$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$source = Get-Content (Join-Path $root 'tools\sysinfoctl.c') -Raw

function Body([string] $text, [string] $startMarker, [string] $endMarker, [string] $what) {
    $start = $text.IndexOf($startMarker)
    if ($start -lt 0) { throw "$what not found" }
    $end = $text.IndexOf($endMarker, $start)
    if ($end -lt 0) { $end = $text.Length }
    return $text.Substring($start, $end - $start)
}

# CmdMonSummary converts a 160-WCHAR subject to UTF-8; a 3x buffer is the
# worst case, and the conversion must be checked and terminated on failure.
$summary = Body $source 'CmdMonSummary(const char' 'CmdMonDump(' 'CmdMonSummary'
if (-not $summary.Contains('char subject[SYSINFO_SUMMARY_SUBJECT * 3 + 1];')) {
    throw 'the summary subject buffer is not sized for UTF-8'
}
if (-not $summary.Contains('subject[0] = 0;')) {
    throw 'the summary subject is not initialised before the conversion'
}
if (-not $summary.Contains('WideCharToMultiByte(CP_UTF8, 0, rows[i].Subject, -1, subject,')) {
    throw 'the summary subject is not converted with the sized buffer'
}
if (-not $summary.Contains('== 0) {') -or -not $summary.Contains('strcpy_s(subject')) {
    throw 'a failed summary conversion is not checked and replaced with a terminated fallback'
}

Write-Host 'summary UTF-8 regression passed'
