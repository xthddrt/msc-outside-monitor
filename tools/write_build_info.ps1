param([string]$Root)
$ErrorActionPreference = 'Stop'
$Root = $Root.TrimEnd('\')
$driver = Join-Path $Root 'build\Release\driver\msmon.sys'
$agent = Join-Path $Root 'build\Release\agent\msmon-agent.exe'
$commit = 'unknown'
$gitPath = $null
$git = Get-Command git -ErrorAction SilentlyContinue
if ($git) { $gitPath = $git.Source }
if (-not $gitPath) {
    $candidate = Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
    if (Test-Path $candidate) { $gitPath = $candidate }
}
if ($gitPath) {
    try {
        $value = (& $gitPath -C $Root rev-parse HEAD 2>$null)
        if ($value) { $commit = "$value".Trim() }
    } catch { $commit = 'unknown' }
}
function Hash-File([string]$Path) {
    if (Test-Path $Path) { return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower() }
    return ''
}
$record = [ordered]@{
    schema_version = 1
    commit = "$commit".Trim()
    built_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    driver_sha256 = Hash-File $driver
    agent_sha256 = Hash-File $agent
}
$json = $record | ConvertTo-Json
$path = Join-Path $Root 'build\build-info.json'
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($path, $json, $utf8)
Write-Host "build-info: $path"
