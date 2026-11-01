$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$driver = Join-Path $root 'build\compat\msmon-legacy.sys'
$control = Join-Path $root 'build\compat\msmon-legacyctl.exe'
$target = Join-Path $env:SystemRoot 'System32\drivers\msmon-legacy.sys'
$service = 'SysInfoMon'
$started = Get-Date
$jobs = @()

foreach ($path in $driver, $control) {
    if (-not (Test-Path $path)) { throw "Build compat first: missing $path" }
}

try {
    Copy-Item $driver $target -Force
    & sc.exe stop $service | Out-Null
    & sc.exe delete $service | Out-Null
    & sc.exe create $service type= filesys start= demand error= normal `
        binPath= '\SystemRoot\System32\drivers\msmon-legacy.sys' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not create $service" }

    for ($iteration = 0; $iteration -lt 20; $iteration++) {
        & sc.exe start $service | Out-Null
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056) { throw "Could not start $service" }
        & $control mon on | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not enable the monitor' }

        $jobs = 1..4 | ForEach-Object {
            Start-Job -ScriptBlock {
                param($exe)
                for ($read = 0; $read -lt 1000; $read++) {
                    & $exe mon dump | Out-Null
                    & $exe mon summary | Out-Null
                }
            } -ArgumentList $control
        }
        Start-Sleep -Milliseconds 50
        & sc.exe stop $service | Out-Null
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1062) { throw "Could not stop $service" }

        $jobs | Wait-Job -Timeout 30 | Out-Null
        if (@($jobs | Where-Object State -eq 'Running').Count -ne 0) {
            throw 'A monitor read hung during driver unload'
        }
        $jobs | Remove-Job -Force
        $jobs = @()
    }

    $bugchecks = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; StartTime=$started} `
        -ErrorAction SilentlyContinue)
    if ($bugchecks.Count -ne 0) { throw 'A bugcheck was reported during unload testing' }
    Write-Host 'compat lifetime regression passed: concurrent reads drained and driver reloaded 20 times'
} finally {
    $jobs | Stop-Job -ErrorAction SilentlyContinue
    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
    & sc.exe stop $service | Out-Null
    & sc.exe delete $service | Out-Null
}
