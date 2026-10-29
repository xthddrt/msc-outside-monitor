# Elevated: replace the loaded (10/28) driver with the current build and restart it.
$ErrorActionPreference = 'Continue'
function Say($m) { Write-Host $m }
$repo = 'C:\Users\richa\Documents\Default Project\msc-outside-monitor'
$build = Join-Path $repo 'build\Release\driver\msmon.sys'
$info  = Get-Content (Join-Path $repo 'build\build-info.json') | ConvertFrom-Json
$target = Join-Path $env:SystemRoot 'System32\drivers\msmon.sys'
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq 'CN=msmon test signing' | Sort-Object NotAfter -Descending | Select-Object -First 1
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe |
            Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1

Say "== verify build matches build-info =="
$h = (Get-FileHash $build -Algorithm SHA256).Hash.ToLower()
Say "build sha256 : $h"
Say "build-info   : $($info.driver_sha256)"
Say "match: $($h -eq $info.driver_sha256)   commit: $($info.commit.Substring(0,8))"

Say "== sign current build =="
$work = Join-Path $env:TEMP 'msmon-sign'
New-Item -ItemType Directory -Force -Path $work | Out-Null
Copy-Item $build (Join-Path $work 'msmon.sys') -Force
& $signtool.FullName sign /sm /s My /sha1 $cert.Thumbprint /fd sha256 (Join-Path $work 'msmon.sys') | Out-Null
Say "signed: $((Get-AuthenticodeSignature (Join-Path $work 'msmon.sys')).Status)"

Say "== stop collector + driver =="
New-Item -ItemType File -Path 'C:\msmon-sessions\STOP' -Force | Out-Null
for ($i=0; $i -lt 40; $i++) { if (-not (Get-Process msmon-agent -ErrorAction SilentlyContinue)) { break }; Start-Sleep -Milliseconds 500 }
Remove-Item 'C:\msmon-sessions\STOP' -Force -ErrorAction SilentlyContinue
Say "agent running: $([bool](Get-Process msmon-agent -ErrorAction SilentlyContinue))"
& sc.exe stop msmon 2>&1 | ForEach-Object { Say "  $_" }
for ($i=0; $i -lt 30; $i++) { if ((& sc.exe query msmon) -notmatch 'RUNNING') { break }; Start-Sleep -Milliseconds 500 }
Say ((& sc.exe query msmon) -join ' ')

Say "== take ownership + replace =="
& takeown /f $target | ForEach-Object { Say "  $_" }
& icacls $target /grant 'Administrators:F' | ForEach-Object { Say "  $_" }
try {
    Copy-Item (Join-Path $work 'msmon.sys') $target -Force -ErrorAction Stop
    Say "deployed: $((Get-Item $target).Length) bytes, sha256 $((Get-FileHash $target -Algorithm SHA256).Hash.ToLower())"
    Say "signature: $((Get-AuthenticodeSignature $target).Status)"
} catch { Say "DEPLOY FAILED: $($_.Exception.Message)" }

Say "== start =="
& sc.exe start msmon 2>&1 | ForEach-Object { Say "  $_" }
Start-Sleep -Seconds 3
$q = (& sc.exe query msmon 2>&1) -join "`n"
Say $q
(& fltmc.exe filters 2>&1) | Select-String 'msmon' | ForEach-Object { Say "  $_" }
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-3)} -MaxEvents 8 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,Id,ProviderName,@{n='m';e={($_.Message -split "`n")[0]}} | ForEach-Object { Say ("  {0} {1} {2} :: {3}" -f $_.TimeCreated,$_.Id,$_.ProviderName,$_.m) }
if ($q -match 'RUNNING') { Say "RESULT: driver_running_new_build" } else { Say "RESULT: driver_NOT_running" }
