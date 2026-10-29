# Elevated: test whether a Kernel-Mode-Code-Signing EKU cert unlocks ObRegisterCallbacks + WFP.
$ErrorActionPreference = 'Continue'
function Say($m) { Write-Host $m }
$repo = 'C:\Users\richa\Documents\Default Project\msc-outside-monitor'
$build = Join-Path $repo 'build\Release\driver\msmon.sys'
$target = Join-Path $env:SystemRoot 'System32\drivers\msmon.sys'
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe |
            Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1

Say "== cert with code-signing + kernel-mode EKU =="
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq 'CN=msmon kernel test' | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type Custom -Subject 'CN=msmon kernel test' `
        -KeyUsage DigitalSignature -KeyUsageProperty Sign -KeyAlgorithm RSA -KeyLength 2048 `
        -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.61.1.1') `
        -CertStoreLocation Cert:\LocalMachine\My
}
Say "thumbprint $($cert.Thumbprint)"
$eku = ($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }).Format($false)
Say "EKU: $eku"
$cer = Join-Path $env:TEMP 'msmon-kernel.cer'
Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null
foreach ($s in 'Root','TrustedPublisher') { Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\$s" | Out-Null }

Say "== sign + deploy =="
$work = Join-Path $env:TEMP 'msmon-sign2'
New-Item -ItemType Directory -Force -Path $work | Out-Null
Copy-Item $build (Join-Path $work 'msmon.sys') -Force
& $signtool.FullName sign /sm /s My /sha1 $cert.Thumbprint /fd sha256 (Join-Path $work 'msmon.sys') | Out-Null
Say "signature: $((Get-AuthenticodeSignature (Join-Path $work 'msmon.sys')).Status)"
& sc.exe stop msmon | Out-Null; Start-Sleep 1
Copy-Item (Join-Path $work 'msmon.sys') $target -Force
& sc.exe start msmon | Out-Null
Start-Sleep 2

Say "== probe: short agent session, read registration statuses =="
$stop = 'C:\msmon-sessions\STOP'; Remove-Item $stop -ErrorAction SilentlyContinue
$agent = Join-Path $repo 'build\Release\agent\msmon-agent.exe'
$p = Start-Process -FilePath $agent -WindowStyle Hidden -PassThru -ArgumentList @(
  '--client','C:\Nexon\Library\maplestorycw','--log-dir','C:\msmon-sessions',
  '--session-label','probe-eku','--scenario','mixed','--stop-file',$stop)
Start-Sleep 8
New-Item -ItemType File -Path $stop -Force | Out-Null
Wait-Process -Id $p.Id -Timeout 60 -ErrorAction SilentlyContinue
Remove-Item $stop -ErrorAction SilentlyContinue

$b = Get-ChildItem 'C:\msmon-sessions' -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$cov = Get-Content (Join-Path $b.FullName 'coverage.json') -Raw | ConvertFrom-Json
$rs = $cov.driver.registration_status
Say "session: $($b.Name)"
Say ("object_process(23)=0x{0:X8}  object_thread(24)=0x{1:X8}" -f ($rs[23] -band 0xFFFFFFFF), ($rs[24] -band 0xFFFFFFFF))
foreach ($i in 28..34) { Say ("wfp slot {0} = 0x{1:X8}" -f $i, ($rs[$i] -band 0xFFFFFFFF)) }
Say ("registered_ok={0} failed={1}" -f $cov.driver.registration_ok, $cov.driver.registration_failed)
