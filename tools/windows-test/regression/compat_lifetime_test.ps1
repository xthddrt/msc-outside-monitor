# compat_lifetime_test.ps1 - control IRPs must not outlive MonShutdown.
#
# Loads the legacy SysInfoMon driver (compat\build\msmon-legacy.sys), keeps
# readers inside MON_READ/MON_SUMMARY while the service is stopped, and requires
# every stop to return with the machine still up. Without the control-IRP
# rundown in DispatchControl/DriverUnload, MonShutdown frees the ring and the
# summary under a reader (bugcheck 0x50 / 0x7C).
#
# Requires a signed (test-signed) compat build and an elevated shell in the
# isolated VM. Never on a production host.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$ctl = Join-Path $root 'build\compat\msmon-legacyctl.exe'
$sys = Join-Path $root 'build\compat\msmon-legacy.sys'
$hooksEnabled = (Get-Content (Join-Path $root 'compat\driver\trace.c') -Raw) -match '(?m)^#define\s+SYSINFO_ENABLE_TRACE_HOOKS\s+1'
$service = 'SysInfoMon'
$rounds = 20
$work = Join-Path ([IO.Path]::GetTempPath()) 'msmon-compat-lifetime'
$stop = Join-Path $work 'STOP'
$collector = Join-Path $work 'collector.ps1'

New-Item -ItemType Directory -Force -Path $work | Out-Null
foreach ($file in $ctl, $sys) {
    if (-not (Test-Path $file)) { throw "missing $file (build with: build.cmd --with-compat)" }
}

# A dense stream of one-shot control calls, so an IRP is inside MonRead or
# MonSummary almost continuously while the service is stopped.
@"
while (-not (Test-Path '$stop')) {
    & '$ctl' mon dump  | Out-Null
    & '$ctl' mon summary | Out-Null
}
"@ | Set-Content -Path $collector -Encoding UTF8

function Start-Legacy {
    sc.exe stop $service | Out-Null
    Start-Sleep -Milliseconds 300
    if (-not (Get-Service $service -ErrorAction SilentlyContinue)) {
        sc.exe create $service type= kernel start= demand binPath= $sys | Out-Null
    }
    sc.exe start $service | Out-Null
    if ((Get-Service $service).Status -ne 'Running') { throw 'SysInfoMon did not start' }
}

function Stop-Legacy {
    # A busy device is acceptable; a bugcheck is not.
    sc.exe stop $service | Out-Null
    Start-Sleep -Milliseconds 300
}

function Invoke-LegacyCtl([string[]]$Arguments) {
    $process = Start-Process $ctl -ArgumentList $Arguments -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(10000)) {
        Stop-Process -Id $process.Id -Force
        throw "sysinfoctl $($Arguments -join ' ') did not return within 10 seconds"
    }
    if ($process.ExitCode -ne 0) { throw "sysinfoctl $($Arguments -join ' ') failed with $($process.ExitCode)" }
}

function Bugchecks {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1001;
                                    StartTime = (Get-Date).AddSeconds(-30) } -ErrorAction SilentlyContinue
}

try {
    Start-Legacy
    & $ctl mon on | Out-Null
    for ($round = 1; $round -le $rounds; $round++) {
        Remove-Item $stop -ErrorAction SilentlyContinue
        $drainer = Start-Process powershell -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass',
                                                          '-File', $collector) -PassThru -WindowStyle Hidden
        # mon watch holds one handle and issues MON_READ every 500 ms for as
        # long as it runs, so the stop lands inside a live read.
        $watcher = Start-Process $ctl -ArgumentList @('mon', 'watch') -PassThru -WindowStyle Hidden
        Start-Sleep -Milliseconds 700
        Stop-Legacy
        New-Item -ItemType File -Path $stop -Force | Out-Null
        foreach ($process in $drainer, $watcher) {
            if ($null -ne $process -and -not $process.HasExited) {
                if (-not $process.WaitForExit(10000)) { Stop-Process -Id $process.Id -Force }
            }
        }
        if (Bugchecks) { throw "round ${round}: the machine recorded a bugcheck" }
        # A control call after the drain must fail cleanly, not crash.
        & $ctl status | Out-Null
        Start-Legacy
        & $ctl mon on | Out-Null
    }
    Write-Host "compat lifetime regression passed: $rounds stops with readers in flight, no bugcheck"
    if ($hooksEnabled) {
        # MON_CONFIG is delivered through the hooked NtDeviceIoControlFile: a
        # quiesce that waits for the caller's own detour never returns and
        # blocks the next configuration and the service stop.
        Invoke-LegacyCtl @('mon', 'on', 'unsafe')
        Invoke-LegacyCtl @('mon', 'off')
        Invoke-LegacyCtl @('mon', 'collect', (Join-Path $work 'unsafe-events.json'))
        Invoke-LegacyCtl @('mon', 'on', 'unsafe')
        # Two overlapping configurations: the mutex holder must not drain for
        # the caller parked behind it, or both sleep forever and unload hangs.
        foreach ($pair in @(@(@('mon', 'off'), @('mon', 'collect', (Join-Path $work 'race-events.json'))),
                            @(@('mon', 'off'), @('mon', 'on')))) {
            $first = Start-Process $ctl -ArgumentList $pair[0] -PassThru -WindowStyle Hidden
            $second = Start-Process $ctl -ArgumentList $pair[1] -PassThru -WindowStyle Hidden
            foreach ($process in $first, $second) {
                if (-not $process.WaitForExit(10000)) {
                    Stop-Process -Id $process.Id -Force
                    throw "concurrent mon $($pair[0] -join ' ') / mon $($pair[1] -join ' ') hung with inline hooks enabled"
                }
            }
            if ($first.ExitCode -ne 0 -or $second.ExitCode -ne 0) {
                throw 'a concurrent configuration failed with inline hooks enabled'
            }
            Invoke-LegacyCtl @('mon', 'on', 'unsafe')
        }
        Stop-Legacy
        Start-Legacy
        if (Bugchecks) { throw 'the inline-hook configure/disable cycle produced a bugcheck' }
        Write-Host 'inline-hook configure/disable cycle passed'
    }
} finally {
    New-Item -ItemType File -Path $stop -Force -ErrorAction SilentlyContinue | Out-Null
    Stop-Legacy
}
