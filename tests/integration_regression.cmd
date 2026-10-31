@echo off
setlocal
set "ROOT=%~dp0.."
set "OUT=%ROOT%\build\tests"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VCVARS="
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do (
    if not defined VCVARS if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined VCVARS (
  echo Visual Studio C++ tools were not found.
  exit /b 1
)
call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
if not exist "%OUT%" mkdir "%OUT%"
cl /nologo /W4 /WX /O2 /EHsc /std:c++17 /Fo"%OUT%\\" /Fe:"%OUT%\integration_regression.exe" "%~dp0integration_regression.cpp" "%ROOT%\agent\integrations.cpp" "%ROOT%\agent\telemetry.cpp" bcrypt.lib
if errorlevel 1 exit /b 1
pushd "%ROOT%"
"%OUT%\integration_regression.exe"
set "RESULT=%errorlevel%"
popd
if not "%RESULT%"=="0" exit /b %RESULT%
where python >nul 2>nul
if errorlevel 1 (
  echo [warn] Python was not found; the verify_log gate was skipped.
  exit /b 0
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$r = & python '%ROOT%\tools\verify_log.py' '%OUT%\integration-events.jsonl' | ConvertFrom-Json; if ($r.events -ne 3 -or $r.missing_events -ne 0) { Write-Host ('verify_log events=' + $r.events + ' missing=' + $r.missing_events + '; expected 3/0'); exit 1 }"
exit /b %errorlevel%
