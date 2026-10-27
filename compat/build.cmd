@echo off
setlocal enabledelayedexpansion
pushd "%~dp0"

set "VSROOT=C:\Program Files\Microsoft Visual Studio\2022\Community"
set "KITS=C:\Program Files (x86)\Windows Kits\10"
set "KITVER=10.0.26100.0"
set "ROOT=%~dp0"
set "OUT=%ROOT%..\build\compat"
set "SYSN=msmon-legacy.sys"
set "EXEN=msmon-legacyctl.exe"

if not exist "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" (
    echo [!] Visual Studio not found at "%VSROOT%"
    exit /b 1
)
call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo [!] vcvars64 failed & exit /b 1 )

set "INCLUDE=%KITS%\Include\%KITVER%\km;%INCLUDE%"
set "LIB=%KITS%\Lib\%KITVER%\km\x64;%LIB%"
if not exist "%OUT%" mkdir "%OUT%"

echo === compatibility driver ===
cl /nologo /c /W4 /O2 /GS- /GR- /kernel /Zi /DDBG ^
   /D_AMD64_ /DAMD64 /D_WIN64 ^
   /Fo"%OUT%\\" "%ROOT%driver\hooks.c" "%ROOT%driver\disasm.c" ^
   "%ROOT%driver\syscall.c" "%ROOT%driver\monitor.c" "%ROOT%driver\trace.c" ^
   "%ROOT%driver\guard.c" "%ROOT%driver\main.c"
if errorlevel 1 ( echo [!] driver compile failed & exit /b 1 )

link /nologo /DRIVER:WDM /MAP:"%OUT%\msmon-legacy.map" /SUBSYSTEM:NATIVE /MACHINE:X64 /OPT:REF,ICF ^
     /ENTRY:DriverEntry /DYNAMICBASE /NXCOMPAT ^
     /SECTION:TRAMP,ER ^
     /OUT:"%OUT%\%SYSN%" ^
     "%OUT%\disasm.obj" "%OUT%\hooks.obj" "%OUT%\syscall.obj" ^
     "%OUT%\monitor.obj" "%OUT%\trace.obj" "%OUT%\guard.obj" "%OUT%\main.obj" ^
     ntoskrnl.lib hal.lib Wdmsec.lib kernel32.lib
if errorlevel 1 ( echo [!] driver link failed & exit /b 1 )

echo === compatibility control tool ===
cl /nologo /W4 /O2 /MT /Zi /D_CRT_SECURE_NO_WARNINGS ^
   /Fe:"%OUT%\%EXEN%" "%ROOT%tools\sysinfoctl.c" ^
   /link /SUBSYSTEM:CONSOLE /DYNAMICBASE /NXCOMPAT advapi32.lib psapi.lib
if errorlevel 1 ( echo [!] tool build failed & exit /b 1 )

echo built:
echo   %OUT%\%SYSN%
echo   %OUT%\%EXEN%
popd
endlocal
exit /b 0
