@echo off
setlocal enabledelayedexpansion
pushd "%~dp0"

set "KITS=C:\Program Files (x86)\Windows Kits\10"
set "KITVER=10.0.26100.0"
set "ROOT=%~dp0"
set "OUT=%ROOT%..\build\compat"
set "SYSN=msmon-legacy.sys"
set "EXEN=msmon-legacyctl.exe"
set "VSROOT="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do (
        if not defined VSROOT set "VSROOT=%%i"
    )
)
if not defined VSROOT if exist "C:\Program Files\Microsoft Visual Studio\2022\Community" set "VSROOT=C:\Program Files\Microsoft Visual Studio\2022\Community"
if not defined VSROOT if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" set "VSROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"

if not defined VSROOT (
    echo [!] Visual Studio not found
    exit /b 1
)
if not exist "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" (
    echo [!] Visual Studio C++ tools not found at "%VSROOT%"
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
     ntoskrnl.lib hal.lib Wdmsec.lib BufferOverflowFastFailK.lib
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
