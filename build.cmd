@echo off
setlocal
set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not exist %MSBUILD% (
  echo MSBuild was not found at %MSBUILD%.
  exit /b 1
)
%MSBUILD% "%~dp0ms-monitor.sln" /m /p:Configuration=Release /p:Platform=x64 && call "%~dp0compat\build.cmd"
