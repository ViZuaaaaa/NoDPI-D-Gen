@echo off
setlocal

set "ROOT=%~dp0"
set "VBS=%ROOT%oneclick-local.vbs"
set "WSCRIPT=%SystemRoot%\System32\wscript.exe"
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "LAUNCHER=%ROOT%D-Gen\launcher.ps1"

rem Preferred: no-console start via Windows Script Host
if exist "%WSCRIPT%" if exist "%VBS%" (
  "%WSCRIPT%" //nologo "%VBS%"
  if %errorlevel%==0 exit /b 0
)

rem Fallback: start PowerShell minimized (console minimized, launcher UI should still appear)
if exist "%PS%" if exist "%LAUNCHER%" (
  start "" /min "%PS%" -NoProfile -ExecutionPolicy Bypass -STA -File "%LAUNCHER%"
  exit /b 0
)

echo D-Gen: failed to start launcher
echo - %PS%
echo - %LAUNCHER%
exit /b 1
