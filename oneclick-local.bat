@echo off
:: D-Gen | https://t.me/DisappearGen
setlocal

set "ROOT=%~dp0"
set "VBS=%ROOT%oneclick-local.vbs"
set "WSCRIPT=%SystemRoot%\System32\wscript.exe"
:: D-Gen | https://t.me/DisappearGen
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "LAUNCHER=%ROOT%D-Gen\launcher.ps1"

rem
if exist "%WSCRIPT%" if exist "%VBS%" (
  "%WSCRIPT%" //nologo "%VBS%"
  if %errorlevel%==0 exit /b 0
)

rem
if exist "%PS%" if exist "%LAUNCHER%" (
  "%PS%" -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ps='%PS%'; $launcher='%LAUNCHER%'; $wd='%ROOT%'; Start-Process -FilePath $ps -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File', $launcher) -WorkingDirectory $wd -Verb RunAs -WindowStyle Hidden"
  exit /b 0
)

echo D-Gen: failed to start launcher
echo - %PS%
echo - %LAUNCHER%
exit /b 1
