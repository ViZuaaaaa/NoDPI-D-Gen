@echo off
setlocal
cd /d "%~dp0"

rem D-Gen v4 one-button launcher (recommended):
rem - enables YouTube preset
rem - starts proxy+PAC in a separate window
rem - launches Chrome via PAC (fast-noext)

rem Prefer Windows Python launcher (py), then fall back to python/python3
set "PY="

where py >nul 2>nul && set "PY=py"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY where python3 >nul 2>nul && set "PY=python3"

rem Fallbacks for common py launcher locations (when PATH differs between shells)
if not defined PY if exist "%SystemRoot%\py.exe" set "PY=%SystemRoot%\py.exe"
if not defined PY if exist "%LocalAppData%\Programs\Python\Launcher\py.exe" set "PY=%LocalAppData%\Programs\Python\Launcher\py.exe"

if not defined PY (
  echo Python not found.
  echo.
  echo Install Python 3.8+ from python.org - recommended - OR enable the Windows Python launcher: py
  echo After install, reopen cmd and retry.
  echo.
  pause
  exit /b 1
)

echo [1/3] Enable YouTube preset (rules + TLS fragmentation strategy)
%PY% dgen_nodpi.py enable-youtube >nul 2>nul

echo [2/3] Start D-Gen proxy + PAC (new window)
start "D-Gen v4 Proxy" cmd /c "%PY% dgen_nodpi.py run"

rem Give the server a moment to bind ports
timeout /t 2 >nul

echo [3/3] Launch Chrome via PAC (fast-noext)

set "PACURL=http://127.0.0.1:8882/proxy.pac"

set "CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if exist "%CHROME%" goto :launch

set "CHROME=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if exist "%CHROME%" goto :launch

echo Chrome not found.
echo.
echo Launch manually with:
echo   --proxy-pac-url="%PACURL%" --disable-extensions --disable-quic
echo.
pause
exit /b 1

:launch
echo This launcher needs Chrome fully closed, otherwise PAC/proxy flags may be ignored.
echo.

choice /M "Kill all chrome.exe processes now"
if errorlevel 2 goto :launch2

taskkill /IM chrome.exe /F >nul 2>nul
timeout /t 1 >nul

:launch2
echo Launching Chrome (existing profile) with PAC: %PACURL%
echo Extensions: disabled
echo QUIC: disabled
echo.

start "" "%CHROME%" --proxy-pac-url="%PACURL%" --disable-extensions --disable-quic --new-window

exit /b 0
