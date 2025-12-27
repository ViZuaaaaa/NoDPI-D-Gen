@echo off
setlocal
cd /d "%~dp0"

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

REM Launch without a subcommand: script will show 1-start / 2-menu prompt.
%PY% dgen_nodpi.py

echo.
pause
