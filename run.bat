@echo off
setlocal
cd /d "%~dp0"

rem Prefer Windows Python launcher (py), then fall back to python
where py >nul 2>nul
if %errorlevel%==0 (
  set "PY=py"
) else (
  set "PY=python"
)

REM Launch without a subcommand: script will show 1-start / 2-menu prompt.
%PY% dgen_nodpi.py

echo.
pause
