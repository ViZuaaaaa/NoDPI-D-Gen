@echo off
:: D-Gen | https://t.me/DisappearGen
set "SYS32=%SystemRoot%\System32"
set "PATH=%SYS32%;%SystemRoot%;%PATH%"
"%SYS32%\chcp.com" 65001 > nul

set "ROOT=%~dp0.."
cd /d "%ROOT%"
call service.bat status_dgen
if not "%DGEN_SKIP_UPDATE_CHECK%"=="1" (
    call service.bat check_updates
)
if not defined GameFilter call service.bat load_game_filter
echo:

set "BIN=%ROOT%\bin\"
set "LISTS=%ROOT%\lists\"
cd /d "%BIN%"
if not defined GameFilter set "GameFilter=12"
if not defined AGGRESSIVE_MODE set "AGGRESSIVE_MODE=0"

set "REPEATS_6=6"
set "REPEATS_8=8"
set "REPEATS_10=10"
set "REPEATS_11=11"
if "%AGGRESSIVE_MODE%"=="1" (
    set "REPEATS_6=8"
    set "REPEATS_8=10"
    set "REPEATS_10=12"
    set "REPEATS_11=12"
)

:: DGEN_PREFLIGHT_BEGIN
if not defined GameFilter set "GameFilter=12"
if not defined AGGRESSIVE_MODE set "AGGRESSIVE_MODE=0"

if not exist "%BIN%DGen.exe" (
    echo [ERROR] DGen.exe not found in %BIN%
    exit /b 1
)
for %%F in ("ipset-all.txt" "ipset-exclude.txt" "list-exclude.txt" "list-general.txt" "list-google.txt") do (
    if not exist "%LISTS%%%~F" (
        echo [ERROR] Required list missing: %LISTS%%%~F
        exit /b 1
    )
)
echo [D-Gen] Starting %~n0 (GameFilter=%GameFilter% Aggressive=%AGGRESSIVE_MODE%) with BIN=%BIN% LISTS=%LISTS%
set REPEATS_
:: DGEN_PREFLIGHT_END

start "D-Gen: %~n0" /b "%BIN%DGen.exe" --profile general_fake_tls_auto_alt3



