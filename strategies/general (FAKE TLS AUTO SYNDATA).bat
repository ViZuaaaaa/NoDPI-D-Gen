@echo off
:: D-Gen | https://t.me/DisappearGen
set "ROOT=%~dp0.."
set "BIN=%ROOT%\bin"
set "LISTS=%ROOT%\lists"
cd /d "%BIN%"
"%BIN%\DGen.exe" --profile general_fake_tls_auto_syndata
