@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -File "%~dp0build.ps1"
if errorlevel 1 exit /b 1
if /i not "%~1"=="--no-pause" pause
