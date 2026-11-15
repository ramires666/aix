@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -File "%~dp0build.ps1" -AgentOnly
set "buildResult=%errorlevel%"
if /i not "%~1"=="--no-pause" pause
exit /b %buildResult%
