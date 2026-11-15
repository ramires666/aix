@echo off
setlocal
cd /d "%~dp0"
if not exist "bin\aix\webcodex-agent.exe" (
    echo Agent EXE is missing. Run build-agent.bat first.
    if /i not "%~1"=="--no-pause" pause
    exit /b 1
)
"bin\aix\webcodex-agent.exe" --local
set "agentResult=%errorlevel%"
if not "%agentResult%"=="0" if /i not "%~1"=="--no-pause" pause
exit /b %agentResult%
