@echo off
setlocal
cd /d "%~dp0"
set "agentPath=%~dp0webcodex-agent.exe"
if not exist "%agentPath%" set "agentPath=%~dp0bin\aix\webcodex-agent.exe"
if not exist "%agentPath%" (
    echo Agent EXE is missing. Check that you extracted the complete release ZIP.
    if /i not "%~1"=="--no-pause" pause
    exit /b 1
)
"%agentPath%" --local
set "agentResult=%errorlevel%"
if not "%agentResult%"=="0" if /i not "%~1"=="--no-pause" pause
exit /b %agentResult%
