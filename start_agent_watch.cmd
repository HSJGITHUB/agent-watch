@echo off
where py >nul 2>nul
if errorlevel 1 (
    start "AgentWatch8810" /min python -X utf8 -B "%~dp0server.py" --port 8810
) else (
    start "AgentWatch8810" /min py -3 -X utf8 -B "%~dp0server.py" --port 8810
)
timeout /t 2 >nul
start "" "http://127.0.0.1:8810/"
