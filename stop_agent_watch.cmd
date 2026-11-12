@echo off
if not exist "%~dp0state" mkdir "%~dp0state"
type nul > "%~dp0state\agent_watch.stop"
