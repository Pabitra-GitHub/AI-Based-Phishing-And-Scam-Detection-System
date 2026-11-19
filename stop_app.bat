@echo off
title PhishGuard AI - Stopping Application
cd /d "%~dp0"

echo ======================================================================
echo             PhishGuard AI - Stopping Application Services
echo ======================================================================
echo.

if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0scripts\stop_servers.py"
) else (
    python "%~dp0scripts\stop_servers.py"
)

taskkill /FI "WINDOWTITLE eq PhishGuard AI - Backend Server*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq PhishGuard AI - Frontend UI*" /T /F >nul 2>&1

echo.
echo [OK] All PhishGuard AI services have been stopped cleanly.
echo.
ping 127.0.0.1 -n 3 >nul
