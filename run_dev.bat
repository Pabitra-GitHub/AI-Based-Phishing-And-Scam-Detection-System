@echo off
setlocal enabledelayedexpansion
title PhishGuard AI - Launcher
color 0A

cd /d "%~dp0"

echo.
echo  ================================================================
echo         PhishGuard AI ^| AI-Based Phishing ^& Scam Detector
echo  ================================================================
echo.

REM ── 1. Check Python ─────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo  Install Python 3.10+ from https://www.python.org/
    echo  During setup, enable "Add Python to PATH".
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  [OK] %%v found.

REM ── 2. Check Node.js ────────────────────────────────────────────────
node --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Node.js is not installed or not in PATH.
    echo  Install Node.js LTS from https://nodejs.org/
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('node --version 2^>^&1') do echo  [OK] Node.js %%v found.

echo.
echo  ── Setting up environment ──────────────────────────────────────
echo.

REM ── 3. Python Virtual Environment ───────────────────────────────────
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo  [1/5] Creating Python virtual environment (.venv)...
    python -m venv "%~dp0.venv"
    if errorlevel 1 (
        echo  [ERROR] Could not create virtual environment.
        pause
        exit /b 1
    )

    echo  [1/5] Installing backend dependencies (this takes ~1 min first time)...
    "%~dp0.venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
    "%~dp0.venv\Scripts\python.exe" -m pip install -r "%~dp0backend\requirements.txt" --quiet
    if errorlevel 1 (
        echo  [ERROR] Failed to install backend dependencies.
        echo  Check your internet connection and try again.
        pause
        exit /b 1
    )
    echo  [1/5] Backend dependencies installed successfully.
) else (
    echo  [1/5] Python virtual environment is ready.
)

REM ── 4. Frontend Node Modules ─────────────────────────────────────────
if not exist "%~dp0frontend\node_modules" (
    echo  [2/5] Installing frontend npm packages (this takes ~1 min first time)...
    cd /d "%~dp0frontend"
    call npm install --silent
    cd /d "%~dp0"
    if errorlevel 1 (
        echo  [ERROR] Failed to install frontend packages.
        echo  Check your internet connection and try again.
        pause
        exit /b 1
    )
    echo  [2/5] Frontend packages installed successfully.
) else (
    echo  [2/5] Frontend packages are ready.
)

REM ── 5. ML Model Check ────────────────────────────────────────────────
if not exist "%~dp0ml\models\phishing_model.joblib" (
    echo  [3/5] AI model not found. Training now (may take a few minutes)...
    "%~dp0.venv\Scripts\python.exe" "%~dp0ml\training\train_models.py"
    if errorlevel 1 (
        echo  [ERROR] Model training failed. Check ml\training\train_models.py.
        pause
        exit /b 1
    )
    echo  [3/5] AI model trained and saved successfully.
) else (
    echo  [3/5] AI Machine Learning model is ready.
)

REM ── 6. Database Migrations ───────────────────────────────────────────
echo  [4/5] Running database migrations...
if exist "%~dp0.venv\Scripts\alembic.exe" (
    "%~dp0.venv\Scripts\alembic.exe" upgrade head >nul 2>&1
    echo  [4/5] Database is up to date.
) else (
    echo  [4/5] Alembic not found in venv - skipping migrations (DB auto-creates on first run).
)

REM ── 7. Launch Servers ────────────────────────────────────────────────
echo  [5/5] Starting Backend and Frontend servers...
echo.

start "PhishGuard AI - Backend (port 8000)" cmd /k "title PhishGuard Backend ^& color 0B ^& echo Starting backend... ^& .venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload"
timeout /t 2 /nobreak >nul
start "PhishGuard AI - Frontend (port 5173)" cmd /k "title PhishGuard Frontend ^& color 0E ^& echo Starting frontend... ^& cd frontend ^& node node_modules\vite\bin\vite.js"

REM ── 8. Wait for backend health ───────────────────────────────────────
echo  Waiting for backend to be ready...
"%~dp0.venv\Scripts\python.exe" "%~dp0scripts\wait_for_health.py" 2>nul
if errorlevel 1 (
    echo  [NOTE] Backend may still be starting up. Please wait a few seconds.
) else (
    echo  [OK] Backend is healthy and ready!
)

REM ── 9. Open Browser ──────────────────────────────────────────────────
echo.
echo  Opening PhishGuard AI in your browser...
timeout /t 2 /nobreak >nul
start http://localhost:5173

echo.
echo  ================================================================
echo   PhishGuard AI is RUNNING!
echo.
echo   Web Interface   :  http://localhost:5173
echo   Backend API     :  http://127.0.0.1:8000/docs
echo   Health Check    :  http://127.0.0.1:8000/api/v1/health
echo.
echo   To STOP: Close the Backend and Frontend terminal windows,
echo            or double-click  stop_app.bat
echo  ================================================================
echo.
pause
