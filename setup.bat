@echo off
REM Secure Online Voting System - Windows Setup Script
REM This script sets up the development environment

echo =====================================
echo Secure Online Voting System - Setup
echo =====================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.11 or later
    pause
    exit /b 1
)

echo [1/6] Python detected
python --version
echo.

REM Create virtual environment
echo [2/6] Creating virtual environment...
if exist venv (
    echo Virtual environment already exists, skipping...
) else (
    python -m venv venv
    echo Virtual environment created successfully
)
echo.

REM Activate virtual environment
echo [3/6] Activating virtual environment...
call venv\Scripts\activate.bat
echo.

REM Install dependencies
echo [4/6] Installing dependencies...
pip install --upgrade pip
pip install -r requirements.txt
echo.

REM Create .env file if it doesn't exist
echo [5/6] Setting up environment configuration...
if exist .env (
    echo .env file already exists, skipping...
) else (
    copy .env.example .env
    echo .env file created from template
    echo IMPORTANT: Edit .env file with your database and secret key settings
)
echo.

REM Create necessary directories
echo [6/6] Creating required directories...
if not exist logs mkdir logs
if not exist keys mkdir keys
if not exist app\static\uploads mkdir app\static\uploads
echo Directories created
echo.

echo =====================================
echo Setup Complete!
echo =====================================
echo.
echo Next steps:
echo 1. Edit .env file with your database credentials
echo 2. Run: python init_db.py (to initialize database)
echo 3. Run: python run.py (to start the application)
echo 4. Access: http://localhost:5000
echo.
echo For security scanning:
echo - Run: bandit -r app/.
echo.
pause
