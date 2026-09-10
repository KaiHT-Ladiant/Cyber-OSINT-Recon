@echo off
REM Setup script for Python dependencies (Windows)

echo Setting up Python dependencies for Cyber OSINT Recon...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed. Please install Python 3 first.
    exit /b 1
)

REM Install Python dependencies
echo Installing Python dependencies...
pip install -r python_modules\requirements.txt

echo Python setup complete!
