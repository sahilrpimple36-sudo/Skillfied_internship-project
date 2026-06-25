@echo off
:: Change to the folder where this .bat file lives
cd /d "%~dp0"

title BasicAV — Antivirus Simulation Launcher

echo.
echo  ============================================================
echo    BasicAV — Basic Antivirus Simulation (Signature Scanner)
echo  ============================================================
echo.
echo  [1] Checking Python installation...

python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ERROR: Python is not installed or not in PATH.
    echo  Please install Python 3.8+ from https://python.org
    echo  and make sure to tick "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

echo  [2] Installing required packages (Flask)...
python -m pip install flask --quiet --disable-pip-version-check

echo  [3] Starting BasicAV server...
echo  [4] Browser will open automatically at http://localhost:5000
echo  [5] Press Ctrl+C in this window to stop the server
echo.
echo  TIP: Click "Create Demo Test Files" in the UI to generate
echo       sample files you can immediately scan!
echo.
echo  ============================================================
echo.

python server.py

pause
