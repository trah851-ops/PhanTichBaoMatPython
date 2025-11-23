@echo off
echo ============================================
echo   PyScan Pro - Python Security Scanner
echo ============================================
echo.

REM Check if venv exists
if not exist "venv\" (
    echo [1/3] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create venv
        pause
        exit /b 1
    )
)

REM Activate venv
echo [2/3] Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo [3/3] Installing dependencies...
pip install -r requirements.txt --quiet

REM Create necessary directories
if not exist "templates\" mkdir templates
if not exist "uploads\" mkdir uploads
if not exist "web_reports\" mkdir web_reports

REM Run the app
echo.
echo ============================================
echo Starting PyScan Pro Web Server...
echo Open: http://127.0.0.1:5000
echo Press Ctrl+C to stop
echo ============================================
echo.

python app.py

pause