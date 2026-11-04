@echo off
title Steganography Pro Server
cd /d "%~dp0"

echo ========================================================
echo   Starting Image Steganography Pro Server...
echo ========================================================
echo.
echo Opening web interface in your browser: http://127.0.0.1:8080
echo.

:: Open the browser after 2 seconds
start "" http://127.0.0.1:8080

where python >nul 2>nul
if %errorlevel% equ 0 (
    python app.py
) else (
    "%LocalAppData%\Programs\Python\Python311\python.exe" app.py
)

pause
