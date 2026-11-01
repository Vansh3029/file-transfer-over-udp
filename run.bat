@echo off
cd /d "%~dp0"
echo ===================================================
echo   Reliable File Transfer over UDP
echo   Dashboard: http://127.0.0.1:8000
echo ===================================================
echo.

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py -3 backend\app.py
) else (
    python backend\app.py
)

pause
