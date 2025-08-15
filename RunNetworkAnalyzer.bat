@echo off
REM =========================================
REM Run Advanced Network Packet Analyzer
REM =========================================

REM Change directory to your project folder
cd /d "C:\Users\Admin\Desktop\Advance Network Packet Analyser"

REM Run with Administrator check
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo [ERROR] Please run this file as Administrator!
    echo Right-click the .bat file and select "Run as administrator".
    pause
    exit /b
)

REM Launch Python script
python network_analyzer.py

pause
