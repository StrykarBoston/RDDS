@echo off
:: RDDS — Rogue Device Detection System
:: Windows Installer Script
:: Run as ADMINISTRATOR

title RDDS Installer

echo.
echo  ██████╗ ██████╗ ██████╗ ███████╗
echo  ██╔══██╗██╔══██╗██╔══██╗██╔════╝
echo  ██████╔╝██║  ██║██║  ██║███████╗
echo  ██╔══██╗██║  ██║██║  ██║╚════██║
echo  ██║  ██║██████╔╝██████╔╝███████║
echo  ╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚══════╝
echo  Rogue Device Detection System - Installer
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [ERROR] Please run this script as Administrator!
    pause
    exit /b 1
)

echo [1/4] Checking Python...
python --version >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [ERROR] Python not found. Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)
python --version
echo [OK] Python found.

echo.
echo [2/4] Installing Python dependencies...
pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
if %errorLevel% NEQ 0 (
    echo [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
)
echo [OK] Dependencies installed.

echo.
echo [3/4] Checking Npcap...
if exist "C:\Windows\System32\wpcap.dll" (
    echo [OK] Npcap/WinPcap driver found.
) else (
    echo.
    echo =============================================
    echo  IMPORTANT: Npcap Required for Scapy!
    echo  Download from: https://npcap.com/#download
    echo  Install with "WinPcap API-compatible mode"
    echo  Then re-run RDDS as Administrator.
    echo =============================================
    echo.
)

echo.
echo [4/4] Initializing data directories...
if not exist "data"    mkdir data
if not exist "logs"    mkdir logs
if not exist "reports" mkdir reports
echo [OK] Directories ready.

echo.
echo ================================================
echo   RDDS Installation Complete!
echo ================================================
echo.
echo   Run as ADMINISTRATOR:
echo.
echo   Web Dashboard:    python rdds.py dashboard
echo   Real-Time Mon:    python rdds.py rtmonitor
echo   Attack Detect:    python rdds.py detect
echo   IoT Profiler:     python rdds.py iot
echo   DHCP Monitor:     python rdds.py dhcp
echo   Traffic Flow:     python rdds.py traffic
echo   Rogue AP Detect:  python rdds.py ap
echo   Generate Report:  python rdds.py report
echo.
echo   Dashboard URL: http://localhost:5000
echo ================================================
pause
