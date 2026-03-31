#!/bin/bash
# RDDS — Rogue Device Detection System
# Linux Installer Script
# Run with sudo

echo ""
echo "  ██████╗ ██████╗ ██████╗ ███████╗"
echo "  ██╔══██╗██╔══██╗██╔══██╗██╔════╝"
echo "  ██████╔╝██║  ██║██║  ██║███████╗"
echo "  ██╔══██╗██║  ██║██║  ██║╚════██║"
echo "  ██║  ██║██████╔╝██████╔╝███████║"
echo "  ╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚══════╝"
echo "  Rogue Device Detection System - Installer"
echo ""

if [ "$EUID" -ne 0 ]; then
  echo "[ERROR] Please run this script as root (sudo ./install.sh)"
  exit 1
fi

echo "[1/4] Checking Python 3..."
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 not found. Installing..."
    apt-get update && apt-get install -y python3 python3-pip
fi
echo "[OK] Python 3 found."

echo ""
echo "[2/4] Installing Python dependencies..."
python3 -m pip install --upgrade pip >/dev/null 2>&1
python3 -m pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[ERROR] pip install failed. Check your internet connection."
    exit 1
fi
echo "[OK] Dependencies installed."

echo ""
echo "[3/4] Checking Scapy Dependencies (tcpdump)..."
if ! command -v tcpdump &> /dev/null; then
    echo "[INFO] tcpdump not found, installing for packet sniffing capabilities..."
    apt-get install -y tcpdump
fi
echo "[OK] System dependencies met."

echo ""
echo "[4/4] Initializing data directories..."
mkdir -p data logs reports
echo "[OK] Directories ready."

echo ""
echo "================================================"
echo "  RDDS Installation Complete!"
echo "================================================"
echo ""
echo "  Run using sudo:"
echo ""
echo "  Web Dashboard:    sudo python3 rdds.py dashboard"
echo "  Real-Time Mon:    sudo python3 rdds.py rtmonitor"
echo "  Attack Detect:    sudo python3 rdds.py detect"
echo "  IoT Profiler:     sudo python3 rdds.py iot"
echo "  DHCP Monitor:     sudo python3 rdds.py dhcp"
echo "  Traffic Flow:     sudo python3 rdds.py traffic"
echo "  Rogue AP Detect:  sudo python3 rdds.py ap"
echo "  Generate Report:  sudo python3 rdds.py report"
echo ""
echo "  Dashboard URL: http://localhost:5000"
echo "================================================"
