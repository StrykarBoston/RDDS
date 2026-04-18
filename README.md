# 🛡️ RDDS — Rogue Device Detection System (v1.0)

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue)](https://python.org)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-lightgrey)](https://microsoft.com/windows)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-orange)](https://ubuntu.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> **Enterprise-grade network security monitoring for Windows and Linux.** Detect unauthorized (rogue) devices, MAC spoofing, Evil Twin Access Points, ARP poisoning, MITM attacks, and IoT vulnerabilities in real time.

---

## 🔗 Project Links
- **GitHub Repository**: [https://github.com/StrykarBoston/RDDS.git](https://github.com/StrykarBoston/RDDS.git)
- **Problem Statement**: Internal network trust is often exploited by attackers. RDDS bridges the gap between passive firewalls and active threat detection.

---

## 📋 Table of Contents
1. [What Is RDDS?](#-what-is-rdds)
2. [Key Features](#-key-features)
3. [Architecture](#-architecture)
4. [Installation](#-installation)
5. [Usage Guide](#-usage-guide)
6. [Web Dashboard](#-web-dashboard)
7. [Testing & Simulations](#-testing--simulations)
8. [Security Notes](#-security-notes)

---

## 🔍 What Is RDDS?

RDDS monitors your network for professional-grade threat vectors:

| Threat | Detection Method |
|--------|-----------------|
| 🚨 **Unknown Devices** | Continuous ARP scanning compared against a secure whitelist, utilizing a massive 36,000+ entry OUI database for pinpoint vendor identification. |
| 🎭 **MAC Spoofing** | Real-time correlation of IP↔MAC historical bindings with intelligent suppression for mesh network proxy-ARP hardware (e.g., eero, TP-Link). |
| 📡 **Evil Twin AP** | SSID/BSSID pattern mismatch and encryption downgrade detection. |
| 🕵️ **MITM Attack** | Cryptographic gateway integrity monitoring. |
| 🌊 **ARP Flood & DDoS** | IQR-based packet rate-limiting (tuned >500 PPS) and behavioral anomaly analysis. |
| 🌐 **DNS Spoofing** | Analyzing multiple concurrent IP resolutions for specific domains with latency-resilient timeouts. |
| 🤖 **IoT Profiling** | Automated vulnerability assessment for smart-enterprise devices. |
| 🛡️ **Payload Entropy** | Deep packet inspection with whitelists for modern encrypted ports (443, 22) to trace covert exfiltration channels without false positives. |

---

## 🧠 Architecture

RDDS is built on a **modular engine architecture**, allowing simultaneous monitoring of different network layers:

```text
rdds.py (Main CLI Controller)
      │
      ├── core/ (Analytical Engines)
      │   ├── ai_model.py          ← AI Risk Scoring (TensorFlow)
      │   ├── attack_detector.py   ← Real-time MITM/DDoS Sniffer
      │   ├── network_scanner.py   ← Active ARP/ICMP Discovery
      │   ├── rogue_ap_detector.py ← Wi-Fi Structure Analysis
      │   └── [Other engines...]   ← DHCP, IoT, Traffic, Alerts
      │
      ├── dashboard/ (Premium UI)
      │   ├── app.py               ← Flask REST API
      │   └── templates/index.html ← Glassmorphism Dashboard
      │
      └── data/ (Persistence)
          ├── rdds.db              ← Incident History (SQLite)
          └── whitelist.json       ← Authorized Devices
```

---

## ⚙️ Installation

### 🪟 Windows (Administrator Required)
1. **Prerequisites**: 
   - Install **Python 3.10+** ([python.org](https://python.org))
   - Install **Npcap** ([npcap.com](https://npcap.com/#download)). *Crucial: Check "WinPcap API-compatible mode" during install.*
2. **Run Installer**:
   ```powershell
   # Open PowerShell or CMD as Administrator
   .\install.bat
   ```

### 🐧 Linux (Root/Sudo Required)
Compatible with Debian/Ubuntu (Kali-ready).
1. **Permissions**:
   ```bash
   chmod +x install.sh
   sudo ./install.sh
   ```
2. **Dependencies**: The script will automatically install `python3-pip` and `tcpdump`.

---

## 🚀 Usage Guide

### 1. Launch the Dashboard (Recommended)
Monitor everything through the premium web interface:
```bash
python rdds.py dashboard
# Navigate to: http://localhost:5000
```

### 2. Standard Monitoring (CLI)
```bash
# General real-time monitor
python rdds.py rtmonitor

# Core attack detection engine (Sniffing mode)
python rdds.py detect
```

### 3. Specialized Engines
- **IoT Profiler**: `python rdds.py iot`
- **DHCP Monitor**: `python rdds.py dhcp`
- **Traffic Analyzer**: `python rdds.py traffic`
- **Rogue AP Scan**: `python rdds.py ap`
- **Audit Report**: `python rdds.py report`

---

## 🖥️ Web Dashboard & Reporting
The RDDS dashboard offers a **Premium Dark-Mode Experience**:
- **Live Stats Cards**: Instant view of total devices and rogue threats.
- **Intelligent Alert Timeline**: Auto-collapsing badge arrays (e.g., `(78x)`) for repeated identical offenses to prevent UI clutter.
- **Smart HTML Reporting**: Auto-generated security reports featuring colored severity badges (Critical, High, Medium, Low) and External/Local IP context tagging.
- **Device Management**: Whitelist or remove devices with one click.
- **Real-Time Feed**: Color-coded alerts with technical details.

---

## 🧪 Testing & Simulations

### Connect an Unknown Device
1. Connect a phone or new laptop to your Wi-Fi.
2. Run: `python rdds.py scan`
3. ✅ **Expected**: A `NEW_UNKNOWN_DEVICE` alert will fire instantly.

### Port Scan Simulation
1. Run RDDS in monitoring mode: `python rdds.py detect`
2. From another machine (e.g., Kali), scan your host: `nmap -sS <target_ip>`
3. ✅ **Expected**: A `PORT_SCAN_DETECTED` High-Severity alert.

---

## 🔐 Security Notes
- ⚠️ **Privileges**: This tool performs raw packet capture; it **must** be run as Administrator/Root.
- ⚠️ **Legal Use**: Deploy RDDS only on systems you own or have explicit authorization to monitor. Unauthorized network monitoring can be a violation of the law.
- ⚠️ **Npcap**: On Windows, without Npcap in WinPcap mode, Scapy-based features (MITM detection, etc.) will fail.

---

*Developed for cybersecurity research and Red Team monitoring environments.*
*© 2026 RDDS Project Team*
