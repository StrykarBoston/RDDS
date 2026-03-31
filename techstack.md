# 🛡️ RDDS — Tech Stack & Architecture

## 🚀 Overview
RDDS is a modular, high-performance network security system designed to detect and alert on rogue device activities, spoofing attacks, and malicious traffic patterns in real-time.

---

## 🛠️ Tech Stack

### 💻 Core Programming Languages
- **Python 3.10+**: Powering the core backend logic, low-level packet manipulation, and REST API.
- **JavaScript (Vanilla)**: Handling high-frequency frontend updates and dynamic data polling.
- **HTML5 & CSS3**: Modern glassmorphism UI for a premium, dark-mode administrative dashboard.

### 🔌 Networking & Security
- **Scapy (`2.5.0`)**: Used for packet crafting, ARP/ICMP scanning, and deep packet inspection (DPI).
- **Npcap (Windows)** / **libpcap (Linux)**: Low-level driver required for high-fidelity packet capture.
- **REST API (Flask)**: Serving real-time telemetry to the dashboard layer.

### 🧠 AI & Deep Learning (Threat Analysis)
- **TensorFlow (`2.15.0`)**: Neural networks trained to identify malicious traffic patterns (Evil Twin/DDoS).
- **Scikit-Learn**: Powering the scaling algorithms for telemetry data.
- **Joblib**: Efficient serialization of trained machine learning models.
- **Weighted Risk Engine**: Custom logic balancing vendor history, OUI age, and behavioral anomalies to assign 0-100 risk scores.

### 📊 Storage & Reporting
- **SQLite3**: Lightweight relational database for persistent device tracking and incident logging.
- **JSON Registry**: Fast flat-file storage for the trusted whitelist and OUI vendor databases.
- **Python-Docx**: Automated report generator creating professional security audit documents.

---

## 🧠 Architecture Summary

The RDDS architecture is split into four distinct layers to ensure scalability and reliability:

### 1. 🎛️ Command-Line Interface (rdds.py)
The primary entry point. Orchestrates the startup of various analytical engines and handles configuration.

### 2. ⚙️ Core Detection Engines (core/)
Autonomous modules working in parallel to monitor specific threat vectors:
- **`attack_detector.py`**: Real-time sniffer for MITM and DDoS detection.
- **`packet_engine.py`**: Deep inspection of ARP, DNS, and TCP sequences.
- **`rogue_ap_detector.py`**: Wi-Fi structure analysis and Evil Twin identification.
- **`dhcp_monitor.py`**: Protection against DHCP starvation and rogue servers.
- **`iot_profiler.py`**: Specialized fingerprinting for smart home/enterprise IoT devices.

### 3. 🌐 Web Dashboard Layer (dashboard/)
- **Flask Backend**: Exposes asynchronous endpoints (`/api/devices`, `/api/alerts`).
- **Web UI**: Premium dashboard with live charts (Chart.js) and real-time polling.

### 4. 🗃️ Persistence Layer (data/)
- **`rdds.db`**: Relational store for scan history and active alerts.
- **`whitelist.json`**: Permanent record of authorized network devices.
