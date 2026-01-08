# 🖥️ RDDS GUI Windows Version Documentation

## 📋 Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Features](#features)
5. [User Interface](#user-interface)
6. [Advanced Settings](#advanced-settings)
7. [Security Features](#security-features)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

---

## 🎯 Overview

The **Rogue Detection & Defense System (RDDS) GUI Windows Version** is a comprehensive network security monitoring tool designed for Windows environments. It provides an intuitive graphical interface for detecting rogue devices, monitoring network traffic, analyzing SSL certificates, and identifying advanced attack patterns.

### 🔧 Key Components

- **Modern Tkinter GUI** with dark theme support
- **Real-time Network Monitoring** with live updates
- **Multi-threaded Architecture** for responsive performance
- **Advanced Settings Management** with persistent configuration
- **Comprehensive Reporting** with detailed security analysis

---

## 💻 System Requirements

### Minimum Requirements

- **Operating System:** Windows 10/11 (64-bit)
- **Python:** 3.8 or higher
- **RAM:** 4GB minimum, 8GB recommended
- **Storage:** 500MB free space
- **Network:** Ethernet or Wi-Fi adapter
- **Privileges:** Administrator rights required

### Recommended Requirements

- **Operating System:** Windows 11 Pro
- **Python:** 3.10 or higher
- **RAM:** 16GB or more
- **Storage:** 2GB free space
- **Network:** Multiple network interfaces
- **Display:** 1920x1080 resolution or higher

---

## 🚀 Installation

### Step 1: Install Python

1. Download Python 3.10+ from [python.org](https://www.python.org/downloads/)
2. Run installer with **"Add Python to PATH"** checked
3. Verify installation: `python --version`

### Step 2: Install Required Dependencies

```bash
# Install core dependencies
pip install scapy python-nmap psutil pyshark flask requests pandas colorama tabulate

# Install GUI dependencies (tkinter comes with Python)
# No additional GUI dependencies needed

# Optional: Install advanced features
pip install cryptography  # For enhanced SSL monitoring
```

### Step 3: Install Npcap (Required for Packet Capture)

1. Download Npcap from [https://npcap.com/](https://npcap.com/)
2. Run installer with **"Install Npcap in WinPcap API-compatible Mode"**
3. Restart computer after installation

### Step 4: Clone/Download RDDS

```bash
# Option 1: Clone from Git
git clone <repository-url>
cd RDDS

# Option 2: Download ZIP and extract
# Navigate to extracted folder
```

### Step 5: Run the Application

```bash
# Launch GUI
python gui_main.py
```

### Quick Installation Script

```batch
@echo off
echo Installing RDDS GUI Requirements...
pip install scapy python-nmap psutil pyshark flask requests pandas colorama tabulate
echo.
echo Installation complete!
echo Run: python gui_main.py
pause
```

---

## ✨ Features

### 🔍 Network Discovery & Scanning

- **ARP Network Scanning** - Discover all devices on network
- **Interface Selection** - Choose specific network interface
- **Real-time Device Detection** - Live network monitoring
- **Device Fingerprinting** - Identify device types and vendors
- **Network Range Detection** - Automatic network configuration

### 🛡️ Rogue Device Detection

- **ARP Spoofing Detection** - Identify MAC address spoofing
- **Rogue AP Detection** - Detect unauthorized access points
- **Evil Twin Detection** - Identify cloned wireless networks
- **Device Behavior Analysis** - Monitor suspicious activities
- **Whitelist Management** - Trusted device configuration

### 🔬 Advanced Security Features

#### 📱 IoT Device Profiling & Risk Assessment
- **Device Fingerprinting** - OS detection via TTL and window size analysis
- **Manufacturer Identification** - MAC OUI database with geopolitical risk assessment
- **Service/Port Analysis** - Open port identification and IoT device type recognition
- **Communication Pattern Analysis** - Cloud/P2P communication detection
- **Update Status & Vulnerability Checking** - Firmware version and CVE mapping

**Supported IoT Device Types:**
- **Cameras** (ports 80, 554, 8080, 8000)
- **Smart Speakers** (ports 443, 80, 8080)
- **Smart TVs** (ports 80, 443, 8080, 49152)
- **Printers** (ports 80, 443, 631, 9100)
- **Routers** (ports 22, 23, 80, 443, 8080)
- **Smart Home** (ports 80, 443, 1883, 5683)
- **IP Cameras** (ports 80, 554, 8000, 8080, 49152)

**Risk Assessment Factors:**
- **High Risk** (30-35 points): Unpatched firmware, default credentials, open telnet/SSH
- **Medium Risk** (15-25 points): Unknown vendor, unusual ports, cloud communication
- **Low Risk** (5-10 points): Known vendor, secure configuration, recent updates

#### 🌐 DHCP Security Monitoring
- **DHCP Starvation Detection** - Monitor DHCP request patterns
- **Rogue DHCP Detection** - Identify unauthorized DHCP servers
- **Configuration Analysis** - DHCP option validation
- **IP Address Tracking** - Monitor IP allocation patterns

**DHCP Attack Detection:**
- **Starvation Attacks** - Excessive DHCP requests
- **Rogue Servers** - Unauthorized DHCP servers
- **Configuration Conflicts** - Overlapping IP ranges
- **Malicious Options** - Suspicious DHCP parameters

#### 📊 Network Traffic Analysis
- **Real-time Packet Capture** - Live network traffic monitoring
- **Flow-based Analysis** - NetFlow v9 compatible flow records
- **Bandwidth Usage Per Device** - Individual bandwidth consumption tracking
- **Application Identification** - 20+ common applications recognition
- **Connection Tracking** - Source-destination mapping and frequency analysis
- **Data Exfiltration Detection** - Volume thresholds and pattern recognition

**Supported Applications:**
- **Web Services** - HTTP (80), HTTPS (443), HTTP-Alt (8080), HTTPS-Alt (8443)
- **Remote Access** - SSH (22), Telnet (23), RDP (3389), VNC (5900)
- **Email Services** - SMTP (25), POP3 (110), IMAP (143)
- **DNS Services** - DNS (53)
- **File Transfer** - FTP (20, 21)
- **Network Services** - DHCP (67, 68), NTP (123), SNMP (161, 162)

#### 🔒 SSL/TLS Certificate Monitoring
- **Comprehensive Certificate Validation** - Self-signed, expiry, subject mismatch detection
- **Weak Signature Detection** - MD5/SHA1 algorithm identification
- **Weak Key Size Detection** - RSA key size below 2048 bits
- **Certificate Transparency** - CT log verification
- **Revocation Status** - OCSP/CRL checking
- **Trusted CA Database** - Major CAs and enterprise CAs

**Security Alert Types:**
- **SELF_SIGNED** - Certificate not signed by trusted CA (Risk: +40)
- **EXPIRED** - Certificate has expired (Risk: +50)
- **EXPIRING_SOON** - Certificate expires within 30 days (Risk: +20)
- **SUBJECT_MISMATCH** - Certificate doesn't match hostname (Risk: +30)
- **WEAK_SIGNATURE** - Uses MD5/SHA1 algorithms (Risk: +35)
- **WEAK_KEY_SIZE** - RSA key below 2048 bits (Risk: +25)
- **UNTRUSTED_CA** - Issued by untrusted authority (Risk: +30)

#### ⚔️ Advanced Attack Detection
- **Multi-Layer Detection** - Layers 2, 3, 4, and application layer protection
- **MAC Flooding Detection** - CAM table overflow attack detection
- **SYN/UDP/ICMP Flood Detection** - DDoS attack identification
- **Port Scanning Detection** - Network reconnaissance detection
- **MITM Detection** - Man-in-the-middle attack identification

### 📊 Real-time Monitoring

- **Live Dashboard** - Real-time security status
- **Threat Level Indicators** - Visual risk assessment
- **Activity Logging** - Detailed event tracking
- **Alert Notifications** - Immediate threat warnings
- **Performance Metrics** - System resource monitoring

### ⚙️ Advanced Settings

- **Configurable Timeouts** - Adjust scan durations
- **Threshold Settings** - Customize detection sensitivity
- **Feature Toggles** - Enable/disable specific features
- **Export/Import Settings** - Backup and restore configurations
- **Profile Management** - Multiple configuration profiles

---

## 🖼️ User Interface

### Main Window Layout

```
┌─────────────────────────────────────────────────────────────┐
│ 🛡️ Rogue Detection & Defense System v2.0    [⚙️] [🔄] │
├─────────────────────────────────────────────────────────────┤
│ [Dashboard] [Network Scan] [Devices] [Monitoring] [Reports] │
├─────────────────────────────────────────────────────────────┤
│                                                         │
│                    Tab Content Area                        │
│                                                         │
├─────────────────────────────────────────────────────────────┤
│ Status: ● Ready    Last Activity: Scanning completed      │
└─────────────────────────────────────────────────────────────┘
```

### Dashboard Tab

- **Device Statistics** - Total, Rogue, Suspicious, Trusted counts
- **Security Status** - Overall threat level indicator
- **Recent Alerts** - Latest security events
- **Network Overview** - Interface and connection information

### Network Scan Tab

- **Scan Type Selection** - Choose scan mode
- **Progress Tracking** - Real-time scan progress
- **Results Display** - Detailed device information
- **Action Buttons** - Whitelist, blacklist, investigate

### Device Management Tab

- **Device List** - All discovered devices
- **Device Details** - MAC, IP, vendor, behavior
- **Whitelist Controls** - Add/remove trusted devices
- **Device History** - Track device changes over time

### Real-time Monitoring Tab

- **Monitoring Controls** - Start/stop monitoring
- **Live Alerts** - Real-time threat notifications
- **Traffic Graphs** - Network usage visualization
- **Attack Detection** - Active threat monitoring

---

## ⚙️ Advanced Settings

### Accessing Settings

1. Click the **⚙️ Settings** button in the header
2. Navigate through category tabs
3. Modify desired settings
4. Click **Save** to apply changes

### Settings Categories

#### 🔍 Network Discovery Settings

- **Scan Timeout** - Duration for network scans (1-300 seconds)
- **Max Threads** - Concurrent scan threads (1-100)
- **Ping Timeout** - ICMP response timeout (1-10 seconds)
- **ARP Timeout** - ARP request timeout (1-10 seconds)
- **Retry Count** - Scan retry attempts (1-5)
- **Scan Delay** - Delay between scans (0.1-5.0 seconds)

#### 🔒 SSL Monitoring Settings

- **Monitor Duration** - SSL monitoring period (60-3600 seconds)
- **Connection Timeout** - SSL connection timeout (5-60 seconds)
- **Max Hosts** - Maximum hosts to monitor (10-1000)
- **Expiry Threshold** - Certificate expiry warning (1-90 days)
- **Key Size Threshold** - Minimum RSA key size (1024-4096 bits)
- **Check Revocation** - Enable certificate revocation checking
- **Strict Validation** - Enforce strict certificate validation

#### ⚔️ Advanced Attack Detection Settings

- **Monitor Duration** - Attack detection period (60-3600 seconds)
- **MAC Flood Threshold** - Packets per second threshold (10-10000)
- **SYN Flood Threshold** - SYN packets per second (100-10000)
- **UDP Flood Threshold** - UDP packets per second (100-10000)
- **ICMP Flood Threshold** - ICMP packets per second (50-5000)
- **Port Scan Threshold** - Ports scanned threshold (10-1000)
- **Layer 2 Detection** - Enable MAC/ARP attack detection
- **Layer 3 Detection** - Enable IP/network attack detection
- **Layer 4 Detection** - Enable TCP/UDP attack detection
- **MITM Detection** - Enable man-in-the-middle detection

#### 📋 General Settings

- **Log Level** - DEBUG, INFO, WARNING, ERROR
- **Auto Save** - Automatically save scan results
- **Save Interval** - Auto-save frequency (60-3600 seconds)
- **Enable Notifications** - Show desktop notifications
- **Sound Alerts** - Play sound for alerts

### Settings Management

- **Export Settings** - Save configuration to file
- **Import Settings** - Load configuration from file
- **Reset to Defaults** - Restore default settings
- **Backup Settings** - Create automatic backups

---

## 🔐 Security Features

### Multi-Layer Detection

#### Layer 2 (Data Link Layer)

- **MAC Flooding Detection** - Switch CAM table overflow attacks
- **ARP Spoofing Detection** - MAC address impersonation
- **STP Attack Detection** - Spanning Tree Protocol manipulation
- **VLAN Hopping Detection** - Virtual LAN security breaches

#### Layer 3 (Network Layer)

- **IP Spoofing Detection** - Fake source IP addresses
- **Fragmentation Attacks** - Packet fragmentation exploits
- **ICMP Tunneling** - Covert communication channels
- **Smurf Attacks** - ICMP broadcast amplification

#### Layer 4 (Transport Layer)

- **SYN Flood Detection** - TCP connection exhaustion
- **UDP Flood Detection** - UDP packet flooding
- **Port Scanning Detection** - Network reconnaissance
- **Session Hijacking** - TCP session takeover

#### Application Layer

- **SSL Stripping** - HTTPS downgrade attacks
- **Certificate Analysis** - SSL/TLS validation
- **Application Identification** - Protocol and service detection
- **Data Exfiltration** - Unauthorized data transfer

### Attack Mitigation

- **Automatic Whitelisting** - Trusted device management
- **Real-time Alerting** - Immediate threat notification
- **Network Isolation** - Automated threat containment
- **Forensic Logging** - Detailed attack evidence

---

## 🔧 Troubleshooting

### Common Issues

#### "Npcap Required" Error

**Problem:** Npcap not installed or not running
**Solution:**

1. Download Npcap from https://npcap.com/
2. Install with "WinPcap API-compatible Mode"
3. Restart computer
4. Run as Administrator

#### "Administrator Privileges Required" Error

**Problem:** Insufficient permissions for packet capture
**Solution:**

1. Right-click on Command Prompt/PowerShell
2. Select "Run as Administrator"
3. Navigate to RDDS folder
4. Run: `python gui_main.py`

#### "No Network Interfaces Found" Error

**Problem:** No available network adapters
**Solution:**

1. Check network cable/connection
2. Disable/enable network adapter
3. Update network drivers
4. Restart application

#### "Scan Returns No Devices" Error

**Problem:** Network scan configuration issues
**Solution:**

1. Verify correct network interface selected
2. Check firewall settings
3. Confirm network connectivity
4. Try different scan settings

#### "GUI Freezes During Scan" Issue

**Problem:** Long-running operations blocking UI
**Solution:**

1. Reduce scan timeout settings
2. Decrease max threads
3. Close other applications
4. Check system resources

### Performance Optimization

#### Memory Usage

- **Reduce Max Threads** in network discovery settings
- **Decrease Monitor Duration** for real-time features
- **Clear Device History** periodically
- **Restart Application** after extended use

#### CPU Usage

- **Adjust Scan Delays** to reduce system load
- **Disable Unused Features** in settings
- **Limit Concurrent Operations**
- **Update Network Drivers**

#### Network Performance

- **Use Wired Connection** for better performance
- **Configure QoS** settings
- **Optimize Scan Timing**
- **Monitor Bandwidth Usage**

---

## ❓ FAQ

### Q: Does RDDS work on Windows Home editions?

A: Yes, but Administrator privileges are still required for packet capture.

### Q: Can I run RDDS on multiple network interfaces simultaneously?

A: Currently, RDDS monitors one interface at a time. Switch interfaces in settings.

### Q: How accurate is the device detection?

A: RDDS uses multiple detection methods with 95%+ accuracy for common devices.

### Q: Will RDDS detect all types of attacks?

A: RDDS detects common network attacks but may miss sophisticated or novel attacks.

### Q: Can I use RDDS in a corporate environment?

A: Yes, but ensure compliance with company security policies and obtain proper authorization.

### Q: How much network bandwidth does RDDS use?

A: Minimal - RDDS primarily monitors traffic rather than generating significant traffic.

### Q: Is my data stored locally?

A: Yes, all data is stored locally on your machine unless configured otherwise.

### Q: Can I customize the alert thresholds?

A: Yes, all detection thresholds are configurable in Advanced Settings.

### Q: Does RDDS work with VPN connections?

A: Limited functionality - VPN traffic is encrypted and may not be fully analyzable.

### Q: How often should I run network scans?

A: Depends on environment - recommended daily for high-security networks.

### Q: Can RDDS integrate with other security tools?

A: Currently, RDDS operates standalone but supports data export for integration.

---

## 📞 Support

### Getting Help

- **Documentation:** Check this guide and feature-specific documentation
- **Logs:** Review application logs in the `logs` directory
- **Settings:** Verify configuration in Advanced Settings
- **Community:** Join forums or discussion groups for user support

### Reporting Issues

When reporting issues, include:

- **Windows Version** and build number
- **Python Version** (`python --version`)
- **RDDS Version** (shown in application title)
- **Error Messages** and screenshots
- **Network Environment** details
- **Steps to Reproduce** the issue

### Feature Requests

Submit feature requests through:

- **GitHub Issues** (if available)
- **Community Forums**
- **Direct Contact** (if provided)

---

## 📝 Version History

### v2.0 (Current)

- ✅ Advanced Settings Management
- ✅ SSL/TLS Certificate Monitoring
- ✅ Advanced Attack Detection
- ✅ IoT Device Profiling
- ✅ Network Traffic Analysis
- ✅ Enhanced GUI with Dark Theme
- ✅ Real-time Monitoring Dashboard
- ✅ Multi-threaded Architecture

### v1.0

- ✅ Basic Network Scanning
- ✅ Rogue Device Detection
- ✅ Simple GUI Interface
- ✅ Basic Reporting

---

## 🔒 Security Considerations

### Data Privacy

- All network data is processed locally
- No data transmitted to external servers
- User controls data retention policies
- Secure storage of sensitive information

### Network Impact

- Minimal network overhead
- Non-disruptive scanning methods
- Configurable scan intensity
- Respect for network policies

### Best Practices

- Run with minimum required privileges
- Regularly update application
- Backup configuration settings
- Monitor system resources
- Follow organizational security policies

---

**© 2026 Rogue Detection & Defense System (RDDS)**
*Enterprise Network Security Monitoring Solution*
