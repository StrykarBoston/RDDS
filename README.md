
# 🛡️ Rogue Detection & Defense System (RDDS) -

[![Installation](https://img.shields.io/badge/Installation-Windows%20%7C%20Linux-blue)](README.md#-installation)
[![Python](https://img.shields.io/badge/Python-3.8%2B-green)](requirements.txt)
[![License](https://img.shields.io/badge/License-Educational%20%2F%20Research-orange)](LICENSE)

A modern, responsive graphical user interface for enterprise network security monitoring and rogue device detection. **Cross-platform support for Windows and Linux with automated installation scripts.**

## 🌟 Features

### 📊 **Dashboard**
- Real-time network statistics
- Device status overview (Trusted, Suspicious, Rogue)
- Recent activity log
- Live status indicators

### 🔍 **Network Scanning**
- Full network discovery with ARP scanning
- Device vendor identification
- Risk assessment and scoring
- Color-coded results display

### 📱 **Device Management**
- Interactive whitelist management
- Add/remove trusted devices
- Device details and history
- Bulk operations support

### 🎯 **Real-time Monitoring**
- Live attack detection
- Configurable monitoring duration
- Real-time alert streaming
- Attack pattern analysis

### 📄 **Reporting**
- Comprehensive security reports
- Export functionality
- Historical data analysis
- Custom report formats

### ⚙️ **Settings & Configuration**
- Network interface selection
- Detection thresholds
- GUI preferences
- Logging configuration

## 🚀 Installation

### 🪟 Windows Installation

#### Method 1: Automated Installation (Recommended)
```bash
# Clone the repository
git clone https://github.com/StrykarBoston/RDDS.git
cd RDDS

# Run automated installer
python install.py

# Launch application (as Administrator)
python gui_main.py
```

#### Method 2: Manual Installation
```bash
# 1. Install Npcap (required for packet capture)
# Download from: https://npcap.com/
# Install with "WinPcap API-compatible Mode" checked

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Run application (as Administrator)
python gui_main.py
```

#### Windows Prerequisites
- **Python 3.8+**
- **Npcap** (for packet capture)
- **Administrator privileges** (required for network operations)
- **Windows 10/11** (recommended)

---

### 🐧 Linux Installation

#### Method 1: Automated Installation (Recommended)
```bash
# Clone the repository
git clone https://github.com/StrykarBoston/RDDS.git
cd RDDS

# Run automated installer (requires sudo)
sudo python3 install_linux.py

# Launch application
sudo python3 gui_main.py
```

#### Method 2: Manual Installation
```bash
# 1. Install system dependencies
sudo apt update
sudo apt install python3 python3-pip python3-tk libpcap-dev nmap

# 2. Install Python packages
sudo pip3 install -r requirements.txt

# 3. Run application (with sudo)
sudo python3 gui_main.py
```

#### Alternative: Set Capabilities (Avoid sudo)
```bash
# Set Python capabilities (one-time setup)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Then run without sudo
python3 gui_main.py
```

#### Linux Prerequisites
- **Python 3.8+**
- **sudo access** (for network operations)
- **libpcap-dev** (for packet capture)
- **nmap** (for network scanning)
- **Kali Linux/Ubuntu/Debian** (tested)

---

### 📱 Cross-Platform Quick Start

```bash
# Clone repository
git clone https://github.com/StrykarBoston/RDDS.git
cd RDDS

# Run appropriate installer
python install.py          # Windows
sudo python3 install_linux.py  # Linux

# Start application
python gui_main.py         # Windows (as Admin)
sudo python3 gui_main.py   # Linux
```

### 🔧 Verification

After installation, verify everything works:

```bash
# Test installation
python install.py          # Windows
sudo python3 install_linux.py  # Linux

# Test imports
python -c "from gui_main import ModernRDDS_GUI; print('✅ GUI imports successfully')"

# Test network scanner
python -c "from network_discovery import NetworkScanner; print('✅ Network scanner works')"
```

### 🚨 Important Notes

- **Windows**: Must run as Administrator for packet capture
- **Linux**: Must use sudo or set capabilities for network operations
- **Npcap**: Required on Windows for Scapy functionality
- **Firewall**: May need to adjust firewall settings for network scanning



## 🔧 Configuration

### Settings File
Configuration is stored in `settings.json`:
```json
{
  "network": {
    "interface": "auto",
    "scan_timeout": 2,
    "max_threads": 10
  },
  "detection": {
    "risk_threshold": 70,
    "enable_mac_spoof_detection": true,
    "enable_vendor_check": true
  },
  "monitoring": {
    "default_duration": 60,
    "alert_sound": true,
    "auto_save_reports": true
  },
  "gui": {
    "theme": "light",
    "auto_refresh": true,
    "refresh_interval": 5
  }
}
```

### Whitelist Management
Trusted devices are stored in `whitelist.json`:
```json
[
  {
    "mac": "00:1A:2B:3C:4D:5E",
    "ip": "192.168.1.100",
    "name": "Office Server",
    "added_date": "2024-01-01 12:00:00"
  }
]
```

## 🚨 Security Features

### Detection Capabilities
- **MAC Address Spoofing**: Detect duplicate MACs
- **Unauthorized Devices**: Identify unknown devices
- **Vendor Analysis**: Suspicious vendor detection
- **Risk Scoring**: Automated risk assessment
- **Attack Patterns**: Real-time attack detection

### Alert System
- **Severity Levels**: Critical, High, Medium, Low
- **Real-time Notifications**: Immediate alert display
- **Alert History**: Complete alert log
- **Alert Filtering**: Customizable alert rules

## 📊 Reporting

### Report Types
- **Security Summary**: Overall network status
- **Device Analysis**: Detailed device information
- **Alert History**: Security events timeline
- **Risk Assessment**: Threat level analysis

### Export Formats
- **Text Reports**: Human-readable summaries
- **JSON Data**: Machine-readable format
- **CSV Export**: Spreadsheet compatibility
- **Custom Formats**: Configurable output

## 🛠️ Troubleshooting

### Windows Issues

#### Administrator Privileges
- **Issue**: "Administrator privileges required"
- **Solution**: Right-click and "Run as administrator"

#### Npcap Not Found
- **Issue**: "Npcap is required for network operations"
- **Solution**: 
  1. Download Npcap from https://npcap.com/
  2. Install with "WinPcap API-compatible Mode"
  3. Restart application as Administrator

#### Network Interface Issues
- **Issue**: "No network interface found"
- **Solution**: 
  1. Check network adapter is enabled
  2. Disable VPN temporarily
  3. Select correct interface in Settings

#### GUI Freezes
- **Issue**: GUI becomes unresponsive during scans
- **Solution**: Enhanced with progress bar - should be resolved in latest version

---

### Linux Issues

#### Permission Denied
- **Issue**: "Operation not permitted" or "Permission denied"
- **Solution**: Use sudo for network operations
  ```bash
  sudo python3 gui_main.py
  ```

#### Packet Capture Issues
- **Issue**: "Cannot open network interface"
- **Solution**: Set capabilities or use sudo
  ```bash
  # Option 1: Use sudo (recommended)
  sudo python3 gui_main.py
  
  # Option 2: Set capabilities
  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
  python3 gui_main.py
  ```

#### GUI Display Issues
- **Issue**: GUI doesn't display or X11 errors
- **Solution**: 
  ```bash
  export DISPLAY=:0
  sudo python3 gui_main.py
  ```

#### Missing Dependencies
- **Issue**: Import errors or missing packages
- **Solution**: Install system dependencies
  ```bash
  sudo apt install python3-tk libpcap-dev nmap
  ```

---

### Cross-Platform Issues

#### Python Version
- **Issue**: "Python 3.8+ required"
- **Solution**: Upgrade Python or use correct version
  ```bash
  python3 --version  # Should be 3.8+
  ```

#### Module Import Errors
- **Issue**: "No module named 'scapy'" or similar
- **Solution**: Install requirements
  ```bash
  pip install -r requirements.txt  # Windows
  sudo pip3 install -r requirements.txt  # Linux
  ```

#### Scan Failures
- **Issue**: "Scan failed" or network errors
- **Solution**: 
  1. Check network connectivity
  2. Disable firewall temporarily
  3. Verify network interface status
  4. Run as Administrator/sudo

---

### Debug Mode

Enable debug logging in settings:
```json
{
  "logging": {
    "level": "DEBUG"
  }
}
```

### Log Files

Check log files for detailed errors:
- **Windows**: `logs/` directory in project folder
- **Linux**: Same location, may need sudo to access

### Getting Help

1. **Run installation test**:
   ```bash
   python install.py          # Windows
   sudo python3 install_linux.py  # Linux
   ```

2. **Check system requirements**:
   ```bash
   python --version
   pip list | grep scapy
   ```

3. **Verify network access**:
   ```bash
   ip addr show  # Linux
   ipconfig      # Windows
   ```


## 📞 Support

### Getting Help
- **Documentation**: Read this README thoroughly
- **Settings**: Configure using the Settings tab
- **Logs**: Check log files for detailed errors
- **Community**: Report issues and request features

### Contributing
- **Code**: Follow Python style guidelines
- **Features**: Submit feature requests
- **Bugs**: Report with detailed information
- **Documentation**: Help improve documentation

## 📄 License

This project is provided for educational and research purposes. Use responsibly and in accordance with applicable laws and regulations.

---

**⚠️ Important**: This tool requires administrator privileges and should only be used on networks you own or have explicit permission to monitor.
=======
