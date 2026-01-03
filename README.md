
# 🛡️ Rogue Detection & Defense System (RDDS) - GUI Version

A modern, responsive graphical user interface for enterprise network security monitoring and rogue device detection.

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

## 🚀 Quick Start

### Prerequisites
- **Python 3.7+**
- **Administrator Privileges** (required for network operations)
- **Windows OS** (optimized for Windows)

### Installation

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd RDDS
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   # Method 1: Using the launcher (recommended)
   python launcher.py
   
   # Method 2: Direct GUI launch
   python gui_main.py
   
   # Method 3: Original CLI version
   python main.py
   ```

## 🖥️ GUI Overview

### Main Interface
- **Header**: Application title, status indicator, settings button
- **Tabbed Interface**: Organized functionality sections
- **Status Bar**: Current status and timestamp

### Tab Navigation

#### 📊 Dashboard
- **Statistics Cards**: Total devices, rogue devices, suspicious devices, trusted devices
- **Activity Log**: Real-time activity feed with timestamps
- **Quick Actions**: Launch scans and monitoring

#### 🔍 Network Scan
- **Scan Controls**: Start/stop scanning operations
- **Progress Indicators**: Visual feedback during operations
- **Results Table**: Detailed device information with color coding
- **Risk Assessment**: Device risk scores and factors

#### 📱 Device Management
- **Whitelist Display**: Trusted devices table
- **Add Device Dialog**: Simple device addition form
- **Device Details**: MAC, IP, name, and addition date
- **Bulk Operations**: Multiple device management

#### 🎯 Real-time Monitoring
- **Monitoring Controls**: Start/stop with configurable duration
- **Live Alerts**: Real-time attack detection display
- **Status Indicators**: Current monitoring state
- **Alert History**: Previous alerts and timestamps

#### 📄 Reports
- **Report Generation**: One-click report creation
- **Report Display**: In-app report viewer
- **Export Options**: Save reports to files
- **Report Content**: Comprehensive security analysis

#### ⚙️ Settings
- **Network Settings**: Interface selection, scan parameters
- **Detection Settings**: Risk thresholds, detection options
- **Monitoring Settings**: Default duration, alert options
- **GUI Settings**: Theme, refresh options
- **Logging Settings**: Log levels, file management



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

### Common Issues

#### Administrator Privileges
- **Issue**: "Administrator privileges required"
- **Solution**: Run as Administrator or use launcher.py

#### Network Interface
- **Issue**: "No network interface found"
- **Solution**: Check network connections and select correct interface in settings

#### Missing Dependencies
- **Issue**: Import errors
- **Solution**: Install all requirements: `pip install -r requirements.txt`

#### Scan Failures
- **Issue**: "Scan failed" errors
- **Solution**: Check network connectivity and firewall settings

### Debug Mode
Enable debug logging in settings:
```json
{
  "logging": {
    "level": "DEBUG"
  }
}
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
