# 🐧 Kali Linux Setup Guide for RDDS

## 🔐 Administrative Permissions Setup

### Method 1: Using sudo (Recommended)

#### Basic Commands
```bash
# Install dependencies with sudo
sudo python install.py

# Run GUI with sudo
sudo python gui_main.py

# Run CLI with sudo
sudo python main.py
```

#### Permanent sudo access (if not configured)
```bash
# Check if user is in sudo group
groups $USER

# Add user to sudo group (if needed)
sudo usermod -aG sudo $USER

# Logout and login again for changes to take effect
```

### Method 2: Root User

#### Switch to root user
```bash
# Switch to root
sudo su -

# Or direct root login
su - root

# Then run the application
python install.py
python gui_main.py
```

#### Exit root when done
```bash
exit
```

## 📦 Kali Linux Specific Setup

### Install System Dependencies
```bash
# Update package lists
sudo apt update

# Install Python and development tools
sudo apt install python3 python3-pip python3-dev

# Install network tools
sudo apt install nmap wireshark tcpdump

# Install GUI dependencies
sudo apt install python3-tk

# Install libpcap development (for Scapy)
sudo apt install libpcap-dev

# Install build tools (if needed)
sudo apt install build-essential
```

### Python Package Installation
```bash
# Install requirements
sudo pip3 install -r requirements.txt

# Or use the automated installer
sudo python install.py
```

## 🔧 Network Interface Permissions

### Method 1: Using sudo (Simplest)
```bash
# Always run with sudo for network operations
sudo python gui_main.py
```

### Method 2: Set Capabilities (Advanced)
```bash
# Give Python raw socket capabilities
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Give specific script capabilities
sudo setcap cap_net_raw,cap_net_admin=eip $(realpath gui_main.py)

# Verify capabilities
getcap $(which python3)
```

### Method 3: User Groups
```bash
# Add user to netdev group (for network interface access)
sudo usermod -aG netdev $USER

# Add user to wireshark group (for packet capture)
sudo usermod -aG wireshark $USER

# Logout and login again
```

## 🛡️ Security Considerations

### Recommended Approach
```bash
# 1. Use sudo for individual commands (safest)
sudo python gui_main.py

# 2. Create a dedicated script runner
echo '#!/bin/bash
cd /path/to/RDDS
sudo python3 gui_main.py' > rdds-runner.sh
chmod +x rdds-runner.sh
./rdds-runner.sh
```

### Avoid These Practices
```bash
# ❌ DON'T: Run as root all the time
# ❌ DON'T: Give Python permanent capabilities
# ❌ DON'T: Disable security features
```

## 🚀 Quick Start Commands

### One-Time Setup
```bash
# 1. Navigate to project directory
cd /path/to/RDDS

# 2. Install dependencies
sudo apt update && sudo apt install python3 python3-pip python3-tk libpcap-dev

# 3. Install Python packages
sudo pip3 install -r requirements.txt

# 4. Test installation
python3 install.py
```

### Daily Usage
```bash
# Navigate to project
cd /path/to/RDDS

# Run with sudo
sudo python3 gui_main.py

# Or CLI version
sudo python3 main.py
```

## 🔍 Troubleshooting

### Permission Denied Errors
```bash
# Error: "Operation not permitted"
# Solution: Use sudo
sudo python3 gui_main.py

# Error: "Permission denied" on network interfaces
# Solution: Check interface permissions
sudo ip link show

# Error: "Cannot open /dev/eth0"
# Solution: Use sudo or set capabilities
sudo setcap cap_net_raw+eip $(which python3)
```

### GUI Issues on Linux
```bash
# If GUI doesn't display
export DISPLAY=:0
sudo python3 gui_main.py

# If tkinter not found
sudo apt install python3-tk

# If X11 forwarding issues (SSH)
ssh -X user@kali-machine
cd /path/to/RDDS
python3 gui_main.py
```

### Network Interface Issues
```bash
# List available interfaces
ip addr show

# Check interface status
sudo ip link show

# Bring interface up if needed
sudo ip link set eth0 up

# Check permissions
sudo tcpdump -i eth0 -c 1
```

## 📋 Kali Linux Specific Notes

### Pre-installed Tools
Kali Linux comes with many tools pre-installed:
- ✅ `nmap` - Network scanning
- ✅ `wireshark` - Packet analysis  
- ✅ `tcpdump` - Command-line packet capture
- ✅ `python3` - Python 3.x

### Security Best Practices
```bash
# 1. Keep system updated
sudo apt update && sudo apt upgrade

# 2. Use dedicated user for RDDS
sudo useradd -m rdds-user
sudo usermod -aG sudo,netdev,wireshark rdds-user

# 3. Set proper file permissions
sudo chown -R rdds-user:rdds-user /path/to/RDDS
chmod +x /path/to/RDDS/*.py
```

## 🎯 Recommended Workflow

### Development Mode
```bash
# 1. Clone/setup project
git clone <repository>
cd RDDS

# 2. Setup virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run with sudo when needed
sudo python gui_main.py
```

### Production Mode
```bash
# 1. System-wide installation
sudo pip3 install -r requirements.txt

# 2. Create systemd service (optional)
sudo tee /etc/systemd/system/rdds.service > /dev/null <<EOF
[Unit]
Description=Rogue Detection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/RDDS
ExecStart=/usr/bin/python3 /path/to/RDDS/gui_main.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 3. Enable and start service
sudo systemctl enable rdds
sudo systemctl start rdds
```

## 🚨 Important Reminders

1. **Always use sudo** for network operations on Linux
2. **Never disable security** features permanently
3. **Keep system updated** for latest security patches
4. **Use dedicated user** for production deployments
5. **Monitor logs** for security events

## 📞 Help Commands

```bash
# Check user permissions
groups
id

# Check sudo access
sudo -l

# Check network interfaces
ip addr show

# Check Python installation
which python3
python3 --version

# Check installed packages
pip3 list | grep -E "(scapy|nmap|psutil)"
```

This setup ensures proper administrative permissions while maintaining security on Kali Linux! 🐧
