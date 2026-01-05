#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# install_linux.py - Linux-specific installation script for RDDS

import os
import sys
import subprocess
import platform
import getpass

def run_command(command, description, use_sudo=False):
    """Run a command with optional sudo"""
    print(f"[*] {description}...")
    
    if use_sudo:
        command = f"sudo {command}"
    
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"[+] {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] {description} failed: {e}")
        if e.stdout:
            print(f"    Output: {e.stdout}")
        if e.stderr:
            print(f"    Error: {e.stderr}")
        return False

def check_linux_distribution():
    """Check Linux distribution"""
    try:
        with open('/etc/os-release', 'r') as f:
            content = f.read()
            if 'kali' in content.lower():
                return 'Kali Linux'
            elif 'ubuntu' in content.lower():
                return 'Ubuntu'
            elif 'debian' in content.lower():
                return 'Debian'
            else:
                return 'Unknown Linux'
    except:
        return 'Linux'

def check_root_privileges():
    """Check if running as root or with sudo"""
    if platform.system() == 'Windows':
        print("[!] This script is for Linux only")
        return False
    elif hasattr(os, 'geteuid'):
        if os.geteuid() == 0:
            print("[+] Running as root")
            return True
        else:
            print("[!] Not running as root")
            return False
    else:
        print("[!] Cannot check root privileges on this system")
        return False

def install_system_packages():
    """Install system packages using apt"""
    print("\n[*] Installing system packages...")
    
    packages = [
        "python3",
        "python3-pip", 
        "python3-dev",
        "python3-tk",
        "libpcap-dev",
        "nmap",
        "tcpdump",
        "build-essential"
    ]
    
    # Update package lists
    if not run_command("apt update", "Updating package lists", use_sudo=True):
        return False
    
    # Install packages
    for package in packages:
        if not run_command(f"apt install -y {package}", f"Installing {package}", use_sudo=True):
            print(f"[!] Failed to install {package}")
    
    return True

def install_python_packages():
    """Install Python packages"""
    print("\n[*] Installing Python packages...")
    
    # Upgrade pip first
    if not run_command("pip3 install --upgrade pip", "Upgrading pip", use_sudo=True):
        print("[!] Failed to upgrade pip")
    
    # Install requirements
    if os.path.exists("requirements.txt"):
        success = run_command("pip3 install -r requirements.txt", "Installing requirements", use_sudo=True)
        if not success:
            print("[!] Failed to install from requirements.txt, trying individual packages...")
            
            # Fallback to individual packages
            packages = [
                "scapy>=2.4.5",
                "python-nmap>=0.7.1",
                "psutil>=5.9.0",
                "pyshark>=0.6.0",
                "flask>=2.3.0",
                "requests>=2.31.0",
                "pandas>=2.0.0",
                "colorama>=0.4.6",
                "tabulate>=0.9.0"
            ]
            
            for package in packages:
                run_command(f"pip3 install {package}", f"Installing {package}", use_sudo=True)
    else:
        print("[!] requirements.txt not found")

def check_network_permissions():
    """Check network permissions"""
    print("\n[*] Checking network permissions...")
    
    # Check if user can access network interfaces
    try:
        result = subprocess.run("ip addr show", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Can list network interfaces")
        else:
            print("[!] Cannot list network interfaces - may need sudo")
    except Exception as e:
        print(f"[!] Error checking network interfaces: {e}")
    
    # Test packet capture permission
    try:
        result = subprocess.run("tcpdump -i lo -c 1 2>/dev/null", shell=True, timeout=5, capture_output=True, text=True)
        if result.returncode == 0 or "permission denied" not in result.stderr.lower():
            print("[+] Packet capture permission available")
        else:
            print("[!] Packet capture requires sudo or capabilities")
            print("    Run: sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")
    except Exception as e:
        print(f"[!] Error checking packet capture: {e}")

def setup_capabilities():
    """Set up capabilities for Python (optional)"""
    print("\n[*] Setting up capabilities...")
    
    print("To run without sudo, you can set capabilities:")
    print("sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")
    print()
    print("Or continue using sudo:")
    print("sudo python3 gui_main.py")

def create_launcher_script():
    """Create a launcher script"""
    script_content = """#!/bin/bash
# RDDS Launcher Script

cd "$(dirname "$0")"

if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges for network operations."
    echo "Using sudo..."
    sudo python3 gui_main.py
else
    python3 gui_main.py
fi
"""
    
    with open("rdds-launcher.sh", "w") as f:
        f.write(script_content)
    
    os.chmod("rdds-launcher.sh", 0o755)
    print("[+] Created rdds-launcher.sh")

def test_installation():
    """Test if installation works"""
    print("\n[*] Testing installation...")
    
    # Test Python imports
    modules = ["scapy", "nmap", "psutil", "pandas", "flask", "requests"]
    failed_modules = []
    
    for module in modules:
        try:
            __import__(module)
            print(f"[+] {module} imported successfully")
        except ImportError as e:
            print(f"[!] Failed to import {module}: {e}")
            failed_modules.append(module)
    
    if failed_modules:
        print(f"\n[!] Failed to import: {', '.join(failed_modules)}")
        return False
    else:
        print("[+] All modules imported successfully")
        return True

def main():
    """Main installation function"""
    print("=" * 60)
    print("🐧 RDDS Linux Installation Script")
    print("=" * 60)
    
    # Check Linux distribution
    distro = check_linux_distribution()
    print(f"[*] Detected: {distro}")
    
    # Check privileges
    is_root = check_root_privileges()
    
    if not is_root:
        print("\n[!] This installation requires root privileges")
        print("    Please run with sudo: sudo python3 install_linux.py")
        print("    Or run as root: su - root")
        sys.exit(1)
    
    # Install system packages
    if not install_system_packages():
        print("[!] System package installation failed")
        sys.exit(1)
    
    # Install Python packages
    install_python_packages()
    
    # Check network permissions
    check_network_permissions()
    
    # Setup capabilities
    setup_capabilities()
    
    # Create launcher script
    create_launcher_script()
    
    # Test installation
    if test_installation():
        print("\n" + "=" * 60)
        print("✅ Installation completed successfully!")
        print("\nNext steps:")
        print("1. Run with sudo:")
        print("   sudo python3 gui_main.py")
        print("   or")
        print("   ./rdds-launcher.sh")
        print("\n2. Or set capabilities to avoid sudo:")
        print("   sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")
        print("   python3 gui_main.py")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("❌ Installation completed with errors")
        print("Please check the failed modules above")
        print("=" * 60)

if __name__ == "__main__":
    main()
