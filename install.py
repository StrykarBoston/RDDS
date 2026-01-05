#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# install.py - RDDS Installation Script

import sys
import subprocess
import platform
import os

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"[*] {description}...")
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

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    print(f"[*] Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("[!] Python 3.8 or higher is required")
        return False
    
    return True

def install_pip_packages():
    """Install required packages"""
    print("\n[*] Installing Python packages...")
    
    # Upgrade pip first
    run_command(f"{sys.executable} -m pip install --upgrade pip", "Upgrading pip")
    
    # Install requirements
    if os.path.exists("requirements.txt"):
        success = run_command(f"{sys.executable} -m pip install -r requirements.txt", "Installing requirements")
        if not success:
            print("[!] Failed to install from requirements.txt, trying individual packages...")
            # Fallback to individual package installation
            packages = [
                "scapy>=2.4.5",
                "python-nmap>=0.7.1", 
                "netifaces>=0.11.0",
                "psutil>=5.9.0",
                "pyshark>=0.6.0",
                "flask>=2.3.0",
                "requests>=2.31.0",
                "pandas>=2.0.0",
                "colorama>=0.4.6",
                "tabulate>=0.9.0"
            ]
            
            for package in packages:
                run_command(f"{sys.executable} -m pip install {package}", f"Installing {package}")
    else:
        print("[!] requirements.txt not found")

def check_npcap():
    """Check Npcap on Windows"""
    if platform.system() == "Windows":
        print("\n[*] Checking Npcap installation...")
        try:
            from npcapy_check import check_npcap_installation
            installed, message = check_npcap_installation()
            if installed:
                print(f"[+] {message}")
            else:
                print(f"[!] {message}")
                print("\n[*] Npcap Installation Instructions:")
                print("1. Download Npcap from: https://npcap.com/")
                print("2. Choose the Npcap SDK version (recommended)")
                print("3. During installation, make sure to:")
                print("   - Check 'Install Npcap in WinPcap API-compatible Mode'")
                print("   - Check 'Support loopback traffic' (optional but useful)")
                print("4. Restart this application as Administrator")
        except ImportError:
            print("[!] Cannot check Npcap - npcapy_check.py not found")
        except Exception as e:
            print(f"[!] Error checking Npcap: {e}")

def create_directories():
    """Create necessary directories"""
    directories = ["logs", "reports"]
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"[+] Created directory: {directory}")

def test_imports():
    """Test if all modules can be imported"""
    print("\n[*] Testing module imports...")
    
    modules = [
        "scapy",
        "nmap", 
        # "netifaces",  # Removed - requires Visual C++ build tools on Windows
        "psutil",
        "pandas",
        "flask",
        "requests"
    ]
    
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
    print("🛡️  Rogue Detection & Defense System - Installation")
    print("=" * 60)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Install packages
    install_pip_packages()
    
    # Test imports
    imports_ok = test_imports()
    
    # Check Npcap on Windows
    check_npcap()
    
    print("\n" + "=" * 60)
    if imports_ok:
        print("✅ Installation completed successfully!")
        print("\nNext steps:")
        print("1. Install Npcap if on Windows (see above instructions)")
        print("2. Run the application as Administrator:")
        print("   python gui_main.py")
        print("   or")
        print("   python main.py")
    else:
        print("❌ Installation completed with errors")
        print("Please check the failed modules above and try to install them manually")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
