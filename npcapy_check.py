# -*- coding: utf-8 -*-
# npcapy_check.py - Npcap/WinPcap installation checker

import os
import sys
import subprocess
import platform
from scapy.all import conf

def check_npcap_installation():
    """Check if Npcap/WinPcap is installed and working"""
    
    if platform.system() != "Windows":
        return True, "Not Windows - Npcap not required"
    
    try:
        # Check if Npcap is installed by testing scapy
        conf.sniff_sockets = {"eth": "ethernet"}
        
        # Try to get available interfaces
        interfaces = conf.ifaces
        
        if not interfaces:
            return False, "No network interfaces found - Npcap may not be installed"
        
        # Test if we can actually use the interface
        test_iface = list(interfaces.keys())[0]
        
        # Try a simple capture test (non-blocking)
        from scapy.all import sniff, IP
        try:
            # Quick test to see if packet capture works
            packets = sniff(iface=test_iface, count=1, timeout=2, store=False)
            return True, f"Npcap is working on interface: {test_iface}"
        except Exception as e:
            if "Permission denied" in str(e):
                return False, "Npcap requires administrator privileges"
            elif "No such device" in str(e):
                return False, "Npcap installed but no valid network interface"
            else:
                return False, f"Npcap error: {str(e)}"
                
    except ImportError:
        return False, "Scapy not installed - cannot check Npcap"
    except Exception as e:
        return False, f"Error checking Npcap: {str(e)}"

def check_npcap_service():
    """Check if Npcap service is running"""
    try:
        result = subprocess.run(
            ['sc', 'query', 'npcap'], 
            capture_output=True, 
            text=True, 
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode == 0:
            if "RUNNING" in result.stdout:
                return True, "Npcap service is running"
            else:
                return False, "Npcap service is not running"
        else:
            # Try npf service name (older versions)
            result = subprocess.run(
                ['sc', 'query', 'npf'], 
                capture_output=True, 
                text=True, 
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.returncode == 0 and "RUNNING" in result.stdout:
                return True, "NPF service is running"
            else:
                return False, "Npcap/NPF service not found"
                
    except Exception as e:
        return False, f"Error checking service: {str(e)}"

def install_npcap_instructions():
    """Return instructions for installing Npcap"""
    instructions = """
Npcap Installation Required:

1. Download Npcap from: https://npcap.com/
2. Choose the Npcap SDK version (recommended)
3. During installation, make sure to:
   - Check "Install Npcap in WinPcap API-compatible Mode"
   - Check "Support loopback traffic" (optional but useful)
4. Restart this application as Administrator

Alternative: Install with Chocolatey:
  choco install npcapy

Note: You must run this application as Administrator after installing Npcap.
"""
    return instructions

def main():
    """Main check function"""
    print("🔍 Checking Npcap installation...")
    
    # Basic installation check
    installed, message = check_npcap_installation()
    if installed:
        print(f"✅ {message}")
        return True
    else:
        print(f"❌ {message}")
        
        # Service check
        service_ok, service_msg = check_npcap_service()
        if not service_ok:
            print(f"❌ {service_msg}")
        
        print(install_npcap_instructions())
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
