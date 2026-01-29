# -*- coding: utf-8 -*-
# network_discovery.py

from scapy.all import ARP, Ether, srp, sniff, conf
import socket
import re
import psutil
import sys
import warnings
import platform
warnings.filterwarnings("ignore")

class NetworkScanner:
    def __init__(self, interface=None):
        self.platform = platform.system().lower()
        self.interface = interface or self.get_default_interface()
        self.devices = []
        print(f"[*] Platform detected: {self.platform}")
        print(f"[*] Using interface: {self.interface}")
    
    def list_available_interfaces(self):
        """List all available network interfaces with details"""
        interfaces = psutil.net_if_addrs()
        print("\n" + "="*60)
        print("📡 AVAILABLE NETWORK INTERFACES")
        print("="*60)
        
        interface_list = []
        for i, (name, addrs) in enumerate(interfaces.items(), 1):
            ipv4_addr = None
            mac_addr = None
            
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    ipv4_addr = addr.address
                elif addr.family == psutil.AF_LINK:
                    mac_addr = addr.address
            
            if ipv4_addr:  # Only show interfaces with IPv4
                interface_list.append((name, ipv4_addr, mac_addr))
                print(f"{i}. {name:15} | IP: {ipv4_addr:15} | MAC: {mac_addr or 'Unknown'}")
        
        return interface_list
    
    def select_interface_interactive(self):
        """Let user select interface interactively"""
        interface_list = self.list_available_interfaces()
        
        if not interface_list:
            print("\n❌ No network interfaces found!")
            return None
        
        while True:
            try:
                choice = input(f"\nSelect interface (1-{len(interface_list)}) or press Enter for auto: ").strip()
                
                if not choice:
                    # Auto-select best interface
                    selected = self.get_default_interface()
                    print(f"[*] Auto-selected interface: {selected}")
                    return selected
                
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(interface_list):
                    selected = interface_list[choice_idx][0]
                    print(f"[*] Selected interface: {selected}")
                    return selected
                else:
                    print(f"❌ Please enter a number between 1 and {len(interface_list)}")
            except ValueError:
                print("❌ Please enter a valid number")
            except KeyboardInterrupt:
                print("\n[*] Interface selection cancelled")
                return None
    
    def get_default_interface(self, auto_select=True):
        """Get default network interface with platform-specific logic"""
        try:
            # Method 1: Try psutil first
            interfaces = psutil.net_if_addrs()
            if not interfaces:
                raise Exception("No network interfaces found")
            
            if not auto_select:
                # Interactive mode - let user choose
                return self.select_interface_interactive()
            
            # Platform-specific interface selection
            if self.platform == "windows":
                return self._get_windows_interface(interfaces)
            else:
                return self._get_linux_interface(interfaces)
                
        except Exception as e:
            print(f"[!] Error getting default interface: {e}")
            # Platform-specific fallbacks
            if self.platform == "windows":
                fallback = "Wi-Fi"  # Changed from Ethernet to Wi-Fi
            else:
                fallback = "wlan0"  # Changed from eth0 to wlan0
            print(f"[!] Using fallback interface: {fallback}")
            return fallback
    
    def _get_windows_interface(self, interfaces):
        """Get Windows interface with IPv4 connectivity - prioritize Wi-Fi"""
        # Prioritize Wi-Fi first, then Ethernet, then others
        priority_names = ['Wi-Fi', 'Wireless', 'WLAN', 'WiFi', 'Ethernet', 'Local Area Connection']
        
        for priority in priority_names:
            if priority in interfaces:
                for addr in interfaces[priority]:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        print(f"[*] Found Windows interface: {priority} ({addr.address})")
                        return priority
        
        # Fallback to any interface with IPv4
        for name, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    print(f"[*] Using fallback Windows interface: {name} ({addr.address})")
                    return name
        
        raise Exception("No suitable Windows interface found")
    
    def _get_linux_interface(self, interfaces):
        """Get Linux interface with IPv4 connectivity - prioritize Wi-Fi"""
        # Prioritize wireless interfaces first
        priority_names = ['wlan0', 'wlp2s0', 'wlan1', 'wlp3s0', 'wifi0', 'eth0', 'enp0s3', 'ens33']
        
        for priority in priority_names:
            if priority in interfaces:
                for addr in interfaces[priority]:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        print(f"[*] Found Linux interface: {priority} ({addr.address})")
                        return priority
        
        # Fallback to any non-loopback interface with IPv4
        for name, addrs in interfaces.items():
            if not name.startswith('lo') and not name.startswith('docker') and not name.startswith('virbr'):
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        print(f"[*] Using fallback Linux interface: {name} ({addr.address})")
                        return name
        
        raise Exception("No suitable Linux interface found")
    
    def get_network_range(self):
        """Calculate network CIDR"""
        try:
            interfaces = psutil.net_if_addrs()
            
            if not interfaces:
                raise Exception("No network interfaces available")
            
            for name, addrs in interfaces.items():
                if name == self.interface:
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            ip = addr.address
                            netmask = addr.netmask
                            # Convert to CIDR
                            network = self.calculate_network(ip, netmask)
                            print(f"[*] Network range: {network}")
                            return network
            
            # Fallback to common network range
            print(f"[!] Could not determine network range for {self.interface}, using fallback")
            return "192.168.1.0/24"
            
        except Exception as e:
            print(f"[!] Error getting network range: {e}")
            return "192.168.1.0/24"
    
    def calculate_network(self, ip, netmask):
        """Calculate network address"""
        ip_parts = [int(x) for x in ip.split('.')]
        mask_parts = [int(x) for x in netmask.split('.')]
        
        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        cidr = sum([bin(x).count('1') for x in mask_parts])
        
        return f"{'.'.join(map(str, network_parts))}/{cidr}"
    
    def arp_scan(self, target_ip):
        """ARP scanning for device discovery with improved error handling"""
        try:
            print(f"[*] Scanning network: {target_ip} on {self.interface}")
            
            # Platform-specific permission check
            if not self._check_permissions():
                if self.platform == "windows":
                    print("[!] ERROR: Administrator privileges required on Windows")
                    print("[!] Please restart as Administrator")
                else:
                    print("[!] ERROR: Root privileges required on Linux")
                    print("[!] Please restart with sudo")
                return []
            
            # Test interface availability
            if not self._test_interface():
                print(f"[!] ERROR: Interface {self.interface} is not available")
                return []
            
            # Create ARP request with platform-specific settings
            arp_request = ARP(pdst=target_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Platform-specific timeout and retry settings
            timeout = 5 if self.platform == "windows" else 3
            retry = 1 if self.platform == "windows" else 2
            
            print(f"[*] Sending ARP requests (timeout: {timeout}s, retries: {retry})...")
            
            # Send and receive with better error handling
            answered_list = srp(
                arp_request_broadcast, 
                timeout=timeout, 
                verbose=False, 
                retry=retry,
                iface=self.interface
            )[0]
            
            devices = []
            for sent, received in answered_list:
                try:
                    device = {
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'vendor': self.get_vendor(received.hwsrc)
                    }
                    devices.append(device)
                    print(f"[+] Found device: {received.psrc} -> {received.hwsrc}")
                except Exception as e:
                    print(f"[!] Error processing device response: {e}")
                    continue
            
            print(f"[+] ARP scan completed: Found {len(devices)} devices")
            self.devices = devices
            return devices
            
        except Exception as e:
            print(f"[!] ARP scan failed: {e}")
            if "Permission denied" in str(e):
                if self.platform == "windows":
                    print("[!] Please run this application as Administrator on Windows")
                else:
                    print("[!] Please run this application with sudo on Linux")
            elif "No such device" in str(e):
                print(f"[!] Network interface '{self.interface}' not found or not available")
            elif "Operation not permitted" in str(e):
                print(f"[!] Operation not permitted - check privileges and interface status")
            return []
    
    def get_vendor(self, mac):
        """Get vendor from MAC OUI"""
        # OUI lookup (first 6 chars)
        oui = mac[:8].upper().replace(':', '')
        
        # Basic vendor database (expand this)
        vendors = {
            '001A2B': 'Cisco',
            '00E04C': 'Realtek',
            '0050F2': 'Microsoft',
            'B827EB': 'Raspberry Pi',
            '001EC0': 'Apple',
            '00D861': 'Hon Hai (Foxconn)'
        }
        
        return vendors.get(oui, 'Unknown')
    
    def passive_sniff(self, count=100):
        """Passive traffic monitoring"""
        try:
            print("[*] Starting passive sniffing...")
            
            if not self._check_raw_socket_permission():
                raise Exception("Insufficient privileges for packet capture. Run as Administrator.")
            
            packets = sniff(iface=self.interface, count=count, timeout=10, store=False)
            
            # Extract unique devices
            devices = {}
            for pkt in packets:
                try:
                    if pkt.haslayer(ARP):
                        ip = pkt[ARP].psrc
                        mac = pkt[ARP].hwsrc
                        if ip and mac:
                            devices[mac] = {
                                'ip': ip, 
                                'mac': mac,
                                'vendor': self.get_vendor(mac)
                            }
                except Exception as e:
                    print(f"[!] Error processing packet: {e}")
                    continue
            
            device_list = list(devices.values())
            print(f"[+] Found {len(device_list)} devices via passive sniffing")
            return device_list
            
        except Exception as e:
            print(f"[!] Passive sniffing failed: {e}")
            if "Permission denied" in str(e):
                print("[!] Please run this application as Administrator")
            elif "No such device" in str(e):
                print(f"[!] Network interface '{self.interface}' not available")
            return []

    def _check_raw_socket_permission(self):
        """Check if we have permission to use raw sockets"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.close()
            return True
        except socket.error:
            return False

    def _check_permissions(self):
        """Platform-specific permission checking"""
        try:
            if self.platform == "windows":
                # Windows: Check for admin rights
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                # Linux: Check if we can create raw socket
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                s.close()
                return True
        except:
            return False
    
    def _test_interface(self):
        """Test if interface is available and working"""
        try:
            interfaces = psutil.net_if_addrs()
            return self.interface in interfaces
        except:
            return False

# Usage Example
if __name__ == "__main__":
    scanner = NetworkScanner()
    network_range = scanner.get_network_range()
    devices = scanner.arp_scan(network_range)
    
    print(f"\n[+] Found {len(devices)} devices:")
    for device in devices:
        print(f"  IP: {device['ip']:15} MAC: {device['mac']:17} Vendor: {device['vendor']}")