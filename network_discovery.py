# -*- coding: utf-8 -*-
# network_discovery.py

from scapy.all import ARP, Ether, srp, sniff, conf
import socket
import re
import psutil
import sys
import warnings
warnings.filterwarnings("ignore")

class NetworkScanner:
    def __init__(self, interface=None):
        self.interface = interface or self.get_default_interface()
        self.devices = []
    
    def get_default_interface(self):
        """Get default network interface"""
        try:
            # Get default interface using psutil
            interfaces = psutil.net_if_addrs()
            if not interfaces:
                raise Exception("No network interfaces found")
                
            for name, addrs in interfaces.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        print(f"[*] Using interface: {name}")
                        return name
            
            # fallback
            fallback = list(interfaces.keys())[0]
            print(f"[!] Using fallback interface: {fallback}")
            return fallback
            
        except Exception as e:
            print(f"[!] Error getting default interface: {e}")
            # Return a common interface name as last resort
            return "eth0"
    
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
        """ARP scanning for device discovery"""
        try:
            print(f"[*] Scanning network: {target_ip}")
            
            # Check if we have permission to use raw sockets
            if not self._check_raw_socket_permission():
                raise Exception("Insufficient privileges for ARP scanning. Run as Administrator.")
            
            # Create ARP request
            arp_request = ARP(pdst=target_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send and receive with timeout
            answered_list = srp(arp_request_broadcast, timeout=3, verbose=False, retry=2)[0]
            
            devices = []
            for sent, received in answered_list:
                try:
                    device = {
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'vendor': self.get_vendor(received.hwsrc)
                    }
                    devices.append(device)
                except Exception as e:
                    print(f"[!] Error processing device response: {e}")
                    continue
            
            print(f"[+] Found {len(devices)} devices via ARP scan")
            self.devices = devices
            return devices
            
        except Exception as e:
            print(f"[!] ARP scan failed: {e}")
            if "Permission denied" in str(e):
                print("[!] Please run this application as Administrator")
            elif "No such device" in str(e):
                print(f"[!] Network interface '{self.interface}' not available")
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

# Usage Example
if __name__ == "__main__":
    scanner = NetworkScanner()
    network_range = scanner.get_network_range()
    devices = scanner.arp_scan(network_range)
    
    print(f"\n[+] Found {len(devices)} devices:")
    for device in devices:
        print(f"  IP: {device['ip']:15} MAC: {device['mac']:17} Vendor: {device['vendor']}")