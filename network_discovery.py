# network_discovery.py

from scapy.all import ARP, Ether, srp, sniff, conf
import socket
import re
import psutil

class NetworkScanner:
    def __init__(self, interface=None):
        self.interface = interface or self.get_default_interface()
        self.devices = []
    
    def get_default_interface(self):
        """Get default network interface"""
        # Get default interface using psutil
        interfaces = psutil.net_if_addrs()
        for name, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    return name
        return list(interfaces.keys())[0]  # fallback
    
    def get_network_range(self):
        """Calculate network CIDR"""
        interfaces = psutil.net_if_addrs()
        
        for name, addrs in interfaces.items():
            if name == self.interface:
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        netmask = addr.netmask
                        # Convert to CIDR
                        network = self.calculate_network(ip, netmask)
                        return network
        
        # Fallback to common network range
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
        print(f"[*] Scanning network: {target_ip}")
        
        # Create ARP request
        arp_request = ARP(pdst=target_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Send and receive
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        devices = []
        for sent, received in answered_list:
            device = {
                'ip': received.psrc,
                'mac': received.hwsrc,
                'vendor': self.get_vendor(received.hwsrc)
            }
            devices.append(device)
        
        self.devices = devices
        return devices
    
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
        print("[*] Starting passive sniffing...")
        packets = sniff(iface=self.interface, count=count, timeout=10)
        
        # Extract unique devices
        devices = {}
        for pkt in packets:
            if pkt.haslayer(ARP):
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if ip and mac:
                    devices[mac] = {'ip': ip, 'mac': mac}
        
        return list(devices.values())

# Usage Example
if __name__ == "__main__":
    scanner = NetworkScanner()
    network_range = scanner.get_network_range()
    devices = scanner.arp_scan(network_range)
    
    print(f"\n[+] Found {len(devices)} devices:")
    for device in devices:
        print(f"  IP: {device['ip']:15} MAC: {device['mac']:17} Vendor: {device['vendor']}")