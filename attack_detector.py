# -*- coding: utf-8 -*-
# attack_detector.py

from scapy.all import ARP, sniff, wrpcap
from collections import defaultdict
import time
import platform
import sys

class AttackDetector:
    def __init__(self):
        self.platform = platform.system().lower()
        self.arp_cache = {}
        self.arp_requests = defaultdict(list)
        self.alerts = []
        print(f"[*] AttackDetector initialized for {self.platform}")
    
    def detect_arp_poisoning(self, packet):
        """Detect ARP poisoning attacks"""
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            
            if arp_layer.op == 2:  # ARP Reply
                src_ip = arp_layer.psrc
                src_mac = arp_layer.hwsrc
                
                # Check if IP-MAC mapping changed
                if src_ip in self.arp_cache:
                    if self.arp_cache[src_ip] != src_mac:
                        alert = {
                            'type': 'ARP_POISONING',
                            'severity': 'CRITICAL',
                            'source_ip': src_ip,
                            'old_mac': self.arp_cache[src_ip],
                            'new_mac': src_mac,
                            'message': f"MAC address changed from {self.arp_cache[src_ip]} to {src_mac}",
                            'timestamp': time.time()
                        }
                        self.alerts.append(alert)
                        print(f"\n🚨 [CRITICAL] ARP Poisoning: {src_ip}")
                        print(f"   MAC address changed from {self.arp_cache[src_ip]} to {src_mac}")
                        print(f"   Time: {time.strftime('%H:%M:%S')}")
                        return alert
                
                self.arp_cache[src_ip] = src_mac
        
        return None
    
    def detect_mac_spoofing(self, packet):
        """Detect MAC address spoofing by monitoring multiple MACs for same IP"""
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            
            if arp_layer.op in [1, 2]:  # ARP Request or Reply
                src_ip = arp_layer.psrc
                src_mac = arp_layer.hwsrc
                
                # Track MAC addresses seen for each IP
                if src_ip not in self.mac_tracker:
                    self.mac_tracker[src_ip] = {'macs': set(), 'first_seen': time.time()}
                
                self.mac_tracker[src_ip]['macs'].add(src_mac)
                
                # If multiple MACs seen for same IP within short time
                if len(self.mac_tracker[src_ip]['macs']) > 1:
                    time_diff = time.time() - self.mac_tracker[src_ip]['first_seen']
                    if time_diff < 60:  # Within 1 minute
                        alert = {
                            'type': 'MAC_SPOOFING',
                            'severity': 'CRITICAL',
                            'source_ip': src_ip,
                            'mac_addresses': list(self.mac_tracker[src_ip]['macs']),
                            'message': f"MAC spoofing detected! IP {src_ip} using multiple MAC addresses",
                            'timestamp': time.time()
                        }
                        self.alerts.append(alert)
                        print(f"\n🚨 [CRITICAL] MAC Spoofing: {src_ip}")
                        print(f"   Device {src_ip} shows signs of MAC address spoofing")
                        print(f"   MAC addresses seen: {list(self.mac_tracker[src_ip]['macs'])}")
                        print(f"   Time: {time.strftime('%H:%M:%S')}")
                        return alert
        
        return None
    
    def detect_arp_flood(self, packet):
        """Detect ARP flood/storm"""
        if packet.haslayer(ARP):
            src_mac = packet[ARP].hwsrc
            current_time = time.time()
            
            # Track ARP requests per MAC
            self.arp_requests[src_mac].append(current_time)
            
            # Clean old requests (older than 10 seconds)
            self.arp_requests[src_mac] = [
                t for t in self.arp_requests[src_mac] 
                if current_time - t < 10
            ]
            
            # Alert if more than 50 requests in 10 seconds
            if len(self.arp_requests[src_mac]) > 50:
                alert = {
                    'type': 'ARP_FLOOD',
                    'severity': 'HIGH',
                    'source_mac': src_mac,
                    'request_count': len(self.arp_requests[src_mac]),
                    'message': f"ARP flood detected from {src_mac}",
                    'timestamp': current_time
                }
                self.alerts.append(alert)
                print(f" [HIGH] ARP Flood: {src_mac}")
                return alert
        
        return None
    
    def detect_rogue_dhcp(self, packet):
        """Detect rogue DHCP servers"""
        # Check for DHCP Offer/Ack from unauthorized servers
        # Implementation requires DHCP packet parsing
        pass
    
    def start_monitoring(self, interface, duration=60):
        """Start real-time attack monitoring with improved error handling"""
        print(f"[*] Starting attack detection on {interface}...")
        print(f"[*] Monitoring for {duration} seconds...")
        print(f"[*] Press Ctrl+C to stop early")
        print("="*60)
        
        try:
            # Test interface availability
            import psutil
            interfaces = psutil.net_if_addrs()
            if interface not in interfaces:
                print(f"[!] ERROR: Interface {interface} not found")
                return []
            
            # Clear previous alerts
            self.alerts = []
            self.arp_cache = {}
            self.arp_requests = defaultdict(list)
            self.mac_tracker = {}
            
            print(f"[*] Monitoring interface: {interface}")
            print(f"[*] Waiting for network activity...")
            
            def packet_handler(pkt):
                try:
                    # Check all attack types
                    alert1 = self.detect_mac_spoofing(pkt)
                    alert2 = self.detect_arp_poisoning(pkt)
                    alert3 = self.detect_arp_flood(pkt)
                    
                    # Print immediate feedback for any detection
                    if alert1 or alert2 or alert3:
                        print("\n" + "="*50)
                        print(f"[!] Attack detected at {time.strftime('%H:%M:%S')}")
                        print("="*50)
                except Exception as e:
                    print(f"[!] Error processing packet: {e}")
            
            print(f"[*] Starting packet capture on {interface}...")
            
            # Start sniffing with better error handling
            packets = sniff(
                iface=interface, 
                prn=packet_handler, 
                timeout=duration, 
                store=False,
                stop_filter=lambda x: False  # Don't stop early
            )
            
            print("\n" + "="*60)
            print(f"[*] Monitoring completed.")
            print(f"[*] Total alerts generated: {len(self.alerts)}")
            
            if self.alerts:
                print("\n[*] SUMMARY OF DETECTED ATTACKS:")
                for i, alert in enumerate(self.alerts, 1):
                    print(f"  {i}. [{alert['severity']}] {alert['type']}: {alert['message']}")
            else:
                print("\n[*] No attacks detected during monitoring period.")
                print("[*] Make sure:")
                print("    - You are generating network traffic")
                print("    - Kali VM is on same network")
                print("    - Interface is correct")
            
            print("="*60)
            return self.alerts
            
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user")
            return self.alerts
        except Exception as e:
            print(f"[!] Monitoring failed: {e}")
            if "Permission denied" in str(e):
                if self.platform == "windows":
                    print("[!] Please run as Administrator on Windows")
                else:
                    print("[!] Please run with sudo on Linux")
            elif "No such device" in str(e):
                print(f"[!] Interface {interface} not available")
            return []

# Usage Example
if __name__ == "__main__":
    detector = AttackDetector()
    alerts = detector.start_monitoring(interface="Ethernet", duration=30)
    
    print(f"\n[+] Detected {len(alerts)} attacks:")
    for alert in alerts:
        print(f"  {alert['type']}: {alert['message']}")