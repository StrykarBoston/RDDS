# -*- coding: utf-8 -*-
# attack_detector.py

from scapy.all import ARP, sniff, wrpcap
from collections import defaultdict
import time

class AttackDetector:
    def __init__(self):
        self.arp_cache = {}
        self.arp_requests = defaultdict(list)
        self.alerts = []
    
    def detect_arp_poisoning(self, packet):
        """Detect ARP spoofing/poisoning"""
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
                            'message': f"ARP poisoning detected! IP {src_ip} MAC changed",
                            'timestamp': time.time()
                        }
                        self.alerts.append(alert)
                        print(f"🚨 [CRITICAL] ARP Poisoning: {src_ip}")
                        return alert
                
                self.arp_cache[src_ip] = src_mac
        
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
                print(f"⚠ [HIGH] ARP Flood: {src_mac}")
                return alert
        
        return None
    
    def detect_rogue_dhcp(self, packet):
        """Detect rogue DHCP servers"""
        # Check for DHCP Offer/Ack from unauthorized servers
        # Implementation requires DHCP packet parsing
        pass
    
    def start_monitoring(self, interface, duration=60):
        """Start real-time attack monitoring"""
        print(f"[*] Starting attack detection on {interface}...")
        print(f"[*] Monitoring for {duration} seconds...")
        
        def packet_handler(pkt):
            self.detect_arp_poisoning(pkt)
            self.detect_arp_flood(pkt)
        
        sniff(iface=interface, prn=packet_handler, timeout=duration, store=False)
        
        return self.alerts

# Usage Example
if __name__ == "__main__":
    detector = AttackDetector()
    alerts = detector.start_monitoring(interface="Ethernet", duration=30)
    
    print(f"\n[+] Detected {len(alerts)} attacks:")
    for alert in alerts:
        print(f"  {alert['type']}: {alert['message']}")