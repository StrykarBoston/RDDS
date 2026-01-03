# rogue_ap_detector.py

import subprocess
import re
from collections import defaultdict

class RogueAPDetector:
    def __init__(self):
        self.known_aps = []  # Load from config
        self.detected_aps = []
    
    def scan_wireless_networks_windows(self):
        """Scan for wireless networks on Windows"""
        try:
            # Run netsh command
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True,
                text=True
            )
            
            networks = self.parse_netsh_output(result.stdout)
            return networks
        
        except Exception as e:
            print(f"Error scanning networks: {e}")
            return []
    
    def parse_netsh_output(self, output):
        """Parse netsh wlan output"""
        networks = []
        current_ssid = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('SSID'):
                match = re.search(r'SSID \d+ : (.+)', line)
                if match:
                    current_ssid = match.group(1)
            
            elif 'BSSID' in line and current_ssid:
                match = re.search(r'BSSID \d+\s+:\s+([0-9a-fA-F:]+)', line)
                if match:
                    bssid = match.group(1)
                    networks.append({
                        'ssid': current_ssid,
                        'bssid': bssid
                    })
        
        return networks
    
    def detect_evil_twin(self, networks):
        """Detect Evil Twin APs (same SSID, different BSSID)"""
        ssid_map = defaultdict(list)
        alerts = []
        
        for network in networks:
            ssid_map[network['ssid']].append(network['bssid'])
        
        for ssid, bssids in ssid_map.items():
            if len(bssids) > 1:
                alert = {
                    'type': 'EVIL_TWIN_AP',
                    'severity': 'CRITICAL',
                    'ssid': ssid,
                    'bssids': bssids,
                    'message': f"Multiple APs detected with SSID: {ssid}",
                    'count': len(bssids)
                }
                alerts.append(alert)
                print(f"🚨 Evil Twin AP detected: {ssid} ({len(bssids)} BSSIDs)")
        
        return alerts
    
    def detect_rogue_ap(self, networks):
        """Detect unauthorized access points"""
        rogues = []
        
        # Compare against known good APs
        known_bssids = [ap['bssid'] for ap in self.known_aps]
        
        for network in networks:
            if network['bssid'] not in known_bssids:
                rogues.append({
                    'type': 'ROGUE_AP',
                    'severity': 'HIGH',
                    'ssid': network['ssid'],
                    'bssid': network['bssid'],
                    'message': f"Unauthorized AP: {network['ssid']}"
                })
        
        return rogues

# Usage Example
if __name__ == "__main__":
    detector = RogueAPDetector()
    networks = detector.scan_wireless_networks_windows()
    
    print(f"[+] Found {len(networks)} wireless networks")
    
    evil_twin_alerts = detector.detect_evil_twin(networks)
    print(f"[!] {len(evil_twin_alerts)} Evil Twin alerts")