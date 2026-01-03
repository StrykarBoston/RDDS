# rogue_detector.py

import json
import os
from datetime import datetime
import hashlib

class RogueDetector:
    def __init__(self, whitelist_file='whitelist.json'):
        self.whitelist_file = whitelist_file
        self.whitelist = self.load_whitelist()
        self.detected_rogues = []
        self.alerts = []
    
    def load_whitelist(self):
        """Load trusted devices"""
        if os.path.exists(self.whitelist_file):
            with open(self.whitelist_file, 'r') as f:
                return json.load(f)
        return []
    
    def save_whitelist(self):
        """Save whitelist to disk"""
        with open(self.whitelist_file, 'w') as f:
            json.dump(self.whitelist, f, indent=2)
    
    def add_to_whitelist(self, device):
        """Add device to trusted list"""
        if not any(d['mac'] == device['mac'] for d in self.whitelist):
            device['added_date'] = str(datetime.now())
            self.whitelist.append(device)
            self.save_whitelist()
            return True
        return False
    
    def is_whitelisted(self, mac):
        """Check if device is trusted"""
        return any(d['mac'] == mac for d in self.whitelist)
    
    def detect_mac_spoofing(self, devices):
        """Detect MAC address spoofing"""
        alerts = []
        
        # Check for duplicate MACs with different IPs
        mac_ip_map = {}
        for device in devices:
            mac = device['mac']
            ip = device['ip']
            
            if mac in mac_ip_map:
                if mac_ip_map[mac] != ip:
                    alerts.append({
                        'type': 'MAC_SPOOFING',
                        'severity': 'CRITICAL',
                        'mac': mac,
                        'ip': [mac_ip_map[mac], ip],
                        'message': f"MAC {mac} seen with multiple IPs",
                        'timestamp': str(datetime.now())
                    })
            else:
                mac_ip_map[mac] = ip
        
        return alerts
    
    def detect_vendor_mismatch(self, device):
        """Detect suspicious vendor changes"""
        mac = device['mac']
        current_vendor = device.get('vendor', 'Unknown')
        
        # Check against whitelist
        for known_device in self.whitelist:
            if known_device['mac'] == mac:
                if known_device.get('vendor') != current_vendor:
                    return {
                        'type': 'VENDOR_MISMATCH',
                        'severity': 'HIGH',
                        'mac': mac,
                        'expected': known_device.get('vendor'),
                        'actual': current_vendor,
                        'message': f"Vendor changed for {mac}",
                        'timestamp': str(datetime.now())
                    }
        return None
    
    def detect_new_devices(self, devices):
        """Detect unauthorized new devices"""
        rogues = []
        
        for device in devices:
            if not self.is_whitelisted(device['mac']):
                rogues.append({
                    'type': 'UNAUTHORIZED_DEVICE',
                    'severity': 'MEDIUM',
                    'device': device,
                    'message': f"New unauthorized device: {device['mac']}",
                    'timestamp': str(datetime.now())
                })
        
        return rogues
    
    def calculate_risk_score(self, device, alerts):
        """Calculate risk score for device"""
        score = 0
        factors = []
        
        # Base score for unknown device
        if not self.is_whitelisted(device['mac']):
            score += 30
            factors.append('Not Whitelisted')
        
        # Suspicious vendor
        suspicious_vendors = ['Unknown', 'Raspberry Pi']
        if device.get('vendor') in suspicious_vendors:
            score += 25
            factors.append('Suspicious Vendor')
        
        # Check alerts related to this device
        device_alerts = [a for a in alerts if a.get('mac') == device['mac']]
        for alert in device_alerts:
            if alert['severity'] == 'CRITICAL':
                score += 40
            elif alert['severity'] == 'HIGH':
                score += 25
            else:
                score += 10
            factors.append(alert['type'])
        
        return min(score, 100), factors
    
    def analyze_network(self, devices):
        """Complete rogue analysis"""
        all_alerts = []
        
        # Detect MAC spoofing
        spoof_alerts = self.detect_mac_spoofing(devices)
        all_alerts.extend(spoof_alerts)
        
        # Detect new devices
        new_device_alerts = self.detect_new_devices(devices)
        all_alerts.extend(new_device_alerts)
        
        # Vendor mismatch
        for device in devices:
            vendor_alert = self.detect_vendor_mismatch(device)
            if vendor_alert:
                all_alerts.append(vendor_alert)
        
        # Calculate risk scores
        enriched_devices = []
        for device in devices:
            risk_score, risk_factors = self.calculate_risk_score(device, all_alerts)
            device['risk_score'] = risk_score
            device['risk_factors'] = risk_factors
            
            if risk_score >= 70:
                device['status'] = 'ROGUE'
            elif risk_score >= 40:
                device['status'] = 'SUSPICIOUS'
            else:
                device['status'] = 'TRUSTED'
            
            enriched_devices.append(device)
        
        self.alerts = all_alerts
        return enriched_devices, all_alerts

# Usage Example
if __name__ == "__main__":
    detector = RogueDetector()
    
    # Simulate discovered devices
    devices = [
        {'ip': '192.168.1.100', 'mac': '00:1A:2B:3C:4D:5E', 'vendor': 'Cisco'},
        {'ip': '192.168.1.50', 'mac': 'B8:27:EB:12:34:56', 'vendor': 'Raspberry Pi'}
    ]
    
    analyzed_devices, alerts = detector.analyze_network(devices)
    
    print("\n[+] Analysis Results:")
    for device in analyzed_devices:
        print(f"  {device['ip']} - {device['status']} (Risk: {device['risk_score']})")
    
    print(f"\n[!] {len(alerts)} Alerts Generated")