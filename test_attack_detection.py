#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# test_attack_detection.py - Test attack detection functionality

import sys
import time
from attack_detector import AttackDetector

def test_attack_detection():
    """Test the attack detection system"""
    print("="*60)
    print("🧪 TESTING ATTACK DETECTION SYSTEM")
    print("="*60)
    
    try:
        # Initialize detector
        detector = AttackDetector()
        
        # Show current interface
        print(f"[*] Attack detector initialized")
        print(f"[*] Platform: {detector.platform}")
        print(f"[*] Ready to detect:")
        print("    - MAC Address Spoofing")
        print("    - ARP Poisoning") 
        print("    - ARP Flood Attacks")
        print()
        
        # Get interface
        from network_discovery import NetworkScanner
        scanner = NetworkScanner()
        interface = scanner.interface
        
        print(f"[*] Using interface: {interface}")
        print(f"[*] Starting monitoring...")
        print()
        
        # Start monitoring
        alerts = detector.start_monitoring(interface, duration=120)  # 2 minutes
        
        # Show results
        print("\n" + "="*60)
        print("📊 MONITORING RESULTS")
        print("="*60)
        
        if alerts:
            print(f"\n✅ SUCCESS: Detected {len(alerts)} attack(s)!")
            for i, alert in enumerate(alerts, 1):
                print(f"\n{i}. [{alert['severity']}] {alert['type']}")
                print(f"   Message: {alert['message']}")
                if 'source_ip' in alert:
                    print(f"   Source IP: {alert['source_ip']}")
                if 'old_mac' in alert and 'new_mac' in alert:
                    print(f"   MAC Change: {alert['old_mac']} → {alert['new_mac']}")
        else:
            print("\n⚠️  NO ATTACKS DETECTED")
            print("\nTroubleshooting:")
            print("1. Make sure Kali VM is generating traffic (ping commands)")
            print("2. Ensure both VMs are on same network")
            print("3. Check that interface is correct")
            print("4. Run with sudo/administrator privileges")
            print("5. Try generating more network activity")
        
        print("\n" + "="*60)
        
    except Exception as e:
        print(f"[!] Error during testing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_attack_detection()
