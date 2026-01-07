# -*- coding: utf-8 -*-
# main_clean.py - Enterprise Rogue Detection System without update feature

import sys
import time
import ctypes
from network_discovery import NetworkScanner
from rogue_detector import RogueDetector
from attack_detector import AttackDetector
from rogue_ap_detector import RogueAPDetector
from logger import SecurityLogger

# ============================================
# ADMINISTRATOR PRIVILEGES CHECK
# ============================================
def is_admin():
    """Check if script is running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_admin_privileges():
    """Verify admin rights before running"""
    if not is_admin():
        print("\n" + "="*60)
        print("⚠️  ERROR: ADMINISTRATOR PRIVILEGES REQUIRED")
        print("="*60)
        print("\nThis tool requires Administrator privileges to:")
        print("  ✗ Capture network packets (Scapy)")
        print("  ✗ Perform ARP scanning")
        print("  ✗ Monitor network interfaces")
        print("  ✗ Access raw socket operations")
        print("\n📌 HOW TO FIX:")
        print("  1. Right-click on Command Prompt or PowerShell")
        print("  2. Select 'Run as Administrator'")
        print("  3. Navigate to project folder")
        print("  4. Run: python main_clean.py")
        print("\n" + "="*60)
        sys.exit(1)
    else:
        print("✓ Administrator privileges confirmed")

# ============================================
# MAIN APPLICATION CLASS
# ============================================
class RogueDetectionSystem:
    def __init__(self, interface=None):
        # Allow interface selection or auto-detect
        if interface is None:
            # Ask user if they want to select interface
            print("\n" + "="*60)
            print("🔌 NETWORK INTERFACE SELECTION")
            print("="*60)
            choice = input("Do you want to select network interface manually? (y/N): ").strip().lower()
            
            if choice == 'y':
                # Interactive interface selection
                temp_scanner = NetworkScanner()
                selected_interface = temp_scanner.select_interface_interactive()
                if selected_interface:
                    self.scanner = NetworkScanner(selected_interface)
                else:
                    print("[*] Using auto-detected interface")
                    self.scanner = NetworkScanner()
            else:
                # Auto-detect
                self.scanner = NetworkScanner()
        else:
            # Use specified interface
            self.scanner = NetworkScanner(interface)
            
        self.detector = RogueDetector()
        self.attack_detector = AttackDetector()
        self.ap_detector = RogueAPDetector()
        self.logger = SecurityLogger()
        
        print("""
╔══════════════════════════════════════════════════════════╗
║   🛡️  ROGUE DEVICE DETECTION SYSTEM v1.0               ║
║   Enterprise Network Security Monitor                    ║
╚══════════════════════════════════════════════════════════╝
        """)
    
    def run_full_scan(self):
        """Execute complete security scan"""
        print("\n[1/4] 🔍 Discovering network devices...")
        
        # Show current interface info
        print(f"[*] Using interface: {self.scanner.interface}")
        
        network_range = self.scanner.get_network_range()
        print(f"[*] Scanning network range: {network_range}")
        
        devices = self.scanner.arp_scan(network_range)
        print(f"      ✓ Found {len(devices)} devices")
        
        if not devices:
            print("\n⚠️  No devices found! This could be due to:")
            print("   1. Wrong network interface selected")
            print("   2. Insufficient privileges (run as Administrator/root)")
            print("   3. Network configuration issues")
            print("   4. Firewall blocking ARP requests")
            
            choice = input("\nWould you like to try a different interface? (y/N): ").strip().lower()
            if choice == 'y':
                # Re-initialize scanner with new interface
                temp_scanner = NetworkScanner()
                selected_interface = temp_scanner.select_interface_interactive()
                if selected_interface:
                    print(f"[*] Switching to interface: {selected_interface}")
                    self.scanner = NetworkScanner(selected_interface)
                    network_range = self.scanner.get_network_range()
                    devices = self.scanner.arp_scan(network_range)
                    print(f"      ✓ Found {len(devices)} devices with new interface")
        
        print("\n[2/4] 🕵️  Analyzing for rogue devices...")
        analyzed_devices, alerts = self.detector.analyze_network(devices)
        
        rogue_count = sum(1 for d in analyzed_devices if d['status'] == 'ROGUE')
        suspicious_count = sum(1 for d in analyzed_devices if d['status'] == 'SUSPICIOUS')
        
        print(f"      ✓ Rogue: {rogue_count} | Suspicious: {suspicious_count}")
        
        print("\n[3/4] 📡 Scanning wireless networks...")
        wireless_networks = self.ap_detector.scan_wireless_networks_windows()
        ap_alerts = self.ap_detector.detect_evil_twin(wireless_networks)
        alerts.extend(ap_alerts)
        print(f"      ✓ Found {len(wireless_networks)} APs, {len(ap_alerts)} alerts")
        
        print("\n[4/4] 💾 Generating report...")
        report_file = self.logger.generate_report(analyzed_devices, alerts)
        print(f"      ✓ Report saved: {report_file}")
        
        return analyzed_devices, alerts
    
    def monitor_attacks(self, duration=60):
        """Real-time attack monitoring"""
        print(f"\n🎯 Starting real-time attack detection ({duration}s)...")
        interface = self.scanner.interface
        attack_alerts = self.attack_detector.start_monitoring(interface, duration)
        
        for alert in attack_alerts:
            self.logger.log_alert(alert)
        
        return attack_alerts
    
    def display_results(self, devices, alerts):
        """Display scan results"""
        print("\n" + "="*60)
        print("📊 SCAN RESULTS")
        print("="*60)
        
        rogue = [d for d in devices if d['status'] == 'ROGUE']
        suspicious = [d for d in devices if d['status'] == 'SUSPICIOUS']
        trusted = [d for d in devices if d['status'] == 'TRUSTED']
        
        if rogue:
            print(f"\n🚨 ROGUE DEVICES ({len(rogue)}):")
            for d in rogue:
                print(f"  ├─ {d['ip']:15} | {d['mac']} | {d.get('vendor', 'Unknown')}")
                print(f"  │  Risk: {d['risk_score']}/100 | Factors: {', '.join(d['risk_factors'])}")
        
        if suspicious:
            print(f"\n⚠️  SUSPICIOUS DEVICES ({len(suspicious)}):")
            for d in suspicious:
                print(f"  ├─ {d['ip']:15} | {d['mac']} | {d.get('vendor', 'Unknown')}")
        
        print(f"\n✅ TRUSTED DEVICES ({len(trusted)})")
        
        if alerts:
            print(f"\n🔔 ALERTS ({len(alerts)}):")
            for alert in alerts[:5]:
                print(f"  ├─ [{alert['severity']}] {alert['type']}: {alert['message']}")
    
    def view_whitelist(self):
        """View whitelist with better formatting"""
        print("\n📋 WHITELISTED DEVICES:")
        if not self.detector.whitelist:
            print("  No devices in whitelist.")
            return
            
        for i, device in enumerate(self.detector.whitelist, 1):
            print(f"  {i}. {device['mac']} | {device.get('ip', 'N/A')} | {device.get('name', 'Unknown')}")
    
    def add_device_to_whitelist(self):
        """Add device to whitelist with validation"""
        print("\n➕ Add Device to Whitelist")
        mac = input("Enter MAC address: ").strip()
        ip = input("Enter IP address: ").strip()
        name = input("Enter device name: ").strip()
        
        if not mac:
            print("❌ MAC address is required!")
            return
            
        # Basic MAC validation
        import re
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
            print("❌ Invalid MAC address format!")
            return
        
        device = {'mac': mac, 'ip': ip, 'name': name}
        if self.detector.add_to_whitelist(device):
            print(f"✓ Device {mac} added to whitelist")
        else:
            print(f"❌ Device {mac} already exists in whitelist!")
    
    def generate_report_interactive(self):
        """Generate report with interactive options"""
        print("\n📊 Generate Report")
        try:
            # Get last scan results if available
            devices = getattr(self, '_last_devices', [])
            alerts = getattr(self, '_last_alerts', [])
            
            if not devices and not alerts:
                print("⚠️  No scan data available.")
                choice = input("Would you like to run a quick scan first? (y/N): ").strip().lower()
                if choice == 'y':
                    devices, alerts = self.run_full_scan()
                    self._last_devices = devices
                    self._last_alerts = alerts
                else:
                    print("[*] Generating report with no scan data...")
            
            print("[*] Generating security report...")
            report_file = self.logger.generate_report(devices, alerts)
            
            if report_file:
                print(f"✓ Report generated: {report_file}")
                
                # Ask if user wants to open the report
                try:
                    import platform
                    if platform.system().lower() == 'linux':
                        choice = input("Would you like to open the report in browser? (y/N): ").strip().lower()
                        if choice == 'y':
                            import subprocess
                            subprocess.run(['xdg-open', report_file], check=True)
                except:
                    pass
            else:
                print("❌ Failed to generate report")
                
        except Exception as e:
            print(f"❌ Error generating report: {e}")
    
    def edit_device_from_whitelist(self):
        """Edit device in whitelist"""
        if not self.detector.whitelist:
            print("❌ No devices in whitelist!")
            return
            
        print("\n📋 WHITELISTED DEVICES:")
        for i, device in enumerate(self.detector.whitelist, 1):
            print(f"  {i}. {device['mac']} | {device.get('ip', 'N/A')} | {device.get('name', 'Unknown')}")
        
        try:
            choice = int(input("\nSelect device number to edit: ")) - 1
            if 0 <= choice < len(self.detector.whitelist):
                device = self.detector.whitelist[choice]
                print(f"\n✏️  Editing device: {device['mac']}")
                
                new_ip = input(f"Enter new IP address [{device.get('ip', 'N/A')}]: ").strip()
                new_name = input(f"Enter new device name [{device.get('name', 'Unknown')}]: ").strip()
                
                # Update device using new method
                if self.detector.update_whitelist_device(device['mac'], new_ip if new_ip else None, new_name if new_name else None):
                    print(f"✓ Device {device['mac']} updated successfully!")
                else:
                    print(f"❌ Failed to update device {device['mac']}")
            else:
                print("❌ Invalid selection!")
        except ValueError:
            print("❌ Please enter a valid number!")
    
    def remove_device_from_whitelist(self):
        """Remove device from whitelist"""
        if not self.detector.whitelist:
            print("❌ No devices in whitelist!")
            return
            
        print("\n📋 WHITELISTED DEVICES:")
        for i, device in enumerate(self.detector.whitelist, 1):
            print(f"  {i}. {device['mac']} | {device.get('ip', 'N/A')} | {device.get('name', 'Unknown')}")
        
        try:
            choice = int(input("\nSelect device number to remove: ")) - 1
            if 0 <= choice < len(self.detector.whitelist):
                device = self.detector.whitelist[choice]
                confirm = input(f"\n⚠️  Are you sure you want to remove {device['mac']}? (y/N): ").strip().lower()
                
                if confirm == 'y':
                    if self.detector.remove_from_whitelist(device['mac']):
                        print(f"✓ Device {device['mac']} removed from whitelist!")
                    else:
                        print(f"❌ Failed to remove device {device['mac']}")
                else:
                    print("❌ Operation cancelled.")
            else:
                print("❌ Invalid selection!")
        except ValueError:
            print("❌ Please enter a valid number!")
    
    def show_manual_update_info(self):
        """Show manual update instructions"""
        print("\n📥 Manual Update Instructions")
        print("="*50)
        print("To check for updates manually:")
        print("1. Visit: https://github.com/StrykarBoston/RDDS/releases")
        print("2. Download the latest version")
        print("3. Extract the zip file")
        print("4. Replace the current installation")
        print(f"\nCurrent version: 1.0.0")
        print("="*50)
    
    def interactive_menu(self):
        """Interactive CLI menu with back button functionality"""
        while True:
            print("\n" + "="*60)
            print("MAIN MENU")
            print("="*60)
            print("1. Run Full Network Scan")
            print("2. Monitor for Attacks (Real-time)")
            print("3. View Whitelist")
            print("4. Add Device to Whitelist")
            print("5. Edit Device in Whitelist")
            print("6. Remove Device from Whitelist")
            print("7. Generate Report")
            print("8. Manual Update Instructions")
            print("9. Exit")
            
            choice = input("\nSelect option (or 'back' to return): ").strip()
            
            if choice.lower() == 'back':
                print("[*] Returning to main menu...")
                continue
            
            if choice == '1':
                devices, alerts = self.run_full_scan()
                self.display_results(devices, alerts)
                # Store for later report generation
                self._last_devices = devices
                self._last_alerts = alerts
                
            elif choice == '2':
                try:
                    duration = int(input("Monitor duration (seconds): "))
                    self.monitor_attacks(duration)
                except ValueError:
                    print("❌ Please enter a valid number!")
                
            elif choice == '3':
                self.view_whitelist()
                
            elif choice == '4':
                self.add_device_to_whitelist()
                
            elif choice == '5':
                self.edit_device_from_whitelist()
                
            elif choice == '6':
                self.remove_device_from_whitelist()
                
            elif choice == '7':
                self.generate_report_interactive()
                
            elif choice == '8':
                self.show_manual_update_info()
                
            elif choice == '9':
                print("\n👋 Exiting...")
                break
            else:
                print("❌ Invalid option. Please try again.")

# ============================================
# MAIN ENTRY POINT
# ============================================
def main():
    """Main entry point with admin check"""
    
    # STEP 1: Check admin privileges FIRST
    check_admin_privileges()
    
    # STEP 2: Initialize system
    system = RogueDetectionSystem()
    
    # STEP 3: Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--scan':
            devices, alerts = system.run_full_scan()
            system.display_results(devices, alerts)
        elif sys.argv[1] == '--monitor':
            duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
            system.monitor_attacks(duration)
    else:
        # STEP 4: Run interactive menu
        system.interactive_menu()

if __name__ == "__main__":
    main()
