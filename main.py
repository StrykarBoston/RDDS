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
from deep_packet_inspector import DeepPacketInspector
from enhanced_rogue_ap_detector import EnhancedRogueAPDetector
from iot_profiler import IoTProfiler
from dhcp_security import DHCPSecurityMonitor
from network_traffic_analyzer import NetworkTrafficAnalyzer
from ssl_tls_monitor import SSLTLSMonitor
from advanced_attack_detector import AdvancedAttackDetector

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
            
        # Initialize components
        self.detector = RogueDetector()
        self.attack_detector = AttackDetector()
        self.ap_detector = RogueAPDetector()
        self.enhanced_ap_detector = EnhancedRogueAPDetector()
        self.dpi_inspector = DeepPacketInspector()
        self.iot_profiler = IoTProfiler()
        self.dhcp_monitor = DHCPSecurityMonitor()
        self.traffic_analyzer = NetworkTrafficAnalyzer()
        self.ssl_monitor = SSLTLSMonitor()
        self.advanced_detector = AdvancedAttackDetector()
        self.logger = SecurityLogger()
        
        print("""
╔══════════════════════════════════════════════════════════╗
║   🛡️  ROGUE DEVICE DETECTION SYSTEM v2.0                 ║
║   Enterprise Network Security Monitor                    ║
║   Enhanced with Advanced Detection                       ║
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
    
    def run_enhanced_scan(self):
        """Execute enhanced security scan with new detection capabilities"""
        print("\n🚀 Starting Enhanced Security Scan...")
        print("="*60)
        
        # Step 1: Standard Network Discovery
        print("[1/5] 🔍 Discovering network devices...")
        print(f"[*] Using interface: {self.scanner.interface}")
        
        network_range = self.scanner.get_network_range()
        print(f"[*] Scanning network range: {network_range}")
        
        devices = self.scanner.arp_scan(network_range)
        print(f"      ✓ Found {len(devices)} devices")
        
        # Step 2: Traditional Rogue Detection
        print("\n[2/5] 🕵️  Analyzing for rogue devices...")
        analyzed_devices, alerts = self.detector.analyze_network(devices)
        
        rogue_count = sum(1 for d in analyzed_devices if d['status'] == 'ROGUE')
        suspicious_count = sum(1 for d in analyzed_devices if d['status'] == 'SUSPICIOUS')
        
        print(f"      ✓ Rogue: {rogue_count} | Suspicious: {suspicious_count}")
        
        # Step 3: Enhanced Rogue AP Detection
        print("\n[3/5] 📡 Enhanced wireless network analysis...")
        wireless_networks = self.enhanced_ap_detector.scan_wireless_networks_windows()
        enhanced_ap_alerts = self.enhanced_ap_detector.detect_evil_twin(wireless_networks)
        rogue_ap_alerts = self.enhanced_ap_detector.detect_rogue_ap(wireless_networks)
        karma_alerts = self.enhanced_ap_detector.detect_karma_attack(wireless_networks)
        
        alerts.extend(enhanced_ap_alerts)
        alerts.extend(rogue_ap_alerts)
        alerts.extend(karma_alerts)
        
        print(f"      ✓ Found {len(wireless_networks)} APs")
        print(f"      ✓ Evil Twins: {len(enhanced_ap_alerts)} | Rogue APs: {len(rogue_ap_alerts)} | Karma Attacks: {len(karma_alerts)}")
        
        # Step 4: Deep Packet Inspection
        print("\n[4/5] 🔬 Deep Packet Inspection...")
        if devices:
            # Simulate packet capture for DPI analysis
            dpi_results = []
            for device in devices[:20]:  # Limit to first 20 devices for demo
                packet_data = {
                    'size': 1500,
                    'protocol': 'TCP',
                    'src_port': 80,
                    'dst_port': 8080,
                    'flags': 0x18,
                    'src_ip': device['ip'],
                    'dst_ip': '8.8.8.8'
                }
                dpi_analysis = self.dpi_inspector.analyze_packet(packet_data)
                dpi_results.append(dpi_analysis)
            
            high_risk_packets = [r for r in dpi_results if r['risk_score'] > 50]
            print(f"      ✓ Analyzed {len(dpi_results)} packet samples")
            print(f"      ✓ High-risk packets: {len(high_risk_packets)}")
            
            # Add DPI alerts
            for result in high_risk_packets:
                for anomaly in result['anomalies']:
                    alerts.append({
                        'type': 'DPI_ANOMALY',
                        'severity': 'HIGH' if result['risk_score'] > 70 else 'MEDIUM',
                        'message': f"{anomaly['type']}: {anomaly['description']}",
                        'risk_score': result['risk_score']
                    })
        
        # Step 5: Generate Enhanced Report
        print("\n[5/5] 📊 Generating enhanced report...")
        report_file = self.logger.generate_report(analyzed_devices, alerts)
        print(f"      ✓ Enhanced report saved: {report_file}")
        
        return analyzed_devices, alerts, wireless_networks, dpi_results if 'dpi_results' in locals() else []
    
    def run_iot_profiling(self):
        """IoT Device Profiling & Risk Assessment"""
        print("\n🔍 Starting IoT Device Profiling...")
        print("="*50)
        
        # Get network devices
        network_range = self.scanner.get_network_range()
        devices = self.scanner.arp_scan(network_range)
        
        if not devices:
            print("❌ No devices found for IoT profiling")
            return []
        
        print(f"[*] Profiling {len(devices)} devices...")
        
        iot_profiles = []
        for i, device in enumerate(devices):
            print(f"  [{i+1}/{len(devices)}] Profiling {device['ip']}...")
            
            # Simulate device data for profiling
            device_data = {
                'ip': device['ip'],
                'mac': device['mac'],
                'open_ports': [80, 443, 8080],  # Simulated port scan
                'ttl': 64,
                'window_size': 8192,
                'cloud_communication': ['cloud.iot-device.com'],
                'firmware_version': '1.0.0'
            }
            
            # Profile the device
            profile = self.iot_profiler.profile_device(device_data)
            iot_profiles.append(profile)
            
            # Display results
            risk_level = "🔴 HIGH" if profile['risk_score'] >= 70 else "🟡 MEDIUM" if profile['risk_score'] >= 40 else "🟢 LOW"
            print(f"    ✓ {profile['device_type']} - {profile['manufacturer']} - Risk: {profile['risk_score']}% {risk_level}")
        
        # Generate IoT security report
        report = self.iot_profiler.generate_iot_report()
        
        print(f"\n📊 IoT Security Summary:")
        print(f"  Total Devices: {report['total_devices']}")
        print(f"  High Risk: {report['high_risk_devices']}")
        print(f"  Medium Risk: {report['medium_risk_devices']}")
        print(f"  Low Risk: {report['low_risk_devices']}")
        print(f"  Total Vulnerabilities: {report['total_vulnerabilities']}")
        
        return iot_profiles
    
    def run_dhcp_security(self):
        """DHCP Security Monitoring"""
        print("\n🔒 Starting DHCP Security Monitoring...")
        print("="*50)
        
        # Start DHCP monitoring
        interface = self.scanner.interface
        print(f"[*] Starting DHCP monitoring on {interface}...")
        
        if not self.dhcp_monitor.start_monitoring(interface):
            print("❌ Failed to start DHCP monitoring")
            return []
        
        print("✅ DHCP monitoring started")
        print("[*] Monitoring for 60 seconds...")
        
        # Monitor for 60 seconds
        time.sleep(60)
        
        # Get security summary
        summary = self.dhcp_monitor.get_security_summary()
        recent_alerts = self.dhcp_monitor.get_recent_alerts(10)
        
        print(f"\n📊 DHCP Security Summary:")
        print(f"  DHCP Servers: {summary['dhcp_servers']}")
        print(f"  Authorized Servers: {summary['authorized_servers']}")
        print(f"  Active Leases: {summary['active_leases']}")
        print(f"  Recent Requests: {summary['recent_requests']}")
        print(f"  Recent Alerts: {summary['recent_alerts']}")
        print(f"  High Risk Alerts: {summary['high_risk_alerts']}")
        
        if recent_alerts:
            print(f"\n🚨 Recent DHCP Alerts:")
            for alert in recent_alerts[:5]:
                severity_emoji = "🔴" if alert['severity'] == 'HIGH' else "🟡"
                print(f"  {severity_emoji} [{alert['severity']}] {alert['type']}: {alert['message']}")
        
        # Stop monitoring
        self.dhcp_monitor.stop_monitoring()
        print("\n✅ DHCP monitoring stopped")
        
        return recent_alerts
    
    def run_traffic_analysis(self, duration=300):
        """Network Traffic Analysis with NetFlow/sFlow Integration"""
        print("\n📊 Starting Network Traffic Analysis...")
        print("="*60)
        
        # Start traffic monitoring
        interface = self.scanner.interface
        print(f"[*] Starting traffic monitoring on {interface}...")
        print(f"[*] Monitoring duration: {duration} seconds")
        
        # Start monitoring
        report = self.traffic_analyzer.start_monitoring(interface, duration)
        
        if not report:
            print("❌ Traffic monitoring failed")
            return None
        
        # Display results
        print(f"\n📈 Traffic Analysis Results:")
        print(f"  Total Flows: {report['total_flows']}")
        print(f"  Total Bandwidth: {report['total_bandwidth'] / (1024*1024):.2f} MB")
        print(f"  Suspicious IPs: {len(report['suspicious_ips'])}")
        
        # Bandwidth usage
        print(f"\n📊 Bandwidth Usage (Top 10):")
        usage = report['bandwidth_usage']
        sorted_usage = sorted(usage.items(), key=lambda x: x[1], reverse=True)
        
        for i, (ip, percent) in enumerate(sorted_usage[:10]):
            print(f"  {i+1:2d}. {ip:15} | {percent:5.1f}%")
        
        # Top applications
        print(f"\n🔧 Top Applications:")
        for i, (app, count) in enumerate(report['top_applications'][:10]):
            print(f"  {i+1:2d}. {app:15} | {count:6d} connections")
        
        # Data exfiltration suspects
        if report['data_exfiltration_suspects']:
            print(f"\n🚨 Data Exfiltration Suspects:")
            for suspect in report['data_exfiltration_suspects'][:5]:
                print(f"  🔴 {suspect['src_ip']} -> {suspect['dst_ip']}")
                print(f"     Bytes: {suspect['bytes_transferred'] / (1024*1024):.2f} MB | Risk: {suspect['risk_level']}")
        
        # DDoS attacks
        if report['ddos_attacks']:
            print(f"\n💥 DDoS Attacks Detected:")
            for attack in report['ddos_attacks'][:5]:
                print(f"  🔴 Target: {attack['target_ip']}")
                print(f"     Rate: {attack['packets_per_second']} packets/sec | Severity: {attack['severity']}")
        
        # Connection summary
        print(f"\n🔗 Connection Summary (Top 10):")
        connections = report['connection_summary']
        sorted_connections = sorted(connections.items(), 
                              key=lambda x: len(x[1]), reverse=True)
        
        for i, (src_ip, dsts) in enumerate(sorted_connections[:10]):
            print(f"  {i+1:2d}. {src_ip:15} -> {len(dsts)} destinations")
        
        return report
    
    def run_ssl_certificate_monitoring(self, hosts, duration=300):
        """SSL/TLS Certificate Monitoring"""
        print("\n🔒 Starting SSL/TLS Certificate Monitoring...")
        print("="*60)
        
        print(f"[*] Monitoring {len(hosts)} hosts for {duration} seconds...")
        
        # Start certificate monitoring
        report = self.ssl_monitor.start_monitoring(hosts, duration)
        
        if not report:
            print("❌ Certificate monitoring failed")
            return None
        
        # Display results
        print(f"\n🔐 Certificate Analysis Results:")
        print(f"  Total Hosts: {report['total_hosts']}")
        print(f"  High Risk: {report['high_risk_certificates']}")
        print(f"  Medium Risk: {report['medium_risk_certificates']}")
        print(f"  Low Risk: {report['low_risk_certificates']}")
        print(f"  Total Alerts: {len(report['certificate_alerts'])}")
        
        # Show certificate alerts
        if report['certificate_alerts']:
            print(f"\n🚨 Certificate Security Alerts:")
            for alert in report['certificate_alerts'][:10]:
                severity_emoji = "🔴" if alert['severity'] == 'HIGH' else "🟡"
                print(f"  {severity_emoji} [{alert['severity']}] {alert['type']}: {alert['message']}")
                print(f"     Host: {alert['host']}:{alert['port']}")
                print(f"     Details: {alert['description']}")
        
        return report
    
    def run_advanced_attack_detection(self, duration=60):
        """Advanced Attack Detection Beyond ARP Spoofing"""
        print("\n⚔️ Starting Advanced Attack Detection...")
        print("="*60)
        
        interface = self.scanner.interface
        print(f"[*] Starting advanced attack detection on {interface}...")
        print(f"[*] Monitoring duration: {duration} seconds")
        
        # Start advanced attack detection
        report = self.advanced_detector.start_monitoring(interface, duration)
        
        if not report:
            print("❌ Advanced attack detection failed")
            return None
        
        # Display results
        print(f"\n⚔️ Advanced Attack Detection Results:")
        print(f"  Total Attacks: {report['total_attacks']}")
        print(f"  High Severity: {report['high_severity']}")
        print(f"  Medium Severity: {report['medium_severity']}")
        print(f"  Low Severity: {report['low_severity']}")
        
        # Show attack types
        if report['attack_types']:
            print(f"\n🎯 Attack Types Detected:")
            for attack_type, count in report['attack_types'].items():
                details = self.advanced_detector._get_attack_details(attack_type)
                print(f"  {count:3d}x {details['name']}")
                print(f"     {details['description']}")
        
        # Show mitigation recommendations
        if report['mitigation_recommendations']:
            print(f"\n🛡️ Mitigation Recommendations:")
            for rec in report['mitigation_recommendations']:
                priority_emoji = "🔴" if rec['priority'] == 'HIGH' else "🟡"
                print(f"  {priority_emoji} {rec['attack']}: {rec['recommendation']}")
        
        return report
    
    def monitor_attacks(self, duration=60):
        """Real-time attack monitoring"""
        print(f"\n🎯 Starting real-time attack detection ({duration}s)...")
        interface = self.scanner.interface
        attack_alerts = self.attack_detector.start_monitoring(interface, duration)
        
        for alert in attack_alerts:
            self.logger.log_alert(alert)
        
        return attack_alerts
    
    def display_enhanced_results(self, devices, alerts, wireless_networks, dpi_results):
        """Display enhanced scan results"""
        print("\n" + "="*60)
        print("📊 ENHANCED SCAN RESULTS")
        print("="*60)
        
        # Device Analysis
        rogue = [d for d in devices if d['status'] == 'ROGUE']
        suspicious = [d for d in devices if d['status'] == 'SUSPICIOUS']
        trusted = [d for d in devices if d['status'] == 'TRUSTED']
        
        print(f"\n🖥️  DEVICE ANALYSIS:")
        print(f"  Total Devices: {len(devices)}")
        print(f"  Rogue: {len(rogue)} | Suspicious: {len(suspicious)} | Trusted: {len(trusted)}")
        
        # Wireless Analysis
        if wireless_networks:
            print(f"\n📡 WIRELESS ANALYSIS:")
            print(f"  Total APs: {len(wireless_networks)}")
            
            # Count by type
            evil_twins = [a for a in alerts if a['type'] == 'EVIL_TWIN_AP']
            rogue_aps = [a for a in alerts if a['type'] == 'ROGUE_AP']
            karma_attacks = [a for a in alerts if a['type'] == 'KARMA_ATTACK']
            
            print(f"  Evil Twins: {len(evil_twins)} | Rogue APs: {len(rogue_aps)} | Karma Attacks: {len(karma_attacks)}")
        
        # DPI Analysis
        if dpi_results:
            high_risk_packets = [r for r in dpi_results if r['risk_score'] > 50]
            print(f"\n🔬 DEEP PACKET INSPECTION:")
            print(f"  Packets Analyzed: {len(dpi_results)}")
            print(f"  High-Risk Packets: {len(high_risk_packets)}")
            
            if high_risk_packets:
                avg_risk = sum(r['risk_score'] for r in high_risk_packets) / len(high_risk_packets)
                print(f"  Average Risk Score: {avg_risk:.1f}%")
        
        # Alert Summary
        alert_types = {}
        for alert in alerts:
            alert_type = alert['type']
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
        
        if alert_types:
            print(f"\n🔔 ALERT SUMMARY:")
            for alert_type, count in sorted(alert_types.items()):
                print(f"  {alert_type}: {count}")
        
        # Top Risk Items
        print(f"\n⚠️  TOP RISK ITEMS:")
        all_risks = []
        
        # Add device risks
        for device in rogue + suspicious:
            all_risks.append({
                'type': 'Device',
                'name': f"{device['ip']} ({device['mac'][:8]}...)",
                'risk': device.get('risk_score', 50),
                'details': device.get('risk_factors', [])
            })
        
        # Add alert risks
        for alert in alerts:
            if alert.get('severity') in ['HIGH', 'CRITICAL']:
                all_risks.append({
                    'type': alert['type'],
                    'name': alert.get('message', 'Unknown')[:50] + '...',
                    'risk': alert.get('risk_score', 75),
                    'details': []
                })
        
        # Sort by risk and show top 5
        all_risks.sort(key=lambda x: x['risk'], reverse=True)
        for i, risk in enumerate(all_risks[:5]):
            print(f"  {i+1}. [{risk['type']}] {risk['name']} (Risk: {risk['risk']}%)")
        
        if not all_risks:
            print("  No high-risk items detected. ✅")
    
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
        print(f"\nCurrent version: 2.0.0 (No ML)")
        print("="*50)
    
    def interactive_menu(self):
        """Interactive CLI menu with back button functionality"""
        while True:
            print("\n" + "="*60)
            print("MAIN MENU")
            print("="*60)
            print("1. Run Full Network Scan (Standard)")
            print("2. Run Enhanced Security Scan (NEW)")
            print("3. IoT Device Profiling & Risk Assessment")
            print("4. DHCP Security Monitoring")
            print("5. Network Traffic Analysis (NetFlow/sFlow)")
            print("6. SSL/TLS Certificate Monitoring")
            print("7. Advanced Attack Detection")
            print("8. Monitor for Attacks (Real-time)")
            print("9. View Whitelist")
            print("10. Add Device to Whitelist")
            print("11. Edit Device in Whitelist")
            print("12. Remove Device from Whitelist")
            print("13. Generate Report")
            print("14. Manual Update Instructions")
            print("15. Exit")
            
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
                devices, alerts, wireless_networks, dpi_results = self.run_enhanced_scan()
                self.display_enhanced_results(devices, alerts, wireless_networks, dpi_results)
                # Store for later report generation
                self._last_devices = devices
                self._last_alerts = alerts
                self._last_wireless_networks = wireless_networks
                self._last_dpi_results = dpi_results
                
            elif choice == '3':
                self.run_iot_profiling()
                
            elif choice == '4':
                self.run_dhcp_security()
                
            elif choice == '5':
                try:
                    duration = int(input("Traffic analysis duration (seconds, default=300): ") or "300")
                    self.run_traffic_analysis(duration)
                except ValueError:
                    print("❌ Please enter a valid number!")
                    
            elif choice == '6':
                hosts_input = input("Enter hosts to monitor (comma-separated): ").strip()
                if hosts_input:
                    hosts = [h.strip() for h in hosts_input.split(',')]
                    try:
                        duration = int(input("Monitoring duration (seconds, default=300): ") or "300")
                        self.run_ssl_certificate_monitoring(hosts, duration)
                    except ValueError:
                        print("❌ Please enter a valid number!")
                else:
                    print("❌ No hosts specified!")
                    
            elif choice == '7':
                try:
                    duration = int(input("Advanced attack detection duration (seconds, default=60): ") or "60")
                    self.run_advanced_attack_detection(duration)
                except ValueError:
                    print("❌ Please enter a valid number!")
                    
            elif choice == '8':
                try:
                    duration = int(input("Monitor duration (seconds): "))
                    self.monitor_attacks(duration)
                except ValueError:
                    print("❌ Please enter a valid number!")
                    
            elif choice == '9':
                self.view_whitelist()
                
            elif choice == '10':
                self.add_device_to_whitelist()
                
            elif choice == '11':
                self.edit_device_from_whitelist()
                
            elif choice == '12':
                self.remove_device_from_whitelist()
                
            elif choice == '13':
                self.generate_report_interactive()
                
            elif choice == '14':
                self.show_manual_update_info()
                
            elif choice == '15':
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
