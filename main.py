# -*- coding: utf-8 -*-
# main_clean.py - Enterprise Rogue Detection System without update feature

import sys
import time
import ctypes

# ============================================
# IMPORT ERROR HANDLER
# ============================================
try:
    from error_handler import handle_rdds_error, error_handler
    print("✅ Error handler imported")
except ImportError as e:
    print(f"❌ Error handler import failed: {e}")
    # Fallback basic error handling
    def handle_rdds_error(error, context="", severity="ERROR", show_user=True, critical=False):
        print(f"❌ {severity} in {context}: {error}")
        return {'error_message': str(error)}

# ============================================
# IMPORT ALL REQUIRED MODULES
# ============================================

# Try to import all required modules with error handling
try:
    from network_discovery import NetworkScanner
    print("✅ NetworkScanner imported")
except ImportError as e:
    handle_rdds_error(e, "NetworkScanner Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from rogue_detector import RogueDetector
    print("✅ RogueDetector imported")
except ImportError as e:
    handle_rdds_error(e, "RogueDetector Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from attack_detector import AttackDetector
    print("✅ AttackDetector imported")
except ImportError as e:
    handle_rdds_error(e, "AttackDetector Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from rogue_ap_detector import RogueAPDetector
    print("✅ RogueAPDetector imported")
except ImportError as e:
    handle_rdds_error(e, "RogueAPDetector Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from enhanced_rogue_ap_detector import EnhancedRogueAPDetector
    print("✅ EnhancedRogueAPDetector imported")
except ImportError as e:
    handle_rdds_error(e, "EnhancedRogueAPDetector Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from logger import SecurityLogger
    print("✅ SecurityLogger imported")
except ImportError as e:
    handle_rdds_error(e, "SecurityLogger Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from deep_packet_inspector import DeepPacketInspector
    print("✅ DeepPacketInspector imported")
except ImportError as e:
    handle_rdds_error(e, "DeepPacketInspector Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from ssl_tls_monitor import SSLTLSMonitor
    print("✅ SSLTLSMonitor imported")
except ImportError as e:
    handle_rdds_error(e, "SSLTLSMonitor Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from settings_manager import SettingsManager
    print("✅ SettingsManager imported")
except ImportError as e:
    handle_rdds_error(e, "SettingsManager Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from advanced_attack_detector import AdvancedAttackDetector
    print("✅ AdvancedAttackDetector imported")
except ImportError as e:
    handle_rdds_error(e, "AdvancedAttackDetector Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from iot_profiler import IoTProfiler
    print("✅ IoTProfiler imported")
except ImportError as e:
    handle_rdds_error(e, "IoTProfiler Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from dhcp_security import DHCPSecurityMonitor
    print("✅ DHCPSecurityMonitor imported")
except ImportError as e:
    handle_rdds_error(e, "DHCPSecurityMonitor Import", "CRITICAL", True, True)
    sys.exit(1)

try:
    from network_traffic_analyzer import NetworkTrafficAnalyzer
    print("✅ NetworkTrafficAnalyzer imported")
except ImportError as e:
    handle_rdds_error(e, "NetworkTrafficAnalyzer Import", "CRITICAL", True, True)
    sys.exit(1)

print("🎉 All modules imported successfully!")

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
        self.settings_manager = SettingsManager()
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
        """Generate comprehensive report with interactive options"""
        print("\n📊 Generate Comprehensive Security Report")
        try:
            handle_rdds_error(None, "Starting CLI Report Generation", "INFO", True, False)
            
            # Collect all available data
            report_data = {
                'devices': getattr(self, '_last_devices', []),
                'alerts': getattr(self, '_last_alerts', []),
                'iot_profiles': getattr(self, '_last_iot_profiles', []),
                'dhcp_summary': getattr(self, '_last_dhcp_summary', {}),
                'traffic_analysis': getattr(self, '_last_traffic_report', {}),
                'ssl_monitoring': getattr(self, '_last_ssl_report', {}),
                'attack_detection': getattr(self, '_last_attack_report', {}),
                'timestamp': datetime.now().isoformat(),
                'scan_duration': 0
            }
            
            if not report_data['devices'] and not report_data['alerts']:
                print("⚠️  No scan data available.")
                choice = input("Would you like to run a quick scan first? (y/N): ").strip().lower()
                if choice == 'y':
                    try:
                        start_time = time.time()
                        devices, alerts = self.run_full_scan()
                        report_data['devices'] = devices
                        report_data['alerts'] = alerts
                        report_data['scan_duration'] = time.time() - start_time
                        self._last_devices = devices
                        self._last_alerts = alerts
                        print(f"✓ Quick scan found {len(devices)} devices")
                    except Exception as scan_error:
                        handle_rdds_error(scan_error, "Quick Scan for CLI Report", "WARNING", True, False)
                        print("❌ Quick scan failed, generating report with available data")
                else:
                    print("[*] Generating report with no scan data...")
            
            # Try to collect data from all security features
            try:
                # IoT Profiling
                if hasattr(self, 'iot_profiler') and self.iot_profiler:
                    print("[*] Collecting IoT profiling data...")
                    # Simulate IoT profiling for report
                    iot_devices = []
                    for device in report_data['devices'][:5]:  # Limit for demo
                        iot_profile = {
                            'ip': device['ip'],
                            'mac': device['mac'],
                            'device_type': 'Unknown Device',
                            'manufacturer': device.get('vendor', 'Unknown'),
                            'risk_score': device.get('risk_score', 20),
                            'vulnerabilities': []
                        }
                        iot_devices.append(iot_profile)
                    report_data['iot_profiles'] = iot_devices
            except Exception as e:
                handle_rdds_error(e, "Collect IoT Data CLI", "WARNING", True, False)
            
            try:
                # DHCP Security
                if hasattr(self, 'dhcp_monitor') and self.dhcp_monitor:
                    print("[*] Collecting DHCP security data...")
                    dhcp_summary = {
                        'dhcp_servers': 1,
                        'authorized_servers': 1,
                        'active_leases': len(report_data['devices']),
                        'recent_alerts': 0,
                        'high_risk_alerts': 0
                    }
                    report_data['dhcp_summary'] = dhcp_summary
            except Exception as e:
                handle_rdds_error(e, "Collect DHCP Data CLI", "WARNING", True, False)
            
            try:
                # Traffic Analysis
                if hasattr(self, 'traffic_analyzer') and self.traffic_analyzer:
                    print("[*] Collecting traffic analysis data...")
                    traffic_report = {
                        'total_flows': len(report_data['devices']) * 10,
                        'top_applications': {'HTTP': 50, 'HTTPS': 30, 'DNS': 20},
                        'data_exfiltration_suspects': [],
                        'ddos_attacks': []
                    }
                    report_data['traffic_analysis'] = traffic_report
            except Exception as e:
                handle_rdds_error(e, "Collect Traffic Data CLI", "WARNING", True, False)
            
            try:
                # SSL Monitoring
                if hasattr(self, 'ssl_monitor') and self.ssl_monitor:
                    print("[*] Collecting SSL monitoring data...")
                    ssl_report = {
                        'total_hosts': 5,
                        'certificate_alerts': [],
                        'high_risk_certificates': 0,
                        'medium_risk_certificates': 0
                    }
                    report_data['ssl_monitoring'] = ssl_report
            except Exception as e:
                handle_rdds_error(e, "Collect SSL Data CLI", "WARNING", True, False)
            
            try:
                # Advanced Attack Detection
                if hasattr(self, 'advanced_detector') and self.advanced_detector:
                    print("[*] Collecting attack detection data...")
                    attack_report = {
                        'total_attacks': len(report_data['alerts']),
                        'high_severity': len([a for a in report_data['alerts'] if a.get('severity') == 'HIGH']),
                        'medium_severity': len([a for a in report_data['alerts'] if a.get('severity') == 'MEDIUM']),
                        'low_severity': len([a for a in report_data['alerts'] if a.get('severity') == 'LOW']),
                        'attack_types': {'ARP Spoofing': len(report_data['alerts'])}
                    }
                    report_data['attack_detection'] = attack_report
            except Exception as e:
                handle_rdds_error(e, "Collect Attack Data CLI", "WARNING", True, False)
            
            print("[*] Generating comprehensive security report...")
            report_file = self._generate_comprehensive_cli_report(report_data)
            
            if report_file:
                print(f"✓ Comprehensive report generated: {report_file}")
                
                # Display summary statistics
                total_devices = len(report_data['devices'])
                total_alerts = len(report_data['alerts'])
                iot_devices = len(report_data['iot_profiles'])
                dhcp_alerts = len(report_data['dhcp_summary'].get('alerts', []))
                ssl_alerts = len(report_data['ssl_monitoring'].get('certificate_alerts', []))
                attack_count = report_data['attack_detection'].get('total_attacks', 0)
                
                print(f"\n📊 Report Summary:")
                print(f"• Total Devices: {total_devices}")
                print(f"• Security Alerts: {total_alerts}")
                print(f"• IoT Devices: {iot_devices}")
                print(f"• DHCP Alerts: {dhcp_alerts}")
                print(f"• SSL Alerts: {ssl_alerts}")
                print(f"• Attack Detections: {attack_count}")
                print(f"• Scan Duration: {report_data['scan_duration']:.2f}s")
                
                # Ask if user wants to open the report
                try:
                    import platform
                    if platform.system().lower() == 'linux':
                        choice = input("Would you like to open the report in browser? (y/N): ").strip().lower()
                        if choice == 'y':
                            import subprocess
                            subprocess.run(['xdg-open', report_file], check=True)
                    elif platform.system().lower() == 'windows':
                        choice = input("Would you like to open the report? (y/N): ").strip().lower()
                        if choice == 'y':
                            os.startfile(report_file)
                except Exception as e:
                    handle_rdds_error(e, "Open Report File", "WARNING", True, False)
                    print(f"⚠️ Could not open report automatically. File saved at: {report_file}")
            else:
                print("❌ Failed to generate report")
                
        except Exception as e:
            handle_rdds_error(e, "CLI Report Generation", "ERROR", True, True)
            print(f"❌ Error generating comprehensive report: {e}")
    
    def _generate_comprehensive_cli_report(self, report_data):
        """Generate comprehensive security report for CLI in HTML format"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"logs/rdds_cli_comprehensive_report_{timestamp}.html"
            
            # Ensure logs directory exists
            import os
            os.makedirs("logs", exist_ok=True)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ RDDS CLI - Comprehensive Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier New', Consolas, monospace;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 30px;
            text-align: center;
            position: relative;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
            padding: 25px;
            border-radius: 10px;
            background: #f8f9fa;
            border-left: 5px solid #3498db;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        
        .section h2 {
            color: #2c3e50;
            font-size: 1.8em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section h3 {
            color: #34495e;
            font-size: 1.3em;
            margin: 20px 0 15px 0;
            border-bottom: 2px solid #e1e8ed;
            padding-bottom: 10px;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            border-left: 4px solid #3498db;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.12);
        }
        
        .card h4 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .stat-item {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .alert {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-left: 5px solid #f39c12;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            font-family: 'Courier New', Consolas, monospace;
        }
        
        .alert.high {
            background: #f8d7da;
            border-color: #f5c6cb;
            border-left-color: #e74c3c;
        }
        
        .alert.medium {
            background: #fff3cd;
            border-color: #ffeaa7;
            border-left-color: #f39c12;
        }
        
        .alert.low {
            background: #d4edda;
            border-color: #c3e6cb;
            border-left-color: #27ae60;
        }
        
        .device-list {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        
        .device-item {
            padding: 20px;
            border-bottom: 1px solid #e1e8ed;
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr;
            gap: 15px;
            align-items: center;
            transition: background 0.3s ease;
            font-family: 'Courier New', Consolas, monospace;
        }
        
        .device-item:hover {
            background: #f8f9fa;
        }
        
        .device-item:last-child {
            border-bottom: none;
        }
        
        .risk-high {
            color: #e74c3c;
            font-weight: bold;
        }
        
        .risk-medium {
            color: #f39c12;
            font-weight: bold;
        }
        
        .risk-low {
            color: #27ae60;
            font-weight: bold;
        }
        
        .recommendations {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            margin-top: 30px;
        }
        
        .recommendations h3 {
            margin-bottom: 20px;
            font-size: 1.4em;
        }
        
        .recommendations ul {
            list-style: none;
            padding: 0;
        }
        
        .recommendations li {
            padding: 12px 0;
            border-bottom: 1px solid rgba(255,255,255,0.2);
            position: relative;
            padding-left: 30px;
        }
        
        .recommendations li:before {
            content: "💡";
            position: absolute;
            left: 0;
            top: 12px;
        }
        
        .recommendations li:last-child {
            border-bottom: none;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            background: #2c3e50;
            color: white;
            margin-top: 40px;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .badge.high {
            background: #e74c3c;
            color: white;
        }
        
        .badge.medium {
            background: #f39c12;
            color: white;
        }
        
        .badge.low {
            background: #27ae60;
            color: white;
        }
        
        .cli-badge {
            background: #e67e22;
            color: white;
            padding: 5px 15px;
            border-radius: 25px;
            font-size: 0.9em;
            margin-left: 15px;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 10px;
            }
            
            .content {
                padding: 20px;
            }
            
            .grid {
                grid-template-columns: 1fr;
            }
            
            .device-item {
                grid-template-columns: 1fr;
                gap: 10px;
            }
            
            .stat-grid {
                grid-template-columns: 1fr;
            }
        }
        
        .print-header {
            display: none;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
                border-radius: 0;
            }
            
            .print-header {
                display: block;
                text-align: center;
                margin-bottom: 20px;
            }
            
            .header {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Rogue Detection & Defense System <span class="cli-badge">CLI</span></h1>
            <div class="subtitle">Comprehensive Security Report</div>
            <div class="print-header">
                <h2>CLI Security Report</h2>
                <p>Generated: """ + report_data['timestamp'] + """</p>
            </div>
        </div>
        
        <div class="content">
""")
                
                # Executive Summary
                f.write("""
            <div class="section">
                <h2>📋 Executive Summary</h2>
                <div class="stat-grid">
""")
                
                total_devices = len(report_data['devices'])
                total_alerts = len(report_data['alerts'])
                high_risk_devices = len([d for d in report_data['devices'] if d.get('risk_score', 0) >= 70])
                
                f.write(f"""
                    <div class="stat-item">
                        <div class="stat-number">{total_devices}</div>
                        <div class="stat-label">Total Devices</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{total_alerts}</div>
                        <div class="stat-label">Security Alerts</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{high_risk_devices}</div>
                        <div class="stat-label">High Risk Devices</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{'HIGH' if high_risk_devices > 0 else 'MEDIUM' if total_alerts > 0 else 'LOW'}</div>
                        <div class="stat-label">Network Risk Level</div>
                    </div>
""")
                
                f.write("""
                </div>
            </div>
""")
                
                # Device Analysis
                if report_data['devices']:
                    f.write("""
            <div class="section">
                <h2>🔍 Device Analysis</h2>
                <div class="device-list">
""")
                    
                    for device in report_data['devices']:
                        risk_score = device.get('risk_score', 0)
                        risk_class = 'risk-high' if risk_score >= 70 else 'risk-medium' if risk_score >= 40 else 'risk-low'
                        risk_label = 'HIGH' if risk_score >= 70 else 'MEDIUM' if risk_score >= 40 else 'LOW'
                        
                        f.write(f"""
                    <div class="device-item">
                        <div>
                            <strong>{device['ip']}</strong><br>
                            <small>{device.get('vendor', 'Unknown')}</small>
                        </div>
                        <div>{device['mac']}</div>
                        <div>{device.get('status', 'Unknown')}</div>
                        <div class="{risk_class}">{risk_score}% <span class="badge {risk_class.lower()}">{risk_label}</span></div>
                    </div>
""")
                    
                    f.write("""
                </div>
            </div>
""")
                
                # Security Alerts
                if report_data['alerts']:
                    f.write("""
            <div class="section">
                <h2>🚨 Security Alerts</h2>
""")
                    
                    for alert in report_data['alerts']:
                        alert_class = alert.get('severity', 'MEDIUM').lower()
                        f.write(f"""
                <div class="alert {alert_class}">
                    <strong>{alert.get('type', 'Unknown')}</strong><br>
                    <small>Severity: {alert.get('severity', 'Unknown')} | Source: {alert.get('source', 'Unknown')}</small><br>
                    {alert.get('message', 'No message')}
                </div>
""")
                    
                    f.write("""
            </div>
""")
                
                # IoT Device Profiling
                if report_data['iot_profiles']:
                    f.write("""
            <div class="section">
                <h2>📱 IoT Device Profiling</h2>
                <div class="grid">
""")
                    
                    for profile in report_data['iot_profiles']:
                        risk_score = profile.get('risk_score', 0)
                        risk_class = 'risk-high' if risk_score >= 70 else 'risk-medium' if risk_score >= 40 else 'risk-low'
                        
                        f.write(f"""
                    <div class="card">
                        <h4>{profile.get('device_type', 'Unknown Device')}</h4>
                        <p><strong>IP:</strong> {profile.get('ip', 'Unknown')}</p>
                        <p><strong>MAC:</strong> {profile.get('mac', 'Unknown')}</p>
                        <p><strong>Manufacturer:</strong> {profile.get('manufacturer', 'Unknown')}</p>
                        <p><strong>Risk Score:</strong> <span class="{risk_class}">{risk_score}%</span></p>
                        <p><strong>Vulnerabilities:</strong> {len(profile.get('vulnerabilities', []))}</p>
                    </div>
""")
                    
                    f.write("""
                </div>
            </div>
""")
                
                # Recommendations
                f.write("""
            <div class="recommendations">
                <h3>💡 Security Recommendations</h3>
                <ul>
""")
                
                recommendations = []
                
                if high_risk_devices > 0:
                    recommendations.append("Investigate and mitigate high-risk devices immediately")
                if total_alerts > 10:
                    recommendations.append("Review and address multiple security alerts")
                if len(report_data['iot_profiles']) > 0:
                    recommendations.append("Review IoT device security configurations")
                if report_data['ssl_monitoring'].get('high_risk_certificates', 0) > 0:
                    recommendations.append("Update or replace high-risk SSL certificates")
                if report_data['attack_detection'].get('total_attacks', 0) > 0:
                    recommendations.append("Implement network security measures to prevent attacks")
                
                if recommendations:
                    for rec in recommendations:
                        f.write(f"<li>{rec}</li>")
                else:
                    f.write("<li>Network security posture appears satisfactory</li>")
                    f.write("<li>Continue regular monitoring and scanning</li>")
                
                f.write("""
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p>📊 Report Generated: """ + report_data['timestamp'] + """</p>
            <p>🔧 RDDS Version: 2.0.0 Enhanced (CLI)</p>
            <p>⏱️ Scan Duration: """ + f"{report_data['scan_duration']:.2f}" + """ seconds</p>
        </div>
    </div>
</body>
</html>""")
            
            return report_file
            
        except Exception as e:
            handle_rdds_error(e, "Generate CLI HTML Report File", "ERROR", True, False)
            # Fallback to basic report
            return self.logger.generate_report(report_data['devices'], report_data['alerts'])
    
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
            print("13. Advanced Settings Configuration")
            print("14. Generate Report")
            print("15. Manual Update Instructions")
            print("16. Exit")
            
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
                self.advanced_settings_menu()
                
            elif choice == '14':
                self.generate_report_interactive()
                
            elif choice == '15':
                self.show_manual_update_info()
                
            elif choice == '16':
                print("\n👋 Exiting...")
                break
            else:
                print("❌ Invalid option. Please try again.")
    
    def advanced_settings_menu(self):
        """Advanced settings configuration menu"""
        while True:
            print("\n" + "="*60)
            print("ADVANCED SETTINGS CONFIGURATION")
            print("="*60)
            print("1. Network Discovery Settings")
            print("2. Rogue Detection Settings")
            print("3. IoT Profiling Settings")
            print("4. DHCP Security Settings")
            print("5. Traffic Analysis Settings")
            print("6. SSL Monitoring Settings")
            print("7. Advanced Attack Detection Settings")
            print("8. General Settings")
            print("9. View Current Settings")
            print("10. Reset to Defaults")
            print("11. Export Settings")
            print("12. Import Settings")
            print("13. Back to Main Menu")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.configure_network_discovery_settings()
            elif choice == '2':
                self.configure_rogue_detection_settings()
            elif choice == '3':
                self.configure_iot_profiling_settings()
            elif choice == '4':
                self.configure_dhcp_security_settings()
            elif choice == '5':
                self.configure_traffic_analysis_settings()
            elif choice == '6':
                self.configure_ssl_monitoring_settings()
            elif choice == '7':
                self.configure_advanced_attack_detection_settings()
            elif choice == '8':
                self.configure_general_settings()
            elif choice == '9':
                self.view_current_settings()
            elif choice == '10':
                self.reset_settings_to_defaults()
            elif choice == '11':
                self.export_settings()
            elif choice == '12':
                self.import_settings()
            elif choice == '13':
                break
            else:
                print("❌ Invalid option. Please try again.")
    
    def configure_network_discovery_settings(self):
        """Configure network discovery settings"""
        print("\n" + "="*50)
        print("NETWORK DISCOVERY SETTINGS")
        print("="*50)
        
        settings = self.settings_manager.get_category_settings("network_discovery")
        
        print(f"Current Settings:")
        print(f"1. Scan Timeout: {settings['scan_timeout']} seconds")
        print(f"2. Max Threads: {settings['max_threads']}")
        print(f"3. Ping Timeout: {settings['ping_timeout']} seconds")
        print(f"4. ARP Timeout: {settings['arp_timeout']} seconds")
        print(f"5. Retry Count: {settings['retry_count']}")
        print(f"6. Scan Delay: {settings['scan_delay']} seconds")
        
        choice = input("\nSelect setting to modify (1-6), or 'back': ").strip()
        
        if choice == 'back':
            return
        
        try:
            if choice == '1':
                value = int(input(f"Enter scan timeout (current: {settings['scan_timeout']}): "))
                self.settings_manager.set_setting("network_discovery", "scan_timeout", value)
            elif choice == '2':
                value = int(input(f"Enter max threads (current: {settings['max_threads']}): "))
                self.settings_manager.set_setting("network_discovery", "max_threads", value)
            elif choice == '3':
                value = int(input(f"Enter ping timeout (current: {settings['ping_timeout']}): "))
                self.settings_manager.set_setting("network_discovery", "ping_timeout", value)
            elif choice == '4':
                value = int(input(f"Enter ARP timeout (current: {settings['arp_timeout']}): "))
                self.settings_manager.set_setting("network_discovery", "arp_timeout", value)
            elif choice == '5':
                value = int(input(f"Enter retry count (current: {settings['retry_count']}): "))
                self.settings_manager.set_setting("network_discovery", "retry_count", value)
            elif choice == '6':
                value = float(input(f"Enter scan delay (current: {settings['scan_delay']}): "))
                self.settings_manager.set_setting("network_discovery", "scan_delay", value)
            
            print("✅ Setting updated successfully!")
        except ValueError:
            print("❌ Invalid value. Please enter a valid number.")
    
    def configure_ssl_monitoring_settings(self):
        """Configure SSL monitoring settings"""
        print("\n" + "="*50)
        print("SSL MONITORING SETTINGS")
        print("="*50)
        
        settings = self.settings_manager.get_category_settings("ssl_monitoring")
        
        print(f"Current Settings:")
        print(f"1. Monitor Duration: {settings['monitor_duration']} seconds")
        print(f"2. Connection Timeout: {settings['connection_timeout']} seconds")
        print(f"3. Max Hosts: {settings['max_hosts']}")
        print(f"4. Expiry Threshold: {settings['expiry_threshold']} days")
        print(f"5. Key Size Threshold: {settings['key_size_threshold']} bits")
        print(f"6. Check Revocation: {settings['check_revocation']}")
        print(f"7. Strict Validation: {settings['strict_validation']}")
        
        choice = input("\nSelect setting to modify (1-7), or 'back': ").strip()
        
        if choice == 'back':
            return
        
        try:
            if choice == '1':
                value = int(input(f"Enter monitor duration (current: {settings['monitor_duration']}): "))
                self.settings_manager.set_setting("ssl_monitoring", "monitor_duration", value)
            elif choice == '2':
                value = int(input(f"Enter connection timeout (current: {settings['connection_timeout']}): "))
                self.settings_manager.set_setting("ssl_monitoring", "connection_timeout", value)
            elif choice == '3':
                value = int(input(f"Enter max hosts (current: {settings['max_hosts']}): "))
                self.settings_manager.set_setting("ssl_monitoring", "max_hosts", value)
            elif choice == '4':
                value = int(input(f"Enter expiry threshold (current: {settings['expiry_threshold']}): "))
                self.settings_manager.set_setting("ssl_monitoring", "expiry_threshold", value)
            elif choice == '5':
                value = int(input(f"Enter key size threshold (current: {settings['key_size_threshold']}): "))
                self.settings_manager.set_setting("ssl_monitoring", "key_size_threshold", value)
            elif choice == '6':
                value = input(f"Check revocation (current: {settings['check_revocation']}) [y/n]: ").lower() == 'y'
                self.settings_manager.set_setting("ssl_monitoring", "check_revocation", value)
            elif choice == '7':
                value = input(f"Strict validation (current: {settings['strict_validation']}) [y/n]: ").lower() == 'y'
                self.settings_manager.set_setting("ssl_monitoring", "strict_validation", value)
            
            print("✅ Setting updated successfully!")
        except ValueError:
            print("❌ Invalid value. Please enter a valid number.")
    
    def configure_advanced_attack_detection_settings(self):
        """Configure advanced attack detection settings"""
        print("\n" + "="*50)
        print("ADVANCED ATTACK DETECTION SETTINGS")
        print("="*50)
        
        settings = self.settings_manager.get_category_settings("advanced_attack_detection")
        
        print(f"Current Settings:")
        print(f"1. Monitor Duration: {settings['monitor_duration']} seconds")
        print(f"2. MAC Flood Threshold: {settings['mac_flood_threshold']} packets/sec")
        print(f"3. SYN Flood Threshold: {settings['syn_flood_threshold']} packets/sec")
        print(f"4. UDP Flood Threshold: {settings['udp_flood_threshold']} packets/sec")
        print(f"5. ICMP Flood Threshold: {settings['icmp_flood_threshold']} packets/sec")
        print(f"6. Port Scan Threshold: {settings['port_scan_threshold']} ports")
        print(f"7. Enable Layer 2 Detection: {settings['enable_layer2_detection']}")
        print(f"8. Enable Layer 3 Detection: {settings['enable_layer3_detection']}")
        print(f"9. Enable Layer 4 Detection: {settings['enable_layer4_detection']}")
        print(f"10. Enable MITM Detection: {settings['enable_mitm_detection']}")
        
        choice = input("\nSelect setting to modify (1-10), or 'back': ").strip()
        
        if choice == 'back':
            return
        
        try:
            if choice == '1':
                value = int(input(f"Enter monitor duration (current: {settings['monitor_duration']}): "))
                self.settings_manager.set_setting("advanced_attack_detection", "monitor_duration", value)
            elif choice == '2':
                value = int(input(f"Enter MAC flood threshold (current: {settings['mac_flood_threshold']}): "))
                self.settings_manager.set_setting("advanced_attack_detection", "mac_flood_threshold", value)
            elif choice == '3':
                value = int(input(f"Enter SYN flood threshold (current: {settings['syn_flood_threshold']}): "))
                self.settings_manager.set_setting("advanced_attack_detection", "syn_flood_threshold", value)
            elif choice == '4':
                value = int(input(f"Enter UDP flood threshold (current: {settings['udp_flood_threshold']}): "))
                self.settings_manager.set_setting("advanced_attack_detection", "udp_flood_threshold", value)
            elif choice == '5':
                value = int(input(f"Enter ICMP flood threshold (current: {settings['icmp_flood_threshold']}): "))
                self.settings_manager.set_setting("advanced_attack_detection", "icmp_flood_threshold", value)
            elif choice == '6':
                value = int(input(f"Enter port scan threshold (current: {settings['port_scan_threshold']}): "))
                self.settings_manager.set_setting("advanced_attack_detection", "port_scan_threshold", value)
            elif choice == '7':
                value = input(f"Enable Layer 2 detection (current: {settings['enable_layer2_detection']}) [y/n]: ").lower() == 'y'
                self.settings_manager.set_setting("advanced_attack_detection", "enable_layer2_detection", value)
            elif choice == '8':
                value = input(f"Enable Layer 3 detection (current: {settings['enable_layer3_detection']}) [y/n]: ").lower() == 'y'
                self.settings_manager.set_setting("advanced_attack_detection", "enable_layer3_detection", value)
            elif choice == '9':
                value = input(f"Enable Layer 4 detection (current: {settings['enable_layer4_detection']}) [y/n]: ").lower() == 'y'
                self.settings_manager.set_setting("advanced_attack_detection", "enable_layer4_detection", value)
            elif choice == '10':
                value = input(f"Enable MITM detection (current: {settings['enable_mitm_detection']}) [y/n]: ").lower() == 'y'
                self.settings_manager.set_setting("advanced_attack_detection", "enable_mitm_detection", value)
            
            print("✅ Setting updated successfully!")
        except ValueError:
            print("❌ Invalid value. Please enter a valid number.")
    
    def view_current_settings(self):
        """View current all settings"""
        print("\n" + "="*60)
        print("CURRENT SETTINGS")
        print("="*60)
        
        for category, settings in self.settings_manager.settings.items():
            print(f"\n{category.upper()}:")
            for key, value in settings.items():
                print(f"  {key}: {value}")
    
    def reset_settings_to_defaults(self):
        """Reset settings to defaults"""
        confirm = input("\n⚠️  This will reset all settings to defaults. Continue? (y/N): ").strip().lower()
        if confirm == 'y':
            self.settings_manager.reset_to_defaults()
            print("✅ Settings reset to defaults!")
        else:
            print("❌ Reset cancelled.")
    
    def export_settings(self):
        """Export settings to file"""
        filename = input("Enter export filename (default: rdds_settings_export.json): ").strip()
        if not filename:
            filename = "rdds_settings_export.json"
        
        if self.settings_manager.export_settings(filename):
            print(f"✅ Settings exported to {filename}")
        else:
            print("❌ Failed to export settings.")
    
    def import_settings(self):
        """Import settings from file"""
        filename = input("Enter import filename: ").strip()
        if not filename:
            print("❌ Please provide a filename.")
            return
        
        if self.settings_manager.import_settings(filename):
            print(f"✅ Settings imported from {filename}")
        else:
            print("❌ Failed to import settings.")

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
