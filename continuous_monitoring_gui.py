# -*- coding: utf-8 -*-
# Continuous Monitoring GUI Extension for RDDS

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from datetime import datetime

class ContinuousMonitoringGUI:
    def __init__(self, parent_gui):
        self.parent_gui = parent_gui
        self.monitoring_active = False
        self.monitoring_thread = None
        self.known_devices = {}
        self.all_alerts = []
        
    def toggle_continuous_monitoring(self):
        """Toggle continuous monitoring on/off"""
        if not self.monitoring_active:
            self.start_continuous_monitoring()
        else:
            self.stop_continuous_monitoring()
    
    def start_continuous_monitoring(self):
        """Start continuous monitoring in a separate thread"""
        if self.monitoring_active:
            return
            
        self.monitoring_active = True
        self.parent_gui.monitoring_button.config(
            text="⏹️ Stop Continuous Monitoring",
            bg="#dc3545"  # Red color for stop button
        )
        
        # Clear previous data
        self.known_devices = {}
        self.all_alerts = []
        
        # Start monitoring in separate thread
        self.monitoring_thread = threading.Thread(
            target=self._continuous_monitoring_loop,
            daemon=True
        )
        self.monitoring_thread.start()
        
        self.parent_gui.add_activity("🔄 Continuous monitoring started")
        
    def stop_continuous_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        self.parent_gui.monitoring_button.config(
            text="🔄 Start Continuous Monitoring",
            bg=self.parent_gui.colors['success']
        )
        
        self.parent_gui.add_activity("⏹️ Continuous monitoring stopped")
        
        # Generate final report
        self._generate_final_report()
    
    def _continuous_monitoring_loop(self):
        """Main monitoring loop running in separate thread"""
        scan_cycle = 0
        
        try:
            while self.monitoring_active:
                scan_cycle += 1
                
                # Update GUI with cycle info
                self.parent_gui.root.after(0, self._update_cycle_display, scan_cycle)
                
                # Step 1: Network Device Discovery
                try:
                    network_range = self.parent_gui.scanner.get_network_range()
                    current_devices = self.parent_gui.scanner.arp_scan(network_range)
                    
                    # Update device display
                    self.parent_gui.root.after(0, self._update_device_display, current_devices, scan_cycle)
                    
                except Exception as e:
                    self.parent_gui.root.after(0, self.parent_gui.add_activity, f"❌ Scan error: {str(e)}")
                
                # Step 2: Device Analysis
                try:
                    if current_devices:
                        analyzed_devices, alerts = self.parent_gui.detector.analyze_network(current_devices)
                        self._detect_new_devices(analyzed_devices, alerts)
                        
                        # Update alerts display
                        self.parent_gui.root.after(0, self._update_alerts_display, alerts)
                        
                except Exception as e:
                    self.parent_gui.root.after(0, self.parent_gui.add_activity, f"❌ Analysis error: {str(e)}")
                
                # Step 3: Wireless Monitoring
                try:
                    wireless_networks = self.parent_gui.enhanced_ap_detector.scan_wireless_networks_windows()
                    wireless_alerts = (
                        self.parent_gui.enhanced_ap_detector.detect_evil_twin(wireless_networks) +
                        self.parent_gui.enhanced_ap_detector.detect_rogue_ap(wireless_networks) +
                        self.parent_gui.enhanced_ap_detector.detect_karma_attack(wireless_networks)
                    )
                    
                    if wireless_alerts:
                        self.all_alerts.extend(wireless_alerts)
                        self.parent_gui.root.after(0, self._update_wireless_alerts, wireless_alerts)
                        
                except Exception as e:
                    self.parent_gui.root.after(0, self.parent_gui.add_activity, f"❌ Wireless scan error: {str(e)}")
                
                # Step 4: Attack Detection (short burst)
                try:
                    attack_alerts = self.parent_gui.attack_detector.start_monitoring(
                        interface=self.parent_gui.scanner.interface,
                        duration=10  # Short monitoring burst
                    )
                    
                    if attack_alerts:
                        self.all_alerts.extend(attack_alerts)
                        self.parent_gui.root.after(0, self._update_attack_alerts, attack_alerts)
                        
                except Exception as e:
                    self.parent_gui.root.after(0, self.parent_gui.add_activity, f"❌ Attack detection error: {str(e)}")
                
                # Wait before next scan
                for i in range(60, 0, -1):
                    if not self.monitoring_active:
                        break
                    time.sleep(1)
                    
        except Exception as e:
            self.parent_gui.root.after(0, self.parent_gui.add_activity, f"❌ Monitoring loop error: {str(e)}")
        finally:
            self.parent_gui.root.after(0, self.stop_continuous_monitoring)
    
    def _update_cycle_display(self, scan_cycle):
        """Update cycle information in GUI"""
        cycle_text = f"🔄 Cycle #{scan_cycle} - {datetime.now().strftime('%H:%M:%S')}"
        self.parent_gui.update_status(cycle_text)
        
        # Update progress bar to show cycle progress
        self.parent_gui.scan_progress['value'] = (scan_cycle % 10) * 10
    
    def _update_device_display(self, devices, scan_cycle):
        """Update device display in GUI"""
        # Clear existing items
        for item in self.parent_gui.scan_tree.get_children():
            self.parent_gui.scan_tree.delete(item)
        
        # Add current devices
        for device in devices:
            device_key = f"{device['ip']}_{device['mac']}"
            
            # Determine status and tag
            if device_key in self.known_devices:
                tag = 'trusted'
                status = 'Known'
            else:
                tag = 'suspicious'
                status = 'New'
            
            self.parent_gui.scan_tree.insert('', 'end', values=(
                device['ip'],
                device['mac'],
                device.get('vendor', 'Unknown'),
                status,
                f"{scan_cycle}"
            ), tags=(tag,))
        
        # Update status
        self.parent_gui.add_activity(f"📊 Found {len(devices)} devices (Cycle #{scan_cycle})")
    
    def _detect_new_devices(self, analyzed_devices, alerts):
        """Detect and track new devices"""
        for device in analyzed_devices:
            device_key = f"{device['ip']}_{device['mac']}"
            
            if device_key not in self.known_devices:
                self.known_devices[device_key] = {
                    'first_seen': datetime.now(),
                    'status': device['status'],
                    'last_seen': datetime.now()
                }
                
                # Create alert for new unknown device
                if device['status'] in ['ROGUE', 'SUSPICIOUS']:
                    alert = {
                        'type': 'NEW_UNKNOWN_DEVICE',
                        'severity': 'HIGH' if device['status'] == 'ROGUE' else 'MEDIUM',
                        'message': f"New {device['status'].lower()} device: {device['ip']} ({device['mac']})",
                        'timestamp': datetime.now().isoformat()
                    }
                    alerts.append(alert)
                    self.all_alerts.append(alert)
            else:
                self.known_devices[device_key]['last_seen'] = datetime.now()
    
    def _update_alerts_display(self, alerts):
        """Update alerts display in GUI"""
        for alert in alerts:
            alert_text = f"🚨 {alert.get('severity', 'MEDIUM')}: {alert.get('message', 'Unknown alert')}"
            self.parent_gui.add_activity(alert_text)
    
    def _update_wireless_alerts(self, alerts):
        """Update wireless alerts in GUI"""
        for alert in alerts:
            alert_text = f"📡 Wireless: {alert.get('message', 'Wireless threat detected')}"
            self.parent_gui.add_activity(alert_text)
    
    def _update_attack_alerts(self, alerts):
        """Update attack alerts in GUI"""
        for alert in alerts:
            alert_text = f"🛡️ Attack: {alert.get('message', 'Attack detected')}"
            self.parent_gui.add_activity(alert_text)
    
    def _generate_final_report(self):
        """Generate final comprehensive report"""
        try:
            # Create summary data
            report_data = {
                'monitoring_summary': {
                    'total_cycles': len(self.known_devices),
                    'total_devices': len(self.known_devices),
                    'total_alerts': len(self.all_alerts),
                    'monitoring_duration': 'Continuous',
                    'timestamp': datetime.now().isoformat()
                },
                'devices': list(self.known_devices.values()),
                'alerts': self.all_alerts
            }
            
            # Generate report using logger
            report_file = self.parent_gui.logger.generate_report(
                report_data['devices'], 
                report_data['alerts']
            )
            
            self.parent_gui.add_activity(f"📄 Final report saved: {report_file}")
            
            # Show summary dialog
            self._show_summary_dialog(report_data)
            
        except Exception as e:
            self.parent_gui.add_activity(f"❌ Report generation error: {str(e)}")
    
    def _show_summary_dialog(self, report_data):
        """Show monitoring summary dialog"""
        summary = report_data['monitoring_summary']
        
        message = f"""
📊 CONTINUOUS MONITORING SUMMARY
═════════════════════════════════

Total Devices Tracked: {summary['total_devices']}
Total Alerts Generated: {summary['total_alerts']}
Monitoring Duration: {summary['monitoring_duration']}

High Priority Alerts: {len([a for a in self.all_alerts if a.get('severity') in ['HIGH', 'CRITICAL']])}

Report saved to: logs/ directory
        """
        
        messagebox.showinfo("Monitoring Summary", message.strip())
