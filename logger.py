# -*- coding: utf-8 -*-
# logger.py

import json
import csv
from datetime import datetime
import os

class SecurityLogger:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
    
    def log_device(self, device):
        """Log device discovery with rotation"""
        log_file = os.path.join(self.log_dir, 'devices.json')
        
        # Check file size and rotate if needed (10MB limit)
        if os.path.exists(log_file) and os.path.getsize(log_file) > 10485760:
            # Rotate log file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(self.log_dir, f'devices_{timestamp}.json')
            os.rename(log_file, backup_file)
            print(f"[*] Log rotated to: {backup_file}")
        
        log_entry = {
            'timestamp': str(datetime.now()),
            'device': device
        }
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def log_alert(self, alert):
        """Log security alert"""
        log_file = os.path.join(self.log_dir, 'alerts.json')
        
        alert['logged_at'] = str(datetime.now())
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')
    
    def generate_report(self, devices, alerts):
        """Generate comprehensive security report with improved error handling"""
        try:
            # Ensure devices and alerts are lists
            if not devices:
                devices = []
            if not alerts:
                alerts = []
            
            # Create report filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(self.log_dir, f'security_report_{timestamp}.html')
            
            # Count device types
            rogue_count = sum(1 for d in devices if d.get('status') == 'ROGUE')
            suspicious_count = sum(1 for d in devices if d.get('status') == 'SUSPICIOUS')
            trusted_count = sum(1 for d in devices if d.get('status') == 'TRUSTED')
            
            # Generate device rows HTML
            device_rows = ""
            if devices:
                for device in devices:
                    status_class = device.get('status', 'trusted').lower()
                    device_rows += f'''
        <tr class="{status_class}">
            <td>{device.get('ip', 'N/A')}</td>
            <td>{device.get('mac', 'N/A')}</td>
            <td>{device.get('vendor', 'Unknown')}</td>
            <td>{device.get('status', 'N/A')}</td>
            <td>{device.get('risk_score', 0)}</td>
        </tr>'''
            else:
                device_rows = '''
        <tr class="no-data">
            <td colspan="5">No devices detected</td>
        </tr>'''
            
            # Generate alert rows HTML
            alert_rows = ""
            if alerts:
                for alert in alerts:
                    alert_rows += f'''
        <tr>
            <td>{alert.get('type', 'N/A')}</td>
            <td>{alert.get('severity', 'N/A')}</td>
            <td>{alert.get('message', 'N/A')}</td>
            <td>{alert.get('timestamp', 'N/A')}</td>
        </tr>'''
            else:
                alert_rows = '''
        <tr class="no-data">
            <td colspan="4">No security alerts</td>
        </tr>'''
            
            # Complete HTML template
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Rogue Device Detection Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #c00; text-align: center; margin-bottom: 30px; }}
        h2 {{ color: #333; border-bottom: 2px solid #c00; padding-bottom: 10px; }}
        .summary {{ background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .summary ul {{ margin: 0; padding-left: 20px; }}
        .summary li {{ margin: 5px 0; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; background: white; }}
        th {{ background: #333; color: white; padding: 12px; text-align: left; }}
        td {{ border: 1px solid #ddd; padding: 10px; }}
        .rogue {{ background: #ffebee; color: #c62828; }}
        .suspicious {{ background: #fff8e1; color: #f57c00; }}
        .trusted {{ background: #e8f5e8; color: #2e7d32; }}
        .no-data {{ background: #f5f5f5; text-align: center; font-style: italic; color: #666; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Rogue Device Detection Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <h2>Summary</h2>
        <div class="summary">
            <ul>
                <li><strong>Total Devices:</strong> {len(devices)}</li>
                <li><strong>Rogue Devices:</strong> {rogue_count}</li>
                <li><strong>Suspicious Devices:</strong> {suspicious_count}</li>
                <li><strong>Trusted Devices:</strong> {trusted_count}</li>
                <li><strong>Total Alerts:</strong> {len(alerts)}</li>
            </ul>
        </div>
        
        <h2>Detected Devices</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Vendor</th>
                <th>Status</th>
                <th>Risk Score</th>
            </tr>
            {device_rows}
        </table>
        
        <h2>Security Alerts</h2>
        <table>
            <tr>
                <th>Alert Type</th>
                <th>Severity</th>
                <th>Message</th>
                <th>Timestamp</th>
            </tr>
            {alert_rows}
        </table>
        
        <div class="footer">
            <p>Report generated by RDDS (Rogue Detection & Defense System)</p>
        </div>
    </div>
</body>
</html>"""
            
            # Write report to file
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html)
            
            print(f"[+] Report generated successfully: {report_file}")
            return report_file
            
        except Exception as e:
            print(f"[!] Error generating report: {e}")
            # Return None on error, but also create a simple text report as fallback
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                fallback_file = os.path.join(self.log_dir, f'fallback_report_{timestamp}.txt')
                with open(fallback_file, 'w', encoding='utf-8') as f:
                    f.write(f"Rogue Device Detection Report\n")
                    f.write(f"Generated: {datetime.now()}\n\n")
                    f.write(f"Total Devices: {len(devices)}\n")
                    f.write(f"Rogue Devices: {rogue_count}\n")
                    f.write(f"Suspicious Devices: {suspicious_count}\n")
                    f.write(f"Trusted Devices: {trusted_count}\n")
                    f.write(f"Total Alerts: {len(alerts)}\n")
                print(f"[+] Fallback report created: {fallback_file}")
                return fallback_file
            except Exception as fallback_error:
                print(f"[!] Even fallback report failed: {fallback_error}")
                return None

# Usage Example
if __name__ == "__main__":
    logger = SecurityLogger()
    
    # Sample data
    devices = [
        {'ip': '192.168.1.100', 'mac': '00:11:22:33:44:55', 'vendor': 'Test Vendor', 'status': 'TRUSTED', 'risk_score': 10}
    ]
    alerts = [
        {'type': 'TEST_ALERT', 'severity': 'LOW', 'message': 'Test alert message', 'timestamp': str(datetime.now())}
    ]
    
    report_file = logger.generate_report(devices, alerts)
    print(f"Report saved to: {report_file}")