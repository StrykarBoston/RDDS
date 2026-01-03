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
        """Log device discovery"""
        log_file = os.path.join(self.log_dir, 'devices.json')
        
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
        """Generate comprehensive security report"""
        report_file = os.path.join(
            self.log_dir, 
            f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
        )
        
        # Ensure devices and alerts are lists
        if not devices:
            devices = []
        if not alerts:
            alerts = []
            
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Rogue Device Detection Report</title>
    <style>
        body {{ font-family: Arial; margin: 40px; }}
        h1 {{ color: #c00; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th {{ background: #333; color: white; padding: 10px; }}
        td {{ border: 1px solid #ddd; padding: 8px; }}
        .rogue {{ background: #ffdddd; }}
        .suspicious {{ background: #ffffdd; }}
        .trusted {{ background: #ddffdd; }}
        .no-data {{ background: #f9f9f9; text-align: center; font-style: italic; }}
    </style>
</head>
<body>
    <h1>🛡️ Rogue Device Detection Report</h1>
    <p><strong>Generated:</strong> {datetime.now()}</p>
    
    <h2>Summary</h2>
    <ul>
        <li>Total Devices: {len(devices)}</li>
        <li>Rogue Devices: {sum(1 for d in devices if d.get('status') == 'ROGUE')}</li>
        <li>Suspicious: {sum(1 for d in devices if d.get('status') == 'SUSPICIOUS')}</li>
        <li>Total Alerts: {len(alerts)}</li>
    </ul>
    
    <h2>Detected Devices</h2>
    <table>
        <tr>
            <th>IP</th>
            <th>MAC</th>
            <th>Vendor</th>
            <th>Status</th>
            <th>Risk Score</th>
        </tr>
        {''.join([f'''
        <tr class="{d.get('status', 'trusted').lower()}">
            <td>{d['ip']}</td>
            <td>{d['mac']}</td>
            <td>{d.get('vendor', 'Unknown')}</td>
            <td>{d.get('status', 'N/A')}</td>
            <td>{d.get('risk_score', 0)}</td>
        </tr>
        ''' for d in devices]) if devices else '''
        <tr class="no-data">
            <td colspan="5">No devices detected</td>
        </tr>
        '''}
    </table>
    
    <h2>Security Alerts</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>Severity</th>
            <th>Message</th>
            <th>Timestamp</th>
        </tr>
        {''.join([f'''
        <tr>
            <td>{a['type']}</td>
            <td>{a['severity']}</td>
            <td>{a['message']}</td>
            <td>{a.get('timestamp', 'N/A')}</td>
        </tr>
        ''' for a in alerts]) if alerts else '''
        <tr class="no-data">
            <td colspan="4">No security alerts</td>
        </tr>
        '''}
    </table>
</body>
</html>
        """
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"[+] Report generated: {report_file}")
            return report_file
        except Exception as e:
            print(f"[!] Error generating report: {e}")
            return None