# -*- coding: utf-8 -*-
# iot_profiler.py - IoT Device Profiling & Risk Assessment Module

import re
import json
import time
import requests
from collections import defaultdict
from datetime import datetime, timedelta
import logging

class IoTProfiler:
    def __init__(self):
        self.device_profiles = {}
        self.oui_database = self._load_oui_database()
        self.cve_database = {}
        self.risk_factors = {
            'unpatched_firmware': 30,
            'weak_auth': 25,
            'open_ports': 20,
            'unencrypted': 15,
            'default_creds': 35,
            'chinese_origin': 10,
            'russian_origin': 10
        }
        self.iot_signatures = {
            'cameras': [80, 554, 8080, 8000],
            'smart_speakers': [443, 80, 8080],
            'smart_tv': [80, 443, 8080, 49152],
            'printers': [80, 443, 631, 9100],
            'routers': [22, 23, 80, 443, 8080],
            'smart_home': [80, 443, 1883, 5683],
            'ip_cameras': [80, 554, 8000, 8080, 49152]
        }
        
    def _load_oui_database(self):
        """Load MAC address OUI database for manufacturer identification"""
        # Simplified OUI database - in production, load from file
        return {
            '00:1A:2B': 'Unknown',
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:0C:29': 'VMware',
            '00:05:9A': 'Huawei',
            '00:12:17': 'Huawei',
            '00:E0:4C': 'Realtek',
            'B4:99:BA': 'Xiaomi',
            '28:E3:1F': 'Xiaomi',
            '64:09:80': 'Xiaomi',
            'F8:E7:1E': 'Huawei',
            '00:1E:8F': 'Huawei',
            'AC:C1:EE': 'Huawei',
            '28:6E:D4': 'Huawei',
            '70:85:C2': 'Huawei',
            '00:11:32': 'Xiaomi',
            '34:CE:00': 'Xiaomi',
            '78:11:DC': 'Xiaomi',
            '50:8F:4C': 'Xiaomi',
            '64:20:9F': 'Xiaomi',
            '7C:49:EB': 'Xiaomi',
            'F0:B4:29': 'Xiaomi'
        }
    
    def profile_device(self, device_data):
        """Comprehensive IoT device profiling and risk assessment"""
        ip = device_data.get('ip', '0.0.0.0')
        mac = device_data.get('mac', '00:00:00:00:00:00')
        open_ports = device_data.get('open_ports', [])
        ttl = device_data.get('ttl', 64)
        window_size = device_data.get('window_size', 8192)
        
        profile = {
            'ip': ip,
            'mac': mac,
            'timestamp': time.time(),
            'device_type': 'Unknown',
            'manufacturer': 'Unknown',
            'os_detection': self._detect_os(ttl, window_size),
            'risk_score': 0,
            'risk_factors': [],
            'vulnerabilities': [],
            'communication_patterns': [],
            'services': self._analyze_services(open_ports),
            'security_issues': []
        }
        
        # Manufacturer identification
        profile['manufacturer'] = self._identify_manufacturer(mac)
        
        # Device type identification
        profile['device_type'] = self._identify_device_type(open_ports, profile['manufacturer'])
        
        # Risk assessment
        risk_score, risk_factors = self._assess_risk(profile, device_data)
        profile['risk_score'] = risk_score
        profile['risk_factors'] = risk_factors
        
        # Check for known vulnerabilities
        profile['vulnerabilities'] = self._check_vulnerabilities(profile)
        
        # Communication pattern analysis
        profile['communication_patterns'] = self._analyze_communication_patterns(device_data)
        
        # Store profile
        self.device_profiles[ip] = profile
        
        return profile
    
    def _detect_os(self, ttl, window_size):
        """Detect operating system based on TTL and window size"""
        os_detection = {
            'ttl': ttl,
            'window_size': window_size,
            'likely_os': 'Unknown'
        }
        
        # TTL-based OS detection
        if ttl <= 64:
            os_detection['likely_os'] = 'Linux/Unix'
        elif ttl <= 128:
            os_detection['likely_os'] = 'Windows'
        elif ttl <= 255:
            os_detection['likely_os'] = 'Cisco/Network Device'
        
        # Window size analysis
        if window_size == 8192:
            os_detection['likely_os'] = 'Linux/Unix'
        elif window_size == 65535:
            os_detection['likely_os'] = 'Windows'
        elif window_size in [4096, 16384]:
            os_detection['likely_os'] = 'Network Device'
        
        return os_detection
    
    def _identify_manufacturer(self, mac):
        """Identify device manufacturer from MAC address OUI"""
        if len(mac) < 8:
            return 'Unknown'
        
        oui = mac[:8].upper()
        return self.oui_database.get(oui, 'Unknown')
    
    def _identify_device_type(self, open_ports, manufacturer):
        """Identify device type based on open ports and manufacturer"""
        port_set = set(open_ports)
        
        for device_type, ports in self.iot_signatures.items():
            if port_set.intersection(ports):
                return device_type.replace('_', ' ').title()
        
        # Manufacturer-based identification
        if 'xiaomi' in manufacturer.lower():
            return 'Smart Home Device'
        elif 'huawei' in manufacturer.lower():
            return 'Network Device'
        
        return 'Unknown IoT Device'
    
    def _analyze_services(self, open_ports):
        """Analyze services based on open ports"""
        services = []
        port_service_map = {
            22: 'SSH',
            23: 'Telnet',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            554: 'RTSP',
            8080: 'HTTP-Alt',
            1883: 'MQTT',
            5683: 'CoAP',
            631: 'IPP',
            9100: 'Raw Print',
            49152: 'UPnP'
        }
        
        for port in open_ports:
            service = port_service_map.get(port, f'Unknown-{port}')
            services.append({'port': port, 'service': service})
        
        return services
    
    def _assess_risk(self, profile, device_data):
        """Comprehensive risk assessment"""
        risk_score = 0
        risk_factors = []
        
        # Check for unpatched firmware
        if self._is_unpatched_firmware(profile):
            risk_score += self.risk_factors['unpatched_firmware']
            risk_factors.append('Unpatched firmware detected')
        
        # Check for weak authentication
        if self._has_weak_authentication(profile):
            risk_score += self.risk_factors['weak_auth']
            risk_factors.append('Weak authentication methods')
        
        # Check for unnecessary open ports
        if len(profile['services']) > 5:
            risk_score += self.risk_factors['open_ports']
            risk_factors.append('Excessive open ports')
        
        # Check for unencrypted communication
        unencrypted_services = [s for s in profile['services'] if 'HTTP' in s['service'] and 'HTTPS' not in s['service']]
        if unencrypted_services:
            risk_score += self.risk_factors['unencrypted']
            risk_factors.append('Unencrypted communication detected')
        
        # Check for default credentials
        if self._has_default_credentials(profile):
            risk_score += self.risk_factors['default_creds']
            risk_factors.append('Potential default credentials')
        
        # Geopolitical risk assessment
        if self._is_chinese_origin(profile):
            risk_score += self.risk_factors['chinese_origin']
            risk_factors.append('Chinese manufacturer (geopolitical risk)')
        
        if self._is_russian_origin(profile):
            risk_score += self.risk_factors['russian_origin']
            risk_factors.append('Russian manufacturer (geopolitical risk)')
        
        return min(risk_score, 100), risk_factors
    
    def _is_unpatched_firmware(self, profile):
        """Check if device has unpatched firmware"""
        # Simplified check - in production, query manufacturer databases
        return profile['device_type'] != 'Unknown' and len(profile['vulnerabilities']) > 0
    
    def _has_weak_authentication(self, profile):
        """Check for weak authentication methods"""
        weak_auth_services = ['Telnet', 'HTTP']
        return any(s['service'] in weak_auth_services for s in profile['services'])
    
    def _has_default_credentials(self, profile):
        """Check for potential default credentials"""
        # Simplified check - in production, test common default credentials
        default_creds_devices = ['camera', 'router', 'printer', 'smart']
        device_type_lower = profile['device_type'].lower()
        return any(device in device_type_lower for device in default_creds_devices)
    
    def _is_chinese_origin(self, profile):
        """Check if device is from Chinese manufacturer"""
        chinese_manufacturers = ['huawei', 'xiaomi', 'zte', 'tenda', 'tp-link']
        return any(mfr in profile['manufacturer'].lower() for mfr in chinese_manufacturers)
    
    def _is_russian_origin(self, profile):
        """Check if device is from Russian manufacturer"""
        russian_manufacturers = ['kaspersky', 'yandex', 'mail.ru']
        return any(mfr in profile['manufacturer'].lower() for mfr in russian_manufacturers)
    
    def _check_vulnerabilities(self, profile):
        """Check for known CVEs"""
        vulnerabilities = []
        
        # Simplified vulnerability checking - in production, query CVE databases
        device_type = profile['device_type'].lower()
        
        if 'camera' in device_type:
            vulnerabilities.append({
                'cve_id': 'CVE-2021-36260',
                'severity': 'HIGH',
                'description': 'Hikvision camera authentication bypass'
            })
        
        if 'router' in device_type:
            vulnerabilities.append({
                'cve_id': 'CVE-2020-8903',
                'severity': 'MEDIUM',
                'description': 'Router firmware vulnerability'
            })
        
        return vulnerabilities
    
    def _analyze_communication_patterns(self, device_data):
        """Analyze communication patterns"""
        patterns = []
        
        # Check for cloud communication
        if 'cloud_communication' in device_data:
            patterns.append({
                'type': 'Cloud Communication',
                'destinations': device_data.get('cloud_communication', []),
                'risk': 'LOW'
            })
        
        # Check for P2P communication
        if 'p2p_communication' in device_data:
            patterns.append({
                'type': 'P2P Communication',
                'destinations': device_data.get('p2p_communication', []),
                'risk': 'MEDIUM'
            })
        
        return patterns
    
    def get_device_summary(self, ip):
        """Get device profile summary"""
        if ip not in self.device_profiles:
            return None
        
        profile = self.device_profiles[ip]
        return {
            'ip': profile['ip'],
            'mac': profile['mac'],
            'device_type': profile['device_type'],
            'manufacturer': profile['manufacturer'],
            'risk_score': profile['risk_score'],
            'risk_factors': profile['risk_factors'],
            'vulnerabilities': len(profile['vulnerabilities']),
            'services': len(profile['services'])
        }
    
    def get_all_profiles(self):
        """Get all device profiles"""
        return list(self.device_profiles.values())
    
    def get_high_risk_devices(self, threshold=70):
        """Get devices with risk score above threshold"""
        return [profile for profile in self.device_profiles.values() 
                if profile['risk_score'] >= threshold]
    
    def generate_iot_report(self):
        """Generate comprehensive IoT security report"""
        profiles = list(self.device_profiles.values())
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_devices': len(profiles),
            'high_risk_devices': len([p for p in profiles if p['risk_score'] >= 70]),
            'medium_risk_devices': len([p for p in profiles if 40 <= p['risk_score'] < 70]),
            'low_risk_devices': len([p for p in profiles if p['risk_score'] < 40]),
            'device_types': defaultdict(int),
            'manufacturers': defaultdict(int),
            'total_vulnerabilities': sum(len(p['vulnerabilities']) for p in profiles),
            'common_risk_factors': defaultdict(int)
        }
        
        # Aggregate statistics
        for profile in profiles:
            report['device_types'][profile['device_type']] += 1
            report['manufacturers'][profile['manufacturer']] += 1
            for factor in profile['risk_factors']:
                report['common_risk_factors'][factor] += 1
        
        return report
