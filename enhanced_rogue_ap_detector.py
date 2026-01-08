# -*- coding: utf-8 -*-
# enhanced_rogue_ap_detector.py - Advanced Rogue AP Detection with RF Fingerprinting

import subprocess
import re
import time
import math
import json
import os
from collections import defaultdict, deque
import hashlib
import logging
from datetime import datetime, timedelta
import numpy as np

class EnhancedRogueAPDetector:
    def __init__(self, config_file="ap_config.json"):
        self.config_file = config_file
        self.known_aps = []
        self.detected_aps = []
        self.signal_history = defaultdict(deque)
        self.beacon_frames = defaultdict(list)
        self.probe_responses = defaultdict(list)
        self.channel_hopping_data = defaultdict(list)
        self.rss_i_anomalies = defaultdict(list)
        
        # Detection thresholds
        self.rssi_variance_threshold = 10.0  # dBm variance threshold
        self.beacon_interval_threshold = 0.1  # seconds
        self.channel_hop_threshold = 3  # channels per minute
        self.probe_response_threshold = 100  # ms
        
        # Load configuration
        self._load_config()
        
        print("[*] Enhanced Rogue AP Detector initialized")
        print("    - RF Fingerprinting: ENABLED")
        print("    - Evil Twin Detection: ENHANCED")
        print("    - Channel Hopping Detection: ENABLED")
        print("    - RSSI Anomaly Detection: ENABLED")
    
    def scan_wireless_networks_windows(self):
        """Enhanced wireless network scanning with RF data"""
        try:
            # Run netsh command with detailed BSSID information
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            networks = self._parse_enhanced_netsh_output(result.stdout)
            
            # Enhance with RF fingerprinting data
            for network in networks:
                network.update(self._get_rf_fingerprint(network['bssid']))
                network.update(self._analyze_beacon_timing(network['bssid']))
                network.update(self._detect_channel_hopping(network))
            
            return networks
        
        except Exception as e:
            print(f"Error scanning networks: {e}")
            return []
    
    def _parse_enhanced_netsh_output(self, output):
        """Parse enhanced netsh wlan output with detailed RF information"""
        networks = []
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Parse SSID
            if line.startswith('SSID'):
                match = re.search(r'SSID \d+ : (.+)', line)
                if match:
                    if current_network:  # Save previous network
                        networks.append(current_network)
                    current_network = {
                        'ssid': match.group(1),
                        'bssids': []
                    }
            
            # Parse BSSID information
            elif line.startswith('BSSID') and current_network:
                match = re.search(r'BSSID \d+\s+:\s+([0-9a-fA-F:]+)', line)
                if match:
                    bssid = match.group(1)
                    bssid_info = {
                        'bssid': bssid,
                        'signal': 0,
                        'channel': 0,
                        'network_type': 'Infrastructure'
                    }
                    current_network['bssids'].append(bssid_info)
            
            # Parse signal strength
            elif 'Signal' in line and current_network and current_network['bssids']:
                match = re.search(r'Signal\s*:\s*(\d+)%', line)
                if match:
                    signal_percent = int(match.group(1))
                    # Convert percentage to dBm (approximate)
                    signal_dbm = -100 + (signal_percent * 0.6)
                    current_network['bssids'][-1]['signal'] = signal_dbm
            
            # Parse channel
            elif 'Channel' in line and current_network and current_network['bssids']:
                match = re.search(r'Channel\s*:\s*(\d+)', line)
                if match:
                    current_network['bssids'][-1]['channel'] = int(match.group(1))
            
            # Parse network type
            elif 'Network type' in line and current_network:
                match = re.search(r'Network type\s*:\s*(.+)', line)
                if match:
                    current_network['network_type'] = match.group(1).strip()
            
            # Parse authentication
            elif 'Authentication' in line and current_network:
                match = re.search(r'Authentication\s*:\s*(.+)', line)
                if match:
                    current_network['authentication'] = match.group(1).strip()
            
            # Parse encryption
            elif 'Encryption' in line and current_network:
                match = re.search(r'Encryption\s*:\s*(.+)', line)
                if match:
                    current_network['encryption'] = match.group(1).strip()
        
        # Add last network
        if current_network:
            networks.append(current_network)
        
        # Flatten networks (multiple BSSIDs per SSID)
        flattened_networks = []
        for network in networks:
            for bssid_info in network['bssids']:
                ap_data = {
                    'ssid': network['ssid'],
                    'bssid': bssid_info['bssid'],
                    'signal': bssid_info['signal'],
                    'channel': bssid_info['channel'],
                    'network_type': network.get('network_type', 'Unknown'),
                    'authentication': network.get('authentication', 'Unknown'),
                    'encryption': network.get('encryption', 'Unknown'),
                    'timestamp': time.time()
                }
                flattened_networks.append(ap_data)
        
        return flattened_networks
    
    def _get_rf_fingerprint(self, bssid):
        """Generate RF fingerprint for AP"""
        fingerprint = {
            'rf_fingerprint': {},
            'rssi_variance': 0.0,
            'signal_quality': 'Unknown'
        }
        
        # Store signal history
        current_time = time.time()
        if bssid in self.signal_history:
            # Keep last 60 seconds of data
            cutoff_time = current_time - 60
            recent_signals = [s for s in self.signal_history[bssid] if s['timestamp'] > cutoff_time]
            
            if len(recent_signals) > 5:
                signals = [s['signal'] for s in recent_signals]
                fingerprint['rssi_variance'] = np.var(signals)
                fingerprint['avg_signal'] = np.mean(signals)
                fingerprint['signal_quality'] = self._classify_signal_quality(np.mean(signals))
        
        return fingerprint
    
    def _classify_signal_quality(self, signal_dbm):
        """Classify signal quality based on RSSI"""
        if signal_dbm > -30:
            return 'Excellent'
        elif signal_dbm > -50:
            return 'Good'
        elif signal_dbm > -70:
            return 'Fair'
        elif signal_dbm > -85:
            return 'Poor'
        else:
            return 'Very Poor'
    
    def _analyze_beacon_timing(self, bssid):
        """Analyze beacon frame timing"""
        timing_info = {
            'beacon_interval_anomaly': False,
            'beacon_timing_variance': 0.0
        }
        
        current_time = time.time()
        if bssid in self.beacon_frames and len(self.beacon_frames[bssid]) > 3:
            recent_beacons = [b for b in self.beacon_frames[bssid] if current_time - b['timestamp'] < 30]
            
            if len(recent_beacons) > 2:
                intervals = []
                for i in range(1, len(recent_beacons)):
                    interval = recent_beacons[i]['timestamp'] - recent_beacons[i-1]['timestamp']
                    intervals.append(interval)
                
                if intervals:
                    timing_info['beacon_timing_variance'] = np.var(intervals)
                    # Check for irregular beacon intervals
                    if np.var(intervals) > self.beacon_interval_threshold:
                        timing_info['beacon_interval_anomaly'] = True
        
        return timing_info
    
    def _detect_channel_hopping(self, network):
        """Detect channel hopping behavior"""
        hopping_info = {
            'channel_hopping_detected': False,
            'channel_hop_rate': 0.0,
            'channels_used': []
        }
        
        bssid = network['bssid']
        current_channel = network['channel']
        current_time = time.time()
        
        # Track channel changes
        if bssid in self.channel_hopping_data:
            recent_channels = [c for c in self.channel_hopping_data[bssid] if current_time - c['timestamp'] < 60]
            
            if len(recent_channels) > 1:
                channels = [c['channel'] for c in recent_channels]
                unique_channels = list(set(channels))
                hopping_info['channels_used'] = unique_channels
                hopping_info['channel_hop_rate'] = len(unique_channels) / 1.0  # per minute
                
                if len(unique_channels) >= self.channel_hop_threshold:
                    hopping_info['channel_hopping_detected'] = True
        
        # Add current channel
        self.channel_hopping_data[bssid].append({
            'channel': current_channel,
            'timestamp': current_time
        })
        
        return hopping_info
    
    def detect_evil_twin(self, networks):
        """Enhanced Evil Twin detection with multiple techniques"""
        alerts = []
        ssid_map = defaultdict(list)
        
        # Group by SSID
        for network in networks:
            ssid_map[network['ssid']].append(network)
        
        for ssid, aps in ssid_map.items():
            if len(aps) > 1:
                # Multiple APs with same SSID - potential evil twin
                evil_twin_analysis = self._analyze_evil_twin_candidates(ssid, aps)
                
                if evil_twin_analysis['is_evil_twin']:
                    alert = {
                        'type': 'EVIL_TWIN_AP',
                        'severity': 'CRITICAL',
                        'ssid': ssid,
                        'legitimate_ap': evil_twin_analysis['legitimate_ap'],
                        'evil_twins': evil_twin_analysis['evil_twins'],
                        'confidence': evil_twin_analysis['confidence'],
                        'evidence': evil_twin_analysis['evidence'],
                        'message': f"Evil Twin APs detected for SSID: {ssid}",
                        'count': len(evil_twin_analysis['evil_twins'])
                    }
                    alerts.append(alert)
                    print(f"🚨 Evil Twin AP detected: {ssid} ({len(evil_twin_analysis['evil_twins'])} evil twins)")
        
        return alerts
    
    def _analyze_evil_twin_candidates(self, ssid, aps):
        """Analyze AP candidates to identify evil twins"""
        analysis = {
            'is_evil_twin': False,
            'legitimate_ap': None,
            'evil_twins': [],
            'confidence': 0.0,
            'evidence': []
        }
        
        if len(aps) < 2:
            return analysis
        
        # Sort by signal strength (strongest is likely legitimate)
        aps_sorted = sorted(aps, key=lambda x: x['signal'], reverse=True)
        
        # Analyze each AP
        for i, ap in enumerate(aps_sorted):
            risk_score = 0
            evidence = []
            
            # Check BSSID similarity
            if i > 0:  # Not the strongest signal
                bssid_similarity = self._calculate_bssid_similarity(
                    aps_sorted[0]['bssid'], ap['bssid']
                )
                if bssid_similarity > 0.7:
                    risk_score += 30
                    evidence.append(f"High BSSID similarity: {bssid_similarity:.2f}")
            
            # Check encryption downgrade
            if ap.get('encryption') != aps_sorted[0].get('encryption'):
                risk_score += 25
                evidence.append(f"Different encryption: {ap.get('encryption')} vs {aps_sorted[0].get('encryption')}")
            
            # Check signal anomalies
            if ap.get('rssi_variance', 0) > self.rssi_variance_threshold:
                risk_score += 20
                evidence.append(f"High RSSI variance: {ap.get('rssi_variance', 0):.1f} dBm")
            
            # Check channel hopping
            if ap.get('channel_hopping_detected', False):
                risk_score += 25
                evidence.append("Channel hopping detected")
            
            # Check beacon timing anomalies
            if ap.get('beacon_interval_anomaly', False):
                risk_score += 15
                evidence.append("Beacon timing anomaly")
            
            # Check if it's a captive portal (heuristic)
            if self._is_captive_portal_candidate(ap):
                risk_score += 20
                evidence.append("Potential captive portal")
            
            ap['risk_score'] = risk_score
            ap['evidence'] = evidence
        
        # Classify APs
        legitimate_ap = None
        evil_twins = []
        
        for ap in aps_sorted:
            if ap['risk_score'] > 50:  # High risk threshold
                evil_twins.append(ap)
            else:
                legitimate_ap = ap
        
        if evil_twins:
            analysis['is_evil_twin'] = True
            analysis['legitimate_ap'] = legitimate_ap
            analysis['evil_twins'] = evil_twins
            analysis['confidence'] = max(ap['risk_score'] for ap in evil_twins) / 100.0
            analysis['evidence'] = [evidence for ap in evil_twins for evidence in ap.get('evidence', [])]
        
        return analysis
    
    def _calculate_bssid_similarity(self, bssid1, bssid2):
        """Calculate similarity between two BSSIDs"""
        # Remove colons and convert to integers
        b1 = int(bssid1.replace(':', ''), 16)
        b2 = int(bssid2.replace(':', ''), 16)
        
        # Calculate Hamming distance
        xor = b1 ^ b2
        hamming_distance = bin(xor).count('1')
        
        # Convert to similarity (0-1 scale)
        max_distance = 48  # 48 bits in MAC address
        similarity = 1 - (hamming_distance / max_distance)
        
        return similarity
    
    def _is_captive_portal_candidate(self, ap):
        """Check if AP might be a captive portal"""
        # Heuristics for captive portal detection
        suspicious_ssids = ['Free WiFi', 'Public WiFi', 'Airport WiFi', 'Hotel WiFi']
        
        # Check SSID patterns
        for pattern in suspicious_ssids:
            if pattern.lower() in ap['ssid'].lower():
                return True
        
        # Check for open authentication
        if ap.get('authentication', '').lower() == 'open':
            return True
        
        return False
    
    def detect_rogue_ap(self, networks):
        """Enhanced rogue AP detection with RF fingerprinting"""
        rogues = []
        
        # Load known APs
        known_bssids = [ap['bssid'] for ap in self.known_aps]
        
        for network in networks:
            is_rogue = False
            risk_factors = []
            risk_score = 0
            
            # Check if BSSID is unknown
            if network['bssid'] not in known_bssids:
                is_rogue = True
                risk_factors.append('Unknown BSSID')
                risk_score += 30
            
            # Check for suspicious signal patterns
            if network.get('rssi_variance', 0) > self.rssi_variance_threshold:
                risk_factors.append('High RSSI variance')
                risk_score += 20
            
            # Check for channel hopping
            if network.get('channel_hopping_detected', False):
                risk_factors.append('Channel hopping')
                risk_score += 25
            
            # Check for beacon anomalies
            if network.get('beacon_interval_anomaly', False):
                risk_factors.append('Beacon timing anomaly')
                risk_score += 15
            
            # Check for weak encryption
            if network.get('encryption', '').lower() in ['wep', 'open']:
                risk_factors.append('Weak encryption')
                risk_score += 20
            
            # Check for suspicious SSID patterns
            if self._is_suspicious_ssid(network['ssid']):
                risk_factors.append('Suspicious SSID pattern')
                risk_score += 15
            
            if is_rogue or risk_score > 40:
                rogues.append({
                    'type': 'ROGUE_AP',
                    'severity': 'HIGH' if risk_score > 60 else 'MEDIUM',
                    'ssid': network['ssid'],
                    'bssid': network['bssid'],
                    'signal': network['signal'],
                    'channel': network['channel'],
                    'risk_score': risk_score,
                    'risk_factors': risk_factors,
                    'message': f"Rogue AP detected: {network['ssid']} ({network['bssid']})",
                    'rf_fingerprint': network.get('rf_fingerprint', {}),
                    'channel_hopping': network.get('channel_hopping_detected', False)
                })
        
        return rogues
    
    def _is_suspicious_ssid(self, ssid):
        """Check for suspicious SSID patterns"""
        suspicious_patterns = [
            r'.*free.*wifi.*',
            r'.*public.*wifi.*',
            r'.*airport.*',
            r'.*hotel.*',
            r'.*starbucks.*',
            r'.*mcdonalds.*',
            r'^FreeWiFi.*',
            r'^PublicWiFi.*',
            r'.*\.tk$',
            r'.*\.ml$'
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, ssid, re.IGNORECASE):
                return True
        
        return False
    
    def detect_karma_attack(self, networks):
        """Detect Karma attacks (AP responding to all probe requests)"""
        karma_alerts = []
        
        for network in networks:
            # Check for APs that respond to probes too quickly
            if network.get('probe_response_time', 0) < self.probe_response_threshold:
                alert = {
                    'type': 'KARMA_ATTACK',
                    'severity': 'HIGH',
                    'ssid': network['ssid'],
                    'bssid': network['bssid'],
                    'probe_response_time': network.get('probe_response_time', 0),
                    'message': f"Potential Karma attack: {network['ssid']} responds to probes too quickly"
                }
                karma_alerts.append(alert)
        
        return karma_alerts
    
    def geolocate_rogue_ap(self, bssid, signal_samples):
        """Triangulate rogue AP location using signal strength"""
        if len(signal_samples) < 3:
            return {'error': 'Need at least 3 signal samples for triangulation'}
        
        # Simple triangulation based on signal strength
        # In practice, this would require multiple receivers at known locations
        locations = []
        
        for sample in signal_samples:
            # Estimate distance based on signal strength (simplified path loss model)
            signal_dbm = sample['signal']
            # Free space path loss approximation
            distance = 10 ** ((-30 - signal_dbm) / 20)  # meters
            locations.append({
                'x': sample.get('x', 0),
                'y': sample.get('y', 0),
                'estimated_distance': distance
            })
        
        # Calculate intersection point (simplified)
        if len(locations) >= 3:
            # This is a very simplified triangulation
            # Real implementation would use proper trilateration algorithms
            center_x = sum(loc['x'] for loc in locations) / len(locations)
            center_y = sum(loc['y'] for loc in locations) / len(locations)
            avg_distance = sum(loc['estimated_distance'] for loc in locations) / len(locations)
            
            return {
                'estimated_location': {
                    'x': center_x,
                    'y': center_y,
                    'accuracy_radius': avg_distance
                },
                'confidence': min(1.0, len(signal_samples) / 5.0),
                'method': 'RSSI Triangulation'
            }
        
        return {'error': 'Insufficient data for accurate triangulation'}
    
    def verify_wpa_security(self, network):
        """Verify WPA/WPA2/WPA3 security configuration"""
        security_analysis = {
            'wpa_version': 'Unknown',
            'encryption_strength': 'Unknown',
            'pmf_enabled': False,
            'security_issues': []
        }
        
        auth = network.get('authentication', '').lower()
        enc = network.get('encryption', '').lower()
        
        # Determine WPA version
        if 'wpa3' in auth:
            security_analysis['wpa_version'] = 'WPA3'
        elif 'wpa2' in auth:
            security_analysis['wpa_version'] = 'WPA2'
        elif 'wpa' in auth:
            security_analysis['wpa_version'] = 'WPA'
        else:
            security_analysis['wpa_version'] = 'None'
            security_analysis['security_issues'].append('No WPA authentication')
        
        # Determine encryption strength
        if 'ccmp' in enc or 'aes' in enc:
            security_analysis['encryption_strength'] = 'Strong (AES-CCMP)'
        elif 'tkip' in enc:
            security_analysis['encryption_strength'] = 'Weak (TKIP)'
            security_analysis['security_issues'].append('TKIP encryption is deprecated')
        elif 'wep' in enc:
            security_analysis['encryption_strength'] = 'Very Weak (WEP)'
            security_analysis['security_issues'].append('WEP encryption is broken')
        else:
            security_analysis['encryption_strength'] = 'None'
            security_analysis['security_issues'].append('No encryption')
        
        # PMF (Protected Management Frames) - simplified detection
        # In practice, this would require deeper packet analysis
        if 'wpa3' in auth:
            security_analysis['pmf_enabled'] = True
        
        return security_analysis
    
    def _load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.known_aps = config.get('known_aps', [])
                    print(f"[*] Loaded {len(self.known_aps)} known APs from config")
        except Exception as e:
            print(f"[!] Error loading config: {e}")
            self.known_aps = []
    
    def save_config(self):
        """Save configuration to file"""
        try:
            config = {
                'known_aps': self.known_aps,
                'detection_thresholds': {
                    'rssi_variance_threshold': self.rssi_variance_threshold,
                    'beacon_interval_threshold': self.beacon_interval_threshold,
                    'channel_hop_threshold': self.channel_hop_threshold,
                    'probe_response_threshold': self.probe_response_threshold
                },
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"[*] Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"[!] Error saving config: {e}")
    
    def add_known_ap(self, ssid, bssid, location=""):
        """Add a known AP to the whitelist"""
        ap = {
            'ssid': ssid,
            'bssid': bssid,
            'location': location,
            'added_date': datetime.now().isoformat()
        }
        
        # Check if already exists
        for known_ap in self.known_aps:
            if known_ap['bssid'] == bssid:
                print(f"[!] AP {bssid} already exists in known APs")
                return False
        
        self.known_aps.append(ap)
        self.save_config()
        print(f"[*] Added known AP: {ssid} ({bssid})")
        return True
    
    def remove_known_ap(self, bssid):
        """Remove a known AP from the whitelist"""
        for i, ap in enumerate(self.known_aps):
            if ap['bssid'] == bssid:
                removed_ap = self.known_aps.pop(i)
                self.save_config()
                print(f"[*] Removed known AP: {removed_ap['ssid']} ({bssid})")
                return True
        
        print(f"[!] AP {bssid} not found in known APs")
        return False
    
    def get_detection_summary(self):
        """Get summary of detection capabilities and recent findings"""
        summary = {
            'detection_capabilities': [
                'RF Fingerprinting',
                'Evil Twin Detection',
                'Channel Hopping Detection',
                'RSSI Anomaly Detection',
                'Beacon Frame Analysis',
                'Karma Attack Detection',
                'WPA/WPA2/WPA3 Validation',
                'PMF Verification',
                'Captive Portal Detection',
                'AP Geolocation'
            ],
            'known_aps_count': len(self.known_aps),
            'recent_detections': len(self.detected_aps),
            'last_scan_time': None
        }
        
        if self.detected_aps:
            summary['last_scan_time'] = max(ap['timestamp'] for ap in self.detected_aps)
        
        return summary
