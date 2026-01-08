# -*- coding: utf-8 -*-
# advanced_attack_detector.py - Advanced Attack Detection Beyond ARP Spoofing

import time
import threading
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether

class AdvancedAttackDetector:
    def __init__(self):
        self.attack_alerts = deque(maxlen=1000)
        self.monitoring = False
        self.statistics = defaultdict(int)
        
        # Attack detection thresholds
        self.syn_flood_threshold = 1000  # SYN packets/second
        self.udp_flood_threshold = 1000  # UDP packets/second
        self.icmp_flood_threshold = 500  # ICMP packets/second
        self.port_scan_threshold = 50  # ports scanned per minute
        self.mac_flood_threshold = 1000  # MAC changes per minute
        
        # Tracking data
        self.connection_tracking = defaultdict(list)
        self.port_scan_tracking = defaultdict(set)
        self.mac_changes = defaultdict(list)
        self.packet_counts = defaultdict(int)
        self.stp_frames = defaultdict(int)
        
    def start_monitoring(self, interface, duration=60):
        """Start advanced attack detection monitoring"""
        self.monitoring = True
        start_time = time.time()
        
        logging.info(f"Starting advanced attack detection on {interface} for {duration}s")
        
        try:
            # Start packet capture
            sniff(
                iface=interface,
                prn=self._process_packet,
                timeout=duration,
                store=0
            )
        except Exception as e:
            logging.error(f"Error in advanced attack detection: {e}")
        
        self.monitoring = False
        logging.info("Advanced attack detection stopped")
        
        return self.generate_attack_report()
    
    def _process_packet(self, packet):
        """Process packets for advanced attack detection"""
        try:
            current_time = time.time()
            
            # Update packet statistics
            self._update_packet_stats(packet, current_time)
            
            # Layer 2 Attacks
            if packet.haslayer(Ether):
                self._detect_layer2_attacks(packet, current_time)
            
            # Layer 3 Attacks
            if packet.haslayer(IP):
                self._detect_layer3_attacks(packet, current_time)
            
            # Layer 4 Attacks
            if packet.haslayer(TCP):
                self._detect_tcp_attacks(packet, current_time)
            elif packet.haslayer(UDP):
                self._detect_udp_attacks(packet, current_time)
            elif packet.haslayer(ICMP):
                self._detect_icmp_attacks(packet, current_time)
                
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def _update_packet_stats(self, packet, current_time):
        """Update packet statistics for rate limiting"""
        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                protocol = ip_layer.proto
                
                # Count packets per second
                time_bucket = int(current_time)
                self.packet_counts[(protocol, time_bucket)] += 1
                
        except Exception as e:
            logging.error(f"Error updating packet stats: {e}")
    
    def _detect_layer2_attacks(self, packet, current_time):
        """Detect Layer 2 attacks"""
        try:
            ether_layer = packet[Ether]
            src_mac = ether_layer.src
            dst_mac = ether_layer.dst
            
            # MAC flooding detection
            time_bucket = int(current_time // 60)  # Per minute
            self.mac_changes[(src_mac, time_bucket)].append(current_time)
            
            recent_changes = len(self.mac_changes[(src_mac, time_bucket)])
            if recent_changes > self.mac_flood_threshold:
                self._create_alert(
                    'MAC_FLOODING',
                    'HIGH',
                    f'MAC flooding detected from {src_mac}',
                    f'{recent_changes} MAC changes in 1 minute',
                    src_mac
                )
            
            # STP (Spanning Tree) attack detection
            if ether_layer.type == 0x0026:  # STP BPDU type
                self.stp_frames[time_bucket] += 1
                
                if self.stp_frames[time_bucket] > 10:  # Unusual STP activity
                    self._create_alert(
                        'STP_ATTACK',
                        'HIGH',
                        f'Suspicious STP activity detected',
                        f'{self.stp_frames[time_bucket]} STP frames in 1 minute',
                        src_mac
                    )
            
            # CAM table overflow detection
            self._detect_cam_overflow(packet, current_time)
            
        except Exception as e:
            logging.error(f"Error in Layer 2 attack detection: {e}")
    
    def _detect_layer3_attacks(self, packet, current_time):
        """Detect Layer 3 attacks"""
        try:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # IP spoofing detection
            if self._is_spoofed_ip(src_ip):
                self._create_alert(
                    'IP_SPOOFING',
                    'HIGH',
                    f'IP spoofing detected from {src_ip}',
                    f'Suspicious source IP address',
                    src_ip
                )
            
            # Fragmentation attack detection
            if ip_layer.flags & 0x1:  # More fragments flag
                self._create_alert(
                    'FRAGMENTATION_ATTACK',
                    'MEDIUM',
                    f'IP fragmentation detected',
                    f'Fragmented packet from {src_ip} to {dst_ip}',
                    src_ip
                )
                
        except Exception as e:
            logging.error(f"Error in Layer 3 attack detection: {e}")
    
    def _detect_tcp_attacks(self, packet, current_time):
        """Detect TCP-based attacks"""
        try:
            tcp_layer = packet[TCP]
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            
            # SYN flood detection
            if tcp_layer.flags & 0x02 and not (tcp_layer.flags & 0x10):  # SYN without ACK
                time_bucket = int(current_time)
                syn_count = self.packet_counts[(6, time_bucket)]  # TCP protocol = 6
                
                if syn_count > self.syn_flood_threshold:
                    self._create_alert(
                        'SYN_FLOOD',
                        'HIGH',
                        f'SYN flood detected from {src_ip}',
                        f'{syn_count} SYN packets/second',
                        src_ip
                    )
            
            # Port scan detection
            self.port_scan_tracking[src_ip].add(dst_port)
            if len(self.port_scan_tracking[src_ip]) > self.port_scan_threshold:
                self._create_alert(
                    'PORT_SCAN',
                    'MEDIUM',
                    f'Port scanning detected from {src_ip}',
                    f'Scanning {len(self.port_scan_tracking[src_ip])} ports',
                    src_ip
                )
            
            # Connection tracking for MITM detection
            self.connection_tracking[src_ip].append({
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'timestamp': current_time,
                'flags': str(tcp_layer.flags)
            })
            
            # Detect suspicious connection patterns
            self._detect_mitm_patterns(src_ip, current_time)
            
        except Exception as e:
            logging.error(f"Error in TCP attack detection: {e}")
    
    def _detect_udp_attacks(self, packet, current_time):
        """Detect UDP-based attacks"""
        try:
            udp_layer = packet[UDP]
            src_ip = packet[IP].src
            dst_port = udp_layer.dport
            
            # UDP flood detection
            time_bucket = int(current_time)
            udp_count = self.packet_counts[(17, time_bucket)]  # UDP protocol = 17
            
            if udp_count > self.udp_flood_threshold:
                self._create_alert(
                    'UDP_FLOOD',
                    'HIGH',
                    f'UDP flood detected from {src_ip}',
                    f'{udp_count} UDP packets/second to port {dst_port}',
                    src_ip
                )
            
            # Smurf attack detection (ICMP broadcast amplification)
            if dst_port == 7 and packet.haslayer(IP):
                ip_layer = packet[IP]
                if ip_layer.dst.endswith('.255'):  # Broadcast address
                    self._create_alert(
                        'SMURF_ATTACK',
                        'HIGH',
                        f'Smurf attack detected from {src_ip}',
                        f'UDP to broadcast {ip_layer.dst}',
                        src_ip
                    )
                    
        except Exception as e:
            logging.error(f"Error in UDP attack detection: {e}")
    
    def _detect_icmp_attacks(self, packet, current_time):
        """Detect ICMP-based attacks"""
        try:
            icmp_layer = packet[ICMP]
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code
            
            # ICMP flood detection
            time_bucket = int(current_time)
            icmp_count = self.packet_counts[(1, time_bucket)]  # ICMP protocol = 1
            
            if icmp_count > self.icmp_flood_threshold:
                self._create_alert(
                    'ICMP_FLOOD',
                    'HIGH',
                    f'ICMP flood detected from {src_ip}',
                    f'{icmp_count} ICMP packets/second',
                    src_ip
                )
            
            # ICMP tunneling detection
            if icmp_type in [0, 8]:  # Echo Reply/Request
                payload_size = len(packet) - 28  # ICMP header size
                if payload_size > 64:  # Unusually large ICMP payload
                    self._create_alert(
                        'ICMP_TUNNELING',
                        'MEDIUM',
                        f'ICMP tunneling detected from {src_ip}',
                        f'Large ICMP payload: {payload_size} bytes',
                        src_ip
                    )
                    
        except Exception as e:
            logging.error(f"Error in ICMP attack detection: {e}")
    
    def _detect_cam_overflow(self, packet, current_time):
        """Detect CAM table overflow attacks"""
        try:
            ether_layer = packet[Ether]
            src_mac = ether_layer.src
            
            # Track MAC address changes per switch port
            time_bucket = int(current_time // 60)
            
            # Count unique MAC addresses from this source
            recent_macs = set()
            for mac_change_time in self.mac_changes[(src_mac, time_bucket)]:
                # This is simplified - in production, track per switch port
                pass
            
            # If we see many different MAC addresses, potential CAM overflow
            if len(self.mac_changes) > 100:  # Simplified threshold
                self._create_alert(
                    'CAM_OVERFLOW',
                    'HIGH',
                    f'CAM table overflow attempt detected',
                    f'Excessive MAC address changes from {src_mac}',
                    src_mac
                )
                    
        except Exception as e:
            logging.error(f"Error in CAM overflow detection: {e}")
    
    def _detect_mitm_patterns(self, src_ip, current_time):
        """Detect Man-in-the-Middle attack patterns"""
        try:
            connections = self.connection_tracking[src_ip]
            
            if len(connections) < 10:
                return  # Not enough data
            
            # Check for session hijacking patterns
            recent_connections = [c for c in connections 
                              if current_time - c['timestamp'] < 300]  # Last 5 minutes
            
            # Multiple connections to same destination with different flags
            dst_connections = defaultdict(list)
            for conn in recent_connections:
                dst_connections[conn['dst_ip']].append(conn)
            
            for dst_ip, conns in dst_connections.items():
                if len(conns) > 3:  # Multiple connections to same destination
                    flags = [c['flags'] for c in conns]
                    unique_flags = set(flags)
                    
                    if len(unique_flags) > 2:  # Different TCP flags
                        self._create_alert(
                            'SESSION_HIJACKING',
                            'HIGH',
                            f'Session hijacking suspected from {src_ip}',
                            f'Multiple connection patterns to {dst_ip}',
                            src_ip
                        )
            
            # Check for SSL stripping patterns
            self._detect_ssl_stripping(src_ip, recent_connections)
            
        except Exception as e:
            logging.error(f"Error in MITM detection: {e}")
    
    def _detect_ssl_stripping(self, src_ip, connections):
        """Detect SSL stripping attacks"""
        try:
            # Look for HTTP connections immediately followed by HTTPS to same destination
            http_connections = [c for c in connections if c['dst_port'] == 80]
            https_connections = [c for c in connections if c['dst_port'] == 443]
            
            for http_conn in http_connections:
                for https_conn in https_connections:
                    # If HTTPS connection follows HTTP to same destination
                    if (abs(https_conn['timestamp'] - http_conn['timestamp']) < 5 and
                        https_conn['dst_ip'] == http_conn['dst_ip']):
                        
                        self._create_alert(
                            'SSL_STRIPPING',
                            'HIGH',
                            f'SSL stripping detected from {src_ip}',
                            f'HTTP to {http_conn["dst_ip"]} followed by HTTPS',
                            src_ip
                        )
                        
        except Exception as e:
            logging.error(f"Error in SSL stripping detection: {e}")
    
    def _is_spoofed_ip(self, ip):
        """Check if IP address is likely spoofed"""
        try:
            # Simple heuristics for IP spoofing detection
            if ip.startswith('0.') or ip.startswith('127.') or ip.startswith('169.254.'):
                return True  # Private/loopback addresses on public network
            
            # Check for impossible IP addresses
            octets = ip.split('.')
            if len(octets) == 4:
                if int(octets[0]) > 223 or int(octets[0]) == 0:
                    return True  # Invalid or reserved addresses
                    
            return False
        except Exception:
            return False
    
    def _create_alert(self, attack_type, severity, message, description, source):
        """Create and store attack alert"""
        alert = {
            'timestamp': time.time(),
            'type': attack_type,
            'severity': severity,
            'message': message,
            'description': description,
            'source': source,
            'attack_details': self._get_attack_details(attack_type)
        }
        
        self.attack_alerts.append(alert)
        logging.warning(f"{severity} {attack_type}: {message}")
    
    def _get_attack_details(self, attack_type):
        """Get detailed information about attack type"""
        attack_details = {
            'MAC_FLOODING': {
                'name': 'MAC Flooding Attack',
                'description': 'Overwhelming switch MAC address table',
                'mitigation': 'Port security, MAC limiting'
            },
            'STP_ATTACK': {
                'name': 'STP (Spanning Tree) Attack',
                'description': 'Manipulating network topology',
                'mitigation': 'BPDU guard, root guard'
            },
            'IP_SPOOFING': {
                'name': 'IP Spoofing Attack',
                'description': 'Faking source IP addresses',
                'mitigation': 'Ingress/egress filtering, uRPF'
            },
            'FRAGMENTATION_ATTACK': {
                'name': 'IP Fragmentation Attack',
                'description': 'Overlapping fragment attacks',
                'mitigation': 'Fragment reassembly limits'
            },
            'SYN_FLOOD': {
                'name': 'SYN Flood Attack',
                'description': 'TCP SYN packet flooding',
                'mitigation': 'SYN cookies, rate limiting'
            },
            'UDP_FLOOD': {
                'name': 'UDP Flood Attack',
                'description': 'UDP packet flooding',
                'mitigation': 'Rate limiting, filtering'
            },
            'ICMP_FLOOD': {
                'name': 'ICMP Flood Attack',
                'description': 'ICMP packet flooding',
                'mitigation': 'Rate limiting, ICMP filtering'
            },
            'SMURF_ATTACK': {
                'name': 'Smurf Attack',
                'description': 'ICMP broadcast amplification',
                'mitigation': 'Disable directed broadcast'
            },
            'ICMP_TUNNELING': {
                'name': 'ICMP Tunneling',
                'description': 'Data exfiltration via ICMP',
                'mitigation': 'ICMP filtering, inspection'
            },
            'PORT_SCAN': {
                'name': 'Port Scanning Attack',
                'description': 'Network reconnaissance',
                'mitigation': 'Port knocking detection, rate limiting'
            },
            'CAM_OVERFLOW': {
                'name': 'CAM Table Overflow',
                'description': 'Switch MAC table overflow',
                'mitigation': 'Port security, MAC limiting'
            },
            'SESSION_HIJACKING': {
                'name': 'Session Hijacking',
                'description': 'TCP session takeover',
                'mitigation': 'TCP sequence randomization'
            },
            'SSL_STRIPPING': {
                'name': 'SSL Stripping Attack',
                'description': 'Downgrading HTTPS to HTTP',
                'mitigation': 'HSTS, SSL enforcement'
            }
        }
        
        return attack_details.get(attack_type, {
            'name': 'Unknown Attack',
            'description': 'Attack type not recognized',
            'mitigation': 'General security measures'
        })
    
    def generate_attack_report(self):
        """Generate comprehensive attack detection report"""
        current_time = datetime.now()
        
        report = {
            'timestamp': current_time.isoformat(),
            'total_attacks': len(self.attack_alerts),
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'attack_types': defaultdict(int),
            'attack_sources': defaultdict(int),
            'mitigation_recommendations': []
        }
        
        # Analyze all attacks
        for alert in self.attack_alerts:
            severity = alert['severity']
            attack_type = alert['type']
            source = alert['source']
            
            # Count by severity
            if severity == 'HIGH':
                report['high_severity'] += 1
            elif severity == 'MEDIUM':
                report['medium_severity'] += 1
            else:
                report['low_severity'] += 1
            
            # Count by type
            report['attack_types'][attack_type] += 1
            
            # Count by source
            report['attack_sources'][source] += 1
        
        # Generate mitigation recommendations
        report['mitigation_recommendations'] = self._generate_mitigation_recommendations(report)
        
        return report
    
    def _generate_mitigation_recommendations(self, report):
        """Generate attack mitigation recommendations"""
        recommendations = []
        
        # Based on attack types detected
        if report['attack_types'].get('SYN_FLOOD', 0) > 0:
            recommendations.append({
                'attack': 'SYN Flood',
                'recommendation': 'Implement SYN cookies and rate limiting',
                'priority': 'HIGH'
            })
        
        if report['attack_types'].get('IP_SPOOFING', 0) > 0:
            recommendations.append({
                'attack': 'IP Spoofing',
                'recommendation': 'Enable ingress/egress filtering and uRPF',
                'priority': 'HIGH'
            })
        
        if report['attack_types'].get('PORT_SCAN', 0) > 0:
            recommendations.append({
                'attack': 'Port Scanning',
                'recommendation': 'Implement port scan detection and rate limiting',
                'priority': 'MEDIUM'
            })
        
        if report['attack_types'].get('MAC_FLOODING', 0) > 0:
            recommendations.append({
                'attack': 'MAC Flooding',
                'recommendation': 'Enable port security and MAC address limiting',
                'priority': 'HIGH'
            })
        
        if report['attack_types'].get('SSL_STRIPPING', 0) > 0:
            recommendations.append({
                'attack': 'SSL Stripping',
                'recommendation': 'Implement HSTS and enforce HTTPS',
                'priority': 'HIGH'
            })
        
        return recommendations
    
    def get_attack_summary(self):
        """Get summary of attack detection results"""
        if not self.attack_alerts:
            return {'total_attacks': 0, 'high_severity': 0, 'medium_severity': 0}
        
        total_attacks = len(self.attack_alerts)
        high_severity = sum(1 for alert in self.attack_alerts if alert['severity'] == 'HIGH')
        medium_severity = sum(1 for alert in self.attack_alerts if alert['severity'] == 'MEDIUM')
        
        return {
            'total_attacks': total_attacks,
            'high_severity': high_severity,
            'medium_severity': medium_severity,
            'low_severity': total_attacks - high_severity - medium_severity
        }
    
    def reset_detection(self):
        """Reset all attack detection data"""
        self.attack_alerts.clear()
        self.connection_tracking.clear()
        self.port_scan_tracking.clear()
        self.mac_changes.clear()
        self.packet_counts.clear()
        self.stp_frames.clear()
        logging.info("Advanced attack detection data reset")
