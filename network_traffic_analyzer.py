# -*- coding: utf-8 -*-
# network_traffic_analyzer.py - Network Traffic Analysis with NetFlow/sFlow Integration

import time
import threading
import socket
import struct
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging

class NetworkTrafficAnalyzer:
    def __init__(self):
        self.flows = {}
        self.bandwidth_usage = defaultdict(int)
        self.applications = defaultdict(int)
        self.connections = defaultdict(list)
        self.suspicious_ips = set()
        self.ddos_threshold = 1000  # packets per second
        self.exfil_threshold = 100 * 1024 * 1024  # 100MB
        
        # NetFlow/sFlow templates
        self.netflow_template = {
            'version': 9,
            'count': 0,
            'uptime': 0,
            'time_sec': 0,
            'time_nanosec': 0,
            'flow_sequence': 0,
            'engine_type': 0,
            'engine_id': 0,
            'sampling_interval': 0
        }
        
    def analyze_packet(self, packet):
        """Analyze network packet for traffic patterns"""
        try:
            if not packet.haslayer('IP'):
                return None
                
            ip_layer = packet['IP']
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            size = len(packet)
            
            # Create flow key
            flow_key = f"{src_ip}:{dst_ip}:{protocol}"
            
            # Update flow statistics
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'packets': 0,
                    'bytes': 0,
                    'start_time': time.time(),
                    'last_seen': time.time(),
                    'flags': set()
                }
            
            self.flows[flow_key]['packets'] += 1
            self.flows[flow_key]['bytes'] += size
            self.flows[flow_key]['last_seen'] = time.time()
            
            # Update bandwidth usage
            self.bandwidth_usage[src_ip] += size
            self.bandwidth_usage[dst_ip] += size
            
            # Application identification
            app = self._identify_application(packet)
            self.applications[app] += 1
            
            # Connection tracking
            self.connections[src_ip].append({
                'dst_ip': dst_ip,
                'timestamp': time.time(),
                'protocol': protocol,
                'size': size
            })
            
            # Check for anomalies
            self._check_anomalies(flow_key, src_ip, dst_ip, size)
            
            return self.flows[flow_key]
            
        except Exception as e:
            logging.error(f"Error analyzing packet: {e}")
            return None
    
    def _identify_application(self, packet):
        """Identify application based on port and protocol"""
        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            dst_port = tcp_layer.dport
            src_port = tcp_layer.sport
            
            # Common application ports
            port_apps = {
                80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 23: 'Telnet',
                25: 'SMTP', 110: 'POP3', 143: 'IMAP',
                53: 'DNS', 67: 'DHCP', 68: 'DHCP',
                20: 'FTP', 21: 'FTP', 3389: 'RDP',
                5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
            }
            
            return port_apps.get(dst_port, port_apps.get(src_port, f'TCP-{dst_port}'))
        
        elif packet.haslayer('UDP'):
            udp_layer = packet['UDP']
            dst_port = udp_layer.dport
            
            udp_apps = {
                53: 'DNS', 67: 'DHCP', 123: 'NTP',
                161: 'SNMP', 162: 'SNMP-Trap', 500: 'IPSec',
                4500: 'IPSec-NAT', 514: 'Syslog'
            }
            
            return udp_apps.get(dst_port, f'UDP-{dst_port}')
        
        return 'Unknown'
    
    def _check_anomalies(self, flow_key, src_ip, dst_ip, size):
        """Check for traffic anomalies"""
        current_time = time.time()
        flow = self.flows[flow_key]
        
        # Check for data exfiltration
        if flow['bytes'] > self.exfil_threshold:
            self.suspicious_ips.add(src_ip)
            logging.warning(f"Potential data exfiltration from {src_ip}: {flow['bytes']} bytes")
        
        # Check for DDoS patterns
        recent_flows = [f for f in self.flows.values() 
                       if current_time - f['last_seen'] < 60]
        
        if len(recent_flows) > self.ddos_threshold:
            logging.warning(f"Potential DDoS attack detected: {len(recent_flows)} flows/second")
        
        # Check for C&C communication
        if self._is_cc_communication(src_ip, dst_ip):
            self.suspicious_ips.add(src_ip)
            logging.warning(f"Potential C&C communication: {src_ip} -> {dst_ip}")
    
    def _is_cc_communication(self, src_ip, dst_ip):
        """Check for Command & Control communication patterns"""
        # Simple heuristic: regular communication to suspicious destinations
        suspicious_dsts = self.connections[src_ip]
        if len(suspicious_dsts) > 10:
            # Check if communication is very regular (same timing)
            intervals = []
            for i in range(1, len(suspicious_dsts)):
                interval = suspicious_dsts[i]['timestamp'] - suspicious_dsts[i-1]['timestamp']
                intervals.append(interval)
            
            if len(intervals) > 5:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                
                # Low variance suggests automated/beacon communication
                if variance < 10:  # Very regular timing
                    return True
        
        return False
    
    def get_bandwidth_usage(self):
        """Get bandwidth usage per device"""
        total_bandwidth = sum(self.bandwidth_usage.values())
        usage_percent = {}
        
        for ip, bytes_used in self.bandwidth_usage.items():
            if total_bandwidth > 0:
                usage_percent[ip] = (bytes_used / total_bandwidth) * 100
            else:
                usage_percent[ip] = 0
        
        return usage_percent
    
    def get_top_applications(self, limit=10):
        """Get top applications by traffic volume"""
        sorted_apps = sorted(self.applications.items(), 
                         key=lambda x: x[1], reverse=True)
        return sorted_apps[:limit]
    
    def get_connection_summary(self):
        """Get connection summary showing who talks to whom"""
        summary = {}
        
        for src_ip, connections in self.connections.items():
            dst_count = defaultdict(int)
            for conn in connections:
                dst_count[conn['dst_ip']] += 1
            
            summary[src_ip] = dict(dst_count)
        
        return summary
    
    def detect_data_exfiltration(self, threshold_mb=100):
        """Detect potential data exfiltration"""
        exfil_suspects = []
        threshold_bytes = threshold_mb * 1024 * 1024
        
        for flow_key, flow in self.flows.items():
            if flow['bytes'] > threshold_bytes:
                exfil_suspects.append({
                    'flow_key': flow_key,
                    'src_ip': flow['src_ip'],
                    'dst_ip': flow['dst_ip'],
                    'bytes_transferred': flow['bytes'],
                    'risk_level': 'HIGH' if flow['bytes'] > threshold_bytes * 2 else 'MEDIUM'
                })
        
        return exfil_suspects
    
    def detect_ddos_attack(self):
        """Detect potential DDoS attacks"""
        current_time = time.time()
        recent_flows = []
        
        for flow in self.flows.values():
            if current_time - flow['last_seen'] < 60:  # Last minute
                recent_flows.append(flow)
        
        # Group by destination
        dst_counts = defaultdict(int)
        for flow in recent_flows:
            dst_counts[flow['dst_ip']] += flow['packets']
        
        ddos_targets = []
        for dst_ip, packet_count in dst_counts.items():
            if packet_count > self.ddos_threshold:
                ddos_targets.append({
                    'target_ip': dst_ip,
                    'packets_per_second': packet_count,
                    'attack_type': 'Volumetric DDoS',
                    'severity': 'HIGH' if packet_count > self.ddos_threshold * 2 else 'MEDIUM'
                })
        
        return ddos_targets
    
    def generate_netflow_record(self, flow):
        """Generate NetFlow v9 record"""
        record = self.netflow_template.copy()
        record.update({
            'count': flow['packets'],
            'bytes': flow['bytes'],
            'src_ip': flow['src_ip'],
            'dst_ip': flow['dst_ip'],
            'protocol': flow['protocol'],
            'time_sec': int(flow['start_time']),
            'time_nanosec': int((flow['start_time'] % 1) * 1e9)
        })
        return record
    
    def generate_traffic_report(self):
        """Generate comprehensive traffic analysis report"""
        current_time = datetime.now()
        
        report = {
            'timestamp': current_time.isoformat(),
            'total_flows': len(self.flows),
            'total_bandwidth': sum(self.bandwidth_usage.values()),
            'top_applications': self.get_top_applications(10),
            'bandwidth_usage': self.get_bandwidth_usage(),
            'connection_summary': self.get_connection_summary(),
            'data_exfiltration_suspects': self.detect_data_exfiltration(),
            'ddos_attacks': self.detect_ddos_attack(),
            'suspicious_ips': list(self.suspicious_ips)
        }
        
        return report
    
    def start_monitoring(self, interface, duration=300):
        """Start traffic monitoring for specified duration"""
        try:
            from scapy.all import sniff, IP
            
            logging.info(f"Starting traffic monitoring on {interface} for {duration}s")
            
            def packet_handler(packet):
                self.analyze_packet(packet)
            
            # Start packet capture
            sniff(iface=interface, prn=packet_handler, 
                  timeout=duration, store=0)
            
            logging.info("Traffic monitoring completed")
            return self.generate_traffic_report()
            
        except Exception as e:
            logging.error(f"Error in traffic monitoring: {e}")
            return None
    
    def reset_statistics(self):
        """Reset all traffic statistics"""
        self.flows.clear()
        self.bandwidth_usage.clear()
        self.applications.clear()
        self.connections.clear()
        self.suspicious_ips.clear()
        logging.info("Traffic statistics reset")
