# -*- coding: utf-8 -*-
# deep_packet_inspector.py - Advanced Deep Packet Inspection Module

from scapy.all import IP, Raw, ARP, Ether
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
import ssl
import socket
import struct
import time
import re
import hashlib
from collections import defaultdict, deque
import logging

class DeepPacketInspector:
    def __init__(self):
        self.protocol_stats = defaultdict(int)
        self.port_usage = defaultdict(int)
        self.dns_queries = deque(maxlen=1000)
        self.ssl_certificates = {}
        self.anomalies = []
        self.baseline_protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 'HTTP': 0, 'HTTPS': 0}
        self.suspicious_ports = [22, 23, 80, 443, 3389, 5900, 1433, 3306, 5432]
        self.dns_tunnelling_patterns = [
            r'.*\.tk$',
            r'.*\.ml$', 
            r'.*\.ga$',
            r'.*\.cf$',
            r'.*\.nyan\.cat$',
            r'.*\.bit$',
            r'.*\.onion$'
        ]
        
    def analyze_packet(self, packet):
        """Perform comprehensive packet analysis"""
        # Handle dictionary input (from GUI simulation)
        if isinstance(packet, dict):
            return self._analyze_packet_dict(packet)
        
        # Original Scapy packet analysis
        analysis_result = {
            'timestamp': time.time(),
            'protocols': [],
            'anomalies': [],
            'risk_score': 0,
            'details': {}
        }
        
        # Layer 2 Analysis
        if packet.haslayer(Ether):
            analysis_result['details']['ethernet'] = {
                'src_mac': packet[Ether].src,
                'dst_mac': packet[Ether].dst,
                'type': hex(packet[Ether].type)
            }
        
        # Layer 3 Analysis
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            analysis_result['details']['ip'] = {
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'ttl': ip_layer.ttl,
                'id': ip_layer.id,
                'flags': ip_layer.flags
            }
            
            # Check for IP anomalies
            self._analyze_ip_anomalies(ip_layer, analysis_result)
        
        # Layer 4 Analysis
        if packet.haslayer(TCP):
            self._analyze_tcp_packet(packet, analysis_result)
        elif packet.haslayer(UDP):
            self._analyze_udp_packet(packet, analysis_result)
        elif packet.haslayer(ICMP):
            self._analyze_icmp_packet(packet, analysis_result)
        
        # Application Layer Analysis
        if packet.haslayer(DNS):
            self._analyze_dns_packet(packet, analysis_result)
        elif packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            self._analyze_http_packet(packet, analysis_result)
        
        # SSL/TLS Analysis
        if self._is_ssl_tls_packet(packet):
            self._analyze_ssl_tls_packet(packet, analysis_result)
        
        # Protocol Anomaly Detection
        self._detect_protocol_anomalies(analysis_result)
        
        return analysis_result
    
    def _analyze_tcp_packet(self, packet, analysis_result):
        """Analyze TCP packet for anomalies"""
        tcp_layer = packet[TCP]
        analysis_result['protocols'].append('TCP')
        self.protocol_stats['TCP'] += 1
        
        tcp_details = {
            'src_port': tcp_layer.sport,
            'dst_port': tcp_layer.dport,
            'seq': tcp_layer.seq,
            'ack': tcp_layer.ack,
            'flags': str(tcp_layer.flags),
            'window': tcp_layer.window,
            'options': tcp_layer.options
        }
        analysis_result['details']['tcp'] = tcp_details
        
        # Check for unusual port usage
        if tcp_layer.dport in self.suspicious_ports or tcp_layer.sport in self.suspicious_ports:
            analysis_result['anomalies'].append({
                'type': 'SUSPICIOUS_PORT_USAGE',
                'severity': 'MEDIUM',
                'description': f'Traffic on suspicious port {tcp_layer.dport}/{tcp_layer.sport}'
            })
            analysis_result['risk_score'] += 20
        
        # Check for HTTP on non-standard ports
        if tcp_layer.dport not in [80, 8080, 8000, 443] and self._is_http_traffic(packet):
            analysis_result['anomalies'].append({
                'type': 'HTTP_NON_STANDARD_PORT',
                'severity': 'HIGH',
                'description': f'HTTP traffic detected on non-standard port {tcp_layer.dport}'
            })
            analysis_result['risk_score'] += 35
        
        # Port usage tracking
        self.port_usage[tcp_layer.dport] += 1
        
        # TCP flag anomalies
        if tcp_layer.flags == 0x02:  # SYN only
            pass  # Normal connection start
        elif tcp_layer.flags == 0x12:  # SYN-ACK
            pass  # Normal connection response
        elif tcp_layer.flags == 0x10:  # ACK only
            pass  # Normal data
        elif tcp_layer.flags == 0x11:  # FIN-ACK
            pass  # Normal connection close
        elif tcp_layer.flags == 0x04:  # RST
            analysis_result['anomalies'].append({
                'type': 'TCP_RESET',
                'severity': 'LOW',
                'description': 'TCP connection reset detected'
            })
            analysis_result['risk_score'] += 10
        
        # Check for port scanning
        if tcp_layer.flags == 0x02 and len(self.port_usage) > 50:
            analysis_result['anomalies'].append({
                'type': 'POTENTIAL_PORT_SCAN',
                'severity': 'HIGH',
                'description': 'Multiple SYN flags detected - possible port scan'
            })
            analysis_result['risk_score'] += 40
    
    def _analyze_udp_packet(self, packet, analysis_result):
        """Analyze UDP packet for anomalies"""
        udp_layer = packet[UDP]
        analysis_result['protocols'].append('UDP')
        self.protocol_stats['UDP'] += 1
        
        udp_details = {
            'src_port': udp_layer.sport,
            'dst_port': udp_layer.dport,
            'len': udp_layer.len,
            'chksum': udp_layer.chksum
        }
        analysis_result['details']['udp'] = udp_details
        
        # Check for suspicious UDP ports
        if udp_layer.dport in [53, 123, 161, 162, 500, 4500]:
            pass  # Common UDP services
        elif udp_layer.dport > 49152:
            pass  # Dynamic/private ports
        else:
            analysis_result['anomalies'].append({
                'type': 'UNUSUAL_UDP_PORT',
                'severity': 'MEDIUM',
                'description': f'UDP traffic on unusual port {udp_layer.dport}'
            })
            analysis_result['risk_score'] += 15
        
        self.port_usage[udp_layer.dport] += 1
    
    def _analyze_icmp_packet(self, packet, analysis_result):
        """Analyze ICMP packet for anomalies"""
        icmp_layer = packet[ICMP]
        analysis_result['protocols'].append('ICMP')
        self.protocol_stats['ICMP'] += 1
        
        icmp_details = {
            'type': icmp_layer.type,
            'code': icmp_layer.code,
            'id': icmp_layer.id,
            'seq': icmp_layer.seq
        }
        analysis_result['details']['icmp'] = icmp_details
        
        # Check for ICMP tunneling
        if icmp_layer.type == 8:  # Echo request
            if packet.haslayer(Raw) and len(packet[Raw].load) > 64:
                analysis_result['anomalies'].append({
                    'type': 'ICMP_TUNNELING',
                    'severity': 'HIGH',
                    'description': 'Large ICMP packet detected - possible tunneling'
                })
                analysis_result['risk_score'] += 30
        
        # Check for ICMP flood
        if self.protocol_stats['ICMP'] > 100:
            analysis_result['anomalies'].append({
                'type': 'ICMP_FLOOD',
                'severity': 'HIGH',
                'description': 'High volume of ICMP traffic detected'
            })
            analysis_result['risk_score'] += 35
    
    def _analyze_dns_packet(self, packet, analysis_result):
        """Analyze DNS packet for anomalies and tunneling"""
        dns_layer = packet[DNS]
        analysis_result['protocols'].append('DNS')
        self.protocol_stats['DNS'] += 1
        
        dns_details = {
            'id': dns_layer.id,
            'qr': dns_layer.qr,
            'opcode': dns_layer.opcode,
            'aa': dns_layer.aa,
            'tc': dns_layer.tc,
            'rd': dns_layer.rd,
            'ra': dns_layer.ra,
            'z': dns_layer.z,
            'rcode': dns_layer.rcode
        }
        analysis_result['details']['dns'] = dns_details
        
        # DNS Query Analysis
        if dns_layer.qr == 0 and dns_layer.qd:  # Query
            for qd in dns_layer.qd:
                query_name = qd.qname.decode('utf-8').rstrip('.')
                dns_details['query'] = query_name
                
                # Store query for analysis
                self.dns_queries.append({
                    'timestamp': time.time(),
                    'query': query_name,
                    'type': qd.qtype
                })
                
                # DNS Tunneling Detection
                for pattern in self.dns_tunnelling_patterns:
                    if re.match(pattern, query_name):
                        analysis_result['anomalies'].append({
                            'type': 'DNS_TUNNELING',
                            'severity': 'CRITICAL',
                            'description': f'DNS tunneling detected: {query_name}'
                        })
                        analysis_result['risk_score'] += 50
                
                # Check for unusually long domain names
                if len(query_name) > 100:
                    analysis_result['anomalies'].append({
                        'type': 'LONG_DOMAIN_NAME',
                        'severity': 'MEDIUM',
                        'description': f'Unusually long domain name: {query_name[:50]}...'
                    })
                    analysis_result['risk_score'] += 20
                
                # Check for high entropy domains (DGA)
                if self._calculate_entropy(query_name) > 4.5:
                    analysis_result['anomalies'].append({
                        'type': 'DGA_DOMAIN',
                        'severity': 'HIGH',
                        'description': f'High entropy domain detected: {query_name}'
                    })
                    analysis_result['risk_score'] += 35
        
        # DNS Response Analysis
        if dns_layer.qr == 1 and dns_layer.an:  # Response with answers
            for an in dns_layer.an:
                if hasattr(an, 'rdata'):
                    dns_details['response'] = str(an.rdata)
                    
                    # Check for suspicious DNS responses
                    if an.type == 1:  # A record
                        ip_addr = str(an.rdata)
                        if self._is_suspicious_ip(ip_addr):
                            analysis_result['anomalies'].append({
                                'type': 'SUSPICIOUS_DNS_RESPONSE',
                                'severity': 'MEDIUM',
                                'description': f'DNS resolving to suspicious IP: {ip_addr}'
                            })
                            analysis_result['risk_score'] += 25
    
    def _analyze_http_packet(self, packet, analysis_result):
        """Analyze HTTP packet for anomalies"""
        analysis_result['protocols'].append('HTTP')
        self.protocol_stats['HTTP'] += 1
        
        http_details = {}
        
        if packet.haslayer(HTTPRequest):
            http_req = packet[HTTPRequest]
            http_details.update({
                'method': http_req.Method.decode('utf-8') if http_req.Method else 'UNKNOWN',
                'path': http_req.Path.decode('utf-8') if http_req.Path else '/',
                'version': http_req.Http_Version.decode('utf-8') if http_req.Http_Version else 'HTTP/1.1',
                'host': http_req.Host.decode('utf-8') if http_req.Host else 'UNKNOWN',
                'user_agent': http_req.User_Agent.decode('utf-8') if http_req.User_Agent else 'UNKNOWN'
            })
            
            # Check for suspicious HTTP methods
            if http_details['method'] not in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']:
                analysis_result['anomalies'].append({
                    'type': 'SUSPICIOUS_HTTP_METHOD',
                    'severity': 'MEDIUM',
                    'description': f'Unusual HTTP method: {http_details["method"]}'
                })
                analysis_result['risk_score'] += 20
            
            # Check for suspicious User-Agents
            suspicious_ua_patterns = [
                r'.*bot.*',
                r'.*crawler.*',
                r'.*scanner.*',
                r'.*nikto.*',
                r'.*nmap.*',
                r'.*sqlmap.*'
            ]
            
            for pattern in suspicious_ua_patterns:
                if re.match(pattern, http_details['user_agent'], re.IGNORECASE):
                    analysis_result['anomalies'].append({
                        'type': 'SUSPICIOUS_USER_AGENT',
                        'severity': 'HIGH',
                        'description': f'Suspicious User-Agent detected: {http_details["user_agent"][:50]}...'
                    })
                    analysis_result['risk_score'] += 30
                    break
        
        elif packet.haslayer(HTTPResponse):
            http_resp = packet[HTTPResponse]
            http_details.update({
                'status_code': int(http_resp.Status_Code.decode('utf-8')) if http_resp.Status_Code else 200,
                'reason_phrase': http_resp.Reason_Phrase.decode('utf-8') if http_resp.Reason_Phrase else 'OK'
            })
            
            # Check for unusual HTTP status codes
            if http_details['status_code'] not in [200, 201, 202, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]:
                analysis_result['anomalies'].append({
                    'type': 'UNUSUAL_HTTP_STATUS',
                    'severity': 'LOW',
                    'description': f'Unusual HTTP status code: {http_details["status_code"]}'
                })
                analysis_result['risk_score'] += 10
        
        analysis_result['details']['http'] = http_details
    
    def _analyze_ssl_tls_packet(self, packet, analysis_result):
        """Analyze SSL/TLS packet for certificate validation"""
        analysis_result['protocols'].append('SSL/TLS')
        self.protocol_stats['HTTPS'] += 1
        
        # Basic SSL/TLS detection
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if len(payload) >= 6:
                # Check for TLS handshake
                if payload[0] == 0x16:  # Handshake message
                    analysis_result['details']['ssl_tls'] = {
                        'type': 'HANDSHAKE',
                        'version': f"{payload[1]}.{payload[2]}",
                        'length': struct.unpack('>H', payload[3:5])[0]
                    }
                    
                    # Certificate validation would require deeper packet analysis
                    # For now, we'll flag any SSL/TLS on non-standard ports
                    if packet.haslayer(TCP):
                        tcp_layer = packet[TCP]
                        if tcp_layer.dport not in [443, 8443]:
                            analysis_result['anomalies'].append({
                                'type': 'SSL_NON_STANDARD_PORT',
                                'severity': 'MEDIUM',
                                'description': f'SSL/TLS traffic on non-standard port {tcp_layer.dport}'
                            })
                            analysis_result['risk_score'] += 25
    
    def _analyze_ip_anomalies(self, ip_layer, analysis_result):
        """Analyze IP layer for anomalies"""
        # Check for TTL anomalies
        if ip_layer.ttl < 32:
            analysis_result['anomalies'].append({
                'type': 'LOW_TTL',
                'severity': 'MEDIUM',
                'description': f'Low TTL value: {ip_layer.ttl}'
            })
            analysis_result['risk_score'] += 15
        
        # Check for IP fragmentation
        if ip_layer.flags & 0x1:  # MF flag
            analysis_result['anomalies'].append({
                'type': 'IP_FRAGMENTATION',
                'severity': 'LOW',
                'description': 'IP packet fragmentation detected'
            })
            analysis_result['risk_score'] += 10
        
        # Check for reserved/private IPs in unusual places
        if self._is_private_ip(ip_layer.src) and not self._is_private_ip(ip_layer.dst):
            analysis_result['anomalies'].append({
                'type': 'PRIVATE_TO_PUBLIC',
                'severity': 'LOW',
                'description': f'Traffic from private IP {ip_layer.src} to public IP {ip_layer.dst}'
            })
    
    def _detect_protocol_anomalies(self, analysis_result):
        """Detect protocol distribution anomalies"""
        total_packets = sum(self.protocol_stats.values())
        if total_packets > 100:
            for protocol, count in self.protocol_stats.items():
                percentage = (count / total_packets) * 100
                
                # Flag unusual protocol distributions
                if protocol == 'ICMP' and percentage > 20:
                    analysis_result['anomalies'].append({
                        'type': 'HIGH_ICMP_RATIO',
                        'severity': 'MEDIUM',
                        'description': f'High ICMP traffic ratio: {percentage:.1f}%'
                    })
                    analysis_result['risk_score'] += 20
                elif protocol == 'DNS' and percentage > 30:
                    analysis_result['anomalies'].append({
                        'type': 'HIGH_DNS_RATIO',
                        'severity': 'MEDIUM',
                        'description': f'High DNS traffic ratio: {percentage:.1f}%'
                    })
                    analysis_result['risk_score'] += 20
    
    def _is_ssl_tls_packet(self, packet):
        """Check if packet contains SSL/TLS traffic"""
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            # Common SSL/TLS ports
            if tcp_layer.dport in [443, 8443, 993, 995, 465, 636, 989, 990]:
                return True
            # Check for TLS handshake signature
            if packet.haslayer(Raw) and len(packet[Raw].load) >= 6:
                payload = packet[Raw].load
                return payload[0] == 0x16  # Handshake message
        return False
    
    def _is_http_traffic(self, packet):
        """Check if packet contains HTTP traffic"""
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if isinstance(payload, bytes):
                try:
                    text = payload[:100].decode('utf-8', errors='ignore')
                    return any(method in text.upper() for method in ['GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE '])
                except:
                    pass
        return False
    
    def _is_suspicious_ip(self, ip_addr):
        """Check if IP address is suspicious"""
        try:
            parts = list(map(int, ip_addr.split('.')))
            # Check for known suspicious ranges
            if parts[0] == 0 or parts[0] == 127 or parts[0] >= 224:
                return True
            # Check for bogon IPs
            if parts[0] == 169 and parts[1] == 254:
                return True
            if parts[0] == 100 and parts[1] >= 64 and parts[1] <= 127:
                return True
        except:
            pass
        return False
    
    def _is_private_ip(self, ip_addr):
        """Check if IP address is private"""
        try:
            parts = list(map(int, ip_addr.split('.')))
            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
        except:
            pass
        return False
    
    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        entropy = 0
        for char in set(string):
            p = string.count(char) / len(string)
            entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    def get_protocol_statistics(self):
        """Get current protocol distribution statistics"""
        total = sum(self.protocol_stats.values())
        if total == 0:
            return {}
        
        stats = {}
        for protocol, count in self.protocol_stats.items():
            stats[protocol] = {
                'count': count,
                'percentage': (count / total) * 100
            }
        
        return stats
    
    def get_recent_dns_queries(self, limit=50):
        """Get recent DNS queries for analysis"""
        return list(self.dns_queries)[-limit:]
    
    def reset_statistics(self):
        """Reset all statistics for new monitoring session"""
        self.protocol_stats.clear()
        self.port_usage.clear()
        self.dns_queries.clear()
        self.anomalies.clear()
    
    def _analyze_packet_dict(self, packet_data):
        """Analyze packet from dictionary input (GUI simulation)"""
        analysis_result = {
            'timestamp': time.time(),
            'protocols': [],
            'anomalies': [],
            'risk_score': 0,
            'details': {}
        }
        
        # Extract packet information from dictionary
        size = packet_data.get('size', 1500)
        protocol = packet_data.get('protocol', 'TCP')
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        flags = packet_data.get('flags', 0)
        src_ip = packet_data.get('src_ip', '0.0.0.0')
        dst_ip = packet_data.get('dst_ip', '0.0.0.0')
        
        # Protocol detection
        analysis_result['protocols'].append(protocol)
        self.protocol_stats[protocol] += 1
        
        # Port usage analysis
        if src_port > 0:
            self.port_usage[src_port] += 1
        if dst_port > 0:
            self.port_usage[dst_port] += 1
        
        # Store packet details
        analysis_result['details'] = {
            'size': size,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'flags': flags,
            'src_ip': src_ip,
            'dst_ip': dst_ip
        }
        
        # Protocol-specific analysis
        if protocol == 'TCP':
            analysis_result['protocols'].append('TCP')
            self._analyze_tcp_dict(packet_data, analysis_result)
        elif protocol == 'UDP':
            analysis_result['protocols'].append('UDP')
            self._analyze_udp_dict(packet_data, analysis_result)
        elif protocol == 'ICMP':
            analysis_result['protocols'].append('ICMP')
            self._analyze_icmp_dict(packet_data, analysis_result)
        
        # Check for suspicious ports
        if dst_port in self.suspicious_ports or src_port in self.suspicious_ports:
            analysis_result['anomalies'].append({
                'type': 'SUSPICIOUS_PORT',
                'severity': 'MEDIUM',
                'description': f'Traffic on suspicious port {dst_port or src_port}'
            })
            analysis_result['risk_score'] += 20
        
        # Check for unusual packet size
        if size > 8000:  # Unusually large packet
            analysis_result['anomalies'].append({
                'type': 'LARGE_PACKET',
                'severity': 'MEDIUM',
                'description': f'Unusually large packet size: {size} bytes'
            })
            analysis_result['risk_score'] += 15
        
        # Check for protocol anomalies
        if protocol not in ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS']:
            analysis_result['anomalies'].append({
                'type': 'UNKNOWN_PROTOCOL',
                'severity': 'LOW',
                'description': f'Unknown protocol: {protocol}'
            })
            analysis_result['risk_score'] += 10
        
        # Cap risk score at 100
        analysis_result['risk_score'] = min(analysis_result['risk_score'], 100)
        
        return analysis_result
    
    def _analyze_tcp_dict(self, packet_data, analysis_result):
        """Analyze TCP packet from dictionary"""
        dst_port = packet_data.get('dst_port', 0)
        flags = packet_data.get('flags', 0)
        
        # Check for common TCP flags
        if flags & 0x02:  # SYN flag
            analysis_result['protocols'].append('TCP_HANDSHAKE')
        
        # Check for suspicious TCP ports
        if dst_port in [22, 23, 3389, 5900]:  # SSH, RDP, VNC
            analysis_result['anomalies'].append({
                'type': 'REMOTE_ACCESS_TRAFFIC',
                'severity': 'MEDIUM',
                'description': f'Traffic to remote access port {dst_port}'
            })
            analysis_result['risk_score'] += 25
    
    def _analyze_udp_dict(self, packet_data, analysis_result):
        """Analyze UDP packet from dictionary"""
        dst_port = packet_data.get('dst_port', 0)
        
        # Check for DNS traffic
        if dst_port == 53:
            analysis_result['protocols'].append('DNS')
            # Simulate DNS analysis
            if packet_data.get('size', 0) > 512:  # Large DNS response
                analysis_result['anomalies'].append({
                    'type': 'LARGE_DNS_RESPONSE',
                    'severity': 'MEDIUM',
                    'description': 'Unusually large DNS response'
                })
                analysis_result['risk_score'] += 20
    
    def _analyze_icmp_dict(self, packet_data, analysis_result):
        """Analyze ICMP packet from dictionary"""
        size = packet_data.get('size', 0)
        
        # Check for ICMP tunneling
        if size > 64:  # Large ICMP payload
            analysis_result['anomalies'].append({
                'type': 'ICMP_TUNNELING',
                'severity': 'HIGH',
                'description': f'Possible ICMP tunneling (payload size: {size})'
            })
            analysis_result['risk_score'] += 35
