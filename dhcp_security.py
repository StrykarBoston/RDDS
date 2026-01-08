# -*- coding: utf-8 -*-
# dhcp_security.py - DHCP Starvation & Rogue DHCP Detection Module

import re
import time
import socket
import struct
import threading
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import IP, UDP, Ether, DHCP, BOOTP, sendp, sniff, conf

class DHCPSecurityMonitor:
    def __init__(self):
        self.dhcp_servers = {}
        self.dhcp_requests = deque(maxlen=1000)
        self.lease_table = {}
        self.suspicious_activity = []
        self.authorized_servers = []
        self.rate_limits = defaultdict(int)
        self.alerts = []
        self.monitoring = False
        self.interface = None
        
        # DHCP security thresholds
        self.request_threshold = 50  # Requests per minute
        self.lease_threshold = 200   # Maximum leases
        self.gateway_check_enabled = True
        
    def start_monitoring(self, interface='eth0'):
        """Start DHCP security monitoring"""
        self.interface = interface
        self.monitoring = True
        
        # Start packet capture thread
        monitor_thread = threading.Thread(target=self._monitor_dhcp_traffic, daemon=True)
        monitor_thread.start()
        
        logging.info(f"DHCP security monitoring started on {interface}")
        return True
    
    def stop_monitoring(self):
        """Stop DHCP security monitoring"""
        self.monitoring = False
        logging.info("DHCP security monitoring stopped")
    
    def _monitor_dhcp_traffic(self):
        """Monitor DHCP traffic for security threats"""
        try:
            sniff(filter="udp and (port 67 or port 68)", 
                  prn=self._process_dhcp_packet,
                  store=0,
                  stop_filter=lambda x: not self.monitoring)
        except Exception as e:
            logging.error(f"DHCP monitoring error: {e}")
    
    def _process_dhcp_packet(self, packet):
        """Process DHCP packet for security analysis"""
        try:
            if not packet.haslayer(DHCP):
                return
            
            dhcp_layer = packet[DHCP]
            bootp_layer = packet[BOOTP]
            ip_layer = packet[IP] if packet.haslayer(IP) else None
            
            src_mac = packet[Ether].src if packet.haslayer(Ether) else '00:00:00:00:00:00'
            src_ip = ip_layer.src if ip_layer else '0.0.0.0'
            dst_ip = ip_layer.dst if ip_layer else '255.255.255.255'
            
            dhcp_options = {}
            if hasattr(dhcp_layer, 'options'):
                for opt in dhcp_layer.options:
                    if len(opt) == 2 and opt[0] != 'end':
                        dhcp_options[opt[0]] = opt[1]
            
            # Process different DHCP message types
            if dhcp_layer.options[0][1] == 1:  # DHCP Discover
                self._process_dhcp_discover(src_mac, src_ip, dhcp_options)
            elif dhcp_layer.options[0][1] == 2:  # DHCP Offer
                self._process_dhcp_offer(src_mac, src_ip, dhcp_options)
            elif dhcp_layer.options[0][1] == 3:  # DHCP Request
                self._process_dhcp_request(src_mac, src_ip, dhcp_options)
            elif dhcp_layer.options[0][1] == 5:  # DHCP ACK
                self._process_dhcp_ack(src_mac, src_ip, dhcp_options)
                
        except Exception as e:
            logging.error(f"Error processing DHCP packet: {e}")
    
    def _process_dhcp_discover(self, src_mac, src_ip, options):
        """Process DHCP Discover messages"""
        timestamp = time.time()
        
        # Check for DHCP starvation
        self._check_dhcp_starvation(src_mac, timestamp)
        
        # Store request
        self.dhcp_requests.append({
            'type': 'DISCOVER',
            'mac': src_mac,
            'ip': src_ip,
            'timestamp': timestamp,
            'options': options
        })
    
    def _process_dhcp_offer(self, src_mac, src_ip, options):
        """Process DHCP Offer messages"""
        timestamp = time.time()
        
        # Identify DHCP server
        server_ip = options.get('server_id', src_ip)
        
        if server_ip not in self.dhcp_servers:
            self.dhcp_servers[server_ip] = {
                'mac': src_mac,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'offers_sent': 0,
                'authorized': False
            }
        
        self.dhcp_servers[server_ip]['offers_sent'] += 1
        self.dhcp_servers[server_ip]['last_seen'] = timestamp
        
        # Check for rogue DHCP server
        self._check_rogue_dhcp_server(server_ip, src_mac, options)
    
    def _process_dhcp_request(self, src_mac, src_ip, options):
        """Process DHCP Request messages"""
        timestamp = time.time()
        
        # Store request
        self.dhcp_requests.append({
            'type': 'REQUEST',
            'mac': src_mac,
            'ip': src_ip,
            'timestamp': timestamp,
            'options': options
        })
        
        # Check for rate limiting violations
        self._check_rate_limiting(src_mac, timestamp)
    
    def _process_dhcp_ack(self, src_mac, src_ip, options):
        """Process DHCP ACK messages"""
        timestamp = time.time()
        
        # Extract lease information
        client_ip = options.get('yiaddr', '0.0.0.0')
        lease_time = options.get('lease_time', 86400)
        server_ip = options.get('server_id', src_ip)
        gateway = options.get('router', '')
        
        # Store lease information
        self.lease_table[client_ip] = {
            'mac': src_mac,
            'server_ip': server_ip,
            'gateway': gateway,
            'lease_time': lease_time,
            'timestamp': timestamp,
            'expires': timestamp + lease_time
        }
        
        # Check for gateway manipulation
        if self.gateway_check_enabled:
            self._check_gateway_manipulation(gateway, server_ip)
        
        # Check for lease exhaustion
        self._check_lease_exhaustion()
    
    def _check_dhcp_starvation(self, src_mac, timestamp):
        """Check for DHCP starvation attacks"""
        recent_requests = [req for req in self.dhcp_requests 
                           if req['mac'] == src_mac and 
                           timestamp - req['timestamp'] < 60]
        
        if len(recent_requests) > self.request_threshold:
            alert = {
                'type': 'DHCP_STARVATION',
                'severity': 'HIGH',
                'message': f'DHCP starvation attack detected from {src_mac}',
                'source_mac': src_mac,
                'request_count': len(recent_requests),
                'timestamp': timestamp
            }
            self.alerts.append(alert)
            logging.warning(f"DHCP starvation attack detected: {src_mac}")
    
    def _check_rogue_dhcp_server(self, server_ip, server_mac, options):
        """Check for rogue DHCP servers"""
        # Check if server is authorized
        if self.authorized_servers and server_ip not in self.authorized_servers:
            alert = {
                'type': 'ROGUE_DHCP_SERVER',
                'severity': 'HIGH',
                'message': f'Rogue DHCP server detected: {server_ip} ({server_mac})',
                'server_ip': server_ip,
                'server_mac': server_mac,
                'timestamp': time.time()
            }
            self.alerts.append(alert)
            logging.warning(f"Rogue DHCP server detected: {server_ip}")
        
        # Check for suspicious DHCP options
        suspicious_options = self._check_suspicious_options(options)
        if suspicious_options:
            alert = {
                'type': 'SUSPICIOUS_DHCP_OPTIONS',
                'severity': 'MEDIUM',
                'message': f'Suspicious DHCP options from {server_ip}: {suspicious_options}',
                'server_ip': server_ip,
                'suspicious_options': suspicious_options,
                'timestamp': time.time()
            }
            self.alerts.append(alert)
    
    def _check_suspicious_options(self, options):
        """Check for suspicious DHCP options"""
        suspicious = []
        
        # Check for unusual DNS servers
        if 'name_server' in options:
            dns_servers = options['name_server']
            if isinstance(dns_servers, list):
                for dns in dns_servers:
                    if self._is_suspicious_dns(dns):
                        suspicious.append(f'DNS: {dns}')
        
        # Check for unusual gateways
        if 'router' in options:
            gateway = options['router']
            if self._is_suspicious_gateway(gateway):
                suspicious.append(f'Gateway: {gateway}')
        
        return suspicious
    
    def _is_suspicious_dns(self, dns_ip):
        """Check if DNS server is suspicious"""
        # Check for public DNS servers that might be used for attacks
        suspicious_dns = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        return dns_ip in suspicious_dns
    
    def _is_suspicious_gateway(self, gateway_ip):
        """Check if gateway is suspicious"""
        # Check if gateway is not in expected range
        if gateway_ip.startswith('192.168.') or gateway_ip.startswith('10.') or gateway_ip.startswith('172.'):
            return False
        return True
    
    def _check_rate_limiting(self, src_mac, timestamp):
        """Check for rate limiting violations"""
        current_minute = int(timestamp // 60)
        self.rate_limits[(src_mac, current_minute)] += 1
        
        if self.rate_limits[(src_mac, current_minute)] > self.request_threshold:
            alert = {
                'type': 'DHCP_RATE_LIMIT',
                'severity': 'MEDIUM',
                'message': f'DHCP rate limit exceeded for {src_mac}',
                'source_mac': src_mac,
                'requests_per_minute': self.rate_limits[(src_mac, current_minute)],
                'timestamp': timestamp
            }
            self.alerts.append(alert)
    
    def _check_gateway_manipulation(self, gateway, server_ip):
        """Check for gateway manipulation"""
        if gateway and gateway != '0.0.0.0':
            # Check if gateway is suspicious
            if self._is_suspicious_gateway(gateway):
                alert = {
                    'type': 'GATEWAY_MANIPULATION',
                    'severity': 'HIGH',
                    'message': f'Gateway manipulation detected: {gateway} from DHCP server {server_ip}',
                    'gateway': gateway,
                    'server_ip': server_ip,
                    'timestamp': time.time()
                }
                self.alerts.append(alert)
    
    def _check_lease_exhaustion(self):
        """Check for DHCP lease exhaustion"""
        active_leases = len([lease for lease in self.lease_table.values() 
                           if lease['expires'] > time.time()])
        
        if active_leases > self.lease_threshold:
            alert = {
                'type': 'DHCP_LEASE_EXHAUSTION',
                'severity': 'HIGH',
                'message': f'DHCP lease exhaustion detected: {active_leases} active leases',
                'active_leases': active_leases,
                'threshold': self.lease_threshold,
                'timestamp': time.time()
            }
            self.alerts.append(alert)
    
    def add_authorized_server(self, server_ip):
        """Add authorized DHCP server"""
        self.authorized_servers.append(server_ip)
        if server_ip in self.dhcp_servers:
            self.dhcp_servers[server_ip]['authorized'] = True
        logging.info(f"Added authorized DHCP server: {server_ip}")
    
    def remove_authorized_server(self, server_ip):
        """Remove authorized DHCP server"""
        if server_ip in self.authorized_servers:
            self.authorized_servers.remove(server_ip)
        if server_ip in self.dhcp_servers:
            self.dhcp_servers[server_ip]['authorized'] = False
        logging.info(f"Removed authorized DHCP server: {server_ip}")
    
    def get_dhcp_servers(self):
        """Get list of detected DHCP servers"""
        return self.dhcp_servers
    
    def get_active_leases(self):
        """Get active DHCP leases"""
        current_time = time.time()
        return {ip: lease for ip, lease in self.lease_table.items() 
                if lease['expires'] > current_time}
    
    def get_recent_alerts(self, limit=50):
        """Get recent DHCP security alerts"""
        return sorted(self.alerts, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def get_security_summary(self):
        """Get DHCP security summary"""
        current_time = time.time()
        active_leases = len([lease for lease in self.lease_table.values() 
                           if lease['expires'] > current_time])
        
        recent_alerts = [alert for alert in self.alerts 
                        if current_time - alert['timestamp'] < 3600]  # Last hour
        
        return {
            'dhcp_servers': len(self.dhcp_servers),
            'authorized_servers': len(self.authorized_servers),
            'active_leases': active_leases,
            'recent_requests': len(self.dhcp_requests),
            'recent_alerts': len(recent_alerts),
            'high_risk_alerts': len([a for a in recent_alerts if a['severity'] == 'HIGH']),
            'monitoring': self.monitoring
        }
    
    def simulate_dhcp_discovery(self, interface='eth0'):
        """Simulate DHCP discovery for testing"""
        try:
            # Create DHCP Discover packet using DHCP options
            dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff') / \
                           IP(src='0.0.0.0', dst='255.255.255.255') / \
                           UDP(sport=68, dport=67) / \
                           BOOTP(chaddr=bytes.fromhex('001122334456')) / \
                           DHCP(options=[('message-type', 'discover'), ('end')])
            
            sendp(dhcp_discover, iface=interface, verbose=False)
            logging.info("DHCP Discover packet sent for testing")
            return True
        except Exception as e:
            logging.error(f"Error sending DHCP Discover: {e}")
            return False
    
    def enable_dhcp_snooping(self):
        """Enable DHCP snooping (simulation)"""
        logging.info("DHCP snooping enabled")
        return True
    
    def disable_dhcp_snooping(self):
        """Disable DHCP snooping (simulation)"""
        logging.info("DHCP snooping disabled")
        return True
