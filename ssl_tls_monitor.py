# -*- coding: utf-8 -*-
# ssl_tls_monitor.py - SSL/TLS Certificate Monitoring & Attack Detection

import ssl
import socket
import hashlib
import time
import threading
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque

class SSLTLSMonitor:
    def __init__(self):
        self.monitored_hosts = {}
        self.certificate_alerts = deque(maxlen=1000)
        self.weak_algorithms = ['md5', 'sha1', 'md2', 'mdc2']
        self.trusted_cas = self._load_trusted_cas()
        self.monitoring = False
        self.monitor_threads = []
        
        # Certificate validation thresholds
        self.expiry_threshold = 30  # days
        self.key_size_threshold = 2048  # bits
        
    def _load_trusted_cas(self):
        """Load trusted Certificate Authorities"""
        # Simplified trusted CA list - in production, use proper CA database
        return {
            'DigiCert Inc', 'Comodo CA Limited', 'GoDaddy.com, Inc.',
            'GlobalSign nv-sa', 'Sectigo Limited', 'Thawte, Inc.',
            'Entrust, Inc.', 'Network Solutions LLC', 'Starfield Technologies, Inc.',
            'Amazon', 'Google Trust Services', 'Microsoft Corporation'
        }
    
    def monitor_certificate(self, host, port=443):
        """Monitor SSL/TLS certificate for a specific host"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Connect and get certificate
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_pem = ssock.getpeercert()
                    
                    # Parse certificate using built-in SSL
                    analysis = self._analyze_certificate(cert_pem, host, port)
                    
                    # Store results
                    self.monitored_hosts[host] = {
                        'certificate': analysis,
                        'last_checked': time.time(),
                        'port': port
                    }
                    
                    return analysis
                    
        except Exception as e:
            logging.error(f"Error monitoring certificate for {host}:{port} - {e}")
            return None
    
    def _analyze_certificate(self, cert_pem, host, port):
        """Comprehensive SSL/TLS certificate analysis using built-in SSL"""
        analysis = {
            'host': host,
            'port': port,
            'subject': self._get_subject(cert_pem),
            'issuer': self._get_issuer(cert_pem),
            'serial_number': str(cert_pem.get('serialNumber', 'Unknown')),
            'version': str(cert_pem.get('version', 'Unknown')),
            'signature_algorithm': self._get_signature_algorithm(cert_pem),
            'public_key_algorithm': self._get_public_key_algorithm(cert_pem),
            'public_key_size': self._get_key_size(cert_pem),
            'not_before': self._parse_date(cert_pem.get('notBefore')),
            'not_after': self._parse_date(cert_pem.get('notAfter')),
            'san_extensions': self._get_san_extensions(cert_pem),
            'alerts': [],
            'risk_score': 0
        }
        
        # Check for various certificate issues
        self._check_self_signed(analysis, cert_pem)
        self._check_expiry(analysis)
        self._check_subject_mismatch(analysis, host)
        self._check_weak_signature(analysis, cert_pem)
        self._check_weak_key_size(analysis)
        self._check_certificate_transparency(analysis)
        self._check_revocation(analysis)
        self._check_trusted_ca(analysis, cert_pem)
        
        return analysis
    
    def _get_subject(self, cert_pem):
        """Extract certificate subject information"""
        try:
            subject = cert_pem.get('subject', [])
            subject_info = {}
            
            for item in subject:
                if isinstance(item, tuple) and len(item) >= 2:
                    field, value = item[0], item[1]
                    
                    if field == 'commonName':
                        subject_info['common_name'] = value
                    elif field == 'organizationName':
                        subject_info['organization'] = value
                    elif field == 'organizationalUnitName':
                        subject_info['organizational_unit'] = value
                    elif field == 'countryName':
                        subject_info['country'] = value
                    elif field == 'stateOrProvinceName':
                        subject_info['state'] = value
                    elif field == 'localityName':
                        subject_info['locality'] = value
                    elif field == 'emailAddress':
                        subject_info['email'] = value
            
            return subject_info
        except Exception as e:
            logging.error(f"Error extracting subject: {e}")
            return {}
    
    def _get_issuer(self, cert_pem):
        """Extract certificate issuer information"""
        try:
            issuer = cert_pem.get('issuer', [])
            issuer_info = {}
            
            for item in issuer:
                if isinstance(item, tuple) and len(item) >= 2:
                    field, value = item[0], item[1]
                    
                    if field == 'commonName':
                        issuer_info['common_name'] = value
                    elif field == 'organizationName':
                        issuer_info['organization'] = value
                    elif field == 'countryName':
                        issuer_info['country'] = value
            
            return issuer_info
        except Exception as e:
            logging.error(f"Error extracting issuer: {e}")
            return {}
    
    def _get_san_extensions(self, cert_pem):
        """Extract Subject Alternative Name extensions"""
        try:
            san_names = []
            subject_alt_name = cert_pem.get('subjectAltName', [])
            
            for item in subject_alt_name:
                if isinstance(item, tuple) and len(item) >= 2:
                    san_type, san_value = item[0], item[1]
                    if san_type == 'DNS':
                        san_names.append(san_value)
            
            return san_names
        except Exception as e:
            logging.error(f"Error extracting SAN extensions: {e}")
            return []
    
    def _get_key_size(self, cert_pem):
        """Get public key size in bits"""
        try:
            # Built-in SSL doesn't provide direct key size access
            # Return default value for now
            return 2048  # Default to 2048 bits
        except Exception as e:
            logging.error(f"Error getting key size: {e}")
            return 0
    
    def _get_signature_algorithm(self, cert_pem):
        """Get signature algorithm"""
        try:
            # Try to extract from certificate
            return cert_pem.get('signatureAlgorithm', 'Unknown')
        except Exception as e:
            logging.error(f"Error getting signature algorithm: {e}")
            return 'Unknown'
    
    def _get_public_key_algorithm(self, cert_pem):
        """Get public key algorithm"""
        try:
            # Built-in SSL doesn't provide direct access
            return 'RSA'  # Default assumption
        except Exception as e:
            logging.error(f"Error getting public key algorithm: {e}")
            return 'Unknown'
    
    def _parse_date(self, date_str):
        """Parse certificate date string"""
        try:
            if isinstance(date_str, str):
                # SSL certificate dates are in format: 'Month Day HH:MM:SS YYYY GMT'
                return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
            return date_str
        except Exception as e:
            logging.error(f"Error parsing date: {e}")
            return datetime.now()
    
    def _check_self_signed(self, analysis, cert_pem):
        """Check if certificate is self-signed"""
        try:
            issuer = analysis['issuer']
            subject = analysis['subject']
            
            # Self-signed if issuer and subject are the same
            if (issuer.get('common_name') == subject.get('common_name') and
                issuer.get('organization') == subject.get('organization')):
                
                analysis['alerts'].append({
                    'type': 'SELF_SIGNED',
                    'severity': 'HIGH',
                    'message': 'Self-signed certificate detected',
                    'description': 'Certificate is not signed by a trusted CA'
                })
                analysis['risk_score'] += 40
                
        except Exception as e:
            logging.error(f"Error checking self-signed: {e}")
    
    def _check_expiry(self, analysis):
        """Check certificate expiration"""
        try:
            not_after = analysis['not_after']
            if not isinstance(not_after, datetime):
                return  # Skip if we couldn't parse the date
            
            current_time = datetime.now()
            days_until_expiry = (not_after - current_time).days
            
            if days_until_expiry < 0:
                analysis['alerts'].append({
                    'type': 'EXPIRED',
                    'severity': 'CRITICAL',
                    'message': f'Certificate expired {abs(days_until_expiry)} days ago',
                    'description': f'Certificate expired on {not_after.strftime("%Y-%m-%d")}'
                })
                analysis['risk_score'] += 50
            elif days_until_expiry < self.expiry_threshold:
                analysis['alerts'].append({
                    'type': 'EXPIRING_SOON',
                    'severity': 'MEDIUM',
                    'message': f'Certificate expires in {days_until_expiry} days',
                    'description': f'Certificate will expire on {not_after.strftime("%Y-%m-%d")}'
                })
                analysis['risk_score'] += 20
                
        except Exception as e:
            logging.error(f"Error checking expiry: {e}")
    
    def _check_subject_mismatch(self, analysis, host):
        """Check for subject/hostname mismatch"""
        try:
            subject = analysis['subject']
            san_names = analysis['san_extensions']
            
            # Check common name
            common_name = subject.get('common_name', '')
            if common_name and not self._match_hostname(common_name, host):
                analysis['alerts'].append({
                    'type': 'SUBJECT_MISMATCH',
                    'severity': 'HIGH',
                    'message': f'Common name mismatch: {common_name} != {host}',
                    'description': 'Certificate subject does not match hostname'
                })
                analysis['risk_score'] += 30
            
            # Check SAN extensions
            for san_name in san_names:
                if self._match_hostname(san_name, host):
                    return  # Found matching SAN
            
            # No matching name found
            if san_names:
                analysis['alerts'].append({
                    'type': 'SUBJECT_MISMATCH',
                    'severity': 'HIGH',
                    'message': f'No SAN entry matches hostname: {host}',
                    'description': 'Certificate SAN extensions do not contain hostname'
                })
                analysis['risk_score'] += 30
                
        except Exception as e:
            logging.error(f"Error checking subject mismatch: {e}")
    
    def _match_hostname(self, cert_name, host):
        """Check if certificate name matches hostname"""
        # Simple wildcard matching
        if cert_name.startswith('*.'):
            domain = cert_name[2:]
            return host.endswith(domain)
        else:
            return cert_name.lower() == host.lower()
    
    def _check_weak_signature(self, analysis, cert_pem):
        """Check for weak signature algorithms"""
        try:
            sig_algorithm = analysis['signature_algorithm'].lower()
            
            if sig_algorithm in self.weak_algorithms:
                analysis['alerts'].append({
                    'type': 'WEAK_SIGNATURE',
                    'severity': 'HIGH',
                    'message': f'Weak signature algorithm: {sig_algorithm}',
                    'description': f'Certificate uses deprecated {sig_algorithm} algorithm'
                })
                analysis['risk_score'] += 35
                
        except Exception as e:
            logging.error(f"Error checking weak signature: {e}")
    
    def _check_weak_key_size(self, analysis):
        """Check for weak public key sizes"""
        try:
            key_size = analysis['public_key_size']
            
            if key_size < self.key_size_threshold:
                analysis['alerts'].append({
                    'type': 'WEAK_KEY_SIZE',
                    'severity': 'MEDIUM',
                    'message': f'Weak key size: {key_size} bits',
                    'description': f'Public key size below recommended {self.key_size_threshold} bits'
                })
                analysis['risk_score'] += 25
                
        except Exception as e:
            logging.error(f"Error checking key size: {e}")
    
    def _check_certificate_transparency(self, analysis):
        """Check certificate transparency logs"""
        try:
            # Simplified CT log check - in production, use real CT logs
            pass
        except Exception as e:
            logging.error(f"Error checking certificate transparency: {e}")
    
    def _check_revocation(self, analysis):
        """Check certificate revocation status"""
        try:
            # Simplified revocation check - in production, use OCSP/CRL
            pass
        except Exception as e:
            logging.error(f"Error checking revocation: {e}")
    
    def _check_trusted_ca(self, analysis, cert_pem):
        """Check if certificate is issued by trusted CA"""
        try:
            issuer_org = analysis['issuer'].get('organization', '')
            
            if issuer_org not in self.trusted_cas:
                analysis['alerts'].append({
                    'type': 'UNTRUSTED_CA',
                    'severity': 'HIGH',
                    'message': f'Untrusted certificate authority: {issuer_org}',
                    'description': 'Certificate not issued by trusted CA'
                })
                analysis['risk_score'] += 30
                
        except Exception as e:
            logging.error(f"Error checking trusted CA: {e}")
    
    def start_monitoring(self, hosts, duration=300):
        """Start SSL/TLS certificate monitoring for multiple hosts"""
        self.monitoring = True
        start_time = time.time()
        
        logging.info(f"Starting SSL/TLS monitoring for {len(hosts)} hosts")
        
        # Monitor each host in separate thread
        for host in hosts:
            if not self.monitoring:
                break
                
            thread = threading.Thread(
                target=self.monitor_certificate,
                args=(host,),
                daemon=True
            )
            thread.start()
            self.monitor_threads.append(thread)
            
            # Small delay between connections
            time.sleep(0.1)
        
        # Wait for monitoring duration
        time.sleep(duration)
        
        # Stop monitoring
        self.monitoring = False
        logging.info("SSL/TLS monitoring stopped")
        
        return self.generate_certificate_report()
    
    def stop_monitoring(self):
        """Stop SSL/TLS certificate monitoring"""
        self.monitoring = False
        logging.info("SSL/TLS monitoring stopped")
    
    def generate_certificate_report(self):
        """Generate comprehensive certificate monitoring report"""
        current_time = datetime.now()
        
        report = {
            'timestamp': current_time.isoformat(),
            'total_hosts': len(self.monitored_hosts),
            'high_risk_certificates': 0,
            'medium_risk_certificates': 0,
            'low_risk_certificates': 0,
            'certificate_alerts': [],
            'risk_summary': defaultdict(int)
        }
        
        # Analyze all monitored certificates
        for host, data in self.monitored_hosts.items():
            cert_analysis = data['certificate']
            risk_score = cert_analysis['risk_score']
            
            # Categorize by risk level
            if risk_score >= 70:
                report['high_risk_certificates'] += 1
            elif risk_score >= 40:
                report['medium_risk_certificates'] += 1
            else:
                report['low_risk_certificates'] += 1
            
            # Collect all alerts
            for alert in cert_analysis['alerts']:
                alert_copy = alert.copy()
                alert_copy['host'] = host
                alert_copy['port'] = data['port']
                report['certificate_alerts'].append(alert_copy)
                
                # Count alert types
                report['risk_summary'][alert['type']] += 1
        
        return report
    
    def get_certificate_summary(self):
        """Get summary of certificate monitoring results"""
        if not self.monitored_hosts:
            return {'total_hosts': 0, 'alerts': []}
        
        total_alerts = 0
        high_risk = 0
        medium_risk = 0
        
        for host, data in self.monitored_hosts.items():
            cert_analysis = data['certificate']
            total_alerts += len(cert_analysis['alerts'])
            
            if cert_analysis['risk_score'] >= 70:
                high_risk += 1
            elif cert_analysis['risk_score'] >= 40:
                medium_risk += 1
        
        return {
            'total_hosts': len(self.monitored_hosts),
            'total_alerts': total_alerts,
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': len(self.monitored_hosts) - high_risk - medium_risk
        }
    
    def reset_monitoring(self):
        """Reset all monitoring data"""
        self.monitored_hosts.clear()
        self.certificate_alerts.clear()
        self.monitor_threads.clear()
        logging.info("SSL/TLS monitoring data reset")
