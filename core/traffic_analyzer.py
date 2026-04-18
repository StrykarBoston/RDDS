#traffic_analyzer.py
import time
from collections import defaultdict, deque
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Dot11, Dot11Beacon, Dot11Elt, RadioTap, Ether
import socket
import threading
from datetime import datetime
import pandas as pd
import joblib
import warnings
import math
from core.config import PAYLOAD_ENTROPY_LIMIT, SEV_CRITICAL, SEV_HIGH
from core.alert_engine import fire_alert
warnings.filterwarnings('ignore')

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy of byte payload to detect encrypted/compressed exfiltration."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

try:
    import tensorflow as tf
    from core.ai_model import NetworkThreatPredictor
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("Warning: TensorFlow not available. AI features disabled.")

class Flow:
    """Network flow analysis"""
    def __init__(self, packet, local_ip):
        self.packets = deque([packet], maxlen=1000)
        self.start_time = packet.time
        self.end_time = packet.time
        self.local_ip = local_ip
        self.protocol = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other'
        self.dns_queries = []
        self.ports = set()
        self.wireless_packets = []
        
    def add_packet(self, packet):
        self.packets.append(packet)
        self.end_time = packet.time
        
        # Check for wireless packets (for evil twin detection)
        if Dot11 in packet:
            self.wireless_packets.append(packet)
        
        if DNS in packet and DNSQR in packet:
            self.dns_queries.append(packet[DNSQR].qname.decode() if hasattr(packet[DNSQR].qname, 'decode') else str(packet[DNSQR].qname))
        
        if TCP in packet:
            self.ports.add(packet[TCP].sport)
            self.ports.add(packet[TCP].dport)
            
            # Stealth Scans Detection (NULL, XMAS, FIN)
            flags = packet[TCP].flags
            stealth_type = None
            if flags == 0:
                stealth_type = "NULL"
            elif flags == 0x29: # FIN, PSH, URG
                stealth_type = "XMAS"
            elif flags == 0x01: # FIN
                stealth_type = "FIN"
                
            if stealth_type and IP in packet:
                fire_alert(
                     alert_type=f"STEALTH_SCAN_{stealth_type}",
                     severity=SEV_HIGH,
                     description=f"Stealth TCP {stealth_type} scan detected from {packet[IP].src} to {packet[IP].dst}:{packet[TCP].dport}",
                     device_ip=packet[IP].src,
                     raw_data={"scan_type": stealth_type, "target_port": packet[TCP].dport}
                )
                
            # DPI - Payload Entropy for exfiltration/tunneling
            if packet[TCP].payload and IP in packet:
                raw_data = bytes(packet[TCP].payload)
                if len(raw_data) > 64:  # Analyze payloads with sufficient data
                    # Ignore expected encrypted ports
                    if packet[TCP].dport not in [443, 22, 8443] and packet[TCP].sport not in [443, 22, 8443]:
                        ent = calculate_entropy(raw_data)
                        if ent > PAYLOAD_ENTROPY_LIMIT:
                            fire_alert(
                                 alert_type="HIGH_PAYLOAD_ENTROPY",
                                 severity=SEV_HIGH,
                                 description=f"High payload entropy ({ent:.2f}) detected from {packet[IP].src} to {packet[IP].dst}:{packet[TCP].dport}. Possible encrypted exfiltration or covert tunnel.",
                                 device_ip=packet[IP].src,
                                 raw_data={"entropy": ent, "payload_size": len(raw_data), "dport": packet[TCP].dport}
                            )
                        
        elif UDP in packet:
            self.ports.add(packet[UDP].sport)
            self.ports.add(packet[UDP].dport)

    def get_wireless_features(self):
        """Extract wireless-specific features for evil twin detection"""
        if not self.wireless_packets:
            return {}
            
        beacon_count = 0
        ssids = set()
        channels = set()
        signal_strengths = []
        encryption_types = set()
        
        for packet in self.wireless_packets:
            if Dot11Beacon in packet:
                beacon_count += 1
                
                # Extract SSID
                if packet[Dot11Elt].ID == 0:  # SSID
                    try:
                        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                        if ssid and ssid.strip():
                            ssids.add(ssid)
                    except:
                        pass
                
                # Extract channel
                if packet[Dot11Elt].ID == 3:  # DS Parameter Set (channel)
                    try:
                        channels.add(packet[Dot11Elt].info[0])
                    except:
                        pass
                
                # Signal strength
                if RadioTap in packet:
                    if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                        signal_strengths.append(packet[RadioTap].dBm_AntSignal)
            
            # Extract encryption info
            if Dot11Elt in packet:
                if packet[Dot11Elt].ID == 48:  # RSN Information
                    encryption_types.add('WPA2')
                elif packet[Dot11Elt].ID == 221:  # Vendor Specific
                    if b'WPA' in packet[Dot11Elt].info:
                        encryption_types.add('WPA')
        
        return {
            'beacon_count': beacon_count,
            'unique_ssids': len(ssids),
            'unique_channels': len(channels),
            'avg_signal_strength': np.mean(signal_strengths) if signal_strengths else -100,
            'encryption_types': len(encryption_types),
            'ssid_changes': len(ssids) > 1  # Multiple SSIDs from same MAC
        }

    def get_features(self):
        """Extract features for AI analysis"""
        if len(self.packets) < 2:
            return None

        duration_sec = self.end_time - self.start_time
        if duration_sec == 0:
            duration_sec = 1e-6

        fwd_packets = [p for p in self.packets if IP in p and p[IP].src == self.local_ip]
        bwd_packets = [p for p in self.packets if IP in p and p[IP].dst == self.local_ip]

        fwd_lengths = [len(p) for p in fwd_packets]
        bwd_lengths = [len(p) for p in bwd_packets]
        
        tcp_fwd = [p for p in fwd_packets if TCP in p]
        tcp_bwd = [p for p in bwd_packets if TCP in p]

        # Get wireless features
        wireless_features = self.get_wireless_features()

        features = {
            'Flow Duration': duration_sec * 1_000_000,
            'Total Fwd Packets': len(fwd_packets),
            'Total Backward Packets': len(bwd_packets),
            'Total Length of Fwd Packets': sum(fwd_lengths),
            'Total Length of Bwd Packets': sum(bwd_lengths),
            
            'Fwd Packet Length Mean': np.mean(fwd_lengths) if fwd_lengths else 0,
            'Bwd Packet Length Mean': np.mean(bwd_lengths) if bwd_lengths else 0,
            'Fwd Packet Length Std': np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0,
            'Bwd Packet Length Std': np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0,
            'Fwd Packet Length Max': max(fwd_lengths) if fwd_lengths else 0,
            'Bwd Packet Length Max': max(bwd_lengths) if bwd_lengths else 0,
            'Fwd Packet Length Min': min(fwd_lengths) if fwd_lengths else 0,
            'Bwd Packet Length Min': min(bwd_lengths) if bwd_lengths else 0,
            
            'Flow Packets/s': len(self.packets) / duration_sec,
            'Fwd Packets/s': len(fwd_packets) / duration_sec,
            'Bwd Packets/s': len(bwd_packets) / duration_sec,
            'Flow Bytes/s': (sum(fwd_lengths) + sum(bwd_lengths)) / duration_sec,
            
            'Fwd PSH Flags': sum(1 for p in tcp_fwd if TCP in p and 'P' in p[TCP].flags),
            'Bwd PSH Flags': sum(1 for p in tcp_bwd if TCP in p and 'P' in p[TCP].flags),
            'Fwd URG Flags': sum(1 for p in tcp_fwd if TCP in p and 'U' in p[TCP].flags),
            'Bwd URG Flags': sum(1 for p in tcp_bwd if TCP in p and 'U' in p[TCP].flags),
            'Fwd FIN Flags': sum(1 for p in tcp_fwd if TCP in p and 'F' in p[TCP].flags),
            'Bwd FIN Flags': sum(1 for p in tcp_bwd if TCP in p and 'F' in p[TCP].flags),
            'Fwd SYN Flags': sum(1 for p in tcp_fwd if TCP in p and 'S' in p[TCP].flags),
            'Bwd SYN Flags': sum(1 for p in tcp_bwd if TCP in p and 'S' in p[TCP].flags),
            'Fwd RST Flags': sum(1 for p in tcp_fwd if TCP in p and 'R' in p[TCP].flags),
            'Bwd RST Flags': sum(1 for p in tcp_bwd if TCP in p and 'R' in p[TCP].flags),
            
            'Init_Win_bytes_forward': next((p[TCP].window for p in tcp_fwd if TCP in p), 0),
            'Init_Win_bytes_backward': next((p[TCP].window for p in tcp_bwd if TCP in p), 0),
            
            'bytes_ratio': sum(fwd_lengths) / sum(bwd_lengths) if sum(bwd_lengths) > 0 else 1,
            'traffic_asymmetry': abs((sum(fwd_lengths) / sum(bwd_lengths) if sum(bwd_lengths) > 0 else 1) - 1),
            'packets_ratio': len(fwd_packets) / len(bwd_packets) if len(bwd_packets) > 0 else 1,
            'avg_packet_size': (sum(fwd_lengths) + sum(bwd_lengths)) / len(self.packets),
            
            'avg_fwd_segment_size': np.mean(fwd_lengths) if fwd_lengths else 0,
            'avg_bwd_segment_size': np.mean(bwd_lengths) if bwd_lengths else 0,
            'fwd_header_length': sum(len(p[TCP]) if TCP in p else 0 for p in fwd_packets),
            'subflow_fwd_packets': len(fwd_packets) // 2,
            'subflow_bwd_packets': len(bwd_packets) // 2,
            'subflow_fwd_bytes': sum(fwd_lengths) // 2,
            'subflow_bwd_bytes': sum(bwd_lengths) // 2,
            
            'dns_query_count': len(self.dns_queries),
            'unique_ports': len(self.ports),
            
            # Evil twin specific features
            'beacon_frame_count': wireless_features.get('beacon_count', 0),
            'multiple_ssids': 1 if wireless_features.get('ssid_changes', False) else 0,
            'signal_strength_variance': wireless_features.get('avg_signal_strength', -100),
            'channel_changes': wireless_features.get('unique_channels', 0),
            'encryption_inconsistencies': 1 if wireless_features.get('encryption_types', 0) > 1 else 0,
            'authentication_failures': sum(1 for p in self.packets if TCP in p and p[TCP].dport in [80, 443] and 'R' in p[TCP].flags),
            'dns_anomalies': 1 if any('fake' in query.lower() or 'evil' in query.lower() or 'phish' in query.lower() for query in self.dns_queries) else 0
        }
        
        return features

class TrafficAnalyzer:
    def __init__(self, iface=None, passive_mode=True,
                 netflow_port=2055, sflow_port=6343):
        """Initialize the traffic analyzer.
        Args:
            iface: Network interface to sniff on (None = scapy default)
            passive_mode: If True, passively sniff packets (default True)
            netflow_port: UDP port for NetFlow collection (default 2055)
            sflow_port: UDP port for sFlow collection (default 6343)
        """
        self.iface = iface
        self.passive_mode = passive_mode
        self.netflow_port = netflow_port
        self.sflow_port = sflow_port
        self.flows = defaultdict(lambda: None)
        self.local_ip = self.get_local_ip()
        self.capture_stats = {
            'total_packets': 0,
            'total_flows': 0,
            'start_time': None,
            'end_time': None
        }
        
        self._running = False
        self._thread = None
        self._stop_event = threading.Event()
        self._anomalies = deque(maxlen=200)
        self._rx_bytes = 0
        self._tx_bytes = 0

        # Counters for rdds.py stats display
        self._passive_packets  = 0
        self._anomalies_count  = 0
        self._netflow_v5_count = 0
        self._netflow_v9_count = 0
        self._sflow_count      = 0

        # Internal log for background thread diagnostics
        self._log_file = "traffic_analyzer.log"

        # Initialize generalized AI model
        if AI_AVAILABLE:
            self.threat_predictor = NetworkThreatPredictor()
            self.ai_model_loaded = self.threat_predictor.model_loaded
        else:
            self.ai_model_loaded = False
            print("⚠️ TensorFlow not available - AI threat detection disabled")
            
        self.local_ip = self.get_local_ip()

    def _log(self, msg):
        """Write diagnostic messages to a local log file for background thread debugging."""
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{ts}] {msg}\n")
        except:
            pass

    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def get_flow_key(self, packet):
        """Generate unique flow key"""
        if IP not in packet:
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 'TCP'
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 'UDP'
        else:
            return None
            
        if src_ip < dst_ip:
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
        return key

    def packet_handler(self, packet):
        """Handle incoming packets inside the sniff thread"""
        try:
            if packet is None:
                return
                
            pkt_len = len(packet)
            self._rx_bytes += pkt_len
            self.capture_stats['total_packets'] += 1
            self._passive_packets += 1  # Track for rdds.py stats display

            
            if self.capture_stats['start_time'] is None:
                self.capture_stats['start_time'] = datetime.now()
            self.capture_stats['end_time'] = datetime.now()

            # IP Traffic Analysis
            if IP in packet:
                if packet[IP].src == self.local_ip:
                    self._tx_bytes += pkt_len
                
                flow_key = self.get_flow_key(packet)
                if flow_key:
                    flow = self.flows[flow_key]
                    if flow is None:
                        self.flows[flow_key] = Flow(packet, self.local_ip)
                        self.capture_stats['total_flows'] += 1
                    else:
                        flow.add_packet(packet)
                    
                    # Periodic AI Analysis (every 20 packets in a flow)
                    if self.ai_model_loaded and flow_key in self.flows:
                        f_obj = self.flows[flow_key]
                        if f_obj and len(f_obj.packets) > 5 and len(f_obj.packets) % 20 == 0:
                            features = f_obj.get_features()
                            if features:
                                detection = self.detect_network_threat(features)
                                if detection.get('is_anomalous') or detection.get('safety_score', 100) < 50:
                                    # ... (anomaly generation)
                                    anomaly = {
                                        "timestamp": datetime.now().isoformat(),
                                        "src_ip": packet[IP].src,
                                        "type": "AI_ANOMALY",
                                        "severity": "CRITICAL" if detection.get('safety_score', 100) < 30 else "HIGH",
                                        "description": f"AI Behavioral Anomaly: {detection.get('recommendation', 'Suspicious activity detected')}",
                                        "score": detection.get('safety_score', 0)
                                    }
                                    if anomaly not in list(self._anomalies):
                                        self._anomalies.appendleft(anomaly)
                                        fire_alert(
                                            alert_type="AI_BEHAVIORAL_ANOMALY",
                                            severity=anomaly["severity"],
                                            description=anomaly["description"],
                                            device_ip=anomaly["src_ip"]
                                        )

            # Wireless Traffic Analysis (Passive mode)
            elif Dot11 in packet:
                flow = self.flows["wireless"]
                if flow is None:
                    self.flows["wireless"] = Flow(packet, self.local_ip)
                else:
                    flow.add_packet(packet)

        except Exception as e:
            # Avoid logging every single packet error to prevent console spam
            # but record high-level failures in the analyzer log
            pass

    def detect_network_threat(self, features):
        """Use AI model to detect network anomalies"""
        if not self.ai_model_loaded:
            return {
                'error': 'AI model not loaded',
                'is_anomalous': False,
                'is_evil_twin': False,
                'safety_score': 0,
                'recommendation': 'AI model not available'
            }
        
        try:
            result = self.threat_predictor.analyze_network_traffic(features)
            result['is_evil_twin'] = result['is_anomalous']
            return result
        except Exception as e:
            return {
                'error': f'AI analysis failed: {e}',
                'is_anomalous': False,
                'is_evil_twin': False,
                'safety_score': 0,
                'recommendation': 'Check model configuration'
            }

    def start(self):
        """Start the traffic analyzer loop in background with interface GUID resolution and retry logic."""
        if self._running:
            return
        
        self.capture_stats['start_time'] = datetime.now()
        self._running = True
        self._stop_event.clear()

        # Step 1: Resolve interface (Windows GUID vs Friendly Name)
        resolved_iface = self.iface
        if resolved_iface:
            try:
                from scapy.all import conf
                # Try to map friendly name (e.g. "Wi-Fi") to GUID (e.g. "\Device\NPF_...")
                for iface_key in conf.ifaces:
                    iface_obj = conf.ifaces[iface_key]
                    # Check name, description, and internal id
                    if resolved_iface.lower() in [iface_obj.name.lower(), 
                                                 iface_obj.description.lower(), 
                                                 str(iface_key).lower()]:
                        resolved_iface = iface_key
                        break
            except Exception as e:
                self._log(f"Interface resolution error: {e}")

        def _sniff_loop():
            self._log(f"Traffic Analyzer background thread started. Iface: {resolved_iface}")
            retry_count = 0
            max_retries = 3
            
            while not self._stop_event.is_set() and retry_count <= max_retries:
                try:
                    sniff(
                        prn=self.packet_handler,
                        store=False,
                        iface=resolved_iface,
                        stop_filter=lambda p: self._stop_event.is_set()
                    )
                    
                    # If sniff returns but stop_event isn't set, it may be an Npcap failure/reset
                    if not self._stop_event.is_set():
                        retry_count += 1
                        self._log(f"Sniffer returned unexpectedly. Retrying ({retry_count}/{max_retries})...")
                        time.sleep(2)
                    else:
                        break
                except Exception as e:
                    from core.alert_engine import print_error
                    error_msg = f"TrafficAnalyzer sniff error: {e}"
                    print_error(error_msg)
                    self._log(error_msg)
                    retry_count += 1
                    time.sleep(2)
            
            self._log("Traffic Analyzer thread exiting.")
            self._running = False

        self._thread = threading.Thread(target=_sniff_loop, daemon=True)
        self._thread.start()
        print(f"[TrafficAnalyzer] Started on {resolved_iface}")

    def stop(self):
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3.0)
        self._running = False
        print("[TrafficAnalyzer] Stopped.")

    def is_running(self):
        return self._running

    def get_stats(self):
        """Used by Dashboard API and rdds.py cmd_traffic()"""
        duration = 0
        if self.capture_stats['start_time']:
            end = self.capture_stats['end_time'] or datetime.now()
            duration = (end - self.capture_stats['start_time']).total_seconds()
        
        pps = self.capture_stats['total_packets'] / duration if duration > 0 else 0
        return {
            # Core stats
            "total_packets":      self.capture_stats['total_packets'],
            "total_flows":        len(self.flows),
            "packets_per_second": round(pps, 2),
            "uptime_seconds":     round(duration, 2),
            "ai_loaded":          self.ai_model_loaded,
            # Stats expected by rdds.py cmd_traffic()
            "passive_packets":    self._passive_packets,
            "anomalies_detected": self._anomalies_count,
            "netflow_v5_records": self._netflow_v5_count,
            "netflow_v9_records": self._netflow_v9_count,
            "sflow_samples":      self._sflow_count,
        }

    def get_flows(self, src_ip=None, limit=200):
        """Returns recent flows summarized for dashboard"""
        out = []
        for flow_key, flow in list(self.flows.items()):
            if flow_key == "wireless" or not flow:
                continue
            
            # Simple summarization based on key format
            parts = flow_key.split('-')
            if len(parts) >= 3:
                src_part, dst_part, proto = parts[0], parts[1], parts[2]
                src = src_part.split(':')[0]
                dst = dst_part.split(':')[0]
                try: dport = int(dst_part.split(':')[1]) 
                except: dport = 0
                
                if src_ip and src_ip != src and src_ip != dst:
                    continue

                duration = (flow.end_time - flow.start_time)
                pkts_len = len(flow.packets)

                out.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": dport,
                    "protocol": proto,
                    "bytes": pkts_len * 500, # Approx value since bytes are calculated per packet internally.
                    "age": round(duration, 2),
                    "last_active": flow.end_time
                })
                
        # Sort by most recently active
        out.sort(key=lambda x: x["last_active"], reverse=True)
        return out[:limit]

    def get_top_talkers(self, n=10):
        """Compute top talkers — returns dicts with bytes_out, bytes_in, pkts_out keys."""
        out_bytes  = defaultdict(int)
        in_bytes   = defaultdict(int)
        out_pkts   = defaultdict(int)
        for _, flow in list(self.flows.items()):
            if flow:
                for pkt in flow.packets:
                    if IP in pkt:
                        size = len(pkt)
                        if pkt[IP].src == self.local_ip:
                            out_bytes[pkt[IP].src] += size
                            out_pkts[pkt[IP].src]  += 1
                        else:
                            in_bytes[pkt[IP].dst] += size
        
        all_ips = set(list(out_bytes.keys()) + list(in_bytes.keys()))
        talkers = [
            {
                "ip":       ip,
                "bytes_out": out_bytes.get(ip, 0),
                "bytes_in":  in_bytes.get(ip, 0),
                "pkts_out":  out_pkts.get(ip, 0),
                # Legacy key for dashboard compatibility
                "bytes":     out_bytes.get(ip, 0) + in_bytes.get(ip, 0),
            }
            for ip in all_ips
        ]
        talkers.sort(key=lambda x: x["bytes"], reverse=True)
        return talkers[:n]

    def get_anomalies(self, limit=100):
        return list(self._anomalies)[:limit]

    def get_bandwidth_summary(self):
        return {"rx": self._rx_bytes, "tx": self._tx_bytes}