"""
RDDS — Packet Analysis Engine
Detects ARP spoofing, MITM, port scanning, and lateral movement
via Scapy packet analysis.
"""

import time
import threading
from collections import defaultdict
from typing import Dict, Set, Callable, Optional

try:
    from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, DNSRR, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core.config import (
    PORT_SCAN_THRESHOLD, ARP_FLOOD_THRESHOLD, DNS_SPOOF_THRESHOLD,
    ALERT_ARP_SPOOF, ALERT_MITM, ALERT_PORT_SCAN, ALERT_ARP_FLOOD,
    ALERT_DNS_SPOOF, ALERT_LATERAL_MOVE,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW,
    PACKET_ENGINE_BPF_FILTER, PACKET_BUFFER_SIZE, get_default_gateway
)
from core.alert_engine import fire_alert, print_info, print_warn

# ─────────────────────────────────────────────
#  SHARED STATE
# ─────────────────────────────────────────────

# ip → mac  (our seen ARP cache)
_arp_table: Dict[str, str] = {}
_arp_lock  = threading.Lock()

# ip → list of (mac, timestamp)
_arp_reply_log: Dict[str, list] = defaultdict(list)

# (src_ip) → set of dst_ports seen (port scan tracker)
_port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
_port_scan_times:   Dict[str, float]    = {}

# mac → ARP packet count in window
_arp_flood_tracker: Dict[str, list] = defaultdict(list)

# (query_name) → list of answer IPs seen
_dns_answers: Dict[str, list] = defaultdict(list)

# Gateway IP reference (set externally)
_gateway_ip: Optional[str] = None

# Lateral movement ports
LATERAL_PORTS = {
    445,    # SMB
    3389,   # RDP
    135,    # DCOM/RPC
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    22,     # SSH
    23,     # Telnet
    139,    # NetBIOS
}
_lateral_tracker: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
LATERAL_THRESHOLD = 5   # hits to same lateral port from same IP

# Callbacks for external notification
_alert_callbacks: list = []


def set_gateway_ip(ip: str):
    global _gateway_ip
    _gateway_ip = ip


def register_callback(fn: Callable):
    _alert_callbacks.append(fn)


def _dispatch(alert_type, severity, description, device_mac="", device_ip="", raw=None):
    fire_alert(alert_type, severity, description, device_mac, device_ip, raw or {})
    for cb in _alert_callbacks:
        try:
            cb(alert_type, severity, description)
        except Exception:
            pass


# ─────────────────────────────────────────────
#  ARP SPOOF DETECTION
# ─────────────────────────────────────────────

def _process_arp(pkt):
    if not pkt.haslayer(ARP):
        return
    op  = pkt[ARP].op   # 1=who-has, 2=is-at
    src_ip  = pkt[ARP].psrc
    src_mac = pkt[ARP].hwsrc.lower()

    if op == 2:  # ARP reply
        with _arp_lock:
            if src_ip in _arp_table:
                known_mac = _arp_table[src_ip]
                if known_mac != src_mac:
                    # IP → MAC changed!
                    if _gateway_ip and src_ip == _gateway_ip:
                        _dispatch(
                            ALERT_MITM, SEV_CRITICAL,
                            f"Gateway IP {src_ip} MAC changed: "
                            f"{known_mac} → {src_mac}. MITM/ARP POISONING DETECTED!",
                            device_mac=src_mac, device_ip=src_ip,
                            raw={"was": known_mac, "now": src_mac}
                        )
                    else:
                        _dispatch(
                            ALERT_ARP_SPOOF, SEV_HIGH,
                            f"ARP Spoofing: IP {src_ip} was {known_mac}, "
                            f"now claims MAC {src_mac}",
                            device_mac=src_mac, device_ip=src_ip,
                            raw={"was": known_mac, "now": src_mac}
                        )
            else:
                _arp_table[src_ip] = src_mac

        # ARP flood tracker
        now = time.time()
        _arp_flood_tracker[src_mac].append(now)
        # Keep only last 1 second
        _arp_flood_tracker[src_mac] = [
            t for t in _arp_flood_tracker[src_mac] if now - t <= 1
        ]
        if len(_arp_flood_tracker[src_mac]) >= ARP_FLOOD_THRESHOLD:
            _dispatch(
                ALERT_ARP_FLOOD, SEV_HIGH,
                f"ARP Flood from MAC {src_mac}: "
                f"{len(_arp_flood_tracker[src_mac])} ARP replies/sec",
                device_mac=src_mac, raw={}
            )
            _arp_flood_tracker[src_mac] = []  # reset to avoid re-spam


# ─────────────────────────────────────────────
#  PORT SCAN DETECTION
# ─────────────────────────────────────────────

PORT_SCAN_WINDOW = 10   # seconds

def _process_tcp(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    src = pkt[IP].src
    dst_port = pkt[TCP].dport
    flags    = pkt[TCP].flags

    # SYN only (no ACK) = typical port scan
    if flags == 0x02:
        now = time.time()
        start = _port_scan_times.get(src)
        if start is None or (now - start) > PORT_SCAN_WINDOW:
            _port_scan_times[src] = now
            _port_scan_tracker[src] = set()

        _port_scan_tracker[src].add(dst_port)

        if len(_port_scan_tracker[src]) >= PORT_SCAN_THRESHOLD:
            _dispatch(
                ALERT_PORT_SCAN, SEV_HIGH,
                f"Port Scan from {src}: {len(_port_scan_tracker[src])} ports "
                f"probed in {PORT_SCAN_WINDOW}s",
                device_ip=src,
                raw={"ports": list(_port_scan_tracker[src])[:30]}
            )
            _port_scan_tracker[src] = set()
            _port_scan_times[src]   = now

    # Lateral movement: repeated hits to high-risk ports
    if dst_port in LATERAL_PORTS:
        _lateral_tracker[src][dst_port] += 1
        if _lateral_tracker[src][dst_port] >= LATERAL_THRESHOLD:
            _dispatch(
                ALERT_LATERAL_MOVE, SEV_HIGH,
                f"Lateral Movement: {src} repeatedly hitting port "
                f"{dst_port} ({_port_label(dst_port)})",
                device_ip=src,
                raw={"port": dst_port, "service": _port_label(dst_port)}
            )
            _lateral_tracker[src][dst_port] = 0  # reset


def _port_label(port: int) -> str:
    labels = {
        445: "SMB", 3389: "RDP", 135: "DCOM", 22: "SSH",
        23: "Telnet", 139: "NetBIOS", 5985: "WinRM"
    }
    return labels.get(port, str(port))


# ─────────────────────────────────────────────
#  DNS SPOOF DETECTION
# ─────────────────────────────────────────────

def _process_dns(pkt):
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 1):  # qr=1 → response
        return
    if not pkt.haslayer(DNSRR):
        return
    try:
        query_name = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
        answer_ip  = pkt[DNSRR].rdata
        if not isinstance(answer_ip, str):
            return

        _dns_answers[query_name].append(answer_ip)
        unique_answers = set(_dns_answers[query_name][-20:])  # last 20

        if len(unique_answers) >= DNS_SPOOF_THRESHOLD:
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            _dispatch(
                ALERT_DNS_SPOOF, SEV_CRITICAL,
                f"DNS Spoofing: '{query_name}' resolved to {len(unique_answers)} "
                f"different IPs: {unique_answers}. Possible DNS poisoning!",
                device_ip=src,
                raw={"query": query_name, "answers": list(unique_answers)}
            )
            _dns_answers[query_name] = []  # reset
    except Exception:
        pass


# ─────────────────────────────────────────────
#  UNIFIED PACKET HANDLER
# ─────────────────────────────────────────────

def packet_handler(pkt):
    try:
        _process_arp(pkt)
        if pkt.haslayer(TCP):
            _process_tcp(pkt)
        if pkt.haslayer(DNS):
            _process_dns(pkt)
    except Exception:
        pass


# ─────────────────────────────────────────────
#  SNIFFER THREAD
# ─────────────────────────────────────────────

_sniff_thread: Optional[threading.Thread] = None
_stop_event   = threading.Event()


def start_packet_engine(iface=None, duration=0):
    """
    Start the packet engine in a background thread.
    duration=0 → run indefinitely until stop_packet_engine() called.
    """
    if not SCAPY_AVAILABLE:
        print_warn("Scapy not available — packet engine disabled.")
        return

    global _sniff_thread, _stop_event, _gateway_ip
    _stop_event.clear()
    
    if _gateway_ip is None:
        set_gateway_ip(get_default_gateway())
        
    print_info(f"Starting packet engine on iface={iface or 'default'} (Gateway: {_gateway_ip})...")

    def _run():
        import sys
        kwargs = {}
        if sys.platform != "win32":
            kwargs["buffer_size"] = PACKET_BUFFER_SIZE
            
        sniff(
            prn=packet_handler,
            iface=iface,
            store=False,
            filter=PACKET_ENGINE_BPF_FILTER,
            stop_filter=lambda _: _stop_event.is_set(),
            timeout=duration if duration > 0 else None,
            **kwargs
        )

    _sniff_thread = threading.Thread(target=_run, daemon=True, name="PacketEngine")
    _sniff_thread.start()


def stop_packet_engine():
    _stop_event.set()
    if _sniff_thread:
        _sniff_thread.join(timeout=5)
    print_info("Packet engine stopped.")


def get_arp_table() -> Dict[str, str]:
    with _arp_lock:
        return dict(_arp_table)
