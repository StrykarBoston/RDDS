"""
RDDS — DHCP Security Monitoring Module
Passively sniffs DHCP traffic to detect:
  • Rogue DHCP servers (unauthorized OFFER senders)
  • DHCP starvation / flood attacks
  • DHCP lease exhaustion
  • IP address conflicts
  • MAC address randomisation during DISCOVER floods
"""

import time
import struct
import threading
import socket
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from core.config import SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO, DHCP_STARVATION_RATE
from core.alert_engine import fire_alert, print_info, print_warn, print_error

# ────────────────────────────────────────────
#  CONSTANTS
# ────────────────────────────────────────────

DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST",
    4: "DECLINE",  5: "ACK",   6: "NAK",
    7: "RELEASE",  8: "INFORM"
}

# Detection thresholds
STARVATION_DISCOVER_THRESHOLD = DHCP_STARVATION_RATE    # DISCOVERs from unique MACs within window
STARVATION_WINDOW_SECS        = 60    # sliding window for starvation detection (mapped to starvation rate MINUTE)
FLOOD_SAME_MAC_THRESHOLD      = 15    # same MAC sending >15 DISCOVERs in window
FLOOD_SAME_MAC_WINDOW         = 10    # seconds
EXHAUSTION_RATIO_THRESHOLD    = 0.85  # discovers/acks ratio indicating exhaustion

# ────────────────────────────────────────────
#  SHARED STATE  (thread-safe)
# ────────────────────────────────────────────

_lock = threading.Lock()

# Set of known/authorized DHCP server IPs (configurable)
_authorized_servers: Set[str] = set()

# mac → (ip, lease_time, server_mac, timestamp)
_lease_table: Dict[str, Tuple[str, int, str, float]] = {}

# mac → deque of timestamps (for DISCOVER flood per MAC)
_discover_times: Dict[str, deque] = defaultdict(lambda: deque())

# Sliding window of all DISCOVER events: list of (mac, timestamp)
_discover_window: deque = deque()

# ip → list of macs that have this IP (for conflict detection)
_ip_to_macs: Dict[str, Set[str]] = defaultdict(set)

# Alert de-duplication: (alert_type, key) → last alerted timestamp
_alert_dedup: Dict[Tuple[str, str], float] = {}
DEDUP_WINDOW  = 60   # seconds — suppress duplicate alerts within this window

# All captured DHCP events (in-memory ring buffer, max 1000)
_events: deque = deque(maxlen=1000)

# Statistics counters
_stats = {
    "total_discover": 0,
    "total_offer": 0,
    "total_ack": 0,
    "total_nak": 0,
    "rogue_servers_detected": 0,
    "starvation_events": 0,
    "conflict_events": 0,
}

# ────────────────────────────────────────────
#  SCAPY-BASED DHCP PACKET PARSER
# ────────────────────────────────────────────

try:
    from scapy.all import (sniff, DHCP, BOOTP, Ether, IP, UDP, conf)
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ────────────────────────────────────────────
#  DHCP OPTION PARSER (fallback raw struct)
# ────────────────────────────────────────────

def _parse_dhcp_options_raw(options_bytes: bytes) -> Dict:
    """
    Parse DHCP option bytes (after magic cookie) into a dict.
    Used only when Scapy is not available (raw socket fallback).
    """
    parsed = {}
    i = 0
    while i < len(options_bytes):
        opt = options_bytes[i]
        if opt == 255:  # End
            break
        if opt == 0:    # Pad
            i += 1
            continue
        if i + 1 >= len(options_bytes):
            break
        length = options_bytes[i + 1]
        val    = options_bytes[i + 2: i + 2 + length]
        parsed[opt] = val
        i += 2 + length
    return parsed


def _ip_from_bytes(b: bytes) -> str:
    return ".".join(str(x) for x in b[:4]) if len(b) >= 4 else ""


# ────────────────────────────────────────────
#  DETECTION LOGIC
# ────────────────────────────────────────────

def _dedup_ok(alert_type: str, key: str) -> bool:
    """Return True if we should fire this alert (not de-duplicated)."""
    dkey = (alert_type, key)
    now  = time.time()
    with _lock:
        last = _alert_dedup.get(dkey, 0)
        if now - last < DEDUP_WINDOW:
            return False
        _alert_dedup[dkey] = now
    return True


def _record_event(msg_type: str, src_mac: str, src_ip: str,
                  offered_ip: str = "", server_ip: str = "",
                  options: Dict = None):
    """Record a DHCP event to the in-memory ring buffer."""
    event = {
        "timestamp":  datetime.now().isoformat(),
        "msg_type":   msg_type,
        "client_mac": src_mac,
        "client_ip":  src_ip,
        "offered_ip": offered_ip,
        "server_ip":  server_ip,
        "options":    options or {},
    }
    with _lock:
        _events.append(event)
    return event


def _handle_discover(src_mac: str):
    """Handle DHCP DISCOVER — check for starvation flood."""
    now = time.time()
    with _lock:
        _stats["total_discover"] += 1
        # Per-MAC flood window
        dq = _discover_times[src_mac]
        dq.append(now)
        while dq and now - dq[0] > FLOOD_SAME_MAC_WINDOW:
            dq.popleft()
        same_mac_count = len(dq)

        # Sliding global window — collect unique MACs
        _discover_window.append((src_mac, now))
        while _discover_window and now - _discover_window[0][1] > STARVATION_WINDOW_SECS:
            _discover_window.popleft()
        unique_macs_in_window = len(set(m for m, _ in _discover_window))

    # Same-MAC flood
    if same_mac_count >= FLOOD_SAME_MAC_THRESHOLD:
        if _dedup_ok("DHCP_FLOOD_SAME_MAC", src_mac):
            fire_alert(
                alert_type="DHCP_STARVATION",
                severity=SEV_HIGH,
                description=(
                    f"DHCP flood from single MAC {src_mac}: "
                    f"{same_mac_count} DISCOVERs in {FLOOD_SAME_MAC_WINDOW}s. "
                    "Possible DoS attack against DHCP pool."
                ),
                device_mac=src_mac,
                raw_data={"discover_count": same_mac_count, "window_secs": FLOOD_SAME_MAC_WINDOW}
            )
            with _lock:
                _stats["starvation_events"] += 1

    # Multi-MAC starvation (randomised MACs)
    if unique_macs_in_window >= STARVATION_DISCOVER_THRESHOLD:
        if _dedup_ok("DHCP_STARVATION_MULTI", "global"):
            fire_alert(
                alert_type="DHCP_STARVATION",
                severity=SEV_CRITICAL,
                description=(
                    f"DHCP starvation attack detected: {unique_macs_in_window} unique MACs "
                    f"sent DISCOVER in {STARVATION_WINDOW_SECS}s. "
                    "Attacker may be using randomised MACs to exhaust the DHCP pool (e.g. dhcpstarv / Yersinia)."
                ),
                raw_data={"unique_macs": unique_macs_in_window,
                          "window_secs": STARVATION_WINDOW_SECS}
            )
            with _lock:
                _stats["starvation_events"] += 1


def _handle_offer(server_mac: str, server_ip: str, offered_ip: str,
                  client_mac: str):
    """Handle DHCP OFFER — check for rogue DHCP servers."""
    with _lock:
        _stats["total_offer"] += 1

    if not server_ip:
        return

    is_authorized = (not _authorized_servers) or (server_ip in _authorized_servers)
    if not is_authorized:
        if _dedup_ok("ROGUE_DHCP_SERVER", server_ip):
            fire_alert(
                alert_type="ROGUE_DHCP_SERVER",
                severity=SEV_CRITICAL,
                description=(
                    f"Rogue DHCP server detected! Unauthorized OFFER from "
                    f"{server_ip} (MAC: {server_mac}) offering IP {offered_ip} to {client_mac}. "
                    "This is a classic MITM / network hijack attack vector."
                ),
                device_ip=server_ip,
                device_mac=server_mac,
                raw_data={
                    "server_ip":   server_ip,
                    "server_mac":  server_mac,
                    "offered_ip":  offered_ip,
                    "client_mac":  client_mac,
                }
            )
            with _lock:
                _stats["rogue_servers_detected"] += 1


def _handle_nak(server_ip: str, client_mac: str):
    """Handle DHCP NAK — check for rogue NAK spoofing."""
    with _lock:
        _stats["total_nak"] += 1

    if not server_ip:
        return

    is_authorized = (not _authorized_servers) or (server_ip in _authorized_servers)
    if not is_authorized:
        if _dedup_ok("DHCP_NAK_SPOOFING", server_ip):
            fire_alert(
                alert_type="DHCP_NAK_SPOOFING",
                severity=SEV_CRITICAL,
                description=(
                    f"Rogue DHCP NAK sent by {server_ip} (unauthorized). "
                    f"Attempt to force {client_mac} off the network."
                ),
                device_ip=server_ip,
                device_mac=client_mac,
                raw_data={"server_ip": server_ip, "client_mac": client_mac}
            )


def _handle_ack(server_ip: str, client_mac: str, assigned_ip: str,
                lease_time: int):
    """Handle DHCP ACK — update lease table, check IP conflicts."""
    with _lock:
        _stats["total_ack"] += 1

    if not client_mac or not assigned_ip:
        return

    # Update lease table
    with _lock:
        _lease_table[client_mac] = (
            assigned_ip, lease_time, server_ip, time.time()
        )
        if assigned_ip != "0.0.0.0":
            # Conflict detection: same IP mapped to multiple MACs
            _ip_to_macs[assigned_ip].add(client_mac)
            conflicting_macs = _ip_to_macs[assigned_ip].copy()
        else:
            conflicting_macs = set()

    if len(conflicting_macs) > 1:
        if _dedup_ok("DHCP_IP_CONFLICT", assigned_ip):
            fire_alert(
                alert_type="DHCP_IP_CONFLICT",
                severity=SEV_HIGH,
                description=(
                    f"IP conflict detected! IP {assigned_ip} is being "
                    f"assigned to multiple MACs: {list(conflicting_macs)}. "
                    "Could indicate ARP spoofing or misconfigured hosts."
                ),
                device_ip=assigned_ip,
                raw_data={"ip": assigned_ip, "macs": list(conflicting_macs)}
            )
            with _lock:
                _stats["conflict_events"] += 1

    # Lease exhaustion heuristic
    with _lock:
        total_d = max(_stats["total_discover"], 1)
        total_a = _stats["total_ack"]
        if total_d > 20 and (total_a / total_d) < (1 - EXHAUSTION_RATIO_THRESHOLD):
            if _dedup_ok("DHCP_LEASE_EXHAUSTION", "global"):
                fire_alert(
                    alert_type="DHCP_LEASE_EXHAUSTION",
                    severity=SEV_HIGH,
                    description=(
                        f"DHCP lease exhaustion suspected: "
                        f"{total_d} DISCOVERs but only {total_a} ACKs. "
                        f"ACK ratio: {total_a/total_d:.1%}. "
                        "The DHCP pool may be nearly full."
                    ),
                    raw_data={"discovers": total_d, "acks": total_a}
                )


# ────────────────────────────────────────────
#  SCAPY PACKET HANDLER
# ────────────────────────────────────────────

def _scapy_packet_handler(pkt):
    """Process each sniffed packet via Scapy."""
    try:
        if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
            return

        bootp = pkt[BOOTP]
        src_mac    = pkt[Ether].src.lower() if pkt.haslayer(Ether) else ""
        src_ip     = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"
        client_mac = ":".join(f"{b:02x}" for b in bootp.chaddr[:6])
        offered_ip = bootp.yiaddr
        server_ip  = bootp.siaddr

        # Extract DHCP options safely (handle 'end' and 'pad' strings)
        dhcp_opts = {}
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                dhcp_opts[opt[0]] = opt[1]
                
        msg_type_raw = dhcp_opts.get("message-type", 0)
        msg_type     = DHCP_MSG_TYPES.get(msg_type_raw, f"TYPE-{msg_type_raw}")
        lease_time   = dhcp_opts.get("lease_time", 0) or 0
        server_id    = dhcp_opts.get("server_id", server_ip)
        if isinstance(server_id, bytes):
            server_id = socket.inet_ntoa(server_id)

        _record_event(msg_type, src_mac, src_ip, offered_ip, server_id or src_ip)

        if msg_type_raw == 1:    # DISCOVER
            _handle_discover(client_mac or src_mac)
        elif msg_type_raw == 2:  # OFFER
            _handle_offer(src_mac, server_id or src_ip, offered_ip, client_mac)
        elif msg_type_raw == 5:  # ACK
            _handle_ack(server_id or src_ip, client_mac, offered_ip, lease_time)
        elif msg_type_raw == 6:  # NAK
            _handle_nak(server_id or src_ip, client_mac)

    except Exception as e:
        print_error(f"DHCP Packet Handler Error: {e}")


# ────────────────────────────────────────────
#  RAW SOCKET FALLBACK (when Scapy unavailable)
# ────────────────────────────────────────────

def _raw_dhcp_listener(stop_event: threading.Event):
    """
    Listen for raw UDP DHCP packets (ports 67/68) using raw sockets.
    Windows requires admin privileges. Falls back gracefully.
    """
    try:
        import socket as _sock
        # Bind raw socket to capture UDP
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_RAW, _sock.IPPROTO_UDP)
        s.setsockopt(_sock.IPPROTO_IP, _sock.IP_HDRINCL, 1)
        s.settimeout(2.0)

        print_info("DHCP Monitor: raw socket mode active (Scapy unavailable)")
        while not stop_event.is_set():
            try:
                data, addr = s.recvfrom(65535)
                if len(data) < 20:
                    continue
                # Extract UDP payload (skip IP header + UDP header)
                ip_header_len = (data[0] & 0x0F) * 4
                udp_payload   = data[ip_header_len + 8:]
                if len(udp_payload) < 240:
                    continue

                # BOOTP/DHCP checks
                op     = udp_payload[0]
                chaddr = ":".join(f"{b:02x}" for b in udp_payload[28:34])
                yiaddr = _ip_from_bytes(udp_payload[16:20])
                siaddr = _ip_from_bytes(udp_payload[20:24])

                # Parse options (skip 4-byte magic cookie at offset 236)
                if udp_payload[236:240] == b'\x63\x82\x53\x63':
                    opts    = _parse_dhcp_options_raw(udp_payload[240:])
                    mt_raw  = opts.get(53, b'\x00')[0] if opts.get(53) else 0
                    msg_type = DHCP_MSG_TYPES.get(mt_raw, f"TYPE-{mt_raw}")
                    src_ip   = addr[0]

                    _record_event(msg_type, chaddr, src_ip, yiaddr, siaddr)
                    if mt_raw == 1:
                        _handle_discover(chaddr)
                    elif mt_raw == 2:
                        _handle_offer(chaddr, src_ip, yiaddr, chaddr)
                    elif mt_raw == 5:
                        lease_bytes = opts.get(51, b'\x00\x00\x01\x00')
                        lt = struct.unpack("!I", lease_bytes[:4])[0] if len(lease_bytes) >= 4 else 3600
                        _handle_ack(src_ip, chaddr, yiaddr, lt)
                    elif mt_raw == 6:
                        _handle_nak(src_ip, chaddr)
            except _sock.timeout:
                continue
            except Exception as e:
                print_error(f"Error in DHCP raw listener loop: {e}")
        s.close()
    except Exception as e:
        print_warn(f"DHCP raw socket unavailable: {e}. Run as Administrator for DHCP monitoring.")


# ────────────────────────────────────────────
#  PUBLIC API — Monitor Lifecycle
# ────────────────────────────────────────────

class DHCPMonitor:
    """
    Thread-based DHCP security monitor.
    Usage:
        mon = DHCPMonitor(iface="Wi-Fi", authorized_servers=["192.168.1.1"])
        mon.start()
        ...
        mon.stop()
    """
    def __init__(self, iface: Optional[str] = None,
                 authorized_servers: Optional[List[str]] = None):
        self.iface    = iface
        self._thread  = None
        self._stop    = threading.Event()
        if authorized_servers:
            with _lock:
                _authorized_servers.update(authorized_servers)

    def start(self):
        """Start background DHCP monitoring thread."""
        self._stop.clear()
        if SCAPY_OK:
            self._thread = threading.Thread(
                target=self._run_scapy, daemon=True, name="DHCPMonitor"
            )
        else:
            self._thread = threading.Thread(
                target=_raw_dhcp_listener, args=(self._stop,),
                daemon=True, name="DHCPMonitor-Raw"
            )
        self._thread.start()
        print_info(f"DHCP Monitor started (iface={self.iface or 'default'}, "
                   f"authorized={list(_authorized_servers) or 'any'})")

    def _run_scapy(self):
        """Scapy-based DHCP sniff loop."""
        from core.config import normalize_iface
        try:
            sniff(
                iface=normalize_iface(self.iface),
                filter="udp and (port 67 or port 68)",
                prn=_scapy_packet_handler,
                stop_filter=lambda p: self._stop.is_set(),
                store=False
            )
        except Exception as e:
            print_error(f"DHCP Monitor Scapy error: {e}. Are you running as Administrator?")

    def stop(self):
        """Signal the monitor thread to stop."""
        self._stop.set()
        print_info("DHCP Monitor stopped.")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def set_authorized_servers(self, server_ips: List[str]):
        with _lock:
            _authorized_servers.clear()
            _authorized_servers.update(server_ips)

    def add_authorized_server(self, server_ip: str):
        with _lock:
            _authorized_servers.add(server_ip)


# ────────────────────────────────────────────
#  PUBLIC API — Data Access
# ────────────────────────────────────────────

def get_events(limit: int = 200) -> List[Dict]:
    with _lock:
        return list(reversed(list(_events)))[:limit]


def get_lease_table() -> Dict:
    with _lock:
        return {
            mac: {
                "ip":           lease[0],
                "lease_time":   lease[1],
                "server_ip":    lease[2],
                "seen_at":      datetime.fromtimestamp(lease[3]).isoformat(),
            }
            for mac, lease in _lease_table.items()
        }


def get_stats() -> Dict:
    with _lock:
        return _stats.copy()


def get_authorized_servers() -> List[str]:
    with _lock:
        return list(_authorized_servers)
