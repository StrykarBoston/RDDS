"""
RDDS — Behavioral Analyzer Module
Tracks per-device behavior over time and flags anomalous patterns
such as sudden traffic spikes, protocol abuse, etc.
"""

import time
import threading
from collections import defaultdict
from typing import Dict, List, Tuple

from core.config import (ARP_FLOOD_THRESHOLD, PORT_SCAN_THRESHOLD,
                          SEV_HIGH, SEV_MEDIUM, SEV_CRITICAL)
from core.alert_engine import fire_alert, print_info

# ─────────────────────────────────────────────
#  TRAFFIC TRACKING STATE
# ─────────────────────────────────────────────

WINDOW = 60   # seconds for behavioral window

# mac → list of (timestamp, pkt_size)
_traffic: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
_lock    = threading.Lock()

# mac → dict of protocol counts
_protocol_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

# Flood detection: mac → recent packet timestamps in WINDOW
_pkt_flood: Dict[str, List[float]] = defaultdict(list)
FLOOD_PKT_THRESHOLD = 5000   # pkts per WINDOW seconds

# Promiscuous mode heuristic:
# A device receiving packets destined to many different MACs is suspicious
_dst_mac_seen: Dict[str, set] = defaultdict(set)
PROMISCUOUS_THRESHOLD = 20

# ─────────────────────────────────────────────
#  RECORD TRAFFIC
# ─────────────────────────────────────────────

def record_traffic(src_mac: str, dst_mac: str,
                   protocol: str, pkt_size: int = 0):
    """
    Log a packet from src_mac for behavioral analysis.
    Call this from the packet engine handler for every packet.
    """
    now = time.time()
    with _lock:
        # Traffic log
        _traffic[src_mac].append((now, pkt_size))
        # Trim old entries
        _traffic[src_mac] = [
            e for e in _traffic[src_mac] if now - e[0] <= WINDOW
        ]

        # Protocol count
        _protocol_counts[src_mac][protocol] += 1

        # Flood counter
        _pkt_flood[src_mac].append(now)
        _pkt_flood[src_mac] = [
            t for t in _pkt_flood[src_mac] if now - t <= WINDOW
        ]
        if len(_pkt_flood[src_mac]) >= FLOOD_PKT_THRESHOLD:
            fire_alert(
                alert_type="PACKET_FLOOD",
                severity=SEV_HIGH,
                description=(f"Packet flood from MAC {src_mac}: "
                             f"{len(_pkt_flood[src_mac])} pkts in {WINDOW}s"),
                device_mac=src_mac
            )
            _pkt_flood[src_mac] = []

        # Promiscuous mode heuristic
        _dst_mac_seen[src_mac].add(dst_mac)
        if len(_dst_mac_seen[src_mac]) >= PROMISCUOUS_THRESHOLD:
            fire_alert(
                alert_type="PROMISCUOUS_MODE",
                severity=SEV_MEDIUM,
                description=(f"Device {src_mac} receiving packets to "
                             f"{len(_dst_mac_seen[src_mac])} different MACs — "
                             "possible network sniffing in promiscuous mode."),
                device_mac=src_mac
            )
            _dst_mac_seen[src_mac] = set()


# ─────────────────────────────────────────────
#  ANOMALY SCORING
# ─────────────────────────────────────────────

def compute_behavior_score(mac: str) -> Tuple[int, List[str]]:
    """
    Analyze behavioral history and return an anomaly score (0–100)
    and list of detected anomaly tags.
    """
    score = 0
    tags  = []
    with _lock:
        traffic   = _traffic.get(mac, [])
        protocols = _protocol_counts.get(mac, {})
        pkt_count = len(traffic)
        flood_cnt = len(_pkt_flood.get(mac, []))

    # High packet volume
    if pkt_count > 1000:
        score += 20
        tags.append("high_traffic_volume")

    # Flood indicator
    if flood_cnt > FLOOD_PKT_THRESHOLD * 0.5:
        score += 30
        tags.append("packet_flood")

    # Dangerous protocol dominance
    total_pkts = sum(protocols.values()) or 1
    smb_ratio  = protocols.get("SMB", 0) / total_pkts
    rdp_ratio  = protocols.get("RDP", 0) / total_pkts
    dns_ratio  = protocols.get("DNS", 0) / total_pkts
    icmp_ratio = protocols.get("ICMP", 0) / total_pkts

    if smb_ratio > 0.4:
        score += 20
        tags.append("smb_dominance")
    if rdp_ratio > 0.4:
        score += 20
        tags.append("rdp_dominance")
    if dns_ratio > 0.6:
        score += 25
        tags.append("dns_tunneling_suspected")
    if icmp_ratio > 0.4:
        score += 20
        tags.append("icmp_flood_suspected")

    # Unknown/rare protocols
    known_protocols = {"ARP", "DNS", "HTTP", "HTTPS", "SMB", "RDP",
                       "TCP", "UDP", "ICMP", "TLS", "MDNS", "LLMNR", "DHCP"}
    for proto in protocols:
        if proto not in known_protocols:
            score += 10
            tags.append(f"rare_protocol:{proto}")
            break

    return min(score, 100), tags


# ─────────────────────────────────────────────
#  PERIODIC BEHAVIORAL REPORT
# ─────────────────────────────────────────────

def analyze_all_devices() -> List[Dict]:
    """
    Run behavioral analysis on every tracked device.
    Returns list of dicts: {mac, anomaly_score, tags}
    """
    results = []
    with _lock:
        macs = list(_traffic.keys())

    for mac in macs:
        score, tags = compute_behavior_score(mac)
        if score > 20:
            results.append({
                "mac":           mac,
                "anomaly_score": score,
                "tags":          tags
            })
            if score >= 60:
                fire_alert(
                    alert_type="BEHAVIORAL_ANOMALY",
                    severity=SEV_HIGH if score < 80 else SEV_CRITICAL,
                    description=(f"High behavioral anomaly score for {mac}: "
                                 f"{score}/100 — Tags: {tags}"),
                    device_mac=mac,
                    raw_data={"score": score, "tags": tags}
                )
    return results


def reset_device_history(mac: str):
    """Clear behavioral history for a device (e.g., after whitelisting)."""
    with _lock:
        _traffic.pop(mac, None)
        _protocol_counts.pop(mac, None)
        _pkt_flood.pop(mac, None)
        _dst_mac_seen.pop(mac, None)
