"""
RDDS — MAC Analyzer Module
Detects MAC spoofing, OUI mismatches, and rapid MAC changes.
"""

import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from core.config import (MAC_CHANGE_WINDOW, ALERT_MAC_SPOOF,
                          SEV_HIGH, SEV_CRITICAL)
from core import database as db
from core.alert_engine import fire_alert

# ─────────────────────────────────────────────
#  STATE TRACKING (in-memory)
# ─────────────────────────────────────────────

# mac → list of (ip, timestamp)
_mac_ip_history: Dict[str, List[Tuple[str, float]]] = defaultdict(list)

# ip → list of (mac, timestamp)
_ip_mac_history: Dict[str, List[Tuple[str, float]]] = defaultdict(list)


# ─────────────────────────────────────────────
#  VENDOR PROFILE ANALYSIS
# ─────────────────────────────────────────────

# Known mismatches: vendor prefix but behaves like server/infra
SUSPICIOUS_VENDOR_BEHAVIORS = {
    "apple":   ["server", "smb", "domain_controller"],
    "samsung": ["server", "router", "gateway"],
    "xiaomi":  ["gateway", "server"],
    "tp-link": [],
    "unknown": ["all"],  # Unknown vendor is always suspicious
}

VIRTUALIZED_OUIS = {"vmware", "virtualbox", "qemu", "proxmox", "hyper-v", "xen", "parallels"}
PHYSICAL_ONLY_BEHAVIORS = {"camera", "smart_plug", "iot_sensor", "printer"}

def vendor_mismatch_suspicious(vendor: str, behavior_tags: List[str]) -> bool:
    """
    Returns True if the vendor/behavior combination looks suspicious.
    E.g., MAC says 'Apple Inc' but device is acting like a server,
    or MAC is 'VMware' but behaves like an IoT camera.
    """
    v = vendor.lower()
    
    # Check for Virtualized OUI spoofing as physical hardware
    is_virtualized = any(virt in v for virt in VIRTUALIZED_OUIS)
    if is_virtualized:
        for b in behavior_tags:
            if b in PHYSICAL_ONLY_BEHAVIORS:
                return True
                
    # Check standard mappings
    for key, bad_behaviors in SUSPICIOUS_VENDOR_BEHAVIORS.items():
        if key in v:
            if bad_behaviors == ["all"]:
                return True
            for b in behavior_tags:
                if b in bad_behaviors:
                    return True
    return False


# ─────────────────────────────────────────────
#  MAC-IP RELATIONSHIP TRACKING
# ─────────────────────────────────────────────

def track_device(mac: str, ip: str):
    """
    Record a MAC→IP mapping observation.
    Must be called for every discovered device.
    Returns list of anomaly flags detected.
    """
    mac = mac.lower()
    now = time.time()
    flags = []

    # Track mac → ip
    _mac_ip_history[mac].append((ip, now))
    # Keep only last 100 observations
    _mac_ip_history[mac] = _mac_ip_history[mac][-100:]

    # Track ip → mac
    _ip_mac_history[ip].append((mac, now))
    _ip_mac_history[ip] = _ip_mac_history[ip][-100:]

    # ── Check 1: Same MAC, multiple different IPs ──────────────────────────
    recent_ips = {e[0] for e in _mac_ip_history[mac]
                  if now - e[1] <= MAC_CHANGE_WINDOW}
    if len(recent_ips) > 2:
        flags.append("multiple_ips_same_mac")
        fire_alert(
            alert_type=ALERT_MAC_SPOOF,
            severity=SEV_HIGH,
            description=(f"MAC {mac} observed on {len(recent_ips)} different IPs "
                         f"within {MAC_CHANGE_WINDOW}s: {recent_ips}"),
            device_mac=mac,
            device_ip=ip,
            raw_data={"ips": list(recent_ips)}
        )

    # ── Check 2: Same IP, multiple different MACs ──────────────────────────
    recent_macs = {e[0] for e in _ip_mac_history[ip]
                   if now - e[1] <= MAC_CHANGE_WINDOW}
    recent_macs_fast = {e[0] for e in _ip_mac_history[ip]
                        if now - e[1] <= 30}
    if len(recent_macs_fast) > 5:
        flags.append("fast_flux_mac_spoofing")
        fire_alert(
            alert_type=ALERT_MAC_SPOOF,
            severity=SEV_CRITICAL,
            description=(f"Fast-Flux MAC Spoofing: IP {ip} used by {len(recent_macs_fast)} "
                         f"different MACs in 30s! Immediate exhaustion/spoofing attack targeting infrastructure."),
            device_mac=mac,
            device_ip=ip,
            raw_data={"macs": list(recent_macs_fast)}
        )
    elif len(recent_macs) > 1:
        flags.append("mac_changed_recently")
        fire_alert(
            alert_type=ALERT_MAC_SPOOF,
            severity=SEV_CRITICAL,
            description=(f"IP {ip} used by {len(recent_macs)} different MACs "
                         f"in {MAC_CHANGE_WINDOW}s: {recent_macs} — Possible MAC Spoofing!"),
            device_mac=mac,
            device_ip=ip,
            raw_data={"macs": list(recent_macs)}
        )

    return flags


# ─────────────────────────────────────────────
#  GATEWAY MAC INTEGRITY
# ─────────────────────────────────────────────

_known_gateway_mac: Optional[str] = None


def set_gateway_mac(mac: str):
    """Call this once at startup to record the legitimate gateway MAC."""
    global _known_gateway_mac
    _known_gateway_mac = mac.lower()


def check_gateway_mac(ip: str, mac: str, gateway_ip: str) -> bool:
    """
    If `ip` equals the gateway IP but `mac` doesn't match the known
    gateway MAC → likely MITM / ARP poisoning.
    Returns True if suspicious.
    """
    global _known_gateway_mac
    if ip != gateway_ip:
        return False
    if _known_gateway_mac is None:
        _known_gateway_mac = mac.lower()
        return False
    if mac.lower() != _known_gateway_mac:
        fire_alert(
            alert_type="MITM_DETECTED",
            severity=SEV_CRITICAL,
            description=(f"Gateway IP {gateway_ip} is now associated with "
                         f"MAC {mac} — was {_known_gateway_mac}. "
                         "POSSIBLE ARP SPOOFING / MITM ATTACK!"),
            device_mac=mac,
            device_ip=ip,
            raw_data={"expected_mac": _known_gateway_mac, "seen_mac": mac}
        )
        return True
    return False


# ─────────────────────────────────────────────
#  OUI MISMATCH ANALYZER
# ─────────────────────────────────────────────

def analyze_oui_vs_behavior(mac: str, vendor: str,
                             behavior_tags: List[str]) -> Optional[str]:
    """
    Cross-check MAC vendor vs. observed behavior.
    Returns a warning string, or None if clean.
    """
    if vendor_mismatch_suspicious(vendor, behavior_tags):
        msg = (f"OUI Mismatch: MAC {mac} belongs to '{vendor}' "
               f"but behavior tags {behavior_tags} look suspicious.")
        fire_alert(
            alert_type=ALERT_MAC_SPOOF,
            severity=SEV_HIGH,
            description=msg,
            device_mac=mac,
            raw_data={"vendor": vendor, "behavior": behavior_tags}
        )
        return msg
    return None


# ─────────────────────────────────────────────
#  ANALYZE A BATCH OF DEVICES
# ─────────────────────────────────────────────

def analyze_devices(devices: List[Dict]) -> List[Dict]:
    """
    Run MAC analysis on a list of discovered devices.
    Returns each device enriched with mac_flags list.
    """
    for d in devices:
        try:
            mac  = d.get("mac", "")
            ip   = d.get("ip",  "")
            if not mac or not ip:
                continue
            flags = track_device(mac, ip)
            d.setdefault("flags", [])
            d["flags"].extend(flags)
        except Exception as e:
            from core.alert_engine import print_error
            print_error(f"Error analyzing device {d.get('ip', 'unknown')}: {e}")
    return devices
