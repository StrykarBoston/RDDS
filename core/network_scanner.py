"""
RDDS — Network Scanner Module
Performs ARP scanning, ICMP ping sweep, and passive packet sniffing
to discover all devices on the local network.
"""

import time
import json
import socket
import threading
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

try:
    from scapy.all import (ARP, Ether, srp, IP, ICMP, sr1,
                           sniff, conf, get_if_list)
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core.config import (NETWORK_TARGET, SNIFF_TIMEOUT, OUI_PATH,
                          SNIFF_IFACE, SEV_INFO)
from core import database as db

# ─────────────────────────────────────────────
#  OUI / VENDOR DATABASE
# ─────────────────────────────────────────────

_oui_cache: Dict[str, str] = {}

def _load_oui():
    global _oui_cache
    try:
        with open(OUI_PATH, "r") as f:
            _oui_cache = json.load(f)
    except FileNotFoundError:
        _oui_cache = {}

_load_oui()


def get_vendor(mac: str) -> str:
    """Lookup MAC vendor from OUI prefix (first 6 hex chars)."""
    if not mac:
        return "Unknown"
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return _oui_cache.get(prefix, "Unknown")


# ─────────────────────────────────────────────
#  HOSTNAME RESOLUTION
# ─────────────────────────────────────────────

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ─────────────────────────────────────────────
#  ARP SCAN (Active)
# ─────────────────────────────────────────────

def arp_scan(target: str = NETWORK_TARGET, timeout: int = 3) -> List[Dict]:
    """
    Send ARP requests to the network range and collect responses.
    Returns list of dicts: {ip, mac, vendor, hostname}
    """
    if not SCAPY_AVAILABLE:
        print("[!] Scapy not available — falling back to arp_table_windows()")
        return arp_table_windows()

    discovered = []
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        answered, _ = srp(packet, timeout=timeout, verbose=False)
        for sent, received in answered:
            mac    = received.hwsrc.lower()
            ip     = received.psrc
            vendor = get_vendor(mac)
            host   = resolve_hostname(ip)
            discovered.append({
                "ip":       ip,
                "mac":      mac,
                "vendor":   vendor,
                "hostname": host,
                "is_randomized_mac": is_mac_randomized(mac),
                "os_guess": "Unknown",
                "method":   "ARP"
            })
    except Exception as e:
        print(f"[!] ARP scan error: {e}")
        return arp_table_windows()

    return discovered


# ─────────────────────────────────────────────
#  WINDOWS ARP TABLE FALLBACK
# ─────────────────────────────────────────────

def arp_table_windows() -> List[Dict]:
    """
    Parse Windows ARP table via `arp -a` as a fallback
    when Scapy/Npcap is not available.
    """
    discovered = []
    try:
        result = subprocess.check_output(
            ["arp", "-a"], text=True, stderr=subprocess.DEVNULL
        )
        for line in result.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0][0].isdigit():
                ip  = parts[0]
                mac = parts[1].lower().replace("-", ":")
                if mac in ("ff:ff:ff:ff:ff:ff", "01:00:5e", "33:33"):
                    continue
                vendor = get_vendor(mac)
                host   = resolve_hostname(ip)
                discovered.append({
                    "ip":       ip,
                    "mac":      mac,
                    "vendor":   vendor,
                    "hostname": host,
                    "is_randomized_mac": is_mac_randomized(mac),
                    "os_guess": "Unknown",
                    "method":   "ARP-TABLE"
                })
    except Exception as e:
        print(f"[!] ARP table fallback error: {e}")
    return discovered


# ─────────────────────────────────────────────
#  ICMP PING SWEEP
# ─────────────────────────────────────────────

def ping_sweep(target: str = NETWORK_TARGET) -> List[str]:
    """
    Use Windows `ping` in parallel threads to sweep a /24 subnet.
    Returns list of responding IPs.
    """
    # Parse base from CIDR (supports /24 only for sweep)
    base = ".".join(target.split(".")[:3])
    alive = []
    lock  = threading.Lock()

    def _ping(ip):
        try:
            out = subprocess.run(
                ["ping", "-n", "1", "-w", "500", ip],
                capture_output=True, text=True, timeout=3
            )
            if "TTL=" in out.stdout or "ttl=" in out.stdout:
                with lock:
                    alive.append(ip)
        except Exception:
            pass

    threads = []
    for i in range(1, 255):
        ip = f"{base}.{i}"
        t  = threading.Thread(target=_ping, args=(ip,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=5)

    return alive


# ─────────────────────────────────────────────
#  PASSIVE SNIFFER
# ─────────────────────────────────────────────

def is_mac_randomized(mac: str) -> bool:
    """Check if the Locally Administered bit is set indicating randomization."""
    try:
        first_byte = int(mac.replace(':', '')[:2], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False

def guess_os(ttl: int, window: int) -> str:
    """Passively guess OS based on TTL and Window Size heuristics."""
    if not ttl: return "Unknown"
    if 65 <= ttl <= 128:
        return "Windows"
    elif ttl <= 64:
        if window in (65535, 65536) or window > 60000:
            return "macOS/iOS"
        else:
            return "Linux/Android"
    elif ttl > 128:
        return "Network Device/Appliance"
    return "Unknown"

_sniffed_devices: Dict[str, Dict] = {}
_sniff_lock = threading.Lock()

def _handle_packet(pkt):
    """Process each sniffed packet for device discovery and OS profiling."""
    mac, ip, os_guess = None, None, "Unknown"
    
    with _sniff_lock:
        if pkt.haslayer(ARP):
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc.lower()
            if mac and ip and not ip.startswith("0."):
                if mac not in _sniffed_devices:
                    _sniffed_devices[mac] = {
                        "ip": ip, "mac": mac,
                        "vendor": get_vendor(mac),
                        "is_randomized_mac": is_mac_randomized(mac),
                        "os_guess": "Unknown",
                        "method": "PASSIVE"
                    }
        elif pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip = pkt[IP].src
            mac = pkt.src.lower() if hasattr(pkt, 'src') and isinstance(pkt.src, str) else None
            # Extract Passive Fingerprints
            ttl = pkt[IP].ttl
            window = pkt[TCP].window
            os_guess = guess_os(ttl, window)
            
            if mac and ip and not ip.startswith("0."):
                if mac not in _sniffed_devices:
                    _sniffed_devices[mac] = {
                        "ip": ip, "mac": mac,
                        "vendor": get_vendor(mac),
                        "is_randomized_mac": is_mac_randomized(mac),
                        "os_guess": os_guess,
                        "method": "PASSIVE"
                    }
                else:
                    if os_guess != "Unknown":
                        _sniffed_devices[mac]["os_guess"] = os_guess


def passive_sniff(iface=None, timeout: int = SNIFF_TIMEOUT) -> List[Dict]:
    """
    Passively sniff ARP and TCP packets for discovery and OS fingerprinting.
    """
    if not SCAPY_AVAILABLE:
        return []
    global _sniffed_devices
    iface = iface or SNIFF_IFACE
    _sniffed_devices = {}
    
    # We use importing from SCAPY_AVAILABLE scope for TCP
    try:
        from core.config import PACKET_ENGINE_BPF_FILTER
        sniff(filter="arp or tcp", prn=_handle_packet,
              iface=iface, timeout=timeout, store=False)
    except Exception as e:
        print(f"[!] Passive sniff error: {e}")

    with _sniff_lock:
        return list(_sniffed_devices.values())


# ─────────────────────────────────────────────
#  FULL SCAN ORCHESTRATOR
# ─────────────────────────────────────────────

def full_scan(target: str = NETWORK_TARGET,
              use_passive: bool = False,
              passive_timeout: int = 15) -> List[Dict]:
    """
    Run ARP scan + optional passive sniff, merge results,
    persist to DB, and return merged device list.
    """
    print(f"[*] Running ARP scan on {target}...")
    devices = arp_scan(target)

    if use_passive:
        print(f"[*] Passive sniff for {passive_timeout}s...")
        passive = passive_sniff(timeout=passive_timeout)
        # Merge: passive results enhance active results or add new ones
        existing_macs = {d["mac"]: d for d in devices}
        for p in passive:
            if p["mac"] not in existing_macs:
                devices.append(p)
            else:
                if p.get("os_guess", "Unknown") != "Unknown":
                    existing_macs[p["mac"]]["os_guess"] = p["os_guess"]

    # Persist to DB
    for d in devices:
        existing = db.get_device(d["mac"])
        is_wl = 1 if (existing and existing["is_whitelisted"]) else 0
        db.upsert_device(
            mac=d["mac"], ip=d["ip"], vendor=d["vendor"],
            hostname=d.get("hostname", ""), is_whitelisted=is_wl
        )

    return devices
