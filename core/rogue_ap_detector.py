"""
RDDS — Rogue Access Point Detector Module
Detects Evil Twin APs, open/weak encryption, unknown BSSIDs.
"""

import subprocess
import platform
import re
import time
import threading
from typing import Dict, List, Optional
from collections import defaultdict
from scapy.all import sniff, Dot11Beacon, Dot11

from core.config import (ALERT_ROGUE_AP, ALERT_EVIL_TWIN, ALERT_OPEN_AP,
                          SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, BEACON_JITTER_THRESHOLD)
from core.alert_engine import fire_alert, print_info, print_warn
from core.device_manager import is_ssid_allowed

# ─────────────────────────────────────────────
#  WINDOWS WIFI SCANNER (netsh)
# ─────────────────────────────────────────────

def scan_wifi_networks() -> List[Dict]:
    """
    Scans visible Wi-Fi networks according to the underlying platform.
    Returns list of AP dicts: {ssid, bssids: [], authentication, encryption, signal, channel, radio_type}
    """
    system = platform.system()
    if system == "Windows":
        return _scan_windows()
    elif system == "Linux":
        return _scan_linux()
    else:
        print_warn(f"Unsupported OS for Wi-Fi scanning: {system}")
        return []

def _scan_windows() -> List[Dict]:
    aps = []
    try:
        result = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            text=True, stderr=subprocess.DEVNULL, encoding="utf-8", errors="ignore"
        )
        current_ap = {}
        for line in result.splitlines():
            line = line.strip()
            if line.startswith("SSID") and "BSSID" not in line:
                if current_ap:
                    aps.append(current_ap)
                name = line.split(":", 1)[-1].strip()
                current_ap = {"ssid": name, "bssids": []}
            elif line.startswith("BSSID"):
                bssid = line.split(":", 1)[-1].strip().lower()
                current_ap.setdefault("bssids", []).append(bssid)
            elif "Authentication" in line:
                current_ap["authentication"] = line.split(":", 1)[-1].strip()
            elif "Encryption" in line:
                current_ap["encryption"] = line.split(":", 1)[-1].strip()
            elif "Signal" in line:
                current_ap["signal"] = line.split(":", 1)[-1].strip()
            elif "Channel" in line:
                current_ap["channel"] = line.split(":", 1)[-1].strip()
            elif "Radio type" in line:
                current_ap["radio_type"] = line.split(":", 1)[-1].strip()
        if current_ap:
            aps.append(current_ap)
    except Exception as e:
        print_warn(f"netsh scan failed: {e}")
    return aps

def _scan_linux() -> List[Dict]:
    aps = []
    try:
        result = subprocess.check_output(
            ["nmcli", "-m", "multiline", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN", "dev", "wifi"],
            text=True, stderr=subprocess.DEVNULL, encoding="utf-8", errors="ignore"
        )
        current_ap = {}
        for line in result.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
            if key == "SSID":
                if current_ap: aps.append(current_ap)
                current_ap = {"ssid": val, "bssids": []}
            elif key == "BSSID":
                current_ap.setdefault("bssids", []).append(val.lower())
            elif key == "SECURITY":
                current_ap["authentication"] = val  
                current_ap["encryption"] = val
            elif key == "SIGNAL":
                current_ap["signal"] = val
            elif key == "CHAN":
                current_ap["channel"] = val
        if current_ap:
            aps.append(current_ap)
    except Exception as e:
        print_warn(f"nmcli scan failed: {e}")
    return aps


# ─────────────────────────────────────────────
#  CONNECTED NETWORK INFO
# ─────────────────────────────────────────────

def get_connected_ap() -> Dict:
    """Get currently connected AP info (SSID, BSSID, channel, auth)."""
    info = {}
    try:
        result = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            text=True, stderr=subprocess.DEVNULL, encoding="utf-8", errors="ignore"
        )
        for line in result.splitlines():
            line = line.strip()
            if "SSID" in line and "BSSID" not in line:
                info["ssid"] = line.split(":", 1)[-1].strip()
            elif "BSSID" in line:
                info["bssid"] = line.split(":", 1)[-1].strip().lower()
            elif "Authentication" in line:
                info["authentication"] = line.split(":", 1)[-1].strip()
            elif "Channel" in line:
                info["channel"] = line.split(":", 1)[-1].strip()
            elif "Signal" in line:
                info["signal"] = line.split(":", 1)[-1].strip()
    except Exception as e:
        print_warn(f"Could not get connected AP info: {e}")
    return info


# ─────────────────────────────────────────────
#  ADVANCED DETECTION STATE & SNIFFING
# ─────────────────────────────────────────────
_known_bssids: Dict[str, str] = {}   # bssid → ssid baseline
_beacon_timestamps = defaultdict(list)
_bssid_capabilities = {}
_capture_lock = threading.Lock()

def _beacon_handler(pkt):
    """
    Extract exact timestamps of Dot11 Beacons and standard capabilities.
    Software Rogue APs suffer from microsecond jitter due to host CPU 
    scheduling, while hardware APs have precise ASIC clocks.
    """
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt.addr2
        if bssid:
            bssid = bssid.lower()
            with _capture_lock:
                _beacon_timestamps[bssid].append(time.time())
                # Keep last 50 timestamps to prevent memory bloat
                if len(_beacon_timestamps[bssid]) > 50:
                    _beacon_timestamps[bssid].pop(0)
                _bssid_capabilities[bssid] = pkt[Dot11Beacon].cap

def start_beacon_analysis_thread():
    """Start passive beacon sniffing in the background."""
    def _sniff_loop():
        try:
            # Captures for a limited window to populate jitter stats
            sniff(prn=_beacon_handler, store=0, timeout=15)
        except Exception:
            pass  # Fails gently if monitor mode or Npcap missing

    t = threading.Thread(target=_sniff_loop, daemon=True)
    t.start()

def _calculate_jitter(bssid: str) -> float:
    """Calculate variance of beacon intervals. High variance = high jitter."""
    with _capture_lock:
        stamps = _beacon_timestamps.get(bssid, [])
        if len(stamps) < 10:
            return 0.0
        intervals = [stamps[i] - stamps[i-1] for i in range(1, len(stamps))]
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval == 0:
            return 0.0
        # Calculate variance directly targeting timing jitter
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        return variance


def load_known_aps(baseline: Dict[str, str]):
    """
    Provide a known BSSID→SSID mapping as the trusted baseline.
    You can build this on first run and compare on subsequent scans.
    """
    global _known_bssids
    _known_bssids = {k.lower(): v for k, v in baseline.items()}


def detect_evil_twin(aps: List[Dict]) -> List[Dict]:
    """
    Detect Evil Twin APs:
    - Same SSID → multiple different BSSIDs with different encryption/channel
    - A BSSID claiming an SSID that the known baseline maps to a different SSID
    Returns list of suspicious APs.
    """
    suspicious = []
    ssid_map: Dict[str, List[Dict]] = defaultdict(list)

    for ap in aps:
        ssid = ap.get("ssid", "").strip()
        for bssid in ap.get("bssids", []):
            ssid_map[ssid].append({**ap, "bssid": bssid})

    for ssid, instances in ssid_map.items():
        if is_ssid_allowed(ssid):
            continue
            
        if len(instances) > 1:
            # Multiple BSSIDs with same SSID — possible Evil Twin
            encryptions = {i.get("encryption", "?") for i in instances}
            channels    = {i.get("channel", "?") for i in instances}

            if len(encryptions) > 1 or len(channels) > 1:
                # Basic mismatch logic
                desc = (
                    f"EVIL TWIN DETECTED: SSID '{ssid}' seen from "
                    f"{len(instances)} BSSIDs with different "
                    f"encryption({encryptions}) or channel({channels}). "
                    "Possible rogue AP cloning your network!"
                )
                fire_alert(
                    alert_type=ALERT_EVIL_TWIN,
                    severity=SEV_CRITICAL,
                    description=desc,
                    raw_data={"ssid": ssid, "instances": instances}
                )
                for inst in instances:
                    inst["flag"] = "EVIL_TWIN"
                    suspicious.append(inst)
            else:
                # Advanced logic: Jitter and Capabilities
                caps = {i.get("bssid", "unknown"): _bssid_capabilities.get(i.get("bssid", "").lower(), 0) for i in instances}
                unique_caps = set(c for c in caps.values() if c != 0)
                
                jitters = {i.get("bssid", "unknown"): _calculate_jitter(i.get("bssid", "").lower()) for i in instances}
                high_jitter_bssids = [b for b, j in jitters.items() if j > BEACON_JITTER_THRESHOLD]

                if len(unique_caps) > 1 or high_jitter_bssids:
                    desc_adv = (
                        f"EVIL TWIN DETECTED (ADVANCED): SSID '{ssid}'. "
                        f"Hardware capability mismatch ({unique_caps}) or "
                        f"Software AP Beacon Jitter detected ({high_jitter_bssids})."
                    )
                    fire_alert(
                        alert_type=ALERT_EVIL_TWIN,
                        severity=SEV_CRITICAL,
                        description=desc_adv,
                        raw_data={"ssid": ssid, "caps": list(unique_caps), "jitters": jitters}
                    )
                    for inst in instances:
                        inst["flag"] = "EVIL_TWIN_ADVANCED"
                        suspicious.append(inst)
                else:
                    # Same encryption/channel, capabilities match, timing stable
                    desc = (
                        f"Multiple BSSIDs for SSID '{ssid}': "
                        f"{[i['bssid'] for i in instances]} — "
                        "Verify if this is a legitimate mesh network."
                    )
                    fire_alert(
                        alert_type=ALERT_ROGUE_AP,
                        severity=SEV_MEDIUM,
                        description=desc,
                        raw_data={"ssid": ssid, "bssids": [i["bssid"] for i in instances]}
                    )

    # Check against known baseline
    for ap in aps:
        ssid = ap.get("ssid", "")
        for bssid in ap.get("bssids", []):
            if bssid in _known_bssids and _known_bssids[bssid] != ssid:
                desc = (
                    f"BSSID {bssid} was previously '{_known_bssids[bssid]}' "
                    f"but now claims to be '{ssid}'. "
                    "Possible rogue AP using a known BSSID!"
                )
                fire_alert(
                    alert_type=ALERT_EVIL_TWIN,
                    severity=SEV_CRITICAL,
                    description=desc,
                    device_mac=bssid,
                    raw_data={"bssid": bssid, "expected": _known_bssids[bssid],
                              "seen": ssid}
                )
                suspicious.append({**ap, "bssid": bssid, "flag": "BSSID_MISMATCH"})

    return suspicious


# ─────────────────────────────────────────────
#  OPEN / WEAK ENCRYPTION DETECTION
# ─────────────────────────────────────────────

WEAK_AUTH    = {"open", "wep", "wpa-personal", "wpa"}
STRONG_AUTH  = {"wpa2-personal", "wpa2-enterprise", "wpa3-personal",
                "wpa3-enterprise"}


def detect_weak_encryption(aps: List[Dict]) -> List[Dict]:
    """Detect APs with no/weak encryption."""
    risky = []
    for ap in aps:
        ssid = ap.get("ssid", "Unknown")
        if is_ssid_allowed(ssid):
            continue

        auth = ap.get("authentication", "").lower()
        enc  = ap.get("encryption",     "").lower()

        is_open = enc in ("none", "") or auth in ("open", "")
        is_weak = any(w in auth for w in WEAK_AUTH)

        if is_open:
            fire_alert(
                alert_type=ALERT_OPEN_AP,
                severity=SEV_HIGH,
                description=(f"Open Wi-Fi AP detected: SSID='{ssid}' "
                             "— No encryption! Risk of traffic interception."),
                raw_data=ap
            )
            risky.append({**ap, "flag": "OPEN_AP"})
        elif is_weak:
            fire_alert(
                alert_type=ALERT_OPEN_AP,
                severity=SEV_MEDIUM,
                description=(f"Weak encryption on SSID='{ssid}': auth={auth}, "
                             f"enc={enc} — Upgrade to WPA2/WPA3."),
                raw_data=ap
            )
            risky.append({**ap, "flag": "WEAK_ENCRYPTION"})

    return risky


# ─────────────────────────────────────────────
#  FULL AP SCAN ORCHESTRATOR
# ─────────────────────────────────────────────

def run_ap_detection(baseline: Optional[Dict] = None) -> Dict:
    """
    Full rogue AP detection cycle:
    1. Scan surrounding Wi-Fi networks
    2. Detect Evil Twin APs
    3. Detect open/weak encryption
    Returns summary dict.
    """
    print_info("Scanning Wi-Fi networks via netsh...")
    start_beacon_analysis_thread()
    aps = scan_wifi_networks()
    print_info(f"Found {len(aps)} visible SSIDs.")

    if baseline:
        load_known_aps(baseline)

    evil_twins   = detect_evil_twin(aps)
    weak_aps     = detect_weak_encryption(aps)
    connected    = get_connected_ap()

    return {
        "total_aps":    len(aps),
        "evil_twins":   evil_twins,
        "weak_aps":     weak_aps,
        "connected_ap": connected,
        "all_aps":      aps
    }
