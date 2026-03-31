"""
RDDS — Device Manager Module
Manages whitelist, risk scoring, and device classification.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from core.config import (WHITELIST_PATH, ALLOWLIST_PATH, RISK_SCORE_CRITICAL,
                          RISK_SCORE_HIGH, RISK_SCORE_MEDIUM,
                          SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW)
from core import database as db


# ─────────────────────────────────────────────
#  WHITELIST MANAGEMENT
# ─────────────────────────────────────────────

def load_whitelist() -> Dict:
    """
    Load whitelist.json — returns dict keyed by MAC.
    {
      "aa:bb:cc:dd:ee:ff": {
          "label": "Router",
          "added": "2025-01-01T00:00:00",
          "note": "Managed switch"
      }
    }
    """
    if not os.path.exists(WHITELIST_PATH):
        _save_whitelist({})
        return {}
    try:
        with open(WHITELIST_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_whitelist(whitelist: Dict):
    with open(WHITELIST_PATH, "w") as f:
        json.dump(whitelist, f, indent=2)


def add_to_whitelist(mac: str, label: str = "", note: str = "", ip: str = "", hostname: str = "", vendor: str = "", risk_score: int = 0) -> bool:
    """Add a device MAC (and optional IP, hostname, vendor, etc) to the whitelist and mark in DB."""
    mac = mac.lower().strip()
    wl  = load_whitelist()
    wl[mac] = {
        "label": label,
        "ip":    ip.strip() if ip else "",
        "hostname": hostname,
        "vendor": vendor,
        "risk_score": risk_score,
        "note":  note,
        "added": datetime.now().isoformat()
    }
    _save_whitelist(wl)
    db.mark_whitelisted(mac, True)
    return True


def remove_from_whitelist(mac: str) -> bool:
    """Remove a device from the whitelist."""
    mac = mac.lower().strip()
    wl  = load_whitelist()
    if mac not in wl:
        return False
    del wl[mac]
    _save_whitelist(wl)
    db.mark_whitelisted(mac, False)
    return True


def is_whitelisted(mac: str) -> bool:
    return mac.lower().strip() in load_whitelist()


def get_whitelist_label(mac: str) -> str:
    wl = load_whitelist()
    entry = wl.get(mac.lower(), {})
    return entry.get("label", "")


# ─────────────────────────────────────────────
#  WIFI ALLOWLIST MANAGEMENT
# ─────────────────────────────────────────────

def load_wifi_allowlist() -> set:
    if not os.path.exists(ALLOWLIST_PATH):
        return set()
    try:
        with open(ALLOWLIST_PATH, "r", encoding="utf-8") as file:
            return set(line.strip() for line in file if line.strip())
    except Exception:
        return set()

def save_wifi_allowlist(ssids: set):
    os.makedirs(os.path.dirname(ALLOWLIST_PATH), exist_ok=True)
    with open(ALLOWLIST_PATH, "w", encoding="utf-8") as file:
        for ssid in sorted(list(ssids)):
            file.write(f"{ssid}\n")

def is_ssid_allowed(ssid: str) -> bool:
    return ssid in load_wifi_allowlist()

def add_to_wifi_allowlist(ssid: str):
    wl = load_wifi_allowlist()
    wl.add(ssid)
    save_wifi_allowlist(wl)

def remove_from_wifi_allowlist(ssid: str):
    wl = load_wifi_allowlist()
    if ssid in wl:
        wl.remove(ssid)
        save_wifi_allowlist(wl)


# ─────────────────────────────────────────────
#  RISK SCORING ENGINE
# ─────────────────────────────────────────────

RISK_WEIGHTS = {
    # Factor                     : points
    "not_whitelisted":             40,
    "vendor_unknown":              20,
    "vendor_mismatch":             30,
    "mac_changed_recently":        35,
    "multiple_ips_same_mac":       40,
    "open_dangerous_ports":        25,
    "arp_spoof_flag":              50,
    "port_scan_flag":              30,
    "dns_spoof_flag":              45,
    "lateral_movement_flag":       40,
    "new_device":                  15,
    "mac_randomized":              20,
}


def compute_risk_score(mac: str, flags: List[str],
                       vendor: str = "", is_known: bool = False) -> int:
    """
    Calculate risk score (0–100) based on flags and device attributes.
    Flags match keys in RISK_WEIGHTS.
    """
    score = 0
    if not is_known:
        score += RISK_WEIGHTS["not_whitelisted"]
    if vendor.lower() in ("unknown", ""):
        score += RISK_WEIGHTS["vendor_unknown"]

    for flag in flags:
        score += RISK_WEIGHTS.get(flag, 0)

    return min(score, 100)


def severity_from_score(score: int) -> str:
    if score >= RISK_SCORE_CRITICAL:
        return SEV_CRITICAL
    elif score >= RISK_SCORE_HIGH:
        return SEV_HIGH
    elif score >= RISK_SCORE_MEDIUM:
        return SEV_MEDIUM
    else:
        return SEV_LOW


# ─────────────────────────────────────────────
#  DEVICE CLASSIFICATION
# ─────────────────────────────────────────────

def classify_new_device(device: Dict) -> Dict:
    """
    Given a discovered device dict, determine:
    - Is it whitelisted?
    - What risk flags apply?
    - What risk score?
    Returns enriched device dict.
    """
    mac    = device.get("mac", "").lower()
    vendor = device.get("vendor", "")
    flags  = device.get("flags", [])
    known  = is_whitelisted(mac)

    if not known:
        flags.append("not_whitelisted")
        flags.append("new_device")

    if vendor.lower() in ("", "unknown"):
        flags.append("vendor_unknown")
        
    if device.get("is_randomized_mac"):
        if "mac_randomized" not in flags:
            flags.append("mac_randomized")

    score    = compute_risk_score(mac, flags, vendor, known)
    severity = severity_from_score(score)

    return {
        **device,
        "is_whitelisted": known,
        "risk_score":     score,
        "severity":       severity,
        "flags":          flags,
        "label":          get_whitelist_label(mac) if known else "UNKNOWN"
    }


def sync_db_whitelist():
    """
    Ensure the DB reflects the current whitelist file
    (in case whitelist.json was edited manually).
    """
    wl = load_whitelist()
    for mac in wl:
        db.mark_whitelisted(mac, True)


def get_all_devices_enriched() -> List[Dict]:
    """Return all DB devices with whitelist label and severity."""
    devices = db.get_all_devices()
    wl      = load_whitelist()
    for d in devices:
        mac = d.get("mac", "").lower()
        d["label"]    = wl.get(mac, {}).get("label", "")
        d["severity"] = severity_from_score(d.get("risk_score", 0))
        d["flags_list"] = d.get("flags", "").split(",") if d.get("flags") else []
    return devices


def process_risk_decay():
    """
    Apply Dynamic Risk Decay:
    Devices scoring high will naturally decay over days of 'good' behavior.
    """
    devices = db.get_all_devices()
    now = datetime.now()
    for d in devices:
        score = d.get("risk_score", 0)
        mac = d.get("mac")
        if score > 0 and mac:
            try:
                last_seen_str = d.get("last_seen", "")
                if not last_seen_str:
                    continue
                last_seen = datetime.fromisoformat(last_seen_str)
                delta_days = (now - last_seen).days
                
                # If a device stays quiet/off for 1+ days, decay risk
                if delta_days >= 1:
                    # Decay 10% per day, minimum 1 point
                    decay = int(delta_days * max(1, score * 0.10))
                    new_score = max(0, score - decay)
                    if new_score != score:
                        db.update_risk_score(mac, new_score)
            except Exception:
                pass
