"""
RDDS — Whitelist-DB Sync & Risk Score Fix
Fixes two issues:
  1. Whitelisted MACs not marked as is_whitelisted=1 in DB
  2. Non-whitelisted devices with risk_score=0 (unknown devices)

Run this once after any whitelist changes:
    python fix_whitelist_sync.py
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import database as db
from core.device_manager import load_whitelist, compute_risk_score
from core.network_scanner import get_vendor, is_mac_randomized

db.init_db()

wl       = load_whitelist()
all_devs = db.get_all_devices()

print(f"\n[RDDS Whitelist Sync] Whitelist entries: {len(wl)}")
print(f"[RDDS Whitelist Sync] DB devices: {len(all_devs)}")

# Fix 1: Mark whitelisted MACs in DB
synced = 0
for mac in wl:
    dd = next((d for d in all_devs if d["mac"] == mac), None)
    if dd:
        if dd["is_whitelisted"] != 1:
            db.mark_whitelisted(mac, True)
            db.update_risk_score(mac, 0)  # Whitelisted devices = 0 risk
            print(f"  [FIXED] {mac} → is_whitelisted=1, risk_score=0")
            synced += 1
        else:
            print(f"  [OK]    {mac} already whitelisted in DB")
    else:
        print(f"  [SKIP]  {mac} not in DB yet (normal if device not scanned)")

print(f"\n[RDDS Whitelist Sync] Fixed {synced} whitelist mismatches")

# Fix 2: Compute risk scores for non-whitelisted devices with score=0
print("\n[RDDS Risk Score Fix] Computing risk scores...")
fixed_scores = 0
for dev in all_devs:
    mac = dev["mac"]
    if dev["is_whitelisted"] == 1 or mac in wl:
        continue  # Skip whitelisted devices

    if dev.get("risk_score", 0) == 0:
        # Compute base risk
        vendor  = dev.get("vendor", "Unknown") or "Unknown"
        is_rand = is_mac_randomized(mac)
        flags   = []

        if vendor == "Unknown":
            flags.append("unknown_vendor")
        if is_rand:
            flags.append("randomized_mac")

        score = compute_risk_score(mac, flags, vendor=vendor, is_known=False)
        db.update_risk_score(mac, score)

        status = "active" if dev.get("status") != "gone" else "gone"
        db.upsert_device(
            mac=mac,
            ip=dev.get("ip", ""),
            vendor=vendor,
            hostname=dev.get("hostname", ""),
            risk_score=score,
            status=status,
            open_ports=dev.get("open_ports", ""),
            is_whitelisted=0,
            flags=",".join(flags)
        )
        print(f"  [SCORED] {mac:<22} IP={dev.get('ip','?'):<18} vendor={vendor:<22} flags={flags} → score={score}")
        fixed_scores += 1

print(f"\n[RDDS Risk Score Fix] Computed risk scores for {fixed_scores} devices")
print("\n[DONE] Run `python rdds.py scan` to refresh with live data.\n")
