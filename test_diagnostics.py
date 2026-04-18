"""
RDDS Comprehensive Diagnostic Test (no TensorFlow / no sniff calls)
"""
import sys, os, json, re, socket, subprocess, inspect, pathlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Patch to avoid TF import hang
import unittest.mock as _mock
sys.modules['tensorflow'] = _mock.MagicMock()
sys.modules['tensorflow.keras'] = _mock.MagicMock()

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
WARN = "\033[93m[WARN]\033[0m"
INFO = "\033[96m[INFO]\033[0m"

bugs = []
warns = []

def check(name, condition, detail="", critical=True):
    if condition:
        print(f"  {PASS} {name}")
    else:
        tag = FAIL if critical else WARN
        print(f"  {tag} {name}")
        if detail:
            print(f"        └─ {detail}")
        if critical:
            bugs.append(f"{name}: {detail}")
        else:
            warns.append(f"{name}: {detail}")

print("\n" + "="*70)
print("  RDDS NETWORK DIAGNOSTIC TEST SUITE")
print("="*70)

# ─── 1. NETWORK CONFIG ────────────────────────
print("\n[1] NETWORK CONFIG CHECK")
from core.config import NETWORK_TARGET, get_default_gateway, get_local_ip

gw = get_default_gateway()
local_ip = get_local_ip()
print(f"  {INFO} Configured NETWORK_TARGET : {NETWORK_TARGET}")
print(f"  {INFO} Detected Gateway          : {gw}")
print(f"  {INFO} Detected Local IP         : {local_ip}")

local_subnet_base = ".".join(local_ip.split(".")[:3])
check("NETWORK_TARGET matches your actual LAN subnet",
      NETWORK_TARGET.startswith(local_subnet_base),
      f"Config={NETWORK_TARGET}, your LAN={local_subnet_base}.0/24 — scan may miss devices")

# ─── 2. OUI VENDOR DATABASE ──────────────────
print("\n[2] OUI VENDOR DATABASE")
from core.network_scanner import get_vendor, is_mac_randomized, arp_table_windows
from core.config import OUI_PATH

with open(OUI_PATH) as f:
    oui_db = json.load(f)
print(f"  {INFO} OUI database size: {len(oui_db)} entries")
check("OUI database has >=500 entries (for accurate vendor lookup)",
      len(oui_db) >= 500,
      f"Only {len(oui_db)} entries — most real MACs will show 'Unknown'. Need to download full OUI DB.")

# ─── 3. ARP TABLE PARSING ────────────────────
print("\n[3] ARP TABLE PARSING — REAL DEVICES ON YOUR LAN")
arp_devs = arp_table_windows()
print(f"  {INFO} ARP table returned {len(arp_devs)} unicast devices")
check("ARP table parsed at least 1 device",
      len(arp_devs) > 0,
      "No devices found — check permissions or interface")

macs_found = [d['mac'] for d in arp_devs]
check("Broadcast ff:ff:ff:ff:ff:ff filtered",
      "ff:ff:ff:ff:ff:ff" not in macs_found)
check("Multicast 01:00:5e prefix filtered",
      not any(m.startswith("01:00:5e") for m in macs_found))

unknown_vendors = 0
for d in arp_devs:
    vendor = get_vendor(d['mac'])
    rand = is_mac_randomized(d['mac'])
    if vendor == "Unknown": unknown_vendors += 1
    status = "\033[93m[RANDOMIZED]\033[0m" if rand else ""
    print(f"  {INFO} IP={d['ip']:<18} MAC={d['mac']:<20} Vendor={vendor:<22} {status}")

vendor_pct = (unknown_vendors / len(arp_devs)) * 100 if arp_devs else 0
check(f"Most devices have known vendor (< 80% unknown)",
      vendor_pct < 80,
      f"{unknown_vendors}/{len(arp_devs)} ({vendor_pct:.0f}%) devices show 'Unknown' vendor — OUI DB is too small",
      critical=False)

# ─── 4. MAC RANDOMIZATION DETECTION ─────────
print("\n[4] MAC RANDOMIZATION DETECTION (bit-level check)")
cases = [
    ("02:ab:cd:ef:01:02", True,  "Locally administered (LA bit set)"),
    ("c6:4a:d2:b7:94:2a", True,  "LA bit set — randomized"),
    ("0a:8f:d8:96:d7:8a", True,  "LA bit set — randomized"),
    ("08:bf:b8:d0:08:74", False, "Real OUI — not randomized"),
    ("70:b6:4f:37:44:35", False, "Real OUI — not randomized"),
]
for mac, expected, desc in cases:
    result = is_mac_randomized(mac)
    check(f"{mac} ({desc})", result == expected,
          f"is_mac_randomized() returned {result}, expected {expected}")

# Identify randomized MACs on actual network
rand_on_lan = [d for d in arp_devs if d['is_randomized_mac']]
if rand_on_lan:
    print(f"  {WARN} {len(rand_on_lan)} RANDOMIZED MAC(s) on your LAN:")
    for d in rand_on_lan:
        print(f"        IP={d['ip']}  MAC={d['mac']} (privacy MAC — vendor lookup will fail)")

# ─── 5. TRAFFIC ANALYZER SIGNATURE BUG ───────
print("\n[5] TRAFFIC ANALYZER — API SIGNATURE MISMATCH BUG")
import importlib.util
spec = importlib.util.spec_from_file_location("traffic_analyzer", "core/traffic_analyzer.py")
ta_mod = importlib.util.load_from_spec = None  # don't actually load (has TF import)

# Read source directly
ta_src = pathlib.Path("core/traffic_analyzer.py").read_text(encoding="utf-8")

# Check class signature
ta_init_match = re.search(r'class TrafficAnalyzer.*?def __init__\(self(.*?)\):', ta_src, re.DOTALL)
if ta_init_match:
    ta_params_raw = ta_init_match.group(1)
    print(f"  {INFO} TrafficAnalyzer.__init__ signature: (self{ta_params_raw.strip()})")
    has_netflow = "netflow_port" in ta_params_raw
    has_sflow   = "sflow_port" in ta_params_raw
    has_passive = "passive_mode" in ta_params_raw
    check("TrafficAnalyzer accepts 'netflow_port' parameter",
          has_netflow,
          "rdds.py cmd_traffic() passes netflow_port= but TrafficAnalyzer.__init__ doesn't have it → TypeError CRASH")
    check("TrafficAnalyzer accepts 'sflow_port' parameter",
          has_sflow,
          "rdds.py cmd_traffic() passes sflow_port= but TrafficAnalyzer.__init__ doesn't have it → TypeError CRASH")
    check("TrafficAnalyzer accepts 'passive_mode' parameter",
          has_passive,
          "rdds.py cmd_traffic() passes passive_mode=True but TrafficAnalyzer.__init__ may not have it → TypeError CRASH")

# Check get_stats() keys used by rdds.py
rdds_src = pathlib.Path("rdds.py").read_text(encoding="utf-8")
# rdds.py reads: stats['netflow_v5_records'], stats['netflow_v9_records'], stats['sflow_samples'],
#                stats['passive_packets'], stats['anomalies_detected']
# TrafficAnalyzer.get_stats() returns: total_packets, total_flows, packets_per_second, uptime_seconds, ai_loaded
ta_get_stats_match = re.search(r'def get_stats\(self\).*?return \{(.*?)\}', ta_src, re.DOTALL)
if ta_get_stats_match:
    stats_body = ta_get_stats_match.group(1)
    print(f"  {INFO} TrafficAnalyzer.get_stats() returns keys found in source")

expected_rdds_keys = ["netflow_v5_records", "netflow_v9_records", "sflow_samples",
                      "passive_packets", "anomalies_detected"]
for k in expected_rdds_keys:
    in_stats = k in ta_src and "get_stats" in ta_src[ta_src.find("get_stats"):ta_src.find("get_stats")+500]
    # More reliable: check if key appears in get_stats method body
    gs_start = ta_src.find("def get_stats")
    gs_end = ta_src.find("\n    def ", gs_start + 1)
    gs_body = ta_src[gs_start:gs_end] if gs_end > gs_start else ta_src[gs_start:gs_start+500]
    check(f"get_stats() returns '{k}' (used by rdds.py display)",
          k in gs_body,
          f"rdds.py cmd_traffic() does stats['{k}'] but get_stats() doesn't return it → KeyError CRASH")

# Check get_top_talkers keys
talker_keys = ["bytes_out", "bytes_in", "pkts_out"]
gt_start = ta_src.find("def get_top_talkers")
gt_end = ta_src.find("\n    def ", gt_start + 1)
gt_body = ta_src[gt_start:gt_end] if gt_end > gt_start else ta_src[gt_start:gt_start+500]
for k in talker_keys:
    check(f"get_top_talkers() dicts contain '{k}' (used by rdds.py)",
          k in gt_body,
          f"rdds.py accesses talker['{k}'] but key not in get_top_talkers() result → KeyError CRASH")

# get_anomalies keys
anomaly_keys = ["severity", "type", "detail", "src_ip"]
ga_start = ta_src.find("def get_anomalies")
# anomalies are _anomalies deque — items are built in packet_handler
# search for anomaly dict construction in packet_handler
ph_start = ta_src.find("def packet_handler")
ph_end = ta_src.find("\n    def ", ph_start + 1)
ph_body = ta_src[ph_start:ph_end] if ph_end > ph_start else ta_src[ph_start:ph_start+1000]
for k in anomaly_keys:
    check(f"Anomaly dicts contain '{k}' (used by rdds.py cmd_traffic)",
          k in ph_body,
          f"rdds.py reads anomaly['{k}'] but packet_handler builds anomaly dict without it → KeyError CRASH")

# ─── 6. BEHAVIORAL SAMPLER LOCK BUG ─────────
print("\n[6] THREAD SAFETY — BEHAVIORAL SAMPLER BUG")
atk_src = pathlib.Path("core/attack_detector.py").read_text(encoding="utf-8")
# Bug: line 802 `with threading.Lock():` creates NEW lock each time
lines = atk_src.splitlines()
for i, line in enumerate(lines, 1):
    if "with threading.Lock():" in line and "_behavioral_sampler" in "\n".join(lines[max(0,i-20):i]):
        print(f"  {INFO} Found at line {i}: `{line.strip()}`")
        check("No anonymous threading.Lock() in _behavioral_sampler",
              False,
              f"Line {i}: `with threading.Lock():` creates a FRESH lock every call — no mutual exclusion. Use self._events_lock")
        break
else:
    # Check more broadly
    new_lock_in_sampler = False
    in_sampler = False
    for i, line in enumerate(lines, 1):
        if "_behavioral_sampler" in line:
            in_sampler = True
        if in_sampler and "def " in line and "_behavioral_sampler" not in line:
            in_sampler = False
        if in_sampler and "threading.Lock()" in line:
            new_lock_in_sampler = True
            print(f"  {INFO} Found threading.Lock() at line {i}: {line.strip()}")
    check("No anonymous threading.Lock() in _behavioral_sampler",
          not new_lock_in_sampler,
          "Anonymous lock provides no real thread safety")

# ─── 7. WHITELIST DB SYNC BUG ─────────────────
print("\n[7] WHITELIST ↔ DATABASE CONSISTENCY")
from core.device_manager import load_whitelist
from core import database as db
db.init_db()

wl = load_whitelist()
print(f"  {INFO} Whitelist has {len(wl)} entries")
all_devs = db.get_all_devices()

wl_mismatches = []
for mac in wl:
    db_dev = next((d for d in all_devs if d["mac"] == mac), None)
    if db_dev and db_dev["is_whitelisted"] != 1:
        wl_mismatches.append(mac)
check("All whitelisted MACs have is_whitelisted=1 in DB",
      len(wl_mismatches) == 0,
      f"Mismatched MACs: {wl_mismatches} — in whitelist.json but DB shows is_whitelisted=0")

# Vendor field in whitelist
wl_unknown_vendors = [mac for mac, v in wl.items() if v.get("vendor", "Unknown") in ("Unknown", "")]
if wl_unknown_vendors:
    print(f"  {WARN} {len(wl_unknown_vendors)} whitelisted device(s) have no vendor set:")
    for mac in wl_unknown_vendors:
        print(f"        {mac} — vendor='Unknown' (update with --vendor flag for better tracking)")

# ─── 8. DATABASE RISK SCORE ISSUE ────────────
print("\n[8] RISK SCORE CONSISTENCY IN DATABASE")
zero_risk_not_wl = [d for d in all_devs if d.get("risk_score", 0) == 0 and d.get("is_whitelisted", 0) == 0]
print(f"  {INFO} Non-whitelisted devices with risk_score=0: {len(zero_risk_not_wl)}")
check("Non-whitelisted devices have non-zero risk score",
      len(zero_risk_not_wl) == 0,
      f"{len(zero_risk_not_wl)} devices — classify_new_device() not running at scan time (missing risk computation)",
      critical=False)

# ─── 9. GATEWAY MAC IN WHITELIST ─────────────
print("\n[9] GATEWAY MAC IN WHITELIST")
gw_in_wl = "70:b6:4f:37:44:35" in wl
check("Gateway MAC is in whitelist (prevents false MITM alerts)",
      gw_in_wl,
      "Add gateway MAC to whitelist: python rdds.py whitelist --add 70:b6:4f:37:44:35 --label Router --ip 192.168.1.1",
      critical=False)

# ─── 10. ALERT ENGINE DEDUP ────────────────────
print("\n[10] ALERT ENGINE DEDUP & LOGGING")
from core.alert_engine import fire_alert, ALERT_AGGREGATION_WINDOW
print(f"  {INFO} Alert aggregation window: {ALERT_AGGREGATION_WINDOW}s")
check("Alert aggregation window is 30s (prevents log spam)",
      ALERT_AGGREGATION_WINDOW == 30,
      f"Window is {ALERT_AGGREGATION_WINDOW}s")

# ─── 11. CONFIG SUBNET MATCH ─────────────────
print("\n[11] SUBNET CONFIGURATION")
actual_subnet = local_subnet_base + ".0/24"
check("NETWORK_TARGET matches your active LAN subnet",
      NETWORK_TARGET == actual_subnet,
      f"Config has {NETWORK_TARGET} but your LAN is {actual_subnet}. Scan may miss/misidentify devices.")
if NETWORK_TARGET != actual_subnet:
    print(f"        └─ Fix: set NETWORK_TARGET = '{actual_subnet}' in core/config.py")

# ─── 12. ATTACK DETECTOR ALERT DEDUP TTL ─────
print("\n[12] ATTACK DETECTOR DEDUP COVERAGE")
ad_src = pathlib.Path("core/attack_detector.py").read_text(encoding="utf-8")
dedup_ttl_match = re.search(r"ALERT_DEDUP_TTL\s*=\s*(\d+)", ad_src)
if dedup_ttl_match:
    ttl = int(dedup_ttl_match.group(1))
    print(f"  {INFO} Attack detector dedup TTL: {ttl}s")
    check("Attack detector dedup TTL >= 30s",
          ttl >= 30,
          f"TTL={ttl}s is too low — same attack will re-fire too frequently", critical=False)

# ─── 13. ROGUE AP DETECTOR ───────────────────
print("\n[13] ROGUE AP DETECTOR")
from core.rogue_ap_detector import run_ap_detection
try:
    result = run_ap_detection()
    total_aps = result.get("total_aps", 0)
    evil = result.get("evil_twins", [])
    weak = result.get("weak_aps", [])
    connected = result.get("connected_ap", None)
    print(f"  {INFO} Total APs visible: {total_aps}")
    print(f"  {INFO} Evil twin/rogue APs: {len(evil)}")
    print(f"  {INFO} Open/weak APs: {len(weak)}")
    if connected:
        print(f"  {INFO} Connected to: SSID={connected.get('ssid','?')} BSSID={connected.get('bssid','?')} Auth={connected.get('authentication','?')}")
    check("Rogue AP detector returns data without crashing",
          isinstance(result, dict) and "total_aps" in result)
    if evil:
        for e in evil:
            print(f"  \033[91m[ROGUE AP DETECTED]\033[0m SSID={e.get('ssid','?')} Flag={e.get('flag','?')}")
    if weak:
        for w in weak:
            print(f"  {WARN} WEAK AP: SSID={w.get('ssid','?')} Flag={w.get('flag','?')}")
except Exception as e:
    print(f"  {WARN} AP detection error (may need admin/Wi-Fi for full AP scan): {e}")
    warns.append(f"Rogue AP detector: {e}")

# ─── FINAL SUMMARY ────────────────────────────
print("\n" + "="*70)
print("  DIAGNOSTIC SUMMARY")
print("="*70)
print(f"\n  \033[91mCRITICAL BUGS FOUND: {len(bugs)}\033[0m")
for i, b in enumerate(bugs, 1):
    print(f"    {i}. {b}")

print(f"\n  \033[93mWARNINGS: {len(warns)}\033[0m")
for i, w in enumerate(warns, 1):
    print(f"    {i}. {w}")

if not bugs:
    print("\n  \033[92mAll critical checks passed!\033[0m")
print()
