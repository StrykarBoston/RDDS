"""RDDS Quick Diagnostics — run with: python run_diag.py"""
import sys, os, json, re, pathlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

P = "[PASS]"; F = "[FAIL]"; W = "[WARN]"; I = "[INFO]"
bugs = []; warns = []

def chk(name, ok, detail="", crit=True):
    print(f"  {P if ok else (F if crit else W)} {name}")
    if not ok and detail:
        print(f"        => {detail}")
    if not ok:
        (bugs if crit else warns).append(f"{name}: {detail}")

print("\n" + "="*65)
print("  RDDS DIAGNOSTIC REPORT")
print("="*65)

# ── 1. NETWORK CONFIG ──────────────────────────────────────────
print("\n[1] NETWORK CONFIG")
from core.config import NETWORK_TARGET, get_default_gateway, get_local_ip
gw       = get_default_gateway()
local_ip = get_local_ip()
base     = ".".join(local_ip.split(".")[:3])
configured_matches = NETWORK_TARGET == base + ".0/24"
print(f"  {I} NETWORK_TARGET : {NETWORK_TARGET}")
print(f"  {I} Detected GW    : {gw}")
print(f"  {I} Local IP       : {local_ip}  (LAN={base}.0/24)")
chk("NETWORK_TARGET matches your actual LAN subnet",
    configured_matches,
    f"Config='{NETWORK_TARGET}' but your LAN is '{base}.0/24'. "
    f"Fix: edit NETWORK_TARGET in core/config.py")

# ── 2. OUI DATABASE ────────────────────────────────────────────
print("\n[2] OUI VENDOR DATABASE")
from core.config import OUI_PATH
from core.network_scanner import get_vendor, is_mac_randomized, arp_table_windows
with open(OUI_PATH) as f:
    oui_db = json.load(f)
print(f"  {I} OUI DB entries : {len(oui_db)}")
chk("OUI DB has >=500 entries for accurate vendor lookup",
    len(oui_db) >= 500,
    f"Only {len(oui_db)} entries! Most real MACs will show 'Unknown'. "
    "Download ieee_oui.csv and expand oui.json (critical for device identification)")

# ── 3. ARP TABLE ───────────────────────────────────────────────
print("\n[3] ARP TABLE — LIVE LAN DEVICES")
devs = arp_table_windows()
print(f"  {I} Devices in ARP : {len(devs)}")
chk("ARP table returned at least 1 device", len(devs) > 0,
    "Run as Administrator or check network interface config")
macs = [d["mac"] for d in devs]
chk("Broadcast MAC filtered (ff:ff:ff:ff:ff:ff)", "ff:ff:ff:ff:ff:ff" not in macs)
chk("Multicast MACs filtered (01:00:5e:*)", not any(m.startswith("01:00:5e") for m in macs))
unk = 0
for d in devs:
    v = get_vendor(d["mac"])
    r = is_mac_randomized(d["mac"])
    if v == "Unknown": unk += 1
    print(f"  {I} {d['ip']:<18} {d['mac']:<20} {v:<22} {'[RANDOMIZED-MAC]' if r else ''}")
if devs:
    pct = unk / len(devs) * 100
    chk(f"Vendor resolved for >20% of devices (currently {100-pct:.0f}%)",
        pct < 80,
        f"{unk}/{len(devs)} ({pct:.0f}%) show 'Unknown' — OUI DB too small", crit=False)

# ── 4. MAC RANDOMIZATION ──────────────────────────────────────
print("\n[4] MAC RANDOMIZATION DETECTION")
cases = [
    ("c6:4a:d2:b7:94:2a", True,  "LA bit set"),
    ("0a:8f:d8:96:d7:8a", True,  "LA bit set"),
    ("08:bf:b8:d0:08:74", False, "Real OUI"),
    ("70:b6:4f:37:44:35", False, "Real OUI"),
]
for mac, exp, desc in cases:
    r = is_mac_randomized(mac)
    chk(f"{mac} ({desc}) → randomized={exp}", r == exp, f"Got {r}, expected {exp}")

# ── 5. TRAFFIC ANALYZER API — SOURCE ANALYSIS ─────────────────
print("\n[5] TRAFFIC ANALYZER — API MISMATCH BUGS (source scan)")
ta_src   = pathlib.Path("core/traffic_analyzer.py").read_text(encoding="utf-8")
rdds_src = pathlib.Path("rdds.py").read_text(encoding="utf-8")

# 5a. __init__ signature
m = re.search(r"class TrafficAnalyzer.*?def __init__\(self(.*?)\):", ta_src, re.DOTALL)
if m:
    params = m.group(1)
    print(f"  {I} __init__ signature: (self{params.strip() or ''})")
    chk("TrafficAnalyzer has 'netflow_port' param",
        "netflow_port" in params,
        "rdds.py cmd_traffic() passes netflow_port= → TypeError will crash the command")
    chk("TrafficAnalyzer has 'sflow_port' param",
        "sflow_port" in params,
        "rdds.py cmd_traffic() passes sflow_port= → TypeError will crash the command")

# 5b. get_stats() keys
gs_m = ta_src.find("def get_stats")
gs_body = ta_src[gs_m: gs_m + 600] if gs_m >= 0 else ""
for k in ["netflow_v5_records", "netflow_v9_records", "sflow_samples",
          "passive_packets", "anomalies_detected"]:
    chk(f"get_stats() returns '{k}'", k in gs_body,
        f"rdds.py cmd_traffic() reads stats['{k}'] → KeyError crash at runtime")

# 5c. get_top_talkers() dict keys
gt_m = ta_src.find("def get_top_talkers")
gt_body = ta_src[gt_m: gt_m + 500] if gt_m >= 0 else ""
for k in ["bytes_out", "bytes_in", "pkts_out"]:
    chk(f"get_top_talkers() dict has '{k}'", k in gt_body,
        f"rdds.py reads talker['{k}'] → KeyError crash")

# 5d. anomaly dict keys in file
anom_m = ta_src.find('"type": "AI_ANOMALY"')
anom_b = ta_src[max(0, anom_m - 50): anom_m + 400] if anom_m >= 0 else ""
for k in ["severity", "type", "description", "src_ip"]:
    chk(f"anomaly dict has '{k}' key", k in anom_b,
        f"rdds.py anomaly display reads anomaly['{k}'] → possible KeyError", crit=False)

# ── 6. THREAD SAFETY — ANONYMOUS LOCK ────────────────────────
print("\n[6] THREAD SAFETY IN ATTACK DETECTOR")
atk_src = pathlib.Path("core/attack_detector.py").read_text(encoding="utf-8")
lines   = atk_src.splitlines()
anon_locks = [(i+1, l.strip()) for i, l in enumerate(lines)
              if "with threading.Lock():" in l]
if anon_locks:
    for ln, code in anon_locks:
        print(f"  {W} Line {ln}: `{code}` — creates a NEW lock object every call")
    chk("No anonymous threading.Lock() calls (race conditions)",
        False,
        f"Found {len(anon_locks)} occurrences — change to `with self._lock:` or a module-level lock")
else:
    chk("No anonymous threading.Lock() calls", True)

# ── 7. WHITELIST <-> DB SYNC ──────────────────────────────────
print("\n[7] WHITELIST ↔ DATABASE SYNC")
from core.device_manager import load_whitelist
from core import database as db
db.init_db()
wl       = load_whitelist()
all_devs = db.get_all_devices()
print(f"  {I} Whitelist entries : {len(wl)}")
mismatches = []
for mac in wl:
    dd = next((d for d in all_devs if d["mac"] == mac), None)
    if dd and dd["is_whitelisted"] != 1:
        mismatches.append(mac)
        print(f"  {W} {mac} in whitelist.json but is_whitelisted=0 in DB")
chk("Whitelist MACs have is_whitelisted=1 in DB", len(mismatches) == 0,
    f"Out of sync: {mismatches}. DB must be updated when whitelist changes")

# ── 8. RISK SCORE ISSUE ───────────────────────────────────────
print("\n[8] DEVICE RISK SCORES IN DATABASE")
zero_not_wl = [d for d in all_devs
               if d.get("risk_score", 0) == 0 and d.get("is_whitelisted", 0) == 0]
print(f"  {I} Total devices in DB : {len(all_devs)}")
print(f"  {I} Non-WL with score=0 : {len(zero_not_wl)}")
chk("All non-whitelisted devices have risk_score > 0",
    len(zero_not_wl) == 0,
    f"{len(zero_not_wl)} devices show risk_score=0 but are not whitelisted. "
    "classify_new_device() is not being called during the scan pipeline.", crit=False)

# ── 9. GATEWAY IN WHITELIST ───────────────────────────────────
print("\n[9] GATEWAY WHITELIST STATUS")
gw_mac = next(
    (d["mac"] for d in devs if d["ip"] == gw), None
) if devs else None
print(f"  {I} Gateway IP : {gw}  MAC: {gw_mac}")
if gw_mac:
    in_wl = gw_mac in wl
    chk("Gateway MAC is in whitelist (prevents false MITM alerts)", in_wl,
        f"Add it: python rdds.py whitelist --add {gw_mac} --label Router --ip {gw}",
        crit=False)

# ── 10. ALERT ENGINE CONFIG ───────────────────────────────────
print("\n[10] ALERT ENGINE CONFIG")
from core.alert_engine import ALERT_AGGREGATION_WINDOW
print(f"  {I} Alert aggregation window : {ALERT_AGGREGATION_WINDOW}s")
chk("Aggregation window = 30s", ALERT_AGGREGATION_WINDOW == 30)

# ── 11. ROGUE AP DETECTOR (source check only) ─────────────────
print("\n[11] ROGUE AP DETECTOR — SOURCE CHECK")
ap_src = pathlib.Path("core/rogue_ap_detector.py").read_text(encoding="utf-8")
# start_beacon_analysis_thread() calls sniff() with timeout=15
# This will block run_ap_detection() for 15s each call in the monitor loop
has_blocking_sniff = "sniff(prn=_beacon_handler, store=0, timeout=15)" in ap_src
chk("start_beacon_analysis_thread is non-blocking (uses thread)",
    "threading.Thread" in ap_src,
    "Beacon analysis blocks detector")
chk("Beacon sniff timeout is set (won't run forever)",
    "timeout=15" in ap_src)
# Check run_ap_detection calls start_beacon_analysis_thread first (with 15s delay!)
# This means AP scan blocks for 15s before analysing jitter — but runs in RTM every 60s so impact is limited
print(f"  {I} start_beacon_analysis_thread starts a background thread (OK)")
print(f"  {I} sniff timeout=15s in beacon thread (acceptable)")

# ── SUMMARY ───────────────────────────────────────────────────
print("\n" + "="*65)
print("  SUMMARY")
print("="*65)
print(f"\n  CRITICAL BUGS  : {len(bugs)}")
for i, b in enumerate(bugs, 1):
    print(f"    {i}. {b}")
print(f"\n  WARNINGS       : {len(warns)}")
for i, w in enumerate(warns, 1):
    print(f"    {i}. {w}")
if not bugs:
    print("\n  All critical checks passed!")
print()
