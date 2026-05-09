# Graph Report - RDDS-P  (2026-05-03)

## Corpus Check
- 21 files · ~91,816 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 523 nodes · 1191 edges · 23 communities detected
- Extraction: 63% EXTRACTED · 37% INFERRED · 0% AMBIGUOUS · INFERRED: 442 edges (avg confidence: 0.74)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]

## God Nodes (most connected - your core abstractions)
1. `AttackDetector` - 50 edges
2. `RealTimeMonitor` - 42 edges
3. `TrafficAnalyzer` - 34 edges
4. `fire_alert()` - 31 edges
5. `DHCPMonitor` - 27 edges
6. `print_info()` - 25 edges
7. `IoTProfiler` - 23 edges
8. `print_warn()` - 22 edges
9. `get_vendor()` - 21 edges
10. `NetworkThreatPredictor` - 18 edges

## Surprising Connections (you probably didn't know these)
- `NetworkThreatPredictor` --uses--> `Start the traffic analyzer loop in background with interface GUID resolution and`  [INFERRED]
  core\ai_model.py → core\traffic_analyzer.py
- `load_whitelist()` --calls--> `api_get_whitelist()`  [INFERRED]
  core\device_manager.py → dashboard\app.py
- `remove_from_whitelist()` --calls--> `api_remove_whitelist()`  [INFERRED]
  core\device_manager.py → dashboard\app.py
- `get_all_devices_enriched()` --calls--> `api_devices()`  [INFERRED]
  core\device_manager.py → dashboard\app.py
- `cmd_rtmonitor()` --calls--> `print_banner()`  [INFERRED]
  rdds.py → core\alert_engine.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.05
Nodes (64): api_add_whitelist(), api_alerts(), api_attack_events(), api_attack_summary(), api_attack_threats(), api_attack_timeline(), api_attacks_start(), api_attacks_status() (+56 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (61): api_iot_profiles(), api_report_generate(), api_stats(), delete_device(), get_alert_stats(), get_alerts(), get_all_devices(), get_all_iot_profiles() (+53 more)

### Community 2 - "Community 2"
Cohesion: 0.05
Nodes (25): api_monitor_ap_scan(), Latest Rogue AP scan results., cmd_rtmonitor(), Continuous real-time network monitor:     ARP sweep + Rogue AP + Pattern recogn, ARPTable, CorrelationEngine, DeviceRecord, get_monitor() (+17 more)

### Community 3 - "Community 3"
Cohesion: 0.05
Nodes (51): _cfg(), fire_alert(), _print_alert(), print_banner(), print_error(), RDDS — Alert Engine Module Handles terminal printing, log writing, and optional, Central function to raise an RDDS alert.     Implements Rate Limiting/Aggregati, _write_log() (+43 more)

### Community 4 - "Community 4"
Cohesion: 0.1
Nodes (24): AttackDetector, get_detector(), is_ioc(), load_threat_intel(), _port_name(), RDDS — Real-Time Attack Detector ================================== Multi-laye, Cached reverse-DNS lookup with a 1-second timeout to prevent blocking., Real-time multi-layer network attack detection engine.      Works via: (+16 more)

### Community 5 - "Community 5"
Cohesion: 0.09
Nodes (31): addToWhitelist(), alertHtml(), chartOptions(), closeSidebar(), escHtml(), fetchAlerts(), fetchDevices(), fetchStats() (+23 more)

### Community 6 - "Community 6"
Cohesion: 0.1
Nodes (18): NetworkThreatPredictor, Takes a dictionary of network features and predicts if it's an Evil Twin., api_top_talkers(), api_traffic_flows(), calculate_entropy(), Flow, Extract wireless-specific features for evil twin detection, Extract features for AI analysis (+10 more)

### Community 7 - "Community 7"
Cohesion: 0.1
Nodes (23): print_info(), run_dashboard(), Start background DHCP monitoring thread., Signal the monitor thread to stop., Profile a list of device dicts ({ip, mac, vendor}).         Runs concurrently w, _dispatch(), packet_handler(), _port_label() (+15 more)

### Community 8 - "Community 8"
Cohesion: 0.09
Nodes (25): get_default_gateway(), get_local_ip(), normalize_iface(), RDDS — Rogue Device Detection System Configuration Module, Get the local IP address of the primary interface., Best-effort default gateway IP detection on Windows., r"""     Format interface string for Scapy on Windows.     Converts raw GUID {, Scapy-based DHCP sniff loop. (+17 more)

### Community 9 - "Community 9"
Cohesion: 0.13
Nodes (28): api_add_wifi_allowlist(), api_get_wifi_allowlist(), api_remove_wifi_allowlist(), mark_whitelisted(), add_to_whitelist(), add_to_wifi_allowlist(), classify_new_device(), compute_risk_score() (+20 more)

### Community 10 - "Community 10"
Cohesion: 0.13
Nodes (21): print_warn(), api_wifi_scan(), is_ssid_allowed(), Rogue AP scan loop — fires every AP_SCAN_INTERVAL seconds., _beacon_handler(), detect_weak_encryption(), get_connected_ap(), load_known_aps() (+13 more)

### Community 11 - "Community 11"
Cohesion: 0.38
Nodes (6): build_from_ieee_csv(), build_from_local_txt(), main(), RDDS — OUI Database Expander Downloads the full IEEE OUI database and converts i, Try to build from a locally downloaded oui.txt file.     Download from: https://, Download IEEE OUI CSV directly (smaller and cleaner format).     CSV URL: https:

### Community 13 - "Community 13"
Cohesion: 1.0
Nodes (1): Outer wrapper — called for all packets.

### Community 14 - "Community 14"
Cohesion: 1.0
Nodes (1): Runs every 1 second.         Measures PPS per src MAC, builds IQR baseline, fir

### Community 15 - "Community 15"
Cohesion: 1.0
Nodes (1): Compute rate-of-change (d(PPS)/dt).         If acceleration > threshold, fire a

### Community 16 - "Community 16"
Cohesion: 1.0
Nodes (1): Process each sniffed packet via Scapy.

### Community 17 - "Community 17"
Cohesion: 1.0
Nodes (1): Listen for raw UDP DHCP packets (ports 67/68) using raw sockets.     Windows re

### Community 18 - "Community 18"
Cohesion: 1.0
Nodes (1): Thread-based DHCP security monitor.     Usage:         mon = DHCPMonitor(iface

### Community 19 - "Community 19"
Cohesion: 1.0
Nodes (1): Start background DHCP monitoring thread.

### Community 20 - "Community 20"
Cohesion: 1.0
Nodes (1): Scapy-based DHCP sniff loop.

### Community 21 - "Community 21"
Cohesion: 1.0
Nodes (1): Signal the monitor thread to stop.

### Community 22 - "Community 22"
Cohesion: 1.0
Nodes (1): Detect APs with no/weak encryption.

### Community 23 - "Community 23"
Cohesion: 1.0
Nodes (1): Full rogue AP detection cycle:     1. Scan surrounding Wi-Fi networks     2. D

## Knowledge Gaps
- **127 isolated node(s):** `RDDS — OUI Database Expander Downloads the full IEEE OUI database and converts i`, `Try to build from a locally downloaded oui.txt file.     Download from: https://`, `Download IEEE OUI CSV directly (smaller and cleaner format).     CSV URL: https:`, `Takes a dictionary of network features and predicts if it's an Evil Twin.`, `RDDS — Alert Engine Module Handles terminal printing, log writing, and optional` (+122 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 13`** (1 nodes): `Outer wrapper — called for all packets.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 14`** (1 nodes): `Runs every 1 second.         Measures PPS per src MAC, builds IQR baseline, fir`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 15`** (1 nodes): `Compute rate-of-change (d(PPS)/dt).         If acceleration > threshold, fire a`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 16`** (1 nodes): `Process each sniffed packet via Scapy.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 17`** (1 nodes): `Listen for raw UDP DHCP packets (ports 67/68) using raw sockets.     Windows re`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 18`** (1 nodes): `Thread-based DHCP security monitor.     Usage:         mon = DHCPMonitor(iface`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 19`** (1 nodes): `Start background DHCP monitoring thread.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 20`** (1 nodes): `Scapy-based DHCP sniff loop.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 21`** (1 nodes): `Signal the monitor thread to stop.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 22`** (1 nodes): `Detect APs with no/weak encryption.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 23`** (1 nodes): `Full rogue AP detection cycle:     1. Scan surrounding Wi-Fi networks     2. D`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `generateReport()` connect `Community 5` to `Community 4`?**
  _High betweenness centrality (0.109) - this node is a cross-community bridge._
- **Why does `fire_alert()` connect `Community 3` to `Community 0`, `Community 1`, `Community 2`, `Community 4`, `Community 6`, `Community 7`, `Community 9`, `Community 10`?**
  _High betweenness centrality (0.102) - this node is a cross-community bridge._
- **Why does `RealTimeMonitor` connect `Community 2` to `Community 0`, `Community 3`, `Community 4`, `Community 7`, `Community 10`?**
  _High betweenness centrality (0.075) - this node is a cross-community bridge._
- **Are the 18 inferred relationships involving `AttackDetector` (e.g. with `RDDS — Main CLI Entry Point Usage:   python rdds.py scan       — one-shot ARP` and `Continuous real-time network monitor:     ARP sweep + Rogue AP + Pattern recogn`) actually correct?**
  _`AttackDetector` has 18 INFERRED edges - model-reasoned connections that need verification._
- **Are the 18 inferred relationships involving `RealTimeMonitor` (e.g. with `RDDS — Main CLI Entry Point Usage:   python rdds.py scan       — one-shot ARP` and `Continuous real-time network monitor:     ARP sweep + Rogue AP + Pattern recogn`) actually correct?**
  _`RealTimeMonitor` has 18 INFERRED edges - model-reasoned connections that need verification._
- **Are the 19 inferred relationships involving `TrafficAnalyzer` (e.g. with `RDDS — Main CLI Entry Point Usage:   python rdds.py scan       — one-shot ARP` and `Continuous real-time network monitor:     ARP sweep + Rogue AP + Pattern recogn`) actually correct?**
  _`TrafficAnalyzer` has 19 INFERRED edges - model-reasoned connections that need verification._
- **Are the 26 inferred relationships involving `fire_alert()` (e.g. with `cmd_scan()` and `cmd_monitor()`) actually correct?**
  _`fire_alert()` has 26 INFERRED edges - model-reasoned connections that need verification._