"""
RDDS — Main CLI Entry Point
Usage:
  python rdds.py scan       — one-shot ARP scan
  python rdds.py monitor    — continuous real-time device monitoring
  python rdds.py dashboard  — launch the web dashboard
  python rdds.py report     — generate a JSON/HTML report
  python rdds.py ap         — scan for rogue access points
  python rdds.py whitelist  — manage the device whitelist
  python rdds.py iot        — IoT device profiling & risk assessment
  python rdds.py dhcp       — DHCP security monitoring
  python rdds.py traffic    — NetFlow/sFlow network traffic analysis
  python rdds.py rtmonitor  — continuous real-time network monitor (NEW)
  python rdds.py detect     — real-time attack detection (MITM/DDoS/DoS) (NEW)
"""

import argparse
import sys
import os
import json
import time
import threading
import subprocess
import warnings
from datetime import datetime

# Suppress harmless CryptographyDeprecationWarning from Scapy
warnings.filterwarnings("ignore", category=UserWarning, module="scapy")
warnings.filterwarnings("ignore", message=".*TripleDES has been moved.*")

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import database as db
from core.config import (NETWORK_TARGET, SCAN_INTERVAL, REPORTS_DIR)
from core.alert_engine import (fire_alert, print_info, print_warn,
                                print_error, print_banner)
from core.network_scanner import full_scan
from core.device_manager  import (classify_new_device, load_whitelist,
                                   add_to_whitelist, remove_from_whitelist,
                                   get_all_devices_enriched)
from core.mac_analyzer    import analyze_devices
from core.rogue_ap_detector import run_ap_detection
from core.config import (ALERT_NEW_DEVICE, SEV_HIGH)


# ─────────────────────────────────────────────
#  CONTINUOUS REAL-TIME MONITOR COMMAND
# ─────────────────────────────────────────────

def cmd_rtmonitor(args):
    """
    Continuous real-time network monitor:
    ARP sweep + Rogue AP + Pattern recognition + Correlation engine.
    """
    from core.realtime_monitor import RealTimeMonitor

    interval = getattr(args, 'interval', 30)
    iface    = getattr(args, 'iface',    None)
    no_ap    = getattr(args, 'no_ap',    False)
    duration = getattr(args, 'duration', 0)

    print_banner()
    print_info(f"Starting Continuous Real-Time Monitor")
    print_info(f"  Network : {NETWORK_TARGET}")
    print_info(f"  Interval: {interval}s")
    print_info(f"  Interface: {iface or 'auto'}")
    print_info(f"  AP Scan : {'disabled' if no_ap else 'enabled (every 60s)'}")
    print_info(f"  Duration: {'until Ctrl+C' if not duration else str(duration) + 's'}")
    print_info("")

    mon = RealTimeMonitor(
        iface=iface,
        network=NETWORK_TARGET,
        interval=interval,
        ap_scan=not no_ap
    )
    mon.start()

    start = time.time()
    try:
        while True:
            time.sleep(5)
            if duration and (time.time() - start) >= duration:
                break

            devices = mon.get_devices()
            stats   = mon.get_stats()

            print(f"\n\033[36m{'='*70}\033[0m")
            print(f"  \033[1m\033[32mREAL-TIME MONITOR  │  Scan #{stats['scan_count']}  "
                  f"│  Devices: {len(devices)}  │  Alerts: {stats['alerts_fired']}\033[0m")
            print(f"\033[36m{'='*70}\033[0m")

            if devices:
                print(f"  {'IP Address':<18} {'MAC Address':<20} "
                      f"{'Vendor':<22} {'Hostname':<20} {'Risk':<8} {'Status'}")
                print(f"  {'-'*18} {'-'*20} {'-'*22} {'-'*20} {'-'*8} {'-'*8}")
                for dev in sorted(devices, key=lambda d: d.get('risk_score', 0), reverse=True):
                    rlvl  = dev.get('risk_level', 'LOW')
                    color = {'CRITICAL': '\033[91m', 'HIGH': '\033[91m',
                             'MEDIUM': '\033[93m', 'LOW': '\033[92m'}.get(rlvl, '')
                    print(f"  {dev['ip']:<18} {dev['mac']:<20} "
                          f"{dev['vendor'][:22]:<22} {dev.get('hostname','')[:20]:<20} "
                          f"{color}{rlvl:<8}\033[0m {dev['status']}")
            else:
                print("  No devices discovered yet...")

            # Correlation events
            events = mon.get_correlation_events(5)
            if events:
                print(f"\n  \033[95m⚠  Correlation Events (last 5):\033[0m")
                for ev in events[-5:]:
                    sev   = ev.get('severity', 'INFO')
                    icon  = {'CRITICAL': '\033[91m🚨', 'HIGH': '\033[91m⚠',
                             'MEDIUM': '\033[93m⚠', 'INFO': '\033[92mℹ'}.get(sev, '')
                    print(f"  {icon} [{ev.get('timestamp','')}] "
                          f"{ev.get('type','')} — {ev.get('description','')[:60]}... \033[0m")

            # AP results
            if not no_ap:
                ap_res  = mon.get_ap_results()
                n_evil  = len(ap_res.get('evil_twins', []))
                n_total = ap_res.get('total_aps', 0)
                if n_total:
                    color = '\033[91m' if n_evil else '\033[92m'
                    print(f"\n  {color}Wi-Fi: {n_total} APs visible, "
                          f"{n_evil} EVIL TWIN(s) detected\033[0m")

    except KeyboardInterrupt:
        print_info("\nStopping real-time monitor...")
    finally:
        mon.stop()
        final = mon.get_stats()
        print_info(f"Session complete: {final['scan_count']} scans, "
                   f"{final['new_devices']} new devices, "
                   f"{final['alerts_fired']} alerts")


# ─────────────────────────────────────────────
#  REAL-TIME ATTACK DETECTION COMMAND
# ─────────────────────────────────────────────

def cmd_detect(args):
    """
    Real-time multi-layer attack detection:
    MITM, DDoS, SYN/ICMP/UDP Flood, Behavioral Anomaly,
    Threat Intelligence, Predictive Analysis.
    """
    from core.attack_detector import AttackDetector

    iface    = getattr(args, 'iface',    None)
    duration = getattr(args, 'duration', 0)
    gateway  = getattr(args, 'gateway',  None)

    print_banner()
    print_info("Starting Real-Time Attack Detection Engine")
    print_info(f"  Interface: {iface or 'auto'}")
    print_info(f"  Gateway  : {gateway or 'auto-detect'}")
    print_info(f"  Duration : {'until Ctrl+C' if not duration else str(duration) + 's'}")
    print_info("  Detectors: MITM / DDoS / SYN-Flood / ICMP-Flood / UDP-Flood /")
    print_info("             Behavioral-Anomaly / Threat-Intel / Predictive")
    print_info("")

    det = AttackDetector(iface=iface, duration=duration, gateway_ip=gateway)
    det.start()

    start     = time.time()
    last_shown = 0
    try:
        while True:
            time.sleep(3)
            if duration and (time.time() - start) >= duration:
                break

            events = det.get_events(20)    # last 20 events
            stats  = det.get_stats()
            now    = time.time()

            new_events = [e for e in events if e.get('ts_epoch', 0) > last_shown]
            if new_events:
                last_shown = now
                for ev in new_events:
                    sev   = ev.get('severity', 'INFO')
                    color = {'CRITICAL': '\033[91m\033[1m',
                             'HIGH':     '\033[91m',
                             'MEDIUM':   '\033[93m',
                             'LOW':      '\033[96m'}.get(sev, '')
                    icon  = {'CRITICAL': '\ud83d\udea8\ud83d\udea8',
                             'HIGH':     '\ud83d\udea8',
                             'MEDIUM':   '⚠️ ',
                             'LOW':      'ℹ️ '}.get(sev, '•')
                    print(f"  {color}{icon} [{ev['timestamp']}] "
                          f"{ev['attack_type']:<22}\033[0m  "
                          f"SRC={ev['src_ip']:<15} "
                          f"MAC={ev.get('src_mac','?'):<18} "
                          f"Vendor={ev.get('src_vendor','?'):<18} "
                          f"Host={ev.get('src_hostname','')[:16]}")
                    if ev.get('description'):
                        print(f"    \033[2m{ev['description'][:100]}\033[0m")
            else:
                # Print live heartbeat every ~15s
                if int(now) % 15 == 0:
                    s = det.get_summary()
                    print(f"  [Monitoring] pkts={stats['pkts_processed']} "
                          f" alerts={stats['total_alerts']} "
                          f" MITM={stats['mitm_alerts']}"
                          f" DDoS={stats['ddos_alerts']}"
                          f" SYN={stats['syn_alerts']}"
                          f" IOC={stats['ioc_matches']}")

    except KeyboardInterrupt:
        print_info("\nStopping attack detector...")
    finally:
        det.stop()
        final = det.get_stats()
        print_info(f"Detection session: {final['pkts_processed']} packets analysed, "
                   f"{final['total_alerts']} alerts fired")
        summary = det.get_summary()
        print_info("Attack breakdown:")
        for atype, cnt in summary.get('by_type', {}).items():
            print(f"   {atype}: {cnt}")


# ─────────────────────────────────────────────
#  IoT COMMAND
# ─────────────────────────────────────────────

def cmd_iot(args):
    from core.iot_profiler import IoTProfiler
    from core.network_scanner import full_scan

    target = args.target or NETWORK_TARGET
    print_info(f"IoT Profiling scan on {target} ...")
    devices = full_scan(target=target)

    profiler = IoTProfiler(
        port_timeout=args.timeout,
        max_port_workers=args.workers
    )
    profiles = profiler.profile_all(devices)

    print(f"\n{'─'*90}")
    print(f"{'IP':<17} {'MAC':<20} {'TYPE':<25} {'CATEGORY':<16} {'RISK':>6} {'SEVERITY':<10} {'CVEs'}")
    print(f"{'─'*90}")

    sev_colors = {
        'CRITICAL': '\033[91m\033[1m',
        'HIGH':     '\033[91m',
        'MEDIUM':   '\033[93m',
        'LOW':      '\033[92m',
    }
    reset = '\033[0m'

    for p in sorted(profiles, key=lambda x: x["iot_risk_score"], reverse=True):
        sev   = p.get("severity", "LOW")
        color = sev_colors.get(sev, '')
        print(
            f"{p['ip']:<17} {p['mac']:<20} "
            f"{p['device_type'][:24]:<25} {p['category'][:15]:<16} "
            f"{color}{p['iot_risk_score']:>6}{reset} "
            f"{color}{sev:<10}{reset} "
            f"{len(p.get('cve_indicators', []))}"
        )
        if args.verbose:
            for cve in p.get("cve_indicators", []):
                print(f"  {'':>17} \033[91m└ {cve}{reset}")
            for port, info in p.get("open_iot_ports", {}).items():
                print(f"  {'':>17}   Port {port:<6} {info.get('service','?'):<16} risk={info.get('risk',0)}")

    print(f"{'─'*90}")
    print(f"\n[+] Profiled {len(profiles)} devices | "
          f"High/Critical: {sum(1 for p in profiles if p['iot_risk_score']>=60)}")


# ─────────────────────────────────────────────
#  DHCP COMMAND
# ─────────────────────────────────────────────

def cmd_dhcp(args):
    from core.dhcp_monitor import DHCPMonitor, get_events, get_stats, get_lease_table

    authorized = []
    if args.authorized:
        authorized = [ip.strip() for ip in args.authorized.split(',') if ip.strip()]

    monitor = DHCPMonitor(iface=args.iface, authorized_servers=authorized or None)
    monitor.start()

    duration = args.duration
    print_info(f"DHCP Monitor running for {duration}s (Ctrl+C to stop early)")
    if authorized:
        print_info(f"Authorized DHCP servers: {authorized}")
    else:
        print_warn("No authorized servers specified — any DISCOVER/OFFER will be logged")
        print_warn("Use --authorized 192.168.1.1 to flag rogue servers")

    try:
        start = time.time()
        while time.time() - start < duration:
            time.sleep(5)
            stats = get_stats()
            elapsed = int(time.time() - start)
            print_info(
                f"[{elapsed:>3}s] DISCOVERs={stats['total_discover']} "
                f"OFFERs={stats['total_offer']} ACKs={stats['total_ack']} "
                f"Rogue={stats['rogue_servers_detected']} "
                f"Starvation={stats['starvation_events']} "
                f"Conflicts={stats['conflict_events']}"
            )
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()

    # Final summary
    events = get_events(50)
    leases = get_lease_table()
    stats  = get_stats()

    print(f"\n{'─'*60}")
    print(f"[DHCP Summary]")
    print(f"  DISCOVERs   : {stats['total_discover']}")
    print(f"  OFFERs      : {stats['total_offer']}")
    print(f"  ACKs        : {stats['total_ack']}")
    print(f"  Rogue DHCP  : \033[91m{stats['rogue_servers_detected']}\033[0m")
    print(f"  Starvation  : \033[91m{stats['starvation_events']}\033[0m")
    print(f"  IP Conflicts: \033[91m{stats['conflict_events']}\033[0m")
    print(f"\n[Active Leases]")
    for mac, lease in list(leases.items())[:20]:
        print(f"  {mac:<20} → {lease['ip']:<16} via {lease.get('server_ip','?')}")
    print(f"{'─'*60}")


# ─────────────────────────────────────────────
#  TRAFFIC COMMAND
# ─────────────────────────────────────────────

def cmd_traffic(args):
    from core.traffic_analyzer import TrafficAnalyzer

    analyzer = TrafficAnalyzer(
        netflow_port=args.netflow_port,
        sflow_port=args.sflow_port,
        iface=args.iface,
        passive_mode=True
    )
    analyzer.start()

    duration = args.duration
    print_info(f"Traffic Analyzer running for {duration}s (Ctrl+C to stop early)")
    print_info(f"NetFlow: UDP/{args.netflow_port}  sFlow: UDP/{args.sflow_port}  Passive: ON")

    try:
        start = time.time()
        while time.time() - start < duration:
            time.sleep(10)
            elapsed = int(time.time() - start)
            stats   = analyzer.get_stats()
            talkers = analyzer.get_top_talkers(5)
            anomalies = analyzer.get_anomalies(5)

            print(f"\n[{elapsed:>4}s elapsed] "
                  f"NFv5={stats['netflow_v5_records']} "
                  f"NFv9={stats['netflow_v9_records']} "
                  f"sFlow={stats['sflow_samples']} "
                  f"Passive={stats['passive_packets']} "
                  f"Anomalies={stats['anomalies_detected']}")

            if talkers:
                print("  Top Talkers (src):")
                for t in talkers:
                    out_mb = t['bytes_out'] / 1024 / 1024
                    in_mb  = t['bytes_in']  / 1024 / 1024
                    print(f"    {t['ip']:<18} out={out_mb:7.2f}MB  in={in_mb:7.2f}MB "
                          f"pkts_out={t['pkts_out']:>8}")

            if anomalies:
                for a in anomalies[-3:]:
                    sev_c = '\033[91m' if a['severity'] in ('CRITICAL','HIGH') else '\033[93m'
                    print(f"  {sev_c}[ANOMALY] [{a['type']}] {a['detail'][:80]}...\033[0m")

    except KeyboardInterrupt:
        pass
    finally:
        analyzer.stop()

    # Final summary
    stats   = analyzer.get_stats()
    talkers = analyzer.get_top_talkers(10)
    anom    = analyzer.get_anomalies(20)

    print(f"\n{'─'*72}")
    print(f"[Traffic Analysis Summary]")
    print(f"  NetFlow v5  records : {stats['netflow_v5_records']:>8}")
    print(f"  NetFlow v9  records : {stats['netflow_v9_records']:>8}")
    print(f"  sFlow samples       : {stats['sflow_samples']:>8}")
    print(f"  Passive packets     : {stats['passive_packets']:>8}")
    print(f"  Anomalies detected  : \033[91m{stats['anomalies_detected']:>4}\033[0m")

    print(f"\n  Top 10 Talkers:")
    for t in talkers:
        out_mb = t['bytes_out'] / 1024 / 1024
        print(f"    {t['ip']:<20} {out_mb:8.2f} MB out")

    if anom:
        print(f"\n  Detected Anomalies:")
        for a in anom:
            print(f"    [{a['severity']}] {a['type']} → {a['src_ip']} — {a['detail'][:60]}")
    print(f"{'─'*72}")



# ─────────────────────────────────────────────
#  STARTUP
# ─────────────────────────────────────────────

def startup():
    """Initialize DB and run startup tasks."""
    db.init_db()
    
    # Run dynamic risk decay once on startup 
    from core.device_manager import process_risk_decay
    try:
        process_risk_decay()
    except Exception:
        pass


# ─────────────────────────────────────────────
#  SCAN COMMAND
# ─────────────────────────────────────────────

def cmd_scan(args):
    print_info(f"Target: {args.target or NETWORK_TARGET}")
    print_info("Running network scan...")

    devices = full_scan(
        target=args.target or NETWORK_TARGET,
        use_passive=args.passive,
        passive_timeout=args.passive_timeout
    )
    devices = analyze_devices(devices)

    wl      = load_whitelist()
    new_cnt = 0

    print(f"\n{'─'*72}")
    print(f"{'IP':<17} {'MAC':<20} {'VENDOR':<22} {'STATUS':<14} RISK")
    print(f"{'─'*72}")

    for d in devices:
        enriched = classify_new_device(d)
        mac      = d.get("mac", "")
        ip       = d.get("ip",  "")
        vendor   = d.get("vendor", "Unknown")[:20]
        score    = enriched.get("risk_score", 0)
        is_wl    = mac in wl

        status = "TRUSTED" if is_wl else ("ROGUE" if score >= 60 else "UNKNOWN")
        color  = "\033[92m" if is_wl else ("\033[91m" if score >= 60 else "\033[93m")
        reset  = "\033[0m"

        print(f"{ip:<17} {mac:<20} {vendor:<22} {color}{status:<14}{reset} {score}")

        db.upsert_device(
            mac=mac, ip=ip, vendor=vendor,
            hostname=d.get("hostname",""),
            risk_score=score, is_whitelisted=1 if is_wl else 0,
            flags=",".join(enriched.get("flags", []))
        )

        if not is_wl:
            new_cnt += 1
            fire_alert(
                alert_type=ALERT_NEW_DEVICE,
                severity=SEV_HIGH if score >= 60 else "MEDIUM",
                description=(f"Unknown device on network: IP={ip}, "
                             f"MAC={mac}, Vendor={vendor}"),
                device_mac=mac, device_ip=ip
            )

    print(f"{'─'*72}")
    print(f"\n[+] Total: {len(devices)} | Unknown/Rogue: {new_cnt}")
    db.log_scan(len(devices), new_cnt, new_cnt)


# ─────────────────────────────────────────────
#  MONITOR COMMAND
# ─────────────────────────────────────────────

def cmd_monitor(args):
    print_info(f"Starting continuous monitor (interval={args.interval}s)")
    print_info("Press Ctrl+C to stop\n")

    # Optionally start packet engine
    if args.deep:
        from core.packet_engine import start_packet_engine
        print_info("Deep mode: packet engine active (ARP/DNS/Port scan detection)")
        start_packet_engine(iface=args.iface)

    scan_count = 0
    try:
        while True:
            scan_count += 1
            print_info(f"Scan #{scan_count} at {datetime.now().strftime('%H:%M:%S')}")
            devices = full_scan(target=args.target or NETWORK_TARGET)
            devices = analyze_devices(devices)

            wl      = load_whitelist()
            new_cnt = 0
            for d in devices:
                enriched = classify_new_device(d)
                mac      = d.get("mac","")
                ip       = d.get("ip", "")
                vendor   = d.get("vendor","Unknown")
                score    = enriched.get("risk_score",0)
                is_wl    = mac in wl

                db.upsert_device(
                    mac=mac, ip=ip, vendor=vendor,
                    hostname=d.get("hostname",""),
                    risk_score=score, is_whitelisted=1 if is_wl else 0,
                    flags=",".join(enriched.get("flags",[]))
                )

                if not is_wl:
                    new_cnt += 1
                    fire_alert(
                        alert_type=ALERT_NEW_DEVICE,
                        severity=SEV_HIGH if score >= 60 else "MEDIUM",
                        description=(f"Unknown device: IP={ip} MAC={mac} "
                                     f"Vendor={vendor} Score={score}"),
                        device_mac=mac, device_ip=ip
                    )

            print_info(f"Found {len(devices)} devices, {new_cnt} unknown/rogue")
            db.log_scan(len(devices), new_cnt, new_cnt)

            # Run behavioral analysis every 5 scans
            if scan_count % 5 == 0 and args.deep:
                from core.behavioral_analyzer import analyze_all_devices
                results = analyze_all_devices()
                if results:
                    print_warn(f"Behavioral anomalies: {len(results)} device(s) flagged")

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print_info("\nMonitor stopped by user.")
        if args.deep:
            from core.packet_engine import stop_packet_engine
            stop_packet_engine()


# ─────────────────────────────────────────────
#  DASHBOARD COMMAND
# ─────────────────────────────────────────────

def cmd_dashboard(args):
    print_info(f"Launching dashboard at http://localhost:{args.port}")
    print_info("Open your browser and navigate to the URL above.")
    print_info("Press Ctrl+C to stop.")

    # Override port if provided
    import core.config as cfg
    cfg.DASHBOARD_PORT = args.port

    # Optionally run monitor in background
    if args.monitor:
        print_info("Background monitor started (scan every 60s)")
        def _bg_monitor():
            while True:
                try:
                    devices = full_scan(target=NETWORK_TARGET)
                    devices = analyze_devices(devices)
                    wl      = load_whitelist()
                    for d in devices:
                        enriched = classify_new_device(d)
                        mac = d.get("mac","")
                        is_wl = mac in wl
                        db.upsert_device(
                            mac=mac, ip=d.get("ip",""),
                            vendor=d.get("vendor",""),
                            hostname=d.get("hostname",""),
                            risk_score=enriched.get("risk_score",0),
                            is_whitelisted=1 if is_wl else 0
                        )
                except Exception as e:
                    print_error(f"Background scan error: {e}")
                time.sleep(SCAN_INTERVAL)

        t = threading.Thread(target=_bg_monitor, daemon=True)
        t.start()

    # Start packet engine for deep monitoring
    if args.deep:
        from core.packet_engine import start_packet_engine
        start_packet_engine()

    from dashboard.app import run_dashboard
    run_dashboard()


# ─────────────────────────────────────────────
#  AP COMMAND
# ─────────────────────────────────────────────

def cmd_ap(args):
    print_info("Scanning for rogue access points...")
    baseline = {}
    if args.baseline and os.path.exists(args.baseline):
        with open(args.baseline) as f:
            baseline = json.load(f)

    def _run_single_scan():
        result = run_ap_detection(baseline=baseline or None)
        print(f"\n[+] Total APs visible: {result['total_aps']}")
        print(f"[!] Evil twin / rogue: {len(result['evil_twins'])}")
        print(f"[!] Open/weak APs:     {len(result['weak_aps'])}")

        if result.get("connected_ap"):
            c = result["connected_ap"]
            print(f"\n[*] Currently connected to:")
            print(f"    SSID:  {c.get('ssid','?')}")
            print(f"    BSSID: {c.get('bssid','?')}")
            print(f"    Auth:  {c.get('authentication','?')}")
            
        all_issues = result['evil_twins'] + result['weak_aps']
        unified_rogues = []
        for r in all_issues:
            unified_rogues.append({
                "SSID": r.get('ssid', 'Unknown'),
                "Issue": r.get('flag', 'Unknown Risk'),
                "BSSIDs": r.get('bssids', [r.get('bssid', '?')])
            })
            
        if getattr(args, 'report', False) and unified_rogues:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(REPORTS_DIR, f"rogue_ap_scan_{ts}.json")
            with open(report_path, "w") as rf:
                json.dump(unified_rogues, rf, indent=4)
            print_info(f"Report saved to {report_path}")

    if getattr(args, 'monitor', False):
        interval = getattr(args, 'interval', 30)
        print_info(f"Starting continuous AP monitor (interval={interval}s)")
        print_info("Press Ctrl+C to stop\n")
        try:
            while True:
                _run_single_scan()
                time.sleep(interval)
        except KeyboardInterrupt:
            print_info("\nAP Monitor stopped by user.")
    else:
        _run_single_scan()


# ─────────────────────────────────────────────
#  WHITELIST COMMAND
# ─────────────────────────────────────────────

def cmd_whitelist(args):
    if args.add:
        add_to_whitelist(
            args.add.strip(),
            label=args.label,
            note=args.note,
            ip=args.ip,
            hostname=args.hostname,
            vendor=args.vendor
        )
        print_info(f"Added to whitelist: {args.add.strip()}")

    elif getattr(args, 'modify', False) and args.modify:
        wl = load_whitelist()
        mac = args.modify.strip().lower()
        if mac not in wl:
            print_warn(f"MAC {mac} not found in whitelist.")
            return
        
        entry = wl[mac]
        if args.label: entry["label"] = args.label
        if args.ip: entry["ip"] = args.ip
        if args.note: entry["note"] = args.note
        if args.hostname: entry["hostname"] = args.hostname
        if args.vendor: entry["vendor"] = args.vendor
        
        add_to_whitelist(
            mac,
            label=entry.get("label", ""),
            note=entry.get("note", ""),
            ip=entry.get("ip", ""),
            hostname=entry.get("hostname", ""),
            vendor=entry.get("vendor", ""),
            risk_score=entry.get("risk_score", 0)
        )
        print_info(f"Modified whitelist entry: {mac}")

    elif args.remove:
        ok = remove_from_whitelist(args.remove.strip())
        if ok:
            print_info(f"Removed: {args.remove}")
        else:
            print_warn(f"Not found in whitelist: {args.remove}")

    else:
        wl = load_whitelist()
        if not wl:
            print_info("Whitelist is empty.")
        else:
            print(f"\n{'MAC':<18} {'IP':<15} {'HOSTNAME':<15} {'VENDOR':<15} {'LABEL':<15} ADDED")
            print("─"*95)
            for mac, v in wl.items():
                added = v.get("added","?")[:10]
                ip_str = v.get('ip','')[:14]
                host_str = v.get('hostname','')[:14]
                ven_str = v.get('vendor','')[:14]
                lbl_str = v.get('label','')[:14]
                print(f"{mac:<18} {ip_str:<15} {host_str:<15} {ven_str:<15} {lbl_str:<15} {added}")


# ─────────────────────────────────────────────
#  REPORT COMMAND
# ─────────────────────────────────────────────

def cmd_report(args):
    devices = get_all_devices_enriched()
    alerts  = db.get_alerts(limit=500)
    stats   = db.get_alert_stats()
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")

    report = {
        "generated":   datetime.now().isoformat(),
        "stats":       stats,
        "devices":     devices,
        "alerts":      alerts,
    }

    json_path = os.path.join(REPORTS_DIR, f"rdds_report_{ts}.json")
    html_path = os.path.join(REPORTS_DIR, f"rdds_report_{ts}.html")

    # JSON report
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    # HTML report
    _generate_html_report(html_path, report)

    print_info(f"JSON report: {json_path}")
    print_info(f"HTML report: {html_path}")


def _generate_html_report(path: str, data: dict):
    devices = data.get("devices", [])
    alerts  = data.get("alerts",  [])
    stats   = data.get("stats",   {})
    ts      = data.get("generated","")

    device_rows = "".join(
        f"<tr><td>{d.get('ip','—')}</td><td>{d.get('mac','—')}</td>"
        f"<td>{d.get('vendor','—')}</td>"
        f"<td>{'✓ Trusted' if d.get('is_whitelisted') else '⚠ Unknown'}</td>"
        f"<td>{d.get('risk_score',0)}</td></tr>"
        for d in devices
    )
    alert_rows = "".join(
        f"<tr><td>{a.get('timestamp','—')[:19]}</td>"
        f"<td><b>{a.get('severity','—')}</b></td>"
        f"<td>{a.get('alert_type','—')}</td>"
        f"<td>{a.get('description','—')[:100]}</td></tr>"
        for a in alerts[:100]
    )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>RDDS Security Report</title>
<style>
  body{{font-family:Inter,sans-serif;background:#0a0c10;color:#e8edf5;margin:0;padding:32px}}
  h1{{color:#00ff88;letter-spacing:2px}}h2{{color:#4da6ff;margin-top:2rem}}
  table{{width:100%;border-collapse:collapse;font-size:0.85rem;margin-top:1rem}}
  th{{background:#141720;padding:10px 14px;color:#7a8499;text-align:left;border-bottom:1px solid #1e2430}}
  td{{padding:9px 14px;border-bottom:1px solid #141720}}
  tr:hover td{{background:#141720}}
  .stat{{display:inline-block;background:#141720;border:1px solid #1e2430;border-radius:10px;
         padding:16px 24px;margin:8px;text-align:center}}
  .stat b{{display:block;font-size:2rem;color:#00ff88}}
  .stat span{{font-size:0.8rem;color:#7a8499}}
</style></head><body>
<h1>🛡️ RDDS Security Report</h1>
<p style="color:#4a5568">Generated: {ts}</p>
<h2>Summary</h2>
<div class="stat"><b>{stats.get('total_devices',0)}</b><span>Devices Found</span></div>
<div class="stat"><b style="color:#ff3b5c">{stats.get('rogue_devices',0)}</b><span>Rogue/Unknown</span></div>
<div class="stat"><b style="color:#ff8c42">{stats.get('total',0)}</b><span>Total Alerts</span></div>
<div class="stat"><b style="color:#ff3b5c">{stats.get('CRITICAL',0)}</b><span>Critical</span></div>
<h2>Devices</h2>
<table><thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Status</th><th>Risk Score</th></tr></thead>
<tbody>{device_rows}</tbody></table>
<h2>Alerts (Last 100)</h2>
<table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Description</th></tr></thead>
<tbody>{alert_rows}</tbody></table>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    try:
        startup()
        print_banner()

        parser = argparse.ArgumentParser(
            prog="rdds",
            description="RDDS — Rogue Device Detection System (Enterprise-Grade)",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Commands:
  scan       Active network scan (ARP + ping)
  monitor    Continuous real-time monitoring
  dashboard  Launch web dashboard at localhost:5000
  ap         Rogue Access Point detection
  whitelist  Manage the trusted device whitelist
  report     Generate JSON + HTML security report
"""
        )

        sub = parser.add_subparsers(dest="command")

        # scan
        p_scan = sub.add_parser("scan", help="One-shot network scan")
        p_scan.add_argument("--target",          default=None,  help="CIDR range (default from config)")
        p_scan.add_argument("--passive",         action="store_true", help="Also run passive ARP sniff")
        p_scan.add_argument("--passive-timeout", type=int, default=15, help="Passive sniff seconds (default 15)")

        # monitor
        p_mon = sub.add_parser("monitor", help="Continuous monitoring loop")
        p_mon.add_argument("--target",   default=None,  help="CIDR range")
        p_mon.add_argument("--interval", type=int, default=SCAN_INTERVAL, help="Scan interval seconds")
        p_mon.add_argument("--iface",    default=None,  help="Network interface for packet capture")
        p_mon.add_argument("--deep",     action="store_true", help="Enable deep packet inspection")

        # dashboard
        p_dash = sub.add_parser("dashboard", help="Launch web dashboard")
        p_dash.add_argument("--port",    type=int, default=5000, help="Port (default 5000)")
        p_dash.add_argument("--monitor", action="store_true",     help="Run background network scan")
        p_dash.add_argument("--deep",    action="store_true",     help="Enable packet engine")

        # ap
        p_ap = sub.add_parser("ap", help="Rogue Access Point detection")
        p_ap.add_argument("--baseline", default=None, help="Path to known BSSIDs JSON file")
        p_ap.add_argument("--monitor", action="store_true", help="Run AP scan continuously")
        p_ap.add_argument("--interval", type=int, default=30, help="Scan interval (default 30s)")
        p_ap.add_argument("--report", action="store_true", help="Generate TXT, CSV, JSON reports of rogue APs")

        # whitelist
        p_wl = sub.add_parser(
            "whitelist",
            help="Manage trusted devices",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # View Whitelist Devices (shows MAC, IP, Hostname, Vendor, Label, Date)
  python rdds.py whitelist

  # Add a Device manually (IP, Vendor, Hostname are optional but recommended)
  python rdds.py whitelist --add AA:BB:CC:DD:EE:FF --ip 192.168.1.50 --vendor "Apple" --hostname "iPhone" --label "John's Phone" --note "Approved"

  # Modify an existing entry (Update specific fields by MAC)
  python rdds.py whitelist --modify AA:BB:CC:DD:EE:FF --label "Jane's Phone" --note "Updated role"

  # Delete/Remove a Device from whitelist
  python rdds.py whitelist --remove AA:BB:CC:DD:EE:FF

Note: Adding a device to the whitelist will reset its risk score to 0 in the database.
"""
        )
        p_wl.add_argument("--add",    default=None, help="MAC address to add")
        p_wl.add_argument("--remove", default=None, help="MAC address to remove")
        p_wl.add_argument("--modify", default=None, help="MAC address to modify (use with other flag args)")
        p_wl.add_argument("--ip", default="", help="IP Address")
        p_wl.add_argument("--label", default="", help="Label")
        p_wl.add_argument("--note", default="", help="Note")
        p_wl.add_argument("--hostname", default="", help="Hostname")
        p_wl.add_argument("--vendor", default="", help="Vendor")

        # report
        p_rep = sub.add_parser("report", help="Generate security report")

        # iot
        p_iot = sub.add_parser("iot", help="IoT device profiling & risk assessment")
        p_iot.add_argument("--target",  default=None,  help="CIDR range (default from config)")
        p_iot.add_argument("--timeout", type=float, default=1.5, help="Port scan timeout per port (default 1.5s)")
        p_iot.add_argument("--workers", type=int, default=25, help="Concurrent port scan threads (default 25)")
        p_iot.add_argument("--verbose", action="store_true", help="Show CVE indicators and port details")

        # dhcp
        p_dhcp = sub.add_parser("dhcp", help="DHCP security monitor")
        p_dhcp.add_argument("--iface",      default=None, help="Network interface (e.g. 'Wi-Fi')")
        p_dhcp.add_argument("--authorized", default=None, help="Comma-separated authorized DHCP server IPs")
        p_dhcp.add_argument("--duration",   type=int, default=120, help="Monitor duration in seconds (default 120)")

        # traffic
        p_tr = sub.add_parser("traffic", help="NetFlow/sFlow network traffic analysis")
        p_tr.add_argument("--netflow-port", type=int, default=2055, help="NetFlow UDP port (default 2055)")
        p_tr.add_argument("--sflow-port",   type=int, default=6343, help="sFlow UDP port (default 6343)")
        p_tr.add_argument("--iface",        default=None, help="Interface for passive sniffing")
        p_tr.add_argument("--duration",     type=int, default=120, help="Collection duration in seconds (default 120)")

        # rtmonitor
        p_rtm = sub.add_parser("rtmonitor", help="Continuous real-time network monitor (ARP + Rogue AP + Pattern + Correlation)")
        p_rtm.add_argument("--iface",    default=None, help="Network interface (default: auto)")
        p_rtm.add_argument("--interval", type=int, default=30, help="ARP sweep interval in seconds (default 30)")
        p_rtm.add_argument("--duration", type=int, default=0, help="Run duration in seconds (0=infinite)")
        p_rtm.add_argument("--no-ap",    action="store_true", help="Disable Wi-Fi Rogue AP scanning")

        # detect
        p_det = sub.add_parser("detect", help="Real-time attack detection (MITM/DDoS/DoS/Behavioral/ThreatIntel)")
        p_det.add_argument("--iface",    default=None, help="Network interface to sniff (default: auto)")
        p_det.add_argument("--duration", type=int, default=0, help="Detection duration in seconds (0=infinite)")
        p_det.add_argument("--gateway",  default=None, help="Gateway IP for MITM baseline (default: auto-detect)")

        args = parser.parse_args()

        if not args.command:
            parser.print_help()
            return

        dispatch = {
            "scan":      cmd_scan,
            "monitor":   cmd_monitor,
            "dashboard": cmd_dashboard,
            "ap":        cmd_ap,
            "whitelist": cmd_whitelist,
            "report":    cmd_report,
            "iot":       cmd_iot,
            "dhcp":      cmd_dhcp,
            "traffic":   cmd_traffic,
            "rtmonitor": cmd_rtmonitor,
            "detect":    cmd_detect,
        }

        fn = dispatch.get(args.command)
        if fn:
            fn(args)
        else:
            parser.print_help()
    except Exception as e:
        print_error(f"FATAL ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
