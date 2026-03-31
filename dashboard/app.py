"""
RDDS — Flask Dashboard Backend (app.py)
REST API + Dashboard server for the Rogue Device Detection System.
Includes API routes for: Devices, Alerts, Stats, Whitelist, Scan trigger,
IoT Profiling, DHCP Security, Network Traffic Analysis.
"""

import os
import sys
import json
import socket
import subprocess
import threading

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request, render_template, abort, send_file
from core import database as db
from core.device_manager import (load_whitelist, add_to_whitelist,
                                  remove_from_whitelist, get_all_devices_enriched)
from core.config import (DASHBOARD_HOST, DASHBOARD_PORT,
                         DASHBOARD_DEBUG, MAX_ALERTS_DISPLAY)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(24)

db.init_db()

# Run dynamic risk decay once on dashboard startup
try:
    from core.device_manager import process_risk_decay
    process_risk_decay()
except Exception:
    pass

_dhcp_monitor     = None
_traffic_analyzer = None
_dhcp_lock        = threading.Lock()
_traffic_lock     = threading.Lock()


def _get_dhcp(iface=None):
    global _dhcp_monitor
    with _dhcp_lock:
        # Recreate if interface changed
        if _dhcp_monitor is None or (iface and getattr(_dhcp_monitor, 'iface', None) != iface):
            from core.dhcp_monitor import DHCPMonitor
            _dhcp_monitor = DHCPMonitor(iface=iface)
    return _dhcp_monitor


def _get_traffic(iface=None):
    global _traffic_analyzer
    with _traffic_lock:
        if _traffic_analyzer is None or (iface and getattr(_traffic_analyzer, 'iface', None) != iface):
            from core.traffic_analyzer import TrafficAnalyzer
            _traffic_analyzer = TrafficAnalyzer(iface=iface, passive_mode=True)
    return _traffic_analyzer


# ─────────────────────────────────────────────
#  NETWORK INTERFACE DISCOVERY
# ─────────────────────────────────────────────

def _get_interfaces():
    """
    Enumerate available network interfaces.
    Deduplicates results by MAC address and IP to prevent double-listing
    (merging Scapy descriptions with Windows friendly names).
    """
    interfaces_by_mac = {}
    interfaces_by_ip  = {}
    final_list = []

    # Method 1: Scapy (best for packet capture)
    try:
        from scapy.all import IFACES, conf
        try:
            conf.ifaces.reload()
        except:
            pass

        for iface_name, iface_obj in IFACES.items():
            try:
                ip = getattr(iface_obj, 'ip', '') or ''
                mac = getattr(iface_obj, 'mac', '').lower() or ''
                desc = getattr(iface_obj, 'description', '') or iface_name
                is_up = getattr(iface_obj, 'is_valid', lambda: True)()
                
                # Filter out pure "dead" miniports (common on Windows)
                if not ip and "WAN Miniport" in desc:
                    continue

                iface_info = {
                    "name":        iface_name,
                    "ip":          ip,
                    "mac":         mac,
                    "description": desc[:70],
                    "is_up":       bool(is_up),
                    "source":      "scapy"
                }

                if mac and mac != '00:00:00:00:00:00':
                    interfaces_by_mac[mac] = iface_info
                if ip and ip != '0.0.0.0':
                    interfaces_by_ip[ip] = iface_info
                
                # Always add to physical list if no reliable deduplicator yet
                if not mac and not ip:
                    final_list.append(iface_info)
            except Exception:
                pass
    except Exception:
        pass

    # Method 2: Windows netsh (best for finding 'real' IPs and names)
    try:
        # Get active interfaces and their IPs
        out = subprocess.check_output(
            ["netsh", "interface", "ip", "show", "addresses"],
            text=True, stderr=subprocess.DEVNULL, timeout=5
        )
        current_iface = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Configuration for interface"):
                current_iface = line.split('"')[1] if '"' in line else line.split()[-1]
            elif "IP Address" in line and current_iface:
                ip = line.split()[-1]
                
                if ip in interfaces_by_ip:
                    entry = interfaces_by_ip[ip]
                    # Prioritize the friendlier Windows name (e.g., "Wi-Fi")
                    # Over Scapy's hardware description (e.g., "MediaTek...")
                    entry["description"] = current_iface
                else:
                    # New interface not seen by scapy (less likely)
                    interfaces_by_ip[ip] = {
                        "name":        current_iface,
                        "ip":          ip,
                        "mac":         "",
                        "description": current_iface,
                        "is_up":       True,
                        "source":      "netsh"
                    }
                current_iface = None
    except Exception:
        pass

    # Merge unique interfaces
    unique_results = []
    seen_identifiers = set()

    # Priority 1: Interfaces with MACs
    for mac, info in interfaces_by_mac.items():
        unique_results.append(info)
        seen_identifiers.add(mac)
        if info.get("ip"):
            seen_identifiers.add(info["ip"])

    # Priority 2: Interfaces with IPs not already seen via MAC
    for ip, info in interfaces_by_ip.items():
        if ip not in seen_identifiers:
            unique_results.append(info)
            seen_identifiers.add(ip)

    # Priority 3: Anything else left over
    for info in final_list:
        if info["name"] not in seen_identifiers:
            unique_results.append(info)

    # Sort: Interfaces with IPs first
    unique_results.sort(key=lambda x: (not x['ip'], x['description']))

    return unique_results or [{"name": "Default", "ip": "—", "description": "No interfaces found", "is_up": True, "source": "none"}]


# ─────────────────────────────────────────────
#  MAIN DASHBOARD PAGE
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─────────────────────────────────────────────
#  API: NETWORK INTERFACES
# ─────────────────────────────────────────────

@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    """Return all available network interfaces on the server host."""
    try:
        ifaces = _get_interfaces()
        return jsonify({"interfaces": ifaces, "count": len(ifaces)})
    except Exception as e:
        return jsonify({"interfaces": [], "count": 0, "error": str(e)})


# ─────────────────────────────────────────────
#  API: DEVICES
# ─────────────────────────────────────────────

@app.route("/api/devices", methods=["GET"])
def api_devices():
    devices = get_all_devices_enriched()
    return jsonify({"devices": devices, "count": len(devices)})


@app.route("/api/devices/<mac>", methods=["GET"])
def api_device_detail(mac):
    try:
        device = db.get_device(mac)
        if not device:
            abort(404)
        return jsonify(device)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/devices/<mac>", methods=["DELETE"])
def api_delete_device(mac):
    try:
        db.delete_device(mac)
        return jsonify({"status": "deleted", "mac": mac})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
#  API: ALERTS
# ─────────────────────────────────────────────

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    limit  = request.args.get("limit", MAX_ALERTS_DISPLAY, type=int)
    alerts = db.get_alerts(limit=limit)
    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/alerts/clear", methods=["POST"])
def api_clear_alerts():
    return jsonify({"status": "cleared"})


# ─────────────────────────────────────────────
#  API: STATS
# ─────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
def api_stats():
    raw_stats = db.get_alert_stats()
    normalized_stats = {}
    for k, v in raw_stats.items():
        if k in ["total", "total_devices", "rogue_devices"]:
            normalized_stats[k] = v
        elif k is not None:
            normalized_stats[str(k).upper()] = v

    history = db.get_scan_history(limit=20)
    return jsonify({"stats": normalized_stats, "history": history})


# ─────────────────────────────────────────────
#  API: WHITELIST
# ─────────────────────────────────────────────

@app.route("/api/whitelist", methods=["GET"])
def api_get_whitelist():
    wl = load_whitelist()
    return jsonify({"whitelist": wl})


@app.route("/api/whitelist", methods=["POST"])
def api_add_whitelist():
    data  = request.get_json()
    mac   = data.get("mac", "").strip().lower()
    label = data.get("label", "")
    note  = data.get("note", "")
    ip    = data.get("ip", "").strip()
    hostname = data.get("hostname", "")
    vendor   = data.get("vendor", "")
    risk_score = data.get("risk_score", 0)
    
    if not mac:
        return jsonify({"error": "mac required"}), 400
    try:
        add_to_whitelist(mac, label, note, ip=ip, hostname=hostname, vendor=vendor, risk_score=risk_score)
        db.update_risk_score(mac, 0)
        return jsonify({"status": "added", "mac": mac, "ip": ip})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/whitelist/<mac>", methods=["DELETE"])
def api_remove_whitelist(mac):
    ok = remove_from_whitelist(mac.lower())
    if not ok:
        return jsonify({"error": "MAC not in whitelist"}), 404
    return jsonify({"status": "removed", "mac": mac})


# ─────────────────────────────────────────────
#  API: SCAN TRIGGER
# ─────────────────────────────────────────────

_scan_status = {"running": False, "last_result": None}


@app.route("/api/scan", methods=["POST"])
def api_trigger_scan():
    if _scan_status["running"]:
        return jsonify({"status": "already_running"})

    def _do_scan():
        _scan_status["running"] = True
        try:
            from core.network_scanner import full_scan
            from core.config import NETWORK_TARGET
            
            alerts_before = db.get_alert_stats().get("total", 0)
            devs_before = len(get_all_devices_enriched())
            
            result = full_scan(NETWORK_TARGET)
            
            alerts_after = db.get_alert_stats().get("total", 0)
            devs_after = len(get_all_devices_enriched())
            db.log_scan(len(result), max(0, alerts_after - alerts_before), max(0, devs_after - devs_before))
            
            _scan_status["last_result"] = {"count": len(result), "devices": result}
        except Exception as e:
            _scan_status["last_result"] = {"error": str(e)}
        finally:
            _scan_status["running"] = False

    threading.Thread(target=_do_scan, daemon=True).start()
    return jsonify({"status": "scan_started"})


@app.route("/api/scan/status", methods=["GET"])
def api_scan_status():
    return jsonify(_scan_status)


# ─────────────────────────────────────────────────────────────────────
#  API: IoT DEVICE PROFILING & RISK ASSESSMENT
# ─────────────────────────────────────────────────────────────────────

_iot_scan_status = {"running": False, "last_count": 0}


@app.route("/api/iot/profiles", methods=["GET"])
def api_iot_profiles():
    try:
        from core.iot_profiler import get_all_profiles
        mem_profiles = get_all_profiles()
        db_profiles  = db.get_all_iot_profiles()
        merged = {p["mac"]: p for p in db_profiles}
        for p in mem_profiles:
            merged[p["mac"]] = p
        profiles = sorted(merged.values(),
                          key=lambda x: x.get("iot_risk_score", 0), reverse=True)
        return jsonify({"profiles": profiles, "count": len(profiles)})
    except Exception as e:
        return jsonify({"profiles": [], "count": 0, "error": str(e)})


@app.route("/api/iot/scan", methods=["POST"])
def api_iot_scan():
    if _iot_scan_status["running"]:
        return jsonify({"status": "already_running"})
    data    = request.get_json(silent=True) or {}
    timeout = data.get("timeout", 1.5)
    workers = data.get("workers", 20)
    iface   = data.get("iface") or None

    def _do_iot():
        _iot_scan_status["running"] = True
        try:
            from core.iot_profiler import IoTProfiler
            from core.network_scanner import full_scan
            from core.config import NETWORK_TARGET
            devices  = full_scan(NETWORK_TARGET)
            profiler = IoTProfiler(port_timeout=timeout, max_port_workers=workers)
            profiles = profiler.profile_all(devices)
            _iot_scan_status["last_count"] = len(profiles)
            _iot_scan_status["iface"]      = iface
        except Exception:
            pass
        finally:
            _iot_scan_status["running"] = False

    threading.Thread(target=_do_iot, daemon=True).start()
    return jsonify({"status": "iot_scan_started"})


@app.route("/api/iot/status", methods=["GET"])
def api_iot_status():
    return jsonify(_iot_scan_status)


# ─────────────────────────────────────────────────────────────────────
#  API: DHCP SECURITY MONITORING
# ─────────────────────────────────────────────────────────────────────

@app.route("/api/dhcp/events", methods=["GET"])
def api_dhcp_events():
    try:
        from core.dhcp_monitor import get_events
        limit  = request.args.get("limit", 200, type=int)
        return jsonify({"events": get_events(limit), "count": len(get_events(limit))})
    except Exception as e:
        return jsonify({"events": [], "count": 0, "error": str(e)})


@app.route("/api/dhcp/leases", methods=["GET"])
def api_dhcp_leases():
    try:
        from core.dhcp_monitor import get_lease_table
        leases = get_lease_table()
        return jsonify({"leases": leases, "count": len(leases)})
    except Exception as e:
        return jsonify({"leases": {}, "count": 0, "error": str(e)})


@app.route("/api/dhcp/stats", methods=["GET"])
def api_dhcp_stats():
    try:
        from core.dhcp_monitor import get_stats, get_authorized_servers
        return jsonify({"stats": get_stats(),
                        "authorized_servers": get_authorized_servers()})
    except Exception as e:
        return jsonify({"stats": {}, "error": str(e)})


@app.route("/api/dhcp/start", methods=["POST"])
def api_dhcp_start():
    try:
        data  = request.get_json(silent=True) or {}
        iface = data.get("iface") or None
        mon   = _get_dhcp(iface=iface)
        if data.get("authorized_servers"):
            mon.set_authorized_servers(data["authorized_servers"])
        if not mon.is_running():
            mon.start()
        return jsonify({"status": "running", "iface": iface})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.route("/api/dhcp/stop", methods=["POST"])
def api_dhcp_stop():
    try:
        _get_dhcp().stop()
        return jsonify({"status": "stopped"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.route("/api/dhcp/status", methods=["GET"])
def api_dhcp_status():
    try:
        from core.dhcp_monitor import get_stats
        return jsonify({"running": _get_dhcp().is_running(), "stats": get_stats()})
    except Exception as e:
        return jsonify({"running": False, "error": str(e)})


# ─────────────────────────────────────────────────────────────────────
#  API: NETWORK TRAFFIC ANALYSIS (NetFlow/sFlow)
# ─────────────────────────────────────────────────────────────────────

@app.route("/api/traffic/flows", methods=["GET"])
def api_traffic_flows():
    try:
        ta    = _get_traffic()
        limit = request.args.get("limit", 200, type=int)
        src   = request.args.get("src", None)
        return jsonify({"flows": ta.get_flows(src_ip=src, limit=limit)})
    except Exception as e:
        return jsonify({"flows": [], "error": str(e)})


@app.route("/api/traffic/top-talkers", methods=["GET"])
def api_top_talkers():
    try:
        ta = _get_traffic()
        n  = request.args.get("n", 10, type=int)
        return jsonify({"top_talkers": ta.get_top_talkers(n)})
    except Exception as e:
        return jsonify({"top_talkers": [], "error": str(e)})


@app.route("/api/traffic/anomalies", methods=["GET"])
def api_traffic_anomalies():
    try:
        ta    = _get_traffic()
        limit = request.args.get("limit", 100, type=int)
        anom  = ta.get_anomalies(limit)
        return jsonify({"anomalies": anom, "count": len(anom)})
    except Exception as e:
        return jsonify({"anomalies": [], "error": str(e)})


@app.route("/api/traffic/bandwidth", methods=["GET"])
def api_traffic_bandwidth():
    try:
        return jsonify({"bandwidth": _get_traffic().get_bandwidth_summary()})
    except Exception as e:
        return jsonify({"bandwidth": [], "error": str(e)})


@app.route("/api/traffic/status", methods=["GET"])
def api_traffic_status():
    try:
        ta = _get_traffic()
        return jsonify({"running": ta.is_running(), "stats": ta.get_stats()})
    except Exception as e:
        return jsonify({"running": False, "error": str(e)})


@app.route("/api/traffic/start", methods=["POST"])
def api_traffic_start():
    try:
        data  = request.get_json(silent=True) or {}
        iface = data.get("iface") or None
        ta    = _get_traffic(iface=iface)
        if not ta.is_running():
            ta.start()
        return jsonify({"status": "running", "iface": iface})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.route("/api/traffic/stop", methods=["POST"])
def api_traffic_stop():
    try:
        _get_traffic().stop()
        return jsonify({"status": "stopped"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


# ─────────────────────────────────────────────────────────────────────
#  API: CONTINUOUS REAL-TIME MONITOR
# ─────────────────────────────────────────────────────────────────────

_rt_monitor     = None
_rt_monitor_lock = threading.Lock()

def _get_rt_monitor(iface=None):
    global _rt_monitor
    with _rt_monitor_lock:
        if _rt_monitor is None or (iface and getattr(_rt_monitor, 'iface', None) != iface):
            from core.realtime_monitor import RealTimeMonitor
            _rt_monitor = RealTimeMonitor(iface=iface)
    return _rt_monitor


@app.route("/api/monitor/devices", methods=["GET"])
def api_monitor_devices():
    """Live device table: IP, MAC, Vendor, Hostname, Risk, Events."""
    try:
        mon     = _get_rt_monitor()
        devices = mon.get_devices()
        return jsonify({"devices": devices, "count": len(devices)})
    except Exception as e:
        return jsonify({"devices": [], "count": 0, "error": str(e)})


@app.route("/api/monitor/ap-scan", methods=["GET"])
def api_monitor_ap_scan():
    """Latest Rogue AP scan results."""
    try:
        return jsonify(_get_rt_monitor().get_ap_results())
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/monitor/events", methods=["GET"])
def api_monitor_events():
    """Correlation engine event ring buffer."""
    try:
        n      = request.args.get("n", 50, type=int)
        events = _get_rt_monitor().get_correlation_events(n)
        return jsonify({"events": events, "count": len(events)})
    except Exception as e:
        return jsonify({"events": [], "error": str(e)})


@app.route("/api/monitor/stats", methods=["GET"])
def api_monitor_stats():
    """Uptime, scan count, device count, alert count."""
    try:
        mon   = _get_rt_monitor()
        stats = mon.get_stats()
        stats["device_count"]  = len(mon.get_devices())
        stats["is_running"]    = mon.is_running()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"is_running": False, "error": str(e)})


@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    try:
        data  = request.get_json(silent=True) or {}
        iface = data.get("iface") or None
        no_ap = data.get("no_ap", False)
        interval = data.get("interval", 30)
        mon   = _get_rt_monitor(iface=iface)
        mon.interval = interval
        mon.ap_scan  = not no_ap
        if not mon.is_running():
            mon.start()
        return jsonify({"status": "running", "iface": iface})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    try:
        _get_rt_monitor().stop()
        return jsonify({"status": "stopped"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.route("/api/system/reset", methods=["POST"])
def api_system_reset():
    """Wipe all data and restart the monitor."""
    try:
        # 1. Stop the monitor if running
        mon = _get_rt_monitor()
        if mon.is_running():
            mon.stop()
        
        # 2. Clear the database
        db.clear_all_data()
        
        # 3. Clear in-memory buffers in RealTimeMonitor
        mon.devices = {}
        mon.alerts = []
        mon.scan_history = []
        mon.packet_counts = {}
        
        return jsonify({"status": "success", "message": "System reset successfully. All data cleared."})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


# ─────────────────────────────────────────────────────────────────────
#  API: REAL-TIME ATTACK DETECTOR
# ─────────────────────────────────────────────────────────────────────

_attack_detector     = None
_attack_detector_lock = threading.Lock()

def _get_attack_detector(iface=None, gateway=None):
    global _attack_detector
    with _attack_detector_lock:
        if _attack_detector is None or (iface and getattr(_attack_detector, 'iface', None) != iface):
            from core.attack_detector import AttackDetector
            _attack_detector = AttackDetector(iface=iface, gateway_ip=gateway)
    return _attack_detector


@app.route("/api/attacks/events", methods=["GET"])
def api_attack_events():
    """Live attack events ring buffer (last N events)."""
    try:
        n      = request.args.get("n", 100, type=int)
        events = _get_attack_detector().get_events(n)
        return jsonify({"events": events, "count": len(events)})
    except Exception as e:
        return jsonify({"events": [], "error": str(e)})


@app.route("/api/attacks/summary", methods=["GET"])
def api_attack_summary():
    """Active attack counts by type + severity totals."""
    try:
        return jsonify(_get_attack_detector().get_summary())
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/attacks/timeline", methods=["GET"])
def api_attack_timeline():
    """Events grouped per minute for chart rendering."""
    try:
        return jsonify({"timeline": _get_attack_detector().get_timeline()})
    except Exception as e:
        return jsonify({"timeline": [], "error": str(e)})


@app.route("/api/attacks/threats", methods=["GET"])
def api_attack_threats():
    """Threat intelligence IOC matches."""
    try:
        matches = _get_attack_detector().get_ioc_matches()
        return jsonify({"threats": matches, "count": len(matches)})
    except Exception as e:
        return jsonify({"threats": [], "error": str(e)})


@app.route("/api/attacks/start", methods=["POST"])
def api_attacks_start():
    try:
        data    = request.get_json(silent=True) or {}
        iface   = data.get("iface") or None
        gateway = data.get("gateway") or None
        det     = _get_attack_detector(iface=iface, gateway=gateway)
        if not det.is_running():
            det.start()
        return jsonify({"status": "running", "iface": iface})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.route("/api/attacks/stop", methods=["POST"])
def api_attacks_stop():
    try:
        _get_attack_detector().stop()
        return jsonify({"status": "stopped"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.route("/api/attacks/status", methods=["GET"])
def api_attacks_status():
    try:
        det   = _get_attack_detector()
        stats = det.get_stats()
        stats["is_running"] = det.is_running()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"is_running": False, "error": str(e)})


# ─────────────────────────────────────────────
#  API: WI-FI SECURITY (AI ROGUE AP DETECTOR)
# ─────────────────────────────────────────────

@app.route("/api/wifi/scan", methods=["POST"])
def api_wifi_scan():
    try:
        from core.rogue_ap_detector import run_ap_detection
        res = run_ap_detection()
        return jsonify(res)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/wifi/allowlist", methods=["GET"])
def api_get_wifi_allowlist():
    try:
        from core.device_manager import load_wifi_allowlist
        wl = list(load_wifi_allowlist())
        return jsonify({"allowlist": wl})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/wifi/allowlist", methods=["POST"])
def api_add_wifi_allowlist():
    try:
        data = request.get_json()
        ssid = data.get("ssid", "").strip()
        if not ssid:
            return jsonify({"error": "ssid required"}), 400
        from core.device_manager import add_to_wifi_allowlist
        add_to_wifi_allowlist(ssid)
        return jsonify({"status": "added", "ssid": ssid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/wifi/allowlist/<ssid>", methods=["DELETE"])
def api_remove_wifi_allowlist(ssid):
    try:
        from core.device_manager import remove_from_wifi_allowlist, load_wifi_allowlist
        wl = load_wifi_allowlist()
        if ssid not in wl:
             return jsonify({"error": "SSID not found"}), 404
        remove_from_wifi_allowlist(ssid)
        return jsonify({"status": "removed", "ssid": ssid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
#  API: REPORTS
# ─────────────────────────────────────────────

@app.route("/api/report/generate", methods=["GET"])
def api_report_generate():
    try:
        from core.report_generator import (generate_docx_report, generate_txt_report, 
                                           generate_csv_report, generate_json_report, generate_html_report)
        
        fmt = request.args.get("format", "docx").lower()
        
        if fmt == "txt":
            filepath = generate_txt_report()
            mimetype = "text/plain"
        elif fmt == "csv":
            filepath = generate_csv_report()
            mimetype = "text/csv"
        elif fmt == "json":
            filepath = generate_json_report()
            mimetype = "application/json"
        elif fmt == "html":
            filepath = generate_html_report()
            mimetype = "text/html"
        else: # default to docx
            filepath = generate_docx_report()
            mimetype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            
        return send_file(
            filepath,
            as_attachment=True,
            download_name=os.path.basename(filepath),
            mimetype=mimetype
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to generate report: {str(e)}"}), 500


# ─────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────

def run_dashboard():
    print(f"[RDDS] Dashboard starting at http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT,
            debug=DASHBOARD_DEBUG, use_reloader=False)


if __name__ == "__main__":
    run_dashboard()

