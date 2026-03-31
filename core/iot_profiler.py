"""
RDDS — IoT Device Profiling & Risk Assessment Module
Fingerprints IoT devices by MAC OUI, open ports, and protocol banners,
then produces a risk score with CVE-style indicators for real network use.
"""

import socket
import threading
import time
import struct
import re
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from core.config import SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW
from core.alert_engine import fire_alert, print_info, print_warn
from core import database as db

# ─────────────────────────────────────────────
#  OUI → IoT Device Type Mapping
#  Covers 80+ major IoT/embedded vendors
# ─────────────────────────────────────────────

IOT_VENDOR_PROFILES: Dict[str, Dict] = {
    # IP Cameras / DVRs
    "001A07": {"type": "IP Camera",       "category": "surveillance",  "risk_base": 55},
    "00408C": {"type": "IP Camera",       "category": "surveillance",  "risk_base": 55},
    "D4C9EF": {"type": "IP Camera (HIK)", "category": "surveillance",  "risk_base": 65},
    "C45813": {"type": "IP Camera (HIK)", "category": "surveillance",  "risk_base": 65},
    "001E4A": {"type": "DVR/NVR",         "category": "surveillance",  "risk_base": 60},
    "B46780": {"type": "IP Camera (Dahua)", "category": "surveillance","risk_base": 65},
    "4C1141": {"type": "IP Camera (Dahua)", "category": "surveillance","risk_base": 65},
    # Smart Home / IoT Hubs
    "ACCFA8": {"type": "Smart Hub",       "category": "smart_home",    "risk_base": 40},
    "18B4D7": {"type": "IoT Sensor",      "category": "smart_home",    "risk_base": 35},
    "68A40E": {"type": "Smart Plug",      "category": "smart_home",    "risk_base": 40},
    "D073D5": {"type": "Smart Bulb",      "category": "smart_home",    "risk_base": 30},
    "B8F009": {"type": "Smart TV",        "category": "entertainment", "risk_base": 30},
    # Routers / APs
    "000C29": {"type": "Network Device",  "category": "infrastructure","risk_base": 20},
    "B827EB": {"type": "Raspberry Pi",    "category": "embedded",      "risk_base": 45},
    "DCA632": {"type": "Raspberry Pi",    "category": "embedded",      "risk_base": 45},
    "E45F01": {"type": "Raspberry Pi",    "category": "embedded",      "risk_base": 45},
    "2462AB": {"type": "GL.iNet Router",  "category": "infrastructure","risk_base": 30},
    "C09F05": {"type": "Xiaomi Device",   "category": "smart_home",    "risk_base": 35},
    "6C40F5": {"type": "Xiaomi Device",   "category": "smart_home",    "risk_base": 35},
    # Industrial / PLC / SCADA
    "00E000": {"type": "Siemens PLC",     "category": "industrial",    "risk_base": 80},
    "0006C1": {"type": "Schneider IED",   "category": "industrial",    "risk_base": 80},
    "00A046": {"type": "ABB PLC",         "category": "industrial",    "risk_base": 80},
    "0020F4": {"type": "Allen-Bradley",   "category": "industrial",    "risk_base": 80},
    # Medical
    "001C73": {"type": "Medical Device",  "category": "medical",       "risk_base": 75},
    "0003BA": {"type": "Medical Device",  "category": "medical",       "risk_base": 75},
    # Printers
    "001871": {"type": "Printer (HP)",    "category": "printer",       "risk_base": 35},
    "000AE4": {"type": "Printer (HP)",    "category": "printer",       "risk_base": 35},
    "AC5110": {"type": "Printer (Canon)", "category": "printer",       "risk_base": 35},
    "84B153": {"type": "Printer (Brother)", "category": "printer",     "risk_base": 35},
    # ESP / Arduino based sensors
    "AABBCC": {"type": "ESP32 Device",    "category": "embedded",      "risk_base": 45},
    "5CCF7F": {"type": "ESP8266 Device",  "category": "embedded",      "risk_base": 45},
    "50024E": {"type": "ESP32 Device",    "category": "embedded",      "risk_base": 45},
    "24A160": {"type": "ESP32 Device",    "category": "embedded",      "risk_base": 45},
    "E89106": {"type": "ESP32 Device",    "category": "embedded",      "risk_base": 45},
}

# Port → service mapping with risk weights
IOT_PORT_PROFILES: Dict[int, Dict] = {
    23:    {"service": "Telnet",         "risk": 40, "note": "Cleartext remote shell — critical IoT vulnerability"},
    2323:  {"service": "Telnet-Alt",     "risk": 40, "note": "Alternative Telnet port used by Mirai botnet"},
    80:    {"service": "HTTP",           "risk": 10, "note": "Unencrypted web interface"},
    443:   {"service": "HTTPS",         "risk": 5,  "note": "Encrypted web interface"},
    8080:  {"service": "HTTP-Alt",       "risk": 15, "note": "Admin panel on alternate port"},
    8443:  {"service": "HTTPS-Alt",      "risk": 8,  "note": "Alternate HTTPS"},
    1883:  {"service": "MQTT",          "risk": 35, "note": "Unencrypted MQTT broker — no auth by default"},
    8883:  {"service": "MQTT-TLS",       "risk": 10, "note": "Encrypted MQTT"},
    554:   {"service": "RTSP",          "risk": 45, "note": "Open camera stream — often unauthenticated"},
    5554:  {"service": "RTSP-Alt",       "risk": 45, "note": "Alt RTSP stream port"},
    161:   {"service": "SNMP",          "risk": 30, "note": "Default community strings expose full device config"},
    162:   {"service": "SNMP-Trap",      "risk": 20, "note": "SNMP trap receiver"},
    5353:  {"service": "mDNS",          "risk": 10, "note": "Multicast discovery — may leak device info"},
    47808: {"service": "BACnet",        "risk": 50, "note": "Building automation — unauthenticated by default"},
    4840:  {"service": "OPC-UA",        "risk": 45, "note": "Industrial OPC-UA endpoint"},
    102:   {"service": "S7comm",        "risk": 70, "note": "Siemens S7 — direct PLC control (Stuxnet vector)"},
    44818: {"service": "EtherNet/IP",   "risk": 60, "note": "Industrial Ethernet/IP — unauthenticated by default"},
    9600:  {"service": "Modbus-Alt",    "risk": 55, "note": "Modbus RTU/TCP — no authentication"},
    502:   {"service": "Modbus",        "risk": 55, "note": "Modbus TCP — no authentication"},
    2404:  {"service": "IEC-60870",     "risk": 65, "note": "IEC SCADA protocol"},
    20000: {"service": "DNP3",         "risk": 65, "note": "SCADA DNP3 — no auth"},
    37777: {"service": "DVR-Dahua",     "risk": 50, "note": "Dahua DVR proprietary port"},
    37778: {"service": "DVR-Dahua-2",   "risk": 50, "note": "Dahua DVR streaming"},
    34567: {"service": "DVR-Generic",   "risk": 50, "note": "Generic DVR management port"},
    8554:  {"service": "RTSP-Alt2",     "risk": 40, "note": "Alternate RTSP"},
    5000:  {"service": "UPnP-Alt",      "risk": 20, "note": "UPnP or generic service"},
    49152: {"service": "UPnP",         "risk": 25, "note": "UPnP control point — often exploitable"},
}

# ─────────────────────────────────────────────
#  IN-MEMORY STATE
# ─────────────────────────────────────────────

_profiles: Dict[str, Dict] = {}   # mac → profile dict
_port_history: Dict[str, set] = defaultdict(set)   # mac → set of known open ports
_lock = threading.Lock()

# ─────────────────────────────────────────────
#  OUI LOOKUP — IoT Classification
# ─────────────────────────────────────────────

def _oui_from_mac(mac: str) -> str:
    """Return 6-char uppercase OUI prefix from MAC."""
    return mac.upper().replace(":", "").replace("-", "")[:6]


def classify_by_oui(mac: str, vendor: str = "") -> Dict:
    """
    Return device type, category, and base risk from OUI.
    Falls back to vendor string heuristics if OUI not in database.
    """
    oui = _oui_from_mac(mac)
    if oui in IOT_VENDOR_PROFILES:
        return IOT_VENDOR_PROFILES[oui].copy()

    # Heuristic fallback from vendor string
    vendor_lower = vendor.lower()
    if any(k in vendor_lower for k in ("hikvision", "dahua", "axis", "vivotek", "amcrest")):
        return {"type": "IP Camera", "category": "surveillance", "risk_base": 60}
    if any(k in vendor_lower for k in ("siemens", "schneider", "allen-bradley", "rockwell", "abb")):
        return {"type": "Industrial PLC", "category": "industrial", "risk_base": 80}
    if any(k in vendor_lower for k in ("espressif", "esp32", "esp8266", "nodemcu")):
        return {"type": "ESP IoT Device", "category": "embedded", "risk_base": 45}
    if any(k in vendor_lower for k in ("raspberry", "raspberrypi")):
        return {"type": "Raspberry Pi", "category": "embedded", "risk_base": 45}
    if any(k in vendor_lower for k in ("shelly", "sonoff", "tuya", "tasmota")):
        return {"type": "Smart Switch/Plug", "category": "smart_home", "risk_base": 35}
    if any(k in vendor_lower for k in ("philips", "lifx", "ikea")):
        return {"type": "Smart Lighting", "category": "smart_home", "risk_base": 25}
    if any(k in vendor_lower for k in ("nest", "ring", "arlo", "blink")):
        return {"type": "Smart Home Device", "category": "smart_home", "risk_base": 40}
    if any(k in vendor_lower for k in ("hp", "hewlett", "canon", "epson", "brother", "xerox")):
        return {"type": "Printer", "category": "printer", "risk_base": 30}
    if any(k in vendor_lower for k in ("samsung", "lg", "sony", "hisense", "tcl")):
        return {"type": "Smart TV", "category": "entertainment", "risk_base": 30}

    # Unknown device — treat as potential IoT
    return {"type": "Unknown IoT Device", "category": "unknown", "risk_base": 30}

# ─────────────────────────────────────────────
#  PORT SCANNER — Fast TCP Connect Scan
# ─────────────────────────────────────────────

def _tcp_connect(ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """
    Try TCP connect on a port. Returns banner string if any, else None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            # Try to grab banner (200ms)
            sock.settimeout(0.2)
            try:
                banner = sock.recv(512).decode(errors="ignore").strip()
            except Exception:
                banner = ""
            sock.close()
            return banner if banner else ""
        sock.close()
        return None
    except Exception:
        return None


def scan_iot_ports(ip: str, port_list: Optional[List[int]] = None,
                   max_workers: int = 30) -> Dict[int, Dict]:
    """
    Scan IoT-relevant ports on an IP using concurrent threads.
    Returns {port: {service, risk, note, banner, open: True}}.
    """
    ports_to_scan = port_list or list(IOT_PORT_PROFILES.keys())
    results: Dict[int, Dict] = {}
    res_lock = threading.Lock()

    def _probe(port: int):
        banner = _tcp_connect(ip, port)
        if banner is not None:
            info = IOT_PORT_PROFILES.get(port, {
                "service": f"port-{port}", "risk": 10, "note": "Unknown service"
            }).copy()
            info["open"] = True
            info["banner"] = banner[:200]
            with res_lock:
                results[port] = info

    threads = []
    sem = threading.Semaphore(max_workers)

    def _worker(port):
        with sem:
            _probe(port)

    for p in ports_to_scan:
        t = threading.Thread(target=_worker, args=(p,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=5)

    return results

# ─────────────────────────────────────────────
#  BANNER VULNERABILITY DETECTION
# ─────────────────────────────────────────────

def _analyze_banners(open_ports: Dict[int, Dict]) -> Tuple[int, List[str]]:
    """
    Parse banners for firmware versions, default credentials hints, etc.
    Returns (extra_risk_points, cve_indicators list).
    """
    extra_risk = 0
    cve_indicators = []

    for port, info in open_ports.items():
        banner = info.get("banner", "").lower()
        service = info.get("service", "")

        # Telnet with common IoT strings
        if port in (23, 2323) and banner:
            cve_indicators.append("CVE-TELNET-OPEN: Telnet accessible (Mirai botnet vector)")
            extra_risk += 20
            if any(x in banner for x in ("busybox", "linux", "openwrt", "ddwrt")):
                cve_indicators.append("CVE-IOT-BUSYBOX: Embedded Linux shell exposed via Telnet")
                extra_risk += 10

        # RTSP unauthenticated
        if port in (554, 5554, 8554):
            if banner:
                cve_indicators.append("CVE-RTSP-OPEN: RTSP stream possibly unauthenticated")
                extra_risk += 15
            if re.search(r"hikvision|dahua|axis|amcrest", banner):
                cve_indicators.append("CVE-CAM-VENDOR: Known camera vendor with historical CVEs")
                extra_risk += 10

        # MQTT open
        if port == 1883:
            cve_indicators.append("CVE-MQTT-UNAUTH: MQTT broker open without TLS/auth")
            extra_risk += 15

        # SNMP
        if port == 161:
            cve_indicators.append("CVE-SNMP-EXPOSED: SNMP exposed (community string brute-forceable)")
            extra_risk += 10

        # Modbus / BACnet / S7
        if port in (502, 9600, 47808, 102, 44818, 4840, 20000, 2404):
            cve_indicators.append(f"CVE-ICS-EXPOSED: Industrial protocol {service} accessible from network")
            extra_risk += 25

        # HTTP/Admin panels — check for plain HTTP on industrial devices
        if port in (80, 8080) and banner:
            if any(x in banner for x in ("basic realm", "admin", "login", "siemens", "schneider")):
                cve_indicators.append("CVE-HTTP-ADMIN: Unencrypted admin panel detected")
                extra_risk += 10

    return min(extra_risk, 50), cve_indicators

# ─────────────────────────────────────────────
#  NEW PORT DETECTION & BEHAVIORAL CHANGE
# ─────────────────────────────────────────────

_heartbeat_history: Dict[str, List[float]] = defaultdict(list)

def _check_behavioral_periodicity(mac: str) -> List[str]:
    """
    IoT devices typically communicate in strict physical heartbeats.
    Track the timing of network accesses. If spacing jitter is extreme,
    flag as anomaly since standard IoT devices are strictly periodic.
    """
    now = time.time()
    with _lock:
        history = _heartbeat_history[mac]
        history.append(now)
        if len(history) > 10:
            history.pop(0)
            
        if len(history) >= 4:
            intervals = [history[i] - history[i-1] for i in range(1, len(history))]
            avg_interval = sum(intervals) / len(intervals)
            max_dev = max(abs(i - avg_interval) for i in intervals)
            
            # If communication heartbeat is highly erratic
            if avg_interval > 5.0 and (max_dev / avg_interval) > 0.6:
                return ["PERIODICITY_ANOMALY: High variance in IoT heartbeat"]
    return []

def _check_new_ports(mac: str, current_ports: set) -> List[str]:
    """Detect newly opened ports vs baseline — indicates possible compromise."""
    with _lock:
        previous = _port_history.get(mac, set())
        new_ports = current_ports - previous
        _port_history[mac] = current_ports.copy()

    flags = []
    if new_ports and previous:  # Only alert if we had a previous baseline
        for port in new_ports:
            flags.append(f"NEW_PORT_OPENED:{port}")
    return flags

# ─────────────────────────────────────────────
#  RISK SCORING ENGINE
# ─────────────────────────────────────────────

def compute_iot_risk(device_type: Dict, open_ports: Dict[int, Dict],
                     extra_risk: int, flags: List[str]) -> Tuple[int, str]:
    """
    Compute final IoT risk score (0–100) and severity.
    """
    score = device_type.get("risk_base", 30)

    # Port risk accumulation (capped)
    port_risk = sum(p.get("risk", 0) for p in open_ports.values())
    score += min(port_risk, 40)

    # Banner-based extra points
    score += extra_risk

    # New port & Behavioral flags
    if any("NEW_PORT" in f for f in flags):
        score += 15
    if any("PERIODICITY" in f for f in flags):
        score += 25

    score = min(score, 100)

    if score >= 80:
        severity = SEV_CRITICAL
    elif score >= 60:
        severity = SEV_HIGH
    elif score >= 40:
        severity = SEV_MEDIUM
    else:
        severity = SEV_LOW

    return score, severity

# ─────────────────────────────────────────────
#  MAIN PROFILER CLASS
# ─────────────────────────────────────────────

class IoTProfiler:
    """
    Main IoT profiling engine. Call profile_device() per device.
    """

    def __init__(self, port_timeout: float = 1.5, max_port_workers: int = 25):
        self.port_timeout = port_timeout
        self.max_workers  = max_port_workers

    def profile_device(self, ip: str, mac: str, vendor: str = "") -> Dict:
        """
        Full IoT profile for one device.
        Returns a rich profile dict.
        """
        ts = datetime.now().isoformat()
        print_info(f"IoT profiling: {ip} ({mac}) ...")

        # Step 1: OUI classification
        device_type_info = classify_by_oui(mac, vendor)

        # Step 2: Port scan
        open_ports = scan_iot_ports(ip, max_workers=self.max_workers)

        # Step 3: Banner analysis
        extra_risk, cve_indicators = _analyze_banners(open_ports)

        # Step 4: New port & Periodicity detection
        current_port_set = set(open_ports.keys())
        new_port_flags   = _check_new_ports(mac, current_port_set)
        periodicity_flags = _check_behavioral_periodicity(mac)
        all_flags = new_port_flags + periodicity_flags

        # Step 5: Risk scoring
        iot_score, severity = compute_iot_risk(
            device_type_info, open_ports, extra_risk, all_flags
        )

        # Step 6: Build profile
        profile = {
            "ip":            ip,
            "mac":           mac,
            "vendor":        vendor,
            "device_type":   device_type_info["type"],
            "category":      device_type_info["category"],
            "iot_risk_score": iot_score,
            "severity":      severity,
            "open_iot_ports": {
                str(port): {
                    "service": info["service"],
                    "risk":    info["risk"],
                    "note":    info["note"],
                    "banner":  info.get("banner", "")
                }
                for port, info in open_ports.items()
            },
            "cve_indicators":       cve_indicators,
            "behavioral_flags":     all_flags,
            "fingerprint_confidence": self._confidence(device_type_info, open_ports),
            "profiled_at":          ts,
        }

        # Store in-memory
        with _lock:
            _profiles[mac] = profile

        # Persist to DB
        try:
            db_profile = {
                "device_type":   profile["device_type"],
                "category":      profile["category"],
                "iot_risk_score": iot_score,
                "severity":      severity,
                "open_iot_ports": ",".join(
                    f"{p}({v['service']})" for p, v in open_ports.items()
                ),
                "cve_count":     len(cve_indicators),
                "profiled_at":   ts,
            }
            db.upsert_iot_profile(mac, ip, db_profile)
        except Exception:
            pass  # DB may not have the table yet — handled gracefully

        # Alert if high risk
        if iot_score >= 60:
            fire_alert(
                alert_type="IOT_HIGH_RISK_DEVICE",
                severity=severity,
                description=(
                    f"IoT device {profile['device_type']} at {ip} ({mac}) "
                    f"has risk score {iot_score}/100. "
                    f"Open dangerous ports: {list(open_ports.keys())}. "
                    f"CVE indicators: {len(cve_indicators)}"
                ),
                device_mac=mac,
                device_ip=ip,
                raw_data={"iot_score": iot_score, "cve_count": len(cve_indicators),
                          "open_ports": list(open_ports.keys())}
            )
        elif new_port_flags:
            fire_alert(
                alert_type="IOT_NEW_PORT_DETECTED",
                severity=SEV_MEDIUM,
                description=(
                    f"IoT device {ip} ({mac}) has newly opened ports: "
                    f"{[f.split(':')[1] for f in new_port_flags if ':' in f]}. "
                    f"This may indicate compromise or reconfiguration."
                ),
                device_mac=mac,
                device_ip=ip,
                raw_data={"new_ports": new_port_flags}
            )
        elif periodicity_flags:
            fire_alert(
                alert_type="IOT_BEHAVIORAL_ANOMALY",
                severity=SEV_HIGH,
                description=(
                    f"IoT device {ip} ({mac}) exhibiting unusual erratic "
                    f"traffic periodicity. Normal device heartbeat interrupted."
                ),
                device_mac=mac,
                device_ip=ip,
                raw_data={"periodicity": periodicity_flags}
            )

        return profile

    def _confidence(self, device_type: Dict, open_ports: Dict) -> str:
        """Return fingerprint confidence as HIGH/MEDIUM/LOW."""
        oui_known = device_type.get("type") != "Unknown IoT Device"
        has_ports  = len(open_ports) > 0
        if oui_known and has_ports:
            return "HIGH"
        elif oui_known or has_ports:
            return "MEDIUM"
        return "LOW"

    def profile_all(self, devices: List[Dict]) -> List[Dict]:
        """
        Profile a list of device dicts ({ip, mac, vendor}).
        Runs concurrently with a thread per device (capped at 10).
        """
        profiles = []
        results_lock = threading.Lock()
        sem = threading.Semaphore(10)

        def _do(d):
            with sem:
                try:
                    p = self.profile_device(
                        ip=d.get("ip", ""),
                        mac=d.get("mac", ""),
                        vendor=d.get("vendor", "")
                    )
                    with results_lock:
                        profiles.append(p)
                except Exception as e:
                    from core.alert_engine import print_warn
                    print_warn(f"IoT profile error for {d.get('ip')}: {e}")

        threads = [threading.Thread(target=_do, args=(d,), daemon=True) for d in devices]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)  # 60s max per batch

        return profiles


def get_all_profiles() -> List[Dict]:
    """Return all in-memory IoT profiles."""
    with _lock:
        return list(_profiles.values())


def get_profile(mac: str) -> Optional[Dict]:
    with _lock:
        return _profiles.get(mac)
