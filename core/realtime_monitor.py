"""
RDDS — Continuous Real-Time Network Monitor
============================================
Provides perpetual, multi-layered network surveillance:

  • Continuous ARP-based device discovery loop
  • Rogue Access Point detection & Evil-Twin alerting
  • Pattern Recognition Engine  (Z-score, rolling baseline)
  • Correlation Engine          (multi-source event linking)
  • Automated Response          (alert dedup, severity escalation)

Every discovered device is enriched with: IP, MAC, Vendor,
Hostname, status, risk level, and the events that triggered alerts.
"""

import time
import math
import socket
import threading
import statistics
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Deque, Tuple

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core.config import (
    NETWORK_TARGET, SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO
)
from core.alert_engine import fire_alert, print_info, print_warn
from core.network_scanner import get_vendor, resolve_hostname
from core import database as db

# ──────────────────────────────────────────────────────────────
#  CONSTANTS & TUNING
# ──────────────────────────────────────────────────────────────

SCAN_INTERVAL_DEFAULT   = 30   # seconds between ARP sweeps
AP_SCAN_INTERVAL        = 60   # seconds between Wi-Fi AP scans
PATTERN_WINDOW          = 300  # 5-minute rolling window (seconds)
CORRELATION_WINDOW      = 30   # seconds for event correlation
ZSCORE_THRESHOLD        = 3.0  # Z-score cutoff for anomaly
BURST_PPS_THRESHOLD     = 200  # packets/s burst trigger
MAX_EVENTS_RING         = 500  # max correlation events kept

ALERT_NEW_DEVICE        = "NEW_DEVICE_DETECTED"
ALERT_DEVICE_GONE       = "DEVICE_DISAPPEARED"
ALERT_ARP_CHANGE        = "ARP_TABLE_CHANGE"
ALERT_PATTERN_ANOMALY   = "PATTERN_ANOMALY"
ALERT_CORRELATED        = "CORRELATED_SECURITY_EVENT"
ALERT_ROGUE_AP_LIVE     = "ROGUE_AP_LIVE"

# ──────────────────────────────────────────────────────────────
#  DATA STRUCTURES
# ──────────────────────────────────────────────────────────────

class DeviceRecord:
    """Rich device record with enriched fields."""
    __slots__ = (
        "ip", "mac", "vendor", "hostname",
        "first_seen", "last_seen", "packet_times",
        "protocol_stats", "risk_score", "risk_level",
        "events", "is_whitelisted", "status"
    )

    def __init__(self, ip: str, mac: str):
        self.ip             = ip
        self.mac            = mac.lower()
        self.vendor         = get_vendor(mac) or "Unknown"
        self.hostname       = ""           # resolved lazily
        self.first_seen     = time.time()
        self.last_seen      = time.time()
        self.packet_times: List[float] = []
        self.protocol_stats: Dict[str, int] = defaultdict(int)
        self.risk_score     = 0
        self.risk_level     = "LOW"
        self.events: List[dict] = []
        self.is_whitelisted = False
        self.status         = "active"     # active | gone

    def touch(self):
        self.last_seen = time.time()
        self.status    = "active"

    def to_dict(self) -> dict:
        return {
            "ip":           self.ip,
            "mac":          self.mac,
            "vendor":       self.vendor,
            "hostname":     self.hostname or "",
            "first_seen":   datetime.fromtimestamp(self.first_seen).strftime("%H:%M:%S"),
            "last_seen":    datetime.fromtimestamp(self.last_seen).strftime("%H:%M:%S"),
            "status":       self.status,
            "risk_score":   self.risk_score,
            "risk_level":   self.risk_level,
            "events_count": len(self.events),
            "recent_events": self.events[-5:],
            "is_whitelisted": self.is_whitelisted,
        }


# ──────────────────────────────────────────────────────────────
#  PATTERN RECOGNITION ENGINE
# ──────────────────────────────────────────────────────────────

class PatternEngine:
    """
    Rolling-window pattern recognition per device MAC.
    Maintains a baseline of normal behavior and flags Z-score anomalies.
    """

    def __init__(self):
        # mac → deque of (timestamp, pkt_size) within PATTERN_WINDOW
        self._traffic: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=10000)
        )
        # mac → rolling pps history list (one sample per second)
        self._pps_history: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_packet(self, mac: str, pkt_size: int = 64):
        now = time.time()
        with self._lock:
            self._traffic[mac].append((now, pkt_size))
            # Prune old entries
            cutoff = now - PATTERN_WINDOW
            while self._traffic[mac] and self._traffic[mac][0][0] < cutoff:
                self._traffic[mac].popleft()

    def _current_pps(self, mac: str, window: float = 5.0) -> float:
        now = time.time()
        cutoff = now - window
        with self._lock:
            count = sum(1 for t, _ in self._traffic[mac] if t >= cutoff)
        return count / window

    def sample_and_detect(self, mac: str) -> Optional[dict]:
        """
        Sample current PPS, update rolling history, run Z-score.
        Returns anomaly dict if detected, else None.
        """
        pps = self._current_pps(mac)
        hist = self._pps_history[mac]
        hist.append(pps)

        # Need ≥10 samples for meaningful baseline
        if len(hist) < 10:
            return None

        mean = statistics.mean(hist[-60:])  # last-60 samples baseline
        stdev = statistics.pstdev(hist[-60:]) or 0.1

        z = (pps - mean) / stdev
        
        # Compute packet size variance for identical payload floods
        now = time.time()
        cutoff = now - 5.0
        with self._lock:
            recent_sizes = [s for t, s in self._traffic[mac] if t >= cutoff]
        
        size_var = statistics.pvariance(recent_sizes) if len(recent_sizes) >= 10 else 1000

        # High Z-score or extreme identically-sized bursts (variance ~0 and pps > 50)
        is_burst = z > ZSCORE_THRESHOLD
        is_flood = size_var < 5.0 and pps > 50

        if is_burst or is_flood:
            return {
                "type":    "TRAFFIC_BURST" if is_burst else "AUTOMATED_FLOOD",
                "mac":     mac,
                "z_score": round(z, 2),
                "pps":     round(pps, 1),
                "mean_pps": round(mean, 1),
                "size_variance": round(size_var, 2),
                "severity": SEV_CRITICAL if is_flood else (SEV_HIGH if z > 5 else SEV_MEDIUM)
            }

        return None

    def get_bytes_in_window(self, mac: str) -> int:
        with self._lock:
            return sum(s for _, s in self._traffic[mac])


# ──────────────────────────────────────────────────────────────
#  CORRELATION ENGINE
# ──────────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Links security events from multiple detectors within a time window.
    If ≥2 different event sources fire on the same IP/MAC within
    CORRELATION_WINDOW seconds, escalate to a correlated alert.
    """

    def __init__(self):
        # ring buffer of all events: {ts, source, ip, mac, type, severity}
        self._events: Deque[dict] = deque(maxlen=MAX_EVENTS_RING)
        self._lock = threading.Lock()
        # Track fired correlated alerts (dedup key → last fired ts)
        self._correlated_fired: Dict[str, float] = {}
        CORR_DEDUP_TTL = 60   # suppress same correlation for 60s
        self._dedup_ttl = CORR_DEDUP_TTL

    def push_event(self, source: str, ip: str, mac: str,
                   event_type: str, severity: str, description: str):
        ev = {
            "ts":          time.time(),
            "timestamp":   datetime.now().strftime("%H:%M:%S"),
            "source":      source,
            "ip":          ip,
            "mac":         mac,
            "type":        event_type,
            "severity":    severity,
            "description": description
        }
        with self._lock:
            self._events.append(ev)
        self._correlate(ip, mac)

    def _correlate(self, ip: str, mac: str):
        """Check if multiple sources fired on same target recently."""
        now = time.time()
        cutoff = now - CORRELATION_WINDOW
        with self._lock:
            recent = [
                e for e in self._events
                if e["ts"] >= cutoff and (e["ip"] == ip or e["mac"] == mac)
            ]
        if len(recent) < 2:
            return
        sources = {e["source"] for e in recent}
        if len(sources) < 2:
            return

        dedup_key = f"{ip}:{mac}"
        last_fired = self._correlated_fired.get(dedup_key, 0)
        if now - last_fired < self._dedup_ttl:
            return

        self._correlated_fired[dedup_key] = now
        desc = (
            f"CORRELATED THREAT on {ip} [{mac}]: "
            f"{len(recent)} events from {len(sources)} detectors "
            f"in {CORRELATION_WINDOW}s window — "
            f"Sources: {', '.join(sources)}"
        )
        fire_alert(
            alert_type=ALERT_CORRELATED,
            severity=SEV_CRITICAL,
            description=desc,
            device_mac=mac,
            device_ip=ip,
            raw_data={"events": recent[-10:], "sources": list(sources)}
        )

    def get_recent_events(self, n: int = 50) -> List[dict]:
        with self._lock:
            return list(self._events)[-n:]

    def get_stats(self) -> dict:
        with self._lock:
            evs = list(self._events)
        total     = len(evs)
        critical  = sum(1 for e in evs if e["severity"] == SEV_CRITICAL)
        high      = sum(1 for e in evs if e["severity"] == SEV_HIGH)
        sources   = {e["source"] for e in evs}
        return {
            "total_events":    total,
            "critical":        critical,
            "high":            high,
            "sources_active":  list(sources),
            "window_seconds":  CORRELATION_WINDOW,
        }


# ──────────────────────────────────────────────────────────────
#  ARP TABLE — tracks known MAC↔IP mappings
# ──────────────────────────────────────────────────────────────

class ARPTable:
    """In-memory ARP table with change detection."""

    def __init__(self):
        self._table: Dict[str, str] = {}   # ip → mac
        self._lock = threading.Lock()

    def update(self, ip: str, mac: str) -> Optional[str]:
        """
        Update entry. Returns old MAC if it changed (ARP change event),
        None if this is a new or unchanged entry.
        """
        mac = mac.lower()
        with self._lock:
            old = self._table.get(ip)
            self._table[ip] = mac
            if old and old != mac:
                return old
            return None

    def get(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._table.get(ip)

    def snapshot(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._table)


# ──────────────────────────────────────────────────────────────
#  REAL-TIME MONITOR — MAIN CLASS
# ──────────────────────────────────────────────────────────────

class RealTimeMonitor:
    """
    Orchestrates all continuous real-time monitoring components.

    Threads:
      • _scan_thread    — ARP sweep loop
      • _ap_thread      — Rogue AP scan loop
      • _pattern_thread — Pattern recognition sampler
    """

    def __init__(self,
                 iface:    Optional[str] = None,
                 network:  str           = NETWORK_TARGET,
                 interval: int           = SCAN_INTERVAL_DEFAULT,
                 ap_scan:  bool          = True,
                 whitelist: Optional[List[str]] = None):
        self.iface     = iface
        self.network   = network
        self.interval  = interval
        self.ap_scan   = ap_scan
        self.whitelist = set(w.lower() for w in (whitelist or []))

        # Sub-engines
        self.pattern_engine    = PatternEngine()
        self.correlation_engine = CorrelationEngine()
        self.arp_table         = ARPTable()

        # Device registry: mac → DeviceRecord
        self._devices: Dict[str, DeviceRecord] = {}
        self._devices_lock = threading.Lock()

        # AP scan results
        self._ap_results: dict = {}
        self._ap_lock    = threading.Lock()

        # Runtime state
        self._running    = False
        self._scan_thread:    Optional[threading.Thread] = None
        self._ap_thread:      Optional[threading.Thread] = None
        self._pattern_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Stats
        self._stats = {
            "scan_count":    0,
            "start_time":    None,
            "alerts_fired":  0,
            "last_scan_ts":  None,
            "new_devices":   0,
            "gone_devices":  0,
            "arp_changes":   0,
        }

    # ── PUBLIC API ─────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._stats["start_time"] = time.time()
        print_info(
            f"[RTMonitor] Starting — iface={self.iface or 'auto'}, "
            f"network={self.network}, interval={self.interval}s, "
            f"ap_scan={self.ap_scan}"
        )
        self._scan_thread = threading.Thread(
            target=self._scan_loop, daemon=True, name="RTM-ARPScan"
        )
        self._pattern_thread = threading.Thread(
            target=self._pattern_loop, daemon=True, name="RTM-Pattern"
        )
        self._scan_thread.start()
        self._pattern_thread.start()

        if self.ap_scan:
            self._ap_thread = threading.Thread(
                target=self._ap_loop, daemon=True, name="RTM-APScan"
            )
            self._ap_thread.start()

    def stop(self):
        self._running = False
        self._stop_event.set()
        for t in (self._scan_thread, self._ap_thread, self._pattern_thread):
            if t and t.is_alive():
                t.join(timeout=5)
        print_info("[RTMonitor] Stopped.")

    def is_running(self) -> bool:
        return self._running

    def get_devices(self) -> List[dict]:
        with self._devices_lock:
            return [d.to_dict() for d in self._devices.values()]

    def get_stats(self) -> dict:
        up = 0
        if self._stats["start_time"]:
            up = int(time.time() - self._stats["start_time"])
        return {**self._stats, "uptime_seconds": up}

    def get_ap_results(self) -> dict:
        with self._ap_lock:
            return dict(self._ap_results)

    def get_correlation_events(self, n: int = 50) -> List[dict]:
        return self.correlation_engine.get_recent_events(n)

    # ── INTERNAL LOOPS ─────────────────────────────────────────

    def _scan_loop(self):
        """Main ARP sweep loop — runs every self.interval seconds."""
        while not self._stop_event.wait(timeout=0.1):
            try:
                alerts_before = db.get_alert_stats().get("total", 0)
                devs_before   = len(db.get_all_devices())
                
                results = self._arp_sweep()
                self._process_scan_results(results)
                
                alerts_after = db.get_alert_stats().get("total", 0)
                devs_after   = len(db.get_all_devices())
                
                db.log_scan(len(results), max(0, alerts_after - alerts_before), max(0, devs_after - devs_before))
                
                self._stats["scan_count"] += 1
                self._stats["last_scan_ts"] = datetime.now().strftime("%H:%M:%S")
            except Exception as e:
                print_warn(f"[RTMonitor] Scan error: {e}")
            # Wait for next interval (interruptible)
            self._stop_event.wait(timeout=float(self.interval))

    def _pattern_loop(self):
        """Pattern recognition sampler — fires every 5 seconds."""
        while not self._stop_event.wait(timeout=5.0):
            try:
                with self._devices_lock:
                    macs = list(self._devices.keys())
                for mac in macs:
                    anomaly = self.pattern_engine.sample_and_detect(mac)
                    if anomaly:
                        with self._devices_lock:
                            dev = self._devices.get(mac)
                        if dev:
                            self._handle_pattern_anomaly(dev, anomaly)
            except Exception as e:
                print_warn(f"[RTMonitor] Pattern error: {e}")

    def _ap_loop(self):
        """Rogue AP scan loop — fires every AP_SCAN_INTERVAL seconds."""
        while not self._stop_event.wait(timeout=float(AP_SCAN_INTERVAL)):
            try:
                from core.rogue_ap_detector import run_ap_detection
                results = run_ap_detection()
                with self._ap_lock:
                    self._ap_results = results

                # Push evil twin / rogue AP events into correlation engine
                for ap in results.get("evil_twins", []):
                    bssid = ap.get("bssid", "")
                    ssid  = ap.get("ssid", "?")
                    self.correlation_engine.push_event(
                        source="rogue_ap",
                        ip="", mac=bssid,
                        event_type=ALERT_ROGUE_AP_LIVE,
                        severity=SEV_CRITICAL,
                        description=f"Evil Twin AP: SSID '{ssid}' BSSID {bssid}"
                    )
            except Exception as e:
                print_warn(f"[RTMonitor] AP scan error: {e}")

    # ── ARP SWEEP ──────────────────────────────────────────────

    def _arp_sweep(self) -> List[dict]:
        """
        ARP sweep of self.network.
        Returns list of {ip, mac, vendor, hostname}.
        Falls back to subprocess arp -a on no Scapy.
        """
        if SCAPY_AVAILABLE:
            return self._scapy_arp_sweep()
        return self._fallback_arp_sweep()

    def _scapy_arp_sweep(self) -> List[dict]:
        results = []
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.network)
            kwargs = {"timeout": 2, "verbose": False}
            if self.iface:
                from core.config import normalize_iface
                kwargs["iface"] = normalize_iface(self.iface)
            answered, _ = srp(pkt, **kwargs)
            for _, rcv in answered:
                ip  = rcv[ARP].psrc
                mac = rcv[ARP].hwsrc.lower()
                results.append({
                    "ip":       ip,
                    "mac":      mac,
                    "vendor":   get_vendor(mac),
                    "hostname": "",
                })
        except Exception as e:
            print_warn(f"[RTMonitor] Scapy ARP sweep failed: {e}")
        return results

    def _fallback_arp_sweep(self) -> List[dict]:
        """Parse `arp -a` output as fallback."""
        import subprocess, re
        results = []
        try:
            out = subprocess.check_output(
                ["arp", "-a"], text=True, timeout=5
            )
            for line in out.splitlines():
                m = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F:-]{17})", line
                )
                if m:
                    ip  = m.group(1)
                    mac = m.group(2).lower().replace("-", ":")
                    results.append({
                        "ip":       ip,
                        "mac":      mac,
                        "vendor":   get_vendor(mac),
                        "hostname": "",
                    })
        except Exception as e:
            print_warn(f"[RTMonitor] arp -a fallback failed: {e}")
        return results

    # ── PROCESS SCAN RESULTS ───────────────────────────────────

    def _process_scan_results(self, results: List[dict]):
        now = time.time()
        seen_macs = set()

        for item in results:
            ip  = item["ip"]
            mac = item["mac"]
            seen_macs.add(mac)

            # ARP change detection
            old_mac = self.arp_table.update(ip, mac)
            if old_mac:
                self._handle_arp_change(ip, mac, old_mac, item)

            with self._devices_lock:
                if mac not in self._devices:
                    # New device
                    dev = DeviceRecord(ip, mac)
                    self._devices[mac] = dev
                    self._stats["new_devices"] += 1
                    self._handle_new_device(dev)
                else:
                    dev = self._devices[mac]
                    dev.ip = ip
                    dev.touch()

            # Lazy hostname resolution (only if empty)
            if not self._devices[mac].hostname:
                threading.Thread(
                    target=self._resolve_hostname,
                    args=(mac, ip),
                    daemon=True
                ).start()

        # Mark gone devices
        with self._devices_lock:
            gone_threshold = now - (self.interval * 3)
            for mac, dev in self._devices.items():
                if mac not in seen_macs and dev.last_seen < gone_threshold:
                    if dev.status != "gone":
                        dev.status = "gone"
                        self._stats["gone_devices"] += 1
                        self._handle_device_gone(dev)

    def _resolve_hostname(self, mac: str, ip: str):
        try:
            hn = socket.gethostbyaddr(ip)[0]
            with self._devices_lock:
                if mac in self._devices:
                    self._devices[mac].hostname = hn
        except Exception as e:
            # Silence common DNS failures but log unexpected errors
            if "not found" not in str(e).lower() and "timed out" not in str(e).lower():
                from core.alert_engine import print_error
                print_error(f"Hostname resolution error for {ip}: {e}")

    # ── EVENT HANDLERS ─────────────────────────────────────────

    def _handle_new_device(self, dev: DeviceRecord):
        desc = (
            f"[NEW DEVICE] IP={dev.ip}  MAC={dev.mac}  "
            f"Vendor={dev.vendor}  Hostname={dev.hostname or '?'}"
        )
        print_info(desc)
        fire_alert(
            alert_type=ALERT_NEW_DEVICE,
            severity=SEV_INFO,
            description=desc,
            device_mac=dev.mac,
            device_ip=dev.ip,
            raw_data={"vendor": dev.vendor, "ip": dev.ip, "mac": dev.mac}
        )
        self.correlation_engine.push_event(
            source="arp_scan", ip=dev.ip, mac=dev.mac,
            event_type=ALERT_NEW_DEVICE, severity=SEV_INFO,
            description=desc
        )
        dev.events.append({"type": "new_device", "ts": datetime.now().strftime("%H:%M:%S")})

    def _handle_device_gone(self, dev: DeviceRecord):
        desc = (
            f"[DEVICE GONE] IP={dev.ip}  MAC={dev.mac}  "
            f"Vendor={dev.vendor}  last seen {dev.last_seen:.0f}"
        )
        print_warn(desc)
        self.correlation_engine.push_event(
            source="arp_scan", ip=dev.ip, mac=dev.mac,
            event_type=ALERT_DEVICE_GONE, severity=SEV_LOW,
            description=desc
        )
        dev.events.append({"type": "gone", "ts": datetime.now().strftime("%H:%M:%S")})

    def _handle_arp_change(self, ip: str, new_mac: str, old_mac: str, item: dict):
        vendor_new = item.get("vendor", get_vendor(new_mac))
        desc = (
            f"[ARP TABLE CHANGE] IP={ip}  was MAC={old_mac}  now MAC={new_mac}  "
            f"New Vendor={vendor_new} — Possible ARP spoofing / network change!"
        )
        print_warn(desc)
        fire_alert(
            alert_type=ALERT_ARP_CHANGE,
            severity=SEV_HIGH,
            description=desc,
            device_mac=new_mac,
            device_ip=ip,
            raw_data={"was": old_mac, "now": new_mac, "vendor": vendor_new}
        )
        self._stats["arp_changes"] += 1
        self.correlation_engine.push_event(
            source="arp_table", ip=ip, mac=new_mac,
            event_type=ALERT_ARP_CHANGE, severity=SEV_HIGH,
            description=desc
        )

    def _handle_pattern_anomaly(self, dev: DeviceRecord, anomaly: dict):
        self._stats["alerts_fired"] += 1
        desc = (
            f"[PATTERN ANOMALY] IP={dev.ip}  MAC={dev.mac}  "
            f"Vendor={dev.vendor}  Z-score={anomaly['z_score']}  "
            f"PPS={anomaly['pps']} (mean={anomaly['mean_pps']})"
        )
        fire_alert(
            alert_type=ALERT_PATTERN_ANOMALY,
            severity=anomaly["severity"],
            description=desc,
            device_mac=dev.mac,
            device_ip=dev.ip,
            raw_data=anomaly
        )
        self.correlation_engine.push_event(
            source="pattern_engine", ip=dev.ip, mac=dev.mac,
            event_type=ALERT_PATTERN_ANOMALY, severity=anomaly["severity"],
            description=desc
        )
        dev.events.append({
            "type":    "pattern_anomaly",
            "ts":      datetime.now().strftime("%H:%M:%S"),
            "z_score": anomaly["z_score"],
            "pps":     anomaly["pps"]
        })
        dev.risk_score = min(dev.risk_score + 15, 100)
        dev.risk_level = _score_to_level(dev.risk_score)

    # ── EXTERNAL PACKET FEED (optional) ────────────────────────

    def feed_packet(self, mac: str, pkt_size: int = 64):
        """
        Optional: call this from packet_engine to feed traffic
        into the pattern recognition engine.
        """
        self.pattern_engine.record_packet(mac, pkt_size)


# ──────────────────────────────────────────────────────────────
#  MODULE-LEVEL SINGLETON
# ──────────────────────────────────────────────────────────────

_monitor_instance: Optional[RealTimeMonitor] = None
_monitor_lock = threading.Lock()


def get_monitor(**kwargs) -> RealTimeMonitor:
    global _monitor_instance
    with _monitor_lock:
        if _monitor_instance is None:
            _monitor_instance = RealTimeMonitor(**kwargs)
    return _monitor_instance


def reset_monitor():
    global _monitor_instance
    with _monitor_lock:
        if _monitor_instance and _monitor_instance.is_running():
            _monitor_instance.stop()
        _monitor_instance = None


# ──────────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────────

def _score_to_level(score: int) -> str:
    if score >= 75:  return "CRITICAL"
    if score >= 50:  return "HIGH"
    if score >= 25:  return "MEDIUM"
    return "LOW"
