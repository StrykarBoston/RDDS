"""
RDDS — Real-Time Attack Detector
==================================
Multi-layer network attack detection with advanced algorithms:

  1. MITM / ARP Poisoning  — gateway MAC-change + gratuitous ARP flood
  2. DDoS Detection        — >N unique sources flooding one destination
  3. SYN Flood (DoS)       — high SYN rate from single source
  4. ICMP Flood            — ICMP pkt/s threshold per source
  5. UDP Flood             — UDP bytes/s threshold per src→dst pair
  6. Behavioral Anomaly    — IQR-based outlier detection per device
  7. Threat Intelligence   — offline IOC lookup (known bad IPs)
  8. Predictive Analysis   — rate-of-change (d(PPS)/dt) pre-alerting

Every detected event is enriched with:
  IP, MAC, Vendor, Hostname, Attack type, Severity, Correlated events
"""

import os
import json
import math
import time
import socket
import threading
import statistics
from collections  import defaultdict, deque
from datetime     import datetime
from typing       import Dict, List, Optional, Set, Deque, Tuple

try:
    from scapy.all import (
        sniff, ARP, IP, TCP, UDP, ICMP, Ether, conf as scapy_conf,
        DNS, DNSRR, Dot11, Dot11Deauth, Dot11ProbeReq, Dot11ProbeResp
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core.config       import (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM,
                                SEV_LOW, SEV_INFO, get_default_gateway)
from core.alert_engine import fire_alert, print_info, print_warn
from core.network_scanner import get_vendor, resolve_hostname

# ──────────────────────────────────────────────────────────────
#  ALERT TYPE CONSTANTS
# ──────────────────────────────────────────────────────────────

ATK_MITM          = "MITM_ATTACK"
ATK_ARP_SPOOF     = "ARP_SPOOF"
ATK_DDOS          = "DDOS_ATTACK"
ATK_SYN_FLOOD     = "SYN_FLOOD"
ATK_ICMP_FLOOD    = "ICMP_FLOOD"
ATK_UDP_FLOOD     = "UDP_FLOOD"
ATK_GRAT_ARP      = "GRATUITOUS_ARP_FLOOD"
ATK_BEHAVIORAL    = "BEHAVIORAL_ANOMALY"
ATK_THREAT_INTEL  = "THREAT_INTEL_MATCH"
ATK_PREDICTIVE    = "PREDICTIVE_PRE_ALERT"
ATK_CORRELATED    = "MULTI_LAYER_CORRELATED"
ATK_PORT_SCAN     = "PORT_SCAN_DETECTED"
ATK_LATERAL       = "LATERAL_MOVEMENT"
ATK_DNS_SPOOF     = "DNS_SPOOF"
ATK_DEAUTH        = "DEAUTH_FLOOD"
ATK_KARMA         = "KARMA_ATTACK"

# ──────────────────────────────────────────────────────────────
#  TUNING THRESHOLDS
# ──────────────────────────────────────────────────────────────

DDOS_SOURCES_THRESHOLD  = 30    # unique senders to same dest in 10s
DDOS_WINDOW             = 10    # seconds
SYN_FLOOD_THRESHOLD     = 150   # SYN pkts/s from one src to one dst
ICMP_FLOOD_THRESHOLD    = 80    # ICMP pkts/s from one src
UDP_FLOOD_BYTES         = 5_000_000   # 5 MB/s UDP from one src to one dst
UDP_FLOOD_WINDOW        = 5     # seconds
GRAT_ARP_MIN            = 20    # gratuitous ARPs in 3 seconds
DEAUTH_THRESHOLD        = 50    # Deauths in 10s
DEAUTH_WINDOW           = 10    # seconds
KARMA_PROBE_THRESHOLD   = 5     # AP responding to >5 different probed SSIDs
PORT_SCAN_PORTS         = 10    # unique dst ports in PORT_SCAN_WIN
PORT_SCAN_WIN           = 10    # seconds
LATERAL_PORTS           = {22, 23, 135, 139, 445, 3389, 5985, 5986, 4444, 1433, 5432}
LATERAL_THRESHOLD       = 5     # hits to high-risk port from one src
BEHAVIORAL_IQR_MULT     = 3.0   # IQR multiplier for outlier detection
BEHAVIORAL_MIN_SAMPLES  = 15    # minimum samples before IQR fires
PREDICT_ACCEL_THRESHOLD = 50.0  # PPS acceleration (pkts/s²) pre-alert
ALERT_DEDUP_TTL         = 30    # seconds to suppress repeat alert
MAX_EVENTS_RING         = 1000  # ring buffer size for events

# ──────────────────────────────────────────────────────────────
#  THREAT INTELLIGENCE — IOC LIST
# ──────────────────────────────────────────────────────────────

_ioc_set: Set[str] = set()
_ioc_lock = threading.Lock()

def load_threat_intel(path: Optional[str] = None):
    """Load known bad IPs/CIDRs from threat_intel.json."""
    global _ioc_set
    if path is None:
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "threat_intel.json"
        )
    try:
        with open(path, "r") as f:
            data = json.load(f)
        flat: List[str] = []
        flat += data.get("malicious_ips", [])
        flat += data.get("c2_servers",    [])
        flat += data.get("tor_exits",     [])
        flat += data.get("scanners",      [])
        with _ioc_lock:
            _ioc_set = set(flat)
        print_info(f"[AttackDetector] Threat intel loaded: {len(_ioc_set)} IOCs")
    except FileNotFoundError:
        print_warn("[AttackDetector] threat_intel.json not found — creating empty list")
        _ioc_set = set()
    except Exception as e:
        print_warn(f"[AttackDetector] Threat intel load error: {e}")

def is_ioc(ip: str) -> bool:
    with _ioc_lock:
        return ip in _ioc_set

# Load on import
load_threat_intel()

# ──────────────────────────────────────────────────────────────
#  HELPER — REVERSE DNS (cached)
# ──────────────────────────────────────────────────────────────

_dns_cache: Dict[str, str] = {}
_dns_lock  = threading.Lock()

def _rdns(ip: str) -> str:
    """Cached reverse-DNS lookup with a 1-second timeout to prevent blocking."""
    with _dns_lock:
        if ip in _dns_cache:
            return _dns_cache[ip]
    try:
        _old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.0)
        name = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(_old)
    except Exception:
        socket.setdefaulttimeout(None)
        name = ""
    with _dns_lock:
        _dns_cache[ip] = name
    return name

# ──────────────────────────────────────────────────────────────
#  ALERT DEDUPLICATION
# ──────────────────────────────────────────────────────────────

_dedup: Dict[str, float] = {}
_dedup_lock = threading.Lock()

def _should_fire(key: str) -> bool:
    now = time.time()
    with _dedup_lock:
        last = _dedup.get(key, 0)
        if now - last < ALERT_DEDUP_TTL:
            return False
        _dedup[key] = now
        return True

# ──────────────────────────────────────────────────────────────
#  ATTACK DETECTOR — MAIN CLASS
# ──────────────────────────────────────────────────────────────

class AttackDetector:
    """
    Real-time multi-layer network attack detection engine.

    Works via:
      • Passive Scapy packet sniffer (primary)
      • Raw socket fallback (if Scapy unavailable)
      • Per-packet dispatch to all detector sub-engines
    """

    def __init__(self,
                 iface:       Optional[str] = None,
                 duration:    int           = 0,
                 gateway_ip:  Optional[str] = None):
        self.iface      = iface
        self.duration   = duration   # 0 = run forever
        self.gateway_ip = gateway_ip or get_default_gateway()

        # ── ARP Table for MITM ────────────────────────────────
        self._arp_table: Dict[str, str] = {}   # ip → mac
        self._gateway_mac: Optional[str] = None

        # ── DDoS ──────────────────────────────────────────────
        # dst_ip → deque of (ts, src_ip)
        self._ddos_srcmap: Dict[str, Deque[Tuple[float, str]]] = defaultdict(
            lambda: deque(maxlen=5000)
        )

        # ── SYN Flood ─────────────────────────────────────────
        # (src_ip, dst_ip) → deque of timestamps
        self._syn_map: Dict[Tuple[str,str], Deque[float]] = defaultdict(
            lambda: deque(maxlen=5000)
        )

        # ── ICMP Flood ────────────────────────────────────────
        self._icmp_map: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=5000)
        )

        # ── UDP Flood ─────────────────────────────────────────
        # (src_ip, dst_ip) → deque of (ts, bytes)
        self._udp_map: Dict[Tuple[str,str], Deque[Tuple[float,int]]] = defaultdict(
            lambda: deque(maxlen=5000)
        )

        # ── Gratuitous ARP ────────────────────────────────────
        self._grat_arp: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=1000)
        )

        # ── Deauth Flood ──────────────────────────────────────
        self._deauth_map: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=1000)
        )

        # ── Karma Attack ──────────────────────────────────────
        # AP MAC -> set of SSIDs it responded to
        self._karma_tracker: Dict[str, set] = defaultdict(set)

        # ── Port Scan ─────────────────────────────────────────
        # src_ip → {start_ts, set of dst_ports}
        self._port_scan_tracker: Dict[str, dict] = {}

        # ── Lateral Movement ──────────────────────────────────
        # (src_ip, dst_port) → hit count
        self._lateral_counts: Dict[Tuple[str,int], int] = defaultdict(int)

        # ── Behavioral (IQR) baseline ─────────────────────────
        # mac → list of per-second PPS samples
        self._beh_pps_hist:    Dict[str, List[float]] = defaultdict(list)
        self._beh_last_sample: Dict[str, Tuple[float, int]] = {}  # mac → (ts, pkt_count)
        self._beh_pkt_count:   Dict[str, int] = defaultdict(int)

        # ── Predictive analysis ───────────────────────────────
        # src_ip → recent PPS samples (last 6) for derivative
        self._predict_hist: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=6)
        )

        # ── Event ring buffer ─────────────────────────────────
        self._events: Deque[dict] = deque(maxlen=MAX_EVENTS_RING)
        self._events_lock = threading.Lock()

        # ── Multi-layer correlation ───────────────────────────
        # ip → list of (ts, attack_type)
        self._multilayer: Dict[str, Deque[Tuple[float,str]]] = defaultdict(
            lambda: deque(maxlen=100)
        )

        # ── Runtime ───────────────────────────────────────────
        self._running     = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._sample_thread: Optional[threading.Thread] = None
        self._stop_event  = threading.Event()

        # ── Stats ─────────────────────────────────────────────
        self._stats = {
            "start_time":    None,
            "pkts_processed": 0,
            "mitm_alerts":   0,
            "ddos_alerts":   0,
            "syn_alerts":    0,
            "icmp_alerts":   0,
            "udp_alerts":    0,
            "dns_spoof":     0,
            "deauth_alerts": 0,
            "karma_alerts":  0,
            "behavioral":    0,
            "ioc_matches":   0,
            "predictive":    0,
            "correlated":    0,
            "total_alerts":  0,
        }

    # ── PUBLIC API ───────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._stats["start_time"] = time.time()
        
        # Proactively fetch gateway MAC to prevent MITM races
        try:
            if self.gateway_ip and SCAPY_AVAILABLE:
                from scapy.all import getmacbyip
                mac = getmacbyip(self.gateway_ip)
                if mac:
                    self._gateway_mac = mac
                    self._arp_table[self.gateway_ip] = mac
                    print_info(f"[AttackDetector] Pre-cached Gateway MAC = {mac}")
        except Exception as e:
            print_warn(f"[AttackDetector] Could not pre-cache gateway MAC: {e}")

        print_info(
            f"[AttackDetector] Starting — iface={self.iface or 'auto'}, "
            f"gateway={self.gateway_ip}, duration={self.duration or '∞'}s"
        )
        self._sniff_thread = threading.Thread(
            target=self._run_sniffer, daemon=True, name="AttackDet-Sniff"
        )
        self._sample_thread = threading.Thread(
            target=self._behavioral_sampler, daemon=True, name="AttackDet-BehSample"
        )
        self._sniff_thread.start()
        self._sample_thread.start()

    def stop(self):
        self._running = False
        self._stop_event.set()
        for t in (self._sniff_thread, self._sample_thread):
            if t and t.is_alive():
                t.join(timeout=5)
        print_info("[AttackDetector] Stopped.")

    def is_running(self) -> bool:
        return self._running

    def get_events(self, n: int = 100) -> List[dict]:
        with self._events_lock:
            return list(self._events)[-n:]

    def get_stats(self) -> dict:
        uptime = 0
        if self._stats["start_time"]:
            uptime = int(time.time() - self._stats["start_time"])
        return {**self._stats, "uptime_seconds": uptime}

    def get_summary(self) -> dict:
        with self._events_lock:
            evs = list(self._events)
        counts: Dict[str, int] = defaultdict(int)
        for e in evs:
            counts[e.get("attack_type", "?")] += 1
        return {
            "by_type":   dict(counts),
            "total":     len(evs),
            "critical":  sum(1 for e in evs if e.get("severity") == SEV_CRITICAL),
            "high":      sum(1 for e in evs if e.get("severity") == SEV_HIGH),
        }

    def get_timeline(self) -> List[dict]:
        """Events grouped per minute for chart rendering."""
        with self._events_lock:
            evs = list(self._events)
        buckets: Dict[str, dict] = defaultdict(lambda: {"count": 0, "critical": 0})
        for e in evs:
            ts   = e.get("timestamp", "")[:5]   # "HH:MM"
            bucket = buckets[ts]
            bucket["count"] += 1
            if e.get("severity") == SEV_CRITICAL:
                bucket["critical"] += 1
        return [{"minute": k, **v} for k, v in sorted(buckets.items())]

    def get_ioc_matches(self) -> List[dict]:
        with self._events_lock:
            return [e for e in self._events if e.get("attack_type") == ATK_THREAT_INTEL]

    # ── SNIFFER ─────────────────────────────────────────────

    def _run_sniffer(self):
        if SCAPY_AVAILABLE:
            self._scapy_sniff()
        else:
            self._raw_socket_fallback()

    def _scapy_sniff(self):
        kwargs = {
            "prn":         self._process_packet,
            "store":       False,
            "stop_filter": lambda _: self._stop_event.is_set(),
        }
        if self.iface:
            kwargs["iface"] = self.iface
        if self.duration > 0:
            kwargs["timeout"] = self.duration
        try:
            sniff(**kwargs)
        except Exception as e:
            print_warn(f"[AttackDetector] Sniff error: {e}")

    def _raw_socket_fallback(self):
        """Minimal fallback: parses arp -a periodically."""
        import subprocess, re
        print_warn("[AttackDetector] Scapy unavailable — using ARP-table fallback only")
        while not self._stop_event.is_set():
            try:
                out = subprocess.check_output(
                    ["arp", "-a"], text=True, timeout=5
                )
                for line in out.splitlines():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F:-]{17})", line)
                    if m:
                        ip  = m.group(1)
                        mac = m.group(2).lower().replace("-", ":")
                        old = self._arp_table.get(ip)
                        self._arp_table[ip] = mac
                        if old and old != mac:
                            self._fire_arp_change(ip, mac, old)
            except Exception:
                pass
            self._stop_event.wait(10)

    # ── PACKET DISPATCH ─────────────────────────────────────

    def _process_packet(self, pkt):
        try:
            self._stats["pkts_processed"] += 1
            if pkt.haslayer(ARP):
                self._detect_arp(pkt)
            if pkt.haslayer(Dot11):
                self._detect_dot11(pkt)
            if pkt.haslayer(DNS):
                self._detect_dns(pkt)
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                self._beh_pkt_count[src] += 1
                self._check_ioc(src, pkt)
                self._check_ioc(dst, pkt)
                self._update_predict(src)
                if pkt.haslayer(TCP):
                    self._detect_tcp(pkt, src, dst)
                if pkt.haslayer(ICMP):
                    self._detect_icmp(pkt, src, dst)
                if pkt.haslayer(UDP):
                    self._detect_udp(pkt, src, dst)
                self._detect_ddos(dst, src)
                self._detect_port_scan(src, pkt)
        except Exception as e:
            from core.alert_engine import print_error
            print_error(f"Attack Detector _process_packet error: {e}")

    # ── 1. MITM / ARP POISONING ────────────────────────────

    def _detect_arp(self, pkt):
        arp = pkt[ARP]
        op      = arp.op
        src_ip  = arp.psrc
        src_mac = arp.hwsrc.lower()
        dst_ip  = arp.pdst

        # Gratuitous ARP: sender IP == target IP
        if src_ip == dst_ip and op == 1:
            self._grat_arp[src_mac].append(time.time())
            w = 3.0
            cutoff = time.time() - w
            cnt = sum(1 for t in self._grat_arp[src_mac] if t >= cutoff)
            if cnt >= GRAT_ARP_MIN:
                key = f"grat:{src_mac}"
                if _should_fire(key):
                    self._emit_event(
                        attack_type=ATK_GRAT_ARP,
                        severity=SEV_HIGH,
                        src_ip=src_ip, src_mac=src_mac,
                        dst_ip="broadcast", dst_mac="",
                        details={"grat_arp_count": cnt, "window_s": w},
                        msg=(
                            f"Gratuitous ARP FLOOD from {src_ip} [{src_mac}] — "
                            f"{cnt} gratuitious ARPs in {w}s "
                            f"Vendor={get_vendor(src_mac)}"
                        )
                    )
            return   # don't also check ARP reply for gratuitous

        if op == 2:    # ARP reply
            old_mac = self._arp_table.get(src_ip)
            self._arp_table[src_ip] = src_mac
            if old_mac and old_mac != src_mac:
                self._fire_arp_change(src_ip, src_mac, old_mac)
            if src_ip == self.gateway_ip:
                if self._gateway_mac and self._gateway_mac != src_mac:
                    key = f"mitm:{src_ip}"
                    if _should_fire(key):
                        self._emit_event(
                            attack_type=ATK_MITM,
                            severity=SEV_CRITICAL,
                            src_ip=src_ip, src_mac=src_mac,
                            dst_ip="", dst_mac="",
                            details={"was": self._gateway_mac, "now": src_mac},
                            msg=(
                                f"MITM ATTACK DETECTED! Gateway IP={src_ip} "
                                f"MAC changed from {self._gateway_mac} → {src_mac} "
                                f"Vendor={get_vendor(src_mac)} — ARP POISONING!"
                            )
                        )
                    self._stats["mitm_alerts"] += 1
                else:
                    self._gateway_mac = src_mac

    def _fire_arp_change(self, ip: str, new_mac: str, old_mac: str):
        vendor_new = get_vendor(new_mac).lower()
        if any(v in vendor_new for v in ["tp-link", "netgear", "eero", "mesh", "repeater"]):
            return  # Suppress known proxy-ARP behaviors
            
        key = f"arp:{ip}"
        if _should_fire(key):
            self._emit_event(
                attack_type=ATK_ARP_SPOOF,
                severity=SEV_HIGH,
                src_ip=ip, src_mac=new_mac,
                dst_ip="", dst_mac="",
                details={"was": old_mac, "now": new_mac},
                msg=(
                    f"ARP SPOOF: IP={ip} was MAC={old_mac} "
                    f"now claims {new_mac} "
                    f"New Vendor={get_vendor(new_mac)}"
                )
            )

    # ── 2. DDoS DETECTION ──────────────────────────────────

    def _detect_ddos(self, dst_ip: str, src_ip: str):
        now = time.time()
        q = self._ddos_srcmap[dst_ip]
        q.append((now, src_ip))
        cutoff = now - DDOS_WINDOW
        while q and q[0][0] < cutoff:
            q.popleft()
        unique_srcs = {s for _, s in q}
        if len(unique_srcs) >= DDOS_SOURCES_THRESHOLD:
            key = f"ddos:{dst_ip}"
            if _should_fire(key):
                self._emit_event(
                    attack_type=ATK_DDOS,
                    severity=SEV_CRITICAL,
                    src_ip=",".join(list(unique_srcs)[:5]) + "...",
                    src_mac="", dst_ip=dst_ip, dst_mac="",
                    details={
                        "unique_sources": len(unique_srcs),
                        "window_s": DDOS_WINDOW,
                        "sample_sources": list(unique_srcs)[:10]
                    },
                    msg=(
                        f"DDoS ATTACK on {dst_ip}: "
                        f"{len(unique_srcs)} unique sources in {DDOS_WINDOW}s — "
                        f"Sample attackers: {list(unique_srcs)[:5]}"
                    )
                )
                self._stats["ddos_alerts"] += 1

    # ── 3. SYN FLOOD ───────────────────────────────────────

    def _detect_tcp(self, pkt, src: str, dst: str):
        tcp = pkt[TCP]
        flags = tcp.flags

        # SYN flag only (not ACK)
        if flags & 0x02 and not (flags & 0x10):
            dport = tcp.dport
            now   = time.time()
            key_pair = (src, dst)
            q = self._syn_map[key_pair]
            q.append(now)
            cutoff = now - 1.0
            while q and q[0] < cutoff:
                q.popleft()
            rate = len(q)
            if rate >= SYN_FLOOD_THRESHOLD:
                key = f"syn:{src}:{dst}"
                if _should_fire(key):
                    self._emit_event(
                        attack_type=ATK_SYN_FLOOD,
                        severity=SEV_CRITICAL,
                        src_ip=src, src_mac=self._arp_table.get(src, ""),
                        dst_ip=dst, dst_mac="",
                        details={"syn_rate_per_s": rate, "dst_port": dport},
                        msg=(
                            f"SYN FLOOD from {src} → {dst}:{dport} "
                            f"Rate={rate} SYN/s "
                            f"SrcVendor={get_vendor(self._arp_table.get(src,''))}"
                        )
                    )
                    self._stats["syn_alerts"] += 1

        # Lateral movement to high-risk ports
        if tcp.dport in LATERAL_PORTS:
            pair = (src, tcp.dport)
            self._lateral_counts[pair] += 1
            if self._lateral_counts[pair] >= LATERAL_THRESHOLD:
                key = f"lateral:{src}:{tcp.dport}"
                if _should_fire(key):
                    self._emit_event(
                        attack_type=ATK_LATERAL,
                        severity=SEV_HIGH,
                        src_ip=src, src_mac=self._arp_table.get(src,""),
                        dst_ip=dst, dst_mac="",
                        details={"port": tcp.dport, "hits": self._lateral_counts[pair]},
                        msg=(
                            f"LATERAL MOVEMENT: {src} → {dst}:{tcp.dport} "
                            f"({self._port_name(tcp.dport)}) — "
                            f"{self._lateral_counts[pair]} hits  "
                            f"SrcHostname={_rdns(src)}"
                        )
                    )
                self._lateral_counts[pair] = 0

        # Port scan (SYN sweep)
        if flags & 0x02:
            self._check_port_scan(src, tcp.dport)

    def _check_port_scan(self, src_ip: str, dport: int):
        now = time.time()
        rec = self._port_scan_tracker.get(src_ip)
        if rec is None or (now - rec["start"]) > PORT_SCAN_WIN:
            self._port_scan_tracker[src_ip] = {"start": now, "ports": set()}
            rec = self._port_scan_tracker[src_ip]
        rec["ports"].add(dport)
        if len(rec["ports"]) >= PORT_SCAN_PORTS:
            key = f"scan:{src_ip}"
            if _should_fire(key):
                self._emit_event(
                    attack_type=ATK_PORT_SCAN,
                    severity=SEV_HIGH,
                    src_ip=src_ip, src_mac=self._arp_table.get(src_ip,""),
                    dst_ip="", dst_mac="",
                    details={
                        "unique_ports": len(rec["ports"]),
                        "sample_ports": sorted(list(rec["ports"]))[:20]
                    },
                    msg=(
                        f"PORT SCAN from {src_ip}: "
                        f"{len(rec['ports'])} ports in {PORT_SCAN_WIN}s  "
                        f"SrcHostname={_rdns(src_ip)}"
                    )
                )

    def _detect_port_scan(self, src_ip: str, pkt):
        """Outer wrapper — called for all packets."""
        pass   # handled inside _detect_tcp

    # ── 4. ICMP FLOOD ──────────────────────────────────────

    def _detect_icmp(self, pkt, src: str, dst: str):
        now = time.time()
        q   = self._icmp_map[src]
        q.append(now)
        cutoff = now - 1.0
        while q and q[0] < cutoff:
            q.popleft()
        rate = len(q)
        if rate >= ICMP_FLOOD_THRESHOLD:
            key = f"icmp:{src}"
            if _should_fire(key):
                self._emit_event(
                    attack_type=ATK_ICMP_FLOOD,
                    severity=SEV_HIGH,
                    src_ip=src, src_mac=self._arp_table.get(src,""),
                    dst_ip=dst, dst_mac="",
                    details={"icmp_rate_per_s": rate},
                    msg=(
                        f"ICMP FLOOD from {src} → {dst}  "
                        f"Rate={rate} pkts/s  "
                        f"SrcHostname={_rdns(src)}"
                    )
                )
                self._stats["icmp_alerts"] += 1

    # ── 5. UDP FLOOD ───────────────────────────────────────

    def _detect_udp(self, pkt, src: str, dst: str):
        now  = time.time()
        size = len(pkt)
        pair = (src, dst)
        q    = self._udp_map[pair]
        q.append((now, size))
        cutoff = now - UDP_FLOOD_WINDOW
        while q and q[0][0] < cutoff:
            q.popleft()
        total_bytes = sum(b for _, b in q)
        rate_per_s  = total_bytes / max(UDP_FLOOD_WINDOW, 1)
        if total_bytes >= UDP_FLOOD_BYTES:
            key = f"udp:{src}:{dst}"
            if _should_fire(key):
                self._emit_event(
                    attack_type=ATK_UDP_FLOOD,
                    severity=SEV_HIGH,
                    src_ip=src, src_mac=self._arp_table.get(src,""),
                    dst_ip=dst, dst_mac="",
                    details={
                        "bytes_in_window": total_bytes,
                        "mbps":            round(rate_per_s / 1_000_000, 2),
                        "window_s":        UDP_FLOOD_WINDOW
                    },
                    msg=(
                        f"UDP FLOOD from {src} → {dst}  "
                        f"{round(rate_per_s/1_000_000,2)} MB/s  "
                        f"SrcVendor={get_vendor(self._arp_table.get(src,''))}"
                    )
                )
                self._stats["udp_alerts"] += 1

    # ── 5.5. DNS SPOOFING ──────────────────────────────────

    def _detect_dns(self, pkt):
        if not pkt.haslayer(DNSRR):
            return
        if not pkt.haslayer(IP):
            return
            
        dns = pkt[DNS]
        src_ip = pkt[IP].src
        
        if dns.qr == 1 and dns.ancount > 0:
            for i in range(dns.ancount):
                rr = dns.an[i]
                if rr.type == 1:  # A record
                    rdata = rr.rdata if isinstance(rr.rdata, str) else (rr.rdata.decode(errors='ignore') if hasattr(rr.rdata, 'decode') else str(rr.rdata))
                    qname = rr.rrname.decode(errors='ignore') if hasattr(rr, 'rrname') and rr.rrname else ""
                    
                    if rdata.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")):
                        if "." in qname and not qname.endswith((".local.", ".lan.", ".home.", ".corp.")):
                            key = f"dnsspoof:{src_ip}:{qname}"
                            if _should_fire(key):
                                self._emit_event(
                                    attack_type=ATK_DNS_SPOOF,
                                    severity=SEV_HIGH,
                                    src_ip=src_ip, src_mac=self._arp_table.get(src_ip, ""),
                                    dst_ip="", dst_mac="",
                                    details={"domain": qname, "spoofed_ip": rdata},
                                    msg=(
                                        f"DNS SPOOFING: {src_ip} replied for {qname} "
                                        f"with private IP {rdata} "
                                        f"SrcHostname={_rdns(src_ip)}"
                                    )
                                )
                                self._stats["dns_spoof"] += 1

    # ── 5.6. DEAUTH & KARMA (802.11) ───────────────────────

    def _detect_dot11(self, pkt):
        if pkt.haslayer(Dot11Deauth):
            addr1 = pkt.addr1  # Destination
            addr2 = pkt.addr2  # Source (BSSID)
            
            if not addr1 or not addr2:
                return
                
            now = time.time()
            q = self._deauth_map[addr2]
            q.append(now)
            cutoff = now - DEAUTH_WINDOW
            while q and q[0] < cutoff:
                q.popleft()
                
            if len(q) >= DEAUTH_THRESHOLD:
                key = f"deauth:{addr2}"
                if _should_fire(key):
                    self._emit_event(
                        attack_type=ATK_DEAUTH,
                        severity=SEV_CRITICAL,
                        src_ip="", src_mac=addr2,
                        dst_ip="", dst_mac=addr1,
                        details={"target": addr1, "count": len(q)},
                        msg=(
                            f"DEAUTHENTICATION FLOOD: BSSID {addr2} "
                            f"targeted {addr1} with {len(q)} frames in {DEAUTH_WINDOW}s. "
                            f"Vendor={get_vendor(addr2)}"
                        )
                    )
                    self._stats["deauth_alerts"] += 1

        elif pkt.haslayer(Dot11ProbeResp):
            addr2 = pkt.addr2  # AP answering
            if not addr2:
                return
                
            info = pkt.info.decode(errors='ignore') if hasattr(pkt, 'info') and pkt.info else ""
            if info:
                self._karma_tracker[addr2].add(info)
                if len(self._karma_tracker[addr2]) >= KARMA_PROBE_THRESHOLD:
                    key = f"karma:{addr2}"
                    if _should_fire(key):
                        self._emit_event(
                            attack_type=ATK_KARMA,
                            severity=SEV_CRITICAL,
                            src_ip="", src_mac=addr2,
                            dst_ip="", dst_mac="",
                            details={"ssids_responded": list(self._karma_tracker[addr2])},
                            msg=(
                                f"KARMA ATTACK: BSSID {addr2} is responding to "
                                f"{len(self._karma_tracker[addr2])} different probed SSIDs. "
                                f"Vendor={get_vendor(addr2)}"
                            )
                        )
                        self._stats["karma_alerts"] += 1
                        self._karma_tracker[addr2].clear()

    # ── 6. BEHAVIORAL ANOMALY (IQR) ────────────────────────

    def _behavioral_sampler(self):
        """
        Runs every 1 second.
        Measures PPS per src MAC, builds IQR baseline, fires on outliers.
        """
        while not self._stop_event.wait(1.0):
            try:
                now = time.time()
                with self._events_lock:  # Use the shared instance lock for mutual exclusion
                    snapshot = dict(self._beh_pkt_count)
                    self._beh_pkt_count.clear()
                for ip_src, count in snapshot.items():
                    pps = float(count)   # packets in the last second
                    hist = self._beh_pps_hist[ip_src]
                    hist.append(pps)
                    # Predictive: store for derivative
                    self._predict_hist[ip_src].append(pps)
                    self._run_predict(ip_src)
                    if len(hist) < BEHAVIORAL_MIN_SAMPLES:
                        continue
                    tail = hist[-60:]
                    try:
                        q1 = statistics.quantiles(tail, n=4)[0]
                        q3 = statistics.quantiles(tail, n=4)[2]
                        iqr = q3 - q1
                        upper = q3 + BEHAVIORAL_IQR_MULT * iqr
                        if pps > upper and pps > 500:
                            mac  = self._arp_table.get(ip_src, "")
                            key  = f"beh:{ip_src}"
                            if _should_fire(key):
                                self._emit_event(
                                    attack_type=ATK_BEHAVIORAL,
                                    severity=SEV_MEDIUM,
                                    src_ip=ip_src, src_mac=mac,
                                    dst_ip="", dst_mac="",
                                    details={
                                        "pps":    pps,
                                        "q3":     round(q3, 1),
                                        "iqr":    round(iqr, 1),
                                        "upper":  round(upper, 1)
                                    },
                                    msg=(
                                        f"BEHAVIORAL ANOMALY: {ip_src} [{mac}] "
                                        f"PPS={pps:.0f} (IQR upper={upper:.1f})  "
                                        f"Vendor={get_vendor(mac)}"
                                    )
                                )
                                self._stats["behavioral"] += 1
                    except Exception:
                        pass
            except Exception as e:
                print_warn(f"[AttackDetector] Behavioral sampler error: {e}")

    # ── 7. THREAT INTELLIGENCE ─────────────────────────────

    def _check_ioc(self, ip: str, pkt):
        if not is_ioc(ip):
            return
        mac = ""
        if pkt.haslayer(Ether):
            mac = pkt[Ether].src.lower() if pkt[IP].src == ip else pkt[Ether].dst.lower()
        key = f"ioc:{ip}"
        if _should_fire(key):
            self._emit_event(
                attack_type=ATK_THREAT_INTEL,
                severity=SEV_CRITICAL,
                src_ip=ip, src_mac=mac,
                dst_ip="", dst_mac="",
                details={"ioc_ip": ip},
                msg=(
                    f"THREAT INTEL MATCH: IP {ip} is in known IOC list  "
                    f"MAC={mac}  Vendor={get_vendor(mac)}  "
                    f"Hostname={_rdns(ip)}"
                )
            )
            self._stats["ioc_matches"] += 1

    # ── 8. PREDICTIVE ANALYSIS ─────────────────────────────

    def _update_predict(self, src_ip: str):
        pass   # actual update happens in _behavioral_sampler

    def _run_predict(self, ip: str):
        """
        Compute rate-of-change (d(PPS)/dt).
        If acceleration > threshold, fire a pre-alert.
        """
        hist = list(self._predict_hist[ip])
        if len(hist) < 4:
            return
        # Simple discrete derivative: last vs 3-sample mean before
        recent = hist[-1]
        prev   = statistics.mean(hist[-4:-1])
        accel  = recent - prev  # pkts/s gained per sample
        if accel >= PREDICT_ACCEL_THRESHOLD:
            mac = self._arp_table.get(ip, "")
            key = f"pred:{ip}"
            if _should_fire(key):
                self._emit_event(
                    attack_type=ATK_PREDICTIVE,
                    severity=SEV_MEDIUM,
                    src_ip=ip, src_mac=mac,
                    dst_ip="", dst_mac="",
                    details={
                        "current_pps": round(recent, 1),
                        "acceleration": round(accel, 1),
                        "threshold":    PREDICT_ACCEL_THRESHOLD
                    },
                    msg=(
                        f"PREDICTIVE PRE-ALERT: {ip} [{mac}] "
                        f"PPS accelerating +{accel:.0f}/s — "
                        f"Possible imminent attack!  "
                        f"Vendor={get_vendor(mac)}  Hostname={_rdns(ip)}"
                    )
                )
                self._stats["predictive"] += 1

    # ── MULTI-LAYER CORRELATION ─────────────────────────────

    def _check_multilayer(self, ip: str, attack_type: str):
        now = time.time()
        q   = self._multilayer[ip]
        q.append((now, attack_type))
        cutoff = now - 5.0   # 5-second correlation window
        recent = [(t, a) for t, a in q if t >= cutoff]
        unique_types = {a for _, a in recent}
        if len(unique_types) >= 2:
            key = f"multi:{ip}"
            if _should_fire(key):
                mac = self._arp_table.get(ip, "")
                self._emit_event(
                    attack_type=ATK_CORRELATED,
                    severity=SEV_CRITICAL,
                    src_ip=ip, src_mac=mac,
                    dst_ip="", dst_mac="",
                    details={
                        "attack_types": list(unique_types),
                        "event_count":  len(recent)
                    },
                    msg=(
                        f"MULTI-LAYER ATTACK CORRELATED on {ip} [{mac}]: "
                        f"{len(unique_types)} attack types simultaneously — "
                        f"{', '.join(unique_types)}  "
                        f"Vendor={get_vendor(mac)}  Hostname={_rdns(ip)}"
                    )
                )
                self._stats["correlated"]    += 1
                self._stats["total_alerts"]  += 1

    # ── EVENT EMITTER ─────────────────────────────────────

    def _emit_event(self, attack_type: str, severity: str,
                    src_ip: str, src_mac: str,
                    dst_ip: str, dst_mac: str,
                    details: dict, msg: str):
        src_vendor   = get_vendor(src_mac) if src_mac else ""
        src_hostname = _rdns(src_ip) if src_ip else ""
        ev = {
            "timestamp":     datetime.now().strftime("%H:%M:%S"),
            "ts_epoch":      time.time(),
            "attack_type":   attack_type,
            "severity":      severity,
            "src_ip":        src_ip,
            "src_mac":       src_mac,
            "src_vendor":    src_vendor,
            "src_hostname":  src_hostname,
            "dst_ip":        dst_ip,
            "dst_mac":       dst_mac,
            "details":       details,
            "description":   msg,
        }
        with self._events_lock:
            self._events.append(ev)
        self._stats["total_alerts"] += 1

        fire_alert(
            alert_type=attack_type,
            severity=severity,
            description=msg,
            device_mac=src_mac,
            device_ip=src_ip,
            raw_data={**details,
                      "vendor": src_vendor, "hostname": src_hostname}
        )

        # Multi-layer correlation
        if src_ip:
            self._multilayer[src_ip].append((time.time(), attack_type))
            self._check_multilayer(src_ip, attack_type)

    # ── HELPERS ──────────────────────────────────────────

    @staticmethod
    def _port_name(port: int) -> str:
        names = {
            22: "SSH", 23: "Telnet", 135: "DCOM/RPC",
            139: "NetBIOS", 445: "SMB", 3389: "RDP",
            5985: "WinRM", 5986: "WinRM-HTTPS",
            4444: "Metasploit", 1433: "MSSQL", 5432: "PostgreSQL"
        }
        return names.get(port, str(port))


# ──────────────────────────────────────────────────────────────
#  MODULE-LEVEL SINGLETON
# ──────────────────────────────────────────────────────────────

_detector_instance: Optional[AttackDetector] = None
_detector_lock = threading.Lock()


def get_detector(**kwargs) -> AttackDetector:
    global _detector_instance
    with _detector_lock:
        if _detector_instance is None:
            _detector_instance = AttackDetector(**kwargs)
    return _detector_instance


def reset_detector():
    global _detector_instance
    with _detector_lock:
        if _detector_instance and _detector_instance.is_running():
            _detector_instance.stop()
        _detector_instance = None
