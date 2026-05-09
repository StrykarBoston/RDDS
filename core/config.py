"""
RDDS — Rogue Device Detection System
Configuration Module
"""

import os
import socket

# ─────────────────────────────────────────────
#  NETWORK SETTINGS
# ─────────────────────────────────────────────
# Auto-detect or override manually
NETWORK_INTERFACE = None          # None = auto-detect, or e.g. "Ethernet", "Wi-Fi"
NETWORK_TARGET    = "192.168.1.0/24"  # CIDR range to scan; override with your subnet
SCAN_INTERVAL     = 60            # seconds between continuous scans
SNIFF_TIMEOUT     = 30            # seconds per passive sniff window
SNIFF_IFACE       = None          # None = default interface for Scapy

# ─────────────────────────────────────────────
#  DETECTION THRESHOLDS
# ─────────────────────────────────────────────
PORT_SCAN_THRESHOLD    = 15       # unique ports hit in time window → port scan
ARP_FLOOD_THRESHOLD    = 50       # ARP packets/sec from same MAC → flood
DNS_SPOOF_THRESHOLD    = 5        # duplicate DNS answers for same query
MAC_CHANGE_WINDOW      = 300      # seconds; if MAC changes within this → flag
RISK_SCORE_CRITICAL    = 80       # 80–100  → CRITICAL
RISK_SCORE_HIGH        = 60       # 60–79   → HIGH
RISK_SCORE_MEDIUM      = 40       # 40–59   → MEDIUM
RISK_SCORE_LOW         = 0        # 0–39    → LOW

# ─────────────────────────────────────────────
#  ADVANCED DETECTION & ENGINE CONFIG
# ─────────────────────────────────────────────
PACKET_ENGINE_BPF_FILTER = "arp or tcp or udp or icmp"
PACKET_BUFFER_SIZE      = 10485760 # 10MB pcap buffer for extreme packet loads
BEACON_JITTER_THRESHOLD = 0.005    # High variance mapped to floating sec = rogue
DHCP_STARVATION_RATE    = 20       # Discover packets / minute = Starvation
PAYLOAD_ENTROPY_LIMIT   = 7.5      # Shannon entropy above 7.5 is often encrypted/obfuscated

# ─────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR       = os.path.join(BASE_DIR, "data")
LOG_DIR        = os.path.join(BASE_DIR, "logs")
REPORTS_DIR    = os.path.join(BASE_DIR, "reports")
DB_PATH        = os.path.join(DATA_DIR, "rdds.db")
WHITELIST_PATH = os.path.join(DATA_DIR, "whitelist.json")
ALLOWLIST_PATH = os.path.join(DATA_DIR, "allowlist.txt")
OUI_PATH       = os.path.join(DATA_DIR, "oui.json")
ALERT_LOG      = os.path.join(LOG_DIR,  "alerts.log")
SCAN_LOG       = os.path.join(LOG_DIR,  "scans.log")

# ─────────────────────────────────────────────
#  ALERT SETTINGS
# ─────────────────────────────────────────────
ENABLE_EMAIL_ALERTS = False
SMTP_SERVER   = "smtp.gmail.com"
SMTP_PORT     = 587
SMTP_USER     = "your_email@gmail.com"
SMTP_PASSWORD = "your_app_password"
ALERT_TO      = "security_team@company.com"

# ─────────────────────────────────────────────
#  DASHBOARD
# ─────────────────────────────────────────────
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
DASHBOARD_DEBUG = False
MAX_ALERTS_DISPLAY = 200

# ─────────────────────────────────────────────
#  SEVERITY LEVELS
# ─────────────────────────────────────────────
SEV_CRITICAL = "CRITICAL"
SEV_HIGH     = "HIGH"
SEV_MEDIUM   = "MEDIUM"
SEV_LOW      = "LOW"
SEV_INFO     = "INFO"

# ─────────────────────────────────────────────
#  ALERT TYPES
# ─────────────────────────────────────────────
ALERT_NEW_DEVICE      = "NEW_UNKNOWN_DEVICE"
ALERT_MAC_SPOOF       = "MAC_SPOOFING"
ALERT_ROGUE_AP        = "ROGUE_ACCESS_POINT"
ALERT_EVIL_TWIN       = "EVIL_TWIN_AP"
ALERT_ARP_SPOOF       = "ARP_SPOOFING"
ALERT_MITM            = "MITM_DETECTED"
ALERT_PORT_SCAN       = "PORT_SCAN_DETECTED"
ALERT_ARP_FLOOD       = "ARP_FLOOD"
ALERT_DNS_SPOOF       = "DNS_SPOOFING"
ALERT_LATERAL_MOVE    = "LATERAL_MOVEMENT"
ALERT_OPEN_AP         = "OPEN_AP_DETECTED"

# ─────────────────────────────────────────────
#  GATEWAY
# ─────────────────────────────────────────────
def get_local_ip():
    """Get the local IP address of the primary interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_default_gateway():
    """Best-effort default gateway IP detection on Windows."""
    try:
        import subprocess, re
        # Try routing table first (most accurate)
        try:
            out = subprocess.check_output(["route", "print", "0.0.0.0"], text=True, errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "0.0.0.0":
                    return parts[2]
        except:
            pass
        
        # Fallback to ipconfig parsing
        out = subprocess.check_output(["ipconfig"], text=True, errors="ignore", timeout=5)
        m = re.search(r"Default Gateway[^:]*:\s*([\d.]+)", out)
        if m:
            return m.group(1)
            
        return "192.168.1.1" # Generic fallback
    except Exception:
        return "192.168.1.1"

def normalize_iface(iface):
    r"""
    Format interface string for Scapy on Windows.
    Converts raw GUID {XXXX...} strings to \Device\NPF_{XXXX...}
    to prevent 'Error opening adapter (123)'.
    """
    if not iface:
        return iface
    if os.name == 'nt' and isinstance(iface, str):
        iface = iface.strip()
        if iface.startswith('{') and iface.endswith('}'):
            return f"\\Device\\NPF_{iface}"
    return iface

# Ensure directories exist at import time
for _d in [DATA_DIR, LOG_DIR, REPORTS_DIR]:
    os.makedirs(_d, exist_ok=True)
