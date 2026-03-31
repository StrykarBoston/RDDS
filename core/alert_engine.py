"""
RDDS — Alert Engine Module
Handles terminal printing, log writing, and optional email alerts.
"""

import json
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText
from typing import Dict, Optional

from core import database as db

# Lazy import config to avoid circular imports
def _cfg():
    from core import config
    return config

# ─────────────────────────────────────────────
#  TERMINAL COLOR CODES (no external deps)
# ─────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
DIM     = "\033[2m"

SEV_COLORS = {
    "CRITICAL": RED    + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     GREEN,
}

SEV_ICONS = {
    "CRITICAL": "🚨🚨",
    "HIGH":     "🚨",
    "MEDIUM":   "⚠️ ",
    "LOW":      "ℹ️ ",
    "INFO":     "✅",
}

_print_lock = threading.Lock()


# ─────────────────────────────────────────────
#  CORE ALERT DISPATCHER
# ─────────────────────────────────────────────

import time
_recent_alerts = {}
_alert_agg_lock = threading.Lock()
ALERT_AGGREGATION_WINDOW = 30  # seconds

def fire_alert(alert_type: str,
               severity: str,
               description: str,
               device_mac: str  = "",
               device_ip: str   = "",
               raw_data: object = None):
    """
    Central function to raise an RDDS alert.
    Implements Rate Limiting/Aggregation to prevent log spam.
    - Prints color-coded terminal output
    - Writes JSON entry to alerts.log
    - Saves to SQLite
    - Optionally sends email
    """
    # Enforce whitelist for the device
    if device_mac:
        from core.device_manager import is_whitelisted
        if is_whitelisted(device_mac):
            # Do not suppress critical spoofing or threat intel matches
            critical_types = ("MITM_ATTACK", "ARP_SPOOF", "DNS_SPOOF", "THREAT_INTEL_MATCH")
            if alert_type not in critical_types:
                # Silently ignore the alert for trusted devices
                return

    sig = f"{alert_type}_{device_mac}_{device_ip}"
    now_ts = time.time()
    
    with _alert_agg_lock:
        last_fired, suppressed = _recent_alerts.get(sig, (0.0, 0))
        if now_ts - last_fired < ALERT_AGGREGATION_WINDOW:
            _recent_alerts[sig] = (last_fired, suppressed + 1)
            return
            
        if suppressed > 0:
            description = f"[+{suppressed} identical alerts suppressed] " + description
            
        _recent_alerts[sig] = (now_ts, 0)
    cfg  = _cfg()
    now  = datetime.now()
    ts   = now.strftime("%Y-%m-%d %H:%M:%S")

    payload = {
        "timestamp":   ts,
        "alert_type":  alert_type,
        "severity":    severity,
        "description": description,
        "device_mac":  device_mac,
        "device_ip":   device_ip,
        "raw_data":    raw_data or {}
    }

    _print_alert(payload)
    _write_log(payload, cfg.ALERT_LOG)
    db.insert_alert(
        alert_type=alert_type,
        severity=severity,
        description=description,
        device_mac=device_mac,
        device_ip=device_ip,
        raw_data=json.dumps(raw_data or {})
    )

    if cfg.ENABLE_EMAIL_ALERTS and severity in ("CRITICAL", "HIGH"):
        threading.Thread(
            target=_send_email,
            args=(payload, cfg),
            daemon=True
        ).start()


# ─────────────────────────────────────────────
#  TERMINAL PRINTER
# ─────────────────────────────────────────────

def _print_alert(payload: Dict):
    cfg   = _cfg()
    sev   = payload.get("severity", "INFO")
    color = SEV_COLORS.get(sev, WHITE)
    icon  = SEV_ICONS.get(sev, "•")
    ts    = payload.get("timestamp", "")
    atype = payload.get("alert_type", "")
    desc  = payload.get("description", "")
    mac   = payload.get("device_mac", "")
    ip    = payload.get("device_ip",  "")

    with _print_lock:
        print(f"\n{color}{'='*70}{RESET}")
        print(f"{color}{icon}  [{ts}] {sev} ALERT{RESET}")
        print(f"{BOLD}Type    : {RESET}{atype}")
        print(f"{BOLD}Details : {RESET}{desc}")
        if mac:
            print(f"{BOLD}MAC     : {RESET}{mac}")
        if ip:
            print(f"{BOLD}IP      : {RESET}{ip}")
        print(f"{color}{'='*70}{RESET}")


def print_info(message: str):
    ts = datetime.now().strftime("%H:%M:%S")
    with _print_lock:
        print(f"{DIM}[{ts}]{RESET} {GREEN}[INFO]{RESET} {message}")


def print_warn(message: str):
    ts = datetime.now().strftime("%H:%M:%S")
    with _print_lock:
        print(f"{DIM}[{ts}]{RESET} {YELLOW}[WARN]{RESET} {message}")


def print_error(message: str):
    ts = datetime.now().strftime("%H:%M:%S")
    with _print_lock:
        print(f"{DIM}[{ts}]{RESET} {RED}[ERR ]{RESET} {message}")


def print_banner():
    banner = rf"""
{CYAN}{BOLD}
 ██████╗ ██████╗ ██████╗ ███████╗
 ██╔══██╗██╔══██╗██╔══██╗██╔════╝
 ██████╔╝██║  ██║██║  ██║███████╗
 ██╔══██╗██║  ██║██║  ██║╚════██║
 ██║  ██║██████╔╝██████╔╝███████║
 ╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚══════╝
{RESET}{WHITE}  Rogue Device Detection System{RESET}
{DIM}  Enterprise-Grade | v1.0 | by RDDS Team{RESET}
{CYAN}{'─'*40}{RESET}
"""
    print(banner)


# ─────────────────────────────────────────────
#  LOG FILE WRITER
# ─────────────────────────────────────────────

def _write_log(payload: Dict, log_path: str):
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception as e:
        print(f"[!] Log write error: {e}")


# ─────────────────────────────────────────────
#  EMAIL ALERT (OPTIONAL)
# ─────────────────────────────────────────────

def _send_email(payload: Dict, cfg):
    try:
        subject = f"[RDDS ALERT] {payload['severity']} — {payload['alert_type']}"
        body    = (
            f"RDDS Security Alert\n"
            f"{'='*50}\n"
            f"Time      : {payload['timestamp']}\n"
            f"Severity  : {payload['severity']}\n"
            f"Type      : {payload['alert_type']}\n"
            f"Details   : {payload['description']}\n"
            f"Device MAC: {payload['device_mac']}\n"
            f"Device IP : {payload['device_ip']}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = cfg.SMTP_USER
        msg["To"]      = cfg.ALERT_TO

        with smtplib.SMTP(cfg.SMTP_SERVER, cfg.SMTP_PORT) as server:
            server.starttls()
            server.login(cfg.SMTP_USER, cfg.SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"[!] Email alert failed: {e}")
