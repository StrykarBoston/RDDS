"""
RDDS — Database Module
SQLite persistence for devices and alerts.
"""

import sqlite3
import threading
from datetime import datetime
from core.config import DB_PATH

_lock = threading.Lock()


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    try:
        with _lock:
            conn = get_connection()
            c = conn.cursor()
            c.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    mac         TEXT PRIMARY KEY,
                    ip          TEXT,
                    vendor      TEXT,
                    hostname    TEXT,
                    first_seen  TEXT,
                    last_seen   TEXT,
                    risk_score  INTEGER DEFAULT 0,
                    status      TEXT DEFAULT 'unknown',
                    open_ports  TEXT,
                    is_whitelisted INTEGER DEFAULT 0,
                    flags       TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT,
                    alert_type  TEXT,
                    severity    TEXT,
                    description TEXT,
                    device_mac  TEXT,
                    device_ip   TEXT,
                    raw_data    TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT,
                    devices_found INTEGER,
                    new_devices   INTEGER,
                    alerts_raised INTEGER
                );

                CREATE TABLE IF NOT EXISTS iot_profiles (
                    mac          TEXT PRIMARY KEY,
                    ip           TEXT,
                    device_type  TEXT,
                    category     TEXT,
                    iot_risk_score INTEGER DEFAULT 0,
                    severity     TEXT,
                    open_iot_ports TEXT,
                    cve_count    INTEGER DEFAULT 0,
                    profiled_at  TEXT
                );
                
                -- High Performance B-Tree Indexes
                CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
                CREATE INDEX IF NOT EXISTS idx_devices_risk ON devices(risk_score);
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_scan_hist_ts ON scan_history(timestamp);
            """)
            conn.commit()
            conn.close()
    except Exception as e:
        from core.alert_engine import print_error
        print_error(f"Database Initialization Error: {e}")


# ─────────────────────────────────────────────
#  DEVICE OPERATIONS
# ─────────────────────────────────────────────

def upsert_device(mac, ip, vendor="", hostname="", risk_score=0,
                  status="unknown", open_ports="", is_whitelisted=0, flags=""):
    now = datetime.now().isoformat()
    with _lock:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT mac, first_seen FROM devices WHERE mac=?", (mac,))
        row = c.fetchone()
        if row:
            c.execute("""
                UPDATE devices SET ip=?, vendor=?, hostname=?, last_seen=?,
                    risk_score=?, status=?, open_ports=?, is_whitelisted=?, flags=?
                WHERE mac=?
            """, (ip, vendor, hostname, now, risk_score, status,
                  open_ports, is_whitelisted, flags, mac))
        else:
            c.execute("""
                INSERT INTO devices (mac, ip, vendor, hostname, first_seen,
                    last_seen, risk_score, status, open_ports, is_whitelisted, flags)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (mac, ip, vendor, hostname, now, now,
                  risk_score, status, open_ports, is_whitelisted, flags))
        conn.commit()
        conn.close()


def get_all_devices():
    with _lock:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
    return rows


def get_device(mac):
    with _lock:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE mac=?", (mac,))
        row = c.fetchone()
        conn.close()
    return dict(row) if row else None


def delete_device(mac):
    with _lock:
        conn = get_connection()
        conn.execute("DELETE FROM devices WHERE mac=?", (mac,))
        conn.commit()
        conn.close()


def update_risk_score(mac, score):
    with _lock:
        conn = get_connection()
        conn.execute("UPDATE devices SET risk_score=? WHERE mac=?", (score, mac))
        conn.commit()
        conn.close()


def mark_whitelisted(mac, flag: bool):
    with _lock:
        conn = get_connection()
        conn.execute("UPDATE devices SET is_whitelisted=? WHERE mac=?",
                     (1 if flag else 0, mac))
        conn.commit()
        conn.close()


# ─────────────────────────────────────────────
#  ALERT OPERATIONS
# ─────────────────────────────────────────────

def insert_alert(alert_type, severity, description,
                 device_mac="", device_ip="", raw_data=""):
    now = datetime.now().isoformat()
    with _lock:
        conn = get_connection()
        conn.execute("""
            INSERT INTO alerts (timestamp, alert_type, severity,
                description, device_mac, device_ip, raw_data)
            VALUES (?,?,?,?,?,?,?)
        """, (now, alert_type, severity, description,
              device_mac, device_ip, str(raw_data)))
        conn.commit()
        conn.close()


def get_alerts(limit=200):
    with _lock:
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT * FROM alerts ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
    return rows


def get_alert_stats():
    with _lock:
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts GROUP BY severity
        """)
        stats = {row["severity"]: row["count"] for row in c.fetchall()}
        c.execute("SELECT COUNT(*) as total FROM alerts")
        stats["total"] = c.fetchone()["total"]
        c.execute("SELECT COUNT(*) as total FROM devices")
        stats["total_devices"] = c.fetchone()["total"]
        c.execute("SELECT COUNT(*) as total FROM devices WHERE is_whitelisted=0")
        stats["rogue_devices"] = c.fetchone()["total"]
        conn.close()
    return stats


def log_scan(devices_found, new_devices, alerts_raised):
    now = datetime.now().isoformat()
    with _lock:
        conn = get_connection()
        conn.execute("""
            INSERT INTO scan_history (timestamp, devices_found, new_devices, alerts_raised)
            VALUES (?,?,?,?)
        """, (now, devices_found, new_devices, alerts_raised))
        conn.commit()
        conn.close()


def get_scan_history(limit=50):
    with _lock:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
    return rows


# ─────────────────────────────────────────────
#  IoT PROFILE OPERATIONS
# ─────────────────────────────────────────────

def upsert_iot_profile(mac: str, ip: str, profile: dict):
    """Insert or update an IoT device profile."""
    with _lock:
        conn = get_connection()
        conn.execute("""
            INSERT INTO iot_profiles
                (mac, ip, device_type, category, iot_risk_score, severity,
                 open_iot_ports, cve_count, profiled_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(mac) DO UPDATE SET
                ip=excluded.ip,
                device_type=excluded.device_type,
                category=excluded.category,
                iot_risk_score=excluded.iot_risk_score,
                severity=excluded.severity,
                open_iot_ports=excluded.open_iot_ports,
                cve_count=excluded.cve_count,
                profiled_at=excluded.profiled_at
        """, (
            mac, ip,
            profile.get("device_type", ""),
            profile.get("category", ""),
            profile.get("iot_risk_score", 0),
            profile.get("severity", ""),
            profile.get("open_iot_ports", ""),
            profile.get("cve_count", 0),
            profile.get("profiled_at", ""),
        ))
        conn.commit()
        conn.close()


def get_iot_profile(mac: str):
    with _lock:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM iot_profiles WHERE mac=?", (mac,))
        row = c.fetchone()
        conn.close()
    return dict(row) if row else None


def get_all_iot_profiles():
    with _lock:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM iot_profiles ORDER BY iot_risk_score DESC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
    return rows


def clear_all_data():
    """Wipe all security data, devices, and history from the database."""
    with _lock:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM devices")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM scan_history")
            conn.execute("DELETE FROM iot_profiles")
            conn.commit()
            # Vacuumn to rebuild the database file and free space
            conn.execute("VACUUM")
        finally:
            conn.close()
