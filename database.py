import os
import sqlite3
from datetime import datetime, timedelta

from config import DATA_DIR, DB_PATH
from utils import event_fingerprint, now_string

os.makedirs(DATA_DIR, exist_ok=True)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Safer local SQLite behaviour for a console plus background collector.
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _columns(cursor, table):
    cursor.execute(f"PRAGMA table_info({table})")
    return {row["name"] for row in cursor.fetchall()}


def _add_column(cursor, table, name, definition):
    if name not in _columns(cursor, table):
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT NOT NULL DEFAULT 'SYSTEM',
            source TEXT NOT NULL DEFAULT 'Unknown',
            computer TEXT DEFAULT '',
            channel TEXT DEFAULT '',
            event_id INTEGER DEFAULT 0,
            severity TEXT DEFAULT 'INFO',
            message TEXT DEFAULT '',
            raw_event TEXT DEFAULT '',
            record_number INTEGER DEFAULT 0,
            fingerprint TEXT UNIQUE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            threat TEXT NOT NULL,
            message TEXT NOT NULL,
            username TEXT DEFAULT 'SYSTEM',
            source TEXT DEFAULT 'Unknown',
            computer TEXT DEFAULT '',
            event_id INTEGER DEFAULT 0,
            recommendation TEXT DEFAULT '',
            mitre TEXT DEFAULT '',
            alert_key TEXT UNIQUE,
            count INTEGER DEFAULT 1,
            last_seen TEXT
        )
    """)


    cursor.execute("""
        CREATE TABLE IF NOT EXISTS collector_state(
            channel TEXT PRIMARY KEY,
            last_record_number INTEGER DEFAULT 0,
            last_run TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            severity TEXT NOT NULL, title TEXT NOT NULL, body TEXT DEFAULT '',
            alert_id INTEGER, acknowledged INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS console_users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'Viewer', full_name TEXT DEFAULT '',
            email TEXT DEFAULT '', phone TEXT DEFAULT '', created_at TEXT NOT NULL
        )
    """)
    for name, definition in {"full_name":"TEXT DEFAULT ''", "email":"TEXT DEFAULT ''", "phone":"TEXT DEFAULT ''"}.items():
        _add_column(cursor, "console_users", name, definition)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS console_settings(
            setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL
        )
    """)

    for name, definition in {
        "severity": "TEXT DEFAULT 'INFO'",
        "computer": "TEXT DEFAULT ''",
        "channel": "TEXT DEFAULT ''",
        "event_id": "INTEGER DEFAULT 0",
        "message": "TEXT DEFAULT ''",
        "raw_event": "TEXT DEFAULT ''",
        "record_number": "INTEGER DEFAULT 0",
        "fingerprint": "TEXT",
    }.items():
        _add_column(cursor, "logs", name, definition)

    for name, definition in {
        "timestamp": "TEXT",
        "threat": "TEXT DEFAULT ''",
        "username": "TEXT DEFAULT 'SYSTEM'",
        "source": "TEXT DEFAULT 'Unknown'",
        "computer": "TEXT DEFAULT ''",
        "event_id": "INTEGER DEFAULT 0",
        "recommendation": "TEXT DEFAULT ''",
        "mitre": "TEXT DEFAULT ''",
        "alert_key": "TEXT",
        "count": "INTEGER DEFAULT 1",
        "last_seen": "TEXT",
        "status": "TEXT DEFAULT 'Open'",
        "assignee": "TEXT DEFAULT ''",
        "notes": "TEXT DEFAULT ''",
        "category": "TEXT DEFAULT ''",
        "sub_category": "TEXT DEFAULT ''",
        "evidence": "TEXT DEFAULT '{}'",
        "previous_value": "TEXT DEFAULT ''",
        "new_value": "TEXT DEFAULT ''",
        "detected_at": "TEXT DEFAULT ''",
        "event_timestamp": "TEXT DEFAULT ''",
        "confidence": "REAL DEFAULT 0.5",
    }.items():
        _add_column(cursor, "alerts", name, definition)

    # Additive endpoint schema: safe to run against an existing SIEM database.
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS software_inventory (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, version TEXT DEFAULT '', publisher TEXT DEFAULT '',
            install_date TEXT DEFAULT '', install_location TEXT DEFAULT '', architecture TEXT DEFAULT '', source TEXT DEFAULT '',
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(name, version, publisher, architecture));
        CREATE TABLE IF NOT EXISTS software_changes (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, change_type TEXT NOT NULL, name TEXT NOT NULL,
            previous_version TEXT DEFAULT '', current_version TEXT DEFAULT '', details TEXT DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS system_updates (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, os_name TEXT DEFAULT '', os_version TEXT DEFAULT '',
            build_number TEXT DEFAULT '', update_id TEXT DEFAULT '', update_title TEXT DEFAULT '', install_date TEXT DEFAULT '', status TEXT DEFAULT 'UNKNOWN');
        CREATE TABLE IF NOT EXISTS browser_inventory (
            id INTEGER PRIMARY KEY, browser TEXT NOT NULL, installed_version TEXT DEFAULT '', installation_path TEXT DEFAULT '',
            status TEXT DEFAULT 'UNKNOWN', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(browser, installation_path));
        CREATE TABLE IF NOT EXISTS system_settings (
            setting_key TEXT PRIMARY KEY, setting_value TEXT DEFAULT 'UNKNOWN', last_seen TEXT NOT NULL, source TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS system_setting_changes (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, setting_key TEXT NOT NULL, previous_value TEXT DEFAULT '', new_value TEXT DEFAULT '', source TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS usb_devices (
            id INTEGER PRIMARY KEY, device_id TEXT UNIQUE NOT NULL, serial_number TEXT DEFAULT '', manufacturer TEXT DEFAULT '',
            product_name TEXT DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, connection_count INTEGER DEFAULT 0, approved TEXT DEFAULT 'Unknown');
        CREATE TABLE IF NOT EXISTS usb_events (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, device_id TEXT DEFAULT '', serial_number TEXT DEFAULT '',
            manufacturer TEXT DEFAULT '', product_name TEXT DEFAULT '', username TEXT DEFAULT 'SYSTEM', computer TEXT DEFAULT '', event_id INTEGER DEFAULT 0, source TEXT DEFAULT '', details TEXT DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS endpoint_snapshots (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, snapshot_type TEXT NOT NULL, data TEXT NOT NULL, status TEXT DEFAULT 'UNKNOWN');
        CREATE TABLE IF NOT EXISTS hardware_inventory (
            device_id TEXT PRIMARY KEY, device_name TEXT DEFAULT '', manufacturer TEXT DEFAULT '',
            driver_version TEXT DEFAULT '', driver_date TEXT DEFAULT '', is_signed TEXT DEFAULT 'UNKNOWN', last_seen TEXT NOT NULL,
            missing_since TEXT DEFAULT '', missing_count INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS hardware_changes (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, device_id TEXT NOT NULL, device_name TEXT DEFAULT '',
            change_type TEXT NOT NULL, previous_value TEXT DEFAULT '', new_value TEXT DEFAULT '', severity TEXT DEFAULT 'MEDIUM');
        CREATE TABLE IF NOT EXISTS network_flow_baselines (
            interface_name TEXT PRIMARY KEY, timestamp TEXT NOT NULL, received_bytes INTEGER NOT NULL DEFAULT 0,
            sent_bytes INTEGER NOT NULL DEFAULT 0, received_packets INTEGER NOT NULL DEFAULT 0, sent_packets INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_usb_events_timestamp ON usb_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_setting_changes_timestamp ON system_setting_changes(timestamp);
        CREATE INDEX IF NOT EXISTS idx_software_changes_timestamp ON software_changes(timestamp);
        CREATE INDEX IF NOT EXISTS idx_hardware_changes_timestamp ON hardware_changes(timestamp);
    """)
    for name, definition in {
        "missing_since": "TEXT DEFAULT ''",
        "missing_count": "INTEGER DEFAULT 0",
    }.items():
        _add_column(cursor, "hardware_inventory", name, definition)

    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(username)",
        "CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)",
        "CREATE INDEX IF NOT EXISTS idx_logs_event_id ON logs(event_id)",
        "CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_fingerprint ON logs(fingerprint)",
        "CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity)",
        "CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts(timestamp)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_key ON alerts(alert_key)",
    ]
    for statement in indexes:
        cursor.execute(statement)

    cursor.execute("UPDATE logs SET severity='INFO' WHERE severity IS NULL OR severity=''")
    cursor.execute("UPDATE alerts SET timestamp=? WHERE timestamp IS NULL OR timestamp=''", (now_string(),))
    cursor.execute("UPDATE alerts SET username='SYSTEM' WHERE username IS NULL OR username=''")
    cursor.execute("UPDATE alerts SET source='Unknown' WHERE source IS NULL OR source=''")
    cursor.execute("UPDATE alerts SET threat = message WHERE threat = '' OR threat IS NULL")
    cursor.execute("UPDATE alerts SET last_seen = timestamp WHERE last_seen IS NULL OR last_seen=''")
    cursor.execute("UPDATE alerts SET status='Open' WHERE status IS NULL OR status=''")
    # Reclassify historical service-install events: 7045 alone is not HIGH.
    cursor.execute("UPDATE logs SET severity='MEDIUM' WHERE event_id IN (4697,7045) AND severity='HIGH'")
    cursor.execute("UPDATE logs SET severity='LOW' WHERE event_id IN (4697,7045) AND (lower(message) LIKE '%\\program files\\mcafee\\%' OR lower(message) LIKE '%microsoft defender%')")
    cursor.execute("UPDATE logs SET severity='HIGH' WHERE event_id IN (4697,7045) AND (lower(message) LIKE '%\\appdata\\%' OR lower(message) LIKE '%\\temp\\%' OR lower(message) LIKE '%powershell%')")

    conn.commit()
    conn.close()


def count_console_users():
    conn = get_connection(); count = conn.execute("SELECT COUNT(*) FROM console_users").fetchone()[0]; conn.close(); return count


def create_console_user(username, password_hash, role="Viewer", full_name="", email="", phone=""):
    conn = get_connection(); conn.execute("INSERT INTO console_users(username,password_hash,role,full_name,email,phone,created_at) VALUES(?,?,?,?,?,?,?)", (username, password_hash, role, full_name, email, phone, now_string())); conn.commit(); conn.close()


def get_console_user(username):
    conn = get_connection(); row = conn.execute("SELECT * FROM console_users WHERE username=?", (username,)).fetchone(); conn.close(); return row


def get_console_users():
    conn = get_connection(); rows = conn.execute("SELECT id,username,role,full_name,email,phone,created_at FROM console_users ORDER BY id").fetchall(); conn.close(); return rows


def delete_console_user(user_id):
    conn = get_connection(); conn.execute("DELETE FROM console_users WHERE id=?", (user_id,)); conn.commit(); conn.close()


def get_console_settings():
    conn = get_connection(); rows = conn.execute("SELECT setting_key,setting_value FROM console_settings").fetchall(); conn.close(); return {row["setting_key"]: row["setting_value"] for row in rows}


def save_console_settings(values):
    conn = get_connection()
    for key, value in values.items():
        conn.execute("INSERT INTO console_settings(setting_key,setting_value) VALUES(?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value", (key, str(value)))
    conn.commit(); conn.close()


def insert_log(timestamp, event_type, username, source, severity="INFO", computer="", channel="", event_id=0, message="", raw_event="", record_number=0):
    fingerprint = event_fingerprint(timestamp, event_type, username, source, computer, event_id, record_number)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO logs(
            timestamp, event_type, username, source, severity, computer, channel,
            event_id, message, raw_event, record_number, fingerprint
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    """, (timestamp, event_type, username, source, severity, computer, channel, event_id, message, raw_event, record_number, fingerprint))
    inserted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return inserted


def insert_alert(severity, message, username="SYSTEM", source="Unknown", recommendation="", threat=None, computer="", event_id=0, mitre="", alert_key=None, timestamp=None, category="", sub_category="", evidence="{}", previous_value="", new_value="", confidence=0.5, event_timestamp=""):
    timestamp = timestamp or now_string()
    detected_at = now_string()
    threat = threat or message
    alert_key = alert_key or event_fingerprint(threat, username, source, computer, event_id)
    conn = get_connection()
    cursor = conn.cursor()
    existing = cursor.execute("SELECT id FROM alerts WHERE alert_key=?", (alert_key,)).fetchone()
    cursor.execute("""
        INSERT INTO alerts(
            timestamp, severity, threat, message, username, source, computer,
            event_id, recommendation, mitre, alert_key, count, last_seen, category, sub_category, evidence, previous_value, new_value, detected_at, event_timestamp, confidence
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(alert_key) DO UPDATE SET
            -- Re-reading the same Windows record on a page refresh must not
            -- inflate the incident count or make it look newly detected.
            count = alerts.count,
            last_seen = alerts.last_seen,
            severity = excluded.severity,
            recommendation = excluded.recommendation,
            mitre = excluded.mitre, evidence = excluded.evidence, confidence = excluded.confidence
    """, (timestamp, severity, threat, message, username, source, computer, event_id, recommendation, mitre, alert_key, timestamp, category, sub_category, evidence, previous_value, new_value, detected_at, event_timestamp or timestamp, confidence))
    cursor.execute("SELECT * FROM alerts WHERE alert_key=?", (alert_key,))
    row = dict(cursor.fetchone())
    if existing is None and severity in {"MEDIUM", "HIGH", "CRITICAL"}:
        cursor.execute("INSERT INTO notifications(timestamp, severity, title, body, alert_id) VALUES(?,?,?,?,?)",
            (timestamp, severity, threat, message, row["id"]))
    row["is_new"] = existing is None
    conn.commit()
    conn.close()
    return row


def _query_logs(where="", params=(), limit=250, offset=0):
    conn = get_connection()
    query = f"SELECT * FROM logs {where} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
    rows = conn.execute(query, (*params, limit, offset)).fetchall()
    conn.close()
    return rows


def get_logs(limit=250, offset=0):
    return _query_logs(limit=limit, offset=offset)


def search_logs(keyword="", severity="", minimum_severity="", username="", source="", event_type="", date_from="", date_to="", limit=250, offset=0):
    clauses = ["1=1"]
    params = []
    if keyword:
        like = f"%{keyword}%"
        clauses.append("(event_type LIKE ? OR username LIKE ? OR source LIKE ? OR computer LIKE ? OR message LIKE ? OR raw_event LIKE ?)")
        params.extend([like] * 6)
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    elif minimum_severity:
        ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        allowed = [name for name, rank in ranks.items() if rank >= ranks.get(minimum_severity, 0)]
        clauses.append("severity IN (%s)" % ",".join("?" for _ in allowed))
        params.extend(allowed)
    if username:
        clauses.append("username LIKE ?")
        params.append(f"%{username}%")
    if source:
        clauses.append("(source LIKE ? OR computer LIKE ? OR channel LIKE ?)")
        params.extend([f"%{source}%"] * 3)
    if event_type:
        clauses.append("(event_type LIKE ? OR event_id=?)")
        params.extend([f"%{event_type}%", int(event_type) if str(event_type).isdigit() else -1])
    if date_from:
        clauses.append("timestamp>=?")
        params.append(date_from)
    if date_to:
        clauses.append("timestamp<=?")
        params.append(date_to)
    return _query_logs("WHERE " + " AND ".join(clauses), params, limit, offset)


def filter_logs(severity=None, source=None):
    return search_logs(severity=severity or "", source=source or "")


def get_alerts(limit=250):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY last_seen DESC, timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def search_alerts(keyword="", severity="", username="", source=""):
    conn = get_connection()
    clauses = ["1=1"]
    params = []
    if keyword:
        like = f"%{keyword}%"
        clauses.append("(threat LIKE ? OR message LIKE ? OR recommendation LIKE ? OR username LIKE ? OR source LIKE ?)")
        params.extend([like] * 5)
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    if username:
        clauses.append("username LIKE ?")
        params.append(f"%{username}%")
    if source:
        clauses.append("(source LIKE ? OR computer LIKE ?)")
        params.extend([f"%{source}%"] * 2)
    rows = conn.execute("SELECT * FROM alerts WHERE " + " AND ".join(clauses) + " ORDER BY last_seen DESC", params).fetchall()
    conn.close()
    return rows


def get_users():
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            l.username,
            COUNT(l.id) AS event_count,
            MAX(l.timestamp) AS last_activity,
            COALESCE(a.threat_count, 0) AS threat_count,
            SUM(CASE l.severity WHEN 'CRITICAL' THEN 12 WHEN 'HIGH' THEN 8 WHEN 'MEDIUM' THEN 4 WHEN 'LOW' THEN 2 ELSE 1 END)
                + COALESCE(a.threat_count, 0) * 5 AS risk_score
        FROM logs l
        LEFT JOIN (
            SELECT username, COUNT(*) AS threat_count
            FROM alerts
            GROUP BY username
        ) a ON a.username = l.username
        WHERE lower(l.username) NOT IN ('unknown','application-specific','machine-default','0','-')
        GROUP BY l.username
        ORDER BY risk_score DESC, event_count DESC
    """).fetchall()
    conn.close()
    return rows


def get_systems():
    conn = get_connection()
    rows = conn.execute("""
        SELECT COALESCE(NULLIF(computer,''), source) AS hostname, MAX(source) AS source,
               MAX(timestamp) AS last_seen, MAX(username) AS username, COUNT(*) AS event_count,
               SUM(CASE WHEN severity IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) AS high_events
        FROM logs GROUP BY COALESCE(NULLIF(computer,''), source) ORDER BY last_seen DESC
    """).fetchall()
    conn.close()
    return rows


def get_active_sessions():
    conn = get_connection()
    rows = conn.execute("SELECT username, COALESCE(NULLIF(computer,''), source) AS hostname, timestamp, event_id, event_type FROM logs WHERE event_id IN (4624,4634,4647) OR event_type LIKE '%Login%' OR event_type LIKE '%Logoff%' ORDER BY id DESC").fetchall()
    conn.close()
    sessions = {}
    for row in rows:
        key = (row["username"], row["hostname"])
        if key not in sessions:
            is_logon = row["event_id"] == 4624 or "login" in row["event_type"].lower()
            sessions[key] = {"username":row["username"], "hostname":row["hostname"], "login_time":row["timestamp"] if is_logon else "Unknown", "last_seen":row["timestamp"], "status":"Active" if is_logon else "Signed out"}
        elif sessions[key]["login_time"] == "Unknown" and (row["event_id"] == 4624 or "login" in row["event_type"].lower()):
            sessions[key]["login_time"] = row["timestamp"]
    return sorted(sessions.values(), key=lambda item: item["last_seen"], reverse=True)


def get_notifications(limit=20):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM notifications WHERE acknowledged=0 ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def acknowledge_notification(notification_id):
    conn = get_connection(); conn.execute("UPDATE notifications SET acknowledged=1 WHERE id=?", (notification_id,)); conn.commit(); conn.close()


def update_alert_case(alert_id, status, assignee, notes):
    conn = get_connection(); conn.execute("UPDATE alerts SET status=?, assignee=?, notes=? WHERE id=?", (status, assignee, notes, alert_id)); conn.commit(); conn.close()


def get_firewall_statistics():
    conn = get_connection()
    stats = {
        "allowed": conn.execute("SELECT COUNT(*) FROM logs WHERE event_id=5156 OR event_type LIKE '%Firewall Allowed%' ").fetchone()[0],
        "blocked": conn.execute("SELECT COUNT(*) FROM logs WHERE event_id=5157 OR event_type LIKE '%Firewall Block%' OR message LIKE '%blocked%' ").fetchone()[0],
        "rules": conn.execute("SELECT COUNT(DISTINCT source) FROM logs WHERE event_type LIKE '%Firewall%' ").fetchone()[0],
    }
    conn.close(); return stats


def get_firewall_events(limit=100):
    """Return genuine Windows firewall/WFP events, not product-name matches."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM logs
        WHERE event_id IN (4946,4947,4948,4949,4950,4951,5152,5153,5154,5155,5156,5157,5158)
           OR event_type IN ('Firewall Allowed Connection','Firewall Blocked Connection','Firewall Bound Port')
        ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return rows


def get_dashboard_totals():
    conn = get_connection()
    totals = {
        "logs": conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "users": conn.execute("SELECT COUNT(DISTINCT username) FROM logs WHERE lower(username) NOT IN ('unknown','application-specific','machine-default','0','-')").fetchone()[0],
        "sources": conn.execute("SELECT COUNT(DISTINCT COALESCE(NULLIF(computer,''), source)) FROM logs").fetchone()[0],
    }
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        totals[f"{severity.lower()}_alerts"] = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity=?", (severity,)).fetchone()[0]
    conn.close()
    return totals


def get_alert_statistics():
    conn = get_connection()
    rows = conn.execute("SELECT severity, COUNT(*) AS total FROM alerts GROUP BY severity").fetchall()
    conn.close()
    return rows


def get_severity_statistics():
    conn = get_connection()
    rows = conn.execute("SELECT severity, COUNT(*) AS total FROM logs GROUP BY severity ORDER BY total DESC").fetchall()
    conn.close()
    return rows


def get_event_statistics(limit=10):
    conn = get_connection()
    rows = conn.execute("SELECT event_type, COUNT(*) AS total FROM logs GROUP BY event_type ORDER BY total DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def get_top_users(limit=10):
    conn = get_connection()
    rows = conn.execute("""
        SELECT username, COUNT(*) AS total
        FROM logs
        WHERE lower(username) NOT IN ('unknown','application-specific','machine-default','0','-')
        GROUP BY username
        ORDER BY total DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return rows


def get_top_sources(limit=10):
    conn = get_connection()
    rows = conn.execute("""
        SELECT COALESCE(NULLIF(computer,''), source) AS source, COUNT(*) AS total
        FROM logs
        GROUP BY COALESCE(NULLIF(computer,''), source)
        ORDER BY total DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return rows


def get_threat_statistics(limit=10):
    conn = get_connection()
    rows = conn.execute("""SELECT threat, COUNT(*) AS total,
        MAX(COALESCE(event_timestamp, last_seen, timestamp)) AS last_event,
        CASE MAX(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END)
        WHEN 4 THEN 'CRITICAL' WHEN 3 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' WHEN 1 THEN 'LOW' ELSE 'INFO' END AS severity
        FROM alerts GROUP BY threat ORDER BY total DESC LIMIT ?""", (limit,)).fetchall()
    conn.close()
    return rows


def get_threat_trend(days=7):
    conn = get_connection()
    start = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    rows = conn.execute("""
        SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS total
        FROM alerts
        WHERE substr(timestamp, 1, 10) >= ?
        GROUP BY day
        ORDER BY day
    """, (start,)).fetchall()
    conn.close()
    return rows


def get_log_trend(days=7):
    """Return the most recent observed log days, including legacy Windows timestamp formats.

    Windows Event Log timestamps already stored by older versions use strings such as
    ``Tue Jul  7 22:46:32 2026`` rather than ISO dates, so SQL string comparisons
    cannot reliably build a historical trend from them.
    """
    conn = get_connection()
    rows = conn.execute("SELECT timestamp FROM logs").fetchall()
    conn.close()
    counts = {}
    for row in rows:
        raw = row["timestamp"] or ""
        parsed = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%a %b %d %H:%M:%S %Y"):
            try:
                parsed = datetime.strptime(raw[:19] if fmt.startswith("%Y") else raw, fmt)
                break
            except ValueError:
                continue
        if parsed:
            day = parsed.date().isoformat()
            counts[day] = counts.get(day, 0) + 1
    if not counts:
        return []
    selected_days = sorted(counts)[-days:]
    return [{"day": day, "total": counts[day]} for day in selected_days]


def get_hourly_events():
    conn = get_connection()
    rows = conn.execute("""
        SELECT substr(timestamp, 12, 2) AS hour, COUNT(*) AS total
        FROM logs
        WHERE length(timestamp) >= 13
        GROUP BY hour
        ORDER BY hour
    """).fetchall()
    conn.close()
    return rows


def get_login_summary():
    conn = get_connection()
    success = conn.execute("SELECT COUNT(*) FROM logs WHERE event_type LIKE '%SUCCESS%' OR event_id=4624").fetchone()[0]
    failed = conn.execute("SELECT COUNT(*) FROM logs WHERE event_type LIKE '%FAILED%' OR event_id=4625").fetchone()[0]
    conn.close()
    return {"success": success, "failed": failed}


def get_collector_status():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM collector_state ORDER BY channel").fetchall()
    conn.close()
    return rows


def update_collector_state(channel, last_record_number):
    conn = get_connection()
    conn.execute("""
        INSERT INTO collector_state(channel, last_record_number, last_run)
        VALUES(?,?,?)
        ON CONFLICT(channel) DO UPDATE SET
            last_record_number=MAX(collector_state.last_record_number, excluded.last_record_number),
            last_run=excluded.last_run
    """, (channel, last_record_number or 0, now_string()))
    conn.commit()
    conn.close()


def database_info():
    totals = get_dashboard_totals()
    return totals


def reset_demo_database():
    conn = get_connection()
    cursor = conn.cursor()
    for table in ("logs", "alerts", "notifications", "collector_state"):
        cursor.execute(f"DELETE FROM {table}")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name=?", (table,))
    conn.commit()
    conn.close()


def clear_logs(reset_ids=True):
    conn = get_connection()
    conn.execute("DELETE FROM logs")
    if reset_ids:
        conn.execute("DELETE FROM sqlite_sequence WHERE name='logs'")
    conn.commit()
    conn.close()


def clear_alerts(reset_ids=True):
    conn = get_connection()
    conn.execute("DELETE FROM alerts")
    if reset_ids:
        conn.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
    conn.commit()
    conn.close()


def close_database():
    pass


def save_snapshot(snapshot_type, data, status="UNKNOWN"):
    import json
    conn = get_connection(); conn.execute("INSERT INTO endpoint_snapshots(timestamp,snapshot_type,data,status) VALUES(?,?,?,?)", (now_string(), snapshot_type, json.dumps(data, default=str), status)); conn.commit(); conn.close()


def get_latest_snapshot(snapshot_type):
    import json
    conn = get_connection(); row = conn.execute("SELECT * FROM endpoint_snapshots WHERE snapshot_type=? ORDER BY id DESC LIMIT 1", (snapshot_type,)).fetchone(); conn.close()
    if not row: return None
    data = dict(row)
    try: data["data"] = json.loads(data["data"])
    except (ValueError, TypeError): data["data"] = {}
    return data


def upsert_setting(setting_key, setting_value, source="endpoint"):
    conn = get_connection(); old = conn.execute("SELECT setting_value FROM system_settings WHERE setting_key=?", (setting_key,)).fetchone(); changed = old is not None and old["setting_value"] != str(setting_value)
    if changed: conn.execute("INSERT INTO system_setting_changes(timestamp,setting_key,previous_value,new_value,source) VALUES(?,?,?,?,?)", (now_string(), setting_key, old["setting_value"], str(setting_value), source))
    conn.execute("INSERT INTO system_settings(setting_key,setting_value,last_seen,source) VALUES(?,?,?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,last_seen=excluded.last_seen,source=excluded.source", (setting_key, str(setting_value), now_string(), source)); conn.commit(); conn.close()
    return old["setting_value"] if changed else None


def upsert_usb_device(device):
    conn = get_connection(); old = conn.execute("SELECT * FROM usb_devices WHERE device_id=?", (device["device_id"],)).fetchone(); now = now_string()
    conn.execute("INSERT INTO usb_devices(device_id,serial_number,manufacturer,product_name,first_seen,last_seen,connection_count) VALUES(?,?,?,?,?,?,1) ON CONFLICT(device_id) DO UPDATE SET serial_number=excluded.serial_number,manufacturer=excluded.manufacturer,product_name=excluded.product_name,last_seen=excluded.last_seen,connection_count=usb_devices.connection_count+1", (device["device_id"], device.get("serial_number", ""), device.get("manufacturer", ""), device.get("product_name", ""), now, now)); conn.commit(); conn.close()
    return dict(old) if old else None


def record_usb_event(event):
    import json
    conn = get_connection(); conn.execute("INSERT INTO usb_events(timestamp,event_type,device_id,serial_number,manufacturer,product_name,username,computer,event_id,source,details) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (event["timestamp"], event["event_type"], event.get("device_id", ""), event.get("serial_number", ""), event.get("manufacturer", ""), event.get("product_name", ""), event.get("username", "SYSTEM"), event.get("computer", ""), event.get("event_id", 0), event.get("source", ""), json.dumps(event.get("details", {})))); conn.commit(); conn.close()


def endpoint_data():
    conn = get_connection()
    data = {"software": conn.execute("SELECT * FROM software_inventory ORDER BY name").fetchall(), "software_changes": conn.execute("SELECT * FROM software_changes ORDER BY id DESC LIMIT 100").fetchall(), "updates": conn.execute("SELECT * FROM system_updates ORDER BY id DESC LIMIT 100").fetchall(), "browsers": conn.execute("SELECT * FROM browser_inventory ORDER BY browser").fetchall(), "settings": conn.execute("SELECT * FROM system_settings ORDER BY setting_key").fetchall(), "setting_changes": conn.execute("SELECT * FROM system_setting_changes ORDER BY id DESC LIMIT 100").fetchall(), "usb_devices": conn.execute("SELECT * FROM usb_devices ORDER BY last_seen DESC").fetchall(), "usb_events": conn.execute("SELECT * FROM usb_events ORDER BY id DESC LIMIT 200").fetchall(), "hardware": conn.execute("SELECT * FROM hardware_inventory ORDER BY device_name LIMIT 500").fetchall(), "hardware_changes": conn.execute("SELECT * FROM hardware_changes ORDER BY id DESC LIMIT 100").fetchall()}
    conn.close(); return data


if __name__ == "__main__":
    initialize_database()
    print(database_info())
