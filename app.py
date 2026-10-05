import hmac
import platform
import sys
import threading
import time

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from flask_socketio import SocketIO
except ImportError:  # The dashboard remains usable if Socket.IO is not installed yet.
    SocketIO = None

from collector import collect_windows_logs
from database import (
    acknowledge_notification, get_active_sessions, get_alert_statistics, get_alerts,
    get_collector_status, get_dashboard_totals, get_event_statistics, get_firewall_statistics, get_firewall_events,
    get_hourly_events, get_login_summary, get_logs, get_notifications, get_severity_statistics,
    get_systems, get_threat_statistics, get_threat_trend, get_log_trend, get_top_sources, get_top_users,
    initialize_database, search_alerts, search_logs, update_alert_case, count_console_users,
    create_console_user, get_console_user, get_console_users, delete_console_user,
    get_console_settings, save_console_settings, endpoint_data, get_latest_snapshot,
    insert_log,
)
from detector import detect_threats
from correlation_engine import correlate_recent_alerts
from endpoint_monitor import run_endpoint_scan
from severity_policy import explain_event
from firewall_monitor import get_firewall_profiles
from recommendations import get_recommendation
from report_generator import rows_to_csv, rows_to_pdf
from port_monitor import get_open_ports
from packet_monitor import collect_packet_flow
from active_user_monitor import get_live_windows_users
from config import (BACKGROUND_MONITORING, ENDPOINT_INVENTORY_INTERVAL_SECONDS,
                    EVENT_LOG_INTERVAL_SECONDS, HOST, INGEST_API_KEY, PORT,
                    REQUIRE_LOGIN, SECRET_KEY)
from storage_security import protect_database_file

app = Flask(__name__)
if REQUIRE_LOGIN and SECRET_KEY == "siem-local-console":
    raise RuntimeError("Set a long SIEM_SECRET_KEY before using SIEM_REQUIRE_LOGIN=1.")
app.config["SECRET_KEY"] = SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins=[f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"]) if SocketIO else None
initialize_database()
protect_database_file()


@app.before_request
def require_login():
    # The classroom standalone mode is intentionally local/no-login.  A network
    # deployment can enable authentication without changing the project files.
    if not REQUIRE_LOGIN:
        return None
    if request.endpoint in {"static", "setup", "login", "logout", "ingest_events"}:
        return None
    if not count_console_users():
        return redirect(url_for("setup"))
    if session.get("user_id"):
        return None
    return redirect(url_for("login", next=request.full_path))


def _admin_allowed():
    return not REQUIRE_LOGIN or session.get("role") == "Admin"


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if not REQUIRE_LOGIN:
        return redirect(url_for("dashboard"))
    if count_console_users(): return redirect(url_for("login"))
    if request.method == "POST":
        username, password = request.form.get("username", "").strip(), request.form.get("password", "")
        if len(username) < 3 or len(password) < 10 or password != request.form.get("confirm_password", ""):
            flash("Use a username of at least 3 characters, a 10-character password, and matching confirmation.")
        else:
            create_console_user(username, generate_password_hash(password), "Admin", request.form.get("full_name", "").strip(), request.form.get("email", "").strip(), request.form.get("phone", "").strip())
            session.update({"user_id": username, "role": "Admin", "name": request.form.get("full_name", "").strip() or username})
            return redirect(url_for("dashboard"))
    return render_template("setup.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if not REQUIRE_LOGIN:
        return redirect(url_for("dashboard"))
    # Network deployments are provisioned by an administrator in Settings.
    if not _admin_allowed():
        return redirect(url_for("login"))
    if request.method == "POST":
        username, password = request.form.get("username", "").strip(), request.form.get("password", "")
        if len(username) < 3 or len(password) < 10 or password != request.form.get("confirm_password", ""):
            flash("Check the username and password confirmation.")
        else:
            try:
                create_console_user(username, generate_password_hash(password), "Viewer", request.form.get("full_name", "").strip(), request.form.get("email", "").strip(), request.form.get("phone", "").strip())
                flash("Account created. Please sign in."); return redirect(url_for("login"))
            except Exception: flash("That username already exists.")
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not REQUIRE_LOGIN:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        user = get_console_user(request.form.get("username", "").strip())
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.update({"user_id": user["username"], "role": user["role"], "name": user["full_name"] or user["username"]})
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("dashboard"))

@app.post("/session-end")
def session_end():
    session.clear(); return ("", 204)


def refresh_pipeline():
    collection = collect_windows_logs()
    packet_flow = collect_packet_flow()
    logs = get_logs(500)
    generated = detect_threats(logs)
    generated += correlate_recent_alerts()
    if socketio:
        socketio.emit("dashboard_update", dashboard_payload())
    return {"collection": collection, "packet_flow": packet_flow, "alerts_generated": generated}


def _background_monitor_loop():
    """Continuously collect local evidence without relying on page refreshes."""
    next_endpoint_scan = 0.0
    while True:
        try:
            refresh_pipeline()
            now = time.monotonic()
            if platform.system() == "Windows" and now >= next_endpoint_scan:
                run_endpoint_scan()
                next_endpoint_scan = now + max(60, ENDPOINT_INVENTORY_INTERVAL_SECONDS)
        except Exception as exc:  # Keep a local education console running after a transient Windows API error.
            print(f"SIEM background monitor error: {exc}")
        time.sleep(max(5, EVENT_LOG_INTERVAL_SECONDS))


def start_background_monitoring():
    if not BACKGROUND_MONITORING:
        return
    thread = threading.Thread(target=_background_monitor_loop, name="siem-background-monitor", daemon=True)
    thread.start()


def chart_pair(rows, label_key, value_key="total"):
    return {"labels": [row[label_key] for row in rows], "values": [row[value_key] for row in rows]}


def _trend_days(value):
    try:
        return max(1, min(int(value), 90))
    except (TypeError, ValueError):
        return 7


def dashboard_payload(days=7):
    return {
        "totals": get_dashboard_totals(), "log_trend": chart_pair(get_log_trend(days), "day"),
        "severity": chart_pair(get_alert_statistics(), "severity"),
        "top_sources": chart_pair(get_top_sources(8), "source"),
        "events": chart_pair(get_event_statistics(8), "event_type"),
        "notifications": [dict(row) for row in get_notifications(8)],
    }


@app.route("/")
def dashboard():
    days = _trend_days(request.args.get("days", 7))
    # First use establishes the local endpoint baseline.  Later collection is
    # performed by the background monitor rather than by opening this page.
    if platform.system() == "Windows" and not get_latest_snapshot("endpoint_scan"):
        run_endpoint_scan()
    return render_template("dashboard.html", totals=get_dashboard_totals(), logs=get_logs(12), alerts=get_alerts(8),
        collector_status=get_collector_status(), log_trend=chart_pair(get_log_trend(days), "day"), trend_days=days,
        severity_chart=chart_pair(get_alert_statistics(), "severity"), top_sources=chart_pair(get_top_sources(8), "source"),
        event_chart=chart_pair(get_event_statistics(8), "event_type"), notifications=get_notifications(6))


def endpoint_view(title, section=None):
    data = endpoint_data()
    return render_template("security.html", title=title, data=data, scan=get_latest_snapshot("endpoint_scan"), section=section)


@app.route("/security")
@app.route("/security-posture")
def security_posture_page(): return endpoint_view("Endpoint Security Posture")

@app.route("/software")
def software_page(): return endpoint_view("Software Inventory", "software")

@app.route("/software/changes")
def software_changes_page(): return endpoint_view("Software Changes", "software_changes")

@app.route("/updates")
def updates_page(): return endpoint_view("OS Updates", "updates")

@app.route("/browsers")
def browsers_page(): return endpoint_view("Browser Security", "browsers")

@app.route("/system-changes")
def system_changes_page(): return endpoint_view("System Changes", "settings")

@app.route("/usb")
@app.route("/usb/timeline")
def usb_page(): return endpoint_view("USB Activity", "usb")

@app.route("/time-integrity")
def time_integrity_page(): return render_template("alerts.html", alerts=search_alerts(keyword="SYSTEM_"), recommendations={}, filters={})

@app.post("/endpoint/scan")
def endpoint_scan():
    if not _admin_allowed():
        flash("Only an administrator can start an endpoint scan in protected mode.")
        return redirect(url_for("security_posture_page"))
    run_endpoint_scan()
    return redirect(url_for("security_posture_page"))

@app.route("/logs")
def logs_page():
    minimum_severity = request.args.get("minimum_severity", "MEDIUM")
    logs = search_logs(keyword=request.args.get("q", ""), severity=request.args.get("severity", ""), minimum_severity=minimum_severity,
        username=request.args.get("username", ""), source=request.args.get("source", ""),
        event_type=request.args.get("event_type", ""), date_from=request.args.get("date_from", ""),
        date_to=request.args.get("date_to", ""), limit=250)
    logs = [dict(log, explanation=explain_event(dict(log))) for log in logs]
    filters = request.args.to_dict(); filters.setdefault("minimum_severity", minimum_severity)
    return render_template("logs.html", logs=logs, filters=filters)


@app.route("/alerts")
def alerts_page():
    alerts = search_alerts(keyword=request.args.get("q", ""), severity=request.args.get("severity", ""),
        username=request.args.get("username", ""), source=request.args.get("source", ""))
    return render_template("alerts.html", alerts=alerts, recommendations={a["id"]: get_recommendation(a["threat"]) for a in alerts}, filters=request.args)


@app.post("/alerts/<int:alert_id>")
def update_alert(alert_id):
    update_alert_case(alert_id, request.form.get("status", "Open"), request.form.get("assignee", ""), request.form.get("notes", ""))
    if socketio: socketio.emit("dashboard_update", dashboard_payload())
    return redirect(url_for("alerts_page"))


@app.route("/analytics")
def analytics_page():
    return render_template("analytics.html", totals=get_dashboard_totals(), threat_trend=chart_pair(get_threat_trend(30), "day"),
        severity_distribution=chart_pair(get_alert_statistics(), "severity"), user_activity=chart_pair(get_top_users(10), "username"),
        hourly_events=chart_pair(get_hourly_events(), "hour"), event_types=chart_pair(get_event_statistics(10), "event_type"),
        top_sources=chart_pair(get_top_sources(10), "source"), threat_stats=chart_pair(get_threat_statistics(10), "threat"))


@app.route("/users")
def users_page():
    return render_template("users.html", systems=get_systems(), totals=get_dashboard_totals())


@app.route("/active-users")
def active_users_page():
    live = get_live_windows_users()
    observed = [dict(item, source="Collected Windows event", access="Historical event (role unavailable)") for item in get_active_sessions()]
    live_keys = {(item["username"].lower(), item["hostname"].lower()) for item in live}
    sessions = live + [item for item in observed if (item["username"].lower(), item["hostname"].lower()) not in live_keys]
    return render_template("active_users.html", sessions=sessions)


@app.route("/firewall")
def firewall_page():
    return render_template("firewall.html", stats=get_firewall_statistics(), events=get_firewall_events(100), controls=get_firewall_profiles())

@app.route("/ports")
def ports_page():
    return render_template("ports.html", ports=get_open_ports())


@app.route("/system-info")
def system_info_page():
    return render_template("system_info.html", info={"hostname": platform.node(), "os": platform.platform(), "kernel": platform.release(),
        "python": sys.version.split()[0], "database": "Connected", "application": "SIEM SOC Console 2.0"}, collectors=get_collector_status())


@app.route("/threat-intelligence")
def threat_intelligence_page():
    threats = get_threat_statistics(20)
    return render_template("threat_intelligence.html", threats=threats, recommendations={row["threat"]: get_recommendation(row["threat"]) for row in threats})

@app.route("/reports")
def reports_page():
    return render_template("reports.html", totals=get_dashboard_totals(), recent_alerts=get_alerts(10))

@app.route("/settings")
def settings_page():
    return render_template("settings.html", collectors=get_collector_status(), settings=get_console_settings(), users=get_console_users())

@app.post("/settings/save")
def save_settings():
    if not _admin_allowed():
        flash("Only an administrator can change settings in protected mode.")
        return redirect(url_for("settings_page"))
    save_console_settings({key: request.form.get(key, "") for key in ("theme", "font_size", "retention_days", "backup_schedule", "disk_alert", "alert_threshold", "syslog_input", "api_input", "webhook_input", "sso_provider", "mfa_enabled")})
    flash("Settings saved."); return redirect(url_for("settings_page"))

@app.post("/settings/users")
def add_settings_user():
    if not _admin_allowed():
        flash("Only an administrator can manage accounts in protected mode.")
        return redirect(url_for("settings_page"))
    username, password, role = request.form.get("username", "").strip(), request.form.get("password", ""), request.form.get("role", "Viewer")
    if len(username) >= 3 and len(password) >= 10:
        try: create_console_user(username, generate_password_hash(password), role); flash("User account added.")
        except Exception: flash("That username already exists.")
    else: flash("New users need a 3-character username and 10-character password.")
    return redirect(url_for("settings_page"))

@app.post("/settings/users/<int:user_id>/delete")
def remove_settings_user(user_id):
    if not _admin_allowed():
        flash("Only an administrator can manage accounts in protected mode.")
        return redirect(url_for("settings_page"))
    delete_console_user(user_id); flash("User removed."); return redirect(url_for("settings_page"))


@app.route("/search")
def global_search():
    keyword = request.args.get("q", "")
    logs = [dict(log, explanation=explain_event(dict(log))) for log in search_logs(keyword=keyword, limit=250)]
    return render_template("logs.html", logs=logs, filters={"q": keyword}, global_search=True)


@app.route("/api/dashboard")
def dashboard_api(): return jsonify(dashboard_payload(_trend_days(request.args.get("days", 7))))

@app.route("/api/notifications")
def notifications_api(): return jsonify([dict(row) for row in get_notifications(20)])

@app.route("/api/preferences")
def preferences_api(): return jsonify(get_console_settings())

@app.route("/api/session")
def session_api(): return jsonify({"name": session.get("name", session.get("user_id", "")), "role": session.get("role", "")})


def _safe_remote_text(value, default="", limit=8000):
    return str(value if value is not None else default).strip()[:limit]


@app.post("/api/ingest")
def ingest_events():
    """Receive selected Event Viewer records from an opted-in remote agent."""
    if not INGEST_API_KEY:
        return jsonify({"error": "Remote ingestion is disabled."}), 404
    supplied_key = request.headers.get("X-SIEM-API-Key", "")
    if not hmac.compare_digest(supplied_key, INGEST_API_KEY):
        return jsonify({"error": "Unauthorized."}), 401
    body = request.get_json(silent=True) or {}
    events = body.get("events") if isinstance(body, dict) else None
    if not isinstance(events, list) or not 1 <= len(events) <= 500:
        return jsonify({"error": "Provide between 1 and 500 events."}), 400

    inserted = []
    for item in events:
        if not isinstance(item, dict):
            continue
        timestamp = _safe_remote_text(item.get("timestamp"), limit=40)
        event_type = _safe_remote_text(item.get("event_type"), limit=200)
        computer = _safe_remote_text(item.get("computer"), limit=255)
        if not timestamp or not event_type or not computer:
            continue
        try:
            event_id = int(item.get("event_id", 0) or 0)
            record_number = int(item.get("record_number", 0) or 0)
        except (TypeError, ValueError):
            continue
        event = {
            "timestamp": timestamp, "event_type": event_type,
            "username": _safe_remote_text(item.get("username"), "SYSTEM", 255) or "SYSTEM",
            "source": _safe_remote_text(item.get("source"), "Remote Windows event", 120) or "Remote Windows event",
            "severity": _safe_remote_text(item.get("severity"), "INFO", 20).upper() or "INFO",
            "computer": computer, "channel": _safe_remote_text(item.get("channel"), "", 120),
            "event_id": event_id, "message": _safe_remote_text(item.get("message"), "", 4000),
            "raw_event": _safe_remote_text(item.get("raw_event"), "", 8000), "record_number": record_number,
        }
        if event["severity"] not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            event["severity"] = "INFO"
        if insert_log(**event):
            inserted.append(event)
    generated = detect_threats(inserted)
    generated += correlate_recent_alerts()
    if socketio:
        socketio.emit("dashboard_update", dashboard_payload())
    return jsonify({"received": len(events), "inserted": len(inserted), "alerts_generated": generated})

@app.post("/api/notifications/<int:notification_id>/dismiss")
def dismiss_notification(notification_id):
    acknowledge_notification(notification_id)
    return jsonify({"ok": True})

@app.route("/collect")
def collect_now():
    refresh_pipeline()
    return redirect(url_for("dashboard"))

@app.route("/export/<kind>/<fmt>")
def export_data(kind, fmt):
    rows = search_alerts(keyword=request.args.get("q", ""), severity=request.args.get("severity", "")) if kind == "alerts" else search_logs(keyword=request.args.get("q", ""), severity=request.args.get("severity", ""), username=request.args.get("username", ""), source=request.args.get("source", ""), event_type=request.args.get("event_type", ""), date_from=request.args.get("date_from", ""), date_to=request.args.get("date_to", ""), limit=1000)
    fields = ["id", "timestamp", "last_seen", "severity", "threat", "username", "source", "computer", "event_id", "count", "mitre", "recommendation"] if kind == "alerts" else ["id", "timestamp", "event_id", "event_type", "severity", "username", "source", "computer", "channel", "message"]
    payload = rows_to_pdf("SIEM " + kind.title() + " Report", rows, fields) if fmt == "pdf" else rows_to_csv(rows, fields)
    return Response(payload, mimetype="application/pdf" if fmt == "pdf" else "text/csv", headers={"Content-Disposition": f"attachment; filename={kind}.{fmt}"})


if __name__ == "__main__":
    start_background_monitoring()
    if socketio:
        socketio.run(app, host=HOST, port=PORT, debug=False, use_reloader=False)
    else:
        app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
