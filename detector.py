from collections import Counter, defaultdict
import re

from database import insert_alert
from recommendations import format_recommendation, get_recommendation
from utils import event_fingerprint, now_string
from time_integrity_monitor import time_change_from_message
from severity_policy import severity_for_event


def _event_id(log):
    try:
        return int(log["event_id"] or 0)
    except Exception:
        return 0


def _text(log):
    return f"{log['event_type']} {log['message'] if 'message' in log.keys() else ''}".lower()


def is_administrator_password_event(log):
    """Only flag Security 4723/4724 when the event evidence names an admin account."""
    if _event_id(log) not in {4723, 4724}:
        return False
    evidence = f"{log.get('message', '') if hasattr(log, 'get') else log['message']} {log.get('raw_event', '') if hasattr(log, 'get') else ''}"
    return bool(re.search(r"(?<![a-z0-9])(administrator|admin)(?![a-z0-9])", evidence, re.IGNORECASE))


def _rule_for_log(log):
    event_id = _event_id(log)
    event = log["event_type"]
    username = log["username"] or "SYSTEM"
    text = _text(log)

    rules = {
        4624: ("Successful Login", "INFO"),
        4625: ("Failed Login", "MEDIUM"),
        4672: ("Privilege Escalation", "HIGH"),
        4719: ("Audit Policy Changed", "HIGH"),
        4720: ("New User", "HIGH"),
        4722: ("User Enabled", "MEDIUM"),
        4723: ("Password Changed", "HIGH"),
        4724: ("Password Reset", "HIGH"),
        4725: ("User Disabled", "MEDIUM"),
        4726: ("Deleted User", "HIGH"),
        4732: ("Group Membership Changes", "HIGH"),
        4733: ("Group Membership Removed", "HIGH"),
        4740: ("Account Locked", "HIGH"),
        4771: ("Kerberos Failure", "MEDIUM"),
        4776: ("NTLM Authentication", "LOW"),
        6008: ("Unexpected Shutdown", "HIGH"),
        7031: ("Service Crash", "MEDIUM"),
        7034: ("Service Crash", "MEDIUM"),
        7045: ("New Service Installed", "HIGH"),
        1000: ("Application Crash", "MEDIUM"),
        1001: ("Application Crash", "LOW"),
        1026: ("Application Crash", "MEDIUM"),
        1102: ("Audit Log Cleared", "CRITICAL"),
        4616: ("SYSTEM_TIME_CHANGED", "MEDIUM"),
        6416: ("USB_DEVICE_CONNECTED", "MEDIUM"),
        20001: ("DRIVER_CHANGED", "MEDIUM"),
        20003: ("DRIVER_CHANGED", "MEDIUM"),
        219: ("HARDWARE_DEVICE_CHANGED", "MEDIUM"),
    }

    if event_id in rules:
        threat, severity = rules[event_id]
    elif "powershell" in text:
        threat, severity = "PowerShell Related Events", "MEDIUM"
    elif "firewall" in text or event_id in {5156, 5157, 5158}:
        threat, severity = "Firewall Related Events", "LOW"
    elif "remote" in text or "rdp" in text:
        threat, severity = "Remote Login", "MEDIUM"
    elif "crash" in event.lower() or "exception" in event.lower():
        threat, severity = "Application Crash", "MEDIUM"
    else:
        return None

    if is_administrator_password_event(log):
        return ("ADMINISTRATOR_PASSWORD_CHANGED", "CRITICAL")

    if event_id == 4616:
        assessment = time_change_from_message(log["message"])
        return (assessment["event_type"], assessment["severity"]) if assessment else ("SYSTEM_TIME_CHANGED", "MEDIUM")

    severity = severity_for_event(event_id, log["message"], severity)

    if username.lower() in {"administrator", "admin"} and severity in {"INFO", "LOW", "MEDIUM"}:
        threat, severity = "Administrator Login", "MEDIUM"

    return threat, severity


def _store_alert(log, threat, severity):
    rec = get_recommendation(threat)
    recommendation = format_recommendation(threat)
    message = f"{threat} detected for {log['username']} on {log['source']}"
    alert = insert_alert(
        severity,
        message,
        username=log["username"],
        source=log["source"],
        recommendation=recommendation,
        threat=threat,
        computer=log["computer"] if "computer" in log.keys() else "",
        event_id=_event_id(log),
        mitre=rec["mitre"],
        # One alert per Windows record.  Do not merge unrelated service installs
        # or increment a count merely because the dashboard was refreshed.
        alert_key=event_fingerprint(threat, log["fingerprint"] if "fingerprint" in log.keys() else "", log["timestamp"], log["username"], log["source"], log["computer"] if "computer" in log.keys() else "", _event_id(log)),
        # Keep Event Viewer time separate from the detection run time.
        timestamp=log["timestamp"],
        event_timestamp=log["timestamp"],
    )
    return bool(alert and alert.get("is_new") and severity in {"MEDIUM", "HIGH", "CRITICAL"})


def detect_threats(logs):
    failures_by_user = defaultdict(list)
    failures_by_source = defaultdict(set)
    generated = 0

    for log in logs:
        rule = _rule_for_log(log)
        if rule:
            threat, severity = rule
            if severity != "INFO":
                if _store_alert(log, threat, severity):
                    generated += 1
            elif threat == "Successful Login":
                _store_alert(log, threat, severity)

        if _event_id(log) == 4625 or "failed" in log["event_type"].lower():
            failures_by_user[log["username"]].append(log)
            failures_by_source[log["source"]].add(log["username"])

    for username, events in failures_by_user.items():
        if len(events) >= 3:
            threat = "Multiple Failed Logins"
            severity = "HIGH" if len(events) < 8 else "CRITICAL"
            _store_alert(events[0], threat, severity)
        if len(events) >= 8:
            _store_alert(events[0], "Brute Force", "CRITICAL")

    for source, users in failures_by_source.items():
        if len(users) >= 5:
            sample = next((log for log in logs if log["source"] == source), None)
            if sample:
                _store_alert(sample, "Password Spray", "CRITICAL")

    return generated
