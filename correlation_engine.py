"""Small, transparent correlation layer kept separate from atomic detections."""
from database import get_alerts, insert_alert
from utils import event_fingerprint

def correlate_recent_alerts():
    alerts = list(get_alerts(200)); threats = {row["threat"] for row in alerts}; generated = 0
    rules = [
        ({"SYSTEM_CLOCK_BACKDATED", "Audit Log Cleared"}, "CLOCK_CHANGE_AND_LOG_TAMPERING", "CRITICAL", "Clock backdating and audit-log clearing were both observed; preserve evidence and investigate immediately."),
        ({"UNREGISTERED_SOFTWARE", "New Service Installed"}, "SOFTWARE_SERVICE_PERSISTENCE", "CRITICAL", "Unregistered software and a newly installed service were observed."),
        ({"USB_DEVICE_FIRST_SEEN", "UNREGISTERED_SOFTWARE"}, "USB_RELATED_SOFTWARE_INSTALL", "HIGH", "An unknown USB device and unregistered software were observed."),
        ({"FIREWALL_DISABLED", "DEFENDER_DISABLED"}, "DEFENSES_IMPAIRED", "CRITICAL", "Firewall and Defender protections appear to be disabled."),
    ]
    for required, threat, severity, message in rules:
        if required <= threats:
            alert = insert_alert(severity, message, threat=threat, category="CORRELATION", confidence=.9, alert_key=event_fingerprint(threat, *sorted(required)))
            generated += bool(alert.get("is_new"))
    return generated
