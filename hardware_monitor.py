"""Local Windows hardware and signed-driver baseline monitoring."""
import json
import platform
import subprocess
from datetime import datetime

from database import get_connection, insert_alert


def _driver_changes(previous, current):
    """Return meaningful driver changes; a first inventory is a baseline, not an alert."""
    changes = []
    for field, label in (("driver_version", "DRIVER_VERSION_CHANGED"), ("driver_date", "DRIVER_DATE_CHANGED"), ("is_signed", "DRIVER_SIGNATURE_CHANGED")):
        old, new = str(previous.get(field, "")), str(current.get(field, ""))
        if old and new and old != new:
            severity = "HIGH" if field == "is_signed" and new.lower() == "false" else "MEDIUM"
            changes.append({"change_type": label, "previous_value": old, "new_value": new, "severity": severity})
    return changes


def _missing_driver_changes(previous_rows, present_ids, now):
    """Mark baseline drivers/devices absent from a successful later inventory.

    A removed PnP driver is not proof of malicious activity: unplugging a device
    or a legitimate uninstall can cause it.  It is still important evidence and
    is kept distinct from version/signature changes.
    """
    changes = []
    for row in previous_rows:
        item = dict(row)
        if item["device_id"] in present_ids or item.get("missing_count", 0):
            continue
        changes.append({
            "device_id": item["device_id"],
            "device_name": item.get("device_name") or "Unknown device",
            "change_type": "DRIVER_OR_DEVICE_REMOVED",
            "previous_value": item.get("driver_version") or "Present in baseline",
            "new_value": "Not present in current Windows PnP driver inventory",
            "severity": "CRITICAL",
            "timestamp": now,
        })
    return changes


def _read_driver_inventory():
    command = [
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-CimInstance Win32_PnPSignedDriver | Where-Object {$_.DeviceID} | "
        "Select-Object DeviceID,DeviceName,Manufacturer,DriverVersion,DriverDate,IsSigned | ConvertTo-Json -Compress",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    try:
        data = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else []
    except ValueError:
        return None
    return [data] if isinstance(data, dict) else data


def collect_hardware_and_drivers():
    if platform.system() != "Windows":
        return {"status": "UNKNOWN", "devices": [], "message": "Hardware and driver inventory requires Windows."}
    rows = _read_driver_inventory()
    if rows is None:
        return {"status": "UNKNOWN", "devices": [], "message": "Windows driver inventory is unavailable."}

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    changes, devices = [], []
    conn = get_connection()
    previous_rows = conn.execute("SELECT * FROM hardware_inventory").fetchall()
    previous_count = len(previous_rows)
    present_ids = set()
    for raw in rows:
        device_id = str(raw.get("DeviceID") or "")
        if not device_id:
            continue
        present_ids.add(device_id)
        item = {
            "device_id": device_id, "device_name": str(raw.get("DeviceName") or "Unknown device"),
            "manufacturer": str(raw.get("Manufacturer") or ""), "driver_version": str(raw.get("DriverVersion") or ""),
            "driver_date": str(raw.get("DriverDate") or ""), "is_signed": str(raw.get("IsSigned") if raw.get("IsSigned") is not None else "UNKNOWN"),
        }
        previous = conn.execute("SELECT * FROM hardware_inventory WHERE device_id=?", (device_id,)).fetchone()
        if previous:
            for change in _driver_changes(dict(previous), item):
                change.update({"device_id": device_id, "device_name": item["device_name"]})
                changes.append(change)
                conn.execute("INSERT INTO hardware_changes(timestamp,device_id,device_name,change_type,previous_value,new_value,severity) VALUES(?,?,?,?,?,?,?)", (now, device_id, item["device_name"], change["change_type"], change["previous_value"], change["new_value"], change["severity"]))
        conn.execute("INSERT INTO hardware_inventory(device_id,device_name,manufacturer,driver_version,driver_date,is_signed,last_seen,missing_since,missing_count) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET device_name=excluded.device_name,manufacturer=excluded.manufacturer,driver_version=excluded.driver_version,driver_date=excluded.driver_date,is_signed=excluded.is_signed,last_seen=excluded.last_seen,missing_since='',missing_count=0", (device_id, item["device_name"], item["manufacturer"], item["driver_version"], item["driver_date"], item["is_signed"], now, "", 0))
        devices.append(item)

    # Only compare a complete-looking later inventory against an existing
    # baseline.  If PowerShell returns a tiny/incomplete result, do not turn a
    # collection failure into hundreds of false deletion alerts.
    if previous_count and len(present_ids) >= max(3, min(10, previous_count // 4)):
        removals = _missing_driver_changes(previous_rows, present_ids, now)
        for change in removals:
            conn.execute("UPDATE hardware_inventory SET missing_since=?, missing_count=1 WHERE device_id=?", (now, change["device_id"]))
            conn.execute("INSERT INTO hardware_changes(timestamp,device_id,device_name,change_type,previous_value,new_value,severity) VALUES(?,?,?,?,?,?,?)", (now, change["device_id"], change["device_name"], change["change_type"], change["previous_value"], change["new_value"], change["severity"]))
        changes.extend(removals)
    conn.commit()
    conn.close()

    for change in changes:
        threat = "DRIVER_OR_DEVICE_REMOVED" if change["change_type"] == "DRIVER_OR_DEVICE_REMOVED" else "HARDWARE_OR_DRIVER_CHANGED"
        insert_alert(change["severity"], f"{change['change_type'].replace('_', ' ').title()}: {change['device_name']}", threat=threat, source="Windows driver inventory", category="HARDWARE", evidence=json.dumps(change), alert_key=f"hardware:{change['device_id']}:{change['change_type']}:{change['new_value']}", confidence=.8)
    status = "CRITICAL" if any(item["severity"] == "CRITICAL" for item in changes) else "HIGH" if any(item["severity"] == "HIGH" for item in changes) else "WARNING" if changes else "PASS"
    return {"status": status, "devices": devices, "changes": changes, "message": "First scan establishes a local driver baseline; later version, signature, and disappearance changes are alerted."}
