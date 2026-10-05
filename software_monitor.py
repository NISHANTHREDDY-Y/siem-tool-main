import json
import os
import platform
from datetime import datetime

from config import APPROVED_SOFTWARE_PATH, UNREGISTERED_SOFTWARE_SEVERITY
from database import get_connection, insert_alert


def is_approved(item, allowlist):
    for allowed in allowlist.get("approved_software", []):
        if allowed.get("name", "").lower() == item["name"].lower() and (not allowed.get("publisher") or allowed["publisher"].lower() == item.get("publisher", "").lower()):
            versions = allowed.get("allowed_versions", [])
            return not versions or item.get("version") in versions
    return False


def _allowlist():
    try:
        with open(APPROVED_SOFTWARE_PATH, encoding="utf-8") as f: return json.load(f)
    except (OSError, ValueError): return {"approved_software": []}


def assess_software(item, allowlist, has_existing_baseline, previously_seen):
    """Return the policy state without treating a first empty allowlist as malware."""
    allowlist_active = bool(allowlist.get("approved_software", []))
    if allowlist_active:
        return "APPROVED" if is_approved(item, allowlist) else "UNAPPROVED"
    if not has_existing_baseline:
        return "BASELINED"
    return "KNOWN" if previously_seen else "NEW_SINCE_BASELINE"


def _registry_inventory():
    if platform.system() != "Windows": return []
    try: import winreg
    except ImportError: return []
    locations = [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "64-bit"), (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "32-bit")]
    items = []
    for hive, path, architecture in locations:
        try:
            with winreg.OpenKey(hive, path) as root:
                for i in range(winreg.QueryInfoKey(root)[0]):
                    try:
                        with winreg.OpenKey(root, winreg.EnumKey(root, i)) as key:
                            name = winreg.QueryValueEx(key, "DisplayName")[0]
                            if not name: continue
                            def value(k):
                                try: return str(winreg.QueryValueEx(key, k)[0])
                                except OSError: return ""
                            items.append({"name": str(name), "version": value("DisplayVersion"), "publisher": value("Publisher"), "install_date": value("InstallDate"), "install_location": value("InstallLocation"), "architecture": architecture, "source": "Registry"})
                    except OSError: continue
        except OSError: continue
    return items


def collect_software():
    if platform.system() != "Windows": return {"status": "UNKNOWN", "message": "Windows endpoint monitoring requires Windows.", "items": []}
    items, approved, unregistered, now, allowlist = _registry_inventory(), 0, 0, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), _allowlist()
    unregistered_items = []
    conn = get_connection()
    has_existing_baseline = bool(conn.execute("SELECT 1 FROM software_inventory LIMIT 1").fetchone())
    allowlist_active = bool(allowlist.get("approved_software", []))
    for item in items:
        prior = conn.execute("SELECT version FROM software_inventory WHERE name=? AND publisher=? AND architecture=? ORDER BY id DESC LIMIT 1", (item["name"], item["publisher"], item["architecture"])).fetchone()
        conn.execute("INSERT INTO software_inventory(name,version,publisher,install_date,install_location,architecture,source,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(name,version,publisher,architecture) DO UPDATE SET last_seen=excluded.last_seen,install_location=excluded.install_location", (item["name"], item["version"], item["publisher"], item["install_date"], item["install_location"], item["architecture"], item["source"], now, now))
        if prior and prior["version"] != item["version"]: conn.execute("INSERT INTO software_changes(timestamp,change_type,name,previous_version,current_version,details) VALUES(?,?,?,?,?,?)", (now, "SOFTWARE_VERSION_CHANGED", item["name"], prior["version"], item["version"], "{}"))
        state = assess_software(item, allowlist, has_existing_baseline, bool(prior))
        item["policy_state"] = state
        if state in {"APPROVED", "KNOWN", "BASELINED"}:
            approved += 1
        else:
            unregistered += 1
            unregistered_items.append(item)
    conn.commit(); conn.close()
    for item in unregistered_items:
        if allowlist_active:
            title = "Unapproved software detected: %s %s" % (item["name"], item["version"])
            key = "unapproved:" + item["name"] + ":" + item["version"]
        else:
            title = "New software detected after baseline: %s %s" % (item["name"], item["version"])
            key = "new-software:" + item["name"] + ":" + item["version"]
        insert_alert(UNREGISTERED_SOFTWARE_SEVERITY, title, threat="UNREGISTERED_SOFTWARE", source=item["source"], category="SOFTWARE", evidence=json.dumps(item), alert_key=key, confidence=.7)
    mode = "allowlist" if allowlist_active else "baseline"
    message = "Approved-software allowlist is active." if allowlist_active else ("First scan established a software baseline; later newly installed software is alerted." if not has_existing_baseline else "No allowlist is active; only software newly appearing after the baseline is alerted.")
    return {"status": "WARNING" if unregistered else "PASS", "items": items, "total": len(items), "approved": approved, "unregistered": unregistered, "policy_mode": mode, "message": message}
