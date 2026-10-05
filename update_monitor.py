import platform, subprocess
from datetime import datetime, timedelta
from config import OS_UPDATE_MAX_AGE_DAYS
from database import get_connection, insert_alert

def collect_updates():
    if platform.system() != "Windows": return {"status":"UNKNOWN", "updates":[]}
    # CIM is used only for data retrieval, with a timeout and no user supplied input.
    command = ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_QuickFixEngineering | Select-Object HotFixID,Description,InstalledOn | ConvertTo-Json -Compress"]
    try: result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired): return {"status":"UNKNOWN", "updates":[], "message":"Windows Update inventory unavailable"}
    import json
    try: rows = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else []
    except ValueError: rows = []
    if isinstance(rows, dict): rows = [rows]
    now, newest = datetime.now(), None
    conn = get_connection()
    for row in rows:
        date = str(row.get("InstalledOn") or "")
        try: parsed = datetime.fromisoformat(date.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError: parsed = None
        if parsed and (not newest or parsed > newest): newest = parsed
        conn.execute("INSERT INTO system_updates(timestamp,update_id,update_title,install_date,status) VALUES(?,?,?,?,?)", (now.strftime("%Y-%m-%d %H:%M:%S"), row.get("HotFixID", ""), row.get("Description", ""), date, "INSTALLED"))
    conn.commit(); conn.close()
    age = (now - newest).days if newest else None
    status = "WARNING" if age is None or age > OS_UPDATE_MAX_AGE_DAYS else "PASS"
    if status == "WARNING": insert_alert("MEDIUM", "No recent OS security update is recorded within the configured update age threshold.", threat="NO_RECENT_OS_UPDATE", category="PATCHING", evidence=json.dumps({"latest_update": newest.isoformat() if newest else "UNKNOWN", "max_age_days": OS_UPDATE_MAX_AGE_DAYS}), alert_key="os-update-age")
    return {"status":status,"updates":rows,"latest_update":newest.isoformat() if newest else "UNKNOWN","age_days":age}
