import os
import platform
from datetime import datetime
from database import get_connection, insert_alert
from config import BROWSER_OUTDATED_SEVERITY, DEFAULT_BROWSER_MINIMUM_VERSIONS

MINIMUM_VERSIONS = {
    "Google Chrome": os.getenv("SIEM_MIN_CHROME_VERSION", DEFAULT_BROWSER_MINIMUM_VERSIONS["Google Chrome"]),
    "Microsoft Edge": os.getenv("SIEM_MIN_EDGE_VERSION", DEFAULT_BROWSER_MINIMUM_VERSIONS["Microsoft Edge"]),
    "Mozilla Firefox": os.getenv("SIEM_MIN_FIREFOX_VERSION", DEFAULT_BROWSER_MINIMUM_VERSIONS["Mozilla Firefox"]),
    "Brave": os.getenv("SIEM_MIN_BRAVE_VERSION", DEFAULT_BROWSER_MINIMUM_VERSIONS["Brave"]),
}

def version_at_least(installed, minimum):
    if not minimum: return "UNKNOWN"
    try:
        a, b = [tuple(int(x) for x in v.split(".") if x.isdigit()) for v in (installed, minimum)]
        return "CURRENT" if a >= b else "OUTDATED"
    except (AttributeError, ValueError): return "UNKNOWN"


def version_decreased(previous, current):
    """True only for comparable numeric browser versions."""
    try:
        old = tuple(int(x) for x in str(previous).split(".") if x.isdigit())
        new = tuple(int(x) for x in str(current).split(".") if x.isdigit())
        return bool(old and new and new < old)
    except (AttributeError, ValueError):
        return False

def collect_browsers():
    if platform.system() != "Windows": return {"status":"UNKNOWN", "items":[]}
    paths = {"Google Chrome": [os.path.join(os.environ.get("PROGRAMFILES", ""), "Google", "Chrome", "Application", "chrome.exe")], "Microsoft Edge": [os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Microsoft", "Edge", "Application", "msedge.exe")], "Mozilla Firefox": [os.path.join(os.environ.get("PROGRAMFILES", ""), "Mozilla Firefox", "firefox.exe")], "Brave": [os.path.join(os.environ.get("PROGRAMFILES", ""), "BraveSoftware", "Brave-Browser", "Application", "brave.exe")]}
    try: import win32api
    except ImportError: win32api = None
    items, now, outdated = [], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), []
    conn = get_connection()
    for browser, candidates in paths.items():
        path = next((p for p in candidates if os.path.isfile(p)), "")
        if not path: continue
        version = "UNKNOWN"
        if win32api:
            try: version = win32api.GetFileVersionInfo(path, "\\")["FileVersion"].split("\0")[0]
            except Exception: pass
        minimum = MINIMUM_VERSIONS[browser]
        status = version_at_least(version, minimum)
        prior = conn.execute("SELECT installed_version FROM browser_inventory WHERE browser=? AND installation_path=?", (browser, path)).fetchone()
        item = {"browser":browser,"installed_version":version,"minimum_version":minimum,"installation_path":path,"status":status}; items.append(item)
        conn.execute("INSERT INTO browser_inventory(browser,installed_version,installation_path,status,first_seen,last_seen) VALUES(?,?,?,?,?,?) ON CONFLICT(browser,installation_path) DO UPDATE SET installed_version=excluded.installed_version,status=excluded.status,last_seen=excluded.last_seen", (browser,version,path,status,now,now))
        if status == "OUTDATED": outdated.append(item)
        if prior and version_decreased(prior["installed_version"], version):
            insert_alert("HIGH", f"{browser} version decreased from {prior['installed_version']} to {version}.", threat="BROWSER_VERSION_DOWNGRADED", category="PATCHING", evidence=str(item), alert_key=f"browser-downgrade:{browser}:{prior['installed_version']}:{version}", confidence=.85)
    conn.commit(); conn.close()
    for item in outdated:
        insert_alert(BROWSER_OUTDATED_SEVERITY, f"{item['browser']} ({item['installed_version']}) is below the local minimum version {item['minimum_version']}.", threat="OUTDATED_BROWSER", category="PATCHING", evidence=str(item), alert_key=f"browser:{item['browser']}:{item['installed_version']}")
    return {"status":"WARNING" if outdated else "PASS", "items":items, "message":"Browser status uses a built-in minimum policy that can be overridden with SIEM_MIN_*_VERSION values."}
