import platform, subprocess
from database import upsert_setting, insert_alert

def collect_security_settings():
    if platform.system() != "Windows": return {"status":"UNKNOWN", "settings":{}}
    commands = {"firewall": "(Get-NetFirewallProfile | Select-Object -Expand Enabled) -join ','", "rdp_enabled": "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections", "uac": "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA).EnableLUA"}
    settings = {}
    for key, ps in commands.items():
        try: run = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",ps], capture_output=True, text=True, timeout=10, check=False); value = run.stdout.strip() if run.returncode == 0 and run.stdout.strip() else "UNKNOWN"
        except (OSError, subprocess.TimeoutExpired): value = "UNKNOWN"
        previous = upsert_setting(key, value)
        settings[key] = value
        if previous is not None:
            severity = "HIGH" if key == "firewall" and "False" in value else "MEDIUM"
            threat = "FIREWALL_DISABLED" if key == "firewall" and "False" in value else "SYSTEM_SETTING_CHANGED"
            insert_alert(severity, f"Protected setting changed: {key} ({previous} → {value})", threat=threat, category="SYSTEM_INTEGRITY", previous_value=previous, new_value=value, alert_key=f"setting:{key}:{value}")
    return {"status":"WARNING" if "False" in settings.get("firewall", "") else "PASS", "settings":settings}
