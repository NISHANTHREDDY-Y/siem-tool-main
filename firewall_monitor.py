"""Read-only local Windows Defender Firewall status and platform information."""
import json
import platform
import subprocess
from datetime import datetime


def get_firewall_profiles():
    if platform.system() != "Windows":
        return {"status": "UNKNOWN", "profiles": [], "enabled_rules": 0, "disabled_rules": 0, "service": {}, "platform": {}, "audit": "Unavailable", "message": "Windows Defender Firewall status requires Windows."}

    command = [
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "$profiles=Get-NetFirewallProfile | Select-Object Name,Enabled,@{N='DefaultInboundAction';E={$_.DefaultInboundAction.ToString()}},@{N='DefaultOutboundAction';E={$_.DefaultOutboundAction.ToString()}}; "
        "$rules=Get-NetFirewallRule | Group-Object Enabled | ForEach-Object {[pscustomobject]@{State=$_.Name;Count=$_.Count}}; "
        "$service=Get-CimInstance Win32_Service -Filter \"Name='mpssvc'\" | Select-Object Name,DisplayName,State,StartMode,PathName; "
        "$os=Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber; "
        "$dll=Get-Item \"$env:windir\\System32\\mpssvc.dll\" -ErrorAction SilentlyContinue; "
        "$hotfix=Get-HotFix | Sort-Object {[datetime]$_.InstalledOn} -Descending | Select-Object -First 1 HotFixID,Description,InstalledOn; "
        "$audit=(auditpol /get /subcategory:\"Filtering Platform Connection\" 2>$null | Out-String).Trim(); "
        "[pscustomobject]@{Profiles=$profiles;Rules=$rules;Service=$service;Audit=$audit;Platform=[pscustomobject]@{OperatingSystem=$os.Caption;OSVersion=$os.Version;Build=$os.BuildNumber;FirewallComponentVersion=if($dll){$dll.VersionInfo.FileVersion}else{'Unknown'};LatestHotfix=$hotfix} } | ConvertTo-Json -Depth 6 -Compress",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "UNKNOWN", "profiles": [], "enabled_rules": 0, "disabled_rules": 0, "service": {}, "platform": {}, "audit": "Unavailable", "message": "Firewall command is unavailable or timed out."}
    try:
        payload = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else {}
    except ValueError:
        payload = {}
    profiles = payload.get("Profiles", []) if isinstance(payload, dict) else []
    rules = payload.get("Rules", []) if isinstance(payload, dict) else []
    service = payload.get("Service", {}) if isinstance(payload, dict) else {}
    platform_info = payload.get("Platform", {}) if isinstance(payload, dict) else {}
    audit = str(payload.get("Audit") or "Unavailable") if isinstance(payload, dict) else "Unavailable"
    if isinstance(profiles, dict):
        profiles = [profiles]
    if isinstance(rules, dict):
        rules = [rules]
    if not isinstance(platform_info, dict):
        platform_info = {}
    if not isinstance(platform_info.get("LatestHotfix"), dict):
        platform_info["LatestHotfix"] = {}
    enabled_rules = next((item.get("Count", 0) for item in rules if str(item.get("State", "")).lower() == "true"), 0)
    disabled_rules = next((item.get("Count", 0) for item in rules if str(item.get("State", "")).lower() == "false"), 0)
    service_running = str(service.get("State", "")).lower() == "running" if isinstance(service, dict) else False
    audit_active = "success" in audit.lower() or "failure" in audit.lower()
    status = "WARNING" if not profiles or any(not item.get("Enabled") for item in profiles) or not service_running or not audit_active else "PASS"
    return {
        "status": status, "profiles": profiles, "enabled_rules": enabled_rules, "disabled_rules": disabled_rules,
        "service": service if isinstance(service, dict) else {}, "platform": platform_info, "audit": audit,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": "Live local Windows Defender Firewall profile, service, rule, audit-policy, and platform information.",
    }
