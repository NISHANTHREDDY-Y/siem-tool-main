DEFAULT_COMMANDS = [
    "whoami /all",
    "net user <username>",
    "wevtutil qe Security /q:\"*[System[(EventID=<event_id>)]]\" /f:text /c:10",
]

RECOMMENDATIONS = {
    "ADMINISTRATOR_PASSWORD_CHANGED": {
        "description": "Windows recorded a password change or reset involving an account identified as Administrator or admin.",
        "why": "Administrative password changes can be authorized, but an unexpected one can immediately affect control of the computer.",
        "immediate_action": "Confirm the approved change with the administrator. If it was not authorized, preserve the Security event, secure the account, and review recent privileged activity.",
        "recommended_fix": "Reset the affected account through the approved recovery process and remove any unauthorized access.",
        "long_term_defense": "Use separate named admin accounts, MFA where available, and change-control records for privileged password resets.",
        "mitre": "T1098 - Account Manipulation",
        "commands": ["wevtutil qe Security /q:\"*[System[(EventID=4723 or EventID=4724)]]\" /f:text /c:20", "net localgroup administrators"],
    },
    "DRIVER_CHANGED": {
        "description": "Windows recorded a driver installation, update, or configuration event.",
        "why": "Driver changes are normally part of approved updates, but unsigned or unexpected drivers can affect system integrity.",
        "immediate_action": "Confirm the device, driver publisher, version, signature, and related change request.",
        "recommended_fix": "Roll back or remove only an unauthorized driver using the supported device-management process.",
        "long_term_defense": "Keep a signed-driver baseline and apply drivers through approved update channels.",
        "mitre": "T1547.006 - Kernel Modules and Extensions",
        "commands": ["pnputil /enum-drivers", "Get-CimInstance Win32_PnPSignedDriver | Select DeviceName,Manufacturer,DriverVersion,IsSigned"],
    },
    "HARDWARE_DEVICE_CHANGED": {
        "description": "Windows recorded a hardware or device configuration event.",
        "why": "New or changed hardware may be expected, but can also introduce removable media or an unapproved device.",
        "immediate_action": "Identify the device and verify its owner and business purpose.",
        "recommended_fix": "Disconnect or disable an unauthorized device using the approved endpoint process.",
        "long_term_defense": "Maintain a hardware inventory and device-control policy.",
        "mitre": "T1200 - Hardware Additions",
        "commands": ["Get-PnpDevice -PresentOnly", "Get-CimInstance Win32_PnPSignedDriver"],
    },
    "HARDWARE_OR_DRIVER_CHANGED": {
        "description": "The local driver baseline changed after a previous endpoint scan.",
        "why": "The detected version, date, or signature is different from the previous local baseline.",
        "immediate_action": "Compare the old and new values in the alert evidence and validate the update with the device owner.",
        "recommended_fix": "Roll back or remove only an unauthorized driver.",
        "long_term_defense": "Keep signed-driver inventory baselines and use controlled driver deployment.",
        "mitre": "T1547.006 - Kernel Modules and Extensions",
        "commands": ["pnputil /enum-drivers"],
    },
    "DRIVER_OR_DEVICE_REMOVED": {
        "description": "A device or signed-driver entry that existed in the previous successful local baseline did not appear in the latest Windows inventory.",
        "why": "It may be a legitimate device unplug or driver uninstall, but an unexpected disappearance can reduce endpoint capability or hide a device change.",
        "immediate_action": "Compare the alert evidence with the latest driver inventory and confirm whether a device was unplugged or a driver was intentionally removed.",
        "recommended_fix": "Restore only an approved driver through Windows Update or the device manufacturer; investigate an unexplained removal before reinstalling.",
        "long_term_defense": "Keep regular endpoint scans and document hardware/driver maintenance changes.",
        "mitre": "T1562 - Impair Defenses (investigate context)",
        "commands": ["pnputil /enum-drivers", "Get-CimInstance Win32_PnPSignedDriver | Select DeviceName,DriverVersion,IsSigned"],
    },
    "HIGH_PACKET_FLOW": {
        "description": "The SIEM measured a high local network packet rate between two adapter samples.",
        "why": "High packet rates can be normal for downloads, backups, or video calls, but can also accompany scanning, flooding, or malware activity.",
        "immediate_action": "Identify the adapter and active connections, then confirm whether an expected transfer or backup was running.",
        "recommended_fix": "Contain the responsible process or host only if the traffic is unauthorized; do not block normal business traffic without validation.",
        "long_term_defense": "Set packet-rate thresholds for the local environment and monitor unexpected sustained spikes.",
        "mitre": "T1498 - Network Denial of Service",
        "commands": ["Get-NetTCPConnection | Sort-Object State", "Get-NetAdapterStatistics"],
    },
    "BROWSER_VERSION_DOWNGRADED": {
        "description": "A browser executable version is lower than the version observed in the prior local scan.",
        "why": "Downgrades can reintroduce vulnerabilities or indicate an unexpected installer or rollback.",
        "immediate_action": "Verify the browser update/rollback was approved and check the installer source.",
        "recommended_fix": "Update the browser through its supported enterprise or vendor channel.",
        "long_term_defense": "Use managed browser updates and retain an approved minimum-version policy.",
        "mitre": "T1072 - Software Deployment Tools (investigate context)",
        "commands": ["Get-Item 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' | Select VersionInfo"],
    },
    "Service Crash": {
        "description": "A Windows service terminated unexpectedly.",
        "why": "This is often an application, driver, or dependency failure; repeated crashes can also affect security tooling.",
        "immediate_action": "Check the service name, Windows System event details, and whether protection or a critical business service is affected.",
        "recommended_fix": "Restart only after reviewing the error; repair, update, or roll back the responsible application or driver.",
        "long_term_defense": "Monitor repeated service failures and maintain tested recovery procedures.",
        "mitre": "N/A - Availability event",
        "commands": ["sc query <service_name>", "wevtutil qe System /q:\"*[System[(EventID=7031 or EventID=7034)]]\" /f:text /c:20"],
    },
    "Failed Login": {
        "description": "A Windows authentication attempt failed.",
        "why": "The password may be wrong, the account may be targeted, or a service may be using stale credentials.",
        "immediate_action": "Confirm whether the user attempted to sign in and review the source host.",
        "recommended_fix": "Reset the password if suspicious and remove stale saved credentials.",
        "long_term_defense": "Enable account lockout policy, MFA where possible, and alert on repeated failures.",
        "mitre": "T1110 - Brute Force",
        "commands": ["net user <username>", "wevtutil qe Security /q:\"*[System[(EventID=4625)]]\" /f:text /c:20"],
    },
    "Multiple Failed Logins": {
        "description": "Several failed sign-ins were seen for the same user in a short window.",
        "why": "This often happens during password guessing or misconfigured services.",
        "immediate_action": "Temporarily lock or monitor the account and check the source workstation.",
        "recommended_fix": "Reset credentials and remove suspicious sessions.",
        "long_term_defense": "Tune lockout thresholds and monitor failed login velocity.",
        "mitre": "T1110 - Brute Force",
        "commands": ["net accounts", "net user <username> /domain"],
    },
    "Brute Force": {
        "description": "A high volume of failed authentication attempts suggests brute force activity.",
        "why": "An attacker may be trying many passwords against one account.",
        "immediate_action": "Disable the affected account if activity is unauthorized.",
        "recommended_fix": "Reset the password, review recent successful logins, and block the source.",
        "long_term_defense": "Use MFA, account lockout, and IP-based conditional access.",
        "mitre": "T1110 - Brute Force",
        "commands": ["net user <username> /active:no", "netsh advfirewall firewall show rule name=all"],
    },
    "Password Spray": {
        "description": "Failures across multiple accounts can indicate password spraying.",
        "why": "Attackers often try one common password across many users to avoid lockouts.",
        "immediate_action": "Identify affected users and block the source address or host.",
        "recommended_fix": "Force password resets for impacted accounts.",
        "long_term_defense": "Ban common passwords and require MFA.",
        "mitre": "T1110.003 - Password Spraying",
        "commands": ["net accounts", "Get-LocalUser | Select Name,Enabled"],
    },
    "Successful Login": {
        "description": "A successful Windows logon was recorded.",
        "why": "Normal activity unless the account, source, or time is unusual.",
        "immediate_action": "Validate unusual privileged or remote sessions.",
        "recommended_fix": "No action required for expected activity.",
        "long_term_defense": "Baseline normal user activity and alert on deviations.",
        "mitre": "T1078 - Valid Accounts",
        "commands": ["query user", "whoami /groups"],
    },
    "Administrator Login": {
        "description": "Activity from an administrator-equivalent account was detected.",
        "why": "Privileged accounts create higher operational risk and are commonly targeted.",
        "immediate_action": "Confirm the admin action was authorized.",
        "recommended_fix": "Review group membership and recent privilege use.",
        "long_term_defense": "Use separate admin accounts and just-in-time administration.",
        "mitre": "T1078.002 - Domain Accounts",
        "commands": ["net localgroup administrators", "whoami /priv"],
    },
    "Privilege Escalation": {
        "description": "Special privileges were assigned or used.",
        "why": "This can be legitimate admin work or a sign of privilege escalation.",
        "immediate_action": "Review the account, logon session, and parent activity.",
        "recommended_fix": "Remove unnecessary privileges and investigate recent process creation.",
        "long_term_defense": "Implement least privilege and privileged access monitoring.",
        "mitre": "T1068 - Exploitation for Privilege Escalation",
        "commands": ["whoami /priv", "net localgroup administrators"],
    },
    "Account Locked": {
        "description": "A Windows account was locked.",
        "why": "Repeated failed sign-ins exceeded the configured policy.",
        "immediate_action": "Contact the account owner and review failed login sources.",
        "recommended_fix": "Unlock only after confirming legitimacy.",
        "long_term_defense": "Monitor lockout sources and stale service credentials.",
        "mitre": "T1110 - Brute Force",
        "commands": ["net user <username>", "wevtutil qe Security /q:\"*[System[(EventID=4740)]]\" /f:text /c:10"],
    },
    "Audit Log Cleared": {
        "description": "The Windows audit log was cleared.",
        "why": "Log clearing can be administrative maintenance or attacker anti-forensics.",
        "immediate_action": "Treat as high priority unless tied to approved maintenance.",
        "recommended_fix": "Preserve remaining logs and investigate the account that cleared them.",
        "long_term_defense": "Forward logs to centralized storage and restrict log management rights.",
        "mitre": "T1070.001 - Clear Windows Event Logs",
        "commands": ["wevtutil gli Security", "auditpol /get /category:*"],
    },
    "New Service Installed": {
        "description": "A service was installed on the host.",
        "why": "Services are often used for persistence or legitimate software deployment.",
        "immediate_action": "Validate the service name, path, publisher, and installer.",
        "recommended_fix": "Disable and remove unauthorized services.",
        "long_term_defense": "Monitor service creation and enforce application control.",
        "mitre": "T1543.003 - Windows Service",
        "commands": ["sc query", "sc qc <service_name>"],
    },
    "Application Crash": {
        "description": "An application crash or .NET exception was observed.",
        "why": "Crashes may be stability issues, exploit attempts, or failed tooling.",
        "immediate_action": "Review the crashing process and recent changes.",
        "recommended_fix": "Patch or reinstall the affected application.",
        "long_term_defense": "Monitor recurring crashes and protect high-risk applications.",
        "mitre": "T1499 - Endpoint Denial of Service",
        "commands": ["wevtutil qe Application /f:text /c:20"],
    },
    "Unexpected Shutdown": {
        "description": "The host shut down unexpectedly.",
        "why": "Power loss, crash, tampering, or system failure may have occurred.",
        "immediate_action": "Check system health and nearby security events.",
        "recommended_fix": "Resolve driver, power, or hardware issues and investigate suspicious timing.",
        "long_term_defense": "Centralize logs and monitor endpoint health.",
        "mitre": "T1529 - System Shutdown/Reboot",
        "commands": ["wevtutil qe System /q:\"*[System[(EventID=6008)]]\" /f:text /c:10"],
    },
}

# Endpoint-specific responses use safe, read-only diagnostic commands by default.
RECOMMENDATIONS.update({
    "UNREGISTERED_SOFTWARE": {"description":"Software is not present in the approved inventory.", "why":"Unapproved applications can increase endpoint risk.", "immediate_action":"Validate the owner, publisher and business approval.", "recommended_fix":"Remove only after authorization; otherwise add an approved allowlist entry.", "long_term_defense":"Use application control and maintain the approved inventory.", "mitre":"", "commands":["Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"]},
    "OUTDATED_BROWSER": {"description":"A browser is below a configured minimum version.", "why":"Browsers are frequent targets for exploitation.", "immediate_action":"Confirm the browser update state.", "recommended_fix":"Update through the vendor-supported mechanism.", "long_term_defense":"Set approved minimum versions and patch regularly.", "mitre":"", "commands":["Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"]},
    "NO_RECENT_OS_UPDATE": {"description":"No recent installed OS update was recorded within the configured threshold.", "why":"Missing patches may expose known vulnerabilities.", "immediate_action":"Review update history and maintenance windows.", "recommended_fix":"Install approved security updates and reboot when required.", "long_term_defense":"Use managed patch deployment and monitor failures.", "mitre":"", "commands":["Get-HotFix | Sort InstalledOn -Descending"]},
    "SYSTEM_SETTING_CHANGED": {"description":"A protected security setting changed from its previous observed value.", "why":"Security-control changes can weaken endpoint defenses.", "immediate_action":"Confirm the change record and responsible administrator.", "recommended_fix":"Restore the approved baseline if unauthorized.", "long_term_defense":"Restrict configuration rights and review changes.", "mitre":"T1112 - Modify Registry", "commands":["Get-NetFirewallProfile"]},
    "SYSTEM_CLOCK_BACKDATED": {"description":"The system clock moved backwards beyond the configured threshold.", "why":"It can disrupt event chronology and obscure activity.", "immediate_action":"Preserve logs and validate the time change.", "recommended_fix":"Restore a trusted time source and investigate related events.", "long_term_defense":"Use authenticated time synchronization and central logging.", "mitre":"", "commands":["w32tm /query /status", "wevtutil qe Security /q:\"*[System[(EventID=4616)]]\" /f:text /c:10"]},
    "USB_DEVICE_FIRST_SEEN": {"description":"A USB device was observed for the first time.", "why":"Removable media can introduce unapproved software or data movement.", "immediate_action":"Validate the device owner and approval status.", "recommended_fix":"Mark approved devices or remove unauthorized media.", "long_term_defense":"Use device control policy and maintain a USB inventory.", "mitre":"", "commands":["Get-PnpDevice -PresentOnly -Class USB"]},
    "FIREWALL_DISABLED": {"description":"Firewall protection appears disabled.", "why":"This reduces network-layer protection.", "immediate_action":"Validate authorization and restore the approved profile.", "recommended_fix":"Enable the required firewall profiles.", "long_term_defense":"Protect firewall policy with centralized management.", "mitre":"T1562.004 - Disable or Modify System Firewall", "commands":["Get-NetFirewallProfile"]},
})


def get_recommendation(threat):
    data = RECOMMENDATIONS.get(threat, {})
    return {
        "threat": threat,
        "description": data.get("description", "A security-relevant event was detected by the SIEM."),
        "why": data.get("why", "The event matched a monitored Windows security condition."),
        "immediate_action": data.get("immediate_action", "Review the event context and validate whether the activity is expected."),
        "recommended_fix": data.get("recommended_fix", "Contain the source if suspicious and document the investigation."),
        "long_term_defense": data.get("long_term_defense", "Continue collecting logs and tune alerts against normal activity."),
        "mitre": data.get("mitre", "T1087 - Account Discovery"),
        "commands": data.get("commands", DEFAULT_COMMANDS),
    }


def format_recommendation(threat):
    rec = get_recommendation(threat)
    commands = "\n".join(f"- {command}" for command in rec["commands"])
    return (
        f"Threat: {rec['threat']}\n"
        f"Description: {rec['description']}\n"
        f"Why it happened: {rec['why']}\n"
        f"Immediate Action: {rec['immediate_action']}\n"
        f"Recommended Fix: {rec['recommended_fix']}\n"
        f"Long-term Defense: {rec['long_term_defense']}\n"
        f"MITRE ATT&CK: {rec['mitre']}\n"
        f"Investigation Commands:\n{commands}"
    )
