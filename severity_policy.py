"""Context-aware severity and human-readable event explanations."""
TRUSTED_SERVICE_MARKERS = (
    "\\program files\\mcafee\\", "\\program files (x86)\\mcafee\\",
    "microsoft defender", "windows defender", "\\program files\\windowsapps\\",
    "\\program files\\google\\", "\\program files\\mozilla firefox\\",
    "\\program files\\microsoft\\", "\\program files (x86)\\microsoft\\",
    "microsoft edge update", "adobe acrobat update", "\\program files (x86)\\adobe\\",
    "\\program files\\hp\\", "\\program files (x86)\\k7 computing\\",
)
SUSPICIOUS_SERVICE_MARKERS = ("\\appdata\\", "\\temp\\", "powershell", "rundll32", "regsvr32", "mshta", "wscript", "cscript")

def service_severity(message):
    text = (message or "").lower()
    if any(marker in text for marker in TRUSTED_SERVICE_MARKERS):
        return "LOW"
    if any(marker in text for marker in SUSPICIOUS_SERVICE_MARKERS):
        return "HIGH"
    return "MEDIUM"

def severity_for_event(event_id, message, default):
    return service_severity(message) if event_id in {4697, 7045} else default

def explain_event(log):
    event_id, raw = int(log.get("event_id", 0) or 0), log.get("raw_event") or log.get("message") or "No event details were supplied by Windows."
    if event_id == 7045:
        severity = service_severity(raw)
        why = "Windows Service Control Manager recorded a new service registration. This event is common during legitimate software installation and updates."
        if severity == "LOW": reason = "The executable path matches a recognised installed security or software vendor location. It is low priority unless the installation was unexpected."
        elif severity == "HIGH": reason = "The command or executable path includes a commonly abused location or interpreter. Verify the file, publisher, and change approval promptly."
        else: reason = "The service has not been identified as trusted or suspicious from this event alone. It needs review, but is not by itself proof of compromise."
        return {"what": why, "severity_reason": reason, "response": "Confirm the service name, executable path, publisher, and associated change request. Do not remove it until it is verified."}
    mapping = {1102:("Windows recorded that the Security audit log was cleared.", "Clearing audit history can obstruct an investigation.", "Preserve remaining logs and investigate the responsible account immediately."), 4719:("Windows recorded an audit policy change.", "Reduced auditing can remove security visibility.", "Verify the authorized policy change and restore the approved audit baseline if needed."), 4625:("A logon attempt failed.", "Single failures are common; repeated failures can indicate guessing or stale credentials.", "Check the user and source; investigate repeated failures."), 4723:("Windows recorded an account password change.", "Password changes involving privileged accounts need change approval verification.", "Validate the target account and approved change record."), 4724:("Windows recorded an account password reset.", "Password resets can affect access control and should be verified for privileged accounts.", "Validate the target account and immediately investigate an unexpected administrator reset."), 4616:("Windows recorded a system time change.", "Backdating can affect the order and reliability of security evidence.", "Verify the time source and review nearby security events."), 6416:("Windows recognised an external device.", "Removable devices require ownership and approval validation.", "Confirm the device owner and approval status."), 20001:("Windows recorded a driver installation or update.", "Drivers run with high privileges and should come from approved publishers.", "Verify the driver publisher, signature, and change record."), 20003:("Windows recorded a driver installation event.", "Unexpected driver changes can affect system integrity.", "Verify the device and driver publisher."), 219:("Windows recorded a driver or device configuration event.", "A device or driver may need review if the change was unexpected.", "Review the device identity and related driver event details.")}
    what, reason, response = mapping.get(event_id, ("Windows recorded this monitored event.", "Its severity reflects the event type and currently available context.", "Review the timestamp, user, host, and raw event details to determine whether it was expected."))
    return {"what":what, "severity_reason":reason, "response":response}
