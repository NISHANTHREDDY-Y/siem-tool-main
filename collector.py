try:
    import win32evtlog
except ImportError:
    win32evtlog = None

from config import COLLECTOR_CHANNELS, COLLECTOR_LIMIT_PER_CHANNEL
from database import get_collector_status, insert_log, update_collector_state
from utils import first_meaningful_username, normalize_timestamp
from severity_policy import severity_for_event

SUPPORTED_EVENTS = {
    4624: ("Successful Login", "INFO"),
    4625: ("Failed Login", "MEDIUM"),
    4634: ("User Logoff", "INFO"),
    4647: ("User Initiated Logoff", "INFO"),
    4672: ("Privilege Escalation", "HIGH"),
    4688: ("Process Created", "LOW"),
    4689: ("Process Exited", "INFO"),
    4697: ("Service Installed", "HIGH"),
    4698: ("Scheduled Task Created", "MEDIUM"),
    4702: ("Scheduled Task Updated", "MEDIUM"),
    4719: ("Audit Policy Changed", "HIGH"),
    4720: ("New User", "HIGH"),
    4722: ("User Enabled", "MEDIUM"),
    4723: ("Password Change", "HIGH"),
    4724: ("Password Reset", "HIGH"),
    4725: ("User Disabled", "MEDIUM"),
    4726: ("Deleted User", "HIGH"),
    4732: ("Group Membership Changes", "HIGH"),
    4740: ("Account Locked", "HIGH"),
    4768: ("Kerberos TGT Request", "INFO"),
    4769: ("Kerberos Service Ticket", "INFO"),
    4771: ("Kerberos Failure", "MEDIUM"),
    4776: ("NTLM Authentication", "LOW"),
    5140: ("Network Share Access", "LOW"),
    5156: ("Firewall Allowed Connection", "INFO"),
    5157: ("Firewall Blocked Connection", "MEDIUM"),
    5158: ("Firewall Bound Port", "LOW"),
    20001: ("Driver Installed or Updated", "MEDIUM"),
    20003: ("Driver Installation Event", "MEDIUM"),
    219: ("Driver or Device Configuration", "MEDIUM"),
    6005: ("System Startup", "INFO"),
    6006: ("System Shutdown", "INFO"),
    6008: ("Unexpected Shutdown", "HIGH"),
    7031: ("Service Crash", "MEDIUM"),
    7034: ("Service Crash", "MEDIUM"),
    7045: ("New Service Installed", "HIGH"),
    1000: ("Application Crash", "MEDIUM"),
    1001: ("Application Hang", "LOW"),
    1026: (".NET Runtime Exception", "MEDIUM"),
    1102: ("Audit Log Cleared", "CRITICAL"),
    4616: ("System Time Changed", "MEDIUM"),
    6416: ("External Device Recognized", "MEDIUM"),
    4733: ("Group Membership Removed", "HIGH"),
}


def collect_windows_logs():
    if win32evtlog is None:
        return {"status": "unavailable", "message": "pywin32 is not available", "collected": 0}

    state = {row["channel"]: row["last_record_number"] for row in get_collector_status()}
    total = 0
    max_records = {}

    for channel in COLLECTOR_CHANNELS:
        collected = 0
        last_seen = state.get(channel, 0) or 0
        max_record = last_seen
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            while collected < COLLECTOR_LIMIT_PER_CHANNEL:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break
                for event in events:
                    record_number = getattr(event, "RecordNumber", 0) or 0
                    if record_number <= last_seen:
                        continue
                    event_id = event.EventID & 0xFFFF
                    if event_id not in SUPPORTED_EVENTS:
                        continue
                    event_type, severity = SUPPORTED_EVENTS[event_id]
                    strings = list(getattr(event, "StringInserts", []) or [])
                    username = first_meaningful_username(strings)
                    computer = getattr(event, "ComputerName", "") or ""
                    message = " | ".join(str(item) for item in strings if item)
                    severity = severity_for_event(event_id, message, severity)
                    inserted = insert_log(
                        normalize_timestamp(event.TimeGenerated),
                        event_type,
                        username,
                        channel,
                        severity=severity,
                        computer=computer,
                        channel=channel,
                        event_id=event_id,
                        message=message[:4000],
                        raw_event=message[:8000],
                        record_number=record_number,
                    )
                    if inserted:
                        total += 1
                        collected += 1
                    max_record = max(max_record, record_number)
                    if collected >= COLLECTOR_LIMIT_PER_CHANNEL:
                        break
        except Exception as exc:
            max_records[channel] = {"error": str(exc), "last_record_number": max_record}
        finally:
            if handle is not None:
                try:
                    win32evtlog.CloseEventLog(handle)
                except Exception:
                    pass
            if max_record > last_seen:
                update_collector_state(channel, max_record)
            max_records.setdefault(channel, {"last_record_number": max_record})

    return {"status": "ok", "collected": total, "channels": max_records}


if __name__ == "__main__":
    print(collect_windows_logs())
