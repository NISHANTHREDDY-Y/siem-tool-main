import re
from config import TIME_BACKDATE_WARNING_SECONDS, TIME_BACKDATE_CRITICAL_SECONDS

def evaluate_time_change(old_time, new_time):
    delta = (new_time - old_time).total_seconds()
    if delta < 0:
        severity = "CRITICAL" if delta <= -TIME_BACKDATE_CRITICAL_SECONDS else "HIGH" if delta <= -TIME_BACKDATE_WARNING_SECONDS else "MEDIUM"
        return {"event_type":"SYSTEM_CLOCK_BACKDATED", "severity":severity,"delta_seconds":delta}
    return {"event_type":"SYSTEM_TIME_CHANGED","severity":"MEDIUM","delta_seconds":delta}

def time_change_from_message(message):
    # Windows formats differ by locale; only return an assessment when two ISO timestamps are present.
    values = re.findall(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", message or "")
    if len(values) < 2: return None
    from datetime import datetime
    return evaluate_time_change(datetime.fromisoformat(values[0]), datetime.fromisoformat(values[1]))
