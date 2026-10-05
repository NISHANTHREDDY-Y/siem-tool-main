"""Optional lightweight Windows event forwarder for the central SIEM mode.

Run this file on a Windows endpoint only after the central console has an
SIEM_INGEST_API_KEY.  It forwards selected Windows Event Viewer records over
HTTPS or a trusted private network; it never executes commands received from
the server.
"""
import argparse
import json
import os
import time
import urllib.error
import urllib.request

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

from collector import SUPPORTED_EVENTS
from severity_policy import severity_for_event
from utils import first_meaningful_username, normalize_timestamp

CHANNELS = ("Security", "System", "Application")
STATE_PATH = os.getenv("SIEM_AGENT_STATE", os.path.join(os.path.dirname(__file__), "data", "remote_collector_state.json"))
CENTRAL_URL = os.getenv("SIEM_CENTRAL_URL", "").rstrip("/")
API_KEY = os.getenv("SIEM_INGEST_API_KEY", "")
LIMIT = int(os.getenv("SIEM_AGENT_LIMIT", "300"))


def _load_state():
    try:
        with open(STATE_PATH, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)


def collect_events(state):
    if win32evtlog is None:
        raise RuntimeError("pywin32 is not installed. Run python -m pip install -r requirements.txt.")
    events, updated = [], dict(state)
    for channel in CHANNELS:
        previous = int(state.get(channel, 0) or 0)
        highest, accepted, handle = previous, 0, None
        try:
            handle = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            while accepted < LIMIT:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for event in batch:
                    record = int(getattr(event, "RecordNumber", 0) or 0)
                    if record <= previous:
                        continue
                    highest = max(highest, record)
                    event_id = event.EventID & 0xFFFF
                    if event_id not in SUPPORTED_EVENTS:
                        continue
                    event_type, default_severity = SUPPORTED_EVENTS[event_id]
                    strings = list(getattr(event, "StringInserts", []) or [])
                    message = " | ".join(str(value) for value in strings if value)
                    events.append({
                        "timestamp": normalize_timestamp(event.TimeGenerated), "event_type": event_type,
                        "username": first_meaningful_username(strings), "source": channel,
                        "channel": channel, "computer": getattr(event, "ComputerName", "") or "Remote Windows host",
                        "event_id": event_id, "severity": severity_for_event(event_id, message, default_severity),
                        "message": message[:4000], "raw_event": message[:8000], "record_number": record,
                    })
                    accepted += 1
                    if accepted >= LIMIT:
                        break
        finally:
            if handle is not None:
                win32evtlog.CloseEventLog(handle)
        updated[channel] = highest
    return events, updated


def send_events(events):
    if not CENTRAL_URL or not API_KEY:
        raise RuntimeError("Set SIEM_CENTRAL_URL and SIEM_INGEST_API_KEY before starting the remote collector.")
    body = json.dumps({"events": events}).encode("utf-8")
    request = urllib.request.Request(CENTRAL_URL + "/api/ingest", data=body, method="POST", headers={"Content-Type": "application/json", "X-SIEM-API-Key": API_KEY})
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            if response.status != 200:
                raise RuntimeError(f"Central SIEM returned HTTP {response.status}.")
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError) as exc:
        raise RuntimeError(f"Could not deliver events to central SIEM: {exc}") from exc


def run_once():
    state = _load_state()
    events, updated = collect_events(state)
    if events:
        response = send_events(events)
        _save_state(updated)
        return {"forwarded": len(events), "response": response}
    _save_state(updated)
    return {"forwarded": 0, "response": "No new selected Event Viewer records."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Forward selected Windows Event Viewer records to a central SIEM.")
    parser.add_argument("--loop", action="store_true", help="Run repeatedly instead of once.")
    parser.add_argument("--interval", type=int, default=int(os.getenv("SIEM_AGENT_INTERVAL_SECONDS", "30")), help="Seconds between runs in loop mode.")
    args = parser.parse_args()
    while True:
        try:
            print(run_once())
        except RuntimeError as exc:
            print(f"Remote collector error: {exc}")
        if not args.loop:
            break
        time.sleep(max(10, args.interval))
