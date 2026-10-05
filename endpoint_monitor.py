"""Windows endpoint inventory orchestration.  No synthetic telemetry is emitted."""
import platform
from datetime import datetime

from browser_monitor import collect_browsers
from software_monitor import collect_software
from system_change_monitor import collect_security_settings
from update_monitor import collect_updates
from usb_monitor import collect_usb_devices
from hardware_monitor import collect_hardware_and_drivers
from database import save_snapshot


def endpoint_supported():
    return platform.system() == "Windows"


def run_endpoint_scan():
    if not endpoint_supported():
        return {"status": "UNKNOWN", "message": "Windows endpoint monitoring requires Windows.", "timestamp": datetime.now().isoformat(timespec="seconds")}
    results = {"software": collect_software(), "updates": collect_updates(), "browsers": collect_browsers(), "settings": collect_security_settings(), "usb": collect_usb_devices(), "hardware": collect_hardware_and_drivers()}
    states = [item.get("status", "UNKNOWN") for item in results.values()]
    status = "CRITICAL" if "CRITICAL" in states else "HIGH" if "HIGH" in states else "WARNING" if "WARNING" in states else "PASS" if states and all(x == "PASS" for x in states) else "UNKNOWN"
    payload = {"status": status, "timestamp": datetime.now().isoformat(timespec="seconds"), "results": results}
    save_snapshot("endpoint_scan", payload, status)
    return payload
