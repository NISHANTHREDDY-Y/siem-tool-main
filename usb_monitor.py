import platform, subprocess
from datetime import datetime
from database import upsert_usb_device, record_usb_event, insert_alert
from config import UNKNOWN_USB_SEVERITY

def collect_usb_devices():
    if platform.system() != "Windows": return {"status":"UNKNOWN", "devices":[]}
    command=["powershell","-NoProfile","-NonInteractive","-Command","Get-PnpDevice -PresentOnly -Class USB | Select-Object InstanceId,FriendlyName,Manufacturer,Status | ConvertTo-Json -Compress"]
    try: result=subprocess.run(command,capture_output=True,text=True,timeout=15,check=False)
    except (OSError, subprocess.TimeoutExpired): return {"status":"UNKNOWN","devices":[]}
    import json
    try: devices=json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else []
    except ValueError: devices=[]
    if isinstance(devices,dict): devices=[devices]
    observed=[]
    for raw in devices:
        device={"device_id":raw.get("InstanceId", ""),"serial_number":raw.get("InstanceId", "").split("\\")[-1],"manufacturer":raw.get("Manufacturer", ""),"product_name":raw.get("FriendlyName", ""),"timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"event_type":"USB_CONNECTED","source":"PnP"}
        if not device["device_id"]: continue
        old=upsert_usb_device(device); record_usb_event(device); observed.append(device)
        if not old:
            insert_alert(UNKNOWN_USB_SEVERITY, f"Unknown USB device connected: {device['product_name'] or device['device_id']}", threat="USB_DEVICE_FIRST_SEEN", category="USB", evidence=json.dumps(device), alert_key="usb:"+device["device_id"])
    return {"status":"WARNING" if observed else "PASS","devices":observed}
