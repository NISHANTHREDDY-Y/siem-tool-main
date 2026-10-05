"""Local adapter packet-rate monitor using Windows interface counters."""
import json
import platform
import subprocess
from datetime import datetime

from config import PACKET_RATE_WARNING_PER_SECOND, PACKET_RATE_CRITICAL_PER_SECOND
from database import get_connection, insert_alert


def classify_packet_rate(packet_rate):
    if packet_rate >= PACKET_RATE_CRITICAL_PER_SECOND:
        return "CRITICAL"
    if packet_rate >= PACKET_RATE_WARNING_PER_SECOND:
        return "HIGH"
    return "PASS"


def _connection_snapshot():
    """Return a best-effort snapshot of current established TCP connections.

    Adapter counters cannot attribute packets to a process.  This snapshot is
    attached as nearby investigative evidence, never presented as the proven
    cause of the measured traffic spike.
    """
    command = [
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
        "ForEach-Object {$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;PID=$_.OwningProcess;ProcessName=if($p){$p.ProcessName}else{'Unknown'}}} | "
        "Select-Object -First 30 | ConvertTo-Json -Compress",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=12, check=False)
        rows = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else []
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []
    return [rows] if isinstance(rows, dict) else rows if isinstance(rows, list) else []


def summarize_connections(rows, limit=3):
    values = []
    for row in rows[:limit]:
        remote = f"{row.get('RemoteAddress', 'Unknown')}:{row.get('RemotePort', '')}".rstrip(":")
        values.append(f"{row.get('ProcessName', 'Unknown')} (PID {row.get('PID', '?')}) → {remote}")
    return "; ".join(values) or "No established TCP connection snapshot was available."


def collect_packet_flow():
    if platform.system() != "Windows":
        return {"status": "UNKNOWN", "interfaces": [], "message": "Packet-rate monitoring requires Windows."}
    command = ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes,ReceivedUnicastPackets,SentUnicastPackets | ConvertTo-Json -Compress"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "UNKNOWN", "interfaces": [], "message": "Network adapter statistics are unavailable."}
    try:
        rows = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else []
    except ValueError:
        rows = []
    if isinstance(rows, dict):
        rows = [rows]
    if not rows:
        return {"status": "UNKNOWN", "interfaces": [], "message": "No active adapter statistics were returned."}

    now = datetime.now()
    now_string = now.strftime("%Y-%m-%d %H:%M:%S")
    results = []
    conn = get_connection()
    for row in rows:
        name = str(row.get("Name") or "")
        if not name:
            continue
        received = int(row.get("ReceivedUnicastPackets") or 0)
        sent = int(row.get("SentUnicastPackets") or 0)
        baseline = conn.execute("SELECT * FROM network_flow_baselines WHERE interface_name=?", (name,)).fetchone()
        packet_rate, elapsed = None, None
        if baseline:
            try:
                previous_time = datetime.strptime(baseline["timestamp"], "%Y-%m-%d %H:%M:%S")
                elapsed = max((now - previous_time).total_seconds(), 1)
                packet_delta = max(0, received - baseline["received_packets"]) + max(0, sent - baseline["sent_packets"])
                packet_rate = packet_delta / elapsed
            except (ValueError, TypeError):
                pass
        conn.execute("INSERT INTO network_flow_baselines(interface_name,timestamp,received_bytes,sent_bytes,received_packets,sent_packets) VALUES(?,?,?,?,?,?) ON CONFLICT(interface_name) DO UPDATE SET timestamp=excluded.timestamp,received_bytes=excluded.received_bytes,sent_bytes=excluded.sent_bytes,received_packets=excluded.received_packets,sent_packets=excluded.sent_packets", (name, now_string, int(row.get("ReceivedBytes") or 0), int(row.get("SentBytes") or 0), received, sent))
        severity = classify_packet_rate(packet_rate or 0) if packet_rate is not None else "PASS"
        result_item = {"interface": name, "packet_rate": round(packet_rate, 2) if packet_rate is not None else None, "sample_seconds": round(elapsed, 2) if elapsed is not None else None, "severity": severity}
        results.append(result_item)
    conn.commit()
    conn.close()

    connections = _connection_snapshot()
    connection_summary = summarize_connections(connections)
    for item in results:
        if item["severity"] in {"HIGH", "CRITICAL"}:
            bucket = now.strftime("%Y%m%d%H%M")
            evidence = dict(item, established_tcp_connections=connections, connection_snapshot_note="Connection entries are current nearby evidence, not proven packet attribution.")
            insert_alert(item["severity"], f"Measured {item['packet_rate']} packets/second on local adapter {item['interface']} over {item['sample_seconds']} seconds. Current established TCP evidence: {connection_summary}", threat="HIGH_PACKET_FLOW", source="Local network adapter", category="NETWORK", evidence=json.dumps(evidence), alert_key=f"packet-flow:{item['interface']}:{bucket}:{item['severity']}", confidence=.8)
    overall = "CRITICAL" if any(item["severity"] == "CRITICAL" for item in results) else "WARNING" if any(item["severity"] == "HIGH" for item in results) else "PASS"
    return {"status": overall, "interfaces": results, "connections": connections, "message": "First measurement establishes a local baseline; later measurements calculate packets per second. Current TCP connections are evidence for investigation, not confirmed packet attribution."}
