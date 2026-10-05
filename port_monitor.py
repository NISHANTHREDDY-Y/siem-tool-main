"""Local endpoint port inventory. Remote endpoints require collector telemetry."""
import subprocess

KNOWN_PORTS = {20:"FTP data transfer",21:"FTP control",22:"Secure Shell remote administration",23:"Telnet (legacy remote administration)",25:"SMTP mail transfer",53:"DNS resolution",80:"HTTP web service",123:"Network Time Protocol",135:"Windows RPC",139:"NetBIOS session service",389:"LDAP directory service",443:"HTTPS web service",445:"SMB file sharing",500:"IPsec/IKE key exchange",623:"IPMI remote management",1900:"SSDP device discovery",3389:"Remote Desktop",3306:"MySQL database",3702:"WS-Discovery",5432:"PostgreSQL database",6379:"Redis database",8080:"Alternative HTTP service",8443:"Alternative HTTPS service"}


def process_name(pid):
    try:
        result = subprocess.run(["tasklist", "/FI", f"PID eq {int(pid)}", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=5, check=False)
        line = result.stdout.strip()
        return line.split('","')[0].strip('"') if line and not line.startswith("INFO:") else "Unknown process"
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return "Unknown process"


def _port_from_address(address):
    try:
        return int(address.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None


def _purpose(port, process, pid):
    service = KNOWN_PORTS.get(port)
    if service:
        return f"{service}. Process {process} (PID {pid}) owns this listener. Confirm that this service is expected on this host."
    return f"Process {process} (PID {pid}) owns this application-specific listener. Netstat cannot determine its business purpose; verify the process path and owner before treating it as expected."


def get_open_ports():
    try:
        tcp = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=8, check=False)
        udp = subprocess.run(["netstat", "-ano", "-p", "udp"], capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    ports = []
    for raw in tcp.stdout.splitlines():
        fields = raw.split()
        if len(fields) < 5 or fields[0].upper() != "TCP" or fields[3].upper() != "LISTENING":
            continue
        port = _port_from_address(fields[1])
        if port is None:
            continue
        pid, process = fields[4], process_name(fields[4])
        ports.append({"protocol":"TCP", "local_address":fields[1], "port":port, "state":"LISTENING", "pid":pid, "process":process, "purpose":_purpose(port, process, pid)})
    for raw in udp.stdout.splitlines():
        fields = raw.split()
        if len(fields) < 4 or fields[0].upper() != "UDP":
            continue
        port = _port_from_address(fields[1])
        if port is None:
            continue
        pid, process = fields[-1], process_name(fields[-1])
        ports.append({"protocol":"UDP", "local_address":fields[1], "port":port, "state":"BOUND", "pid":pid, "process":process, "purpose":_purpose(port, process, pid)})
    return sorted({(x["protocol"], x["local_address"], x["pid"]): x for x in ports}.values(), key=lambda x: (x["port"], x["protocol"]))
