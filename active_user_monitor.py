"""Live local Windows session inventory, with no synthetic session data."""
import platform
import re
import subprocess


def _access_type(username):
    """Classify only the local session running the SIEM; never guess other users' roles."""
    try:
        current = subprocess.run(["whoami"], capture_output=True, text=True, timeout=5, check=False).stdout.strip().lower()
        if current and current != username.lower():
            return "Windows user (role not queried)"
        groups = subprocess.run(["whoami", "/groups"], capture_output=True, text=True, timeout=5, check=False).stdout.lower()
        return "Administrator" if "s-1-5-32-544" in groups or "builtin\\administrators" in groups else "Standard user"
    except (OSError, subprocess.TimeoutExpired):
        return "Windows user (role unavailable)"


def get_live_windows_users():
    if platform.system() != "Windows":
        return []
    try:
        result = subprocess.run(["query", "user"], capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    sessions = []
    for line in result.stdout.splitlines()[1:] if result.returncode == 0 else []:
        text = line.lstrip().lstrip(">").strip()
        if not text:
            continue
        fields = re.split(r"\s+", text)
        if not fields:
            continue
        state_index = next((index for index, value in enumerate(fields) if value.lower() in {"active", "disc", "disconnected"}), None)
        if state_index is None:
            continue
        state = fields[state_index]
        sessions.append({"username": fields[0], "hostname": platform.node() or "Local host", "login_time": " ".join(fields[state_index + 2:]) or "Reported by Windows", "last_seen": "Live query", "status": "Active" if state.lower() == "active" else state.title(), "source": "Live Windows session", "access": _access_type(fields[0])})
    if sessions:
        return sessions
    try:
        result = subprocess.run(["whoami"], capture_output=True, text=True, timeout=5, check=False)
        username = result.stdout.strip()
        if result.returncode == 0 and username:
            return [{"username": username, "hostname": platform.node() or "Local host", "login_time": "Not supplied by Windows", "last_seen": "Live query", "status": "Active", "source": "Local process identity", "access": _access_type(username)}]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return sessions
