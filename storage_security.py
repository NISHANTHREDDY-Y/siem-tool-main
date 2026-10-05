"""Optional local storage hardening for the standalone Windows deployment."""
import getpass
import os
import platform
import subprocess

from config import DATABASE_PROTECTION, DB_PATH


def protect_database_file():
    """Limit the SQLite file ACL only when the administrator explicitly opts in.

    Encryption is intentionally not pretended here.  Use BitLocker or EFS for
    encryption at rest; this option simply reduces who can read the local file.
    """
    if not DATABASE_PROTECTION:
        return {"enabled": False, "message": "Database ACL protection is not enabled."}
    if platform.system() != "Windows" or not os.path.exists(DB_PATH):
        return {"enabled": False, "message": "Database ACL protection requires an existing Windows database."}
    user = getpass.getuser()
    command = [
        "icacls", DB_PATH, "/inheritance:r", "/grant:r",
        f"{user}:(R,W)", "SYSTEM:(F)", "Administrators:(F)",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"enabled": False, "message": "Could not apply the requested database ACL."}
    return {
        "enabled": result.returncode == 0,
        "message": "Database file ACL protection applied." if result.returncode == 0 else "Database ACL protection could not be applied; run as Administrator.",
    }
