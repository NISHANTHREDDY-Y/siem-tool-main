import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.path.join(DATA_DIR, "siem.db")

COLLECTOR_CHANNELS = ("Security", "System", "Application")
COLLECTOR_LIMIT_PER_CHANNEL = int(os.getenv("SIEM_COLLECTOR_LIMIT", "500"))
DEMO_MODE = os.getenv("SIEM_DEMO_MODE", "0") == "1"

# Endpoint monitoring is Windows-only; collectors return UNKNOWN on other hosts.
OS_UPDATE_MAX_AGE_DAYS = int(os.getenv("SIEM_OS_UPDATE_MAX_AGE_DAYS", "30"))
TIME_BACKDATE_WARNING_SECONDS = int(os.getenv("SIEM_TIME_BACKDATE_WARNING_SECONDS", "60"))
TIME_BACKDATE_CRITICAL_SECONDS = int(os.getenv("SIEM_TIME_BACKDATE_CRITICAL_SECONDS", "300"))
UNKNOWN_USB_SEVERITY = os.getenv("SIEM_UNKNOWN_USB_SEVERITY", "MEDIUM").upper()
UNREGISTERED_SOFTWARE_SEVERITY = os.getenv("SIEM_UNREGISTERED_SOFTWARE_SEVERITY", "MEDIUM").upper()
BROWSER_OUTDATED_SEVERITY = os.getenv("SIEM_BROWSER_OUTDATED_SEVERITY", "MEDIUM").upper()
EVENT_LOG_INTERVAL_SECONDS = int(os.getenv("SIEM_EVENT_LOG_INTERVAL_SECONDS", "10"))
ENDPOINT_INVENTORY_INTERVAL_SECONDS = int(os.getenv("SIEM_ENDPOINT_INVENTORY_INTERVAL_SECONDS", "300"))
UPDATE_CHECK_INTERVAL_SECONDS = int(os.getenv("SIEM_UPDATE_CHECK_INTERVAL_SECONDS", "3600"))
USB_CHECK_INTERVAL_SECONDS = int(os.getenv("SIEM_USB_CHECK_INTERVAL_SECONDS", "30"))
PACKET_RATE_WARNING_PER_SECOND = int(os.getenv("SIEM_PACKET_RATE_WARNING_PER_SECOND", "1000"))
PACKET_RATE_CRITICAL_PER_SECOND = int(os.getenv("SIEM_PACKET_RATE_CRITICAL_PER_SECOND", "10000"))
APPROVED_SOFTWARE_PATH = os.path.join(BASE_DIR, "config", "approved_software.json")

# A conservative local policy is supplied so a newly copied project can assess
# installed browsers immediately.  These are minimum supported versions, not a
# claim about the vendor's latest release; organisations can override them.
DEFAULT_BROWSER_MINIMUM_VERSIONS = {
    "Google Chrome": "120.0",
    "Microsoft Edge": "120.0",
    "Mozilla Firefox": "120.0",
    "Brave": "120.0",
}

# The default is deliberately local and simple.  Authentication and remote
# ingestion are opt-in so a copied classroom project works without setup.
REQUIRE_LOGIN = os.getenv("SIEM_REQUIRE_LOGIN", "0") == "1"
SECRET_KEY = os.getenv("SIEM_SECRET_KEY", "siem-local-console")
HOST = os.getenv("SIEM_HOST", "127.0.0.1")
PORT = int(os.getenv("SIEM_PORT", "5000"))
INGEST_API_KEY = os.getenv("SIEM_INGEST_API_KEY", "")
BACKGROUND_MONITORING = os.getenv("SIEM_BACKGROUND_MONITORING", "1") == "1"
DATABASE_PROTECTION = os.getenv("SIEM_PROTECT_DATABASE", "0") == "1"

NOTIFICATION_ALERT_LEVELS = {"MEDIUM", "HIGH", "CRITICAL"}

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
