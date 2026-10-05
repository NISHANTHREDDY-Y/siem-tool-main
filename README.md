# Windows Endpoint SIEM SOC Console

## What this project is

A Windows-focused Flask and SQLite SIEM for a local lab or student submission. By default it monitors the single Windows computer on which it is started, stores data beside the project, and opens at `http://127.0.0.1:5000` without requiring an account. It does not invent security telemetry: a Windows API or audit event that is unavailable is shown as unavailable/unknown rather than as a false result.

## Run the standalone project

### First-time Windows setup

1. Extract the downloaded ZIP.
2. Open the extracted folder named `siem-tool-main` in File Explorer.
3. Right-click inside that folder and choose **Open in Terminal**, then open **PowerShell as Administrator** if you can. Your PowerShell prompt must end in `\siem-tool-main>` and that folder must contain both `app.py` and `requirements.txt`.

Check before installing anything:

```powershell
Get-ChildItem .\app.py, .\requirements.txt
```

If both files are listed, run these commands one at a time:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
python .\app.py
```

When the final command says that the server is running, open this address in your browser:

`http://127.0.0.1:5000`

Open `http://127.0.0.1:5000`. The first endpoint scan establishes local inventory baselines. After that, the background monitor collects selected Event Viewer records and packet-rate measurements every 10 seconds; endpoint inventory is refreshed every five minutes. Use **Security → Run Security Scan** whenever you want an immediate scan.

### If PowerShell says `requirements.txt` cannot be found

You are one folder too high or too low. Do **not** run `cd siem-tool-main` again if the prompt already ends with `\siem-tool-main>`.

Run this to locate the correct folder:

```powershell
Get-ChildItem -Path . -Recurse -Filter requirements.txt | Select-Object -ExpandProperty FullName
```

Move into the folder shown immediately before `requirements.txt`, then run the installation commands again. For example, if the result ends in `\siem-tool-main\requirements.txt`:

```powershell
cd .\siem-tool-main
```

### If startup says `No module named 'werkzeug'` or another Python package is missing

The old virtual environment is incomplete or was created with a Python installation that no longer exists. Close the running app, keep the project files, and rebuild **only** the virtual environment:

```powershell
deactivate
Remove-Item -LiteralPath .\.venv -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath .\venv -Recurse -Force -ErrorAction SilentlyContinue
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
python .\app.py
```

Deleting `.venv` or `venv` in this step is safe: they contain installed Python packages only. Do not delete `data\siem.db` unless you intentionally want to erase collected logs, alerts, baselines, and settings.

Run automated checks with:

```powershell
python -m unittest discover -s tests -v
```

## What it collects and alerts on

| Feature | Data source | Behaviour |
| --- | --- | --- |
| Event logs | Local Windows Security, System, and Application Event Viewer logs | Collects selected event IDs with their original Event Viewer timestamp, channel, computer, and message. |
| Critical alerts | Event rules and correlation | Critical: audit-log clearing, brute force/password-spray thresholds, major clock backdating, administrator password change/reset, critical packet-rate threshold, and a driver/device baseline entry that disappears. |
| Software | Windows uninstall registry | With an approved allowlist, non-approved applications are alerted. With an empty allowlist, the first scan makes a baseline and only software appearing later is alerted. |
| OS updates | Windows hotfix inventory | Alerts when no recent installed update meets `SIEM_OS_UPDATE_MAX_AGE_DAYS` (default 30). |
| Browsers | Installed executable file versions | Uses a built-in minimum policy (120.0) so checking works on a copied project. Set the `SIEM_MIN_*_VERSION` values to your organisation's requirement. A detected downgrade is High. |
| Security settings | Firewall, RDP and UAC setting snapshots | The first scan establishes a baseline; later setting changes are recorded and alerted. |
| Time integrity | Windows Event ID 4616 | Detects time change and grades backwards changes by the configured duration. |
| USB | Windows USB inventory / events | Records first-seen device evidence and connection timeline. |
| Hardware and drivers | `Win32_PnPSignedDriver` | Baselines driver version, date and signature. A later missing baseline driver/device is Critical evidence; validate it because unplugging or legitimate uninstallation can also cause it. |
| Packet flow | Local adapter packet counters plus TCP connection snapshot | Measures packets/second on each local adapter. Spike alerts include current remote IP/port and process snapshots as investigation evidence, not proven packet attribution. |
| Ports | Local `netstat`/PowerShell inventory | Displays TCP and UDP listeners, address, PID, owning process and an explanatory note. |
| Firewall monitor | Current Defender Firewall PowerShell/CIM state and saved WFP events | Displays profiles, rules, service, Windows build, component version, most recent hotfix, and current connection-audit policy. Historical allowed/blocked records require Windows WFP audit events 5156/5157. |

### Important limits

- This is an educational local SIEM, not an EDR or a replacement for a managed production SIEM.
- A driver/device disappearance is evidence, not proof of malicious deletion. Review the alert details before taking action.
- Packet counters identify an adapter. The accompanying TCP connections are only a nearby snapshot and cannot prove which process generated the packet spike.
- Browser minimum versions are a local policy floor, not an automatically downloaded vendor “latest version.” Update the policy as needed.
- Security Event log access, driver inventory, firewall audit status, and Event Viewer history work best when the console is run as Administrator.

## Firewall connection history

The Firewall page **reads** audit status but never changes Windows audit policy by itself. If the page shows no historical allowed/blocked events and your instructor permits enabling it, run this in an elevated PowerShell window:

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

Then make a connection and wait for the collector. This setting can generate many Security log entries, so only enable it deliberately.

## Optional policy configuration

Set variables in the same PowerShell window before `python app.py`.

```powershell
$env:SIEM_OS_UPDATE_MAX_AGE_DAYS="30"
$env:SIEM_MIN_CHROME_VERSION="120.0"
$env:SIEM_MIN_EDGE_VERSION="120.0"
$env:SIEM_MIN_FIREFOX_VERSION="120.0"
$env:SIEM_MIN_BRAVE_VERSION="120.0"
$env:SIEM_TIME_BACKDATE_WARNING_SECONDS="60"
$env:SIEM_TIME_BACKDATE_CRITICAL_SECONDS="300"
$env:SIEM_PACKET_RATE_WARNING_PER_SECOND="1000"
$env:SIEM_PACKET_RATE_CRITICAL_PER_SECOND="10000"
```

To use an approval list instead of baseline mode, edit `config\approved_software.json`:

```json
{
  "approved_software": [
    {"name": "Google Chrome", "publisher": "Google", "allowed_versions": []}
  ]
}
```

An empty list is safe: it does **not** flag every application at the first scan.

## Optional protected local deployment

The normal standalone setup is intentionally no-login and bound to `127.0.0.1`. Do not expose it to a shared network in that mode.

To require local accounts, set a long random secret before starting. The first visitor creates the Admin account; that Admin creates additional users in Settings.

```powershell
$env:SIEM_REQUIRE_LOGIN="1"
$env:SIEM_SECRET_KEY="replace-this-with-a-long-random-secret"
python app.py
```

To limit access to the local database file with Windows ACLs (run as Administrator):

```powershell
$env:SIEM_PROTECT_DATABASE="1"
python app.py
```

ACL protection is not encryption. Use BitLocker or EFS if encryption at rest is required.

## Optional multi-device central collection

The default project monitors only its own Windows computer. The included `remote_collector.py` makes multi-device collection possible when you explicitly opt in.

1. On the **central** Windows computer, set a strong shared API key and bind the console only to a trusted private network address. Configure HTTPS/reverse proxy protection for any real network deployment.

   ```powershell
   $env:SIEM_INGEST_API_KEY="replace-with-a-long-random-shared-key"
   $env:SIEM_HOST="0.0.0.0"
   $env:SIEM_REQUIRE_LOGIN="1"
   $env:SIEM_SECRET_KEY="replace-with-a-different-long-random-secret"
   python app.py
   ```

2. Copy the project to each remote Windows computer, install requirements, then set the central URL and the same ingestion key.

   ```powershell
   $env:SIEM_CENTRAL_URL="https://central-siem.example:5000"
   $env:SIEM_INGEST_API_KEY="replace-with-a-long-random-shared-key"
   python remote_collector.py --loop --interval 30
   ```

The remote collector forwards only the project’s selected Event Viewer records and keeps its own per-channel cursor. It never accepts remote commands. Use a Windows service or Task Scheduler for persistence in a real lab deployment; use TLS, firewall rules, a unique key per agent, log forwarding, protected backups, and a production web server before treating this as production software.

## Submission demonstration

1. Open **Dashboard** and show local counts and charts.
2. Open **Logs**, point out the **Log Type** column (Security/System/Application), and expand an event explanation.
3. Open **Alerts**, click the `?` severity guide, and explain the level of one alert.
4. Open **Security** and run **Run Security Scan** to show software, updates, browsers, USB, hardware, and driver baseline data.
5. Open **Firewall Monitor** to show current firewall profiles/version/audit status and any collected Windows firewall evidence.

## Project data and files

```text
siem-tool-main/
├── app.py                  Web console, optional authentication and ingestion API
├── collector.py            Local Event Viewer collector
├── remote_collector.py     Optional outbound remote Windows event forwarder
├── endpoint_monitor.py     Endpoint scan coordinator
├── hardware_monitor.py     Hardware/driver baseline and disappearance detection
├── packet_monitor.py       Adapter packet rate and TCP evidence snapshot
├── firewall_monitor.py     Live read-only Defender Firewall status
├── database.py             Additive SQLite schema and queries
├── config/approved_software.json
├── data/siem.db            Created locally on first run; do not distribute this file
└── tests/                  Rule tests
```

The packaged standalone copy excludes `data/siem.db`, virtual environments, logs, and Python cache files so it begins on the computer where it is installed.

Version: **3.0**
