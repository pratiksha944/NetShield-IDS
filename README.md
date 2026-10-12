# NetShield IDS — Python Computer Networks Project

An educational, rule-based Intrusion Detection System (IDS) with a Flask dashboard, SQLite event log, simulated demo events, and optional live packet metadata monitoring.

## Requirements
- Python 3.10+
- VS Code
- For Windows live capture: install Npcap from its official website and run VS Code/terminal with appropriate permissions if required.
- Monitor only networks and devices you own or are authorized to inspect.

## Setup (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```
If activation is blocked:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```
Open http://127.0.0.1:5000 in your browser.

## Test without live capture
Click **Add simulated demo events**. The dashboard should show three events marked `DEMO`. These are synthetic examples, not actual attack traffic.

## Live monitoring
1. Install Npcap from its official source on Windows if needed.
2. Start the app with the required permissions for your environment.
3. Leave Interface name empty to use Scapy's default interface. If necessary, enter an interface name supported by Scapy.
4. Click Start monitoring and generate ordinary traffic on your own device/network.
5. Click Stop when finished.

If capture fails, the error appears in the dashboard notice. The dashboard itself runs on localhost only. Do not expose Flask's development server publicly.

## Detection rules
- Packet-rate heuristic: at least 25 packets from one source IP within 10 seconds → MEDIUM alert.
- Port-diversity heuristic: at least 8 distinct destination ports from one source IP within 30 seconds → HIGH alert.
These thresholds are demonstration values, not universal indicators of an attack. They can produce false positives and do not guarantee detection.

## Files
- `app.py`: Flask routes and application entry point
- `monitor.py`: Scapy capture loop and detection rules
- `database.py`: SQLite persistence
- `templates/index.html`: dashboard layout
- `static/style.css`: dashboard styles
- `static/app.js`: dashboard refresh and actions
- `ids_events.db`: created automatically on first run

## Limitations and future scope
This prototype analyzes IP packet metadata only; it does not inspect packet payloads, block connections, or guarantee detection. Future work could include PCAP upload/replay, configurable rules, authentication for multi-user deployment, alert export, and evaluation against a labeled dataset.
