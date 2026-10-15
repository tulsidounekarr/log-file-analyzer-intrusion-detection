# Log File Analyzer for Intrusion Detection

A Python, Pandas, Scikit-learn, and Streamlit dashboard for reviewing authentication and web access logs, highlighting suspicious patterns, and exporting incident reports.

## Features
- Upload CSV, SSH/auth `.log` or `.txt`, and common Apache access logs.
- Normalize timestamps, IP addresses, usernames, and outcomes.
- Flag repeated failed logins and attempts against multiple accounts.
- Detect common web scanning indicators such as `/.env`, `/wp-admin`, and `/phpmyadmin`.
- Use Scikit-learn Isolation Forest to flag unusual per-IP activity when enough IPs are present.
- Visualize login outcomes and event volume over time.
- Download incident alerts and normalized logs as CSV.
- Built-in synthetic sample dataset for a quick demo.

## Run on Windows PowerShell
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```
Open the local URL printed by Streamlit (normally `http://localhost:8501`). Keep the terminal open while using the app.

## CSV input format
CSV should have a header row. Recognized aliases include:
- Timestamp: `timestamp`, `time`, `datetime`, `date`, `@timestamp`
- IP: `ip`, `src_ip`, `source_ip`, `client_ip`, `remote_addr`, `remote_ip`
- Username: `username`, `user`, `account`, `login`
- Event: `event`, `message`, `action`, `request`, `log`, `details`
- Status: `status`, `result`, `outcome`, `auth_status`

Example:
```csv
timestamp,ip,username,event
2026-10-15 08:00:00,192.0.2.10,alice,login_success
2026-10-15 08:00:10,198.51.100.20,admin,login_failed
```

Plain-text parsing supports common SSH authentication lines and Apache Combined Log Format entries. Convert unsupported formats to CSV using the fields above.

## Detection logic
1. Repeated failures: source IP at or above the configurable failed/denied event threshold.
2. Multiple accounts targeted: IP associated with at least the configured number of distinct usernames.
3. Web scanning indicator: selected common probe strings in request/event text.
4. Isolation Forest: per-IP activity features; enabled with at least six unique IPs.

These heuristics are triage indicators, not proof of compromise. Review surrounding events before drawing conclusions. Sample data is synthetic and uses documentation-only IP ranges.

## Limitations and safety
- Does not block IPs or change firewall rules.
- Does not contact an external IP reputation service.
- IP-based anomaly flags are contextual clues, not a verdict.
- Upload only logs you are authorized to analyze; logs may contain personal or sensitive data.
