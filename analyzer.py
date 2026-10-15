from __future__ import annotations
from io import StringIO
import re
from typing import Any
import pandas as pd
from sklearn.ensemble import IsolationForest

SAMPLE_ROWS = [
("2026-10-15 08:00:00","192.0.2.10","alice","login_success","auth"),
("2026-10-15 08:03:00","192.0.2.11","bob","login_success","auth"),
("2026-10-15 08:10:00","198.51.100.20","admin","login_failed","auth"),
("2026-10-15 08:10:15","198.51.100.20","root","login_failed","auth"),
("2026-10-15 08:10:30","198.51.100.20","test","login_failed","auth"),
("2026-10-15 08:10:45","198.51.100.20","guest","login_failed","auth"),
("2026-10-15 08:11:00","198.51.100.20","alice","login_failed","auth"),
("2026-10-15 08:12:00","198.51.100.20","service","login_failed","auth"),
("2026-10-15 08:14:00","203.0.113.8","admin","login_failed","auth"),
("2026-10-15 08:14:10","203.0.113.8","administrator","login_failed","auth"),
("2026-10-15 08:14:20","203.0.113.8","support","login_failed","auth"),
("2026-10-15 09:00:00","192.0.2.10","alice","login_success","auth"),
("2026-10-15 09:10:00","198.51.100.44","-","GET /.env HTTP/1.1 404","apache"),
("2026-10-15 09:10:10","198.51.100.44","-","GET /wp-admin HTTP/1.1 404","apache"),
("2026-10-15 09:10:20","198.51.100.44","-","GET /phpmyadmin HTTP/1.1 404","apache"),
("2026-10-15 10:00:00","203.0.113.25","carol","login_success","auth"),
("2026-10-15 10:15:00","203.0.113.25","carol","login_failed","auth"),
("2026-10-15 10:16:00","203.0.113.25","carol","login_failed","auth"),
]
ALIASES = {
"timestamp":{"timestamp","time","datetime","date","@timestamp"},
"ip":{"ip","src_ip","source_ip","client_ip","remote_addr","remote_ip","host_ip"},
"username":{"username","user","account","login","user_name"},
"event":{"event","message","action","request","log","details"},
"status":{"status","result","outcome","auth_status"},
}
FAIL_TERMS = ("fail","denied","invalid","unauthorized","401","403","error")
SUCCESS_TERMS = ("success","accepted","logged in","200")
SCAN_TERMS = ("/.env","/wp-admin","/phpmyadmin","/.git","union select","../","etc/passwd")

def make_sample_csv() -> str:
    return pd.DataFrame(SAMPLE_ROWS, columns=["timestamp","ip","username","event","source_type"]).to_csv(index=False)

def _find_column(df: pd.DataFrame, target: str):
    normalized = {str(col).strip().lower(): col for col in df.columns}
    return next((normalized[a] for a in ALIASES[target] if a in normalized), None)

def _parse_plain_log(text: str, filename: str) -> pd.DataFrame:
    rows = []
    ssh = re.compile(r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d).*?(?:Failed password|Accepted password|Accepted publickey) for (?:invalid user )?(?P<username>[\w.@-]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I)
    apache = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+\S+')
    for line in text.splitlines():
        m = ssh.search(line)
        if m:
            d = m.groupdict()
            rows.append({"timestamp": d["timestamp"], "ip": d["ip"], "username": d["username"], "event": line, "source_type": "ssh"})
            continue
        m = apache.search(line)
        if m:
            d = m.groupdict()
            rows.append({"timestamp": d["timestamp"], "ip": d["ip"], "username": "-", "event": f'{d["request"]} {d["status"]}', "source_type": "apache"})
    if not rows:
        raise ValueError("No supported SSH authentication or Apache access log lines were recognized.")
    return pd.DataFrame(rows)

def load_log_file(raw_bytes: bytes, filename: str) -> pd.DataFrame:
    text = raw_bytes.decode("utf-8", errors="replace")
    if filename.lower().endswith(".csv"):
        df = pd.read_csv(StringIO(text))
    else:
        try:
            candidate = pd.read_csv(StringIO(text))
            if _find_column(candidate, "ip") and (_find_column(candidate, "event") or _find_column(candidate, "status")):
                df = candidate
            else:
                df = _parse_plain_log(text, filename)
        except Exception:
            df = _parse_plain_log(text, filename)
    if df.empty:
        raise ValueError("The uploaded file contains no rows.")
    return normalize_logs(df)

def _classify(event: str) -> str:
    if any(t in event for t in ("denied","unauthorized","403")): return "denied"
    if any(t in event for t in FAIL_TERMS): return "failed"
    if any(t in event for t in SUCCESS_TERMS): return "success"
    return "other"

def normalize_logs(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty: raise ValueError("The uploaded file contains no rows.")
    ip_col, event_col, status_col = _find_column(df,"ip"), _find_column(df,"event"), _find_column(df,"status")
    time_col, user_col = _find_column(df,"timestamp"), _find_column(df,"username")
    if ip_col is None: raise ValueError("Could not find an IP column (try ip, src_ip, source_ip, client_ip, or remote_addr).")
    if event_col is None and status_col is None: raise ValueError("Could not find an event or status column.")
    out = pd.DataFrame(index=df.index)
    out["timestamp"] = pd.to_datetime(df[time_col], errors="coerce") if time_col else pd.Series(pd.NaT, index=df.index)
    out["ip"] = df[ip_col].astype(str).str.strip()
    out["username"] = df[user_col].astype(str).str.strip() if user_col else "-"
    ev = df[event_col].fillna("").astype(str) if event_col else pd.Series("", index=df.index)
    status = df[status_col].fillna("").astype(str) if status_col else pd.Series("", index=df.index)
    out["event"] = (ev + " " + status).str.strip()
    out["source_type"] = df["source_type"].astype(str) if "source_type" in df.columns else "csv"
    out["outcome"] = out["event"].str.lower().map(_classify)
    out["failed"] = out["outcome"].isin(["failed","denied"])
    out["success"] = out["outcome"].eq("success")
    out["scan_hint"] = out["event"].str.lower().apply(lambda s: any(term in s for term in SCAN_TERMS))
    return out.reset_index(drop=True)

def analyze_logs(logs: pd.DataFrame, failed_threshold: int = 5, account_threshold: int = 5) -> dict[str, Any]:
    if logs.empty: raise ValueError("No log events to analyze.")
    stats = logs.groupby("ip", dropna=False).agg(
        events=("ip","size"), failed_attempts=("failed","sum"),
        distinct_accounts=("username",lambda x: x.replace("-",pd.NA).nunique()),
        scan_hints=("scan_hint","sum"), successful_logins=("success","sum")
    ).reset_index()
    alerts = []
    for _, r in stats.iterrows():
        ip = str(r["ip"])
        if int(r["failed_attempts"]) >= failed_threshold:
            alerts.append({"timestamp":"","ip":ip,"severity":"High","alert_type":"Repeated failed logins","evidence":f'{int(r["failed_attempts"])} failed/denied events (threshold: {failed_threshold})',"recommended_action":"Review authentication logs; consider rate limiting and MFA."})
        if int(r["distinct_accounts"]) >= account_threshold:
            alerts.append({"timestamp":"","ip":ip,"severity":"Medium","alert_type":"Multiple accounts targeted","evidence":f'{int(r["distinct_accounts"])} distinct usernames observed',"recommended_action":"Check whether the source is probing accounts; correlate with other telemetry."})
        if int(r["scan_hints"]) > 0:
            alerts.append({"timestamp":"","ip":ip,"severity":"Medium","alert_type":"Web scanning indicator","evidence":f'{int(r["scan_hints"])} request(s) matched common probe patterns',"recommended_action":"Inspect request paths and server responses; verify exposed files and routes."})
    features = ["events","failed_attempts","distinct_accounts","scan_hints","successful_logins"]
    if len(stats) >= 6:
        labels = IsolationForest(n_estimators=100, contamination="auto", random_state=42).fit_predict(stats[features].fillna(0).astype(float))
        for ip in stats.loc[labels == -1,"ip"].astype(str):
            alerts.append({"timestamp":"","ip":ip,"severity":"Low","alert_type":"Unusual IP activity (Isolation Forest)","evidence":"Per-IP activity differs from the learned baseline","recommended_action":"Review this IP in context; an anomaly is not proof of malicious activity."})
    alerts_df = pd.DataFrame(alerts, columns=["timestamp","ip","severity","alert_type","evidence","recommended_action"])
    if not alerts_df.empty:
        first = logs.groupby("ip")["timestamp"].min().astype(str).to_dict()
        alerts_df["timestamp"] = alerts_df["ip"].map(first).replace("NaT","")
        alerts_df = alerts_df.sort_values(["severity","ip"]).reset_index(drop=True)
    suspicious = stats[(stats["failed_attempts"] >= failed_threshold) | (stats["distinct_accounts"] >= account_threshold) | (stats["scan_hints"] > 0) | stats["ip"].astype(str).isin(set(alerts_df["ip"].astype(str)) if not alerts_df.empty else set())]
    suspicious = suspicious.sort_values(["failed_attempts","scan_hints","events"], ascending=False).reset_index(drop=True)
    return {"logs":logs,"ip_stats":stats.sort_values("events",ascending=False).reset_index(drop=True),"alerts":alerts_df,"suspicious_ips":suspicious,
            "summary":{"events":int(len(logs)),"failed":int(logs["failed"].sum()),"unique_ips":int(logs["ip"].nunique()),"flagged_events":int(logs["ip"].astype(str).isin(set(suspicious["ip"].astype(str))).sum())}}

def report_csv(alerts: pd.DataFrame) -> bytes:
    return alerts.to_csv(index=False).encode("utf-8")
