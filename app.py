from __future__ import annotations
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from analyzer import analyze_logs, load_log_file, make_sample_csv, report_csv

st.set_page_config(page_title="Log File Analyzer", page_icon="🛡️", layout="wide")
st.title("🛡️ Log File Analyzer for Intrusion Detection")
st.caption("Analyze authentication and web access logs, flag suspicious patterns, and export an incident report.")

with st.sidebar:
    st.header("Analysis settings")
    failed_threshold = st.slider("Failed logins from one IP to flag", 3, 20, 5)
    account_threshold = st.slider("Distinct accounts from one IP", 3, 30, 5)
    st.markdown("---")
    st.write("Supports CSV, common SSH/auth logs, and Apache access logs.")
    st.caption("Alerts are heuristic indicators, not proof of compromise.")

uploaded = st.file_uploader("Upload a log file (.csv, .log, .txt)", type=["csv", "log", "txt"])
use_sample = st.toggle("Use included sample dataset", value=uploaded is None)
if uploaded is not None:
    raw_bytes, source_name = uploaded.getvalue(), uploaded.name
elif use_sample:
    raw_bytes, source_name = make_sample_csv().encode("utf-8"), "sample_security_logs.csv"
else:
    raw_bytes, source_name = None, ""

if raw_bytes is None:
    st.info("Upload a file or enable the included sample dataset to begin.")
    st.stop()

try:
    logs = load_log_file(raw_bytes, source_name)
    result = analyze_logs(logs, failed_threshold, account_threshold)
except Exception as exc:
    st.error(f"Could not analyze this file: {exc}")
    st.info("Check that your CSV has a header row, or upload a supported SSH/auth or Apache access log.")
    st.stop()

summary = result["summary"]
c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analyzed", f"{summary['events']:,}")
c2.metric("Failed / denied", f"{summary['failed']:,}")
c3.metric("Unique source IPs", f"{summary['unique_ips']:,}")
c4.metric("Flagged events", f"{summary['flagged_events']:,}")

left, right = st.columns(2)
with left:
    st.subheader("Login outcomes")
    fig, ax = plt.subplots()
    counts = result["logs"]["outcome"].value_counts()
    if counts.empty:
        ax.text(.5, .5, "No outcomes found", ha="center", va="center")
        ax.set_axis_off()
    else:
        counts.plot(kind="bar", ax=ax)
        ax.set_ylabel("Events")
        ax.tick_params(axis="x", rotation=20)
    st.pyplot(fig, clear_figure=True)
with right:
    st.subheader("Events over time")
    timeline = result["logs"].dropna(subset=["timestamp"]).copy()
    if not timeline.empty:
        timeline["hour"] = timeline["timestamp"].dt.floor("h")
        fig2, ax2 = plt.subplots()
        timeline.groupby("hour").size().plot(ax=ax2, marker="o")
        ax2.set_ylabel("Events")
        ax2.set_xlabel("Hour")
        ax2.tick_params(axis="x", rotation=30)
        st.pyplot(fig2, clear_figure=True)
    else:
        st.info("No parseable timestamps found for timeline chart.")

st.subheader("Suspicious source IPs")
if result["suspicious_ips"].empty:
    st.success("No IPs met the current rule thresholds.")
else:
    st.dataframe(result["suspicious_ips"], use_container_width=True, hide_index=True)

st.subheader("Detected alerts")
if result["alerts"].empty:
    st.success("No alerts generated with the current thresholds.")
else:
    st.dataframe(result["alerts"], use_container_width=True, hide_index=True)

st.subheader("Normalized events")
st.dataframe(result["logs"].head(500), use_container_width=True, hide_index=True)
if len(result["logs"]) > 500:
    st.caption("Showing the first 500 normalized events.")

st.download_button("⬇️ Download incident report (CSV)", report_csv(result["alerts"]),
                   "intrusion_detection_report.csv", "text/csv")
st.download_button("⬇️ Download normalized logs (CSV)",
                   result["logs"].to_csv(index=False).encode("utf-8"),
                   "normalized_logs.csv", "text/csv")

with st.expander("How detection works"):
    st.markdown("""
    - **Repeated failures:** flags IPs with failed/denied events at or above the selected threshold.
    - **Account probing:** flags IPs attempting multiple distinct usernames.
    - **Web scanning hints:** flags common probes such as `/.env`, `/wp-admin`, `/phpmyadmin`, and SQL-injection-like strings.
    - **Anomaly detection:** Isolation Forest identifies unusual per-IP activity when enough IPs are present.
    """)

