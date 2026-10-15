import pandas as pd
from analyzer import analyze_logs, load_log_file, make_sample_csv, normalize_logs

def test_sample_loads_and_flags_bruteforce():
    logs = load_log_file(make_sample_csv().encode(), "sample.csv")
    result = analyze_logs(logs, failed_threshold=5, account_threshold=5)
    assert result["summary"]["events"] > 0
    assert not result["alerts"].empty
    assert "198.51.100.20" in set(result["alerts"]["ip"])

def test_column_aliases_and_failure_detection():
    raw = pd.DataFrame({"time":["2026-01-01 10:00:00"]*3, "source_ip":["203.0.113.7"]*3,
                        "user":["admin","root","test"], "status":["failed login"]*3})
    logs = normalize_logs(raw)
    result = analyze_logs(logs, failed_threshold=3, account_threshold=3)
    assert "203.0.113.7" in set(result["alerts"]["ip"])

def test_empty_input_rejected():
    try:
        normalize_logs(pd.DataFrame())
    except ValueError:
        return
    raise AssertionError("Expected ValueError")
