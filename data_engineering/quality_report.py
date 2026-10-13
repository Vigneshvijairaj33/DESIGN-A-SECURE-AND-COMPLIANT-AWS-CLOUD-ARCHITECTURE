"""
quality_report.py
=================
Generates a data quality report for the processed security event dataset.

Checks:
  1. Row count and completeness rate
  2. Null counts per column
  3. Cardinality of categorical columns
  4. Timestamp range and ordering
  5. Distribution of outcomes, regions, and anomaly labels
  6. Off-hours and sensitive-action rates

Usage:
    python data_engineering/quality_report.py

Input:  sample_data/processed_events.parquet
Output: reports/data_quality_report.json
        reports/data_quality_report.txt  (human-readable summary)
"""

import json
import os
from datetime import datetime, timezone

import pandas as pd

INPUT_PATH = "sample_data/processed_events.parquet"
REPORT_JSON = "reports/data_quality_report.json"
REPORT_TXT = "reports/data_quality_report.txt"


def generate_quality_report() -> dict:
    print("[quality_report] Loading processed events...")
    df = pd.read_parquet(INPUT_PATH)
    total_rows = len(df)
    print(f"  Loaded {total_rows} records")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": INPUT_PATH,
        "total_rows": total_rows,
        "checks": {},
        "distributions": {},
        "quality_score": 0.0,
    }

    checks_passed = 0
    total_checks = 0

    # ── Check 1: Row count ───────────────────────────────────────────────────
    total_checks += 1
    min_expected = 100
    passed = total_rows >= min_expected
    if passed:
        checks_passed += 1
    report["checks"]["row_count"] = {
        "passed": passed,
        "value": total_rows,
        "minimum_expected": min_expected,
    }

    # ── Check 2: Null completeness ───────────────────────────────────────────
    total_checks += 1
    null_counts = df.isnull().sum().to_dict()
    null_counts = {k: int(v) for k, v in null_counts.items()}
    required_cols_nulls = {
        col: null_counts.get(col, 0)
        for col in ["event_id", "event_time", "event_name", "principal_id", "outcome"]
    }
    has_nulls_in_required = any(v > 0 for v in required_cols_nulls.values())
    if not has_nulls_in_required:
        checks_passed += 1
    report["checks"]["null_completeness"] = {
        "passed": not has_nulls_in_required,
        "null_counts_required_columns": required_cols_nulls,
        "all_null_counts": null_counts,
    }

    # ── Check 3: Timestamp ordering ──────────────────────────────────────────
    total_checks += 1
    if "event_time" in df.columns and pd.api.types.is_datetime64_any_dtype(df["event_time"]):
        is_sorted = df["event_time"].is_monotonic_increasing
        ts_min = str(df["event_time"].min())
        ts_max = str(df["event_time"].max())
    else:
        is_sorted = False
        ts_min = ts_max = "N/A"
    if is_sorted:
        checks_passed += 1
    report["checks"]["timestamp_ordering"] = {
        "passed": is_sorted,
        "min_timestamp": ts_min,
        "max_timestamp": ts_max,
        "is_sorted_ascending": is_sorted,
    }

    # ── Check 4: Duplicate event_ids ────────────────────────────────────────
    total_checks += 1
    dup_count = int(df.duplicated(subset=["event_id"]).sum())
    passed = dup_count == 0
    if passed:
        checks_passed += 1
    report["checks"]["duplicate_event_ids"] = {
        "passed": passed,
        "duplicate_count": dup_count,
    }

    # ── Check 5: Outcome distribution ───────────────────────────────────────
    total_checks += 1
    outcome_dist = df["outcome"].value_counts().to_dict() if "outcome" in df.columns else {}
    failure_rate = outcome_dist.get("failure", 0) / total_rows if total_rows > 0 else 0
    # Expect failure rate < 30% in a realistic normal-baseline dataset
    passed = failure_rate < 0.30
    if passed:
        checks_passed += 1
    report["checks"]["outcome_distribution"] = {
        "passed": passed,
        "distribution": outcome_dist,
        "failure_rate": round(failure_rate, 4),
        "note": "Failure rate >30% may indicate credential abuse or misconfiguration",
    }

    # ── Check 6: Anomaly label balance ──────────────────────────────────────
    if "is_anomaly" in df.columns:
        anomaly_dist = df["is_anomaly"].value_counts().to_dict()
        anomaly_dist = {str(k): int(v) for k, v in anomaly_dist.items()}
        anomaly_rate = int(anomaly_dist.get("1", 0)) / total_rows if total_rows > 0 else 0
        report["distributions"]["anomaly_labels"] = {
            "distribution": anomaly_dist,
            "anomaly_rate": round(anomaly_rate, 4),
        }

    # ── Distributions ────────────────────────────────────────────────────────
    for col in ["aws_region", "event_category", "anomaly_scenario"]:
        if col in df.columns:
            dist = df[col].value_counts().head(10).to_dict()
            report["distributions"][col] = {str(k): int(v) for k, v in dist.items()}

    # Risk flag rates
    for flag in ["is_unusual_region", "is_sensitive_action", "is_off_hours", "is_weekend"]:
        if flag in df.columns:
            rate = float(df[flag].mean())
            report["distributions"][flag + "_rate"] = round(rate, 4)

    # ── Quality Score ────────────────────────────────────────────────────────
    quality_score = round((checks_passed / total_checks) * 100, 1) if total_checks > 0 else 0
    report["quality_score"] = quality_score
    report["checks_passed"] = checks_passed
    report["total_checks"] = total_checks

    return report


def save_report(report: dict) -> None:
    os.makedirs("reports", exist_ok=True)

    with open(REPORT_JSON, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  [saved] {REPORT_JSON}")

    # Human-readable text version
    lines = [
        "=" * 60,
        "DATA QUALITY REPORT — Secure Compliant Cloud",
        f"Generated : {report['generated_at']}",
        f"Input     : {report['input_file']}",
        f"Total Rows: {report['total_rows']}",
        f"Quality Score: {report['quality_score']}% ({report['checks_passed']}/{report['total_checks']} checks passed)",
        "=" * 60,
        "",
        "CHECKS",
        "-" * 40,
    ]
    for name, detail in report["checks"].items():
        status = "PASS" if detail.get("passed") else "FAIL"
        lines.append(f"  [{status}] {name}")
        for k, v in detail.items():
            if k != "passed":
                lines.append(f"         {k}: {v}")

    lines += ["", "DISTRIBUTIONS", "-" * 40]
    for name, val in report["distributions"].items():
        lines.append(f"  {name}: {val}")

    with open(REPORT_TXT, "w") as f:
        f.write("\n".join(lines))
    print(f"  [saved] {REPORT_TXT}")


if __name__ == "__main__":
    report = generate_quality_report()
    save_report(report)
    print(f"\n[quality_report] Quality Score: {report['quality_score']}%")
