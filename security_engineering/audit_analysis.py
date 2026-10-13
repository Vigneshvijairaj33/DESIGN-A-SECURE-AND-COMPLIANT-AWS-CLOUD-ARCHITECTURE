"""
audit_analysis.py
=================
Analyses the synthetic security event dataset to simulate the kind of
investigation a security analyst would perform using CloudTrail logs.

This script demonstrates:
  1. Top API callers by volume
  2. High-failure-rate principals
  3. Sensitive API action inventory
  4. Off-hours activity summary
  5. Unusual region activity
  6. Synthetic audit timeline reconstruction

IMPORTANT: This analysis runs entirely on SYNTHETIC data.
It does NOT query real CloudTrail, GuardDuty, or any live AWS service.

Usage:
    python security_engineering/audit_analysis.py

Input:  sample_data/processed_events.parquet
Output: reports/audit_analysis_report.txt
        reports/audit_analysis_report.json
"""

import json
import os
from datetime import datetime, timezone

import pandas as pd

INPUT_PATH = "sample_data/processed_events.parquet"
REPORT_TXT = "reports/audit_analysis_report.txt"
REPORT_JSON = "reports/audit_analysis_report.json"


def load_events() -> pd.DataFrame:
    df = pd.read_parquet(INPUT_PATH)
    if not pd.api.types.is_datetime64_any_dtype(df["event_time"]):
        df["event_time"] = pd.to_datetime(df["event_time"], utc=True, errors="coerce")
    return df


def top_callers(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Most active principals by API call volume."""
    return (
        df.groupby("principal_id")
        .agg(
            total_calls=("event_id", "count"),
            unique_actions=("event_name", "nunique"),
            failure_count=("outcome_code", "sum"),
        )
        .sort_values("total_calls", ascending=False)
        .head(n)
        .reset_index()
    )


def high_failure_principals(df: pd.DataFrame, min_calls: int = 5) -> pd.DataFrame:
    """Principals with high API failure rates."""
    agg = (
        df.groupby("principal_id")
        .agg(total=("event_id", "count"), failures=("outcome_code", "sum"))
        .reset_index()
    )
    agg = agg[agg["total"] >= min_calls].copy()
    agg["failure_rate"] = agg["failures"] / agg["total"]
    return agg.sort_values("failure_rate", ascending=False).head(10)


def sensitive_action_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Count of sensitive API actions by action name and principal."""
    if "is_sensitive_action" not in df.columns:
        return pd.DataFrame()
    sensitive = df[df["is_sensitive_action"] == 1]
    if sensitive.empty:
        return pd.DataFrame()
    return (
        sensitive.groupby(["event_name", "principal_id"])
        .agg(count=("event_id", "count"))
        .sort_values("count", ascending=False)
        .reset_index()
        .head(20)
    )


def off_hours_summary(df: pd.DataFrame) -> dict:
    """Summary of off-hours (before 7am or after 9pm UTC) API activity."""
    if "is_off_hours" not in df.columns:
        return {}
    off = df[df["is_off_hours"] == 1]
    return {
        "total_off_hours_events": int(len(off)),
        "off_hours_principals": int(off["principal_id"].nunique()),
        "off_hours_rate": round(len(off) / len(df), 4) if len(df) > 0 else 0,
        "top_off_hours_principals": off["principal_id"].value_counts().head(5).to_dict(),
    }


def unusual_region_summary(df: pd.DataFrame) -> dict:
    """Summary of activity from unexpected AWS regions."""
    if "is_unusual_region" not in df.columns:
        return {}
    unusual = df[df["is_unusual_region"] == 1]
    return {
        "total_unusual_region_events": int(len(unusual)),
        "regions_seen": unusual["aws_region"].value_counts().to_dict(),
        "top_principals_in_unusual_regions": (
            unusual["principal_id"].value_counts().head(5).to_dict()
        ),
    }


def suspicious_event_timeline(df: pd.DataFrame) -> list:
    """
    Reconstruct the timeline of synthetic suspicious events.
    Simulates what a CloudTrail investigation would surface.
    """
    if "is_anomaly" not in df.columns:
        return []

    suspicious = df[df["is_anomaly"] == 1].copy()
    suspicious = suspicious.sort_values("event_time")

    timeline = []
    for _, row in suspicious.iterrows():
        timeline.append({
            "timestamp": str(row["event_time"]),
            "principal_id": str(row.get("principal_id", "unknown")),
            "event_name": str(row.get("event_name", "unknown")),
            "source_ip": str(row.get("source_ip", "unknown")),
            "aws_region": str(row.get("aws_region", "unknown")),
            "outcome": str(row.get("outcome", "unknown")),
            "scenario": str(row.get("anomaly_scenario", "unknown")),
        })
    return timeline[:50]  # Limit to first 50 for readability


def run_analysis() -> dict:
    print("[audit_analysis] Loading processed events...")
    df = load_events()
    print(f"  Loaded {len(df)} events")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "SYNTHETIC — demonstration data only",
        "total_events": len(df),
    }

    print("[audit_analysis] Computing top callers...")
    callers = top_callers(df)
    report["top_callers"] = callers.to_dict(orient="records")

    print("[audit_analysis] Identifying high-failure principals...")
    failures = high_failure_principals(df)
    report["high_failure_principals"] = failures.to_dict(orient="records")

    print("[audit_analysis] Cataloguing sensitive API actions...")
    sensitive = sensitive_action_summary(df)
    report["sensitive_actions"] = sensitive.to_dict(orient="records") if not sensitive.empty else []

    print("[audit_analysis] Summarising off-hours activity...")
    report["off_hours"] = off_hours_summary(df)

    print("[audit_analysis] Summarising unusual-region activity...")
    report["unusual_regions"] = unusual_region_summary(df)

    print("[audit_analysis] Building suspicious event timeline...")
    report["suspicious_timeline"] = suspicious_event_timeline(df)

    return report


def save_report(report: dict) -> None:
    os.makedirs("reports", exist_ok=True)

    with open(REPORT_JSON, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  [saved] {REPORT_JSON}")

    lines = [
        "=" * 60,
        "AUDIT ANALYSIS REPORT — Synthetic Security Events",
        f"Generated : {report['generated_at']}",
        f"Dataset   : {report['dataset']}",
        f"Total Events: {report['total_events']}",
        "=" * 60,
        "",
        "TOP 10 MOST ACTIVE PRINCIPALS",
        "-" * 40,
    ]
    for r in report.get("top_callers", []):
        lines.append(f"  {r['principal_id']:35} calls={r['total_calls']}  failures={r['failure_count']}")

    lines += ["", "HIGH FAILURE-RATE PRINCIPALS (min 5 calls)", "-" * 40]
    for r in report.get("high_failure_principals", []):
        lines.append(f"  {r['principal_id']:35} failure_rate={r['failure_rate']:.2%}")

    lines += ["", "SENSITIVE API ACTIONS", "-" * 40]
    for r in report.get("sensitive_actions", []):
        lines.append(f"  {r['event_name']:35} principal={r['principal_id']}  count={r['count']}")

    lines += ["", "OFF-HOURS ACTIVITY", "-" * 40]
    oh = report.get("off_hours", {})
    lines.append(f"  Total off-hours events : {oh.get('total_off_hours_events', 0)}")
    lines.append(f"  Off-hours rate         : {oh.get('off_hours_rate', 0):.1%}")

    lines += ["", "UNUSUAL REGION ACTIVITY", "-" * 40]
    ur = report.get("unusual_regions", {})
    lines.append(f"  Total unusual-region events: {ur.get('total_unusual_region_events', 0)}")
    lines.append(f"  Regions observed           : {ur.get('regions_seen', {})}")

    lines += ["", "SUSPICIOUS EVENT TIMELINE (first 20)", "-" * 40]
    for entry in report.get("suspicious_timeline", [])[:20]:
        lines.append(
            f"  {entry['timestamp'][:19]}  {entry['principal_id']:30}  "
            f"{entry['event_name']:30}  {entry['scenario']}"
        )

    with open(REPORT_TXT, "w") as f:
        f.write("\n".join(lines))
    print(f"  [saved] {REPORT_TXT}")


if __name__ == "__main__":
    report = run_analysis()
    save_report(report)
    print("\n[audit_analysis] Done.")
