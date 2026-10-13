"""
validate.py
===========
Validates the raw security event dataset.

Checks performed:
  1. Required fields present
  2. No null values in required columns
  3. Timestamps are valid ISO-8601 UTC
  4. outcome values are within allowed set
  5. aws_region matches known AWS region pattern
  6. event_id is a valid UUID
  7. No duplicate event_ids

Usage:
    python data_engineering/validate.py

Input:  sample_data/raw_security_events.parquet
Output: sample_data/validation_report.json
        sample_data/quarantined_records.csv   (malformed rows)
        sample_data/validated_events.parquet  (clean rows only)
"""

import json
import os
import re
import uuid
from datetime import datetime, timezone

import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
INPUT_PATH = "sample_data/raw_security_events.parquet"
OUTPUT_VALID_PATH = "sample_data/validated_events.parquet"
OUTPUT_QUARANTINE_PATH = "sample_data/quarantined_records.csv"
REPORT_PATH = "sample_data/validation_report.json"

REQUIRED_COLUMNS = [
    "event_id",
    "event_time",
    "event_source",
    "event_name",
    "principal_id",
    "source_ip",
    "aws_region",
    "resource_type",
    "outcome",
    "user_agent",
    "event_category",
]

ALLOWED_OUTCOMES = {"Success", "Failure"}
ALLOWED_CATEGORIES = {"Management", "Data", "Insight"}

# AWS region format: xx-xxxx-N (e.g., ap-south-1, us-east-1)
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2,3}-[a-z]+-[0-9]$")

# ISO-8601 UTC format used by CloudTrail
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


# ─────────────────────────────────────────────────────────────────────────────
# Validation functions
# ─────────────────────────────────────────────────────────────────────────────

def _check_required_columns(df: pd.DataFrame) -> list:
    """Return list of missing required column names."""
    return [col for col in REQUIRED_COLUMNS if col not in df.columns]


def _is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError):
        return False


def _is_valid_timestamp(value: str) -> bool:
    try:
        datetime.strptime(str(value), TIMESTAMP_FORMAT)
        return True
    except (ValueError, TypeError):
        return False


def _is_valid_region(value: str) -> bool:
    return bool(AWS_REGION_PATTERN.match(str(value)))


def _validate_rows(df: pd.DataFrame) -> pd.Series:
    """
    Return a boolean Series — True = valid row, False = quarantine.
    Adds _validation_errors column explaining each failure.
    """
    errors = pd.Series([""] * len(df), index=df.index)
    valid_mask = pd.Series([True] * len(df), index=df.index)

    # 1. Required fields not null
    for col in REQUIRED_COLUMNS:
        if col in df.columns:
            null_mask = df[col].isnull() | (df[col].astype(str).str.strip() == "")
            errors = errors.where(~null_mask, errors + f"|NULL:{col}")
            valid_mask = valid_mask & ~null_mask

    # 2. Valid UUID event_id
    if "event_id" in df.columns:
        bad_uuid = ~df["event_id"].apply(_is_valid_uuid)
        errors = errors.where(~bad_uuid, errors + "|INVALID_UUID")
        valid_mask = valid_mask & ~bad_uuid

    # 3. Valid timestamp
    if "event_time" in df.columns:
        bad_ts = ~df["event_time"].apply(_is_valid_timestamp)
        errors = errors.where(~bad_ts, errors + "|INVALID_TIMESTAMP")
        valid_mask = valid_mask & ~bad_ts

    # 4. Valid outcome
    if "outcome" in df.columns:
        bad_outcome = ~df["outcome"].isin(ALLOWED_OUTCOMES)
        errors = errors.where(~bad_outcome, errors + "|INVALID_OUTCOME")
        valid_mask = valid_mask & ~bad_outcome

    # 5. Valid region
    if "aws_region" in df.columns:
        bad_region = ~df["aws_region"].apply(_is_valid_region)
        errors = errors.where(~bad_region, errors + "|INVALID_REGION")
        valid_mask = valid_mask & ~bad_region

    # 6. Valid event_category
    if "event_category" in df.columns:
        bad_cat = ~df["event_category"].isin(ALLOWED_CATEGORIES)
        errors = errors.where(~bad_cat, errors + "|INVALID_CATEGORY")
        valid_mask = valid_mask & ~bad_cat

    df["_validation_errors"] = errors
    return valid_mask


def _find_duplicates(df: pd.DataFrame) -> pd.Series:
    """Return boolean mask of duplicate event_ids (keep first occurrence)."""
    return df.duplicated(subset=["event_id"], keep="first")


# ─────────────────────────────────────────────────────────────────────────────
# Main validation pipeline
# ─────────────────────────────────────────────────────────────────────────────

def validate() -> dict:
    print("[validate] Loading raw events...")
    df = pd.read_parquet(INPUT_PATH)
    initial_count = len(df)
    print(f"  Loaded {initial_count} records")

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "input_file": INPUT_PATH,
        "initial_record_count": initial_count,
        "checks": {},
    }

    # ── Check 1: Required columns ────────────────────────────────────────────
    missing_cols = _check_required_columns(df)
    report["checks"]["required_columns"] = {
        "passed": len(missing_cols) == 0,
        "missing": missing_cols,
    }
    if missing_cols:
        print(f"  [FAIL] Missing required columns: {missing_cols}")
        # Cannot proceed without required columns
        with open(REPORT_PATH, "w") as f:
            json.dump(report, f, indent=2)
        return report

    print("  [PASS] All required columns present")

    # ── Check 2: Duplicate event_ids ─────────────────────────────────────────
    dup_mask = _find_duplicates(df)
    dup_count = dup_mask.sum()
    report["checks"]["duplicate_event_ids"] = {
        "passed": dup_count == 0,
        "duplicate_count": int(dup_count),
    }
    if dup_count > 0:
        print(f"  [WARN] {dup_count} duplicate event_id(s) found — removing")
        df = df[~dup_mask].reset_index(drop=True)
    else:
        print("  [PASS] No duplicate event_ids")

    # ── Check 3: Row-level validation ────────────────────────────────────────
    valid_mask = _validate_rows(df)
    valid_df = df[valid_mask].copy()
    quarantine_df = df[~valid_mask].copy()

    quarantine_count = len(quarantine_df)
    valid_count = len(valid_df)

    report["checks"]["row_validation"] = {
        "passed": quarantine_count == 0,
        "valid_rows": valid_count,
        "quarantined_rows": quarantine_count,
    }

    if quarantine_count > 0:
        print(f"  [WARN] {quarantine_count} malformed record(s) quarantined")
        quarantine_df.to_csv(OUTPUT_QUARANTINE_PATH, index=False)
        print(f"  [saved] Quarantine file: {OUTPUT_QUARANTINE_PATH}")
    else:
        print("  [PASS] All rows passed row-level validation")

    # Remove internal validation error column before saving
    if "_validation_errors" in valid_df.columns:
        valid_df = valid_df.drop(columns=["_validation_errors"])

    # ── Save validated dataset ───────────────────────────────────────────────
    os.makedirs("sample_data", exist_ok=True)
    valid_df.to_parquet(OUTPUT_VALID_PATH, index=False, engine="pyarrow")
    print(f"  [saved] Validated events: {OUTPUT_VALID_PATH} ({valid_count} rows)")

    # ── Summary ──────────────────────────────────────────────────────────────
    report["output"] = {
        "valid_record_count": valid_count,
        "quarantined_record_count": quarantine_count,
        "duplicate_records_removed": int(dup_count),
        "valid_file": OUTPUT_VALID_PATH,
        "quarantine_file": OUTPUT_QUARANTINE_PATH if quarantine_count > 0 else None,
    }

    overall_pass = (
        not missing_cols
        and dup_count == 0
        and quarantine_count == 0
    )
    report["overall_status"] = "PASS" if overall_pass else "WARN"

    def _json_safe(obj):
        """Convert numpy/pandas booleans to Python native types for JSON."""
        import numpy as np
        if isinstance(obj, (np.bool_,)):
            return bool(obj)
        if isinstance(obj, (np.integer,)):
            return int(obj)
        if isinstance(obj, (np.floating,)):
            return float(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, default=_json_safe)
    print(f"  [saved] Validation report: {REPORT_PATH}")
    print(f"\n[validate] Status: {report['overall_status']}")

    return report


if __name__ == "__main__":
    result = validate()
    print("\n[validate] Report summary:")
    for check, detail in result.get("checks", {}).items():
        status = "PASS" if detail.get("passed") else "WARN/FAIL"
        print(f"  {check}: {status}")
