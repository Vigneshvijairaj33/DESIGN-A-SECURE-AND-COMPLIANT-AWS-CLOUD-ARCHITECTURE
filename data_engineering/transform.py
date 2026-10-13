"""
transform.py
============
Transforms the validated security event dataset into a processed,
analytics-ready form.

Transformations:
  1. Timestamp normalization — parse event_time to datetime64[UTC]
  2. Categorical normalization — lowercase and strip event_name, event_source
  3. Hour-of-day and day-of-week extraction
  4. Outcome encoding — Success=0, Failure=1
  5. Region risk flag — home vs. unusual regions
  6. Sensitive API flag
  7. Remove duplicate rows (belt-and-braces after validation)
  8. Sort by event_time ascending

Usage:
    python data_engineering/transform.py

Input:  sample_data/validated_events.parquet
Output: sample_data/processed_events.parquet
        sample_data/processed_events.csv
"""

import os
from datetime import timezone

import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
INPUT_PATH = "sample_data/validated_events.parquet"
OUTPUT_PARQUET = "sample_data/processed_events.parquet"
OUTPUT_CSV = "sample_data/processed_events.csv"

HOME_REGION = "ap-south-1"

# API actions considered sensitive from a security standpoint
SENSITIVE_ACTIONS = {
    "putrolepolicy", "createuser", "attachuserpolicy", "deletetrail",
    "stoplogging", "putbucketpolicy", "deletebucketpolicy", "createaccesskey",
    "updateassumerolepolicy", "deleteuser", "putbucketacl",
    "putuserpolicy", "createpolicyversion", "deletepolicyversion",
    "attachrolepolicy", "detachrolepolicy",
}


# ─────────────────────────────────────────────────────────────────────────────
# Transformation functions
# ─────────────────────────────────────────────────────────────────────────────

def normalize_timestamps(df: pd.DataFrame) -> pd.DataFrame:
    """Parse event_time strings to timezone-aware datetime objects."""
    df = df.copy()
    df["event_time"] = pd.to_datetime(df["event_time"], utc=True, errors="coerce")
    invalid = df["event_time"].isna().sum()
    if invalid > 0:
        print(f"  [WARN] {invalid} unparseable timestamps set to NaT")
    return df


def extract_time_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add hour_of_day and day_of_week columns from event_time."""
    df = df.copy()
    df["hour_of_day"] = df["event_time"].dt.hour
    df["day_of_week"] = df["event_time"].dt.dayofweek  # 0=Monday, 6=Sunday
    df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
    # Off-hours: before 7am or after 9pm UTC
    df["is_off_hours"] = ((df["hour_of_day"] < 7) | (df["hour_of_day"] > 21)).astype(int)
    return df


def normalize_categoricals(df: pd.DataFrame) -> pd.DataFrame:
    """Lowercase and strip string fields for consistent comparison."""
    df = df.copy()
    for col in ["event_name", "event_source", "aws_region", "user_agent", "event_category"]:
        if col in df.columns:
            df[col] = df[col].str.strip().str.lower()
    return df


def encode_outcome(df: pd.DataFrame) -> pd.DataFrame:
    """Encode outcome as a binary integer: success=0, failure=1."""
    df = df.copy()
    df["outcome_code"] = df["outcome"].str.lower().map({"success": 0, "failure": 1}).fillna(-1).astype(int)
    return df


def add_risk_flags(df: pd.DataFrame) -> pd.DataFrame:
    """Add derived risk-indicator boolean columns."""
    df = df.copy()

    # Unusual region — any region other than home
    df["is_unusual_region"] = (df["aws_region"] != HOME_REGION.lower()).astype(int)

    # Sensitive API action
    df["is_sensitive_action"] = df["event_name"].isin(SENSITIVE_ACTIONS).astype(int)

    # Unusual user agent — programmatic clients that are not the standard CLI
    df["is_unusual_ua"] = df["user_agent"].str.contains(
        "python-requests|curl|wget|postman", na=False
    ).astype(int)

    return df


def deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    """Remove exact duplicate rows."""
    before = len(df)
    df = df.drop_duplicates()
    removed = before - len(df)
    if removed > 0:
        print(f"  [INFO] Removed {removed} exact duplicate rows")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Main transform pipeline
# ─────────────────────────────────────────────────────────────────────────────

def transform() -> pd.DataFrame:
    print("[transform] Loading validated events...")
    df = pd.read_parquet(INPUT_PATH)
    print(f"  Input rows: {len(df)}")

    print("[transform] Step 1: Timestamp normalization")
    df = normalize_timestamps(df)

    print("[transform] Step 2: Extract time features")
    df = extract_time_features(df)

    print("[transform] Step 3: Normalize categorical values")
    df = normalize_categoricals(df)

    print("[transform] Step 4: Encode outcome")
    df = encode_outcome(df)

    print("[transform] Step 5: Add risk flags")
    df = add_risk_flags(df)

    print("[transform] Step 6: Deduplicate")
    df = deduplicate(df)

    # Sort chronologically
    df = df.sort_values("event_time").reset_index(drop=True)

    print(f"[transform] Output rows: {len(df)}")

    # Save
    os.makedirs("sample_data", exist_ok=True)
    df.to_parquet(OUTPUT_PARQUET, index=False, engine="pyarrow")
    # Save CSV with datetime as string for readability
    df_csv = df.copy()
    df_csv["event_time"] = df_csv["event_time"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    df_csv.to_csv(OUTPUT_CSV, index=False)
    print(f"  [saved] {OUTPUT_PARQUET}")
    print(f"  [saved] {OUTPUT_CSV}")

    # Quick sanity checks
    print("\n[transform] Column summary:")
    print(df[["event_name", "outcome_code", "is_unusual_region",
               "is_sensitive_action", "is_off_hours", "is_weekend"]].describe().to_string())

    return df


if __name__ == "__main__":
    transform()
