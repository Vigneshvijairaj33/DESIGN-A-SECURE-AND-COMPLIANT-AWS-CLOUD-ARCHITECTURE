"""
features.py
===========
Feature engineering for the AI anomaly-detection model.

We aggregate raw per-event records into per-principal time-windowed
feature vectors. These features capture behavioural patterns that
distinguish normal principals from anomalous ones.

Feature groups:
  A. Volume features   — how much activity?
  B. Failure features  — how many errors?
  C. Sensitive actions — how risky are the actions?
  D. Network features  — how many distinct IPs?
  E. Temporal features — when is the activity happening?
  F. Geographic features — how many distinct regions?

IMPORTANT: Features are derived from SYNTHETIC data only.
No real personal data, real AWS account IDs, or real network information
is processed here.

Usage:
    python ai_engineering/features.py

Input:  sample_data/processed_events.parquet
Output: sample_data/feature_matrix.parquet
        sample_data/feature_matrix.csv
"""

import os

import numpy as np
import pandas as pd

INPUT_PATH = "sample_data/processed_events.parquet"
OUTPUT_PARQUET = "sample_data/feature_matrix.parquet"
OUTPUT_CSV = "sample_data/feature_matrix.csv"

# Time window for aggregation: 1 hour
TIME_WINDOW = "1h"


def load_processed_events() -> pd.DataFrame:
    df = pd.read_parquet(INPUT_PATH)
    # Ensure event_time is timezone-aware datetime
    if not pd.api.types.is_datetime64_any_dtype(df["event_time"]):
        df["event_time"] = pd.to_datetime(df["event_time"], utc=True, errors="coerce")
    elif df["event_time"].dt.tz is None:
        df["event_time"] = df["event_time"].dt.tz_localize("UTC")
    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate events per principal per 1-hour window into feature vectors.
    Returns a DataFrame where each row = (principal_id, time_window).
    """
    print("[features] Engineering per-principal time-windowed features...")

    # Set time index for resampling
    df = df.set_index("event_time").sort_index()

    feature_rows = []

    for principal, group in df.groupby("principal_id"):
        # Resample into 1-hour windows
        windows = group.resample(TIME_WINDOW)

        for window_start, window_df in windows:
            if len(window_df) == 0:
                continue

            # ── A. Volume features ────────────────────────────────────────
            total_calls = len(window_df)
            unique_actions = window_df["event_name"].nunique()

            # ── B. Failure features ───────────────────────────────────────
            failure_count = int(window_df.get("outcome_code", pd.Series(dtype=int)).sum())
            failure_rate = failure_count / total_calls if total_calls > 0 else 0.0

            # ── C. Sensitive action features ──────────────────────────────
            sensitive_count = int(window_df.get("is_sensitive_action", pd.Series(dtype=int)).sum())
            sensitive_rate = sensitive_count / total_calls if total_calls > 0 else 0.0

            # ── D. Network features ───────────────────────────────────────
            distinct_ips = window_df["source_ip"].nunique() if "source_ip" in window_df.columns else 0
            unusual_ua_count = int(window_df.get("is_unusual_ua", pd.Series(dtype=int)).sum())

            # ── E. Temporal features ──────────────────────────────────────
            off_hours_count = int(window_df.get("is_off_hours", pd.Series(dtype=int)).sum())
            off_hours_rate = off_hours_count / total_calls if total_calls > 0 else 0.0
            weekend_count = int(window_df.get("is_weekend", pd.Series(dtype=int)).sum())

            # ── F. Geographic features ────────────────────────────────────
            distinct_regions = window_df["aws_region"].nunique() if "aws_region" in window_df.columns else 1
            unusual_region_count = int(window_df.get("is_unusual_region", pd.Series(dtype=int)).sum())
            unusual_region_rate = unusual_region_count / total_calls if total_calls > 0 else 0.0

            # ── Ground-truth label (for evaluation only — not used in training) ──
            is_anomaly = int(window_df["is_anomaly"].max()) if "is_anomaly" in window_df.columns else 0
            anomaly_scenario = window_df["anomaly_scenario"].mode()[0] if "anomaly_scenario" in window_df.columns else "none"

            feature_rows.append({
                "principal_id": principal,
                "window_start": window_start,
                # Volume
                "total_api_calls": total_calls,
                "unique_api_actions": unique_actions,
                # Failures
                "failure_count": failure_count,
                "failure_rate": round(failure_rate, 4),
                # Sensitive
                "sensitive_action_count": sensitive_count,
                "sensitive_action_rate": round(sensitive_rate, 4),
                # Network
                "distinct_source_ips": distinct_ips,
                "unusual_ua_count": unusual_ua_count,
                # Temporal
                "off_hours_count": off_hours_count,
                "off_hours_rate": round(off_hours_rate, 4),
                "weekend_count": weekend_count,
                # Geographic
                "distinct_regions": distinct_regions,
                "unusual_region_count": unusual_region_count,
                "unusual_region_rate": round(unusual_region_rate, 4),
                # Label (not used in model training)
                "is_anomaly": is_anomaly,
                "anomaly_scenario": anomaly_scenario,
            })

    features_df = pd.DataFrame(feature_rows)

    # Log-transform volume features to reduce skewness
    for col in ["total_api_calls", "failure_count", "sensitive_action_count", "distinct_source_ips"]:
        if col in features_df.columns:
            features_df[f"log_{col}"] = np.log1p(features_df[col])

    print(f"  Feature matrix shape: {features_df.shape}")
    print(f"  Anomalous windows   : {features_df['is_anomaly'].sum()}")
    print(f"  Normal windows      : {(features_df['is_anomaly'] == 0).sum()}")

    return features_df


def save_features(features_df: pd.DataFrame) -> None:
    os.makedirs("sample_data", exist_ok=True)
    features_df.to_parquet(OUTPUT_PARQUET, index=False, engine="pyarrow")
    # Convert timestamps to string for CSV compatibility
    csv_df = features_df.copy()
    csv_df["window_start"] = csv_df["window_start"].astype(str)
    csv_df.to_csv(OUTPUT_CSV, index=False)
    print(f"  [saved] {OUTPUT_PARQUET}")
    print(f"  [saved] {OUTPUT_CSV}")


# Columns used by the model (exclude labels and identifiers)
FEATURE_COLUMNS = [
    "total_api_calls",
    "unique_api_actions",
    "failure_count",
    "failure_rate",
    "sensitive_action_count",
    "sensitive_action_rate",
    "distinct_source_ips",
    "unusual_ua_count",
    "off_hours_count",
    "off_hours_rate",
    "weekend_count",
    "distinct_regions",
    "unusual_region_count",
    "unusual_region_rate",
    "log_total_api_calls",
    "log_failure_count",
    "log_sensitive_action_count",
    "log_distinct_source_ips",
]


if __name__ == "__main__":
    df = load_processed_events()
    features_df = engineer_features(df)
    save_features(features_df)
    print("\n[features] Sample feature matrix:")
    print(features_df[FEATURE_COLUMNS].describe().to_string())
