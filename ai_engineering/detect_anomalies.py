"""
detect_anomalies.py
===================
Runs the trained Isolation Forest model on the feature matrix and
generates explainable security alerts for flagged windows.

Alert output contains:
  - event_id (synthetic window identifier)
  - timestamp of the window
  - principal_id
  - risk_score (0–100, higher = more anomalous)
  - risk_category (LOW / MEDIUM / HIGH / CRITICAL)
  - top contributing indicators
  - explanation in plain English
  - recommended investigation steps

SAFETY: This module generates ADVISORY alerts only.
It does NOT modify IAM permissions, block users, delete resources,
or take any automated remediation action.

Usage:
    python ai_engineering/detect_anomalies.py

Input:
    sample_data/feature_matrix.parquet
    sample_data/isolation_forest_model.joblib
    sample_data/scaler.joblib
    sample_data/model_metadata.json

Output:
    reports/security_alerts.json
    reports/security_alerts.csv
"""

import json
import os
import uuid
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai_engineering.features import FEATURE_COLUMNS

FEATURE_PATH = "sample_data/feature_matrix.parquet"
MODEL_PATH = "sample_data/isolation_forest_model.joblib"
SCALER_PATH = "sample_data/scaler.joblib"
METADATA_PATH = "sample_data/model_metadata.json"
ALERTS_JSON = "reports/security_alerts.json"
ALERTS_CSV = "reports/security_alerts.csv"


# ─────────────────────────────────────────────────────────────────────────────
# Risk categorization
# ─────────────────────────────────────────────────────────────────────────────

def score_to_risk_category(risk_score: float) -> str:
    """Map a 0–100 risk score to a human-readable severity category."""
    if risk_score >= 85:
        return "CRITICAL"
    elif risk_score >= 65:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def anomaly_score_to_risk(raw_score: float, threshold: float, min_score: float, max_score: float) -> float:
    """
    Convert Isolation Forest decision_function score to 0–100 risk scale.
    Raw score is negative-is-more-anomalous; we invert and normalise.
    """
    # Invert: more negative raw score → higher risk
    inverted = -raw_score
    inverted_threshold = -threshold
    inverted_min = -max_score  # was most anomalous
    inverted_max = -min_score  # was least anomalous

    if inverted_max == inverted_min:
        return 50.0  # Fallback if all scores equal

    # Normalise to 0–100
    normalised = (inverted - inverted_min) / (inverted_max - inverted_min)
    return round(min(max(normalised * 100, 0), 100), 1)


# ─────────────────────────────────────────────────────────────────────────────
# Explainability — identify top contributing features
# ─────────────────────────────────────────────────────────────────────────────

# Human-readable descriptions for each feature
FEATURE_DESCRIPTIONS = {
    "total_api_calls": "High API call volume",
    "unique_api_actions": "Many distinct API actions",
    "failure_count": "High number of API failures",
    "failure_rate": "Elevated failure rate",
    "sensitive_action_count": "Sensitive IAM/S3/CloudTrail actions performed",
    "sensitive_action_rate": "High proportion of sensitive actions",
    "distinct_source_ips": "Multiple distinct source IP addresses",
    "unusual_ua_count": "Unusual user-agent strings (non-CLI tools)",
    "off_hours_count": "Activity outside normal business hours",
    "off_hours_rate": "High off-hours activity rate",
    "weekend_count": "Weekend activity",
    "distinct_regions": "Multiple AWS regions accessed",
    "unusual_region_count": "Activity in unexpected AWS regions",
    "unusual_region_rate": "High proportion of unusual-region activity",
    "log_total_api_calls": "High API volume (log-scaled)",
    "log_failure_count": "High failure count (log-scaled)",
    "log_sensitive_action_count": "High sensitive action count (log-scaled)",
    "log_distinct_source_ips": "High distinct IP count (log-scaled)",
}

# Investigation steps per scenario type
INVESTIGATION_STEPS = {
    "CRITICAL": [
        "1. Immediately review CloudTrail events for this principal in the last 24 hours.",
        "2. Check if any IAM policies were modified: look for PutRolePolicy, AttachUserPolicy events.",
        "3. Verify whether CloudTrail logging is still enabled (DeleteTrail / StopLogging).",
        "4. Check S3 bucket policies for any unauthorized changes.",
        "5. Review VPC Flow Logs for unusual outbound connections.",
        "6. Consider isolating the IAM role/user pending investigation.",
        "7. Escalate to security team immediately.",
    ],
    "HIGH": [
        "1. Review CloudTrail events for this principal in the last 6 hours.",
        "2. Identify the source IP addresses and correlate with known office/VPN ranges.",
        "3. Check for unusual region activity and confirm business justification.",
        "4. Review any sensitive API calls (IAM, S3 policy changes).",
        "5. Confirm the user agent is expected for this principal.",
    ],
    "MEDIUM": [
        "1. Review CloudTrail events for this principal.",
        "2. Confirm the off-hours or unusual-region activity has a business explanation.",
        "3. Check for any failed API calls that may indicate misconfigured permissions.",
        "4. Monitor for repeated occurrences over the next 24 hours.",
    ],
    "LOW": [
        "1. Log this finding for trending analysis.",
        "2. Confirm no related HIGH/CRITICAL alerts for the same principal.",
        "3. No immediate action required — review in next daily report.",
    ],
}


def explain_alert(row: pd.Series, X_scaled_row: np.ndarray, feature_names: list) -> tuple[str, list]:
    """
    Identify the top 3 features most responsible for the high anomaly score
    by comparing scaled feature values to the mean (0 in StandardScaler space).
    Features furthest from the mean in the anomalous direction are highlighted.
    """
    # In StandardScaler space: mean=0, std=1
    # Features with large positive scaled values drove the anomaly
    deviations = {name: float(abs(val)) for name, val in zip(feature_names, X_scaled_row)}
    top_features = sorted(deviations.items(), key=lambda x: x[1], reverse=True)[:3]

    indicators = []
    for feat_name, deviation in top_features:
        description = FEATURE_DESCRIPTIONS.get(feat_name, feat_name)
        raw_value = row.get(feat_name, "N/A")
        indicators.append({
            "feature": feat_name,
            "description": description,
            "raw_value": float(raw_value) if isinstance(raw_value, (int, float, np.number)) else str(raw_value),
            "deviation_from_normal": round(deviation, 3),
        })

    # Plain-English explanation
    top_descriptions = [i["description"] for i in indicators[:3]]
    explanation = (
        f"This activity window was flagged because: "
        f"{'; '.join(top_descriptions)}. "
        f"These patterns deviate significantly from the synthetic baseline behaviour "
        f"established for this principal."
    )

    return explanation, indicators


# ─────────────────────────────────────────────────────────────────────────────
# Main detection loop
# ─────────────────────────────────────────────────────────────────────────────

def detect_anomalies() -> list:
    print("[detect] Loading model artifacts...")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    with open(METADATA_PATH) as f:
        metadata = json.load(f)

    threshold = metadata["best_threshold"]
    print(f"  Model type  : {metadata['model_type']}")
    print(f"  Threshold   : {threshold:.4f}")

    print("[detect] Loading feature matrix...")
    df = pd.read_parquet(FEATURE_PATH)
    X = df[FEATURE_COLUMNS].fillna(df[FEATURE_COLUMNS].median())

    print(f"[detect] Scoring {len(X)} windows...")
    X_scaled = scaler.transform(X)
    scores = model.decision_function(X_scaled)  # Lower = more anomalous

    score_min, score_max = scores.min(), scores.max()
    df["_anomaly_score"] = scores
    df["_is_flagged"] = (scores <= threshold).astype(int)

    flagged_df = df[df["_is_flagged"] == 1].copy()
    print(f"  Flagged windows : {len(flagged_df)} / {len(df)}")

    alerts = []
    for idx, row in flagged_df.iterrows():
        risk_score = anomaly_score_to_risk(
            row["_anomaly_score"], threshold, score_min, score_max
        )
        risk_category = score_to_risk_category(risk_score)

        # Get the scaled feature vector for this row for explanation
        row_position = df.index.get_loc(idx)
        scaled_row = X_scaled[row_position]

        explanation, indicators = explain_alert(row, scaled_row, FEATURE_COLUMNS)

        alert = {
            "alert_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "window_start": str(row.get("window_start", "unknown")),
            "principal_id": str(row.get("principal_id", "unknown")),
            "risk_score": risk_score,
            "risk_category": risk_category,
            "anomaly_score_raw": round(float(row["_anomaly_score"]), 4),
            "threshold_used": round(threshold, 4),
            "ground_truth_label": int(row.get("is_anomaly", -1)),
            "ground_truth_scenario": str(row.get("anomaly_scenario", "unknown")),
            "top_indicators": indicators,
            "explanation": explanation,
            "investigation_steps": INVESTIGATION_STEPS.get(risk_category, []),
            "advisory_only": True,
            "data_source": "SYNTHETIC — demonstration data only",
            # Key feature values for the alert
            "feature_summary": {
                "total_api_calls": int(row.get("total_api_calls", 0)),
                "failure_count": int(row.get("failure_count", 0)),
                "failure_rate": float(row.get("failure_rate", 0)),
                "sensitive_action_count": int(row.get("sensitive_action_count", 0)),
                "distinct_source_ips": int(row.get("distinct_source_ips", 0)),
                "unusual_region_count": int(row.get("unusual_region_count", 0)),
                "off_hours_count": int(row.get("off_hours_count", 0)),
            },
        }
        alerts.append(alert)

    # Sort by risk score descending
    alerts.sort(key=lambda a: a["risk_score"], reverse=True)
    return alerts


def save_alerts(alerts: list) -> None:
    os.makedirs("reports", exist_ok=True)

    with open(ALERTS_JSON, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"  [saved] {ALERTS_JSON} ({len(alerts)} alerts)")

    if alerts:
        flat = []
        for a in alerts:
            row = {k: v for k, v in a.items()
                   if k not in ("top_indicators", "investigation_steps", "feature_summary")}
            # Flatten indicators
            for i, ind in enumerate(a["top_indicators"][:3]):
                row[f"indicator_{i+1}"] = ind["description"]
            flat.append(row)
        pd.DataFrame(flat).to_csv(ALERTS_CSV, index=False)
        print(f"  [saved] {ALERTS_CSV}")


def print_sample_alerts(alerts: list, n: int = 3) -> None:
    print(f"\n{'='*60}")
    print(f"TOP {min(n, len(alerts))} SECURITY ALERTS (Advisory — Synthetic Data)")
    print("=" * 60)

    for alert in alerts[:n]:
        print(f"\n{'─'*50}")
        print(f"  Alert ID      : {alert['alert_id']}")
        print(f"  Principal     : {alert['principal_id']}")
        print(f"  Window Start  : {alert['window_start']}")
        print(f"  Risk Score    : {alert['risk_score']}/100")
        print(f"  Risk Category : {alert['risk_category']}")
        print(f"  Scenario      : {alert['ground_truth_scenario']}")
        print(f"\n  Explanation:")
        print(f"    {alert['explanation']}")
        print(f"\n  Top Indicators:")
        for ind in alert["top_indicators"]:
            print(f"    • {ind['description']} (value={ind['raw_value']}, deviation={ind['deviation_from_normal']})")
        print(f"\n  Next Steps:")
        for step in alert["investigation_steps"][:3]:
            print(f"    {step}")
        print(f"\n  ⚠️  {alert['data_source']}")


if __name__ == "__main__":
    alerts = detect_anomalies()
    save_alerts(alerts)
    print_sample_alerts(alerts, n=3)

    print(f"\n[detect] Summary:")
    from collections import Counter
    category_counts = Counter(a["risk_category"] for a in alerts)
    for cat in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"  {cat:10}: {category_counts.get(cat, 0)}")
