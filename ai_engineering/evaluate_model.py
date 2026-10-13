"""
evaluate_model.py
=================
Evaluates the trained anomaly-detection model against the ground-truth
labels in the synthetic dataset.

Produces:
  - Confusion matrix
  - Precision, Recall, F1-score
  - Per-scenario breakdown
  - False-positive and false-negative analysis
  - Limitation commentary

Usage:
    python ai_engineering/evaluate_model.py

Input:
    sample_data/feature_matrix.parquet
    sample_data/isolation_forest_model.joblib
    sample_data/scaler.joblib
    sample_data/model_metadata.json

Output:
    reports/model_evaluation_report.json
    reports/model_evaluation_report.txt
"""

import json
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai_engineering.features import FEATURE_COLUMNS

FEATURE_PATH = "sample_data/feature_matrix.parquet"
MODEL_PATH = "sample_data/isolation_forest_model.joblib"
SCALER_PATH = "sample_data/scaler.joblib"
METADATA_PATH = "sample_data/model_metadata.json"
REPORT_JSON = "reports/model_evaluation_report.json"
REPORT_TXT = "reports/model_evaluation_report.txt"


def evaluate():
    print("[evaluate] Loading artifacts...")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    with open(METADATA_PATH) as f:
        metadata = json.load(f)
    threshold = metadata["best_threshold"]

    df = pd.read_parquet(FEATURE_PATH)
    X = df[FEATURE_COLUMNS].fillna(df[FEATURE_COLUMNS].median())
    y_true = df["is_anomaly"].values

    X_scaled = scaler.transform(X)
    scores = model.decision_function(X_scaled)
    y_pred = (scores <= threshold).astype(int)

    # ── Overall metrics ──────────────────────────────────────────────────────
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    # AUC-ROC using raw scores (inverted so higher = more anomalous)
    try:
        auc = roc_auc_score(y_true, -scores)
    except Exception:
        auc = None

    tn, fp, fn, tp = cm.ravel()

    print(f"\n[evaluate] Overall Metrics:")
    print(f"  Precision : {precision:.3f}")
    print(f"  Recall    : {recall:.3f}")
    print(f"  F1-Score  : {f1:.3f}")
    print(f"  AUC-ROC   : {auc:.3f}" if auc else "  AUC-ROC  : N/A")
    print(f"\n  Confusion Matrix (rows=Actual, cols=Predicted):")
    print(f"                 Pred Normal  Pred Anomaly")
    print(f"  Actual Normal  {tn:11d}  {fp:12d}")
    print(f"  Actual Anomaly {fn:11d}  {tp:12d}")
    print(f"\n  True Positives  (correctly flagged anomalies): {tp}")
    print(f"  True Negatives  (correctly passed normal)     : {tn}")
    print(f"  False Positives (normal flagged as anomaly)   : {fp}  ← Alert fatigue risk")
    print(f"  False Negatives (anomaly missed)              : {fn}  ← Coverage gap")

    # ── Per-scenario breakdown ───────────────────────────────────────────────
    df["_predicted"] = y_pred
    scenario_results = {}
    if "anomaly_scenario" in df.columns:
        for scenario, grp in df.groupby("anomaly_scenario"):
            grp_true = grp["is_anomaly"].values
            grp_pred = grp["_predicted"].values
            detected = int((grp_pred[grp_true == 1] == 1).sum()) if grp_true.sum() > 0 else 0
            total_anomalies = int(grp_true.sum())
            fp_in_grp = int((grp_pred[grp_true == 0] == 1).sum())
            scenario_results[scenario] = {
                "total_windows": int(len(grp)),
                "anomalous_windows": total_anomalies,
                "detected": detected,
                "false_positives": fp_in_grp,
                "detection_rate": round(detected / total_anomalies, 3) if total_anomalies > 0 else None,
            }
        print("\n[evaluate] Per-Scenario Detection:")
        for sc, r in scenario_results.items():
            rate = r["detection_rate"]
            rate_str = f"{rate:.0%}" if rate is not None else "N/A"
            print(f"  {sc:25}: detected {r['detected']}/{r['anomalous_windows']} ({rate_str}), FP={r['false_positives']}")

    # ── Classification report ────────────────────────────────────────────────
    report_str = classification_report(
        y_true, y_pred,
        target_names=["Normal", "Anomaly"],
        zero_division=0
    )
    print(f"\n[evaluate] Full Classification Report:\n{report_str}")

    # ── Build and save report ────────────────────────────────────────────────
    report = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "model_type": metadata["model_type"],
        "dataset": "SYNTHETIC — demonstration only",
        "threshold": float(threshold),
        "total_windows": int(len(df)),
        "anomalous_windows": int(y_true.sum()),
        "normal_windows": int((y_true == 0).sum()),
        "metrics": {
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
            "auc_roc": round(float(auc), 4) if auc else None,
        },
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
        "per_scenario": scenario_results,
        "limitations": [
            "Model trained and evaluated on SYNTHETIC data only.",
            "Synthetic scenarios are simplified; real-world attacks are more varied.",
            "Precision/Recall reflect synthetic baseline — real performance is unknown.",
            "Class imbalance (20% anomalies) was factored in via contamination parameter.",
            "Threshold was selected on training data — may be overfit to synthetic patterns.",
            "No temporal train/test split was used — use time-based splits in production.",
            "Model does not account for seasonality or legitimate business-hours variation.",
            "False positive rate must be validated by SOC analysts before production use.",
        ],
        "recommendations": [
            "Retrain on at least 3 months of authorized real security events.",
            "Use a time-based train/test split (train on older data, evaluate on recent).",
            "Tune contamination parameter based on actual incident frequency.",
            "Implement human-review queue for MEDIUM alerts before sending to SOC.",
            "Monitor model drift: retrain if weekly false-positive rate exceeds 5%.",
            "Consider complementing with supervised models once labeled real data is available.",
        ],
    }

    os.makedirs("reports", exist_ok=True)

    with open(REPORT_JSON, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  [saved] {REPORT_JSON}")

    # Human-readable text report
    lines = [
        "=" * 60,
        "AI MODEL EVALUATION REPORT",
        "Secure Compliant Cloud — Anomaly Detection",
        f"Evaluated : {report['evaluated_at']}",
        f"Dataset   : {report['dataset']}",
        "=" * 60,
        "",
        f"Precision : {report['metrics']['precision']:.4f}",
        f"Recall    : {report['metrics']['recall']:.4f}",
        f"F1-Score  : {report['metrics']['f1_score']:.4f}",
        f"AUC-ROC   : {report['metrics']['auc_roc']}",
        "",
        "Confusion Matrix:",
        f"  True Positives  : {tn}",
        f"  True Negatives  : {tp}",
        f"  False Positives : {fp}",
        f"  False Negatives : {fn}",
        "",
        "LIMITATIONS:",
    ]
    for lim in report["limitations"]:
        lines.append(f"  - {lim}")
    lines += ["", "RECOMMENDATIONS:"]
    for rec in report["recommendations"]:
        lines.append(f"  - {rec}")

    with open(REPORT_TXT, "w") as f:
        f.write("\n".join(lines))
    print(f"  [saved] {REPORT_TXT}")

    return report


if __name__ == "__main__":
    evaluate()
