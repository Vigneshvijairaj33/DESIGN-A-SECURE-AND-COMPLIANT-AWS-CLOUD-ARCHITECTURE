"""
train_model.py
==============
Trains an Isolation Forest anomaly-detection model on the synthetic
security event feature matrix.

Why Isolation Forest?
- Unsupervised: no labeled anomalies needed for training
- Explainable: anomaly score derived from average path length in trees
- Computationally efficient: O(n log n) training
- Well-suited to tabular security telemetry

Training strategy:
- Train on ALL data (unsupervised; labels held out for evaluation only)
- Isolation Forest assigns anomaly scores; we tune the threshold on
  the labeled subset without retraining (avoids data leakage)

IMPORTANT: This model is trained on SYNTHETIC data.
Real-world accuracy is unknown. The model must not take automated
remediation actions — it produces advisory alerts only.

Usage:
    python ai_engineering/train_model.py

Input:  sample_data/feature_matrix.parquet
Output: sample_data/isolation_forest_model.joblib
        sample_data/scaler.joblib
        sample_data/model_metadata.json
"""

import json
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Import feature column list from features module
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai_engineering.features import FEATURE_COLUMNS

INPUT_PATH = "sample_data/feature_matrix.parquet"
MODEL_PATH = "sample_data/isolation_forest_model.joblib"
SCALER_PATH = "sample_data/scaler.joblib"
METADATA_PATH = "sample_data/model_metadata.json"

# ─────────────────────────────────────────────────────────────────────────────
# Hyperparameters
# Contamination = expected fraction of anomalies in the dataset (~20%)
# n_estimators = 200 trees (more stable scores than default 100)
# max_samples = "auto" uses min(256, n_samples) for each tree
# random_state = fixed for reproducibility
# ─────────────────────────────────────────────────────────────────────────────
MODEL_PARAMS = {
    "n_estimators": 200,
    "contamination": 0.20,   # We know ~20% of windows contain anomalies
    "max_samples": "auto",
    "max_features": 1.0,
    "bootstrap": False,
    "random_state": 42,
    "n_jobs": -1,
}


def load_features() -> tuple[pd.DataFrame, np.ndarray, list]:
    df = pd.read_parquet(INPUT_PATH)
    print(f"[train] Loaded {len(df)} feature windows")

    # Verify all required feature columns are present
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing feature columns: {missing}")

    X = df[FEATURE_COLUMNS].copy()
    y = df["is_anomaly"].values  # Ground-truth labels — held out, not used in training
    return X, y, df


def handle_missing_values(X: pd.DataFrame) -> pd.DataFrame:
    """Fill NaN with column median — safe for Isolation Forest."""
    null_counts = X.isnull().sum()
    if null_counts.any():
        print(f"  [WARN] Filling {null_counts.sum()} NaN values with column medians")
        X = X.fillna(X.median())
    return X


def train(X: pd.DataFrame) -> tuple:
    print(f"[train] Training Isolation Forest on {len(X)} samples, {X.shape[1]} features")
    print(f"[train] Parameters: {MODEL_PARAMS}")

    # Scale features — IsolationForest is robust to scale but scaling helps
    # interpretability of feature importances
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(**MODEL_PARAMS)
    model.fit(X_scaled)

    print("[train] Training complete")
    return model, scaler, X_scaled


def evaluate_threshold(model, scaler, X: pd.DataFrame, y: np.ndarray) -> dict:
    """
    Isolation Forest returns anomaly scores in range (-1 negative = anomaly).
    We use decision_function() which returns the raw anomaly score
    (lower = more anomalous).
    We find the threshold that maximises F1-score on the labeled data.
    NOTE: In production, threshold would be validated on a held-out test set.
    """
    from sklearn.metrics import f1_score, precision_score, recall_score

    X_scaled = scaler.transform(X)
    scores = model.decision_function(X_scaled)  # Lower = more anomalous

    best_threshold = None
    best_f1 = 0.0
    results = []

    # Search thresholds in the score distribution
    for pct in range(5, 40, 1):
        threshold = np.percentile(scores, pct)
        y_pred = (scores <= threshold).astype(int)
        if y_pred.sum() == 0:
            continue
        f1 = f1_score(y, y_pred, zero_division=0)
        results.append({
            "threshold": float(threshold),
            "percentile": pct,
            "f1": float(f1),
            "precision": float(precision_score(y, y_pred, zero_division=0)),
            "recall": float(recall_score(y, y_pred, zero_division=0)),
            "predicted_anomalies": int(y_pred.sum()),
        })
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold

    best_result = max(results, key=lambda r: r["f1"])
    print(f"  [threshold] Best threshold: {best_result['threshold']:.4f} "
          f"(percentile {best_result['percentile']}%) — "
          f"F1={best_result['f1']:.3f}, "
          f"P={best_result['precision']:.3f}, "
          f"R={best_result['recall']:.3f}")

    return best_result, scores


def save_artifacts(model, scaler, best_threshold_result: dict, feature_names: list) -> None:
    os.makedirs("sample_data", exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"  [saved] Model  : {MODEL_PATH}")
    print(f"  [saved] Scaler : {SCALER_PATH}")

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "model_type": "IsolationForest",
        "library": "scikit-learn",
        "parameters": MODEL_PARAMS,
        "feature_columns": feature_names,
        "best_threshold": best_threshold_result["threshold"],
        "threshold_percentile": best_threshold_result["percentile"],
        "training_f1": best_threshold_result["f1"],
        "training_precision": best_threshold_result["precision"],
        "training_recall": best_threshold_result["recall"],
        "disclaimer": (
            "This model is trained on SYNTHETIC data. "
            "Performance metrics reflect synthetic scenarios only. "
            "Do not claim real-world accuracy without validation on "
            "authorized real security events."
        ),
        "advisory_only": True,
    }

    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  [saved] Metadata: {METADATA_PATH}")


def run_training():
    print("=" * 60)
    print("AI ANOMALY DETECTION — Model Training")
    print("Dataset: SYNTHETIC — for demonstration only")
    print("=" * 60)

    X, y, df = load_features()
    X = handle_missing_values(X)
    model, scaler, X_scaled = train(X)
    best_result, scores = evaluate_threshold(model, scaler, X, y)
    save_artifacts(model, scaler, best_result, FEATURE_COLUMNS)

    print("\n[train] Training summary:")
    print(f"  Samples trained  : {len(X)}")
    print(f"  Features used    : {len(FEATURE_COLUMNS)}")
    print(f"  Anomaly threshold: {best_result['threshold']:.4f}")
    print(f"  Best F1-score    : {best_result['f1']:.3f}")
    print(f"  Precision        : {best_result['precision']:.3f}")
    print(f"  Recall           : {best_result['recall']:.3f}")
    print("\nNOTE: Metrics are on synthetic training data — not real-world performance.")


if __name__ == "__main__":
    run_training()
