"""
test_ai_model.py
================
Unit tests for the AI anomaly-detection components.

Tests cover:
  - Feature engineering (shape, column presence, log transforms)
  - Model scoring (score range, threshold behaviour)
  - Alert generation (structure, advisory-only flag)
  - Explainability (indicators present, no sensitive data in output)

Run with:
    python -m pytest tests/test_ai_model.py -v
"""

import json
import os
import sys

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_engineering.features import (
    FEATURE_COLUMNS,
    engineer_features,
)
from ai_engineering.detect_anomalies import (
    anomaly_score_to_risk,
    score_to_risk_category,
    explain_alert,
    FEATURE_DESCRIPTIONS,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def processed_df():
    """Load processed events for feature tests. Skip if file not found."""
    path = "sample_data/processed_events.parquet"
    if not os.path.exists(path):
        pytest.skip("processed_events.parquet not found — run the pipeline first")
    return pd.read_parquet(path)


@pytest.fixture(scope="module")
def feature_df(processed_df):
    """Build the feature matrix from processed events."""
    return engineer_features(processed_df)


@pytest.fixture(scope="module")
def model_metadata():
    """Load model metadata. Skip if model hasn't been trained."""
    path = "sample_data/model_metadata.json"
    if not os.path.exists(path):
        pytest.skip("model_metadata.json not found — run train_model.py first")
    with open(path) as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Feature Engineering Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureEngineering:

    def test_feature_matrix_has_expected_columns(self, feature_df):
        """All expected feature columns should be present."""
        for col in FEATURE_COLUMNS:
            assert col in feature_df.columns, f"Missing feature column: {col}"

    def test_feature_matrix_has_rows(self, feature_df):
        """Feature matrix should have at least one row."""
        assert len(feature_df) > 0

    def test_log_features_are_non_negative(self, feature_df):
        """Log-transformed features must be >= 0 (log1p of non-negative integers)."""
        log_cols = [c for c in FEATURE_COLUMNS if c.startswith("log_")]
        for col in log_cols:
            assert (feature_df[col] >= 0).all(), \
                f"Negative values found in {col}"

    def test_rate_features_bounded_zero_to_one(self, feature_df):
        """Rate features (failure_rate, off_hours_rate, etc.) must be in [0, 1]."""
        rate_cols = [c for c in FEATURE_COLUMNS if c.endswith("_rate")]
        for col in rate_cols:
            assert feature_df[col].between(0, 1).all(), \
                f"Rate column {col} has values outside [0, 1]"

    def test_anomaly_label_in_feature_matrix(self, feature_df):
        """is_anomaly column should be present (for evaluation)."""
        assert "is_anomaly" in feature_df.columns

    def test_principal_id_in_feature_matrix(self, feature_df):
        """principal_id must be preserved for alert generation."""
        assert "principal_id" in feature_df.columns

    def test_no_inf_values(self, feature_df):
        """Feature matrix should not contain infinite values."""
        numeric_cols = feature_df.select_dtypes(include=[np.number]).columns
        has_inf = np.isinf(feature_df[numeric_cols]).any().any()
        assert not has_inf, "Feature matrix contains infinite values"

    def test_all_feature_columns_have_descriptions(self):
        """Every feature column should have a human-readable description."""
        for col in FEATURE_COLUMNS:
            assert col in FEATURE_DESCRIPTIONS, \
                f"Feature '{col}' has no description in FEATURE_DESCRIPTIONS"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Risk Scoring Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskScoring:

    def test_risk_score_range(self):
        """Risk scores must be in [0, 100]."""
        for raw in [-2.0, -1.0, -0.5, 0.0, 0.5, 1.0]:
            score = anomaly_score_to_risk(raw, threshold=-0.5, min_score=-2.0, max_score=1.0)
            assert 0 <= score <= 100, f"Risk score {score} out of range for raw={raw}"

    def test_more_anomalous_gets_higher_risk(self):
        """A more negative raw score (more anomalous) should yield a higher risk score."""
        score_low_anomaly = anomaly_score_to_risk(0.5, -0.5, -2.0, 1.0)
        score_high_anomaly = anomaly_score_to_risk(-1.5, -0.5, -2.0, 1.0)
        assert score_high_anomaly > score_low_anomaly, \
            "More anomalous raw score should produce higher risk score"

    def test_risk_categories(self):
        """Correct category boundaries."""
        assert score_to_risk_category(90) == "CRITICAL"
        assert score_to_risk_category(70) == "HIGH"
        assert score_to_risk_category(50) == "MEDIUM"
        assert score_to_risk_category(20) == "LOW"
        # Edge cases
        assert score_to_risk_category(85) == "CRITICAL"
        assert score_to_risk_category(84) == "HIGH"
        assert score_to_risk_category(65) == "HIGH"
        assert score_to_risk_category(64) == "MEDIUM"
        assert score_to_risk_category(40) == "MEDIUM"
        assert score_to_risk_category(39) == "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Model Metadata Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestModelMetadata:

    def test_metadata_has_required_fields(self, model_metadata):
        required = ["model_type", "feature_columns", "best_threshold",
                    "disclaimer", "advisory_only"]
        for field in required:
            assert field in model_metadata, f"Missing metadata field: {field}"

    def test_model_is_advisory_only(self, model_metadata):
        """Model must be flagged as advisory only — no auto-remediation."""
        assert model_metadata["advisory_only"] is True

    def test_disclaimer_present(self, model_metadata):
        """Disclaimer about synthetic data must be present."""
        assert "SYNTHETIC" in model_metadata["disclaimer"] or \
               "synthetic" in model_metadata["disclaimer"]

    def test_feature_columns_match(self, model_metadata):
        """Feature columns in metadata must match FEATURE_COLUMNS."""
        assert model_metadata["feature_columns"] == FEATURE_COLUMNS

    def test_threshold_is_numeric(self, model_metadata):
        assert isinstance(model_metadata["best_threshold"], (int, float))

    def test_training_f1_is_reasonable(self, model_metadata):
        """Training F1 on synthetic data should be > 0.5 (sanity check)."""
        f1 = model_metadata.get("training_f1", 0)
        assert f1 > 0.5, \
            f"Training F1 {f1:.3f} too low — check model or feature engineering"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Alert Generation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertGeneration:

    def test_alerts_are_advisory_only(self):
        """Every generated alert must carry the advisory_only flag."""
        alerts_path = "reports/security_alerts.json"
        if not os.path.exists(alerts_path):
            pytest.skip("security_alerts.json not found — run detect_anomalies.py first")
        with open(alerts_path) as f:
            alerts = json.load(f)
        for alert in alerts:
            assert alert.get("advisory_only") is True, \
                f"Alert {alert.get('alert_id')} missing advisory_only flag"

    def test_alerts_have_required_fields(self):
        alerts_path = "reports/security_alerts.json"
        if not os.path.exists(alerts_path):
            pytest.skip("security_alerts.json not found")
        with open(alerts_path) as f:
            alerts = json.load(f)
        required = ["alert_id", "principal_id", "risk_score", "risk_category",
                    "top_indicators", "explanation", "investigation_steps"]
        for alert in alerts[:10]:
            for field in required:
                assert field in alert, f"Alert missing field: {field}"

    def test_alerts_have_investigation_steps(self):
        alerts_path = "reports/security_alerts.json"
        if not os.path.exists(alerts_path):
            pytest.skip("security_alerts.json not found")
        with open(alerts_path) as f:
            alerts = json.load(f)
        for alert in alerts[:10]:
            assert len(alert.get("investigation_steps", [])) > 0, \
                "Alert missing investigation steps"

    def test_no_credentials_in_alerts(self):
        """Alerts must not contain credential-like strings."""
        import re
        alerts_path = "reports/security_alerts.json"
        if not os.path.exists(alerts_path):
            pytest.skip("security_alerts.json not found")
        with open(alerts_path) as f:
            content = f.read()
        # Check for AKIA pattern (real AWS key prefix)
        assert not re.search(r"AKIA[0-9A-Z]{16}", content), \
            "Potential AWS access key found in alerts"

    def test_explain_alert_returns_indicators(self):
        """explain_alert should return exactly 3 indicators."""
        row = pd.Series({col: 1.0 for col in FEATURE_COLUMNS})
        scaled_row = np.ones(len(FEATURE_COLUMNS))
        explanation, indicators = explain_alert(row, scaled_row, FEATURE_COLUMNS)
        assert len(indicators) == 3
        assert isinstance(explanation, str)
        assert len(explanation) > 20

    def test_risk_scores_are_ordered(self):
        """Alerts in the saved file should be sorted by risk_score descending."""
        alerts_path = "reports/security_alerts.json"
        if not os.path.exists(alerts_path):
            pytest.skip("security_alerts.json not found")
        with open(alerts_path) as f:
            alerts = json.load(f)
        if len(alerts) < 2:
            return
        scores = [a["risk_score"] for a in alerts]
        assert scores == sorted(scores, reverse=True), \
            "Alerts are not sorted by risk_score descending"

    def test_alert_data_source_is_synthetic(self):
        """Alerts must be labeled as SYNTHETIC data."""
        alerts_path = "reports/security_alerts.json"
        if not os.path.exists(alerts_path):
            pytest.skip("security_alerts.json not found")
        with open(alerts_path) as f:
            alerts = json.load(f)
        for alert in alerts[:5]:
            assert "SYNTHETIC" in alert.get("data_source", ""), \
                "Alert data_source must be labeled SYNTHETIC"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Model Evaluation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestModelEvaluation:

    def test_evaluation_report_exists(self):
        if not os.path.exists("reports/model_evaluation_report.json"):
            pytest.skip("Evaluation report not found — run evaluate_model.py first")

    def test_evaluation_report_has_metrics(self):
        path = "reports/model_evaluation_report.json"
        if not os.path.exists(path):
            pytest.skip()
        with open(path) as f:
            report = json.load(f)
        metrics = report.get("metrics", {})
        for m in ["precision", "recall", "f1_score"]:
            assert m in metrics, f"Missing metric: {m}"
            assert 0 <= metrics[m] <= 1, f"Metric {m} out of [0,1] range"

    def test_evaluation_report_has_limitations(self):
        path = "reports/model_evaluation_report.json"
        if not os.path.exists(path):
            pytest.skip()
        with open(path) as f:
            report = json.load(f)
        assert len(report.get("limitations", [])) > 0, \
            "Evaluation report must include limitations"

    def test_confusion_matrix_consistent(self):
        path = "reports/model_evaluation_report.json"
        if not os.path.exists(path):
            pytest.skip()
        with open(path) as f:
            report = json.load(f)
        cm = report.get("confusion_matrix", {})
        total = cm.get("true_negatives", 0) + cm.get("false_positives", 0) + \
                cm.get("false_negatives", 0) + cm.get("true_positives", 0)
        assert total == report.get("total_windows", total), \
            "Confusion matrix totals don't match total_windows"


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
