"""
test_data_pipeline.py
=====================
Unit tests for the data engineering pipeline.

Tests cover:
  - Event generation (shape, types, label balance)
  - Validation (null rejection, duplicate removal, bad timestamps)
  - Transformation (timestamp parsing, feature derivation)
  - Quality report (score calculation)

Run with:
    python -m pytest tests/test_data_pipeline.py -v
"""

import os
import sys
import uuid
from datetime import datetime, timezone

import pandas as pd
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_engineering.generate_events import generate_dataset
from data_engineering.validate import (
    _check_required_columns,
    _find_duplicates,
    _is_valid_timestamp,
    _is_valid_uuid,
    _validate_rows,
    REQUIRED_COLUMNS,
)
from data_engineering.transform import (
    add_risk_flags,
    deduplicate,
    encode_outcome,
    extract_time_features,
    normalize_categoricals,
    normalize_timestamps,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def raw_df():
    """Generate the synthetic dataset once for the whole module."""
    return generate_dataset()


@pytest.fixture
def minimal_valid_df():
    """A tiny valid DataFrame with all required columns."""
    return pd.DataFrame([
        {
            "event_id": str(uuid.uuid4()),
            "event_time": "2026-01-15T10:30:00Z",
            "event_source": "iam.amazonaws.com",
            "event_name": "ListRoles",
            "principal_id": "AIDA-SYNTHETIC-USER-001",
            "source_ip": "192.0.2.10",
            "aws_region": "ap-south-1",
            "resource_type": "AWS::IAM::Role",
            "outcome": "Success",
            "user_agent": "aws-cli/2.35.0",
            "event_category": "Management",
            "is_anomaly": 0,
            "anomaly_scenario": "none",
        }
    ])


# ─────────────────────────────────────────────────────────────────────────────
# 1. Event Generation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEventGeneration:

    def test_generates_expected_row_count(self, raw_df):
        """Dataset should contain the configured number of events (1000)."""
        assert len(raw_df) == 1000, f"Expected 1000 rows, got {len(raw_df)}"

    def test_contains_required_columns(self, raw_df):
        """All required columns must be present."""
        for col in REQUIRED_COLUMNS:
            assert col in raw_df.columns, f"Missing column: {col}"

    def test_anomaly_label_balance(self, raw_df):
        """~20% of events should be labeled anomalous."""
        anomaly_rate = raw_df["is_anomaly"].mean()
        assert 0.15 <= anomaly_rate <= 0.25, \
            f"Anomaly rate {anomaly_rate:.2%} outside expected 15–25% range"

    def test_all_scenarios_represented(self, raw_df):
        """All five anomaly scenarios should appear in the dataset."""
        scenarios = raw_df["anomaly_scenario"].unique()
        expected = {"credential_abuse", "privilege_escalation", "audit_tampering",
                    "data_exfiltration", "unusual_region"}
        for s in expected:
            assert s in scenarios, f"Scenario '{s}' missing from dataset"

    def test_no_real_credentials_in_data(self, raw_df):
        """Principal IDs should all be synthetic (contain 'SYNTHETIC')."""
        principals = raw_df["principal_id"].unique()
        for p in principals:
            assert "SYNTHETIC" in p or "ATTACKER" in p, \
                f"Non-synthetic principal found: {p}"

    def test_event_ids_are_unique(self, raw_df):
        """Every event_id must be unique."""
        assert raw_df["event_id"].nunique() == len(raw_df), \
            "Duplicate event_ids found in generated dataset"

    def test_outcome_values_are_valid(self, raw_df):
        """Outcome column must only contain 'Success' or 'Failure'."""
        invalid = raw_df[~raw_df["outcome"].isin(["Success", "Failure"])]
        assert len(invalid) == 0, f"{len(invalid)} rows with invalid outcome values"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Validation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestValidation:

    def test_valid_uuid_passes(self):
        assert _is_valid_uuid(str(uuid.uuid4())) is True

    def test_invalid_uuid_fails(self):
        assert _is_valid_uuid("not-a-uuid") is False
        assert _is_valid_uuid("") is False

    def test_valid_timestamp_passes(self):
        assert _is_valid_timestamp("2026-01-15T10:30:00Z") is True

    def test_invalid_timestamp_formats_fail(self):
        assert _is_valid_timestamp("2026-01-15") is False
        assert _is_valid_timestamp("not-a-timestamp") is False
        assert _is_valid_timestamp("15/01/2026 10:30:00") is False

    def test_required_columns_check_detects_missing(self):
        df = pd.DataFrame({"event_id": [1], "event_time": ["2026-01-01T00:00:00Z"]})
        missing = _check_required_columns(df)
        assert "event_name" in missing
        assert "principal_id" in missing

    def test_required_columns_check_passes_complete_df(self, minimal_valid_df):
        missing = _check_required_columns(minimal_valid_df)
        assert missing == [], f"Unexpected missing columns: {missing}"

    def test_null_values_are_quarantined(self, minimal_valid_df):
        """A row with a null required field should fail validation."""
        df = minimal_valid_df.copy()
        df.loc[0, "event_name"] = None
        valid_mask = _validate_rows(df)
        assert not valid_mask.iloc[0], "Row with null event_name should be invalid"

    def test_invalid_outcome_is_quarantined(self, minimal_valid_df):
        df = minimal_valid_df.copy()
        df.loc[0, "outcome"] = "Unknown"
        valid_mask = _validate_rows(df)
        assert not valid_mask.iloc[0], "Row with invalid outcome should be quarantined"

    def test_invalid_region_is_quarantined(self, minimal_valid_df):
        df = minimal_valid_df.copy()
        df.loc[0, "aws_region"] = "not-a-region"
        valid_mask = _validate_rows(df)
        assert not valid_mask.iloc[0], "Row with invalid region should be quarantined"

    def test_valid_row_passes_validation(self, minimal_valid_df):
        valid_mask = _validate_rows(minimal_valid_df)
        assert valid_mask.iloc[0], "Valid row should pass validation"

    def test_duplicate_detection(self, minimal_valid_df):
        """Duplicated event_id should be detected."""
        df = pd.concat([minimal_valid_df, minimal_valid_df], ignore_index=True)
        dup_mask = _find_duplicates(df)
        assert dup_mask.sum() == 1, "Should detect exactly 1 duplicate"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Transformation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTransformation:

    def test_timestamp_normalization_produces_datetime(self, minimal_valid_df):
        result = normalize_timestamps(minimal_valid_df)
        assert pd.api.types.is_datetime64_any_dtype(result["event_time"]), \
            "event_time should be datetime64 after normalization"

    def test_time_features_extracted(self, minimal_valid_df):
        df = normalize_timestamps(minimal_valid_df)
        result = extract_time_features(df)
        assert "hour_of_day" in result.columns
        assert "day_of_week" in result.columns
        assert "is_off_hours" in result.columns
        assert "is_weekend" in result.columns
        # Timestamp 10:30:00 UTC is NOT off-hours (7am–9pm)
        assert result.iloc[0]["is_off_hours"] == 0

    def test_outcome_encoding(self, minimal_valid_df):
        result = encode_outcome(minimal_valid_df)
        assert result.iloc[0]["outcome_code"] == 0  # Success → 0

    def test_failure_encoding(self, minimal_valid_df):
        df = minimal_valid_df.copy()
        df.loc[0, "outcome"] = "Failure"
        # Need lowercase after normalization
        df = normalize_categoricals(df)
        result = encode_outcome(df)
        assert result.iloc[0]["outcome_code"] == 1  # Failure → 1

    def test_unusual_region_flagged(self, minimal_valid_df):
        df = minimal_valid_df.copy()
        df = normalize_categoricals(df)
        df.loc[0, "aws_region"] = "us-east-1"  # Not home region
        result = add_risk_flags(df)
        assert result.iloc[0]["is_unusual_region"] == 1

    def test_home_region_not_flagged(self, minimal_valid_df):
        df = normalize_categoricals(minimal_valid_df)
        result = add_risk_flags(df)
        assert result.iloc[0]["is_unusual_region"] == 0

    def test_sensitive_action_flagged(self, minimal_valid_df):
        df = minimal_valid_df.copy()
        df = normalize_categoricals(df)
        df.loc[0, "event_name"] = "createuser"
        result = add_risk_flags(df)
        assert result.iloc[0]["is_sensitive_action"] == 1

    def test_normal_action_not_sensitive(self, minimal_valid_df):
        df = normalize_categoricals(minimal_valid_df)
        result = add_risk_flags(df)
        # "listRoles" → normalized to "listroles" — not in sensitive set
        assert result.iloc[0]["is_sensitive_action"] == 0

    def test_deduplication_removes_exact_duplicates(self, minimal_valid_df):
        df = pd.concat([minimal_valid_df, minimal_valid_df], ignore_index=True)
        result = deduplicate(df)
        assert len(result) == 1, "Deduplication should leave exactly 1 row"

    def test_categorical_normalization_lowercases(self, minimal_valid_df):
        df = minimal_valid_df.copy()
        df.loc[0, "event_name"] = "  ListRoles  "
        result = normalize_categoricals(df)
        assert result.iloc[0]["event_name"] == "listroles"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Security-Specific Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityProperties:

    def test_no_real_aws_account_id_in_dataset(self, raw_df):
        """
        Dataset should not contain standalone 12-digit AWS account IDs.
        We check only non-UUID fields (principal_id, source_ip, aws_region, event_name)
        to avoid false positives from UUID digit sequences.
        """
        import re
        # Only scan fields that could realistically contain a real account ID
        check_cols = ["principal_id", "source_ip", "aws_region",
                      "event_name", "event_source", "user_agent"]
        aws_account_pattern = re.compile(r"\b\d{12}\b")
        for col in check_cols:
            if col not in raw_df.columns:
                continue
            for val in raw_df[col].dropna().unique():
                matches = aws_account_pattern.findall(str(val))
                assert len(matches) == 0, \
                    f"Possible AWS account ID in {col}='{val}': {matches}"

    def test_synthetic_ip_ranges_only(self, raw_df):
        """IPs must be in RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x)."""
        for ip in raw_df["source_ip"].unique():
            assert ip.startswith("192.0.2.") or ip.startswith("198.51.100."), \
                f"Non-synthetic IP found: {ip}"

    def test_malformed_records_can_be_quarantined(self):
        """Malformed records with missing fields should be separable."""
        good_row = {
            "event_id": str(uuid.uuid4()),
            "event_time": "2026-01-15T10:30:00Z",
            "event_source": "iam.amazonaws.com",
            "event_name": "ListRoles",
            "principal_id": "AIDA-SYNTHETIC-USER-001",
            "source_ip": "192.0.2.10",
            "aws_region": "ap-south-1",
            "resource_type": "AWS::IAM::Role",
            "outcome": "Success",
            "user_agent": "aws-cli/2.35.0",
            "event_category": "Management",
        }
        bad_row = good_row.copy()
        bad_row["event_name"] = None
        bad_row["event_id"] = str(uuid.uuid4())

        df = pd.DataFrame([good_row, bad_row])
        valid_mask = _validate_rows(df)

        good_rows = df[valid_mask]
        quarantined = df[~valid_mask]

        assert len(good_rows) == 1
        assert len(quarantined) == 1

    def test_duplicate_event_ids_removed(self):
        """Duplicate event IDs should be detected and removable."""
        shared_id = str(uuid.uuid4())
        row_template = {
            "event_id": shared_id,
            "event_time": "2026-01-15T10:30:00Z",
            "event_source": "iam.amazonaws.com",
            "event_name": "ListRoles",
            "principal_id": "AIDA-SYNTHETIC-USER-001",
            "source_ip": "192.0.2.10",
            "aws_region": "ap-south-1",
            "resource_type": "AWS::IAM::Role",
            "outcome": "Success",
            "user_agent": "aws-cli/2.35.0",
            "event_category": "Management",
        }
        df = pd.DataFrame([row_template, row_template])
        dup_mask = _find_duplicates(df)
        clean_df = df[~dup_mask]
        assert len(clean_df) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
