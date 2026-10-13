"""
test_security_checks.py
=======================
Tests for the security configuration checks module.

These tests verify the check logic itself — they do not make
any live AWS API calls.

Run with:
    python -m pytest tests/test_security_checks.py -v
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_engineering.security_checks import (
    _should_exclude,
    check_aws_credentials_configured,
    check_gitignore,
    check_hardcoded_credentials,
    check_iam_wildcards,
    check_kms_rotation,
    check_s3_public_access_block,
)


class TestExclusionLogic:

    def test_git_directory_excluded(self):
        p = Path(".git/config")
        assert _should_exclude(p)

    def test_pycache_excluded(self):
        p = Path("src/__pycache__/module.pyc")
        assert _should_exclude(p)

    def test_normal_file_not_excluded(self):
        p = Path("security_engineering/security_checks.py")
        assert not _should_exclude(p)


class TestCredentialChecks:

    def test_check_returns_dict_with_required_keys(self):
        result = check_aws_credentials_configured()
        assert "check" in result
        assert "passed" in result
        assert "description" in result
        # Never expose actual key values
        env_vars = result.get("env_vars", {})
        for k, v in env_vars.items():
            assert v in ("set", "not set"), \
                f"Credential value for {k} should be 'set' or 'not set', not the actual value"

    def test_no_credential_values_in_output(self):
        """Result must not expose actual credential values."""
        result = check_aws_credentials_configured()
        result_str = str(result)
        # Should not contain anything that looks like a real key
        assert "AKIA" not in result_str, "Actual AWS key found in check output"


class TestGitignoreCheck:

    def test_missing_gitignore_fails(self, tmp_path, monkeypatch):
        """If .gitignore doesn't exist, check should fail."""
        monkeypatch.chdir(tmp_path)
        result = check_gitignore()
        assert not result["passed"]
        assert ".env" in result["missing_entries"]

    def test_complete_gitignore_passes(self, tmp_path, monkeypatch):
        """A .gitignore with all required entries should pass."""
        monkeypatch.chdir(tmp_path)
        entries = [
            ".env", "terraform.tfvars", "*.tfstate", "*.tfstate.backup",
            ".terraform/", "*.joblib", "__pycache__", "*.pyc",
        ]
        (tmp_path / ".gitignore").write_text("\n".join(entries))
        result = check_gitignore()
        assert result["passed"]
        assert result["missing_entries"] == []

    def test_partial_gitignore_reports_missing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".gitignore").write_text(".env\n__pycache__\n")
        result = check_gitignore()
        assert not result["passed"]
        assert "terraform.tfvars" in result["missing_entries"]


class TestIAMWildcardCheck:

    def test_no_wildcards_passes(self, tmp_path, monkeypatch):
        """Terraform with no wildcard actions should pass."""
        monkeypatch.chdir(tmp_path)
        tf = tmp_path / "main.tf"
        tf.write_text("""
resource "aws_iam_policy" "safe" {
  policy = jsonencode({
    Statement = [{
      Effect  = "Allow"
      Actions = ["s3:GetObject", "s3:ListBucket"]
    }]
  })
}
""")
        result = check_iam_wildcards()
        assert result["non_root_wildcards"] == 0

    def test_non_root_wildcard_fails(self, tmp_path, monkeypatch):
        """A wildcard action not in a root policy should be flagged."""
        monkeypatch.chdir(tmp_path)
        tf = tmp_path / "bad.tf"
        tf.write_text("""
resource "aws_iam_policy" "too_broad" {
  policy = jsonencode({
    Statement = [{
      Effect  = "Allow"
      actions = ["*"]
    }]
  })
}
""")
        result = check_iam_wildcards()
        assert result["non_root_wildcards"] >= 1

    def test_root_wildcard_is_acceptable(self, tmp_path, monkeypatch):
        """Wildcard in a root account emergency policy should not fail the check."""
        monkeypatch.chdir(tmp_path)
        tf = tmp_path / "root_policy.tf"
        tf.write_text("""
data "aws_iam_policy_document" "root_emergency" {
  statement {
    sid     = "AllowRootAccountAdmin"
    actions = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
  }
}
""")
        result = check_iam_wildcards()
        # Should be flagged but as root policy
        for finding in result.get("findings", []):
            if "root" in finding.get("file", "") or finding.get("is_root_emergency_policy"):
                assert finding["is_root_emergency_policy"] is True


class TestKMSRotationCheck:

    def test_kms_rotation_enabled_passes(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        tf = tmp_path / "kms.tf"
        tf.write_text("""
resource "aws_kms_key" "main" {
  description         = "Test key"
  enable_key_rotation = true
}
""")
        result = check_kms_rotation()
        assert result["passed"]
        assert result["keys_found"] == 1
        assert result["keys_with_rotation"] == 1

    def test_kms_rotation_missing_fails(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        tf = tmp_path / "kms.tf"
        tf.write_text("""
resource "aws_kms_key" "main" {
  description         = "Test key"
  enable_key_rotation = false
}
""")
        result = check_kms_rotation()
        assert not result["passed"]


class TestS3PublicAccessCheck:

    def test_matching_bucket_and_block_passes(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        tf = tmp_path / "s3.tf"
        tf.write_text("""
resource "aws_s3_bucket" "data" { bucket = "test-bucket" }
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
""")
        result = check_s3_public_access_block()
        assert result["s3_buckets_defined"] == 1
        assert result["with_public_access_block"] == 1
        assert result["passed"]

    def test_bucket_without_block_fails(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        tf = tmp_path / "s3.tf"
        tf.write_text("""
resource "aws_s3_bucket" "data" { bucket = "test-bucket" }
""")
        result = check_s3_public_access_block()
        assert not result["passed"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
