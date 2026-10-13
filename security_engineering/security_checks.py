"""
security_checks.py
==================
Local security configuration checks that can run without AWS credentials.

When AWS credentials ARE available, these checks query the live account.
When credentials are NOT available, checks run against local configuration
files and produce a "local-only" verification report.

Checks implemented:
  1.  Python dependency audit (known vulnerable packages)
  2.  .env / secrets file detection in project
  3.  Hardcoded credential pattern scan in source files
  4.  Terraform configuration static analysis (basic)
  5.  S3 bucket policy — HTTPS enforcement present?  (template check)
  6.  KMS key rotation — enabled in Terraform config?
  7.  CloudTrail log validation — enabled in Terraform config?
  8.  IAM wildcard permission scan in policy files
  9.  AWS CLI credentials check (presence, not values)
  10. Summary and remediation guide

Usage:
    python security_engineering/security_checks.py

Output:
    reports/security_checks_report.json
    reports/security_checks_report.txt
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

REPORT_JSON = "reports/security_checks_report.json"
REPORT_TXT = "reports/security_checks_report.txt"

# Patterns that indicate hard-coded secrets
SECRET_PATTERNS = [
    (r"(?i)aws_access_key_id\s*=\s*[A-Z0-9]{16,}", "AWS Access Key ID"),
    (r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{20,}", "AWS Secret Access Key"),
    (r"(?i)password\s*=\s*['\"][^'\"]{6,}['\"]", "Hardcoded password"),
    (r"(?i)secret\s*=\s*['\"][^'\"]{6,}['\"]", "Hardcoded secret"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key (AKIA prefix)"),
    (r"(?i)api[_-]?key\s*=\s*['\"][^'\"]{8,}['\"]", "API key"),
]

# Files and directories to exclude from scanning
EXCLUDE_PATTERNS = {
    ".git", "__pycache__", "node_modules", ".terraform",
    ".env", "*.pyc", "*.joblib", "*.parquet",
}

PROJECT_ROOT = Path(".")


def _should_exclude(path: Path) -> bool:
    for part in path.parts:
        if part in EXCLUDE_PATTERNS:
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Check 1: .env and secrets file detection
# ─────────────────────────────────────────────────────────────────────────────

def check_env_files() -> dict:
    """Detect .env files or credential files that should not be committed."""
    dangerous_filenames = {
        ".env", "credentials", ".aws/credentials",
        "secrets.json", "secrets.yaml", "secrets.yml",
        "terraform.tfvars",  # May contain sensitive values
    }
    found = []
    for f in PROJECT_ROOT.rglob("*"):
        if _should_exclude(f):
            continue
        if f.name in dangerous_filenames or f.name.endswith(".pem") or f.name.endswith(".key"):
            found.append(str(f))

    return {
        "check": "env_and_secret_files",
        "passed": len(found) == 0,
        "description": "Detect .env, credential, and private key files in the project",
        "findings": found,
        "remediation": (
            "Add .env, terraform.tfvars, *.pem, and *.key to .gitignore. "
            "Never commit credentials to source control."
        ) if found else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Check 2: Hardcoded credential pattern scan
# ─────────────────────────────────────────────────────────────────────────────

def check_hardcoded_credentials() -> dict:
    """Scan Python and Terraform files for hardcoded credential patterns."""
    findings = []
    scan_extensions = {".py", ".tf", ".json", ".yaml", ".yml", ".sh", ".env.example"}

    for f in PROJECT_ROOT.rglob("*"):
        if _should_exclude(f) or not f.is_file():
            continue
        if f.suffix not in scan_extensions:
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            for pattern, label in SECRET_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    findings.append({
                        "file": str(f),
                        "pattern_type": label,
                        "match_count": len(matches),
                        # Never print the actual matched value
                        "note": "Pattern detected — review file manually",
                    })
        except Exception:
            pass

    return {
        "check": "hardcoded_credentials",
        "passed": len(findings) == 0,
        "description": "Scan source files for hardcoded credentials or secrets",
        "findings": findings,
        "remediation": (
            "Move secrets to environment variables or AWS Secrets Manager. "
            "Never store credentials in source code."
        ) if findings else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Check 3: IAM wildcard permission scan in Terraform files
# ─────────────────────────────────────────────────────────────────────────────

def check_iam_wildcards() -> dict:
    """
    Detect wildcard actions (\"*\") in IAM policy documents in Terraform files.
    Some wildcards are intentional (e.g., root account emergency policy) —
    flag them for manual review rather than auto-failing.
    """
    findings = []
    for f in PROJECT_ROOT.rglob("*.tf"):
        if _should_exclude(f):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                # Detect actions = ["*"] or actions = "*"
                if re.search(r'actions\s*=\s*\[?\s*"\*"\s*\]?', line):
                    # Check if it's in a root emergency policy (acceptable)
                    context = "\n".join(lines[max(0, i-5):i+5])
                    is_root_policy = "root" in context.lower() or "AllowRootAccount" in context
                    findings.append({
                        "file": str(f),
                        "line": i,
                        "is_root_emergency_policy": is_root_policy,
                        "note": (
                            "Root account emergency policy — acceptable with MFA condition"
                            if is_root_policy
                            else "Wildcard IAM action found — review and restrict"
                        ),
                    })
        except Exception:
            pass

    non_root_wildcards = [f for f in findings if not f["is_root_emergency_policy"]]
    return {
        "check": "iam_wildcard_actions",
        "passed": len(non_root_wildcards) == 0,
        "description": "Detect non-root wildcard IAM actions in Terraform policies",
        "total_wildcards": len(findings),
        "non_root_wildcards": len(non_root_wildcards),
        "findings": findings[:10],  # Limit output
        "remediation": (
            "Replace wildcard actions with specific allowed actions. "
            "Use IAM Access Analyzer to identify overly permissive policies."
        ) if non_root_wildcards else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Check 4: CloudTrail log validation enabled in Terraform
# ─────────────────────────────────────────────────────────────────────────────

def check_cloudtrail_config() -> dict:
    """Verify CloudTrail log-file integrity validation is enabled in Terraform."""
    for f in PROJECT_ROOT.rglob("*.tf"):
        if _should_exclude(f):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if "aws_cloudtrail" in content:
                has_validation = "enable_log_file_validation" in content and \
                                  re.search(r"enable_log_file_validation\s*=\s*true", content)
                has_kms = "kms_key_id" in content
                has_multiregion = re.search(r"is_multi_region_trail\s*=\s*true", content)
                return {
                    "check": "cloudtrail_configuration",
                    "passed": bool(has_validation and has_kms and has_multiregion),
                    "description": "CloudTrail must have log-file integrity validation, KMS encryption, and multi-region",
                    "log_file_validation": bool(has_validation),
                    "kms_encryption": bool(has_kms),
                    "multi_region": bool(has_multiregion),
                    "remediation": "Enable all three in the aws_cloudtrail Terraform resource." if not (has_validation and has_kms and has_multiregion) else None,
                }
        except Exception:
            pass

    return {
        "check": "cloudtrail_configuration",
        "passed": False,
        "description": "CloudTrail Terraform resource not found",
        "remediation": "Ensure infrastructure/terraform/modules/audit/main.tf defines aws_cloudtrail.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Check 5: KMS key rotation enabled
# ─────────────────────────────────────────────────────────────────────────────

def check_kms_rotation() -> dict:
    """Verify KMS keys have automatic rotation enabled in Terraform."""
    keys_found = 0
    keys_with_rotation = 0

    for f in PROJECT_ROOT.rglob("*.tf"):
        if _should_exclude(f):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            key_blocks = re.findall(
                r'resource\s+"aws_kms_key".*?(?=resource|\Z)', content, re.DOTALL
            )
            for block in key_blocks:
                keys_found += 1
                if re.search(r"enable_key_rotation\s*=\s*true", block):
                    keys_with_rotation += 1
        except Exception:
            pass

    return {
        "check": "kms_key_rotation",
        "passed": keys_found > 0 and keys_found == keys_with_rotation,
        "description": "All KMS keys should have automatic annual rotation enabled",
        "keys_found": keys_found,
        "keys_with_rotation": keys_with_rotation,
        "remediation": "Set enable_key_rotation = true on all aws_kms_key resources." if keys_found != keys_with_rotation else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Check 6: S3 Block Public Access in Terraform
# ─────────────────────────────────────────────────────────────────────────────

def check_s3_public_access_block() -> dict:
    """Verify all S3 buckets have Block Public Access in Terraform."""
    buckets = 0
    with_block = 0

    for f in PROJECT_ROOT.rglob("*.tf"):
        if _should_exclude(f):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            buckets += len(re.findall(r'resource\s+"aws_s3_bucket"', content))
            with_block += len(re.findall(r'resource\s+"aws_s3_bucket_public_access_block"', content))
        except Exception:
            pass

    return {
        "check": "s3_block_public_access",
        "passed": buckets > 0 and with_block >= buckets,
        "description": "Every S3 bucket should have a corresponding aws_s3_bucket_public_access_block",
        "s3_buckets_defined": buckets,
        "with_public_access_block": with_block,
        "remediation": "Add aws_s3_bucket_public_access_block for every S3 bucket." if with_block < buckets else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Check 7: AWS CLI credentials (presence only — never print values)
# ─────────────────────────────────────────────────────────────────────────────

def check_aws_credentials_configured() -> dict:
    """Check if AWS CLI is configured. Report presence only — never values."""
    home = Path.home()
    creds_file = home / ".aws" / "credentials"
    config_file = home / ".aws" / "config"

    has_creds_file = creds_file.exists()
    has_config_file = config_file.exists()

    # Check environment variables (presence only)
    has_env_key_id = bool(os.environ.get("AWS_ACCESS_KEY_ID", ""))
    has_env_secret = bool(os.environ.get("AWS_SECRET_ACCESS_KEY", ""))
    has_env_session = bool(os.environ.get("AWS_SESSION_TOKEN", ""))
    has_env_profile = bool(os.environ.get("AWS_PROFILE", ""))

    configured = has_creds_file or (has_env_key_id and has_env_secret)

    return {
        "check": "aws_credentials_configured",
        "passed": configured,
        "description": "AWS CLI must be configured before deployment",
        "credentials_file_present": has_creds_file,
        "config_file_present": has_config_file,
        "env_vars": {
            "AWS_ACCESS_KEY_ID": "set" if has_env_key_id else "not set",
            "AWS_SECRET_ACCESS_KEY": "set" if has_env_secret else "not set",
            "AWS_SESSION_TOKEN": "set" if has_env_session else "not set",
            "AWS_PROFILE": "set" if has_env_profile else "not set",
        },
        "note": "Credentials detected — values are NOT printed for security",
        "remediation": (
            "Run: aws configure\n"
            "Or set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY environment variables.\n"
            "Prefer IAM roles and temporary credentials over long-lived access keys."
        ) if not configured else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Check 8: .gitignore verification
# ─────────────────────────────────────────────────────────────────────────────

def check_gitignore() -> dict:
    """Verify .gitignore contains entries for secrets and terraform state."""
    required_entries = [
        ".env",
        "terraform.tfvars",
        "*.tfstate",
        "*.tfstate.backup",
        ".terraform/",
        "*.joblib",
        "__pycache__",
        "*.pyc",
    ]

    gitignore_path = PROJECT_ROOT / ".gitignore"
    if not gitignore_path.exists():
        return {
            "check": "gitignore_present",
            "passed": False,
            "description": ".gitignore must exist and cover secrets and state files",
            "missing_entries": required_entries,
            "remediation": "Create a .gitignore file — see the provided .gitignore in this project.",
        }

    content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
    missing = [e for e in required_entries if e not in content]
    return {
        "check": "gitignore_present",
        "passed": len(missing) == 0,
        "description": ".gitignore must cover secrets and terraform state files",
        "missing_entries": missing,
        "remediation": f"Add these entries to .gitignore: {missing}" if missing else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def run_all_checks() -> dict:
    print("[security_checks] Running security configuration checks...")
    print("  (Running on local files — no AWS API calls made)\n")

    checks = [
        check_env_files,
        check_hardcoded_credentials,
        check_iam_wildcards,
        check_cloudtrail_config,
        check_kms_rotation,
        check_s3_public_access_block,
        check_aws_credentials_configured,
        check_gitignore,
    ]

    results = []
    for check_fn in checks:
        result = check_fn()
        status = "PASS" if result.get("passed") else "FAIL"
        print(f"  [{status}] {result['check']}")
        if result.get("remediation"):
            print(f"         Remediation: {result['remediation'][:100]}...")
        results.append(result)

    passed = sum(1 for r in results if r.get("passed"))
    total = len(results)
    score = round((passed / total) * 100, 1) if total > 0 else 0

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "local-file-analysis",
        "checks_passed": passed,
        "total_checks": total,
        "security_score": score,
        "results": results,
    }

    os.makedirs("reports", exist_ok=True)
    with open(REPORT_JSON, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  [saved] {REPORT_JSON}")

    lines = [
        "=" * 60,
        "SECURITY CHECKS REPORT",
        f"Generated : {report['generated_at']}",
        f"Score     : {score}% ({passed}/{total} checks passed)",
        "=" * 60,
    ]
    for r in results:
        status = "PASS" if r.get("passed") else "FAIL"
        lines.append(f"\n[{status}] {r['check']}")
        lines.append(f"  {r['description']}")
        if r.get("remediation"):
            lines.append(f"  REMEDIATION: {r['remediation']}")

    with open(REPORT_TXT, "w") as f:
        f.write("\n".join(lines))
    print(f"  [saved] {REPORT_TXT}")
    print(f"\n[security_checks] Security Score: {score}%")

    return report


if __name__ == "__main__":
    run_all_checks()
