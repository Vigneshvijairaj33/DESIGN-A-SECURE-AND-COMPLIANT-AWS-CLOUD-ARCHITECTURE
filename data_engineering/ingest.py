"""
ingest.py
=========
Ingestion orchestrator — runs generate → validate → transform in sequence,
then optionally uploads results to S3 if credentials are available.

Usage:
    python data_engineering/ingest.py                # local only
    python data_engineering/ingest.py --upload-s3   # local + S3 upload

S3 upload requires:
    - AWS credentials configured (aws configure or IAM role)
    - Environment variable: S3_RAW_BUCKET=your-bucket-name
    - Appropriate IAM permissions: s3:PutObject on the raw bucket
"""

import argparse
import os
import sys
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# Add project root to path so sibling modules are importable
# ─────────────────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_engineering.generate_events import generate_dataset, save_dataset
from data_engineering.validate import validate
from data_engineering.transform import transform


def upload_to_s3(local_path: str, bucket: str, s3_key: str) -> bool:
    """
    Upload a local file to S3.
    Returns True on success, False on failure.
    Never prints credentials or access keys.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError

        s3 = boto3.client("s3")
        print(f"  [s3] Uploading {local_path} → s3://{bucket}/{s3_key}")
        s3.upload_file(local_path, bucket, s3_key)
        print(f"  [s3] Upload successful")
        return True

    except ImportError:
        print("  [WARN] boto3 not installed — skipping S3 upload")
        return False
    except Exception as exc:
        # Catch broadly and print the message only — never expose credentials
        print(f"  [ERROR] S3 upload failed: {type(exc).__name__}: {exc}")
        return False


def run_pipeline(upload_s3: bool = False) -> None:
    start = datetime.now(timezone.utc)
    print("=" * 60)
    print("SECURE COMPLIANT CLOUD — Data Ingestion Pipeline")
    print(f"Started: {start.isoformat()}")
    print("=" * 60)

    # ── Phase 1: Generate ────────────────────────────────────────────────────
    print("\n── Phase 1: Generate synthetic events ──")
    df_raw = generate_dataset()
    save_dataset(df_raw)

    # ── Phase 2: Validate ────────────────────────────────────────────────────
    print("\n── Phase 2: Validate raw events ──")
    report = validate()
    if report.get("overall_status") == "FAIL":
        print("[ABORT] Validation failed — check sample_data/validation_report.json")
        sys.exit(1)

    # ── Phase 3: Transform ───────────────────────────────────────────────────
    print("\n── Phase 3: Transform and enrich events ──")
    df_processed = transform()

    # ── Phase 4: Optional S3 upload ─────────────────────────────────────────
    if upload_s3:
        print("\n── Phase 4: Upload to S3 ──")
        bucket = os.environ.get("S3_RAW_BUCKET", "")
        if not bucket:
            print("  [WARN] S3_RAW_BUCKET environment variable not set — skipping")
        else:
            date_prefix = datetime.now(timezone.utc).strftime("%Y/%m/%d")
            upload_to_s3(
                "sample_data/raw_security_events.parquet",
                bucket,
                f"raw/security-events/{date_prefix}/raw_security_events.parquet",
            )
            upload_to_s3(
                "sample_data/processed_events.parquet",
                bucket,
                f"processed/security-events/{date_prefix}/processed_events.parquet",
            )

    # ── Summary ──────────────────────────────────────────────────────────────
    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print(f"  Duration       : {elapsed:.1f}s")
    print(f"  Raw events     : {len(df_raw)}")
    print(f"  Valid events   : {report['output']['valid_record_count']}")
    print(f"  Processed rows : {len(df_processed)}")
    print(f"  Quarantined    : {report['output']['quarantined_record_count']}")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the security event ingestion pipeline")
    parser.add_argument(
        "--upload-s3",
        action="store_true",
        help="Upload processed files to S3 (requires credentials and S3_RAW_BUCKET env var)",
    )
    args = parser.parse_args()
    run_pipeline(upload_s3=args.upload_s3)
