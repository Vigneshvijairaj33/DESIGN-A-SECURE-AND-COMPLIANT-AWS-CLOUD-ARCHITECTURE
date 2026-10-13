"""
generate_events.py
==================
Generates a SYNTHETIC dataset of AWS-style security events.

IMPORTANT: This dataset is entirely fabricated for demonstration purposes.
It does NOT contain real user data, real AWS account IDs, real IP addresses
linked to real people, or any confidential information.

Usage:
    python data_engineering/generate_events.py

Output:
    sample_data/raw_security_events.csv
    sample_data/raw_security_events.parquet
"""

import os
import random
import uuid
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# Seed for reproducibility — same seed → same dataset every run
# ─────────────────────────────────────────────────────────────────────────────
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
NUM_NORMAL_EVENTS = 800       # Benign baseline events
NUM_SUSPICIOUS_EVENTS = 200   # Synthetic anomalies — labeled for evaluation
OUTPUT_DIR = "sample_data"

# Synthetic principal IDs (not real AWS ARNs — fictional)
PRINCIPALS = [
    "AIDA-SYNTHETIC-USER-001",
    "AIDA-SYNTHETIC-USER-002",
    "AIDA-SYNTHETIC-USER-003",
    "AIDA-SYNTHETIC-USER-004",
    "AIDA-SYNTHETIC-USER-005",
    "AROA-SYNTHETIC-ROLE-APP",
    "AROA-SYNTHETIC-ROLE-DATA",
]

# Suspicious principal — appears only in anomaly scenarios
SUSPICIOUS_PRINCIPAL = "AIDA-SYNTHETIC-ATTACKER-099"

# Common AWS API actions — split into normal and sensitive categories
NORMAL_API_ACTIONS = [
    "DescribeInstances",
    "ListBuckets",
    "GetObject",
    "PutObject",
    "DescribeSecurityGroups",
    "DescribeVpcs",
    "ListRoles",
    "GetCallerIdentity",
    "DescribeLogGroups",
    "GetMetricData",
    "ListFunctions",
    "DescribeDBInstances",
    "GetQueueAttributes",
    "ListTopics",
]

SENSITIVE_API_ACTIONS = [
    "PutRolePolicy",
    "CreateUser",
    "AttachUserPolicy",
    "DeleteTrail",
    "StopLogging",
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "CreateAccessKey",
    "UpdateAssumeRolePolicy",
    "DeleteUser",
    "PutBucketAcl",
]

# Synthetic CIDR space — fictional RFC 5737 documentation range
NORMAL_IPS = [f"192.0.2.{i}" for i in range(1, 50)]  # RFC 5737 TEST-NET-1
UNUSUAL_IPS = [f"198.51.100.{i}" for i in range(1, 20)]  # RFC 5737 TEST-NET-2

# AWS regions — home region is ap-south-1
HOME_REGION = "ap-south-1"
UNUSUAL_REGIONS = ["us-east-1", "eu-west-1", "ap-northeast-1", "sa-east-1"]
ALL_REGIONS = [HOME_REGION] + UNUSUAL_REGIONS

# Event sources
EVENT_SOURCES = {
    "DescribeInstances": "ec2.amazonaws.com",
    "ListBuckets": "s3.amazonaws.com",
    "GetObject": "s3.amazonaws.com",
    "PutObject": "s3.amazonaws.com",
    "DescribeSecurityGroups": "ec2.amazonaws.com",
    "DescribeVpcs": "ec2.amazonaws.com",
    "ListRoles": "iam.amazonaws.com",
    "GetCallerIdentity": "sts.amazonaws.com",
    "DescribeLogGroups": "logs.amazonaws.com",
    "GetMetricData": "monitoring.amazonaws.com",
    "ListFunctions": "lambda.amazonaws.com",
    "DescribeDBInstances": "rds.amazonaws.com",
    "GetQueueAttributes": "sqs.amazonaws.com",
    "ListTopics": "sns.amazonaws.com",
    "PutRolePolicy": "iam.amazonaws.com",
    "CreateUser": "iam.amazonaws.com",
    "AttachUserPolicy": "iam.amazonaws.com",
    "DeleteTrail": "cloudtrail.amazonaws.com",
    "StopLogging": "cloudtrail.amazonaws.com",
    "PutBucketPolicy": "s3.amazonaws.com",
    "DeleteBucketPolicy": "s3.amazonaws.com",
    "CreateAccessKey": "iam.amazonaws.com",
    "UpdateAssumeRolePolicy": "iam.amazonaws.com",
    "DeleteUser": "iam.amazonaws.com",
    "PutBucketAcl": "s3.amazonaws.com",
}

USER_AGENTS = [
    "aws-cli/2.35.0 Python/3.11.0 Windows/11 botocore/2.0.0",
    "Boto3/1.34.0 Python/3.11.0",
    "console.amazonaws.com",
    "aws-sdk-java/2.20.0",
    "aws-sdk-go/1.50.0",
]


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _random_timestamp(start_hours_ago: int = 168, end_hours_ago: int = 0) -> str:
    """Return a random ISO-8601 UTC timestamp within the specified window."""
    now = datetime.now(timezone.utc)
    delta_seconds = random.randint(end_hours_ago * 3600, start_hours_ago * 3600)
    ts = now - timedelta(seconds=delta_seconds)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _resource_type_for(event_name: str) -> str:
    source = EVENT_SOURCES.get(event_name, "unknown")
    mapping = {
        "ec2.amazonaws.com": "AWS::EC2::Instance",
        "s3.amazonaws.com": "AWS::S3::Bucket",
        "iam.amazonaws.com": "AWS::IAM::Role",
        "sts.amazonaws.com": "AWS::IAM::User",
        "logs.amazonaws.com": "AWS::Logs::LogGroup",
        "monitoring.amazonaws.com": "AWS::CloudWatch::Alarm",
        "lambda.amazonaws.com": "AWS::Lambda::Function",
        "rds.amazonaws.com": "AWS::RDS::DBInstance",
        "sqs.amazonaws.com": "AWS::SQS::Queue",
        "sns.amazonaws.com": "AWS::SNS::Topic",
        "cloudtrail.amazonaws.com": "AWS::CloudTrail::Trail",
    }
    return mapping.get(source, "AWS::Unknown")


def _make_normal_event() -> dict:
    """Create one synthetic normal (benign) security event."""
    event_name = random.choice(NORMAL_API_ACTIONS)
    return {
        "event_id": str(uuid.uuid4()),
        "event_time": _random_timestamp(),
        "event_source": EVENT_SOURCES.get(event_name, "unknown"),
        "event_name": event_name,
        "principal_id": random.choice(PRINCIPALS),
        "source_ip": random.choice(NORMAL_IPS),
        "aws_region": random.choices(
            ALL_REGIONS, weights=[0.85, 0.05, 0.04, 0.04, 0.02], k=1
        )[0],
        "resource_type": _resource_type_for(event_name),
        "outcome": random.choices(["Success", "Failure"], weights=[0.97, 0.03], k=1)[0],
        "user_agent": random.choice(USER_AGENTS),
        "event_category": "Management",
        "is_anomaly": 0,  # Ground-truth label for evaluation
        "anomaly_scenario": "none",
    }


def _make_suspicious_event(scenario: str) -> dict:
    """Create one synthetic suspicious event for a named anomaly scenario."""
    base = {
        "event_id": str(uuid.uuid4()),
        "anomaly_scenario": scenario,
        "is_anomaly": 1,
    }

    if scenario == "credential_abuse":
        # Many failed API calls from an unusual IP in a short window
        event_name = random.choice(NORMAL_API_ACTIONS)
        base.update({
            "event_time": _random_timestamp(start_hours_ago=2, end_hours_ago=0),
            "event_source": EVENT_SOURCES.get(event_name, "unknown"),
            "event_name": event_name,
            "principal_id": random.choice(PRINCIPALS),
            "source_ip": random.choice(UNUSUAL_IPS),
            "aws_region": HOME_REGION,
            "resource_type": _resource_type_for(event_name),
            "outcome": "Failure",
            "user_agent": "python-requests/2.31.0",  # Unusual UA
            "event_category": "Management",
        })

    elif scenario == "privilege_escalation":
        # Sensitive IAM actions from an unusual region
        event_name = random.choice(SENSITIVE_API_ACTIONS[:5])
        base.update({
            "event_time": _random_timestamp(start_hours_ago=12, end_hours_ago=0),
            "event_source": "iam.amazonaws.com",
            "event_name": event_name,
            "principal_id": SUSPICIOUS_PRINCIPAL,
            "source_ip": random.choice(UNUSUAL_IPS),
            "aws_region": random.choice(UNUSUAL_REGIONS),
            "resource_type": "AWS::IAM::Role",
            "outcome": "Success",
            "user_agent": random.choice(USER_AGENTS),
            "event_category": "Management",
        })

    elif scenario == "audit_tampering":
        # CloudTrail stop/delete events — very high severity
        event_name = random.choice(["DeleteTrail", "StopLogging"])
        base.update({
            "event_time": _random_timestamp(start_hours_ago=6, end_hours_ago=0),
            "event_source": "cloudtrail.amazonaws.com",
            "event_name": event_name,
            "principal_id": random.choice(PRINCIPALS),
            "source_ip": random.choice(UNUSUAL_IPS),
            "aws_region": HOME_REGION,
            "resource_type": "AWS::CloudTrail::Trail",
            "outcome": "Success",
            "user_agent": "aws-cli/2.35.0 Python/3.11.0 Windows/11 botocore/2.0.0",
            "event_category": "Management",
        })

    elif scenario == "data_exfiltration":
        # Unusual GetObject spike from a new IP, off-hours
        base.update({
            "event_time": _random_timestamp(start_hours_ago=3, end_hours_ago=1),
            "event_source": "s3.amazonaws.com",
            "event_name": "GetObject",
            "principal_id": random.choice(PRINCIPALS),
            "source_ip": random.choice(UNUSUAL_IPS),
            "aws_region": HOME_REGION,
            "resource_type": "AWS::S3::Bucket",
            "outcome": "Success",
            "user_agent": "python-requests/2.31.0",
            "event_category": "Data",
        })

    elif scenario == "unusual_region":
        # Normal action but from an unexpected region
        event_name = random.choice(NORMAL_API_ACTIONS)
        base.update({
            "event_time": _random_timestamp(start_hours_ago=24, end_hours_ago=0),
            "event_source": EVENT_SOURCES.get(event_name, "unknown"),
            "event_name": event_name,
            "principal_id": random.choice(PRINCIPALS),
            "source_ip": random.choice(NORMAL_IPS),
            "aws_region": random.choice(UNUSUAL_REGIONS),
            "resource_type": _resource_type_for(event_name),
            "outcome": "Success",
            "user_agent": random.choice(USER_AGENTS),
            "event_category": "Management",
        })

    return base


# ─────────────────────────────────────────────────────────────────────────────
# Main generation logic
# ─────────────────────────────────────────────────────────────────────────────

def generate_dataset() -> pd.DataFrame:
    print("[generate_events] Generating synthetic security events...")

    normal_events = [_make_normal_event() for _ in range(NUM_NORMAL_EVENTS)]

    # Distribute suspicious events across scenarios
    scenarios = [
        "credential_abuse",
        "privilege_escalation",
        "audit_tampering",
        "data_exfiltration",
        "unusual_region",
    ]
    suspicious_events = []
    per_scenario = NUM_SUSPICIOUS_EVENTS // len(scenarios)
    for scenario in scenarios:
        for _ in range(per_scenario):
            suspicious_events.append(_make_suspicious_event(scenario))

    all_events = normal_events + suspicious_events
    random.shuffle(all_events)

    df = pd.DataFrame(all_events)

    # Column ordering — mirrors CloudTrail structure
    columns = [
        "event_id",
        "event_time",
        "event_source",
        "event_name",
        "principal_id",
        "source_ip",
        "aws_region",
        "resource_type",
        "outcome",
        "user_agent",
        "event_category",
        "is_anomaly",
        "anomaly_scenario",
    ]
    df = df[columns]

    print(f"  Total events     : {len(df)}")
    print(f"  Normal events    : {(df['is_anomaly'] == 0).sum()}")
    print(f"  Suspicious events: {(df['is_anomaly'] == 1).sum()}")
    print(f"  Scenarios        : {df['anomaly_scenario'].value_counts().to_dict()}")

    return df


def save_dataset(df: pd.DataFrame) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # CSV — human-readable
    csv_path = os.path.join(OUTPUT_DIR, "raw_security_events.csv")
    df.to_csv(csv_path, index=False)
    print(f"  [saved] {csv_path}")

    # Parquet — efficient for pipeline processing
    parquet_path = os.path.join(OUTPUT_DIR, "raw_security_events.parquet")
    df.to_parquet(parquet_path, index=False, engine="pyarrow")
    print(f"  [saved] {parquet_path}")


if __name__ == "__main__":
    df = generate_dataset()
    save_dataset(df)
    print("\n[generate_events] Done. Dataset summary:")
    print(df.describe(include="all").to_string())
