# Monitoring and Alerting Configuration
## Project: Secure Compliant Cloud Architecture

---

## Monitoring Matrix

| ID | Service | Event / Condition | Detection Method | Severity | Notification | Investigation Procedure |
|----|---------|-------------------|-----------------|----------|-------------|------------------------|
| M01 | CloudTrail | Root account used | CW metric filter → alarm | CRITICAL | SNS email | Check CT event for action, source IP, time. Verify MFA was used. Rotate root credentials. |
| M02 | CloudTrail | IAM policy change | CW metric filter → alarm | HIGH | SNS email | Identify which policy changed. Verify business justification. Check for privilege escalation. |
| M03 | CloudTrail | Unauthorized API calls (≥5 in 5min) | CW metric filter → alarm | MEDIUM | SNS email | Identify principal, source IP. Check if credentials compromised. |
| M04 | CloudTrail | S3 bucket policy changed | CW metric filter → alarm | HIGH | SNS email | Verify new policy. Check if public access was inadvertently enabled. |
| M05 | CloudTrail | CloudTrail itself modified/stopped | CW metric filter → alarm | CRITICAL | SNS email | Verify change was authorized. Re-enable logging immediately if stopped. |
| M06 | AWS Config | s3-bucket-public-read-prohibited | Config rule evaluation | HIGH | Config findings | Identify bucket, who made it public, revert immediately. |
| M07 | AWS Config | s3-bucket-server-side-encryption | Config rule evaluation | HIGH | Config findings | Enable SSE-KMS on non-compliant bucket. Check data exposure window. |
| M08 | AWS Config | cloudtrail-enabled | Config rule evaluation | CRITICAL | Config findings | Re-enable CloudTrail. Review gap period in logs. |
| M09 | AWS Config | root-mfa-enabled | Config rule evaluation | CRITICAL | Config findings | Enable MFA on root account immediately. |
| M10 | AWS Config | cmk-backing-key-rotation-enabled | Config rule evaluation | MEDIUM | Config findings | Enable rotation on non-compliant KMS keys. |
| M11 | IAM Access Analyzer | External principal can access resource | Access Analyzer finding | HIGH | Console finding | Review finding. Archive if intentional (document reason). Restrict if unintentional. |
| M12 | AI Model | Anomaly score ≥ 85 (CRITICAL) | Isolation Forest | CRITICAL | Alert JSON | Full CloudTrail investigation for principal. Consider role suspension pending review. |
| M13 | AI Model | Anomaly score 65–84 (HIGH) | Isolation Forest | HIGH | Alert JSON | Review last 6 hours CloudTrail for principal. Correlate with Config findings. |
| M14 | AI Model | Anomaly score 40–64 (MEDIUM) | Isolation Forest | MEDIUM | Alert JSON | Review event patterns. Confirm business justification. Monitor for 24 hours. |

---

## CloudTrail — What It Detects and What It Does Not

### What CloudTrail Records

- Every AWS API call: who, what, when, from where
- Management events: IAM, EC2, S3 bucket operations, KMS, VPC changes
- Data events (if enabled, incurs cost): S3 object-level GET/PUT, Lambda invocations
- Insights events (if enabled): unusual API call rates

### What CloudTrail Does NOT Detect

- Network-level threats (port scans, DDoS) — use VPC Flow Logs + Shield
- Application-layer attacks — use WAF
- Malware on EC2 instances — use GuardDuty malware protection
- Data content of API calls (only metadata and parameters)
- Actions taken within an OS or application — use CloudWatch Agent

### Reading a CloudTrail Event

Example event structure:
```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAXXXXXXXXXXXXXXXXX",
    "arn": "arn:aws:iam::123456789012:user/alice",
    "accountId": "123456789012"
  },
  "eventTime": "2026-01-15T10:30:00Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "PutRolePolicy",
  "awsRegion": "ap-south-1",
  "sourceIPAddress": "203.0.113.10",
  "userAgent": "aws-cli/2.35.0",
  "requestParameters": { "roleName": "my-role", "policyName": "inline-policy" },
  "responseElements": null,
  "errorCode": null,
  "errorMessage": null
}
```

Key fields to investigate:
- `userIdentity.arn` — who made the call
- `eventName` — what was done
- `sourceIPAddress` — from where
- `awsRegion` — in which region
- `errorCode` — if present, the call failed (useful for detecting enumeration)

---

## AWS Config — Rule Reference

| Rule | What It Checks | Trigger |
|------|---------------|---------|
| S3_BUCKET_PUBLIC_READ_PROHIBITED | No bucket allows public read access | Configuration change |
| S3_BUCKET_PUBLIC_WRITE_PROHIBITED | No bucket allows public write access | Configuration change |
| S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED | All buckets have SSE enabled | Configuration change |
| CLOUD_TRAIL_ENABLED | At least one multi-region trail is active | Periodic |
| ROOT_ACCOUNT_MFA_ENABLED | Root account has MFA | Periodic |
| IAM_ROOT_ACCESS_KEY_CHECK | Root account has no access keys | Periodic |
| IAM_PASSWORD_POLICY | Account password policy meets requirements | Periodic |
| CMK_BACKING_KEY_ROTATION_ENABLED | All KMS CMKs have rotation enabled | Configuration change |

Costs: ~$0.001 per configuration item recorded + $0.001 per rule evaluation.

---

## GuardDuty — Optional Threat Detection

GuardDuty is disabled in this demo due to cost ($4 per 1M CloudTrail events).

### What GuardDuty Detects That CloudTrail Alone Cannot

- Cryptocurrency mining (EC2 / ECS findings)
- Backdoor communication (DNS exfiltration, command-and-control)
- Compromised IAM credentials used from known malicious IPs
- Port scanning from EC2 instances
- S3 data exfiltration patterns
- Unusual container activity

### Enabling GuardDuty (When Approved)

```powershell
# Enable in your region
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Generate sample findings for testing (does NOT affect real resources)
aws guardduty create-sample-findings \
  --detector-id <detector-id> \
  --finding-types "UnauthorizedAccess:IAMUser/MaliciousIPCaller"
```

Cost estimate: First 30 days free trial, then ~$4/1M CloudTrail events.

---

## Security Hub — Optional CSPM Aggregation

Security Hub is disabled in this demo due to cost.

### What It Provides

- Aggregates findings from GuardDuty, IAM Access Analyzer, Config, Macie
- CIS AWS Foundations Benchmark compliance score
- AWS Foundational Security Best Practices standard
- Single pane of glass across multiple AWS accounts (with Organizations)

### Enabling Security Hub (When Approved)

```powershell
aws securityhub enable-security-hub --enable-default-standards

# Enable CIS AWS Foundations Benchmark standard
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
  StandardsArn="arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
```

Cost: $0.0010 per Security Hub finding check per resource per month.
