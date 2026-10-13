# Threat Model — Secure Compliant Cloud Architecture

## Project: Secure and Compliant Cloud Architecture with AI-Powered Security Monitoring
## Classification: SYNTHETIC / DEMONSTRATION — Not a production security assessment
## Date: 2026-10-13

---

## 1. Assets to Protect

| Asset | Sensitivity | Owner |
|-------|------------|-------|
| AWS IAM credentials and roles | Critical | Cloud/Security Team |
| KMS encryption keys (CMKs) | Critical | Security Team |
| CloudTrail audit logs | High | Security/Compliance Team |
| S3 raw security event data | High | Data Engineering Team |
| S3 processed / curated datasets | Medium-High | Data / AI Team |
| AI model artifacts and thresholds | Medium | AI Engineering Team |
| VPC network topology | Medium | Cloud Engineering Team |
| AWS Config compliance state | Medium | Cloud/Compliance Team |
| Secrets (DB passwords, API keys) | Critical | All Teams |

---

## 2. Trust Boundaries

```
[Internet / External]
      |
      | (IAM AuthN/AuthZ with MFA)
      v
[AWS Management Plane]  — CloudTrail records all API calls
      |
      | (VPC boundary)
      v
[Public Subnet]         — Only NAT Gateway (no workloads)
      |
      | (Security Groups / NACLs)
      v
[Private App Subnet]    — Lambda, SSM Session Manager
      |
      | (VPC Endpoints — no public routing)
      v
[Private Data Subnet]   — Glue, Athena
      |
      | (IAM + KMS)
      v
[S3 Storage Layer]      — Raw / Processed / Curated / Audit-Logs
```

---

## 3. Potential Attackers and Threats

| Threat Actor | Capability | Motivation |
|-------------|-----------|-----------|
| External attacker | Low–High (depends on exposed surface) | Data theft, ransomware, disruption |
| Compromised IAM credentials | Medium (stolen long-lived keys) | Lateral movement, data exfiltration |
| Malicious insider | High (legitimate access) | Data exfiltration, sabotage |
| Supply-chain compromise | Medium (infected Lambda layer/library) | Persistent backdoor |
| Automated scanner / bot | Low (opportunistic) | Find misconfigured public S3, open ports |

---

## 4. STRIDE Threat Analysis

### S — Spoofing (Impersonation)

| Threat | Attack Surface | Control |
|--------|---------------|---------|
| Attacker uses stolen long-lived access keys to impersonate an IAM user | AWS API / CLI | IAM roles + temporary credentials; no long-lived keys; MFA required for sensitive actions |
| Forged S3 presigned URLs | S3 API | Short expiry on presigned URLs; bucket policies with strict aws:SourceIp or aws:PrincipalOrgID conditions |

### T — Tampering (Data Integrity Attacks)

| Threat | Attack Surface | Control |
|--------|---------------|---------|
| Attacker modifies CloudTrail logs to hide activity | S3 audit-log bucket | CloudTrail log-file integrity validation; S3 Object Lock (WORM); MFA Delete |
| Attacker injects malformed events into the data pipeline to poison the AI model | S3 raw zone | Schema validation in validate.py; malformed-record quarantine; data provenance tagging |
| Attacker modifies AI model thresholds to suppress alerts | Model artifacts in S3 | Restrict write access on curated bucket; version model files; detect threshold drift |

### R — Repudiation (Denial of Actions)

| Threat | Attack Surface | Control |
|--------|---------------|---------|
| Admin denies making a destructive API call | AWS Management Plane | CloudTrail records actor ARN, timestamp, source IP, and request parameters for every API call |
| Data engineer denies uploading bad data | S3 data lake | S3 server-access logging + CloudTrail data events; S3 object tagging with uploader principal |

### I — Information Disclosure (Data Leakage)

| Threat | Attack Surface | Control |
|--------|---------------|---------|
| S3 bucket accidentally made public | S3 ACLs / bucket policy | S3 Block Public Access (account-level + bucket-level); AWS Config s3-bucket-public-read-prohibited rule |
| Unencrypted data at rest | S3 / EBS / RDS | SSE-KMS enforced via bucket policy (deny if not encrypted); AWS Config s3-bucket-server-side-encryption-enabled rule |
| KMS key shared across classification levels | KMS | Separate CMKs per data zone; key policies restrict usage to specific IAM roles |
| Secrets hard-coded in source code | GitHub / Lambda env vars | Secrets Manager / SSM Parameter Store; git-secrets pre-commit hook; .gitignore on .env files |
| Sensitive log data sent to external AI service without authorization | Amazon Bedrock / third-party | Bedrock integration is explicitly opt-in; synthetic data only in this demonstration |

### D — Denial of Service

| Threat | Attack Surface | Control |
|--------|---------------|---------|
| Attacker floods Lambda with events to exhaust concurrency limit | Lambda API | Reserved concurrency limits; S3 event filtering; CloudWatch alarms on Lambda throttles |
| Runaway Glue job exhausts DPU budget | AWS Glue | Glue job bookmark + max DPU cap; CloudWatch Glue metrics + budget alert |
| CloudWatch alarm flood from AI false positives | SNS / email | AI alert threshold tuning; alarm suppression policies; composite alarms |

### E — Elevation of Privilege

| Threat | Attack Surface | Control |
|--------|---------------|---------|
| Lambda execution role over-permissioned; attacker uses it for lateral movement | IAM | Least-privilege Lambda role; IAM Access Analyzer; periodic permission reviews |
| Attacker modifies IAM policies to grant themselves admin | IAM API | SCP denying iam:* without MFA; CloudWatch alarm on iam:PutRolePolicy / iam:CreateUser |
| Attacker uses writable KMS key policy to re-encrypt data | KMS | Strict key policy; separate key administrators from key users; CloudTrail KMS events |

---

## 5. Threat-to-Control Mapping Table

| # | Threat | STRIDE | Likelihood | Impact | Control Type | Implemented Control |
|---|--------|--------|-----------|--------|-------------|-------------------|
| T1 | Publicly exposed S3 bucket | I | High (common) | Critical | Preventive | S3 Block Public Access; restrictive bucket policy; Config rule |
| T2 | Excessive IAM permissions | E | High | High | Preventive | Least-privilege policies; IAM Access Analyzer; no wildcard actions |
| T3 | Unencrypted data at rest | I | Medium | High | Preventive | SSE-KMS; bucket policy denying unencrypted PutObject |
| T4 | Missing or tampered audit logs | R, T | Medium | Critical | Detective + Preventive | CloudTrail + log-file integrity; S3 Object Lock; separate log bucket |
| T5 | Unusual API call pattern | S, E | Medium | High | Detective | CloudTrail → CloudWatch metric filter → Alarm; AI anomaly detection |
| T6 | Unauthorized data access | I | Medium | High | Preventive + Detective | IAM authorization; S3 bucket policy; KMS key policy; CloudTrail data events |
| T7 | Data poisoning of AI pipeline | T | Low–Medium | High | Preventive + Detective | Schema validation; malformed-record quarantine; data quality scoring |
| T8 | AI false positives causing alert fatigue | D (indirect) | Medium | Medium | Responsive | Threshold tuning; F1-score monitoring; human-review queue |
| T9 | Stolen long-lived credentials | S | High | Critical | Preventive | No long-lived keys; IAM roles; MFA; credential-report audit |
| T10 | Secrets in source code | I | Medium | Critical | Preventive | Secrets Manager; .gitignore; no credentials in code or logs |
| T11 | Lambda supply-chain compromise | T, E | Low | High | Preventive + Detective | Pin dependency versions; Lambda layer signing; GuardDuty malware scan (optional) |
| T12 | Configuration drift | T, I | Medium | Medium | Detective + Responsive | AWS Config continuous recording; Config rules; CloudWatch config drift alarm |

---

## 6. Residual Risks

| Risk | Reason Residual | Mitigation Strategy |
|------|----------------|-------------------|
| GuardDuty disabled in demo | Cost constraint | Enable before any production use; costs ~$4/M events |
| Security Hub disabled in demo | Cost constraint | Enable when aggregating findings from multiple accounts |
| No WAF on public endpoints | No public application endpoint in this demo | Add AWS WAF if any public API or ALB is added |
| AI model trained on synthetic data only | Accuracy on real events is unknown | Retrain on authorized real events before production use |
| Single AWS account (no Organizations) | SCP and account-level isolation not available | Extend to AWS Organizations + multi-account for production |
| VPC Flow Logs incur cost | ~$0.50/GB CloudWatch Logs ingestion | Enable only for specific investigation windows or export to S3 |

---

## 7. Security Assumptions

1. The AWS account is a sandbox or development account — not shared with production.
2. The root user is protected with MFA and not used for daily operations.
3. All deployed IAM roles use temporary credentials via STS.
4. The synthetic dataset does not contain real personal data or confidential information.
5. The AI model's alerts are advisory only — no automated remediation actions are taken.
6. KMS Customer Managed Keys are created in the same region as the data.
7. Terraform state is stored locally for the demo; a remote encrypted backend (S3 + DynamoDB) is required for production.
