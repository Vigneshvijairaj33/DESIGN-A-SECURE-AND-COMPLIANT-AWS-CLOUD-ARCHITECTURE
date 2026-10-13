# Security Control Matrix
## Project: Secure and Compliant Cloud Architecture
## Classification: SYNTHETIC / DEMONSTRATION

---

## Control Categories

| Category | Controls |
|----------|---------|
| Preventive | Stop an attack before it succeeds |
| Detective | Identify an attack in progress or after the fact |
| Responsive | Contain and recover from an incident |
| Recovery | Restore systems and data after an incident |

---

## Full Security Control Matrix

| ID | Control | Type | AWS Service / Tool | NIST CSF | NIST SP 800-53 | CIS AWS | ISO 27001 | DPDPA 2023 |
|----|---------|------|-------------------|---------|---------------|---------|----------|-----------|
| SC-01 | S3 Block Public Access (account + bucket) | Preventive | S3 | PR.AC-3 | AC-3, SC-7 | 2.1.1 | A.9.4 | Art. 8(4) |
| SC-02 | S3 SSE-KMS encryption at rest | Preventive | S3 + KMS | PR.DS-1 | SC-28 | 2.1.2 | A.10.1 | Art. 8(4) |
| SC-03 | S3 enforce HTTPS (deny HTTP) | Preventive | S3 Bucket Policy | PR.DS-2 | SC-8 | 2.1.3 | A.13.1 | Art. 8(4) |
| SC-04 | S3 versioning on audit logs | Preventive + Recovery | S3 | PR.IP-4 | CP-9 | 2.1.4 | A.12.3 | Art. 8(7) |
| SC-05 | S3 Object Lock / MFA Delete on log bucket | Preventive | S3 | PR.DS-6 | AU-9 | 2.1.4 | A.12.7 | Art. 8(7) |
| SC-06 | IAM least-privilege roles (no wildcards) | Preventive | IAM | PR.AC-4 | AC-6 | 1.1–1.22 | A.9.1 | Art. 8(1) |
| SC-07 | IAM roles with temporary credentials (STS) | Preventive | IAM / STS | PR.AC-1 | IA-5 | 1.1 | A.9.2 | — |
| SC-08 | No long-lived IAM access keys | Preventive | IAM | PR.AC-1 | IA-5 | 1.13 | A.9.4 | — |
| SC-09 | MFA required for sensitive IAM actions | Preventive | IAM Policy Condition | PR.AC-7 | IA-2 | 1.10 | A.9.4 | — |
| SC-10 | IAM Access Analyzer — external access findings | Detective | IAM Access Analyzer | DE.CM-3 | AC-6, AC-17 | 1.21 | A.9.2 | — |
| SC-11 | KMS Customer Managed Key per data zone | Preventive | KMS | PR.DS-1 | SC-12 | — | A.10.1 | Art. 8(4) |
| SC-12 | KMS automatic annual key rotation | Preventive | KMS | PR.DS-1 | SC-12 | — | A.10.1 | Art. 8(4) |
| SC-13 | CloudTrail — multi-region, all management events | Detective | CloudTrail | DE.CM-3 | AU-2, AU-12 | 3.1 | A.12.4 | Art. 8(6) |
| SC-14 | CloudTrail log-file integrity validation | Detective | CloudTrail | DE.CM-3 | AU-9 | 3.2 | A.12.4 | Art. 8(6) |
| SC-15 | CloudTrail logs stored in protected S3 bucket | Preventive + Detective | S3 + CloudTrail | PR.DS-6 | AU-9 | 3.3 | A.12.4 | Art. 8(6) |
| SC-16 | AWS Config continuous recording | Detective | AWS Config | DE.CM-7 | CM-6, CM-7 | 3.5 | A.12.1 | — |
| SC-17 | AWS Config — s3-bucket-public-read-prohibited | Detective | AWS Config | DE.CM-7 | SI-7 | 2.1.1 | A.9.4 | Art. 8(4) |
| SC-18 | AWS Config — s3-bucket-server-side-encryption | Detective | AWS Config | DE.CM-7 | SC-28 | 2.1.2 | A.10.1 | Art. 8(4) |
| SC-19 | AWS Config — cloudtrail-enabled | Detective | AWS Config | DE.CM-7 | AU-2 | 3.1 | A.12.4 | Art. 8(6) |
| SC-20 | CloudWatch metric filter — root account usage | Detective | CloudWatch | DE.AE-3 | AU-6 | 3.3 | A.12.4 | — |
| SC-21 | CloudWatch metric filter — IAM policy changes | Detective | CloudWatch | DE.AE-3 | AU-6 | 3.4 | A.12.4 | — |
| SC-22 | CloudWatch metric filter — unauthorized API calls | Detective | CloudWatch | DE.AE-3 | AU-6 | 3.1 | A.12.4 | — |
| SC-23 | CloudWatch alarm → SNS notification | Responsive | CloudWatch + SNS | RS.CO-2 | IR-6 | — | A.16.1 | — |
| SC-24 | VPC with private subnets (no public workloads) | Preventive | VPC | PR.AC-5 | SC-7 | 4.1–4.6 | A.13.1 | — |
| SC-25 | Security Groups — least-privilege ingress/egress | Preventive | VPC Security Groups | PR.AC-5 | SC-7 | 4.1 | A.13.1 | — |
| SC-26 | VPC Endpoints (S3, KMS, SSM) — no IGW path | Preventive | VPC Endpoints | PR.AC-5 | SC-7 | — | A.13.1 | — |
| SC-27 | No SSH/RDP open to 0.0.0.0/0 | Preventive | Security Groups | PR.AC-5 | SC-7 | 4.1 | A.13.1 | — |
| SC-28 | Systems Manager Session Manager (no bastion) | Preventive | SSM | PR.AC-3 | AC-17 | — | A.6.2 | — |
| SC-29 | Secrets in Secrets Manager / SSM Parameter Store | Preventive | Secrets Manager | PR.DS-1 | SC-28 | — | A.9.4 | Art. 8(4) |
| SC-30 | Data pipeline schema validation + quarantine | Preventive + Detective | Python / Glue | PR.DS-2 | SI-10 | — | A.14.2 | Art. 8(3) |
| SC-31 | Data quality scoring and reporting | Detective | Python pipeline | DE.AE-1 | SI-12 | — | A.14.2 | Art. 8(3) |
| SC-32 | AI anomaly detection — Isolation Forest | Detective | Python / scikit-learn | DE.AE-2 | SI-4 | — | A.12.4 | — |
| SC-33 | AI explainable alerts (not auto-remediation) | Detective + Responsive | Python / scikit-learn | RS.AN-1 | IR-5 | — | A.16.1 | — |
| SC-34 | AI model evaluation metrics (P, R, F1) | Detective | Python / scikit-learn | ID.RA-1 | CA-7 | — | A.12.4 | — |
| SC-35 | No real credentials in source code or logs | Preventive | Policy + .gitignore | PR.DS-5 | IA-5 | — | A.9.4 | Art. 8(4) |
| SC-36 | GuardDuty threat detection (optional) | Detective | GuardDuty | DE.CM-1 | SI-4 | — | A.12.4 | — |
| SC-37 | Security Hub CSPM aggregation (optional) | Detective | Security Hub | DE.CM-8 | CA-7 | — | A.18.2 | — |

---

## DPDPA 2023 (India) Mapping Summary

| Article | Obligation | This Architecture |
|---------|-----------|-----------------|
| Art. 4 | Process personal data only for lawful purpose | Synthetic data only in demo; production must obtain consent |
| Art. 8(1) | Implement appropriate technical safeguards | IAM least-privilege, VPC isolation, KMS encryption |
| Art. 8(3) | Data accuracy and quality | Schema validation, data quality reports |
| Art. 8(4) | Data protection measures | SSE-KMS, HTTPS enforcement, Block Public Access, Secrets Manager |
| Art. 8(6) | Notify within 72 hours of a breach | CloudTrail + CloudWatch alarms + SNS; GuardDuty findings (if enabled) |
| Art. 8(7) | Data retention and erasure | S3 lifecycle policies; bucket versioning; documented retention schedule |

> **Disclaimer:** This table is a design-level mapping for educational purposes only.
> It does not constitute legal advice, a formal compliance certification, or an audit-ready assessment.
> Legal and organizational obligations under DPDPA 2023 require professional legal review.

---

## Gap Analysis

| Gap | Description | Recommended Remediation |
|-----|------------|------------------------|
| G1 | GuardDuty disabled | Enable in all regions; review findings weekly |
| G2 | Security Hub disabled | Enable; subscribe to CIS AWS Foundations standard |
| G3 | Single AWS account | Move to multi-account AWS Organizations for production |
| G4 | Terraform state is local | Use S3 backend + DynamoDB lock table for team use |
| G5 | No WAF | Add AWS WAF + Shield if any public ALB/API Gateway is added |
| G6 | AI model trained on synthetic data | Retrain with authorized real security events before production |
| G7 | No formal incident response runbook | Create IR runbook; test with annual tabletop exercise |
| G8 | No data retention policy document | Define and document retention schedules per data classification |
| G9 | VPC Flow Logs disabled | Enable for investigation windows; export to S3 to reduce cost |
