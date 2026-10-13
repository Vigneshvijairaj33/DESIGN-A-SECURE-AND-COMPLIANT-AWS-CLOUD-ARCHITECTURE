# Deployment Guide — Secure Compliant Cloud Architecture
## Classification: DEMONSTRATION

---

## Before You Deploy — Checklist

Complete every item before running `terraform apply`.

- [ ] AWS account is a sandbox or explicitly authorized environment
- [ ] Root account has MFA enabled
- [ ] `aws sts get-caller-identity` returns the expected account ID and identity
- [ ] Selected region supports all required services (see Regional Availability)
- [ ] You have reviewed all Terraform files and understand every resource
- [ ] You have reviewed the Cost Estimation below and accepted the charges
- [ ] `terraform.tfvars` is populated with real values (copied from `.env.example`)
- [ ] `terraform.tfvars` is in `.gitignore`
- [ ] `alarm_email` is set to an inbox you can access (for SNS confirmation)
- [ ] You have a plan to run `terraform destroy` when the demo is complete

---

## Phase 1 — Local Environment Setup

### 1.1 Install Python dependencies

```powershell
# From the project root:
cd "e:\WIPRO CCP 2\secure-compliant-cloud"
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Expected output: All packages installed without errors.

### 1.2 Install Terraform

Terraform is NOT currently installed. Install it:

```powershell
# Option A: Using Chocolatey (if installed)
choco install terraform

# Option B: Manual install
# 1. Go to https://developer.hashicorp.com/terraform/downloads
# 2. Download the Windows AMD64 zip
# 3. Extract terraform.exe to C:\Windows\System32 or add to PATH
# 4. Verify:
terraform --version
```

Expected: `Terraform v1.x.x`

### 1.3 Verify AWS CLI

```powershell
aws --version
# Expected: aws-cli/2.x.x

aws configure list
# Expected: Shows profile, region (not credentials values)

aws sts get-caller-identity
# Expected: JSON with Account, UserId, Arn — STOP if this fails
```

---

## Phase 2 — Run Local Pipeline (No AWS Required)

Run this phase first — it requires no AWS credentials.

```powershell
cd "e:\WIPRO CCP 2\secure-compliant-cloud"

# Step 1: Run complete data pipeline
python data_engineering/ingest.py
# Expected outputs: sample_data/*.parquet, sample_data/*.csv, reports/validation_report.json

# Step 2: Generate data quality report
python data_engineering/quality_report.py
# Expected output: reports/data_quality_report.json

# Step 3: Engineer features
python ai_engineering/features.py
# Expected output: sample_data/feature_matrix.parquet

# Step 4: Train anomaly detection model
python ai_engineering/train_model.py
# Expected output: sample_data/isolation_forest_model.joblib, sample_data/model_metadata.json

# Step 5: Detect anomalies and generate alerts
python ai_engineering/detect_anomalies.py
# Expected output: reports/security_alerts.json, reports/security_alerts.csv

# Step 6: Evaluate model
python ai_engineering/evaluate_model.py
# Expected output: reports/model_evaluation_report.json

# Step 7: Run audit analysis
python security_engineering/audit_analysis.py
# Expected output: reports/audit_analysis_report.json

# Step 8: Run security checks
python security_engineering/security_checks.py
# Expected output: reports/security_checks_report.json

# Step 9: Run tests
python -m pytest tests/ -v
# Expected: All tests pass (some skip if pipeline hasn't run)
```

---

## Phase 3 — Terraform Deployment (Requires AWS Approval)

> **STOP — Do NOT run this phase until you have:**
> 1. Reviewed the Cost Estimation below
> 2. Confirmed this is a sandbox account
> 3. Explicitly decided to deploy

### 3.1 Configure variables

```powershell
cd infrastructure/terraform
copy terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — set aws_region, alarm_email, environment
```

### 3.2 Initialize Terraform

```powershell
terraform init
# Expected: "Terraform has been successfully initialized!"
```

### 3.3 Validate and plan

```powershell
terraform validate
# Expected: "Success! The configuration is valid."

terraform plan -out=tfplan
# Expected: Shows all resources to be created — READ THIS CAREFULLY
# Review every resource before proceeding
```

### 3.4 Apply (requires explicit confirmation)

```powershell
terraform apply tfplan
# Terraform will show the plan again and ask: "Do you want to perform these actions?"
# Type "yes" only if you have reviewed the plan and cost estimate

# After apply: confirm the SNS email subscription in your inbox
```

### 3.5 Verify deployment

```powershell
# Check CloudTrail is active
aws cloudtrail get-trail-status --name $(terraform output -raw cloudtrail_name)

# Check Config recorder
aws configservice describe-configuration-recorder-status

# Check S3 buckets exist
aws s3 ls | grep $(terraform output -raw s3_raw_bucket_name)

# List CloudWatch alarms
aws cloudwatch describe-alarms --alarm-name-prefix $(terraform output -raw account_id)
```

---

## Phase 4 — Teardown (IMPORTANT — Run to Avoid Charges)

```powershell
cd infrastructure/terraform

# Preview what will be destroyed
terraform plan -destroy

# Destroy all resources
terraform destroy
# Type "yes" to confirm

# Verify destruction
aws s3 ls | grep scc-  # Should return nothing
aws cloudtrail describe-trails  # Should show no project trails
```

### Resources That May Require Manual Deletion

| Resource | Why | How |
|----------|-----|-----|
| S3 Audit Logs bucket | `force_destroy = false` in production | `aws s3 rb s3://bucket-name --force` |
| CloudWatch Log Groups | May persist after trail deletion | AWS Console → CloudWatch → Log Groups |
| KMS Keys | 30-day deletion window | AWS Console → KMS → Schedule deletion |
| SNS Subscriptions | May remain pending | AWS Console → SNS → Subscriptions |

---

## Regional Availability

| Service | ap-south-1 | us-east-1 | Notes |
|---------|-----------|-----------|-------|
| VPC, S3, IAM | ✅ | ✅ | All regions |
| KMS | ✅ | ✅ | All regions |
| CloudTrail | ✅ | ✅ | All regions |
| AWS Config | ✅ | ✅ | All regions |
| CloudWatch | ✅ | ✅ | All regions |
| IAM Access Analyzer | ✅ | ✅ | Most regions |
| GuardDuty | ✅ | ✅ | Most regions |
| Security Hub | ✅ | ✅ | Most regions |
| AWS Glue | ✅ | ✅ | Most regions |
| Amazon Bedrock | ❌ | ✅ | Limited regions |

---

## Cost Estimation (ap-south-1, Demo Usage)

| Resource | Monthly Estimate | Notes |
|----------|-----------------|-------|
| NAT Gateway | ~$32/month | **Most expensive item** — delete immediately after demo |
| VPC Endpoints (Interface) × 2 | ~$15/month | SSM endpoints |
| S3 Storage (< 1 GB) | < $0.03 | Negligible |
| CloudTrail (management events) | Free (first trail) | Multi-region trail is free |
| AWS Config (recording) | ~$0.003/resource/month | ~50 resources = $0.15 |
| Config Rules × 8 | ~$0.001/evaluation | Estimate < $1 |
| CloudWatch Log Groups | ~$0.57/GB ingested | < $1 for demo |
| CloudWatch Alarms × 5 | $0.10/alarm/month | $0.50 |
| KMS Keys × 4 | $1.00/key/month | $4.00 |
| SNS (email) | Free tier | Free |
| **TOTAL ESTIMATE** | **~$52–$55/month** | **Delete NAT GW after demo** |

> Without NAT Gateway: ~$20–$23/month.
> All estimates are approximate. Use AWS Cost Explorer to verify.
> Free Tier applies to new accounts — check eligibility.
