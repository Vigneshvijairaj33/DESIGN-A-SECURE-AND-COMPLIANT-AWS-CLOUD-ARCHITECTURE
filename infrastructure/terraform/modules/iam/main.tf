##############################################################################
# modules/iam/main.tf
# Purpose : IAM roles for four separation-of-duty personas
#   1. data_processor  — Lambda / Glue write raw + read raw, write processed
#   2. data_analyst    — Read processed + curated, run Athena
#   3. security_auditor— Read-only audit logs + Config + CloudTrail
#   4. lambda_execution— Minimal runtime role for event-driven Lambda
# Security: No wildcard actions; resource-scoped permissions; no long-lived keys
##############################################################################

##############################################################################
# 1. Data Processor Role — Lambda / Glue event ingestion
##############################################################################
data "aws_iam_policy_document" "data_processor_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com", "glue.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "data_processor" {
  name               = "${var.name_prefix}-data-processor-role"
  assume_role_policy = data.aws_iam_policy_document.data_processor_trust.json
  description        = "Allows Lambda and Glue to read raw zone and write to processed zone"

  tags = { Name = "${var.name_prefix}-data-processor-role" }
}

data "aws_iam_policy_document" "data_processor_policy" {
  # Write to raw zone
  statement {
    sid     = "WriteRawZone"
    effect  = "Allow"
    actions = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = [
      var.s3_raw_bucket_arn,
      "${var.s3_raw_bucket_arn}/*",
    ]
  }

  # Write to processed zone
  statement {
    sid     = "WriteProcessedZone"
    effect  = "Allow"
    actions = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = [
      var.s3_proc_bucket_arn,
      "${var.s3_proc_bucket_arn}/*",
    ]
  }

  # Use KMS keys for raw and processed zones
  statement {
    sid    = "UseRawAndProcessedKMSKeys"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [var.kms_key_raw_arn, var.kms_key_proc_arn]
  }

  # CloudWatch Logs — Lambda execution logs
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/*"]
  }
}

resource "aws_iam_policy" "data_processor" {
  name   = "${var.name_prefix}-data-processor-policy"
  policy = data.aws_iam_policy_document.data_processor_policy.json
}

resource "aws_iam_role_policy_attachment" "data_processor" {
  role       = aws_iam_role.data_processor.name
  policy_arn = aws_iam_policy.data_processor.arn
}

##############################################################################
# 2. Data Analyst Role — read-only analytics access
##############################################################################
data "aws_iam_policy_document" "data_analyst_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
    # Require MFA for sensitive analytics role assumption
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "data_analyst" {
  name               = "${var.name_prefix}-data-analyst-role"
  assume_role_policy = data.aws_iam_policy_document.data_analyst_trust.json
  description        = "Read-only access to processed and curated zones; Athena query execution"

  tags = { Name = "${var.name_prefix}-data-analyst-role" }
}

data "aws_iam_policy_document" "data_analyst_policy" {
  statement {
    sid     = "ReadProcessedAndCurated"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      var.s3_proc_bucket_arn,
      "${var.s3_proc_bucket_arn}/*",
      var.s3_cur_bucket_arn,
      "${var.s3_cur_bucket_arn}/*",
    ]
  }

  statement {
    sid    = "UseKMSReadOnly"
    effect = "Allow"
    actions = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
    resources = [var.kms_key_proc_arn, var.kms_key_curated_arn]
  }

  # Athena query execution
  statement {
    sid    = "AthenaQueryExecution"
    effect = "Allow"
    actions = [
      "athena:StartQueryExecution",
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
      "athena:StopQueryExecution",
      "athena:ListQueryExecutions",
    ]
    resources = ["arn:aws:athena:${var.region}:${var.account_id}:workgroup/primary"]
  }

  # Glue catalog read for Athena
  statement {
    sid    = "GlueCatalogRead"
    effect = "Allow"
    actions = [
      "glue:GetDatabase",
      "glue:GetTable",
      "glue:GetTables",
      "glue:GetPartition",
      "glue:GetPartitions",
    ]
    resources = ["*"]
  }

  # Athena query results bucket
  statement {
    sid    = "AthenaResultsBucket"
    effect = "Allow"
    actions = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = [
      var.s3_cur_bucket_arn,
      "${var.s3_cur_bucket_arn}/athena-results/*",
    ]
  }
}

resource "aws_iam_policy" "data_analyst" {
  name   = "${var.name_prefix}-data-analyst-policy"
  policy = data.aws_iam_policy_document.data_analyst_policy.json
}

resource "aws_iam_role_policy_attachment" "data_analyst" {
  role       = aws_iam_role.data_analyst.name
  policy_arn = aws_iam_policy.data_analyst.arn
}

##############################################################################
# 3. Security Auditor Role — read-only for audit evidence collection
##############################################################################
data "aws_iam_policy_document" "security_auditor_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "security_auditor" {
  name               = "${var.name_prefix}-security-auditor-role"
  assume_role_policy = data.aws_iam_policy_document.security_auditor_trust.json
  description        = "Read-only access to audit logs, Config, CloudTrail, and CloudWatch"

  tags = { Name = "${var.name_prefix}-security-auditor-role" }
}

data "aws_iam_policy_document" "security_auditor_policy" {
  # Read audit logs
  statement {
    sid     = "ReadAuditLogs"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      var.s3_logs_bucket_arn,
      "${var.s3_logs_bucket_arn}/*",
    ]
  }

  statement {
    sid    = "UseLogsKMSKey"
    effect = "Allow"
    actions = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_logs_arn]  # Note: variable reference
  }

  # CloudTrail read
  statement {
    sid    = "CloudTrailRead"
    effect = "Allow"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:LookupEvents",
      "cloudtrail:GetTrail",
    ]
    resources = ["*"]
  }

  # AWS Config read
  statement {
    sid    = "ConfigRead"
    effect = "Allow"
    actions = [
      "config:DescribeConfigRules",
      "config:GetComplianceDetailsByConfigRule",
      "config:DescribeConfigurationRecorders",
      "config:GetResourceConfigHistory",
      "config:DescribeComplianceByResource",
    ]
    resources = ["*"]
  }

  # CloudWatch read
  statement {
    sid    = "CloudWatchRead"
    effect = "Allow"
    actions = [
      "cloudwatch:DescribeAlarms",
      "cloudwatch:GetMetricData",
      "logs:DescribeLogGroups",
      "logs:FilterLogEvents",
      "logs:GetLogEvents",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "security_auditor" {
  name   = "${var.name_prefix}-security-auditor-policy"
  policy = data.aws_iam_policy_document.security_auditor_policy.json
}

resource "aws_iam_role_policy_attachment" "security_auditor" {
  role       = aws_iam_role.security_auditor.name
  policy_arn = aws_iam_policy.security_auditor.arn
}

##############################################################################
# IAM Access Analyzer — detects externally accessible resources
##############################################################################
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.name_prefix}-access-analyzer"
  type          = "ACCOUNT"

  tags = { Name = "${var.name_prefix}-access-analyzer" }
}
