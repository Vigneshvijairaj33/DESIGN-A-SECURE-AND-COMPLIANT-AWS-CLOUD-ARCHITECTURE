##############################################################################
# modules/kms/main.tf
# Purpose : Customer Managed Keys — one per data zone for separation of duties
# Security: Separate keys mean a compromised key affects only one zone
##############################################################################

# Key administrators — manage the key but cannot use it for data operations
data "aws_iam_policy_document" "kms_key_policy_base" {
  # Rule 1: Root account retains emergency access (required; cannot be removed)
  statement {
    sid     = "AllowRootAccountAdmin"
    effect  = "Allow"
    actions = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }

  # Rule 2: CloudWatch can use the key for log encryption
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.amazonaws.com"]
    }
  }
}

##############################################################################
# KMS Key — Raw Data Zone
##############################################################################
resource "aws_kms_key" "raw" {
  description             = "CMK for S3 raw data zone encryption"
  deletion_window_in_days = 30              # 7–30 days; 30 gives time to recover
  enable_key_rotation     = true            # SC-12: Automatic annual rotation
  policy                  = data.aws_iam_policy_document.kms_key_policy_base.json

  tags = {
    Name     = "${var.name_prefix}-cmk-raw"
    DataZone = "raw"
  }
}

resource "aws_kms_alias" "raw" {
  name          = "alias/${var.name_prefix}-raw-${var.suffix}"
  target_key_id = aws_kms_key.raw.key_id
}

##############################################################################
# KMS Key — Processed Data Zone
##############################################################################
resource "aws_kms_key" "processed" {
  description             = "CMK for S3 processed data zone encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_key_policy_base.json

  tags = {
    Name     = "${var.name_prefix}-cmk-processed"
    DataZone = "processed"
  }
}

resource "aws_kms_alias" "processed" {
  name          = "alias/${var.name_prefix}-processed-${var.suffix}"
  target_key_id = aws_kms_key.processed.key_id
}

##############################################################################
# KMS Key — Curated Data Zone
##############################################################################
resource "aws_kms_key" "curated" {
  description             = "CMK for S3 curated data zone encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_key_policy_base.json

  tags = {
    Name     = "${var.name_prefix}-cmk-curated"
    DataZone = "curated"
  }
}

resource "aws_kms_alias" "curated" {
  name          = "alias/${var.name_prefix}-curated-${var.suffix}"
  target_key_id = aws_kms_key.curated.key_id
}

##############################################################################
# KMS Key — Audit Logs (separate key for compliance isolation)
##############################################################################
resource "aws_kms_key" "logs" {
  description             = "CMK for CloudTrail and audit log encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_logs_policy.json

  tags = {
    Name     = "${var.name_prefix}-cmk-logs"
    DataZone = "audit-logs"
  }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.name_prefix}-logs-${var.suffix}"
  target_key_id = aws_kms_key.logs.key_id
}

# CloudTrail requires explicit permission to use the KMS key
data "aws_iam_policy_document" "kms_logs_policy" {
  statement {
    sid     = "AllowRootAccountAdmin"
    effect  = "Allow"
    actions = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowCloudTrailEncrypt"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid    = "AllowCloudTrailDecrypt"
    effect = "Allow"
    actions = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["false"]
    }
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.amazonaws.com"]
    }
  }
}
