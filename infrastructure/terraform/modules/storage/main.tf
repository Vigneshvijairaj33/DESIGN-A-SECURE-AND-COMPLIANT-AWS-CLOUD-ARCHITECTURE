##############################################################################
# modules/storage/main.tf
# Purpose : Secure S3 data lake — raw, processed, curated, and audit-log zones
# Security: Block public access, SSE-KMS, HTTPS enforcement, versioning
##############################################################################

locals {
  raw_bucket_name     = "${var.name_prefix}-raw-${var.suffix}"
  processed_bucket_name = "${var.name_prefix}-processed-${var.suffix}"
  curated_bucket_name = "${var.name_prefix}-curated-${var.suffix}"
  logs_bucket_name    = "${var.name_prefix}-audit-logs-${var.suffix}"
}

##############################################################################
# Helper: reusable policy — deny non-HTTPS requests (SC-03)
##############################################################################
data "aws_iam_policy_document" "deny_http" {
  for_each = {
    raw       = local.raw_bucket_name
    processed = local.processed_bucket_name
    curated   = local.curated_bucket_name
    logs      = local.logs_bucket_name
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${each.value}",
      "arn:aws:s3:::${each.value}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

##############################################################################
# RAW ZONE — Security event ingestion landing area
##############################################################################
resource "aws_s3_bucket" "raw" {
  bucket        = local.raw_bucket_name
  force_destroy = true  # OK for demo; remove for production

  tags = {
    Name        = local.raw_bucket_name
    DataZone    = "raw"
    Sensitivity = "High"
  }
}

resource "aws_s3_bucket_public_access_block" "raw" {
  bucket                  = aws_s3_bucket.raw.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "raw" {
  bucket = aws_s3_bucket.raw.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "raw" {
  bucket = aws_s3_bucket.raw.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_raw_arn
    }
    bucket_key_enabled = true  # Reduces KMS API costs
  }
}

resource "aws_s3_bucket_policy" "raw" {
  bucket = aws_s3_bucket.raw.id
  policy = data.aws_iam_policy_document.deny_http["raw"].json
  depends_on = [aws_s3_bucket_public_access_block.raw]
}

resource "aws_s3_bucket_lifecycle_configuration" "raw" {
  bucket = aws_s3_bucket.raw.id
  rule {
    id     = "raw-retention"
    status = "Enabled"
    filter { prefix = "" }
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    expiration { days = 365 }
  }
}

##############################################################################
# PROCESSED ZONE
##############################################################################
resource "aws_s3_bucket" "processed" {
  bucket        = local.processed_bucket_name
  force_destroy = true

  tags = {
    Name        = local.processed_bucket_name
    DataZone    = "processed"
    Sensitivity = "Medium"
  }
}

resource "aws_s3_bucket_public_access_block" "processed" {
  bucket                  = aws_s3_bucket.processed.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "processed" {
  bucket = aws_s3_bucket.processed.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "processed" {
  bucket = aws_s3_bucket.processed.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_proc_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "processed" {
  bucket     = aws_s3_bucket.processed.id
  policy     = data.aws_iam_policy_document.deny_http["processed"].json
  depends_on = [aws_s3_bucket_public_access_block.processed]
}

##############################################################################
# CURATED ZONE — Athena-queryable Parquet files
##############################################################################
resource "aws_s3_bucket" "curated" {
  bucket        = local.curated_bucket_name
  force_destroy = true

  tags = {
    Name        = local.curated_bucket_name
    DataZone    = "curated"
    Sensitivity = "Medium"
  }
}

resource "aws_s3_bucket_public_access_block" "curated" {
  bucket                  = aws_s3_bucket.curated.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "curated" {
  bucket = aws_s3_bucket.curated.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_curated_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "curated" {
  bucket     = aws_s3_bucket.curated.id
  policy     = data.aws_iam_policy_document.deny_http["curated"].json
  depends_on = [aws_s3_bucket_public_access_block.curated]
}

##############################################################################
# AUDIT LOGS BUCKET — CloudTrail, Config, Flow Logs
# Extra hardening: versioning + restrict delivery service access
##############################################################################
resource "aws_s3_bucket" "logs" {
  bucket        = local.logs_bucket_name
  force_destroy = false  # Keep for compliance — do NOT set to true in production

  tags = {
    Name        = local.logs_bucket_name
    DataZone    = "audit-logs"
    Sensitivity = "Critical"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_logs_arn
    }
    bucket_key_enabled = true
  }
}

# Audit log bucket policy — allow CloudTrail delivery + enforce HTTPS
data "aws_iam_policy_document" "logs_bucket_policy" {
  # Allow CloudTrail to check bucket ACL
  statement {
    sid     = "AWSCloudTrailAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${local.logs_bucket_name}"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  # Allow CloudTrail to write log files
  statement {
    sid     = "AWSCloudTrailWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${local.logs_bucket_name}/AWSLogs/${var.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  # Allow Config to write
  statement {
    sid     = "AWSConfigBucketPermissionsCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${local.logs_bucket_name}"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }

  statement {
    sid     = "AWSConfigBucketExistenceCheck"
    effect  = "Allow"
    actions = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${local.logs_bucket_name}"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }

  statement {
    sid     = "AWSConfigBucketDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${local.logs_bucket_name}/AWSLogs/${var.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }

  # Deny non-HTTPS
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${local.logs_bucket_name}",
      "arn:aws:s3:::${local.logs_bucket_name}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.logs.id
  policy     = data.aws_iam_policy_document.logs_bucket_policy.json
  depends_on = [aws_s3_bucket_public_access_block.logs]
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "log-retention"
    status = "Enabled"
    filter { prefix = "" }
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 365
      storage_class = "GLACIER"
    }
    expiration { days = 2557 }  # 7 years — common compliance requirement
  }
}
