##############################################################################
# modules/audit/main.tf
# Purpose : CloudTrail + AWS Config — the detective foundation
# Security: Log-file integrity validation, KMS encryption, Config managed rules
##############################################################################

##############################################################################
# CloudWatch Log Group — CloudTrail delivers events here for real-time analysis
##############################################################################
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.name_prefix}-trail"
  retention_in_days = 90  # Balance cost and investigation window
  kms_key_id        = var.kms_key_logs_arn

  tags = { Name = "${var.name_prefix}-cloudtrail-logs" }
}

# IAM role allowing CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cw" {
  name = "${var.name_prefix}-cloudtrail-cw-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "${var.name_prefix}-cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_cw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

##############################################################################
# CloudTrail — management events, multi-region, log-file integrity
##############################################################################
resource "aws_cloudtrail" "main" {
  name                          = "${var.name_prefix}-trail-${var.suffix}"
  s3_bucket_name                = var.s3_logs_bucket_id
  s3_key_prefix                 = "cloudtrail"
  kms_key_id                    = var.kms_key_logs_arn
  include_global_service_events = true   # IAM, STS, Route 53 events
  is_multi_region_trail         = true   # Capture events from all regions
  enable_log_file_validation    = true   # SC-14: Tamper detection
  enable_logging                = true

  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn

  # Management events — read + write API calls
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name = "${var.name_prefix}-cloudtrail"
  }

  depends_on = [aws_cloudwatch_log_group.cloudtrail]
}

##############################################################################
# AWS Config — Configuration recorder and delivery channel
##############################################################################

# IAM role for Config
resource "aws_iam_role" "config" {
  name = "${var.name_prefix}-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Config recorder — records all supported resource types
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.name_prefix}-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

# Delivery channel — where Config sends snapshots and findings
resource "aws_config_delivery_channel" "main" {
  name           = "${var.name_prefix}-config-channel"
  s3_bucket_name = var.s3_logs_bucket_id
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.main]
}

# Start recording
resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

##############################################################################
# AWS Config Managed Rules — Detective controls (SC-17, SC-18, SC-19)
# NOTE: Each rule costs ~$0.001/evaluation. Monitor usage in Cost Explorer.
##############################################################################

# SC-17: S3 buckets must not be publicly readable
resource "aws_config_config_rule" "s3_public_read_prohibited" {
  name = "${var.name_prefix}-s3-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# SC-17: S3 buckets must not be publicly writable
resource "aws_config_config_rule" "s3_public_write_prohibited" {
  name = "${var.name_prefix}-s3-public-write-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# SC-18: S3 buckets must have server-side encryption enabled
resource "aws_config_config_rule" "s3_encryption" {
  name = "${var.name_prefix}-s3-encryption-enabled"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# SC-19: CloudTrail must be enabled
resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "${var.name_prefix}-cloudtrail-enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# Root MFA should be enabled
resource "aws_config_config_rule" "root_mfa" {
  name = "${var.name_prefix}-root-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# No root access keys
resource "aws_config_config_rule" "no_root_access_key" {
  name = "${var.name_prefix}-no-root-access-key"
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# IAM password policy
resource "aws_config_config_rule" "iam_password_policy" {
  name = "${var.name_prefix}-iam-password-policy"
  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# KMS key rotation
resource "aws_config_config_rule" "kms_rotation" {
  name = "${var.name_prefix}-cmk-backing-key-rotation"
  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}
