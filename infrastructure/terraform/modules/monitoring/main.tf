##############################################################################
# modules/monitoring/main.tf
# Purpose : CloudWatch metric filters, alarms, SNS notifications, dashboard
# These alarms correspond to CIS AWS Foundations Benchmark section 3
##############################################################################

##############################################################################
# SNS Topic for alarm notifications
##############################################################################
resource "aws_sns_topic" "security_alarms" {
  name = "${var.name_prefix}-security-alarms-${var.suffix}"

  tags = { Name = "${var.name_prefix}-security-alarms" }
}

# Email subscription — requires manual confirmation in the inbox
resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

##############################################################################
# Helper: create a metric filter + alarm pair
# Each filter watches the CloudTrail log group for specific API patterns
##############################################################################

# ── CIS 3.3: Root account usage ──────────────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "${var.name_prefix}-root-usage"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "${var.name_prefix}/SecurityAlarms"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "${var.name_prefix}-root-account-usage"
  alarm_description   = "CRITICAL: Root account was used. Root should not be used for daily operations."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "${var.name_prefix}/SecurityAlarms"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
  ok_actions          = [aws_sns_topic.security_alarms.arn]
}

# ── CIS 3.4: IAM policy changes ─────────────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  name           = "${var.name_prefix}-iam-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=SetDefaultPolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy)}"

  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "${var.name_prefix}/SecurityAlarms"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  alarm_name          = "${var.name_prefix}-iam-policy-changes"
  alarm_description   = "HIGH: IAM policy change detected. Verify this was authorized."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPolicyChanges"
  namespace           = "${var.name_prefix}/SecurityAlarms"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
}

# ── CIS 3.1: Unauthorized API calls ─────────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api" {
  name           = "${var.name_prefix}-unauthorized-api"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied\")}"

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "${var.name_prefix}/SecurityAlarms"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "${var.name_prefix}-unauthorized-api-calls"
  alarm_description   = "MEDIUM: Multiple unauthorized API calls detected. Possible credential misuse."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "${var.name_prefix}/SecurityAlarms"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
}

# ── CIS 3.8: S3 Bucket Policy changes ───────────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "s3_policy_changes" {
  name           = "${var.name_prefix}-s3-policy-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"

  metric_transformation {
    name      = "S3BucketPolicyChanges"
    namespace = "${var.name_prefix}/SecurityAlarms"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_policy_changes" {
  alarm_name          = "${var.name_prefix}-s3-bucket-policy-changes"
  alarm_description   = "HIGH: S3 bucket policy or ACL changed. Verify this was authorized."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "S3BucketPolicyChanges"
  namespace           = "${var.name_prefix}/SecurityAlarms"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
}

# ── CIS 3.5: CloudTrail configuration changes ────────────────────────────────
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  name           = "${var.name_prefix}-cloudtrail-config-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"

  metric_transformation {
    name      = "CloudTrailChanges"
    namespace = "${var.name_prefix}/SecurityAlarms"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_changes" {
  alarm_name          = "${var.name_prefix}-cloudtrail-config-changes"
  alarm_description   = "CRITICAL: CloudTrail configuration changed. Audit logging may be disrupted."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudTrailChanges"
  namespace           = "${var.name_prefix}/SecurityAlarms"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
}

##############################################################################
# CloudWatch Dashboard — Security overview
##############################################################################
resource "aws_cloudwatch_dashboard" "security" {
  dashboard_name = "${var.name_prefix}-security-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "alarm"
        x      = 0; y = 0; width = 24; height = 6
        properties = {
          title  = "Active Security Alarms"
          alarms = [
            aws_cloudwatch_metric_alarm.root_usage.arn,
            aws_cloudwatch_metric_alarm.iam_changes.arn,
            aws_cloudwatch_metric_alarm.unauthorized_api.arn,
            aws_cloudwatch_metric_alarm.s3_policy_changes.arn,
            aws_cloudwatch_metric_alarm.cloudtrail_changes.arn,
          ]
        }
      },
      {
        type   = "metric"
        x      = 0; y = 6; width = 12; height = 6
        properties = {
          title   = "Unauthorized API Calls (5-min)"
          metrics = [[
            "${var.name_prefix}/SecurityAlarms",
            "UnauthorizedAPICalls",
            { stat = "Sum", period = 300 }
          ]]
          view    = "timeSeries"
          stacked = false
        }
      },
      {
        type   = "metric"
        x      = 12; y = 6; width = 12; height = 6
        properties = {
          title   = "IAM Policy Changes (5-min)"
          metrics = [[
            "${var.name_prefix}/SecurityAlarms",
            "IAMPolicyChanges",
            { stat = "Sum", period = 300 }
          ]]
          view    = "timeSeries"
          stacked = false
        }
      }
    ]
  })
}
