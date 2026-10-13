##############################################################################
# outputs.tf — Values surfaced after terraform apply
# These outputs are safe to display — they do NOT contain secrets or keys
##############################################################################

output "vpc_id" {
  description = "ID of the created VPC"
  value       = module.network.vpc_id
}

output "public_subnet_id" {
  description = "ID of the public subnet"
  value       = module.network.public_subnet_id
}

output "app_subnet_id" {
  description = "ID of the private application subnet"
  value       = module.network.app_subnet_id
}

output "data_subnet_id" {
  description = "ID of the private data-processing subnet"
  value       = module.network.data_subnet_id
}

output "s3_raw_bucket_name" {
  description = "Name of the S3 raw data bucket"
  value       = module.storage.s3_raw_bucket_id
}

output "s3_processed_bucket_name" {
  description = "Name of the S3 processed data bucket"
  value       = module.storage.s3_processed_bucket_id
}

output "s3_curated_bucket_name" {
  description = "Name of the S3 curated data bucket"
  value       = module.storage.s3_curated_bucket_id
}

output "s3_logs_bucket_name" {
  description = "Name of the S3 audit-logs bucket"
  value       = module.storage.s3_logs_bucket_id
}

output "kms_key_raw_id" {
  description = "KMS key ID for raw data encryption"
  value       = module.kms.kms_key_raw_id
}

output "kms_key_logs_id" {
  description = "KMS key ID for audit log encryption"
  value       = module.kms.kms_key_logs_id
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  value       = module.audit.cloudtrail_name
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group receiving CloudTrail events"
  value       = module.audit.cloudtrail_log_group_name
}

output "sns_alarm_topic_arn" {
  description = "SNS topic ARN for security alarms"
  value       = module.monitoring.sns_alarm_topic_arn
}

output "account_id" {
  description = "AWS Account ID (from data source)"
  value       = local.account_id
}

output "region" {
  description = "AWS region where resources are deployed"
  value       = local.region
}
