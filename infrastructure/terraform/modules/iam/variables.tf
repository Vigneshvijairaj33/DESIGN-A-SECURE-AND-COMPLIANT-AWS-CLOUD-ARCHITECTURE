variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "region" { type = string }
variable "s3_raw_bucket_arn" { type = string }
variable "s3_proc_bucket_arn" { type = string }
variable "s3_cur_bucket_arn" { type = string }
variable "s3_logs_bucket_arn" { type = string }
variable "kms_key_raw_arn" { type = string }
variable "kms_key_proc_arn" { type = string }
variable "kms_key_curated_arn" { type = string }

variable "kms_key_logs_arn" {
  description = "KMS key ARN for audit logs bucket"
  type        = string
  default     = ""
}
