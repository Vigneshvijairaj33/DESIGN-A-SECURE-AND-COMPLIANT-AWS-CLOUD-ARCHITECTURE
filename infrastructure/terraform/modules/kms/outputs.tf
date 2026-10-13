output "kms_key_raw_arn" { value = aws_kms_key.raw.arn }
output "kms_key_raw_id" { value = aws_kms_key.raw.key_id }
output "kms_key_processed_arn" { value = aws_kms_key.processed.arn }
output "kms_key_curated_arn" { value = aws_kms_key.curated.arn }
output "kms_key_logs_arn" { value = aws_kms_key.logs.arn }
output "kms_key_logs_id" { value = aws_kms_key.logs.key_id }
