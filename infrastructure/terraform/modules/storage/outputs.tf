output "s3_raw_bucket_id" { value = aws_s3_bucket.raw.id }
output "s3_raw_bucket_arn" { value = aws_s3_bucket.raw.arn }
output "s3_processed_bucket_id" { value = aws_s3_bucket.processed.id }
output "s3_processed_bucket_arn" { value = aws_s3_bucket.processed.arn }
output "s3_curated_bucket_id" { value = aws_s3_bucket.curated.id }
output "s3_curated_bucket_arn" { value = aws_s3_bucket.curated.arn }
output "s3_logs_bucket_id" { value = aws_s3_bucket.logs.id }
output "s3_logs_bucket_arn" { value = aws_s3_bucket.logs.arn }
