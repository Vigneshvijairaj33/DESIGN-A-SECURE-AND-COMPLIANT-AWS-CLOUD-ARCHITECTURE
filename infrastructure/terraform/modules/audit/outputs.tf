output "cloudtrail_name" { value = aws_cloudtrail.main.name }
output "cloudtrail_log_group_name" { value = aws_cloudwatch_log_group.cloudtrail.name }
output "cloudtrail_log_group_arn" { value = aws_cloudwatch_log_group.cloudtrail.arn }
