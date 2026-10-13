output "sns_alarm_topic_arn" { value = aws_sns_topic.security_alarms.arn }
output "dashboard_name" { value = aws_cloudwatch_dashboard.security.dashboard_name }
