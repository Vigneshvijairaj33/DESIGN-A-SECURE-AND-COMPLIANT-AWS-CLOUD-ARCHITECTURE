output "data_processor_role_arn" { value = aws_iam_role.data_processor.arn }
output "data_analyst_role_arn" { value = aws_iam_role.data_analyst.arn }
output "security_auditor_role_arn" { value = aws_iam_role.security_auditor.arn }
output "access_analyzer_arn" { value = aws_accessanalyzer_analyzer.main.arn }
