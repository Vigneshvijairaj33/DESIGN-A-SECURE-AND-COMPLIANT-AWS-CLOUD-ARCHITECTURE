output "vpc_id" { value = aws_vpc.main.id }
output "public_subnet_id" { value = aws_subnet.public.id }
output "app_subnet_id" { value = aws_subnet.app.id }
output "data_subnet_id" { value = aws_subnet.data.id }
output "lambda_sg_id" { value = aws_security_group.lambda.id }
output "glue_sg_id" { value = aws_security_group.glue.id }
