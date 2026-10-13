##############################################################################
# modules/network/main.tf
# Purpose : VPC, subnets, security groups, and VPC endpoints
# Security: No workloads in public subnet; SSM replaces bastion host
##############################################################################

##############################################################################
# VPC
##############################################################################
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

##############################################################################
# Internet Gateway — needed only for NAT Gateway in the public subnet
##############################################################################
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

##############################################################################
# PUBLIC SUBNET — NAT Gateway only; no EC2 workloads
##############################################################################
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone_1
  map_public_ip_on_launch = false  # Never auto-assign public IPs

  tags = {
    Name = "${var.name_prefix}-public-subnet"
    Tier = "Public"
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.name_prefix}-nat-eip"
  }
}

# NAT Gateway — allows private subnets to reach internet for pip installs etc.
# COST: ~$0.045/hour + $0.045/GB. Remove after demos to avoid charges.
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id

  tags = {
    Name        = "${var.name_prefix}-nat-gw"
    CostWarning = "Charges-apply-delete-when-not-in-use"
  }

  depends_on = [aws_internet_gateway.main]
}

##############################################################################
# PRIVATE APPLICATION SUBNET — Lambda, SSM
##############################################################################
resource "aws_subnet" "app" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.app_subnet_cidr
  availability_zone       = var.availability_zone_1
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-app-subnet"
    Tier = "Private-App"
  }
}

##############################################################################
# PRIVATE DATA SUBNET — Glue, Athena
##############################################################################
resource "aws_subnet" "data" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.data_subnet_cidr
  availability_zone       = var.availability_zone_2
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-data-subnet"
    Tier = "Private-Data"
  }
}

##############################################################################
# ROUTE TABLES
##############################################################################

# Public route table — routes to IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Private app route table — routes to NAT Gateway
resource "aws_route_table" "private_app" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "${var.name_prefix}-private-app-rt" }
}

resource "aws_route_table_association" "private_app" {
  subnet_id      = aws_subnet.app.id
  route_table_id = aws_route_table.private_app.id
}

# Private data route table — routes to NAT Gateway
resource "aws_route_table" "private_data" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "${var.name_prefix}-private-data-rt" }
}

resource "aws_route_table_association" "private_data" {
  subnet_id      = aws_subnet.data.id
  route_table_id = aws_route_table.private_data.id
}

##############################################################################
# SECURITY GROUPS
##############################################################################

# Lambda security group — no inbound; HTTPS egress to VPC endpoints only
resource "aws_security_group" "lambda" {
  name        = "${var.name_prefix}-lambda-sg"
  description = "Lambda functions — no inbound, HTTPS egress to VPC endpoints"
  vpc_id      = aws_vpc.main.id

  # No ingress rules — Lambda is invoked via event triggers, not TCP connections

  egress {
    description = "HTTPS to VPC endpoints and AWS services"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "${var.name_prefix}-lambda-sg" }
}

# Glue security group — inter-node communication only
resource "aws_security_group" "glue" {
  name        = "${var.name_prefix}-glue-sg"
  description = "Glue ETL jobs — self-referencing for Spark cluster communication"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Glue Spark cluster node-to-node communication"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  egress {
    description = "HTTPS to S3 and AWS services"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-glue-sg" }
}

##############################################################################
# VPC ENDPOINTS — Keep traffic on the AWS network; no IGW path required
# Benefit: Reduces attack surface; S3 and KMS traffic stays private
##############################################################################

# S3 Gateway Endpoint — free of charge
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = [
    aws_route_table.private_app.id,
    aws_route_table.private_data.id,
  ]

  tags = { Name = "${var.name_prefix}-s3-endpoint" }
}

# SSM Interface Endpoint — enables Session Manager without bastion host
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.app.id]
  security_group_ids  = [aws_security_group.lambda.id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-ssm-endpoint" }
}

resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.app.id]
  security_group_ids  = [aws_security_group.lambda.id]
  private_dns_enabled = true

  tags = { Name = "${var.name_prefix}-ssmmessages-endpoint" }
}
