##############################################################################
# variables.tf — Input variable declarations
# All sensitive values are sourced from terraform.tfvars (never committed)
##############################################################################

variable "aws_region" {
  description = "AWS region for all resources. Choose a region where required services are available."
  type        = string
  default     = "ap-south-1"  # Mumbai — change to your preferred region
}

variable "environment" {
  description = "Deployment environment label (dev / staging / prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Short project name used as a prefix in all resource names"
  type        = string
  default     = "scc"  # secure-compliant-cloud
}

variable "owner" {
  description = "Team or individual responsible for these resources (used in tags)"
  type        = string
  default     = "DevSecOps"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR for the public subnet (NAT Gateway only — no workloads)"
  type        = string
  default     = "10.0.1.0/24"
}

variable "app_subnet_cidr" {
  description = "CIDR for the private application subnet (Lambda, SSM)"
  type        = string
  default     = "10.0.2.0/24"
}

variable "data_subnet_cidr" {
  description = "CIDR for the private data-processing subnet (Glue, Athena)"
  type        = string
  default     = "10.0.3.0/24"
}

variable "availability_zone_1" {
  description = "First availability zone for subnets"
  type        = string
  default     = "ap-south-1a"
}

variable "availability_zone_2" {
  description = "Second availability zone (for future HA)"
  type        = string
  default     = "ap-south-1b"
}

variable "alarm_email" {
  description = "Email address for CloudWatch alarm SNS notifications"
  type        = string
  default     = ""  # Set in terraform.tfvars — do NOT hard-code here
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs (incurs CloudWatch Logs charges ~$0.50/GB)"
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Enable Amazon GuardDuty (incurs per-event charges)"
  type        = bool
  default     = false
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub (incurs per-check charges)"
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "CloudWatch Log Group retention in days"
  type        = number
  default     = 90
}
