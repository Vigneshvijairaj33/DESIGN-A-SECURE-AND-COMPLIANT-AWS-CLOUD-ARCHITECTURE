##############################################################################
# main.tf — Root Terraform configuration
# Project : Secure and Compliant Cloud Architecture
# Purpose : Orchestrates all infrastructure modules
# IMPORTANT: This is a demonstration template. Review every resource and
#            cost implication before applying to any AWS account.
##############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  # For production: replace local backend with S3 + DynamoDB backend
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "secure-cloud/terraform.tfstate"
  #   region         = "ap-south-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-lock"
  # }
}

provider "aws" {
  region = var.aws_region

  # Best practice: set default tags so every resource is tagged consistently
  default_tags {
    tags = {
      Project     = "SecureCompliantCloud"
      Environment = var.environment
      Owner       = var.owner
      ManagedBy   = "Terraform"
      CostCenter  = "Demo"
    }
  }
}

# Random suffix to make resource names globally unique
resource "random_id" "suffix" {
  byte_length = 4
}

# Local values — centralized naming and computed values
locals {
  name_prefix = "${var.project_name}-${var.environment}"
  account_id  = data.aws_caller_identity.current.account_id
  region      = var.aws_region
  suffix      = random_id.suffix.hex
}

# Data sources — read current AWS context (no resource creation)
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

##############################################################################
# Module: Network
##############################################################################
module "network" {
  source = "./modules/network"

  name_prefix         = local.name_prefix
  vpc_cidr            = var.vpc_cidr
  public_subnet_cidr  = var.public_subnet_cidr
  app_subnet_cidr     = var.app_subnet_cidr
  data_subnet_cidr    = var.data_subnet_cidr
  availability_zone_1 = var.availability_zone_1
  availability_zone_2 = var.availability_zone_2
  suffix              = local.suffix
}

##############################################################################
# Module: KMS — Encryption Key Management
##############################################################################
module "kms" {
  source = "./modules/kms"

  name_prefix = local.name_prefix
  account_id  = local.account_id
  suffix      = local.suffix
}

##############################################################################
# Module: S3 — Secure Data Lake Buckets
##############################################################################
module "storage" {
  source = "./modules/storage"

  name_prefix         = local.name_prefix
  account_id          = local.account_id
  kms_key_raw_arn     = module.kms.kms_key_raw_arn
  kms_key_proc_arn    = module.kms.kms_key_processed_arn
  kms_key_curated_arn = module.kms.kms_key_curated_arn
  kms_key_logs_arn    = module.kms.kms_key_logs_arn
  suffix              = local.suffix
}

##############################################################################
# Module: IAM — Roles and Policies
##############################################################################
module "iam" {
  source = "./modules/iam"

  name_prefix          = local.name_prefix
  account_id           = local.account_id
  region               = local.region
  s3_raw_bucket_arn    = module.storage.s3_raw_bucket_arn
  s3_proc_bucket_arn   = module.storage.s3_processed_bucket_arn
  s3_cur_bucket_arn    = module.storage.s3_curated_bucket_arn
  s3_logs_bucket_arn   = module.storage.s3_logs_bucket_arn
  kms_key_raw_arn      = module.kms.kms_key_raw_arn
  kms_key_proc_arn     = module.kms.kms_key_processed_arn
  kms_key_curated_arn  = module.kms.kms_key_curated_arn
}

##############################################################################
# Module: Audit — CloudTrail + AWS Config
##############################################################################
module "audit" {
  source = "./modules/audit"

  name_prefix        = local.name_prefix
  account_id         = local.account_id
  region             = local.region
  s3_logs_bucket_id  = module.storage.s3_logs_bucket_id
  s3_logs_bucket_arn = module.storage.s3_logs_bucket_arn
  kms_key_logs_arn   = module.kms.kms_key_logs_arn
  suffix             = local.suffix
}

##############################################################################
# Module: Monitoring — CloudWatch + Alarms
##############################################################################
module "monitoring" {
  source = "./modules/monitoring"

  name_prefix          = local.name_prefix
  cloudtrail_log_group = module.audit.cloudtrail_log_group_name
  alarm_email          = var.alarm_email
  suffix               = local.suffix
}
