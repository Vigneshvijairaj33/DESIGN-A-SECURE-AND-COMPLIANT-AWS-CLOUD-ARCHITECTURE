variable "name_prefix" { type = string }
variable "vpc_cidr" { type = string }
variable "public_subnet_cidr" { type = string }
variable "app_subnet_cidr" { type = string }
variable "data_subnet_cidr" { type = string }
variable "availability_zone_1" { type = string }
variable "availability_zone_2" { type = string }
variable "suffix" { type = string }

variable "aws_region" {
  type    = string
  default = "ap-south-1"
}
