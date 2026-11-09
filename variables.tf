variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Name prefix / tag for all resources"
  type        = string
  default     = "gwlb-demo"
}

variable "availability_zone" {
  description = "Single AZ used for the demo (null = first available AZ)"
  type        = string
  default     = null
}

variable "customer_vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "customer_gwlbe_subnet_cidr" {
  description = "Public subnet of the Customer VPC (hosts the GWLB endpoint)"
  type        = string
  default     = "10.0.0.0/24"
}

variable "customer_app_subnet_cidr" {
  description = "Private subnet of the Customer VPC (hosts the application)"
  type        = string
  default     = "10.0.1.0/24"
}

variable "security_vpc_cidr" {
  type    = string
  default = "10.1.0.0/16"
}

variable "security_gwlb_subnet_cidr" {
  description = "Subnet of the Security VPC hosting the GWLB nodes"
  type        = string
  default     = "10.1.1.0/24"
}

variable "security_appliance_subnet_cidr" {
  description = "Subnet of the Security VPC hosting the appliances"
  type        = string
  default     = "10.1.0.0/24"
}

variable "app_allowed_cidrs" {
  description = "Source CIDRs allowed to reach the application on HTTP/80"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "appliance_count" {
  description = "Number of security appliances behind the GWLB"
  type        = number
  default     = 2
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}
