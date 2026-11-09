# ---------------------------------------------------------------------------
# Customer VPC
# ---------------------------------------------------------------------------
resource "aws_vpc" "customer" {
  cidr_block           = var.customer_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project}-customer-vpc" }
}

resource "aws_internet_gateway" "customer" {
  vpc_id = aws_vpc.customer.id
  tags   = { Name = "${var.project}-customer-igw" }
}

# Public subnet: contains the GWLB endpoint (GWLBe); default route -> IGW
resource "aws_subnet" "customer_gwlbe" {
  vpc_id            = aws_vpc.customer.id
  cidr_block        = var.customer_gwlbe_subnet_cidr
  availability_zone = local.az
  tags              = { Name = "${var.project}-customer-public-gwlbe" }
}

# Private subnet: contains the application (no direct route to the IGW)
resource "aws_subnet" "customer_app" {
  vpc_id            = aws_vpc.customer.id
  cidr_block        = var.customer_app_subnet_cidr
  availability_zone = local.az
  tags              = { Name = "${var.project}-customer-private-app" }
}

# ---------------------------------------------------------------------------
# Security Service VPC
# ---------------------------------------------------------------------------
resource "aws_vpc" "security" {
  cidr_block           = var.security_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project}-security-vpc" }
}

# IGW only used by the appliances for management (SSM) / package egress.
# Customer traffic never goes out through it: it only travels over GENEVE.
resource "aws_internet_gateway" "security" {
  vpc_id = aws_vpc.security.id
  tags   = { Name = "${var.project}-security-igw" }
}

resource "aws_subnet" "security_gwlb" {
  vpc_id            = aws_vpc.security.id
  cidr_block        = var.security_gwlb_subnet_cidr
  availability_zone = local.az
  tags              = { Name = "${var.project}-security-gwlb" }
}

resource "aws_subnet" "security_appliance" {
  vpc_id                  = aws_vpc.security.id
  cidr_block              = var.security_appliance_subnet_cidr
  availability_zone       = local.az
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.project}-security-appliance" }
}
