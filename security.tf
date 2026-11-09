# ---------------------------------------------------------------------------
# Security Groups
# ---------------------------------------------------------------------------

# Application instance (Customer VPC): HTTP from allowed CIDRs only
resource "aws_security_group" "app" {
  name        = "${var.project}-app-sg"
  description = "Application instance - HTTP in, all out"
  vpc_id      = aws_vpc.customer.id
  tags        = { Name = "${var.project}-app-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "app_http" {
  for_each          = toset(var.app_allowed_cidrs)
  security_group_id = aws_security_group.app.id
  description       = "HTTP from clients (after GWLB inspection)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "app_icmp" {
  security_group_id = aws_security_group.app.id
  description       = "ICMP for troubleshooting"
  ip_protocol       = "icmp"
  from_port         = -1
  to_port           = -1
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "app_all" {
  security_group_id = aws_security_group.app.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# Security appliances (Security VPC): GENEVE (UDP 6081) + health check (TCP 8080)
resource "aws_security_group" "appliance" {
  name        = "${var.project}-appliance-sg"
  description = "Security appliances - GENEVE from GWLB, health checks"
  vpc_id      = aws_vpc.security.id
  tags        = { Name = "${var.project}-appliance-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "appliance_geneve" {
  security_group_id = aws_security_group.appliance.id
  description       = "GENEVE encapsulated traffic from the GWLB"
  ip_protocol       = "udp"
  from_port         = 6081
  to_port           = 6081
  cidr_ipv4         = var.security_vpc_cidr
}

resource "aws_vpc_security_group_ingress_rule" "appliance_health" {
  security_group_id = aws_security_group.appliance.id
  description       = "GWLB health checks"
  ip_protocol       = "tcp"
  from_port         = 8080
  to_port           = 8080
  cidr_ipv4         = var.security_vpc_cidr
}

resource "aws_vpc_security_group_egress_rule" "appliance_all" {
  security_group_id = aws_security_group.appliance.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# ---------------------------------------------------------------------------
# Network ACLs (stateless -> both directions are explicit)
# ---------------------------------------------------------------------------
locals {
  customer_nacl_ingress = [
    { rule = 100, protocol = "tcp", from = 80, to = 80, cidr = "0.0.0.0/0" },
    { rule = 110, protocol = "tcp", from = 443, to = 443, cidr = "0.0.0.0/0" },
    { rule = 120, protocol = "tcp", from = 1024, to = 65535, cidr = "0.0.0.0/0" }, # return traffic
    { rule = 130, protocol = "udp", from = 1024, to = 65535, cidr = "0.0.0.0/0" }, # DNS/NTP replies
    { rule = 140, protocol = "icmp", from = 0, to = 0, cidr = "0.0.0.0/0" },
  ]

  security_nacl_ingress = [
    { rule = 100, protocol = "udp", from = 6081, to = 6081, cidr = var.security_vpc_cidr },  # GENEVE
    { rule = 110, protocol = "udp", from = 1024, to = 65535, cidr = var.security_vpc_cidr }, # GENEVE return (any src port)
    { rule = 120, protocol = "tcp", from = 8080, to = 8080, cidr = var.security_vpc_cidr },  # health checks
    { rule = 130, protocol = "tcp", from = 1024, to = 65535, cidr = "0.0.0.0/0" },           # return traffic (SSM, dnf)
    { rule = 140, protocol = "udp", from = 1024, to = 65535, cidr = "0.0.0.0/0" },           # DNS replies
    { rule = 150, protocol = "icmp", from = 0, to = 0, cidr = var.security_vpc_cidr },
  ]
}

resource "aws_network_acl" "customer" {
  vpc_id     = aws_vpc.customer.id
  subnet_ids = [aws_subnet.customer_gwlbe.id, aws_subnet.customer_app.id]
  tags       = { Name = "${var.project}-customer-nacl" }

  dynamic "ingress" {
    for_each = local.customer_nacl_ingress
    content {
      rule_no    = ingress.value.rule
      action     = "allow"
      protocol   = ingress.value.protocol
      cidr_block = ingress.value.cidr
      from_port  = ingress.value.from
      to_port    = ingress.value.to
      icmp_type  = ingress.value.protocol == "icmp" ? -1 : null
      icmp_code  = ingress.value.protocol == "icmp" ? -1 : null
    }
  }

  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

resource "aws_network_acl" "security" {
  vpc_id     = aws_vpc.security.id
  subnet_ids = [aws_subnet.security_gwlb.id, aws_subnet.security_appliance.id]
  tags       = { Name = "${var.project}-security-nacl" }

  dynamic "ingress" {
    for_each = local.security_nacl_ingress
    content {
      rule_no    = ingress.value.rule
      action     = "allow"
      protocol   = ingress.value.protocol
      cidr_block = ingress.value.cidr
      from_port  = ingress.value.from
      to_port    = ingress.value.to
      icmp_type  = ingress.value.protocol == "icmp" ? -1 : null
      icmp_code  = ingress.value.protocol == "icmp" ? -1 : null
    }
  }

  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}
