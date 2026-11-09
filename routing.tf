# ===========================================================================
# Customer VPC routing - everything is steered through the GWLBe
#
#   Internet --> IGW --(edge RT: app subnet CIDR -> GWLBe)--> GWLBe --> GWLB --> appliance
#   appliance --> GWLB --> GWLBe --(local route)--> app instance
#   app instance --(app RT: 0.0.0.0/0 -> GWLBe)--> GWLBe --> GWLB --> appliance
#   GWLBe --(gwlbe RT: 0.0.0.0/0 -> IGW)--> Internet
# ===========================================================================

# Public subnet (GWLBe): default route to the Internet Gateway
resource "aws_route_table" "customer_gwlbe" {
  vpc_id = aws_vpc.customer.id
  tags   = { Name = "${var.project}-customer-gwlbe-rt" }
}

resource "aws_route" "customer_gwlbe_default" {
  route_table_id         = aws_route_table.customer_gwlbe.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.customer.id
}

resource "aws_route_table_association" "customer_gwlbe" {
  subnet_id      = aws_subnet.customer_gwlbe.id
  route_table_id = aws_route_table.customer_gwlbe.id
}

# Private subnet (app): all outbound traffic goes to the GWLBe
resource "aws_route_table" "customer_app" {
  vpc_id = aws_vpc.customer.id
  tags   = { Name = "${var.project}-customer-app-rt" }
}

resource "aws_route" "customer_app_default" {
  route_table_id         = aws_route_table.customer_app.id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = aws_vpc_endpoint.gwlbe.id
}

resource "aws_route_table_association" "customer_app" {
  subnet_id      = aws_subnet.customer_app.id
  route_table_id = aws_route_table.customer_app.id
}

# Ingress routing (edge association on the IGW): inbound traffic destined to the
# app subnet is sent to the GWLBe first.
resource "aws_route_table" "customer_edge" {
  vpc_id = aws_vpc.customer.id
  tags   = { Name = "${var.project}-customer-igw-edge-rt" }
}

resource "aws_route" "customer_edge_to_gwlbe" {
  route_table_id         = aws_route_table.customer_edge.id
  destination_cidr_block = var.customer_app_subnet_cidr
  vpc_endpoint_id        = aws_vpc_endpoint.gwlbe.id
}

resource "aws_route_table_association" "customer_edge" {
  gateway_id     = aws_internet_gateway.customer.id
  route_table_id = aws_route_table.customer_edge.id
}

# ===========================================================================
# Security VPC routing
# ===========================================================================
resource "aws_route_table" "security_appliance" {
  vpc_id = aws_vpc.security.id
  tags   = { Name = "${var.project}-security-appliance-rt" }
}

resource "aws_route" "security_appliance_default" {
  route_table_id         = aws_route_table.security_appliance.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.security.id
}

resource "aws_route_table_association" "security_appliance" {
  subnet_id      = aws_subnet.security_appliance.id
  route_table_id = aws_route_table.security_appliance.id
}

# GWLB subnet: local route only
resource "aws_route_table" "security_gwlb" {
  vpc_id = aws_vpc.security.id
  tags   = { Name = "${var.project}-security-gwlb-rt" }
}

resource "aws_route_table_association" "security_gwlb" {
  subnet_id      = aws_subnet.security_gwlb.id
  route_table_id = aws_route_table.security_gwlb.id
}
