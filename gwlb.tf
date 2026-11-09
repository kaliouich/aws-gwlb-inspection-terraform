# ---------------------------------------------------------------------------
# Gateway Load Balancer (Security Service VPC)
# ---------------------------------------------------------------------------
resource "aws_lb" "gwlb" {
  name                             = "${var.project}-gwlb"
  load_balancer_type               = "gateway"
  subnets                          = [aws_subnet.security_gwlb.id]
  enable_cross_zone_load_balancing = false
  tags                             = { Name = "${var.project}-gwlb" }
}

resource "aws_lb_target_group" "appliances" {
  name        = "${var.project}-appliances"
  port        = 6081
  protocol    = "GENEVE"
  vpc_id      = aws_vpc.security.id
  target_type = "instance"

  # Health checks hit the small HTTP endpoint exposed by the appliance (TCP 8080)
  health_check {
    protocol            = "HTTP"
    port                = "8080"
    path                = "/health"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "gwlb" {
  load_balancer_arn = aws_lb.gwlb.id

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.appliances.id
  }
}

resource "aws_lb_target_group_attachment" "appliances" {
  count            = var.appliance_count
  target_group_arn = aws_lb_target_group.appliances.arn
  target_id        = aws_instance.appliance[count.index].id
}

# ---------------------------------------------------------------------------
# Endpoint service (exposes the GWLB) + GWLB endpoint in the Customer VPC
# ---------------------------------------------------------------------------
resource "aws_vpc_endpoint_service" "gwlb" {
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.gwlb.arn]
  tags                       = { Name = "${var.project}-gwlb-endpoint-service" }
}

resource "aws_vpc_endpoint_service_allowed_principal" "self" {
  vpc_endpoint_service_id = aws_vpc_endpoint_service.gwlb.id
  principal_arn           = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
}

resource "aws_vpc_endpoint" "gwlbe" {
  vpc_id            = aws_vpc.customer.id
  service_name      = aws_vpc_endpoint_service.gwlb.service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.customer_gwlbe.id]
  tags              = { Name = "${var.project}-gwlbe" }

  depends_on = [aws_vpc_endpoint_service_allowed_principal.self]
}
