# ---------------------------------------------------------------------------
# Security appliances (Security VPC) - lightweight GENEVE inline IPS
# ---------------------------------------------------------------------------
resource "aws_instance" "appliance" {
  count                  = var.appliance_count
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.security_appliance.id
  vpc_security_group_ids = [aws_security_group.appliance.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  user_data = templatefile("${path.module}/templates/appliance_userdata.sh.tpl", {
    ips_script_b64 = base64gzip(file("${path.module}/templates/ips.py"))
  })
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2
  }

  tags = { Name = "${var.project}-appliance-${count.index + 1}" }

  depends_on = [aws_route.security_appliance_default]
}

# ---------------------------------------------------------------------------
# Application instance (Customer VPC, private subnet)
# ---------------------------------------------------------------------------
resource "aws_instance" "app" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.customer_app.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  user_data = templatefile("${path.module}/templates/app_userdata.sh.tpl", {
    app_script_b64 = base64gzip(file("${path.module}/templates/app.py"))
  })
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = { Name = "${var.project}-app" }

  # The inspection path must exist before the instance boots
  # (its default route goes through the GWLBe -> GWLB -> appliances).
  depends_on = [
    aws_route.customer_app_default,
    aws_route.customer_gwlbe_default,
    aws_route.customer_edge_to_gwlbe,
    aws_lb_target_group_attachment.appliances,
    aws_lb_listener.gwlb,
  ]
}

# Public address so the app is reachable from the Internet *through* the
# IGW -> edge route -> GWLBe path. The subnet itself has no IGW route.
resource "aws_eip" "app" {
  domain     = "vpc"
  instance   = aws_instance.app.id
  tags       = { Name = "${var.project}-app-eip" }
  depends_on = [aws_internet_gateway.customer]
}
