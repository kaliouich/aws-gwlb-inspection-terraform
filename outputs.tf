output "app_public_ip" {
  description = "Public IP (EIP) of the protected application"
  value       = aws_eip.app.public_ip
}

output "app_url" {
  value = "http://${aws_eip.app.public_ip}/"
}

output "app_instance_id" {
  value = aws_instance.app.id
}

output "appliance_instance_ids" {
  value = aws_instance.appliance[*].id
}

output "gwlb_arn" {
  value = aws_lb.gwlb.arn
}

output "target_group_arn" {
  value = aws_lb_target_group.appliances.arn
}

output "gwlb_endpoint_id" {
  value = aws_vpc_endpoint.gwlbe.id
}

output "endpoint_service_name" {
  value = aws_vpc_endpoint_service.gwlb.service_name
}

output "customer_vpc_id" {
  value = aws_vpc.customer.id
}

output "security_vpc_id" {
  value = aws_vpc.security.id
}
