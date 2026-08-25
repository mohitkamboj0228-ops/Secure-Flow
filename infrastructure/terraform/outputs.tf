output "vpc_id" {
  value       = aws_vpc.main.id
  description = "The created VPC resource identifier"
}

output "eks_cluster_name" {
  value       = aws_eks_cluster.eks.name
  description = "EKS Cluster identity reference"
}

output "rds_endpoint" {
  value       = aws_db_instance.postgres.endpoint
  description = "Connection URI for RDS Postgres instance"
}

output "alb_dns_name" {
  value       = aws_lb.alb.dns_name
  description = "Public HTTP entry address for Application Load Balancer"
}
