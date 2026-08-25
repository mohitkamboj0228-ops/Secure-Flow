# Production AWS RDS & EKS Hosting Architecture

This document describes how the **SecureFlow Platform** deploys and operates database and compute workloads inside **Amazon Web Services (AWS)**.

---

## 1. Amazon RDS PostgreSQL Security Configuration

To ensure database isolation and durability, the PostgreSQL RDS instance is configured with these security controls:

### Network Isolation
- **Subnet Placement**: RDS is deployed exclusively inside **Private Subnets** across two Availability Zones (Multi-AZ). It has no public IP addresses assigned.
- **Security Groups**: DB ingress is restricted via Security Group rules permitting incoming traffic **ONLY** from the EKS Node Group Security Group on port `5432` (TCP). All other incoming requests are dropped.

### Encryption & Durability
- **Storage Encryption**: DB volumes are encrypted at rest using an **AWS KMS Customer Managed Key (CMK)** with AES-256 encryption.
- **Automated Backups**: Retention is set to **7 days** by default (scalable to 35 days). Point-in-time recovery (PITR) is enabled.
- **Multi-AZ Availability**: Synchronous replication is configured to a standby instance in a different Availability Zone (Multi-AZ). During primary node failure, DNS failover resolves database connections automatically in <60 seconds.

---

## 2. Elastic Kubernetes Service (EKS) Infrastructure

The Kubernetes compute layer is managed via EKS:

### IAM Roles for Service Accounts (IRSA)
- EKS pods utilize **OpenID Connect (OIDC)** provider integrations.
- Pods are assigned specific **AWS IAM Roles** via service account annotations (`eks.amazonaws.com/role-arn`), preventing node-level credential sharing and adhering to the principle of least privilege.

### Endpoint Security
- The EKS Cluster Endpoint is set to **Private Access Only**. 
- Administrative operations require connecting through a secure bastion host or client VPN endpoint positioned in the public subnets.
