variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "The target AWS deployment Region"
}

variable "db_password" {
  type        = string
  sensitive   = true
  default     = "VaultSuperSecurePass123!"
  description = "Password credentials for PostgreSQL master user"
}
