variable "username" {
  type        = string
  sensitive   = false
  description = "Username for the persona"
  nullable    = false
}

variable "secret_prefix" {
  type        = string
  sensitive   = false
  description = "Prefix for the secret"
  default     = "demo/"
}