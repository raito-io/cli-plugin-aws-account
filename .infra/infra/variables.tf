variable "testing_dataset" {
  type        = bool
  sensitive   = false
  description = "Infrastructure for testing purposes"
  default     = true
}

variable "demo_dataset" {
  type        = bool
  sensitive   = false
  description = "Infrastructure for testing purposes"
  default     = true
}

variable "aws_access_key_id" {
  type        = string
  sensitive   = false
  description = "AWS access key to connect to the AWS account"
  nullable    = false
}

variable "aws_secret_access_key" {
  type        = string
  sensitive   = true
  description = "AWS secret access key to connect to the AWS account"
  nullable    = false
}
