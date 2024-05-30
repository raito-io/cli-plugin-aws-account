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