terraform {
  required_providers {
    eu-central-1 = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    eu-west-1 = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}