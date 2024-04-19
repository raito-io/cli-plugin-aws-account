data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

resource "aws_s3_bucket" "corporate" {
  bucket = "raito-corporate-data"

  tags = {
    Source = "terraform"
  }
}