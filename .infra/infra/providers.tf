provider "aws" {
  alias      = "eu-central-1"
  region     = "eu-central-1"
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
  token      = ""
}

provider "aws" {
  alias      = "eu-west-1"
  region     = "eu-west-1"
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
  token      = ""
}