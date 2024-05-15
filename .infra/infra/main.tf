module "testing" {
  count = var.testing_dataset ? 1 : 0

  source = "./testing"

  providers = {
    aws.eu-central-1 = aws.eu-central-1
    aws.eu-west-1    = aws.eu-west-1
  }
}

module "demo" {
  count = var.demo_dataset ? 1 : 0

  source = "./demo"

  providers = {
    aws = aws
  }
}