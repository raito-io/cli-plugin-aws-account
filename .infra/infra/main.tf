module "testing" {
  count = var.testing_dataset ? 1 : 0

  source     = "./testing"

  providers = {
    aws = aws
  }
}

module "demo" {
  count = var.demo_dataset ? 1 : 0

  source     = "./demo"

  providers = {
    aws = aws
  }
}