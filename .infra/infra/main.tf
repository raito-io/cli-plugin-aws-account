module "testing" {
  count = var.testing_dataset ? 1 : 0

  source = "./testing"

  providers = {
    aws.eu-central-1 = aws.eu-central-1
    aws.eu-west-1    = aws.eu-west-1
  }

  d_hayden_name    = module.d_hayden.user.name
  m_carissa_name = module.m_carissa.user.name
  m_carissa_arn    = module.m_carissa.user.arn
  sales_group_name = aws_iam_group.sales_group.name
}

module "demo" {
  count = var.demo_dataset ? 1 : 0

  source = "./demo"

  providers = {
    aws.eu-central-1 = aws.eu-central-1
    aws.eu-west-1    = aws.eu-west-1
  }

  d_hayden_name    = module.d_hayden.user.name
  m_carissa_name = module.m_carissa.user.name
  m_carissa_arn    = module.m_carissa.user.arn
  sales_group_name = aws_iam_group.sales_group.name
}