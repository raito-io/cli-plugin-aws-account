resource "aws_iam_group" "sales_group" {
  provider = aws.eu-central-1
  name     = "Sales"
}

resource "aws_iam_group" "marketing_group" {
  provider = aws.eu-central-1
  name     = "Marketing"
}

module "m_carissa" {
  source   = "./persona"
  username = "m_carissa"
  providers = {
    aws.region = aws.eu-central-1
  }
}

module "d_hayden" {
  source   = "./persona"
  username = "d_hayden"
  providers = {
    aws.region = aws.eu-central-1
  }
}

// Marissa is part of the Marketing group
resource "aws_iam_group_membership" "m_carissa_membership" {
  provider = aws.eu-central-1
  name     = "m_carissa_membership"
  group    = aws_iam_group.marketing_group.name
  users = [
    module.m_carissa.user.name,
  ]
}

// Dustin is part of the Sales group
resource "aws_iam_group_membership" "d_hayden_membership" {
  provider = aws.eu-central-1
  name     = "d_hayden_membership"
  group    = aws_iam_group.sales_group.name
  users = [
    module.d_hayden.user.name,
  ]
}