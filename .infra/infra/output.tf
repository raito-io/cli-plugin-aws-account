output "user" {
  value = [
    {
      "name" = module.m_carissa.user.name
      "arn"  = module.m_carissa.user.arn
      "secret" = {
        "name" = module.m_carissa.secret.name
        "arn"  = module.m_carissa.secret.arn
      }
    },
    {
      "name" = module.d_hayden.user.name
      "arn"  = module.d_hayden.user.arn
      "secret" = {
        "name" = module.d_hayden.secret.name
        "arn"  = module.d_hayden.secret.arn
      }
    }
  ]
}


output "groups" {
  value = [
    {
      "name" = aws_iam_group.sales_group.name
      "arn"  = aws_iam_group.sales_group.arn
    },
    {
      "name" = aws_iam_group.marketing_group.name
      "arn"  = aws_iam_group.marketing_group.arn

    }
  ]
}

output "files" {
  value = concat(var.testing_dataset ? module.testing[0].files : [], var.demo_dataset ? module.demo[0].files : [])
}