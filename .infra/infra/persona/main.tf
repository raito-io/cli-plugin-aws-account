resource "aws_iam_user" "user" {
  name = var.username
}

resource "aws_iam_access_key" "key" {
  user = aws_iam_user.user.name
}

resource "aws_secretsmanager_secret" "secret" {
  name = "${var.secret_prefix}${aws_iam_user.user.name}_${random_string.random_secret_postfix.result}"
}

resource "aws_secretsmanager_secret_version" "secret_value" {
  secret_id = aws_secretsmanager_secret.secret.id
  secret_string = jsonencode({
    username           = aws_iam_user.user.name
    AwsAccessKeyId     = aws_iam_access_key.key.id
    AwsSecretAccessKey = aws_iam_access_key.key.secret
  })
}

resource "random_string" "random_secret_postfix" {
  length  = 6
  special = false
  lower   = true
  numeric = false
  upper   = false
}