output "user" {
  value = aws_iam_user.user
}

output "secret" {
  value = aws_secretsmanager_secret.secret
}