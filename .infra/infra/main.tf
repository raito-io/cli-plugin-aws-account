data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

resource "aws_s3_bucket" "corporate" {
  bucket = "raito-corporate-data"

  tags = {
    Source = "terraform"
  }
}

resource "aws_s3_bucket_policy" "allow_access_from_access_point" {
  bucket = aws_s3_bucket.corporate.bucket
  policy = data.aws_iam_policy_document.allow_access_from_access_point.json
}

data "aws_iam_policy_document" "allow_access_from_access_point" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = ["*"]

    resources = [
      aws_s3_bucket.corporate.arn,
      "${aws_s3_bucket.corporate.arn}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:DataAccessPointAccount"
      values   = [local.account_id]
    }
  }
}

// S3 objects
resource "aws_s3_object" "housing_prices_2023" {
  bucket = aws_s3_bucket.corporate.bucket
  key    = "sales/housing/prices/housing-prices-2023.parquet"
  source = "data/housing-prices-2023.parquet"
}

resource "aws_s3_object" "weather" {
  bucket = aws_s3_bucket.corporate.bucket
  key    = "operations/weather/weather.parquet"
  source = "data/weather.parquet"
}

resource "aws_s3_object" "passengers" {
  bucket = aws_s3_bucket.corporate.bucket
  key    = "marketing/passengers/passengers.parquet"
  source = "data/passengers.parquet"
}

// Cloudtrail
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "raito-cloudtrail"
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy_statement" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_bucket.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  depends_on = [aws_s3_bucket.cloudtrail_bucket]
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy_statement.json
}

resource "aws_cloudtrail" "cloudtrail" {
  depends_on = [aws_s3_bucket_policy.cloudtrail_bucket_policy, aws_s3_bucket.cloudtrail_bucket]
  name                          = "raito-corporate-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  event_selector {
    include_management_events = false
    read_write_type = "All"
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.corporate.arn}/*"]
    }
  }
}

data "aws_partition" "current" {}

data "aws_region" "current" {}

// Glue
resource "aws_glue_catalog_database" "raito_glue_database" {
  name = "raito_catalog"
}

resource "aws_iam_role" "raito_glue_role" {
  name = "raito_glue_role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "glue.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

data "aws_iam_policy_document" "raito_glue_policy_document" {
  statement {
    effect = "Allow"

    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.corporate.arn}/*"]
  }
}

resource "aws_iam_policy" "raito_glue_policy" {
  name        = "raito_glue_policy"
  description = "Policy for Raito Glue Role"
  policy      = data.aws_iam_policy_document.raito_glue_policy_document.json
}

resource "aws_iam_role_policy_attachment" "raito_glue_role_attach" {
  for_each = toset([
    "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    "${aws_iam_policy.raito_glue_policy.arn}"
  ])

  role       = "${aws_iam_role.raito_glue_role.name}"
  policy_arn = each.value
}

resource "aws_glue_crawler" "raito_crawler" {
  database_name = aws_glue_catalog_database.raito_glue_database.name
  name          = "raito_crawler"
  role          = aws_iam_role.raito_glue_role.arn

  s3_target {
    path = "s3://${aws_s3_bucket.corporate.bucket}"
  }

  schema_change_policy {
    delete_behavior = "DELETE_FROM_DATABASE"
    update_behavior = "UPDATE_IN_DATABASE"
  }

  schedule = "cron(0 2 * * ? *)"
}

// IAM identities
resource "aws_iam_group" "sales_group" {
  name = "Sales"
}

resource "aws_iam_group" "marketing_group" {
  name = "Marketing"
}

resource "aws_iam_user" "m_carissa_user" {
  name = "m_carissa"
}

resource "aws_iam_user" "d_hayden_user" {
  name = "d_hayden"
}

resource "aws_iam_group_membership" "m_carissa_membership" {
  name = "m_carissa_membership"
  group = aws_iam_group.marketing_group.name
  users = [
    aws_iam_user.m_carissa_user.name,
  ]
}

resource "aws_iam_group_membership" "d_hayden_membership" {
  name = "d_hayden_membership"
  group = aws_iam_group.sales_group.name
  users = [
    aws_iam_user.d_hayden_user.name,
  ]
}

// Marketing role is directly assigned to a single user and has a managed policy attached to it to provide access to marketing folder in S3
resource "aws_iam_role" "marketing_role" {
  name = "MarketingRole"
  assume_role_policy = data.aws_iam_policy_document.marketing_assume_rolepolicy_document.json
}

data "aws_iam_policy_document" "marketing_assume_rolepolicy_document" {
  statement {
    effect = "Allow"

    actions   = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.d_hayden_user.arn]
    }
  }
}

data "aws_iam_policy_document" "marketing_policy_document" {
  statement {
    effect = "Allow"

    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.corporate.arn}/marketing/*"]
  }
}

resource "aws_iam_policy" "marketing_policy" {
  name        = "marketing_policy"
  description = "Policy for marketing stuff"
  policy      = data.aws_iam_policy_document.marketing_policy_document.json
}

resource "aws_iam_role_policy_attachment" "raito_marketing_policy_attach" {
  role       = "${aws_iam_role.marketing_role.name}"
  policy_arn = "${aws_iam_policy.marketing_policy.arn}"
}

// Sales role is directly assigned to a single user and has an inline policy pointing to the sales folder in S3
resource "aws_iam_role" "sales_role" {
  name = "SalesRole"
  inline_policy {
    name = "SalesPolicy"
    policy = data.aws_iam_policy_document.sales_policy_document.json
  }
  assume_role_policy = data.aws_iam_policy_document.sales_assume_rolepolicy_document.json
}

data "aws_iam_policy_document" "sales_assume_rolepolicy_document" {
  statement {
    effect = "Allow"

    actions   = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.d_hayden_user.arn]
    }
  }
}

data "aws_iam_policy_document" "sales_policy_document" {
  statement {
    effect = "Allow"

    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.corporate.arn}/sales/*"]
  }
}

// S3 AccessPoint
resource "aws_s3_access_point" "operations_access_point" {
  bucket = aws_s3_bucket.corporate.id
  name   = "operations"

  public_access_block_configuration {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }

  lifecycle {
    ignore_changes = [policy]
  }
}

// Providing access on the access policy to the operations folder to Mary, the Sales group and the Sales role
data "aws_iam_policy_document" "operations_access_point_policy_document" {
  statement {
    effect = "Allow"

    actions   = ["s3:GetObject"]
    principals {
      type = "AWS"
      identifiers = [aws_iam_user.m_carissa_user.arn, aws_iam_role.sales_role.arn]
    }
    resources = ["${aws_s3_access_point.operations_access_point.arn}/object/operations/*"]
  }
}

resource "aws_s3control_access_point_policy" "operations_access_point_policy" {
  access_point_arn = aws_s3_access_point.operations_access_point.arn

  policy = data.aws_iam_policy_document.operations_access_point_policy_document.json
}