output "files" {
  value = [{
    "user" : var.m_carissa_name,
    "files" : [
      {
        "bucket" : aws_s3_bucket.corporate.bucket,
        "files" : [
          aws_s3_object.passengers.key,
        ]
      }
    ]
    },
    {
      "user" : var.d_hayden_name,
      "files" : [
        {
          "bucket" : aws_s3_bucket.corporate.bucket,
          "files" : [
            aws_s3_object.passengers.key,
            aws_s3_object.housing_prices_2023.key,
          ]
        }
      ]
    }
  ]
  sensitive = false
}