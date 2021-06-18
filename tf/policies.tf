resource "aws_iam_policy" "policy001" {
    name        = "policy001"
    path        = "/"
    description = "Custom policy s3 full access"
    policy      = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VisualEditor0",
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    }
  ]
}
POLICY
}

