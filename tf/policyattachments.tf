resource "aws_iam_policy_attachment" "policy001-policy-attachment" {
    name       = "policy001-policy-attachment"
    policy_arn = "arn:aws:iam::947878180334:policy/policy001"
    groups     = []
    users      = []
    roles      = ["role002"]
}

resource "aws_iam_policy_attachment" "AmazonS3FullAccess-policy-attachment" {
    name       = "AmazonS3FullAccess-policy-attachment"
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    groups     = []
    users      = ["Test"]
    roles      = ["role001"]
}



