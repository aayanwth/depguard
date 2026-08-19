provider "aws" {
  region = "us-east-1"
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "bronze_lakehouse" {
  bucket = "depguard-bronze-lakehouse-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "bronze_lakehouse_pab" {
  bucket = aws_s3_bucket.bronze_lakehouse.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "airflow_execution_role" {
  name = "depguard_airflow_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "airflow_s3_policy" {
  name = "depguard_airflow_s3_policy"
  role = aws_iam_role.airflow_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          aws_s3_bucket.bronze_lakehouse.arn,
          "${aws_s3_bucket.bronze_lakehouse.arn}/*"
        ]
      }
    ]
  })
}
