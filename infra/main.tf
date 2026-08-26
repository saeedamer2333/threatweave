###############################################################################
# ThreatWeave demo target infrastructure
#
# WARNING - INTENTIONALLY INSECURE. This deploys the OWASP Juice Shop demo
# target used to validate the AIOps engine. Like Juice Shop itself, it contains
# deliberate misconfigurations (open ingress, unencrypted bucket, permissive
# IAM) so that Checkov and the AWS monitor have realistic findings to report.
#
# DO NOT apply this to a production account. It exists to be scanned.
###############################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  description = "AWS region for the demo target"
  type        = string
  default     = "ap-southeast-1"
}

provider "aws" {
  region = var.region
}

###############################################################################
# Networking - deliberately over-permissive (Scenario 3)
###############################################################################
resource "aws_security_group" "juice_shop" {
  name        = "threatweave-juice-shop-sg"
  description = "Demo target security group for Juice Shop"

  # Application port open to the world - this is the exposure step in the
  # attack path the correlator is designed to detect.
  ingress {
    description = "Juice Shop application"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH open to the world - a classic SME misconfiguration.
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "threatweave-juice-shop"
    Purpose = "demo-target"
  }
}

###############################################################################
# Compute - runs the vulnerable container
###############################################################################
resource "aws_instance" "juice_shop" {
  ami           = "ami-0df7a207adb9748c7" # Amazon Linux 2023, ap-southeast-1
  instance_type = "t3.micro"

  vpc_security_group_ids      = [aws_security_group.juice_shop.id]
  associate_public_ip_address = true

  # IMDSv1 left enabled - allows SSRF to steal instance credentials.
  metadata_options {
    http_tokens = "optional"
  }

  root_block_device {
    encrypted = false
  }

  user_data = <<-EOF
    #!/bin/bash
    dnf install -y docker
    systemctl start docker
    docker run -d -p 3000:3000 --restart always bkimminich/juice-shop:latest
  EOF

  tags = {
    Name    = "juice-shop"
    Purpose = "demo-target"
  }
}

###############################################################################
# Storage - user uploads bucket, deliberately unprotected
###############################################################################
resource "aws_s3_bucket" "uploads" {
  bucket = "threatweave-demo-user-uploads"

  tags = {
    Name    = "app-user-uploads"
    Purpose = "demo-target"
  }
}

# No aws_s3_bucket_public_access_block, no server-side encryption, no
# versioning and no access logging are defined for this bucket on purpose.

###############################################################################
# IAM - over-broad deployment role
###############################################################################
resource "aws_iam_role" "app_deploy" {
  name = "threatweave-app-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "app_deploy_wildcard" {
  name = "threatweave-app-deploy-policy"
  role = aws_iam_role.app_deploy.id

  # Wildcard permissions - the IAM finding the AWS monitor reports.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = "*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

output "juice_shop_url" {
  description = "Public URL of the demo target once deployed"
  value       = "http://${aws_instance.juice_shop.public_ip}:3000"
}
