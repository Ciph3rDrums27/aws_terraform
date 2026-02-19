provider "aws" {
  region  = var.region
  profile = var.aws_profile

  dynamic "assume_role" {
    for_each = var.assume_role_arn != null ? [1] : []
    content {
      role_arn = var.assume_role_arn
    }
  }
}

data "aws_caller_identity" "current" {}

############################
# S3 bucket for AWS Config
############################

resource "aws_s3_bucket" "config" {
  bucket = var.config_bucket_name
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access (best practice)
resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

############################
# IAM role for AWS Config
############################

data "aws_iam_policy_document" "config_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "config" {
  name               = "aws-config-recorder-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume_role.json
  tags               = var.tags
}

# AWS managed policy for Config recorder role
resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn  = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Allow AWS Config to put objects in our bucket
data "aws_iam_policy_document" "config_bucket_policy" {
  statement {
    sid     = "AWSConfigBucketPermissionsCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.config.arn]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }

  statement {
    sid     = "AWSConfigBucketDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.config.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket_policy.json
}

############################
# AWS Config setup
############################

resource "aws_config_delivery_channel" "this" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.config.bucket

  depends_on = [
    aws_s3_bucket_policy.config
  ]
}

resource "aws_config_configuration_recorder" "this" {
  name     = "default"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [
    aws_config_delivery_channel.this
  ]
}

############################
# Basic IAM policy checks (managed rules)
############################

# 1) Flag policies that grant admin access (e.g., "*:*")
resource "aws_config_config_rule" "iam_policy_no_admin" {
  name = "${var.config_rule_prefix}-policy-no-admin-access"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

# 2) Ensure IAM users do not have inline policies directly attached
resource "aws_config_config_rule" "iam_user_no_policies" {
  name = "${var.config_rule_prefix}-user-no-inline-policies"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

# 3) Ensure root account has no access keys
resource "aws_config_config_rule" "root_no_access_keys" {
  name = "${var.config_rule_prefix}-root-no-access-keys"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

# 4) Ensure MFA is enabled for the root account
resource "aws_config_config_rule" "root_mfa_enabled" {
  name = "${var.config_rule_prefix}-root-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

# 5) Ensure an account password policy exists
resource "aws_config_config_rule" "iam_password_policy" {
  name = "${var.config_rule_prefix}-password-policy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  # Optional: tune to your org baseline
  input_parameters = jsonencode({
    "MinimumPasswordLength"        = "17"
    "RequireUppercaseCharacters"   = "true"
    "RequireLowercaseCharacters"   = "true"
    "RequireNumbers"               = "true"
    "RequireSymbols"               = "true"
    "MaxPasswordAge"               = "90"
    "PasswordReusePrevention"      = "24"
    "HardExpiry"                   = "false"
  })

  depends_on = [aws_config_configuration_recorder_status.this]
}

# 6) Ensure MFA is enabled for all IAM users with console password
resource "aws_config_config_rule" "iam_user_mfa_enabled" {
  name = "${var.config_rule_prefix}-user-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}