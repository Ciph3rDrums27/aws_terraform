### Variables ###
variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile configured for Identity Center (SSO)."
  type        = string
}

variable "assume_role_arn" {
  description = "Optional IAM role ARN to assume after SSO authentication."
  type        = string
  default     = null
}

variable "config_bucket_name" {
  description = "Globally-unique S3 bucket name for AWS Config delivery."
  type        = string
}

variable "config_rule_prefix" {
  description = "Prefix to apply to AWS Config rule names."
  type        = string
  default     = "iam"
}

variable "tags" {
  description = "Tags applied to supported resources."
  type        = map(string)
  default     = {}
}