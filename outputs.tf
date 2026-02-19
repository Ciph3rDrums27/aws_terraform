output "config_bucket" {
  value       = aws_s3_bucket.config.bucket
  description = "S3 bucket receiving AWS Config snapshots and compliance history."
}

output "config_recorder_role_arn" {
  value       = aws_iam_role.config.arn
  description = "IAM role used by AWS Config."
}

output "config_rules" {
  value = [
    aws_config_config_rule.iam_policy_no_admin.name,
    aws_config_config_rule.iam_user_no_policies.name,
    aws_config_config_rule.root_no_access_keys.name,
    aws_config_config_rule.root_mfa_enabled.name,
    aws_config_config_rule.iam_password_policy.name,
    aws_config_config_rule.iam_user_mfa_enabled.name
  ]
  description = "AWS Config rule names created by this module."
}