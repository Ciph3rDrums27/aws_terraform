# aws_terraform
This repository contains terraform templates that can be used in AWS

# IAM Policy Checks with AWS Config (Terraform)

This Terraform template enables AWS Config and creates a baseline set of managed AWS Config rules focused on IAM hygiene and high-risk policy patterns.

## What it checks
- Policies with admin access statements (`*:*`)
- IAM users with inline policies
- Root access keys (should not exist)
- Root MFA enabled
- Account password policy exists (customizable)
- IAM user MFA enabled

## Deploy

1) Configure AWS credentials (env vars or AWS profile)

2) Initialize and apply:
```bash
terraform init
terraform apply \
  -var 'config_bucket_name=YOUR-GLOBALLY-UNIQUE-BUCKET-NAME' \
  -var 'region=us-east-1'
