# AWS Security Baseline Lab

A beginner-friendly AWS security hardening project that sets up foundational 
security controls and automates misconfiguration checks using Python (boto3).

This project is part of my AppSec/Security Engineering learning path.

---

## Purpose

This lab demonstrates how to secure an AWS account from scratch and use Python 
to automate basic security checks — a core skill for Security Engineers and 
AppSec roles.

---

## Prerequisites

### AWS Setup
- AWS account (free tier)
- Root account secured with MFA
- IAM admin user created
- IAM user secured with MFA
- CloudTrail enabled with an S3 bucket for log storage and CloudWatch Logs enabled

### Local Machine Setup
- Python 3.x installed
- boto3 installed:
```cmd
pip install boto3
```
- AWS CLI installed and configured:
```cmd
aws configure
```
> You will need an IAM Access Key and Secret Access Key from your IAM user.
> **Never commit these to GitHub.**

- Verify your connection:
```cmd
aws sts get-caller-identity
```
You should see your Account ID and IAM user ARN returned.

---

## Security Controls Implemented

| Control | Status |
|--------|--------|
| Root account MFA | ✅ |
| IAM admin user created | ✅ |
| IAM user MFA | ✅ |
| CloudTrail enabled | ✅ |
| No root access keys | ✅ |

---

##  Security Check Script

`security_check.py` — A Python script that automatically checks your AWS 
account for common misconfigurations:

- IAM users missing MFA
- CloudTrail status
- Root account access keys

### Run it:
```cmd
python security_check.py
```

### Example output:
````
🔍 Running AWS Security Checks...

--- Checking MFA on IAM Users ---
 admin-user has MFA enabled

--- Checking CloudTrail Status ---
✅ Trail found: my-security-trail

--- Checking Root Account Access Keys ---
✅ No root access keys found - good!

✅ Security check complete!
````

---

## What I Learned

- AWS IAM fundamentals and least privilege principles
- Why root account should never be used day-to-day
- How CloudTrail provides audit logging across an AWS account
- How to use boto3 to programmatically audit AWS security configurations

---

## Next Steps

- Enable GuardDuty for threat detection
- Expand the security check script with more misconfiguration checks
- Build a CI/CD pipeline with SAST scanning
- Forward CloudTrail logs to Splunk for monitoring

---
