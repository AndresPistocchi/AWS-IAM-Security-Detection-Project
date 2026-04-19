import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
import json
import sys
import os
import requests

# --- Config (use env variables, NOT hardcoded secrets) ---
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")  # e.g. http://localhost:8088/services/collector
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")

# --- AWS Clients ---
iam = boto3.client("iam")
cloudtrail = boto3.client("cloudtrail")
s3 = boto3.client("s3")

findings = []

# --- Logging Helpers ---
def send_to_splunk(event):
    if not SPLUNK_HEC_URL or not SPLUNK_TOKEN:
        return  # Skip if not configured

    try:
        headers = {"Authorization": f"Splunk {SPLUNK_TOKEN}"}
        data = {"event": event}
        requests.post(SPLUNK_HEC_URL, json=data, headers=headers, timeout=3)
    except Exception:
        pass  # Fail silently for pipeline stability

def log_event(severity, message, resource=None):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "message": message,
        "resource": resource,
        "source": "aws_security_check"
    }

    if severity in ["HIGH", "MEDIUM"]:
        findings.append(event)

    print(json.dumps(event))
    send_to_splunk(event)

def log_pass(message, resource=None):
    log_event("INFO", message, resource)

# --- Security Checks ---

def check_mfa_on_users():
    users = iam.list_users()["Users"]

    if not users:
        log_pass("No IAM users found.")
        return

    for user in users:
        username = user["UserName"]
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

        if not mfa_devices:
            log_event("HIGH", "MFA not enabled for user", username)
        else:
            log_pass("MFA enabled", username)

def check_cloudtrail():
    try:
        trails = cloudtrail.describe_trails()["trailList"]

        if not trails:
            log_event("HIGH", "No CloudTrail trails configured")
        else:
            for trail in trails:
                log_pass("CloudTrail exists", trail["Name"])

    except ClientError as e:
        log_event("MEDIUM", f"CloudTrail check failed: {str(e)}")

def check_root_access_keys():
    try:
        summary = iam.get_account_summary()["SummaryMap"]

        if summary.get("AccountAccessKeysPresent", 0) > 0:
            log_event("HIGH", "Root account has active access keys")
        else:
            log_pass("No root access keys found")

    except ClientError as e:
        log_event("MEDIUM", f"Root key check failed: {str(e)}")

def check_password_policy():
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []

        if policy.get("MinimumPasswordLength", 0) < 12:
            issues.append("min_length < 12")
        if not policy.get("RequireSymbols", False):
            issues.append("no_symbols")
        if not policy.get("RequireNumbers", False):
            issues.append("no_numbers")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("no_uppercase")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("no_lowercase")

        if issues:
            log_event("MEDIUM", f"Weak password policy: {', '.join(issues)}")
        else:
            log_pass("Strong password policy")

    except iam.exceptions.NoSuchEntityException:
        log_event("HIGH", "No password policy configured")

    except ClientError as e:
        log_event("MEDIUM", f"Password policy check failed: {str(e)}")

def check_access_key_age(max_age_days=90):
    users = iam.list_users()["Users"]
    found_keys = False

    for user in users:
        username = user["UserName"]
        access_keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

        for key in access_keys:
            found_keys = True
            key_id = key["AccessKeyId"]
            age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days

            if age_days > max_age_days:
                log_event("MEDIUM", f"Old access key ({age_days} days)", username)
            else:
                log_pass(f"Access key age OK ({age_days} days)", username)

    if not found_keys:
        log_pass("No IAM access keys found")

def check_s3_public_access():
    try:
        buckets = s3.list_buckets()["Buckets"]

        if not buckets:
            log_pass("No S3 buckets found")
            return

        for bucket in buckets:
            name = bucket["Name"]

            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]

                if all(pab.values()):
                    log_pass("Public access blocked", name)
                else:
                    log_event("HIGH", "Public access not fully blocked", name)

            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                log_event("HIGH", "No public access block config", name)

            except ClientError as e:
                log_event("LOW", f"S3 check error: {str(e)}", name)

    except ClientError as e:
        log_event("MEDIUM", f"S3 listing failed: {str(e)}")


def print_summary():
    summary = {
        "total_findings": len(findings),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM")
    }

    print(json.dumps({"summary": summary}))

    # Fail pipeline if HIGH findings exist
    if summary["high"] > 0:
        return 1
    return 0

# --- Run ---
if __name__ == "__main__":
    print(json.dumps({"message": "Starting AWS Security Checks"}))

    check_mfa_on_users()
    check_cloudtrail()
    check_root_access_keys()
    check_password_policy()
    check_access_key_age()
    check_s3_public_access()

    exit_code = print_summary()
    sys.exit(exit_code)
