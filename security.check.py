import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
import sys

# Create clients
iam = boto3.client("iam")
cloudtrail = boto3.client("cloudtrail")
s3 = boto3.client("s3")

findings = []

def add_finding(severity, message):
    findings.append({"severity": severity, "message": message})
    print(f"[{severity}] {message}")

def add_pass(message):
    print(f"[PASS] {message}")

def check_mfa_on_users():
    print("\n--- Checking MFA on IAM Users ---")
    users = iam.list_users()["Users"]

    if not users:
        add_pass("No IAM users found.")
        return

    for user in users:
        username = user["UserName"]
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
        if not mfa_devices:
            add_finding("HIGH", f"{username} does NOT have MFA enabled")
        else:
            add_pass(f"{username} has MFA enabled")

def check_cloudtrail():
    print("\n--- Checking CloudTrail Status ---")
    try:
        trails = cloudtrail.describe_trails()["trailList"]
        if not trails:
            add_finding("HIGH", "No CloudTrail trails found")
        else:
            for trail in trails:
                add_pass(f"Trail found: {trail['Name']}")
    except ClientError as e:
        add_finding("MEDIUM", f"Error checking CloudTrail: {e}")

def check_root_access_keys():
    print("\n--- Checking Root Account Access Keys ---")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            add_finding("HIGH", "Root account has active access keys - dangerous configuration")
        else:
            add_pass("No root access keys found")
    except ClientError as e:
        add_finding("MEDIUM", f"Error checking root access keys: {e}")

def check_password():
    print("\n--- Checking Password Policy ---")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []

        if policy.get("MinimumPasswordLength", 0) < 12:
            issues.append("minimum length is less than 12")
        if not policy.get("RequireSymbols", False):
            issues.append("symbols are not required")
        if not policy.get("RequireNumbers", False):
            issues.append("numbers are not required")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("uppercase letters are not required")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("lowercase letters are not required")

        if issues:
            add_finding("MEDIUM", "Password policy is weak")
            for issue in issues:
                print(f"   - {issue}")
        else:
            add_pass("Password policy is secure")

    except iam.exceptions.NoSuchEntityException:
        add_finding("HIGH", "No account password policy is configured")
    except ClientError as e:
        add_finding("MEDIUM", f"Error checking password policy: {e}")

def check_access_key_age(max_age_days=90):
    print("\n--- Checking Access Key Age ---")
    users = iam.list_users()["Users"]
    found_keys = False

    for user in users:
        username = user["UserName"]
        access_keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

        for key in access_keys:
            found_keys = True
            key_id = key["AccessKeyId"]
            create_date = key["CreateDate"]
            age_days = (datetime.now(timezone.utc) - create_date).days

            if age_days > max_age_days:
                add_finding(
                    "MEDIUM",
                    f"{username} access key {key_id} is {age_days} days old and should be rotated"
                )
            else:
                add_pass(f"{username} access key {key_id} is {age_days} days old")

    if not found_keys:
        add_pass("No IAM user access keys found")

def check_s3_public_access():
    print("\n--- Checking S3 Bucket Public Access ---")
    try:
        buckets = s3.list_buckets()["Buckets"]

        if not buckets:
            add_pass("No S3 buckets found.")
            return

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
                if all(pab.values()):
                    add_pass(f"S3 bucket {bucket_name} has Public Access Block enabled")
                else:
                    add_finding("HIGH", f"S3 bucket {bucket_name} does not fully block public access")
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                add_finding("HIGH", f"S3 bucket {bucket_name} has no Public Access Block configuration")
            except ClientError as e:
                add_finding("LOW", f"Could not evaluate bucket {bucket_name}: {e}")

    except ClientError as e:
        add_finding("MEDIUM", f"Error checking S3 buckets: {e}")

def print_summary():
    print("\n--- Security Check Summary ---")

    if not findings:
        print("[PASS] No security gaps identified.")
        return 0

    print(f"[FAIL] {len(findings)} finding(s) identified:")
    for finding in findings:
        print(f" - [{finding['severity']}] {finding['message']}")
    return 1

# Run all checks
print("Running AWS Security Checks...")
check_mfa_on_users()
check_cloudtrail()
check_root_access_keys()
check_password()
check_access_key_age()
check_s3_public_access()

exit_code = print_summary()
sys.exit(exit_code)
