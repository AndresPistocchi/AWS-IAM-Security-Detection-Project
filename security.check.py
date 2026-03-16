import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone

# Create clients
iam = boto3.client('iam')
cloudtrail = boto3.client('cloudtrail')

def check_mfa_on_users():
    print("\n--- Checking MFA on IAM Users ---")
    users = iam.list_users()['Users']
    for user in users:
        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        if not mfa_devices:
            print(f"❌ {user['UserName']} does NOT have MFA enabled")
        else:
            print(f"✅ {user['UserName']} has MFA enabled")

def check_cloudtrail():
    print("\n--- Checking CloudTrail Status ---")
    trails = cloudtrail.describe_trails()['trailList']
    if not trails:
        print("❌ No CloudTrail trails found!")
    else:
        for trail in trails:
            print(f"✅ Trail found: {trail['Name']}")

def check_root_access_keys():
    print("\n--- Checking Root Account Access Keys ---")
    summary = iam.get_account_summary()['SummaryMap']
    if summary.get('AccountAccessKeysPresent', 0) > 0:
        print("❌ Root account has active access keys - this is dangerous!")
    else:
        print("✅ No root access keys found - good!")

def check_password():
    print("\n--- Checking Password Policy ---")
    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']

        issues = []

        if policy.get('MinimumPasswordLength', 0) < 12:
            issues.append("minimum length is less than 12")
        if not policy.get('RequireSymbols', False):
            issues.append("symbols are not required")
        if not policy.get('RequireNumbers', False):
            issues.append("numbers are not required")
        if not policy.get('RequireUppercaseCharacters', False):
            issues.append("uppercase letters are not required")
        if not policy.get('RequireLowercaseCharacters', False):
            issues.append("lowercase letters are not required")

        if issues:
            print("❌ Password policy is weak:")
            for issue in issues:
                print(f"   - {issue}")
        else:
            print("✅ Password policy is secure!")

    except iam.exceptions.NoSuchEntityException:
        print("❌ No account password policy is configured.")
    except ClientError as e:
        print(f"❌ Error checking password policy: {e}")


def check_access_key_age():
    print("\n--- Checking Access Key Age ---")
    users = iam.list_users()['Users']
    found_keys = False

    for user in users:
        username = user['UserName']
        access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']

        for key in access_keys:
            found_keys = True
            key_id = key['AccessKeyId']
            create_date = key['CreateDate']

            age_days = (datetime.now(timezone.utc) - create_date).days

            if age_days > 90:
                print(f"❌ {username} access key {key_id} is {age_days} days old and should be rotated")
            else:
                print(f"✅ {username} access key {key_id} is {age_days} days old")

    if not found_keys:
        print("✅ No IAM user access keys found.")


# Run all checks
print("🔍 Running AWS Security Checks...")
check_mfa_on_users()
check_cloudtrail()
check_root_access_keys()
check_password()
check_access_key_age()
print("\n✅ Security check complete!")
