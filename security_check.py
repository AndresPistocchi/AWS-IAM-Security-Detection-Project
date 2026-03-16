import boto3

# Create clients
iam = boto3.client('iam')
cloudtrail = boto3.client('cloudtrail')

def check_mfa_on_users():
    print("\n--- Checking MFA on IAM Users ---")
    users = iam.list_users()['Users']
    for user in users:
        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        if not mfa_devices:
            print(f"{user['UserName']} does NOT have MFA enabled")
        else:
            print(f"{user['UserName']} has MFA enabled")

def check_cloudtrail():
    print("\n--- Checking CloudTrail Status ---")
    trails = cloudtrail.describe_trails()['trailList']
    if not trails:
        print("No CloudTrail trails found!")
    else:
        for trail in trails:
            print(f"Trail found: {trail['Name']}")

def check_root_access_keys():
    print("\n--- Checking Root Account Access Keys ---")
    summary = iam.get_account_summary()['SummaryMap']
    if summary.get('AccountAccessKeysPresent', 0) > 0:
        print("Root account has active access keys - this is dangerous!")
    else:
        print("No root access keys found - good!")
def check_password():
    print("\n--- Checking Password Policy ---")
    policy = iam.get_account_password_policy()
    if not policy:
        print("Password not strong enough!")
    else:
        print("Password is Secure!")
def check_access_key_age():
    print("\n--- Checking Access Key Age ---")
    age = iam.get_access_key_age()
    if age > 90:
        print("Access key needs to be changed!")
    else:
        print("Access key is within age limits!")

# Run all checks
print("🔍 Running AWS Security Checks...")
check_mfa_on_users()
check_cloudtrail()
check_root_access_keys()
check_password()
check_access_key_age()
print("\n✅ Security check complete!")
