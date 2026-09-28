# Part 25: Web Application Architecture และ Security

## สารบัญ
- [25.1 Web Application Architecture](#251-web-application-architecture)
- [25.2 HTTP Protocol ลึก](#252-http-protocol-ลึก)
- [25.3 Session และ Cookies](#253-session-และ-cookies)
- [25.4 Authentication และ Authorization](#254-authentication-และ-authorization)
- [25.5 OWASP Top 10](#255-owasp-top-10)
- [25.6 เครื่องมือ Web Testing](#256-เครื่องมือ-web-testing)
- [25.7 Burp Suite เบื้องต้น](#257-burp-suite-เบื้องต้น)
- [25.8 Python HTTP Interaction](#258-python-http-interaction)
- [25.9 แบบฝึกหัด Lab](#259-แบบฝึกหัด-lab)

---

## 25.1 Web Application Architecture

### โครงสร้าง 3-Tier Architecture
```
┌──────────────────────────────────────────────────┐
│                   Internet                        │
└──────────────────────────────────────────────────┘
                          ↓ ↑
┌──────────────────────────────────────────────────┐
│           Presentation Layer (Tier 1)              │
│  Web Browser (HTML, CSS, JavaScript)               │
└──────────────────────────────────────────────────┘
                          ↓ ↑ HTTP/HTTPS
┌──────────────────────────────────────────────────┐
│             Application Layer (Tier 2)             │
│  Web Server: Apache, Nginx, IIS                    │
│  App Server: PHP, Python, Node.js, Java            │
│  Frameworks: Laravel, Django, Express, Spring      │
└──────────────────────────────────────────────────┘
                          ↓ ↑ SQL/API
┌──────────────────────────────────────────────────┐
│               Data Layer (Tier 3)                  │
│  Databases: MySQL, PostgreSQL, MongoDB             │
│  Cache: Redis, Memcached                           │
│  Files: NFS, S3, Local Storage                    │
└──────────────────────────────────────────────────┘
```

### Attack Surfaces ในแต่ละ Layer
```
Presentation Layer:
  - JavaScript Injection
  - DOM-based XSS
  - Clickjacking
  - CSRF

Application Layer:
  - SQL Injection
  - Server-side Injection (RCE)
  - Path Traversal
  - File Upload
  - Authentication Bypass
  - IDOR

Data Layer:
  - Database Injection
  - Exposed Databases
  - Weak Encryption
  - Backup Files
```

---

## 25.2 HTTP Protocol ลึก

### HTTP Request Structure
```
POST /login.php HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Cookie: PHPSESSID=abc123def456; pref=dark
Connection: keep-alive

username=admin&password=password123
```

### HTTP Response Structure
```
HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=xyz789; Path=/; HttpOnly; Secure
Content-Type: text/html; charset=UTF-8
X-Frame-Options: SAMEORIGIN
Content-Length: 12345

<!DOCTYPE html>
<html>...
```

### HTTP Methods
```bash
# Test HTTP Methods
curl -X GET    http://target.com/api/users
curl -X POST   http://target.com/api/users -d '{"name":"test"}'
curl -X PUT    http://target.com/api/users/1 -d '{"name":"new"}'
curl -X DELETE http://target.com/api/users/1
curl -X PATCH  http://target.com/api/users/1
curl -X HEAD   http://target.com/
curl -X OPTIONS http://target.com/
curl -X TRACE  http://target.com/  # Dangerous! ถ้าเปิดอยู่

# ตรวจ Allowed Methods
curl -I -X OPTIONS http://target.com/
# ดู Allow header ใน Response
```

### Status Codes ที่สำคัญ
```
200 OK          - สำเร็จ
301/302         - Redirect
400 Bad Request - Request ผิด
401 Unauthorized - ต้อง Login
403 Forbidden   - ไม่มีสิทธิ์
404 Not Found   - ไม่พบ
500 Server Error - ไม่ปลอดภัย (อาจดู Error)
ด้วยตา Pentest:
403 → เปลี่ยน Method (PUT แทน GET)
500 → Debug Mode? Error เปิดเผย?
```

### HTTP Headers ที่น่าสนใจ (Pentest)
```
X-Forwarded-For: 127.0.0.1           # ส่ง IP อื่น
                                      # อาจ Bypass IP Restriction

X-Real-IP: 192.168.1.1               # เหมือนกัน

Referer: https://admin.example.com/  # เปลี่ยนค่า
                                      # อาจ Bypass Referer Check

User-Agent: SQLMap/1.0               # เปลี่ยนเพื่อหลีก WAF

Host: evil.com                        # Host Header Injection
```

---

## 25.3 Session และ Cookies

### Cookie Attributes
```
Set-Cookie: session=abc123; 
  Path=/;           ใช้ได้ทุก Path
  Domain=.example.com; ใช้ได้ทุก Subdomain
  Expires=Thu, 31 Dec 2024 23:59:59 GMT;
  Secure;           ส่งเฉพาะผ่าน HTTPS
  HttpOnly;         JavaScript ไม่สามารถอ่าน
  SameSite=Strict   ป้องกัน CSRF
```

### Cookie Security Issues
```bash
# ดู Cookies (ไม่มี HttpOnly)
document.cookie

# Cookie ไม่มี Secure Flag → ส่งผ่าน HTTP ได้
curl http://example.com -c /tmp/cookies.txt
cat /tmp/cookies.txt

# Session Fixation - ถ้า Session ID ไม่เปลี่ยนหลัง Login
# ทดสอบ:
# 1. ดู Session ID ก่อน Login
# 2. Login
# 3. ดู Session ID หลัง Login
# ถ้า ID เดิม = อันตราย!
```

### JWT Tokens
```
JSON Web Token Structure:
Header.Payload.Signature

ตัวอย่าง:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VyaWQiOjEsInJvbGUiOiJhZG1pbiIsImV4cCI6MTYwMDAwMDAwMH0.
Sig...

Decode Payload:
echo 'eyJ1c2VyaWQiOjEsInJvbGUiOiJhZG1pbiIsImV4cCI6MTYwMDAwMDAwMH0' | base64 -d
# {"userid":1,"role":"admin","exp":1600000000}

Common JWT Attacks:
  1. None Algorithm - ลบ Signature
  2. Weak Secret - Brute force key
  3. alg confusion - RS256 to HS256
```

```bash
# ตรวจ JWT None Algorithm
python3 << 'EOF'
import base64, json

# Original token
header = base64.b64decode('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9==').decode()
print('Header:', header)

# เปลี่ยนเป็น alg: none
new_header = json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()
new_header_b64 = base64.urlsafe_b64encode(new_header).rstrip(b'=')

payload = base64.b64decode('eyJ1c2VyaWQiOjEsInJvbGUiOiJhZG1pbiJ9==').decode()
print('Payload:', payload)
payload_b64 = base64.urlsafe_b64encode(payload.encode()).rstrip(b'=')

# Token ไม่มี Signature
malicious_token = new_header_b64.decode() + '.' + payload_b64.decode() + '.'
print('Malicious Token:', malicious_token)
EOF
```

---

## 25.4 Authentication และ Authorization

### Authentication Methods
```
1. Basic Auth      - username:password ใน Header
2. Form-based      - HTML Form → POST
3. JWT             - JSON Web Token
4. OAuth 2.0       - Third-party Auth
5. SAML            - Enterprise SSO
6. API Key         - key=abc123
7. Certificate     - mTLS
8. Biometric       - Fingerprint/Face
```

### Common Auth Vulnerabilities
```
1. Weak Passwords            - admin/admin
2. No Rate Limiting          - Brute Force
3. Predictable Username      - user1, user2
4. Information Leakage       - "Password incorrect" vs "User not found"
5. No MFA                    - Easy Account Takeover
6. Session not expired       - After Logout still valid
7. Insecure Password Reset   - Predictable token
8. SQL Injection in Login    - ' OR '1'='1
```

---

## 25.5 OWASP Top 10

```
OWASP Top 10 (2021):

A01 Broken Access Control     - IDOR, Privilege Escalation
A02 Cryptographic Failures    - Weak Encryption, HTTP
A03 Injection                 - SQLi, Command Injection, XSS
A04 Insecure Design           - Missing Rate Limiting
A05 Security Misconfiguration - Default Passwords, Debug Mode
A06 Vulnerable Components     - Outdated Libraries
A07 Auth Failures             - Brute Force, Weak Session
A08 Software Integrity Fails  - Unsigned Updates, Insecure CI/CD
A09 Security Logging Failures - No Audit Logs
A10 SSRF                      - Server-Side Request Forgery
```

### ไเกลีย Quick Check
```bash
# A01 - IDOR Test
# เปลี่ยน ID ใน URL
curl http://target.com/api/user/1
curl http://target.com/api/user/2  # เป็นโปรไฟล์คนอื่น?

# A03 - SQLi Test
curl "http://target.com/product?id=1'"
curl "http://target.com/product?id=1 OR 1=1--"

# A05 - Default Credentials
curl http://target.com/admin/ -u admin:admin
curl http://target.com/admin/ -u admin:password

# A09 - Check No Rate Limiting
for i in $(seq 1 20); do
    curl -s -X POST http://target.com/login \
    -d 'username=admin&password=wrong' | grep -i 'locked\|rate\|too many'
done
```

---

## 25.6 เครื่องมือ Web Testing

### เครื่องมือหลัก
```
Burp Suite     - HTTP Proxy + Scanner
               เครื่องมือสำคัญที่สุด

ZAP (OWASP)    - Open Source Web Scanner
               ทางเลือกฟรีแทน Burp

ffuf           - Web Fuzzer (เร็วมาก)
Gobuster       - Directory/DNS Brute Force
dirsearch      - Directory Scanner
sqlmap         - SQL Injection Automation
wpscan         - WordPress Scanner
droopescan     - Drupal/Joomla Scanner
```

### Directory Brute Force
```bash
# gobuster
gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt

# ffuf
ffuf -u http://192.168.1.100/FUZZ -w /usr/share/wordlists/dirb/common.txt

# dirsearch
dirsearch -u http://192.168.1.100 -e php,html,txt

# feroxbuster
feroxbuster -u http://192.168.1.100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

---

## 25.7 Burp Suite เบื้องต้น

### Setup Burp Suite
```bash
# เริ่ม Burp Suite Community (Free)
burpsuite &

# ตั้งค่า Proxy:
# Proxy → Options → Proxy Listeners
# ตรวจว่า 127.0.0.1:8080
```

### ตั้งค่า Firefox Proxy
```
Firefox → Settings → Network Settings:
  Manual proxy configuration:
  HTTP Proxy: 127.0.0.1  Port: 8080
  Check: Also use this proxy for HTTPS

ติดตั้ง CA Certificate:
  ไป: http://burp/cert
  Download และ Import ใน Firefox
  Firefox → Settings → Certificates → Import
```

### Burp Suite หน้าที่หลัก
```
Proxy    - Intercept และแก้ไข HTTP Requests/Responses
Repeater - ทดสอบ Request ซ้ำหลายครั้ง
Intruder - Automated Attack (Brute Force, Fuzzing)
Scanner  - Auto Vulnerability Scan (Pro only)
Decoder  - Encode/Decode Data (Base64, URL, HTML)
Comparer - เปรียบ Request/Response
Sequencer - Session Token Randomness Analysis
Extender - ติดตั้ง Extensions/Plugins
```

### Burp Proxy - Intercept
```
1. เปิด Proxy → Intercept → Intercept is on
2. เปิด Browser → ทำการ Request
3. Request จะหยุดใน Burp
4. แก้ไขค่า แล้ว Forward
5. หรือ Drop เพื่อยกเลิก
```

### Burp Repeater
```
1. Proxy → HTTP History → Right-click Request → Send to Repeater
2. Repeater Tab → แก้ไข Request
3. Click Go → ดู Response
4. ทดสอบ SQLi/XSS/อื่นๆ ในนี้
```

### Burp Intruder
```
1. Send Request to Intruder
2. Positions Tab: เลือก Payload Position
   คลุม « param_value » แล้ว Click Add §
3. Payloads Tab: ใส่ Wordlist
4. Attack Type:
   Sniper    - 1 position, 1 list
   Battering Ram - All positions ใช้ value เดียวกัน
   Pitchfork - Multiple positions, Multiple lists (same index)
   Cluster Bomb - Multiple positions, All combinations
5. Click Start Attack
```

---

## 25.8 Python HTTP Interaction

```python
#!/usr/bin/env python3
# web_tester.py - Basic Web Testing

import requests
from bs4 import BeautifulSoup
import re

requests.packages.urllib3.disable_warnings()

class WebTester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.session.verify = False

    def get_links(self, path='/'):
        resp = self.session.get(self.base_url + path)
        soup = BeautifulSoup(resp.text, 'html.parser')
        links = set()
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('/'):
                links.add(href)
            elif href.startswith('http'):
                links.add(href)
        return links

    def check_headers(self):
        resp = self.session.head(self.base_url)
        print("\n[*] Security Headers Analysis:")
        security_headers = {
            'X-Frame-Options': ('Present', 'MISSING - Clickjacking risk'),
            'X-Content-Type-Options': ('Present', 'MISSING'),
            'X-XSS-Protection': ('Present', 'MISSING'),
            'Strict-Transport-Security': ('Present', 'MISSING - HSTS'),
            'Content-Security-Policy': ('Present', 'MISSING - XSS risk'),
        }
        for header, (good, bad) in security_headers.items():
            if header in resp.headers:
                print(f"  [OK] {header}: {resp.headers[header][:50]}")
            else:
                print(f"  [!!] {header}: {bad}")
        
        print("\n[*] Info Headers:")
        for h in ['Server', 'X-Powered-By', 'X-Generator', 'X-AspNet-Version']:
            if h in resp.headers:
                print(f"  [INFO] {h}: {resp.headers[h]}")

    def check_forms(self, path='/'):
        resp = self.session.get(self.base_url + path)
        soup = BeautifulSoup(resp.text, 'html.parser')
        print(f"\n[*] Forms in {path}:")
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            print(f"  Form: {method} {action}")
            for inp in form.find_all(['input', 'textarea']):
                name = inp.get('name', '')
                itype = inp.get('type', 'text')
                print(f"    Field: {name} ({itype})")

    def test_sqli_basic(self, path, param):
        payloads = ["'", "'",  "' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]
        print(f"\n[*] Testing SQLi: {path}?{param}=PAYLOAD")
        for payload in payloads:
            try:
                resp = self.session.get(
                    self.base_url + path,
                    params={param: payload}
                )
                if any(err in resp.text.lower() for err in 
                       ['sql', 'mysql', 'syntax', 'error', 'warning']):
                    print(f"  [+] Possible SQLi! Payload: {payload}")
                    print(f"      Status: {resp.status_code}, Length: {len(resp.text)}")
            except Exception as e:
                pass

if __name__ == '__main__':
    tester = WebTester('http://192.168.1.100')
    tester.check_headers()
    tester.check_forms('/')
    tester.check_forms('/login.php')
    links = tester.get_links('/')
    print(f"\n[*] Found {len(links)} links")
    for l in sorted(links)[:10]:
        print(f"  {l}")
```

---

## 25.9 แบบฝึกหัด Lab

### Lab 25-1: HTTP Analysis ด้วย curl
```bash
# 1. ดู Headers
curl -I http://192.168.1.100

# 2. ส่ง POST Request
curl -X POST http://192.168.1.100/login \
  -d 'username=admin&password=admin123' \
  -c /tmp/cookies.txt -v

# 3. ใช้ Cookie
curl http://192.168.1.100/dashboard \
  -b /tmp/cookies.txt

# 4. Test Methods
curl -X OPTIONS http://192.168.1.100 -I | grep Allow
```

### Lab 25-2: Burp Suite Setup
```
1. เปิด Burp Suite
2. ตั้ง Firefox Proxy → 127.0.0.1:8080
3. ติดตั้ง CA Certificate
4. เปิด https://target.com
5. ดู Traffic ใน Proxy → HTTP History
6. ส่ง Request ไป Repeater
7. แก้ไข Parameter และสังเกตผล
```

### Lab 25-3: Python Web Tester
```bash
# Setup DVWA
sudo docker run -d -p 8080:80 vulnerables/web-dvwa

# Run Tester
python3 web_tester.py http://localhost:8080

# ดู Form Fields
# ทดสอบ SQLi
```

---

## สรุป

| ส่วนประกอบ | ช่องโหว่ที่พบบ่อย |
|------------|-------------------|
| Input Forms | SQLi, XSS, Command Injection |
| URL Parameters | SQLi, Path Traversal, IDOR |
| Cookies | Session Hijacking, XSS |
| Headers | HTTP Header Injection |
| File Upload | Remote Code Execution |
| API Endpoints | Auth Bypass, IDOR |
| Error Messages | Info Disclosure |

> **จำไว้:** OWASP Testing Guide คือ Reference หลักสำหรับ Web Pentest - ดาวน์โหลดได้ที่ owasp.org
