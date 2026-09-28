# Part 12: Google Dorking & Advanced Search
## เทคนิคการค้นหาข้อมูลด้วย Search Engines

---

## สารบัญ
1. [Google Dorking คืออะไร](#intro)
2. [Search Operators พื้นฐาน](#basic-operators)
3. [Advanced Dorks](#advanced)
4. [GHDB - Google Hacking Database](#ghdb)
5. [Dorking หาไฟล์ชนิดต่างๆ](#file-search)
6. [Login Pages & Admin Panels](#login)
7. [Exposed Data & Credentials](#exposed)
8. [Camera & IoT Devices](#cameras)
9. [Automation & Tools](#tools)
10. [แบบฝึกหัด](#exercises)

---

## 1. Google Dorking คืออะไร {#intro}

**Google Dorking** คือการใช้ Google และ search engines อื่นๆ เพื่อค้นหาข้อมูลที่มีความอ่อนไหวซึ่งถูก index ไว้โดยไม่ตั้งใจ

### ไม่ได้ทำให้เกิด index?
- ขาดการตั้งค่า robots.txt
- ไฟล์อยู่ใน directory ที่ไม่ได้ป้องกัน
- ลิงก์สาธารณะไปยัง private documents
- Developer ลืม path ที่ sensitive

### ข้อมูลที่หาได้ด้วย Dorking
- Login pages และ admin panels
- Configuration files (มี passwords/API keys)
- Database dumps
- Log files
- Backup files
- Network devices
- Security cameras

---

## 2. Search Operators พื้นฐาน {#basic-operators}

### Core Operators

```
site:example.com
    ค้นหาเฉพาะใน domain นี้
    site:example.com login
    site:example.com -www  (ยกเว้น www)

filetype: / ext:
    ค้นหาเฉพาะไฟล์ประเภทนี้
    filetype:pdf site:example.com
    ext:sql site:example.com

intitle:
    ค้นหาในชื่อหน้า (title tag)
    intitle:"index of"
    intitle:"admin panel"
    intitle:"login"

allintext:
    ค้นหาทุกคำในเนื้อหา
    allintext:username password filetype:log

inurl:
    ค้นหาใน URL
    inurl:admin
    inurl:login.php
    inurl:/phpMyAdmin

allinurl:
    ทุกคำต้องอยู่ใน URL
    allinurl:admin password login

cache:
    ดู cached version
    cache:example.com

link:
    เว็บไหนลิงก์มา
    link:example.com

related:
    เว็บที่เกี่ยวข้อง
    related:example.com

info:
    ข้อมูลเกี่ยวกับ site
    info:example.com

before: / after:
    กรองตามวันที่
    site:example.com after:2023-01-01
```

### Logical Operators

```
AND (default): ค้นคำทั้งหมด
    admin login example.com

OR: ค้นคำใดคำหนึ่งก็ได้
    "sql" OR "database" filetype:sql

- (minus): ไม่เอาคำนี้
    admin -inurl:forum

" " (quotes): exact phrase
    "index of" "parent directory"

* (wildcard): แทนคำใดก็ได้
    "password * database"

.. (range): ช่วงตัวเลข
    port:8000..9000
```

---

## 3. Advanced Dorks {#advanced}

### Directory Listing

```
# หา open directories
intitle:"index of"
intitle:"index of" /
intitle:"index of" /backup
intitle:"index of" /config
intitle:"index of" /logs
intitle:"index of" /uploads
intitle:"index of" /private

# Directory listing โดยไม่ระบุ site
"Parent Directory" /appdata
"Parent Directory" site:example.com
```

### Sensitive Files

```
# Configuration files
filetype:env DB_PASSWORD
filetype:ini "db_password"
filetype:cfg password
filetype:conf password
filetype:yaml "api_key"
filetype:xml "password"

# Database files
filetype:sql "INSERT INTO"
filetype:sql "password"
filetype:sql site:example.com
filetype:mdb site:example.com
filetype:dbf site:example.com

# Backup files
filetype:bak inurl:login
filetype:bak site:example.com
filetype:backup site:example.com
extension:gz site:example.com

# Log files  
filetype:log intext:password
filetype:log "error" site:example.com
allintext:username password filetype:log

# PHP source code
filetype:php intext:mysql_connect
filetype:php intitle:phpinfo
filetype:php inurl:config
```

### Exposed Credentials

```
# Password files
inurl:passwords.txt filetype:txt
filetype:txt "password"
filetype:csv "password,username"

# SSH keys
filetype:pem "RSA PRIVATE KEY"
filetype:key "PRIVATE KEY"
extension:ppk

# AWS credentials
filetype:ini [default] aws
filetype:env AWS_SECRET_ACCESS_KEY
"AWS_SECRET_ACCESS_KEY" filetype:env

# API keys
"api_key" filetype:env
"access_token" filetype:json
```

---

## 4. GHDB - Google Hacking Database {#ghdb}

**GHDB (Google Hacking Database)** คือคลังข้อมูล Google Dorks ที่ Offensive Security รวบรวมไว้

```
URL: https://www.exploit-db.com/google-hacking-database

หมวดหมู่:
- Footholds
- Files Containing Usernames
- Sensitive Directories
- Web Server Detection
- Vulnerable Files
- Vulnerable Servers
- Error Messages
- Files Containing Passwords
- Sensitive Online Shopping Info
- Network or Vulnerability Data
- Pages Containing Login Portals
- Various Online Devices
- Advisories and Vulnerabilities
```

### ตัวอย่าง GHDB Dorks

```
# phpMyAdmin
intitle:phpMyAdmin
inurl:phpmyadmin/index.php
"Welcome to phpMyAdmin" -demo

# WordPress
inurl:wp-login.php
inurl:wp-admin
intitle:"WordPress" inurl:wp-content

# Joomla
inurl:administrator/index.php
intitle:"Joomla! - Administration"

# cPanel
inurl:2082 OR inurl:2083 "cPanel Login"

# Webmin
port:10000 title:"webmin"

# Jenkins
intitle:"Dashboard [Jenkins]"

# Kibana
intitle:"Kibana" inurl:5601

# Grafana
intitle:"Grafana" inurl:3000

# Tomcat
intitle:"Apache Tomcat" inurl:8080
```

---

## 5. Dorking หาไฟล์ชนิดต่างๆ {#file-search}

### Excel/CSV ที่มีข้อมูลสำคัญ

```
filetype:xls site:example.com
filetype:xlsx "salary" site:example.com
filetype:csv intext:@example.com  (หา emails)
filetype:csv "card_number" OR "credit_card"
```

### Word Documents

```
filetype:doc site:example.com
filetype:docx "confidential" site:example.com
filetype:doc intitle:"internal" site:example.com
```

### PDF Documents

```
filetype:pdf site:example.com
filetype:pdf "confidential" site:example.com
filetype:pdf intitle:"network diagram"
filetype:pdf "password" site:example.com
```

### Configuration Files

```
filetype:config inurl:web.config
filetype:env intext:DB_PASSWORD
filetype:ini intext:password
filetype:conf apache site:example.com
```

---

## 6. Login Pages & Admin Panels {#login}

```
# Generic login pages
intitle:"Login" inurl:admin
intitle:"Administrator" inurl:login
intitle:"Admin Panel"

# Specific CMS
site:example.com inurl:/admin
site:example.com inurl:/administrator
site:example.com inurl:/wp-admin
site:example.com inurl:/control-panel

# Database admin
intitle:"phpMyAdmin" AND NOT intext:demo
intitle:"SQL Buddy"
intitle:"adminer" filetype:php

# Remote access
intitle:"Remote Desktop" inurl:nwa OR inurl:8443
inurl:":4899" intitle:"Radmin"

# VPN
intitle:"Pulse Secure" inurl:"://" "+BNSERVER+"
intitle:"GlobalProtect"

# Firewall admin
intitle:"pfSense - Login"
intitle:"Cisco ASDM"
```

---

## 7. Exposed Data & Credentials {#exposed}

### Database Dumps

```
filetype:sql intext:"-- MySQL dump"
filetype:sql intext:"CREATE TABLE"
filetype:sql intext:"INSERT INTO"
"db_password" filetype:sql
"mysqldump" site:pastebin.com
```

### Pastebin Leaks

```
site:pastebin.com "example.com" password
site:pastebin.com "@example.com"
site:pastebin.com "apikey" "example"

# สี่ตีแหล่งสำหรับ leaks:
site:pastebin.com
site:ghostbin.com
site:hastebin.com
site:controlc.com
```

### Exposed APIs

```
inurl:"/api/v1" site:example.com
inurl:"/api/" intext:"api_key"
filetype:json intext:"api_key"
filetype:json intext:"access_token"
"Authorization: Bearer" filetype:txt
```

### GitHub Secrets (via Google)

```
site:github.com "example.com" password
site:github.com "api_key" "example.com"
site:github.com filename:.env DB_PASSWORD
site:github.com extension:pem "PRIVATE KEY"
site:github.com filename:wp-config.php db_password
```

---

## 8. Camera & IoT Devices {#cameras}

### Security Cameras

```
# Axis cameras
intitle:"Live View / - AXIS"

# Panasonic cameras  
inurl:ViewerFrame?Mode=Motion

# Sony cameras
inurl:view/index.shtml

# Generic cameras
intitle:"webcam" live
intitle:"Network Camera" inurl:axis-cgi

# IP cameras
inurl:"top.htm" inurl:"currenttime"
intitle:"snc-rz30" inurl:home/

# D-Link cameras
intitle:"D-LINK Internet Camera"
```

### Network Devices

```
# Printers
intitle:"Printer Status" inurl:hp/device/this.LCDispatcher
intitle:"network printer" OR intitle:"web image monitor"

# Routers
intitle:"Linksys Router" intext:"Firmware Version"
intitle:"NETGEAR" inurl:currentsetting.htm

# VoIP
intitle:"Polycom" inurl:/i/ intext:"to place a call"
intitle:"Cisco CallManager"

# Industrial Control
intitle:"SCADA" inurl:login
intitle:"HMI" web interface
```

---

## 9. Automation & Tools {#tools}

### Googler (Command line Google)

```bash
# ติดตั้ง
# apt install googler
# หรือ pip3 install googler

# Basic search
googler "site:example.com filetype:pdf"
googler -n 50 "intitle:index of"

# JSON output
googler -j "site:example.com password"
```

### Pagodo - GHDB Automation

```bash
# ติดตั้ง
git clone https://github.com/opsdisk/pagodo
cd pagodo
pip3 install -r requirements.txt

# Download GHDB dorks
python3 ghdb_scraper.py -j -s

# Run dorks ต่อ site
python3 pagodo.py -d example.com -g dorks.txt -s -e 35.0 -j 1.1

# Options:
# -d domain
# -g dork file
# -s save results
# -e delay seconds
# -j jitter
```

### GoogDork.py

```python
#!/usr/bin/env python3
# googdork.py - Google Dork Automation

import requests
import time
import urllib.parse
from bs4 import BeautifulSoup

class GoogleDorker:
    def __init__(self, delay=3):
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def search(self, query, num_results=10):
        results = []
        encoded_query = urllib.parse.quote(query)
        url = f"https://www.google.com/search?q={encoded_query}&num={num_results}"
        
        try:
            r = self.session.get(url, timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            for div in soup.find_all('div', class_='g'):
                link = div.find('a')
                title = div.find('h3')
                if link and title:
                    results.append({
                        'url': link.get('href', ''),
                        'title': title.get_text()
                    })
            
            time.sleep(self.delay)  # ป้องกัน rate limiting
            return results
            
        except Exception as e:
            print(f"[-] Error: {e}")
            return []
    
    def dork_scan(self, domain, dork_file):
        with open(dork_file, 'r') as f:
            dorks = [line.strip() for line in f if line.strip()]
        
        all_results = {}
        for dork in dorks:
            query = f"{dork} site:{domain}"
            print(f"[*] Running: {query}")
            results = self.search(query)
            if results:
                all_results[dork] = results
                for r in results:
                    print(f"  [+] {r['url']}")
        
        return all_results

# ใช้งาน
dorker = GoogleDorker(delay=5)  # 5 second delay

# Single dork
results = dorker.search('intitle:"index of" site:example.com')
for r in results:
    print(f"URL: {r['url']}")
    print(f"Title: {r['title']}")
```

### Shodan Dorking

```bash
# Shodan - Search engine สำหรับ IoT/network devices
pip3 install shodan

# CLI
shodan init YOUR_API_KEY
shodan search 'apache country:TH'
shodan search 'port:3306 country:TH'
shodan host 93.184.216.34

# Shodan Dorks
product:"Apache httpd" country:TH
"Server: Apache" country:TH port:80
ssl.cert.subject.cn:"*.example.com"
org:"Company Name" port:22
"default password" country:TH
hostname:"admin" port:8080

# Download results
shodan search 'apache country:TH' --fields ip_str,port,org --limit 100 > shodan_results.csv

# Python API
python3 << 'EOF'
import shodan

api = shodan.Shodan('YOUR_API_KEY')

try:
    results = api.search('apache country:TH')
    print(f"Results: {results['total']}")
    
    for r in results['matches']:
        print(f"IP: {r['ip_str']}:{r['port']}")
        print(f"Org: {r.get('org', 'N/A')}")
        print(f"OS: {r.get('os', 'N/A')}")
        print()
except shodan.APIError as e:
    print(f"Error: {e}")
EOF
```

### Censys Dorking

```bash
# Censys - Internet-wide scanning
pip3 install censys

# Setup
censys config  # ใส่ API credentials

# Search
censys search 'example.com' --index-type hosts
censys search 'services.port:22 AND location.country:TH'
censys view 93.184.216.34

# Python API
python3 << 'EOF'
from censys.search import CensysHosts

h = CensysHosts()
for page in h.search('services.port:8080 AND location.country:TH', pages=1):
    for host in page:
        print(host['ip'], host.get('services', []))
EOF
```

---

## 10. แบบฝึกหัด {#exercises}

### Lab 1: Target Dorking
เลือกเว็บเป้าหมายที่ได้รับอนุญาต แล้ว:
1. `site:target.com` ดู scope
2. `site:target.com filetype:pdf` หาเอกสาร
3. `site:target.com inurl:admin` หา admin areas
4. `site:target.com intitle:"index of"` หา directory listing
5. `site:target.com filetype:env OR filetype:cfg` หา config

### Lab 2: Sensitive File Hunt
ใช้ dorks แต่ละอันนี้ documentสิ่งที่หาได้:
1. Config files with passwords
2. Backup files
3. Log files
4. Database files
5. Private keys

### Lab 3: Shodan Investigation
1. สมัครจน Shodan.io
2. ค้นหา devices ในประเทศไทย (`country:TH`)
3. หา services ที่น่าสนใจ
4. วิเคราะห์หนึ่งในผลลัพธ์

---

## Cheat Sheet

```
# หา login pages
site:target.com intitle:login

# หา admin panels
site:target.com inurl:admin

# หา config files
site:target.com filetype:env OR filetype:cfg OR filetype:ini

# หา database files
site:target.com filetype:sql OR filetype:mdb

# หา backup files
site:target.com filetype:bak OR filetype:backup

# หา log files
site:target.com filetype:log

# Open directories
site:target.com intitle:"index of"

# API endpoints
site:target.com inurl:api

# Sensitive documents
site:target.com filetype:pdf "confidential"
```

---

## สรุป

| เทคนิค | ประโยชน์ |
|-------|----------|
| site: | จำกัดการค้นหา |
| filetype: | หาไฟล์ชนิดเฟ้า |
| intitle: | หาใน title |
| inurl: | หาใน URL |
| allintext: | หาในเนื้อหา |
| GHDB | คลัง dorks สำเร็จรูป |
| Shodan/Censys | หาอุปกรณ์เดินสาย |

**ไม่จำเป็นต้อง hack**: Google Dork สามารถเปิดเผยข้อมูลช่องโหว่ได้แบบ passive!

---
*Part 12/100+ | Kali Linux Penetration Testing Course*
