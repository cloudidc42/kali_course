# Part 15: Maltego & Recon-ng
## เครื่องมือ OSINT ขั้นสูง

---

## สารบัญ
1. [Maltego Overview](#maltego)
2. [Maltego Transforms](#transforms)
3. [Maltego Community Edition](#community)
4. [Recon-ng Overview](#recon-ng)
5. [Recon-ng Modules](#modules)
6. [Recon-ng Workflow](#workflow)
7. [Custom Reports](#reports)
8. [แบบฝึกหัด](#exercises)

---

## 1. Maltego Overview {#maltego}

**Maltego** คือโปรแกรม OSINT แบบ visual ที่แสดงการเชื่อมโยงระหว่างข้อมูลต่างๆ เช่น domains, IPs, emails, social media

```bash
# ติดตั้ง
apt install maltego -y

# หรือ download จาก https://maltego.com
# Edition:
# - Community Edition: ฟรี จำกัด 12 results/transform
# - Classic/XL: ไม่จำกัด

maltego
```

### Entity Types

```
Maltego Entities:
- Person          - บุคคล
- Organization    - องค์กร
- Domain          - ชื่อ domain
- IP Address      - เลข IP
- Email Address   - อีเมล
- URL             - เว็บไซต์
- Phone Number    - เบอร์โทร
- Social Profile  - โปรไฟล์ social media
- Netblock        - ช่วง IP range
- AS Number       - ASN
```

---

## 2. Maltego Transforms {#transforms}

### Common Transform Categories

```
Domain Transforms:
- To DNS Name [AXFR Zone Transfer]
- To Email Address [WHOIS]
- To IP Address [DNS Lookup]
- To Maltego Graph
- To Website [DNS Lookup]

IP Address Transforms:
- To DNS Name [Reverse DNS]
- To Netblock [ARIN]
- To Organization [ARIN/RIPE]
- To City/Country [GeoIP]

Email Transforms:
- To Person [OSINT]
- To Social Network [Pipl]
- To Phone [Hunter.io]

Person Transforms:
- To Email Address
- To Phone
- To Social Profile
- To Organization
```

### Transform Hubs

```
Free Transform Hubs:
- Maltego Public Servers
- AlienVault OTX
- VirusTotal
- Shodan (free tier)
- Have I Been Pwned
- DNS brute force

Paid Transform Hubs:
- ThreatCrowd
- RiskIQ PassiveTotal
- Pipl
- Hunter.io
- Recorded Future
```

---

## 3. Maltego Community Edition {#community}

### การใช้ Maltego สำหรับ Domain Recon

```
# Step-by-step:

1. Open Maltego
2. New Graph
3. Drag Domain entity
4. Enter: example.com

5. Right-click domain entity
6. "Run All Transforms"

# หรือเลือก transforms เฉพาะ:

All Transforms -> เรียกทุก transform
To DNS Name [AXFR] -> ทดสอบ zone transfer
To Email Address [WHOIS] -> หา email จาก WHOIS
To IP Address -> DNS A record
To Website -> HTTP headers

# ผลลัพธ์: Graph แสดงความเชื่อมโยง
# domain -> subdomains -> IP ranges -> organizations
```

### Export Results

```
File -> Export Graph -> เลือก format:
- .mtgx (Maltego format)
- .csv (spreadsheet)
- PDF report
- Image

# Command line export (script)
# Maltego มี API สำหรับ automation
```

---

## 4. Recon-ng Overview {#recon-ng}

**Recon-ng** คือ web reconnaissance framework คล้ายกับ Metasploit แต่เน้น OSINT

```bash
# ติดตั้ง
apt install recon-ng -y

# เริ่มใช้งาน
recon-ng

# เป็น interactive shell:
[recon-ng][default] >
```

### คำสั่งพื้นฐาน

```bash
# จัดการ workspaces
workspaces create target_com
workspaces list
workspaces select target_com

# แสดงสถานะ
show
show domains
show hosts
show emails
show contacts

# เพิ่มข้อมูล
db insert domains example.com
db insert hosts example.com
db insert emails admin@example.com

# Dashboard overview
dashboard

# Help
help
help <command>
```

---

## 5. Recon-ng Modules {#modules}

### การจัดการ Modules

```bash
# ค้นหา modules
marketplace search
marketplace search dns
marketplace search email
marketplace search domain

# ติดตั้ง modules
marketplace install recon/domains-hosts/google_site_web
marketplace install all  # ติดตั้งทั้งหมด

# โหลด module
modules load recon/domains-hosts/google_site_web

# ดูตัวเลือก
show options
options set SOURCE example.com
run
```

### Module Categories

```
Categories:
1. recon/       - เก็บข้อมูล
   - domains-contacts
   - domains-credentials
   - domains-hosts
   - hosts-hosts
   - contacts-contacts
2. discovery/   - ค้นหาสิ่งใหม่
3. exploitation/ - ยึงตัว
4. import/      - นำเข้าข้อมูล
5. reporting/   - สร้างรายงาน
```

### สำคัญ Modules

```bash
# Domain -> Hosts
marketplace install recon/domains-hosts/brute_hosts
modules load recon/domains-hosts/brute_hosts
options set SOURCE example.com
run

# Domain -> Contacts (WHOIS)
marketplace install recon/domains-contacts/whois_pocs
modules load recon/domains-contacts/whois_pocs
options set SOURCE example.com
run

# Hosts -> Resolve IPs
marketplace install recon/hosts-hosts/resolve
modules load recon/hosts-hosts/resolve
run

# Contacts -> Breach check
marketplace install recon/contacts-credentials/hibp_breach
modules load recon/contacts-credentials/hibp_breach
run

# Ports scan
marketplace install discovery/info_disclosure/cache_snoop

# Shodan lookup
marketplace install recon/hosts-hosts/shodan_ip
keys add shodan_api YOUR_SHODAN_KEY
modules load recon/hosts-hosts/shodan_ip
run
```

---

## 6. Recon-ng Workflow {#workflow}

### สมบูรณ์ Workflow

```bash
# Step 1: เริ่ม workspace ใหม่
workspaces create target_org

# Step 2: เพิ่ม seed data
db insert domains target.com

# Step 3: Domain -> Hosts (passive)
modules load recon/domains-hosts/google_site_web
options set SOURCE target.com
run

modules load recon/domains-hosts/bing_domain_web
options set SOURCE target.com
run

# Step 4: Brute force subdomains
modules load recon/domains-hosts/brute_hosts
options set SOURCE target.com
options set WORDLIST /usr/share/wordlists/dns/subdomains-top1million-20000.txt
run

# Step 5: Resolve hosts -> IPs
modules load recon/hosts-hosts/resolve
run

# Step 6: IP -> Reverse DNS
modules load recon/hosts-hosts/reverse_resolve
run

# Step 7: หา contacts/emails
modules load recon/domains-contacts/whois_pocs
options set SOURCE target.com
run

# Step 8: Check breaches
modules load recon/contacts-credentials/hibp_breach
run

# Step 9: ดูผลลัพธ์
show hosts
show contacts
show credentials

# Step 10: Export report
modules load reporting/html
options set FILENAME /tmp/report.html
options set CREATOR "Security Team"
options set CUSTOMER "Target Organization"
run
```

### API Keys Configuration

```bash
# เพิ่ม API keys
keys list
keys add shodan_api YOUR_KEY
keys add bing_api YOUR_KEY
keys add google_api YOUR_KEY
keys add google_cse YOUR_KEY
keys add virustotal_api YOUR_KEY
keys add hibp_api YOUR_KEY
keys add hunter_api YOUR_KEY

# ลบ key
keys remove shodan_api

# Keys ที่สำคัญ:
# Shodan: https://account.shodan.io
# Bing: https://azure.microsoft.com/cognitive-services
# VirusTotal: https://www.virustotal.com/gui/my-apikey
# Hunter: https://hunter.io/api-keys
```

---

## 7. Custom Reports {#reports}

### Recon-ng HTML Report

```bash
# Report modules
modules load reporting/html
options set FILENAME /tmp/recon_report.html
options set CREATOR "Penetration Testing Team"
options set CUSTOMER "Example Corp"
run

# CSV export
modules load reporting/csv
options set FILENAME /tmp/hosts.csv
options set TABLE hosts
run

# JSON export
modules load reporting/json
options set FILENAME /tmp/data.json
options set TABLE hosts
run

# XML export
modules load reporting/xml
options set FILENAME /tmp/data.xml
run
```

### Python สร้าง Custom Report

```python
#!/usr/bin/env python3
import sqlite3
import json
from datetime import datetime

def read_recon_db(workspace_name):
    """Read Recon-ng database"""
    import os
    db_path = os.path.expanduser(f'~/.recon-ng/workspaces/{workspace_name}/{workspace_name}.db')
    
    if not os.path.exists(db_path):
        print(f'[-] Database not found: {db_path}')
        return None
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def generate_report(workspace_name):
    conn = read_recon_db(workspace_name)
    if not conn:
        return
    
    cursor = conn.cursor()
    data = {}
    
    # Get all tables
    tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    
    for table in tables:
        table_name = table['name']
        rows = cursor.execute(f'SELECT * FROM {table_name}').fetchall()
        data[table_name] = [dict(row) for row in rows]
    
    # Summary
    print(f'\n===== RECON REPORT: {workspace_name} =====')
    print(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print()
    
    for table, rows in data.items():
        if rows:
            print(f'{table.upper()} ({len(rows)} records):')
            for row in rows[:5]:  # Top 5
                print(f'  {dict(row)}')
            if len(rows) > 5:
                print(f'  ... and {len(rows)-5} more')
            print()
    
    # Save JSON
    with open(f'/tmp/{workspace_name}_report.json', 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print(f'[+] JSON report saved to /tmp/{workspace_name}_report.json')
    
    conn.close()

# Usage
# generate_report('target_com')
```

---

## 8. แบบฝึกหัด {#exercises}

### Lab 1: Recon-ng Full Scan
1. สร้าง workspace ใหม่
2. เพิ่ม domain seed
3. Run modules: google, bing, brute_hosts
4. Resolve IPs
5. หา contacts จาก WHOIS
6. Export HTML report

### Lab 2: Maltego Visual Map
1. Open Maltego
2. เพิ่ม domain entity
3. Run transforms
4. Map relationships
5. Export graph

### Lab 3: API Integration
1. สมัคร Shodan API (free)
2. เพิ่มใน Recon-ng
3. Run shodan_ip module
4. วิเคราะห์ผลลัพธ์

---

## สรุป

| Tool | จุดเด่น |
|------|--------|
| Maltego | Visual relationship mapping |
| Recon-ng | Modular, automated, database |

**เหมาะสำหรับ**: Domain recon, email harvesting, relationship mapping ก่อนทำ active scanning

---
*Part 15/100+ | Kali Linux Penetration Testing Course*
