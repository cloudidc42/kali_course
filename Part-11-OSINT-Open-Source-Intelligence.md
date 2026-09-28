# Part 11: OSINT - Open Source Intelligence
## การสืบค้นข้อมูลจากแหล่งสาธารณะ

---

## สารบัญ
1. [OSINT คืออะไร](#intro)
2. [OSINT Framework](#framework)
3. [Domain & IP Intelligence](#domain-ip)
4. [Email OSINT](#email)
5. [People Search](#people)
6. [Social Media OSINT](#social)
7. [Company Intelligence](#company)
8. [Geolocation OSINT](#geo)
9. [Tools & Automation](#tools)
10. [แบบฝึกหัด](#exercises)

---

## 1. OSINT คืออะไร {#intro}

**OSINT (Open Source Intelligence)** คือการเก็บรวบรวมและวิเคราะห์ข้อมูลจากแหล่งข้อมูลสาธารณะ เช่น Internet, สื่อสังคม, เว็บไซต์ทางการ

### ทำไม OSINT ถึงสำคัญ?
- **Passive Reconnaissance**: ไม่ต้องสัมผัสเป้าหมายโดยตรง
- **Legal & Ethical**: ข้อมูลสาธารณะ ไม่ผิดกฎหมาย
- **Valuable Intel**: ได้ข้อมูลที่มีคุณค่าก่อนเริ่ม active scan
- **Attack Surface Mapping**: เห็นภาพรวมของเป้าหมาย

### OSINT Lifecycle
```
1. Requirements  -> กำหนดเป้าหมาย OSINT
2. Collection    -> เก็บข้อมูลจากแหล่งต่างๆ
3. Processing   -> จัดเรียงและกรองข้อมูล
4. Analysis     -> วิเคราะห์หาความสัมพันธ์
5. Reporting    -> สรุปและรายงาน
```

---

## 2. OSINT Framework {#framework}

### หมวดหมู่ข้อมูล OSINT

| หมวด | แหล่งข้อมูล |
|------|-------------|
| Domain/DNS | WHOIS, DNS records, Shodan |
| Email | Hunter.io, Phonebook.cz |
| People | LinkedIn, Facebook, Pipl |
| Company | Crunchbase, LinkedIn, SEC |
| Social Media | Twitter, Instagram, Facebook |
| Location | Google Maps, Geosocial Footprint |
| Documents | Google Dorking, Pastebin |
| Credentials | HaveIBeenPwned, Dehashed |

### OSINT Tools Map
```
OSINT
├── Domain Intelligence
│   ├── WHOIS
│   ├── DNS Recon
│   ├── Shodan/Censys
│   └── Certificate Transparency
├── Email Intelligence  
│   ├── Hunter.io
│   ├── theHarvester
│   └── Email permutations
├── People OSINT
│   ├── LinkedIn OSINT
│   ├── Social media search
│   └── Username enumeration
└── Technical OSINT
    ├── GitHub
    ├── Pastebin leaks
    └── Dark web monitoring
```

---

## 3. Domain & IP Intelligence {#domain-ip}

### WHOIS Lookup

```bash
# ข้อมูล domain registration
whois example.com
whois 192.168.1.1

# WHOIS พร้อม output ที่สะอาด
whois example.com | grep -E 'Name|Organization|Registrant|Email|Phone|Date'

# ผลลัพธ์ที่คาดว่าจะได้:
# Domain Name: EXAMPLE.COM
# Registrant Organization: Internet Assigned Numbers Authority
# Registrant Email: noreply@iana.org
# Creation Date: 1992-01-01
# Updated Date: 2023-08-14
```

### DNS Enumeration

```bash
# ดู DNS records ทั้งหมด
dig example.com ANY +noall +answer
dig example.com A       # IPv4 address
dig example.com AAAA    # IPv6 address
dig example.com MX      # Mail servers
dig example.com NS      # Name servers
dig example.com TXT     # Text records (SPF, DKIM)
dig example.com SOA     # Start of Authority
dig example.com CNAME   # Canonical name

# ใช้ nslookup
nslookup example.com
nslookup -type=MX example.com
nslookup -type=NS example.com

# Reverse DNS lookup
dig -x 93.184.216.34
nslookup 93.184.216.34

# Zone transfer (ถ้าอนุญาต)
dig @ns1.example.com example.com AXFR
host -t axfr example.com ns1.example.com
```

### Subdomain Enumeration

```bash
# dnsenum - passive + active
dnsenum --dnsserver 8.8.8.8 --enum -p 0 -s 0 example.com

# sublist3r - passive subdomain
sublist3r -d example.com -o subdomains.txt
sublist3r -d example.com -b -p 80,443  # Brute force

# amass - comprehensive
amass enum -d example.com -passive
amass enum -d example.com -active
amass enum -d example.com -brute -w /usr/share/wordlists/amass/all.txt

# subfinder - fast passive
subfinder -d example.com
subfinder -d example.com -o subs.txt

# fierce - DNS brute force
fierce --domain example.com
fierce --domain example.com --subdomains /usr/share/fierce/hosts.txt

# massdns - ultra-fast DNS resolver
massdns -r resolvers.txt -t A -o S subdomains.txt

# gobuster DNS mode
gobuster dns -d example.com -w /usr/share/wordlists/dns/subdomains-top1million-20000.txt

# dnsx - validate subdomains
cat subdomains.txt | dnsx -a -resp
```

### IP Range Research

```bash
# หา IP range ของ organization
whois -h whois.arin.net 'n + 192.0.2.0'

# BGP routing information
curl https://bgp.he.net/ip/93.184.216.34  # Hurricane Electric

# ASN lookup
whois -h whois.radb.net AS15169  # Google's ASN

# Reverse DNS ของ IP range
for i in $(seq 1 254); do
    host 192.168.1.$i 2>/dev/null | grep 'domain name pointer'
done

# shodan (ต้องมี API key)
shodan host 93.184.216.34
shodan search 'org:"Example Corporation" port:22'
```

### Certificate Transparency

```bash
# ค้นหา subdomains จาก SSL certificates
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | \
    python3 -c "import json,sys; [print(e['name_value']) for e in json.load(sys.stdin)]" | \
    sort -u

# certificate transparency ด้วย certspotter
curl -s 'https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names' | \
    python3 -m json.tool

# คำสั่ง crtsh ด้วย Python
python3 -c "
import requests, json
r = requests.get('https://crt.sh/?q=%25.example.com&output=json')
for cert in r.json():
    for domain in cert['name_value'].split('\\n'):
        print(domain.strip())
" | sort -u
```

---

## 4. Email OSINT {#email}

### หา Email Addresses

```bash
# theHarvester - Email + subdomain harvester
theHarvester -d example.com -l 500 -b google
theHarvester -d example.com -l 500 -b linkedin
theHarvester -d example.com -l 500 -b all

# เก็บผลลัพธ์
theHarvester -d example.com -b all -f output.html

# EmailHarvester
pip3 install EmailHarvester
EmailHarvester -d example.com

# Hunter.io API
curl -s 'https://api.hunter.io/v2/domain-search?domain=example.com&api_key=YOUR_API_KEY' | \
    python3 -m json.tool
```

### Email Format Generation

```bash
# สร้าง email permutations
# ถ้ารู้ชื่อ: John Smith ที่ example.com
# ลองรูปแบบ:
# john@example.com
# jsmith@example.com
# john.smith@example.com
# johnsmith@example.com
# j.smith@example.com
# smith.john@example.com

# สร้างอัตโนมัติด้วย Python
python3 << 'EOF'
first = 'john'
last = 'smith'
domain = 'example.com'

patterns = [
    f"{first}@{domain}",
    f"{last}@{domain}",
    f"{first[0]}{last}@{domain}",
    f"{first}.{last}@{domain}",
    f"{first}_{last}@{domain}",
    f"{first}{last}@{domain}",
    f"{last}.{first}@{domain}",
    f"{last}{first[0]}@{domain}",
    f"{first[0]}.{last}@{domain}",
]

for email in patterns:
    print(email)
EOF
```

### Email Verification

```bash
# ตรวจสอบ email validity
swaks --to target@example.com --server mail.example.com --quit-after RCPT

# Python email check
python3 << 'EOF'
import socket
import smtplib

def verify_email(email):
    domain = email.split('@')[1]
    
    # หา MX records
    import subprocess
    result = subprocess.run(['dig', '+short', 'MX', domain], 
                         capture_output=True, text=True)
    mx_records = result.stdout.strip().split('\n')
    
    if not mx_records or not mx_records[0]:
        return False, 'No MX records'
    
    # เชื่อมต่อกับ SMTP
    mx_host = mx_records[0].split()[-1].rstrip('.')
    
    try:
        with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
            smtp.ehlo('test.com')
            code, msg = smtp.verify(email)
            return code == 250, msg.decode()
    except Exception as e:
        return None, str(e)

result, message = verify_email('test@example.com')
print(f'Valid: {result} - {message}')
EOF

# Check breach databases
curl -s 'https://haveibeenpwned.com/api/v3/breachedaccount/target@example.com' \
    -H 'hibp-api-key: YOUR_KEY'
```

---

## 5. People Search {#people}

### LinkedIn OSINT

```bash
# Google dork สำหรับ LinkedIn
site:linkedin.com/in "example company"
site:linkedin.com/in "Job Title" "Company Name"

# Scrape LinkedIn profiles
# ใช้ linkedin2username
git clone https://github.com/initstring/linkedin2username
cd linkedin2username
python3 linkedin2username.py -u myemail@gmail.com -c 'Company Name'

# ผลลัพธ์: username list สำหรับ password spraying
```

### Username OSINT

```bash
# Sherlock - หา username ทั่ว social media
pip3 install sherlock-project
sherlock username123

# WhatsMyName
git clone https://github.com/WebBreacher/WhatsMyName
cd WhatsMyName
python3 whats-my-name.py -u username123

# Maigret - comprehensive
pip3 install maigret
maigret username123

# ตัวอย่างผลลัพธ์:
# [+] Twitter: https://twitter.com/username123
# [+] Instagram: https://instagram.com/username123
# [+] GitHub: https://github.com/username123
```

### Phone Number OSINT

```bash
# PhoneInfoga
pip3 install phoneinfoga
phoneinfoga scan -n +1234567890
phoneinfoga serve  # Web UI

# Carrier lookup
curl 'https://api.telnyx.com/v2/number_lookup/+1234567890'

# Truecaller (manual)
# เปิด https://www.truecaller.com/search/th/0812345678
```

---

## 6. Social Media OSINT {#social}

### Twitter/X OSINT

```bash
# twint - Twitter OSINT (no API)
pip3 install twint

# Search tweets
twint -u username --tweets
twint -s "keyword" --since 2023-01-01 --until 2023-12-31
twint -u username --email --phone  # หา contact info
twint -u username --followers      # หา followers
twint -u username --following      # หา following
twint -g "13.756,100.502,50km"    # Geo-search Bangkok

# Export
twint -u username --csv -o tweets.csv
twint -u username --json -o tweets.json
```

### Instagram OSINT

```bash
# Osintgram
git clone https://github.com/Datalux/Osintgram
cd Osintgram
pip3 install -r requirements.txt

# Interactive mode
python3 main.py target_username

# Commands:
# > info      - รายละเอียด account
# > followers - รายชื่อ followers
# > following - รายชื่อ following
# > photos    - ภาพถ่าย
# > location  - ตำแหน่งที่ post
# > hashtags  - hashtags ที่ใช้
```

### Facebook OSINT

```bash
# Facebook dorking
site:facebook.com "Company Name"
site:facebook.com/people "City" "Job"

# Lookup by ID
https://www.facebook.com/profile.php?id=100000000000

# พิมพ์ graph URL ใน browser
https://graph.facebook.com/username
```

---

## 7. Company Intelligence {#company}

### Technical Footprint

```bash
# หา subdomains ที่เกี่ยวข้อง
subfinder -d example.com
amass enum -d example.com

# หา IP ranges
whois -h whois.arin.net 'org:Example Corporation'

# Job postings -> tech stack
# https://www.linkedin.com/jobs/search/?keywords=example+company
# สังเกต: Java developer, AWS, Docker -> เดา technology stack

# DNS ดู mail/cloud providers
dig example.com MX  # mail.example.com -> Microsoft 365?
dig example.com TXT  # v=spf1 include:salesforce.com -> ใช้ Salesforce

# Shodan company search
shodan search 'org:"Example Corporation"' --fields ip_str,port,org,hostnames
```

### Document OSINT

```bash
# Google Dorking สำหรับ documents
site:example.com filetype:pdf
site:example.com filetype:docx
site:example.com filetype:xlsx

# Download และวิเคราะห์ metadata
wget -q 'https://example.com/document.pdf'
exiftool document.pdf
# Author, Creation Date, Software used

# FOCA - metadata extractor (Windows)
# Download: https://github.com/ElevenPaths/FOCA

# metagoofil - Python version
pip3 install metagoofil
metagoofil -d example.com -t pdf,docx,xlsx -l 50 -o output/
```

---

## 8. Geolocation OSINT {#geo}

### Image Geolocation

```bash
# ดู EXIF data จากรูปภาพ
exiftool photo.jpg | grep -i 'gps\|location\|lat\|lon'

# Python EXIF reader
python3 << 'EOF'
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

def get_gps(image_path):
    img = Image.open(image_path)
    exif_data = img._getexif()
    
    if not exif_data:
        return None
    
    for tag_id, value in exif_data.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == 'GPSInfo':
            gps = {}
            for key in value.keys():
                name = GPSTAGS.get(key, key)
                gps[name] = value[key]
            return gps
    return None

gps = get_gps('photo.jpg')
if gps:
    lat = gps.get('GPSLatitude')
    lon = gps.get('GPSLongitude')
    print(f'GPS: {lat}, {lon}')
EOF

# Reverse Geocoding
curl 'https://nominatim.openstreetmap.org/reverse?lat=13.756&lon=100.502&format=json'
```

### IP Geolocation

```bash
# หาตำแหน่งของ IP
curl https://ipapi.co/93.184.216.34/json/
curl https://ipinfo.io/93.184.216.34/json
curl https://freegeoip.app/json/93.184.216.34

# MaxMind GeoIP
wget https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City
geoiplookup 93.184.216.34

# ผลลัพธ์:
# {
#   "ip": "93.184.216.34",
#   "city": "Norwell",
#   "region": "Massachusetts",
#   "country": "US",
#   "org": "EDGECAST"
# }
```

---

## 9. Tools & Automation {#tools}

### Maltego

```bash
# Maltego - visual OSINT tool
# Download: https://maltego.com

# Transforms ที่มีประโยชน์:
# Domain to IP
# IP to Netblock
# Email to Person
# Phone to Social Media
# Username to Profiles

# Community Edition: ฟรี แต่จำกัด 12 nodes
# Commercial: ไม่จำกัด
```

### Recon-ng

```bash
# Recon-ng - modular web reconnaissance
recon-ng

# Basic commands
workspaces create example_pentest
workspaces select example_pentest

# Market (download modules)
modules search
marketplace search domain
marketplace install recon/domains-hosts/google_site_web

# Run module
modules load recon/domains-hosts/google_site_web
options set SOURCE example.com
run

# Popular modules:
# recon/domains-hosts/brute_hosts
# recon/hosts-hosts/resolve
# recon/domains-contacts/whois_pocs
# recon/contacts-credentials/hibp_breach
# reporting/html
```

### Spiderfoot

```bash
# SpiderFoot - automated OSINT
pip3 install spiderfoot
spiderfoot -l 127.0.0.1:5001  # Web UI

# CLI mode
spiderfoot -s example.com -t INTERNET_NAME,IP_ADDRESS -m sfp_dns,sfp_whois

# Scan types:
# -t = target types (INTERNET_NAME, EMAILADDR, USERNAME, etc)
# -m = modules to use
# -F = output formats (csv, json, html)
```

### theHarvester

```bash
# theHarvester - comprehensive harvester
theHarvester -d example.com -b all -l 500

# Sources:
# -b google, bing, yahoo, duckduckgo
# -b linkedin, twitter
# -b shodan, censys
# -b dnsdumpster, crtsh
# -b all (ทั้งหมด)

# Export
theHarvester -d example.com -b all -f output
# สร้าง output.html และ output.xml
```

### Automated OSINT Script

```python
#!/usr/bin/env python3
# osint_recon.py - Automated OSINT

import subprocess
import json
import os
from datetime import datetime

def run_command(cmd, timeout=60):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                              text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return f"Error: {e}"

class OSINTRecon:
    def __init__(self, domain):
        self.domain = domain
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"osint_{domain}_{self.timestamp}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.results = {}
    
    def whois_lookup(self):
        print(f"[*] WHOIS lookup: {self.domain}")
        output = run_command(f"whois {self.domain}")
        self.results['whois'] = output
        self._save('whois.txt', output)
    
    def dns_enum(self):
        print(f"[*] DNS enumeration: {self.domain}")
        records = {}
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
            output = run_command(f"dig {self.domain} {record_type} +short")
            records[record_type] = output.strip().split('\n')
        
        self.results['dns'] = records
        self._save('dns.json', json.dumps(records, indent=2))
    
    def subdomain_enum(self):
        print(f"[*] Subdomain enumeration: {self.domain}")
        
        # subfinder
        subs = run_command(f"subfinder -d {self.domain} -silent 2>/dev/null")
        self.results['subdomains'] = subs.strip().split('\n')
        self._save('subdomains.txt', subs)
    
    def certificate_search(self):
        print(f"[*] Certificate transparency search: {self.domain}")
        import urllib.request
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            with urllib.request.urlopen(url, timeout=10) as r:
                data = json.loads(r.read())
            domains = set()
            for cert in data:
                for d in cert.get('name_value', '').split('\n'):
                    domains.add(d.strip())
            self.results['certs'] = list(domains)
            self._save('cert_domains.txt', '\n'.join(sorted(domains)))
        except Exception as e:
            print(f"  [-] Error: {e}")
    
    def _save(self, filename, content):
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            f.write(content)
    
    def generate_report(self):
        print(f"\n[+] OSINT Report for {self.domain}")
        print("=" * 50)
        
        if 'dns' in self.results:
            dns = self.results['dns']
            print(f"\nDNS Records:")
            for rtype, records in dns.items():
                if any(r for r in records):
                    print(f"  {rtype}: {', '.join(r for r in records if r)}")
        
        if 'subdomains' in self.results:
            subs = [s for s in self.results['subdomains'] if s]
            print(f"\nSubdomains found: {len(subs)}")
            for sub in subs[:10]:
                print(f"  - {sub}")
            if len(subs) > 10:
                print(f"  ... and {len(subs)-10} more")
        
        print(f"\n[+] Results saved to: {self.output_dir}/")
    
    def run_all(self):
        self.whois_lookup()
        self.dns_enum()
        self.subdomain_enum()
        self.certificate_search()
        self.generate_report()

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)
    
    recon = OSINTRecon(sys.argv[1])
    recon.run_all()
```

---

## 10. แบบฝึกหัด {#exercises}

### Lab 1: Target Profile
เลือก domain ของบริษัท (เช่น target.com) แล้ว:
1. WHOIS lookup
2. DNS records ทั้งหมด
3. หา subdomains
4. Certificate transparency search
5. สรุปข้อมูลที่ได้

### Lab 2: Email Harvesting
1. theHarvester -d target.com -b all
2. ค้นหา email patterns
3. สร้าง employee email list
4. ตรวจสอบ breach databases

### Lab 3: Social Media OSINT
1. หาพนักงานของบริษัทบน LinkedIn
2. สร้าง username list
3. ค้นหา usernames ด้วย Sherlock
4. วิเคราะห์ social presence

---

## สรุป

| Tool | ใช้สำหรับ |
|------|----------|
| theHarvester | Email + subdomain harvesting |
| sublist3r | Subdomain enumeration |
| amass | Comprehensive DNS recon |
| Maltego | Visual OSINT mapping |
| Recon-ng | Modular OSINT framework |
| SpiderFoot | Automated OSINT |
| Sherlock | Username enumeration |

**สำคัญ**: OSINT เป็น passive recon ซึ่งถูกกฎหมาย แต่ต้องใช้ข้อมูลที่ได้อย่างมีจริยธรรม!

---
*Part 11/100+ | Kali Linux Penetration Testing Course*
