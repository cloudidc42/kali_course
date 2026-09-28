# Part 16: Passive Reconnaissance
## การสืบค้นเป้าหมายโดยไม่บอกให้รู้

---

## สารบัญ
1. [Passive vs Active Recon](#comparison)
2. [WHOIS ลึกซึ้ง](#whois)
3. [DNS Passive Techniques](#dns)
4. [Web Archive & Cache](#archive)
5. [Code Repositories](#code)
6. [Job Listings Intelligence](#jobs)
7. [Network Intelligence](#network)
8. [Automated Passive Recon](#automation)
9. [แบบฝึกหัด](#exercises)

---

## 1. Passive vs Active Recon {#comparison}

```
Passive Reconnaissance:
- ไม่ติดต่อเป้าหมายโดยตรง
- ไม่มี traffic ไปยัง target network
- ใช้แหล่งข้อมูลสาธารณะ
- ช้ากว่า active
- ถูกกฎหมาย
- ตรวจจับยาก

Active Reconnaissance:
- ติดต่อเป้าหมายโดยตรง
- ส่ง packets/requests
- รวดเร็วกว่า
- ตรวจจับได้ง่ายกว่า
- ต้องได้รับอนุญาตเสมอ
```

---

## 2. WHOIS ลึกซึ้ง {#whois}

### ค้นหาข้อมูลจาก WHOIS

```bash
# โครงสร้างข้อมูลใน WHOIS
# - Registrar: ผู้ผ่านการจดทะเบียน domain
# - Registrant: เจ้าของ domain
# - Admin/Tech contacts: email, phone, address
# - Creation/Expiry dates
# - Name servers

whois example.com
whois example.com | egrep -i 'registrant|admin|tech|email|phone|org|name server'

# WHOIS IP
whois 93.184.216.34
whois 93.184.216.34 | grep -i 'org\|isp\|country\|cidr'

# ARIN/RIPE/APNIC
curl https://whois.arin.net/rest/ip/93.184.216.34.json | python3 -m json.tool

# หา domains ของ registrant คนเดียวกัน
# (Privacy protection ส่วนใหญ่ซ่อนแล้ว)
# แต่ผู้ใช้ส่วนตัวอาจยังมีข้อมูลอยู่
bash -c 'host -t ns example.com && whois example.com | grep Name'
```

### Historical WHOIS

```bash
# DomainTools (paid) - historical WHOIS
# WhoisFreaks (free tier)
curl 'https://api.whoisfreaks.com/v1.0/whois?apiKey=FREE&whois=historical&domainName=example.com'

# viewdns.info
curl 'https://api.viewdns.info/whoishistory/?domain=example.com&apikey=FREE&output=json'

# หานิยาย
# Privacy protection อาจเพิ่งใช้ภายหลัง - historical records มีค่า
```

---

## 3. DNS Passive Techniques {#dns}

### Passive DNS

```bash
# Passive DNS - ดูประวัติ DNS resolutions
# โดยไม่ต้อง query target

# VirusTotal Passive DNS
curl -H 'x-apikey: YOUR_VT_KEY' \
    'https://www.virustotal.com/api/v3/domains/example.com/resolutions'

# Robtex
curl 'https://freeapi.robtex.com/pdns/forward/example.com'

# SecurityTrails
curl -H 'APIKEY: YOUR_KEY' \
    'https://api.securitytrails.com/v1/domain/example.com/dns'

# AlienVault OTX
curl 'https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns'

# RiskIQ PassiveTotal (paid)
curl -H 'Authorization: Bearer TOKEN' \
    'https://api.passivetotal.org/v2/dns/passive?query=example.com'
```

### DNS History สำหรับค้นหา Real IP (behind CDN)

```bash
# target.com อาจอยู่หลัง Cloudflare
# Passive DNS อาจเผย real IP จากแฟ้มก่อนเปลี่ยนไปใช้ CDN

# เทคนิคอื่นๆ:
# 1. MX records อาจชี้ไปยัง real IP
dig example.com MX
# mail.example.com -> IP ไม่ได้อยู่หลัง CDN

# 2. SPF record ชี้ mail server
dig example.com TXT | grep spf
# v=spf1 ip4:1.2.3.4 -> real IP

# 3. Subdomain ที่ไม่ได้ป้องกัน
dig dev.example.com   # dev subdomain อาจมี real IP
dig staging.example.com
dig internal.example.com
```

### Certificate Transparency Passive

```bash
# crt.sh - no API needed
curl -s 'https://crt.sh/?q=example.com&output=json' | \
    python3 -c "
import json,sys
for c in json.load(sys.stdin):
    for d in c['name_value'].split('\n'):
        print(d.strip())
" | sort -u | grep -v '^\*'

# Google Certificate Search
curl -s 'https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=false&include_subdomains=true&domain=example.com' | \
    python3 -m json.tool
```

---

## 4. Web Archive & Cache {#archive}

### Wayback Machine

```bash
# ดูประวัติเว็บไซต์
curl 'https://archive.org/wayback/available?url=example.com'

# ดึงรายการ snapshots
curl 'http://web.archive.org/cdx/search/cdx?url=example.com/*&output=text&limit=100&fl=original'

# Python Wayback
python3 << 'EOF'
import requests

def get_wayback_urls(domain):
    url = f'http://web.archive.org/cdx/search/cdx'
    params = {
        'url': f'{domain}/*',
        'output': 'json',
        'limit': 1000,
        'fl': 'original,statuscode,timestamp',
        'filter': 'statuscode:200'
    }
    
    r = requests.get(url, params=params)
    data = r.json()
    
    if len(data) < 2:
        return []
    
    return data[1:]  # Skip header

urls = get_wayback_urls('example.com')
print(f'Found {len(urls)} URLs')
for u in urls[:20]:
    print(u[0])  # original URL
EOF

# หา sensitive files จาก archive
curl 'http://web.archive.org/cdx/search/cdx?url=example.com/*.php&output=text&fl=original' | sort -u
curl 'http://web.archive.org/cdx/search/cdx?url=example.com/*.bak&output=text&fl=original' | sort -u
curl 'http://web.archive.org/cdx/search/cdx?url=example.com/*.config&output=text&fl=original' | sort -u
```

---

## 5. Code Repositories {#code}

### GitHub Intelligence

```bash
# ค้นหาบน GitHub

# 1. ค้นหาองค์กร/project
# https://github.com/search?q=example.com&type=repositories

# 2. GitHub Search API
curl -H 'Accept: application/vnd.github.v3+json' \
    'https://api.github.com/search/code?q=example.com+password'

curl -H 'Authorization: token YOUR_TOKEN' \
    'https://api.github.com/search/code?q=org:TargetOrg+password'

# 3. ค้นหา leaks
# https://github.com/search?q=example.com+"api_key"&type=code
# https://github.com/search?q=example.com+password&type=code
# https://github.com/search?q="@example.com"+password&type=code

# 4. GitLeaks - scan for secrets
git clone https://github.com/gitleaks/gitleaks
cd gitleaks
make build
./gitleaks detect --source . --report-path gitleaks-report.json

# สำหรับ target repository
git clone https://github.com/target/repo
cd repo
gitleaks detect --source . --report-path gitleaks-report.json

# หรือใช้ trufflehog
pip3 install trufflehog
trufflehog github --repo=https://github.com/target/repo
trufflehog git https://github.com/target/repo
```

### Pastebin และ Code Sites

```bash
# ค้นหาใน Pastebin
# Google: site:pastebin.com "example.com"
# Google: site:pastebin.com "@example.com"

# Pasted.co, pastbin.com, hastebin.com
# SourceForge, BitBucket, GitLab

# ค้นหาบน pastebin ด้วย Python
python3 << 'EOF'
import requests
from bs4 import BeautifulSoup

def search_pastebin(query):
    # Use Google to search pastebin
    google_url = f'https://www.google.com/search?q=site:pastebin.com+"{query}"'
    headers = {'User-Agent': 'Mozilla/5.0'}
    r = requests.get(google_url, headers=headers)
    soup = BeautifulSoup(r.text, 'html.parser')
    
    results = []
    for a in soup.find_all('a', href=True):
        if 'pastebin.com' in a['href']:
            results.append(a['href'])
    
    return results

results = search_pastebin('example.com password')
for r in results[:10]:
    print(r)
EOF
```

---

## 6. Job Listings Intelligence {#jobs}

### วิเคราะห์ Job Postings

```bash
# Job listings เปิดเผยเทคโนโลยี
# ตัวอย่าง: "We use AWS, Docker, Jenkins, Java Spring Boot"

# ค้นหา
# Google: site:linkedin.com/jobs "example company" Java
# Google: site:indeed.com "example company" security

# LinkedIn Jobs search
curl -s 'https://www.linkedin.com/jobs/search?keywords=example+company&f_C=COMPANY_ID'

# สิ่งที่หาได้:
# Tech stack (Java, Python, AWS, GCP, Azure)
# อุปกรณ์ security (Palo Alto, Fortinet, CrowdStrike)
# โครงสร้างทีม (5 pentesters, 10 developers)
# Salary ranges (บอกความสำคัญ)
# Office location
```

### OSINT จาก Job Posts

```python
#!/usr/bin/env python3
# Analyze job listings for tech intel

from collections import Counter
import re

# Tech keywords to look for
TECH_KEYWORDS = {
    'languages': ['python', 'java', 'javascript', 'c#', '.net', 'go', 'ruby', 'php', 'perl'],
    'frameworks': ['spring', 'django', 'flask', 'angular', 'react', 'node.js', 'express'],
    'databases': ['mysql', 'postgresql', 'oracle', 'mongodb', 'redis', 'elasticsearch'],
    'cloud': ['aws', 'azure', 'gcp', 'kubernetes', 'docker', 'terraform'],
    'security': ['palo alto', 'crowdstrike', 'splunk', 'qradar', 'rapid7', 'qualys'],
    'networking': ['cisco', 'juniper', 'fortinet', 'f5', 'palo alto'],
    'os': ['windows server', 'rhel', 'ubuntu', 'centos'],
    'ad': ['active directory', 'ldap', 'kerberos', 'azure ad', 'okta'],
}

def analyze_job(text):
    findings = {}
    text_lower = text.lower()
    
    for category, keywords in TECH_KEYWORDS.items():
        found = [k for k in keywords if k in text_lower]
        if found:
            findings[category] = found
    
    return findings

# ตัวอย่าง
job_text = """
We are looking for a Senior DevOps Engineer.
Requirements:
- AWS, Azure, or GCP experience
- Docker and Kubernetes
- Python or Go scripting
- MySQL, PostgreSQL, Redis
- CI/CD with Jenkins, GitLab
- Active Directory administration
"""

results = analyze_job(job_text)
for category, techs in results.items():
    print(f"{category}: {', '.join(techs)}")
```

---

## 7. Network Intelligence {#network}

### BGP และ ASN

```bash
# หา ASN ของ organization
curl 'https://api.bgpview.io/search?query_term=Example+Corp'
curl 'https://api.bgpview.io/asn/15169'  # Google's ASN

# หา IP rangesจาก ASN
curl 'https://api.bgpview.io/asn/15169/prefixes'

# Hurricane Electric BGP Toolkit
# https://bgp.he.net/
# https://bgp.he.net/AS15169

# RIPE NCC
curl 'https://rest.db.ripe.net/search?query-string=Example+Corp&type-filter=organisation'

# ARIN
curl 'https://whois.arin.net/rest/org/GOOGL/nets'

# เหล่านี้ยังใช้ passive (query external APIs)
# ไม่ติดต่อ target
```

### Threat Intelligence Feeds

```bash
# VirusTotal
curl -H 'x-apikey: YOUR_KEY' \
    'https://www.virustotal.com/api/v3/domains/example.com'

# AlienVault OTX
curl 'https://otx.alienvault.com/api/v1/indicators/domain/example.com/general'

# URLhaus
curl 'https://urlhaus-api.abuse.ch/v1/host/' \
    -d 'host=example.com'

# AbuseIPDB
curl -G 'https://api.abuseipdb.com/api/v2/check' \
    --data-urlencode 'ipAddress=93.184.216.34' \
    -H 'Key: YOUR_KEY' \
    -H 'Accept: application/json'

# Threat Intel ช่วย:
# - รู้ว่า IP/domain เคย malicious ไหม
# - หา C2 servers
# - รู้ reputation
```

---

## 8. Automated Passive Recon {#automation}

### All-in-One Passive Recon Script

```python
#!/usr/bin/env python3
# passive_recon.py

import requests
import subprocess
import json
import os
from datetime import datetime

class PassiveRecon:
    def __init__(self, target):
        self.target = target
        self.output = f'passive_recon_{target}_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        os.makedirs(self.output, exist_ok=True)
        self.data = {}
    
    def run_command(self, cmd):
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout
    
    def whois_lookup(self):
        print('[*] WHOIS lookup...')
        output = self.run_command(f'whois {self.target}')
        self.data['whois'] = output
        self._save('whois.txt', output)
    
    def dns_records(self):
        print('[*] DNS records...')
        records = {}
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
            output = self.run_command(f'dig {self.target} {rtype} +short')
            records[rtype] = output.strip().split('\n') if output.strip() else []
        self.data['dns'] = records
        self._save('dns.json', json.dumps(records, indent=2))
    
    def certificate_search(self):
        print('[*] Certificate transparency...')
        try:
            r = requests.get(
                f'https://crt.sh/?q=%25.{self.target}&output=json',
                timeout=15
            )
            domains = set()
            for cert in r.json():
                for d in cert.get('name_value', '').split('\n'):
                    d = d.strip()
                    if d and not d.startswith('*'):
                        domains.add(d)
            self.data['cert_domains'] = list(domains)
            self._save('cert_domains.txt', '\n'.join(sorted(domains)))
            print(f'  [+] Found {len(domains)} domains from certs')
        except Exception as e:
            print(f'  [-] Error: {e}')
    
    def wayback_urls(self):
        print('[*] Wayback Machine...')
        try:
            r = requests.get(
                f'http://web.archive.org/cdx/search/cdx?url={self.target}/*&output=json&limit=200&fl=original&filter=statuscode:200',
                timeout=30
            )
            data = r.json()
            urls = [row[0] for row in data[1:]] if len(data) > 1 else []
            self.data['wayback_urls'] = urls
            self._save('wayback_urls.txt', '\n'.join(urls))
            print(f'  [+] Found {len(urls)} archived URLs')
        except Exception as e:
            print(f'  [-] Error: {e}')
    
    def _save(self, filename, content):
        with open(os.path.join(self.output, filename), 'w') as f:
            f.write(content)
    
    def generate_summary(self):
        print(f'\n===== PASSIVE RECON SUMMARY: {self.target} =====')
        
        if 'dns' in self.data:
            dns = self.data['dns']
            print(f"\nA records: {dns.get('A', [])}")
            print(f"MX records: {dns.get('MX', [])}")
            print(f"NS records: {dns.get('NS', [])}")
        
        if 'cert_domains' in self.data:
            print(f"\nSubdomains from certs: {len(self.data['cert_domains'])}")
            for d in self.data['cert_domains'][:5]:
                print(f'  - {d}')
        
        if 'wayback_urls' in self.data:
            print(f"\nArchived URLs: {len(self.data['wayback_urls'])}")
        
        print(f"\n[+] Results saved to: {self.output}/")
    
    def run_all(self):
        self.whois_lookup()
        self.dns_records()
        self.certificate_search()
        self.wayback_urls()
        self.generate_summary()

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <domain>')
        sys.exit(1)
    
    recon = PassiveRecon(sys.argv[1])
    recon.run_all()
```

---

## 9. แบบฝึกหัด {#exercises}

### Lab 1: Passive Recon เต็มรูปแบบ
1. เลือก domain สาธารณะ
2. WHOIS lookup
3. DNS records
4. Certificate transparency
5. Wayback URLs
6. Passive DNS history
7. สรุปผลลัพธ์

### Lab 2: CDN Bypass
1. เลือกเว็บที่ใช้ Cloudflare
2. สืบหา real IP
3. VirusTotal passive DNS
4. Historical WHOIS
5. Certificate transparency

---

## สรุป

| เทคนิค | แหล่ง |
|-------|-------|
| WHOIS | ARIN, RIPE, APNIC |
| Passive DNS | VirusTotal, Robtex, OTX |
| Archive | Wayback Machine |
| Certs | crt.sh, Censys |
| Code | GitHub, GitLeaks |
| Jobs | LinkedIn, Indeed |

**Passive recon** รวบรวมข้อมูลได้มากโดยไม่ต้องเสี่ยงถูกตรวจจับ!

---
*Part 16/100+ | Kali Linux Penetration Testing Course*
