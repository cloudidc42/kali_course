# Part 20: Service Version Detection และ Fingerprinting

## สารบัญ
- [20.1 Service Detection คืออะไร](#201-service-detection-คืออะไร)
- [20.2 Banner Grabbing พื้นฐาน](#202-banner-grabbing-พื้นฐาน)
- [20.3 Nmap Service และ Version Detection](#203-nmap-service-และ-version-detection)
- [20.4 HTTP Service Fingerprinting](#204-http-service-fingerprinting)
- [20.5 SSL/TLS Fingerprinting](#205-ssltls-fingerprinting)
- [20.6 Database Service Detection](#206-database-service-detection)
- [20.7 OS Fingerprinting](#207-os-fingerprinting)
- [20.8 Python Service Scanner](#208-python-service-scanner)
- [20.9 แบบฝึกหัด Lab](#209-แบบฝึกหัด-lab)

---

## 20.1 Service Detection คืออะไร

Service Version Detection คือการระบุว่า Service ที่สแกนพบคืออะไร เวอร์ชันไหน เพื่อค้นหา CVE ที่ตรงกับ

### ทำไมถึงต้องทำ Service Detection
```
เหตุผล:
1. ระบุ Exact Version เพื่อค้นหา CVE
2. สร้าง Software Inventory
3. รู้ว่ามี Service อะไรบ้างตอนนี้
4. ค้นหา Misconfiguration
5. ระบุ Default Credentials ที่อาจใช้ได้

การทำงาน:
Port Scan → Service Detection → Version Analysis → CVE Search → Exploit
```

### Banner vs Active Detection
```
┌────────────────────────────────────────────────────┐
│  Banner Grabbing  │  Active Probing               │
├──────────────────┬─────────────────────────────────┤
│  - Connect/Read  │  - Send probe packets         │
│  - Passive        │  - Analyze responses          │
│  - Server ตอบรับ │  - Match against signatures   │
│  - อาจเป็น Fake  │  - More accurate              │
└──────────────────┴─────────────────────────────────┘
```

---

## 20.2 Banner Grabbing พื้นฐาน

### ใช้ netcat (nc)
```bash
# Banner Grabbing พื้นฐาน
nc -nv 192.168.1.100 21    # FTP
nc -nv 192.168.1.100 22    # SSH
nc -nv 192.168.1.100 25    # SMTP
nc -nv 192.168.1.100 80    # HTTP
nc -nv 192.168.1.100 110   # POP3
nc -nv 192.168.1.100 143   # IMAP
nc -nv 192.168.1.100 3306  # MySQL
nc -nv 192.168.1.100 5432  # PostgreSQL

# HTTP Banner
echo -e 'HEAD / HTTP/1.0\r\n\r\n' | nc -nv 192.168.1.100 80

# SMTP Banner
nc 192.168.1.100 25
# EHLO test.com
# QUIT
```

### ตัวอย่าง Banners
```
# FTP Banner
220 ProFTPD 1.3.5 Server (Debian) [192.168.1.100]

# SSH Banner  
SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2

# HTTP Banner
HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
...

# MySQL Banner
5.7.32-0ubuntu0.18.04.1

# SMTP Banner
220 mail.company.com ESMTP Postfix (Ubuntu)
```

### ใช้ telnet
```bash
# HTTP Banner ด้วย telnet
telnet 192.168.1.100 80
# พิมพ์:
# HEAD / HTTP/1.0
# (Enter 2 ครั้ง)

# FTP
telnet 192.168.1.100 21
# จะอ่าน Banner ทันที
```

### ใช้ curl
```bash
# HTTP Headers
curl -I http://192.168.1.100
curl -I https://192.168.1.100 -k

# Verbose - ดู Headers ทั้งหมด
curl -v http://192.168.1.100

# ดู Server Header
curl -I http://192.168.1.100 | grep -i server

# Follow Redirects
curl -IL http://192.168.1.100

# Custom Headers
curl -H 'Host: target.com' -I http://192.168.1.100
```

---

## 20.3 Nmap Service และ Version Detection

### -sV Flag
```bash
# Version Detection พื้นฐาน
nmap -sV 192.168.1.100

# เพิ่ม Intensity (0-9, default=7)
nmap -sV --version-intensity 9 192.168.1.100

# All Ports + Version
nmap -p- -sV 192.168.1.100

# ดู Light Probing เท่านั้น
nmap -sV --version-light 192.168.1.100

# สแกน All Common Ports + Version + OS
nmap -A 192.168.1.100
```

### ตัวอย่าง Output -sV
```
Nmap scan report for 192.168.1.100
Host is up (0.00044s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
25/tcp   open  smtp        Postfix smtpd
80/tcp   open  http        Apache httpd 2.4.41 ((Ubuntu))
110/tcp  open  pop3        Dovecot pop3d
143/tcp  open  imap        Dovecot imapd (Ubuntu)
443/tcp  open  ssl/http    Apache httpd 2.4.41 ((Ubuntu))
3306/tcp open  mysql       MySQL 5.7.32-0ubuntu0.18.04.1
5432/tcp open  postgresql  PostgreSQL DB 9.6.20 - 12.4
8080/tcp open  http        Apache Tomcat 9.0.41

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### วิเคราะห์ Output
```bash
# ดึงเฉพาะ Service และ Version
nmap -sV 192.168.1.100 | grep 'open' | awk '{print $1, $3, $4, $5}'

# บันทึกเป็น XML แล้ววิเคราะห์
nmap -sV -oX /tmp/scan.xml 192.168.1.100

# Python parse XML
python3 << 'EOF'
import xml.etree.ElementTree as ET
tree = ET.parse('/tmp/scan.xml')
root = tree.getroot()
for host in root.findall('.//host'):
    addr = host.find('.//address[@addrtype="ipv4"]')
    if addr is not None:
        ip = addr.get('addr')
        for port in host.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                service = port.find('service')
                portid = port.get('portid')
                name = service.get('name', '') if service is not None else ''
                version = service.get('version', '') if service is not None else ''
                print(f"{ip}:{portid}  {name}  {version}")
EOF
```

---

## 20.4 HTTP Service Fingerprinting

### whatweb - Web Technology Scanner
```bash
# ติดตั้ง
sudo apt install whatweb -y

# สแกน Website
whatweb http://192.168.1.100

# Verbose
whatweb -v http://192.168.1.100

# สแกนหลาย URLs
whatweb http://192.168.1.100 http://192.168.1.101

# Aggressive Mode
whatweb -a 3 http://192.168.1.100

# JSON Output
whatweb http://192.168.1.100 --log-json=/tmp/whatweb.json

# สแกน Network Range
whatweb 192.168.1.0/24
```

### ตัวอย่าง whatweb Output
```
http://192.168.1.100 [200 OK] 
Apache[2.4.41], 
Cookies[PHPSESSID], 
Country[RESERVED][ZZ], 
HTML5, 
HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], 
IP[192.168.1.100], 
JQuery[3.3.1], 
PHP[7.4.3],X-Powered-By[PHP/7.4.3], 
Title[Welcome], 
WordPress[5.6],
X-Frame-Options[SAMEORIGIN]
```

### httprint - HTTP Fingerprinting
```bash
# ใช้ curl ดู HTTP Headers แทน
curl -I http://192.168.1.100 2>/dev/null | head -20

# ดู Response Headers ทั้งหมด
curl -sI http://192.168.1.100
```

### HTTP Headers ที่สำคัญ
```
Server: Apache/2.4.41 (Ubuntu)    # Web Server + Version
X-Powered-By: PHP/7.4.3           # Backend Language
X-Generator: Drupal 8             # CMS
X-AspNet-Version: 4.0.30319       # ASP.NET Version
X-Frame-Options: SAMEORIGIN       # Security Header
Strict-Transport-Security: ...    # HSTS
Content-Security-Policy: ...      # CSP
X-Content-Type-Options: nosniff  # MIME Sniffing
```

### wappalyzer CLI
```bash
# ติดตั้ง
npm install -g wappalyzer

# Analyze Website
wappalyzer https://192.168.1.100
```

### Nikto - HTTP Vulnerability Scanner
```bash
# ติดตั้ง
sudo apt install nikto -y

# สแกน พื้นฐาน
nikto -h http://192.168.1.100

# ระบุ Port
nikto -h 192.168.1.100 -p 8080

# SSL
nikto -h https://192.168.1.100 -ssl

# บันทึกผล
nikto -h http://192.168.1.100 -o /tmp/nikto.txt

# Format Output
nikto -h http://192.168.1.100 -Format html -o /tmp/nikto.html
```

### ตัวอย่าง Nikto Output
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.100
+ Target Hostname:    192.168.1.100
+ Target Port:        80
+ Start Time:         2024-01-01 00:00:00 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined.
+ The X-Content-Type-Options header is not set.
+ No CGI Directories found
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54)
+ OSVDB-3268: /icons/README: Apache default file found.
+ /phpinfo.php: Outputs PHP configuration information
+ /admin/: Directory indexing found.
+ OSVDB-3092: /admin/: This might be interesting...
+ 7746 requests: 0 error(s) and 9 item(s) reported on remote host
```

---

## 20.5 SSL/TLS Fingerprinting

### sslyze - SSL/TLS Analysis
```bash
# ติดตั้ง
pip3 install sslyze

# Scan SSL/TLS
sslyze 192.168.1.100

# ดู Certificate
sslyze --certinfo 192.168.1.100

# Check Vulnerabilities
sslyze --heartbleed --robot --reneg 192.168.1.100

# Full Scan
sslyze --regular 192.168.1.100
```

### testssl.sh - Comprehensive SSL Test
```bash
# ดาวน์โหลด
git clone https://github.com/drwetter/testssl.sh
cd testssl.sh

# สแกน SSL
bash testssl.sh https://192.168.1.100

# เฉพาะ Vulnerabilities
bash testssl.sh --vulnerabilities https://192.168.1.100

# ตรวจ Cipher Suites
bash testssl.sh --cipher https://192.168.1.100
```

### Nmap SSL Scripts
```bash
# Certificate Info
nmap -sV --script ssl-cert 192.168.1.100 -p 443

# Supported Ciphers
nmap --script ssl-enum-ciphers -p 443 192.168.1.100

# Heartbleed Vulnerability
nmap --script ssl-heartbleed -p 443 192.168.1.100

# POODLE Vulnerability
nmap --script ssl-poodle -p 443 192.168.1.100

# DROWN Attack
nmap --script sslv2-drown 192.168.1.100

# All SSL Scripts
nmap --script 'ssl-*' -p 443 192.168.1.100
```

### openssl - Manual Certificate Check
```bash
# ดู Certificate
openssl s_client -connect 192.168.1.100:443 2>/dev/null | openssl x509 -noout -text

# ดู Expiry Date
openssl s_client -connect 192.168.1.100:443 2>/dev/null | openssl x509 -noout -dates

# ดู Subject และ Issuer
openssl s_client -connect 192.168.1.100:443 2>/dev/null | openssl x509 -noout -subject -issuer

# ดู SANs (Subject Alternative Names)
openssl s_client -connect 192.168.1.100:443 2>/dev/null | openssl x509 -noout -ext subjectAltName

# Test เวอร์ชัน TLS ที่ Support
openssl s_client -connect 192.168.1.100:443 -tls1    # TLS 1.0
openssl s_client -connect 192.168.1.100:443 -tls1_1  # TLS 1.1
openssl s_client -connect 192.168.1.100:443 -tls1_2  # TLS 1.2
openssl s_client -connect 192.168.1.100:443 -tls1_3  # TLS 1.3
```

---

## 20.6 Database Service Detection

### MySQL Detection
```bash
# Nmap MySQL Scripts
nmap -sV --script mysql-info,mysql-empty-password,mysql-databases -p 3306 192.168.1.100

# mysql-audit
nmap -p 3306 --script mysql-audit --script-args 'mysql-audit.username="root",mysql-audit.password=""' 192.168.1.100

# Test Anonymous Login
mysql -h 192.168.1.100 -u root --password='' -e 'show databases;'

# ดู MySQL Version
mysql -h 192.168.1.100 -u root --password='' -e 'SELECT @@version;'
```

### PostgreSQL Detection
```bash
# Nmap PostgreSQL
nmap -sV --script pgsql-brute -p 5432 192.168.1.100

# Connect
psql -h 192.168.1.100 -U postgres -c 'SELECT version();'
```

### MSSQL Detection
```bash
# Nmap MSSQL
nmap -sV --script ms-sql-info,ms-sql-config -p 1433 192.168.1.100

# ดู Instance Info
nmap -sV --script ms-sql-info 192.168.1.100

# Login
nmap --script ms-sql-empty-password 192.168.1.100
```

### MongoDB Detection
```bash
# Nmap MongoDB
nmap -sV --script mongodb-info -p 27017 192.168.1.100

# Connect (No Auth)
mongo 192.168.1.100
> show dbs
> use admin
> db.getUsers()
```

### Redis Detection
```bash
# Nmap Redis
nmap -sV --script redis-info -p 6379 192.168.1.100

# Connect (No Auth)
redis-cli -h 192.168.1.100 -p 6379
> INFO server
> CONFIG GET *
> KEYS *
```

### Elasticsearch Detection
```bash
# ค้นหา Elasticsearch
nmap -sV -p 9200,9300 192.168.1.100

# REST API
curl http://192.168.1.100:9200/_cat/indices
curl http://192.168.1.100:9200/_cluster/health
curl http://192.168.1.100:9200/_nodes
```

---

## 20.7 OS Fingerprinting

### Nmap OS Detection
```bash
# OS Detection (-O)
sudo nmap -O 192.168.1.100

# เพิ่ม Intensity
sudo nmap -O --osscan-guess 192.168.1.100

# ดู OS + Version
sudo nmap -A 192.168.1.100

# Aggressive OS Scan
nmap -O --osscan-limit 192.168.1.100
```

### ตัวอย่าง OS Detection Output
```
OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap scan report for 192.168.1.100

OS details: Linux 4.15 - 5.6
Network Distance: 1 hop

OS CPE: cpe:/o:linux:linux_kernel:4.15
OS fingerprint: ...

Nmap done: 1 IP address (1 host up) scanned in 4.23 seconds
```

### p0f - Passive OS Fingerprinting
```bash
# ติดตั้ง
sudo apt install p0f -y

# Monitor Traffic Passively
sudo p0f -i eth0

# Analyze pcap file
sudo p0f -r /tmp/capture.pcap

# Output to file
sudo p0f -i eth0 -o /tmp/p0f_log.txt
```

### TTL-based OS Detection
```
TTL = 64   : Linux/Unix/Mac OS
TTL = 128  : Windows
TTL = 255  : Cisco IOS/Solaris
TTL = 254  : Cisco IOS
```

```bash
# ดู TTL จาก Ping
ping -c 1 192.168.1.100 | grep 'ttl='

# hping3 - Custom Ping
hping3 -1 192.168.1.100 -c 1
```

---

## 20.8 Python Service Scanner

### Complete Service Fingerprinter
```python
#!/usr/bin/env python3
# service_fingerprint.py - Complete Service Fingerprinter

import socket
import ssl
import subprocess
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

BANNER_PROBES = {
    'FTP':     (b'', 3),
    'SSH':     (b'', 3),
    'SMTP':    (b'EHLO test\r\n', 3),
    'HTTP':    (b'HEAD / HTTP/1.0\r\n\r\n', 5),
    'POP3':    (b'', 3),
    'IMAP':    (b'', 3),
    'MySQL':   (b'', 3),
    'Unknown': (b'\r\n', 3),
}

SERVICE_SIGNATURES = [
    (r'SSH-2\.0-(OpenSSH_[\d.]+)', 'OpenSSH'),
    (r'ProFTPD ([\d.]+)',           'ProFTPD'),
    (r'Apache/([\.\d]+)',           'Apache'),
    (r'nginx/([\.\d]+)',            'nginx'),
    (r'IIS/([\.\d]+)',              'IIS'),
    (r'Tomcat/([\.\d]+)',           'Tomcat'),
    (r'PHP/([\.\d]+)',              'PHP'),
    (r'MySQL ([\.\d]+)',            'MySQL'),
    (r'Postfix',                    'Postfix'),
    (r'Dovecot',                    'Dovecot'),
    (r'OpenSSL ([\.\d]+)',          'OpenSSL'),
]

def grab_banner(host, port, timeout=3):
    banner = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        probe = b'HEAD / HTTP/1.0\r\n\r\n' if port in [80, 8080, 8443] else b''
        if probe:
            s.send(probe)
        data = s.recv(1024)
        banner = data.decode('utf-8', errors='ignore').strip()
        s.close()
    except Exception:
        pass
    return banner

def grab_ssl_banner(host, port, timeout=5):
    banner = ''
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # Get cert info
                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    cn = subject.get('commonName', '')
                    banner = f'SSL/TLS CN={cn}'
    except Exception as e:
        pass
    return banner

def identify_service(port, banner):
    service_name = 'unknown'
    version = ''
    
    for pattern, name in SERVICE_SIGNATURES:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            service_name = name
            try:
                version = m.group(1)
            except IndexError:
                version = ''
            break
    
    # Port-based guessing
    port_services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
        443: 'https', 445: 'smb', 3306: 'mysql', 5432: 'postgresql',
        6379: 'redis', 8080: 'http-alt', 9200: 'elasticsearch',
        27017: 'mongodb', 1433: 'mssql', 5900: 'vnc',
    }
    if service_name == 'unknown' and port in port_services:
        service_name = port_services[port]
    
    return service_name, version

def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            # เปิด Port
            if port in [443, 8443]:
                banner = grab_ssl_banner(host, port)
            else:
                banner = grab_banner(host, port)
            service, version = identify_service(port, banner)
            return {
                'port': port,
                'state': 'open',
                'service': service,
                'version': version,
                'banner': banner[:100] if banner else ''
            }
    except Exception:
        pass
    return None

def fingerprint_host(host, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 1433, 3306, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
    
    print(f"[*] Fingerprinting: {host}")
    print(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<20}{'VERSION':<20}{'BANNER':<50}")
    print("-" * 106)
    
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                print(f"{result['port']:<8}{'open':<8}{result['service']:<20}{result['version']:<20}{result['banner'][:50]}")
    
    results.sort(key=lambda x: x['port'])
    return results

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    results = fingerprint_host(target)
    
    # บันทึก JSON
    with open(f'/tmp/fingerprint_{target.replace(".","_")}.json', 'w') as f:
        json.dump({'host': target, 'services': results}, f, indent=2)
    print(f"\n[*] Saved to: /tmp/fingerprint_{target.replace('.','_')}.json")
```

### CVE Lookup Script
```python
#!/usr/bin/env python3
# cve_lookup.py - ค้นหา CVE จาก Service Version

import requests
import json

def search_cve(product, version):
    """ค้นหา CVE จาก NVD API"""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': f'{product} {version}',
        'resultsPerPage': 10,
    }
    try:
        resp = requests.get(url, params=params, timeout=10)
        data = resp.json()
        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve_id = vuln['cve']['id']
            desc = vuln['cve']['descriptions'][0]['value'][:100]
            metrics = vuln['cve'].get('metrics', {})
            score = ''
            if 'cvssMetricV31' in metrics:
                score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics:
                score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
            cves.append({'id': cve_id, 'score': score, 'desc': desc})
        return cves
    except Exception as e:
        return []

def analyze_services(services):
    print("\n[*] CVE Analysis Results")
    print("=" * 80)
    for svc in services:
        if svc['version']:
            print(f"\n[+] {svc['service']} {svc['version']} (Port {svc['port']})")
            cves = search_cve(svc['service'], svc['version'])
            if cves:
                for cve in cves[:3]:
                    severity = 'CRITICAL' if float(str(cve['score'])) >= 9.0 else \
                               'HIGH' if float(str(cve['score'])) >= 7.0 else \
                               'MEDIUM' if float(str(cve['score'])) >= 4.0 else 'LOW'
                    print(f"  [{severity}] {cve['id']} (Score: {cve['score']})")
                    print(f"    {cve['desc']}...")
            else:
                print("  [*] No CVEs found (or API rate limited)")

# ตัวอย่าง
services = [
    {'port': 22, 'service': 'OpenSSH', 'version': '7.9', 'state': 'open', 'banner': ''},
    {'port': 80, 'service': 'Apache', 'version': '2.4.41', 'state': 'open', 'banner': ''},
    {'port': 3306, 'service': 'MySQL', 'version': '5.7.32', 'state': 'open', 'banner': ''},
]
analyze_services(services)
```

---

## 20.9 แบบฝึกหัด Lab

### Lab 20-1: Banner Grabbing
```bash
# 1. แบบบึกภาร netcat
nc -nv 192.168.1.100 22
nc -nv 192.168.1.100 80
nc -nv 192.168.1.100 21

# 2. ดู HTTP Headers
curl -I http://192.168.1.100

# 3. บันทึกผล
echo "SSH: $(nc -nv 192.168.1.100 22 2>&1 | head -1)"
echo "HTTP: $(curl -sI http://192.168.1.100 | grep Server)"
```

### Lab 20-2: Version Detection ด้วย Nmap
```bash
# 1. Quick Version Scan
nmap -sV --version-intensity 5 -p 1-1024 192.168.1.100

# 2. Full Version + OS
nmap -A -p- 192.168.1.100 -oA /tmp/lab20_scan

# 3. วิเคราะห์ Output
grep 'open' /tmp/lab20_scan.nmap | awk '{print $1, $3, $4, $5, $6}'
```

### Lab 20-3: SSL Analysis
```bash
# 1. ดู SSL Certificate
openssl s_client -connect 192.168.1.100:443 2>/dev/null | openssl x509 -noout -text | head -40

# 2. ตรวจ Cipher Suites
nmap --script ssl-enum-ciphers -p 443 192.168.1.100

# 3. ตรวจ Heartbleed
nmap --script ssl-heartbleed -p 443 192.168.1.100
```

### Lab 20-4: Python Fingerprinter
```bash
# 1. บันทึก Script
cat > /tmp/fingerprint.py << 'PYEOF'
# ใส่เนื้อหา script จาก Section 20.8 ที่นี่
PYEOF

# 2. Run
python3 /tmp/fingerprint.py 192.168.1.100

# 3. ดูผล
cat /tmp/fingerprint_192_168_1_100.json | python3 -m json.tool
```

---

## สรุป

| เครื่องมือ | หน้าที่ | ความเร็ว |
|-----------|--------|----------|
| netcat | Banner Grabbing | เร็ว |
| curl | HTTP Headers | เร็ว |
| nmap -sV | Service Detection | กลาง |
| nmap -A | Full Fingerprint | ช้า |
| whatweb | Web Tech | เร็ว |
| nikto | HTTP Vulnerabilities | ช้า |
| sslyze | SSL Analysis | กลาง |
| openssl | Manual SSL | เร็ว |
| p0f | Passive OS Detection | Passive |

> **ขั้นตอนที่ดี:** Banner → Version → CVE Search → Exploit Selection → Testing
