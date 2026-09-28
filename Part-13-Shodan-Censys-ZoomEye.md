# Part 13: Shodan, Censys & ZoomEye
## ค้นหาอุปกรณ์เดินสายด้วย Search Engines สำหรับ Hackers

---

## สารบัญ
1. [Shodan](#shodan)
2. [Censys](#censys)
3. [ZoomEye & Fofa](#zoomeye)
4. [Shodan Filters สำคัญ](#filters)
5. [หา Vulnerable Services](#vuln-services)
6. [Industrial Control Systems](#ics)
7. [Python API](#python-api)
8. [แบบฝึกหัด](#exercises)

---

## 1. Shodan {#shodan}

**Shodan** เป็น search engine ที่ scan internet ตลอดเวลาและ index ข้อมูลสักชาติ services ที่เปิดอยู่

### ติดตั้ง Shodan CLI

```bash
pip3 install shodan

# Initialize ด้วย API key
shodan init YOUR_API_KEY

# สมัคร API key ที่: https://account.shodan.io
```

### Shodan CLI พื้นฐาน

```bash
# ค้นหาอุปกรณ์
shodan search 'apache'
shodan search 'nginx country:TH'
shodan search 'openssh port:22'

# ดูรายละเอียด host
shodan host 93.184.216.34

# ดู stats
shodan stats 'apache country:TH'

# ดูนโยบายของตัวเอง
shodan myip
shodan info
shodan account

# Download results
shodan search 'apache country:TH' --limit 100 > results.txt
shodan search 'apache country:TH' --fields ip_str,port,org,country_name --limit 100

# Alert (Monitor เมื่อมีสิ่งใหม่)
shodan alert create 'MY_NETWORK' 203.0.113.0/24
shodan alert list
```

### Shodan Web Filters

```
# Service filters
port:22 country:TH
port:3389 country:TH  (RDP)
port:23 country:TH   (Telnet)

# Product filters
product:"Apache httpd"
product:"nginx"
product:"OpenSSH"
product:"Microsoft IIS"

# OS filters
os:"Windows 7"
os:"Windows XP"
os:"Linux"

# Organization/Network
org:"True Internet" country:TH
net:203.0.113.0/24
asn:AS4750

# Hostname filters
hostname:"admin"
hostname:"vpn"
hostname:".gov.th"

# SSL/TLS
ssl.cert.subject.cn:"*.example.com"
ssl.cert.expired:true

# Tags
tag:database country:TH
tag:ics country:TH
tag:malware

# Vulnerabilities
vuln:CVE-2021-44228  (Log4Shell)
vuln:CVE-2019-0708   (BlueKeep)
vuln:CVE-2020-1472   (Zerologon)
```

---

## 2. Censys {#censys}

**Censys** เป็น search engine อีกตัวที่ scan และ index internet devices

```bash
pip3 install censys
censys config  # ใส่ API credentials

# Search hosts
censys search 'services.port:80 AND location.country_code:TH'
censys search 'services.tls.certificates.leaf_data.subject_dn:"*.example.com"'

# View host details
censys view 93.184.216.34

# Bulk lookup
for ip in $(cat ips.txt); do censys view $ip; done
```

### Censys Query Examples

```
# SSL Certificate search
services.tls.certificates.leaf_data.subject_dn:"example.com"

# Open ports
services.port:3306 AND location.country_code:TH  (MySQL)
services.port:27017 AND location.country_code:TH  (MongoDB)
services.port:6379 AND location.country_code:TH   (Redis)

# Services
services.service_name:SSH
services.service_name:HTTP

# Operating System
services.banner:"Ubuntu"
```

---

## 3. ZoomEye & Fofa {#zoomeye}

```bash
# ZoomEye (Chinese Shodan)
# https://www.zoomeye.org
pip3 install zoomeye-sdk

# Search
app:"Apache httpd" country:TH
port:22 country:TH
hostname:"example.com"

# Fofa (Chinese Shodan)
# https://fofa.info
# Query:
app="Apache" && country="TH"
body="admin panel"
cert="example.com"
port="3389"
```

---

## 4. Shodan Filters สำคัญ {#filters}

```
Filter          Description
---------       -----------
city:           City name
country:        Country code (TH, US, CN)
net:            CIDR block (192.168.1.0/24)
org:            Organization name
os:             Operating system
port:           Port number
product:        Software product
hostname:       DNS hostname
ssl.cert.*      SSL certificate fields
vuln:           CVE vulnerability
asn:            Autonomous System Number
before/after:   Date filters
tag:            Shodan tags
```

### Shodan Dorks ที่น่าใช้

```
# Default credentials
"default password" port:23
"default password" http.title:"Router"

# Exposed databases
port:3306 country:TH product:"MySQL"
port:5432 country:TH product:"PostgreSQL"
port:27017 country:TH  (MongoDB - often no auth)
port:6379 country:TH   (Redis - often no auth)
port:9200 country:TH   (Elasticsearch)

# Webcams
title:"webcam" country:TH
product:"Axis" title:"Live View"

# Printers
port:9100 country:TH  (JetDirect printing)

# SCADA/ICS
port:102 country:TH   (Siemens S7)
port:502 country:TH   (Modbus)
port:47808 country:TH  (BACnet)

# VoIP
port:5060 country:TH   (SIP)

# Remote management
port:3389 os:"Windows XP"
port:22 version:"OpenSSH 5"
```

---

## 5. หา Vulnerable Services {#vuln-services}

### Exposed Databases

```bash
# หา MongoDB ที่ไม่มีการ authenticate
shodan search 'port:27017 country:TH' --fields ip_str,port,org

# ตรวจสอบ
python3 << 'EOF'
from pymongo import MongoClient
import socket

def check_mongodb(host, port=27017, timeout=3):
    try:
        client = MongoClient(host, port, serverSelectionTimeoutMS=timeout*1000)
        dbs = client.list_database_names()
        print(f"[OPEN] {host}:{port} - Databases: {dbs}")
        return True
    except Exception:
        return False

# Test on authorized systems only
# check_mongodb('target_ip')
EOF

# หา Redis ที่ไม่มี auth
shodan search 'port:6379 "NOAUTH" country:TH'

# ตรวจสอบ Redis
redis-cli -h target_ip ping  # PONG = open
redis-cli -h target_ip info server

# หา Elasticsearch
shodan search 'port:9200 "You Know, for Search" country:TH'
curl http://target_ip:9200/
curl http://target_ip:9200/_cat/indices?v
```

### Vulnerable Versions

```bash
# หา Apache Struts (CVE-2017-5638)
shodan search 'product:"Apache" version:"2.3" OR version:"2.5"'

# หา Heartbleed OpenSSL
shodan search 'vuln:CVE-2014-0160'

# หา EternalBlue SMB
shodan search 'vuln:CVE-2017-0144 country:TH'
shodan search 'port:445 os:"Windows 7" country:TH'

# หา BlueKeep RDP
shodan search 'vuln:CVE-2019-0708 country:TH'

# หา Log4Shell
shodan search 'vuln:CVE-2021-44228'

# หา Citrix
shodan search 'product:"Citrix" vuln:CVE-2019-19781'
```

---

## 6. Industrial Control Systems {#ics}

```bash
# ICS/SCADA Protocols
shodan search 'port:102 country:TH'   # Siemens S7
shodan search 'port:502 country:TH'   # Modbus
shodan search 'port:1911 country:TH'  # Niagara Fox
shodan search 'port:4911 country:TH'  # Niagara Fox TLS
shodan search 'port:7001 country:TH'  # DNP3
shodan search 'port:44818 country:TH' # EtherNet/IP
shodan search 'port:2222 country:TH'  # EtherNet/IP

# BACnet (Building automation)
shodan search 'port:47808 country:TH'

# Shodan tag:ics
shodan search 'tag:ics country:TH'

# PLCs
shodan search 'product:"Siemens" country:TH'
shodan search 'product:"Allen-Bradley" country:TH'
```

---

## 7. Python API {#python-api}

### Shodan Python สำหรับ Automation

```python
#!/usr/bin/env python3
import shodan
import json
import csv
from datetime import datetime

class ShodanRecon:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
    
    def host_lookup(self, ip):
        """Lookup single host"""
        try:
            host = self.api.host(ip)
            return {
                'ip': ip,
                'org': host.get('org', 'N/A'),
                'os': host.get('os', 'N/A'),
                'country': host.get('country_name', 'N/A'),
                'city': host.get('city', 'N/A'),
                'ports': host.get('ports', []),
                'hostnames': host.get('hostnames', []),
                'vulns': list(host.get('vulns', [])),
                'last_update': host.get('last_update', '')
            }
        except shodan.APIError as e:
            print(f"[-] Error {ip}: {e}")
            return None
    
    def search(self, query, limit=100):
        """Search Shodan"""
        results = []
        try:
            search_results = self.api.search(query, limit=limit)
            print(f"[+] Total: {search_results['total']} results")
            
            for r in search_results['matches']:
                results.append({
                    'ip': r.get('ip_str', ''),
                    'port': r.get('port', ''),
                    'org': r.get('org', ''),
                    'country': r.get('country_name', ''),
                    'product': r.get('product', ''),
                    'version': r.get('version', ''),
                    'hostname': r.get('hostnames', []),
                })
        except shodan.APIError as e:
            print(f"[-] API Error: {e}")
        
        return results
    
    def scan_ips(self, ip_list):
        """Scan list of IPs"""
        all_results = []
        for ip in ip_list:
            print(f"[*] Looking up: {ip}")
            result = self.host_lookup(ip)
            if result:
                all_results.append(result)
                if result.get('vulns'):
                    print(f"  [!] Vulnerabilities: {result['vulns']}")
        return all_results
    
    def export_csv(self, results, filename):
        """Export to CSV"""
        if not results:
            return
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"[+] Saved to: {filename}")

# ใช้งาน
if __name__ == '__main__':
    API_KEY = 'YOUR_SHODAN_API_KEY'
    recon = ShodanRecon(API_KEY)
    
    # Search Apache in Thailand
    results = recon.search('apache country:TH', limit=50)
    recon.export_csv(results, f'shodan_apache_th_{datetime.now().strftime("%Y%m%d")}.csv')
    
    # Show vulnerable hosts
    for r in results:
        print(f"{r['ip']}:{r['port']} - {r['org']} - {r['product']}")
```

### Censys Python

```python
#!/usr/bin/env python3
from censys.search import CensysHosts
import json

class CensysRecon:
    def __init__(self):
        self.hosts = CensysHosts()  # ใช้ env CENSYS_API_ID, CENSYS_API_SECRET
    
    def search(self, query, max_records=100):
        results = []
        try:
            for host in self.hosts.search(query, pages=max_records//100 + 1):
                for h in host:
                    results.append(h)
                    if len(results) >= max_records:
                        return results
        except Exception as e:
            print(f"[-] Error: {e}")
        return results
    
    def view_host(self, ip):
        try:
            return self.hosts.view(ip)
        except Exception as e:
            print(f"[-] Error: {e}")
            return None

# ใช้งาน
recon = CensysRecon()
results = recon.search('services.port:3306 AND location.country_code:TH')
for r in results:
    print(f"IP: {r['ip']} - Services: {[s['port'] for s in r.get('services', [])]}")
```

---

## 8. แบบฝึกหัด {#exercises}

### Lab 1: Shodan Organization Search
ใช้ Shodan.io:
1. ค้นหา devices ของ organization (org:"Company Name")
2. ดู open ports
3. Check vulnerabilities
4. วิเคราะห์หนึ่ง host โดยละเอียด

### Lab 2: Find Exposed Services
หา services ในประเทศไทยที่:
1. MongoDB ไม่มี authentication
2. Redis ไม่มี authentication
3. Elasticsearch
4. Kibana
5. Jenkins

### Lab 3: SSL Certificate Recon
1. ค้นหา subdomains ด้วย Censys SSL cert search
2. เปรียบเทียบกับผลจาก subfinder
3. วิเคราะห์ต่างกัน

---

## สรุป

| Platform | จุดเด่น |
|----------|--------|
| Shodan | ใหญ่ที่สุด, API ดี |
| Censys | SSL/TLS certificate focus |
| ZoomEye | China focus |
| Fofa | China focus, ฟรีไม่จำกัด |

**สำคัญ**: ใช้เพื่อการวิเคราะห์ attack surface ในการทดสอบที่ได้รับอนุญาตเท่านั้น!

---
*Part 13/100+ | Kali Linux Penetration Testing Course*
