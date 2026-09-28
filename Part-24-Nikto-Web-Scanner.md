# Part 24: Nikto Web Vulnerability Scanner

## สารบัญ
- [24.1 Nikto คืออะไร](#241-nikto-คืออะไร)
- [24.2 การติดตั้งและ Options](#242-การติดตั้งและ-options)
- [24.3 การใช้งาน Nikto หลัก](#243-การใช้งาน-nikto-หลัก)
- [24.4 เทคนิคขั้นสูง](#244-เทคนิคขั้นสูง)
- [24.5 การวิเคราะห์ Output](#245-การวิเคราะห์-output)
- [24.6 Nikto กับ Proxy และ Auth](#246-nikto-กับ-proxy-และ-auth)
- [24.7 Script Integration](#247-script-integration)
- [24.8 แบบฝึกหัด Lab](#248-แบบฝึกหัด-lab)

---

## 24.1 Nikto คืออะไร

Nikto คือ Web Server Scanner Open Source ที่ตรวจหาช่องโหว่ทั่วไปใน Web Server เช่น Default Files, Misconfigurations, Outdated Software

### คุณสมบัติ
```
✓ 6,700+ Dangerous Files/CGIs
✓ Server Configuration Checks
✓ Multiple Index Files
✓ Server-specific Configuration Items
✓ HTTP Server Options
✓ Unusual Headers
✓ SSL/TLS Issues
✓ Multiple Report Formats
✓ Integration with Metasploit
```

### สิ่งที่ Nikto ตรวจหา
```
- Outdated Server Software
- Default Files และ Directories
- Dangerous Files (backdoors, PHP shells)
- Security Header Issues
- SSL Certificate Problems
- CGI Vulnerabilities
- XSS และ Injection Points
- Sensitive Information Disclosure
- Directory Traversal Attempts
- HTTP Method Testing
```

---

## 24.2 การติดตั้งและ Options

```bash
# ติดตั้ง
sudo apt install nikto -y

# ดู Version
nikto -Version

# ดู Help
nikto -Help

# อัปเดต Database
nikto -update
```

### Options หลัก
```
Options:
  -h HOST         : Target host
  -p PORT         : Port (default 80)
  -ssl            : Use HTTPS
  -nossl          : Don't use HTTPS
  -id user:pass   : Authentication (Basic Auth)
  -C all          : Check all CGIs
  -Tuning 1-9     : Test types to run
  -output FILE    : Output file
  -Format FORMAT  : Output format (txt/csv/xml/htm)
  -timeout N      : Timeout (seconds)
  -useproxy       : Use proxy
  -Pause N        : Pause between tests (seconds)
  -Display X      : Display options
  -evasion X      : IDS Evasion Techniques
  -Plugins NAMES  : Run specific plugins
  -list-plugins   : List available plugins
  -mutate N       : Guess additional files
  -nolookup       : Don't DNS lookup
  -nointeractive  : No interactive prompts
  -followredirects: Follow redirects
```

---

## 24.3 การใช้งาน Nikto หลัก

```bash
# Scan พื้นฐาน
nikto -h http://192.168.1.100

# HTTPS
nikto -h https://192.168.1.100 -ssl

# Port อื่น
nikto -h 192.168.1.100 -p 8080
nikto -h 192.168.1.100 -p 8080,8443

# บันทึกผล
nikto -h http://192.168.1.100 -o /tmp/nikto_result.txt

# Output HTML
nikto -h http://192.168.1.100 -o /tmp/nikto_result.html -Format htm

# Output CSV
nikto -h http://192.168.1.100 -o /tmp/nikto_result.csv -Format csv

# Output XML
nikto -h http://192.168.1.100 -o /tmp/nikto_result.xml -Format xml

# Scan Multiple Hosts
nikto -h targets.txt

# Fast Scan (No 404 detection)
nikto -h http://192.168.1.100 -no404
```

### Tuning Options
```bash
# -Tuning Codes:
# 0 = File Upload
# 1 = Interesting File / Seen in logs
# 2 = Misconfiguration / Default File
# 3 = Information Disclosure
# 4 = Injection (XSS/Script/HTML)
# 5 = Remote File Retrieval - Inside Web Root
# 6 = Denial of Service
# 7 = Remote File Retrieval - Server Wide
# 8 = Command Execution / Remote Shell
# 9 = SQL Injection
# a = Authentication Bypass
# b = Software Identification
# c = Remote Source Inclusion
# x = Reverse Tuning Options (test all except)

# Scan เฉพาะ SQL Injection + XSS
nikto -h http://192.168.1.100 -Tuning 94

# Scan Misconfiguration + Info Disclosure
nikto -h http://192.168.1.100 -Tuning 23

# Scan ทุกอย่าง
nikto -h http://192.168.1.100 -Tuning x
```

---

## 24.4 เทคนิคขั้นสูง

### IDS Evasion
```bash
# Evasion Techniques:
# 1 = Random URI encoding (non-UTF8)
# 2 = Directory self-reference (/./)
# 3 = Premature URL ending
# 4 = Prepend long random string
# 5 = Fake parameter
# 6 = TAB as request spacer
# 7 = Change the case of the URL
# 8 = Use Windows directory separator (\\)
# A = Use a carriage return (0x0d) as a request spacer
# B = Use binary value 0x0b as a request spacer

nikto -h http://192.168.1.100 -evasion 1
nikto -h http://192.168.1.100 -evasion 234
nikto -h http://192.168.1.100 -evasion 12345678
```

### Virtual Host Scan
```bash
# Scan Virtual Host บน IP เดียวกัน
nikto -h http://192.168.1.100 -vhost www.company.com
nikto -h http://192.168.1.100 -vhost admin.company.com

# สแกนหลาย VHosts
for vhost in www admin dev test api; do
    echo "Testing: $vhost.company.com"
    nikto -h http://192.168.1.100 -vhost $vhost.company.com -no404 -o /tmp/nikto_$vhost.txt
done
```

### Mutate - Guess Files
```bash
# Mutate Options:
# 1 = Test all files with all root directories
# 2 = Guess for password file names  
# 3 = Enumerate user names via Apache (/~user)
# 4 = Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user)
# 5 = Attempt to brute force sub-domain names (uses -hostnames)
# 6 = Attempt to guess directory names from the supplied dictionary

nikto -h http://192.168.1.100 -mutate 2
nikto -h http://192.168.1.100 -mutate 3
```

---

## 24.5 การวิเคราะห์ Output

### ตัวอย่าง Output
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.100
+ Target Hostname:    192.168.1.100
+ Target Port:        80
+ Start Time:         2024-01-01 00:00:00 (GMT7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user
  agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user
  agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use "-C all" to force check all possible dirs)
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54).
  Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause
  false positives.
+ OSVDB-3268: /icons/README: Apache default file found.
+ /phpinfo.php: Output from the phpinfo() function was found.
  OSVDB-12184: /index.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals
  potentially sensitive information via certain HTTP requests that contain
  specific QUERY strings.
+ /admin/: Directory indexing found.
+ OSVDB-3092: /admin/: This might be interesting...
+ /backup/: Directory indexing found.
+ /backup/backup.sql: Backup file found!
+ /wp-login.php: Drupalgeddon2 exploit file found.
+ 8345 requests: 0 error(s) and 13 item(s) reported on remote host
+ End Time:           2024-01-01 00:05:30 (GMT7) (330 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### การวิเคราะห์ผล
```bash
# Parse ผลสำคัญ
grep 'OSVDB\|phpinfo\|backup\|admin\|password\|config' /tmp/nikto_result.txt

# ดู Critical Issues
grep -i 'vuln\|exploit\|injection\|admin\|backup\|config\|password' /tmp/nikto_result.txt

# นับจำนวนผล
grep -c '+ ' /tmp/nikto_result.txt
```

### ส่วนที่ควรสนใจ
```
เมื่อเป็น Pentest ให้เห็นผลเหล่านี้ ให้ตาม Manually:

1. /phpinfo.php → PHP Version + Config → ฝ่าย System Info
2. /admin/ → ทดสอบ Default Credentials
3. /backup/ → ดาวน์โหลด backup.sql → อ่าน Credentials
4. /.git/ → git clone http://IP/.git → Source Code
5. /config.php → DB Credentials
6. Directory Listing → ปิดการสร้าง
```

---

## 24.6 Nikto กับ Proxy และ Auth

### Proxy Support
```bash
# ใช้ผ่าน Proxy (Burp Suite)
nikto -h http://192.168.1.100 -useproxy http://127.0.0.1:8080

# SOCKS Proxy
nikto -h http://192.168.1.100 -useproxy socks5://127.0.0.1:1080
```

### Authentication
```bash
# HTTP Basic Auth
nikto -h http://192.168.1.100 -id admin:password123

# Cookie Auth
nikto -h http://192.168.1.100 -Cookies "PHPSESSID=abc123; admin=1"

# Custom Header
nikto -h http://192.168.1.100 -Headers "Authorization: Bearer eyJ..."
```

---

## 24.7 Script Integration

### Nikto ร่วมกับ Nmap
```bash
# ใช้ Nmap หา HTTP แล้วส่งให้ Nikto
nmap -p 80,8080,443 --open -oG - 192.168.1.0/24 | grep '80/open\|8080/open\|443/open' | \
awk '{print $2":"$5}' | sed 's/\/tcp.*//g' | \
while read target; do
    nikto -h $target -no404 -o /tmp/nikto_${target//:/_}.txt
done
```

### Auto Scan Script
```bash
#!/bin/bash
# web_scan.sh - Auto Web Scanning Pipeline

NETWORK="$1"
OUTPUT_DIR="/tmp/web_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[*] หา Web Servers ใน $NETWORK..."
nmap -p 80,443,8080,8443 --open -oG - $NETWORK 2>/dev/null | \
grep 'open' | awk '{print $2}' | sort -u > $OUTPUT_DIR/web_hosts.txt

WEB_COUNT=$(wc -l < $OUTPUT_DIR/web_hosts.txt)
echo "[*] พบ Web Hosts: $WEB_COUNT"

while read host; do
    echo "[+] Scanning: $host"
    
    # Nikto HTTP
    nikto -h http://$host -o $OUTPUT_DIR/nikto_${host}.txt -no404 2>/dev/null
    
    # Nikto HTTPS ถ้ามี Port 443
    if nc -z -w1 $host 443 2>/dev/null; then
        nikto -h https://$host -ssl -o $OUTPUT_DIR/nikto_${host}_ssl.txt -no404 2>/dev/null
    fi
done < $OUTPUT_DIR/web_hosts.txt

echo "[*] Complete! Results in: $OUTPUT_DIR"
```

### Python Nikto Parser
```python
#!/usr/bin/env python3
# nikto_parser.py - Parse Nikto XML Output

import xml.etree.ElementTree as ET
import sys

def parse_nikto_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    findings = []
    for scan in root.findall('.//scandetails'):
        host = scan.get('targethostname') or scan.get('targetip', '')
        port = scan.get('targetport', '80')
        
        for item in scan.findall('item'):
            osvdb = item.find('osvdbid')
            desc = item.find('description')
            uri = item.find('uri')
            method = item.find('method')
            
            finding = {
                'host': host,
                'port': port,
                'osvdb': osvdb.text if osvdb is not None else '',
                'description': desc.text if desc is not None else '',
                'uri': uri.text if uri is not None else '',
                'method': method.text if method is not None else '',
            }
            
            # ทำ Severityสำหรับการจัดสำดับ
            desc_lower = finding['description'].lower()
            if any(kw in desc_lower for kw in ['backup', 'password', 'admin', 'shell', 'exec']):
                finding['severity'] = 'HIGH'
            elif any(kw in desc_lower for kw in ['outdated', 'config', 'phpinfo', 'index']):
                finding['severity'] = 'MEDIUM'
            else:
                finding['severity'] = 'LOW'
            
            findings.append(finding)
    
    return findings

def report(findings):
    print(f"\nNikto Analysis Report")
    print("=" * 60)
    print(f"Total Findings: {len(findings)}")
    
    for sev in ['HIGH', 'MEDIUM', 'LOW']:
        sev_findings = [f for f in findings if f['severity'] == sev]
        if sev_findings:
            print(f"\n[{sev}] {len(sev_findings)} findings:")
            for f in sev_findings:
                print(f"  {f['host']}:{f['port']}{f['uri']}")
                print(f"    {f['description'][:80]}")

if __name__ == '__main__':
    xml_file = sys.argv[1] if len(sys.argv) > 1 else '/tmp/nikto_result.xml'
    findings = parse_nikto_xml(xml_file)
    report(findings)
```

---

## 24.8 แบบฝึกหัด Lab

### Lab 24-1: Scan DVWA (Damn Vulnerable Web App)
```bash
# Setup DVWA
sudo apt install dvwa -y
# หรือ docker
docker run -d -p 80:80 vulnerables/web-dvwa

# Nikto Scan
nikto -h http://localhost/dvwa/ -id admin:password
```

### Lab 24-2: Compare กับ Nmap
```bash
# Nmap HTTP Vuln Scan
nmap --script 'http-vuln-*,http-shellshock,http-phpself-xss' -p 80 localhost

# Nikto Scan
nikto -h http://localhost

# เปรียบเทียบผล
echo "Nmap found: $(grep -c '|' /tmp/nmap_web.txt) issues"
echo "Nikto found: $(grep -c '+ ' /tmp/nikto_web.txt) issues"
```

### Lab 24-3: HTML Report
```bash
nikto -h http://192.168.1.100 \
  -o /tmp/report.html \
  -Format htm \
  -Tuning 234b

# เปิดดู
xdg-open /tmp/report.html
```

---

## สรุป

| Option | คำอธิบาย |
|--------|----------|
| -h HOST | เป้าหมาย |
| -ssl | ใช้ HTTPS |
| -p PORT | พอร์ต |
| -Tuning N | ประเภท Test |
| -evasion N | IDS Bypass |
| -o FILE | บันทึกผล |
| -Format htm/csv/xml | รูปแบบผล |
| -id user:pass | Basic Auth |
| -Cookies "c=v" | Cookie Auth |
| -no404 | ไม่ตรวจ 404 |
| -update | อัปเดต DB |

> **ข้อควรระวัง:** Nikto เสียงดังมาก ใช้ได้แค่ในระบบที่ได้รับอนุญาตเท่านั้น
