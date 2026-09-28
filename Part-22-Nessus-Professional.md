# Part 22: Nessus Professional Vulnerability Scanner

## สารบัญ
- [22.1 Nessus คืออะไร](#221-nessus-คืออะไร)
- [22.2 ติดตั้ง Nessus บน Kali](#222-ติดตั้ง-nessus-บน-kali)
- [22.3 การใช้งาน Nessus Web UI](#223-การใช้งาน-nessus-web-ui)
- [22.4 Scan Templates และ Policies](#224-scan-templates-และ-policies)
- [22.5 การวิเคราะห์ Nessus Results](#225-การวิเคราะห์-nessus-results)
- [22.6 Nessus API และ Automation](#226-nessus-api-และ-automation)
- [22.7 ความแตกต่างระหว่าง Nessus Versions](#227-ความแตกต่างระหว่าง-nessus-versions)
- [22.8 แบบฝึกหัด Lab](#228-แบบฝึกหัด-lab)

---

## 22.1 Nessus คืออะไร

Nessus คือ Vulnerability Scanner ที่เป็นที่นิยมที่สุดในโลก พัฒนาโดย Tenable มี Plugin มากกว่า 70,000 รายการ

### คุณสมบัติหลัก
```
✓ 70,000+ Vulnerability Plugins
✓ Supports Windows, Linux, Mac
✓ Web-based Interface
✓ Compliance Scanning (PCI-DSS, HIPAA, CIS)
✓ Credentialed + Non-credentialed Scans
✓ Report หลายรูปแบบ (HTML, PDF, CSV)
✓ API Support
✓ Agent-based Scanning
```

### Nessus Architecture
```
┌───────────────────────────────────────┐
│  Nessus Server (nessusd daemon)          │
│  Port: 8834 (HTTPS)                       │
├───────────────────────────────────────┤
│  Web UI ←→ REST API ←→ Plugin Engine         │
├───────────────────────────────────────┤
│  Database (SQLite) │ Reports Engine           │
└───────────────────────────────────────┘
```

---

## 22.2 ติดตั้ง Nessus บน Kali

```bash
# ดาวน์โหลด Nessus Essentials (ฟรี 16 IPs)
# ไปที่: https://www.tenable.com/products/nessus/nessus-essentials
# เลือก: Linux - Debian - amd64

# ติดตั้ง
dpkg -i Nessus-10.x.x-debian10_amd64.deb

# เริ่ม Service
sudo systemctl start nessusd
sudo systemctl enable nessusd

# ตรวจสถานะ
sudo systemctl status nessusd

# เข้า Web UI
# เปิด Browser: https://localhost:8834
```

### การ Activate
```
1. เปิด https://localhost:8834
2. เลือก "Nessus Essentials" (หรือ Pro)
3. กรอก Activation Code (รับทาง Email หลังเข้าเว็บ)
4. ตั้งค่า Admin Account
5. รอ Download และ Compile Plugins (~5-10 นาที)
```

---

## 22.3 การใช้งาน Nessus Web UI

### สร้าง Scan ใหม่
```
Navigate: Scans → New Scan → เลือก Template

Settings ที่ต้องกาหนด:

  General Tab:
    Name: My Network Scan
    Description: ...
    Folder: My Scans
    Targets: 192.168.1.0/24

  Schedule Tab:
    Frequency: Once / Daily / Weekly
    Start Time: Now / Custom

  Notifications Tab:
    Email: admin@company.com

  Discovery Tab:
    Scan Type: Default / Custom
    Port Scan Range: default (1-65535)

  Assessment Tab:
    General: Default
    Accuracy: Override default...
    Antivirus: Scan for known antivirus installs

  Advanced Tab:
    Max Simultaneous Hosts: 5
    Max Checks Per Host: 5
    Network Timeout: 5
```

### Credentials สำหรับ Credentialed Scan
```
Credentials Tab → Add Credentials:

  SSH:
    Authentication: password / SSH key
    Username: root
    Password: ****
    
  Windows:
    Authentication: Password
    Username: Administrator
    Password: ****
    Domain: CORP
    
  Database:
    Type: MySQL / PostgreSQL / Oracle
    Username: root
    Password: ****
    Port: 3306
```

---

## 22.4 Scan Templates และ Policies

### Template หลักๆ
```
Discovery:
  - Host Discovery       - ค้นหา Live Hosts
  - Port Scan            - สแกน Ports

Vulnerabilities:
  - Basic Network Scan   - สแกนทั่วไปแบบพื้นฐาน
  - Advanced Scan        - สแกนลึก
  - Advanced Dynamic Scan - Plugins ใหม่ล่าสุด
  - Credentialed Patch Audit - ตรวจ Patch ด้วย Credentials
  - Malware Scan         - ตรวจหา Malware
  - Mobile Device Scan   - สแกน Mobile
  - Web Application Tests - สแกน Web App

Compliance:
  - CIS                  - CIS Benchmark
  - DISA STIG            - Government Standard
  - PCI DSS              - Payment Card Industry
  - HIPAA               - Healthcare
```

### Custom Policy
```
Scans → Policies → New Policy:

  1. เลือก Template Base
  2. ปรับแต่ง Plugins
     - Enable/Disable เฉพาะ Plugin Families
     - เช่น: เปิด "Windows" แต่ปิด "Denial of Service"
  3. ปรับ Port Range
  4. ปรับ Timing/Performance
```

---

## 22.5 การวิเคราะห์ Nessus Results

### การดูผล
```
Scans → [Scan Name] →
  
  Summary Tab:
    - Severities Chart (Critical/High/Medium/Low/Info)
    - Top Vulnerabilities
    - Top Hosts by Severity
    - Scan Details
  
  Hosts Tab:
    - รายชื่อ Host พร้อม Vulnerability Count
    - Click Host → ดูรายละเอียด
  
  Vulnerabilities Tab:
    - เรียงตาม Severity
    - Click Vuln → ดู Plugin Info และ Affected Hosts
```

### การอ่าน Vulnerability Detail
```
ตัวอย่างข้อมูลที่ได้:

Plugin ID:   97737
Name:        WannaCry/WannaCrypt Ransomware / MS17-010
Severity:    Critical (CVSS: 10.0)
Family:      Windows

Synopsis:
The remote Windows host is affected by multiple vulnerabilities...

Description:
The remote Windows host has the following vulnerabilities:
- CVE-2017-0143: Remote Code Execution
- CVE-2017-0144: Remote Code Execution  
- CVE-2017-0145: Remote Code Execution

Solution:
Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10 and 2016.

CVSS v3.0 Base Score:    8.1 (High)
CVSS v2.0 Base Score:    9.3 (High)

References:
  CVE: CVE-2017-0144
  IAVA: 2017-A-0065
  MS: MS17-010
```

### Export Reports
```
Scans → [Scan] → Export:
  - PDF Report     : สำหรับ Management
  - HTML Report    : ใน Browser
  - CSV           : สำหรับ Excel Analysis
  - .nessus        : เปิดใน Nessus อีกครั้ง
  - .nessus (v2)   : Tenable.sc format
```

---

## 22.6 Nessus API และ Automation

### API Authentication
```python
#!/usr/bin/env python3
# nessus_api.py - Nessus API Automation

import requests
import json
import time

requests.packages.urllib3.disable_warnings()

NESSUS_URL = 'https://localhost:8834'
USERNAME = 'admin'
PASSWORD = 'password123'

class NessusAPI:
    def __init__(self, url, username, password):
        self.url = url
        self.session = requests.Session()
        self.session.verify = False
        self.token = None
        self.login(username, password)
    
    def login(self, username, password):
        resp = self.session.post(
            f'{self.url}/session',
            json={'username': username, 'password': password}
        )
        self.token = resp.json()['token']
        self.session.headers.update({'X-Cookie': f'token={self.token}'})
        print(f'[+] Login successful. Token: {self.token[:10]}...')
    
    def logout(self):
        self.session.delete(f'{self.url}/session')
        print('[*] Logged out')
    
    def list_scans(self):
        resp = self.session.get(f'{self.url}/scans')
        return resp.json().get('scans', [])
    
    def get_scan_details(self, scan_id):
        resp = self.session.get(f'{self.url}/scans/{scan_id}')
        return resp.json()
    
    def create_scan(self, name, targets, policy_id=None, template='basic'):
        payload = {
            'uuid': self._get_template_uuid(template),
            'settings': {
                'name': name,
                'text_targets': targets,
                'enabled': True,
            }
        }
        if policy_id:
            payload['settings']['policy_id'] = policy_id
        resp = self.session.post(f'{self.url}/scans', json=payload)
        return resp.json()
    
    def launch_scan(self, scan_id):
        resp = self.session.post(f'{self.url}/scans/{scan_id}/launch')
        return resp.json().get('scan_uuid')
    
    def get_scan_status(self, scan_id):
        resp = self.session.get(f'{self.url}/scans/{scan_id}')
        data = resp.json()
        return data.get('info', {}).get('status')
    
    def wait_for_scan(self, scan_id, timeout=3600):
        start = time.time()
        while time.time() - start < timeout:
            status = self.get_scan_status(scan_id)
            print(f'  Status: {status}')
            if status in ['completed', 'aborted']:
                return status
            time.sleep(30)
        return 'timeout'
    
    def export_scan(self, scan_id, format='csv'):
        resp = self.session.post(
            f'{self.url}/scans/{scan_id}/export',
            json={'format': format}
        )
        file_id = resp.json().get('file')
        
        # Wait for export
        while True:
            status = self.session.get(
                f'{self.url}/scans/{scan_id}/export/{file_id}/status'
            ).json().get('status')
            if status == 'ready':
                break
            time.sleep(2)
        
        content = self.session.get(
            f'{self.url}/scans/{scan_id}/export/{file_id}/download'
        ).content
        return content
    
    def _get_template_uuid(self, template_name):
        resp = self.session.get(f'{self.url}/editor/scan/templates')
        for t in resp.json().get('templates', []):
            if t.get('name') == template_name:
                return t.get('uuid')
        return None
    
    def get_vulnerabilities(self, scan_id):
        data = self.get_scan_details(scan_id)
        vulns = data.get('vulnerabilities', [])
        result = []
        for v in vulns:
            result.append({
                'plugin_id': v.get('plugin_id'),
                'plugin_name': v.get('plugin_name'),
                'severity': v.get('severity'),
                'count': v.get('count')
            })
        return sorted(result, key=lambda x: x['severity'], reverse=True)

def severity_name(s):
    return {4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW', 0: 'INFO'}.get(s, 'UNKNOWN')

if __name__ == '__main__':
    nessus = NessusAPI(NESSUS_URL, USERNAME, PASSWORD)
    
    # List Scans
    print('\n[*] Current Scans:')
    scans = nessus.list_scans()
    for s in scans:
        print(f"  [{s['id']}] {s['name']} - Status: {s['status']}")
    
    # Create และ Launch Scan
    print('\n[*] Creating new scan...')
    scan = nessus.create_scan('Auto Scan', '192.168.1.0/24')
    scan_id = scan['scan']['id']
    print(f'  Scan ID: {scan_id}')
    
    print('[*] Launching scan...')
    nessus.launch_scan(scan_id)
    
    print('[*] Waiting for completion...')
    nessus.wait_for_scan(scan_id)
    
    # Get Vulnerabilities
    print('\n[*] Top Vulnerabilities:')
    vulns = nessus.get_vulnerabilities(scan_id)
    for v in vulns[:10]:
        sev = severity_name(v['severity'])
        print(f"  [{sev}] {v['plugin_name']} ({v['count']} hosts)")
    
    # Export
    print('\n[*] Exporting results...')
    csv_data = nessus.export_scan(scan_id, 'csv')
    with open('/tmp/nessus_results.csv', 'wb') as f:
        f.write(csv_data)
    print('  Saved: /tmp/nessus_results.csv')
    
    nessus.logout()
```

### Nessus CLI (nessuscli)
```bash
# หาไฟล์ nessuscli
find / -name nessuscli 2>/dev/null
# ปกติอยู่ที่: /opt/nessus/sbin/nessuscli

# Update Plugins
/opt/nessus/sbin/nessuscli update --all

# Manage Users
/opt/nessus/sbin/nessuscli adduser [username]
/opt/nessus/sbin/nessuscli rmuser [username]
/opt/nessus/sbin/nessuscli lsuser

# Check License
/opt/nessus/sbin/nessuscli fetch --check
```

---

## 22.7 ความแตกต่างระหว่าง Nessus Versions

```
┌────────────────┬────────────┬────────────┐
│ Essentials      │ Expert        │ Professional  │
├────────────────┼────────────┼────────────┤
│ Free            │ $5,990/year   │ $3,990/year   │
│ 16 IPs Max      │ Unlimited     │ Unlimited     │
│ No Compliance   │ + Compliance  │ Basic Comp.   │
│ No Policies     │ + Attack Surf.│ Custom Policy │
│ Personal Use    │ Full Pentest  │ Business Use  │
└────────────────┴────────────┴────────────┘
```

### Tenable.sc และ Tenable.io
```
Tenable.sc (SecurityCenter):
  - Enterprise on-premise
  - Manages multiple Nessus scanners
  - Advanced reporting + dashboards
  - Role-based access

Tenable.io:
  - Cloud-based
  - Automatic updates
  - Scale to thousands of IPs
  - Includes WAS (Web Application Scanning)
```

---

## 22.8 แบบฝึกหัด Lab

### Lab 22-1: ติดตั้ง Nessus
```bash
# 1. Download
# ไปเปิด https://www.tenable.com/downloads/nessus
# เลือก Nessus-XX.X.X-debian10_amd64.deb

# 2. Install
dpkg -i Nessus-*.deb

# 3. Start
sudo systemctl start nessusd

# 4. เปิด Web UI
xdg-open https://localhost:8834
```

### Lab 22-2: Basic Network Scan
```
1. Login https://localhost:8834
2. Scans → New Scan → Basic Network Scan
3. Name: Lab Scan
4. Targets: 192.168.1.0/24 (หรือ Local Network)
5. Save → Launch
6. รอให้เสร็จ (~5-20 นาที)
7. ดูผลใน Hosts และ Vulnerabilities Tab
```

### Lab 22-3: Export และ Analyze
```
1. Scans → [Lab Scan] → Export → CSV
2. เปิด CSV ใน Excel
3. Filter by Severity = "Critical"
4. Sort by Risk
5. เปรียบเทียบกับผล nmap
```

---

## สรุป

| หัวข้อ | รายละเอียด |
|--------|----------|
| URL | https://localhost:8834 |
| Default Port | 8834 (HTTPS) |
| Config Dir | /opt/nessus/ |
| Log Files | /opt/nessus/var/nessus/logs/ |
| Plugin Dir | /opt/nessus/lib/nessus/plugins/ |
| Free Version | Nessus Essentials (16 IPs) |

> **เคล็ดลับ:** Nessus Credentialed Scan ให้ช่องโหว่มากกว่า Unauthenticated Scan 30-40%
