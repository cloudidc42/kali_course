# Part 23: OpenVAS - Open Source Vulnerability Scanner

## สารบัญ
- [23.1 OpenVAS คืออะไร](#231-openvas-คืออะไร)
- [23.2 ติดตั้ง OpenVAS บน Kali](#232-ติดตั้ง-openvas-บน-kali)
- [23.3 Greenbone Security Assistant (GSA)](#233-greenbone-security-assistant-gsa)
- [23.4 การสร้าง Scan Task](#234-การสร้าง-scan-task)
- [23.5 วิเคราะห์ Results](#235-วิเคราะห์-results)
- [23.6 OpenVAS CLI (omp/gvm-cli)](#236-openvas-cli-ompgvm-cli)
- [23.7 แบบฝึกหัด Lab](#237-แบบฝึกหัด-lab)

---

## 23.1 OpenVAS คืออะไร

OpenVAS (Open Vulnerability Assessment System) หรือชื่อใหม่ GVM (Greenbone Vulnerability Management) คือ Vulnerability Scanner Open Source ที่เป็นทางเลือกฟรีแทน Nessus

### คุณสมบัติ
```
✓ Open Source (ฟรี)
✓ 50,000+ Network Vulnerability Tests (NVTs)
✓ Web Interface (Greenbone Security Assistant)
✓ CLI via gvm-cli
✓ Schedule Scans
✓ Custom Scan Configs
✓ Report Export (XML, HTML, PDF, CSV)
✓ Active ด้วย Feed Updates
```

### GVM Architecture
```
┌─────────────────────────────────────────────────┐
│  Greenbone Security Assistant (GSA) - Port 9392  │
│  Web Interface                                    │
├─────────────────────────────────────────────────┤
│  GVM Manager (gvmd) - Port 9390                  │
│  Orchestrates scans, manages data                │
├─────────────────────────────────────────────────┤
│  OpenVAS Scanner - Port 9391                     │
│  Runs NVT plugins against targets                │
├─────────────────────────────────────────────────┤
│  Feed: Community / Enterprise                    │
│  NVTs, CERT Advisories, CPE, SCAP                │
└─────────────────────────────────────────────────┘
```

---

## 23.2 ติดตั้ง OpenVAS บน Kali

```bash
# ติดตั้ง GVM (Greenbone Vulnerability Management)
sudo apt update
sudo apt install gvm -y

# Setup อัตโนมัติ (ดาวน์โหลด Feeds, สร้าง Database)
sudo gvm-setup
# ใช้เวลา 20-60 นาทีขึ้นไป

# ตรวจสอบหลังติดตั้ง
sudo gvm-check-setup

# เริ่ม Services
sudo gvm-start

# ดู Status
sudo gvm-check-setup

# หยุด
sudo gvm-stop
```

### พร้อมแล้ว
```bash
# admin password จะปรากฏหลัง gvm-setup
# เช่น: [*] User created with password 'RANDOM_PASSWORD'

# เปิด Browser
https://127.0.0.1:9392

# Login
Username: admin
Password: (จาก gvm-setup output)
```

### Troubleshooting
```bash
# ดู Log
sudo tail -f /var/log/gvm/gvmd.log
sudo tail -f /var/log/gvm/openvas.log

# Restart Services
sudo systemctl restart gvmd
sudo systemctl restart openvas
sudo systemctl restart gsad

# อัปเดต Feeds
sudo runuser -u _gvm -- greenbone-nvt-sync
sudo runuser -u _gvm -- greenbone-feed-sync --type GVMD_DATA
sudo runuser -u _gvm -- greenbone-feed-sync --type SCAP
sudo runuser -u _gvm -- greenbone-feed-sync --type CERT
```

---

## 23.3 Greenbone Security Assistant (GSA)

### Navigation
```
Dashboard  - ภาพรวม Vulnerability Stats
Scans      - Manage Tasks + Results
Assets     - Hosts และ OS Inventory
SecInfo    - NVTs, CVEs, CPEs Database
Configuration - Scan Configs, Credentials
Administration - Users, Roles, Groups
```

---

## 23.4 การสร้าง Scan Task

### ขั้นตอน
```
1. สร้าง Target:
   Configuration → Targets → New Target
   Name: Lab Network
   Hosts: 192.168.1.0/24
   Exclude Hosts: 192.168.1.1
   Port List: All IANA Assigned TCP and UDP

2. สร้าง Credentials (สำหรับ Authenticated Scan):
   Configuration → Credentials → New Credential
   Name: Linux Root
   Type: Username + Password
   Username: root
   Password: ****

3. เลือก Scan Config:
   (ใช้ Default: Full and Fast)
   - Empty           - ไม่มี NVT
   - Full and Deep    - ใช้เวลานานที่สุด
   - Full and Fast    - สมดุลระหว่างความเร็วและครอบคลุม
   - System Discovery - ค้นหา Hosts เป็นหลัก

4. สร้าง Task:
   Scans → Tasks → New Task
   Name: Full Scan Lab
   Scan Targets: Lab Network
   Credentials: Linux Root (SSH)
   Scan Config: Full and Fast
   Scanner: OpenVAS Default
```

---

## 23.5 วิเคราะห์ Results

### Severity Levels
```
Critical (9.0-10.0) - แดงเข้ม
  ต้องแก้ไขทันที
  เช่น: RCE, Auth Bypass, EternalBlue

High (7.0-8.9) - แดง
  แก้ไขภายใน 7 วัน
  เช่น: Privilege Escalation, SQL Injection

Medium (4.0-6.9) - เหลืองส้ม
  แก้ไขภายใน 30 วัน
  เช่น: XSS, Missing Headers

Low (0.1-3.9) - เหลือง
  แก้ไขใน 90 วัน
  เช่น: Version Disclosure, Weak Cipher

Log/Info (0.0) - เงินเป็นข้อมูลเพิ่มเติม
```

### Export Reports
```
Scans → Reports → [Report] → Export:
  XML  - Raw Data สำหรับ Parsing
  HTML - Web Report
  PDF  - Management Report
  CSV  - Excel Analysis
  TXT  - Plain Text
```

---

## 23.6 OpenVAS CLI (gvm-cli)

```bash
# ติดตั้ง
pip3 install gvm-tools

# Login
gvm-cli --gmp-username admin --gmp-password PASSWORD socket

# ดู Targets
gvm-cli socket --xml '<get_targets/>'

# ดู Tasks
gvm-cli socket --xml '<get_tasks/>'

# สร้าง Task
gvm-cli socket --xml '<create_task>
  <name>CLI Scan</name>
  <target id="TARGET_UUID"/>
  <config id="SCAN_CONFIG_UUID"/>
  <scanner id="SCANNER_UUID"/>
</create_task>'

# Start Task
gvm-cli socket --xml '<start_task task_id="TASK_UUID"/>'

# ดูผล
gvm-cli socket --xml '<get_results task_id="TASK_UUID"/>'
```

### Python GVM Script
```python
#!/usr/bin/env python3
# gvm_scan.py - Automate GVM Scanning

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

def run_scan(target_ip):
    connection = UnixSocketConnection(path='/run/gvmd/gvmd.sock')
    transform = EtreeTransform()
    
    with Gmp(connection, transform=transform) as gmp:
        gmp.authenticate('admin', 'password')
        
        # Get Scanner ID
        scanners = gmp.get_scanners()
        scanner_id = scanners.find('.//scanner').get('id')
        
        # Get Scan Config (Full and Fast)
        configs = gmp.get_scan_configs()
        config_id = None
        for cfg in configs.findall('.//config'):
            if cfg.find('name').text == 'Full and Fast':
                config_id = cfg.get('id')
                break
        
        # Create Target
        target = gmp.create_target(
            name=f'Auto Target {target_ip}',
            hosts=[target_ip],
            port_list_id='33d0cd82-57c6-11e1-8ed1-406186ea4fc5'  # All TCP
        )
        target_id = target.get('id')
        print(f'Created target: {target_id}')
        
        # Create Task
        task = gmp.create_task(
            name=f'Auto Scan {target_ip}',
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id
        )
        task_id = task.get('id')
        print(f'Created task: {task_id}')
        
        # Start Task
        gmp.start_task(task_id)
        print(f'Started scan for {target_ip}')
        return task_id

if __name__ == '__main__':
    task_id = run_scan('192.168.1.100')
    print(f'Monitor at: https://localhost:9392')
```

---

## 23.7 แบบฝึกหัด Lab

### Lab 23-1: Setup และ First Scan
```bash
# 1. Setup GVM
sudo gvm-setup

# 2. Start
sudo gvm-start

# 3. เปิด Browser
https://127.0.0.1:9392

# 4. Login ด้วย admin + password จาก setup

# 5. Scans → Tasks → Scan Wizard
#    Scan IP: 192.168.1.100 (หรือ VM ที่ใช้)
#    Click Start Scan
```

### Lab 23-2: วิเคราะห์ผล
```
1. ดูผลใน Scans → Results
2. Filter by Severity "Critical" และ "High"
3. Click Vulnerability → ดู Description และ Solution
4. Export เป็น PDF
```

---

## สรุป

| หัวข้อ | รายละเอียด |
|--------|----------|
| Web UI | https://127.0.0.1:9392 |
| Setup | sudo gvm-setup |
| Start/Stop | sudo gvm-start / gvm-stop |
| Log | /var/log/gvm/ |
| CLI | gvm-cli / gvm-script |

> **OpenVAS vs Nessus:** OpenVAS ฟรี แต่ Setup ยากกว่า | Nessus จ่ายเงิน แต่ UI ดีกว่าและ Plugins มากกว่า
