# Part 67: Threat Hunting (การล่าหาภัยคุกคาม)

## สารบัญ
1. [Threat Hunting Overview](#threat-hunting-overview)
2. [Threat Hunting Methodologies](#threat-hunting-methodologies)
3. [Hypothesis-Driven Hunting](#hypothesis-driven-hunting)
4. [IOC Hunting](#ioc-hunting)
5. [Behavioral Analytics](#behavioral-analytics)
6. [MITRE ATT&CK Integration](#mitre-attck-integration)
7. [Log Analysis for Threat Hunting](#log-analysis-for-threat-hunting)
8. [Network Traffic Hunting](#network-traffic-hunting)
9. [Endpoint Hunting](#endpoint-hunting)
10. [Hunting Automation](#hunting-automation)

---

## 1. Threat Hunting Overview

### ความแตกต่างจาก Reactive Security

```
Reactive Security (SOC แบบเดิม):
  Alert → Investigate → Respond
  
  ข้อจำกัด: ตรวจพบได้เฉพาะสิ่งที่รู้จัก

Proactive Threat Hunting:
  Hypothesis → Hunt → Discover → Respond → Improve
  
  ข้อดี: ค้นหาสิ่งที่ไม่รู้จัก หรือ Advanced Threats

┌─────────────────────────────────────────────┐
│          Threat Hunting Maturity Model           │
│                                                   │
│  Level 0: Automated (SIEM alerts only)           │
│  Level 1: Ad-hoc (hunt manually when suspected)  │
│  Level 2: Procedural (documented hunt plans)     │
│  Level 3: Hypothesis-driven (intel-based)        │
│  Level 4: Analytics-driven (ML/behavioral)       │
└─────────────────────────────────────────────┘
```

### Threat Hunter Skills

| ทักษะ | รายละเอียด |
|-------|------------|
| OSINT & CTI | อ่าน threat reports, CVEs, IOCs |
| Log Analysis | วิเคราะห์ SIEM, log sources |
| Network Analysis | Wireshark, Zeek, Suricata |
| Scripting | Python, PowerShell, KQL, SPL |
| MITRE ATT&CK | รู้จัก TTPs ทั้งหมด |
| Malware Analysis | รู้พฤติกรรม malware |

---

## 2. Threat Hunting Methodologies

### TaHiTI (Targeted Hunting integrating Threat Intelligence)

```python
#!/usr/bin/env python3
# hunt_planner.py - วางแผน Threat Hunt

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import json
from datetime import datetime

class HuntStatus(Enum):
    PLANNED = "Planned"
    ACTIVE = "Active"
    COMPLETED = "Completed"
    CANCELLED = "Cancelled"

class HuntPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

@dataclass
class HuntPlan:
    """แผนการ Threat Hunt"""
    hunt_id: str
    name: str
    objective: str
    hypothesis: str
    threat_actor: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    queries: List[Dict] = field(default_factory=list)
    iocs_to_hunt: List[str] = field(default_factory=list)
    status: HuntStatus = HuntStatus.PLANNED
    priority: HuntPriority = HuntPriority.MEDIUM
    findings: List[Dict] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_query(self, platform: str, query: str, description: str = ""):
        """เพิ่ม hunt query"""
        self.queries.append({
            'platform': platform,
            'query': query,
            'description': description
        })
    
    def add_finding(self, finding: str, severity: str, evidence: str = ""):
        """เพิ่ม hunting finding"""
        self.findings.append({
            'finding': finding,
            'severity': severity,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat()
        })
    
    def generate_report(self) -> str:
        report = f"""
# Threat Hunt Report: {self.name}
**Hunt ID**: {self.hunt_id}
**Status**: {self.status.value}
**Priority**: {self.priority.name}
**Created**: {self.created_at}

## Objective
{self.objective}

## Hypothesis
{self.hypothesis}

## Threat Actor
{self.threat_actor or 'Unknown'}

## MITRE ATT&CK Techniques
{chr(10).join(f'- {t}' for t in self.mitre_techniques)}

## Data Sources
{chr(10).join(f'- {s}' for s in self.data_sources)}

## IOCs Hunted
{chr(10).join(f'- {ioc}' for ioc in self.iocs_to_hunt)}

## Hunt Queries
"""
        for q in self.queries:
            report += f"\n### {q['platform']}: {q.get('description', '')}\n"
            report += f"```\n{q['query']}\n```\n"
        
        report += f"\n## Findings ({len(self.findings)} found)\n"
        if self.findings:
            for f_item in self.findings:
                report += f"\n### [{f_item['severity']}] {f_item['finding']}\n"
                if f_item.get('evidence'):
                    report += f"Evidence: {f_item['evidence']}\n"
        else:
            report += "No malicious activity detected.\n"
        
        return report


# ตัวอย่าง Hunt Plan สำหรับ APT
def create_apt_hunt() -> HuntPlan:
    plan = HuntPlan(
        hunt_id="HUNT-2024-001",
        name="APT29 Cozy Bear - Lateral Movement Hunt",
        objective="ค้นหาสัญญาณ lateral movement โดย APT29 ในเครือข่าย",
        hypothesis="APT29 ใช้ Living-off-the-Land (LOL) techniques เพื่อ lateral movement",
        threat_actor="APT29 (Cozy Bear)",
        mitre_techniques=[
            "T1021.001 - Remote Desktop Protocol",
            "T1021.006 - Windows Remote Management",
            "T1075 - Pass the Hash",
            "T1097 - Pass the Ticket",
            "T1550.002 - Pass the Hash"
        ],
        data_sources=[
            "Windows Event Logs (Security)",
            "Sysmon Events",
            "Network Flow Logs",
            "Firewall Logs"
        ]
    )
    
    # IOCs
    plan.iocs_to_hunt = [
        "ip:185.220.101.1",
        "domain:svr-001.evil-apt.com",
        "hash:abc123def456abc123"
    ]
    
    # Splunk queries
    plan.add_query(
        platform="Splunk",
        description="Pass the Hash Detection",
        query="""
index=windows EventCode=4624 Logon_Type=3
| where match(Workstation_Name, "^\\$")
| stats count by src_ip, user, Workstation_Name
| where count > 5
| sort -count
"""
    )
    
    plan.add_query(
        platform="Splunk",
        description="WMI Lateral Movement",
        query="""
index=sysmon EventCode=1
| where match(ParentImage, "wmiprvse.exe")
| where NOT match(Image, "(svchost|conhost|WmiApSrv).exe")
| table _time, Computer, Image, CommandLine, User
"""
    )
    
    plan.add_query(
        platform="Splunk",
        description="Unusual Remote Service Creation",
        query="""
index=windows EventCode=7045
| where ServiceType="user mode service"
| table _time, ComputerName, ServiceName, ServiceFileName
| where NOT match(ServiceFileName, "(Windows|Microsoft|C:\\\\Windows)")
"""
    )
    
    # KQL (Microsoft Sentinel/Azure Monitor)
    plan.add_query(
        platform="KQL",
        description="Suspicious PowerShell via WMI",
        query="""
DeviceProcessEvents
| where FileName == "powershell.exe"
| where InitiatingProcessFileName == "WmiPrvSE.exe"
| project Timestamp, DeviceName, AccountName, 
          ProcessCommandLine, InitiatingProcessCommandLine
| limit 50
"""
    )
    
    return plan


if __name__ == "__main__":
    hunt = create_apt_hunt()
    print(hunt.generate_report())
```

---

## 3. Hypothesis-Driven Hunting

### สร้าง Threat Hunt Hypothesis

```python
#!/usr/bin/env python3
# hypothesis_generator.py - สร้าง hunt hypothesis จาก CTI

from typing import List, Dict
import json

class ThreatIntelHypothesis:
    """สร้าง hunting hypothesis จาก Threat Intelligence"""
    
    # MITRE ATT&CK Technique -> Hunt Hypothesis mapping
    TECHNIQUE_HYPOTHESES = {
        "T1055": {
            "technique": "Process Injection",
            "hypotheses": [
                "Attacker injected malicious code into legitimate processes",
                "Unusual parent-child process relationships exist",
                "Processes with unexpected memory regions exist"
            ],
            "data_sources": ["Sysmon Event 8", "EDR telemetry", "Memory forensics"],
            "hunt_queries": [
                {
                    "platform": "Sysmon/Splunk",
                    "query": "EventCode=8 AND TargetImage!=SourceImage"
                }
            ]
        },
        "T1059": {
            "technique": "Command and Scripting Interpreter",
            "hypotheses": [
                "PowerShell ถูกใช้สำหรับ malicious activities",
                "Encoded PowerShell commands ถูก execute",
                "Scripts ถูกดาวน์โหลดและรัน in-memory"
            ],
            "data_sources": ["PowerShell logs", "Script Block Logging", "Windows Events"],
            "hunt_queries": [
                {
                    "platform": "Splunk",
                    "query": "EventCode=4104 | where match(ScriptBlockText, '(IEX|Invoke-Expression|DownloadString|WebClient)')"
                }
            ]
        },
        "T1078": {
            "technique": "Valid Accounts",
            "hypotheses": [
                "Attacker ใช้ stolen credentials",
                "Service accounts ถูก misuse",
                "Accounts login จาก unusual locations"
            ],
            "data_sources": ["Authentication logs", "VPN logs", "AD events"],
            "hunt_queries": [
                {
                    "platform": "Splunk",
                    "query": "EventCode=4624 | stats count by user, src_ip | anomalydetection"
                }
            ]
        },
        "T1190": {
            "technique": "Exploit Public-Facing Application",
            "hypotheses": [
                "Web application ถูก exploit",
                "Unusual web server processes spawned",
                "Web shell ถูก deploy"
            ],
            "data_sources": ["Web server logs", "WAF logs", "Process creation logs"],
            "hunt_queries": [
                {
                    "platform": "Splunk",
                    "query": "index=web | where match(cmd, '(whoami|id|uname|cat /etc|net user)')"
                }
            ]
        },
        "T1566": {
            "technique": "Phishing",
            "hypotheses": [
                "Users รับ phishing emails",
                "Malicious attachments ถูกเปิด",
                "Credential harvesting เกิดขึ้น"
            ],
            "data_sources": ["Email gateway logs", "Proxy logs", "Endpoint events"],
            "hunt_queries": [
                {
                    "platform": "Splunk",
                    "query": "index=email | where match(attachment_name, '\\.(js|vbs|hta|wsf|cmd|bat|ps1)$')"
                }
            ]
        }
    }
    
    def generate_hunt_plan(self, techniques: List[str], 
                            threat_actor: str = "Unknown") -> Dict:
        """สร้าง hunt plan จาก techniques"""
        plan = {
            'threat_actor': threat_actor,
            'techniques': [],
            'data_sources': set(),
            'hypotheses': [],
            'hunt_queries': []
        }
        
        for tech_id in techniques:
            if tech_id in self.TECHNIQUE_HYPOTHESES:
                tech_info = self.TECHNIQUE_HYPOTHESES[tech_id]
                
                plan['techniques'].append({
                    'id': tech_id,
                    'name': tech_info['technique']
                })
                
                plan['hypotheses'].extend(tech_info['hypotheses'])
                plan['data_sources'].update(tech_info['data_sources'])
                plan['hunt_queries'].extend(tech_info['hunt_queries'])
        
        plan['data_sources'] = list(plan['data_sources'])
        return plan
    
    def priority_rank(self, technique_id: str, 
                       environment_context: Dict) -> int:
        """จัดลำดับความสำคัญของ technique ตามบริบท"""
        score = 0
        
        # ถ้ามี CVE ที่เกี่ยวข้อง
        if technique_id in environment_context.get('recent_cves', []):
            score += 3
        
        # ถ้ามี threat intel
        if technique_id in environment_context.get('threat_intel_techniques', []):
            score += 2
        
        # ถ้า technique ใช้บ่อย (top 10)
        common_techniques = ['T1059', 'T1078', 'T1055', 'T1566', 'T1190']
        if technique_id in common_techniques:
            score += 1
        
        return score


# ตัวอย่าง
if __name__ == "__main__":
    generator = ThreatIntelHypothesis()
    
    # APT29 techniques
    apt29_techniques = ['T1059', 'T1078', 'T1055']
    
    plan = generator.generate_hunt_plan(
        techniques=apt29_techniques,
        threat_actor="APT29"
    )
    
    print(f"[*] Hunt Plan for: {plan['threat_actor']}")
    print(f"[*] Techniques: {len(plan['techniques'])}")
    print(f"[*] Data Sources: {len(plan['data_sources'])}")
    print(f"[*] Hypotheses: {len(plan['hypotheses'])}")
    print(f"[*] Hunt Queries: {len(plan['hunt_queries'])}")
    
    print("\nHypotheses:")
    for h in plan['hypotheses']:
        print(f"  - {h}")
```

---

## 4. IOC Hunting

### Hunt IOCs ใน Environment

```python
#!/usr/bin/env python3
# ioc_hunter.py - ค้นหา IOCs ในระบบ

import re
import json
import subprocess
import hashlib
from pathlib import Path
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor

class IOCHunter:
    """ค้นหา IOCs ใน log files, filesystem, network"""
    
    def __init__(self, ioc_feed_file: str = None):
        self.ip_iocs: Set[str] = set()
        self.domain_iocs: Set[str] = set()
        self.hash_iocs: Set[str] = set()
        self.url_iocs: Set[str] = set()
        self.email_iocs: Set[str] = set()
        self.filename_iocs: Set[str] = set()
        self.findings: List[Dict] = []
        
        if ioc_feed_file:
            self.load_iocs(ioc_feed_file)
    
    def load_iocs(self, feed_file: str):
        """โหลด IOC feed"""
        with open(feed_file) as f:
            feed = json.load(f)
        
        self.ip_iocs = set(feed.get('ips', []))
        self.domain_iocs = set(feed.get('domains', []))
        self.hash_iocs = set(feed.get('hashes', []))
        self.url_iocs = set(feed.get('urls', []))
        self.email_iocs = set(feed.get('emails', []))
        self.filename_iocs = set(feed.get('filenames', []))
        
        print(f"[+] Loaded IOCs:")
        print(f"    IPs: {len(self.ip_iocs)}")
        print(f"    Domains: {len(self.domain_iocs)}")
        print(f"    Hashes: {len(self.hash_iocs)}")
        print(f"    URLs: {len(self.url_iocs)}")
    
    def hunt_in_logs(self, log_files: List[str]) -> List[Dict]:
        """ค้นหา IOCs ใน log files"""
        findings = []
        
        for log_file in log_files:
            print(f"[*] Scanning log: {log_file}")
            
            try:
                with open(log_file, 'r', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        # ค้นหา IPs
                        ip_matches = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                        for ip in ip_matches:
                            if ip in self.ip_iocs:
                                findings.append({
                                    'ioc_type': 'ip',
                                    'ioc_value': ip,
                                    'source': log_file,
                                    'line': line_num,
                                    'context': line.strip()[:200]
                                })
                        
                        # ค้นหา domains
                        domain_matches = re.findall(
                            r'\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})\b', 
                            line, re.IGNORECASE
                        )
                        for domain in domain_matches:
                            if domain.lower() in self.domain_iocs:
                                findings.append({
                                    'ioc_type': 'domain',
                                    'ioc_value': domain,
                                    'source': log_file,
                                    'line': line_num,
                                    'context': line.strip()[:200]
                                })
                        
                        # ค้นหา hashes (MD5/SHA256)
                        hash_matches = re.findall(
                            r'\b([0-9a-f]{32}|[0-9a-f]{64})\b', 
                            line, re.IGNORECASE
                        )
                        for h in hash_matches:
                            if h.lower() in self.hash_iocs:
                                findings.append({
                                    'ioc_type': 'hash',
                                    'ioc_value': h,
                                    'source': log_file,
                                    'line': line_num,
                                    'context': line.strip()[:200]
                                })
                
            except PermissionError:
                print(f"[-] Permission denied: {log_file}")
            except FileNotFoundError:
                print(f"[-] File not found: {log_file}")
        
        self.findings.extend(findings)
        return findings
    
    def hunt_filesystem(self, scan_dirs: List[str] = None) -> List[Dict]:
        """ค้นหา IOCs ใน filesystem"""
        if scan_dirs is None:
            scan_dirs = ['/tmp', '/var/tmp', '/dev/shm', '/home', '/opt']
        
        findings = []
        
        for scan_dir in scan_dirs:
            print(f"[*] Scanning directory: {scan_dir}")
            
            for filepath in Path(scan_dir).rglob('*'):
                if not filepath.is_file():
                    continue
                
                # ตรวจสอบชื่อไฟล์
                if filepath.name in self.filename_iocs:
                    findings.append({
                        'ioc_type': 'filename',
                        'ioc_value': filepath.name,
                        'location': str(filepath),
                        'size': filepath.stat().st_size
                    })
                
                # ตรวจสอบ hash
                if self.hash_iocs and filepath.stat().st_size < 50 * 1024 * 1024:  # < 50MB
                    try:
                        file_hash = self._hash_file(str(filepath))
                        if file_hash in self.hash_iocs:
                            findings.append({
                                'ioc_type': 'file_hash',
                                'ioc_value': file_hash,
                                'location': str(filepath)
                            })
                    except Exception:
                        pass
        
        self.findings.extend(findings)
        return findings
    
    def hunt_network_connections(self) -> List[Dict]:
        """ค้นหา IOC IPs ใน network connections"""
        findings = []
        
        # ดึง connections ปัจจุบัน
        result = subprocess.run(
            ['ss', '-tunp'],
            capture_output=True, text=True
        )
        
        for line in result.stdout.split('\n'):
            ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', line)
            for ip, port in ip_matches:
                if ip in self.ip_iocs:
                    findings.append({
                        'ioc_type': 'active_connection',
                        'ioc_value': ip,
                        'port': port,
                        'connection': line.strip()
                    })
        
        self.findings.extend(findings)
        return findings
    
    def _hash_file(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def generate_hunt_report(self) -> str:
        report = f"""# IOC Hunt Report
**Total Findings**: {len(self.findings)}

## IOC Summary
- IPs hunted: {len(self.ip_iocs)}
- Domains hunted: {len(self.domain_iocs)}
- Hashes hunted: {len(self.hash_iocs)}

## Findings\n"""
        
        if not self.findings:
            report += "No IOC matches found.\n"
        else:
            for finding in self.findings:
                report += f"\n### [{finding['ioc_type'].upper()}] {finding['ioc_value']}\n"
                for key, value in finding.items():
                    if key not in ['ioc_type', 'ioc_value']:
                        report += f"- {key}: {value}\n"
        
        return report


# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    # สร้าง IOC feed
    iocs = {
        "ips": ["192.168.1.100", "10.0.0.200"],
        "domains": ["evil.com", "malware.net"],
        "hashes": ["abc123def456abc123def456abc123def456abc123def456abc123def456ab12"],
        "filenames": ["malware.exe", "backdoor.sh"]
    }
    
    with open('/tmp/ioc_feed.json', 'w') as f:
        json.dump(iocs, f)
    
    hunter = IOCHunter('/tmp/ioc_feed.json')
    
    # Hunt in logs
    log_files = [
        '/var/log/auth.log',
        '/var/log/syslog'
    ]
    
    findings = hunter.hunt_in_logs(log_files)
    print(f"\n[+] Log hunting findings: {len(findings)}")
    
    # Hunt network
    net_findings = hunter.hunt_network_connections()
    print(f"[+] Network hunting findings: {len(net_findings)}")
    
    print(hunter.generate_hunt_report())
```

---

## 5. Behavioral Analytics

### Baseline และหา Anomalies

```python
#!/usr/bin/env python3
# behavioral_analytics.py - วิเคราะห์พฤติกรรมผิดปกติ

import json
import statistics
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import math

class UserBehaviorAnalytics:
    """วิเคราะห์พฤติกรรมผู้ใช้ (UEBA)"""
    
    def __init__(self):
        self.user_profiles = {}
        self.alerts = []
    
    def build_baseline(self, events: List[Dict]) -> Dict:
        """สร้าง baseline จากประวัติการณ์"""
        user_stats = defaultdict(lambda: {
            'login_hours': [],
            'login_locations': Counter(),
            'data_accessed_mb': [],
            'failed_logins': [],
            'commands_per_session': [],
            'file_access_count': [],
            'network_bytes_out': []
        })
        
        for event in events:
            user = event.get('user', 'unknown')
            stats = user_stats[user]
            
            if event.get('type') == 'login':
                # เวลา login
                if 'timestamp' in event:
                    ts = datetime.fromisoformat(event['timestamp'])
                    stats['login_hours'].append(ts.hour)
                
                # ที่อยู่
                if 'source_ip' in event:
                    stats['login_locations'][event['source_ip']] += 1
            
            elif event.get('type') == 'data_access':
                if 'bytes' in event:
                    stats['data_accessed_mb'].append(event['bytes'] / 1024 / 1024)
        
        # สร้าง profiles
        profiles = {}
        for user, stats in user_stats.items():
            profile = {}
            
            if stats['login_hours']:
                mean = statistics.mean(stats['login_hours'])
                stdev = statistics.stdev(stats['login_hours']) if len(stats['login_hours']) > 1 else 2
                profile['login_hours_mean'] = mean
                profile['login_hours_stdev'] = stdev
            
            if stats['login_locations']:
                profile['known_locations'] = set(stats['login_locations'].keys())
            
            if stats['data_accessed_mb']:
                mean = statistics.mean(stats['data_accessed_mb'])
                stdev = statistics.stdev(stats['data_accessed_mb']) if len(stats['data_accessed_mb']) > 1 else 1
                profile['data_access_mean_mb'] = mean
                profile['data_access_stdev_mb'] = stdev
            
            profiles[user] = profile
        
        self.user_profiles = profiles
        return profiles
    
    def detect_anomalies(self, current_events: List[Dict]) -> List[Dict]:
        """ตรวจสอบติการณ์ผิดปกติ"""
        anomalies = []
        
        for event in current_events:
            user = event.get('user', 'unknown')
            profile = self.user_profiles.get(user, {})
            
            if not profile:
                # ไม่มี baseline
                continue
            
            # ตรวจสอบเวลา login
            if event.get('type') == 'login' and 'timestamp' in event:
                ts = datetime.fromisoformat(event['timestamp'])
                hour = ts.hour
                
                mean = profile.get('login_hours_mean', 12)
                stdev = profile.get('login_hours_stdev', 3)
                
                # Z-score
                if stdev > 0:
                    z_score = abs(hour - mean) / stdev
                    if z_score > 3:  # > 3 standard deviations
                        anomalies.append({
                            'type': 'UNUSUAL_LOGIN_TIME',
                            'user': user,
                            'detail': f'Login at {hour}:00 is unusual (z-score: {z_score:.2f})',
                            'severity': 'HIGH',
                            'event': event
                        })
                
                # ตรวจสอป location
                if 'source_ip' in event:
                    known_locations = profile.get('known_locations', set())
                    if event['source_ip'] not in known_locations and known_locations:
                        anomalies.append({
                            'type': 'NEW_LOCATION',
                            'user': user,
                            'detail': f'Login from new location: {event["source_ip"]}',
                            'severity': 'MEDIUM',
                            'event': event
                        })
            
            # ตรวจสอบ data access
            elif event.get('type') == 'data_access' and 'bytes' in event:
                mb = event['bytes'] / 1024 / 1024
                mean = profile.get('data_access_mean_mb', 0)
                stdev = profile.get('data_access_stdev_mb', 1)
                
                if stdev > 0:
                    z_score = (mb - mean) / stdev
                    if z_score > 3:
                        anomalies.append({
                            'type': 'UNUSUAL_DATA_TRANSFER',
                            'user': user,
                            'detail': f'Unusually large data transfer: {mb:.2f}MB (z-score: {z_score:.2f})',
                            'severity': 'HIGH',
                            'event': event
                        })
        
        self.alerts.extend(anomalies)
        return anomalies


class NetworkBehaviorAnalytics:
    """วิเคราะห์พฤติกรรมเครือข่าย"""
    
    def detect_c2_beaconing(self, connections: List[Dict], 
                             min_requests: int = 10) -> List[Dict]:
        """ค้นหา C2 beaconing patterns"""
        # กลุ่ม connections ตาม source-destination
        by_pair = defaultdict(list)
        for conn in connections:
            key = f"{conn.get('src_ip')}:{conn.get('dst_ip')}:{conn.get('dst_port')}"
            by_pair[key].append(conn.get('timestamp'))
        
        findings = []
        
        for pair, timestamps in by_pair.items():
            if len(timestamps) < min_requests:
                continue
            
            # คำนวณไอระหว่างการเชื่อมต่อ
            if len(timestamps) > 1:
                sorted_ts = sorted(timestamps)
                intervals = []
                
                for i in range(1, len(sorted_ts)):
                    try:
                        t1 = datetime.fromisoformat(sorted_ts[i-1])
                        t2 = datetime.fromisoformat(sorted_ts[i])
                        interval = (t2 - t1).total_seconds()
                        intervals.append(interval)
                    except:
                        pass
                
                if intervals:
                    mean_interval = statistics.mean(intervals)
                    stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
                    
                    # Beaconing = interval สม่ำเสมอ (low stdev)
                    if mean_interval > 0 and stdev_interval < mean_interval * 0.1:
                        findings.append({
                            'type': 'BEACONING',
                            'pair': pair,
                            'interval_sec': mean_interval,
                            'count': len(timestamps),
                            'regularity': 1 - (stdev_interval / mean_interval)
                        })
        
        return findings
    
    def detect_port_scan(self, connections: List[Dict], 
                          threshold: int = 20) -> List[Dict]:
        """ค้นหา port scanning"""
        src_to_ports = defaultdict(set)
        
        for conn in connections:
            src = conn.get('src_ip')
            dst = conn.get('dst_ip')
            port = conn.get('dst_port')
            
            if src and dst and port:
                key = f"{src}:{dst}"
                src_to_ports[key].add(port)
        
        findings = []
        for pair, ports in src_to_ports.items():
            if len(ports) >= threshold:
                src, dst = pair.split(':', 1)
                findings.append({
                    'type': 'PORT_SCAN',
                    'src_ip': src,
                    'dst_ip': dst,
                    'ports_scanned': len(ports),
                    'severity': 'HIGH' if len(ports) > 100 else 'MEDIUM'
                })
        
        return findings


# ตัวอย่าง
if __name__ == "__main__":
    # UEBA demo
    uba = UserBehaviorAnalytics()
    
    # Baseline events (normal behavior)
    baseline_events = [
        {'user': 'john', 'type': 'login', 'timestamp': '2024-01-15T09:00:00', 'source_ip': '192.168.1.10'},
        {'user': 'john', 'type': 'login', 'timestamp': '2024-01-16T09:30:00', 'source_ip': '192.168.1.10'},
        {'user': 'john', 'type': 'login', 'timestamp': '2024-01-17T08:45:00', 'source_ip': '192.168.1.10'},
        {'user': 'john', 'type': 'data_access', 'bytes': 1024 * 1024},  # 1MB normal
        {'user': 'john', 'type': 'data_access', 'bytes': 2 * 1024 * 1024},  # 2MB normal
    ]
    
    profiles = uba.build_baseline(baseline_events)
    print("[+] Baseline built")
    
    # Current events (ผิดปกติ)
    current_events = [
        # Login กลางคืน (unusual time)
        {'user': 'john', 'type': 'login', 'timestamp': '2024-01-20T02:00:00', 'source_ip': '192.168.1.10'},
        # Login จาก IP ใหม่
        {'user': 'john', 'type': 'login', 'timestamp': '2024-01-21T09:00:00', 'source_ip': '10.10.10.100'},
        # ดึงข้อมูลมาก (data exfiltration)
        {'user': 'john', 'type': 'data_access', 'bytes': 500 * 1024 * 1024},  # 500MB!
    ]
    
    anomalies = uba.detect_anomalies(current_events)
    print(f"[+] Anomalies detected: {len(anomalies)}")
    for a in anomalies:
        print(f"  [{a['severity']}] {a['type']}: {a['detail']}")
```

---

## 6. MITRE ATT&CK Integration

### ค้นหา TTPs ในระบบ

```python
#!/usr/bin/env python3
# mitre_hunt.py - Hunt ตาม MITRE ATT&CK TTPs

MITRE_DETECTION_RULES = {
    # T1003: OS Credential Dumping
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "windows_events": [
            "EventCode=10 TargetImage=*lsass.exe",  # Sysmon process access
            "EventCode=4656 ObjectName=*lsass*",  # Object access
        ],
        "process_names": ["mimikatz", "procdump", "wce"],
        "registry_keys": [
            "HKLM\\SAM",
            "HKLM\\SECURITY\\SAM"
        ],
        "splunk_query": """
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where GrantedAccess IN ("0x1010", "0x1410", "0x1fffff")
| table _time, SourceImage, TargetImage, GrantedAccess, CallTrace
"""
    },
    
    # T1059.001: PowerShell
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "windows_events": [
            "EventCode=4103",  # Module logging
            "EventCode=4104",  # Script block logging
        ],
        "patterns": [
            r'IEX|Invoke-Expression',
            r'DownloadString|WebClient',
            r'EncodedCommand|enc ',
            r'bypass|ExecutionPolicy',
            r'-nop\s+-\w+\s+hidden',
        ],
        "splunk_query": """
index=powershell EventCode=4104
| rex field=ScriptBlockText mode=sed "s/[\\r\\n]/ /g"
| where match(ScriptBlockText, "(?i)(IEX|Invoke-Expression|DownloadString|FromBase64String)")
| table _time, Computer, ScriptBlockText
| sort -_time
"""
    },
    
    # T1086: PowerShell (old)
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "registry_keys": [
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ],
        "splunk_query": """
index=sysmon EventCode=13
| where match(TargetObject, 
    "(Run|RunOnce|RunServices|RunServicesOnce)")
| table _time, Computer, EventType, TargetObject, Details, User
"""
    },
    
    # T1021.001: Remote Desktop Protocol
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "windows_events": [
            "EventCode=4624 Logon_Type=10",
            "EventCode=4778",  # Session reconnected
        ],
        "network_indicators": ["port:3389"],
        "splunk_query": """
index=windows EventCode=4624 Logon_Type=10
| stats count, values(Source_Network_Address) as src_ips by Account_Name
| where count > 5 OR mvcount(src_ips) > 3
| sort -count
"""
    },
    
    # T1071.001: Web Protocols (C2)
    "T1071.001": {
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "network_indicators": ["unusual_user_agents", "periodic_beaconing"],
        "splunk_query": """
index=proxy
| stats count, dc(url) as unique_urls, first(_time) as first_seen 
      by src_ip, dest_ip, user_agent
| where count > 100 AND unique_urls < 5
| eval beacon_ratio = count/unique_urls
| sort -beacon_ratio
"""
    },
    
    # T1218: System Binary Proxy Execution (LOLBAS)
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "lolbas_binaries": [
            "mshta.exe", "regsvr32.exe", "certutil.exe",
            "wscript.exe", "cscript.exe", "msiexec.exe",
            "rundll32.exe", "odbcconf.exe"
        ],
        "splunk_query": """
index=sysmon EventCode=1
| where Image IN ("/mshta.exe", "/regsvr32.exe", "/certutil.exe", "/msiexec.exe")
| where CommandLine!=""
| table _time, Computer, User, Image, CommandLine, ParentImage
"""
    }
}


def generate_hunt_queries(technique_ids: list) -> list:
    """สร้าง hunt queries สำหรับ techniques ที่เลือก"""
    queries = []
    
    for tech_id in technique_ids:
        if tech_id in MITRE_DETECTION_RULES:
            rule = MITRE_DETECTION_RULES[tech_id]
            queries.append({
                'technique_id': tech_id,
                'technique_name': rule['name'],
                'tactic': rule.get('tactic', 'Unknown'),
                'splunk_query': rule.get('splunk_query', ''),
                'indicators': {
                    'events': rule.get('windows_events', []),
                    'patterns': rule.get('patterns', []),
                    'registry': rule.get('registry_keys', []),
                    'network': rule.get('network_indicators', [])
                }
            })
    
    return queries


if __name__ == "__main__":
    # สร้าง hunt queries สำหรับ APT scenario
    apt_techniques = ["T1003", "T1059.001", "T1547.001", "T1021.001", "T1218"]
    
    queries = generate_hunt_queries(apt_techniques)
    
    print("[*] MITRE ATT&CK Hunt Queries Generated:")
    print("=" * 60)
    
    for q in queries:
        print(f"\n[{q['technique_id']}] {q['technique_name']}")
        print(f"Tactic: {q['tactic']}")
        
        if q['indicators']['events']:
            print(f"Events to watch:")
            for e in q['indicators']['events']:
                print(f"  - {e}")
        
        if q['splunk_query']:
            print(f"Splunk Query:")
            print(q['splunk_query'])
```

---

## 7. Log Analysis for Threat Hunting

### Splunk Threat Hunting Queries

```spl
// ===== SPLUNK HUNT QUERIES =====

// 1. หา compromised accounts (password spraying)
index=windows EventCode=4625
| stats count by src_ip, dest_user
| where count > 50
| sort -count

// 2. หา lateral movement ผ่าน Windows admin shares
index=windows EventCode=5140 
| where Share_Name IN ("\\\\*\\\\ADMIN$", "\\\\*\\\\C$", "\\\\*\\\\IPC$")
| stats count by Computer, Source_Network_Address
| sort -count

// 3. หา Kerberoasting
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
| stats count by Account_Name, Service_Name, Client_Address
| where count > 1

// 4. หา Golden/Silver Ticket
index=windows EventCode=4769
| where Ticket_Encryption_Type="0x17"
| where Account_Name!="*$"
| table _time, Account_Name, Service_Name, Client_Address, Failure_Code

// 5. หา DCSync (credential dumping from DC)
index=windows EventCode=4662 
| where Access_Mask="0x100" OR Access_Mask="0x40000"
| where Object_Properties="{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}" 
         OR Object_Properties="{1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}"
| stats count by Computer, Account_Name

// 6. หา suspicious scheduled tasks
index=windows EventCode=4698
| where Task_Name NOT IN ("MicrosoftEdge", "GoogleUpdate", "Adobe")
| table _time, ComputerName, Task_Name, Task_Content

// 7. หา unusual parent-child process
index=sysmon EventCode=1
| where ParentImage IN (
    "*winword.exe", "*excel.exe", "*outlook.exe",
    "*powerpnt.exe", "*iexplore.exe"
  )
| where Image IN (
    "*cmd.exe", "*powershell.exe", "*wscript.exe",
    "*cscript.exe", "*rundll32.exe", "*mshta.exe"
  )
| table _time, Computer, User, ParentImage, Image, CommandLine

// 8. หา DNS tunneling
index=dns
| where len(query) > 50
| rex field=query "(?P<subdomain>^[^.]+)\.(?P<domain>.+$)"
| eval entropy=entropy(subdomain)
| where entropy > 3.5
| table _time, src_ip, query, entropy

// 9. หา large data exfiltration
index=proxy
| stats sum(bytes_out) as total_bytes by src_ip
| where total_bytes > 1073741824  // > 1GB
| eval gb = round(total_bytes/1073741824, 2)
| sort -total_bytes

// 10. หา impossible travel (login จากสองที่พร้อมกัน)
index=windows EventCode=4624
| iplocation Source_Network_Address
| stats values(Country) as countries, count by Account_Name
| where mvcount(countries) > 1
```

### KQL (Microsoft Sentinel) Hunting Queries

```kusto
// 1. Suspicious PowerShell Execution
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("IEX", "DownloadString", "EncodedCommand", "-enc")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| limit 100

// 2. Credential Access - LSASS Memory
DeviceProcessEvents
| where FileName in~ ("procdump.exe", "mimikatz.exe")
    or ProcessCommandLine has "lsass"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// 3. Lateral Movement via SMB
DeviceNetworkEvents
| where RemotePort == 445 and ActionType == "ConnectionSuccess"
| summarize count(), dcount(RemoteIP) by DeviceName, InitiatingProcessFileName
| where count_ > 20 or dcount_RemoteIP > 5
| sort by count_ desc

// 4. Hunting for C2 Beaconing
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIPType != "Private"
| summarize Count=count(), 
            Distinct_Ports=dcount(RemotePort)
            by DeviceName, RemoteIP, bin(Timestamp, 1h)
| where Count > 100 and Distinct_Ports < 3
| sort by Count desc

// 5. Registry Persistence
DeviceRegistryEvents
| where RegistryKey has_any (
    @"\CurrentVersion\Run",
    @"\CurrentVersion\RunOnce"
  )
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, 
          RegistryValueData, InitiatingProcessFileName
```

---

## 8. Network Traffic Hunting

### Zeek/Bro Log Analysis

```python
#!/usr/bin/env python3
# zeek_hunter.py - วิเคราะห์ Zeek logs

import json
import re
from collections import defaultdict, Counter
from pathlib import Path
from typing import List, Dict
from datetime import datetime

class ZeekLogHunter:
    """Hunt ภัยคุกคามจาก Zeek logs"""
    
    def analyze_dns_logs(self, dns_log_file: str) -> Dict:
        """วิเคราะห์ DNS logs"""
        findings = {
            'high_entropy_domains': [],
            'dga_candidates': [],
            'suspicious_record_types': [],
            'excessive_queries': []
        }
        
        query_counter = Counter()
        
        with open(dns_log_file) as f:
            for line in f:
                if line.startswith('#'):
                    continue
                
                parts = line.strip().split('\t')
                if len(parts) < 9:
                    continue
                
                # Zeek DNS log format
                src_ip = parts[2] if len(parts) > 2 else ''
                query = parts[9] if len(parts) > 9 else ''
                record_type = parts[13] if len(parts) > 13 else ''
                
                if not query:
                    continue
                
                query_counter[f"{src_ip}:{query}"] += 1
                
                # Entropy check
                subdomain = query.split('.')[0]
                if len(subdomain) > 10:
                    entropy = self._calc_entropy(subdomain)
                    if entropy > 3.5:
                        findings['high_entropy_domains'].append({
                            'domain': query,
                            'subdomain': subdomain,
                            'entropy': entropy,
                            'src_ip': src_ip
                        })
                
                # DGA-like length
                if len(subdomain) > 30 and subdomain.isalnum():
                    findings['dga_candidates'].append({
                        'domain': query,
                        'src_ip': src_ip
                    })
                
                # TXT/NULL records (อาจใช้สำหรับ tunneling)
                if record_type in ['TXT', 'NULL']:
                    findings['suspicious_record_types'].append({
                        'domain': query,
                        'record_type': record_type,
                        'src_ip': src_ip
                    })
        
        # Excessive DNS queries
        for key, count in query_counter.most_common(20):
            if count > 100:
                findings['excessive_queries'].append({
                    'src_query': key,
                    'count': count
                })
        
        return findings
    
    def analyze_conn_logs(self, conn_log_file: str) -> Dict:
        """วิเคราะห์ Zeek conn logs"""
        findings = {
            'long_connections': [],
            'high_volume': [],
            'unusual_ports': []
        }
        
        common_ports = {80, 443, 22, 25, 53, 110, 143, 8080, 8443}
        c2_ports = {4444, 4445, 1337, 31337, 8888, 9001, 9002}
        
        with open(conn_log_file) as f:
            for line in f:
                if line.startswith('#'):
                    continue
                
                parts = line.strip().split('\t')
                if len(parts) < 10:
                    continue
                
                try:
                    src_ip = parts[2]
                    dst_ip = parts[4]
                    dst_port = int(parts[5]) if parts[5].isdigit() else 0
                    proto = parts[6]
                    duration = float(parts[8]) if parts[8] != '-' else 0
                    orig_bytes = int(parts[9]) if parts[9].isdigit() else 0
                    
                    # Long connections (potential C2)
                    if duration > 3600:  # > 1 hour
                        findings['long_connections'].append({
                            'src': src_ip,
                            'dst': dst_ip,
                            'port': dst_port,
                            'duration_hours': duration/3600
                        })
                    
                    # High data transfer
                    if orig_bytes > 100 * 1024 * 1024:  # > 100MB
                        findings['high_volume'].append({
                            'src': src_ip,
                            'dst': dst_ip,
                            'bytes_mb': orig_bytes / 1024 / 1024
                        })
                    
                    # C2 ports
                    if dst_port in c2_ports:
                        findings['unusual_ports'].append({
                            'src': src_ip,
                            'dst': dst_ip,
                            'port': dst_port
                        })
                
                except (ValueError, IndexError):
                    pass
        
        return findings
    
    def _calc_entropy(self, s: str) -> float:
        """คำนวณ Shannon entropy"""
        if not s:
            return 0.0
        
        from collections import Counter
        import math
        
        counts = Counter(s.lower())
        total = len(s)
        entropy = -sum(
            (c/total) * math.log2(c/total) 
            for c in counts.values()
        )
        return entropy


if __name__ == "__main__":
    hunter = ZeekLogHunter()
    print("[*] Zeek Log Hunter initialized")
    print("[*] Usage:")
    print("  dns_findings = hunter.analyze_dns_logs('/path/to/dns.log')")
    print("  conn_findings = hunter.analyze_conn_logs('/path/to/conn.log')")
```

---

## 9. Endpoint Hunting

### Sysmon Hunting Queries

```bash
# ===== Sysmon Configuration เพื่อ Threat Hunting =====

# ติดตั้ง Sysmon (Windows)
Sysmon64.exe -accepteula -i sysmonconfig.xml

# ===== sysmonconfig.xml (เพื่อ Threat Hunting) =====
cat > /tmp/sysmonconfig.xml << 'SYSMON'
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Process Creation -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains">powershell</CommandLine>
        <CommandLine condition="contains">cmd.exe /c</CommandLine>
        <Image condition="image">mimikatz.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Network Connection -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">4444</DestinationPort>
        <DestinationPort condition="is">1337</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- Registry Modification -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">Run</TargetObject>
        <TargetObject condition="contains">Startup</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
SYSMON

# ===== Linux Endpoint Hunting =====
# ตรวจสอบ processes ที่แปลก (hidden)
ps auxf | grep -v grep | awk '{print $11}' | sort | uniq -c | sort -rn

# ตรวจสอบ connections
ss -tlnup | grep -E '(LISTEN|ESTABLISHED)'
nc -vz 192.168.1.100 4444  # เช็คว่า C2 port เปิดหรือไม่

# ตรวจสอป SUID files ใหม่
# เปรียบเทียบกับเก่า
find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid_current.txt
diff /baseline/suid_baseline.txt /tmp/suid_current.txt

# ตรวจสอปไฟล์ที่เปลี่ยนแปลงใน 24 ชั่วโมง
find /bin /sbin /usr/bin /usr/sbin -mtime -1 -type f 2>/dev/null

# ตรวจสอป cron jobs ที่แปลก
for f in /etc/cron*/*; do echo "=== $f ==="; cat $f 2>/dev/null; done | grep -v '^#'

# ตรวจสอป authorized_keys
for home in /home/* /root; do
    if [ -f "$home/.ssh/authorized_keys" ]; then
        echo "=== $home/.ssh/authorized_keys ==="
        cat "$home/.ssh/authorized_keys"
    fi
done

# ตรวจสอป unusual listening ports
ss -tlnup | awk 'NR>1 {print $5}' | cut -d: -f2 | sort -n | uniq

# ตรวจสอป environment สำหรับ reverse shell indicators
grep -r 'bash -i\|nc -e\|/dev/tcp\|mkfifo' /tmp/ /dev/shm/ 2>/dev/null
```

---

## 10. Hunting Automation

### Automated Threat Hunt Framework

```python
#!/usr/bin/env python3
# auto_hunt.py - Automated Threat Hunting Framework

import json
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ThreatHunter')

class AutomatedThreatHunter:
    """ระบบ Threat Hunting อัตโนมัติ"""
    
    def __init__(self, config_file: str = None):
        self.findings = []
        self.hunt_stats = {
            'start_time': datetime.now().isoformat(),
            'hunts_run': 0,
            'total_findings': 0
        }
        
        # Hunt modules
        self.hunt_modules = [
            self._hunt_suspicious_processes,
            self._hunt_network_connections,
            self._hunt_file_changes,
            self._hunt_user_activity,
            self._hunt_cron_jobs
        ]
    
    def run_hunt(self) -> Dict:
        """รัน threat hunt ทุก module"""
        logger.info("Starting automated threat hunt...")
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(module) 
                for module in self.hunt_modules
            ]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.extend(result)
                except Exception as e:
                    logger.error(f"Hunt module failed: {e}")
        
        self.hunt_stats['hunts_run'] = len(self.hunt_modules)
        self.hunt_stats['total_findings'] = len(self.findings)
        self.hunt_stats['end_time'] = datetime.now().isoformat()
        
        return {
            'stats': self.hunt_stats,
            'findings': self.findings
        }
    
    def _hunt_suspicious_processes(self) -> List[Dict]:
        """ค้นหา suspicious processes"""
        findings = []
        
        suspicious_names = [
            'nc', 'netcat', 'ncat', 'socat',
            'mimikatz', 'meterpreter',
            'powershell'
        ]
        
        try:
            result = subprocess.run(
                ['ps', 'auxf'],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.split('\n'):
                for name in suspicious_names:
                    if name.lower() in line.lower():
                        findings.append({
                            'type': 'SUSPICIOUS_PROCESS',
                            'severity': 'HIGH',
                            'detail': line.strip()
                        })
                        break
        except Exception as e:
            logger.error(f"Process hunt failed: {e}")
        
        return findings
    
    def _hunt_network_connections(self) -> List[Dict]:
        """ค้นหา suspicious connections"""
        findings = []
        c2_ports = {'4444', '4445', '1337', '31337', '8888', '9001'}
        
        try:
            result = subprocess.run(
                ['ss', '-tlnup'],
                capture_output=True, text=True, timeout=30
            )
            
            import re
            for line in result.stdout.split('\n'):
                ports = re.findall(r':(\d+)', line)
                for port in ports:
                    if port in c2_ports:
                        findings.append({
                            'type': 'SUSPICIOUS_PORT',
                            'severity': 'HIGH',
                            'detail': f'C2 port {port} listening: {line.strip()}'
                        })
        except Exception as e:
            logger.error(f"Network hunt failed: {e}")
        
        return findings
    
    def _hunt_file_changes(self) -> List[Dict]:
        """ค้นหาไฟล์ที่เปลี่ยนเมื่อเร็วๆ นี้"""
        findings = []
        
        critical_dirs = ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc']
        
        try:
            for d in critical_dirs:
                result = subprocess.run(
                    ['find', d, '-mtime', '-1', '-type', 'f'],
                    capture_output=True, text=True, timeout=60
                )
                
                for line in result.stdout.split('\n'):
                    if line:
                        findings.append({
                            'type': 'RECENT_FILE_CHANGE',
                            'severity': 'MEDIUM',
                            'detail': f'Modified in last 24h: {line}'
                        })
        except Exception as e:
            logger.error(f"File hunt failed: {e}")
        
        return findings[:20]  # จำกัด findings
    
    def _hunt_user_activity(self) -> List[Dict]:
        """ค้นหา unusual user activity"""
        findings = []
        
        try:
            # ดู users ที่ login อยู่
            result = subprocess.run(
                ['w'],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.split('\n')[2:]:
                parts = line.split()
                if len(parts) >= 3:
                    user = parts[0]
                    tty = parts[1]
                    from_addr = parts[2]
                    
                    # Check สำหรับ unknown sources
                    if from_addr and from_addr != ':0' and not from_addr.startswith('192.168.'):
                        findings.append({
                            'type': 'UNUSUAL_USER_SOURCE',
                            'severity': 'MEDIUM',
                            'detail': f'User {user} logged in from {from_addr}'
                        })
        except Exception as e:
            logger.error(f"User hunt failed: {e}")
        
        return findings
    
    def _hunt_cron_jobs(self) -> List[Dict]:
        """ค้นหา suspicious cron jobs"""
        findings = []
        suspicious_patterns = [
            'bash -i',
            'nc ',
            'wget http',
            'curl http',
            'python -c',
            '/tmp/'
        ]
        
        cron_files = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/var/spool/cron/'
        ]
        
        for cron_path in cron_files:
            path = Path(cron_path)
            files = [path] if path.is_file() else list(path.rglob('*'))
            
            for f in files:
                if not f.is_file():
                    continue
                try:
                    content = f.read_text(errors='ignore')
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            findings.append({
                                'type': 'SUSPICIOUS_CRON',
                                'severity': 'HIGH',
                                'detail': f'Suspicious cron in {f}: contains "{pattern}"'
                            })
                            break
                except Exception:
                    pass
        
        return findings
    
    def save_report(self, output_file: str = "/tmp/hunt_report.json"):
        """บันทึก report"""
        report = {
            'stats': self.hunt_stats,
            'findings': self.findings
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Hunt report saved: {output_file}")


# รัน automated hunt
if __name__ == "__main__":
    hunter = AutomatedThreatHunter()
    
    print("[*] Starting Automated Threat Hunt...")
    results = hunter.run_hunt()
    
    print(f"\n[+] Hunt Complete!")
    print(f"    Modules run: {results['stats']['hunts_run']}")
    print(f"    Findings: {results['stats']['total_findings']}")
    
    if results['findings']:
        print("\n[!] Findings:")
        for f in results['findings']:
            print(f"  [{f['severity']}] {f['type']}: {f['detail'][:100]}")
    
    hunter.save_report()
```

---

## แบบฝึกหัด

### Lab 67.1: MITRE ATT&CK-based Hunt

```bash
# ===== Lab: Hunt for T1059.001 PowerShell Execution =====

# 1. สร้าง simulated malicious activity
# PowerShell download + execute
echo "Simulating PowerShell C2..."

# ตรวจสอบ PowerShell logs
grep -r 'powershell' /var/log/ 2>/dev/null | head -20

# ค้นหา encoded commands
find / -name '*.ps1' -newer /tmp -type f 2>/dev/null

# 2. รัน automated hunt
python3 << 'EOF'
import json
from datetime import datetime

# Mock hunt results
hunt_result = {
    'hunt_id': f"HUNT-{datetime.now().strftime('%Y%m%d-%H%M')}",
    'technique': 'T1059.001 - PowerShell',
    'data_sources': ['Process creation logs', 'PowerShell logs'],
    'findings': [
        {
            'severity': 'HIGH',
            'description': 'Encoded PowerShell command detected',
            'detail': 'powershell.exe -enc SQBFAFgAIAAo...'
        }
    ]
}

print(json.dumps(hunt_result, indent=2))
EOF

# 3. สร้าง YARA rule เพื่อ detect
cat > /tmp/ps_hunt.yar << 'EOF'
rule Suspicious_PowerShell
{
    meta:
        description = "Suspicious PowerShell execution"
        author = "Threat Hunter"
    strings:
        $enc = "-EncodedCommand" nocase
        $iex = "IEX" nocase
        $dl = "DownloadString" nocase
    condition:
        any of them
}
EOF

yara /tmp/ps_hunt.yar /var/log/ -r 2>/dev/null || echo "[*] No matches in logs (expected in clean env)"
```

---

## สรุป

| เครื่องมือ | หน้าที่ |
|-----------|------|
| Splunk | Log hunting + SIEM |
| Microsoft Sentinel | Cloud-native SIEM + KQL |
| Zeek/Bro | Network monitoring |
| MITRE ATT&CK Navigator | TTP visualization |
| Velociraptor | Endpoint hunting at scale |
| YARA | Pattern matching |

### Threat Hunt Checklist

- [ ] สร้าง baseline ของ normal behavior
- [ ] ระบุ MITRE ATT&CK techniques ที่จะ hunt
- [ ] เขียน hypothesis ที่ชัดเจน
- [ ] เก็บ log sources ที่เพียงพอ
- [ ] รัน hunt queries
- [ ] Document findings ทุกอย่าง
- [ ] สร้าง detection rules จาก findings
- [ ] เพิ่ม IOCs เข้า threat intel platform

---

← [Part 66: Incident Response](Part-66-Incident-Response.md) | [Part 68: Malware Analysis](Part-68-Malware-Analysis.md) →
