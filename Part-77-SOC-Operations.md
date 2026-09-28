# Part 77: SOC Operations - ศูนย์ปฏิบัติการความปลอดภัย

## สารบัญ
1. [SOC คืออะไร](#soc-คืออะไร)
2. [SOC Tier Model](#soc-tier-model)
3. [SIEM Architecture](#siem-architecture)
4. [Alert Triage และ Investigation](#alert-triage-และ-investigation)
5. [Incident Response Playbooks](#incident-response-playbooks)
6. [Log Management](#log-management)
7. [EDR Integration](#edr-integration)
8. [SOC Automation (SOAR)](#soc-automation-soar)
9. [SOC Metrics](#soc-metrics)
10. [SOC Tooling](#soc-tooling)

---

## 1. SOC คืออะไร

```
Security Operations Center (SOC):

┌────────────────────────────────────────────────────┐
│                  SOC                               │
│                                                    │
│  People    +    Process    +    Technology          │
│                                                    │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │Analyst  │  │Playbook │  │  SIEM   │            │
│  │ Tier1   │  │Incident │  │  EDR    │            │
│  │ Tier2   │  │Response │  │  SOAR   │            │
│  │ Tier3   │  │ Process │  │  UEBA   │            │
│  └─────────┘  └─────────┘  └─────────┘            │
└────────────────────────────────────────────────────┘

Core Functions:
- Monitor: 24x7 Monitoring ระบบและ Network
- Detect: ตรวจจับ Threats และ Anomalies
- Respond: Incident Response แบบ Structured
- Recover: ฟื้นฟูระบบหลัง Incident
- Improve: เรียนรู้และปรับปรุงอย่างต่อเนื่อง
```

---

## 2. SOC Tier Model

```python
SOC_TIERS = {
    "Tier 1": {
        "role": "Alert Analyst",
        "responsibilities": [
            "ตรวจสอบและคัดกรอง Alerts",
            "ทำ Initial Triage",
            "เก็บ Log และ Evidence เบื้องต้น",
            "ส่งต่อ Tier 2 หากไม่สามารถแก้ไขได้เอง"
        ],
        "tools": ["SIEM Dashboard", "Ticketing System", "Threat Intel Lookup"],
        "avg_response_time": "< 30 minutes"
    },
    "Tier 2": {
        "role": "Incident Responder",
        "responsibilities": [
            "สืบสวน Incidents ที่ซับซ้อน",
            "Digital Forensics เบื้องต้น",
            "Containment และ Eradication",
            "Threat Hunting"
        ],
        "tools": ["EDR Console", "Forensic Tools", "SIEM Advanced Search"],
        "avg_response_time": "< 4 hours"
    },
    "Tier 3": {
        "role": "Senior Analyst / Threat Hunter",
        "responsibilities": [
            "เข้ยน Detection Rules ใหม่",
            "Proactive Threat Hunting",
            "Red Team Support",
            "Malware Analysis",
            "Purple Team Exercises"
        ],
        "tools": ["Malware Sandbox", "Reverse Engineering Tools", "Custom Scripts"],
        "avg_response_time": "Proactive"
    }
}
```

---

## 3. SIEM Architecture

```bash
#!/bin/bash
# siem_setup.sh - ติดตั้ง ELK Stack SIEM

# ติดตั้ง Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  tee /etc/apt/sources.list.d/elastic-8.x.list
apt-get update && apt-get install -y elasticsearch

# Config
cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
cluster.name: soc-cluster
node.name: soc-node-1
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
EOF

systemctl enable elasticsearch --now

# ติดตั้ง Kibana
apt-get install -y kibana

cat > /etc/kibana/kibana.yml << 'EOF'
server.host: "0.0.0.0"
server.port: 5601
elasticsearch.hosts: ["http://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "kibana_password"
EOF

systemctl enable kibana --now

# ติดตั้ง Logstash
apt-get install -y logstash

# Windows Event Log Pipeline
cat > /etc/logstash/conf.d/windows-events.conf << 'EOF'
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/logstash/ssl/logstash.crt"
    ssl_key => "/etc/logstash/ssl/logstash.key"
  }
}

filter {
  if [agent][type] == "winlogbeat" {
    # เพิ่ม GeoIP สำหรับ Network Events
    if [source][ip] {
      geoip {
        source => "[source][ip]"
        target => "[source][geo]"
      }
    }
    
    # Parse Windows Event
    if [winlog][event_id] == 4624 {
      mutate {
        add_tag => ["authentication", "logon"]
      }
    }
    
    if [winlog][event_id] == 4769 {
      mutate {
        add_tag => ["kerberos", "tgs_request"]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "winlogbeat-%{+YYYY.MM.dd}"
    user => "elastic"
    password => "elastic_password"
  }
}
EOF

systemctl enable logstash --now

# ติดตั้ง Winlogbeat บน Windows
# ดาวน์โหลด: https://www.elastic.co/downloads/beats/winlogbeat

# winlogbeat.yml
cat << 'EOF'
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4634, 4648, 4669, 4672, 
              4698, 4702, 4768, 4769, 4776
  - name: System
  - name: Application
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104

output.logstash:
  hosts: ["192.168.1.50:5044"]
  ssl.certificate_authorities: ["/etc/ssl/certs/logstash-ca.crt"]
EOF

echo "[+] ELK Stack SIEM setup complete"
echo "    Kibana: http://localhost:5601"
echo "    Elasticsearch: http://localhost:9200"
```

### Splunk Configuration

```bash
# ติดตั้ง Splunk Enterprise
wget -O splunk.deb 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?...'
dpkg -i splunk.deb
/opt/splunk/bin/splunk start --accept-license --answer-yes

# ติดตั้ง Splunk Universal Forwarder บน Windows
# Download: https://www.splunk.com/en_us/download/universal-forwarder.html

# ตั้งค่า Inputs บน Forwarder
$SPLUNK_HOME\bin\splunk add monitor C:\Windows\System32\winevt\Logs\
$SPLUNK_HOME\bin\splunk add forward-server 192.168.1.50:9997
$SPLUNK_HOME\bin\splunk restart

# inputs.conf สำหรับ Sysmon
cat > C:\Program Files\SplunkUniversalForwarder\etc\apps\search\local\inputs.conf << 'EOF'
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = winsysmon
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
renderXml = 1
EOF

# Splunk Saved Searches (Detection Rules)
cat > /opt/splunk/etc/apps/search/local/savedsearches.conf << 'EOF'
[Kerberoasting Detection]
cron_schedule = */15 * * * *
dispatch.earliest_time = -15m
dispatch.latest_time = now
enableSched = 1
search = index=wineventlog EventCode=4769 TicketEncryptionType=0x17 NOT ServiceName="*$" | stats count by Account_Name, ServiceName | where count > 5
alert.track = 1
alert.severity = 3
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0

[LSASS Access Detection]
cron_schedule = */5 * * * *
dispatch.earliest_time = -5m
dispatch.latest_time = now
enableSched = 1
search = index=winsysmon EventCode=10 TargetImage="*lsass.exe" GrantedAccess=0x1fffff
alert.track = 1
alert.severity = 5
EOF
```

---

## 4. Alert Triage และ Investigation

```python
#!/usr/bin/env python3
# alert_triage.py - Alert Triage System

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum
import json

class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class AlertStatus(str, Enum):
    NEW = "new"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"

@dataclass
class Alert:
    """ออบเจ็กต์แทน Alert"""
    id: str
    title: str
    description: str
    severity: AlertSeverity
    source: str           # SIEM, EDR, etc.
    technique_id: str     # ATT&CK
    affected_host: str
    affected_user: str
    raw_event: Dict
    created_at: datetime = field(default_factory=datetime.now)
    status: AlertStatus = AlertStatus.NEW
    assigned_to: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    iocs: List[Dict] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    escalated: bool = False
    tier: int = 1

class AlertTriageSystem:
    """ระบบ Triage Alert สำหรับ SOC"""
    
    def __init__(self):
        self.alerts: Dict[str, Alert] = {}
        self.analysts = {"tier1": [], "tier2": [], "tier3": []}
    
    def receive_alert(self, alert_data: Dict) -> Alert:
        """รับ Alert ใหม่เข้าระบบ"""
        alert = Alert(
            id=alert_data["id"],
            title=alert_data["title"],
            description=alert_data["description"],
            severity=AlertSeverity(alert_data["severity"]),
            source=alert_data["source"],
            technique_id=alert_data.get("technique_id", ""),
            affected_host=alert_data.get("host", "unknown"),
            affected_user=alert_data.get("user", "unknown"),
            raw_event=alert_data.get("raw_event", {})
        )
        
        # กำหนด Tier อัตโนมัติ
        alert.tier = self._determine_tier(alert)
        
        self.alerts[alert.id] = alert
        print(f"[+] New Alert: [{alert.severity.upper()}] {alert.title}")
        print(f"    Host: {alert.affected_host} | User: {alert.affected_user}")
        print(f"    Assigned to: Tier {alert.tier}")
        
        return alert
    
    def _determine_tier(self, alert: Alert) -> int:
        """กำหนดว่า Alert ควรไปทีมไหน"""
        if alert.severity == AlertSeverity.CRITICAL:
            return 2  # Tier 2 จัดการทันที
        elif alert.severity == AlertSeverity.HIGH:
            # Technique ที่ซับซ้อน ไป Tier 2
            complex_techniques = ["T1003", "T1055", "T1550", "T1558"]
            if any(alert.technique_id.startswith(t) for t in complex_techniques):
                return 2
        return 1
    
    def triage_alert(self, alert_id: str, analyst: str,
                     verdict: str, notes: str) -> Alert:
        """
        Triage Alert
        verdict: 'true_positive', 'false_positive', 'needs_investigation'
        """
        alert = self.alerts[alert_id]
        alert.assigned_to = analyst
        alert.notes.append(f"[{datetime.now().isoformat()}] {analyst}: {notes}")
        
        if verdict == "false_positive":
            alert.status = AlertStatus.FALSE_POSITIVE
            print(f"[*] Alert {alert_id} marked as False Positive")
        elif verdict == "true_positive":
            alert.status = AlertStatus.IN_PROGRESS
            print(f"[!] Alert {alert_id} confirmed as True Positive - Starting IR")
            self._start_incident_response(alert)
        elif verdict == "needs_investigation":
            # Escalate to Tier 2
            if alert.tier == 1:
                alert.tier = 2
                alert.escalated = True
                alert.status = AlertStatus.ESCALATED
                print(f"[*] Alert {alert_id} escalated to Tier 2")
        
        return alert
    
    def _start_incident_response(self, alert: Alert):
        """เริ่ม Incident Response"""
        print(f"[!] Starting IR for: {alert.title}")
        print(f"    Technique: {alert.technique_id}")
        print(f"    Host: {alert.affected_host}")
        print(f"    User: {alert.affected_user}")
        
        # เลือก Playbook ตาม Technique
        playbook = self._get_playbook(alert.technique_id)
        if playbook:
            print(f"    Playbook: {playbook['name']}")
    
    def _get_playbook(self, technique_id: str) -> Optional[Dict]:
        """Map Technique ไปยัง Playbook"""
        TECHNIQUE_PLAYBOOKS = {
            "T1558.003": "Kerberoasting Response",
            "T1003.001": "LSASS Dump Response",
            "T1550.002": "Pass-the-Hash Response",
            "T1059.001": "Malicious PowerShell Response",
            "T1566": "Phishing Response",
            "T1486": "Ransomware Response"
        }
        
        for tech_prefix, playbook_name in TECHNIQUE_PLAYBOOKS.items():
            if technique_id.startswith(tech_prefix):
                return {"name": playbook_name, "technique": tech_prefix}
        return None
    
    def get_dashboard(self) -> Dict:
        """สร้าง SOC Dashboard Data"""
        total = len(self.alerts)
        by_severity = {}
        by_status = {}
        
        for alert in self.alerts.values():
            # By Severity
            sev = alert.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            # By Status
            status = alert.status.value
            by_status[status] = by_status.get(status, 0) + 1
        
        return {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_status": by_status,
            "open_alerts": sum(1 for a in self.alerts.values()
                              if a.status not in [AlertStatus.RESOLVED,
                                                  AlertStatus.FALSE_POSITIVE,
                                                  AlertStatus.CLOSED]),
            "false_positive_rate": (
                sum(1 for a in self.alerts.values()
                    if a.status == AlertStatus.FALSE_POSITIVE) / total * 100
                if total > 0 else 0
            )
        }

# ตัวอย่าง
triage = AlertTriageSystem()

alert = triage.receive_alert({
    "id": "ALT-001",
    "title": "Kerberoasting Detected",
    "description": "Multiple TGS requests for RC4 encryption",
    "severity": "high",
    "source": "Splunk",
    "technique_id": "T1558.003",
    "host": "DC01",
    "user": "suspicious_user",
    "raw_event": {"EventCode": 4769, "count": 15}
})

triage.triage_alert(
    "ALT-001",
    analyst="analyst1",
    verdict="true_positive",
    notes="Confirmed - 15 TGS requests in 5 minutes from single user"
)

print(json.dumps(triage.get_dashboard(), indent=2))
```

---

## 5. Incident Response Playbooks

```python
#!/usr/bin/env python3
# ir_playbooks.py - Incident Response Playbooks

IR_PLAYBOOKS = {
    "ransomware": {
        "name": "Ransomware Incident Response",
        "technique": "T1486",
        "severity": "critical",
        "phases": {
            "1_identify": {
                "name": "Identification",
                "steps": [
                    "ระบุหน่วยงานที่ได้รับผลกระทบ",
                    "ระบุประเภท Ransomware จาก Ransom Note",
                    "ประเมินขอบเขตการเข้ารหัส",
                    "ตรวจสอบ Initial Access Vector"
                ],
                "queries": {
                    "splunk": 'index=endpoint action="file_modification" | stats count by host, user | sort -count'
                }
            },
            "2_contain": {
                "name": "Containment",
                "steps": [
                    "แยกระบบที่ติดเชื้อออกจาก Network ทันที
# ใช้ EDR หรือจับ Network Adapter (วิธี: powershell Disable-NetAdapter)",
                    "ปิดการ Share Network ระหว่างเครื่อง",
                    "สำรองประบวลผลผู้ใช้ (revoke credentials)",
                    "สำรอง Domain Admin Accounts"
                ],
                "commands": [
                    "# Isolate Host via PowerShell",
                    "Disable-NetAdapter -Name * -Confirm:$false",
                    "# Block User Account",
                    "Disable-ADAccount -Identity 'compromised_user'",
                    "# Revoke Active Kerberos Tickets",
                    "Invoke-Command -ComputerName DC01 { klist purge }"
                ]
            },
            "3_eradicate": {
                "name": "Eradication",
                "steps": [
                    "ลบ Malware และ Artifacts",
                    "ระบุและลบ Persistence Mechanisms",
                    "เปลี่ยน Compromised Credentials",
                    "ลบ Domain Account ที่ถูกสร้างโดย Attacker"
                ]
            },
            "4_recover": {
                "name": "Recovery",
                "steps": [
                    "คืนค่าไฟล์จาก Backup (ใช้แอดสำรองหลัง Infection)",
                    "ติดตั้ง OS ใหม่ (หากจำเป็น)",
                    "ตรวจสอบว่าไฟล์ที่คืนค่าไม่ถูกเข้ารหัสแล้ว",
                    "ติดตามการ Monitor หลัง Recovery"
                ]
            }
        }
    },
    
    "phishing": {
        "name": "Phishing Incident Response",
        "technique": "T1566",
        "severity": "medium",
        "phases": {
            "1_identify": {
                "name": "Identification",
                "steps": [
                    "รับ Email Header Analysis",
                    "ตรวจสอบ Link และ Attachment",
                    "ระบุผู้รับ Email ที่คลิก Link",
                    "เปิด URL ใน Sandbox"
                ],
                "commands": [
                    "# ตรวจสอบ URL ด้วย VirusTotal",
                    "curl https://www.virustotal.com/api/v3/urls \\",
                    "  -H 'x-apikey: VT_KEY' \\",
                    "  --data url=https://malicious.com",
                    "",
                    "# ดู Users ที่คลิกลิงก์ไปจาก Proxy Logs",
                    "grep 'malicious.com' /var/log/proxy/access.log | awk '{print $1}' | sort | uniq"
                ]
            },
            "2_contain": {
                "name": "Containment",
                "steps": [
                    "ลบหรือวาง Quarantine Email",
                    "Block Domain/URL ใน Proxy และ Email Gateway",
                    "สั่งให้ Users ที่คลิก Report ความสงสัย",
                    "ตรวจสอบว่ามีการเข้ารหัส Credentials แล้วหรือไม่"
                ]
            }
        }
    },
    
    "credential_theft": {
        "name": "Credential Theft Response",
        "technique": "T1003",
        "severity": "critical",
        "phases": {
            "1_identify": {
                "name": "Identification",
                "steps": [
                    "ระบุ Endpoint ที่ถูก Compromise",
                    "ตรวจสอบ Authentication Logs",
                    "ระบุ Accounts ที่อาจถูก Compromise",
                    "ตรวจหา Lateral Movement ของ Stolen Credentials"
                ],
                "queries": {
                    "splunk": """
# ค้นหาการใช้ Credentials ผิดปกติ
index=wineventlog EventCode=4624 
    Account_Name="VICTIM_USER"
    Logon_Type=3
| stats count by Workstation_Name, IpAddress, _time
| sort -_time"""
                }
            },
            "2_contain": {
                "name": "Containment",
                "steps": [
                    "เปลี่ยน Password ผู้ใช้ที่ถูก Compromise",
                    "Revoke ทุก Session Token และ Certificate",
                    "ปิด Account ชั่วคราวไม่เวลา Off-Hours",
                    "Audit การเข้าถึง Resources ที่ผิดปกติ"
                ],
                "commands": [
                    "# เปลี่ยน Password ผู้ใช้ AD",
                    "Set-ADAccountPassword -Identity 'victim_user' -Reset -NewPassword (ConvertTo-SecureString 'NewP@ssword!' -AsPlainText -Force)",
                    "",
                    "# Disable Account ชั่วคราว",
                    "Disable-ADAccount -Identity 'victim_user'",
                    "",
                    "# ลบ Kerberos Tickets",
                    "klist purge -li 0x3e7"
                ]
            }
        }
    }
}

class PlaybookExecutor:
    """Execute IR Playbook"""
    
    def __init__(self):
        self.playbooks = IR_PLAYBOOKS
        self.execution_log = []
    
    def get_playbook(self, incident_type: str) -> Dict:
        """ดึง Playbook ตามประเภท Incident"""
        return self.playbooks.get(incident_type, {})
    
    def print_playbook(self, playbook_name: str):
        """แสดงขั้นตอน Playbook"""
        pb = self.playbooks.get(playbook_name)
        if not pb:
            print(f"Playbook '{playbook_name}' not found")
            return
        
        print(f"\n{'='*60}")
        print(f"PLAYBOOK: {pb['name']}")
        print(f"Technique: {pb['technique']} | Severity: {pb['severity']}")
        print(f"{'='*60}")
        
        for phase_key in sorted(pb["phases"].keys()):
            phase = pb["phases"][phase_key]
            print(f"\n[Phase {phase_key.split('_')[0]}] {phase['name']}")
            print("-" * 40)
            for i, step in enumerate(phase.get("steps", []), 1):
                print(f"  {i}. {step}")
            
            commands = phase.get("commands", [])
            if commands:
                print("\n  Commands:")
                for cmd in commands:
                    print(f"    {cmd}")

executor = PlaybookExecutor()
executor.print_playbook("ransomware")
```

---

## 6. Log Management

```python
#!/usr/bin/env python3
# log_management.py - จัดการ Logs สำหรับ SOC

LOG_SOURCES = {
    "windows_security": {
        "description": "Windows Security Event Log",
        "critical_event_ids": {
            4624: "Successful Logon",
            4625: "Failed Logon",
            4634: "Logoff",
            4648: "Explicit Credential Logon",
            4672: "Admin Logon",
            4698: "Scheduled Task Created",
            4702: "Scheduled Task Updated",
            4720: "User Account Created",
            4728: "User Added to Security Group",
            4732: "User Added to Local Admin Group",
            4768: "Kerberos TGT Request",
            4769: "Kerberos TGS Request",
            4776: "NTLM Authentication"
        },
        "volume": "high",
        "retention_days": 90
    },
    
    "sysmon": {
        "description": "Sysmon Process and Network Events",
        "critical_event_ids": {
            1: "Process Create",
            3: "Network Connection",
            7: "Image Loaded",
            8: "CreateRemoteThread",
            10: "ProcessAccess",
            11: "File Create",
            12: "Registry Object Added/Deleted",
            13: "Registry Value Set",
            15: "File Create (Stream Hash)",
            22: "DNS Query",
            23: "File Delete Archived",
            25: "Process Tampering"
        },
        "volume": "very_high",
        "retention_days": 30
    },
    
    "network": {
        "description": "Network Flow Logs (NetFlow/PCAP)",
        "critical_fields": [
            "src_ip", "dest_ip", "dest_port", "protocol",
            "bytes_transferred", "connection_duration"
        ],
        "volume": "extremely_high",
        "retention_days": 30
    },
    
    "endpoint": {
        "description": "EDR Telemetry",
        "critical_data": [
            "Process Execution", "Network Connections",
            "File Operations", "Registry Changes",
            "Memory Operations"
        ],
        "volume": "high",
        "retention_days": 90
    },
    
    "dns": {
        "description": "DNS Query Logs",
        "critical_fields": [
            "query", "query_type", "response",
            "src_ip", "timestamp"
        ],
        "volume": "high",
        "retention_days": 30
    }
}

SYSMON_CONFIG = """
<!-- Sysmon Configuration for SOC -->
<Sysmon schemaversion="4.90">
  <HashAlgorithms>MD5,SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  
  <EventFiltering>
    <!-- Log Process Creation -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <!-- ยกเว้น Processes ที่เชื่อถือได้ -->
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Log Network Connections - ยกเว้น Common -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- หยุด Ports สำคัญ -->
        <DestinationPort condition="is">445</DestinationPort>
        <DestinationPort condition="is">3389</DestinationPort>
        <DestinationPort condition="is">5985</DestinationPort>
        <DestinationPort condition="is">5986</DestinationPort>
        <DestinationPort condition="is">22</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
    
    <!-- Log Process Access to LSASS -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
    
    <!-- Log Registry Modifications บน Autorun Keys -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">\CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">\Winlogon\Userinit</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    
    <!-- Log DNS Queries -->
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <!-- ยกเว้น Windows Updates -->
        <QueryName condition="end with">.microsoft.com</QueryName>
        <QueryName condition="end with">.windowsupdate.com</QueryName>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"""

print(SYSMON_CONFIG)

# Log Retention Policy
LOG_RETENTION_POLICY = {
    "critical_security_logs": {
        "description": "Authentication, Privileged Operations",
        "hot_storage_days": 90,    # สำหรับ Query บ่อย
        "warm_storage_days": 365,  # สำหรับ Investigations
        "cold_storage_days": 2555, # 7 years สำหรับ Compliance
    },
    "network_logs": {
        "hot_storage_days": 30,
        "warm_storage_days": 90,
        "cold_storage_days": 365,
    },
    "endpoint_telemetry": {
        "hot_storage_days": 30,
        "warm_storage_days": 90,
        "cold_storage_days": 180,
    }
}
```

---

## 7. EDR Integration

```python
#!/usr/bin/env python3
# edr_integration.py - เชื่อมต่อ EDR สำหรับ SOC Automation

import requests
from typing import Dict, List

class CrowdStrikeIntegration:
    """เชื่อมต่อ CrowdStrike Falcon API"""
    
    def __init__(self, client_id: str, client_secret: str):
        self.base_url = "https://api.crowdstrike.com"
        self.token = self._authenticate(client_id, client_secret)
    
    def _authenticate(self, client_id: str, client_secret: str) -> str:
        """OAuth2 Authentication"""
        resp = requests.post(
            f"{self.base_url}/oauth2/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret
            }
        )
        return resp.json()["access_token"]
    
    def get_detections(self, filter_query: str = "", limit: int = 100) -> List[Dict]:
        """ดึง Detections"""
        headers = {"Authorization": f"Bearer {self.token}"}
        params = {"limit": limit}
        if filter_query:
            params["filter"] = filter_query
        
        resp = requests.get(
            f"{self.base_url}/detects/queries/detects/v1",
            headers=headers, params=params
        )
        detection_ids = resp.json().get("resources", [])
        
        if not detection_ids:
            return []
        
        # ดึง Details
        detail_resp = requests.post(
            f"{self.base_url}/detects/entities/summaries/GET/v1",
            headers={**headers, "Content-Type": "application/json"},
            json={"ids": detection_ids}
        )
        return detail_resp.json().get("resources", [])
    
    def isolate_host(self, device_id: str) -> bool:
        """Network Isolate Host"""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        resp = requests.post(
            f"{self.base_url}/devices/entities/devices-actions/v2",
            headers=headers,
            params={"action_name": "contain"},
            json={"ids": [device_id], "action_parameters": []}
        )
        return resp.status_code == 202
    
    def run_script(self, device_id: str, script: str) -> Dict:
        """RTR (Real-Time Response) - Run Script บน Host"""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        # เริ่ม RTR Session
        session_resp = requests.post(
            f"{self.base_url}/real-time-response/entities/sessions/v1",
            headers=headers,
            json={"device_id": device_id}
        )
        session_id = session_resp.json()["resources"][0]["session_id"]
        
        # รัน Command
        cmd_resp = requests.post(
            f"{self.base_url}/real-time-response/entities/active-responder-command/v1",
            headers=headers,
            json={
                "session_id": session_id,
                "base_command": "runscript",
                "command_string": f"runscript -Raw ```{script}```"
            }
        )
        return cmd_resp.json()
    
    def get_process_tree(self, device_id: str, process_id: str) -> List[Dict]:
        """ดึง Process Tree สำหรับ Investigation"""
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = requests.get(
            f"{self.base_url}/incidents/queries/behaviors/v1",
            headers=headers,
            params={"filter": f"device_id:'{device_id}'+process_id:'{process_id}'"}
        )
        return resp.json().get("resources", [])
    
    def search_threats(self, ioc_type: str, ioc_value: str) -> List[Dict]:
        """ค้นหา Threats ด้วย IOC"""
        headers = {"Authorization": f"Bearer {self.token}"}
        
        ioc_type_map = {
            "md5": "md5",
            "sha256": "sha256",
            "ip": "ipv4",
            "domain": "domain"
        }
        
        falcon_type = ioc_type_map.get(ioc_type, "md5")
        
        resp = requests.get(
            f"{self.base_url}/iocs/queries/indicators/v1",
            headers=headers,
            params={
                "filter": f"type:'{falcon_type}'+value:'{ioc_value}'"
            }
        )
        return resp.json().get("resources", [])

class MicrosoftDefenderIntegration:
    """เชื่อมต่อ Microsoft Defender for Endpoint"""
    
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.token = self._get_token(tenant_id, client_id, client_secret)
        self.base_url = "https://api.securitycenter.microsoft.com/api"
    
    def _get_token(self, tenant_id: str, client_id: str, client_secret: str) -> str:
        """Get OAuth2 Token"""
        resp = requests.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "resource": "https://api.securitycenter.microsoft.com"
            }
        )
        return resp.json()["access_token"]
    
    def get_alerts(self, severity: str = None) -> List[Dict]:
        """ดึง Alerts จาก Defender"""
        headers = {"Authorization": f"Bearer {self.token}"}
        params = {"$top": 100}
        if severity:
            params["$filter"] = f"severity eq '{severity}'"
        
        resp = requests.get(
            f"{self.base_url}/alerts",
            headers=headers, params=params
        )
        return resp.json().get("value", [])
    
    def run_advanced_hunting(self, kql_query: str) -> List[Dict]:
        """KQL Advanced Hunting Query"""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        resp = requests.post(
            f"{self.base_url}/advancedqueries/run",
            headers=headers,
            json={"Query": kql_query}
        )
        return resp.json().get("Results", [])
    
    def isolate_machine(self, machine_id: str, reason: str) -> bool:
        """แยกระบบ Endpoint"""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        resp = requests.post(
            f"{self.base_url}/machines/{machine_id}/isolate",
            headers=headers,
            json={"Comment": reason, "IsolationType": "Selective"}
        )
        return resp.status_code == 201

# ตัวอย่าง Advanced Hunting Query
KQL_QUERIES = {
    "lsass_dump": """
DeviceProcessEvents
| where FileName =~ 'mimikatz.exe' or 
  (FileName =~ 'rundll32.exe' and ProcessCommandLine has 'MiniDump')
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| take 100""",
    
    "kerberoasting": """
DeviceEvents
| where ActionType == "KerberosServiceTicketRequest"
| where AdditionalFields has 'RC4'
| summarize count() by DeviceName, AccountName, bin(Timestamp, 5m)
| where count_ > 5""",
    
    "powershell_download": """
DeviceProcessEvents
| where FileName =~ 'powershell.exe'
| where ProcessCommandLine has_any ('DownloadString', 'WebClient', 'Net.Http')
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| take 100"""
}

print("KQL Queries available:", list(KQL_QUERIES.keys()))
```

---

## 8. SOC Automation (SOAR)

```python
#!/usr/bin/env python3
# soar_automation.py - Security Orchestration, Automation and Response

import asyncio
from typing import Dict, List, Callable
from datetime import datetime

class SOARPlaybook:
    """อัตโนมัติ IR ผ่าน SOAR"""
    
    def __init__(self, name: str):
        self.name = name
        self.steps: List[Dict] = []
        self.conditions: Dict[str, Callable] = {}
    
    def add_step(self, name: str, action: Callable, 
                 condition: Callable = None, continue_on_fail: bool = False):
        """เพิ่มขั้นตอน"""
        self.steps.append({
            "name": name,
            "action": action,
            "condition": condition,
            "continue_on_fail": continue_on_fail
        })
    
    async def execute(self, context: Dict) -> Dict:
        """รัน Playbook"""
        results = []
        context["start_time"] = datetime.now().isoformat()
        context["playbook"] = self.name
        
        for step in self.steps:
            # ตรวจสอบ Condition
            if step["condition"] and not step["condition"](context):
                print(f"  [SKIP] {step['name']} - Condition not met")
                continue
            
            print(f"  [RUN] {step['name']}")
            try:
                result = await step["action"](context)
                results.append({"step": step["name"], "status": "success", "result": result})
                context[f"{step['name']}_result"] = result
                print(f"  [OK] {step['name']}")
            except Exception as e:
                print(f"  [FAIL] {step['name']}: {e}")
                results.append({"step": step["name"], "status": "failed", "error": str(e)})
                if not step["continue_on_fail"]:
                    break
        
        context["end_time"] = datetime.now().isoformat()
        return {"playbook": self.name, "results": results, "context": context}

# สร้าง Automated Playbook สำหรับ Phishing
async def check_url_vt(context: Dict) -> Dict:
    """ตรวจสอบ URL ด้วย VirusTotal"""
    url = context.get("suspicious_url", "")
    # จริงๆ จะ API Call
    return {"url": url, "malicious": True, "detections": 15}

async def block_url(context: Dict) -> bool:
    """บล็อก URL ใน Proxy"""
    url = context.get("suspicious_url", "")
    vt_result = context.get("check_url_vt_result", {})
    if vt_result.get("malicious"):
        print(f"  บล็อก URL: {url} ใน Proxy")
        return True
    return False

async def check_email_recipients(context: Dict) -> List[str]:
    """ระบุผู้รับ Email ที่ได้รับ Phishing"""
    # จริงๆ จะ Query Email Logs
    return ["user1@company.com", "user2@company.com"]

async def quarantine_email(context: Dict) -> bool:
    """เอา Email เข้า Quarantine"""
    recipients = context.get("check_email_recipients_result", [])
    for recipient in recipients:
        print(f"  วาง Quarantine Email ของ {recipient}")
    return True

async def notify_users(context: Dict) -> bool:
    """แจ้งเตือน Users"""
    recipients = context.get("check_email_recipients_result", [])
    for user in recipients:
        print(f"  ส่งแจ้งเตือน Security Alert หากคลิกลิงก์ไปยัง {user}")
    return True

async def create_ticket(context: Dict) -> str:
    """สร้าง Ticket ใน ITSM"""
    ticket_id = f"INC-{int(datetime.now().timestamp())}"
    print(f"  สร้าง Incident Ticket: {ticket_id}")
    return ticket_id

# สร้าง Playbook
phishing_playbook = SOARPlaybook("Phishing Response")
phishing_playbook.add_step("check_url_vt", check_url_vt)
phishing_playbook.add_step("block_url", block_url,
    condition=lambda ctx: ctx.get("check_url_vt_result", {}).get("malicious"))
phishing_playbook.add_step("check_email_recipients", check_email_recipients)
phishing_playbook.add_step("quarantine_email", quarantine_email)
phishing_playbook.add_step("notify_users", notify_users)
phishing_playbook.add_step("create_ticket", create_ticket)

async def main():
    context = {
        "alert_id": "ALT-002",
        "suspicious_url": "https://evil.com/download",
        "triggered_by": "Email Gateway Alert"
    }
    
    print(f"\n=== Running Playbook: Phishing Response ===")
    result = await phishing_playbook.execute(context)
    
    print(f"\n=== Playbook Complete ===")
    for r in result["results"]:
        status = "✅" if r["status"] == "success" else "❌"
        print(f"  {status} {r['step']}")

asyncio.run(main())
```

---

## 9. SOC Metrics

```python
#!/usr/bin/env python3
# soc_metrics.py - KPIs และ Metrics สำหรับ SOC

from dataclasses import dataclass
from typing import List

@dataclass
class SOCMetrics:
    """SOC Performance Metrics"""
    
    # Volume Metrics
    total_alerts: int
    true_positives: int
    false_positives: int
    total_incidents: int
    
    # Time Metrics (minutes)
    mttd_times: List[float]    # Mean Time to Detect
    mttr_times: List[float]    # Mean Time to Respond
    mttc_times: List[float]    # Mean Time to Contain
    
    # Coverage Metrics
    detection_coverage_pct: float
    log_coverage_pct: float
    
    @property
    def false_positive_rate(self) -> float:
        total = self.true_positives + self.false_positives
        return (self.false_positives / total * 100) if total > 0 else 0
    
    @property
    def mttd(self) -> float:
        return sum(self.mttd_times) / len(self.mttd_times) if self.mttd_times else 0
    
    @property
    def mttr(self) -> float:
        return sum(self.mttr_times) / len(self.mttr_times) if self.mttr_times else 0
    
    @property
    def mttc(self) -> float:
        return sum(self.mttc_times) / len(self.mttc_times) if self.mttc_times else 0
    
    def generate_scorecard(self) -> str:
        return f"""
┌────────────────────────────────────────────────────┐
│          SOC Monthly Scorecard                   │
├────────────────────────────────────────────────────┤
│ Alert Metrics:                                  │
│   Total Alerts:       {self.total_alerts:>8d}                  │
│   True Positives:     {self.true_positives:>8d}                  │
│   False Positives:    {self.false_positives:>8d} ({self.false_positive_rate:.1f}%)         │
│   Total Incidents:    {self.total_incidents:>8d}                  │
├────────────────────────────────────────────────────┤
│ Time Metrics:                                   │
│   MTTD:               {self.mttd:>7.1f} min                 │
│   MTTR:               {self.mttr:>7.1f} min                 │
│   MTTC:               {self.mttc:>7.1f} min                 │
├────────────────────────────────────────────────────┤
│ Coverage:                                       │
│   Detection Coverage: {self.detection_coverage_pct:>7.1f}%                │
│   Log Coverage:       {self.log_coverage_pct:>7.1f}%                │
└────────────────────────────────────────────────────┘"""

# ตัวอย่าง
metrics = SOCMetrics(
    total_alerts=1250,
    true_positives=187,
    false_positives=963,
    total_incidents=45,
    mttd_times=[15, 22, 8, 35, 12, 18, 45, 30],
    mttr_times=[120, 240, 60, 480, 90, 150, 360],
    mttc_times=[45, 120, 30, 180, 60, 90],
    detection_coverage_pct=68.5,
    log_coverage_pct=82.3
)

print(metrics.generate_scorecard())

# SOC Maturity Benchmarks
SOC_BENCHMARKS = {
    "industry_average": {
        "mttd": 197,        # วัน (Ponemon Institute 2023)
        "mttr": 69,         # วัน
        "false_positive_rate": 50,  # %
    },
    "best_in_class": {
        "mttd": 15,         # นาที
        "mttr": 60,         # นาที
        "false_positive_rate": 10,  # %
    }
}

print("\nIndustry Benchmarks:")
print(f"  Average MTTD: {SOC_BENCHMARKS['industry_average']['mttd']} days")
print(f"  Best in Class MTTD: {SOC_BENCHMARKS['best_in_class']['mttd']} minutes")
print(f"  Average FP Rate: {SOC_BENCHMARKS['industry_average']['false_positive_rate']}%")
```

---

## 10. SOC Tooling

```
เครื่องมือสำคัญสำหรับ SOC:

SIEM:
  • Splunk Enterprise/SIEM Premium
  • Microsoft Sentinel
  • IBM QRadar
  • Elastic SIEM (Free)
  • Graylog

EDR:
  • CrowdStrike Falcon
  • Microsoft Defender for Endpoint
  • SentinelOne
  • Carbon Black
  • Velociraptor (Open Source)

SOAR:
  • Splunk SOAR (Phantom)
  • Palo Alto XSOAR
  • IBM SOAR
  • Shuffle (Open Source)
  • TheHive + Cortex

Threat Intelligence:
  • MISP
  • OpenCTI
  • ThreatConnect
  • Recorded Future

Ticketing / Case Management:
  • TheHive (Open Source IR Platform)
  • Jira Service Management
  • ServiceNow Security

Forensics:
  • Velociraptor (Remote Forensics)
  • Autopsy / Sleuth Kit
  • Volatility (Memory Forensics)
  • KAPE (Windows Artifacts)

Network Analysis:
  • Wireshark
  • Zeek (Bro)
  • Suricata IDS/IPS
  • NetworkMiner

Vulnerability Management:
  • Nessus / Tenable.io
  • OpenVAS
  • Qualys
```

---

## สรุป

| หัวข้อ | เนื้อหา |
|--------|--------|
| SOC Structure | Tier 1/2/3 + People+Process+Technology |
| SIEM | ELK Stack + Splunk Setup, Detection Rules |
| Alert Triage | รับ Alert → Classify → Triage → IR |
| IR Playbooks | Ransomware, Phishing, Credential Theft |
| Log Management | Windows Events, Sysmon, Network, EDR |
| EDR Integration | CrowdStrike API + Microsoft Defender API |
| SOAR Automation | Async Playbook Execution |
| Metrics | MTTD, MTTR, MTTC, FP Rate, Coverage |

---

← [Part 76: Threat Intelligence](Part-76-Threat-Intelligence.md) | [Part 78: Advanced Exploitation](Part-78-Advanced-Exploitation.md) →
