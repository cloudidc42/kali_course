# Part 87: Blue Team & Defensive Security

## สารบัญ
1. [Blue Team คืออะไร?](#1-blue-team)
2. [Security Operations Center (SOC)](#2-soc)
3. [SIEM และ Log Management](#3-siem)
4. [Detection Engineering: SIGMA Rules](#4-detection-engineering)
5. [Threat Hunting](#5-threat-hunting)
6. [Incident Response (IR)](#6-incident-response)
7. [Endpoint Detection and Response (EDR)](#7-edr)
8. [Network Security Monitoring (NSM)](#8-nsm)
9. [Deception Technology (Honeypots)](#9-honeypots)
10. [Purple Team Exercises](#10-purple-team)

---

## 1. Blue Team

Blue Team คือทีมฝ่ายป้องกันที่รับผิดชอบตรวจจับ (Detect), ตอบสนอง (Respond) และฟื้นฟู (Recover) จากการโจมตีทางไซเบอร์:

| ฟังก์ชัน | เครื่องมือ | ทีม |
|---|---|---|
| Monitor | SIEM, EDR, NDR | SOC Analyst L1/L2 |
| Detect | SIGMA rules, YARA, ML | Detection Engineer |
| Hunt | Threat Hunting platform | Threat Hunter |
| Respond | SOAR, Playbooks | IR Analyst |
| Recover | Backup, BCP | IT Operations |
| Improve | Purple Team, Red Team Lessons | Security Architect |

### 1.1 NIST Cybersecurity Framework
```
Identify → Protect → Detect → Respond → Recover
   ↑                                           |
   └───────── Continuous Improvement ─────────┘
```

---

## 2. SOC

### 2.1 SOC Tier Model
```
Tier 1 (Alert Triage)
  ├── Monitor alerts จาก SIEM 24x7
  ├── Initial triage: false positive vs. true positive
  ├── เปิด ticket + ส่งต่อ Tier 2
  └── ปิด ticket ถ้า false positive

Tier 2 (Incident Investigation)
  ├── Deep-dive investigation
  ├── สร้าง timeline ของเหตุการณ์
  ├── Contain และ remediate
  └── ส่งต่อ Tier 3 ถ้าซับซ้อน

Tier 3 (Threat Intelligence / Hunting)
  ├── Proactive threat hunting
  ├── Malware analysis
  ├── Threat intelligence
  └── Detection rule development
```

### 2.2 Metrics ที่ SOC ควรวัด
```python
#!/usr/bin/env python3
# soc_metrics.py — คำนวณและติดตาม SOC metrics

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List
import statistics

@dataclass
class Incident:
    incident_id: str
    severity: str           # P1, P2, P3, P4
    detected_at: datetime
    triaged_at: datetime
    contained_at: datetime
    resolved_at: datetime
    false_positive: bool = False


class SOCMetrics:
    def __init__(self, incidents: List[Incident]):
        self.incidents = incidents
        self.true_positives = [i for i in incidents if not i.false_positive]
        self.false_positives = [i for i in incidents if i.false_positive]

    def mean_time_to_detect(self) -> float:
        """MTTD — Mean Time to Detect (hours)"""
        # สมมติว่า incident started at 'contained_at - attack_duration'
        # ใช้ detected_at − alert_create เป็น proxy
        return 0.0  # simplified; ในของจริงจะ = attack_start − detect_time

    def mean_time_to_respond(self) -> float:
        """MTTR — Mean Time to Respond (minutes)"""
        times = [
            (i.contained_at - i.detected_at).total_seconds() / 60
            for i in self.true_positives
        ]
        return statistics.mean(times) if times else 0.0

    def mean_time_to_resolve(self) -> float:
        """MTTRS — Mean Time to Resolve (hours)"""
        times = [
            (i.resolved_at - i.detected_at).total_seconds() / 3600
            for i in self.true_positives
        ]
        return statistics.mean(times) if times else 0.0

    def false_positive_rate(self) -> float:
        """False Positive Rate (%)"""
        total = len(self.incidents)
        if total == 0:
            return 0.0
        return len(self.false_positives) / total * 100

    def incidents_by_severity(self) -> dict:
        summary = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for i in self.true_positives:
            summary[i.severity] = summary.get(i.severity, 0) + 1
        return summary

    def print_dashboard(self):
        print("=" * 50)
        print("SOC Performance Dashboard")
        print("=" * 50)
        print(f"Total Incidents:      {len(self.incidents)}")
        print(f"True Positives:       {len(self.true_positives)}")
        print(f"False Positives:      {len(self.false_positives)}")
        print(f"False Positive Rate:  {self.false_positive_rate():.1f}%")
        print(f"MTTR:                 {self.mean_time_to_respond():.1f} minutes")
        print(f"MTTRS:                {self.mean_time_to_resolve():.1f} hours")
        print(f"By Severity:          {self.incidents_by_severity()}")
        print("=" * 50)
```

---

## 3. SIEM

### 3.1 Splunk Queries สำหรับตรวจจับภัยคุกคาม
```spl
<!-- Detect Brute Force Login -->
index=windows EventCode=4625
| stats count by src_ip, user, _time
| where count > 10
| eval risk="brute_force_attempt"
| sort -count
| table _time, src_ip, user, count, risk

<!-- Detect Pass-the-Hash (Kerberos anomaly) -->
index=windows EventCode=4624 Logon_Type=3
| search NOT (src_ip="127.0.0.1")
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 20
| stats count by src_ip, user, dest_host
| where count > 5

<!-- Detect PowerShell Encoded Commands -->
index=windows EventCode=4104
| search ScriptBlockText="*-enc*" OR ScriptBlockText="*-EncodedCommand*"
| eval risk="powershell_encoded"
| table _time, host, user, ScriptBlockText

<!-- Detect Kerberoasting -->
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
| stats count by src_ip, user, ServiceName
| where count > 3
| eval risk="kerberoasting"

<!-- Detect DCSync (Replication from non-DC) -->
index=windows EventCode=4662
| search Properties="*1131f6aa*" OR Properties="*1131f6ab*" OR Properties="*89e95b76*"
| where NOT (src_ip IN (dc_ip_list))
| eval risk="dcsync_attack"

<!-- Detect LSASS Memory Dump -->
index=windows EventCode=10 TargetImage="*lsass.exe*"
| stats count by src_ip, SourceImage, GrantedAccess
| where match(GrantedAccess, "0x1010") OR match(GrantedAccess, "0x1410")

<!-- Network: Detect DNS Tunneling -->
index=network sourcetype=dns
| eval query_length=len(query)
| where query_length > 50
| stats count, avg(query_length) as avg_len by src_ip, query
| where count > 100 AND avg_len > 45
| eval risk="dns_tunneling"

<!-- Detect Lateral Movement via PsExec -->
index=windows EventCode=7045
| search ServiceName="PSEXESVC" OR ImagePath="*\\PSEXESVC.exe*"
| eval risk="psexec_lateral_movement"
| table _time, host, ServiceName, ImagePath

<!-- Detect Scheduled Task Creation (Persistence) -->
index=windows EventCode=4698
| search NOT (TaskName="*Microsoft*" OR TaskName="*Windows*")
| eval risk="suspicious_scheduled_task"
| table _time, host, user, TaskName, Command
```

### 3.2 Elasticsearch / ELK Stack
```python
#!/usr/bin/env python3
# elk_queries.py — ส่ง queries ไป Elasticsearch

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json

class ELKSecurityAnalyst:
    def __init__(self, es_host: str = "localhost", es_port: int = 9200):
        self.es = Elasticsearch([{"host": es_host, "port": es_port}])

    def detect_brute_force(self, threshold: int = 10, minutes: int = 5) -> list:
        """Detect brute force login attempts"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event.code": "4625"}},
                        {"range": {"@timestamp": {
                            "gte": f"now-{minutes}m"
                        }}}
                    ]
                }
            },
            "aggs": {
                "by_src_ip": {
                    "terms": {"field": "source.ip", "size": 100},
                    "aggs": {
                        "fail_count": {"value_count": {"field": "event.id"}}
                    }
                }
            },
            "size": 0
        }
        result = self.es.search(index="winlogbeat-*", body=query)
        findings = []
        for bucket in result["aggregations"]["by_src_ip"]["buckets"]:
            if bucket["fail_count"]["value"] >= threshold:
                findings.append({
                    "src_ip": bucket["key"],
                    "count": bucket["fail_count"]["value"],
                    "risk": "brute_force"
                })
        return findings

    def hunt_powershell_encoded(self, hours: int = 24) -> list:
        """Hunt for encoded PowerShell commands"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event.code": "4104"}},
                        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}
                    ],
                    "should": [
                        {"wildcard": {"powershell.script_block_text": "*-enc*"}},
                        {"wildcard": {"powershell.script_block_text": "*EncodedCommand*"}},
                        {"wildcard": {"powershell.script_block_text": "*IEX*"}},
                        {"wildcard": {"powershell.script_block_text": "*Invoke-Expression*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "_source": ["@timestamp", "host.hostname", "user.name",
                        "powershell.script_block_text"],
            "size": 100
        }
        result = self.es.search(index="winlogbeat-*", body=query)
        return [hit["_source"] for hit in result["hits"]["hits"]]

    def detect_lateral_movement(self, hours: int = 4) -> list:
        """ตรวจจับการ login ผิดปกติจากหลาย host"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event.code": "4624"}},
                        {"terms": {"winlog.event_data.LogonType": ["3", "10"]}},
                        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}
                    ]
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "user.name", "size": 100},
                    "aggs": {
                        "unique_hosts": {
                            "cardinality": {"field": "host.hostname"}
                        }
                    }
                }
            },
            "size": 0
        }
        result = self.es.search(index="winlogbeat-*", body=query)
        findings = []
        for bucket in result["aggregations"]["by_user"]["buckets"]:
            unique_count = bucket["unique_hosts"]["value"]
            if unique_count > 5:
                findings.append({
                    "user": bucket["key"],
                    "unique_hosts": unique_count,
                    "risk": "lateral_movement"
                })
        return findings

    def create_alert_index(self):
        """สร้าง index สำหรับ custom alerts"""
        mapping = {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "risk": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "user": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "details": {"type": "text"}
                }
            }
        }
        self.es.indices.create(index="custom-alerts", body=mapping, ignore=400)

    def save_alert(self, risk: str, details: dict):
        """บันทึก alert ไปยัง Elasticsearch"""
        doc = {
            "@timestamp": datetime.utcnow().isoformat(),
            "risk": risk,
            **details
        }
        self.es.index(index="custom-alerts", body=doc)
```

---

## 4. Detection Engineering

### 4.1 SIGMA Rules
SIGMA คือภาษากลางสำหรับเขียน detection rules ที่แปลงไปใช้ได้กับ SIEM หลายตัว:

```yaml
# sigma_rules/detect_kerberoasting.yml
title: Kerberoasting Attack Detection
id: a6a88e22-8cb2-4b3f-b5d6-c2e0a3b3f4d5
status: stable
description: Detects Kerberoasting - requesting TGS tickets for service accounts with RC4 encryption
references:
  - https://attack.mitre.org/techniques/T1558/003/
author: Blue Team
date: 2024/01/15
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'   # RC4-HMAC (weak, pre-2019 service accounts)
    ServiceName|endswith:
      - '$'  # exclude computer accounts
  filter:
    ServiceName|startswith: 'krbtgt'
  condition: selection AND NOT filter
falsepositives:
  - Old applications requiring RC4 Kerberos
  - Legacy service accounts
level: high
```

```yaml
# sigma_rules/detect_dcsync.yml
title: DCSync Attack - Replication from Non-DC
id: b3a87f01-2d4c-4b8e-9a7f-c1d0e5f3a2b6
status: stable
description: Detects DCSync attack where non-DC machine requests AD replication
tags:
  - attack.credential_access
  - attack.t1003.006
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
      - '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
      - '89e95b76-444d-4c62-991a-0facbeda640c'  # DS-Replication-Get-Changes-In-Filtered-Set
  filter_dc:
    SubjectUserSid|startswith: 'S-1-5-21'  # exclude SYSTEM (DCs)
  condition: selection AND NOT filter_dc
falsepositives:
  - Azure AD Connect
  - Legitimate AD replication tools
level: critical
```

```yaml
# sigma_rules/detect_lolbin_download.yml
title: Living Off the Land - Binary Download via certutil/bitsadmin
id: c7d91b3e-5f2a-4c8f-a0b2-d3e4f5a6b7c8
status: stable
description: Detects use of built-in Windows tools to download files
tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.command_and_control
  - attack.t1105
logsource:
  product: windows
  category: process_creation
detection:
  certutil_download:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-decode'
      - '-split'
  bitsadmin_download:
    Image|endswith: '\\bitsadmin.exe'
    CommandLine|contains:
      - '/transfer'
      - '/download'
  powershell_download:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'WebClient'
      - 'IWR'
  condition: 1 of them
falsepositives:
  - Legitimate IT admin tasks
  - Software deployment scripts
level: medium
```

### 4.2 SIGMA Rule Converter
```python
#!/usr/bin/env python3
# sigma_converter.py — แปลง SIGMA rules เป็น Splunk/ELK queries

import yaml
from pathlib import Path
from typing import Dict, List, Optional

class SigmaConverter:
    """
    แปลง SIGMA rule เป็น query ของ SIEM ต่างๆ
    """

    def load_rule(self, rule_path: str) -> Dict:
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def _detection_to_splunk(self, detection: Dict, logsource: Dict) -> str:
        """แปลง detection section เป็น Splunk SPL"""
        conditions = []

        # Map logsource to index
        index = "index=windows" if logsource.get("product") == "windows" else "index=*"
        conditions.append(index)

        # Parse each named selection
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for field, field_val in value.items():
                    if "|endswith" in field:
                        real_field = field.split("|")[0]
                        if isinstance(field_val, list):
                            vals = " OR ".join(f'{real_field}="*{v}"' for v in field_val)
                            conditions.append(f"({vals})")
                        else:
                            conditions.append(f'{real_field}="*{field_val}"')
                    elif "|contains" in field:
                        real_field = field.split("|")[0]
                        if isinstance(field_val, list):
                            vals = " OR ".join(f'{real_field}="*{v}*"' for v in field_val)
                            conditions.append(f"({vals})")
                        else:
                            conditions.append(f'{real_field}="*{field_val}*"')
                    elif "|startswith" in field:
                        real_field = field.split("|")[0]
                        if isinstance(field_val, list):
                            vals = " OR ".join(f'{real_field}="{v}*"' for v in field_val)
                            conditions.append(f"({vals})")
                        else:
                            conditions.append(f'{real_field}="{field_val}*"')
                    else:
                        if isinstance(field_val, list):
                            vals = " OR ".join(f'{field}="{v}"' for v in field_val)
                            conditions.append(f"({vals})")
                        else:
                            conditions.append(f'{field}="{field_val}"')
        return "\n| ".join(conditions)

    def to_splunk(self, rule_path: str) -> str:
        rule = self.load_rule(rule_path)
        detection = rule.get("detection", {})
        logsource = rule.get("logsource", {})
        query = self._detection_to_splunk(detection, logsource)
        return f"/* SIGMA Rule: {rule.get('title')} */\n{query}\n| table _time, host, user, EventID"

    def to_elk_kql(self, rule_path: str) -> str:
        """แปลงเป็น Kibana Query Language"""
        rule = self.load_rule(rule_path)
        detection = rule.get("detection", {})
        clauses = []
        for key, value in detection.items():
            if key in ("condition", "filter"):
                continue
            if isinstance(value, dict):
                for field, field_val in value.items():
                    clean_field = field.split("|")[0]
                    if isinstance(field_val, list):
                        vals = " OR ".join(f'{clean_field}: "{v}"' for v in field_val)
                        clauses.append(f"({vals})")
                    else:
                        clauses.append(f'{clean_field}: "{field_val}"')
        return " AND ".join(clauses)

    def validate_rule(self, rule_path: str) -> List[str]:
        """Validate SIGMA rule structure"""
        errors = []
        rule = self.load_rule(rule_path)
        required = ["title", "description", "logsource", "detection", "level"]
        for field in required:
            if field not in rule:
                errors.append(f"Missing required field: {field}")
        if "detection" in rule:
            det = rule["detection"]
            if "condition" not in det:
                errors.append("Missing 'condition' in detection")
        valid_levels = {"informational", "low", "medium", "high", "critical"}
        if rule.get("level") not in valid_levels:
            errors.append(f"Invalid level: {rule.get('level')}")
        return errors


# ตัวอย่างการใช้งาน
converter = SigmaConverter()
for rule_file in Path("sigma_rules").glob("*.yml"):
    errors = converter.validate_rule(str(rule_file))
    if errors:
        print(f"[!] {rule_file.name}: {errors}")
    else:
        splunk_query = converter.to_splunk(str(rule_file))
        print(f"[+] {rule_file.name} -> Splunk query generated")
        print(splunk_query)
        print()
```

---

## 5. Threat Hunting

### 5.1 Hypothesis-Driven Hunting
```python
#!/usr/bin/env python3
# threat_hunting.py — เครื่องมือ threat hunting สำหรับ SOC

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List, Dict
import json

class ThreatHunter:
    """
    Threat hunting โดยใช้ hypothesis-driven approach
    บวกกับ ML-based anomaly detection
    """

    def __init__(self):
        self.baseline = {}
        self.anomalies = []

    def hunt_beaconing(
        self, dns_logs: pd.DataFrame,
        min_count: int = 50,
        variance_threshold: float = 0.1
    ) -> pd.DataFrame:
        """
        Hunt for C2 beaconing ผ่านการวิเคราะห์ timing variance
        Beaconing มี interval เสมอต้น → variance ต่ำ
        """
        # dns_logs: columns = [timestamp, src_ip, query, ttl]
        dns_logs["timestamp"] = pd.to_datetime(dns_logs["timestamp"])
        dns_logs = dns_logs.sort_values(["src_ip", "query", "timestamp"])

        results = []
        for (src_ip, query), group in dns_logs.groupby(["src_ip", "query"]):
            if len(group) < min_count:
                continue
            intervals = group["timestamp"].diff().dt.total_seconds().dropna()
            if len(intervals) < 5:
                continue
            coef_var = intervals.std() / intervals.mean() if intervals.mean() > 0 else 999
            if coef_var < variance_threshold:
                results.append({
                    "src_ip": src_ip,
                    "query": query,
                    "count": len(group),
                    "avg_interval_s": intervals.mean(),
                    "variance_coef": coef_var,
                    "risk": "beaconing"
                })
        return pd.DataFrame(results).sort_values("variance_coef")

    def hunt_process_anomalies(
        self, process_logs: pd.DataFrame
    ) -> pd.DataFrame:
        """
        Hunt for anomalous process execution โดยใช้ Isolation Forest
        Features: hour of day, process frequency, parent-child relationship
        """
        # process_logs: columns = [timestamp, host, process_name, parent_name, user]
        features = process_logs.groupby(["host", "process_name"]).agg(
            count=("process_name", "count"),
            unique_users=("user", "nunique"),
            unique_parents=("parent_name", "nunique")
        ).reset_index()

        X = features[["count", "unique_users", "unique_parents"]].values
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        iso = IsolationForest(contamination=0.05, random_state=42)
        predictions = iso.fit_predict(X_scaled)

        features["anomaly"] = predictions
        anomalies = features[features["anomaly"] == -1].copy()
        anomalies["risk"] = "anomalous_process"
        return anomalies

    def hunt_rare_parent_child(
        self, process_logs: pd.DataFrame,
        threshold_pct: float = 0.01
    ) -> pd.DataFrame:
        """
        Hunt parent-child process pairs ที่ผิดปกติ
        เช่น winword.exe → cmd.exe หรือ excel.exe → powershell.exe
        """
        pair_counts = process_logs.groupby(
            ["parent_name", "process_name"]
        ).size().reset_index(name="count")

        total = len(process_logs)
        pair_counts["pct"] = pair_counts["count"] / total

        # คู่ที่ราร (pct < threshold) และน่าสงสัย
        suspicious_parents = [
            "winword.exe", "excel.exe", "powerpnt.exe",
            "outlook.exe", "acrord32.exe", "msiexec.exe"
        ]
        suspicious_children = [
            "cmd.exe", "powershell.exe", "wscript.exe",
            "cscript.exe", "mshta.exe", "certutil.exe"
        ]

        mask = (
            pair_counts["pct"] < threshold_pct) & (
            pair_counts["parent_name"].isin(suspicious_parents)) & (
            pair_counts["process_name"].isin(suspicious_children)
        )
        result = pair_counts[mask].copy()
        result["risk"] = "suspicious_parent_child"
        return result

    def hunt_persistence_registry(
        self, registry_logs: pd.DataFrame
    ) -> pd.DataFrame:
        """
        Hunt registry modifications เพื่อ persistence
        """
        persistence_keys = [
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
        ]
        mask = registry_logs["registry_key"].str.startswith(tuple(persistence_keys))
        result = registry_logs[mask].copy()
        result["risk"] = "persistence_registry"
        return result

    def generate_hunt_report(self, hunt_name: str, findings: Dict) -> str:
        """สร้าง threat hunt report"""
        report = f"""# Threat Hunt Report: {hunt_name}

**Date:** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M UTC')}

## Summary

"""
        for hunt_type, df in findings.items():
            if isinstance(df, pd.DataFrame) and not df.empty:
                report += f"### {hunt_type}\n\n"
                report += f"Found {len(df)} potential indicators\n\n"
                report += df.head(10).to_markdown(index=False) + "\n\n"
            else:
                report += f"### {hunt_type}: No findings\n\n"
        return report
```

---

## 6. Incident Response

### 6.1 IR Playbook: Ransomware
```python
#!/usr/bin/env python3
# ir_playbook.py — Incident Response playbook สำหรับ ransomware

from dataclasses import dataclass, field
from datetime import datetime
from typing import List
import json

@dataclass
class IRAction:
    step: int
    phase: str          # Identify, Contain, Eradicate, Recover, Lessons Learned
    action: str
    owner: str
    priority: str       # immediate, within_1h, within_4h, within_24h
    done: bool = False
    notes: str = ""
    timestamp: str = ""

    def complete(self, notes: str = ""):
        self.done = True
        self.timestamp = datetime.utcnow().isoformat()
        self.notes = notes
        print(f"[+] Step {self.step} completed: {self.action[:60]}")


class RansomwarePlaybook:
    """
    IR Playbook สำหรับ Ransomware incident
    อ้างอิงตาม PICERL methodology
    """

    def __init__(self, incident_id: str, analyst: str):
        self.incident_id = incident_id
        self.analyst = analyst
        self.opened_at = datetime.utcnow().isoformat()
        self.actions = self._create_playbook()
        self.affected_hosts: List[str] = []
        self.iocs: List[str] = []

    def _create_playbook(self) -> List[IRAction]:
        return [
            # === IDENTIFY ===
            IRAction(1, "Identify", "Verify ransomware indicators (encrypted files, ransom note, extension changes)",
                     "L1", "immediate"),
            IRAction(2, "Identify", "Identify affected systems via SIEM / EDR alerts",
                     "L1", "immediate"),
            IRAction(3, "Identify", "Determine Patient Zero (first infected host)",
                     "L2", "within_1h"),
            IRAction(4, "Identify", "Identify ransomware family (ID Ransomware / VirusTotal)",
                     "L2", "within_1h"),
            IRAction(5, "Identify", "Check for known decryptors at nomoreransom.org",
                     "L2", "within_1h"),

            # === CONTAIN ===
            IRAction(6, "Contain", "Isolate affected hosts from network IMMEDIATELY",
                     "L1", "immediate"),
            IRAction(7, "Contain", "Disable affected accounts",
                     "L2", "immediate"),
            IRAction(8, "Contain", "Block C2 IPs/domains at firewall and proxy",
                     "Firewall", "immediate"),
            IRAction(9, "Contain", "Take memory dumps of affected systems (before shutdown)",
                     "Forensics", "within_1h"),
            IRAction(10, "Contain", "Preserve disk images for forensics",
                     "Forensics", "within_1h"),
            IRAction(11, "Contain", "Check backup integrity — verify backups are NOT encrypted",
                     "IT Ops", "within_1h"),
            IRAction(12, "Contain", "Scan all systems for indicators of compromise",
                     "L2", "within_4h"),

            # === ERADICATE ===
            IRAction(13, "Eradicate", "Remove malware from all infected systems",
                     "L3", "within_4h"),
            IRAction(14, "Eradicate", "Reset all compromised credentials",
                     "IAM", "within_4h"),
            IRAction(15, "Eradicate", "Patch initial access vector (phishing / vuln)",
                     "IT Ops", "within_24h"),
            IRAction(16, "Eradicate", "Verify no persistence mechanisms remain",
                     "L3", "within_24h"),

            # === RECOVER ===
            IRAction(17, "Recover", "Restore from clean backup (offline backup preferred)",
                     "IT Ops", "within_24h"),
            IRAction(18, "Recover", "Verify restored systems are clean before reconnecting",
                     "L2", "within_24h"),
            IRAction(19, "Recover", "Reconnect systems to network in controlled manner",
                     "IT Ops", "within_24h"),
            IRAction(20, "Recover", "Monitor restored systems for 72 hours",
                     "SOC", "within_24h"),

            # === LESSONS LEARNED ===
            IRAction(21, "LessonsLearned", "Conduct post-incident review within 2 weeks",
                     "IR Lead", "within_24h"),
            IRAction(22, "LessonsLearned", "Update detection rules based on new IOCs",
                     "Detection Eng", "within_24h"),
            IRAction(23, "LessonsLearned", "File final incident report",
                     "IR Lead", "within_24h"),
        ]

    def get_pending_immediate(self) -> List[IRAction]:
        return [a for a in self.actions
                if not a.done and a.priority == "immediate"]

    def print_status(self):
        phases = {"Identify", "Contain", "Eradicate", "Recover", "LessonsLearned"}
        for phase in phases:
            phase_actions = [a for a in self.actions if a.phase == phase]
            done = sum(1 for a in phase_actions if a.done)
            print(f"{phase:20} {done}/{len(phase_actions)} complete")

    def export_timeline(self, path: str):
        data = {
            "incident_id": self.incident_id,
            "opened_at": self.opened_at,
            "analyst": self.analyst,
            "affected_hosts": self.affected_hosts,
            "iocs": self.iocs,
            "actions": [
                {
                    "step": a.step,
                    "phase": a.phase,
                    "action": a.action,
                    "done": a.done,
                    "timestamp": a.timestamp,
                    "notes": a.notes
                } for a in self.actions
            ]
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Timeline exported: {path}")


# ตัวอย่าง: เริ่มตอบสนอง
playbook = RansomwarePlaybook("INC-2024-0115", "analyst1")
playbook.affected_hosts = ["workstation01", "fileserver01"]
playbook.iocs = ["185.x.x.x", "malware.exe", "SHA256: abc123..."]

print("Immediate actions required:")
for action in playbook.get_pending_immediate():
    print(f"  [{action.step}] {action.action}")

# Mark completed
playbook.actions[0].complete("Confirmed: .locked extension, ransom note found")
playbook.actions[5].complete("Isolated workstation01 from VLAN")

playbook.print_status()
playbook.export_timeline("ir_timeline.json")
```

---

## 7. EDR

### 7.1 Windows Defender และ Sysmon

**ติดตั้ง Sysmon** — ตัวแทน Windows Event Logging ที่ capture ได้มากกว่า:
```powershell
# Download Sysmon
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' \
  -OutFile Sysmon.zip
Expand-Archive Sysmon.zip

# Install with config
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Update config
.\Sysmon64.exe -c sysmonconfig.xml

# Verify installation
Get-Service Sysmon64
```

**Sysmon Config (sysmonconfig.xml):**
```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process creation — log everything except noisy processes -->
    <ProcessCreate onmatch="exclude">
      <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      <Image condition="is">C:\Windows\System32\WerFault.exe</Image>
    </ProcessCreate>

    <!-- Network connections -->
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">443</DestinationPort>
      <DestinationPort condition="is">80</DestinationPort>
      <DestinationPort condition="is">4444</DestinationPort>
    </NetworkConnect>

    <!-- Registry modifications (persistence) -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
      <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
      <TargetObject condition="contains">Winlogon</TargetObject>
    </RegistryEvent>

    <!-- File creation (payload drops, ransomware) -->
    <FileCreate onmatch="include">
      <TargetFilename condition="end with">.exe</TargetFilename>
      <TargetFilename condition="end with">.dll</TargetFilename>
      <TargetFilename condition="end with">.ps1</TargetFilename>
      <TargetFilename condition="contains">Temp</TargetFilename>
      <TargetFilename condition="contains">AppData\Local\Temp</TargetFilename>
    </FileCreate>

    <!-- Process access (LSASS dump detection) -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="end with">lsass.exe</TargetImage>
    </ProcessAccess>

    <!-- DNS queries -->
    <DnsQuery onmatch="exclude">
      <QueryName condition="end with">.microsoft.com</QueryName>
      <QueryName condition="end with">.windows.com</QueryName>
    </DnsQuery>
  </EventFiltering>
</Sysmon>
```

### 7.2 EDR Custom Detection
```python
#!/usr/bin/env python3
# edr_monitor.py — Real-time EDR monitoring บน Linux

import subprocess
import json
import time
import re
from datetime import datetime
from threading import Thread
from typing import Callable

class LinuxEDR:
    """
    ติดตาม process, network, และ file บน Linux แบบ real-time
    ใช้ auditd, inotify, และ /proc
    """

    SUSPICIOUS_COMMANDS = [
        r'nc\s+-[le]',        # netcat listener/exec
        r'bash\s+-i',          # interactive bash (reverse shell)
        r'python.*socket',     # python socket (reverse shell)
        r'chmod\s+[+]?s',     # SUID modification
        r'wget.*\|.*sh',      # download and execute
        r'curl.*\|.*bash',    # download and execute
        r'base64\s+-d',        # base64 decode (potential staging)
        r'dd\s+if=.*/dev/mem', # memory dump
        r'ptrace',             # process injection
    ]

    def __init__(self, alert_callback: Callable = None):
        self.alert_callback = alert_callback or self._default_alert
        self.running = False

    def _default_alert(self, finding: dict):
        print(f"[ALERT] {datetime.utcnow().isoformat()} | "
              f"{finding['risk']} | {finding.get('cmd', finding.get('path', ''))}")

    def _check_process_cmdline(self, pid: int) -> dict:
        """อ่าน cmdline ของ process จาก /proc"""
        try:
            cmdline_path = f"/proc/{pid}/cmdline"
            with open(cmdline_path, 'r') as f:
                cmdline = f.read().replace('\x00', ' ').strip()
            return {"pid": pid, "cmdline": cmdline}
        except Exception:
            return {}

    def monitor_processes(self):
        """Monitor new processes โดยใช้ inotify บน /proc"""
        while self.running:
            try:
                result = subprocess.run(
                    ["auditctl", "-l"],
                    capture_output=True, text=True
                )
                # Parse auditd output for new execve events
                output = subprocess.run(
                    ["ausearch", "-ts", "recent", "-sc", "execve"],
                    capture_output=True, text=True
                )
                for line in output.stdout.splitlines():
                    if "argc" in line:  # command line
                        for pattern in self.SUSPICIOUS_COMMANDS:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.alert_callback({
                                    "risk": "suspicious_process",
                                    "cmd": line,
                                    "pattern": pattern
                                })
            except Exception as e:
                pass
            time.sleep(1)

    def monitor_network(self):
        """Monitor outbound connections"""
        seen_connections = set()
        SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 9001}  # common C2 ports

        while self.running:
            try:
                result = subprocess.run(
                    ["ss", "-tnp"],
                    capture_output=True, text=True
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 5 and parts[0] == "ESTAB":
                        remote = parts[4]
                        port = int(remote.split(":")[-1]) if ":" in remote else 0
                        conn_key = f"{parts[3]}->{remote}"

                        if conn_key not in seen_connections:
                            seen_connections.add(conn_key)
                            if port in SUSPICIOUS_PORTS:
                                self.alert_callback({
                                    "risk": "suspicious_connection",
                                    "local": parts[3],
                                    "remote": remote,
                                    "port": port
                                })
            except Exception:
                pass
            time.sleep(5)

    def start(self):
        self.running = True
        Thread(target=self.monitor_processes, daemon=True).start()
        Thread(target=self.monitor_network, daemon=True).start()
        print("[+] Linux EDR started")

    def stop(self):
        self.running = False
        print("[-] Linux EDR stopped")
```

---

## 8. NSM

### 8.1 Zeek (Bro) + Suricata
```bash
# ติดตั้ง Zeek
apt install zeek

# เริ่ม monitor interface
zeek -i eth0 /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek

# ดู logs
tail -f /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p proto duration
tail -f /opt/zeek/logs/current/http.log | zeek-cut ts id.orig_h uri host
tail -f /opt/zeek/logs/current/dns.log | zeek-cut ts id.orig_h query
tail -f /opt/zeek/logs/current/files.log | zeek-cut ts source md5 filename
```

```python
#!/usr/bin/env python3
# zeek_analyzer.py — วิเคราะห์ Zeek logs

import json
import gzip
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import pandas as pd

class ZeekAnalyzer:
    def __init__(self, log_dir: str = "/opt/zeek/logs/current"):
        self.log_dir = Path(log_dir)

    def parse_log(self, log_file: str) -> list:
        """Parse Zeek log file (JSON format)"""
        records = []
        path = self.log_dir / log_file
        if not path.exists():
            return records
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, 'rt') as f:
            for line in f:
                if line.startswith("#"):
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return records

    def detect_port_scan(self, conn_records: list, threshold: int = 20) -> list:
        """Detect port scans from connection logs"""
        src_port_count = defaultdict(set)
        for r in conn_records:
            src = r.get("id.orig_h", "")
            dst_port = r.get("id.resp_p", 0)
            src_port_count[src].add(dst_port)

        findings = []
        for src, ports in src_port_count.items():
            if len(ports) > threshold:
                findings.append({
                    "src_ip": src,
                    "unique_ports": len(ports),
                    "sample_ports": sorted(ports)[:10],
                    "risk": "port_scan"
                })
        return findings

    def detect_dns_tunneling(self, dns_records: list) -> list:
        """Detect DNS tunneling from DNS logs"""
        findings = []
        domain_query_counts = defaultdict(lambda: {"count": 0, "long_queries": 0})

        for r in dns_records:
            query = r.get("query", "")
            src = r.get("id.orig_h", "")
            parts = query.split(".")
            # Long subdomains = potential data exfiltration
            if parts:
                subdomain = parts[0]
                if len(subdomain) > 40:
                    domain_query_counts[src]["long_queries"] += 1
                domain_query_counts[src]["count"] += 1

        for src, stats in domain_query_counts.items():
            if stats["long_queries"] > 10:
                findings.append({
                    "src_ip": src,
                    "total_queries": stats["count"],
                    "long_queries": stats["long_queries"],
                    "risk": "dns_tunneling"
                })
        return findings

    def detect_c2_http(self, http_records: list) -> list:
        """Detect suspicious HTTP C2 patterns"""
        findings = []
        UA_SUSPICIOUS = ["python-requests", "curl", "libwww", "Go-http-client"]

        for r in http_records:
            ua = r.get("user_agent", "")
            uri = r.get("uri", "")
            src = r.get("id.orig_h", "")
            host = r.get("host", "")

            for suspicious_ua in UA_SUSPICIOUS:
                if suspicious_ua.lower() in ua.lower():
                    findings.append({
                        "src_ip": src,
                        "host": host,
                        "uri": uri,
                        "user_agent": ua,
                        "risk": "suspicious_user_agent"
                    })
                    break
        return findings
```

---

## 9. Honeypots

### 9.1 Honeypot สำหรับตรวจจับ Lateral Movement
```python
#!/usr/bin/env python3
# honeypot.py — Honeypot เพื่อตรวจจับ lateral movement

import socket
import threading
import json
from datetime import datetime
from typing import Callable

class HoneypotService:
    """
    Honeypot service ที่จำลองเป็น SSH/HTTP/SMB
    ผู้ใดเข้ามา = แจ้งเตือน SOC ทันที
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 22,
        service_name: str = "SSH",
        alert_callback: Callable = None
    ):
        self.host = host
        self.port = port
        self.service_name = service_name
        self.alert_callback = alert_callback or self._default_alert
        self.connections = []

    def _default_alert(self, alert: dict):
        print(f"[HONEYPOT ALERT] {alert['timestamp']} | "
              f"{alert['service']} | {alert['src_ip']}:{alert['src_port']}")
        with open("honeypot_alerts.jsonl", "a") as f:
            f.write(json.dumps(alert) + "\n")

    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """Handle incoming connection ส่ง alert แล้วเก็บข้อมูล"""
        src_ip, src_port = addr
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "service": self.service_name,
            "src_ip": src_ip,
            "src_port": src_port,
            "honeypot_port": self.port,
            "risk": "honeypot_triggered"
        }

        # พยายามอ่าน data ที่ส่งมา
        try:
            if self.service_name == "SSH":
                # Send fake SSH banner
                conn.send(b"SSH-2.0-OpenSSH_8.9\r\n")
                data = conn.recv(1024)
                alert["data"] = data.hex()
            elif self.service_name == "HTTP":
                data = conn.recv(4096)
                alert["data"] = data.decode(errors='replace')[:500]
                conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            pass
        finally:
            conn.close()

        self.connections.append(alert)
        self.alert_callback(alert)

    def start(self):
        """เริ่ม honeypot listener"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(50)
        print(f"[+] Honeypot {self.service_name} listening on {self.host}:{self.port}")

        while True:
            conn, addr = server.accept()
            t = threading.Thread(
                target=self._handle_connection, args=(conn, addr)
            )
            t.daemon = True
            t.start()


class HoneytokenDetector:
    """
    Honeytoken — Canary tokens ที่แจ้งเตือนเมื่อถูกเข้าถึง
    ซ่อน fake credentials ใน password vault / files
    """

    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url
        self.tokens = {}

    def create_aws_honey_key(
        self, label: str
    ) -> dict:
        """สร้าง fake AWS key ที่ alert เมื่อถูกใช้"""
        import random
        import string
        chars_upper = string.ascii_uppercase + string.digits
        access_key = "AKIA" + ''.join(random.choices(chars_upper, k=16))
        secret_key = ''.join(random.choices(
            string.ascii_letters + string.digits + "/+", k=40
        ))
        token = {
            "label": label,
            "access_key": access_key,
            "secret_key": secret_key,
            "note": "This is a honeytoken. Access = security incident."
        }
        self.tokens[access_key] = token
        print(f"[+] Honey AWS key created: {access_key}")
        print("[*] Place in: ~/.aws/credentials, config files, code repos")
        return token

    def create_honey_url(
        self, label: str, canary_domain: str = "canarytokens.org"
    ) -> str:
        """สร้าง URL ที่แจ้งเตือนเมื่อ attacker เปิด"""
        # ใช้ canarytokens.org service จริง
        import hashlib
        token_id = hashlib.md5(label.encode()).hexdigest()[:12]
        honey_url = f"https://{token_id}.{canary_domain}/img"
        print(f"[+] Honey URL: {honey_url}")
        print(f"[*] Embed in: documents, emails, web pages")
        return honey_url

    def create_honey_file(
        self, filename: str, label: str
    ) -> str:
        """สร้าง honey file ที่ alert เมื่อ access"""
        content = f"""# Confidential Credentials
# DO NOT SHARE

Database Server: 192.168.1.100
Username: admin
Password: Sup3rS3cur3P@ss!

AWS Access Key: AKIAIOSFODNN7EXAMPLE
AWS Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Canary Token embedded
<!-- <img src='{self.create_honey_url(label)}' width='1' height='1'> -->
"""
        with open(filename, 'w') as f:
            f.write(content)
        print(f"[+] Honey file created: {filename}")
        return filename


# เริ่ม multiple honeypots
if __name__ == "__main__":
    services = [
        HoneypotService(port=22, service_name="SSH"),
        HoneypotService(port=3389, service_name="RDP"),
        HoneypotService(port=445, service_name="SMB"),
        HoneypotService(port=1433, service_name="MSSQL"),
    ]
    for svc in services:
        t = threading.Thread(target=svc.start)
        t.daemon = True
        t.start()

    import time
    while True:
        time.sleep(60)
        total = sum(len(s.connections) for s in services)
        print(f"[*] Total honeypot connections: {total}")
```

---

## 10. Purple Team

### 10.1 Purple Team Exercise Framework
```python
#!/usr/bin/env python3
# purple_team.py — Purple Team exercise automation

from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime
import subprocess
import json

@dataclass
class TTPTest:
    """การทดสอบ TTP เดียว"""
    technique_id: str
    name: str
    tactic: str
    atomic_test_cmd: str   # Atomic Red Team command
    expected_log: str      # Event ID / log ที่ควรเห็น
    sigma_rule_path: str
    detected: bool = False
    alert_fired: bool = False
    response_time_s: float = 0.0
    notes: str = ""


class PurpleTeamExercise:
    """
    Purple Team Exercise — Red Team run TTP, Blue Team verify detection
    แต่ละ TTP ถูก replay พร้อมกัน และตรวจสอบว่า alert fire หรือไม่
    """

    def __init__(self, exercise_name: str):
        self.name = exercise_name
        self.start_time = datetime.utcnow().isoformat()
        self.tests: List[TTPTest] = []

    def add_test(self, test: TTPTest):
        self.tests.append(test)

    def run_atomic_test(self, test: TTPTest) -> bool:
        """รัน Atomic Red Team test สำหรับ TTP นี้"""
        print(f"[*] Running {test.technique_id}: {test.name}")
        print(f"    Command: {test.atomic_test_cmd}")
        # ใน real exercise: จะ execute command บน target machine
        # result = subprocess.run(test.atomic_test_cmd, shell=True, capture_output=True)
        print(f"    [!] Waiting for Blue Team to detect...")
        return True

    def verify_detection(
        self, test: TTPTest, siem_client
    ) -> bool:
        """ตรวจสอบว่า SIEM ตรวจพบ TTP นี้หรือไม่ภายใน 5 นาที"""
        import time
        start = time.time()
        timeout = 300  # 5 minutes

        while time.time() - start < timeout:
            # Check SIEM for alert
            alerts = siem_client.get_recent_alerts(minutes=5)
            for alert in alerts:
                if test.technique_id in alert.get("tags", []):
                    test.detected = True
                    test.alert_fired = True
                    test.response_time_s = time.time() - start
                    print(f"    [+] DETECTED in {test.response_time_s:.1f}s")
                    return True
            time.sleep(15)

        print(f"    [-] NOT DETECTED after {timeout}s")
        test.detected = False
        return False

    def generate_report(self) -> str:
        detected = [t for t in self.tests if t.detected]
        missed = [t for t in self.tests if not t.detected]
        detection_rate = len(detected) / len(self.tests) * 100 if self.tests else 0

        report = f"""# Purple Team Exercise Report
## {self.name}

**Date:** {self.start_time}
**Detection Rate:** {detection_rate:.1f}% ({len(detected)}/{len(self.tests)})

### Detected TTPs
| Technique | Name | Response Time |
|---|---|---|
"""
        for t in detected:
            report += f"| `{t.technique_id}` | {t.name} | {t.response_time_s:.1f}s |\n"

        report += "\n### Missed TTPs (Detection Gaps)\n"
        report += "| Technique | Name | Expected Log |\n|---|---|---|\n"
        for t in missed:
            report += f"| `{t.technique_id}` | {t.name} | {t.expected_log} |\n"

        report += "\n### Recommendations\n"
        for t in missed:
            report += f"- **{t.technique_id}**: Create SIGMA rule for `{t.expected_log}`, "
            report += f"validate Sysmon config captures this event\n"

        return report

    def save(self, path: str):
        with open(path, 'w') as f:
            f.write(self.generate_report())
        print(f"[+] Purple Team report saved: {path}")


# ตัวอย่าง exercise
exercise = PurpleTeamExercise("ACME Purple Team Q1-2024")
exercise.add_test(TTPTest(
    technique_id="T1558.003",
    name="Kerberoasting",
    tactic="Credential Access",
    atomic_test_cmd="Invoke-Mimikatz -Command '\"kerberos::list /export\"'",
    expected_log="EventID 4769 (TGS Request) with RC4 encryption",
    sigma_rule_path="sigma_rules/detect_kerberoasting.yml"
))
exercise.add_test(TTPTest(
    technique_id="T1003.001",
    name="LSASS Memory Dump",
    tactic="Credential Access",
    atomic_test_cmd="procdump64.exe -ma lsass.exe lsass.dmp",
    expected_log="Sysmon EventID 10 (ProcessAccess) targeting lsass.exe",
    sigma_rule_path="sigma_rules/detect_lsass_dump.yml"
))
print(exercise.generate_report())
```

---

## สรุป Blue Team & Defensive Security

| เครื่องมือ/ฟรัมเวิร์ค | ฟังก์ชัน | ไลเซนส์ |
|---|---|---|
| Splunk | SIEM, correlation | Commercial |
| Elastic Stack | SIEM, log management | Open Source |
| Zeek/Bro | Network monitoring | Open Source |
| Suricata | IDS/IPS | Open Source |
| Sysmon | Windows logging | Free (Microsoft) |
| Wazuh | SIEM + EDR | Open Source |
| TheHive | Incident Response | Open Source |
| MISP | Threat Intelligence | Open Source |
| Sigma | Detection rules | Open Source |
| Atomic Red Team | Purple Team testing | Open Source |

---

← [Part 86: Red Team Operations](Part-86-Red-Team-Operations.md) | [Part 88: Security Automation](Part-88-Security-Automation.md) →
