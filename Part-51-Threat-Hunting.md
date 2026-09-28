# Part 51: Threat Hunting

> **หลักสูตร Kali Linux จาก Zero ถึง Professional**  
> Part 51 of 100+ | ระดับ: Professional/World-Class

---

## สารบัญ

1. [Threat Hunting คืออะไร](#1-intro)
2. [Threat Hunting Methodology](#2-methodology)
3. [SIEM และ Log Analysis](#3-siem)
4. [Endpoint Detection (EDR)](#4-edr)
5. [Network Traffic Analysis](#5-network)
6. [Hunting for Common TTPs](#6-ttps)
7. [Sigma Rules](#7-sigma)
8. [Threat Intelligence Integration](#8-threat-intel)
9. [แบบฝึกหัด Lab](#9-lab)

---

## 1. Threat Hunting คืออะไร

### 1.1 ความหมาย

```
Threat Hunting = การค้นหาภัยคุกคามที่ซ่อนอยู่ในระบบ โดยเชิงรุก (proactive)
แทนที่จะรอ alert จาก SIEM (reactive)

Reactive:  Alert → Investigate → Respond
Proactive: Hypothesis → Hunt → Find/Clear → Improve Detection

Why Threat Hunt:
- APT อยู่ในระบบเฉลี่ย 200+ วัน (average dwell time)
- AV/SIEM ไม่ใช่สมบูรณ์ 100%
- LOLBins ไม่ถูกตรวจจับโดยเครื่องมือทั่วไป
```

### 1.2 หลักการ

```
Threat Hunting Maturity Model:

Level 0: Initial
  - พึ่ง alert-driven ล้วน
  - ไม่มี hunt procedures

Level 1: Minimal
  - เริ่มบาง threat intel
  - Hunt เป็นครั้งคราว

Level 2: Procedural
  - Hunt procedures
  - ใช้ TTP-based hunt
  - Irregular cadence

Level 3: Innovative
  - Custom hunt ตาม risk
  - Automate บาง hunt

Level 4: Leading
  - Hunt เป็น continuous
  - Machine learning-assisted
  - Loop back สู่ SIEM rules
```

---

## 2. Threat Hunting Methodology

### 2.1 Hypothesis-Driven Hunting

```
Hunt Process:

1. DEVELOP HYPOTHESIS
   "ถ้า attacker พยายาม lateral move
    แบบ Pass-the-Hash จะเห็นอะไร?"

2. IDENTIFY DATA SOURCES
   - Windows Security Event Log 4624
   - Network: SMB traffic บน port 445
   - EDR: NTLM authentication

3. CREATE HUNT ANALYTICS
   - Logic query สำหรับ detect
   - Baseline normal behavior

4. EXECUTE HUNT
   - รัน query บน SIEM/EDR
   - วิเคราะห์ผลลัพธ์

5. INVESTIGATE FINDINGS
   - True positive / False positive?
   - ต้องการ incident response?

6. IMPROVE DETECTION
   - สร้าง SIEM rule จาก hunt
   - Document ไว้สำหรับครั้งต่อไป
```

### 2.2 TTP-Based Hunt (MITRE)

```python
#!/usr/bin/env python3
# hunt_planner.py - วางแผน hunt

HUNT_HYPOTHESES = [
    {
        'title': 'Suspicious PowerShell Execution',
        'mitre': 'T1059.001',
        'hypothesis': 'Attackers using encoded PS commands',
        'data_sources': ['Windows Event 4688', 'PowerShell logging 4104'],
        'indicators': [
            'powershell.*-enc',
            'powershell.*-EncodedCommand',
            'powershell.*IEX',
            'powershell.*DownloadString',
            'powershell.*bypass'
        ]
    },
    {
        'title': 'Pass-the-Hash Detection',
        'mitre': 'T1550.002',
        'hypothesis': 'Lateral movement via NTLM hash',
        'data_sources': ['Windows Event 4624', 'Zeek auth.log'],
        'indicators': [
            'LogonType=3 + NTLMv2 + no explicit password',
            'Same hash, multiple hosts',
            'Admin share access SMB'
        ]
    },
    {
        'title': 'Kerberoasting Activity',
        'mitre': 'T1558.003',
        'hypothesis': 'Service ticket harvesting',
        'data_sources': ['Windows Event 4769 (TGS request)'],
        'indicators': [
            'Multiple 4769 events',
            'Encryption type 0x17 (RC4)',
            'Same source, different SPN'
        ]
    },
    {
        'title': 'DNS Tunneling',
        'mitre': 'T1071.004',
        'hypothesis': 'C2 via DNS queries',
        'data_sources': ['DNS logs', 'Network traffic'],
        'indicators': [
            'High frequency DNS queries',
            'Long subdomain names',
            'Unusual DNS record types (TXT/NULL)'
        ]
    }
]

for hunt in HUNT_HYPOTHESES:
    print(f"\n{'='*60}")
    print(f"HUNT: {hunt['title']}")
    print(f"MITRE: {hunt['mitre']}")
    print(f"Hypothesis: {hunt['hypothesis']}")
    print(f"Data Sources: {', '.join(hunt['data_sources'])}")
    print("Indicators:")
    for ind in hunt['indicators']:
        print(f"  - {ind}")
```

---

## 3. SIEM และ Log Analysis

### 3.1 Elasticsearch/Kibana (ELK Stack)

```bash
# ติดตั้ง ELK Stack
# Docker Compose
cat > /tmp/elk-docker-compose.yml << 'EOF'
version: '3'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    ports:
      - 9200:9200
    volumes:
      - esdata:/usr/share/elasticsearch/data
  
  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.0
    ports:
      - 5601:5601
    depends_on:
      - elasticsearch
  
  logstash:
    image: docker.elastic.co/logstash/logstash:8.10.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    depends_on:
      - elasticsearch

volumes:
  esdata:
EOF

docker-compose -f /tmp/elk-docker-compose.yml up -d

# Logstash config สำหรับ Windows event log
cat > /tmp/logstash.conf << 'EOF'
input {
  beats {
    port => 5044
  }
}

filter {
  if [event][code] {
    mutate {
      add_field => { "event_id" => "%{[event][code]}" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "winlogbeat-%{+YYYY.MM.dd}"
  }
}
EOF
```

### 3.2 KQL สำหรับ Kibana

```
Kibana Query Language (KQL) - Hunting Queries:

# Hunt: Suspicious PowerShell
process.name:"powershell.exe" AND 
  (process.args:(*-enc* OR *-EncodedCommand* OR *IEX* OR *bypass*))

# Hunt: Lateral Movement via SMB
event.code:4624 AND winlog.logon.type:3 AND
  NOT source.ip:192.168.1.0/24  # จาก external

# Hunt: Kerberoasting
event.code:4769 AND
  winlog.event_data.TicketEncryptionType:0x17 AND
  NOT winlog.event_data.ServiceName:*$  # ไม่ใช่ computer account

# Hunt: Process Injection indicators
event.code:8 AND process.parent.name:(powershell.exe OR cmd.exe)
  # Event 8 = CreateRemoteThread

# Hunt: Persistence via Registry Run keys
event.code:13 AND  # registry value set
  registry.path:(*\\CurrentVersion\\Run* OR *\\RunOnce*)

# Hunt: Scheduled tasks creation
event.code:(4698 OR 4702) AND  # task created/modified
  NOT user.name:("SYSTEM" OR "NT AUTHORITY*")
```

### 3.3 Splunk SPL Queries

```
Splunk Search Processing Language:

# Hunt: Large data exfiltration
index=netflow
| stats sum(bytes_out) as total_out by src_ip, dest_ip, dest_port
| where total_out > 100000000  # 100MB+
| sort -total_out

# Hunt: Beaconing detection
index=proxy
| stats count, avg(bytes), stdev(bytes), avg(time_taken) as avg_time 
  by src_ip, dest_host
| where stdev(bytes) < 100 AND count > 50  # สม่ำเสมอ + บ่อย = beaconing

# Hunt: Mimikatz indicators
index=wineventlog EventCode=4688
| where like(CommandLine, "%sekurlsa%") OR 
        like(CommandLine, "%lsadump%") OR
        like(CommandLine, "%kerberos%")
| table _time, host, user, CommandLine

# Hunt: Pass-the-Hash
index=wineventlog EventCode=4624 LogonType=3
| stats dc(host) as host_count, values(host) as hosts 
  by Security_ID, Account_Name
| where host_count > 3  # access หลายเครื่อง
| sort -host_count

# Hunt: Abnormal DNS
index=dns
| eval query_length = len(query)
| where query_length > 50  # Long subdomains
| stats count by query, src_ip
| sort -count
```

---

## 4. Endpoint Detection (EDR)

### 4.1 Sysmon ตั้งค่า

```xml
<!-- sysmon_config.xml - comprehensive monitoring -->
<Sysmon schemaversion="4.22">
  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  
  <EventFiltering>
    <!-- Process creation (Event 1) -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <Image condition="end with">cmd.exe</Image>
        <Image condition="end with">wscript.exe</Image>
        <Image condition="end with">cscript.exe</Image>
        <Image condition="end with">mshta.exe</Image>
        <Image condition="end with">regsvr32.exe</Image>
        <Image condition="end with">rundll32.exe</Image>
        <CommandLine condition="contains">-enc</CommandLine>
        <CommandLine condition="contains">IEX</CommandLine>
        <CommandLine condition="contains">DownloadString</CommandLine>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Network connections (Event 3) -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <Image condition="end with">wscript.exe</Image>
        <DestinationPort condition="is">4444</DestinationPort>
        <DestinationPort condition="is">1337</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
    
    <!-- File creation (Event 11) -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
      </FileCreate>
    </RuleGroup>
    
    <!-- Registry (Event 13) -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">\CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">\Winlogon</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    
    <!-- CreateRemoteThread (Event 8) -->
    <RuleGroup name="" groupRelation="or">
      <CreateRemoteThread onmatch="exclude">
        <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
      </CreateRemoteThread>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

```powershell
# ติดตั้ง Sysmon บน Windows
# ดาวน์โหลด https://docs.microsoft.com/sysinternals/downloads/sysmon

.\Sysmon64.exe -accepteula -i sysmon_config.xml

# ดู event logs
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | 
  Where-Object {$_.Id -eq 1} | 
  Select-Object -First 20 | 
  Format-List Message
```

### 4.2 Open Source EDR

```bash
# Wazuh HIDS/EDR
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
# Web UI: https://localhost:443

# Wazuh rules location:
# /var/ossec/ruleset/rules/

# สร้าง custom rule
cat > /var/ossec/etc/rules/custom_rules.xml << 'EOF'
<group name="custom_hunt">
  
  <rule id="100001" level="12">
    <if_group>syscheck</if_group>
    <match>/tmp/.*\.sh</match>
    <description>Shell script created in /tmp</description>
    <mitre>
      <id>T1059.004</id>
    </mitre>
  </rule>
  
  <rule id="100002" level="14">
    <if_sid>5715</if_sid>
    <match>chmod.*\+x.*/tmp/</match>
    <description>Executable made from /tmp</description>
  </rule>
  
  <rule id="100003" level="15">
    <if_sid>5715</if_sid>
    <regex>nc.*-e.*bash|bash.*-i.*>&.*tcp</regex>
    <description>Possible reverse shell command</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>
  
</group>
EOF

# Restart Wazuh
sudo systemctl restart wazuh-manager
```

---

## 5. Network Traffic Analysis

### 5.1 Zeek (Bro)

```bash
# ติดตั้ง Zeek
sudo apt install zeek -y

# เริ่ม analysis
cd /usr/share/zeek/site
zeek -r /evidence/capture.pcap local

# ไฟล์ output:
# conn.log    - connections
# dns.log     - DNS queries
# http.log    - HTTP requests
# ssl.log     - TLS connections
# files.log   - transferred files

# วิเคราะห์ conn.log
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | \
  sort -k5 -rn | head 20

# หา beaconing
cat conn.log | zeek-cut id.orig_h id.resp_h duration | \
  awk '{print $1, $2}' | sort | uniq -c | sort -rn | head 20

# Zeek script: ตรวจสอบ DNS tunneling
cat > /tmp/dns_hunt.zeek << 'EOF'
@load base/protocols/dns

event dns_request(c: connection, msg: dns_msg, query: string, 
                  qtype: count, qclass: count) {
    local subdomain_len = |query|;
    if (subdomain_len > 50) {
        print fmt("[DNS TUNNEL?] Long query: %s from %s (len=%d)",
            query, c$id$orig_h, subdomain_len);
    }
}
EOF
zeek -r capture.pcap /tmp/dns_hunt.zeek
```

### 5.2 Network Anomaly Detection

```python
#!/usr/bin/env python3
# network_hunt.py - หา anomalies ใน network logs

import pandas as pd
import numpy as np
from collections import Counter
import json

def detect_beaconing(log_file):
    """Hunt for C2 beaconing by analyzing periodic connections"""
    print("[*] Hunting for beaconing behavior...")
    
    connections = []
    with open(log_file) as f:
        for line in f:
            if line.startswith('#'):
                continue
            parts = line.strip().split('\t')
            if len(parts) >= 5:
                try:
                    connections.append({
                        'ts': float(parts[0]),
                        'src': parts[2],
                        'dst': parts[4],
                        'duration': float(parts[8]) if parts[8] != '-' else 0
                    })
                except:
                    pass
    
    df = pd.DataFrame(connections)
    if df.empty:
        return
    
    # Group by src-dst pair
    for (src, dst), group in df.groupby(['src', 'dst']):
        if len(group) < 10:
            continue
        
        # คำนวณ intervals
        times = sorted(group['ts'].values)
        intervals = np.diff(times)
        
        if len(intervals) < 5:
            continue
        
        # Low standard deviation = periodic = beaconing
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        jitter = (std_interval / mean_interval) * 100 if mean_interval > 0 else 100
        
        if jitter < 15 and 30 < mean_interval < 3600:  # periodic, 30s-1h
            print(f"[!] Beaconing: {src} -> {dst}")
            print(f"    Count: {len(group)}, Interval: {mean_interval:.0f}s, Jitter: {jitter:.1f}%")

def detect_dns_tunneling(dns_log):
    """Hunt for DNS tunneling"""
    print("[*] Hunting for DNS tunneling...")
    
    queries_by_domain = Counter()
    long_queries = []
    
    with open(dns_log) as f:
        for line in f:
            if line.startswith('#'):
                continue
            parts = line.strip().split('\t')
            if len(parts) >= 9 and parts[1] not in ('', '-'):
                query = parts[9] if len(parts) > 9 else ''
                
                # Count by base domain
                parts_domain = query.split('.')
                if len(parts_domain) >= 2:
                    base_domain = '.'.join(parts_domain[-2:])
                    queries_by_domain[base_domain] += 1
                
                # Long subdomain
                if len(query) > 50:
                    long_queries.append(query)
    
    print("\nTop domains by query count:")
    for domain, count in queries_by_domain.most_common(10):
        if count > 100:
            print(f"  [!] {domain}: {count} queries")
    
    if long_queries:
        print("\nLong DNS queries (possible tunneling):")
        for q in long_queries[:5]:
            print(f"  {q}")

if __name__ == '__main__':
    detect_beaconing('conn.log')
    detect_dns_tunneling('dns.log')
```

---

## 6. Hunting for Common TTPs

### 6.1 Hunt: Ransomware Precursors

```bash
# สัญญาณก่อน Ransomware

# 1. หา shadow copy deletion
grep -r 'vssadmin.*delete\|bcdedit.*recoveryenabled.*no' /var/log/

# Windows: Search event 4688
# CommandLine contains "vssadmin delete shadows"
# CommandLine contains "wbadmin delete catalog"

# 2. หา mass file extension changes
# Baseline: นับจำนวน file renames ต่อวินาที
# Anomaly: rename มากผิดปกติ + เปลี่ยนนามสกุล

# Sysmon Event 11 (file creation)
# Correlate: ไฟล์เดิม + .locked extension ใหม่

# 3. หา C2 communication
# DNS ไปหา unknown domain
# HTTPS ไปหา IP address โดยตรง (ไม่ใช่ domain)

# 4. หา network scanning ภายใน
# เครื่องหนึ่งที่ scan ภายในแบบผิดปกติ = lateral movement prelude
```

### 6.2 Hunt: Credential Theft

```python
#!/usr/bin/env python3
# hunt_credential_theft.py

# Hunt: Mimikatz-like activity
MIMIKATZ_PATTERNS = [
    'sekurlsa::',
    'lsadump::',
    'kerberos::',
    'privilege::debug',
    'token::elevate',
    'vault::cred',
    'dpapi::',
    'mimikatz',
    'invoke-mimikatz',
    'safetykatz',
    'rubeus',
    'sharpkatz',
]

# Hunt: LSASS access
LSASS_ACCESS_EVENTS = [
    'EventCode=10',  # ProcessAccess (Sysmon)
    'TargetImage=lsass.exe',
    'GrantedAccess=0x1010',  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    'GrantedAccess=0x1410',
]

# Hunt: NTDS.dit access
NTDS_PATTERNS = [
    'NTDS.dit',
    'vssvc.exe',
    'ntdsutil',
    'secretsdump',
    'invoke-dcsync',
    '\\SYSVOL\\',
]

def hunt_patterns(log_content, patterns, hunt_name):
    print(f"\n{'='*50}")
    print(f"HUNT: {hunt_name}")
    
    found = []
    for line in log_content.split('\n'):
        for pattern in patterns:
            if pattern.lower() in line.lower():
                found.append((pattern, line.strip()[:100]))
                break
    
    if found:
        print(f"[!] {len(found)} matches found!")
        for pattern, line in found[:10]:
            print(f"  Pattern '{pattern}': {line}")
    else:
        print("[-] No matches")
    
    return found

# Example usage
log_content = """
2024-01-15 14:23:45 INFO Process: mimikatz.exe started
2024-01-15 14:23:46 INFO sekurlsa::logonpasswords executed
2024-01-15 14:23:47 INFO LSASS accessed by PID 4567
"""

hunt_patterns(log_content, MIMIKATZ_PATTERNS, "Mimikatz Activity")
```

### 6.3 Hunt: Persistence Mechanisms

```bash
# Linux Persistence Hunt

# 1. Cron jobs ที่น่าสงสัย
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u "$user" 2>/dev/null | while read line; do
        echo "User: $user | Cron: $line"
    done
done

# 2. SUID/SGID binaries ที่ผิดปกติ
find / -perm -4000 -o -perm -2000 2>/dev/null | \
    grep -v -E '^/(bin|sbin|usr)/' | head 20

# 3. Unusual systemd services
systemctl list-units --type=service | grep -v 'masked\|disabled'
find /etc/systemd/ /usr/lib/systemd/ -name '*.service' -newer /etc/passwd

# 4. SSH authorized_keys
for dir in /home/*/.ssh /root/.ssh; do
    if [ -f "$dir/authorized_keys" ]; then
        echo "=== $dir/authorized_keys ==="
        cat "$dir/authorized_keys"
    fi
done

# 5. PAM backdoors
ls -la /etc/pam.d/
grep -r 'pam_exec\|pam_tally2' /etc/pam.d/

# 6. Unusual users
awk -F: '$3 == 0' /etc/passwd  # UID 0 นอกจาก root
awk -F: '$7 == "/bin/bash"' /etc/passwd  # shell accounts

# Windows Persistence Hunt (PowerShell)
# Check Run keys
Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Get-Item 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

# Check scheduled tasks
Get-ScheduledTask | Where-Object State -ne 'Disabled' | 
  Select TaskName, TaskPath, State | Export-Csv tasks.csv

# Check services
Get-Service | Where-Object StartType -eq 'Automatic' | 
  Select Name, DisplayName, Status
```

---

## 7. Sigma Rules

### 7.1 Sigma คืออะไร

```yaml
# Sigma = ภาษากลางสำหรับ detection rules
# แปลงไปเป็น Splunk/Elastic/QRadar/Sentinel query

title: Suspicious PowerShell Encoded Command
id: b3512211-5814-42d9-a9e7-36b2c14c8b85
status: stable
description: Detects PowerShell with encoded command execution
author: Security Team
date: 2024/01/01
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -ec '
  condition: selection
falsepositives:
  - Legitimate admin scripts
  - Software installers
level: medium
```

```yaml
title: LSASS Memory Dump via Procdump
id: a0c08c99-25e9-4f3e-a09d-b17e6a47f279
status: stable
description: Detects procdump usage to dump LSASS process
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\procdump.exe'
    CommandLine|contains:
      - 'lsass'
  selection2:
    Image|endswith:
      - '\rundll32.exe'
      - '\powershell.exe'
    CommandLine|contains: 'MiniDumpWriteDump'
  condition: selection or selection2
level: high
```

### 7.2 แปลง Sigma Rules

```bash
# ติดตั้ง sigma tool
pip3 install sigma-cli
pip3 install pySigma pySigma-backend-splunk pySigma-backend-elasticsearch

# แปลงเป็น Splunk query
sigma convert -t splunk rule.yml

# แปลงเป็น Elastic query
sigma convert -t es-qs rule.yml

# แปลงเป็น KQL (Azure Sentinel)
sigma convert -t kusto rule.yml

# ดาวน์โหลด Sigma rules
git clone https://github.com/SigmaHQ/sigma
ls sigma/rules/windows/
```

---

## 8. Threat Intelligence Integration

### 8.1 MISP

```bash
# MISP - Malware Information Sharing Platform
# ติดตั้งด้วย Docker
docker run -d -p 80:80 -p 443:443 \
  --name misp \
  -e MYSQL_HOST=db \
  harvarditsecurity/misp

# MISP API
import requests

MISP_URL = 'https://misp.local'
MISP_KEY = 'your_api_key'

headers = {
    'Authorization': MISP_KEY,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

# ค้นหา IOC
resp = requests.post(
    f'{MISP_URL}/attributes/restSearch',
    json={'value': '192.168.1.100', 'type': 'ip-dst'},
    headers=headers,
    verify=False
)
print(resp.json())
```

### 8.2 IOC Lookup Tools

```python
#!/usr/bin/env python3
# ioc_lookup.py - ตรวจสอบ IOC กับ threat intelligence

import requests
import hashlib
import json

class ThreatIntelLookup:
    def __init__(self):
        self.vt_api_key = 'YOUR_VT_API_KEY'
        self.abuse_ch_key = 'YOUR_ABUSE_CH_KEY'
    
    def virustotal_hash(self, file_hash):
        """VirusTotal hash lookup"""
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': self.vt_api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'total': sum(stats.values())
                }
        except:
            return None
    
    def abuseipdb(self, ip_address):
        """AbuseIPDB lookup"""
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': self.abuse_ch_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()['data']
                return {
                    'abuse_confidence': data.get('abuseConfidencePercentage', 0),
                    'total_reports': data.get('totalReports', 0),
                    'country': data.get('countryCode', '')
                }
        except:
            return None
    
    def lookup_all(self, ioc, ioc_type='hash'):
        print(f"\n[*] Checking IOC: {ioc} ({ioc_type})")
        
        if ioc_type == 'hash':
            vt = self.virustotal_hash(ioc)
            if vt:
                print(f"  VirusTotal: {vt['malicious']}/{vt['total']} malicious")
        
        elif ioc_type == 'ip':
            abuse = self.abuseipdb(ioc)
            if abuse:
                print(f"  AbuseIPDB: {abuse['abuse_confidence']}% confidence, {abuse['total_reports']} reports")

# ใช้งาน
til = ThreatIntelLookup()
tioc_list = [
    ('5f4dcc3b5aa765d61d8327deb882cf99', 'hash'),  # MD5
    ('192.168.1.100', 'ip'),
]

for ioc, ioc_type in tioc_list:
    til.lookup_all(ioc, ioc_type)
```

---

## 9. แบบฝึกหัด Lab

### Lab: Threat Hunt แบบจฺลอง

```bash
# สร้าง log สำหรับฝึก
cat > /tmp/hunt_lab_log.json << 'EOF'
[
  {"time":"2024-01-15T08:00:00", "event":"process_creation",
   "process":"powershell.exe", "cmdline":"-nop -w hidden -enc BASE64DATA",
   "user":"jdoe", "host":"WS01"},
  {"time":"2024-01-15T08:01:00", "event":"network_connect",
   "process":"powershell.exe", "dest":"185.220.101.45", "port":443,
   "user":"jdoe", "host":"WS01"},
  {"time":"2024-01-15T08:05:00", "event":"process_creation",
   "process":"cmd.exe", "cmdline":"net use \\\\DC01\\C$",
   "user":"jdoe", "host":"WS01"},
  {"time":"2024-01-15T08:10:00", "event":"logon",
   "logon_type":3, "user":"administrator", "src":"WS01", "dest":"DC01",
   "ntlm_hash":"aad3b435..."},
  {"time":"2024-01-15T08:15:00", "event":"process_creation",
   "process":"cmd.exe", "cmdline":"vssadmin delete shadows /all /quiet",
   "user":"SYSTEM", "host":"DC01"}
]
EOF

# Python hunt script
python3 << 'HUNT'
import json

with open('/tmp/hunt_lab_log.json') as f:
    events = json.load(f)

findings = []

for event in events:
    # Hunt 1: Encoded PS
    if event.get('event') == 'process_creation':
        if 'powershell' in event.get('process', '') and '-enc' in event.get('cmdline', '').lower():
            findings.append({'type': 'Encoded PowerShell', 'event': event})
    
    # Hunt 2: External C2 connection
    if event.get('event') == 'network_connect':
        dest = event.get('dest', '')
        if not dest.startswith(('192.168.', '10.', '172.')):
            findings.append({'type': 'External C2 Connection', 'event': event})
    
    # Hunt 3: Shadow copy deletion (Ransomware precursor)
    if event.get('event') == 'process_creation' and 'vssadmin delete' in event.get('cmdline', ''):
        findings.append({'type': 'CRITICAL: Shadow Copy Deletion', 'event': event})

print(f"\n=== Hunt Results: {len(findings)} findings ===")
for finding in findings:
    print(f"\n[{'!'*3}] {finding['type']}")
    for k, v in finding['event'].items():
        print(f"  {k}: {v}")
HUNT
```

### สรุป Threat Hunting

```
หลักการ Threat Hunting:

  Proactive → Hypothesis-based → TTP-focused
  
  Data Sources:
  - Windows: Sysmon, Event Logs, PowerShell logs
  - Network: Zeek, Suricata, NetFlow, DNS logs
  - Cloud: CloudTrail, Azure Monitor, GCP Logging
  
  Tools:
  - SIEM: Splunk, Elastic, Azure Sentinel
  - EDR: CrowdStrike, SentinelOne, Wazuh
  - Network: Zeek, NetworkMiner, Suricata
  - TI: MISP, VirusTotal, AbuseIPDB
  
  Key Hunts:
  - Beaconing (periodic C2)
  - Lateral movement (PtH, PtT)
  - Ransomware precursors
  - Credential theft (LSASS, Mimikatz)
  - Persistence (Run keys, services)
  - DNS/HTTPS tunneling
```

---

**[← Part 50: Red Team Operations](Part-50-Red-Team-Operations.md)** | **[→ Part 52: Security Automation](Part-52-Security-Automation.md)**
