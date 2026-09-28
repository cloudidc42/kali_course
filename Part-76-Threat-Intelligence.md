# Part 76: Threat Intelligence - การใช้ข้อมูลเรื่องภัยคุกคามเชิงลึก

## สารบัญ
1. [Threat Intelligence คืออะไร](#threat-intelligence-คืออะไร)
2. [Threat Intelligence Lifecycle](#threat-intelligence-lifecycle)
3. [Intelligence Sources](#intelligence-sources)
4. [IOC Collection และการวิเคราะห์](#ioc-collection-และการวิเคราะห์)
5. [MISP - Malware Information Sharing Platform](#misp)
6. [Threat Actor Profiling](#threat-actor-profiling)
7. [TTP Analysis](#ttp-analysis)
8. [Threat Intelligence Feeds](#threat-intelligence-feeds)
9. [Automated Intelligence Processing](#automated-intelligence-processing)
10. [Intelligence-Driven Defense](#intelligence-driven-defense)

---

## 1. Threat Intelligence คืออะไร

```
Pyramid of Pain (David Bianco):

          /\
         /  \   สีแดง (Hard)
        / TTPs\  Tactics, Techniques & Procedures
       /________\
      /  Tools   \
     /______________\
    /  Network/Host  \
   /   Artifacts      \
  /____________________\
 /  Domain Names        \
/__________________________\
/  IP Addresses             \
/____________________________\
/  Hash Values (MD5/SHA)      \
/______________________________\
                                
สีเขียว (Easy) - วัดค่าได้ง่าย แต่ Attacker เปลี่ยนได้ง่าย
สีแดง (Hard) - ยากในการแปลง เป็น Indicator ที่มีคุณค่ามากสุด
```

### ประเภท Threat Intelligence

| ประเภท | คำอธิบาย | ผู้ใช้
|--------|-------------|--------|
| Strategic | แนวโน้มภัยคุกคามระยะยาว | CISO, Board |
| Operational | ข้อมูล Campaign และ Threat Actor | SOC Manager |
| Tactical | TTPs ของ Adversary | SOC Analyst |
| Technical | IOCs สำหรับตรวจจับ | SIEM, Firewall |

---

## 2. Threat Intelligence Lifecycle

```python
#!/usr/bin/env python3
# ti_lifecycle.py - Threat Intelligence Lifecycle

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum

class TLPLevel(str, Enum):
    WHITE = "white"    # เผยแพร่ได้เลย
    GREEN = "green"    # เผยแพร่ในวงการ
    AMBER = "amber"    # เผยแพร่เฉพาะกลุ่ม
    RED = "red"        # ไม่เผยแพร่

class ConfidenceLevel(str, Enum):
    HIGH = "high"      # > 85%
    MEDIUM = "medium"  # 50-85%
    LOW = "low"        # < 50%

@dataclass
class ThreatIndicator:
    """ตัวชี้ภัย (Indicator of Compromise)"""
    ioc_type: str        # ip, domain, url, hash, email
    value: str           # ค่า IOC
    source: str          # แหล่งที่มา
    tlp: TLPLevel
    confidence: ConfidenceLevel
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    related_malware: List[str] = field(default_factory=list)
    related_actors: List[str] = field(default_factory=list)
    kill_chain_phase: Optional[str] = None
    score: int = 0       # 0-100, คะแนนความสำคัญ
    
    def is_expired(self, max_age_days: int = 90) -> bool:
        """ตรวจสอบว่า IOC หมดอายุแล้วหรือไม่"""
        age = (datetime.now() - self.last_seen).days
        return age > max_age_days

@dataclass
class IntelligenceReport:
    """Intelligence Report"""
    title: str
    summary: str
    tlp: TLPLevel
    author: str
    created_at: datetime
    indicators: List[ThreatIndicator] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    affected_industries: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_stix(self) -> Dict:
        """Export เป็น STIX 2.1 Format"""
        return {
            "type": "bundle",
            "id": f"bundle--{id(self)}",
            "objects": [
                {
                    "type": "report",
                    "spec_version": "2.1",
                    "name": self.title,
                    "description": self.summary,
                    "published": self.created_at.isoformat(),
                    "object_refs": [f"indicator--{id(ioc)}" for ioc in self.indicators]
                },
                *[
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": f"indicator--{id(ioc)}",
                        "name": ioc.value,
                        "pattern_type": "stix",
                        "pattern": self._to_stix_pattern(ioc),
                        "valid_from": ioc.first_seen.isoformat()
                    }
                    for ioc in self.indicators
                ]
            ]
        }
    
    def _to_stix_pattern(self, ioc: ThreatIndicator) -> str:
        """Convert IOC เป็น STIX Pattern"""
        patterns = {
            "ip": f"[ipv4-addr:value = '{ioc.value}']",
            "domain": f"[domain-name:value = '{ioc.value}']",
            "url": f"[url:value = '{ioc.value}']",
            "md5": f"[file:hashes.MD5 = '{ioc.value}']",
            "sha256": f"[file:hashes.'SHA-256' = '{ioc.value}']",
            "email": f"[email-addr:value = '{ioc.value}']"
        }
        return patterns.get(ioc.ioc_type, f"[artifact:payload_bin = '{ioc.value}']")
```

---

## 3. Intelligence Sources

### Open Source Intelligence (OSINT)

```bash
#!/bin/bash
# osint_collection.sh - เก็บข้อมูล OSINT

# 1. ตรวจสอบ IP Reputation ด้วย AbuseIPDB
curl -s -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=1.2.3.4" \
  -d maxAgeInDays=90 \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json" | python3 -m json.tool

# 2. VirusTotal สำหรับ Hash/IP/Domain
# Hash
curl -s --request GET \
  --url "https://www.virustotal.com/api/v3/files/HASH_HERE" \
  --header "x-apikey: YOUR_VT_KEY" | python3 -m json.tool

# IP
curl -s --request GET \
  --url "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4" \
  --header "x-apikey: YOUR_VT_KEY" | python3 -m json.tool

# Domain
curl -s --request GET \
  --url "https://www.virustotal.com/api/v3/domains/evil.com" \
  --header "x-apikey: YOUR_VT_KEY" | python3 -m json.tool

# 3. Shodan
curl -s "https://api.shodan.io/shodan/host/1.2.3.4?key=YOUR_SHODAN_KEY" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f'OS: {d.get(\"os\", \"Unknown\")}')
print(f'Org: {d.get(\"org\", \"Unknown\")}')
for port in d.get('ports', []):
    print(f'  Port: {port}')
"

# 4. GreyNoise
curl -s "https://api.greynoise.io/v3/community/1.2.3.4" \
  -H "key: YOUR_GN_KEY" | python3 -m json.tool

# 5. URLhaus
curl -s -X POST https://urlhaus-api.abuse.ch/v1/lookup/ \
  --data "url=https://evil.com/malware.exe" | python3 -m json.tool

# 6. MalwareBazaar
curl -s -X POST https://mb-api.abuse.ch/api/v1/ \
  --data 'query=get_info&hash=HASH_HERE' | python3 -m json.tool

# 7. AlienVault OTX
curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general" \
  -H "X-OTX-API-KEY: YOUR_OTX_KEY" | python3 -m json.tool
```

### Python Intelligence Aggregator

```python
#!/usr/bin/env python3
# threat_intel_aggregator.py - รวบรวม Intelligence จากหลายแหล่ง

import requests
import json
import hashlib
from typing import Dict, List, Optional
from datetime import datetime

class ThreatIntelAggregator:
    """รวบรวม Threat Intelligence จากหลายแหล่ง"""
    
    def __init__(self, api_keys: Dict[str, str]):
        self.api_keys = api_keys
        self.cache = {}  # Cache ไว้เพื่อไม่ต้อง Query ซ้ำ
    
    def enrich_ip(self, ip: str) -> Dict:
        """เสริมข้อมูล IP Address"""
        cache_key = f"ip:{ip}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        result = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "sources": {}
        }
        
        # VirusTotal
        vt_result = self._query_virustotal_ip(ip)
        if vt_result:
            result["sources"]["virustotal"] = {
                "malicious": vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                "reputation": vt_result.get("data", {}).get("attributes", {}).get("reputation", 0)
            }
        
        # AbuseIPDB
        abuse_result = self._query_abuseipdb(ip)
        if abuse_result:
            data = abuse_result.get("data", {})
            result["sources"]["abuseipdb"] = {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "total_reports": data.get("totalReports", 0)
            }
        
        # คำนวณคะแนนรวม
        result["risk_score"] = self._calculate_ip_risk(result["sources"])
        result["verdict"] = "malicious" if result["risk_score"] > 70 else \
                            "suspicious" if result["risk_score"] > 40 else "clean"
        
        self.cache[cache_key] = result
        return result
    
    def enrich_hash(self, file_hash: str) -> Dict:
        """เสริมข้อมูล File Hash"""
        result = {
            "hash": file_hash,
            "hash_type": self._detect_hash_type(file_hash),
            "timestamp": datetime.now().isoformat(),
            "sources": {}
        }
        
        # VirusTotal
        vt_result = self._query_virustotal_hash(file_hash)
        if vt_result:
            attrs = vt_result.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result["sources"]["virustotal"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
                "name": attrs.get("meaningful_name", ""),
                "type": attrs.get("type_description", "")
            }
        
        # MalwareBazaar
        mb_result = self._query_malwarebazaar(file_hash)
        if mb_result and mb_result.get("query_status") == "ok":
            data = mb_result.get("data", [{}])[0]
            result["sources"]["malwarebazaar"] = {
                "malware_family": data.get("tags", []),
                "file_type": data.get("file_type_mime"),
                "first_seen": data.get("first_seen")
            }
        
        result["risk_score"] = self._calculate_hash_risk(result["sources"])
        result["verdict"] = "malicious" if result["risk_score"] > 50 else \
                            "suspicious" if result["risk_score"] > 20 else "clean"
        
        return result
    
    def enrich_domain(self, domain: str) -> Dict:
        """เสริมข้อมูล Domain"""
        result = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "sources": {}
        }
        
        # VirusTotal Domain
        vt_result = self._query_virustotal_domain(domain)
        if vt_result:
            attrs = vt_result.get("data", {}).get("attributes", {})
            result["sources"]["virustotal"] = {
                "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                "categories": attrs.get("categories", {}),
                "creation_date": attrs.get("creation_date")
            }
        
        result["risk_score"] = self._calculate_domain_risk(result["sources"])
        result["verdict"] = "malicious" if result["risk_score"] > 60 else \
                            "suspicious" if result["risk_score"] > 30 else "clean"
        
        return result
    
    def _query_virustotal_ip(self, ip: str) -> Optional[Dict]:
        """Query VirusTotal สำหรับ IP"""
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.api_keys.get("virustotal", "")},
                timeout=10
            )
            return resp.json() if resp.status_code == 200 else None
        except:
            return None
    
    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Query AbuseIPDB"""
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.api_keys.get("abuseipdb", ""),
                         "Accept": "application/json"},
                timeout=10
            )
            return resp.json() if resp.status_code == 200 else None
        except:
            return None
    
    def _query_virustotal_hash(self, file_hash: str) -> Optional[Dict]:
        """Query VirusTotal สำหรับ Hash"""
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": self.api_keys.get("virustotal", "")},
                timeout=10
            )
            return resp.json() if resp.status_code == 200 else None
        except:
            return None
    
    def _query_malwarebazaar(self, file_hash: str) -> Optional[Dict]:
        """Query MalwareBazaar"""
        try:
            resp = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": file_hash},
                timeout=10
            )
            return resp.json() if resp.status_code == 200 else None
        except:
            return None
    
    def _query_virustotal_domain(self, domain: str) -> Optional[Dict]:
        """Query VirusTotal สำหรับ Domain"""
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self.api_keys.get("virustotal", "")},
                timeout=10
            )
            return resp.json() if resp.status_code == 200 else None
        except:
            return None
    
    def _detect_hash_type(self, file_hash: str) -> str:
        """Detect ประเภท Hash"""
        lengths = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
        return lengths.get(len(file_hash), "unknown")
    
    def _calculate_ip_risk(self, sources: Dict) -> int:
        """คำนวณ Risk Score สำหรับ IP"""
        score = 0
        if "abuseipdb" in sources:
            score += sources["abuseipdb"]["abuse_score"] * 0.5
        if "virustotal" in sources:
            malicious = sources["virustotal"]["malicious"]
            score += min(malicious * 5, 50)
        return min(int(score), 100)
    
    def _calculate_hash_risk(self, sources: Dict) -> int:
        """คำนวณ Risk Score สำหรับ Hash"""
        if "virustotal" in sources:
            vt = sources["virustotal"]
            total = vt.get("total", 1)
            malicious = vt.get("malicious", 0)
            if total > 0:
                return int((malicious / total) * 100)
        return 0
    
    def _calculate_domain_risk(self, sources: Dict) -> int:
        """คำนวณ Risk Score สำหรับ Domain"""
        score = 0
        if "virustotal" in sources:
            malicious = sources["virustotal"]["malicious"]
            score += min(malicious * 10, 100)
        return min(int(score), 100)
    
    def bulk_check(self, ioc_list: List[Dict]) -> List[Dict]:
        """ตรวจสอบ IOC หลายรายการพร้อมกัน"""
        results = []
        for ioc in ioc_list:
            ioc_type = ioc.get("type")
            value = ioc.get("value")
            
            if ioc_type == "ip":
                result = self.enrich_ip(value)
            elif ioc_type == "hash":
                result = self.enrich_hash(value)
            elif ioc_type == "domain":
                result = self.enrich_domain(value)
            else:
                result = {"type": ioc_type, "value": value, "verdict": "unknown"}
            
            results.append(result)
            print(f"  [{result.get('verdict', 'unknown').upper():>10}] {ioc_type}: {value} "
                  f"(risk: {result.get('risk_score', 0)})")
        
        return results

# ตัวอย่างการใช้งาน
api_keys = {
    "virustotal": "YOUR_VT_API_KEY",
    "abuseipdb": "YOUR_ABUSEIPDB_KEY",
    "otx": "YOUR_OTX_KEY"
}

aggregator = ThreatIntelAggregator(api_keys)

iocs_to_check = [
    {"type": "ip", "value": "1.2.3.4"},
    {"type": "domain", "value": "evil-domain.com"},
    {"type": "hash", "value": "44d88612fea8a8f36de82e1278abb02f"}
]

print("[*] Starting IOC Enrichment...")
results = aggregator.bulk_check(iocs_to_check)
print(f"\n[+] Processed {len(results)} IOCs")
```

---

## 4. IOC Collection และการวิเคราะห์

### การดึง IOC จาก Malware Sample

```python
#!/usr/bin/env python3
# ioc_extractor.py - ดึง IOC จากสองหลายแหล่ง

import re
import ipaddress
from typing import Set, Dict, List
from urllib.parse import urlparse

class IOCExtractor:
    """ดึง IOC จากข้อความและไ༝ล์"""
    
    # Regex Patterns
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}\b'
    )
    URL_PATTERN = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        r'(?:[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=]*)'
    )
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
    
    # Private/Reserved IP Ranges (ยกเว้น)
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
    ]
    
    # Common legitimate domains (ยกเว้น)
    WHITELIST_DOMAINS = {
        'microsoft.com', 'windows.com', 'windowsupdate.com',
        'google.com', 'googleapis.com', 'apple.com',
        'amazon.com', 'amazonaws.com', 'cloudfront.net'
    }
    
    def extract_from_text(self, text: str) -> Dict[str, Set[str]]:
        """ดึง IOC จากข้อความ (Security Report, Email, etc.)"""
        iocs = {
            "ips": set(),
            "domains": set(),
            "urls": set(),
            "emails": set(),
            "md5": set(),
            "sha1": set(),
            "sha256": set()
        }
        
        # IPs
        for ip in self.IP_PATTERN.findall(text):
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not any(ip_obj in net for net in self.PRIVATE_RANGES):
                    iocs["ips"].add(ip)
            except:
                pass
        
        # Domains
        for domain in self.DOMAIN_PATTERN.findall(text):
            domain_lower = domain.lower()
            if not any(domain_lower.endswith(d) for d in self.WHITELIST_DOMAINS):
                iocs["domains"].add(domain_lower)
        
        # URLs
        for url in self.URL_PATTERN.findall(text):
            parsed = urlparse(url)
            if parsed.netloc and not any(
                parsed.netloc.endswith(d) for d in self.WHITELIST_DOMAINS
            ):
                iocs["urls"].add(url)
        
        # Emails
        iocs["emails"] = set(self.EMAIL_PATTERN.findall(text))
        
        # Hashes
        # SHA256 ต้องดูก่อน เพราะมีความยาวเท่ากัน
        sha256_hashes = self.SHA256_PATTERN.findall(text)
        sha1_hashes = set()
        md5_hashes = set()
        
        # SHA1 ต้องตรวจว่าไม่ใช่ส่วนหนึ่งของ SHA256
        sha256_set = set(sha256_hashes)
        for h in self.SHA1_PATTERN.findall(text):
            if not any(sha256.startswith(h) for sha256 in sha256_set):
                sha1_hashes.add(h)
        
        # MD5 ต้องตรวจว่าไม่ใช่ส่วนหนึ่งของ SHA1 หรือ SHA256
        for h in self.MD5_PATTERN.findall(text):
            if not any(sha1.startswith(h) for sha1 in sha1_hashes) and \
               not any(sha256.startswith(h) for sha256 in sha256_set):
                md5_hashes.add(h)
        
        iocs["md5"] = md5_hashes
        iocs["sha1"] = sha1_hashes
        iocs["sha256"] = sha256_set
        
        return iocs
    
    def defang(self, ioc: str, ioc_type: str) -> str:
        """ทำ Defang IOC เพื่อไม่ให้คลิกได้
        
        IP: 1.2.3.4 -> 1[.]2[.]3[.]4
        Domain: evil.com -> evil[.]com
        URL: http://evil.com -> hXXp://evil[.]com
        """
        if ioc_type in ["ip", "domain"]:
            return ioc.replace(".", "[.]")
        elif ioc_type == "url":
            defanged = ioc.replace("http", "hXXp")
            defanged = defanged.replace(".", "[.]", defanged.count(".") - 1)
            return defanged
        return ioc
    
    def refang(self, ioc: str) -> str:
        """เอา Defanged IOC กลับมา"""
        return ioc.replace("[.]", ".").replace("hXXp", "http").replace("hXXps", "https")

# ตัวอย่างการใช้งาน
SAMPLE_REPORT = """
Threat Actor Campaign Analysis - APT-X

The threat actor was observed communicating with C2 server at 185.220.101.42.
Malicious domain observed: malware-c2[.]evil-domain[.]com
Malware hash (SHA256): 44d88612fea8a8f36de82e1278abb02f7ac52b9dc1f85c421a4e8e1c4e8b1234
Phishing email sent from: attacker@spoofed-domain.com
Malicious URL: hXXps://192.168.100.200/payload.ps1

Network indicators:
- 10.0.0.1 (internal pivot)
- 8.8.8.8 (legitimate DNS - ยกเว้น)
- 185.220.101.43 another C2
- evil-download.net C2 domain

File hashes:
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""

extractor = IOCExtractor()
iocs = extractor.extract_from_text(SAMPLE_REPORT)

print("=== Extracted IOCs ===")
for ioc_type, values in iocs.items():
    if values:
        print(f"\n{ioc_type.upper()}:")
        for v in values:
            print(f"  - {v}")

print("\n=== Defanged Examples ===")
print(extractor.defang("185.220.101.42", "ip"))
print(extractor.defang("evil-domain.com", "domain"))
print(extractor.defang("https://evil.com/path", "url"))
```

---

## 5. MISP

### MISP Setup และการใช้งาน

```bash
# ติดตั้ง MISP ด้วย Docker
docker pull misp/misp
docker run -d --name misp \
  -p 443:443 \
  -e "MISP_FQDN=misp.lab.local" \
  -e "MISP_BASEURL=https://misp.lab.local" \
  -e "MISP_SALT=YourSecretSalt" \
  misp/misp

# หรือติดตั้ง MISP แบบ Manual
curl -O https://github.com/MISP/misp-vagrant/raw/master/install.sh
bash install.sh

# ติดตั้ง PyMISP
pip3 install pymisp
```

### PyMISP - Python API

```python
#!/usr/bin/env python3
# misp_integration.py - เชื่อมต่อ MISP

from pymisp import PyMISP, MISPEvent, MISPAttribute
from datetime import datetime
from typing import List, Dict

class MISPIntegration:
    """จัดการ Threat Intelligence ผ่าน MISP"""
    
    def __init__(self, url: str, key: str, verify_ssl: bool = False):
        self.misp = PyMISP(url, key, ssl=verify_ssl)
        print(f"[+] Connected to MISP: {url}")
    
    def create_event(self, title: str, threat_level: int = 2,
                    distribution: int = 0) -> MISPEvent:
        """
        สร้าง MISP Event ใหม่
        threat_level: 1=High, 2=Medium, 3=Low, 4=Undefined
        distribution: 0=Org, 1=Community, 2=Connected, 3=All, 4=Group, 5=Inherit
        """
        event = MISPEvent()
        event.info = title
        event.threat_level_id = threat_level
        event.distribution = distribution
        event.analysis = 2  # Completed
        
        result = self.misp.add_event(event)
        print(f"[+] Created event: {result.id} - {title}")
        return result
    
    def add_ioc(self, event_id: int, ioc_type: str, value: str,
               comment: str = "", to_ids: bool = True) -> MISPAttribute:
        """
        เพิ่ม IOC เข้า Event
        ioc_type: ip-dst, domain, url, md5, sha256, email-src, etc.
        """
        attr = MISPAttribute()
        attr.type = ioc_type
        attr.value = value
        attr.comment = comment
        attr.to_ids = to_ids
        
        result = self.misp.add_attribute(event_id, attr)
        return result
    
    def import_ioc_list(self, event_id: int, iocs: Dict) -> int:
        """นำเข้า IOC List ที่ดึงมาจาก IOCExtractor"""
        type_mapping = {
            "ips": "ip-dst",
            "domains": "domain",
            "urls": "url",
            "emails": "email-src",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256"
        }
        
        count = 0
        for ioc_category, values in iocs.items():
            misp_type = type_mapping.get(ioc_category)
            if not misp_type or not values:
                continue
            
            for value in values:
                self.add_ioc(event_id, misp_type, value)
                count += 1
        
        print(f"[+] Imported {count} IOCs to event {event_id}")
        return count
    
    def search_ioc(self, value: str) -> List[Dict]:
        """ค้นหา IOC ใน MISP"""
        result = self.misp.search(value=value, pythonify=True)
        matches = []
        
        for event in result:
            for attr in event.attributes:
                if value.lower() in str(attr.value).lower():
                    matches.append({
                        "event_id": event.id,
                        "event_name": event.info,
                        "ioc_type": attr.type,
                        "ioc_value": attr.value,
                        "threat_level": event.threat_level_id,
                        "date": str(event.date)
                    })
        
        return matches
    
    def publish_event(self, event_id: int):
        """เผยแพร่ Event ไปยัง MISP Community"""
        event = self.misp.get_event(event_id, pythonify=True)
        event.distribution = 1  # This community
        self.misp.update_event(event)
        self.misp.publish(event_id)
        print(f"[+] Event {event_id} published")
    
    def get_feeds(self) -> List[Dict]:
        """ดึง Threat Intel Feeds ที่ใช้อยู่"""
        feeds = self.misp.feeds()
        return [{"id": f.id, "name": f.name, "enabled": f.enabled}
                for f in feeds]
    
    def sync_feeds(self):
        """อัพเดต Feeds ทั้งหมด"""
        feeds = self.misp.feeds()
        for feed in feeds:
            if feed.enabled:
                print(f"[*] Syncing feed: {feed.name}")
                self.misp.fetch_feed(feed.id)
    
    def export_stix2(self, event_id: int) -> str:
        """ส่งออก Event เป็น STIX 2.1"""
        result = self.misp.get_event(event_id, pythonify=True)
        # ส่งออกเป็น STIX 2.1 JSON
        stix = self.misp.export_event(event_id, 'stix2')
        return stix

# ตัวอย่างการใช้งาน
# misp = MISPIntegration("https://misp.lab.local", "YOUR_API_KEY")

# สร้าง Event สำหรับ Campaign ใหม่
# event = misp.create_event("APT-X Campaign - 2024 Q4", threat_level=1)

# เพิ่ม IOCs
# misp.add_ioc(event.id, "ip-dst", "185.220.101.42", "C2 Server")
# misp.add_ioc(event.id, "domain", "evil-c2.com", "C2 Domain")
# misp.add_ioc(event.id, "sha256", "abc123...", "Malware Hash")

# ค้นหา
# results = misp.search_ioc("185.220.101.42")
# for r in results:
#     print(f"Found in: {r['event_name']} ({r['date']})")
```

---

## 6. Threat Actor Profiling

```python
#!/usr/bin/env python3
# threat_actor_profiles.py

THREAT_ACTORS = {
    "APT29": {
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM"],
        "origin": "Russia",
        "sponsor": "SVR (Foreign Intelligence Service)",
        "active_since": "2008",
        "motivation": ["Espionage", "Intelligence Collection"],
        "target_sectors": [
            "Government", "Defense", "Diplomatic",
            "Healthcare", "Technology", "Energy"
        ],
        "target_regions": ["Western Europe", "North America", "CIS"],
        "known_campaigns": [
            "SolarWinds Supply Chain (2020)",
            "COVID-19 Vaccine Research (2020)",
            "DNC Hack (2016)",
            "TeamViewer Compromise (2019)"
        ],
        "malware": [
            "SUNBURST", "Cobalt Strike", "WellMess",
            "HAMMERTOSS", "MiniDuke", "CosmicDuke", "MagicWeb"
        ],
        "ttps": [
            "T1566.001",  # Spearphishing Attachment
            "T1059.001",  # PowerShell
            "T1053.005",  # Scheduled Task
            "T1078",      # Valid Accounts
            "T1003.001",  # LSASS Memory
            "T1027",      # Obfuscated Files
            "T1071.001",  # Web Protocols
        ],
        "infrastructure": [
            "Legitimate Cloud Services (OneDrive, Dropbox)",
            "Compromised Websites",
            "VPS Providers"
        ]
    },
    
    "APT41": {
        "aliases": ["Double Dragon", "Winnti Group", "BARIUM"],
        "origin": "China",
        "sponsor": "Ministry of State Security (MSS)",
        "active_since": "2012",
        "motivation": ["Espionage", "Financial Gain"],
        "target_sectors": [
            "Healthcare", "Gaming", "Technology",
            "Telecommunications", "Finance"
        ],
        "known_campaigns": [
            "ShadowHammer (ASUS Supply Chain)",
            "COVID-19 Research Theft",
            "Gaming Company Attacks"
        ],
        "malware": [
            "MESSAGETAP", "Cobalt Strike", "ShadowPad",
            "Winnti", "PlugX", "DUSTPAN"
        ],
        "ttps": [
            "T1195.002",  # Compromise Software Supply Chain
            "T1190",      # Exploit Public-Facing Application
            "T1505.003",  # Web Shell
            "T1560",      # Archive Collected Data
        ]
    },
    
    "Lazarus Group": {
        "aliases": ["Hidden Cobra", "ZINC", "APT38"],
        "origin": "North Korea",
        "sponsor": "Reconnaissance General Bureau (RGB)",
        "active_since": "2009",
        "motivation": ["Financial Gain", "Espionage", "Sabotage"],
        "target_sectors": [
            "Financial", "Cryptocurrency", "Defense",
            "Government", "Critical Infrastructure"
        ],
        "known_campaigns": [
            "Sony Pictures Hack (2014)",
            "WannaCry Ransomware (2017)",
            "SWIFT Bank Heist ($81M Bangladesh Bank)",
            "Crypto Exchange Attacks",
            "Operation Dream Job (Fake Recruitment)"
        ],
        "malware": [
            "DarkSeoul", "Destover", "HOPLIGHT",
            "FALLCHILL", "TYPEFRAME", "BADCALL"
        ],
        "ttps": [
            "T1566.002",  # Spearphishing Link
            "T1059.003",  # Windows Command Shell
            "T1055",      # Process Injection
            "T1486",      # Data Encrypted for Impact
            "T1041",      # Exfiltration over C2
        ]
    },
    
    "FIN7": {
        "aliases": ["Carbanak", "Navigator Group", "ELBRUS"],
        "origin": "Ukraine/Russia (Suspected)",
        "sponsor": "Criminal Organization",
        "active_since": "2013",
        "motivation": ["Financial Gain"],
        "target_sectors": [
            "Restaurant", "Retail", "Hospitality",
            "Finance", "Technology"
        ],
        "known_campaigns": [
            "Chipotle, Red Robin Point-of-Sale",
            "Saks Fifth Avenue Breach",
            "REvil Ransomware Operations"
        ],
        "malware": [
            "CARBANAK", "BATELEUR", "HALFBAKED",
            "Cobalt Strike", "PILLOWMINT"
        ],
        "ttps": [
            "T1566.001",  # Spearphishing
            "T1204.002",  # Malicious File Execution
            "T1059.005",  # Visual Basic
            "T1056.001",  # Keylogging
            "T1041",      # Exfiltration
        ]
    }
}

class ThreatActorAnalyzer:
    """วิเคราะห์ Threat Actor"""
    
    def __init__(self):
        self.actors = THREAT_ACTORS
    
    def identify_actor(self, observed_ttps: List[str],
                       observed_malware: List[str] = None,
                       target_sector: str = None) -> List[Dict]:
        """ระบุ Threat Actor จาก TTPs ที่สังเกตเห็น"""
        matches = []
        
        for actor_name, actor_data in self.actors.items():
            score = 0
            matched_ttps = []
            matched_malware = []
            
            # ตรวจสอบ TTPs
            for ttp in observed_ttps:
                if ttp in actor_data.get("ttps", []):
                    score += 10
                    matched_ttps.append(ttp)
            
            # ตรวจสอบ Malware
            if observed_malware:
                for malware in observed_malware:
                    if any(malware.lower() in m.lower() 
                           for m in actor_data.get("malware", [])):
                        score += 20
                        matched_malware.append(malware)
            
            # ตรวจสอบ Target Sector
            if target_sector:
                if any(target_sector.lower() in s.lower()
                       for s in actor_data.get("target_sectors", [])):
                    score += 15
            
            if score > 0:
                matches.append({
                    "actor": actor_name,
                    "aliases": actor_data["aliases"],
                    "origin": actor_data["origin"],
                    "confidence_score": score,
                    "matched_ttps": matched_ttps,
                    "matched_malware": matched_malware,
                    "motivation": actor_data["motivation"]
                })
        
        return sorted(matches, key=lambda x: x["confidence_score"], reverse=True)
    
    def generate_actor_report(self, actor_name: str) -> str:
        """สร้างรายงานข้อมูล Threat Actor"""
        if actor_name not in self.actors:
            return f"ไม่พบข้อมูลของ {actor_name}"
        
        actor = self.actors[actor_name]
        report = f"""
{'='*60}
THREAT ACTOR REPORT: {actor_name}
{'='*60}

Aliases: {', '.join(actor['aliases'])}
Origin: {actor['origin']}
Sponsor: {actor['sponsor']}
Active Since: {actor['active_since']}
Motivation: {', '.join(actor['motivation'])}

Target Sectors:
{chr(10).join(f'  - {s}' for s in actor['target_sectors'])}

Known Campaigns:
{chr(10).join(f'  - {c}' for c in actor['known_campaigns'])}

Malware Arsenal:
{chr(10).join(f'  - {m}' for m in actor['malware'])}

ATT&CK TTPs:
{chr(10).join(f'  - {t}' for t in actor['ttps'])}

Mitigation Recommendations:
  - Monitor for TTPs listed above
  - Block known malware hashes
  - Implement email filtering for spearphishing
  - Enable MFA for all privileged accounts
  - Monitor sensitive data access and exfiltration
{'='*60}
"""
        return report

# ตัวอย่าง
analyzer = ThreatActorAnalyzer()

# สมมติว่าสังเกตเห็น TTPs เหล่านี้
observed_ttps = ["T1566.001", "T1059.001", "T1003.001", "T1071.001"]

matches = analyzer.identify_actor(
    observed_ttps=observed_ttps,
    target_sector="Government"
)

print("\n=== Potential Threat Actors ===")
for match in matches:
    print(f"\n{match['actor']} (Score: {match['confidence_score']})")
    print(f"  Origin: {match['origin']}")
    print(f"  Matched TTPs: {', '.join(match['matched_ttps'])}")

print(analyzer.generate_actor_report("APT29"))
```

---

## 7. TTP Analysis

```python
#!/usr/bin/env python3
# ttp_analyzer.py - วิเคราะห์ TTPs จาก Incident Data

from collections import Counter
import json

TTP_DESCRIPTIONS = {
    "T1566.001": "Spearphishing Attachment - ส่ง Email พร้อม Malicious Attachment",
    "T1059.001": "PowerShell - ใช้ PowerShell รัน Commands",
    "T1003.001": "LSASS Memory - ดึง Credentials จาก LSASS Process",
    "T1558.003": "Kerberoasting - ขโมย Service Tickets",
    "T1550.002": "Pass the Hash - ใช้ Hash เพื่อ Authentication",
    "T1547.001": "Registry Run Keys - ตั้ง Persistence ผ่าน Registry",
    "T1053.005": "Scheduled Task - ตั้ง Persistence ผ่าน Task Scheduler",
    "T1071.001": "Web Protocols - C2 ผ่าน HTTP/HTTPS",
    "T1041": "Exfil over C2 Channel - ส่งข้อมูลผ่าน C2",
    "T1486": "Data Encrypted for Impact - Ransomware"
}

class TTPAnalyzer:
    """วิเคราะห์ TTPs จาก Incident Data"""
    
    def analyze_campaign(self, campaign_ttps: List[Dict]) -> Dict:
        """
        campaign_ttps: List of {"incident_id": x, "ttps": ["T1234", ...]}
        """
        all_ttps = []
        for incident in campaign_ttps:
            all_ttps.extend(incident["ttps"])
        
        ttp_counts = Counter(all_ttps)
        
        # จัดกลุ่มตาม Tactic
        tactic_groups = {
            "Initial Access": ["T1566", "T1190", "T1133", "T1078"],
            "Execution": ["T1059", "T1053", "T1047", "T1204"],
            "Persistence": ["T1547", "T1053", "T1505", "T1136"],
            "Privilege Escalation": ["T1548", "T1134", "T1055", "T1068"],
            "Defense Evasion": ["T1562", "T1070", "T1027", "T1574"],
            "Credential Access": ["T1003", "T1558", "T1552", "T1110"],
            "Discovery": ["T1087", "T1082", "T1046", "T1069"],
            "Lateral Movement": ["T1550", "T1021", "T1570"],
            "Collection": ["T1005", "T1074", "T1056"],
            "Command and Control": ["T1071", "T1095", "T1573", "T1090"],
            "Exfiltration": ["T1041", "T1030", "T1048"],
            "Impact": ["T1486", "T1489", "T1485", "T1491"]
        }
        
        tactic_coverage = {}
        for tactic, base_techniques in tactic_groups.items():
            observed = [t for t in all_ttps 
                       if any(t.startswith(bt) for bt in base_techniques)]
            tactic_coverage[tactic] = {
                "observed": list(set(observed)),
                "count": len(observed)
            }
        
        return {
            "total_incidents": len(campaign_ttps),
            "unique_ttps": len(set(all_ttps)),
            "most_common": ttp_counts.most_common(10),
            "tactic_coverage": tactic_coverage,
            "kill_chain_coverage": self._assess_kill_chain(tactic_coverage)
        }
    
    def _assess_kill_chain(self, tactic_coverage: Dict) -> str:
        """ประเมินว่า Campaign Cover Kill Chain ได้มากแค่ไหน"""
        covered_tactics = sum(1 for t, data in tactic_coverage.items()
                             if data["count"] > 0)
        total_tactics = len(tactic_coverage)
        pct = covered_tactics / total_tactics * 100
        
        if pct > 80:
            return f"Full Campaign ({pct:.0f}% Kill Chain Coverage)"
        elif pct > 50:
            return f"Partial Campaign ({pct:.0f}% Kill Chain Coverage)"
        else:
            return f"Limited Activity ({pct:.0f}% Kill Chain Coverage)"

# ตัวอย่าง Campaign Data
campaign = [
    {"incident_id": "INC-001", "ttps": ["T1566.001", "T1059.001", "T1547.001"]},
    {"incident_id": "INC-002", "ttps": ["T1566.001", "T1003.001", "T1550.002", "T1021.001"]},
    {"incident_id": "INC-003", "ttps": ["T1558.003", "T1071.001", "T1041"]},
]

analyzer = TTPAnalyzer()
results = analyzer.analyze_campaign(campaign)

print(f"Campaign Analysis:")
print(f"  Total Incidents: {results['total_incidents']}")
print(f"  Unique TTPs: {results['unique_ttps']}")
print(f"  Kill Chain: {results['kill_chain_coverage']}")
print(f"\nTop TTPs:")
for ttp, count in results["most_common"]:
    desc = TTP_DESCRIPTIONS.get(ttp, "")
    print(f"  {ttp}: {count}x - {desc}")
```

---

## 8. Threat Intelligence Feeds

```python
#!/usr/bin/env python3
# feed_manager.py - จัดการ Threat Intelligence Feeds

import requests
from datetime import datetime
from typing import Generator

FEED_SOURCES = {
    "abuse_ch_feodotracker": {
        "name": "Feodo Tracker C2 IPs",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
        "type": "ip",
        "format": "txt",
        "frequency": "daily"
    },
    "abuse_ch_urlhaus": {
        "name": "URLhaus Malware URLs",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "type": "url",
        "format": "txt",
        "frequency": "realtime"
    },
    "abuse_ch_malwarebazaar": {
        "name": "MalwareBazaar Recent Samples",
        "url": "https://mb-api.abuse.ch/api/v1/",
        "type": "hash",
        "format": "json",
        "frequency": "realtime"
    },
    "cybercrime_tracker": {
        "name": "Cybercrime Tracker C2",
        "url": "http://cybercrime-tracker.net/all.php",
        "type": "ip",
        "format": "txt",
        "frequency": "daily"
    },
    "emerging_threats": {
        "name": "Emerging Threats IPs",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip",
        "format": "txt",
        "frequency": "daily"
    },
    "openphish": {
        "name": "OpenPhish Phishing URLs",
        "url": "https://openphish.com/feed.txt",
        "type": "url",
        "format": "txt",
        "frequency": "hourly"
    }
}

class FeedManager:
    """จัดการการดึงและประมวลผล Threat Intel Feeds"""
    
    def __init__(self):
        self.loaded_feeds = {}
        self.stats = {}
    
    def fetch_feed(self, feed_name: str) -> Generator:
        """ดึง Feed และ Parse"""
        if feed_name not in FEED_SOURCES:
            raise ValueError(f"Unknown feed: {feed_name}")
        
        feed = FEED_SOURCES[feed_name]
        print(f"[*] Fetching: {feed['name']}")
        
        try:
            resp = requests.get(feed["url"], timeout=30)
            resp.raise_for_status()
            
            if feed["format"] == "txt":
                yield from self._parse_txt(resp.text, feed["type"])
            elif feed["format"] == "json":
                yield from self._parse_json(resp.json(), feed_name)
                
        except Exception as e:
            print(f"[!] Error fetching {feed_name}: {e}")
    
    def _parse_txt(self, content: str, ioc_type: str) -> Generator:
        """Parse Text Format Feed"""
        for line in content.splitlines():
            line = line.strip()
            # ข้าม Comment Lines
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            yield {"type": ioc_type, "value": line, 
                  "timestamp": datetime.now().isoformat()}
    
    def _parse_json(self, data: dict, feed_name: str) -> Generator:
        """Parse JSON Format Feed"""
        if feed_name == "abuse_ch_malwarebazaar":
            for item in data.get("data", []):
                yield {
                    "type": "sha256",
                    "value": item.get("sha256_hash"),
                    "malware_family": item.get("tags", []),
                    "timestamp": item.get("first_seen")
                }
    
    def load_all_feeds(self) -> Dict:
        """โหลด Feeds ทั้งหมด และรวมเป็น Feed เดียว"""
        all_iocs = {
            "ip": set(),
            "url": set(),
            "hash": set(),
            "domain": set()
        }
        
        for feed_name in FEED_SOURCES:
            count = 0
            for ioc in self.fetch_feed(feed_name):
                ioc_type = ioc["type"]
                value = ioc["value"]
                if value and ioc_type in all_iocs:
                    all_iocs[ioc_type].add(value)
                    count += 1
            
            self.stats[feed_name] = count
            print(f"  Loaded {count} IOCs from {feed_name}")
        
        return all_iocs
    
    def to_splunk_lookup(self, iocs: Dict) -> str:
        """Export เป็น Splunk Lookup Table (CSV)"""
        lines = ["ioc_type,ioc_value,source"]
        
        for ioc_type, values in iocs.items():
            for value in values:
                lines.append(f"{ioc_type},{value},threat_intel_feed")
        
        return "\n".join(lines)
    
    def to_firewall_rules(self, ip_list: set) -> str:
        """Export เป็น Firewall Block Rules"""
        rules = []
        for ip in sorted(ip_list):
            rules.append(f"deny ip {ip} any")
        return "\n".join(rules)
    
    def integrate_with_siem(self, siem_type: str, iocs: Dict):
        """ส่ง IOCs ไปยัง SIEM"""
        if siem_type == "splunk":
            csv_content = self.to_splunk_lookup(iocs)
            # Upload ไปยัง Splunk KV Store
            print(f"[*] Uploading {sum(len(v) for v in iocs.values())} IOCs to Splunk")
            # requests.post(splunk_url, data=csv_content)
        elif siem_type == "elastic":
            # Import ไปยัง Elasticsearch
            print(f"[*] Uploading IOCs to Elasticsearch")

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    manager = FeedManager()
    
    # ดึง Feed เดียว
    print("=== Sample from Abuse.ch Feodo Tracker ===")
    count = 0
    for ioc in manager.fetch_feed("abuse_ch_feodotracker"):
        print(f"  {ioc['type']}: {ioc['value']}")
        count += 1
        if count >= 5:
            break
    
    print("\n=== Feed Statistics ===")
    for name, data in FEED_SOURCES.items():
        print(f"  {data['name']}: {data['frequency']} updates")
```

---

## 9. Automated Intelligence Processing

```python
#!/usr/bin/env python3
# intel_pipeline.py - Pipeline ประมวลผล Threat Intelligence อัตโนมัติ

import schedule
import time
import json
from datetime import datetime
from pathlib import Path

class IntelligencePipeline:
    """Pipeline ประมวลผล Threat Intelligence แบบ Automated"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.feed_manager = FeedManager()
        self.aggregator = ThreatIntelAggregator(config.get("api_keys", {}))
        self.output_dir = Path(config.get("output_dir", "/opt/threat-intel"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def run_collection_cycle(self):
        """รันวงจรการเก็บข้อมูล"""
        print(f"[{datetime.now().isoformat()}] Starting collection cycle")
        
        # 1. ดึง Feeds
        print("[1] Fetching threat intel feeds...")
        raw_iocs = self.feed_manager.load_all_feeds()
        
        # 2. Enrich IOCs สำคัญ (IP เท่านั้น เพราะ Rate Limit)
        print("[2] Enriching high-priority IOCs...")
        enriched = []
        for ip in list(raw_iocs.get("ip", set()))[:50]:  # Top 50
            result = self.aggregator.enrich_ip(ip)
            if result.get("risk_score", 0) > 70:
                enriched.append(result)
        
        # 3. บันทึกผล
        print("[3] Saving results...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        output_file = self.output_dir / f"iocs_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump({
                "timestamp": timestamp,
                "raw_counts": {k: len(v) for k, v in raw_iocs.items()},
                "high_risk_ips": enriched
            }, f, indent=2, default=str)
        
        print(f"[+] Saved to {output_file}")
        
        # 4. Export ไปยัง SIEM
        print("[4] Exporting to SIEM...")
        csv_export = self.feed_manager.to_splunk_lookup(raw_iocs)
        
        splunk_lookup = self.output_dir / "threat_intel_lookup.csv"
        with open(splunk_lookup, 'w') as f:
            f.write(csv_export)
        
        print(f"[+] Collection cycle complete")
        print(f"    IPs: {len(raw_iocs.get('ip', []))}")
        print(f"    URLs: {len(raw_iocs.get('url', []))}")
        print(f"    Hashes: {len(raw_iocs.get('hash', []))}")
        print(f"    High Risk IPs: {len(enriched)}")
    
    def start_scheduled(self):
        """รัน Pipeline แบบ Scheduled"""
        # รันทุก 6 ชั่วโมง
        schedule.every(6).hours.do(self.run_collection_cycle)
        
        print("[*] Starting scheduled intelligence pipeline")
        print("    Running every 6 hours")
        
        # รันครั้งแรกทันที
        self.run_collection_cycle()
        
        while True:
            schedule.run_pending()
            time.sleep(60)

# Configuration
config = {
    "api_keys": {
        "virustotal": "YOUR_VT_KEY",
        "abuseipdb": "YOUR_ABUSEIPDB_KEY"
    },
    "output_dir": "/opt/threat-intel/data"
}

# pipeline = IntelligencePipeline(config)
# pipeline.start_scheduled()
```

---

## 10. Intelligence-Driven Defense

```python
#!/usr/bin/env python3
# intel_driven_defense.py - ใช้ Intelligence ในการป้องกัน

# ตัวอย่างการ Block IPs ใน Firewall อัตโนมัติ

class IntelDrivenDefense:
    """ใช้ Threat Intelligence ขับเคลื่อนการป้องกัน"""
    
    SIEM_QUERY_TEMPLATES = {
        "ip_blocklist": """
| inputlookup threat_intel_lookup.csv WHERE ioc_type="ip"
| rename ioc_value as src_ip
| join src_ip [search index=firewall action=allowed]
| stats count by src_ip, dest_ip, dest_port
| sort -count""",
        
        "domain_check": """
index=dns
| lookup threat_intel_lookup.csv ioc_type AS "domain" ioc_value AS query OUTPUTNEW source AS intel_source
| where isnotnull(intel_source)
| stats count by query, src_ip, intel_source
| sort -count""",
        
        "hash_check": """
index=endpoint
| lookup threat_intel_lookup.csv ioc_type AS "hash" ioc_value AS md5 OUTPUTNEW source AS intel_source
| where isnotnull(intel_source)
| stats count by md5, Computer, User"""
    }
    
    def generate_firewall_block_script(self, ip_list: List[str],
                                       fw_type: str = "iptables") -> str:
        """สร้าง Script Block Malicious IPs"""
        if fw_type == "iptables":
            lines = ["#!/bin/bash", "# Auto-generated IP Blocklist",
                     f"# Generated: {datetime.now().isoformat()}", ""]
            for ip in ip_list:
                lines.append(f"iptables -I INPUT -s {ip} -j DROP")
                lines.append(f"iptables -I OUTPUT -d {ip} -j DROP")
            return "\n".join(lines)
        
        elif fw_type == "pf":  # macOS/BSD
            lines = [f"# Generated: {datetime.now().isoformat()}"]
            lines.append("table <malicious_ips> persist {")
            for ip in ip_list:
                lines.append(f"    {ip}")
            lines.append("}")
            lines.append("block quick from <malicious_ips>")
            lines.append("block quick to <malicious_ips>")
            return "\n".join(lines)
        
        elif fw_type == "windows":  # Windows Firewall
            lines = ["# PowerShell - Block Malicious IPs"]
            for ip in ip_list[:10]:  # Windows จำกัดจำนวน
                lines.append(
                    f'New-NetFirewallRule -DisplayName "Block-{ip}" '
                    f'-Direction Inbound -RemoteAddress {ip} -Action Block'
                )
            return "\n".join(lines)
    
    def generate_dns_rpz(self, domain_list: List[str]) -> str:
        """สร้าง DNS Response Policy Zone สำหรับ Block Domains"""
        lines = [
            f"; RPZ zone for malicious domains",
            f"; Generated: {datetime.now().isoformat()}",
            "$TTL 300",
            f"@ SOA rpz.example.com. admin.example.com. (",
            f"  {int(datetime.now().timestamp())} ; Serial",
            "  3600 ; Refresh",
            "  900  ; Retry",
            "  604800 ; Expire",
            "  300 )  ; Minimum TTL",
            "  NS  ns.rpz.example.com.",
            ""
        ]
        
        for domain in domain_list:
            lines.append(f"{domain} CNAME .  ; Blocked - Threat Intel")
        
        return "\n".join(lines)
    
    def create_yara_rule(self, malware_samples: List[Dict]) -> str:
        """สร้าง YARA Rule จาก Malware Intelligence"""
        rules = []
        
        for sample in malware_samples:
            rule_name = f"Malware_{sample['family'].replace('-', '_')}"
            strings = []
            
            for i, string in enumerate(sample.get("strings", [])[:5]):
                strings.append(f'    $s{i} = "{string}"')
            
            rule = f"""rule {rule_name} {{
    meta:
        description = "Detects {sample['family']} malware"
        author = "Threat Intelligence Team"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        hash = "{sample.get('sha256', '')}"
    strings:
{chr(10).join(strings)}
    condition:
        any of them
}}"""
            rules.append(rule)
        
        return "\n\n".join(rules)

# ตัวอย่าง YARA Rule
malware_intel = [
    {
        "family": "Emotet",
        "sha256": "abc123...",
        "strings": ["/online_updates", "Mozilla/4.0", "Content-Type: application/octet-stream"]
    },
    {
        "family": "Cobalt-Strike",
        "sha256": "def456...",
        "strings": ["ReflectiveLoader", "beacon.dll", "checksum8"]
    }
]

defender = IntelDrivenDefense()
print(defender.generate_firewall_block_script(["185.220.101.42", "1.2.3.4"]))
print("\n")
print(defender.create_yara_rule(malware_intel))
```

---

## สรุป

| หัวข้อ | เนื้อหาสำคัญ |
|--------|-------------|
| Pyramid of Pain | Hash → IP → Domain → Artifacts → Tools → TTPs |
| IOC Types | IP, Domain, URL, Hash, Email, User-Agent |
| Intelligence Sources | VirusTotal, AbuseIPDB, OTX, Shodan, MISP |
| MISP | Event Management, IOC Sharing, STIX 2.1 Export |
| Threat Actor Profiling | TTPs, Malware, Campaign History |
| TTP Analysis | Kill Chain Coverage, Campaign Analysis |
| Feeds | Feodo Tracker, URLhaus, OpenPhish, ET Rules |
| Pipeline | Auto Collection → Enrichment → Export → Block |
| Defense | Firewall Rules, DNS RPZ, YARA Rules, SIEM Lookup |

---

← [Part 75: Purple Team](Part-75-Purple-Team.md) | [Part 77: SOC Operations](Part-77-SOC-Operations.md) →
