# Part 96: Threat Intelligence (การข่าวกรองภัยคุกคาม)

## สารบัญ
1. [พื้นฐาน Threat Intelligence](#1-พื้นฐาน-threat-intelligence)
2. [MISP Platform](#2-misp-platform)
3. [OpenCTI Platform](#3-opencti-platform)
4. [IOC Collection และ Analysis](#4-ioc-collection-และ-analysis)
5. [Threat Actor Profiling](#5-threat-actor-profiling)
6. [STIX2/TAXII Feeds](#6-stix2taxii-feeds)
7. [Dark Web Monitoring](#7-dark-web-monitoring)
8. [Threat Hunting ด้วย SIEM](#8-threat-hunting-ด้วย-siem)
9. [YARA Rules สำหรับ Threat Detection](#9-yara-rules-สำหรับ-threat-detection)
10. [Python Automation สำหรับ TI Workflows](#10-python-automation-สำหรับ-ti-workflows)
11. [TheHive Integration](#11-thehive-integration)
12. [Automated TI Report Generation](#12-automated-ti-report-generation)
13. [Threat Feed Aggregation](#13-threat-feed-aggregation)
14. [TI Tools เปรียบเทียบ](#14-ti-tools-เปรียบเทียบ)
15. [TI Program Maturity Model](#15-ti-program-maturity-model)

---

## 1. พื้นฐาน Threat Intelligence

Threat Intelligence (TI) คือข้อมูลที่ผ่านการวิเคราะห์เกี่ยวกับภัยคุกคามทางไซเบอร์ ที่ช่วยให้องค์กรตัดสินใจเพื่อป้องกันตนเอง

### ประเภทของ Threat Intelligence

| ประเภท | กลุ่มเป้าหมาย | ระยะเวลา | ตัวอย่าง |
|--------|--------------|----------|----------|
| **Strategic TI** | C-Suite, Board | ระยะยาว | รายงาน APT trends, geopolitical risks |
| **Tactical TI** | Security Managers | ระยะกลาง | TTPs ของ threat actors, attack patterns |
| **Operational TI** | SOC, IR Teams | ระยะสั้น | Active campaign details, infrastructure |
| **Technical TI** | Analysts, Engineers | Real-time | IOCs, YARA rules, Sigma rules |

### Intelligence Lifecycle

```
1. Direction    → กำหนด Intelligence Requirements (IRs)
2. Collection   → รวบรวมข้อมูลจาก OSINT, HUMINT, Technical feeds
3. Processing   → แปลงข้อมูลดิบเป็น structured data
4. Analysis     → วิเคราะห์ pattern, attribution, impact
5. Dissemination → แจกจ่ายให้ stakeholders ที่เกี่ยวข้อง
6. Feedback     → ประเมินผลและปรับปรุง
```

### Diamond Model of Intrusion Analysis

```
         Adversary
            /\
           /  \
          /    \
    Infra  ----  Capability
          \    /
           \  /
            \/
           Victim
```

แต่ละ node มีความสัมพันธ์:
- **Adversary** ↔ **Infrastructure**: ผู้โจมตีใช้ infrastructure อะไร
- **Infrastructure** ↔ **Capability**: infrastructure รองรับ capability อะไร
- **Capability** ↔ **Victim**: capability โจมตี victim ได้อย่างไร

### Cyber Kill Chain (Lockheed Martin)

```
1. Reconnaissance   → OSINT, scanning, enumeration
2. Weaponization    → สร้าง malware, exploit kit
3. Delivery         → Phishing, drive-by download, USB
4. Exploitation     → CVE exploitation, social engineering
5. Installation     → Install backdoor, persistence
6. Command&Control  → C2 communication
7. Actions on Obj   → Data exfil, ransomware, lateral movement
```

---

## 2. MISP Platform

MISP (Malware Information Sharing Platform) เป็น open-source threat intelligence platform ที่ใช้สำหรับ sharing และวิเคราะห์ IOCs

### การติดตั้ง MISP ด้วย Docker

```bash
# Clone MISP Docker
git clone https://github.com/misp/misp-docker
cd misp-docker

# Copy และแก้ไข environment
cp template.env .env
nano .env

# รัน MISP
docker-compose up -d

# ตรวจสอบ status
docker-compose ps
```

### การสร้าง Events ด้วย PyMISP

```python
import pymisp
from pymisp import MISPEvent, MISPAttribute, MISPObject
from datetime import datetime

class MISPManager:
    def __init__(self, url, key, verify_ssl=False):
        self.misp = pymisp.PyMISP(url, key, verify_ssl)
    
    def create_event(self, title, threat_level=1, distribution=1, analysis=0):
        """สร้าง MISP Event ใหม่"""
        event = MISPEvent()
        event.info = title
        event.threat_level_id = threat_level  # 1=High, 2=Medium, 3=Low
        event.distribution = distribution      # 0=Org only, 1=Community
        event.analysis = analysis              # 0=Initial, 1=Ongoing, 2=Complete
        event.add_tag('tlp:amber')
        return self.misp.add_event(event)
    
    def add_network_ioc(self, event_id, ioc_type, value, comment='', to_ids=True):
        """เพิ่ม network IOC เข้า event"""
        event = self.misp.get_event(event_id, pythonify=True)
        attr = MISPAttribute()
        attr.type = ioc_type  # 'ip-dst', 'domain', 'url', 'email-src'
        attr.value = value
        attr.comment = comment
        attr.to_ids = to_ids
        event.add_attribute(attr)
        self.misp.update_event(event)
    
    def add_file_ioc(self, event_id, filename, md5=None, sha1=None, sha256=None):
        """เพิ่ม file hash IOC"""
        event = self.misp.get_event(event_id, pythonify=True)
        obj = MISPObject('file')
        obj.add_attribute('filename', value=filename)
        if md5:
            obj.add_attribute('md5', value=md5, to_ids=True)
        if sha1:
            obj.add_attribute('sha1', value=sha1, to_ids=True)
        if sha256:
            obj.add_attribute('sha256', value=sha256, to_ids=True)
        event.add_object(obj)
        self.misp.update_event(event)
    
    def search_events(self, value=None, type_attribute=None, tags=None):
        """ค้นหา events"""
        return self.misp.search(
            controller='attributes',
            value=value,
            type_attribute=type_attribute,
            tags=tags,
            pythonify=True
        )
    
    def export_to_stix(self, event_id):
        """Export event เป็น STIX 2.1"""
        return self.misp.get_stix_package(event_id, version='2.1')

# ตัวอย่างการใช้งาน
misp_mgr = MISPManager('https://misp.company.local', 'YOUR_API_KEY')

# สร้าง event สำหรับ APT campaign
event = misp_mgr.create_event('APT29 - SolarWinds Campaign', threat_level=1)
event_id = event['Event']['id']

# เพิ่ม IOCs
misp_mgr.add_network_ioc(event_id, 'ip-dst', '185.220.101.1', 'C2 Server')
misp_mgr.add_network_ioc(event_id, 'domain', 'update.microsoftonline[.]pw', 'C2 Domain')
misp_mgr.add_file_ioc(event_id, 'SolarWinds.Orion.Core.BusinessLayer.dll',
    sha256='ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6')
```

### MISP Taxonomies และ Galaxies

```python
from pymisp import PyMISP

misp = PyMISP('https://misp.local', 'API_KEY', False)

# ดึง taxonomies ทั้งหมด
taxonomies = misp.taxonomies()
for tax in taxonomies:
    print(f"Taxonomy: {tax['Taxonomy']['namespace']}")

# เพิ่ม galaxy cluster (APT group) ให้กับ event
misp_event = misp.get_event(1, pythonify=True)
misp_event.add_tag('misp-galaxy:threat-actor="APT29"')
misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Spearphishing Link - T1566.002"')
misp.update_event(misp_event)

# ค้นหา events ที่มี tag เฉพาะ
results = misp.search(
    controller='events',
    tags=['misp-galaxy:threat-actor="APT29"'],
    pythonify=True
)
print(f"Events related to APT29: {len(results)}")
```

---

## 3. OpenCTI Platform

OpenCTI เป็น threat intelligence platform ที่ใช้ STIX 2.1 natively และมี graph-based visualization

### การติดตั้ง OpenCTI ด้วย Docker

```yaml
# docker-compose.yml สำหรับ OpenCTI
version: '3'
services:
  redis:
    image: redis:7.0.12
    restart: always
    volumes:
      - redisdata:/data
  
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.9.0
    volumes:
      - esdata:/usr/share/elasticsearch/data
    environment:
      - discovery.type=single-node
      - xpack.ml.enabled=false
      - xpack.security.enabled=false
    restart: always
  
  minio:
    image: minio/minio:RELEASE.2023-05-18T00-05-36Z
    volumes:
      - s3data:/data
    ports:
      - "9000:9000"
    environment:
      MINIO_ROOT_USER: changeme
      MINIO_ROOT_PASSWORD: changeme
    command: server /data
    restart: always
  
  opencti:
    image: opencti/platform:5.10.1
    environment:
      - NODE_OPTIONS=--max-old-space-size=8096
      - APP__PORT=8080
      - APP__BASE_URL=http://localhost:8080
      - APP__ADMIN__EMAIL=admin@opencti.io
      - APP__ADMIN__PASSWORD=changeme
      - APP__ADMIN__TOKEN=changeme
      - REDIS__HOSTNAME=redis
      - ELASTICSEARCH__URL=http://elasticsearch:9200
      - MINIO__ENDPOINT=minio
      - MINIO__PORT=9000
      - MINIO__USE_SSL=false
      - MINIO__ACCESS_KEY=changeme
      - MINIO__SECRET_KEY=changeme
    ports:
      - "8080:8080"
    depends_on:
      - redis
      - elasticsearch
      - minio
    restart: always

volumes:
  redisdata:
  esdata:
  s3data:
```

```bash
# Deploy OpenCTI
docker-compose up -d

# ตรวจสอบ logs
docker-compose logs -f opencti
```

### OpenCTI Python Client

```python
from pycti import OpenCTIApiClient
from datetime import datetime

class OpenCTIManager:
    def __init__(self, url, token):
        self.client = OpenCTIApiClient(url, token)
    
    def create_threat_actor(self, name, description, actor_types, aliases):
        """สร้าง Threat Actor"""
        return self.client.threat_actor.create(
            name=name,
            description=description,
            threat_actor_types=actor_types,
            aliases=aliases,
            first_seen=datetime.utcnow().isoformat() + 'Z',
            last_seen=datetime.utcnow().isoformat() + 'Z',
            sophistication='expert',
            resource_level='government'
        )
    
    def create_malware(self, name, description, malware_types, aliases):
        """สร้าง Malware entity"""
        return self.client.malware.create(
            name=name,
            description=description,
            malware_types=malware_types,
            aliases=aliases,
            is_family=True
        )
    
    def create_indicator(self, name, pattern, indicator_types, valid_from):
        """สร้าง STIX Indicator"""
        return self.client.indicator.create(
            name=name,
            description=f'IOC: {name}',
            pattern=pattern,
            pattern_type='stix',
            x_opencti_score=75,
            indicator_types=indicator_types,
            valid_from=valid_from
        )
    
    def create_relationship(self, from_id, to_id, relationship_type):
        """สร้างความสัมพันธ์ระหว่าง entities"""
        return self.client.stix_core_relationship.create(
            fromId=from_id,
            toId=to_id,
            relationship_type=relationship_type
        )
    
    def import_stix_bundle(self, bundle_file):
        """Import STIX 2.1 bundle"""
        with open(bundle_file, 'r') as f:
            bundle = f.read()
        return self.client.stix2.import_bundle_from_json(bundle)
    
    def search_indicators(self, value):
        """ค้นหา indicators ตาม value"""
        return self.client.indicator.list(
            filters=[{'key': 'name', 'values': [value]}]
        )

# ตัวอย่าง
octi = OpenCTIManager('http://opencti.local:8080', 'YOUR_TOKEN')

# สร้าง APT28 entity
apt28 = octi.create_threat_actor(
    name='APT28',
    description='Russian GRU-linked threat actor',
    actor_types=['nation-state'],
    aliases=['Fancy Bear', 'Sofacy', 'STRONTIUM']
)

# สร้าง malware
xagent = octi.create_malware(
    name='X-Agent',
    description='APT28 primary implant for espionage',
    malware_types=['trojan', 'backdoor'],
    aliases=['Sofacy', 'JHUHUGIT']
)

# สร้างความสัมพันธ์ APT28 uses X-Agent
octi.create_relationship(apt28['id'], xagent['id'], 'uses')
```

---

## 4. IOC Collection และ Analysis

### Automated IOC Extraction

```python
import re
import hashlib
from typing import Dict, List
import requests

class IOCExtractor:
    # Regex patterns
    PATTERNS = {
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
        'md5': r'\b[0-9a-fA-F]{32}\b',
        'sha1': r'\b[0-9a-fA-F]{40}\b',
        'sha256': r'\b[0-9a-fA-F]{64}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'cve': r'CVE-\d{4}-\d{4,}',
        'registry': r'HK(?:EY_LOCAL_MACHINE|LM|EY_CURRENT_USER|CU)\\[^\s]+'
    }
    
    # IPs ที่ไม่ควรนับเป็น IOC
    WHITELIST_IPS = {'127.0.0.1', '0.0.0.0', '255.255.255.255', '8.8.8.8', '1.1.1.1'}
    WHITELIST_DOMAINS = {'microsoft.com', 'google.com', 'github.com', 'windows.com'}
    
    def extract_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs จาก text"""
        # Defang URLs (undo defanging)
        text = text.replace('[.]', '.').replace('hxxp', 'http').replace('[://]', '://')
        
        results = {}
        for ioc_type, pattern in self.PATTERNS.items():
            matches = list(set(re.findall(pattern, text)))
            # Filter whitelists
            if ioc_type == 'ipv4':
                matches = [m for m in matches if m not in self.WHITELIST_IPS]
            elif ioc_type == 'domain':
                matches = [m for m in matches if not any(w in m for w in self.WHITELIST_DOMAINS)]
            results[ioc_type] = matches
        return results
    
    def extract_from_pdf(self, pdf_path: str) -> Dict[str, List[str]]:
        """Extract IOCs จาก PDF threat report"""
        try:
            import pdfplumber
            text = ''
            with pdfplumber.open(pdf_path) as pdf:
                for page in pdf.pages:
                    text += page.extract_text() or ''
            return self.extract_from_text(text)
        except ImportError:
            print("pip install pdfplumber")
            return {}

class IOCEnricher:
    def __init__(self, vt_key, shodan_key=None):
        self.vt_key = vt_key
        self.shodan_key = shodan_key
    
    def virustotal_ip(self, ip: str) -> Dict:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {'x-apikey': self.vt_key}
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()['data']['attributes']
            stats = data['last_analysis_stats']
            return {
                'ip': ip,
                'malicious': stats['malicious'],
                'suspicious': stats['suspicious'],
                'harmless': stats['harmless'],
                'country': data.get('country', 'Unknown'),
                'asn': data.get('asn', 'Unknown'),
                'score': round(stats['malicious'] / max(sum(stats.values()), 1) * 100, 2)
            }
        return {'ip': ip, 'error': f'Status {resp.status_code}'}
    
    def virustotal_hash(self, file_hash: str) -> Dict:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': self.vt_key}
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()['data']['attributes']
            stats = data['last_analysis_stats']
            return {
                'hash': file_hash,
                'malicious': stats['malicious'],
                'total_engines': sum(stats.values()),
                'type_description': data.get('type_description', 'Unknown'),
                'magic': data.get('magic', 'Unknown'),
                'score': round(stats['malicious'] / max(sum(stats.values()), 1) * 100, 2)
            }
        return {'hash': file_hash, 'error': f'Status {resp.status_code}'}
    
    def shodan_ip(self, ip: str) -> Dict:
        if not self.shodan_key:
            return {}
        url = f'https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}'
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                'ip': ip,
                'org': data.get('org', 'Unknown'),
                'country': data.get('country_name', 'Unknown'),
                'ports': data.get('ports', []),
                'vulns': list(data.get('vulns', {}).keys()),
                'hostnames': data.get('hostnames', [])
            }
        return {}
```

---

## 5. Threat Actor Profiling

### APT Database

```python
from typing import Dict, List, Optional
import json

class ThreatActorDatabase:
    APT_PROFILES = {
        'APT28': {
            'aliases': ['Fancy Bear', 'Sofacy', 'STRONTIUM', 'Pawn Storm'],
            'origin': 'Russia',
            'sponsor': 'GRU (Military Intelligence)',
            'motivation': ['espionage', 'disinformation'],
            'sectors': ['Government', 'Military', 'Defense', 'Media', 'Political'],
            'regions': ['Europe', 'North America', 'Middle East'],
            'ttps': ['T1566.001', 'T1078', 'T1055', 'T1036', 'T1003.001'],
            'tools': ['X-Agent', 'Zebrocy', 'Responder', 'Mimikatz', 'Cobalt Strike'],
            'known_campaigns': ['Olympic Destroyer', 'DNC Hack 2016', 'NotPetya'],
            'first_seen': '2004',
            'active': True,
            'sophistication': 'nation-state'
        },
        'APT29': {
            'aliases': ['Cozy Bear', 'The Dukes', 'NOBELIUM', 'Midnight Blizzard'],
            'origin': 'Russia',
            'sponsor': 'SVR (Foreign Intelligence)',
            'motivation': ['espionage'],
            'sectors': ['Government', 'Healthcare', 'Technology', 'Think Tanks'],
            'regions': ['Global'],
            'ttps': ['T1195.002', 'T1566', 'T1486', 'T1003', 'T1071.001'],
            'tools': ['Cobalt Strike', 'SUNBURST', 'WellMess', 'MagicWeb', 'FOGGYWEB'],
            'known_campaigns': ['SolarWinds 2020', 'DNC Hack 2015', 'HAMMERTOSS'],
            'first_seen': '2008',
            'active': True,
            'sophistication': 'nation-state'
        },
        'Lazarus': {
            'aliases': ['Hidden Cobra', 'ZINC', 'Guardians of Peace', 'APT38'],
            'origin': 'North Korea',
            'sponsor': 'RGB (Reconnaissance General Bureau)',
            'motivation': ['financial', 'espionage', 'destruction'],
            'sectors': ['Financial', 'Cryptocurrency', 'Defense', 'Government'],
            'regions': ['Global'],
            'ttps': ['T1059', 'T1071', 'T1486', 'T1070', 'T1566'],
            'tools': ['BLINDINGCAN', 'COPPERHEDGE', 'TAINTEDSCRIBE', 'AppleJeus'],
            'known_campaigns': ['WannaCry 2017', 'Bangladesh Bank Heist', 'Sony Pictures Hack'],
            'first_seen': '2009',
            'active': True,
            'sophistication': 'nation-state'
        },
        'APT41': {
            'aliases': ['Double Dragon', 'Winnti', 'Bronze Atlas', 'BARIUM'],
            'origin': 'China',
            'sponsor': 'MSS (Ministry of State Security)',
            'motivation': ['espionage', 'financial'],
            'sectors': ['Healthcare', 'Technology', 'Gaming', 'Telecommunications'],
            'regions': ['Global'],
            'ttps': ['T1195', 'T1078', 'T1055', 'T1190', 'T1571'],
            'tools': ['Cobalt Strike', 'Winnti', 'SPECULOOS', 'Crosswalk'],
            'known_campaigns': ['ShadowHammer', 'ASUS Supply Chain', 'CCleaner Attack'],
            'first_seen': '2012',
            'active': True,
            'sophistication': 'nation-state'
        }
    }
    
    def get_actor(self, name: str) -> Optional[Dict]:
        return self.APT_PROFILES.get(name)
    
    def search_by_ttp(self, ttp_id: str) -> List[str]:
        return [actor for actor, data in self.APT_PROFILES.items()
                if ttp_id in data.get('ttps', [])]
    
    def search_by_sector(self, sector: str) -> List[Dict]:
        return [{'actor': actor, **data} for actor, data in self.APT_PROFILES.items()
                if sector.lower() in [s.lower() for s in data.get('sectors', [])]]
    
    def search_by_tool(self, tool: str) -> List[str]:
        return [actor for actor, data in self.APT_PROFILES.items()
                if any(tool.lower() in t.lower() for t in data.get('tools', []))]
    
    def get_all_active(self) -> List[str]:
        return [actor for actor, data in self.APT_PROFILES.items() if data.get('active')]
    
    def generate_profile_report(self, actor_name: str) -> str:
        actor = self.get_actor(actor_name)
        if not actor:
            return f'Actor {actor_name} not found'
        return f"""
## Threat Actor Profile: {actor_name}
**Aliases**: {', '.join(actor['aliases'])}
**Origin**: {actor['origin']}
**Sponsor**: {actor['sponsor']}
**Motivation**: {', '.join(actor['motivation'])}
**Target Sectors**: {', '.join(actor['sectors'])}
**Known TTPs**: {', '.join(actor['ttps'])}
**Primary Tools**: {', '.join(actor['tools'])}
**Sophistication**: {actor['sophistication']}
**First Seen**: {actor['first_seen']}
**Status**: {'Active' if actor['active'] else 'Inactive'}
"""

# ตัวอย่าง
db = ThreatActorDatabase()
print(db.search_by_ttp('T1566'))   # หา actors ที่ใช้ phishing
print(db.search_by_sector('Financial'))  # หา actors ที่โจมตี Finance
print(db.generate_profile_report('APT29'))
```

---

## 6. STIX2/TAXII Feeds

### การสร้าง STIX 2.1 Bundle

```python
import stix2
from datetime import datetime, timezone
import json

class STIXBundleCreator:
    def create_campaign(self, name, description, first_seen, last_seen):
        return stix2.Campaign(
            name=name,
            description=description,
            first_seen=first_seen,
            last_seen=last_seen,
            objective='Espionage'
        )
    
    def create_threat_actor(self, name, aliases, motivation, sophistication):
        return stix2.ThreatActor(
            name=name,
            aliases=aliases,
            primary_motivation=motivation,
            sophistication=sophistication,
            resource_level='government'
        )
    
    def create_malware(self, name, malware_types, description):
        return stix2.Malware(
            name=name,
            malware_types=malware_types,
            description=description,
            is_family=True
        )
    
    def create_attack_pattern(self, name, mitre_id):
        return stix2.AttackPattern(
            name=name,
            external_references=[stix2.ExternalReference(
                source_name='mitre-attack',
                external_id=mitre_id,
                url=f'https://attack.mitre.org/techniques/{mitre_id}'
            )]
        )
    
    def create_indicator(self, name, pattern, ioc_type):
        return stix2.Indicator(
            name=name,
            description=f'Malicious {ioc_type}',
            pattern=pattern,
            pattern_type='stix',
            valid_from=datetime.now(timezone.utc),
            indicator_types=['malicious-activity']
        )
    
    def create_relationship(self, source, target, rel_type):
        return stix2.Relationship(
            relationship_type=rel_type,
            source_ref=source.id,
            target_ref=target.id
        )
    
    def build_apt_bundle(self, actor_data, iocs):
        """สร้าง STIX bundle จาก APT campaign data"""
        objects = []
        
        # สร้าง threat actor
        actor = self.create_threat_actor(
            actor_data['name'],
            actor_data['aliases'],
            'national-security',
            'expert'
        )
        objects.append(actor)
        
        # สร้าง malware
        for tool_name in actor_data.get('tools', []):
            malware = self.create_malware(tool_name, ['backdoor'], f'{tool_name} malware')
            objects.append(malware)
            rel = self.create_relationship(actor, malware, 'uses')
            objects.append(rel)
        
        # สร้าง indicators จาก IOCs
        for ip in iocs.get('ips', []):
            indicator = self.create_indicator(
                f'Malicious IP: {ip}',
                f"[ipv4-addr:value = '{ip}']",
                'IPv4'
            )
            objects.append(indicator)
        
        for domain in iocs.get('domains', []):
            indicator = self.create_indicator(
                f'Malicious Domain: {domain}',
                f"[domain-name:value = '{domain}']",
                'Domain'
            )
            objects.append(indicator)
        
        return stix2.Bundle(objects=objects, allow_custom=True)

# ตัวอย่าง
creator = STIXBundleCreator()

apt29_data = {
    'name': 'APT29',
    'aliases': ['Cozy Bear', 'NOBELIUM'],
    'tools': ['SUNBURST', 'Cobalt Strike']
}

iocs = {
    'ips': ['185.220.101.47', '194.165.16.11'],
    'domains': ['update.microsoftstore[.]in', 'solarwinds.com.gov[.]co']
}

bundle = creator.build_apt_bundle(apt29_data, iocs)

# บันทึกเป็นไฟล์
with open('apt29_stix_bundle.json', 'w') as f:
    f.write(bundle.serialize(pretty=True))

print(f"Bundle created with {len(bundle.objects)} objects")
```

### TAXII Client

```python
from taxii2client.v21 import Server, Collection
import requests

class TAXIIClient:
    def __init__(self, server_url, username, password):
        self.server = Server(server_url, user=username, password=password)
    
    def list_collections(self):
        """แสดง collections ทั้งหมด"""
        collections = []
        for api_root in self.server.api_roots:
            for collection in api_root.collections:
                collections.append({
                    'id': collection.id,
                    'title': collection.title,
                    'description': collection.description,
                    'can_read': collection.can_read,
                    'can_write': collection.can_write
                })
        return collections
    
    def get_objects(self, collection_id, added_after=None):
        """ดึง STIX objects จาก collection"""
        for api_root in self.server.api_roots:
            for collection in api_root.collections:
                if collection.id == collection_id:
                    kwargs = {}
                    if added_after:
                        kwargs['added_after'] = added_after
                    return collection.get_objects(**kwargs)
        return None
    
    def publish_bundle(self, collection_id, bundle):
        """Publish STIX bundle ไปยัง TAXII server"""
        for api_root in self.server.api_roots:
            for collection in api_root.collections:
                if collection.id == collection_id and collection.can_write:
                    return collection.push_object(bundle)
        return None

# ตัวอย่างการใช้ TAXII public feeds
client = TAXIIClient(
    'https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'guest', 'guest'
)
```

---

## 7. Dark Web Monitoring

```python
import requests
import hashlib
from typing import List, Dict

class BreachMonitor:
    """
    ตรวจสอบข้อมูลรั่วไหลด้วย HIBP (Have I Been Pwned) API
    """
    
    def check_email_breach(self, email: str, api_key: str) -> Dict:
        """ตรวจสอบว่า email เคย breach ไหม"""
        url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
        headers = {'hibp-api-key': api_key, 'user-agent': 'TI-Monitor'}
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            return {'email': email, 'breaches': resp.json()}
        elif resp.status_code == 404:
            return {'email': email, 'breaches': []}
        return {'email': email, 'error': f'Status {resp.status_code}'}
    
    def check_password_pwned(self, password: str) -> Dict:
        """ตรวจสอบ password ด้วย k-anonymity"""
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        resp = requests.get(url)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return {'password': '***', 'pwned': True, 'count': int(count)}
        return {'password': '***', 'pwned': False, 'count': 0}
    
    def check_domain_breaches(self, domain: str, api_key: str) -> List[Dict]:
        """ตรวจสอบ breaches ที่เกี่ยวกับ domain"""
        url = f'https://haveibeenpwned.com/api/v3/breach/{domain}'
        headers = {'hibp-api-key': api_key}
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            return resp.json()
        return []


class PastebinMonitor:
    """Monitor Pastebin สำหรับข้อมูลที่รั่วไหล"""
    
    KEYWORDS = ['password', 'apikey', 'secret', 'credential', 'token', 'private_key']
    
    def check_recent_pastes(self, keywords: List[str] = None) -> List[Dict]:
        """ดึง recent pastes (ต้องการ Scraping API key)"""
        if keywords is None:
            keywords = self.KEYWORDS
        
        try:
            url = 'https://scrape.pastebin.com/api_scraping.php?limit=100'
            resp = requests.get(url, timeout=10)
            pastes = resp.json()
            
            results = []
            for paste in pastes:
                title = paste.get('title', '').lower()
                if any(kw in title for kw in keywords):
                    results.append({
                        'key': paste.get('key'),
                        'title': paste.get('title'),
                        'date': paste.get('date'),
                        'url': f"https://pastebin.com/{paste.get('key')}"
                    })
            return results
        except Exception as e:
            return [{'error': str(e)}]
```

---

## 8. Threat Hunting ด้วย SIEM

### Splunk SPL Queries

```spl
# ตรวจจับ Cobalt Strike Named Pipes
index=windows_events (EventCode=17 OR EventCode=18)
| search PipeName IN ("\\\\msagent_*", "\\\\status_*", "\\\\mojo*", "\\\\wkssvc*", "\\\\ntsvcs*")
| stats count by Computer, PipeName, ProcessName, ProcessId
| sort -count

# ตรวจจับ DCSync Attack
index=windows_security EventCode=4662
| search AccessMask="0x100"
| where match(Properties, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") OR match(Properties, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
| where NOT match(SubjectUserName, ".*\\$")
| stats count by SubjectUserName, SubjectDomainName, ObjectDN
| where count > 0

# ตรวจจับ Kerberoasting
index=windows_security EventCode=4769
| search TicketEncryptionType="0x17" TicketOptions="0x40810000"
| stats count by TargetUserName, ServiceName, ClientAddress, Client_Port
| where count > 3
| sort -count

# ตรวจจับ Lateral Movement ด้วย PsExec
index=windows_events EventCode=7045
| search ServiceName="PSEXESVC" OR ServiceName="*psexec*"
| stats count by Computer, ServiceName, ImagePath, AccountName

# ตรวจจับ PowerShell Empire
index=windows_events EventCode=4104
| search ScriptBlockText="*System.Net.WebClient*" AND ScriptBlockText="*DownloadString*"
| rex field=ScriptBlockText "(?i)http[s]?://(?P<url>[^\\s\"]+)"
| stats count by Computer, UserName, url
| sort -count

# ตรวจจับ LSASS Dumping
index=windows_events EventCode=10
| search TargetImage="*lsass.exe"
| search GrantedAccess IN ("0x1010", "0x1410", "0x147a", "0x1fffff")
| stats count by SourceImage, TargetImage, GrantedAccess, Computer
```

### Elastic KQL Queries

```kql
# ตรวจจับ Mimikatz
process.command_line:(*sekurlsa* OR *lsadump* OR *kerberos::list* OR *kiwi*)

# ตรวจจับ Process Injection
event.code:8 AND target.process.name:"lsass.exe"

# ตรวจจับ Suspicious PowerShell
process.name:"powershell.exe" AND
process.command_line:(*-enc* OR *-encodedcommand* OR *bypass* OR *hidden*) AND
NOT process.parent.name:("msiexec.exe" OR "wmiprvse.exe")

# ตรวจจับ Persistence ด้วย Registry
registry.path:*\\Run* AND registry.value:(*powershell* OR *cmd.exe* OR *wscript*)

# ตรวจจับ Unusual Outbound Connections
destination.port:(4444 OR 4445 OR 8080 OR 8443 OR 1337) AND
NOT source.ip:10.0.0.0/8 AND NOT source.ip:192.168.0.0/16
```

### Sigma Rules

```yaml
# Sigma Rule: Cobalt Strike DNS Beacon
title: Cobalt Strike DNS Beacon Detection
id: 5a2b4a5c-3e1d-4b5c-a8f9-2d3e4f5a6b7c
status: stable
description: Detects DNS queries characteristic of Cobalt Strike DNS beacon
author: ThreatHunter Team
date: 2024/01/01
references:
    - https://attack.mitre.org/techniques/T1071/004/
logsource:
    category: dns
detection:
    selection:
        QueryType: A
    filter_length:
        QueryName|re: '^[a-zA-Z0-9]{20,50}\.'
    filter_freq:
        QueryName|contains:
            - 'windows.com'
            - 'microsoft.com'
    condition: selection and filter_length and not filter_freq
falsepositives:
    - CDN domains with random subdomains
    - Some cloud services
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.004

---
# Sigma Rule: SUNBURST C2 Traffic
title: SUNBURST SolarWinds C2 Communication
id: 7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e
status: stable
description: Detects network traffic associated with SUNBURST backdoor
author: ThreatHunter Team  
logsource:
    category: network_connection
    product: windows
detection:
    selection_process:
        Image|contains: 'SolarWinds'
    selection_domains:
        DestinationHostname|contains:
            - 'avsvmcloud.com'
            - 'databasegalore.com'
            - 'deftsecurity.com'
    condition: selection_process or selection_domains
level: critical
tags:
    - attack.command_and_control
    - attack.t1195.002
```

---

## 9. YARA Rules สำหรับ Threat Detection

```yara
rule APT29_SUNBURST {
    meta:
        description = "Detects SUNBURST backdoor used by APT29/NOBELIUM"
        author = "ThreatHunter"
        date = "2024-01-01"
        severity = "critical"
        reference = "https://www.mandiant.com/resources/sunburst-additional-technical-details"
        
    strings:
        $s1 = "SolarWinds.Orion.Core.BusinessLayer" ascii wide
        $s2 = "avsvmcloud.com" ascii
        $s3 = "OrionImprovementBusinessLayer" ascii wide
        $s4 = "UpdateNotification" ascii wide
        $pdb = "SolarWinds" ascii
        
        $b1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 1A }
        $b2 = { 55 8B EC 83 EC 10 56 57 E8 }
        
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x4D534646) and
        (2 of ($s*)) or
        (any of ($b*))
}

rule CobaltStrike_BeaconDLL {
    meta:
        description = "Detects Cobalt Strike Beacon DLL"
        severity = "high"
        
    strings:
        $header1 = { FC E8 89 00 00 00 60 89 E5 31 D2 }
        $header2 = { FC E8 8F 00 00 00 60 31 D2 89 E5 }
        $str1 = "ReflectiveLoader" ascii
        $str2 = "%d is an x64 process (can't inject x86 content)" ascii
        $str3 = "beacon" nocase ascii wide
        
    condition:
        (any of ($header*)) or
        ($str1 and $str3) or
        (2 of ($str*))
}

rule Mimikatz_Binary {
    meta:
        description = "Detects Mimikatz binary"
        severity = "critical"
        
    strings:
        $str1 = "sekurlsa::" nocase
        $str2 = "kerberos::" nocase
        $str3 = "lsadump::" nocase
        $str4 = "privilege::debug" nocase
        $str5 = "mimikatz" nocase
        $pdb = "mimikatz.pdb" nocase
        
    condition:
        (3 of ($str*)) or $pdb
}
```

```python
import yara
import os
import hashlib
from datetime import datetime

class YARAScanner:
    def __init__(self, rules_path):
        self.rules_path = rules_path
        self.rules = self._compile_rules()
    
    def _compile_rules(self):
        if os.path.isdir(self.rules_path):
            rule_files = {}
            for fn in os.listdir(self.rules_path):
                if fn.endswith(('.yar', '.yara')):
                    rule_files[fn] = os.path.join(self.rules_path, fn)
            return yara.compile(filepaths=rule_files)
        return yara.compile(self.rules_path)
    
    def scan_file(self, filepath):
        try:
            matches = self.rules.match(filepath)
            file_hash = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
            return {
                'file': filepath,
                'sha256': file_hash,
                'matches': [{
                    'rule': m.rule,
                    'tags': m.tags,
                    'meta': m.meta,
                    'strings': [(s.identifier, s.instances[0].offset) for s in m.strings]
                } for m in matches],
                'scanned_at': datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {'file': filepath, 'error': str(e)}
    
    def scan_directory(self, directory, extensions=None):
        if extensions is None:
            extensions = ['.exe', '.dll', '.ps1', '.bat', '.vbs', '.js']
        
        results = []
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if any(filename.lower().endswith(ext) for ext in extensions):
                    filepath = os.path.join(root, filename)
                    result = self.scan_file(filepath)
                    if result.get('matches'):
                        results.append(result)
        return results
    
    def generate_scan_report(self, results):
        report = f"# YARA Scan Report\n**Scanned**: {datetime.utcnow().isoformat()}\n\n"
        report += f"**Files with matches**: {len(results)}\n\n"
        
        for result in results:
            report += f"## {result['file']}\n"
            report += f"**SHA256**: `{result.get('sha256', 'N/A')}`\n"
            for match in result.get('matches', []):
                report += f"- **Rule**: {match['rule']}\n"
                if match.get('meta', {}).get('severity'):
                    report += f"  - Severity: {match['meta']['severity']}\n"
                if match.get('meta', {}).get('description'):
                    report += f"  - Description: {match['meta']['description']}\n"
        return report
```

---

## 10. Python Automation สำหรับ TI Workflows

```python
import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from typing import List, Dict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('TI-Platform')

class ThreatIntelligencePlatform:
    def __init__(self, config: Dict):
        self.vt_key = config['virustotal_key']
        self.otx_key = config['otx_key']
        self.ioc_cache = {}
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, *args):
        await self.session.close()
    
    async def fetch_otx_pulses(self, days=7) -> List[Dict]:
        """ดึง threat intelligence จาก AlienVault OTX"""
        since = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S')
        url = f'https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}'
        headers = {'X-OTX-API-KEY': self.otx_key}
        async with self.session.get(url, headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                logger.info(f"Fetched {len(data.get('results', []))} OTX pulses")
                return data.get('results', [])
        return []
    
    async def check_vt_hash(self, file_hash: str) -> Dict:
        """ตรวจสอบ file hash กับ VirusTotal"""
        if file_hash in self.ioc_cache:
            return self.ioc_cache[file_hash]
        
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': self.vt_key}
        async with self.session.get(url, headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                stats = data['data']['attributes']['last_analysis_stats']
                result = {
                    'hash': file_hash,
                    'malicious': stats['malicious'],
                    'total': sum(stats.values()),
                    'first_seen': data['data']['attributes'].get('first_submission_date'),
                    'family': data['data']['attributes'].get('popular_threat_classification', {}).get('suggested_threat_label', 'Unknown')
                }
                self.ioc_cache[file_hash] = result
                return result
            elif resp.status == 404:
                return {'hash': file_hash, 'malicious': 0, 'total': 0, 'error': 'Not found'}
        return {'hash': file_hash, 'error': 'Request failed'}
    
    async def enrich_iocs_batch(self, hashes: List[str]) -> List[Dict]:
        """Enrich หลาย IOCs พร้อมกัน"""
        tasks = [self.check_vt_hash(h) for h in hashes]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]
    
    def extract_iocs_from_pulses(self, pulses: List[Dict]) -> Dict[str, List]:
        """Extract IOCs จาก OTX pulses"""
        iocs = {'ips': [], 'domains': [], 'hashes': [], 'urls': []}
        type_map = {
            'IPv4': 'ips', 'domain': 'domains',
            'FileHash-MD5': 'hashes', 'FileHash-SHA1': 'hashes',
            'FileHash-SHA256': 'hashes', 'URL': 'urls'
        }
        for pulse in pulses:
            for indicator in pulse.get('indicators', []):
                itype = type_map.get(indicator.get('type', ''))
                if itype:
                    iocs[itype].append(indicator.get('indicator', ''))
        
        # Deduplicate
        return {k: list(set(v)) for k, v in iocs.items()}
    
    async def run_daily_collection(self) -> Dict:
        """รัน daily TI collection workflow"""
        logger.info('Starting daily TI collection...')
        
        # 1. ดึง feeds
        pulses = await self.fetch_otx_pulses(days=1)
        iocs = self.extract_iocs_from_pulses(pulses)
        logger.info(f'Extracted IOCs: {sum(len(v) for v in iocs.values())} total')
        
        # 2. Enrich file hashes
        enriched_hashes = []
        if iocs['hashes']:
            enriched_hashes = await self.enrich_iocs_batch(iocs['hashes'][:50])  # Limit API calls
        
        # 3. ระบุ high-risk IOCs
        high_risk = [h for h in enriched_hashes if h.get('malicious', 0) > 5]
        logger.info(f'High-risk hashes: {len(high_risk)}')
        
        return {
            'date': datetime.utcnow().isoformat(),
            'total_iocs': {k: len(v) for k, v in iocs.items()},
            'high_risk_count': len(high_risk),
            'high_risk_hashes': high_risk[:10],
            'iocs': iocs
        }

# ตัวอย่างการใช้งาน
async def main():
    config = {
        'virustotal_key': 'YOUR_VT_KEY',
        'otx_key': 'YOUR_OTX_KEY'
    }
    async with ThreatIntelligencePlatform(config) as platform:
        results = await platform.run_daily_collection()
        print(json.dumps(results, indent=2))

# asyncio.run(main())
```

---

## 11. TheHive Integration

```python
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, Case, CaseTask
from datetime import datetime
from typing import List, Dict

class TheHiveIntegration:
    def __init__(self, url: str, api_key: str):
        self.api = TheHiveApi(url, api_key)
    
    def create_ti_alert(self, title: str, description: str, iocs: Dict,
                         severity: int = 2, tlp: int = 2) -> Dict:
        """สร้าง Alert จาก Threat Intelligence IOCs"""
        artifacts = []
        
        for ip in iocs.get('ips', []):
            artifacts.append(AlertArtifact(
                dataType='ip', data=ip,
                message='Malicious IP from TI feed', tags=['network', 'c2']
            ))
        
        for domain in iocs.get('domains', []):
            artifacts.append(AlertArtifact(
                dataType='domain', data=domain,
                message='Malicious domain from TI feed', tags=['network']
            ))
        
        for hash_val in iocs.get('hashes', []):
            artifacts.append(AlertArtifact(
                dataType='hash', data=hash_val,
                message='Malicious hash from TI feed', tags=['malware']
            ))
        
        alert = Alert(
            title=title,
            description=description,
            type='external',
            source='TI-Platform',
            sourceRef=f'TI-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}',
            severity=severity,
            tlp=tlp,
            artifacts=artifacts,
            tags=['threat-intelligence', 'automated']
        )
        
        resp = self.api.create_alert(alert)
        if resp.ok:
            return resp.json()
        return {'error': resp.text}
    
    def escalate_to_case(self, alert_id: str, tasks: List[Dict]) -> Dict:
        """Escalate Alert เป็น Case"""
        resp = self.api.promote_alert_to_case(alert_id)
        if resp.ok:
            case = resp.json()
            case_id = case['id']
            
            # เพิ่ม tasks
            for task_data in tasks:
                task = CaseTask(
                    title=task_data['title'],
                    description=task_data.get('description', ''),
                    owner=task_data.get('owner', 'analyst')
                )
                self.api.create_case_task(case_id, task)
            
            return case
        return {'error': resp.text}
    
    def standard_ir_tasks(self) -> List[Dict]:
        """Template tasks สำหรับ IR"""
        return [
            {'title': 'Initial Triage', 'description': 'ตรวจสอบ IOCs และประเมิน severity'},
            {'title': 'Network Blocking', 'description': 'Block IPs/domains ที่เป็นอันตรายบน firewall'},
            {'title': 'Endpoint Investigation', 'description': 'ตรวจสอบ endpoints ที่ติดต่อกับ IOCs'},
            {'title': 'Log Analysis', 'description': 'วิเคราะห์ logs ใน SIEM'},
            {'title': 'Containment', 'description': 'Isolate systems ที่ถูก compromise'},
            {'title': 'Eradication', 'description': 'ลบ malware และ backdoors'},
            {'title': 'Recovery', 'description': 'Restore systems และยืนยัน clean'},
            {'title': 'Post-Incident Report', 'description': 'เขียนรายงาน lessons learned'}
        ]
```

---

## 12. Automated TI Report Generation

```python
from jinja2 import Template
from datetime import datetime
from typing import Dict, List

class TIReportGenerator:
    EXECUTIVE_TEMPLATE = """
# Threat Intelligence Report
**Date**: {{ date }}
**Period**: {{ period }}
**Classification**: {{ classification }}
**TLP**: {{ tlp }}

## Executive Summary
{{ executive_summary }}

## Key Findings
{% for finding in key_findings %}
- {{ finding }}
{% endfor %}

## Threat Actor Activity
{% for actor in threat_actors %}
### {{ actor.name }} ({{ actor.origin }})
- **Motivation**: {{ actor.motivation }}
- **Targeted Sectors**: {{ actor.sectors | join(', ') }}
- **Active Campaigns**: {{ actor.campaigns | join(', ') }}
- **Recommended Actions**: {{ actor.recommendations }}
{% endfor %}

## IOC Statistics
| IOC Type | Total | High Risk | New |
|----------|-------|-----------|-----|
{% for ioc_type, stats in ioc_stats.items() %}
| {{ ioc_type }} | {{ stats.total }} | {{ stats.high_risk }} | {{ stats.new }} |
{% endfor %}

## MITRE ATT&CK Coverage
{% for technique in mitre_techniques %}
- **{{ technique.id }}** - {{ technique.name }}: {{ technique.observed_actors | join(', ') }}
{% endfor %}

## Recommendations
{% for i, rec in enumerate(recommendations, 1) %}
{{ i }}. {{ rec }}
{% endfor %}

## Indicators of Compromise (Top 20)
### Malicious IPs
{% for ip in iocs.ips[:20] %}
- `{{ ip }}`
{% endfor %}

### Malicious Domains
{% for domain in iocs.domains[:20] %}
- `{{ domain }}`
{% endfor %}
"""
    
    def generate_report(self, data: Dict) -> str:
        template = Template(self.EXECUTIVE_TEMPLATE)
        return template.render(**data)
    
    def build_report_data(self, collection_results: Dict) -> Dict:
        return {
            'date': datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
            'period': 'Last 24 hours',
            'classification': 'CONFIDENTIAL',
            'tlp': 'TLP:AMBER',
            'executive_summary': self._generate_executive_summary(collection_results),
            'key_findings': self._extract_key_findings(collection_results),
            'threat_actors': collection_results.get('threat_actors', []),
            'ioc_stats': self._calculate_ioc_stats(collection_results),
            'mitre_techniques': collection_results.get('techniques', []),
            'recommendations': self._generate_recommendations(collection_results),
            'iocs': collection_results.get('iocs', {})
        }
    
    def _generate_executive_summary(self, results: Dict) -> str:
        total_iocs = sum(len(v) for v in results.get('iocs', {}).values())
        high_risk = results.get('high_risk_count', 0)
        return (f"ในช่วง 24 ชั่วโมงที่ผ่านมา ระบบ TI พบ IOCs ทั้งหมด {total_iocs} รายการ "
                f"โดยมี {high_risk} รายการที่ถูกจำแนกเป็น high-risk "
                f"แนะนำให้ทีม SOC ตรวจสอบและ block IOCs เหล่านี้โดยด่วน")
    
    def _extract_key_findings(self, results: Dict) -> List[str]:
        findings = []
        if results.get('high_risk_count', 0) > 0:
            findings.append(f"พบ {results['high_risk_count']} high-risk file hashes ที่ตรวจพบโดย VirusTotal")
        iocs = results.get('iocs', {})
        if iocs.get('ips'):
            findings.append(f"พบ {len(iocs['ips'])} malicious IP addresses จาก threat feeds")
        return findings
    
    def _calculate_ioc_stats(self, results: Dict) -> Dict:
        iocs = results.get('iocs', {})
        return {
            'IP Addresses': {'total': len(iocs.get('ips', [])), 'high_risk': 0, 'new': len(iocs.get('ips', []))},
            'Domains': {'total': len(iocs.get('domains', [])), 'high_risk': 0, 'new': len(iocs.get('domains', []))},
            'File Hashes': {'total': len(iocs.get('hashes', [])), 'high_risk': results.get('high_risk_count', 0), 'new': len(iocs.get('hashes', []))},
            'URLs': {'total': len(iocs.get('urls', [])), 'high_risk': 0, 'new': len(iocs.get('urls', []))}
        }
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        return [
            'Block malicious IPs และ domains บน perimeter firewall และ DNS sinkhole',
            'เพิ่ม file hashes ที่เป็นอันตรายลงใน EDR blacklist',
            'ตรวจสอบ SIEM logs สำหรับการเชื่อมต่อไปยัง IOCs ที่พบ',
            'Update threat intelligence feeds ใน MISP/OpenCTI',
            'แจ้งเตือน stakeholders เกี่ยวกับ active APT campaigns',
            'ทบทวน detection rules ใน SIEM ตาม TTPs ที่พบ'
        ]
```

---

## 13. Threat Feed Aggregation

```python
import requests
from datetime import datetime
from typing import List, Dict

class ThreatFeedAggregator:
    """รวบรวม IOCs จาก public threat feeds"""
    
    def fetch_urlhaus_urls(self, limit=100) -> List[Dict]:
        """ดึง malicious URLs จาก URLhaus"""
        resp = requests.post(
            'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            data={'query': 'get_recent', 'limit': limit},
            timeout=30
        )
        if resp.status_code == 200:
            return resp.json().get('urls', [])
        return []
    
    def fetch_feodo_c2(self) -> List[Dict]:
        """ดึง botnet C2 IPs จาก Feodo Tracker"""
        resp = requests.get(
            'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
            timeout=30
        )
        if resp.status_code == 200:
            return resp.json()
        return []
    
    def fetch_malwarebazaar(self, limit=100) -> List[Dict]:
        """ดึง malware samples จาก MalwareBazaar"""
        resp = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_recent', 'selector': 'time', 'limit': limit},
            timeout=30
        )
        if resp.status_code == 200:
            return resp.json().get('data', [])
        return []
    
    def fetch_threatfox_iocs(self, days=7) -> List[Dict]:
        """ดึง IOCs จาก ThreatFox"""
        resp = requests.post(
            'https://threatfox-api.abuse.ch/api/v1/',
            json={'query': 'get_iocs', 'days': days},
            timeout=30
        )
        if resp.status_code == 200:
            return resp.json().get('data', [])
        return []
    
    def fetch_cisa_kev(self) -> List[Dict]:
        """ดึง Known Exploited Vulnerabilities จาก CISA"""
        resp = requests.get(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            timeout=30
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get('vulnerabilities', [])
        return []
    
    def aggregate_all(self) -> Dict:
        """รวบรวม IOCs จากทุก feeds"""
        print("[*] Fetching URLhaus URLs...")
        urls = self.fetch_urlhaus_urls()
        
        print("[*] Fetching Feodo C2 IPs...")
        c2_ips = self.fetch_feodo_c2()
        
        print("[*] Fetching MalwareBazaar samples...")
        samples = self.fetch_malwarebazaar()
        
        print("[*] Fetching ThreatFox IOCs...")
        threatfox = self.fetch_threatfox_iocs()
        
        aggregated = {
            'timestamp': datetime.utcnow().isoformat(),
            'urls': [{'url': u.get('url'), 'threat': u.get('threat'), 'source': 'URLhaus'} for u in urls],
            'c2_ips': [{'ip': c.get('ip_address'), 'malware': c.get('malware'), 'source': 'Feodo'} for c in c2_ips],
            'hashes': [
                {'md5': s.get('md5_hash'), 'sha256': s.get('sha256_hash'),
                 'tags': s.get('tags', []), 'source': 'MalwareBazaar'}
                for s in samples
            ],
            'iocs': [
                {'type': t.get('ioc_type'), 'value': t.get('ioc_value'),
                 'malware': t.get('malware'), 'source': 'ThreatFox'}
                for t in threatfox
            ],
            'stats': {
                'urls': len(urls),
                'c2_ips': len(c2_ips),
                'hashes': len(samples),
                'iocs': len(threatfox)
            }
        }
        return aggregated

# ตัวอย่าง
agg = ThreatFeedAggregator()
results = agg.aggregate_all()
print(f"Aggregated: {results['stats']}")
```

---

## 14. TI Tools เปรียบเทียบ

| Tool | ประเภท | License | ความสามารถหลัก | เหมาะสำหรับ |
|------|--------|---------|-----------------|-------------|
| **MISP** | TI Platform | Free (AGPL) | IOC sharing, STIX/TAXII, correlation | SOC, ISACs |
| **OpenCTI** | TI Platform | Free (Apache) | Graph-based, STIX 2.1 native | Enterprise SOC |
| **TheHive** | IR Platform | Free (AGPL) | Case management, alert triage | IR Teams |
| **Cortex** | Analyzer | Free (AGPL) | Automated IOC analysis | SOC automation |
| **Maltego** | OSINT | Commercial | Link analysis, OSINT | Investigators |
| **Recorded Future** | TI SaaS | $$$ | AI-powered, dark web monitoring | Enterprise |
| **Mandiant TI** | TI SaaS | $$$ | APT intelligence, vuln intel | Enterprise |
| **CrowdStrike Intel** | EDR+TI | $$$ | Adversary intelligence | Enterprise |
| **VirusTotal** | IOC Lookup | Free/Paid | Multi-AV, file analysis | All teams |
| **Shodan** | Search Engine | Free/Paid | Internet device discovery | All teams |
| **ThreatFox** | IOC Feed | Free | Malware IOC database | Analysts |
| **AlienVault OTX** | TI Community | Free | Community threat sharing | All teams |

---

## 15. TI Program Maturity Model

### Maturity Levels

```
Level 5: Predictive    ──→ AI/ML-driven, real-time, full automation
    ↑
Level 4: Proactive     ──→ Threat hunting, actor profiling, forecasting
    ↑
Level 3: Managed       ──→ MISP/OpenCTI, STIX/TAXII, analyst workflows
    ↑
Level 2: Reactive      ──→ IOC feeds, SIEM integration, basic enrichment
    ↑
Level 1: Ad Hoc        ──→ Manual IOC lookups, no structured program
```

### KPIs สำหรับ TI Program

| KPI | วัดอะไร | เป้าหมาย |
|-----|---------|----------|
| IOC Coverage | % of known bad covered | > 80% |
| MTTD | เวลาเฉลี่ยในการตรวจพบ | < 24 ชั่วโมง |
| MTTR | เวลาเฉลี่ยในการตอบสนอง | < 4 ชั่วโมง |
| Feed Quality | False positive rate | < 5% |
| TI Utilization | IOCs ที่ถูกใช้ใน detections | > 60% |
| Actor Coverage | APT groups ที่ติดตาม | > 50 groups |

### ขั้นตอนการสร้าง TI Program

1. **กำหนด Intelligence Requirements** — ระบุว่าองค์กรต้องการรู้อะไร
2. **เลือก Collection Sources** — OSINT, commercial feeds, ISACs, dark web
3. **ติดตั้ง TI Platform** — MISP หรือ OpenCTI
4. **Integrate กับ SIEM/SOAR** — ส่ง IOCs ไปยัง detection tools
5. **สร้าง Analyst Workflows** — กระบวนการ triage, enrichment, reporting
6. **Share Intelligence** — เข้าร่วม ISACs, sharing communities
7. **วัดผลและปรับปรุง** — ทบทวน KPIs ทุกไตรมาส

---

## สรุป

Threat Intelligence เป็นรากฐานสำคัญของโปรแกรมความปลอดภัยระดับโลก การมี TI ที่ดีช่วยให้:
- ตรวจพบภัยคุกคามได้เร็วขึ้น (MTTD ลดลง)
- ตอบสนองต่อ incidents ได้มีประสิทธิภาพมากขึ้น
- เข้าใจ TTPs ของ threat actors ที่กำหนดเป้าหมายองค์กร
- สร้าง proactive defense แทนที่จะรอให้ถูกโจมตี

---

← [Part 95: Red Team Operations](Part-95-Red-Team-Operations.md) | [Part 97: Advanced Web Application Security](Part-97-Advanced-Web-Security.md) →
