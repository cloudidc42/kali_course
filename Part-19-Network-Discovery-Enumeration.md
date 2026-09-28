# Part 19: Network Discovery และ Enumeration

## สารบัญ
- [19.1 Network Discovery คืออะไร](#191-network-discovery-คืออะไร)
- [19.2 ARP Scanning ด้วย arp-scan](#192-arp-scanning-ด้วย-arp-scan)
- [19.3 netdiscover - Passive/Active Discovery](#193-netdiscover---passiveactive-discovery)
- [19.4 SNMP Enumeration](#194-snmp-enumeration)
- [19.5 NetBIOS/SMB Enumeration](#195-netbiossmb-enumeration)
- [19.6 LDAP Enumeration](#196-ldap-enumeration)
- [19.7 NFS Enumeration](#197-nfs-enumeration)
- [19.8 การสร้าง Network Map อัตโนมัติ](#198-การสร้าง-network-map-อัตโนมัติ)
- [19.9 แบบฝึกหัด Lab](#199-แบบฝึกหัด-lab)

---

## 19.1 Network Discovery คืออะไร

Network Discovery คือขั้นตอนการค้นหาอุปกรณ์ทั้งหมดในเครือข่ายเป้าหมาย เพื่อสร้าง inventory ก่อนการทดสอบเจาะระบบ

### เป้าหมายของ Network Discovery
```
1. ค้นหา Live Hosts ทั้งหมด
2. ระบุ IP Address ของแต่ละอุปกรณ์
3. ค้นหา MAC Address และ Vendor
4. ระบุ Operating System เบื้องต้น
5. สร้าง Network Topology Map
6. ค้นหา Services ที่กำลัง Running
```

### ประเภทของ Network Discovery
```
┌─────────────────────────────────────────────────────┐
│           Network Discovery Methods                  │
├─────────────────┬───────────────────────────────────┤
│  Passive        │  Active                            │
├─────────────────┼───────────────────────────────────┤
│  - ARP Monitor  │  - ARP Scan                        │
│  - Packet Sniff │  - ICMP Ping Sweep                 │
│  - Traffic Anal │  - TCP/UDP Port Scan               │
│  - Wireshark    │  - SNMP Walk                       │
│  - netdiscover  │  - NetBIOS Scan                    │
└─────────────────┴───────────────────────────────────┘
```

---

## 19.2 ARP Scanning ด้วย arp-scan

`arp-scan` ใช้ ARP protocol ในการค้นหา Host ใน Local Network ได้รวดเร็วและแม่นยำมาก

### ติดตั้ง arp-scan
```bash
sudo apt update && sudo apt install arp-scan -y
```

### การใช้งาน arp-scan พื้นฐาน
```bash
# สแกน Network ปัจจุบัน (auto-detect interface)
sudo arp-scan --localnet

# ระบุ Network เอง
sudo arp-scan 192.168.1.0/24

# ระบุ Interface
sudo arp-scan -I eth0 192.168.1.0/24

# สแกน IP Range
sudo arp-scan 192.168.1.1-192.168.1.100

# สแกน IP List จากไฟล์
sudo arp-scan -f /tmp/ip_list.txt
```

### ตัวอย่าง Output
```
Interface: eth0, type: EN10MB, MAC: 00:0c:29:xx:xx:xx, IPv4: 192.168.1.50
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)

192.168.1.1	00:50:56:c0:00:01	VMware, Inc.
192.168.1.2	00:50:56:e7:ff:ff	VMware, Inc.
192.168.1.100	00:0c:29:1a:2b:3c	VMware, Inc.
192.168.1.101	00:0c:29:4d:5e:6f	VMware, Inc.
192.168.1.200	08:00:27:ab:cd:ef	PCS Systemtechnik GmbH

5 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.7: 256 hosts scanned in 2.145 seconds (119.35 hosts/sec). 5 responded
```

### Options ที่ใช้บ่อย
```bash
# ดู Vendor Database
sudo arp-scan --list

# Verbose output
sudo arp-scan -v 192.168.1.0/24

# Double-scan เพื่อลด False Negative
sudo arp-scan -r 2 192.168.1.0/24

# Custom Bandwidth
sudo arp-scan -b 1000 192.168.1.0/24

# Output เป็น CSV
sudo arp-scan 192.168.1.0/24 | awk '{print $1","$2","$3}'
```

### เปรียบเทียบ arp-scan vs Nmap
```bash
# arp-scan - เร็วกว่า แต่ทำงานได้แค่ Local Network
sudo arp-scan 192.168.1.0/24
# ใช้เวลา: ~2 วินาที

# Nmap ARP Scan
sudo nmap -PR -sn 192.168.1.0/24
# ใช้เวลา: ~3-5 วินาที

# Nmap ICMP Ping Sweep (ใช้ได้ข้าม Network)
nmap -sn 192.168.1.0/24
# ใช้เวลา: ~10-30 วินาที
```

---

## 19.3 netdiscover - Passive/Active Discovery

`netdiscover` เป็นเครื่องมือ ARP-based discovery ที่ทำงานได้ทั้ง Passive (แค่ดัก ARP) และ Active (ส่ง ARP request)

### การติดตั้ง
```bash
sudo apt install netdiscover -y
```

### Passive Mode - แค่ Monitor ARP Traffic
```bash
# Passive mode - ไม่ส่ง packet ใดๆ ทั้งสิ้น (Stealth สูงสุด)
sudo netdiscover -p -i eth0

# Passive mode บน WiFi
sudo netdiscover -p -i wlan0
```

### Active Mode - ส่ง ARP Requests
```bash
# สแกน Network ทั้งหมด
sudo netdiscover -r 192.168.1.0/24

# ระบุ Interface
sudo netdiscover -r 192.168.1.0/24 -i eth0

# เร็วขึ้น (ส่งเร็ว แต่อาจ noisy)
sudo netdiscover -r 192.168.1.0/24 -f

# บันทึกผลลัพธ์
sudo netdiscover -r 192.168.1.0/24 -P > /tmp/hosts.txt
```

### ตัวอย่าง Output (Active Mode)
```
 Currently scanning: 192.168.1.0/24   |   Screen View: Unique Hosts

 6 Captured ARP Req/Rep packets, from 5 hosts.   Total size: 360
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
 -----------------------------------------------------------------------------
 192.168.1.1     00:50:56:c0:00:01      2     120  VMware, Inc.
 192.168.1.100   00:0c:29:1a:2b:3c      1      60  VMware, Inc.
 192.168.1.101   00:0c:29:4d:5e:6f      1      60  VMware, Inc.
 192.168.1.200   08:00:27:ab:cd:ef      1      60  PCS Systemtechnik GmbH
 192.168.1.254   00:50:56:e7:ff:ff      1      60  VMware, Inc.
```

### สร้าง Script รวม arp-scan + netdiscover
```bash
#!/bin/bash
# network_discover.sh - รวม Discovery Tools

NETWORK="$1"
INTERFACE="${2:-eth0}"
OUTPUT="/tmp/network_discovery_$(date +%Y%m%d_%H%M%S)"

echo "[*] เริ่ม Network Discovery: $NETWORK"
echo "[*] Interface: $INTERFACE"
echo "[*] Output: $OUTPUT"
echo "" 

# ARP Scan
echo "[+] Running arp-scan..."
sudo arp-scan -I $INTERFACE $NETWORK 2>/dev/null | grep -E '^[0-9]' | awk '{print $1}' | sort -u > ${OUTPUT}_arp.txt
echo "    Found: $(wc -l < ${OUTPUT}_arp.txt) hosts"

# Nmap Ping Sweep
echo "[+] Running Nmap ping sweep..."
nmap -sn $NETWORK -oG - 2>/dev/null | grep 'Up' | awk '{print $2}' | sort -u > ${OUTPUT}_nmap.txt
echo "    Found: $(wc -l < ${OUTPUT}_nmap.txt) hosts"

# รวมผล
cat ${OUTPUT}_arp.txt ${OUTPUT}_nmap.txt | sort -u -V > ${OUTPUT}_combined.txt
echo ""
echo "[*] Total Unique Hosts Found: $(wc -l < ${OUTPUT}_combined.txt)"
echo "[*] Results saved to: ${OUTPUT}_combined.txt"
cat ${OUTPUT}_combined.txt
```

### การใช้งาน Script
```bash
chmod +x network_discover.sh
sudo ./network_discover.sh 192.168.1.0/24 eth0
```

---

## 19.4 SNMP Enumeration

SNMP (Simple Network Management Protocol) ใช้จัดการอุปกรณ์เครือข่าย มักมี Community String ที่อ่อนแอ

### ทำความเข้าใจ SNMP
```
SNMP Versions:
  SNMPv1  - Community String แบบ Plain text (ไม่ปลอดภัย)
  SNMPv2c - Community String แบบ Plain text (ปรับปรุงเล็กน้อย)
  SNMPv3  - มี Authentication + Encryption (ปลอดภัย)

Community Strings ที่พบบ่อย:
  public   - Default Read-only
  private  - Default Read-write
  manager  - Common admin
  cisco    - Cisco devices
  secret   - Custom

Ports:
  UDP 161 - SNMP Agent
  UDP 162 - SNMP Trap
```

### Nmap SNMP Scan
```bash
# ค้นหา SNMP Services
nmap -sU -p 161 192.168.1.0/24

# ใช้ NSE Script
nmap -sU -p 161 --script snmp-info,snmp-sysdescr 192.168.1.0/24

# SNMP Brute Force Community String
nmap -sU -p 161 --script snmp-brute 192.168.1.100

# ดู SNMP System Info
nmap -sU -p 161 --script snmp-sysdescr 192.168.1.100
```

### snmpwalk - Walk MIB Tree
```bash
# ติดตั้ง
sudo apt install snmp snmp-mibs-downloader -y

# Walk ทั้ง MIB Tree
snmpwalk -v2c -c public 192.168.1.100

# ดู System Info
snmpwalk -v2c -c public 192.168.1.100 1.3.6.1.2.1.1

# ดู Interface List
snmpwalk -v2c -c public 192.168.1.100 1.3.6.1.2.1.2.2.1.2

# ดู Running Process
snmpwalk -v2c -c public 192.168.1.100 1.3.6.1.2.1.25.4.2.1.2

# ดู Installed Software (Windows)
snmpwalk -v2c -c public 192.168.1.100 1.3.6.1.2.1.25.6.3.1.2

# ดู Network Connections
snmpwalk -v2c -c public 192.168.1.100 1.3.6.1.2.1.6.13.1

# ดู User Accounts (Windows)
snmpwalk -v2c -c public 192.168.1.100 1.3.6.1.4.1.77.1.2.25
```

### snmpget - ดูค่าเฉพาะ OID
```bash
# ดู System Description
snmpget -v2c -c public 192.168.1.100 1.3.6.1.2.1.1.1.0

# ดู Hostname
snmpget -v2c -c public 192.168.1.100 1.3.6.1.2.1.1.5.0

# ดู Uptime
snmpget -v2c -c public 192.168.1.100 1.3.6.1.2.1.1.3.0
```

### onesixtyone - SNMP Community String Bruteforce
```bash
# ติดตั้ง
sudo apt install onesixtyone -y

# สร้าง Community String Wordlist
cat > /tmp/community.txt << 'EOF'
public
private
manager
cisco
secret
community
admin
monitor
SNMPv2c
test
EOF

# Bruteforce Single Host
onesixtyone 192.168.1.100 -c /tmp/community.txt

# Bruteforce Multiple Hosts
onesixtyone -c /tmp/community.txt -i /tmp/hosts.txt
```

### ตัวอย่าง Output onesixtyone
```
Scanning 1 hosts, 10 communities
192.168.1.100 [public] Linux server01 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64
192.168.1.100 [private] Linux server01 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64
```

### Python SNMP Enumeration
```python
#!/usr/bin/env python3
# snmp_enum.py - Python SNMP Enumerator

from pysnmp.hlapi import *
import sys

# OID สำคัญ
OIDS = {
    'sysDescr':     '1.3.6.1.2.1.1.1.0',
    'sysObjectID':  '1.3.6.1.2.1.1.2.0',
    'sysUpTime':    '1.3.6.1.2.1.1.3.0',
    'sysContact':   '1.3.6.1.2.1.1.4.0',
    'sysName':      '1.3.6.1.2.1.1.5.0',
    'sysLocation':  '1.3.6.1.2.1.1.6.0',
    'sysServices':  '1.3.6.1.2.1.1.7.0',
}

def snmp_get(host, community, oid):
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),  # v2c
        UdpTransportTarget((host, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication or errorStatus:
        return None
    for varBind in varBinds:
        return str(varBind[1])

def snmp_enum(host, community):
    print(f"\n[*] SNMP Enumeration: {host} [community={community}]")
    print("=" * 60)
    for name, oid in OIDS.items():
        value = snmp_get(host, community, oid)
        if value:
            print(f"  {name:15} : {value}")

def brute_community(host, wordlist):
    print(f"[*] Brute forcing SNMP community on {host}")
    with open(wordlist) as f:
        communities = f.read().splitlines()
    found = []
    for comm in communities:
        result = snmp_get(host, comm, '1.3.6.1.2.1.1.1.0')
        if result:
            print(f"  [+] Found community: {comm}")
            found.append(comm)
    return found

if __name__ == '__main__':
    target = '192.168.1.100'
    found = brute_community(target, '/tmp/community.txt')
    for comm in found:
        snmp_enum(target, comm)
```

---

## 19.5 NetBIOS/SMB Enumeration

NetBIOS และ SMB ใช้แชร์ไฟล์และ Printer ใน Windows Network - มักพบช่องโหว่มากมาย

### nmblookup - NetBIOS Lookup
```bash
# ค้นหา NetBIOS Name
nmblookup -A 192.168.1.100

# ค้นหา Workgroup/Domain
nmblookup -M -- -
nmblookup WORKGROUP

# Broadcast Query
nmblookup '*'
```

### nbtscan - NetBIOS Scanner
```bash
# ติดตั้ง
sudo apt install nbtscan -y

# สแกน Network
nbtscan 192.168.1.0/24

# Verbose output
nbtscan -v 192.168.1.0/24

# สแกนและบันทึก
nbtscan 192.168.1.0/24 > /tmp/netbios.txt
```

### ตัวอย่าง Output nbtscan
```
Doing NBT name scan for addresses from 192.168.1.0/24

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
192.168.1.100    WIN-SERVER01     <server>  WIN-SERVER01     00:0c:29:1a:2b:3c
192.168.1.101    WORKSTATION01    <server>            	    00:0c:29:4d:5e:6f
192.168.1.102    DC01             <server>  DC01             08:00:27:ab:cd:ef
```

### enum4linux - SMB/Samba Enumeration
```bash
# ติดตั้ง
sudo apt install enum4linux -y

# Full Enumeration
enum4linux -a 192.168.1.100

# List Shares
enum4linux -S 192.168.1.100

# Enumerate Users
enum4linux -U 192.168.1.100

# Password Policy
enum4linux -P 192.168.1.100

# Group Enumeration
enum4linux -G 192.168.1.100

# OS Info
enum4linux -o 192.168.1.100

# With Credentials
enum4linux -u admin -p password123 -a 192.168.1.100
```

### ตัวอย่าง Output enum4linux
```
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ )

========================== Target Information ==========================

Target ........... 192.168.1.100
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''

=================== Getting domain/workgroup name ====================

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

============== Enumerating Workgroup/Domain on 192.168.1.100 ===============
[+] Got domain/workgroup name: WORKGROUP

==================== Nmap SMB Ports on 192.168.1.100 =======================

[+] Host has netbios-ssn (445/tcp) open

======================== Session Check on 192.168.1.100 ====================

[+] Server 192.168.1.100 allows sessions using username '', password ''

======================= Getting information via SMB ========================

[+] Got OS info for 192.168.1.100 from smbclient: 

Server Information
------------------
Domain=[WORKGROUP] OS=[Windows 10 Pro 10.0] Server=[Windows 10 Pro 6.1]

========================= Share Enumeration ==============================

Sharename       Type      Comment
---------       ----      -------
C$              Disk      Default share
IPC$            IPC       Remote IPC
ADMIN$          Disk      Remote Admin
Users           Disk      
Documents       Disk      Shared Documents

[+] Attempting to map shares on 192.168.1.100
//192.168.1.100/C$   [E] Can't understand response:
//192.168.1.100/Users [+] Mapping: OK, Listing: OK

========================== Users on 192.168.1.100 ==========================

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\admin (Local User)
S-1-22-1-1001 Unix User\user1 (Local User)
S-1-22-1-1002 Unix User\user2 (Local User)
```

### smbclient - SMB Client
```bash
# List Shares (Anonymous)
smbclient -L //192.168.1.100 -N

# Connect to Share (Anonymous)
smbclient //192.168.1.100/Users -N

# Connect ด้วย Credentials
smbclient //192.168.1.100/C$ -U admin%password123

# Download ไฟล์ทั้งหมด
smbclient //192.168.1.100/Documents -N -c 'recurse; prompt; mget *'

# ค้นหาไฟล์สำคัญ
smbclient //192.168.1.100/Documents -N -c 'ls'
```

### Nmap SMB Scripts
```bash
# ข้อมูล SMB พื้นฐาน
nmap --script smb-os-discovery 192.168.1.100

# Enum Users
nmap --script smb-enum-users 192.168.1.100

# Enum Shares
nmap --script smb-enum-shares 192.168.1.100

# Check EternalBlue
nmap --script smb-vuln-ms17-010 192.168.1.100

# Enum Domains
nmap --script smb-enum-domains 192.168.1.100

# ทั้งหมดในครั้งเดียว
nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln-ms17-010 -p 445 192.168.1.100
```

---

## 19.6 LDAP Enumeration

LDAP ใช้กับ Active Directory - การ Enumerate จะช่วยดึงข้อมูล User, Group, Computer ทั้งหมดออกมา

### ทำความเข้าใจ LDAP
```
Port 389 - LDAP (Plain)
Port 636 - LDAPS (SSL)
Port 3268 - Global Catalog
Port 3269 - Global Catalog SSL

Base DN ตัวอย่าง:
  dc=company,dc=com
  dc=corp,dc=local
```

### ldapsearch - LDAP Query
```bash
# Anonymous LDAP Bind (ถ้าเปิดให้)
ldapsearch -x -H ldap://192.168.1.100 -b "dc=company,dc=com"

# ดึง Base DN
ldapsearch -x -H ldap://192.168.1.100 -s base namingcontexts

# ค้นหา Users
ldapsearch -x -H ldap://192.168.1.100 -b "dc=company,dc=com" '(objectClass=user)'

# ดึงเฉพาะ Attributes ที่ต้องการ
ldapsearch -x -H ldap://192.168.1.100 -b "dc=company,dc=com" '(objectClass=user)' sAMAccountName mail

# ใช้ Credentials
ldapsearch -x -H ldap://192.168.1.100 -D 'cn=user1,dc=company,dc=com' -w 'password123' -b 'dc=company,dc=com'

# ค้นหา Computer Accounts
ldapsearch -x -H ldap://192.168.1.100 -b "dc=company,dc=com" '(objectClass=computer)'

# ค้นหา Admin Groups
ldapsearch -x -H ldap://192.168.1.100 -b "dc=company,dc=com" '(cn=Domain Admins)'
```

### Nmap LDAP Scripts
```bash
# ข้อมูล LDAP Server
nmap -p 389,636 --script ldap-rootdse 192.168.1.100

# Search LDAP
nmap -p 389 --script ldap-search --script-args ldap.base="dc=company,dc=com" 192.168.1.100

# Brute Force
nmap -p 389 --script ldap-brute --script-args brute.firstonly=true 192.168.1.100
```

---

## 19.7 NFS Enumeration

NFS (Network File System) ใช้แชร์ไฟล์ใน Unix/Linux - ถ้า Config ไม่ดีจะเข้าถึงได้โดยไม่ต้องมี Password

### ค้นหา NFS Shares
```bash
# Nmap NFS Scan
nmap -sV -p 111,2049 192.168.1.100
nmap --script nfs-ls,nfs-showmount,nfs-statfs 192.168.1.100

# showmount - ดู Export List
showmount -e 192.168.1.100

# ตัวอย่าง Output
# Export list for 192.168.1.100:
# /home/data     192.168.1.0/24
# /var/backups   *
# /secret        192.168.1.50

# Mount NFS Share
mkdir /tmp/nfs_mount
sudo mount -t nfs 192.168.1.100:/home/data /tmp/nfs_mount
ls -la /tmp/nfs_mount

# Unmount
sudo umount /tmp/nfs_mount
```

### NFS UID Impersonation
```bash
# NFS ใช้ UID/GID ในการ Control Access
# ถ้า share อนุญาต UID 1000 เราสามารถสร้าง user UID 1000 แล้ว mount ได้

# ดู UID ของไฟล์ใน NFS
ls -lan /tmp/nfs_mount
# -rw-r--r-- 1 1001 1001 1234 Jan 1 00:00 secret.txt

# สร้าง User ที่มี UID ตรงกัน
sudo useradd -u 1001 nfsuser
sudo su nfsuser
cat /tmp/nfs_mount/secret.txt
```

---

## 19.8 การสร้าง Network Map อัตโนมัติ

### Complete Network Enumeration Script
```bash
#!/bin/bash
# complete_enum.sh - Full Network Enumeration

TARGET="$1"
OUTPUT_DIR="/tmp/enum_$(echo $TARGET | tr '/' '_')_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "================================================================"
echo "  COMPLETE NETWORK ENUMERATION"
echo "  Target: $TARGET"
echo "  Output: $OUTPUT_DIR"
echo "================================================================"

# Phase 1: Host Discovery
echo "[PHASE 1] Host Discovery"
nmap -sn $TARGET -oG - 2>/dev/null | grep 'Up' | awk '{print $2}' > $OUTPUT_DIR/live_hosts.txt
LIVE=$(wc -l < $OUTPUT_DIR/live_hosts.txt)
echo "  Found $LIVE live hosts"

# Phase 2: Port Scan
echo "[PHASE 2] Port Scanning"
nmap -sS -T4 --top-ports 1000 -iL $OUTPUT_DIR/live_hosts.txt -oA $OUTPUT_DIR/port_scan 2>/dev/null
echo "  Port scan complete"

# Phase 3: Service Detection  
echo "[PHASE 3] Service Detection"
nmap -sV -iL $OUTPUT_DIR/live_hosts.txt -p $(grep 'open' $OUTPUT_DIR/port_scan.gnmap 2>/dev/null | grep -oP '\d+/open' | cut -d/ -f1 | sort -u | tr '\n' ',' | sed 's/,$//') -oA $OUTPUT_DIR/service_scan 2>/dev/null
echo "  Service detection complete"

# Phase 4: SMB Enumeration (Port 445 hosts)
echo "[PHASE 4] SMB Enumeration"
grep 'open' $OUTPUT_DIR/port_scan.gnmap | grep '445/open' | awk '{print $2}' > $OUTPUT_DIR/smb_hosts.txt
while read host; do
    echo "  Enumerating SMB: $host"
    nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users -p 445 $host -oN $OUTPUT_DIR/smb_${host}.txt 2>/dev/null
done < $OUTPUT_DIR/smb_hosts.txt

# Phase 5: SNMP Enumeration (Port 161 hosts)
echo "[PHASE 5] SNMP Enumeration"
nmap -sU -p 161 -iL $OUTPUT_DIR/live_hosts.txt -oG - 2>/dev/null | grep 'open' | awk '{print $2}' > $OUTPUT_DIR/snmp_hosts.txt
while read host; do
    echo "  Enumerating SNMP: $host"
    snmpwalk -v2c -c public $host 2>/dev/null | head -50 > $OUTPUT_DIR/snmp_${host}.txt
done < $OUTPUT_DIR/snmp_hosts.txt

# Phase 6: Generate Report
echo "[PHASE 6] Generating Report"
cat > $OUTPUT_DIR/REPORT.md << REPORT
# Network Enumeration Report
**Target:** $TARGET  
**Date:** $(date)  
**Operator:** $USER  

## Summary
- Live Hosts: $(wc -l < $OUTPUT_DIR/live_hosts.txt)
- SMB Hosts: $(wc -l < $OUTPUT_DIR/smb_hosts.txt)
- SNMP Hosts: $(wc -l < $OUTPUT_DIR/snmp_hosts.txt)

## Live Hosts
\`\`\`
$(cat $OUTPUT_DIR/live_hosts.txt)
\`\`\`

## Open Ports Summary
\`\`\`
$(grep 'open' $OUTPUT_DIR/port_scan.gnmap | awk -F'\t' '{print $2, $3}')
\`\`\`
REPORT

echo ""
echo "[*] Enumeration Complete!"
echo "[*] Results in: $OUTPUT_DIR"
ls -la $OUTPUT_DIR
```

---

## 19.9 แบบฝึกหัด Lab

### Lab 19-1: ARP Discovery
```bash
# 1. ค้นหา Network ของเราเอง
ip route | grep 'src'

# 2. สแกนด้วย arp-scan
sudo arp-scan --localnet

# 3. บันทึก IP ทั้งหมด
sudo arp-scan --localnet | grep -E '^[0-9]' | awk '{print $1}' > /tmp/lab_hosts.txt
cat /tmp/lab_hosts.txt
```

### Lab 19-2: SNMP Enumeration
```bash
# Setup: ติดตั้ง SNMP Service บน Target (Lab)
sudo apt install snmpd -y
sudo systemctl start snmpd

# Enumerate SNMP
snmpwalk -v2c -c public 127.0.0.1
snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.2.1.1  # System Info
snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.2.1.25.4.2.1.2  # Processes
```

### Lab 19-3: SMB Enumeration (ต้องมี Windows Target)
```bash
# ค้นหา Windows Host
nbtscan 192.168.1.0/24

# Enumerate SMB
enum4linux -a [WINDOWS_IP]

# List Shares
smbclient -L //[WINDOWS_IP] -N

# ลอง Anonymous Access
smbclient //[WINDOWS_IP]/Users -N
```

---

## สรุป

| เครื่องมือ | Protocol | ใช้งาน | Port |
|-----------|----------|--------|------|
| arp-scan | ARP | Host Discovery (LAN) | - |
| netdiscover | ARP | Passive/Active Discovery | - |
| onesixtyone | SNMP | Community String Brute | UDP 161 |
| snmpwalk | SNMP | MIB Tree Walk | UDP 161 |
| nbtscan | NetBIOS | Windows Network Scan | UDP 137 |
| enum4linux | SMB | Full SMB Enumeration | TCP 445 |
| smbclient | SMB | File Share Access | TCP 445 |
| ldapsearch | LDAP | Active Directory Enum | TCP 389 |
| showmount | NFS | NFS Share Discovery | TCP 2049 |

> **ข้อควรระวัง:** ใช้เครื่องมือเหล่านี้เฉพาะในระบบที่ได้รับอนุญาตเท่านั้น
