# Part 03: Networking Fundamentals - พื้นฐาน Networking

## สารบัญ
- [OSI Model](#osi-model)
- [TCP/IP Model](#tcpip-model)
- [IP Addressing](#ip-addressing)
- [Subnetting](#subnetting)
- [Common Protocols](#common-protocols)
- [Network Devices](#network-devices)
- [Wireshark Basics](#wireshark-basics)
- [แบบฝึกหัด](#แบบฝึกหัด)

---

## OSI Model

**OSI (Open Systems Interconnection) Model** คือ framework สำหรับอธิบายการสื่อสารระหว่าง network devices

```
┌────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, HTTPS, FTP, DNS, SMTP  │
├────────────────────────────────────────┤
│ Layer 6: Presentation   │ SSL/TLS, Encryption, Encoding│
├────────────────────────────────────────┤
│ Layer 5: Session        │ NetBIOS, RPC, SQL, NFS       │
├────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP, UDP                     │
├────────────────────────────────────────┤
│ Layer 3: Network        │ IP, ICMP, IGMP, ARP          │
├────────────────────────────────────────┤
│ Layer 2: Data Link      │ Ethernet, MAC, Switches      │
├────────────────────────────────────────┤
│ Layer 1: Physical       │ Cables, Hubs, Signals        │
└────────────────────────────────────────┘
```

### Layer แต่ละ Layer

**Layer 1 - Physical**
- สายเก็บ, Hub, Repeater
- สิ่งที่ส่งผ่าน: bits (0/1)
- การโจมตี: ตัด/เจาะสายเคเบิล, signal jamming

**Layer 2 - Data Link**
- MAC addresses, Ethernet frames
- Switch, Bridge
- การโจมตี: ARP Spoofing, MAC Flooding, VLAN Hopping

**Layer 3 - Network**
- IP addresses, routing
- Router, L3 Switch
- การโจมตี: IP Spoofing, Route injection, ICMP attacks

**Layer 4 - Transport**
- Port numbers, TCP/UDP
- Firewall, Load Balancer
- การโจมตี: Port scanning, SYN flood, session hijacking

**Layer 5-7 - Application**
- Application protocols
- การโจมตี: XSS, SQLi, CSRF, injection attacks

---

## TCP/IP Model

```
┌─────────────────────┐  ┌─────────────────────┐
│  Application (L5-7)  │  │ HTTP, DNS, SMTP, FTP  │
├─────────────────────┤  ├─────────────────────┤
│  Transport (L4)      │  │ TCP, UDP               │
├─────────────────────┤  ├─────────────────────┤
│  Internet (L3)       │  │ IP, ICMP, ARP         │
├─────────────────────┤  ├─────────────────────┤
│  Link (L1-2)         │  │ Ethernet, MAC, Wi-Fi  │
└─────────────────────┘  └─────────────────────┘
```

---

## IP Addressing

### IPv4

IP address มีขนาด 32 bits แบ่งเป็น 4 octets

```
192.168.1.100
│││ │││ │ │││
11000000.10101000.00000001.01100100
```

### IP Classes

| Class | Range | Default Subnet | ใช้สำหรับ |
|-------|-------|----------------|----------|
| A | 1.0.0.0 - 126.255.255.255 | /8 (255.0.0.0) | Large networks |
| B | 128.0.0.0 - 191.255.255.255 | /16 (255.255.0.0) | Medium networks |
| C | 192.0.0.0 - 223.255.255.255 | /24 (255.255.255.0) | Small networks |
| D | 224.0.0.0 - 239.255.255.255 | N/A | Multicast |
| E | 240.0.0.0 - 255.255.255.255 | N/A | Research |

### Private IP Ranges

| Range | CIDR | ใช้ใน |
|-------|------|--------|
| 10.0.0.0 - 10.255.255.255 | 10.0.0.0/8 | Large orgs |
| 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12 | Medium orgs |
| 192.168.0.0 - 192.168.255.255 | 192.168.0.0/16 | Home networks |

### Special Addresses

```
127.0.0.1      - Loopback (localhost)
0.0.0.0        - Default route / any address
255.255.255.255 - Limited broadcast
169.254.x.x    - APIPA (link-local)
```

---

## Subnetting

### CIDR Notation

```
192.168.1.0/24
           └── 24 bits สำหรับ network
              8 bits เหลือสำหรับ hosts = 254 hosts
```

### Subnet Table

| CIDR | Subnet Mask | # Hosts | # Addresses |
|------|-------------|---------|-------------|
| /8 | 255.0.0.0 | 16,777,214 | 16,777,216 |
| /16 | 255.255.0.0 | 65,534 | 65,536 |
| /24 | 255.255.255.0 | 254 | 256 |
| /25 | 255.255.255.128 | 126 | 128 |
| /26 | 255.255.255.192 | 62 | 64 |
| /27 | 255.255.255.224 | 30 | 32 |
| /28 | 255.255.255.240 | 14 | 16 |
| /29 | 255.255.255.248 | 6 | 8 |
| /30 | 255.255.255.252 | 2 | 4 |
| /32 | 255.255.255.255 | 1 | 1 |

### คำนวณ Subnet

```bash
# ใช้ ipcalc คำนวณ subnet
ipcalc 192.168.1.100/24

# Output:
# Address:   192.168.1.100        11000000.10101000.00000001. 01100100
# Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
# Wildcard:  0.0.0.255            00000000.00000000.00000000. 11111111
# Network:   192.168.1.0/24       11000000.10101000.00000001. 00000000
# HostMin:   192.168.1.1          11000000.10101000.00000001. 00000001
# HostMax:   192.168.1.254        11000000.10101000.00000001. 11111110
# Broadcast: 192.168.1.255        11000000.10101000.00000001. 11111111
# Hosts/Net: 254

# ติดตั้ง
ssudo apt install ipcalc
```

---

## Common Protocols

### TCP vs UDP

| คุณสมบัติ | TCP | UDP |
|----------|-----|-----|
| Connection | Connection-oriented | Connectionless |
| Reliability | Guaranteed delivery | Best-effort |
| Speed | Slower | Faster |
| Error checking | Yes | Minimal |
| ใช้สำหรับ | HTTP, SSH, FTP | DNS, DHCP, SNMP |

### Well-Known Ports

| Port | Protocol | Service |
|------|----------|--------|
| 20/21 | TCP | FTP |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | TCP/UDP | DNS |
| 67/68 | UDP | DHCP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 |
| 139/445 | TCP | SMB |
| 143 | TCP | IMAP |
| 389 | TCP/UDP | LDAP |
| 443 | TCP | HTTPS |
| 636 | TCP | LDAPS |
| 1433 | TCP | MSSQL |
| 1521 | TCP | Oracle DB |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP |
| 5432 | TCP | PostgreSQL |
| 5900 | TCP | VNC |
| 6379 | TCP | Redis |
| 8080 | TCP | HTTP Alt |
| 27017 | TCP | MongoDB |

### การค้นหา Port ด้วย Nmap

```bash
# Scan common ports
nmap 192.168.1.100

# Scan specific ports
nmap -p 80,443,8080 192.168.1.100

# Scan all ports
nmap -p- 192.168.1.100

# Scan with service detection
nmap -sV 192.168.1.100

# UDP scan
nmap -sU --top-ports 100 192.168.1.100
```

---

## ARP - Address Resolution Protocol

```
การทำงาน ARP:

192.168.1.100 ต้องการส่ง packet ไป 192.168.1.200

1. ตรวจ ARP cache ก่อน
2. ถ้าไม่มี: ส่ง ARP broadcast
   "Who has 192.168.1.200? Tell 192.168.1.100"
3. 192.168.1.200 ตอบ: "I am AA:BB:CC:DD:EE:FF"
4. บันทึกใน ARP cache
```

```bash
# ดู ARP cache
arp -n
ip neigh show

# ARP Scan
arp-scan -l
arp-scan 192.168.1.0/24

# ARP Spoofing (ต้องได้รับอนุญาต)
# arpspoof -i eth0 -t target_ip gateway_ip
```

---

## DNS - Domain Name System

```
การทำงาน DNS:

User พิมพ์ www.google.com
         ↓
1. Check /etc/hosts
2. Check DNS cache
3. ถาม DNS Server (8.8.8.8)
4. DNS Server ถาม Root Server
5. Root เปลี่ยน -> .com nameserver
6. .com เปลี่ยน -> google.com nameserver
7. ได้ IP: 142.250.196.100
8. เชื่อมต่อไปเลย
```

### DNS Record Types

| Record | วัตถุประสงค์ |
|--------|-------------|
| A | IP address (IPv4) |
| AAAA | IP address (IPv6) |
| CNAME | Alias/canonical name |
| MX | Mail server |
| NS | Name server |
| TXT | Text records (SPF, DKIM) |
| PTR | Reverse DNS lookup |
| SOA | Start of Authority |

### DNS Commands

```bash
# DNS lookup
nslookup google.com
dig google.com
host google.com

# ดู specific record types
dig google.com MX      # Mail servers
dig google.com NS      # Name servers
dig google.com TXT     # TXT records
dig google.com AXFR    # Zone transfer (ถ้าอนุญาต)

# Reverse lookup
dig -x 8.8.8.8

# ใช้ DNS server อื่น
dig @8.8.8.8 google.com
dig @1.1.1.1 google.com

# DNS Enumeration
dig google.com ANY
dig axfr google.com @ns1.google.com  # Zone transfer attempt

# ค้นหา subdomains
dnsenum google.com
sublist3r -d google.com

# อ่าน /etc/hosts
cat /etc/hosts
echo "192.168.1.100 target.local" >> /etc/hosts
```

---

## Network Scanning Fundamentals

### Ping Sweep

```bash
# ค้นหา hosts ที่ active

# Nmap ping sweep
nmap -sn 192.168.1.0/24

# Nmap output:
# Nmap scan report for 192.168.1.1
# Host is up (0.00086s latency).
# Nmap scan report for 192.168.1.100
# Host is up (0.00034s latency).

# netdiscover
sudo netdiscover -r 192.168.1.0/24

# arp-scan
sudo arp-scan -l
sudo arp-scan 192.168.1.0/24

# fping
fping -a -g 192.168.1.0/24 2>/dev/null
```

### Port Scanning Types

```bash
# TCP Connect Scan (full 3-way handshake)
nmap -sT 192.168.1.100

# SYN Scan (half-open, เร็วกว่า, ต้องการ root)
nmap -sS 192.168.1.100

# UDP Scan
nmap -sU 192.168.1.100

# Version detection
nmap -sV 192.168.1.100

# OS detection
nmap -O 192.168.1.100

# All in one
nmap -A 192.168.1.100

# NULL Scan (เลี่ยง firewall)
nmap -sN 192.168.1.100

# FIN Scan
nmap -sF 192.168.1.100

# Xmas Scan
nmap -sX 192.168.1.100
```

---

## Network Devices

### Hub vs Switch vs Router

```
Hub:     ส่ง traffic ไปทุก port (ไม่ค่อยใช้แล้ว)
Switch:  ส่ง traffic แบบถูกต้องตาม MAC address
Router:  เชื่อม networks ต่างๆ ด้วย IP routing
```

### Firewall Types

| ประเภท | คำอธิบาย |
|---------|----------|
| Packet Filter | ตรวจสอบ header เท่านั้น |
| Stateful | ติดตาม connection state |
| Application | ตรวจสอบ application layer |
| Next-Gen | รวมทุกอย่างพร้อม IPS |

---

## Wireshark Basics

```bash
# เปิด Wireshark
wireshark
sudo wireshark  # ถ้าต้องการ capture

# Command line (tshark)
tshark -i eth0
tshark -i eth0 -w capture.pcap
tshark -r capture.pcap

# Filters
tshark -i eth0 -f "port 80"     # BPF filter
tshark -i eth0 -Y "http"        # Display filter
```

### Display Filters ที่มีประโยชน์

```
http              - HTTP traffic
http.request      - HTTP requests
http.request.method == "POST"  - POST requests
http contains "password"      - packets with "password"
dns               - DNS traffic
tcp.port == 80    - TCP port 80
ip.src == 192.168.1.100       - from specific IP
ip.dst == 192.168.1.200       - to specific IP
tcp.flags.syn == 1            - SYN packets
ssl               - SSL/TLS traffic
smb               - SMB traffic
```

### ดึง Credentials จาก Capture

```bash
# tcpdump - capture ผ่าน command line
sudo tcpdump -i eth0 -w capture.pcap
sudo tcpdump -i eth0 port 80 -A  # ASCII output
sudo tcpdump -i eth0 port 21 -A  # FTP credentials
sudo tcpdump -i eth0 port 23 -A  # Telnet credentials

# วิเคราะห์ pcap file
tshark -r capture.pcap -Y 'http.request.method == "POST"'
strings capture.pcap | grep -i password
```

---

## แบบฝึกหัด

### แบบฝึกหัดที่ 1: ค้นหาเครือข่าย

```bash
# 1. สแกนหา hosts ในเครือข่าย
nmap -sn 192.168.56.0/24

# 2. scan ports ในเครือข่าย
nmap -sV 192.168.56.0/24

# 3. ดู ARP table
ip neigh show

# 4. ทดสอบ DNS
dig 192.168.56.101 PTR
nslookup 192.168.56.101
```

### แบบฝึกหัดที่ 2: Protocol Analysis

```bash
# Capture traffic
sudo tcpdump -i eth0 -c 100 -w /tmp/capture.pcap

# วิเคราะห์ด้วย Wireshark
wireshark /tmp/capture.pcap

# หา HTTP traffic
tshark -r /tmp/capture.pcap -Y 'http'

# หา credentials
tshark -r /tmp/capture.pcap -Y 'ftp'
```

---

## สรุป

| หัวข้อ | สิ่งที่เรียนรู้ |
|--------|----------------|
| OSI Model | 7 layers, แต่ละ layer มีหน้าที่ |
| IP Addressing | Classes, CIDR, Subnetting |
| Protocols | TCP, UDP, DNS, ARP |
| Port Numbers | Well-known ports |
| Scanning | Ping sweep, port scan |

**Part ถัดไป:** [Part 04: TCP/IP Deep Dive](Part-04-TCP-IP-Deep-Dive.md)

---
*Part 03/100 | Kali Linux Course*
