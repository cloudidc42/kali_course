# Part 17: Active Reconnaissance with Nmap
## การสืบค้นเชิงรุก - Nmap พื้นฐาน

---

## สารบัญ
1. [Nmap Overview](#overview)
2. [Scan Types](#scan-types)
3. [Host Discovery](#host-discovery)
4. [Port Scanning](#port-scanning)
5. [Service Detection](#service-detection)
6. [OS Detection](#os-detection)
7. [Nmap Scripting Engine (NSE)](#nse)
8. [Output Formats](#output)
9. [แบบฝึกหัด](#exercises)

---

## 1. Nmap Overview {#overview}

**Nmap (Network Mapper)** เป็นเครื่องมือ open-source สำหรับการสำรวจเครือข่ายและตรวจสอบความปลอดภัย

```bash
# ติดตั้ง
apt install nmap -y
nmap --version

# เริ่มใช้งาน
# nmap [scan_type] [options] [target]
nmap 192.168.1.1              # Basic scan
nmap 192.168.1.0/24          # Scan network
nmap 192.168.1.1-50          # Range
nmap -iL targets.txt          # From file
```

### Target Specification

```bash
nmap 192.168.1.1               # Single IP
nmap 192.168.1.1-254           # Range
nmap 192.168.1.0/24            # CIDR
nmap 10.0.0.0/8                # Large network
nmap host1 host2 host3         # Multiple hosts
nmap -iL hosts.txt             # From file
nmap --exclude 192.168.1.1     # Exclude
nmap --excludefile exclude.txt # Exclude from file

# Random targets
nmap -iR 100 --open            # 100 random hosts
```

---

## 2. Scan Types {#scan-types}

### TCP Scan Types

```bash
# SYN Scan (แนะนำ - Stealth)
nmap -sS 192.168.1.1
# ส่ง SYN, รับ SYN/ACK (เปิด) หรือ RST (ปิด)
# ไม่ complete handshake -> log น้อยกว่า

# TCP Connect Scan
nmap -sT 192.168.1.1
# Full TCP handshake
# ไม่ต้องการ root

# ACK Scan (Firewall rule mapping)
nmap -sA 192.168.1.1
# ส่ง ACK - ยังแน่ RST = unfiltered
# ไม่ใช้หาว่า open หรือไม่ open

# Window Scan
nmap -sW 192.168.1.1

# Maimon Scan (FIN/ACK)
nmap -sM 192.168.1.1

# NULL Scan (no flags)
nmap -sN 192.168.1.1

# FIN Scan
nmap -sF 192.168.1.1

# Xmas Scan (FIN/PSH/URG)
nmap -sX 192.168.1.1

# Idle Scan (เซ็นที่สุด)
nmap -sI zombie_host 192.168.1.1
```

### UDP Scan

```bash
# UDP Scan
nmap -sU 192.168.1.1
nmap -sU -p 53,67,68,69,123,161,162 192.168.1.1

# UDP + TCP combined
nmap -sS -sU 192.168.1.1

# ช้ากว่า TCP - ใช้เวลานาน
# เพราะ UDP ต้องรอ timeout
```

---

## 3. Host Discovery {#host-discovery}

### Ping Sweep

```bash
# Ping sweep (เพียงหาว่าฮอสต์ up หรือไม่)
nmap -sn 192.168.1.0/24

# ICMP ping
nmap -PE 192.168.1.0/24  # Echo request
nmap -PM 192.168.1.0/24  # Timestamp
nmap -PP 192.168.1.0/24  # Netmask

# TCP ping (port 80, 443)
nmap -PS80,443 192.168.1.0/24  # SYN ping
nmap -PA80,443 192.168.1.0/24  # ACK ping

# UDP ping
nmap -PU 192.168.1.0/24

# ARP ping (ดีที่สุดใน LAN)
nmap -PR 192.168.1.0/24

# ไม่ ping scan (no host discovery)
nmap -Pn 192.168.1.1  # เสมือนว่า host up เสมอ

# DNS resolution
nmap -n 192.168.1.0/24  # no DNS
nmap -R 192.168.1.0/24  # always resolve DNS

# Output เฉพาะ IPs
nmap -sn 192.168.1.0/24 | grep 'report for' | awk '{print $5}'
```

---

## 4. Port Scanning {#port-scanning}

### Port Specification

```bash
# แบบพื้นฐาน (1000 common ports)
nmap 192.168.1.1

# พอร์ตเดียว
nmap -p 80 192.168.1.1

# หลายพอร์ต
nmap -p 80,443,8080,8443 192.168.1.1

# Range
nmap -p 1-1024 192.168.1.1
nmap -p 80-100 192.168.1.1

# ทุกพอร์ต (65535)
nmap -p- 192.168.1.1

# Top ports
nmap --top-ports 100 192.168.1.1
nmap --top-ports 1000 192.168.1.1

# เฉพาะเปิด
nmap --open 192.168.1.1

# Fast scan (100 ports)
nmap -F 192.168.1.1
```

### Timing Templates

```bash
# T0 - Paranoid (very slow, IDS evasion)
nmap -T0 192.168.1.1  # 5 minute delay

# T1 - Sneaky (slow)
nmap -T1 192.168.1.1  # 15 second delay

# T2 - Polite (slow)
nmap -T2 192.168.1.1

# T3 - Normal (default)
nmap -T3 192.168.1.1

# T4 - Aggressive (fast, LAN)
nmap -T4 192.168.1.1

# T5 - Insane (very fast, noisy)
nmap -T5 192.168.1.1
```

---

## 5. Service Detection {#service-detection}

```bash
# Service/Version detection
nmap -sV 192.168.1.1

# ความเข้ม (1=light, 9=max)
nmap -sV --version-intensity 5 192.168.1.1
nmap -sV --version-all 192.168.1.1  # intensity 9

# Light detection
nmap -sV --version-light 192.168.1.1  # intensity 2

# Combined
nmap -sV -sC 192.168.1.1  # Service + scripts

# ผลลัพธ์ที่คาดว่า:
# PORT     STATE SERVICE VERSION
# 22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
# 80/tcp   open  http    Apache httpd 2.4.41
# 3306/tcp open  mysql   MySQL 8.0.27
```

---

## 6. OS Detection {#os-detection}

```bash
# OS Detection
nmap -O 192.168.1.1

# กำหนด guess แม้ไม่แน่ใจ
nmap -O --osscan-guess 192.168.1.1

# OS + version combined
nmap -A 192.168.1.1  # -O -sV -sC --traceroute

# ผลลัพธ์ที่คาดว่า:
# OS details: Linux 4.15 - 5.6
# OS CPE: cpe:/o:linux:linux_kernel:4
# Aggressive OS guesses: Linux 4.15 (95%)

# Traceroute
nmap --traceroute 192.168.1.1
```

---

## 7. Nmap Scripting Engine (NSE) {#nse}

### NSE พื้นฐาน

```bash
# รัน default scripts (-sC)
nmap -sC 192.168.1.1

# รัน script เดียว
nmap --script=http-title 192.168.1.1

# รันหลาย scripts
nmap --script="http-headers,http-methods" 192.168.1.1

# รัน category
nmap --script=vuln 192.168.1.1       # Vulnerability scripts
nmap --script=safe 192.168.1.1       # Safe scripts
nmap --script=discovery 192.168.1.1  # Discovery scripts
nmap --script=auth 192.168.1.1       # Authentication checks
nmap --script=brute 192.168.1.1      # Brute force
nmap --script=exploit 192.168.1.1    # Exploits

# Wildcard
nmap --script="http-*" 192.168.1.1      # All http scripts
nmap --script="smb-*" 192.168.1.1       # All smb scripts
nmap --script="ftp-*" 192.168.1.1       # All ftp scripts

# Script arguments
nmap --script=http-brute --script-args="http-brute.path=/login,userdb=/tmp/users.txt,passdb=/tmp/pass.txt" 192.168.1.1
```

### สำคัญ NSE Scripts

```bash
# === HTTP ===
nmap --script=http-title 192.168.1.1 -p 80,443,8080
nmap --script=http-headers 192.168.1.1
nmap --script=http-methods 192.168.1.1
nmap --script=http-robots.txt 192.168.1.1
nmap --script=http-shellshock 192.168.1.1  # Shellshock
nmap --script=http-heartbleed 192.168.1.1  # Heartbleed
nmap --script=http-sql-injection 192.168.1.1  # SQL injection
nmap --script=http-cross-domain-policy 192.168.1.1
nmap --script=http-auth-finder 192.168.1.1
nmap --script=http-enum 192.168.1.1  # Directory enumeration

# === SMB ===
nmap --script=smb-os-discovery 192.168.1.1
nmap --script=smb-security-mode 192.168.1.1
nmap --script=smb-vuln-ms17-010 192.168.1.1  # EternalBlue
nmap --script=smb-vuln-ms08-067 192.168.1.1
nmap --script=smb2-security-mode 192.168.1.1
nmap --script=smb-enum-shares 192.168.1.1
nmap --script=smb-enum-users 192.168.1.1

# === FTP ===
nmap --script=ftp-anon 192.168.1.1  # Anonymous login
nmap --script=ftp-bounce 192.168.1.1
nmap --script=ftp-brute 192.168.1.1
nmap --script=ftp-syst 192.168.1.1

# === SSH ===
nmap --script=ssh-auth-methods 192.168.1.1
nmap --script=ssh-brute 192.168.1.1
nmap --script=ssh-hostkey 192.168.1.1
nmap --script=ssh2-enum-algos 192.168.1.1

# === MySQL ===
nmap --script=mysql-empty-password 192.168.1.1 -p 3306
nmap --script=mysql-brute 192.168.1.1 -p 3306
nmap --script=mysql-databases 192.168.1.1 -p 3306
nmap --script=mysql-info 192.168.1.1 -p 3306

# === DNS ===
nmap --script=dns-zone-transfer 192.168.1.1 -p 53
nmap --script=dns-brute 192.168.1.1 -p 53
nmap --script=dns-recursion 192.168.1.1 -p 53

# === SNMP ===
nmap --script=snmp-info 192.168.1.1 -p 161 -sU
nmap --script=snmp-brute 192.168.1.1 -p 161 -sU
nmap --script=snmp-interfaces 192.168.1.1 -p 161 -sU
```

---

## 8. Output Formats {#output}

```bash
# Normal output
nmap -oN output.txt 192.168.1.1

# XML output (สำหรับ tools อื่นๆ)
nmap -oX output.xml 192.168.1.1

# Grepable output
nmap -oG output.gnmap 192.168.1.1

# Script kiddie output
nmap -oS output.txt 192.168.1.1

# All formats (-oN, -oX, -oG)
nmap -oA output_prefix 192.168.1.1
# สร้าง: output_prefix.nmap, output_prefix.xml, output_prefix.gnmap

# Verbose
nmap -v 192.168.1.1
nmap -vv 192.168.1.1  # เพิ่มเติม

# แสดง progress
nmap -v --stats-every 5s 192.168.1.0/24
```

### Parse XML Output

```python
#!/usr/bin/env python3
# parse_nmap_xml.py

import xml.etree.ElementTree as ET

def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    results = []
    for host in root.findall('host'):
        if host.find('status').get('state') != 'up':
            continue
        
        # Get IP
        addr = host.find('address[@addrtype="ipv4"]')
        ip = addr.get('addr') if addr is not None else 'unknown'
        
        # Get hostname
        hostnames = host.find('hostnames')
        hostname = ''
        if hostnames is not None:
            hn = hostnames.find('hostname')
            hostname = hn.get('name') if hn is not None else ''
        
        # Get ports
        ports = []
        for port in host.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                service = port.find('service')
                service_name = service.get('name', '') if service is not None else ''
                product = service.get('product', '') if service is not None else ''
                version = service.get('version', '') if service is not None else ''
                
                ports.append({
                    'port': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'service': service_name,
                    'product': product,
                    'version': version
                })
        
        results.append({
            'ip': ip,
            'hostname': hostname,
            'ports': ports
        })
    
    return results

# ใช้งาน
results = parse_nmap('output.xml')
for host in results:
    print(f"Host: {host['ip']} ({host['hostname']})")
    for port in host['ports']:
        print(f"  {port['port']}/{port['protocol']} {port['service']} {port['product']} {port['version']}")
```

---

## 9. แบบฝึกหัด {#exercises}

### Lab 1: Network Discovery
```bash
# Discover live hosts
nmap -sn 192.168.1.0/24 -oN /tmp/live_hosts.txt

# ดูรายชื่อ host
grep 'report for' /tmp/live_hosts.txt | awk '{print $5}'
```

### Lab 2: Service Enumeration
```bash
# Full scan บน single host
nmap -sV -sC -O -p- --open -oA full_scan 192.168.1.100

# ดูสิ่งที่น่าสนใจ
cat full_scan.nmap | grep -E 'open|VERSION'
```

### Lab 3: Vulnerability Scan
```bash
# Scan สำหรับ vulnerabilities
nmap --script=vuln -p 80,443,445,3306 192.168.1.100

# วิเคราะห์ผลลัพธ์
```

---

## สรุป Nmap Flags

```
-sS  SYN scan (stealth)
-sT  TCP connect
-sU  UDP scan
-sV  Service version
-sC  Default scripts
-O   OS detection
-A   All (OS+service+scripts+traceroute)
-T4  Fast timing
-p-  All ports
-Pn  No ping
-n   No DNS
--open  Open ports only
-oA  All output formats
-v   Verbose
```

---
*Part 17/100+ | Kali Linux Penetration Testing Course*
