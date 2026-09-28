# Part 07: Virtual Lab Setup - ตั้งค่า Virtual Lab

## สารบัญ
- [ทำไมต้องมี Lab?](#ทำไมต้องมี-lab)
- [VirtualBox Setup](#virtualbox-setup)
- [VMware Setup](#vmware-setup)
- [Kali Linux Setup](#kali-linux-setup)
- [Target VMs](#target-vms)
- [Network Configuration](#network-configuration)
- [Docker Lab](#docker-lab)
- [Online Labs](#online-labs)

---

## ทำไมต้องมี Lab?

ก่อนเจาะระบบจริงต้องฝึกใน **environment ที่ควบคุมได้** เสมอ:

1. **ถูกกฎหมาย** - ทดสอบบนระบบที่คุณเป็นเจ้าของ
2. **ปลอดภัย** - ไม่กระทบระบบจริง
3. **เรียนรู้ได้เร็ว** - ทดลองซ้ำได้ไม่จำกัด
4. **บันทึก** - snapshot ก่อน/หลัง

---

## VirtualBox Setup

### ติดตั้ง VirtualBox

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install virtualbox virtualbox-ext-pack

# Download จาก oracle.com
# https://www.virtualbox.org/wiki/Downloads
```

### ตั้งค่า Host-Only Network

```
1. เปิด VirtualBox
2. ไปที่ File > Host Network Manager
3. กด Create (หรือ +)
4. ตั้งค่า:
   - IPv4 Address: 192.168.56.1
   - IPv4 Network Mask: 255.255.255.0
   - Enable DHCP Server:
     - Server Address: 192.168.56.100
     - Server Mask: 255.255.255.0
     - Lower Address: 192.168.56.101
     - Upper Address: 192.168.56.254
5. กด Apply
```

### สร้าง VM สำหรับ Kali

```
1. กด New
2. Name: Kali Linux
3. Type: Linux
4. Version: Debian (64-bit)
5. Memory: 4096 MB (4GB)
6. Hard Disk: Create a virtual hard disk now
   - Size: 60GB
   - Type: VDI
   - Storage: Dynamically allocated
7. Settings:
   - System > Processor: 2 CPUs
   - System > Enable I/O APIC: Yes
   - Display > Video Memory: 128MB
   - Display > Enable 3D Acceleration: Yes
   - Network > Adapter 1: NAT (internet access)
   - Network > Adapter 2: Host-only Adapter (lab network)
   - Storage > Add ISO: kali-linux.iso
```

---

## Target VMs

### Metasploitable 2

```bash
# Download
# https://sourceforge.net/projects/metasploitable/

# Import ใน VirtualBox:
# 1. สร้าง VM ใหม่ (Linux, Ubuntu 32-bit)
# 2. ใช้ .vmdk ที่ download เป็น hard disk
# 3. Network: Host-only only (ห้ามต่ออินเตอร์เน็ต!)

# Default credentials: msfadmin:msfadmin

# Services ที่มี (vulnerable):
# 21  - vsftpd 2.3.4 (backdoor!)
# 22  - OpenSSH 4.7
# 23  - Telnet
# 25  - Postfix
# 80  - Apache/PHP/DVWA
# 139 - Samba
# 445 - Samba
# 3306 - MySQL
# 5432 - PostgreSQL
# 6667 - UnrealIRCd (backdoor!)
```

### Metasploitable 3

```bash
# ต้องมี Vagrant + VirtualBox

# ติดตั้ง Vagrant
sudo apt install vagrant

# สร้าง Metasploitable 3
mkdir metasploitable3
cd metasploitable3
curl -O https://raw.githubusercontent.com/rapid7/metasploitable3/master/Vagrantfile
vagrant up

# หรือ download OVA โดยตรง
# https://github.com/rapid7/metasploitable3/releases
```

### DVWA (Damn Vulnerable Web Application)

```bash
# ติดตั้งบน Kali
sudo apt install dvwa

# Start services
sudo systemctl start apache2
sudo systemctl start mysql

# ตั้งค่า
sudo mysql -u root
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Access
# http://127.0.0.1/dvwa/setup.php
# กด Create / Reset Database
# Login: admin / password

# ตั้ง Security Level
# DVWA Security > Low (เริ่มต้น)
```

### VulnHub VMs

```bash
# https://vulnhub.com - มี VMs หลายร้อยตัว

# แนะนำสำหรับผู้เริ่มต้น:
# 1. Basic Pentesting: 1 & 2
# 2. DC: 1-9
# 3. Kioptrix Level 1-5
# 4. Mr. Robot
# 5. BoredHackerBlog

# Download .ova file แล้ว import ใน VirtualBox
```

### Windows VMs

```bash
# Microsoft Evaluation VMs (ฟรี 180 วัน)
# https://www.microsoft.com/en-us/evalcenter/
# - Windows Server 2019
# - Windows Server 2022
# - Windows 10 Enterprise
# - Windows 11 Enterprise

# Import ใน VirtualBox:
# 1. แตก zip ที่ download
# 2. import .ova
# 3. Network: Host-only

# สร้าง AD Lab:
# - Windows Server 2019 เป็น Domain Controller
# - Windows 10 เป็น workstation (join domain)
```

---

## Network Configuration

### Lab Network Diagram

```
[Internet]
    |
[Host OS]
    |---[NAT]---[Kali Linux] (eth0=NAT, eth1=192.168.56.101)
    |                            |
    |                     [Host-Only Network]
    |                     192.168.56.0/24
    |---[Host-Only]---[Metasploitable2] (192.168.56.102)
    |                ---[Windows VM]    (192.168.56.103)
    |                ---[DVWA]          (192.168.56.104)
```

### ตั้งค่า Static IP ใน Kali

```bash
# แก้ไข /etc/network/interfaces
sudo nano /etc/network/interfaces

# เพิ่ม:
auto eth1
iface eth1 inet static
    address 192.168.56.101
    netmask 255.255.255.0

# Restart
sudo systemctl restart networking

# ตรวจสอบ
ip addr show eth1
ping 192.168.56.102
```

### ตั้งค่าผ่าน nmcli

```bash
# ดู connections
nmcli connection show

# ตั้งค่า static IP
nmcli con mod "Wired connection 2" ipv4.addresses 192.168.56.101/24
nmcli con mod "Wired connection 2" ipv4.method manual
nmcli con up "Wired connection 2"

# ตรวจสอบ
nmcli device show
```

---

## Docker Lab

```bash
# ติดตั้ง Docker
sudo apt update
sudo apt install docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker kali

# Vulnerable containers

# WebGoat
docker run -p 8080:8080 -p 9090:9090 -t webgoat/webgoat
# Access: http://localhost:8080/WebGoat

# DVWA
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Juice Shop (OWASP)
docker run --rm -p 3000:3000 bkimminich/juice-shop
# Access: http://localhost:3000

# VulnDjango
docker run -p 8000:8000 nVisium/django.nV

# Metasploitable 3
docker pull tleemcjr/metasploitable3
docker run -p 80:80 -p 445:445 -p 22:22 tleemcjr/metasploitable3

# docker-compose vulnerable lab
cat > docker-compose.yml << 'EOF'
version: '3'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "8081:80"
  webgoat:
    image: webgoat/webgoat
    ports:
      - "8082:8080"
  juiceshop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"
EOF

docker-compose up -d
```

---

## Online Labs

### HackTheBox

```bash
# ลงทะเบียนที่ https://hackthebox.com

# เชื่อมต่อ VPN
sudo openvpn your-htb.ovpn

# ตรวจสอบการเชื่อมต่อ
ip addr show tun0
ping 10.10.10.1  # HTB network

# เริ่ม machine ที่ต้องการ
# กดปุ่ม "Join Machine" ใน HTB website
# ได้ IP เช่น 10.10.10.245

# เริ่ม enumerate
nmap -sV -sC 10.10.10.245
```

### TryHackMe

```bash
# ลงทะเบียนที่ https://tryhackme.com
# มี Learning Paths สำหรับผู้เริ่มต้น

# เชื่อมต่อ VPN
sudo openvpn your-thm.ovpn

# ทำ rooms เช่น:
# - Complete Beginner Path
# - Web Fundamentals Path
# - Jr Penetration Tester Path

# เริ่มด้วย rooms เหล่านี้:
# 1. Starting Out In Cyber Sec
# 2. Pre-Security Learning Path
# 3. Linux Fundamentals (Part 1-3)
# 4. Network Exploitation Basics
```

### PentesterLab

```bash
# https://pentesterlab.com
# เน้น Web Application Security
# มี exercises ที่ practical มาก

# Exercises ที่แนะนำ:
# - From SQL injection to Shell
# - Web For Pentester
# - Introduction to Code Review
```

---

## แบบฝึกหัด

### แบบฝึกหัดที่ 1: ตั้งค่า Lab

```bash
# 1. ติดตั้ง VirtualBox + extension pack
# 2. Import Kali Linux OVA
# 3. Import Metasploitable 2
# 4. ตั้งค่า Host-Only Network
# 5. ทดสอบ connectivity

# ทดสอบ:
ping -c 4 192.168.56.102  # ควร ping ได้
nmap -sn 192.168.56.0/24  # ควรเห็น hosts
```

### แบบฝึกหัดที่ 2: Docker Lab

```bash
# 1. ติดตั้ง Docker
# 2. รัน DVWA
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# 3. Access http://localhost/dvwa
# 4. Setup database
# 5. Login
# 6. ตั้ง Security Level = Low

# 7. ทดลองเจาะ SQL Injection page
# Username: ' OR '1'='1
# Password: anything
```

### แบบฝึกหัดที่ 3: First Scan

```bash
# Scan Metasploitable
nmap -sV -sC 192.168.56.102

# บันทึกผล:
# - ports ที่เปิด
# - services ที่รัน
# - versions ต่างๆ

# ค้นหา vulnerabilities
searchsploit vsftpd 2.3.4
# ควรพบ: unix/remote/17491.rb
```

---

## สรุป

| Component | Role |
|-----------|------|
| Kali Linux | Attacker machine |
| Metasploitable 2 | Vulnerable Linux target |
| DVWA | Vulnerable web app |
| Windows Server | AD/Windows target |
| VulnHub VMs | Additional targets |
| HTB/TryHackMe | Online practice |

**Part ถัดไป:** [Part 08: Network Configuration](Part-08-Network-Configuration.md)

---
*Part 07/100 | Kali Linux Course*
