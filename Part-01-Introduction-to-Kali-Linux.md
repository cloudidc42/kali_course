# Part 01: Introduction to Kali Linux - แนะนำ Kali Linux

## สารบัญ
- [Kali Linux คืออะไร?](#kali-linux-คืออะไร)
- [ประวัติและที่มา](#ประวัติและที่มา)
- [วิธีติดตั้ง Kali Linux](#วิธีติดตั้ง-kali-linux)
- [การตั้งค่าเบื้องต้น](#การตั้งค่าเบื้องต้น)
- [เครื่อมือสำคัญ](#เครื่อมือสำคัญ)
- [แบบฝึกหัด](#แบบฝึกหัด)

---

## Kali Linux คืออะไร?

**Kali Linux** คือ Linux distribution ที่ออกแบบมาเพื่อ **Penetration Testing** (Ethical Hacking) โดยเฉพาะ พัฒนาโดย **Offensive Security** เป็นตัวทายาทของ BackTrack Linux

### คุณสมบัติหลัก
- บน Debian GNU/Linux 
- มีเครื่อมือ Security 600+ ตัว
- Open Source & ฟรี
- อัปเดตสม่ำเสมอ
- รองรับ Architecture หลายตัว (x86, x64, ARM, MIPS)

### ใช้ทำอะไร?
1. **Penetration Testing** - ทดสอบบุกระบบอย่างถูกต้องตามกฎหมาย
2. **Security Research** - วิจัยช่องโหว่ Vulnerability
3. **CTF (Capture The Flag)** - แข่งขัน Security
4. **Digital Forensics** - สืบสวนหลักฐานดิจิทัล
5. **Malware Analysis** - วิเคราะห์ Malware
6. **Network Security** - ตรวจสอบความปลอดภัยเครือข่าย

---

## ประวัติและที่มา

### Timeline
```
2006 - Whax และ Auditor Security Collection รวมกัน
2007 - BackTrack 1.0 เปิดตัว
2008 - BackTrack 2.0 (Ubuntu-based)
2010 - BackTrack 4.0 ผลักดันมาก
2012 - BackTrack 5.0 เปลี่ยนเป็น BackTrack R3
2013 - Kali Linux 1.0 เปิดตัว (เปลี่ยนจาก BackTrack)
2015 - Kali Linux 2.0 (Rolling Release)
2019 - Kali Linux 2019.4 (เปลี่ยน Desktop เป็น Xfce default)
2020 - Kali Linux 2020.1 (Non-Root User เป็น default)
2022 - Kali Linux 2022.x (เพิ่ม Kali Purple, Kali Everything)
2024 - Kali Linux 2024.x (ความสามารถใหม่ๆ)
```

### ผู้พัฒนา
- **Offensive Security** - บริษัท Security ชื่อดัง
- Mati Aharoni (muts) - ผู้ร่วมสร้าง
- Devon Kearns - ผู้ร่วมสร้าง

---

## วิธีติดตั้ง Kali Linux

### วิธีที่ 1: ติดตั้งบน VirtualBox (แนะนำสำหรับผู้เริ่มต้น)

#### ความต้องการขั้นต่ำ
- RAM: 4GB+ (แนะนำ 8GB+)
- CPU: 2 cores+ (แนะนำ 4 cores)
- Storage: 30GB+ (แนะนำ 60GB+)
- VirtualBox 7.x ติดตั้งแล้ว

#### ขั้นตอนการติดตั้ง

**ขั้นที่ 1: Download Kali Linux**
ไปที่ https://www.kali.org/get-kali/ และ download:
- **Installer** - สำหรับติดตั้ง bare metal
- **Virtual Machine** - สำหรับ VirtualBox/VMware (แนะนำ)
- **Live Boot** - รันจาก USB

**ขั้นที่ 2: import OVA file**
```
1. เปิด VirtualBox
2. ไปที่ File > Import Appliance
3. เลือกไฟล์ .ova ที่ download
4. กด Next > Import
5. รอจนกระบวนการเสร็จ
```

**ขั้นที่ 3: ตั้งค่า VM settings**
```
- RAM: 4096MB (4GB) ขึ้นไป
- CPU: 2 cores ขึ้นไป
- Network: NAT หรือ Host-only Adapter
- Video: 128MB
- Display: Enable 3D Acceleration
```

**ขั้นที่ 4: เปิด VM**
- Default credentials: `kali / kali`
- เปลี่ยน password ทันที!

### วิธีที่ 2: ติดตั้งบน Bare Metal

#### ขั้นตอน
1. Download ISO file จาก kali.org
2. สร้าง Bootable USB ด้วย Rufus หรือ balenaEtcher
3. Boot จาก USB
4. เลือก Graphical Install
5. ทำตามขั้นตอนการติดตั้ง

```bash
# สร้าง bootable USB ด้วย dd (Linux/Mac)
sudo dd if=kali-linux-2024.1-installer-amd64.iso of=/dev/sdb bs=4M status=progress
sync
```

### วิธีที่ 3: Kali Linux WSL2 (Windows)

```powershell
# เปิด PowerShell as Administrator
wsl --install -d kali-linux

# หลังติดตั้ง update packages
sudo apt update && sudo apt upgrade -y

# ติดตั้ง tools เพิ่มเติม
sudo apt install -y kali-linux-default
```

---

## การตั้งค่าเบื้องต้น

### 1. อัปเดต System

```bash
# อัปเดต package list และ upgrade
sudo apt update && sudo apt full-upgrade -y

# ทำความสะอาด packages เก่า
sudo apt autoremove -y
sudo apt autoclean

# ตรวจสอบ version
cat /etc/os-release
uname -a
```

**Expected Output:**
```
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
ID=kali
VERSION_CODENAME=kali-rolling

Linux kali 6.6.9-amd64 #1 SMP PREEMPT Debian 6.6.9-1kali1 (2024-01-08) x86_64 GNU/Linux
```

### 2. เปลี่ยน Password

```bash
# เปลี่ยน password สำหรับ user ปัจจุบัน
passwd

# เปลี่ยน root password
sudo passwd root
```

### 3. ตั้งค่า SSH

```bash
# เปิด SSH service
sudo systemctl enable ssh
sudo systemctl start ssh

# ตรวจสอบ status
sudo systemctl status ssh

# ดู IP address
ip addr show
hostname -I
```

### 4. ติดตั้ง Tools เพิ่มเติม

```bash
# ติดตั้ง tool sets ต่างๆ
sudo apt install -y kali-tools-web
sudo apt install -y kali-tools-wireless
sudo apt install -y kali-tools-exploitation
sudo apt install -y kali-tools-forensics
sudo apt install -y kali-tools-passwords

# หรือติดตั้งทุกอย่าง (ต้องการ storage เยอะ)
sudo apt install -y kali-linux-everything
```

### 5. ตั้งค่า Terminal

```bash
# ติดตั้ง Terminator (terminal ที่แนะนำ)
sudo apt install -y terminator

# ตั้งค่า Zsh (shell ที่ดีกว่า)
chsh -s /bin/zsh

# ติดตั้ง Oh My Zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```

---

## เครื่อมือสำคัญ

### Information Gathering
| เครื่องมือ | วัตถุประสงค์ |
|-----------|-------------|
| nmap | Network scanning & enumeration |
| recon-ng | Web reconnaissance framework |
| maltego | OSINT & relationship mapping |
| whois | Domain information lookup |
| dig | DNS query tool |
| theHarvester | Email/domain/IP gathering |
| Shodan | IoT & internet device search |

### Vulnerability Analysis
| เครื่องมือ | วัตถุประสงค์ |
|-----------|-------------|
| nessus | Vulnerability scanner (commercial) |
| openvas | Open-source vulnerability scanner |
| nikto | Web server scanner |
| sqlmap | SQL injection automation |
| burpsuite | Web application security testing |

### Exploitation
| เครื่องมือ | วัตถุประสงค์ |
|-----------|-------------|
| metasploit | Exploitation framework |
| msfvenom | Payload generation |
| searchsploit | Exploit database search |
| BeEF | Browser exploitation |

### Post-Exploitation
| เครื่องมือ | วัตถุประสงค์ |
|-----------|-------------|
| meterpreter | Advanced payload shell |
| empire | Post-exploitation framework |
| mimikatz | Credential extraction |
| bloodhound | Active Directory mapping |

### Password Attacks
| เครื่องมือ | วัตถุประสงค์ |
|-----------|-------------|
| hashcat | GPU password cracking |
| john | CPU password cracking |
| hydra | Online brute force |
| medusa | Parallel login brute force |

### Wireless
| เครื่องมือ | วัตถุประสงค์ |
|-----------|-------------|
| aircrack-ng | WEP/WPA cracking suite |
| wireshark | Packet capture & analysis |
| kismet | Wireless network detector |
| wifite | Automated wireless attacks |

---

## Directory Structure ของ Kali Linux

```
/
├── bin/          # Essential command binaries
├── boot/         # Boot files
├── dev/          # Device files
├── etc/          # System configuration files
│   ├── network/  # Network configuration
│   ├── ssh/      # SSH configuration
│   └── apt/      # Package manager config
├── home/         # User home directories
│   └── kali/     # Kali user home
├── opt/          # Optional software (tools ต่างๆ)
├── proc/         # Process information
├── root/         # Root user home
├── sys/          # System files
├── tmp/          # Temporary files
├── usr/          # User programs
│   ├── bin/      # User binaries
│   ├── share/    # Shared data (wordlists, etc.)
│   └── local/    # Locally installed software
└── var/          # Variable data
    ├── log/      # Log files
    └── www/      # Web server files
```

### Kali Tools Location
```bash
# ดู path ของ tool
which nmap
which metasploit
which burpsuite

# Tools ส่วนใหญ่อยู่ที่
/usr/bin/
/usr/sbin/
/opt/

# Wordlists
ls /usr/share/wordlists/
# rockyou.txt.gz  dirbuster/  fasttrack.txt  ...

# Metasploit
/usr/share/metasploit-framework/

# Scripts
/usr/share/nmap/scripts/
```

---

## การตั้งค่า Network สำหรับ Lab

### รูปแบบ Network ที่แนะนำ

```
[Internet] --- [Host OS] --- [VirtualBox/VMware]
                                 |
                    ┌────────────┴─────────────┐
                    │                          │
              [Kali Linux VM]    [Target VM (Metasploitable)]
              192.168.56.101    192.168.56.102
```

### ตั้งค่า Host-Only Network

```bash
# ใน VirtualBox: File > Host Network Manager
# สร้าง Host-Only Adapter: 192.168.56.0/24

# ตั้งค่า network interface ใน Kali
sudo nano /etc/network/interfaces

# เพิ่ม:
auto eth0
iface eth0 inet dhcp

auto eth1
iface eth1 inet static
  address 192.168.56.101
  netmask 255.255.255.0

# Restart networking
sudo systemctl restart networking
```

### ทดสอบ Connectivity

```bash
# ทดสอบ ping
ping -c 4 google.com
ping -c 4 192.168.56.102

# ดู routing table
ip route show
route -n

# ดู active connections
ss -tuln
netstat -tuln
```

---

## Kali Linux Editions

### เวอร์ชันต่างๆ

| Edition | คำอธิบาย | ใช้สำหรับ |
|---------|---------|----------|
| Kali Linux | Standard desktop version | ทั่วไป |
| Kali NetHunter | Android mobile version | Mobile testing |
| Kali Purple | Defensive security version | Blue team |
| Kali ARM | ARM devices (Raspberry Pi) | IoT testing |
| Kali Containers | Docker/LXC containers | CI/CD pipelines |
| Kali WSL | Windows Subsystem for Linux | Windows users |
| Kali Undercover | ซ่อน KDE เป็น Windows 10 | Stealth |

### ตรวจสอบ Tools ที่มีใน Kali

```bash
# ดู tools ทั้งหมด
apt list --installed | grep kali

# ดู package groups
apt-cache search kali-tools

# ดูรายการ:
kali-tools-information-gathering  # Recon tools
kali-tools-vulnerability           # Vuln scanners
kali-tools-web                     # Web testing
kali-tools-database                # Database attacks
kali-tools-passwords               # Password cracking
kali-tools-wireless                # Wireless attacks
kali-tools-reverse-engineering     # RE tools
kali-tools-exploitation            # Exploit tools
kali-tools-sniffing-spoofing       # Sniffing tools
kali-tools-post-exploitation       # Post-exploitation
kali-tools-forensics               # Forensics tools
kali-tools-social-engineering      # SE tools
```

---

## Penetration Testing Methodology

### PTES (Penetration Testing Execution Standard)

```
Phase 1: Pre-engagement
├── กำหนดขอบเขต (Scope)
├── เป้าหมาย (Objectives)
├── กฎหมาย & สัญญา
└── ระยะเวลา

Phase 2: Intelligence Gathering
├── OSINT
├── Active Reconnaissance
└── Passive Reconnaissance

Phase 3: Threat Modeling
├── ประเมินความเสี่ยง
└── วางแผนการโจมตี

Phase 4: Vulnerability Analysis
├── Automated Scanning
└── Manual Testing

Phase 5: Exploitation
├── ใช้ประโยชน์จากช่องโหว่
└── ขยายการเข้าถึง

Phase 6: Post-Exploitation
├── Privilege Escalation
├── Lateral Movement
├── Data Exfiltration
└── Persistence

Phase 7: Reporting
├── Executive Summary
├── Technical Findings
├── Risk Assessment
└── Remediation Recommendations
```

### OWASP Testing Guide

สำหรับ Web Application Penetration Testing:

1. Information Gathering
2. Configuration Management Testing
3. Identity Management Testing
4. Authentication Testing
5. Authorization Testing
6. Session Management Testing
7. Input Validation Testing
8. Error Handling
9. Cryptography Testing
10. Business Logic Testing
11. Client-Side Testing

---

## คำสั่งพื้นฐานที่ต้องรู้

### การจัดการ Services

```bash
# เปิด/ปิด/restart service
sudo systemctl start apache2
sudo systemctl stop apache2
sudo systemctl restart apache2
sudo systemctl status apache2

# เปิด service อัตโนมัติเมื่อ boot
sudo systemctl enable ssh
sudo systemctl enable postgresql

# ดู services ทั้งหมด
sudo systemctl list-units --type=service
```

### การจัดการ Packages

```bash
# อัปเดต
sudo apt update
sudo apt upgrade
sudo apt full-upgrade

# ติดตั้ง
sudo apt install <package-name>

# ลบ
sudo apt remove <package-name>
sudo apt purge <package-name>  # ลบพร้อม config

# ค้นหา
apt search <keyword>
apt-cache search <keyword>

# ดูข้อมูล package
apt show <package-name>
```

### Network Commands

```bash
# ดู IP address
ip addr show
ifconfig  # deprecated แต่ยังใช้งานได้

# ดู routing
ip route show

# Scan network
nmap -sn 192.168.1.0/24

# ดู open ports
ss -tulpn
netstat -tulpn

# Capture traffic
sudo tcpdump -i eth0
sudo wireshark  # GUI
```

---

## การตั้งค่า VPN

```bash
# ติดตั้ง OpenVPN
sudo apt install openvpn

# เชื่อมต่อกับ HackTheBox/TryHackMe
sudo openvpn your-vpn-file.ovpn

# ตรวจสอบ VPN connection
ip addr show tun0
ping 10.10.10.1  # HTB network

# ตัดการเชื่อมต่อ
sudo killall openvpn
```

---

## Useful Aliases สำหรับ Hacker

```bash
# เพิ่มใน ~/.zshrc หรือ ~/.bashrc

# Nmap shortcuts
alias nmap-quick='nmap -sCV --min-rate 5000'
alias nmap-full='nmap -sCV -p- --min-rate 5000'
alias nmap-udp='nmap -sU --top-ports 100'

# Network
alias myip='curl ifconfig.me'
alias localip='hostname -I'

# Python server
alias serve='python3 -m http.server 8080'

# Wordlists
alias rockyou='cat /usr/share/wordlists/rockyou.txt.gz | gunzip'

# Metasploit
alias msfdb-reset='sudo msfdb reinit'

# Reload config
alias reload='source ~/.zshrc'
```

---

## Lab Setup - Metasploitable 2

### ดาวน์โหลดและติดตั้ง Metasploitable 2

```bash
# Metasploitable 2 เป็น VM ที่เจตนาให้มีช่องโหว่
# Download จาก: https://sourceforge.net/projects/metasploitable/

# Import ใน VirtualBox:
# 1. สร้าง VM ใหม่ (Linux, Ubuntu 32-bit)
# 2. ใช้ .vmdk ที่ download มาเป็น hard disk
# 3. ตั้ง Network เป็น Host-only

# Default credentials: msfadmin:msfadmin
```

### ทดสอบว่า Lab ทำงาน

```bash
# จาก Kali ทดสอบ ping ไปที่ Metasploitable
ping -c 4 192.168.56.102  # ปรับ IP ตามจริง

# Scan ports
nmap -sV 192.168.56.102

# Expected output จะเห็น ports หลายตัว:
# 21/tcp   open  ftp     vsftpd 2.3.4
# 22/tcp   open  ssh     OpenSSH 4.7p1
# 23/tcp   open  telnet
# 25/tcp   open  smtp
# 80/tcp   open  http    Apache httpd 2.2.8
# ...
```

---

## Tips และ Tricks

### ประสิทธิภาพ VM

```bash
# เพิ่มความเร็ว Kali VM
# 1. ใช้ SSD แทน HDD
# 2. เพิ่ม RAM เป็น 4-8GB
# 3. เปิด Hardware Acceleration
# 4. ลด visual effects

# ปิด services ที่ไม่ใช้
sudo systemctl disable bluetooth
sudo systemctl disable cups
sudo systemctl disable avahi-daemon
```

### Keyboard Shortcuts ที่มีประโยชน์

```
Ctrl+Alt+T     - เปิด Terminal
Ctrl+Shift+T   - เปิด Terminal ใหม่
Ctrl+L         - Clear terminal
Ctrl+R         - Search command history
Ctrl+C         - ยกเลิก command
Ctrl+Z         - Suspend process
bg             - Run suspended process in background
fg             - Bring background process to foreground
```

### Security Research Resources

```
เว็บไซต์ที่มีประโยชน์:
- exploit-db.com    - Exploit database
- cve.mitre.org     - CVE database  
- nvd.nist.gov      - National Vulnerability Database
- packetstormsecurity.com - Security advisories
- github.com/swisskyrepo/PayloadsAllTheThings - Payloads
- book.hacktricks.xyz - Hacking knowledge base
- gtfobins.github.io  - Linux privilege escalation
- lolbas-project.github.io - Windows living off the land
```

---

## แบบฝึกหัด

### แบบฝึกหัดที่ 1: ติดตั้ง Lab

1. ติดตั้ง VirtualBox บน Host OS
2. Download และ import Kali Linux VM
3. Download และ import Metasploitable 2
4. ตั้งค่า Host-Only Network
5. ทดสอบ connectivity ระหว่าง VMs

### แบบฝึกหัดที่ 2: ทดสอบ Kali Tools

```bash
# ทดสอบ nmap
nmap --version

# ทดสอบ metasploit
msfconsole --version

# ทดสอบ burpsuite
burpsuite

# ทดสอบ wireshark
wireshark
```

### แบบฝึกหัดที่ 3: Basic Scan

```bash
# Scan Metasploitable VM
nmap -sV 192.168.56.102

# ดูผลลัพธ์และจดบันทึก:
# - services ที่เปิดอยู่
# - versions ของ services
# - OS ที่ใช้งาน
```

---

## สรุป

| หัวข้อ | สิ่งที่เรียนรู้ |
|--------|----------------|
| Kali Linux | OS สำหรับ Penetration Testing |
| การติดตั้ง | VirtualBox VM, Bare Metal, WSL2 |
| Tools Overview | 600+ security tools |
| Lab Setup | Kali + Metasploitable |
| Methodology | PTES Framework |

**Part ถัดไป:** [Part 02: Linux Command Line Fundamentals](Part-02-Linux-Command-Line-Fundamentals.md)

---
*Part 01/100 | Kali Linux Course | Ethical Hacking & Penetration Testing*
