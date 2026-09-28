# Part 84: Digital Forensics

> **หลักสูตร Kali Linux จากระดับพื้นฐานถึงระดับโลก**  
> ← [Part 83: Malware Analysis](Part-83-Malware-Analysis.md) | [Part 85: OSINT Advanced](Part-85-OSINT-Advanced.md) →

---

## สารบัญ

1. [พื้นฐาน Digital Forensics](#1-พื้นฐาน-digital-forensics)
2. [Disk Forensics](#2-disk-forensics)
3. [Memory Forensics](#3-memory-forensics)
4. [Network Forensics](#4-network-forensics)
5. [Log Analysis](#5-log-analysis)
6. [File System Analysis](#6-file-system-analysis)
7. [Email Forensics](#7-email-forensics)
8. [Browser Forensics](#8-browser-forensics)
9. [Timeline Analysis](#9-timeline-analysis)
10. [Forensic Report Writing](#10-forensic-report-writing)

---

## 1. พื้นฐาน Digital Forensics

### 1.1 Forensics Process

```
Digital Forensics Methodology:

1. Identification
   └─ ระบุแหล่งข้อมูลที่เกี่ยวข้อง
   └─ ทำความเข้าใจขอบเขตการสืบสวน

2. Preservation
   └─ หยุดการเปลี่ยนแปลงหลักฐาน
   └─ ไอโรตอุปกรณ์ทันที
   └─ Chain of Custody

3. Collection
   └─ เก็บหลักฐานดิจิทัล
   └─ ใช้วิธี forensically sound
   └─ ตรวจสอบ hash integrity

4. Examination
   └─ วิเคราะห์ข้อมูลที่เก็บได้
   └─ ค้นหา artifacts และ IOCs

5. Analysis
   └─ สร้าง timeline
   └─ ไขกระแสเหตุการณ์

6. Reporting
   └─ สรุปสิ่งที่ค้นพบ
   └─ เขียนรายงานทางปฏิบัติการ
```

### 1.2 เครื่องมือหลัก

```bash
# ติดตั้งเครื่องมือ forensics
sudo apt install -y \
    autopsy \
    sleuthkit \
    volatility3 \
    binwalk \
    foremost \
    testdisk \
    photorec \
    bulk-extractor \
    dcfldd

pip3 install \
    volatility3 \
    artifacts-kb \
    dfvfs \
    pyewf

# ติดตั้ง Autopsy (GUI forensics platform)
sudo apt install autopsy
autopsy &  # เปิด web interface ที่ http://localhost:9999
```

---

## 2. Disk Forensics

### 2.1 การสร้าง Forensic Image

```bash
# สร้าง disk image ด้วย dd
sudo dd if=/dev/sdb of=/evidence/disk.img bs=4M status=progress

# คำนวณ hash เพื่อตรวจสอป integrity
md5sum /evidence/disk.img
sha256sum /evidence/disk.img

# ใช้ dcfldd (เพิ่ม hashing ระหว่างหน้าม่)
dcfldd if=/dev/sdb hash=md5,sha256 \
    hashwindow=1G hashlog=/evidence/hash.log \
    of=/evidence/disk.img bs=4M

# Mount image แบบ read-only
sudo mkdir /mnt/evidence
sudo mount -o ro,loop /evidence/disk.img /mnt/evidence

# ใช้ ewftools สำหรับ E01 format (EnCase)
sudo apt install libewf-dev
ewfacquire /dev/sdb -c deflate -o /evidence/disk.E01
```

### 2.2 Partition และ File System Analysis

```bash
# ดู partition table
mmls /evidence/disk.img
# Output:
# DOS Partition Table
# Offset Sector: 0
# Units are in 512-byte sectors
# Slot  Start  End    Size   Description
# 000   2048   1026047  1024000  NTFS (0x07)

# ดู file system info
fsstat -o 2048 /evidence/disk.img  # -o = offset in sectors

# สร้าง listing ของ files
fls -r -o 2048 /evidence/disk.img

# ดึง file จาก inode
icat -o 2048 /evidence/disk.img 12345 > recovered_file.bin

# ค้นหาไฟล์ที่ลบ
fls -r -d -o 2048 /evidence/disk.img  # -d = deleted

# Timeline จาก file system
fls -r -m / -o 2048 /evidence/disk.img > body.txt
mactime -b body.txt -d > timeline.csv
```

### 2.3 File Recovery

```bash
# กู้คืนไฟล์ด้วย foremost
foremost -t jpeg,png,pdf,doc \
    -i /evidence/disk.img \
    -o /evidence/recovered/

# กู้คืนด้วย photorec (GUI)
photorec /evidence/disk.img

# กู้คืนด้วย testdisk
testdisk /evidence/disk.img

# หา artifacts ด้วย bulk_extractor
bulk_extractor -o /evidence/bulk_output \
    /evidence/disk.img
# Output: email, url, domain, telephone, credit card numbers
```

```python
#!/usr/bin/env python3
# disk_forensics.py — Automated disk forensics

import subprocess
import hashlib
import os
from pathlib import Path
from datetime import datetime

class DiskForensicsAnalyzer:
    def __init__(self, image_path, output_dir):
        self.image = Path(image_path)
        self.output = Path(output_dir)
        self.output.mkdir(parents=True, exist_ok=True)
    
    def compute_hash(self):
        print("[*] Computing image hash...")
        with open(self.image, 'rb') as f:
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)
        
        hashes = {
            'md5': md5.hexdigest(),
            'sha256': sha256.hexdigest(),
        }
        
        with open(self.output / 'image_hashes.txt', 'w') as f:
            f.write(f"MD5: {hashes['md5']}\n")
            f.write(f"SHA256: {hashes['sha256']}\n")
        
        print(f"[*] MD5: {hashes['md5']}")
        print(f"[*] SHA256: {hashes['sha256']}")
        return hashes
    
    def get_partitions(self):
        result = subprocess.run(
            ['mmls', str(self.image)],
            capture_output=True, text=True
        )
        partitions = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].isdigit():
                partitions.append({
                    'slot': parts[0],
                    'start': int(parts[1]),
                    'end': int(parts[2]),
                    'size': int(parts[3]),
                    'desc': ' '.join(parts[4:])
                })
        return partitions
    
    def list_files(self, offset_sectors, output_file=None):
        cmd = ['fls', '-r', '-m', '/', '-o', str(offset_sectors), str(self.image)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if output_file:
            with open(self.output / output_file, 'w') as f:
                f.write(result.stdout)
        
        return result.stdout
    
    def create_timeline(self, body_file, output_csv):
        cmd = ['mactime', '-b', str(self.output / body_file),
               '-d', '-z', 'UTC']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        with open(self.output / output_csv, 'w') as f:
            f.write(result.stdout)
        
        print(f"[*] Timeline saved to {output_csv}")
    
    def recover_files(self, offset_sectors):
        recover_dir = self.output / 'recovered'
        recover_dir.mkdir(exist_ok=True)
        
        cmd = ['foremost', '-t', 'all',
               '-o', str(recover_dir),
               '-i', str(self.image)]
        subprocess.run(cmd)
        print(f"[*] Recovery complete: {recover_dir}")
    
    def analyze(self):
        print(f"=== Disk Forensics: {self.image.name} ===")
        
        self.compute_hash()
        
        partitions = self.get_partitions()
        print(f"\n[*] Found {len(partitions)} partitions:")
        for p in partitions:
            print(f"  {p['slot']}: offset={p['start']} size={p['size']} ({p['desc']})")
        
        for p in partitions:
            if 'NTFS' in p['desc'] or 'EXT' in p['desc'].upper() or 'LINUX' in p['desc'].upper():
                print(f"\n[*] Listing files on partition {p['slot']}...")
                body_file = f"partition_{p['slot']}_body.txt"
                self.list_files(p['start'], body_file)
                self.create_timeline(body_file, f"timeline_{p['slot']}.csv")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <disk_image> <output_dir>")
        sys.exit(1)
    
    analyzer = DiskForensicsAnalyzer(sys.argv[1], sys.argv[2])
    analyzer.analyze()
```

---

## 3. Memory Forensics

### 3.1 Memory Acquisition

```bash
# Linux: ใช้ AVML
curl -L https://github.com/microsoft/avml/releases/latest/download/avml \
    -o /usr/local/bin/avml
chmod +x /usr/local/bin/avml
avml /evidence/memory.lime

# หรือใช้ LiME kernel module
sudo apt install linux-headers-$(uname -r)
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src && make
sudo insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# Windows: ใช้ Winpmem
winpmem_mini_x64.exe /evidence/memory.raw

# จาก VM:
# VMware: หยุด VM -> ค้นหาไฟล์ .vmem
# VirtualBox: vboxmanage debugvm "VM Name" dumpvmcore --filename memory.dmp
```

### 3.2 Volatility 3 Analysis

```bash
# ติดตั้ง Volatility 3
pip3 install volatility3

# สั่งพื้นฐาน (Linux)
python3 vol.py -f /evidence/memory.lime linux.pslist
python3 vol.py -f /evidence/memory.lime linux.pstree
python3 vol.py -f /evidence/memory.lime linux.bash
python3 vol.py -f /evidence/memory.lime linux.netstat
python3 vol.py -f /evidence/memory.lime linux.malfind

# สั่งพื้นฐาน (Windows)
python3 vol.py -f /evidence/memory.raw windows.pslist
python3 vol.py -f /evidence/memory.raw windows.pstree
python3 vol.py -f /evidence/memory.raw windows.cmdline
python3 vol.py -f /evidence/memory.raw windows.netscan
python3 vol.py -f /evidence/memory.raw windows.malfind
python3 vol.py -f /evidence/memory.raw windows.dlllist
python3 vol.py -f /evidence/memory.raw windows.handles
python3 vol.py -f /evidence/memory.raw windows.registry.hivelist
python3 vol.py -f /evidence/memory.raw windows.registry.printkey \
    --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

# Dump process memory
python3 vol.py -f /evidence/memory.raw windows.dumpfiles --pid 1234
```

```python
#!/usr/bin/env python3
# memory_forensics.py — Automated memory analysis

import subprocess
import json
import re
from pathlib import Path

class MemoryForensicsAnalyzer:
    def __init__(self, memory_image, output_dir, os_type='windows'):
        self.image = memory_image
        self.output = Path(output_dir)
        self.output.mkdir(parents=True, exist_ok=True)
        self.os_type = os_type
        self.vol_base = ['python3', 'vol.py', '-f', memory_image]
        self.prefix = 'windows' if os_type == 'windows' else 'linux'
    
    def run_plugin(self, plugin, extra_args=None, output_file=None):
        cmd = self.vol_base + [f"{self.prefix}.{plugin}"]
        if extra_args:
            cmd.extend(extra_args)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout
        
        if output_file:
            with open(self.output / output_file, 'w') as f:
                f.write(output)
        
        return output
    
    def get_process_list(self):
        output = self.run_plugin('pslist', output_file='pslist.txt')
        processes = []
        for line in output.splitlines():
            # พยายาม parse output
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                processes.append({
                    'pid': int(parts[0]),
                    'ppid': int(parts[1]),
                    'name': parts[2] if len(parts) > 2 else 'unknown'
                })
        return processes
    
    def find_suspicious_processes(self, processes):
        """ค้นหา processes ที่สงสัย"""
        suspicious = []
        
        # ชื่อ processes ที่มักถูกใช้ masquerade
        legit_processes = {
            'svchost.exe': 'services.exe',
            'explorer.exe': 'userinit.exe',
            'lsass.exe': 'wininit.exe',
        }
        
        proc_by_pid = {p['pid']: p for p in processes}
        
        for proc in processes:
            name = proc.get('name', '').lower()
            ppid = proc.get('ppid')
            
            # ตรวจสอบ parent process
            if name in legit_processes:
                expected_parent = legit_processes[name]
                if ppid and ppid in proc_by_pid:
                    actual_parent = proc_by_pid[ppid].get('name', '').lower()
                    if expected_parent.lower() not in actual_parent:
                        suspicious.append({
                            'pid': proc['pid'],
                            'name': proc['name'],
                            'reason': f"Unexpected parent: {actual_parent} (expected {expected_parent})"
                        })
        
        return suspicious
    
    def analyze_network(self):
        """Network connections"""
        return self.run_plugin('netscan', output_file='netscan.txt')
    
    def find_injected_code(self):
        """Find process injection"""
        return self.run_plugin('malfind', output_file='malfind.txt')
    
    def check_registry_run_keys(self):
        """Persistence via registry"""
        run_keys = [
            'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'SYSTEM\\CurrentControlSet\\Services',
        ]
        results = {}
        for key in run_keys:
            output = self.run_plugin('registry.printkey', ['--key', key])
            results[key] = output
        return results
    
    def full_analysis(self):
        print(f"=== Memory Forensics: {self.image} ===")
        
        print("\n[*] Process list...")
        procs = self.get_process_list()
        print(f"  Found {len(procs)} processes")
        
        suspicious = self.find_suspicious_processes(procs)
        if suspicious:
            print(f"  [!] {len(suspicious)} suspicious processes:")
            for s in suspicious:
                print(f"    PID {s['pid']}: {s['name']} - {s['reason']}")
        
        print("\n[*] Network connections...")
        net = self.analyze_network()
        # ค้นหา established connections
        for line in net.splitlines():
            if 'ESTABLISHED' in line:
                print(f"  {line}")
        
        print("\n[*] Checking for code injection...")
        malfind = self.find_injected_code()
        if 'MZ' in malfind:
            print("  [!] Possible PE injection found!")
        
        if self.os_type == 'windows':
            print("\n[*] Registry persistence keys...")
            reg_results = self.check_registry_run_keys()
            for key, output in reg_results.items():
                if output.strip():
                    print(f"  {key}:")
                    for line in output.splitlines()[:5]:
                        print(f"    {line}")
        
        print(f"\n[*] Results saved to {self.output}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <memory_image> <output_dir> [windows|linux]")
        sys.exit(1)
    
    os_type = sys.argv[3] if len(sys.argv) > 3 else 'windows'
    analyzer = MemoryForensicsAnalyzer(sys.argv[1], sys.argv[2], os_type)
    analyzer.full_analysis()
```

---

## 4. Network Forensics

### 4.1 PCAP Analysis

```bash
# Capture network traffic
tcpdump -i eth0 -w /evidence/capture.pcap
tcpdump -i eth0 -w /evidence/capture.pcap -C 100 -W 10  # rotate 100MB, 10 files

# Wireshark filters ที่มีประโยชน์:
# ดู HTTP traffic:            http
# ดู DNS queries:             dns
# ดู specific IP:            ip.addr == 192.168.1.1
# ดู TCP SYN scan:           tcp.flags.syn==1 && tcp.flags.ack==0
# ดู credentials:           http.authbasic or ftp.request.command=="PASS"
# ดู SMB:                    smb or smb2

# tshark (command-line Wireshark)
tshark -r capture.pcap -Y "http" -T fields \
    -e frame.time -e ip.src -e ip.dst \
    -e http.request.method -e http.request.full_uri

# ดึง files จาก HTTP traffic
tshark -r capture.pcap --export-objects http,/evidence/http_files/

# NetworkMiner (GUI) สำหรับ Windows
```

```python
#!/usr/bin/env python3
# network_forensics.py — PCAP analysis

from scapy.all import *
from collections import defaultdict
from datetime import datetime
import json

class NetworkForensicsAnalyzer:
    def __init__(self, pcap_file):
        print(f"[*] Loading {pcap_file}...")
        self.packets = rdpcap(pcap_file)
        self.start_time = float(self.packets[0].time) if self.packets else 0
    
    def extract_credentials(self):
        """ค้นหา credentials จาก cleartext protocols"""
        creds = []
        
        for pkt in self.packets:
            if not pkt.haslayer(Raw):
                continue
            
            payload = pkt[Raw].load
            
            # FTP
            if pkt.haslayer(TCP) and pkt[TCP].dport == 21:
                if payload.startswith(b'USER') or payload.startswith(b'PASS'):
                    creds.append({
                        'protocol': 'FTP',
                        'data': payload.decode('utf-8', errors='ignore').strip(),
                        'src': pkt[IP].src if pkt.haslayer(IP) else 'unknown',
                    })
            
            # HTTP Basic Auth
            if b'Authorization: Basic' in payload:
                import base64
                import re
                match = re.search(rb'Authorization: Basic ([A-Za-z0-9+/=]+)', payload)
                if match:
                    try:
                        decoded = base64.b64decode(match.group(1)).decode()
                        creds.append({
                            'protocol': 'HTTP_BASIC',
                            'credentials': decoded,
                            'src': pkt[IP].src if pkt.haslayer(IP) else 'unknown',
                        })
                    except:
                        pass
            
            # Telnet (port 23) - plaintext
            if pkt.haslayer(TCP) and pkt[TCP].dport == 23:
                text = payload.decode('utf-8', errors='ignore')
                if text.strip():
                    creds.append({
                        'protocol': 'TELNET',
                        'data': text[:100],
                        'src': pkt[IP].src if pkt.haslayer(IP) else 'unknown',
                    })
        
        return creds
    
    def build_conversation_map(self):
        """สร้าง map ของ network conversations"""
        conversations = defaultdict(lambda: {
            'packets': 0, 'bytes': 0,
            'start': None, 'end': None
        })
        
        for pkt in self.packets:
            if not pkt.haslayer(IP):
                continue
            
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else 'OTHER'
            
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else (
                    pkt[UDP].sport if pkt.haslayer(UDP) else 0)
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else (
                    pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            
            key = f"{src}:{sport} <-> {dst}:{dport} ({proto})"
            t = float(pkt.time)
            
            conv = conversations[key]
            conv['packets'] += 1
            conv['bytes'] += len(pkt)
            if conv['start'] is None:
                conv['start'] = t
            conv['end'] = t
        
        return dict(conversations)
    
    def detect_port_scan(self):
        """ค้นหา port scanning"""
        syn_by_src = defaultdict(set)
        
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
                if pkt.haslayer(IP):
                    syn_by_src[pkt[IP].src].add(pkt[TCP].dport)
        
        scanners = []
        for src, ports in syn_by_src.items():
            if len(ports) > 20:
                scanners.append({'src': src, 'ports_count': len(ports)})
        
        return scanners
    
    def report(self):
        print("\n=== Network Forensics Report ===")
        print(f"Total packets: {len(self.packets)}")
        
        creds = self.extract_credentials()
        if creds:
            print(f"\n[!] Credentials found ({len(creds)}):")
            for c in creds:
                print(f"  [{c['protocol']}] {c.get('credentials') or c.get('data', '')}")
        
        scanners = self.detect_port_scan()
        if scanners:
            print(f"\n[!] Port scans detected:")
            for s in scanners:
                print(f"  {s['src']}: {s['ports_count']} ports")
        
        convs = self.build_conversation_map()
        print(f"\n[*] Top conversations by bytes:")
        top = sorted(convs.items(), key=lambda x: x[1]['bytes'], reverse=True)[:10]
        for key, stats in top:
            print(f"  {key}: {stats['packets']} pkts, {stats['bytes']:,} bytes")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap>")
        sys.exit(1)
    analyzer = NetworkForensicsAnalyzer(sys.argv[1])
    analyzer.report()
```

---

## 5. Log Analysis

### 5.1 Linux Log Analysis

```bash
# Log files สำคัญ:
/var/log/auth.log         # authentication events
/var/log/syslog           # system events
/var/log/kern.log         # kernel events
/var/log/apache2/         # Apache web server
/var/log/nginx/           # Nginx
/var/log/ufw.log          # Firewall
/var/log/wtmp             # login history
/var/log/lastlog          # last login

# ค้นหา failed logins
grep "Failed password" /var/log/auth.log | head -20
grep "authentication failure" /var/log/auth.log

# ค้นหา successful logins จาก IP ถี่ไม่คุ้น
grep "Accepted password" /var/log/auth.log

# ดู login history
last -a | head -20
lastb | head -20  # failed logins

# วิเคราะห์ Apache logs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20
grep " 404 " /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn
grep "../../" /var/log/apache2/access.log  # path traversal
```

```python
#!/usr/bin/env python3
# log_analyzer.py — วิเคราะห์ log files

import re
import gzip
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

class SecurityLogAnalyzer:
    def __init__(self):
        self.events = []
        self.failed_logins = defaultdict(list)
        self.suspicious_cmds = []
    
    def parse_auth_log(self, log_path='/var/log/auth.log'):
        """วิเคราะห์ authentication log"""
        path = Path(log_path)
        
        # รองรับทั้งไฟล์ปกติและ .gz
        if path.suffix == '.gz':
            with gzip.open(path, 'rt') as f:
                lines = f.readlines()
        else:
            lines = path.read_text().splitlines()
        
        patterns = {
            'failed_ssh': re.compile(r'Failed password for (\S+) from (\S+) port'),
            'accepted_ssh': re.compile(r'Accepted password for (\S+) from (\S+) port'),
            'invalid_user': re.compile(r'Invalid user (\S+) from (\S+)'),
            'sudo_cmd': re.compile(r'sudo.*COMMAND=(.+)$'),
            'brute_force': re.compile(r'BREAK-IN ATTEMPT'),
        }
        
        for line in lines:
            for event_type, pattern in patterns.items():
                m = pattern.search(line)
                if m:
                    event = {
                        'type': event_type,
                        'raw': line.strip(),
                        'groups': m.groups(),
                        'timestamp': self._extract_timestamp(line)
                    }
                    self.events.append(event)
                    
                    if event_type == 'failed_ssh':
                        username, ip = m.group(1), m.group(2)
                        self.failed_logins[ip].append({'user': username, 'line': line})
        
        return self.events
    
    def _extract_timestamp(self, line):
        # พยายาม parse timestamps รูปแบบต่างๆ
        patterns = [
            r'(\w+\s+\d+\s+\d+:\d+:\d+)',  # syslog: Jan  1 12:00:00
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',  # ISO: 2024-01-01T12:00:00
        ]
        for p in patterns:
            m = re.search(p, line)
            if m:
                return m.group(1)
        return None
    
    def detect_brute_force(self, threshold=10):
        """ค้นหา brute force attacks"""
        attackers = []
        for ip, attempts in self.failed_logins.items():
            if len(attempts) >= threshold:
                users_tried = list(set(a['user'] for a in attempts))
                attackers.append({
                    'ip': ip,
                    'attempts': len(attempts),
                    'users_tried': users_tried
                })
        return sorted(attackers, key=lambda x: x['attempts'], reverse=True)
    
    def parse_apache_log(self, log_path):
        """วิเคราะห์ Apache/Nginx access log"""
        pattern = re.compile(
            r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\S+)'
        )
        
        attack_patterns = {
            'sql_injection': re.compile(r'(union|select|insert|update|delete|drop)', re.I),
            'path_traversal': re.compile(r'\.\./'),
            'xss': re.compile(r'(<script|javascript:|onerror=)', re.I),
            'cmd_injection': re.compile(r'(;|\|\||&&|`|\$\()', re.I),
            'scanner': re.compile(r'(nmap|nikto|sqlmap|masscan)', re.I),
        }
        
        suspicious = []
        
        for line in Path(log_path).read_text().splitlines():
            m = pattern.match(line)
            if not m:
                continue
            
            ip, timestamp, method, uri, status, size = m.groups()
            
            for attack_type, attack_pattern in attack_patterns.items():
                if attack_pattern.search(uri):
                    suspicious.append({
                        'type': attack_type,
                        'ip': ip,
                        'uri': uri[:200],
                        'status': status,
                        'timestamp': timestamp
                    })
                    break
        
        return suspicious
    
    def report(self, log_path='/var/log/auth.log'):
        self.parse_auth_log(log_path)
        
        print("=== Security Log Analysis ===")
        print(f"Total security events: {len(self.events)}")
        
        attackers = self.detect_brute_force()
        if attackers:
            print(f"\n[!] Brute force attacks:")
            for a in attackers[:10]:
                print(f"  {a['ip']}: {a['attempts']} attempts, tried users: {a['users_tried'][:5]}")
        
        by_type = Counter(e['type'] for e in self.events)
        print(f"\n[*] Events by type:")
        for event_type, count in by_type.most_common():
            print(f"  {event_type}: {count}")

if __name__ == "__main__":
    analyzer = SecurityLogAnalyzer()
    analyzer.report()
```

---

## 6. File System Analysis

### 6.1 File เชิง Forensics

```python
#!/usr/bin/env python3
# filesystem_forensics.py — วิเคราะห์ไฟล์เชิง forensics

import os
import stat
import hashlib
import json
import xattr
from pathlib import Path
from datetime import datetime

class FileSystemForensics:
    def __init__(self, root_path):
        self.root = Path(root_path)
        self.file_catalog = []
    
    def get_file_metadata(self, filepath):
        """ดึง metadata ครบถ้วนของไฟล์"""
        p = Path(filepath)
        if not p.exists():
            return None
        
        s = p.stat()
        
        metadata = {
            'path': str(p),
            'name': p.name,
            'size': s.st_size,
            'created': datetime.fromtimestamp(s.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(s.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(s.st_atime).isoformat(),
            'uid': s.st_uid,
            'gid': s.st_gid,
            'permissions': oct(stat.S_IMODE(s.st_mode)),
            'is_symlink': p.is_symlink(),
        }
        
        # คำนวณ hash สำหรับไฟล์ที่ไม่ใหญ่เกินไป
        if p.is_file() and s.st_size < 100 * 1024 * 1024:  # < 100MB
            with open(p, 'rb') as f:
                metadata['md5'] = hashlib.md5(f.read()).hexdigest()
        
        return metadata
    
    def build_file_catalog(self, extensions=None):
        """สร้าง catalog ของไฟล์ทั้งหมด"""
        for filepath in self.root.rglob('*'):
            if not filepath.is_file():
                continue
            if extensions and filepath.suffix.lower() not in extensions:
                continue
            
            meta = self.get_file_metadata(filepath)
            if meta:
                self.file_catalog.append(meta)
        
        print(f"[*] Cataloged {len(self.file_catalog)} files")
        return self.file_catalog
    
    def find_recently_modified(self, hours=24):
        """ค้นหาไฟล์ที่เพิ่งแก้ไข"""
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(hours=hours)
        
        recent = []
        for meta in self.file_catalog:
            mod_time = datetime.fromisoformat(meta['modified'])
            if mod_time > cutoff:
                recent.append(meta)
        
        return sorted(recent, key=lambda x: x['modified'], reverse=True)
    
    def find_hidden_executables(self):
        """ค้นหา executables ที่ซ่อน (extension ไม่ตรง)"""
        suspects = []
        for meta in self.file_catalog:
            path = Path(meta['path'])
            
            # ตรวจสอบ magic bytes
            try:
                with open(path, 'rb') as f:
                    magic = f.read(4)
                
                # ELF
                if magic[:4] == b'\x7fELF' and path.suffix != '':
                    suspects.append({'path': str(path), 'reason': 'ELF with extension'})
                # PE (Windows)
                elif magic[:2] == b'MZ' and path.suffix not in ['.exe', '.dll', '.sys']:
                    suspects.append({'path': str(path), 'reason': 'PE without .exe/.dll'})
            except:
                pass
        
        return suspects
    
    def find_suspicious_permissions(self):
        """ค้นหา files ที่มี permissions น่าสงสัย"""
        suspicious = []
        for meta in self.file_catalog:
            perms = int(meta['permissions'], 8)
            
            # SUID/SGID bits
            if perms & 0o4000:  # SUID
                suspicious.append({'path': meta['path'], 'reason': 'SUID bit set',
                                  'permissions': meta['permissions']})
            elif perms & 0o2000:  # SGID
                suspicious.append({'path': meta['path'], 'reason': 'SGID bit set',
                                  'permissions': meta['permissions']})
            # World-writable
            elif perms & 0o002:
                suspicious.append({'path': meta['path'], 'reason': 'World-writable',
                                  'permissions': meta['permissions']})
        
        return suspicious
    
    def save_catalog(self, output_file):
        with open(output_file, 'w') as f:
            json.dump(self.file_catalog, f, indent=2)
        print(f"[*] Catalog saved to {output_file}")

if __name__ == "__main__":
    import sys
    root = sys.argv[1] if len(sys.argv) > 1 else '/etc'
    
    fs = FileSystemForensics(root)
    fs.build_file_catalog()
    
    recent = fs.find_recently_modified(hours=72)
    print(f"\n[*] Recently modified files ({len(recent)}):")
    for f in recent[:10]:
        print(f"  {f['modified']}: {f['path']}")
    
    hidden_exec = fs.find_hidden_executables()
    if hidden_exec:
        print(f"\n[!] Suspicious executables:")
        for h in hidden_exec:
            print(f"  {h['path']}: {h['reason']}")
    
    sus_perms = fs.find_suspicious_permissions()
    if sus_perms:
        print(f"\n[!] Files with suspicious permissions:")
        for s in sus_perms[:10]:
            print(f"  {s['path']} ({s['permissions']}): {s['reason']}")
```

---

## 7. Email Forensics

### 7.1 Email Header Analysis

```python
#!/usr/bin/env python3
# email_forensics.py — วิเคราะห์ email headers และ attachments

import email
import email.header
import re
import hashlib
from pathlib import Path

class EmailForensicsAnalyzer:
    def __init__(self, eml_file):
        with open(eml_file, 'rb') as f:
            self.msg = email.message_from_bytes(f.read())
    
    def analyze_headers(self):
        """วิเคราะห์ email headers"""
        headers = {}
        
        # Headers ที่สำคัญ
        important_headers = [
            'From', 'To', 'Subject', 'Date',
            'Received', 'Return-Path', 'Reply-To',
            'X-Originating-IP', 'X-Mailer',
            'DKIM-Signature', 'Authentication-Results',
            'X-Spam-Status', 'X-Spam-Score',
        ]
        
        for header in important_headers:
            value = self.msg.get(header)
            if value:
                # Decode header
                decoded_parts = email.header.decode_header(value)
                decoded = ' '.join(
                    part.decode(enc or 'utf-8') if isinstance(part, bytes) else part
                    for part, enc in decoded_parts
                )
                headers[header] = decoded
        
        return headers
    
    def trace_route(self):
        """ตามเส้นทางจาก Received headers"""
        received_headers = self.msg.get_all('Received') or []
        route = []
        
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        for header in reversed(received_headers):
            ips = ip_pattern.findall(header)
            # กรอง private IPs
            public_ips = [ip for ip in ips if not self._is_private_ip(ip)]
            route.append({
                'header': header[:100],
                'ips': public_ips
            })
        
        return route
    
    def _is_private_ip(self, ip):
        parts = [int(x) for x in ip.split('.')]
        return (
            parts[0] == 10 or
            (parts[0] == 172 and 16 <= parts[1] <= 31) or
            (parts[0] == 192 and parts[1] == 168) or
            parts[0] == 127
        )
    
    def check_spoofing(self):
        """ตรวจสอบการ spoof email"""
        issues = []
        
        from_header = self.msg.get('From', '')
        return_path = self.msg.get('Return-Path', '')
        reply_to = self.msg.get('Reply-To', '')
        
        # ตรวจสอบ From vs Return-Path mismatch
        from_domain = re.search(r'@([\w.]+)', from_header)
        rp_domain = re.search(r'@([\w.]+)', return_path)
        
        if from_domain and rp_domain:
            if from_domain.group(1) != rp_domain.group(1):
                issues.append(f"From/Return-Path mismatch: {from_domain.group(1)} vs {rp_domain.group(1)}")
        
        if reply_to and from_header:
            from_addr = re.search(r'<([^>]+)>', from_header)
            rt_addr = re.search(r'<([^>]+)>', reply_to)
            if from_addr and rt_addr and from_addr.group(1) != rt_addr.group(1):
                issues.append(f"Reply-To differs from From: {rt_addr.group(1)}")
        
        auth = self.msg.get('Authentication-Results', '')
        if 'dkim=fail' in auth.lower():
            issues.append("DKIM verification failed")
        if 'spf=fail' in auth.lower():
            issues.append("SPF check failed")
        
        return issues
    
    def extract_attachments(self, output_dir):
        """ดึง attachments และวิเคราะห์"""
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        
        attachments = []
        for part in self.msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            
            filename = part.get_filename()
            if not filename:
                continue
            
            # Decode filename
            decoded = email.header.decode_header(filename)
            filename = decoded[0][0]
            if isinstance(filename, bytes):
                filename = filename.decode(decoded[0][1] or 'utf-8', errors='ignore')
            
            content = part.get_payload(decode=True)
            if not content:
                continue
            
            filepath = output / filename
            filepath.write_bytes(content)
            
            attachments.append({
                'filename': filename,
                'size': len(content),
                'md5': hashlib.md5(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest(),
                'content_type': part.get_content_type(),
                'saved_to': str(filepath),
            })
        
        return attachments
    
    def analyze(self, output_dir='/tmp/email_analysis'):
        print("=== Email Forensics ===")
        
        headers = self.analyze_headers()
        print(f"\n[*] Headers:")
        for k, v in headers.items():
            print(f"  {k}: {v[:100]}")
        
        route = self.trace_route()
        print(f"\n[*] Email route ({len(route)} hops):")
        for i, hop in enumerate(route):
            ips = ', '.join(hop['ips']) if hop['ips'] else 'no public IP'
            print(f"  Hop {i+1}: {ips}")
        
        issues = self.check_spoofing()
        if issues:
            print(f"\n[!] Spoofing indicators:")
            for issue in issues:
                print(f"  - {issue}")
        
        attachments = self.extract_attachments(output_dir)
        if attachments:
            print(f"\n[*] Attachments ({len(attachments)}):")
            for att in attachments:
                print(f"  {att['filename']} ({att['size']} bytes)")
                print(f"    MD5: {att['md5']}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <email.eml>")
        sys.exit(1)
    analyzer = EmailForensicsAnalyzer(sys.argv[1])
    analyzer.analyze()
```

---

## 8. Browser Forensics

### 8.1 Chrome/Firefox History Analysis

```python
#!/usr/bin/env python3
# browser_forensics.py — วิเคราะห์ประวัติ browser

import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta

class BrowserForensicsAnalyzer:
    # Chrome timestamp: microseconds since Jan 1, 1601
    CHROME_EPOCH = datetime(1601, 1, 1)
    
    def chrome_time(self, timestamp):
        """Convert Chrome timestamp to datetime"""
        return self.CHROME_EPOCH + timedelta(microseconds=timestamp)
    
    def firefox_time(self, timestamp):
        """Convert Firefox timestamp to datetime (microseconds since epoch)"""
        return datetime.fromtimestamp(timestamp / 1_000_000)
    
    def get_chrome_history(self, profile_path=None):
        """ดึงประวัติการเยี่ยมชม Chrome"""
        if not profile_path:
            # Default paths
            import platform
            if platform.system() == 'Linux':
                profile_path = Path.home() / '.config/google-chrome/Default'
            elif platform.system() == 'Windows':
                import os
                profile_path = Path(os.environ['LOCALAPPDATA']) / \
                    'Google/Chrome/User Data/Default'
        
        history_db = Path(profile_path) / 'History'
        if not history_db.exists():
            print(f"[!] Chrome history not found: {history_db}")
            return []
        
        # Copy DB to avoid lock issues
        import shutil
        temp_db = '/tmp/chrome_history_copy'
        shutil.copy2(history_db, temp_db)
        
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT 1000
        """)
        
        history = []
        for url, title, count, last_visit in cursor.fetchall():
            history.append({
                'url': url,
                'title': title,
                'visit_count': count,
                'last_visit': self.chrome_time(last_visit).isoformat() if last_visit else None,
            })
        
        conn.close()
        return history
    
    def get_chrome_downloads(self, profile_path=None):
        """ดึงประวัติการดาวน์โหลด Chrome"""
        if not profile_path:
            profile_path = Path.home() / '.config/google-chrome/Default'
        
        import shutil
        history_db = Path(profile_path) / 'History'
        temp_db = '/tmp/chrome_history_copy2'
        shutil.copy2(history_db, temp_db)
        
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT current_path, target_path, url, received_bytes,
                   total_bytes, start_time, end_time
            FROM downloads
            JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
            ORDER BY start_time DESC
        """)
        
        downloads = []
        for row in cursor.fetchall():
            downloads.append({
                'saved_to': row[0],
                'target': row[1],
                'url': row[2],
                'bytes': row[3],
                'start': self.chrome_time(row[5]).isoformat() if row[5] else None,
            })
        
        conn.close()
        return downloads
    
    def find_suspicious_history(self, history):
        """ค้นหา URLs ที่น่าสงสัย"""
        suspicious_patterns = [
            r'\.onion',
            r'pastebin\.com',
            r'paste\.',
            r'\d+\.\d+\.\d+\.\d+',  # direct IP
            r'darkweb',
            r'exploit',
        ]
        
        import re
        suspicious = []
        for entry in history:
            url = entry.get('url', '')
            for pattern in suspicious_patterns:
                if re.search(pattern, url, re.I):
                    suspicious.append(entry)
                    break
        
        return suspicious
    
    def report(self):
        print("=== Browser Forensics ===")
        
        history = self.get_chrome_history()
        print(f"\n[*] Chrome history: {len(history)} entries")
        
        # แสดง 10 URLs ล่าสุด
        for entry in history[:10]:
            print(f"  [{entry['last_visit']}] {entry['url'][:80]}")
        
        suspicious = self.find_suspicious_history(history)
        if suspicious:
            print(f"\n[!] Suspicious URLs ({len(suspicious)}):")
            for entry in suspicious[:10]:
                print(f"  {entry['url'][:100]}")
        
        downloads = self.get_chrome_downloads()
        print(f"\n[*] Downloads: {len(downloads)} files")
        for d in downloads[:10]:
            print(f"  [{d['start']}] {d['url'][:60]} -> {d['saved_to']}")

if __name__ == "__main__":
    analyzer = BrowserForensicsAnalyzer()
    analyzer.report()
```

---

## 9. Timeline Analysis

### 9.1 Super Timeline Creation

```bash
# สร้าง super timeline ด้วย Plaso (log2timeline)
pip3 install plaso

# ใช้ log2timeline เพื่อประมวลผล artifacts
log2timeline.py /evidence/timeline.plaso /evidence/disk.img

# ค้นหาเหตุการณ์ในช่วงเวลาที่เจาะจง
psort.py -z UTC /evidence/timeline.plaso \
    "date > '2024-01-01' AND date < '2024-01-02'" \
    -o csv > /evidence/timeline_jan1.csv

# ดูด้วย Timesketch (web interface)
timesketch_cli search -q "malware" -n 100
```

```python
#!/usr/bin/env python3
# timeline_builder.py — สร้าง timeline จากหลายแหล่ง

import json
import csv
from datetime import datetime
from pathlib import Path

class TimelineBuilder:
    def __init__(self):
        self.events = []
    
    def add_fs_events(self, fls_body_file):
        """Import filesystem events from fls body file"""
        with open(fls_body_file) as f:
            reader = csv.reader(f, delimiter='|')
            for row in reader:
                if len(row) < 11:
                    continue
                try:
                    md5, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime = row[:11]
                    for ts_type, ts_val in [('accessed', atime), ('modified', mtime),
                                           ('changed', ctime), ('created', crtime)]:
                        if ts_val and ts_val != '0':
                            self.events.append({
                                'timestamp': datetime.fromtimestamp(int(ts_val)).isoformat(),
                                'type': f'filesystem_{ts_type}',
                                'source': 'disk',
                                'details': name,
                                'extra': {'size': size, 'inode': inode},
                            })
                except (ValueError, IndexError):
                    pass
    
    def add_log_events(self, log_events):
        """Import log events"""
        for event in log_events:
            if 'timestamp' in event:
                self.events.append({
                    'timestamp': event['timestamp'],
                    'type': event.get('type', 'log_event'),
                    'source': 'log',
                    'details': event.get('raw', ''),
                })
    
    def add_network_events(self, pcap_file):
        """Add network events from PCAP"""
        from scapy.all import rdpcap, TCP, UDP, IP
        packets = rdpcap(pcap_file)
        
        for pkt in packets:
            if pkt.haslayer(IP):
                proto = 'TCP' if pkt.haslayer(TCP) else 'UDP'
                sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
                dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
                
                self.events.append({
                    'timestamp': datetime.fromtimestamp(float(pkt.time)).isoformat(),
                    'type': f'network_{proto.lower()}',
                    'source': 'pcap',
                    'details': f"{pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport}",
                })
    
    def sort_events(self):
        self.events.sort(key=lambda x: x.get('timestamp', ''))
        return self.events
    
    def export_csv(self, output_file):
        self.sort_events()
        with open(output_file, 'w', newline='') as f:
            if self.events:
                writer = csv.DictWriter(f, fieldnames=['timestamp', 'type', 'source', 'details'])
                writer.writeheader()
                for event in self.events:
                    writer.writerow({k: event.get(k, '') for k in ['timestamp', 'type', 'source', 'details']})
        print(f"[*] {len(self.events)} events saved to {output_file}")
    
    def export_json(self, output_file):
        self.sort_events()
        with open(output_file, 'w') as f:
            json.dump(self.events, f, indent=2)
        print(f"[*] {len(self.events)} events saved to {output_file}")
    
    def search(self, keyword, start_time=None, end_time=None):
        results = []
        for event in self.sort_events():
            ts = event.get('timestamp', '')
            if start_time and ts < start_time:
                continue
            if end_time and ts > end_time:
                continue
            if keyword.lower() in json.dumps(event).lower():
                results.append(event)
        return results

if __name__ == "__main__":
    tl = TimelineBuilder()
    
    # เพิ่ม events จากหลายแหล่ง
    tl.add_log_events([
        {'timestamp': '2024-01-15T10:30:00', 'type': 'auth_failed', 'raw': 'Failed SSH from 1.2.3.4'},
        {'timestamp': '2024-01-15T10:35:00', 'type': 'auth_success', 'raw': 'SSH login success'},
    ])
    
    # ค้นหาเหตุการณ์
    results = tl.search('SSH', '2024-01-15', '2024-01-16')
    for r in results:
        print(f"[{r['timestamp']}] {r['type']}: {r['details']}")
    
    tl.export_csv('/evidence/timeline.csv')
```

---

## 10. Forensic Report Writing

### 10.1 โครงสร้างรายงาน

```python
#!/usr/bin/env python3
# forensic_report.py — สร้างรายงานอย่างเป็นทางการ

from datetime import datetime
from pathlib import Path
import json

class ForensicReportGenerator:
    def __init__(self, case_number, examiner_name):
        self.case_number = case_number
        self.examiner = examiner_name
        self.report_date = datetime.now()
        self.findings = []
        self.timeline_entries = []
        self.iocs = []
        self.recommendations = []
    
    def add_finding(self, title, description, severity, evidence):
        self.findings.append({
            'title': title,
            'description': description,
            'severity': severity,  # critical/high/medium/low
            'evidence': evidence,
        })
    
    def add_ioc(self, ioc_type, value, description=''):
        self.iocs.append({
            'type': ioc_type,
            'value': value,
            'description': description,
        })
    
    def add_recommendation(self, action, priority='high'):
        self.recommendations.append({'action': action, 'priority': priority})
    
    def generate_markdown(self):
        lines = []
        lines.append(f"# Digital Forensics Investigation Report")
        lines.append(f"")
        lines.append(f"**Case Number:** {self.case_number}")
        lines.append(f"**Examiner:** {self.examiner}")
        lines.append(f"**Date:** {self.report_date.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Classification:** CONFIDENTIAL")
        lines.append(f"")
        
        lines.append(f"## Executive Summary")
        lines.append(f"")
        lines.append(f"[สรุปผลการสืบสวนสำหรับผู้บริหาร]")
        lines.append(f"")
        
        lines.append(f"## Findings")
        lines.append(f"")
        for i, finding in enumerate(self.findings, 1):
            severity_marker = {
                'critical': '\U0001f534', 'high': '\U0001f7e0',
                'medium': '\U0001f7e1', 'low': '\U0001f7e2'
            }.get(finding['severity'], '•')
            lines.append(f"### {i}. {finding['title']} {severity_marker}")
            lines.append(f"")
            lines.append(f"**Severity:** {finding['severity'].upper()}")
            lines.append(f"")
            lines.append(f"{finding['description']}")
            lines.append(f"")
            lines.append(f"**Evidence:**")
            lines.append(f"```")
            lines.append(finding['evidence'])
            lines.append(f"```")
            lines.append(f"")
        
        lines.append(f"## Indicators of Compromise (IOCs)")
        lines.append(f"")
        lines.append(f"| Type | Value | Description |")
        lines.append(f"|------|-------|-------------|")
        for ioc in self.iocs:
            lines.append(f"| {ioc['type']} | `{ioc['value']}` | {ioc['description']} |")
        lines.append(f"")
        
        lines.append(f"## Recommendations")
        lines.append(f"")
        for rec in self.recommendations:
            lines.append(f"- **[{rec['priority'].upper()}]** {rec['action']}")
        lines.append(f"")
        
        lines.append(f"## Chain of Custody")
        lines.append(f"")
        lines.append(f"| Date | Examiner | Action |")
        lines.append(f"|------|----------|--------|")
        lines.append(f"| {self.report_date.date()} | {self.examiner} | Initial analysis |")
        lines.append(f"")
        
        lines.append(f"---")
        lines.append(f"*Report generated: {self.report_date.isoformat()}*")
        
        return '\n'.join(lines)
    
    def save(self, output_path):
        report = self.generate_markdown()
        Path(output_path).write_text(report)
        print(f"[*] Report saved to {output_path}")

# ตัวอย่าง
if __name__ == "__main__":
    report = ForensicReportGenerator(
        case_number='CASE-2024-001',
        examiner_name='Security Analyst'
    )
    
    report.add_finding(
        title='Unauthorized SSH Access from External IP',
        description='Attacker gained SSH access using compromised credentials after 127 failed attempts.',
        severity='critical',
        evidence='Jan 15 10:35:00 server sshd[1234]: Accepted password for root from 203.0.113.1 port 45678'
    )
    
    report.add_ioc('ip', '203.0.113.1', 'Attacker IP address')
    report.add_ioc('username', 'root', 'Compromised account')
    
    report.add_recommendation('Reset all credentials immediately')
    report.add_recommendation('Enable MFA for SSH access', priority='medium')
    report.add_recommendation('Block IP 203.0.113.1 at firewall level')
    
    report.save('/evidence/forensic_report.md')
```

---

## สรุป

| บทบาท | เครื่องมือ | ผลลัพธ์ |
|------|--------|--------|
| Disk Forensics | Autopsy, Sleuthkit, dcfldd | Image acquisition, file recovery |
| Memory Forensics | Volatility 3, AVML | Process/network analysis |
| Network Forensics | Wireshark, tshark, Scapy | Traffic analysis, credential extraction |
| Log Analysis | grep, awk, Python | Security event detection |
| Browser Forensics | SQLite, Python | History, downloads, cache |
| Timeline | log2timeline, Plaso | Super timeline creation |
| Reporting | Python, Markdown | Professional report writing |

---

← [Part 83: Malware Analysis](Part-83-Malware-Analysis.md) | [Part 85: OSINT Advanced](Part-85-OSINT-Advanced.md) →
