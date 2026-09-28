# Part 08: Network Configuration - การตั้งค่า Network

## สารบัญ
- [Network Interfaces](#network-interfaces)
- [IP Configuration](#ip-configuration)
- [Routing](#routing)
- [DNS Configuration](#dns-configuration)
- [Firewall (iptables)](#firewall-iptables)
- [VPN Setup](#vpn-setup)
- [Proxy Configuration](#proxy-configuration)
- [แบบฝึกหัด](#แบบฝึกหัด)

---

## Network Interfaces

### ดู Interfaces

```bash
# ดู interfaces ทั้งหมด
ip link show
ip addr show

# ดู specific interface
ip addr show eth0
ip addr show wlan0

# ดู statistics
ip -s link show eth0

# ifconfig (เก่ากว่าแต่ยังใช้ได้)
ifconfig
ifconfig eth0
ifconfig -a  # แสดงทั้ง down interfaces

# ดูด้วย nmcli
nmcli device status
nmcli device show
```

### เปิด/ปิด Interface

```bash
# เปิด interface
sudo ip link set eth0 up
sudo ifconfig eth0 up

# ปิด interface
sudo ip link set eth0 down
sudo ifconfig eth0 down

# Restart networking
sudo systemctl restart networking
sudo service networking restart

# nmcli
nmcli device disconnect eth0
nmcli device connect eth0
```

---

## IP Configuration

### ตั้งค่า IP แบบ Static

**วิธีที่ 1: ip command (temporary)**
```bash
# เพิ่ม IP
sudo ip addr add 192.168.1.100/24 dev eth0

# ลบ IP
sudo ip addr del 192.168.1.100/24 dev eth0

# ตรวจสอบ
ip addr show eth0
```

**วิธีที่ 2: /etc/network/interfaces (permanent)**
```bash
sudo nano /etc/network/interfaces

# เนื้อหา:
uto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 192.168.1.100
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4

# Restart
sudo systemctl restart networking
```

**วิธีที่ 3: nmcli (NetworkManager)**
```bash
# ดู connections
nmcli con show

# สร้าง static connection
nmcli con add type ethernet ifname eth0 con-name static-eth0 \
    ip4 192.168.1.100/24 gw4 192.168.1.1

nmcli con mod static-eth0 ipv4.dns "8.8.8.8 8.8.4.4"
nmcli con mod static-eth0 ipv4.method manual
nmcli con up static-eth0

# ตรวจสอบ
nmcli con show static-eth0
```

### ตั้งค่า DHCP

```bash
# /etc/network/interfaces
auto eth0
iface eth0 inet dhcp

# Renew DHCP lease
sudo dhclient -v eth0
sudo dhclient -r eth0  # release
sudo dhclient eth0     # request new

# nmcli
nmcli con mod eth0 ipv4.method auto
nmcli con up eth0
```

### Multiple IP Addresses

```bash
# เพิ่ม IP หลายตัวบน interface เดียว
sudo ip addr add 192.168.1.100/24 dev eth0
sudo ip addr add 192.168.1.101/24 dev eth0
sudo ip addr add 10.0.0.1/8 dev eth0

# หรือใช้ alias (วิธีเก่า)
sudo ifconfig eth0:0 192.168.1.101 netmask 255.255.255.0
sudo ifconfig eth0:1 192.168.1.102 netmask 255.255.255.0

# ตรวจสอบ
ip addr show eth0
```

---

## Routing

### ดู Routing Table

```bash
# ดู routing table
ip route show
route -n  # เก่ากว่าแต่ยังใช้ได้
netstat -rn

# Output ตัวอย่าง:
# default via 192.168.1.1 dev eth0 proto dhcp
# 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100
# 192.168.56.0/24 dev eth1 proto kernel scope link src 192.168.56.101
```

### เพิ่ม/ลบ Routes

```bash
# เพิ่ม default gateway
sudo ip route add default via 192.168.1.1
sudo ip route add default via 192.168.1.1 dev eth0

# เพิ่ม specific route
sudo ip route add 10.10.10.0/24 via 192.168.1.1
sudo ip route add 10.10.10.0/24 via 192.168.1.1 dev eth0

# ลบ route
sudo ip route del default
sudo ip route del 10.10.10.0/24

# Static routing
# สำหรับ Lab: route traffic ไป target network ผ่าน Kali
```

### IP Forwarding

```bash
# เปิด IP forwarding (สำหรับ routing/MITM)
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Permanent (บันทึกใน /etc/sysctl.conf)
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# ตรวจสอบ
cat /proc/sys/net/ipv4/ip_forward
sysctl net.ipv4.ip_forward
```

---

## DNS Configuration

### /etc/resolv.conf

```bash
# ดู DNS configuration
cat /etc/resolv.conf

# เปลี่ยน DNS
echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf
echo 'nameserver 1.1.1.1' | sudo tee -a /etc/resolv.conf

# ตรวจสอบ
nslookup google.com
dig google.com @8.8.8.8
```

### /etc/hosts

```bash
# ดู hosts file
cat /etc/hosts

# เพิ่ม entries (สำหรับ pentest)
echo '192.168.1.100 target.local target' | sudo tee -a /etc/hosts
echo '192.168.1.101 dc01.domain.local dc01' | sudo tee -a /etc/hosts

# ทดสอบ
ping target.local
nslookup target.local
```

---

## Firewall (iptables)

### iptables Basics

```bash
# ดู rules
sudo iptables -L
sudo iptables -L -v  # verbose
sudo iptables -L --line-numbers  # with line numbers

# Chains:
# INPUT - traffic ขาเข้า
# OUTPUT - traffic ขาออก
# FORWARD - traffic ผ่าน

# Policies
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
```

### Firewall Rules สำหรับ Lab

```bash
# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Block specific IP
sudo iptables -A INPUT -s 192.168.1.50 -j DROP

# Port forward (NAT)
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Log dropped packets
sudo iptables -A INPUT -j LOG --log-prefix "[DROPPED]"
sudo iptables -A INPUT -j DROP

# ล้าง rules ทั้งหมด
sudo iptables -F
sudo iptables -t nat -F

# บันทึก rules
sudo iptables-save > /etc/iptables/rules.v4

# โหลด rules
sudo iptables-restore < /etc/iptables/rules.v4
```

### nftables (modern)

```bash
# ดู rules
sudo nft list ruleset

# เพิ่ม rule
sudo nft add rule ip filter input tcp dport 22 accept

# UFW (Uncomplicated Firewall) - ง่ายกว่า iptables
sudo apt install ufw
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw status verbose
```

---

## VPN Setup

### OpenVPN

```bash
# เชื่อมต่อ HackTheBox/TryHackMe
sudo openvpn htb.ovpn
sudo openvpn tryhackme.ovpn

# Background
sudo openvpn --daemon --config htb.ovpn

# ตรวจสอบ
ip addr show tun0
ping 10.10.10.1

# ปิดการเชื่อมต่อ
sudo pkill openvpn
```

### WireGuard

```bash
# ติดตั้ง
sudo apt install wireguard

# สร้าง keys
wg genkey | tee private.key | wg pubkey > public.key

# Config
sudo nano /etc/wireguard/wg0.conf
# [Interface]
# PrivateKey = <private_key>
# Address = 10.0.0.2/24
# DNS = 1.1.1.1
#
# [Peer]
# PublicKey = <server_public_key>
# Endpoint = server.com:51820
# AllowedIPs = 0.0.0.0/0

# เชื่อมต่อ
sudo wg-quick up wg0
sudo wg-quick down wg0
```

---

## Proxy Configuration

### HTTP Proxy

```bash
# System-wide proxy
export http_proxy=http://proxy.server:8080
export https_proxy=http://proxy.server:8080
export no_proxy=localhost,127.0.0.1

# ถาวร
echo 'export http_proxy=http://proxy.server:8080' >> ~/.zshrc
echo 'export https_proxy=http://proxy.server:8080' >> ~/.zshrc

# apt proxy
echo 'Acquire::http::Proxy "http://proxy.server:8080";' | sudo tee /etc/apt/apt.conf.d/proxy.conf
```

### SOCKS Proxy

```bash
# SSH SOCKS proxy
ssh -D 1080 -N -f user@server

# ใช้กับ curl
curl --socks5 127.0.0.1:1080 http://target.com

# proxychains
sudo nano /etc/proxychains4.conf
# เพิ่มท้ายไฟล์:
# socks5 127.0.0.1 1080

proxychains nmap -sV target.com
proxychains curl http://internal.target.com
proxychains msfconsole
```

### Burp Suite Proxy

```bash
# เปิด Burp Suite
burpsuite

# ไปที่ Proxy > Options
# Bind address: 127.0.0.1:8080

# ตั้งค่า Browser:
# Firefox: Settings > Network Proxy > Manual
# HTTP Proxy: 127.0.0.1 Port: 8080
# SSL Proxy: 127.0.0.1 Port: 8080

# Import CA Certificate:
# 1. Browse to http://burp
# 2. Download CA Certificate
# 3. Import ใน Firefox: Settings > View Certificates > Import

# curl ผ่าน Burp
curl -x http://127.0.0.1:8080 http://target.com
curl --proxy http://127.0.0.1:8080 --cacert burp-ca.crt https://target.com
```

---

## Wireless Configuration

### Monitor Mode

```bash
# ดู wireless interfaces
iwconfig
ip link show | grep wlan

# เปิด Monitor Mode
sudo airmon-ng start wlan0
# สร้าง: wlan0mon

# หรือ
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# ปิด Monitor Mode
sudo airmon-ng stop wlan0mon

# ตรวจสอบ
iwconfig wlan0mon
```

### Network Scanning (Wireless)

```bash
# Scan APs
sudo airodump-ng wlan0mon

# Scan specific channel
sudo airodump-ng --channel 6 wlan0mon

# ดู clients
sudo airodump-ng wlan0mon --bssid AP_MAC
```

---

## แบบฝึกหัด

### แบบฝึกหัดที่ 1: Network Interfaces

```bash
# 1. ดู interfaces ทั้งหมด
ip addr show

# 2. ดู routing table
ip route show

# 3. Test DNS
dig google.com
nslookup google.com

# 4. ตรวจสอบ connectivity
ping -c 4 8.8.8.8
curl -I http://google.com
```

### แบบฝึกหัดที่ 2: ตั้งค่า Static IP

```bash
# สร้าง test interface (loopback)
sudo ip addr add 10.99.99.1/24 dev lo
ip addr show lo

# ทดสอบ
ping -c 4 10.99.99.1

# ลบ
sudo ip addr del 10.99.99.1/24 dev lo
```

### แบบฝึกหัดที่ 3: iptables

```bash
# ดู current rules
sudo iptables -L -v

# Block ICMP (ทดสอบ)
sudo iptables -A INPUT -p icmp -j DROP
ping 127.0.0.1  # ควร timeout

# ยกเลิก
sudo iptables -D INPUT -p icmp -j DROP
ping 127.0.0.1  # ควรใช้ได้
```

---

## สรุป

| หัวข้อ | คำสั่งสำคัญ |
|--------|------------|
| IP Config | `ip addr`, `nmcli con` |
| Routing | `ip route`, `echo 1 > ip_forward` |
| DNS | `/etc/resolv.conf`, `/etc/hosts` |
| Firewall | `iptables -L`, `ufw status` |
| VPN | `openvpn`, `wg-quick` |
| Proxy | `proxychains`, `burpsuite` |

**Part ถัดไป:** [Part 09: Bash Scripting for Hackers](Part-09-Bash-Scripting-for-Hackers.md)

---
*Part 08/100 | Kali Linux Course*
