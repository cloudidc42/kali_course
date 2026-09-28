# Part 18: Nmap Advanced Scanning
## เทคนิค Nmap ขั้นสูง

---

## สารบัญ
1. [Firewall Evasion](#evasion)
2. [IDS Evasion](#ids)
3. [Advanced NSE](#nse)
4. [Custom Scripts](#custom-scripts)
5. [Masscan](#masscan)
6. [Nmap vs Masscan](#comparison)
7. [Real-world Scenarios](#scenarios)
8. [แบบฝึกหัด](#exercises)

---

## 1. Firewall Evasion {#evasion}

### Fragmentation

```bash
# Fragment packets เพื่อเลี่ยง firewall
nmap -f 192.168.1.1           # 8-byte fragments
nmap -f -f 192.168.1.1        # 16-byte fragments
nmap --mtu 24 192.168.1.1     # Custom MTU

# Decoy Scan (รวม IP ปลอม)
nmap -D RND:10 192.168.1.1          # 10 random decoys
nmap -D 10.0.0.1,10.0.0.2,ME 192.168.1.1  # ระบุ decoys
# ME = your real IP ไว้ในกลุ่ม

# Source IP Spoofing
nmap -S 10.0.0.100 -e eth0 192.168.1.1  # Spoof source IP

# Source Port
nmap --source-port 53 192.168.1.1  # แสร้งเป็น DNS
nmap --source-port 80 192.168.1.1  # แสร้งเป็น HTTP
nmap --source-port 443 192.168.1.1 # HTTPS

# Append Random Data
nmap --data-length 25 192.168.1.1  # เพิ่ม random bytes

# Randomize Target Order
nmap --randomize-hosts 192.168.1.0/24

# TTL Manipulation
nmap --ttl 100 192.168.1.1
```

### Proxy และ Tunneling

```bash
# SOCKS Proxy
nmap --proxies socks4://proxy:1080 192.168.1.1
nmap --proxies socks5://proxy:1080 192.168.1.1
nmap --proxies http://proxy:8080 192.168.1.1

# Multiple proxies
nmap --proxies 'socks5://proxy1:1080,socks5://proxy2:1080' 192.168.1.1

# Proxychains กับ nmap
proxychains nmap -sT -Pn 192.168.1.1
# -sT เพราะ proxychains ไม่ support raw sockets
# -Pn เพราะ ICMP ไม่ได้ผ่าน proxy
```

---

## 2. IDS Evasion {#ids}

### Slow Scan Evasion

```bash
# Ultra-slow scan
nmap -T0 -p 80,443 192.168.1.1
# จริงๆ ช้ามาก

# Custom timing
nmap --scan-delay 5s 192.168.1.1  # 5 second delay
nmap --scan-delay 30s 192.168.1.1 # 30 second delay
nmap --max-scan-delay 100ms 192.168.1.1

# Limit rate
nmap --max-rate 1 192.168.1.0/24  # 1 packet/second
nmap --min-rate 10 192.168.1.0/24

# ระวัง: T0/T1 ช้ามากจนเสร็จไม่ได้ในเวลาอันสมเหตุสมผล
```

### MAC Spoofing

```bash
# Randomize MAC address
nmap --spoof-mac 0 192.168.1.0/24  # Random
nmap --spoof-mac Apple 192.168.1.0/24  # Random Apple MAC
nmap --spoof-mac 00:11:22:33:44:55 192.168.1.0/24  # Specific

# ซึ่งใช้ได้เฉพาะ Ethernet scan (-PR)
```

---

## 3. Advanced NSE {#nse}

### NSE Script Arguments

```bash
# Script args
nmap --script=http-brute \
    --script-args='http-brute.path=/login,userdb=users.txt,passdb=pass.txt,http-brute.method=POST' \
    -p 80 192.168.1.1

# SMB brute force
nmap --script=smb-brute \
    --script-args='smbuser=admin,smbpassword=password' \
    -p 445 192.168.1.1

# VNC auth
nmap --script=vnc-brute \
    --script-args='brute.firstonly=true' \
    -p 5900 192.168.1.1

# SNMP brute
nmap --script=snmp-brute \
    --script-args='snmpcommunity=public,brute.firstonly=true' \
    -p 161 192.168.1.1 -sU
```

### Vulnerability Scanning Scripts

```bash
# === Web Vulnerabilities ===

# Shellshock (CVE-2014-6271)
nmap --script=http-shellshock --script-args uri='/cgi-bin/admin.cgi' 192.168.1.1

# Heartbleed (CVE-2014-0160)
nmap --script=ssl-heartbleed -p 443 192.168.1.1

# POODLE
nmap --script=sslv2-drown 192.168.1.1

# Slow loris DoS test
nmap --script=http-slowloris-check -p 80 192.168.1.1

# === Windows Vulnerabilities ===

# EternalBlue (MS17-010)
nmap --script=smb-vuln-ms17-010 -p 445 192.168.1.1

# MS08-067
nmap --script=smb-vuln-ms08-067 -p 445 192.168.1.1

# BlueKeep (CVE-2019-0708)
nmap --script=rdp-vuln-ms12-020 -p 3389 192.168.1.1

# SMB Signing
nmap --script=smb-security-mode -p 445 192.168.1.1

# === RDP ===
nmap --script=rdp-enum-encryption 192.168.1.1 -p 3389
nmap --script=rdp-vuln-ms12-020 192.168.1.1 -p 3389

# === SNMP ===
nmap -sU --script=snmp-info 192.168.1.1 -p 161
nmap -sU --script=snmp-sysdescr 192.168.1.1 -p 161
```

### เช็ค Vulnerabilities Script

```bash
# รัน vuln category บน host
nmap --script=vuln -T4 192.168.1.100 -p-

# Top services
nmap --script=vuln -T4 192.168.1.100 -p 21,22,23,25,53,80,110,139,143,443,445,3306,3389,5900

# Safe vuln scripts
nmap --script='(vuln or safe)' 192.168.1.100

# บันทึก vuln scan
nmap --script=vuln -oA vuln_scan 192.168.1.100
```

---

## 4. Custom NSE Scripts {#custom-scripts}

### NSE Script โครงสร้าง

```lua
-- custom_check.nse
-- Script ตรวจสอบ custom vulnerability

-- Script metadata
description = [[
    Checks for a custom vulnerability
]]

author = "Penetration Tester"
license = "Same as Nmap"
categories = {"discovery", "safe"}

-- NSE libraries
local http = require 'http'
local shortport = require 'shortport'
local stdnse = require 'stdnse'

-- Port rule: เรียก action เมื่อ port นี้เปิด
portrule = shortport.http

-- Main function
action = function(host, port)
    -- ส่ง HTTP request
    local response = http.get(host, port, '/admin/')
    
    -- ตรวจสอบ response
    if response.status == 200 then
        return 'VULNERABLE: Admin page accessible without auth'
    elseif response.status == 401 then
        return 'Protected: Requires authentication'
    else
        return string.format('Status: %d', response.status)
    end
end
```

```bash
# รัน custom script
nmap --script=./custom_check.nse -p 80 192.168.1.1

# หรือใส่ใน nmap scripts directory
cp custom_check.nse /usr/share/nmap/scripts/
nmap --script-updatedb
nmap --script=custom_check 192.168.1.1
```

---

## 5. Masscan {#masscan}

**Masscan** - เร็วที่สุดในโลก scan ได้ 100 ล้าน ports/second

```bash
# ติดตั้ง
apt install masscan -y
masscan --version

# Basic scan
masscan 192.168.1.0/24 -p 80,443

# เร็ว scan (rate per second)
masscan 192.168.1.0/24 -p- --rate 10000

# Scan internet range
masscan 10.0.0.0/8 -p 80 --rate 100000

# Specific ports
masscan 192.168.1.0/24 -p 22,80,443,3389

# Port range
masscan 192.168.1.0/24 -p 1-65535 --rate 50000

# UDP ports
masscan 192.168.1.0/24 -pU:53,161

# Save output
masscan 192.168.1.0/24 -p 80 -oJ masscan_output.json
masscan 192.168.1.0/24 -p 80 -oX masscan_output.xml
masscan 192.168.1.0/24 -p 80 -oL masscan_output.list

# Resume scan
masscan 192.168.1.0/24 -p 80 --resume masscan.conf

# Config file
masscan -c masscan.conf

# Banner grabbing
masscan 192.168.1.0/24 -p 80 --banners
```

### Masscan Config

```bash
# masscan.conf
rate = 10000
output-format = json
output-filename = results.json
ports = 80,443,22,3389
range = 192.168.1.0/24
banner = true

# รัน config
masscan -c masscan.conf
```

---

## 6. Nmap vs Masscan {#comparison}

```
               Nmap                    Masscan
Speed:         Moderate                Very Fast
Accuracy:      High                    Moderate  
Service det:   Yes (-sV)               Basic (--banners)
Scripting:     Yes (NSE)               No
OS detect:     Yes (-O)                No
Best for:      Detailed recon          Port discovery
Evasion:       Yes                     Limited
Protocol:      TCP/UDP                 TCP/UDP

Workflow:
1. Masscan เพื่อหา open ports เร็ว
2. Nmap -sV -sC เพื่อสอบโดยละเอียด open ports ที่ masscan หาเจอ
```

```bash
# Workflow script
#!/bin/bash
TARGET=$1

# Step 1: Masscan หาพอร์ต
echo "[*] Running Masscan..."
masscan $TARGET -p- --rate 10000 -oL /tmp/masscan.txt 2>/dev/null

# ดึง open ports
OPEN_PORTS=$(grep 'open' /tmp/masscan.txt | awk '{print $3}' | tr '\n' ',' | sed 's/,$//')
echo "[+] Open ports: $OPEN_PORTS"

if [ -z "$OPEN_PORTS" ]; then
    echo "[-] No open ports"
    exit 1
fi

# Step 2: Nmap สำหรับ service detection
echo "[*] Running Nmap service detection..."
nmap -sV -sC -p "$OPEN_PORTS" -oA /tmp/nmap_services $TARGET

echo "[+] Done!"
```

---

## 7. Real-world Scenarios {#scenarios}

### Scenario 1: External Network Scan

```bash
# Reconnaissance ของ external IP
TARGET="example.com"

# Step 1: Resolve IP
TARGET_IP=$(dig +short $TARGET | head -1)
echo "Target IP: $TARGET_IP"

# Step 2: Quick port discovery
nmap -T4 -F --open $TARGET_IP

# Step 3: Full port scan
nmap -T4 -p- --open $TARGET_IP -oA full_ports

# Step 4: Service + script
nmap -sV -sC --open -p $(grep 'open' full_ports.nmap | awk '{print $1}' | cut -d/ -f1 | tr '\n' ',' | sed 's/,//') $TARGET_IP -oA services

# Step 5: Vuln scan
nmap --script=vuln -p 80,443,22 $TARGET_IP
```

### Scenario 2: Internal Network Audit

```bash
# Internal network audit

# Phase 1: Host discovery
nmap -sn 192.168.1.0/24 -oN live_hosts.txt

# Phase 2: Service scan
for host in $(grep 'report for' live_hosts.txt | awk '{print $5}'); do
    echo "[*] Scanning $host"
    nmap -T4 -sV --open -p 22,80,443,3306,3389,445,23 $host -oN scan_$host.txt 2>/dev/null
done

# Phase 3: Aggregate results
grep -h 'open' scan_*.txt | sort -u > open_ports_summary.txt

# Phase 4: Windows hosts
for host in $(grep -l '445/tcp.*open' scan_*.txt | sed 's/scan_//; s/.txt//'); do
    echo "[*] SMB scan: $host"
    nmap --script='smb-*' -p 445 $host
done
```

### Scenario 3: Web Application Discovery

```bash
# สำรวจ web services
nmap -sV --script='http-*' -p 80,443,8080,8443 192.168.1.0/24 --open

# ดึง web titles
nmap --script=http-title -p 80,443,8080,8443 192.168.1.0/24 --open | \
    grep -E 'http-title|report for'

# เช็ค default credentials
nmap --script='http-default-accounts' -p 80,443 192.168.1.0/24
```

---

## 8. แบบฝึกหัด {#exercises}

### Lab 1: Evasion Testing
1. ใช้ Kali VM กับ Metasploitable VM
2. Normal scan vs decoy scan
3. ครวจสอบ Snort/Suricata alerts
4. Compare detection

### Lab 2: Custom NSE Script
1. เขียน script สำหรับหาหน้า admin page
2. Test บน Metasploitable
3. เพิ่ม logic เช็ค authentication

### Lab 3: Masscan + Nmap Pipeline
1. Masscan หา ports ใน lab network
2. Nmap สำหรับ service detection
3. Compare results

---
*Part 18/100+ | Kali Linux Penetration Testing Course*
