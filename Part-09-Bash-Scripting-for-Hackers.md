# Part 09: Bash Scripting for Hackers
## การเขียน Bash Script สำหรับ Penetration Testing

---

## สารบัญ
1. [พื้นฐาน Bash Scripting](#พื้นฐาน)
2. [Variables และ Arrays](#variables)
3. [Conditional Statements](#conditions)
4. [Loops](#loops)
5. [Functions](#functions)
6. [Input/Output](#io)
7. [Network Scanning Scripts](#network-scanning)
8. [Automation Scripts](#automation)
9. [แบบฝึกหัด](#exercises)

---

## 1. พื้นฐาน Bash Scripting {#พื้นฐาน}

### โครงสร้างพื้นฐาน

```bash
#!/bin/bash
# Script: my_first_script.sh
# Description: สคริปต์แรกของฉัน
# Author: Hacker
# Date: 2024

echo "Hello, Hacker World!"
echo "Current User: $(whoami)"
echo "Hostname: $(hostname)"
echo "IP Address: $(hostname -I | awk '{print $1}')"
```

### การ Run Script

```bash
# วิธีที่ 1: ให้สิทธิ์และรัน
chmod +x script.sh
./script.sh

# วิธีที่ 2: รันโดยตรง
bash script.sh

# วิธีที่ 3: source (รันใน current shell)
source script.sh
. script.sh
```

### Shebang Lines

```bash
#!/bin/bash          # Bash (แนะนำ)
#!/bin/sh            # POSIX sh
#!/usr/bin/env bash  # Portable bash
#!/usr/bin/env python3  # Python
```

---

## 2. Variables และ Arrays {#variables}

### การประกาศตัวแปร

```bash
#!/bin/bash

# ตัวแปรธรรมดา
TARGET="192.168.1.1"
PORT=80
USERNAME="admin"

# ตัวแปรจาก Command Output
CURRENT_IP=$(ip route get 1 | awk '{print $7}' | head -1)
DATE=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname)

# ตัวแปร Read-only
readonly LOG_DIR="/var/log/pentest"

# Export ตัวแปร (ส่งให้ child process)
export TARGET
export PORT

# แสดงค่าตัวแปร
echo "Target: $TARGET"
echo "Target: ${TARGET}"  # รูปแบบที่แนะนำ
echo "Port: ${PORT}"
echo "My IP: ${CURRENT_IP}"
```

### String Operations

```bash
#!/bin/bash

URL="https://www.example.com/admin/login.php"

# ความยาว String
echo "Length: ${#URL}"

# Substring
echo "First 8: ${URL:0:8}"     # https://
echo "From pos 8: ${URL:8}"    # www.example.com/admin/login.php

# Replace
echo "${URL/http/ftp}"          # แทนที่ครั้งแรก
echo "${URL//http/ftp}"         # แทนที่ทั้งหมด

# Trim
DOMAIN="  example.com  "
echo "Original: '${DOMAIN}'"
TRIMMED=$(echo $DOMAIN | xargs)
echo "Trimmed: '${TRIMMED}'"

# Upper/Lower case
HOST="www.Example.COM"
echo "Upper: ${HOST^^}"
echo "Lower: ${HOST,,}"
echo "First Upper: ${HOST^}"

# ตัด path
FILE="/home/user/documents/report.pdf"
echo "Filename: ${FILE##*/}"    # report.pdf
echo "Directory: ${FILE%/*}"   # /home/user/documents
echo "No ext: ${FILE%.*}"      # /home/user/documents/report
echo "Extension: ${FILE##*.}"  # pdf
```

### Arrays

```bash
#!/bin/bash

# Array ธรรมดา
TARGETS=("192.168.1.1" "192.168.1.2" "192.168.1.100" "10.0.0.1")
PORTS=(21 22 23 25 53 80 110 443 3306 3389)

# เข้าถึงสมาชิก
echo "First: ${TARGETS[0]}"
echo "Second: ${TARGETS[1]}"
echo "Last: ${TARGETS[-1]}"
echo "All: ${TARGETS[@]}"
echo "Count: ${#TARGETS[@]}"

# เพิ่ม/ลบสมาชิก
TARGETS+=("172.16.0.1")           # เพิ่มท้าย
unset TARGETS[1]                   # ลบ index 1

# Loop ผ่าน Array
for target in "${TARGETS[@]}"; do
    echo "Scanning: $target"
done

# Array จาก Output
LIVE_HOSTS=($(nmap -sn 192.168.1.0/24 | grep 'report for' | awk '{print $5}'))
echo "Found ${#LIVE_HOSTS[@]} live hosts"

# Associative Array (Dictionary)
declare -A SERVICES
SERVICES[21]="FTP"
SERVICES[22]="SSH"
SERVICES[80]="HTTP"
SERVICES[443]="HTTPS"
SERVICES[3389]="RDP"

for port in "${!SERVICES[@]}"; do
    echo "Port ${port}: ${SERVICES[$port]}"
done
```

### Special Variables

```bash
#!/bin/bash

echo "Script name: $0"
echo "First argument: $1"
echo "Second argument: $2"
echo "All arguments: $@"
echo "Number of args: $#"
echo "Process ID: $$"
echo "Last PID: $!"
echo "Last exit code: $?"

# ตัวอย่างการใช้ arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <target_ip> <port>"
    echo "Example: $0 192.168.1.1 80"
    exit 1
fi

TARGET=$1
PORT=$2
echo "Scanning $TARGET:$PORT"
```

---

## 3. Conditional Statements {#conditions}

### if-elif-else

```bash
#!/bin/bash

PORT=$1

if [ -z "$PORT" ]; then
    echo "[ERROR] กรุณาระบุ port"
    exit 1
elif [ $PORT -lt 1 ] || [ $PORT -gt 65535 ]; then
    echo "[ERROR] Port ต้องอยู่ระหว่าง 1-65535"
    exit 1
elif [ $PORT -le 1024 ]; then
    echo "[INFO] Well-known port (1-1024)"
else
    echo "[INFO] High port (1025-65535)"
fi
```

### Comparison Operators

```bash
#!/bin/bash

# ตัวเลข
[ $a -eq $b ]   # เท่ากัน (equal)
[ $a -ne $b ]   # ไม่เท่ากัน (not equal)
[ $a -lt $b ]   # น้อยกว่า (less than)
[ $a -le $b ]   # น้อยกว่าหรือเท่ากัน
[ $a -gt $b ]   # มากกว่า (greater than)
[ $a -ge $b ]   # มากกว่าหรือเท่ากัน

# String
[ "$a" == "$b" ]  # เท่ากัน
[ "$a" != "$b" ]  # ไม่เท่ากัน
[ -z "$a" ]       # ว่างเปล่า
[ -n "$a" ]       # ไม่ว่างเปล่า

# File/Directory
[ -f "$file" ]    # เป็นไฟล์
[ -d "$dir" ]     # เป็น directory
[ -e "$path" ]    # มีอยู่
[ -r "$file" ]    # อ่านได้
[ -w "$file" ]    # เขียนได้
[ -x "$file" ]    # execute ได้
[ -s "$file" ]    # ไม่ว่างเปล่า (size > 0)

# Logical
[ $a -gt 0 ] && [ $b -gt 0 ]  # AND
[ $a -gt 0 ] || [ $b -gt 0 ]  # OR
! [ $a -gt 0 ]                 # NOT
```

### Case Statement

```bash
#!/bin/bash

SERVICE=$1

case $SERVICE in
    "ftp"|"21")
        echo "FTP - File Transfer Protocol"
        echo "Tools: ftp, lftp, curl"
        echo "Attack: Brute force, Anonymous login"
        ;;
    "ssh"|"22")
        echo "SSH - Secure Shell"
        echo "Tools: ssh, hydra, medusa"
        echo "Attack: Brute force, Key theft"
        ;;
    "http"|"80")
        echo "HTTP - Web Service"
        echo "Tools: nikto, dirb, burpsuite"
        echo "Attack: SQLi, XSS, Directory traversal"
        ;;
    "https"|"443")
        echo "HTTPS - Secure Web Service"
        echo "Tools: nikto, dirb, burpsuite, sslscan"
        echo "Attack: SQLi, XSS, SSL vulnerabilities"
        ;;
    "smb"|"445")
        echo "SMB - File Sharing"
        echo "Tools: smbclient, crackmapexec, impacket"
        echo "Attack: EternalBlue, Pass-the-Hash"
        ;;
    "rdp"|"3389")
        echo "RDP - Remote Desktop"
        echo "Tools: xfreerdp, rdesktop, hydra"
        echo "Attack: Brute force, BlueKeep"
        ;;
    *)
        echo "Unknown service: $SERVICE"
        ;;
esac
```

---

## 4. Loops {#loops}

### For Loop

```bash
#!/bin/bash

# Loop ผ่าน list
for ip in 192.168.1.1 192.168.1.2 192.168.1.3; do
    echo "Pinging $ip..."
    ping -c 1 -W 1 $ip > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "$ip is UP"
    else
        echo "$ip is DOWN"
    fi
done

# C-style for loop
for ((i=1; i<=254; i++)); do
    IP="192.168.1.$i"
    ping -c 1 -W 1 $IP > /dev/null 2>&1 && echo "$IP is UP"
done

# Loop ผ่าน range
for port in {1..1024}; do
    echo "Checking port $port"
done

# Loop ผ่านไฟล์
while IFS= read -r line; do
    echo "Testing password: $line"
done < /usr/share/wordlists/rockyou.txt

# Loop ผ่าน files
for file in /var/log/*.log; do
    echo "Analyzing: $file"
    grep -i "error\|fail\|attack" "$file" 2>/dev/null
done
```

### While Loop

```bash
#!/bin/bash

# Basic while
COUNTER=0
while [ $COUNTER -lt 10 ]; do
    echo "Count: $COUNTER"
    ((COUNTER++))
done

# อ่านไฟล์ทีละบรรทัด
while IFS= read -r target; do
    # ข้ามบรรทัดว่างและ comment
    [[ -z "$target" || "$target" == "#"* ]] && continue
    
    echo "[*] Scanning: $target"
    nmap -sV --open -T4 "$target" 2>/dev/null | grep 'open'
done < targets.txt

# Infinite loop พร้อม break
while true; do
    read -p "Enter command (quit to exit): " cmd
    case $cmd in
        quit|exit|q) break ;;
        *) eval "$cmd" ;;
    esac
done

# Monitor ไฟล์
tail -f /var/log/auth.log | while read line; do
    if echo "$line" | grep -q "Failed password"; then
        echo "[ALERT] Failed login attempt: $line"
        # ส่ง alert
    fi
done
```

### Until Loop

```bash
#!/bin/bash

# Until loop (ทำจนกว่าเงื่อนไขจะเป็น true)
ATTEMPTS=0
until ping -c 1 -W 1 192.168.1.1 > /dev/null 2>&1; do
    echo "Host unreachable, retrying..."
    ((ATTEMPTS++))
    if [ $ATTEMPTS -ge 10 ]; then
        echo "Host is down after 10 attempts"
        exit 1
    fi
    sleep 2
done
echo "Host is UP!"
```

---

## 5. Functions {#functions}

### การสร้างและใช้ Functions

```bash
#!/bin/bash

# Function ธรรมดา
check_root() {
    if [ $(id -u) -ne 0 ]; then
        echo "[ERROR] Script ต้องรันด้วย root"
        exit 1
    fi
    echo "[OK] Running as root"
}

# Function พร้อม parameters
scan_port() {
    local host=$1
    local port=$2
    local timeout=${3:-1}  # default 1 second
    
    timeout $timeout bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
    return $?  # 0=open, 1=closed/filtered
}

# Function ที่ return ค่า
get_os() {
    local target=$1
    local ttl
    
    ttl=$(ping -c 1 $target 2>/dev/null | grep ttl | awk -F'ttl=' '{print $2}' | awk '{print $1}')
    
    if [ -z "$ttl" ]; then
        echo "unknown"
    elif [ $ttl -le 64 ]; then
        echo "Linux/Unix"
    elif [ $ttl -le 128 ]; then
        echo "Windows"
    else
        echo "Network Device"
    fi
}

# Function ที่ print ผลลัพธ์
print_banner() {
    local title=$1
    local width=60
    
    echo ""
    printf '%0.s=' $(seq 1 $width)
    echo ""
    printf "| %-$((width-4))s |\n" "$title"
    printf '%0.s=' $(seq 1 $width)
    echo ""
}

# Function สี
print_info()    { echo -e "\e[34m[*]\e[0m $1"; }
print_success() { echo -e "\e[32m[+]\e[0m $1"; }
print_warning() { echo -e "\e[33m[!]\e[0m $1"; }
print_error()   { echo -e "\e[31m[-]\e[0m $1"; }

# ใช้งาน functions
check_root
print_banner "Network Scanner"

TARGET="192.168.1.1"
OS=$(get_os $TARGET)
print_info "Target OS: $OS"

for port in 22 80 443 3306; do
    if scan_port $TARGET $port; then
        print_success "Port $port is OPEN"
    else
        print_warning "Port $port is CLOSED"
    fi
done
```

---

## 6. Input/Output {#io}

### Input

```bash
#!/bin/bash

# รับ input จาก user
read -p "Enter target IP: " TARGET
read -s -p "Enter password: " PASSWORD  # -s ไม่แสดงอักษร
echo ""  # ขึ้นบรรทัดใหม่หลัง password
read -t 10 -p "Continue? (y/n): " CONFIRM  # timeout 10 วินาที

# รับ input หลาย values
read -p "Enter IP range (e.g., 192.168.1): " RANGE
for i in $(seq 1 254); do
    echo "$RANGE.$i"
done

# Select menu
PS3="Select scan type: "
SCAN_TYPES=("Quick Scan" "Full Scan" "Stealth Scan" "Service Detection" "Quit")
select scan_type in "${SCAN_TYPES[@]}"; do
    case $scan_type in
        "Quick Scan")
            nmap -T4 -F "$TARGET"
            ;;
        "Full Scan")
            nmap -T4 -p- "$TARGET"
            ;;
        "Stealth Scan")
            nmap -sS -T2 "$TARGET"
            ;;
        "Service Detection")
            nmap -sV -sC "$TARGET"
            ;;
        "Quit")
            break
            ;;
        *)
            echo "Invalid option"
            ;;
    esac
done
```

### Output และ Logging

```bash
#!/bin/bash

LOG_FILE="/tmp/pentest_$(date +%Y%m%d_%H%M%S).log"

# Function logging
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Redirect output
nmap -sV 192.168.1.1 > /tmp/nmap_output.txt 2>&1
nmap -sV 192.168.1.1 >> /tmp/nmap_output.txt  # append
nmap -sV 192.168.1.1 2>/dev/null               # ซ่อน errors
nmap -sV 192.168.1.1 | tee -a scan.log         # screen + file

# Colored output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

echo -e "${RED}Error!${NC}"
echo -e "${GREEN}Success!${NC}"
echo -e "${YELLOW}Warning!${NC}"
echo -e "${BLUE}Info${NC}"

# Progress bar
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percent=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    
    printf "\r["
    printf '%0.s#' $(seq 1 $filled)
    printf '%0.s-' $(seq 1 $empty)
    printf "] %d%%" $percent
    
    [ $current -eq $total ] && echo ""
}

for i in $(seq 1 100); do
    show_progress $i 100
    sleep 0.05
done
```

---

## 7. Network Scanning Scripts {#network-scanning}

### Port Scanner อย่างง่าย

```bash
#!/bin/bash
# port_scanner.sh - Simple port scanner using /dev/tcp

print_banner() {
    echo "================================="
    echo "  Simple Port Scanner v1.0"
    echo "================================="
}

usage() {
    echo "Usage: $0 <target> [start_port] [end_port]"
    echo "Example: $0 192.168.1.1 1 1024"
    exit 1
}

scan_port() {
    local host=$1
    local port=$2
    (echo >/dev/tcp/$host/$port) 2>/dev/null && echo "[OPEN] Port $port"
}

# Main
print_banner

[ $# -lt 1 ] && usage

TARGET=$1
START=${2:-1}
END=${3:-1024}

echo "[*] Scanning $TARGET ports $START-$END"
echo "[*] Started at: $(date)"
echo ""

for port in $(seq $START $END); do
    scan_port $TARGET $port &  # Background สำหรับความเร็ว
done

wait  # รอให้ทุก background job เสร็จ

echo ""
echo "[*] Scan complete at: $(date)"
```

### Network Discovery Script

```bash
#!/bin/bash
# network_discovery.sh - Discover live hosts

[ $# -lt 1 ] && { echo "Usage: $0 <network> (e.g., 192.168.1)"; exit 1; }

NETWORK=$1
LIVE_HOSTS=()
SCAN_TIME=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="/tmp/discovery_$SCAN_TIME"
mkdir -p "$OUTPUT_DIR"

echo "[*] Discovering hosts in $NETWORK.0/24"
echo "[*] Output: $OUTPUT_DIR"

# Ping sweep
ping_sweep() {
    local ip=$1
    if ping -c 1 -W 1 $ip > /dev/null 2>&1; then
        echo "$ip"
    fi
}

export -f ping_sweep

# Parallel ping sweep
HOSTS=$(seq 1 254 | xargs -P 20 -I{} bash -c 'ping_sweep "'$NETWORK'.{}"')

echo "$HOSTS" > "$OUTPUT_DIR/live_hosts.txt"

echo "[+] Found $(echo "$HOSTS" | wc -l) live hosts:"
echo "$HOSTS"

# Basic port scan ของ live hosts
if [ -s "$OUTPUT_DIR/live_hosts.txt" ]; then
    echo ""
    echo "[*] Running quick port scan on live hosts..."
    
    while read -r host; do
        echo "[*] Scanning $host..."
        nmap -T4 -F "$host" 2>/dev/null | grep 'open' | sed "s/^/$host: /"
    done < "$OUTPUT_DIR/live_hosts.txt"
fi

echo ""
echo "[+] Discovery complete. Results saved to $OUTPUT_DIR/"
```

### Web Directory Bruteforce Script

```bash
#!/bin/bash
# web_dirbrute.sh - Directory bruteforcer

TARGET=$1
WORDLIST=${2:-/usr/share/wordlists/dirb/common.txt}
THREADS=${3:-10}

[ -z "$TARGET" ] && { echo "Usage: $0 <url> [wordlist] [threads]"; exit 1; }
[ ! -f "$WORDLIST" ] && { echo "[-] Wordlist not found: $WORDLIST"; exit 1; }

OUTPUT_FILE="/tmp/dirbrute_$(date +%Y%m%d_%H%M%S).txt"

echo "[*] Target: $TARGET"
echo "[*] Wordlist: $WORDLIST ($(wc -l < $WORDLIST) words)"
echo "[*] Threads: $THREADS"

check_url() {
    local url=$1
    local dir=$2
    local full_url="$url/$dir"
    
    status=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 5 "$full_url")
    
    case $status in
        200) echo "[200 OK] $full_url" | tee -a "$OUTPUT_FILE" ;;
        301|302) echo "[${status} REDIRECT] $full_url" | tee -a "$OUTPUT_FILE" ;;
        403) echo "[403 FORBIDDEN] $full_url" | tee -a "$OUTPUT_FILE" ;;
        401) echo "[401 AUTH REQUIRED] $full_url" | tee -a "$OUTPUT_FILE" ;;
    esac
}

export -f check_url
export OUTPUT_FILE

# Run with parallel processing
cat "$WORDLIST" | xargs -P $THREADS -I{} bash -c 'check_url "'$TARGET'" "{}"'

echo ""
echo "[+] Results saved to: $OUTPUT_FILE"
echo "[+] Found: $(grep -c '\[' $OUTPUT_FILE 2>/dev/null || echo 0) paths"
```

---

## 8. Automation Scripts {#automation}

### Auto Recon Script

```bash
#!/bin/bash
# auto_recon.sh - Automated reconnaissance

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════╗"
    echo "║         AUTO RECON v1.0               ║"
    echo "║   Automated Penetration Testing       ║"
    echo "╚═══════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check dependencies
check_deps() {
    local deps=("nmap" "nikto" "gobuster" "curl" "whois")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing tools: ${missing[*]}"
        error "Install with: apt-get install ${missing[*]}"
        exit 1
    fi
    success "All dependencies found"
}

# Setup output directory
setup_output() {
    local target=$1
    OUTPUT_DIR="./recon_${target//\//_}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTPUT_DIR"/{nmap,web,vuln,logs}
    log "Output directory: $OUTPUT_DIR"
}

# Phase 1: Port Scanning
phase_portscan() {
    log "Phase 1: Port Scanning"
    
    # Quick scan
    log "Running quick scan..."
    nmap -T4 -F --open -oA "$OUTPUT_DIR/nmap/quick" "$TARGET" 2>/dev/null
    
    # Full TCP scan
    log "Running full TCP scan..."
    nmap -T4 -p- --open -oA "$OUTPUT_DIR/nmap/full_tcp" "$TARGET" 2>/dev/null &
    
    # Service detection on common ports
    log "Detecting services..."
    nmap -T4 -sV -sC -p 21,22,23,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5900,8080,8443 \
        --open -oA "$OUTPUT_DIR/nmap/services" "$TARGET" 2>/dev/null
    
    success "Port scanning complete"
    
    # Extract open ports
    OPEN_PORTS=$(grep 'open' "$OUTPUT_DIR/nmap/services.nmap" | grep -v '#' | awk '{print $1}' | cut -d'/' -f1)
    log "Open ports: $OPEN_PORTS"
}

# Phase 2: Web Scanning
phase_webscan() {
    log "Phase 2: Web Application Scanning"
    
    # Check if web ports open
    for port in 80 443 8080 8443; do
        if nmap -p $port --open "$TARGET" 2>/dev/null | grep -q 'open'; then
            if [ $port -eq 443 ] || [ $port -eq 8443 ]; then
                PROTO="https"
            else
                PROTO="http"
            fi
            
            WEB_URL="${PROTO}://${TARGET}:${port}"
            log "Scanning web: $WEB_URL"
            
            # Nikto scan
            nikto -h "$WEB_URL" -output "$OUTPUT_DIR/web/nikto_${port}.txt" 2>/dev/null &
            
            # Directory brute force
            gobuster dir -u "$WEB_URL" \
                -w /usr/share/wordlists/dirb/common.txt \
                -o "$OUTPUT_DIR/web/gobuster_${port}.txt" \
                -t 20 -q 2>/dev/null &
        fi
    done
    
    wait
    success "Web scanning complete"
}

# Phase 3: Report Generation
generate_report() {
    local report="$OUTPUT_DIR/report.txt"
    
    echo "==============================" > "$report"
    echo "RECON REPORT" >> "$report"
    echo "Target: $TARGET" >> "$report"
    echo "Date: $(date)" >> "$report"
    echo "==============================" >> "$report"
    echo "" >> "$report"
    
    echo "=== OPEN PORTS ==" >> "$report"
    grep 'open' "$OUTPUT_DIR/nmap/services.nmap" 2>/dev/null >> "$report"
    
    echo "" >> "$report"
    echo "=== WEB FINDINGS ==" >> "$report"
    cat "$OUTPUT_DIR/web/"*.txt 2>/dev/null >> "$report"
    
    success "Report saved to: $report"
}

# Main
banner
check_deps

[ $# -lt 1 ] && { error "Usage: $0 <target>"; exit 1; }
TARGET=$1

setup_output "$TARGET"
phase_portscan
phase_webscan
generate_report

success "Recon complete! Results in: $OUTPUT_DIR"
```

### Password Spray Script

```bash
#!/bin/bash
# password_spray.sh - Password spraying (for authorized testing only)

TARGET=$1
USERLIST=$2
PASSWORD=$3
SERVICE=${4:-ssh}

[ $# -lt 3 ] && { echo "Usage: $0 <target> <userlist> <password> [service]"; exit 1; }

echo "[*] Password Spray Attack"
echo "[*] Target: $TARGET"
echo "[*] Service: $SERVICE"
echo "[*] Password: $PASSWORD"
echo "[*] Users: $(wc -l < $USERLIST)"
echo ""

SUCCESSES=()

while read -r username; do
    [[ -z "$username" || "$username" == '#'* ]] && continue
    
    case $SERVICE in
        ssh)
            result=$(timeout 5 sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=3 "$username@$TARGET" 'echo SUCCESS' 2>&1)
            ;;
        ftp)
            result=$(timeout 5 curl -s --connect-timeout 3 \
                "ftp://$username:$PASSWORD@$TARGET/" 2>&1 | head -1)
            ;;
    esac
    
    if echo "$result" | grep -q 'SUCCESS\|230\|Login'; then
        echo "[SUCCESS] $username:$PASSWORD"
        SUCCESSES+=("$username")
    else
        echo "[-] $username:$PASSWORD - Failed"
    fi
    
    sleep 1  # หน่วงเวลาป้องกัน lockout
done < "$USERLIST"

echo ""
echo "[+] Successful logins:"
for user in "${SUCCESSES[@]}"; do
    echo "  - $user:$PASSWORD"
done
```

---

## 9. แบบฝึกหัด {#exercises}

### Lab 1: Port Scanner

สร้าง script ที่:
1. รับ IP range เป็น argument (เช่น 192.168.1)
2. ทำ ping sweep หา live hosts
3. สำหรับ live hosts แต่ละตัว scan top 100 ports
4. บันทึกผลลัพธ์เป็น CSV format
5. แสดง summary เมื่อเสร็จ

```bash
# Template
#!/bin/bash
NETWORK=$1
[ -z "$NETWORK" ] && { echo "Usage: $0 <network>"; exit 1; }

# TODO: Implement ping sweep
# TODO: Implement port scan
# TODO: Save to CSV
# TODO: Show summary
```

### Lab 2: Log Analyzer

สร้าง script วิเคราะห์ /var/log/auth.log:
1. นับจำนวน failed login attempts
2. แสดง top 10 attacking IPs
3. แสดง top 10 targeted usernames
4. แจ้งเตือนหาก IP ใด attempt มากกว่า 100 ครั้ง

```bash
LOG_FILE="/var/log/auth.log"

# Failed attempts count
FAILED=$(grep 'Failed password' $LOG_FILE | wc -l)
echo "Total failed attempts: $FAILED"

# Top attacking IPs
echo "Top 10 attacking IPs:"
grep 'Failed password' $LOG_FILE | \
    awk '{print $(NF-3)}' | \
    sort | uniq -c | sort -rn | head -10
```

### Lab 3: Web Recon Script

สร้าง script สำหรับ web reconnaissance:
1. ตรวจสอบ HTTP headers
2. หา robots.txt และ sitemap.xml
3. ตรวจสอบ SSL certificate
4. Detect web technologies (Server header, X-Powered-By)
5. Check common admin pages

---

## สรุป

| ทักษะ | การใช้งาน |
|-------|----------|
| Variables | เก็บ target, results |
| Arrays | จัดการ IP lists, port lists |
| Functions | modular code, reusability |
| Loops | scan multiple targets |
| I/O | logging, user input |
| Parallel | เพิ่มความเร็วการ scan |

**ข้อสำคัญ**: ใช้ scripts เหล่านี้เฉพาะบนระบบที่ได้รับอนุญาตเท่านั้น!

---
*Part 09/100+ | Kali Linux Penetration Testing Course*
