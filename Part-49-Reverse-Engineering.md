# Part 49: Reverse Engineering

> **หลักสูตร Kali Linux จาก Zero ถึง Professional**  
> Part 49 of 100+ | ระดับ: Advanced

---

## สารบัญ

1. [Reverse Engineering คืออะไร](#1-re-intro)
2. [Assembly พื้นฐาน](#2-assembly)
3. [Static RE ด้วย Ghidra](#3-ghidra)
4. [Dynamic RE ด้วย GDB](#4-gdb)
5. [Windows RE ด้วย x64dbg](#5-x64dbg)
6. [Crackme Walkthroughs](#6-crackme)
7. [Obfuscation และ Packing](#7-obfuscation)
8. [Python Reversing](#8-python)
9. [แบบฝึกหัด Lab](#9-lab)

---

## 1. RE คืออะไร

### 1.1 วัตถุประสงค์

```
Reverse Engineering = การวิเคราะห์โปรแกรมโดยไม่มี source code

ประยุกต์ใช้:
  - Malware Analysis
  - Vulnerability Research
  - CTF challenges
  - Patch analysis
  - License bypass (authorized testing)
  - Firmware analysis

ขั้นตอน:
  Source Code → Compiler → Assembly → Machine Code
                                   ← Disassembler
             ← Decompiler
```

### 1.2 ติดตั้ง Tools

```bash
# ติดตั้ง RE tools
sudo apt install ghidra radare2 gdb gdb-peda binutils -y
pip3 install pwntools capstone keystone-engine unicorn

# GDB plugins
# PEDA (Python Exploit Development Assistant)
git clone https://github.com/longld/peda.git ~/peda
echo 'source ~/peda/peda.py' >> ~/.gdbinit

# GEF (GDB Enhanced Features)
curl -sSL https://gef.blah.cat/sh | sh

# pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

---

## 2. Assembly พื้นฐาน

### 2.1 x86/x64 Registers

```
General Purpose Registers (x64):
┌────────────────────────────────────────────────┐
│  64-bit  32-bit  16-bit  8-bit  Purpose          │
├────────────────────────────────────────────────┤
│  RAX     EAX     AX      AL     Accumulator      │
│  RBX     EBX     BX      BL     Base             │
│  RCX     ECX     CX      CL     Counter          │
│  RDX     EDX     DX      DL     Data             │
│  RSI     ESI     SI      SIL    Source Index     │
│  RDI     EDI     DI      DIL    Destination      │
│  RSP     ESP     SP      SPL    Stack Pointer    │
│  RBP     EBP     BP      BPL    Base Pointer     │
│  RIP     EIP     IP      -      Instruction Ptr  │
│  R8-R15  R8d-R15d...            Extra (x64 only) │
└────────────────────────────────────────────────┘

Linux x64 syscall convention:
  RAX = syscall number
  RDI = arg1, RSI = arg2, RDX = arg3
  R10 = arg4, R8 = arg5, R9 = arg6

Windows x64 calling convention:
  RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
  Shadow space (32 bytes) ต้อง reserve
```

### 2.2 Common Instructions

```nasm
; Data Movement
mov rax, rbx        ; rax = rbx
mov rax, [rbx]      ; rax = *rbx (memory dereference)
mov [rbx], rax      ; *rbx = rax
lea rax, [rbx+8]    ; rax = rbx + 8 (address, no deref)
push rax            ; RSP -= 8; *RSP = rax
pop rax             ; rax = *RSP; RSP += 8

; Arithmetic
add rax, rbx        ; rax += rbx
sub rax, rbx        ; rax -= rbx
imul rax, rbx       ; rax *= rbx (signed)
idiv rcx            ; rax = rdx:rax / rcx
inc rax             ; rax++
dec rax             ; rax--

; Bitwise
and rax, rbx        ; rax &= rbx
or  rax, rbx        ; rax |= rbx
xor rax, rax        ; rax = 0 (clear register)
not rax             ; rax = ~rax
shl rax, 2          ; rax <<= 2
shr rax, 2          ; rax >>= 2

; Control Flow
cmp rax, rbx        ; ตั้ง flags: rax - rbx
test rax, rax       ; ตั้ง flags: rax & rax
jmp label           ; unconditional jump
je  label           ; jump if equal (ZF=1)
jne label           ; jump if not equal
jl  label           ; jump if less (signed)
jg  label           ; jump if greater
jle label           ; jump if less or equal
jge label           ; jump if greater or equal
call func           ; push RIP; jmp func
ret                 ; pop RIP (return)

; String/Memory
rep movsb           ; copy ECX bytes from RSI to RDI
rep stosb           ; fill ECX bytes at RDI with AL
nop                 ; no operation (0x90)
```

### 2.3 พื้นฐาน Assembly Programming

```nasm
; hello_world.asm (Linux x64)
section .data
    msg db 'Hello, World!', 0x0a
    len equ $ - msg

section .text
    global _start

_start:
    ; write(1, msg, len)
    mov rax, 1      ; syscall: write
    mov rdi, 1      ; fd: stdout
    mov rsi, msg    ; buf
    mov rdx, len    ; count
    syscall
    
    ; exit(0)
    mov rax, 60     ; syscall: exit
    xor rdi, rdi    ; status: 0
    syscall
```

```bash
# compile และ run
nasm -f elf64 hello_world.asm -o hello_world.o
ld hello_world.o -o hello_world
./hello_world
```

---

## 3. Ghidra

### 3.1 การใช้งานเบื้องต้น

```bash
# เริ่ม Ghidra
cd /opt/ghidra
./ghidraRun

# จาก GUI:
# 1. File → New Project
# 2. File → Import File → เลือก binary
# 3. Double-click ไฟล์ → Analysis → Yes
# 4. Window → Symbol Tree (ดู functions)
# 5. คลิก function → Decompiler แสดง C-like code

# Ghidra Script (Python)
# Window → Script Manager → New Script
```

### 3.2 Ghidra Scripting

```python
# ghidra_script.py - รันใน Ghidra Script Manager

# ค้นหา hardcoded strings
from ghidra.program.model.symbol import SymbolType

string_data = []
for data in currentProgram.getListing().getDefinedData(True):
    if data.getDataType().getName() == 'TerminatedCString':
        val = data.getValue()
        if isinstance(val, str) and len(val) > 3:
            string_data.append((data.getAddress(), val))

print("Strings found:")
for addr, s in string_data[:50]:
    print(f"  0x{addr}: {repr(s)}")

# ค้นหา cross-references
from ghidra.app.util.query import TableService
from ghidra.program.util import ProgramLocation

# หา function ที่ชื่อสูง
for func in currentProgram.getFunctionManager().getFunctions(True):
    if func.isThunk():
        continue
    if func.getParameterCount() >= 3:
        print(f"Complex function: {func.getName()} @ 0x{func.getEntryPoint()}")
```

### 3.3 หา Flag ใน Crackme

```
Workflow สำหรับ Crackme:

1. เปิด Ghidra
2. Import binary
3. Run auto-analysis
4. เปิด main() function
5. ดู Decompiler view
6. หา strcmp/strncmp call
7. ติดตาม function ที่ตรวจสอบ password
8. หาค่าที่เปรียบเทียบ

ตัวอย่าง Decompiler output:
  void check_password(char *input) {
    if (strcmp(input, "s3cr3t_p4ss") == 0) {
      printf("Correct!\n");
    }
  }
  → password = "s3cr3t_p4ss"
```

---

## 4. GDB

### 4.1 GDB พื้นฐาน

```bash
# เริ่มใช้งาน
gdb ./binary

# คำสั่งสำคัญ
run [args]        # รันโปรแกรม
break main        # breakpoint ที่ main
break *0x401234   # breakpoint ที่ address
break func_name   # breakpoint ที่ function

info breakpoints  # ดู breakpoints
delete 1          # ลบ breakpoint 1

next              # step over
step              # step into
continue          # continue execution
finish            # run until function return

info registers    # ดู registers
print $rax        # ดูค่า rax
print/x $rax      # ดูเป็น hex
print/s $rsi      # ดูเป็น string

# examine memory
x/16x $rsp        # 16 hex words จาก RSP
x/20i $rip        # 20 instructions จาก RIP
x/s 0x401234      # string ที่ address
x/10b 0x401234    # 10 bytes

backtrace         # call stack
frame 0           # เลือก frame

set $rax = 0      # ตั้งค่า register
set *0x401234 = 1 # ตั้งค่า memory
```

### 4.2 GDB PEDA/GEF

```bash
# เปิดใช้ PEDA (installed in ~/.gdbinit)
gdb ./binary

# PEDA commands:
pdisass main          # แสดง disassembly
context               # แสดง registers + stack + code
find /bin/sh          # ค้นหา /bin/sh string
pattc 200             # create cyclic pattern
patto AAAA            # find offset
trace                 # trace execution
assemble              # เขียน assembly
readelf               # อ่าน ELF info
checksec              # ดูการป้องกัน

# GEF commands:
gef> heap chunks      # ดู heap
gef> vmmap            # ดู memory map
gef> got              # GOT table
gef> telescope $rsp 20 # ดู stack
gef> rop              # find ROP gadgets
```

### 4.3 Debugging ตัวอย่าง

```bash
# สร้าง binary สำหรับฝึก
cat > /tmp/crackme.c << 'EOF'
#include <stdio.h>
#include <string.h>

int main() {
    char input[50];
    printf("Password: ");
    scanf("%49s", input);
    
    // obfuscated comparison
    int check = 0;
    char secret[] = "hack3rm4n";
    for (int i = 0; i < strlen(input); i++) {
        if (i >= strlen(secret)) break;
        check += (input[i] ^ secret[i]);
    }
    
    if (check == 0 && strlen(input) == strlen(secret)) {
        printf("Access granted!\n");
    } else {
        printf("Wrong password!\n");
    }
    return 0;
}
EOF
gcc -g -o /tmp/crackme /tmp/crackme.c

# Debug ด้วย GDB
gdb /tmp/crackme
# (gdb) break main
# (gdb) run
# (gdb) disass main
# (gdb) break *0x<address of strcmp/comparison>
# (gdb) continue
# (gdb) print (char*)$rsi  # ดู secret string

# ltrace เบิลดง่ายกว่า
echo 'test_password' | ltrace /tmp/crackme 2>&1 | grep strcmp
```

---

## 5. Windows RE ด้วย x64dbg

### 5.1 การติดตั้ง

```bash
# Windows: ดาวน์โหลด x64dbg
# https://x64dbg.com/

# พร้อม plugins นี้:
# ScyllaHide - anti-debug bypass
# xAnalyzer - better analysis
# OllyDumpEx - dump process
```

### 5.2 x64dbg Workflow

```
x64dbg workflow:

1. File → Open → เลือก .exe
2. View → Log (ดู log)
3. Debug → Run หรือ F9
4. Search → All Modules → String references
5. หา "password", "key", "flag"
6. double-click → breakpoint
7. Run → หยุดที่ comparison
8. อ่านค่าใน registers

Shortcuts:
  F9    - Run
  F8    - Step Over
  F7    - Step Into
  F4    - Run to cursor
  F2    - Toggle breakpoint
  Ctrl+G - Go to address
  Ctrl+F - Search
```

### 5.3 Bypassing Checks

```
Techniques:

1. NOP out check:
   - หา conditional jump (je, jne)
   - แก้ไข bytes เป็น 0x90 (NOP)
   - jump จะไม่ทำงาน

2. Change jump direction:
   - je → jne (0x74 → 0x75)
   - jz → jnz

3. Patch return value:
   - หา cmp/test instruction
   - ตั้ง ZF flag ด้วย hand
   - x64dbg: modify flags ใน Registers panel

4. Modify memory:
   - Right-click → Binary → Edit
   - เปลี่ยน bytes โดยตรง

5. Python patching:
   import struct
   with open('binary.exe', 'rb') as f:
       data = bytearray(f.read())
   data[OFFSET] = 0xEB  # jmp (unconditional)
   with open('patched.exe', 'wb') as f:
       f.write(data)
```

---

## 6. Crackme Walkthroughs

### 6.1 Simple Password Check

```bash
# สร้าง crackme
cat > /tmp/crackme1.c << 'EOF'
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    
    char password[] = "CTF{r3v3rs3_me_if_u_can}";
    
    if (strcmp(argv[1], password) == 0) {
        printf("Flag: %s\n", password);
    } else {
        printf("Wrong!\n");
    }
    return 0;
}
EOF
gcc -o /tmp/crackme1 /tmp/crackme1.c -s

# วิเคราะห์
# Method 1: strings
strings /tmp/crackme1 | grep CTF

# Method 2: ltrace
/tmp/crackme1 test 2>/dev/null
ltrace /tmp/crackme1 test 2>&1 | grep strcmp

# Method 3: strace
strace /tmp/crackme1 test 2>&1

# Method 4: GDB
gdb /tmp/crackme1
# (gdb) disass main
# (gdb) break *0x<strcmp_call_addr>
# (gdb) run test
# (gdb) print (char*)$rsi
```

### 6.2 XOR Encoded Password

```bash
cat > /tmp/crackme2.c << 'EOF'
#include <stdio.h>
#include <string.h>

int check(char *input) {
    // XOR encoded password
    unsigned char encoded[] = {0x63^0xAA, 0x74^0xAA, 0x66^0xAA, 
                               0x7b^0xAA, 0x78^0xAA, 0x6f^0xAA,
                               0x72^0xAA, 0x7d^0xAA, 0x00};
    char decoded[20];
    for (int i = 0; encoded[i]; i++) {
        decoded[i] = encoded[i] ^ 0xAA;
    }
    decoded[8] = 0;
    return strcmp(input, decoded) == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    if (check(argv[1])) {
        printf("Correct! Flag: %s\n", argv[1]);
    } else {
        printf("Wrong!\n");
    }
    return 0;
}
EOF
gcc -o /tmp/crackme2 /tmp/crackme2.c

# Solution: decode XOR manually
python3 << 'EOF'
encoded = [0x63^0xAA, 0x74^0xAA, 0x66^0xAA,
           0x7b^0xAA, 0x78^0xAA, 0x6f^0xAA,
           0x72^0xAA, 0x7d^0xAA]
password = ''.join(chr(b ^ 0xAA) for b in encoded)
print(f'Password: {password}')
EOF
```

### 6.3 License Key Validation

```bash
cat > /tmp/keygen.py << 'EOF'
#!/usr/bin/env python3
# reverse engineered keygen

def validate_key(key):
    parts = key.split('-')
    if len(parts) != 4:
        return False
    
    # Part 1: checksum
    p1 = int(parts[0], 16)
    if p1 != 0xDEAD:
        return False
    
    # Part 2: based on username
    username = "user123"
    expected = sum(ord(c) for c in username) & 0xFFFF
    p2 = int(parts[1], 16)
    if p2 != expected:
        return False
    
    # Part 3: magic
    p3 = int(parts[2], 16)
    if p3 ^ 0xBEEF != 0x1234:
        return False
    
    # Part 4: CRC-like
    p4 = int(parts[3], 16)
    check = (p1 + expected + (p3 ^ 0xBEEF)) % 0x10000
    if p4 != check:
        return False
    
    return True

# Generate valid key
def generate_key(username):
    p1 = 0xDEAD
    p2 = sum(ord(c) for c in username) & 0xFFFF
    p3 = 0x1234 ^ 0xBEEF  # = 0xBCDB
    p4 = (p1 + p2 + 0x1234) % 0x10000
    return f"{p1:04X}-{p2:04X}-{p3:04X}-{p4:04X}"

key = generate_key("user123")
print(f"Generated key: {key}")
print(f"Valid: {validate_key(key)}")
EOF
python3 /tmp/keygen.py
```

---

## 7. Obfuscation และ Packing

### 7.1 Packed Executables

```bash
# อัดเครื่องมือที่ใช้ pack:
# UPX, MPRESS, Themida, VMProtect, ASPack

# ตรวจสอบ packer
file binary.exe
strings binary.exe | head -5
# UPX: จะเห็น "UPX!" string

# ExeInfo PE (Windows) หรือ Detect-It-Easy (DiE)
# https://github.com/horsicq/Detect-It-Easy

# ถอด UPX packing
upx -d binary.exe -o unpacked.exe
upx --decompress binary.exe

# ถอด ด้วย manual (OEP dump)
# 1. ตั้ง breakpoint ที่ OEP (Original Entry Point)
# 2. รันจนถึง OEP
# 3. dump process memory
# 4. fix imports (IAT)

# Detect-It-Easy
dies binary.exe  # command line
```

### 7.2 Code Obfuscation

```python
#!/usr/bin/env python3
# obfuscation_examples.py

# 1. String obfuscation via XOR
def deobfuscate_xor(data, key):
    return bytes([b ^ key for b in data])

obfuscated = b'\x48\x45\x4c\x4c\x4f'  # HELLO XOR 0
print(deobfuscate_xor(obfuscated, 0).decode())

# 2. Split string
fragments = ['htt', 'p://', '192.', '168.', '1.1', '/c2']
url = ''.join(fragments)
print(f"Reconstructed: {url}")

# 3. Math encoding
def decode_math(n):
    return chr(n ^ 0x42 + 0x10 - 5)

encoded = [0x2A, 0x27, 0x38, 0x38, 0x3B]  # example
try:
    decoded = ''.join(decode_math(n) for n in encoded)
    print(f"Math decoded: {decoded}")
except:
    pass

# 4. Base64 in shellcode
import base64
encoded_cmd = base64.b64encode(b'whoami').decode()
print(f"Encoded: {encoded_cmd}")
decoded_cmd = base64.b64decode(encoded_cmd).decode()
print(f"Decoded: {decoded_cmd}")

# 5. Stack strings (character by character assembly)
# Assembly:
# mov byte [rbp-0x10], 0x63  ; 'c'
# mov byte [rbp-0x0f], 0x6d  ; 'm'
# mov byte [rbp-0x0e], 0x64  ; 'd'
stack_string = bytes([0x63, 0x6d, 0x64]).decode()
print(f"Stack string: {stack_string}")
```

### 7.3 Anti-Disassembly Tricks

```nasm
; Anti-disassembly techniques

; 1. Jump into middle of instruction
jmp label1
db 0xe8        ; fake call opcode
label1:
; real code continues here
nop

; 2. Overlapping instructions
jmp $+5        ; skip next byte
db 0xE8        ; fake byte (confuses linear disassembly)
mov eax, 1    ; real instruction

; 3. Fake CALL/RET trick
call next
next:
pop rax        ; rax = current RIP
; หา offset ของตัวเอง
```

---

## 8. Python Reversing

### 8.1 .pyc Decompilation

```bash
# ถอดรหัส .pyc file
pip3 install decompile3

# decompile Python 3.x
decompyle3 script.pyc > script_decompiled.py

# uncompyle6 (สำหรับ Python 2.x)
pip3 install uncompyle6
uncompyle6 script.pyc

# ดู bytecode
import dis
import marshal

with open('script.pyc', 'rb') as f:
    magic = f.read(4)   # magic number
    f.read(12)           # metadata (timestamp, etc)
    code = marshal.loads(f.read())

dis.dis(code)
```

### 8.2 Packed Python Executables

```bash
# PyInstaller packed executables
pip3 install pyinstxtractor

# extract
python3 pyinstxtractor.py malware.exe
# สร้าง folder: malware.exe_extracted/

# หา main script
ls malware.exe_extracted/
# หาไฟล์ .pyc หลัก

# decompile
decompyle3 malware.exe_extracted/malware.pyc

# Py2exe / cx_Freeze - similar approach
# ใช้ 7-zip หรือ IDA เปิด overlay data
```

### 8.3 ถอดรหัส Custom Encoding

```python
#!/usr/bin/env python3
# reverse_encoding.py

# ตัวอย่าง: encoded string ที่พบใน malware
encoded = [0x72, 0x6f, 0x74, 0x31, 0x33, 0x5f, 0x70, 0x6c, 0x75, 0x73]
key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]

# Method 1: bruteforce single-byte XOR
def brute_xor(data):
    for key in range(256):
        try:
            decoded = bytes([b ^ key for b in data])
            text = decoded.decode('ascii')
            if all(32 <= c < 127 for c in decoded):
                print(f"XOR key 0x{key:02X}: {text}")
        except:
            pass

brute_xor(encoded)

# Method 2: entropy-based scoring
import string
def score_english(text):
    score = 0
    for c in text.lower():
        if c in string.ascii_lowercase:
            score += 1
        elif c in string.digits:
            score += 0.5
        elif c in ' .,!?':
            score += 0.5
    return score / len(text) if text else 0

# Method 3: frequency analysis
from collections import Counter

def freq_analysis(data):
    freq = Counter(data)
    # Most common byte มักจะเป็น 0x20 (space) ใน English text
    most_common = freq.most_common(1)[0][0]
    guessed_key = most_common ^ 0x20
    decoded = bytes([b ^ guessed_key for b in data])
    print(f"Freq analysis guess (key=0x{guessed_key:02X}): {decoded}")
    return decoded

freq_analysis(encoded)
```

---

## 9. แบบฝึกหัด Lab

### Lab 1: Crackme Challenge

```bash
# สร้าง crackme สำหรับฝึก
cat > /tmp/lab_crackme.c << 'EOF'
#include <stdio.h>
#include <string.h>

#define MAGIC 0x1337

int validate(unsigned int serial) {
    unsigned int a = (serial >> 16) & 0xFFFF;
    unsigned int b = serial & 0xFFFF;
    return (a ^ b) == MAGIC && (a + b) == 0xDEAD;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <serial>\n", argv[0]);
        return 1;
    }
    
    unsigned int serial = (unsigned int)strtoul(argv[1], NULL, 16);
    
    if (validate(serial)) {
        printf("Valid serial!\n");
        printf("Flag: CTF{serial_%08X}\n", serial);
    } else {
        printf("Invalid!\n");
    }
    return 0;
}
EOF
gcc -O2 -o /tmp/lab_crackme /tmp/lab_crackme.c

# เฉลยภายใต้:
# a ^ b == 0x1337
# a + b == 0xDEAD
# แก้:
# a = (0xDEAD + 0x1337) / 2 = ?
# เช็คว่า a + b = 0xDEAD, a ^ b = 0x1337
# a = ((a+b) + (a^b)) / 2 = ... (ถ้า a >= b)

python3 << 'SOLVE'
# solve
for a in range(0x10000):
    for b in range(0x10000):
        if (a ^ b) == 0x1337 and (a + b) == 0xDEAD:
            serial = (a << 16) | b
            print(f"Serial: {serial:#010x} (a={a:#06x}, b={b:#06x})")
            break
    else:
        continue
    break
SOLVE
```

### Lab 2: Patching Binary

```bash
# patch binary เพื่อ bypass
python3 << 'PATCH'
import subprocess

binary = '/tmp/lab_crackme'
with open(binary, 'rb') as f:
    data = bytearray(f.read())

# หา pattern: cmp + conditional jump
# แทนที่จะใช้ GDB/Radare2 ในการหา offset

print("[*] Use GDB or radare2 to find the comparison offset")
print("r2 /tmp/lab_crackme")
print("  > aa")
print("  > s main")
print("  > pdf | grep -A2 jne")
PATCH

# radare2 analysis
r2 -q -c 'aaa;s main;pdf' /tmp/lab_crackme 2>/dev/null | head -40
```

### สรุป Reverse Engineering Tools

```
┌────────────────────────────────────────────────────────────┐
│  Tool          Platform    Purpose                       │
├────────────────────────────────────────────────────────────┤
│  Ghidra        Multi       NSA decompiler (free)         │
│  IDA Pro        Multi       Industry standard (paid)      │
│  Binary Ninja   Multi       Modern RE platform            │
│  radare2        Multi       CLI disassembler              │
│  x64dbg         Windows     Dynamic debugger              │
│  OllyDbg        Windows     Classic debugger              │
│  GDB            Linux       GNU debugger                  │
│  PEDA/GEF       Linux       GDB enhancement               │
│  Cutter         Multi       radare2 GUI                   │
│  pwntools       Python      Exploit toolkit               │
└────────────────────────────────────────────────────────────┘
```

---

**[← Part 48: Malware Analysis](Part-48-Malware-Analysis.md)** | **[→ Part 50: Red Team Operations](Part-50-Red-Team-Operations.md)**
