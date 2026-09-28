# Part 82: Reverse Engineering

> **หลักสูตร Kali Linux จากระดับพื้นฐานถึงระดับโลก**  
> ← [Part 81: Wireless Security Advanced](Part-81-Wireless-Security-Advanced.md) | [Part 83: Malware Analysis](Part-83-Malware-Analysis.md) →

---

## สารบัญ

1. [พื้นฐาน Reverse Engineering](#1-พื้นฐาน-reverse-engineering)
2. [Assembly Language สำหรับ RE](#2-assembly-language-สำหรับ-re)
3. [Static Analysis ด้วย Ghidra](#3-static-analysis-ด้วย-ghidra)
4. [Dynamic Analysis ด้วย GDB และ x64dbg](#4-dynamic-analysis-ด้วย-gdb-และ-x64dbg)
5. [IDA Pro และ Binary Ninja](#5-ida-pro-และ-binary-ninja)
6. [Anti-Reversing Techniques Bypass](#6-anti-reversing-techniques-bypass)
7. [Reverse Engineering บน Windows](#7-reverse-engineering-บน-windows)
8. [Reverse Engineering บน Linux](#8-reverse-engineering-บน-linux)
9. [CTF Reverse Engineering Challenges](#9-ctf-reverse-engineering-challenges)
10. [Practical Malware Reversing Workflow](#10-practical-malware-reversing-workflow)

---

## 1. พื้นฐาน Reverse Engineering

### 1.1 Reverse Engineering คืออะไร

Reverse Engineering (RE) คือกระบวนการวิเคราะห์ซอฟต์แวร์เพื่อทำความเข้าใจการทำงานโดยไม่มี source code ต้นฉบับ งานหลักในด้านความปลอดภัยได้แก่:

- **Malware Analysis** — ทำความเข้าใจพฤติกรรมของ malware
- **Vulnerability Research** — ค้นหาช่องโหว่ใน binary
- **CTF Challenges** — แข่งขันด้านความปลอดภัย
- **License Cracking** — (เพื่อการเรียนรู้เท่านั้น)
- **Protocol Reverse Engineering** — ถอดรหัส proprietary protocols

### 1.2 ประเภทของ Analysis

```
┌─────────────────────────────────────────────────────────────┐
│                    Types of Analysis                        │
├─────────────────┬───────────────────────────────────────────┤
│  Static Analysis│ วิเคราะห์โดยไม่รันโปรแกรม                │
│                 │ - Disassembly (asm code)                  │
│                 │ - Decompilation (pseudocode)              │
│                 │ - String analysis                         │
│                 │ - Import/Export analysis                  │
├─────────────────┼───────────────────────────────────────────┤
│ Dynamic Analysis│ วิเคราะห์ขณะรันโปรแกรม                    │
│                 │ - Debugging (GDB, x64dbg)                 │
│                 │ - Tracing (strace, ltrace)                │
│                 │ - API monitoring (Frida)                  │
│                 │ - Memory inspection                       │
└─────────────────┴───────────────────────────────────────────┘
```

### 1.3 เครื่องมือหลัก

```bash
# ติดตั้งเครื่องมือ RE บน Kali Linux
sudo apt update
sudo apt install -y \
    ghidra \
    radare2 \
    gdb \
    gdb-multiarch \
    binutils \
    file \
    strings \
    ltrace \
    strace \
    pwndbg \
    pwntools

# ติดตั้ง pwndbg (GDB plugin ที่ดีที่สุด)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# ติดตั้ง GEF (อีกหนึ่ง GDB plugin)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# ติดตั้ง pwntools
pip3 install pwntools

# ติดตั้ง ROPgadget
pip3 install ROPgadget

# ติดตั้ง angr (symbolic execution)
pip3 install angr
```

### 1.4 การทำความเข้าใจ Binary Formats

```bash
# ตรวจสอบ binary format
file /bin/ls
# ELF 64-bit LSB pie executable, x86-64, dynamically linked

# ดู ELF headers
readelf -h /bin/ls

# ดู sections
readelf -S /bin/ls

# ดู symbols
nm /bin/ls

# ดู dynamic libraries
ldd /bin/ls

# ดู strings ในไฟล์
strings /bin/ls | head -50

# ดู hexdump
xxd /bin/ls | head -20

# ดูข้อมูล PE (Windows)
pefile analysis เช่น python-pefile
```

```python
#!/usr/bin/env python3
# binary_info.py — วิเคราะห์ข้อมูลพื้นฐานของ binary

import subprocess
import sys
import os
from pathlib import Path

class BinaryAnalyzer:
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"ไม่พบไฟล์: {filepath}")
    
    def get_file_type(self):
        result = subprocess.run(['file', str(self.filepath)], 
                               capture_output=True, text=True)
        return result.stdout.strip()
    
    def get_strings(self, min_length=4):
        result = subprocess.run(['strings', '-n', str(min_length), str(self.filepath)],
                               capture_output=True, text=True)
        return result.stdout.splitlines()
    
    def get_imports(self):
        # สำหรับ ELF
        result = subprocess.run(['readelf', '-d', str(self.filepath)],
                               capture_output=True, text=True)
        imports = []
        for line in result.stdout.splitlines():
            if 'NEEDED' in line:
                imports.append(line.split('[')[1].rstrip(']'))
        return imports
    
    def check_security_features(self):
        """ตรวจสอบ security features เช่น ASLR, NX, PIE, Canary"""
        result = subprocess.run(['checksec', '--file=' + str(self.filepath)],
                               capture_output=True, text=True)
        return result.stdout
    
    def get_entropy(self):
        """คำนวณ entropy เพื่อตรวจสอบการ pack/encrypt"""
        data = self.filepath.read_bytes()
        if not data:
            return 0.0
        
        import math
        from collections import Counter
        byte_counts = Counter(data)
        total = len(data)
        entropy = -sum((count/total) * math.log2(count/total) 
                      for count in byte_counts.values())
        return entropy
    
    def analyze(self):
        print(f"[*] วิเคราะห์: {self.filepath.name}")
        print(f"[*] ขนาด: {self.filepath.stat().st_size:,} bytes")
        print(f"[*] ประเภท: {self.get_file_type()}")
        
        entropy = self.get_entropy()
        print(f"[*] Entropy: {entropy:.2f}/8.0", end=" ")
        if entropy > 7.0:
            print("(สูงมาก — อาจ packed/encrypted)")
        elif entropy > 6.0:
            print("(สูง — อาจมีการ compress)")
        else:
            print("(ปกติ)")
        
        imports = self.get_imports()
        if imports:
            print(f"[*] Libraries: {', '.join(imports)}")
        
        strings = self.get_strings()
        interesting = [s for s in strings if any(kw in s.lower() for kw in 
                      ['http', 'password', 'key', 'secret', 'flag', 'admin', '/bin/', 'cmd'])]
        if interesting:
            print(f"[*] Interesting strings ({len(interesting)} found):")
            for s in interesting[:20]:
                print(f"    {s}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    
    analyzer = BinaryAnalyzer(sys.argv[1])
    analyzer.analyze()
```

---

## 2. Assembly Language สำหรับ RE

### 2.1 x86-64 Registers

```
┌──────────────────────────────────────────────────────────────┐
│                   x86-64 Registers                          │
├─────────┬──────────────────────────────────────────────────┤
│ Register│ ความหมายและการใช้งาน                              │
├─────────┼──────────────────────────────────────────────────┤
│ RAX     │ Accumulator — return value ของ function           │
│ RBX     │ Base — preserved across function calls            │
│ RCX     │ Counter — 4th argument, loop counter              │
│ RDX     │ Data — 3rd argument, I/O                          │
│ RSI     │ Source Index — 2nd argument, string source        │
│ RDI     │ Dest Index — 1st argument, string destination     │
│ RSP     │ Stack Pointer — top of stack                      │
│ RBP     │ Base Pointer — bottom of stack frame              │
│ R8-R15  │ Additional general-purpose registers              │
│ RIP     │ Instruction Pointer — current instruction         │
├─────────┼──────────────────────────────────────────────────┤
│ RFLAGS  │ Flags: ZF (zero), CF (carry), SF (sign), OF (ovf)│
└─────────┴──────────────────────────────────────────────────┘

System V AMD64 ABI (Linux calling convention):
  Args: RDI, RSI, RDX, RCX, R8, R9, then stack
  Return: RAX (RDX for 128-bit)
  Callee-saved: RBX, RBP, R12-R15
```

### 2.2 คำสั่ง Assembly พื้นฐาน

```nasm
; === Data Movement ===
mov rax, rbx        ; rax = rbx
mov rax, [rbx]      ; rax = *rbx (memory dereference)
mov [rbx], rax      ; *rbx = rax
lea rax, [rbx+8]    ; rax = rbx + 8 (load effective address)
push rax            ; push rax onto stack
pop rax             ; pop from stack into rax

; === Arithmetic ===
add rax, rbx        ; rax += rbx
sub rax, rbx        ; rax -= rbx
imul rax, rbx       ; rax *= rbx (signed)
idiv rbx            ; rax = rdx:rax / rbx, rdx = remainder
inc rax             ; rax++
dec rax             ; rax--
neg rax             ; rax = -rax

; === Bitwise ===
and rax, rbx        ; rax &= rbx
or  rax, rbx        ; rax |= rbx
xor rax, rbx        ; rax ^= rbx (xor rax, rax clears rax)
not rax             ; rax = ~rax
shl rax, 3          ; rax <<= 3
shr rax, 3          ; rax >>= 3 (logical)
sar rax, 3          ; rax >>= 3 (arithmetic, sign-extend)

; === Comparison & Jumps ===
cmp rax, rbx        ; set flags based on rax - rbx
test rax, rax       ; set flags based on rax & rax (check zero)
jmp label           ; unconditional jump
je  label           ; jump if equal (ZF=1)
jne label           ; jump if not equal (ZF=0)
jl  label           ; jump if less (signed)
jg  label           ; jump if greater (signed)
jle label           ; jump if less or equal
jge label           ; jump if greater or equal

; === Function Call ===
call function       ; push RIP, jump to function
ret                 ; pop RIP, return
leave               ; mov rsp, rbp; pop rbp

; === System Calls (Linux) ===
; syscall number in rax, args in rdi, rsi, rdx, r10, r8, r9
mov rax, 1          ; sys_write
mov rdi, 1          ; stdout
lea rsi, [msg]      ; buffer
mov rdx, 13         ; length
syscall
```

### 2.3 การอ่าน Assembly จาก Disassembly

```python
#!/usr/bin/env python3
# disasm_helper.py — ช่วยอ่าน disassembly output

from capstone import *
import sys

def disassemble_bytes(code_bytes, arch='x86_64', base_addr=0x400000):
    """Disassemble bytes เป็น assembly instructions"""
    if arch == 'x86_64':
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == 'x86':
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == 'arm64':
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch == 'arm':
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    else:
        raise ValueError(f"Unknown arch: {arch}")
    
    md.detail = True
    results = []
    
    for insn in md.disasm(code_bytes, base_addr):
        results.append({
            'address': insn.address,
            'bytes': insn.bytes.hex(),
            'mnemonic': insn.mnemonic,
            'op_str': insn.op_str,
        })
        print(f"0x{insn.address:08x}:  {insn.bytes.hex():20s}  {insn.mnemonic} {insn.op_str}")
    
    return results

# ตัวอย่าง: disassemble shellcode
if __name__ == "__main__":
    # Hello world shellcode (x86-64 Linux)
    shellcode = bytes([
        0x48, 0x31, 0xc0,             # xor rax, rax
        0x48, 0x31, 0xff,             # xor rdi, rdi
        0x48, 0x31, 0xf6,             # xor rsi, rsi
        0x48, 0x31, 0xd2,             # xor rdx, rdx
        0x48, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # mov rax, 1
        0x48, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # mov rdi, 1
        0x0f, 0x05,                   # syscall
    ])
    
    print("[*] Disassembly:")
    disassemble_bytes(shellcode)
```

### 2.4 การจดจำ Patterns ใน Assembly

```
# Pattern: ฟังก์ชัน Prologue/Epilogue
push rbp
mov  rbp, rsp
sub  rsp, 0x20      ; allocate local variables
...
leave               ; หรือ: mov rsp, rbp; pop rbp
ret

# Pattern: if/else
cmp rax, 0
jne  else_branch
; then branch
jmp  end_if
else_branch:
; else branch  
end_if:

# Pattern: for loop
mov rcx, 0          ; i = 0
loop_start:
cmp rcx, 10         ; i < 10
jge loop_end
; loop body
inc rcx             ; i++
jmp loop_start
loop_end:

# Pattern: array access
; int arr[10]; arr[i] = value;
; rax = base address of arr
; rbx = index i
mov rdx, [rax + rbx*4]  ; 4 bytes per int

# Pattern: function call with args
mov  rdi, arg1      ; 1st arg
mov  rsi, arg2      ; 2nd arg
mov  rdx, arg3      ; 3rd arg
call function_name
; return value in rax
```

---

## 3. Static Analysis ด้วย Ghidra

### 3.1 การตั้งค่าและใช้งาน Ghidra

```bash
# ดาวน์โหลดและรัน Ghidra
sudo apt install ghidra
ghidra &

# หรือรันผ่าน command line
ghidraRun

# สร้าง project ใหม่ใน Ghidra:
# File → New Project → Non-Shared Project
# เลือก directory และตั้งชื่อ project

# Import binary:
# File → Import File → เลือก binary
# Ghidra จะ auto-detect format และ architecture

# Analyze:
# Analysis → Auto Analyze → OK
# รอ analysis เสร็จ (อาจใช้เวลาสักครู่)
```

### 3.2 Ghidra Script API

```python
# ghidra_analyze.py — Ghidra Python script
# รันใน Ghidra Script Manager

from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.util.task import ConsoleTaskMonitor

def find_interesting_strings():
    """ค้นหา strings ที่น่าสนใจใน binary"""
    program = currentProgram
    memory = program.getMemory()
    
    interesting_keywords = [
        'password', 'key', 'secret', 'token',
        'admin', 'root', 'flag', 'http://', 'https://'
    ]
    
    results = []
    
    # ค้นหาใน data sections
    for block in memory.getBlocks():
        if block.isInitialized():
            data_iter = program.getListing().getData(block.getStart(), True)
            for data in data_iter:
                if data.hasStringValue():
                    string_val = str(data.getValue()).lower()
                    for keyword in interesting_keywords:
                        if keyword in string_val:
                            results.append({
                                'address': data.getAddress(),
                                'value': str(data.getValue())
                            })
                            break
    
    print(f"[*] พบ {len(results)} interesting strings:")
    for r in results:
        print(f"  {r['address']}: {r['value']}")

def find_crypto_functions():
    """ค้นหาฟังก์ชัน crypto โดยดูจาก constants"""
    # MD5 constants
    md5_const = 0x67452301
    # SHA-1 constants
    sha1_const = 0x67452301
    # AES S-box ค่าแรก
    aes_sbox = 0x63
    
    program = currentProgram
    listing = program.getListing()
    
    for func in listing.getFunctions(True):
        func_body = func.getBody()
        # ค้นหา instructions ใน function
        insn_iter = listing.getInstructions(func_body, True)
        for insn in insn_iter:
            # ตรวจสอบ immediate values
            for i in range(insn.getNumOperands()):
                try:
                    val = insn.getScalar(i)
                    if val and val.getValue() == md5_const:
                        print(f"[!] Possible crypto at {func.getName()} ({func.getEntryPoint()})")
                except:
                    pass

# รัน analysis
find_interesting_strings()
find_crypto_functions()
```

### 3.3 Radare2 สำหรับ Command-line Analysis

```bash
# รัน radare2
r2 -A ./binary        # auto-analyze
r2 -d ./binary        # debug mode

# คำสั่งสำคัญใน r2:
aaa                   # analyze all
afl                   # list all functions
afn main              # rename function to main
pdf @ main            # print disassembly of main
VV                    # visual graph mode
V                     # visual mode
/                     # search
/s password           # search for string "password"
/x 90909090           # search for hex bytes
iz                    # list strings in data sections
iI                    # binary info
iS                    # sections
db 0x401234           # set breakpoint
dc                    # continue
dr                    # print registers
ds                    # single step

# ตัวอย่าง workflow:
r2 -A ./crackme
afl | grep main
pdf @ sym.main
# ดู disassembly และหา logic
```

```python
#!/usr/bin/env python3
# r2_automation.py — ใช้ r2pipe เพื่อ automate radare2

import r2pipe
import json

class R2Analyzer:
    def __init__(self, binary_path):
        self.r2 = r2pipe.open(binary_path, flags=['-A'])
        print(f"[*] Analyzing {binary_path}...")
    
    def get_functions(self):
        """ดึงรายการฟังก์ชันทั้งหมด"""
        funcs_json = self.r2.cmdj('aflj')
        return funcs_json or []
    
    def get_disassembly(self, func_name):
        """ดึง disassembly ของฟังก์ชัน"""
        return self.r2.cmd(f'pdf @ {func_name}')
    
    def get_strings(self):
        """ดึง strings ทั้งหมด"""
        return self.r2.cmdj('izj') or []
    
    def get_imports(self):
        """ดึง imports"""
        return self.r2.cmdj('iij') or []
    
    def find_function_by_string_ref(self, search_str):
        """ค้นหาฟังก์ชันที่อ้างถึง string นั้น"""
        # ค้นหา string ในไฟล์
        strings = self.get_strings()
        target_strings = [s for s in strings 
                         if search_str.lower() in s.get('string', '').lower()]
        
        results = []
        for s in target_strings:
            addr = s.get('vaddr', 0)
            # ค้นหา cross-references
            xrefs = self.r2.cmdj(f'axtj @ {addr}') or []
            for xref in xrefs:
                results.append({
                    'string': s.get('string'),
                    'string_addr': hex(addr),
                    'ref_from': hex(xref.get('from', 0)),
                    'ref_type': xref.get('type')
                })
        return results
    
    def analyze_main(self):
        """วิเคราะห์ฟังก์ชัน main"""
        print("\n[*] Main function disassembly:")
        print(self.get_disassembly('main'))
    
    def close(self):
        self.r2.quit()

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    analyzer = R2Analyzer('./crackme')
    
    funcs = analyzer.get_functions()
    print(f"[*] พบ {len(funcs)} functions")
    
    strings = analyzer.get_strings()
    print(f"[*] พบ {len(strings)} strings")
    
    # ค้นหาฟังก์ชันที่ตรวจสอบ password
    refs = analyzer.find_function_by_string_ref('password')
    for ref in refs:
        print(f"[!] '{ref['string']}' referenced at {ref['ref_from']}")
    
    analyzer.analyze_main()
    analyzer.close()
```

---

## 4. Dynamic Analysis ด้วย GDB และ x64dbg

### 4.1 GDB พร้อม pwndbg

```bash
# รัน GDB
gdb ./binary
gdb -p <pid>         # attach to process
gdb ./binary core    # analyze core dump

# คำสั่ง pwndbg ที่สำคัญ:
start               # run และ break ที่ main
run arg1 arg2       # run with arguments
run < input.txt     # run with stdin
continue (c)        # continue execution
next (n)            # next instruction (step over)
step (s)            # step into function
finish              # run until function return

# Breakpoints:
break main          # break at main
break *0x401234     # break at address
break func_name     # break at function
info breakpoints    # list breakpoints
delete 1            # delete breakpoint 1

# Inspection:
info registers      # show all registers
print $rax          # print register
x/10x $rsp          # examine 10 words at rsp
x/s 0x402010        # examine string at address
disassemble main    # disassemble function
backtrace (bt)      # call stack
info locals         # local variables

# pwndbg specific:
context             # show full context
heap                # show heap info
vmmap               # virtual memory map
search -s "password" # search for string
rop                 # find ROP gadgets
cyclic 100          # generate cyclic pattern
cyclic -l 0x61616166 # find offset in pattern
```

### 4.2 GDB Scripting

```python
# gdb_script.py — GDB Python script
# ใช้ใน GDB: source gdb_script.py

import gdb

class TraceCallsCommand(gdb.Command):
    """Trace ทุก function call"""
    
    def __init__(self):
        super().__init__('trace-calls', gdb.COMMAND_USER)
        self.bp_list = []
    
    def invoke(self, arg, from_tty):
        # ดึงรายการฟังก์ชันทั้งหมด
        sym_table = gdb.selected_inferior().read_memory(0, 0)  # dummy
        
        # สร้าง breakpoint handler
        class FuncBreakpoint(gdb.Breakpoint):
            def stop(self):
                frame = gdb.selected_frame()
                print(f"[CALL] {frame.name()} at {frame.pc():#x}")
                return False  # ไม่หยุด ให้ continue
        
        # ตั้ง breakpoint ที่ฟังก์ชัน target
        target_funcs = arg.split() if arg else ['main']
        for func in target_funcs:
            bp = FuncBreakpoint(func)
            self.bp_list.append(bp)
            print(f"[*] Tracing {func}")

class DumpMemoryCommand(gdb.Command):
    """Dump memory region ไปยังไฟล์"""
    
    def __init__(self):
        super().__init__('dump-mem', gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        args = arg.split()
        if len(args) != 3:
            print("Usage: dump-mem <start_addr> <size> <filename>")
            return
        
        start = int(args[0], 16)
        size = int(args[1], 16)
        filename = args[2]
        
        try:
            inf = gdb.selected_inferior()
            mem = inf.read_memory(start, size)
            with open(filename, 'wb') as f:
                f.write(bytes(mem))
            print(f"[*] Dumped {size:#x} bytes to {filename}")
        except Exception as e:
            print(f"[!] Error: {e}")

# Register commands
TraceCallsCommand()
DumpMemoryCommand()
print("[*] Custom GDB commands loaded")
print("    trace-calls [func1 func2 ...]")
print("    dump-mem <start> <size> <file>")
```

### 4.3 strace และ ltrace

```bash
# strace — trace system calls
strace ./binary
strace -f ./binary        # follow forks
strace -o trace.log ./binary  # save to file
strace -e trace=open,read,write ./binary  # filter syscalls
strace -e trace=network ./binary  # network syscalls only
strace -p <pid>           # attach to running process

# ตัวอย่าง output:
# execve("./crackme", ["./crackme"], ...) = 0
# read(3, "password: ", 10) = 10
# write(1, "Enter password: ", 16) = 16

# ltrace — trace library calls
ltrace ./binary
ltrace -l libc.so ./binary  # trace specific library
ltrace -o ltrace.log ./binary

# ตัวอย่าง: ดู strcmp calls
ltrace -e strcmp ./binary
# strcmp("input_pass", "correct_pass") = -1
```

```python
#!/usr/bin/env python3
# trace_analyzer.py — วิเคราะห์ output จาก strace/ltrace

import re
import sys
from collections import defaultdict

class StraceAnalyzer:
    def __init__(self, trace_file):
        with open(trace_file) as f:
            self.lines = f.readlines()
    
    def find_file_operations(self):
        """ค้นหา file operations"""
        pattern = re.compile(r'(open|openat|read|write|close)\(([^)]+)\)')
        ops = defaultdict(list)
        
        for line in self.lines:
            m = pattern.search(line)
            if m:
                syscall = m.group(1)
                args = m.group(2)
                ops[syscall].append(args)
        
        return dict(ops)
    
    def find_network_activity(self):
        """ค้นหา network operations"""
        pattern = re.compile(r'(connect|bind|sendto|recvfrom|socket)\(([^)]+)\)')
        results = []
        
        for line in self.lines:
            m = pattern.search(line)
            if m:
                results.append({
                    'syscall': m.group(1),
                    'args': m.group(2),
                    'line': line.strip()
                })
        
        return results
    
    def find_string_comparisons(self):
        """ค้นหา string comparisons จาก ltrace"""
        pattern = re.compile(r'strcmp\("([^"]*)",\s*"([^"]*)"\)')
        comparisons = []
        
        for line in self.lines:
            m = pattern.search(line)
            if m:
                comparisons.append({
                    'arg1': m.group(1),
                    'arg2': m.group(2)
                })
        
        return comparisons
    
    def summarize(self):
        print("=== Strace/Ltrace Analysis ===")
        
        file_ops = self.find_file_operations()
        if file_ops:
            print(f"\n[*] File Operations:")
            for op, args_list in file_ops.items():
                print(f"  {op}: {len(args_list)} calls")
        
        net_activity = self.find_network_activity()
        if net_activity:
            print(f"\n[*] Network Activity ({len(net_activity)} ops):")
            for act in net_activity[:10]:
                print(f"  {act['syscall']}: {act['args'][:60]}")
        
        str_comps = self.find_string_comparisons()
        if str_comps:
            print(f"\n[!] String Comparisons ({len(str_comps)} found):")
            for comp in str_comps:
                print(f"  '{comp['arg1']}' vs '{comp['arg2']}'")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <trace_file>")
        sys.exit(1)
    analyzer = StraceAnalyzer(sys.argv[1])
    analyzer.summarize()
```

---

## 5. IDA Pro และ Binary Ninja

### 5.1 IDA Pro Scripting (IDAPython)

```python
# ida_script.py — IDA Pro Python script
# รันใน IDA: File → Script file

import idc
import idaapi
import idautils

def rename_functions_by_string():
    """Rename functions ตาม strings ที่อ้างถึง"""
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        
        # ดู strings ที่ฟังก์ชันอ้างถึง
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.DataRefsFrom(head):
                str_val = idc.get_strlit_contents(xref, -1, idc.STRTYPE_C)
                if str_val:
                    str_decoded = str_val.decode('utf-8', errors='ignore')
                    # ถ้า string น่าสนใจ ให้ rename function
                    if any(kw in str_decoded.lower() for kw in 
                           ['login', 'password', 'encrypt', 'decrypt', 'hash']):
                        new_name = f"sub_{str_decoded[:20].replace(' ', '_')}"
                        idc.set_name(func_ea, new_name, idc.SN_NOWARN)
                        print(f"Renamed {hex(func_ea)} to {new_name}")
                        break

def find_crypto_constants():
    """ค้นหา crypto constants ใน binary"""
    crypto_constants = {
        0x67452301: 'MD5_A',
        0xEFCDAB89: 'MD5_B', 
        0x98BADCFE: 'MD5_C',
        0x10325476: 'MD5_D',
        0x5A827999: 'SHA1_K1',
        0x6ED9EBA1: 'SHA1_K2',
        0x8F1BBCDC: 'SHA1_K3',
        0x63636363: 'AES_SBOX_related',
    }
    
    found = []
    for ea in idautils.Segments():
        seg = idaapi.getseg(ea)
        if not seg:
            continue
        
        for addr in range(seg.start_ea, seg.end_ea, 4):
            val = idc.get_wide_dword(addr)
            if val in crypto_constants:
                constant_name = crypto_constants[val]
                idc.set_cmt(addr, f"Crypto constant: {constant_name}", 0)
                found.append((hex(addr), constant_name))
                print(f"Found {constant_name} at {hex(addr)}")
    
    return found

def extract_all_strings():
    """ดึง strings ทั้งหมดพร้อม addresses"""
    strings = []
    for s in idautils.Strings():
        strings.append({
            'address': hex(s.ea),
            'length': s.length,
            'value': str(s)
        })
    return strings

# รัน scripts
print("[*] Running IDA analysis scripts...")
rename_functions_by_string()
find_crypto_constants()
print("[*] Done")
```

### 5.2 Binary Ninja Scripting

```python
# binja_script.py — Binary Ninja Python script

from binaryninja import *

def analyze_binary(binary_path):
    """วิเคราะห์ binary ด้วย Binary Ninja"""
    bv = BinaryViewType.get_view_of_file(binary_path)
    bv.update_analysis_and_wait()
    
    print(f"[*] Binary: {binary_path}")
    print(f"[*] Architecture: {bv.arch.name}")
    print(f"[*] Platform: {bv.platform.name}")
    print(f"[*] Functions: {len(list(bv.functions))}")
    
    # ค้นหาฟังก์ชันที่น่าสนใจ
    for func in bv.functions:
        # ดู Medium Level IL
        for block in func.medium_level_il:
            for insn in block:
                # ตรวจสอบ function calls
                if insn.operation == MediumLevelILOperation.MLIL_CALL:
                    # ดู arguments
                    dest = insn.dest
                    if hasattr(dest, 'constant'):
                        called_func = bv.get_function_at(dest.constant)
                        if called_func:
                            print(f"  Call to {called_func.name} in {func.name}")
    
    bv.file.close()
    return bv

# ตัวอย่างการใช้ High Level IL (HLIL)
def decompile_function(bv, func_name):
    """แสดง decompiled output ของฟังก์ชัน"""
    for func in bv.functions:
        if func.name == func_name:
            print(f"\n[*] HLIL of {func_name}:")
            for block in func.hlil:
                for insn in block:
                    print(f"  {insn}")
            return
    print(f"[!] Function {func_name} not found")
```

---

## 6. Anti-Reversing Techniques Bypass

### 6.1 Anti-Debug Techniques

```
เทคนิค Anti-Debug ที่พบบ่อย:

1. IsDebuggerPresent() / CheckRemoteDebuggerPresent()
   - Windows API ตรวจสอบว่ามี debugger หรือไม่

2. ptrace() detection (Linux)
   - โปรแกรมเรียก ptrace(PTRACE_TRACEME, 0, 1, 0)
   - ถ้า return -1 แสดงว่ามี debugger

3. Timing checks
   - วัดเวลา execute instructions
   - ถ้าช้าเกินไปแสดงว่ามี debugger

4. Hardware breakpoint detection
   - ตรวจสอบ Debug Registers (DR0-DR7)

5. Exception-based detection
   - ใช้ INT3 (0xCC) และดูว่า exception ถูก handle หรือไม่
```

```python
#!/usr/bin/env python3
# anti_debug_bypass.py — bypass anti-debug techniques

import frida
import sys

ANTI_DEBUG_BYPASS_SCRIPT = """
'use strict';

// Bypass IsDebuggerPresent (Windows)
if (Process.platform === 'windows') {
    const kernel32 = Module.load('kernel32.dll');
    const IsDebuggerPresent = kernel32.getExportByName('IsDebuggerPresent');
    Interceptor.replace(IsDebuggerPresent, new NativeCallback(function() {
        console.log('[*] IsDebuggerPresent() hooked -> returning 0');
        return 0;
    }, 'int', []));
    
    // Bypass CheckRemoteDebuggerPresent
    const CheckRemoteDebuggerPresent = kernel32.getExportByName('CheckRemoteDebuggerPresent');
    Interceptor.attach(CheckRemoteDebuggerPresent, {
        onLeave: function(retval) {
            const pbDebuggerPresent = this.context.rbp;
            // Set *pbDebuggerPresent = FALSE
            Memory.writeU32(pbDebuggerPresent, 0);
            console.log('[*] CheckRemoteDebuggerPresent hooked');
        }
    });
}

// Bypass ptrace detection (Linux)
if (Process.platform === 'linux') {
    Interceptor.attach(Module.getExportByName(null, 'ptrace'), {
        onEnter: function(args) {
            console.log('[*] ptrace() called, args:', args[0]);
        },
        onLeave: function(retval) {
            // ถ้าเรียก ptrace(PTRACE_TRACEME) ให้ return 0 (สำเร็จ)
            retval.replace(0);
        }
    });
}

// Bypass timing checks — hook clock functions
const gettimeofdayPtr = Module.findExportByName(null, 'gettimeofday');
if (gettimeofdayPtr) {
    let baseTime = null;
    let callCount = 0;
    
    Interceptor.attach(gettimeofdayPtr, {
        onLeave: function(retval) {
            callCount++;
            // คืนค่าเวลาที่สอดคล้องกัน ป้องกัน timing detection
        }
    });
}

console.log('[*] Anti-debug bypass loaded');
"""

def bypass_anti_debug(target):
    try:
        if target.isdigit():
            session = frida.attach(int(target))
        else:
            session = frida.spawn([target], stdio='pipe')
            pid = session
            session = frida.attach(pid)
        
        script = session.create_script(ANTI_DEBUG_BYPASS_SCRIPT)
        script.on('message', lambda msg, data: print(f"[Frida] {msg}"))
        script.load()
        
        if not target.isdigit():
            frida.resume(session)
        
        print(f"[*] Anti-debug bypass active for PID {session}")
        input("Press Enter to detach...")
        session.detach()
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pid or binary>")
        sys.exit(1)
    bypass_anti_debug(sys.argv[1])
```

### 6.2 Obfuscation Bypass

```bash
# Unpacking ด้วย GDB
# โปรแกรมที่ packed จะ unpack ตัวเองใน memory
# 1. Run และ break ที่ OEP (Original Entry Point)

gdb ./packed_binary
start
# ใช้ pwndbg: vmmap เพื่อดู memory regions
# หา region ที่ permission เปลี่ยนจาก rw- เป็น r-x

# 2. ตั้ง hardware breakpoint บน execute
hbreak *0x400000  # เดาตำแหน่ง OEP

# 3. Dump ส่วน unpacked
# dump memory dump.bin 0x400000 0x500000

# Detect packers ด้วย Detect-It-Easy (DIE)
die ./binary
# output: Packer: UPX 3.96

# Unpack UPX
upx -d ./packed_binary -o ./unpacked_binary
```

```python
#!/usr/bin/env python3
# deobfuscate.py — ถอด obfuscation techniques

import struct

def decode_xor_string(encoded_bytes, key):
    """ถอด XOR-encoded strings"""
    return bytes(b ^ key for b in encoded_bytes)

def decode_multi_byte_xor(encoded_bytes, key_bytes):
    """ถอด multi-byte XOR"""
    key_len = len(key_bytes)
    return bytes(b ^ key_bytes[i % key_len] for i, b in enumerate(encoded_bytes))

def decode_rot13(text):
    """ถอด ROT13"""
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)

def decode_base64_variants(encoded):
    """ลอง decode base64 variants"""
    import base64
    results = {}
    
    # Standard base64
    try:
        results['base64'] = base64.b64decode(encoded).decode('utf-8', errors='replace')
    except:
        pass
    
    # URL-safe base64
    try:
        results['urlsafe_b64'] = base64.urlsafe_b64decode(encoded + '==').decode('utf-8', errors='replace')
    except:
        pass
    
    # Base32
    try:
        results['base32'] = base64.b32decode(encoded).decode('utf-8', errors='replace')
    except:
        pass
    
    return results

def find_xor_key(ciphertext, known_plaintext_prefix):
    """ค้นหา XOR key โดยใช้ known plaintext attack"""
    prefix_bytes = known_plaintext_prefix.encode()
    key_length_guess = len(prefix_bytes)
    
    key = bytes(c ^ p for c, p in 
                zip(ciphertext[:key_length_guess], prefix_bytes))
    
    # ลอง decode ทั้งข้อความ
    decoded = decode_multi_byte_xor(ciphertext, key)
    return key, decoded

# ตัวอย่าง: ถอด obfuscated strings จาก binary
def extract_obfuscated_strings(binary_path):
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    # ลอง XOR keys ทั้งหมด (single byte)
    print("[*] Trying single-byte XOR keys...")
    for key in range(1, 256):
        decoded = decode_xor_string(data, key)
        # ค้นหา printable strings
        strings = []
        current = []
        for b in decoded:
            if 0x20 <= b <= 0x7e:
                current.append(chr(b))
            else:
                if len(current) >= 6:
                    strings.append(''.join(current))
                current = []
        
        # ตรวจสอบว่ามี strings ที่น่าสนใจหรือไม่
        interesting = [s for s in strings if any(kw in s.lower() for kw in 
                      ['flag', 'key', 'password', 'secret'])]
        if interesting:
            print(f"[!] Key {key:#04x}: Found interesting strings: {interesting}")

if __name__ == "__main__":
    # ตัวอย่าง
    encoded = bytes([0x48 ^ 0x41, 0x65 ^ 0x41, 0x6c ^ 0x41, 0x6c ^ 0x41, 0x6f ^ 0x41])
    decoded = decode_xor_string(encoded, 0x41)
    print(f"XOR decoded: {decoded.decode()}")  # Hello
```

---

## 7. Reverse Engineering บน Windows

### 7.1 PE File Analysis

```python
#!/usr/bin/env python3
# pe_analyzer.py — วิเคราะห์ PE (Windows Executable) files

import pefile
import struct
import sys
from pathlib import Path

class PEAnalyzer:
    def __init__(self, filepath):
        self.pe = pefile.PE(filepath)
        self.filepath = filepath
    
    def get_basic_info(self):
        """ข้อมูลพื้นฐานของ PE file"""
        info = {}
        
        # DOS Header
        info['magic'] = hex(self.pe.DOS_HEADER.e_magic)
        
        # NT Headers
        info['machine'] = hex(self.pe.FILE_HEADER.Machine)
        info['timestamp'] = self.pe.FILE_HEADER.TimeDateStamp
        info['characteristics'] = hex(self.pe.FILE_HEADER.Characteristics)
        
        # Optional Header
        info['subsystem'] = self.pe.OPTIONAL_HEADER.Subsystem
        info['entry_point'] = hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        info['image_base'] = hex(self.pe.OPTIONAL_HEADER.ImageBase)
        
        return info
    
    def get_imports(self):
        """ดึง imported functions"""
        imports = {}
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            imports[dll_name] = []
            
            for imp in entry.imports:
                func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"ordinal_{imp.ordinal}"
                imports[dll_name].append({
                    'name': func_name,
                    'address': hex(imp.address)
                })
        
        return imports
    
    def get_exports(self):
        """ดึง exported functions"""
        exports = []
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports
        
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append({
                'name': exp.name.decode('utf-8', errors='ignore') if exp.name else f"ord_{exp.ordinal}",
                'address': hex(self.pe.OPTIONAL_HEADER.ImageBase + exp.address),
                'ordinal': exp.ordinal
            })
        
        return exports
    
    def get_sections(self):
        """ดึงข้อมูล sections"""
        sections = []
        for section in self.pe.sections:
            name = section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore')
            sections.append({
                'name': name,
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'raw_size': hex(section.SizeOfRawData),
                'entropy': section.get_entropy(),
                'characteristics': hex(section.Characteristics)
            })
        return sections
    
    def detect_packers(self):
        """ตรวจสอบ packers/protectors"""
        indicators = []
        
        # ตรวจสอบ section entropy
        for section in self.pe.sections:
            entropy = section.get_entropy()
            if entropy > 7.0:
                name = section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore')
                indicators.append(f"High entropy section: {name} ({entropy:.2f})")
        
        # ตรวจสอบ section names ที่รู้จัก
        packer_sections = {
            '.upx0': 'UPX', '.upx1': 'UPX',
            '.aspack': 'ASPack', '.adata': 'ASPack',
            '_winzip_': 'WinZip SFX',
        }
        for section in self.pe.sections:
            name = section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore').lower()
            if name in packer_sections:
                indicators.append(f"Known packer section: {name} ({packer_sections[name]})")
        
        # ตรวจสอบ import table
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            if len(self.pe.DIRECTORY_ENTRY_IMPORT) < 3:
                indicators.append("Very few imports (possible packed binary)")
        else:
            indicators.append("No import table (likely packed)")
        
        return indicators
    
    def analyze(self):
        print("=" * 60)
        print(f"PE Analysis: {self.filepath}")
        print("=" * 60)
        
        info = self.get_basic_info()
        print(f"\n[*] Basic Info:")
        for k, v in info.items():
            print(f"    {k}: {v}")
        
        sections = self.get_sections()
        print(f"\n[*] Sections ({len(sections)}):")
        for s in sections:
            print(f"    {s['name']:10} VA={s['virtual_address']:10} Entropy={s['entropy']:.2f}")
        
        imports = self.get_imports()
        print(f"\n[*] Imports ({len(imports)} DLLs):")
        suspicious_apis = [
            'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread',
            'LoadLibrary', 'GetProcAddress', 'ShellExecute',
            'RegOpenKey', 'CreateFile', 'InternetOpen'
        ]
        for dll, funcs in imports.items():
            print(f"    {dll}:")
            for func in funcs:
                is_suspicious = any(api.lower() in func['name'].lower() for api in suspicious_apis)
                marker = "[!]" if is_suspicious else "   "
                print(f"      {marker} {func['name']}")
        
        packers = self.detect_packers()
        if packers:
            print(f"\n[!] Packer Indicators:")
            for p in packers:
                print(f"    {p}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pe_file>")
        sys.exit(1)
    
    analyzer = PEAnalyzer(sys.argv[1])
    analyzer.analyze()
```

### 7.2 Windows API Monitoring

```javascript
// windows_api_monitor.js — Frida script สำหรับ Windows API monitoring

'use strict';

const monitoredAPIs = [
    // File operations
    { module: 'kernel32.dll', name: 'CreateFileW', category: 'File' },
    { module: 'kernel32.dll', name: 'ReadFile', category: 'File' },
    { module: 'kernel32.dll', name: 'WriteFile', category: 'File' },
    
    // Registry
    { module: 'advapi32.dll', name: 'RegOpenKeyExW', category: 'Registry' },
    { module: 'advapi32.dll', name: 'RegSetValueExW', category: 'Registry' },
    
    // Network
    { module: 'wininet.dll', name: 'InternetOpenUrlW', category: 'Network' },
    { module: 'ws2_32.dll', name: 'connect', category: 'Network' },
    { module: 'ws2_32.dll', name: 'send', category: 'Network' },
    
    // Process
    { module: 'kernel32.dll', name: 'CreateProcessW', category: 'Process' },
    { module: 'kernel32.dll', name: 'OpenProcess', category: 'Process' },
    { module: 'kernel32.dll', name: 'WriteProcessMemory', category: 'Injection' },
    { module: 'kernel32.dll', name: 'CreateRemoteThread', category: 'Injection' },
    
    // Crypto
    { module: 'crypt32.dll', name: 'CryptEncrypt', category: 'Crypto' },
    { module: 'crypt32.dll', name: 'CryptDecrypt', category: 'Crypto' },
];

function hookAPI(mod, name, category) {
    try {
        const funcPtr = Module.getExportByName(mod, name);
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                let details = [];
                
                // ดึง arguments ตาม function signature
                if (name === 'CreateFileW') {
                    const filename = args[0].readUtf16String();
                    details.push(`file="${filename}"`);
                } else if (name === 'RegOpenKeyExW') {
                    const keyName = args[1].readUtf16String();
                    details.push(`key="${keyName}"`);
                } else if (name === 'CreateProcessW') {
                    const cmdLine = args[1].readUtf16String();
                    details.push(`cmdline="${cmdLine}"`);
                } else if (name === 'connect') {
                    // sockaddr structure
                    const port = args[1].add(2).readU16();
                    const ip = [
                        args[1].add(4).readU8(),
                        args[1].add(5).readU8(),
                        args[1].add(6).readU8(),
                        args[1].add(7).readU8()
                    ].join('.');
                    details.push(`${ip}:${port}`);
                }
                
                const detailStr = details.length ? ` (${details.join(', ')})` : '';
                console.log(`[${category}] ${name}${detailStr}`);
                this.startTime = Date.now();
            },
            onLeave: function(retval) {
                const elapsed = Date.now() - (this.startTime || Date.now());
                // บันทึก failures
                if (retval.toInt32() === 0 || retval.toInt32() === -1) {
                    // console.log(`  -> FAILED (ret=${retval})`);
                }
            }
        });
    } catch(e) {
        // Function not found in this module, skip silently
    }
}

// Hook all APIs
monitoredAPIs.forEach(api => hookAPI(api.module, api.name, api.category));
console.log(`[*] Monitoring ${monitoredAPIs.length} Windows APIs`);
```

---

## 8. Reverse Engineering บน Linux

### 8.1 ELF Analysis

```bash
# ตรวจสอบ security features
checksec --file=./binary
# Output:
# RELRO    STACK CANARY  NX    PIE    RPATH  RUNPATH  FILE
# Full     Canary found  NX    PIE    No     No       ./binary

# ดู ELF sections
readelf -S ./binary
# ส่วนสำคัญ:
# .text    — code
# .data    — initialized global data
# .bss     — uninitialized global data
# .rodata  — read-only data (strings)
# .plt     — procedure linkage table
# .got     — global offset table
# .got.plt — GOT for PLT entries

# ดู symbols
nm ./binary
nm -D ./binary          # dynamic symbols
nm --defined-only ./binary

# DWARF debug info
objdump -g ./binary | head -50
readelf --debug-dump=info ./binary | head -50

# Trace system calls
strace -c ./binary      # summary of syscalls
strace -T ./binary      # with timing

# Library call tracing
ltrace -C ./binary      # demangle C++ symbols
```

### 8.2 Symbolic Execution ด้วย angr

```python
#!/usr/bin/env python3
# angr_solver.py — ใช้ angr เพื่อ solve crackme/CTF challenges

import angr
import claripy
import sys

def solve_crackme(binary_path):
    """
    ใช้ symbolic execution เพื่อหา input ที่ทำให้โปรแกรม print "Correct!"
    """
    print(f"[*] Loading {binary_path}...")
    project = angr.Project(binary_path, auto_load_libs=False)
    
    # สร้าง symbolic input (สมมติว่า password ยาว 16 ตัวอักษร)
    password_length = 16
    password = claripy.BVS('password', password_length * 8)
    
    # สร้าง initial state
    state = project.factory.full_init_state(
        stdin=angr.SimFile('/dev/stdin', content=password)
    )
    
    # เพิ่ม constraints: ทุก byte ต้องเป็น printable ASCII
    for i in range(password_length):
        byte = password.get_byte(i)
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7e)
    
    # กำหนด goal states
    # ค้นหา addresses ของ "Correct!" และ "Wrong!"
    # วิธีที่ 1: ใช้ string references
    cfg = project.analyses.CFGFast()
    
    # วิธีที่ 2: hardcode addresses (จาก disassembly)
    # find_addr = 0x401234   # address ที่ print "Correct!"
    # avoid_addr = 0x401256  # address ที่ print "Wrong!"
    
    # ใช้ simulation manager
    simgr = project.factory.simulation_manager(state)
    
    print("[*] Exploring...")
    simgr.explore(
        find=lambda s: b'Correct' in s.posix.dumps(1),  # stdout contains "Correct"
        avoid=lambda s: b'Wrong' in s.posix.dumps(1),   # avoid "Wrong" paths
    )
    
    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(password, cast_to=bytes)
        print(f"[!] Found solution: {solution}")
        print(f"[!] Password: {solution.decode('ascii', errors='replace')}")
        return solution
    else:
        print("[!] No solution found")
        return None

def solve_with_hooks(binary_path):
    """
    ใช้ SimProcedure hooks เพื่อเร่ง analysis
    """
    project = angr.Project(binary_path, auto_load_libs=False)
    
    # Hook strcmp เพื่อทำให้ analysis เร็วขึ้น
    class StrcmpHook(angr.SimProcedure):
        def run(self, s1_addr, s2_addr):
            # อ่าน strings
            s1 = self.state.memory.load(s1_addr, 32)
            s2 = self.state.memory.load(s2_addr, 32)
            # Return symbolic value
            return s1 - s2
    
    project.hook_symbol('strcmp', StrcmpHook())
    
    # Hook printf เพื่อหลีกเลี่ยง output issues
    project.hook_symbol('printf', angr.SIM_PROCEDURES['libc']['printf']())
    
    state = project.factory.entry_state()
    simgr = project.factory.simulation_manager(state)
    
    simgr.run(n=1000)  # จำกัดจำนวน steps
    
    return simgr

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>")
        sys.exit(1)
    solve_crackme(sys.argv[1])
```

---

## 9. CTF Reverse Engineering Challenges

### 9.1 Methodology สำหรับ RE CTF

```
CTF RE Methodology:

1. Reconnaissance
   └─ file, strings, checksec, readelf/objdump
   └─ ดู imports/exports
   └─ ค้นหา interesting strings (flag format)

2. Quick Analysis
   └─ รันโปรแกรมดู behavior
   └─ strace/ltrace เพื่อดู system/library calls
   └─ Ghidra/IDA auto-analysis

3. Find Key Logic
   └─ ค้นหา string references (flag, correct, wrong)
   └─ ดู cross-references ไปยัง print functions
   └─ Identify comparison/validation logic

4. Bypass/Extract
   └─ Patch binary (flip jump)
   └─ Extract key from memory
   └─ Symbolic execution
   └─ Brute force
```

### 9.2 ตัวอย่าง CTF RE Challenge Solver

```python
#!/usr/bin/env python3
# ctf_re_solver.py — toolkit สำหรับ CTF RE challenges

import subprocess
import struct
import sys
from pwn import *

def patch_binary(binary_path, offset, new_bytes, output_path=None):
    """Patch bytes ใน binary"""
    with open(binary_path, 'rb') as f:
        data = bytearray(f.read())
    
    for i, b in enumerate(new_bytes):
        data[offset + i] = b
    
    output_path = output_path or binary_path + '.patched'
    with open(output_path, 'wb') as f:
        f.write(data)
    
    # ทำให้ executable
    import os
    os.chmod(output_path, 0o755)
    print(f"[*] Patched binary saved to {output_path}")
    return output_path

def flip_jump(binary_path, jump_offset, output_path=None):
    """Flip conditional jump (je/jne, jl/jg, etc.)"""
    with open(binary_path, 'rb') as f:
        data = bytearray(f.read())
    
    opcode = data[jump_offset]
    
    # 2-byte conditional jumps
    jump_map = {
        0x74: 0x75,  # je  -> jne
        0x75: 0x74,  # jne -> je
        0x7c: 0x7d,  # jl  -> jge
        0x7d: 0x7c,  # jge -> jl
        0x7e: 0x7f,  # jle -> jg
        0x7f: 0x7e,  # jg  -> jle
    }
    
    if opcode in jump_map:
        data[jump_offset] = jump_map[opcode]
        print(f"[*] Flipped jump at offset {hex(jump_offset)}: {hex(opcode)} -> {hex(jump_map[opcode])}")
    
    output_path = output_path or binary_path + '.flipped'
    with open(output_path, 'wb') as f:
        f.write(data)
    return output_path

def brute_force_pin(binary_path, pin_length=4):
    """Brute force numeric PIN"""
    print(f"[*] Brute forcing {pin_length}-digit PIN...")
    
    for i in range(10**pin_length):
        pin = str(i).zfill(pin_length)
        
        result = subprocess.run(
            [binary_path],
            input=pin.encode(),
            capture_output=True,
            timeout=1
        )
        
        output = result.stdout + result.stderr
        if b'Correct' in output or b'flag' in output.lower() or b'CTF{' in output:
            print(f"[!] Found PIN: {pin}")
            print(f"[!] Output: {output}")
            return pin
    
    print("[!] PIN not found")
    return None

def extract_hardcoded_key(binary_path):
    """ดึง hardcoded key/password จาก binary"""
    results = {}
    
    # Method 1: strings command
    result = subprocess.run(['strings', binary_path], capture_output=True, text=True)
    all_strings = result.stdout.splitlines()
    
    # ค้นหา patterns ที่น่าสนใจ
    for s in all_strings:
        if len(s) >= 6:
            if s.startswith('CTF{') or s.startswith('flag{'):
                results['flag_string'] = s
            elif all(c in '0123456789abcdefABCDEF' for c in s) and len(s) in [32, 40, 64]:
                results['hex_string'] = s
    
    # Method 2: ltrace สำหรับ strcmp
    ltrace_result = subprocess.run(
        ['ltrace', '-e', 'strcmp', binary_path],
        input=b'test_input\n',
        capture_output=True,
        text=True,
        timeout=5
    )
    
    import re
    strcmp_pattern = re.compile(r'strcmp\("([^"]+)",\s*"([^"]+)"\)')
    for match in strcmp_pattern.finditer(ltrace_result.stderr):
        results['strcmp_arg1'] = match.group(1)
        results['strcmp_arg2'] = match.group(2)
    
    return results

class CrackmeAutomator:
    """Automated crackme solver"""
    
    def __init__(self, binary_path):
        self.binary = binary_path
        self.elf = ELF(binary_path)
    
    def run_with_input(self, input_data):
        p = process(self.binary)
        p.sendline(input_data)
        try:
            output = p.recvall(timeout=2)
        except:
            output = b''
        p.close()
        return output
    
    def check_output_for_success(self, output):
        success_indicators = [b'Correct', b'correct', b'Flag', b'flag', 
                             b'CTF{', b'Well done', b'success']
        return any(ind in output for ind in success_indicators)
    
    def solve(self):
        print(f"[*] Solving {self.binary}")
        
        # ขั้นที่ 1: ดู strings
        keys = extract_hardcoded_key(self.binary)
        if 'flag_string' in keys:
            print(f"[!] Flag found directly: {keys['flag_string']}")
            return keys['flag_string']
        
        if 'strcmp_arg2' in keys:
            print(f"[*] Possible password from strcmp: {keys['strcmp_arg2']}")
            output = self.run_with_input(keys['strcmp_arg2'].encode())
            if self.check_output_for_success(output):
                print(f"[!] Password works: {keys['strcmp_arg2']}")
                return keys['strcmp_arg2']
        
        print("[!] Automated solve failed, manual analysis needed")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary> [--brute-pin]")
        sys.exit(1)
    
    solver = CrackmeAutomator(sys.argv[1])
    result = solver.solve()
    
    if '--brute-pin' in sys.argv:
        brute_force_pin(sys.argv[1])
```

### 9.3 Buffer Overflow และ ROP Chain

```python
#!/usr/bin/env python3
# bof_solver.py — Buffer Overflow + ROP chain

from pwn import *
import sys

def find_offset(binary_path):
    """ค้นหา offset ของ return address"""
    # สร้าง cyclic pattern
    pattern = cyclic(200)
    
    p = process(binary_path)
    p.sendline(pattern)
    p.wait()
    
    # อ่าน core dump
    core = Coredump('./core')
    print(f"[*] Crash at: {hex(core.rip)}")  # x86-64
    
    offset = cyclic_find(core.rip & 0xffffffff)
    print(f"[*] Offset: {offset}")
    return offset

def build_rop_chain(binary_path, libc_path=None):
    """สร้าง ROP chain สำหรับ ret2libc"""
    elf = ELF(binary_path)
    
    if libc_path:
        libc = ELF(libc_path)
    
    rop = ROP(elf)
    
    # ค้นหา gadgets
    # pop rdi; ret
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    # pop rsi; pop r15; ret
    pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
    # ret (for stack alignment)
    ret_gadget = rop.find_gadget(['ret'])[0]
    
    print(f"[*] pop rdi; ret: {hex(pop_rdi)}")
    print(f"[*] ret: {hex(ret_gadget)}")
    
    # Method 1: ret2plt (ถ้ามี puts/system ใน PLT)
    chain = b''
    if 'puts' in elf.plt:
        # Leak libc address ผ่าน puts
        chain += p64(pop_rdi)
        chain += p64(elf.got['puts'])  # arg: puts@got
        chain += p64(elf.plt['puts'])  # call puts
        chain += p64(elf.sym['main'])  # return to main
    
    return chain

def exploit_bof(binary_path, offset, shellcode=None):
    """Exploit buffer overflow"""
    elf = ELF(binary_path)
    
    context.arch = 'amd64'
    context.os = 'linux'
    
    # สร้าง payload
    padding = b'A' * offset
    
    if shellcode:
        # ret2shellcode (ถ้า NX ปิด)
        payload = padding + shellcode
    else:
        # ROP chain
        rop_chain = build_rop_chain(binary_path)
        payload = padding + rop_chain
    
    return payload

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    binary = './vulnerable_binary'
    
    # หา offset
    # offset = find_offset(binary)
    offset = 72  # หลังจาก analysis
    
    # สร้าง payload
    payload = exploit_bof(binary, offset)
    
    # ส่ง payload
    p = process(binary)
    # p = remote('ctf.example.com', 4444)
    
    p.sendline(payload)
    p.interactive()
```

---

## 10. Practical Malware Reversing Workflow

### 10.1 Safe Analysis Environment

```bash
# ตั้งค่า isolated VM สำหรับ malware analysis
# ใช้ VM snapshot ก่อนทดสอบทุกครั้ง

# ติดตั้ง tools ใน Windows VM (ผ่าน Chocolatey)
choco install -y \
    x64dbg \
    ghidra \
    pestudio \
    processhacker \
    wireshark \
    fakenet-ng \
    regshot

# บน Linux analysis machine:
pip3 install \
    pefile \
    yara-python \
    volatility3
```

### 10.2 Malware Analysis Workflow

```python
#!/usr/bin/env python3
# malware_re_workflow.py — Automated malware reversing workflow

import pefile
import hashlib
import subprocess
import json
import yara
from pathlib import Path
from datetime import datetime

class MalwareREAnalyzer:
    def __init__(self, sample_path):
        self.sample = Path(sample_path)
        self.report = {
            'filename': self.sample.name,
            'analysis_time': datetime.now().isoformat(),
            'hashes': {},
            'file_info': {},
            'imports': {},
            'strings': [],
            'yara_matches': [],
            'behavior_indicators': [],
        }
    
    def compute_hashes(self):
        data = self.sample.read_bytes()
        self.report['hashes'] = {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }
        print(f"[*] MD5: {self.report['hashes']['md5']}")
        print(f"[*] SHA256: {self.report['hashes']['sha256']}")
    
    def static_analysis(self):
        """Static analysis ด้วย pefile"""
        try:
            pe = pefile.PE(str(self.sample))
            
            self.report['file_info'] = {
                'is_dll': pe.is_dll(),
                'is_exe': pe.is_exe(),
                'machine': hex(pe.FILE_HEADER.Machine),
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            }
            
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    funcs = []
                    for imp in entry.imports:
                        if imp.name:
                            funcs.append(imp.name.decode('utf-8', errors='ignore'))
                    self.report['imports'][dll] = funcs
            
            pe.close()
        except pefile.PEFormatError:
            self.report['file_info']['type'] = 'Not a PE file'
    
    def extract_strings(self):
        """ดึง strings ที่น่าสนใจ"""
        result = subprocess.run(
            ['strings', '-n', '6', str(self.sample)],
            capture_output=True, text=True
        )
        all_strings = result.stdout.splitlines()
        
        # กรอง strings ที่น่าสนใจ
        indicators = {
            'urls': [],
            'ips': [],
            'registry_keys': [],
            'file_paths': [],
            'commands': [],
            'crypto': [],
        }
        
        import re
        url_pattern = re.compile(r'https?://[\w\-./:%?&=]+')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        reg_pattern = re.compile(r'HKEY_[\w\\]+')
        
        for s in all_strings:
            if url_pattern.search(s):
                indicators['urls'].append(s)
            elif ip_pattern.search(s):
                indicators['ips'].append(s)
            elif reg_pattern.search(s):
                indicators['registry_keys'].append(s)
            elif any(kw in s.lower() for kw in ['cmd.exe', 'powershell', 'wscript']):
                indicators['commands'].append(s)
            elif any(kw in s.lower() for kw in ['aes', 'rsa', 'encrypt', 'decrypt', 'base64']):
                indicators['crypto'].append(s)
        
        self.report['strings'] = indicators
        return indicators
    
    def yara_scan(self, rules_path='/etc/yara/rules'):
        """Scan ด้วย YARA rules"""
        # YARA rules สำหรับ malware families
        inline_rules = '''
        rule SuspiciousStrings {
            strings:
                $s1 = "cmd.exe" nocase
                $s2 = "powershell" nocase
                $s3 = "CreateRemoteThread"
                $s4 = "VirtualAlloc"
                $s5 = "WriteProcessMemory"
                $s6 = "socket" nocase
            condition:
                3 of them
        }
        
        rule AntiAnalysis {
            strings:
                $a1 = "IsDebuggerPresent"
                $a2 = "CheckRemoteDebuggerPresent"
                $a3 = "NtQueryInformationProcess"
                $a4 = "GetTickCount"
                $a5 = "QueryPerformanceCounter"
            condition:
                2 of them
        }
        
        rule NetworkIndicators {
            strings:
                $n1 = "InternetOpen" wide ascii
                $n2 = "WinHttpOpen" wide ascii
                $n3 = "WSAStartup"
                $n4 = "connect"
                $n5 = "recv"
                $n6 = "send"
            condition:
                3 of them
        }
        '''
        
        try:
            rules = yara.compile(source=inline_rules)
            matches = rules.match(str(self.sample))
            self.report['yara_matches'] = [str(m) for m in matches]
        except Exception as e:
            print(f"[!] YARA error: {e}")
    
    def identify_behavior_indicators(self):
        """ระบุ behavior indicators จาก imports/strings"""
        indicators = []
        
        suspicious_imports = {
            'CreateRemoteThread': 'Process Injection',
            'WriteProcessMemory': 'Process Injection',
            'VirtualAllocEx': 'Process Injection',
            'OpenProcess': 'Process Access',
            'RegOpenKey': 'Registry Access',
            'RegSetValue': 'Registry Modification',
            'InternetOpen': 'Network Communication',
            'CryptEncrypt': 'Encryption',
            'ShellExecute': 'Command Execution',
            'CreateProcess': 'Process Creation',
        }
        
        for dll, funcs in self.report['imports'].items():
            for func in funcs:
                for api, behavior in suspicious_imports.items():
                    if api.lower() in func.lower():
                        indicator = f"{behavior}: {func} ({dll})"
                        if indicator not in indicators:
                            indicators.append(indicator)
        
        self.report['behavior_indicators'] = indicators
        return indicators
    
    def generate_report(self, output_file=None):
        """สร้าง analysis report"""
        self.compute_hashes()
        self.static_analysis()
        self.extract_strings()
        self.yara_scan()
        self.identify_behavior_indicators()
        
        # สรุปผล
        print("\n" + "="*60)
        print("MALWARE RE ANALYSIS REPORT")
        print("="*60)
        print(f"File: {self.report['filename']}")
        print(f"MD5: {self.report['hashes'].get('md5', 'N/A')}")
        print(f"SHA256: {self.report['hashes'].get('sha256', 'N/A')}")
        
        if self.report['yara_matches']:
            print(f"\n[!] YARA Matches: {', '.join(self.report['yara_matches'])}")
        
        if self.report['behavior_indicators']:
            print(f"\n[*] Behavior Indicators:")
            for ind in self.report['behavior_indicators']:
                print(f"    - {ind}")
        
        strings = self.report['strings']
        if strings.get('urls'):
            print(f"\n[*] URLs found:")
            for url in strings['urls'][:10]:
                print(f"    {url}")
        
        if strings.get('ips'):
            print(f"\n[*] IP Addresses:")
            for ip in strings['ips'][:10]:
                print(f"    {ip}")
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(self.report, f, indent=2)
            print(f"\n[*] Full report saved to {output_file}")
        
        return self.report

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <malware_sample> [output.json]")
        sys.exit(1)
    
    output = sys.argv[2] if len(sys.argv) > 2 else None
    analyzer = MalwareREAnalyzer(sys.argv[1])
    analyzer.generate_report(output)
```

### 10.3 Memory Forensics Integration

```bash
# ใช้ Volatility 3 เพื่อวิเคราะห์ memory dump
pip3 install volatility3

# ตัวอย่างการ dump memory จาก VM:
# VMware: ค้นหาไฟล์ .vmem ใน VM directory
# VirtualBox: vboxmanage debugvm <name> dumpvmcore --filename=memory.dmp
# Live: sudo avml /tmp/memory.dmp

# Volatility 3 commands:
python3 vol.py -f memory.dmp windows.pslist          # process list
python3 vol.py -f memory.dmp windows.pstree          # process tree
python3 vol.py -f memory.dmp windows.cmdline         # command lines
python3 vol.py -f memory.dmp windows.netscan         # network connections
python3 vol.py -f memory.dmp windows.malfind         # find injected code
python3 vol.py -f memory.dmp windows.dlllist         # DLL list per process
python3 vol.py -f memory.dmp windows.dumpfiles --pid 1234  # dump process files
python3 vol.py -f memory.dmp windows.strings         # extract strings
```

```python
#!/usr/bin/env python3
# memory_re_helper.py — Memory forensics helper สำหรับ RE

import subprocess
import re
from pathlib import Path

class VolatilityWrapper:
    def __init__(self, memory_image, profile=None):
        self.image = memory_image
        self.vol_cmd = ['python3', 'vol.py', '-f', memory_image]
    
    def run_plugin(self, plugin, extra_args=None):
        cmd = self.vol_cmd + [plugin]
        if extra_args:
            cmd.extend(extra_args)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout
    
    def get_processes(self):
        output = self.run_plugin('windows.pslist')
        processes = []
        for line in output.splitlines()[2:]:  # skip header
            parts = line.split()
            if len(parts) >= 3:
                processes.append({
                    'pid': parts[1],
                    'ppid': parts[2],
                    'name': parts[0]
                })
        return processes
    
    def find_injected_code(self):
        """ค้นหา code injection (process hollowing, PE injection)"""
        output = self.run_plugin('windows.malfind')
        injections = []
        
        current_proc = None
        for line in output.splitlines():
            if 'PID' in line and 'Process' in line:
                current_proc = line
            elif 'MZ' in line or '4d5a' in line.lower():  # PE header
                injections.append({
                    'process': current_proc,
                    'indicator': 'PE header in memory'
                })
        
        return injections
    
    def extract_strings_from_pid(self, pid, output_dir):
        """ดึง strings จาก process memory"""
        output_path = Path(output_dir) / f"pid_{pid}_strings.txt"
        output = self.run_plugin('windows.strings', ['--pid', str(pid)])
        output_path.write_text(output)
        print(f"[*] Strings saved to {output_path}")
        return output_path
    
    def analyze_malware_process(self, pid):
        """วิเคราะห์ process ที่สงสัยว่าเป็น malware"""
        print(f"[*] Analyzing PID {pid}...")
        
        # ดู DLLs ที่ load
        dlls = self.run_plugin('windows.dlllist', ['--pid', str(pid)])
        print(f"[*] Loaded DLLs:")
        for line in dlls.splitlines()[:20]:
            print(f"  {line}")
        
        # ดู network connections
        net = self.run_plugin('windows.netscan')
        pid_str = str(pid)
        connections = [line for line in net.splitlines() if pid_str in line]
        if connections:
            print(f"[*] Network connections:")
            for conn in connections:
                print(f"  {conn}")
        
        # ค้นหา injected code
        malfind = self.run_plugin('windows.malfind', ['--pid', str(pid)])
        if 'MZ' in malfind or 'PAGE_EXECUTE' in malfind:
            print(f"[!] Possible code injection detected!")
            print(malfind[:500])

if __name__ == "__main__":
    vol = VolatilityWrapper('/path/to/memory.dmp')
    
    # ดู processes
    procs = vol.get_processes()
    print(f"[*] Found {len(procs)} processes")
    
    # ค้นหา injections
    injections = vol.find_injected_code()
    if injections:
        print(f"[!] Found {len(injections)} potential injections")
```

---

## แบบฝึกหัด

### Lab 1: Static Analysis Crackme
```
เป้าหมาย: ค้นหา password ใน crackme binary
1. ดาวน์โหลด crackme จาก https://crackmes.one
2. รัน: file, strings, checksec
3. Import ใน Ghidra และ analyze
4. ค้นหา string "Correct" และ trace ไปยัง validation logic
5. ระบุ hardcoded password
```

### Lab 2: Dynamic Analysis
```
เป้าหมาย: ใช้ GDB เพื่อ bypass password check
1. สร้าง vulnerable program ด้วย C:
   int main() {
     char buf[64];
     printf("Password: ");
     gets(buf);
     if (strcmp(buf, "secret123") == 0)
       printf("Correct!\n");
     return 0;
   }
2. Compile: gcc -g -o crackme crackme.c
3. ใช้ GDB: break ที่ strcmp, inspect arguments
4. Patch binary เพื่อ bypass check
```

### Lab 3: CTF RE Challenge
```
เป้าหมาย: Solve CTF RE challenge
1. ไปที่ picoCTF, pwn.college, หรือ HackTheBox
2. เลือก Reverse Engineering challenge
3. ใช้ methodology: reconnaissance → static → dynamic → solve
4. บันทึก writeup
```

---

## สรุป

| หัวข้อ | เครื่องมือหลัก | เทคนิค |
|--------|--------------|--------|
| Static Analysis | Ghidra, Radare2, IDA Pro | Disassembly, Decompilation |
| Dynamic Analysis | GDB+pwndbg, strace, ltrace | Debugging, Tracing |
| Anti-RE Bypass | Frida, GDB patches | Anti-debug bypass, Unpacking |
| CTF RE | angr, pwntools | Symbolic execution, ROP |
| Malware RE | pefile, YARA, Volatility | PE analysis, Memory forensics |
| Windows RE | x64dbg, IDAPython | Windows API monitoring |

---

← [Part 81: Wireless Security Advanced](Part-81-Wireless-Security-Advanced.md) | [Part 83: Malware Analysis](Part-83-Malware-Analysis.md) →
