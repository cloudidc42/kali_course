# Part 69: Advanced Reverse Engineering (การ Reverse Engineering ขั้นสูง)

## สารบัญ
1. [RE Fundamentals Review](#re-fundamentals-review)
2. [x86/x64 Assembly Deep Dive](#x86x64-assembly-deep-dive)
3. [Ghidra Advanced Usage](#ghidra-advanced-usage)
4. [IDA Pro Techniques](#ida-pro-techniques)
5. [Debugger Techniques](#debugger-techniques)
6. [Unpacking Packed Malware](#unpacking-packed-malware)
7. [Obfuscation Bypass](#obfuscation-bypass)
8. [Protocol Reversing](#protocol-reversing)
9. [Firmware Analysis](#firmware-analysis)
10. [CTF RE Challenges](#ctf-re-challenges)

---

## 1. RE Fundamentals Review

### ความเข้าใจเกี่ยวกับ Binary

```
การแปลง Source Code เป็น Binary:

C/C++ Source Code
    ↓ Compiler (gcc, clang, MSVC)
Assembly (.asm)
    ↓ Assembler (nasm, gas)
Object Code (.o)
    ↓ Linker (ld)
Executable Binary (ELF/PE)

การ Reverse Engineering ทำในทิศทางย้อนกลับ:

Executable Binary
    ↓ Disassembler (IDA, Ghidra, radare2)
Assembly
    ↓ Decompiler (HexRays, Ghidra decompiler)
Pseudo-C Code
```

### x86 Register Reference

```asm
; ===== x86 Register Reference =====

; General Purpose (32-bit)
; EAX - Accumulator (return values)
; EBX - Base (preserved across calls)
; ECX - Counter (loop counter)
; EDX - Data (multiply/divide)
; ESI - Source Index
; EDI - Destination Index
; ESP - Stack Pointer
; EBP - Base Pointer (stack frame)

; 64-bit equivalents
; RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP
; Additional: R8-R15

; Segment Registers
; CS, DS, ES, FS, GS, SS

; EFLAGS important bits:
; CF - Carry Flag
; ZF - Zero Flag  
; SF - Sign Flag
; OF - Overflow Flag

; ===== Common Instructions =====

mov eax, 0x10      ; EAX = 0x10
mov [ebp-4], eax   ; store at memory address
mov eax, [ebp-4]   ; load from memory

push eax           ; ESP -= 4; [ESP] = EAX
pop  eax           ; EAX = [ESP]; ESP += 4

add  eax, 1        ; EAX = EAX + 1
sub  eax, 1        ; EAX = EAX - 1
imul eax, ebx      ; EAX = EAX * EBX (signed)
idiv ecx           ; EAX = EAX/ECX, EDX = EAX%ECX

and  eax, 0xff     ; bitwise AND
or   eax, 0x01     ; bitwise OR
xor  eax, eax      ; EAX = 0 (common zero pattern)
not  eax           ; bitwise NOT
shl  eax, 2        ; shift left 2 bits (x4)
shr  eax, 1        ; shift right 1 bit (x/2)

cmp  eax, 0        ; set flags (eax - 0) 
test eax, eax      ; set flags (eax & eax)
jz   label         ; jump if zero (ZF=1)
jnz  label         ; jump if not zero
jl   label         ; jump if less
jg   label         ; jump if greater
jle  label         ; jump if less or equal
jge  label         ; jump if greater or equal

call function      ; push return addr, jump
ret                ; pop return addr, jump
leave              ; mov esp, ebp; pop ebp

lea  eax, [ebp-8]  ; Load Effective Address (ptr arithmetic)
nop                ; No operation
```

---

## 2. x86/x64 Assembly Deep Dive

### อ่าน Assembly แบบมืออาชีพ

```asm
; ===== Analyzing Function Prologue/Epilogue =====

; Standard x86 function prologue:
push ebp          ; save old frame pointer
mov  ebp, esp     ; create new frame
sub  esp, 0x20    ; allocate local variables

; Standard epilogue:
mov  esp, ebp     ; or 'leave'
pop  ebp
ret

; ===== Loop Recognition =====

; for (i = 0; i < 10; i++) { ... }
    mov  ecx, 0           ; i = 0
loop_start:
    cmp  ecx, 10          ; i < 10?
    jge  loop_end         ; if not, exit
    ; ... loop body ...
    inc  ecx              ; i++
    jmp  loop_start
loop_end:

; while (cond) {...} 
    ; Compiler often converts to:
    jmp  check
loop_body:
    ; ... body ...
check:
    test eax, eax
    jnz  loop_body

; ===== String Operations =====

; strlen equivalent
    xor  ecx, ecx         ; ecx = 0
    mov  esi, str_ptr     ; esi points to string
strlen_loop:
    cmp  byte [esi+ecx], 0  ; null check
    jz   strlen_done
    inc  ecx
    jmp  strlen_loop
strlen_done:
    ; ecx = length

; memcpy equivalent
    mov  ecx, size        ; byte count
    mov  esi, src
    mov  edi, dst
    rep  movsb            ; copy ECX bytes from [ESI] to [EDI]

; memset equivalent
    mov  ecx, size
    mov  edi, dst
    xor  eax, eax         ; fill with 0
    rep  stosb

; ===== Switch Statement Pattern =====

; switch(x) { case 0:... case 1:... case 2:... }
    cmp  eax, 2           ; check max case
    ja   default_case     ; if x > max, goto default
    jmp  [table + eax*4]  ; jump table lookup

table:
    dd case_0
    dd case_1
    dd case_2

; ===== Struct Access Pattern =====

; struct { int a; int b; char c[8]; } s;
; s.a -> [ebp-x]
; s.b -> [ebp-x+4]
; s.c -> [ebp-x+8]

    mov  eax, [ebp-0x10]  ; load s.a
    mov  ecx, [ebp-0xc]   ; load s.b
    lea  edx, [ebp-0x8]   ; ptr to s.c
```

### วิเคราะห์ Calling Conventions

```python
#!/usr/bin/env python3
# calling_convention_analyzer.py

CALLING_CONVENTIONS = {
    'cdecl': {
        'platform': 'x86 Windows/Linux',
        'arg_passing': 'Stack (right to left)',
        'cleanup': 'Caller',
        'return': 'EAX (int), EDX:EAX (64-bit)',
        'preserved': ['EBX', 'ESI', 'EDI', 'EBP'],
        'example': 'func(1, 2, 3) -> push 3; push 2; push 1; call func; add esp,12'
    },
    'stdcall': {
        'platform': 'x86 Windows API',
        'arg_passing': 'Stack (right to left)',
        'cleanup': 'Callee',
        'return': 'EAX',
        'preserved': ['EBX', 'ESI', 'EDI', 'EBP'],
        'example': 'Used by Win32 API (MessageBoxA, etc.)'
    },
    'fastcall': {
        'platform': 'x86 MSVC',
        'arg_passing': 'ECX, EDX first, rest on stack',
        'cleanup': 'Callee',
        'return': 'EAX',
        'note': 'First 2 args in ECX/EDX'
    },
    'x64_windows': {
        'platform': 'x64 Windows',
        'arg_passing': 'RCX, RDX, R8, R9, then stack',
        'cleanup': 'Caller',
        'return': 'RAX',
        'preserved': ['RBX', 'RBP', 'RDI', 'RSI', 'R12-R15'],
        'shadow_space': '32 bytes reserved on stack by caller'
    },
    'system_v_amd64': {
        'platform': 'x64 Linux/macOS',
        'arg_passing': 'RDI, RSI, RDX, RCX, R8, R9, then stack',
        'cleanup': 'Caller',
        'return': 'RAX, RDX',
        'preserved': ['RBX', 'RBP', 'R12-R15']
    }
}

def explain_convention(name: str):
    conv = CALLING_CONVENTIONS.get(name, {})
    if not conv:
        return f"Unknown convention: {name}"
    
    output = f"\n=== {name} ==="
    for key, value in conv.items():
        output += f"\n  {key}: {value}"
    return output


if __name__ == "__main__":
    for name in CALLING_CONVENTIONS:
        print(explain_convention(name))
```

---

## 3. Ghidra Advanced Usage

### Ghidra Scripting (Python/Java)

```python
# ghidra_script.py - Ghidra Python Script
# เรียกใช้ใน Ghidra Script Manager

# ===== ค้นหา function calls =====
def find_interesting_functions():
    function_manager = currentProgram.getFunctionManager()
    
    interesting = []
    for func in function_manager.getFunctions(True):
        name = func.getName().lower()
        
        # ค้นหาความสนใจ
        if any(keyword in name for keyword in 
               ['crypto', 'decrypt', 'encode', 'key', 'password']):
            interesting.append(func)
    
    return interesting


# ===== ค้นหา strings แปลก =====
def find_suspicious_strings():
    from ghidra.program.model.listing import DataIterator
    
    suspicious = []
    for data in currentProgram.getListing().getDefinedData(True):
        if data.getDataType().getName() == 'string':
            value = str(data.getValue())
            if any(p in value.lower() for p in 
                   ['http', 'cmd', 'exec', 'shell', 'base64']):
                suspicious.append((data.getAddress(), value))
    
    return suspicious


# ===== Rename functions อัตโนมัติ =====
def rename_by_pattern():
    from ghidra.program.model.symbol import SourceType
    
    function_manager = currentProgram.getFunctionManager()
    
    for func in function_manager.getFunctions(True):
        # รับไป listing (โค้ดและ comments)
        listing = currentProgram.getListing()
        instructions = listing.getInstructions(func.getBody(), True)
        
        has_network = False
        for inst in instructions:
            if 'connect' in str(inst).lower() or 'send' in str(inst).lower():
                has_network = True
                break
        
        if has_network and func.getName().startswith('FUN_'):
            new_name = f"network_{func.getName()[4:]}"
            func.setName(new_name, SourceType.USER_DEFINED)
            print(f"Renamed: {func.getName()} -> {new_name}")


# ===== Cross-reference analysis =====
def analyze_xrefs(func_name):
    from ghidra.program.model.symbol import SymbolType
    
    symbol_table = currentProgram.getSymbolTable()
    symbols = symbol_table.getGlobalSymbols(func_name)
    
    for symbol in symbols:
        print(f"Function: {symbol.getName()} at {symbol.getAddress()}")
        
        # หาสิ่งที่เรียกฟังก์ชันนี้
        refs = currentProgram.getReferenceManager().getReferencesTo(symbol.getAddress())
        for ref in refs:
            caller_addr = ref.getFromAddress()
            caller_func = getFunctionContaining(caller_addr)
            if caller_func:
                print(f"  Called from: {caller_func.getName()} at {caller_addr}")
```

### Ghidra Command-Line Usage

```bash
# ===== Ghidra CLI Automation =====

# เริ่ม Ghidra headless
$GHIDRA_HOME/support/analyzeHeadless \
    /projects MyProject \
    -import malware.exe \
    -postScript analyze_script.py \
    -scriptPath /scripts/ \
    -log /tmp/ghidra.log

# สร้าง Ghidra Python script สำหรับ headless
cat > /scripts/extract_strings.py << 'EOF'
from ghidra.program.model.listing import DataType

for data in currentProgram.getListing().getDefinedData(True):
    if data.getDataType().getName() == 'string':
        print(f"{data.getAddress()}: {data.getValue()}")
EOF

# Batch analysis
for sample in /malware/samples/*.exe; do
    $GHIDRA_HOME/support/analyzeHeadless \
        /projects BatchAnalysis \
        -import "$sample" \
        -postScript extract_strings.py > "/malware/reports/$(basename $sample).txt" 2>&1
done
```

---

## 4. IDA Pro Techniques

### IDA Pro IDAPython Scripts

```python
# idapython_scripts.py - IDAPython automation
# เรียกใช้ใน IDA Pro Script Manager

import idc
import idaapi
import idautils
import ida_bytes
import ida_funcs

# ===== ค้นหาสิ่งที่น่าสนใจ =====
def find_interesting_calls():
    interesting_funcs = [
        'CreateFile', 'WriteFile', 'ReadFile',
        'RegSetValueEx', 'RegCreateKey',
        'socket', 'connect', 'send', 'recv',
        'WinExec', 'ShellExecute', 'CreateProcess'
    ]
    
    results = []
    for func_name in interesting_funcs:
        addr = idc.get_name_ea_simple(func_name)
        if addr != idc.BADADDR:
            # หา cross-references
            for xref in idautils.XrefsTo(addr):
                caller = idaapi.get_func(xref.frm)
                if caller:
                    results.append({
                        'function': func_name,
                        'call_addr': hex(xref.frm),
                        'caller': idc.get_func_name(xref.frm)
                    })
    
    return results


# ===== Decrypt XOR-encoded data =====
def decrypt_xor(start_addr, size, key):
    """ถอดรหัส XOR ใน IDA"""
    for i in range(size):
        byte = idc.get_wide_byte(start_addr + i)
        decrypted = byte ^ key
        idc.patch_byte(start_addr + i, decrypted)
    
    idc.create_strlit(start_addr, size)  # re-analyze as string
    print(f"Decrypted {size} bytes at {hex(start_addr)}")


# ===== Find all strings referenced in function =====
def get_strings_in_function(func_addr):
    strings = []
    func = idaapi.get_func(func_addr)
    
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(head):
            # Check if it's a string reference
            s = idc.get_strlit_contents(xref.to)
            if s:
                strings.append(s.decode('utf-8', errors='replace'))
    
    return strings


# ===== Auto-comment function args =====
def comment_api_args():
    # Windows API args auto-comment
    api_args = {
        'MessageBoxA': ['hWnd', 'lpText', 'lpCaption', 'uType'],
        'CreateFileA': ['lpFileName', 'dwAccess', 'dwShare', 'lpSecurity',
                        'dwDisposition', 'dwFlags', 'hTemplate'],
    }
    
    for api_name, args in api_args.items():
        addr = idc.get_name_ea_simple(api_name)
        if addr == idc.BADADDR:
            continue
        
        for xref in idautils.XrefsTo(addr):
            # เอา args จาก stack
            head = xref.frm
            for i, arg in reversed(list(enumerate(args))):
                prev = idc.prev_head(head)
                if prev == idc.BADADDR:
                    break
                idc.set_cmt(prev, f"arg{i}: {arg}", False)
                head = prev


# ===== Export decompiled pseudocode =====
def export_all_pseudocode(output_file):
    import ida_hexrays
    
    with open(output_file, 'w') as f:
        for func in idautils.Functions():
            try:
                cfunc = ida_hexrays.decompile(func)
                if cfunc:
                    f.write(f"\n// Function at {hex(func)}\n")
                    f.write(str(cfunc))
                    f.write("\n")
            except:
                pass
    
    print(f"Exported to {output_file}")
```

---

## 5. Debugger Techniques

### x64dbg / pwndbg Advanced

```python
#!/usr/bin/env python3
# debug_automation.py - เดบัก automation

import subprocess
import struct
from typing import Optional

class GDBWrapper:
    """ควบคุม GDB ผ่าน subprocess"""
    
    def __init__(self, binary: str, args: str = ""):
        self.binary = binary
        self.args = args
        self.breakpoints = []
        self.script_commands = []
    
    def add_breakpoint(self, location: str):
        """เพิ่ม breakpoint"""
        self.breakpoints.append(f"b {location}")
    
    def add_command(self, cmd: str):
        """เพิ่ม GDB command"""
        self.script_commands.append(cmd)
    
    def generate_script(self) -> str:
        """สร้าง GDB script"""
        script = []
        
        # Breakpoints
        script.extend(self.breakpoints)
        
        # เพิ่ม logging ที่ breakpoint
        for bp in self.breakpoints:
            addr = bp.split()[-1]
            script.append(f"commands")
            script.append(f"  info registers")
            script.append(f"  x/32x $esp")
            script.append(f"  continue")
            script.append(f"end")
        
        # Custom commands
        script.extend(self.script_commands)
        script.append("run")
        
        return "\n".join(script)
    
    def run_with_script(self, timeout: int = 60) -> str:
        """รัน GDB พร้อม script"""
        script = self.generate_script()
        
        # เซเสคริปต์
        with open('/tmp/gdb_script.gdb', 'w') as f:
            f.write(script)
        
        cmd = [
            'gdb', '-batch', 
            '-x', '/tmp/gdb_script.gdb',
            '--args', self.binary, self.args
        ]
        
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr


# ===== pwntools for CTF debugging =====
def create_pwntools_script(binary: str, remote_host: str = None):
    """สร้าง pwntools exploit script template"""
    
    script = f"""#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

elf = ELF('{binary}')
libc = elf.libc

# เชื่อมต่อ process หรือ remote
if args.REMOTE:
    p = remote('{remote_host or 'TARGET_HOST'}', 1337)
else:
    p = process('{binary}')
    if args.GDB:
        gdb.attach(p, '''
            b main
            b *0x401234
            c
        ''')

# Helpers
def send_payload(payload, recv=True):
    p.sendline(payload)
    if recv:
        return p.recvuntil(b'> ', timeout=3)

# ===== Exploit Development =====

# 1. หา offset
# pattern = cyclic(300)
# p.sendline(pattern)
# p.wait()
# offset = cyclic_find(core.read(p64_offset, 4))

offset = 72  # ปรับค่าตามข้อมูลจริง

# 2. สร้าง payload
payload = b'A' * offset
payload += p64(elf.sym['win_function'])  # overwrite RIP

# 3. ส่ง payload
p.sendline(payload)

p.interactive()
"""
    return script


# Pwntools helper functions
def find_gadgets(binary_path: str, gadget_pattern: str):
    """หา ROP gadgets"""
    from pwn import ROP, ELF
    
    elf = ELF(binary_path)
    rop = ROP(elf)
    
    # หา gadgets
    gadgets = []
    
    # Common useful gadgets
    wanted = [
        'pop rdi; ret',
        'pop rsi; ret',
        'pop rdx; ret',
        'pop rax; ret',
        'syscall; ret',
        'ret',  # stack alignment
    ]
    
    for gadget in wanted:
        try:
            addr = rop.find_gadget(gadget.split('; '))
            if addr:
                gadgets.append({'gadget': gadget, 'address': hex(addr.address)})
        except:
            pass
    
    return gadgets


if __name__ == "__main__":
    # Demo
    print("[*] GDB Wrapper Example")
    gdb = GDBWrapper('./target_binary')
    gdb.add_breakpoint('main')
    gdb.add_breakpoint('*0x401234')
    gdb.add_command('info registers')
    
    script = gdb.generate_script()
    print("Generated GDB Script:")
    print(script)
```

---

## 6. Unpacking Packed Malware

### Manual Unpacking

```python
#!/usr/bin/env python3
# unpacker.py - Manual unpacking techniques

import struct
import zlib
import base64
from typing import bytes

class SimpleUnpacker:
    """ถอด common packing methods"""
    
    @staticmethod
    def unpack_upx(binary_data: bytes) -> bytes:
        """ถอด UPX (ใช้ upx -d เป็นทางเลือกที่ดีกว่า)"""
        # ตรวจสอป UPX signature
        if b'UPX!' not in binary_data[:1000]:
            return binary_data
        
        # ใช้ upx tool
        import subprocess
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
            f.write(binary_data)
            temp_file = f.name
        
        try:
            result = subprocess.run(
                ['upx', '-d', temp_file, '-o', temp_file + '.unpacked'],
                capture_output=True
            )
            
            if result.returncode == 0:
                with open(temp_file + '.unpacked', 'rb') as f:
                    return f.read()
        finally:
            os.unlink(temp_file)
            if os.path.exists(temp_file + '.unpacked'):
                os.unlink(temp_file + '.unpacked')
        
        return binary_data
    
    @staticmethod
    def extract_from_dropper(data: bytes) -> bytes:
        """ดึง embedded payload จาก dropper"""
        # ค้นหา PE header ภายใน
        pe_header = b'\x4d\x5a'  # MZ
        
        offset = 0
        while True:
            idx = data.find(pe_header, offset)
            if idx == -1:
                break
            if idx > 0:
                potential_pe = data[idx:]
                if len(potential_pe) > 0x40:
                    e_lfanew = struct.unpack_from('<I', potential_pe, 0x3c)[0]
                    if e_lfanew < len(potential_pe) - 4:
                        pe_sig = potential_pe[e_lfanew:e_lfanew+4]
                        if pe_sig == b'PE\x00\x00':
                            return potential_pe
            offset = idx + 1
        
        return None
    
    @staticmethod 
    def decrypt_rc4(data: bytes, key: bytes) -> bytes:
        """ถอดรหัส RC4"""
        S = list(range(256))
        j = 0
        
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        i = j = 0
        result = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])
        
        return bytes(result)
    
    @staticmethod
    def decrypt_xor(data: bytes, key: int) -> bytes:
        """ถอดรหัส XOR (single byte key)"""
        return bytes([b ^ key for b in data])
    
    @staticmethod
    def find_xor_key(encrypted: bytes, known_plaintext: bytes, offset: int = 0) -> int:
        """หา XOR key จาก known plaintext"""
        if offset < len(encrypted) and offset < len(known_plaintext):
            return encrypted[offset] ^ known_plaintext[offset]
        return -1
    
    @staticmethod
    def brute_force_xor(encrypted: bytes, expected_header: bytes) -> int:
        """เดา XOR key จาก 0-255"""
        for key in range(256):
            decrypted = SimpleUnpacker.decrypt_xor(encrypted[:len(expected_header)], key)
            if decrypted == expected_header:
                return key
        return -1


# ===== Automatic Unpacking Script =====
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 unpacker.py <packed_file>")
        sys.exit(1)
    
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    
    unpacker = SimpleUnpacker()
    
    print(f"[*] Analyzing: {sys.argv[1]}")
    print(f"[*] Size: {len(data)} bytes")
    
    # ตรวจสอป UPX
    if b'UPX' in data:
        print("[+] UPX packing detected")
        unpacked = unpacker.unpack_upx(data)
        if unpacked != data:
            with open(sys.argv[1] + '.unpacked', 'wb') as f:
                f.write(unpacked)
            print(f"[+] Unpacked to: {sys.argv[1]}.unpacked")
    
    # ค้นหา embedded PE
    embedded = unpacker.extract_from_dropper(data[512:])  # Skip first 512 bytes
    if embedded:
        print("[+] Embedded PE found!")
        with open(sys.argv[1] + '.embedded', 'wb') as f:
            f.write(embedded)
```

---

## 7. Obfuscation Bypass

### Deobfuscation Techniques

```python
#!/usr/bin/env python3
# deobfuscator.py - Bypass obfuscation

import re
import base64
import binascii
from typing import str

class PowerShellDeobfuscator:
    """ถอดรหัส PowerShell obfuscation"""
    
    def deobfuscate(self, ps_code: str) -> str:
        """ถอดรหัสหลายชั้น"""
        code = ps_code
        
        # 1. ถอด Base64 -EncodedCommand
        code = self._decode_encoded_command(code)
        
        # 2. ถอด string concatenation
        code = self._decode_string_concat(code)
        
        # 3. ถอด char codes
        code = self._decode_char_codes(code)
        
        # 4. ถอด reversed strings
        code = self._decode_reversed(code)
        
        # 5. ถอด replace
        code = self._decode_replace(code)
        
        return code
    
    def _decode_encoded_command(self, code: str) -> str:
        """ถอด -EncodedCommand"""
        pattern = r'-(?:enc|EncodedCommand)\s+([A-Za-z0-9+/=]+)'
        
        def decode(match):
            try:
                b64 = match.group(1)
                # Pad if needed
                b64 += '=' * (4 - len(b64) % 4)
                decoded = base64.b64decode(b64).decode('utf-16-le', errors='ignore')
                return f'# DECODED: {decoded}'
            except:
                return match.group(0)
        
        return re.sub(pattern, decode, code, flags=re.IGNORECASE)
    
    def _decode_string_concat(self, code: str) -> str:
        """ถอด 'he' + 'llo' -> 'hello'"""
        pattern = r"'([^']+)'\s*\+\s*'([^']+)'"
        
        while re.search(pattern, code):
            code = re.sub(pattern, lambda m: f"'{m.group(1)}{m.group(2)}'", code)
        
        return code
    
    def _decode_char_codes(self, code: str) -> str:
        """ถอด [char]0x41 -> 'A'"""
        pattern = r'\[char\](0x[0-9a-f]+|\d+)'
        
        def decode_char(match):
            try:
                if match.group(1).startswith('0x'):
                    char_code = int(match.group(1), 16)
                else:
                    char_code = int(match.group(1))
                return f"'{chr(char_code)}'"
            except:
                return match.group(0)
        
        return re.sub(pattern, decode_char, code, flags=re.IGNORECASE)
    
    def _decode_reversed(self, code: str) -> str:
        """ถอด reversed strings"""
        # ([REVERSE] 'dlrow olleh') -> 'hello world'
        pattern = r"\(\s*'([^']+)'\s*\)\[\s*-1\s*\.\.\.\s*-\s*\(\s*'[^']*'\s*\.Length\s*\)\s*\]"
        
        def decode_reversed(match):
            return f"'{match.group(1)[::-1]}'"
        
        return re.sub(pattern, decode_reversed, code)
    
    def _decode_replace(self, code: str) -> str:
        """ถอด string replace"""
        # 'h3ll0'.Replace('3','e').Replace('0','o') -> 'hello'
        pattern = r"'([^']+)'\.Replace\('(.)', '(.)'\)"
        
        def decode_replace(match):
            return f"'{match.group(1).replace(match.group(2), match.group(3))}'"
        
        changed = True
        while changed:
            new_code = re.sub(pattern, decode_replace, code)
            changed = new_code != code
            code = new_code
        
        return code


class JavaScriptDeobfuscator:
    """ถอดรหัส JavaScript"""
    
    def deobfuscate(self, js_code: str) -> str:
        code = js_code
        
        # Eval base64
        code = self._decode_eval_base64(code)
        
        # String.fromCharCode
        code = self._decode_fromcharcode(code)
        
        return code
    
    def _decode_eval_base64(self, code: str) -> str:
        pattern = r'eval\(atob\(["\']([A-Za-z0-9+/=]+)["\']\)\)'
        
        def decode(match):
            try:
                decoded = base64.b64decode(match.group(1)).decode()
                return f'/* DECODED */ {decoded}'
            except:
                return match.group(0)
        
        return re.sub(pattern, decode, code)
    
    def _decode_fromcharcode(self, code: str) -> str:
        pattern = r'String\.fromCharCode\(([\d,\s]+)\)'
        
        def decode(match):
            try:
                char_codes = [int(c.strip()) for c in match.group(1).split(',')]
                return '"' + ''.join(chr(c) for c in char_codes) + '"'
            except:
                return match.group(0)
        
        return re.sub(pattern, decode, code)


# ตัวอย่าง
if __name__ == "__main__":
    # PowerShell deobfuscation
    ps_deob = PowerShellDeobfuscator()
    
    obfuscated_ps = """('dlrow' + ' ' + 'olleh').replace('olleh','hello')"""
    
    result = ps_deob.deobfuscate(obfuscated_ps)
    print(f"Deobfuscated PS: {result}")
    
    # JS deobfuscation
    js_deob = JavaScriptDeobfuscator()
    
    obfuscated_js = "String.fromCharCode(72, 101, 108, 108, 111)"
    result = js_deob.deobfuscate(obfuscated_js)
    print(f"Deobfuscated JS: {result}")
```

---

## 8. Protocol Reversing

### ถอด Unknown Network Protocols

```python
#!/usr/bin/env python3
# protocol_reverser.py - ถอด custom protocols

import struct
import socket
from typing import Dict, List, Optional

class ProtocolAnalyzer:
    """วิเคราะห์ unknown protocols จาก pcap"""
    
    def analyze_binary_stream(self, data: bytes) -> Dict:
        """วิเคราะห์ binary stream"""
        result = {
            'length': len(data),
            'possible_structures': [],
            'text_regions': [],
            'interesting_bytes': []
        }
        
        # หาบริเวณ ASCII
        text_pattern = []
        for i, byte in enumerate(data):
            if 0x20 <= byte <= 0x7e:
                text_pattern.append((i, chr(byte)))
            else:
                if len(text_pattern) >= 4:
                    text = ''.join(c for _, c in text_pattern)
                    result['text_regions'].append({
                        'offset': text_pattern[0][0],
                        'text': text
                    })
                text_pattern = []
        
        # หาโครงสร้าง (length fields, magic bytes)
        self._find_structures(data, result)
        
        return result
    
    def _find_structures(self, data: bytes, result: Dict):
        """หาโครงสร้าง protocol"""
        # ค้นหา length fields
        for i in range(0, len(data) - 4, 2):
            # Big-endian 16-bit length
            be_len = struct.unpack_from('>H', data, i)[0]
            remaining = len(data) - i - 2
            
            if be_len == remaining or be_len == remaining - 1:
                result['possible_structures'].append({
                    'type': 'length_field_BE',
                    'offset': i,
                    'value': be_len
                })
            
            # Little-endian 32-bit length
            if i + 4 <= len(data):
                le_len = struct.unpack_from('<I', data, i)[0]
                if le_len == len(data) - i - 4:
                    result['possible_structures'].append({
                        'type': 'length_field_LE',
                        'offset': i,
                        'value': le_len
                    })
    
    def create_dissector_template(self, data: bytes, protocol_name: str) -> str:
        """สร้าง Wireshark dissector template"""
        analysis = self.analyze_binary_stream(data)
        
        template = f"""-- Wireshark Lua Dissector for {protocol_name}
local {protocol_name.lower()} = Proto("{protocol_name.lower()}", "{protocol_name} Protocol")

-- Fields
local f = {protocol_name.lower()}.fields
"""
        
        # เพิ่ม fields จาก analysis
        for i, text in enumerate(analysis.get('text_regions', [])[:5]):
            template += f'f.field_{i} = ProtoField.string("{protocol_name.lower()}.field{i}", "Field {i}")\n'
        
        template += f"""
function {protocol_name.lower()}.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "{protocol_name}"
    local subtree = tree:add({protocol_name.lower()}, buffer())
    
    local offset = 0
    -- Add fields here based on analysis
    subtree:add(f.field_0, buffer(offset, 4))
    offset = offset + 4
end

-- Register on port
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(8080, {protocol_name.lower()})
"""
        return template


if __name__ == "__main__":
    # ตัวอย่าง protocol data
    sample_data = bytes([
        0x00, 0x0a,          # length = 10
        0x01,               # type = 1 (request)
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21,  # "Hello!"
        0x00, 0x00          # padding
    ])
    
    analyzer = ProtocolAnalyzer()
    result = analyzer.analyze_binary_stream(sample_data)
    
    print("Protocol Analysis:")
    print(f"  Length: {result['length']} bytes")
    print(f"  Text regions: {result['text_regions']}")
    print(f"  Possible structures: {result['possible_structures']}")
    
    # สร้าง Wireshark dissector
    dissector = analyzer.create_dissector_template(sample_data, "MyProtocol")
    print("\nWireshark Dissector Template:")
    print(dissector)
```

---

## 9. Firmware Analysis

```bash
# ===== Firmware Analysis =====

# 1. ตรวจสอบ firmware
file firmware.bin
binwalk firmware.bin

# 2. แยก firmware (extract)
binwalk -e firmware.bin
binwalk --dd='.*' firmware.bin  # extract everything

# 3. วิเคราะห์ filesystem
ls -la _firmware.bin.extracted/
cd _firmware.bin.extracted/squashfs-root/  # ถ้ามี

# 4. หา credentials hardcoded
grep -r 'password\|passwd\|secret\|key' . --include='*.conf' 2>/dev/null
find . -name 'shadow' -o -name 'passwd' 2>/dev/null

# 5. หา command injection
grep -r 'system(\|exec(\|popen(' . --include='*.c' 2>/dev/null

# 6. จำลอง MIPS binary
qemu-mips-static -L . ./bin/busybox

# 7. เปิด web interface
python3 -m http.server 8080 --directory www/

# 8. ค้นหา debug interfaces
strings firmware.bin | grep -E '(uart|serial|debug|shell|telnet)'
```

---

## 10. CTF RE Challenges

### CTF RE Techniques

```python
#!/usr/bin/env python3
# ctf_re_toolkit.py - เครื่องมือสำหรับ CTF RE challenges

from pwn import *
from z3 import *  # pip install z3-solver
import angr      # pip install angr
import hashlib

# ===== Z3 Constraint Solving =====
def solve_crackme_with_z3():
    """ใช้ Z3 SMT solver แก้โจทย์ crackme"""
    # ตัวอย่าง: crackme ตรวจสอปสหรัส
    # s = b''
    # for i in range(8):
    #     s += bytes([input[i] ^ 0x42 + i])
    # if s == b'\x4f\x4d\x47\x5a\x48\x41\x58\x23': print('Correct!'
    
    solver = Solver()
    
    # สร้าง variables
    inp = [BitVec(f'inp_{i}', 8) for i in range(8)]
    
    # เงื่อนไข: ตัวอักขระ printable
    for char in inp:
        solver.add(char >= 0x20, char <= 0x7e)
    
    # เงื่อนไข: transformation
    target = [0x4f, 0x4d, 0x47, 0x5a, 0x48, 0x41, 0x58, 0x23]
    
    for i, (char, t) in enumerate(zip(inp, target)):
        transformed = (char ^ 0x42) + i
        solver.add((transformed & 0xff) == t)
    
    if solver.check() == sat:
        model = solver.model()
        solution = ''.join(chr(model[c].as_long()) for c in inp)
        return f"Solution: {solution}"
    
    return "No solution found"


# ===== Angr for Symbolic Execution =====
def solve_with_angr(binary_path: str, find_addr: int, avoid_addrs: list):
    """ใช้ Angr symbolic execution"""
    project = angr.Project(binary_path, auto_load_libs=False)
    
    # Initial state
    state = project.factory.entry_state(
        stdin=angr.SimFile('/dev/stdin', content=angr.SimFileStream)
    )
    
    # Simulation manager
    simgr = project.factory.simulation_manager(state)
    
    # Explore
    simgr.explore(
        find=find_addr,
        avoid=avoid_addrs
    )
    
    if simgr.found:
        found_state = simgr.found[0]
        # ดึง input
        stdin_content = found_state.posix.dumps(0)
        return stdin_content.decode('latin-1')
    
    return None


# ===== Common CTF Techniques =====
def xor_bruteforce(ciphertext: bytes) -> list:
    """เดา XOR key"""
    results = []
    
    for key in range(256):
        decrypted = bytes([b ^ key for b in ciphertext])
        # ตรวจสอปว่า printable
        if all(0x20 <= b <= 0x7e for b in decrypted):
            results.append({
                'key': key,
                'plaintext': decrypted.decode('ascii')
            })
    
    return results


def rot13_all(text: str) -> list:
    """ลอง ROT13 ทุกค่า"""
    results = []
    for shift in range(26):
        result = ''
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        results.append({'shift': shift, 'text': result})
    return results


def detect_cipher(data: bytes) -> str:
    """ตรวจสอปว่า cipher อะไร"""
    import math
    from collections import Counter
    
    freq = Counter(data)
    entropy = -sum(
        (c/len(data)) * math.log2(c/len(data))
        for c in freq.values()
    )
    
    clues = []
    
    # Check length
    if len(data) % 16 == 0:
        clues.append("Length multiple of 16 -> possible AES")
    elif len(data) % 8 == 0:
        clues.append("Length multiple of 8 -> possible DES/3DES")
    
    # Check entropy
    if entropy > 7.9:
        clues.append(f"High entropy ({entropy:.2f}) -> well-encrypted or compressed")
    elif entropy > 4:
        clues.append(f"Medium entropy ({entropy:.2f}) -> possible XOR or simple cipher")
    else:
        clues.append(f"Low entropy ({entropy:.2f}) -> encoding or weak cipher")
    
    # Check for common patterns
    if data[:4] == b'PK\x03\x04':
        clues.append("ZIP archive")
    elif data[:2] == b'MZ':
        clues.append("PE executable")
    elif data[:3] == b'BZh':
        clues.append("BZIP2 compressed")
    
    return '\n'.join(clues)


# ตัวอย่าง
if __name__ == "__main__":
    print("[*] CTF RE Toolkit")
    
    # Z3 solver demo
    try:
        result = solve_crackme_with_z3()
        print(f"\nZ3 Solver: {result}")
    except ImportError:
        print("\n[!] z3 not installed: pip install z3-solver")
    
    # XOR bruteforce
    cipher = bytes([0x48 ^ 0x42, 0x65 ^ 0x42, 0x6c ^ 0x42, 0x6c ^ 0x42, 0x6f ^ 0x42])
    results = xor_bruteforce(cipher)
    print(f"\nXOR Brute Force Results:")
    for r in results[:3]:
        print(f"  Key=0x{r['key']:02x}: {r['plaintext']}")
    
    # Cipher detection
    test_data = b'\x00' * 16 + b'\xff' * 16
    analysis = detect_cipher(test_data)
    print(f"\nCipher Analysis:\n{analysis}")
```

---

## สรุป

### RE Tools Arsenal

| เครื่องมือ | หน้าที่ | ระดับ |
|-----------|---------|-------|
| Ghidra | Disassembly + Decompile (Free) | All |
| IDA Pro | Industry standard | Advanced |
| x64dbg | Windows debugger | Intermediate |
| GDB+PEDA | Linux debugger | Intermediate |
| radare2 | CLI disassembler | Advanced |
| pwntools | Exploit dev framework | Advanced |
| Z3 | SMT solver | Expert |
| angr | Symbolic execution | Expert |
| FRIDA | Dynamic instrumentation | Advanced |

### RE Methodology

```
1. Static Analysis First
   - File info, strings, imports, entropy
   
2. Identify Main Logic
   - Find main(), WinMain()
   - Trace execution flow
   
3. Rename + Comment
   - Meaningful names ช่วย RE ได้เร็ว
   
4. Dynamic Analysis
   - Run + observe
   - Set breakpoints at interesting calls
   
5. Patch + Verify
   - NOP anti-debug
   - Patch jumps
```

---

← [Part 68: Malware Analysis](Part-68-Malware-Analysis.md) | [Part 70: Bug Bounty Methodology](Part-70-Bug-Bounty.md) →
