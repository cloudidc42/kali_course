# Part 52: Security Automation

> **หลักสูตร Kali Linux จาก Zero ถึง Professional**  
> Part 52 of 100+ | ระดับ: Professional/World-Class

---

## สารบัญ

1. [Security Automation คืออะไร](#1-intro)
2. [Python Security Scripts](#2-python)
3. [Ansible Security Automation](#3-ansible)
4. [SOAR Platforms](#4-soar)
5. [CI/CD Security (DevSecOps)](#5-devsecops)
6. [Security APIs](#6-apis)
7. [Automated Scanning Pipeline](#7-pipeline)
8. [แบบฝึกหัด Lab](#8-lab)

---

## 1. Security Automation คืออะไร

### 1.1 วัตถุประสงค์

```
Security Automation ช่วย:
  - เร็วขึ้น (automated response แทน manual)
  - ลดข้อผิดพลาดของมนุษย์
  - Scale (ตรวจสอบหลายสิ่งพร้อมกัน)
  - Consistency (ทำเหมือนกันทุกครั้ง)
  - Log/Audit trail

Areas:
  - Vulnerability scanning
  - Incident response
  - Compliance checking
  - Threat hunting queries
  - Patch management
  - Log collection/analysis
```

---

## 2. Python Security Scripts

### 2.1 Network Scanner

```python
#!/usr/bin/env python3
# security_scanner.py - comprehensive security scanner

import socket
import subprocess
import ipaddress
import concurrent.futures
import json
from datetime import datetime

class SecurityScanner:
    def __init__(self, targets, max_workers=50):
        self.targets = targets
        self.max_workers = max_workers
        self.results = {}
    
    def ping_host(self, host):
        """ICMP ping"""
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', str(host)],
            capture_output=True, text=True
        )
        return result.returncode == 0
    
    def scan_port(self, host, port, timeout=1):
        """TCP port scan"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((str(host), port))
                return result == 0
        except:
            return False
    
    def scan_host(self, host):
        """Scan single host"""
        host_str = str(host)
        self.results[host_str] = {'alive': False, 'open_ports': []}
        
        # Ping check
        if not self.ping_host(host_str):
            return
        
        self.results[host_str]['alive'] = True
        
        # Port scan
        common_ports = [21,22,23,25,53,80,110,135,139,143,443,445,
                       993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            port_futures = {executor.submit(self.scan_port, host_str, p): p 
                          for p in common_ports}
            for future in concurrent.futures.as_completed(port_futures):
                port = port_futures[future]
                if future.result():
                    self.results[host_str]['open_ports'].append(port)
        
        self.results[host_str]['open_ports'].sort()
        return self.results[host_str]
    
    def get_banner(self, host, port):
        """Grab service banner"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((host, port))
                banner = s.recv(1024).decode(errors='replace').strip()[:100]
                return banner
        except:
            return ''
    
    def run(self):
        print(f"[*] Scanning {len(self.targets)} targets...")
        start = datetime.now()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_host, t): t for t in self.targets}
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                result = self.results.get(str(host), {})
                if result.get('alive'):
                    ports = result.get('open_ports', [])
                    print(f"  [+] {host}: {ports}")
        
        elapsed = (datetime.now() - start).seconds
        print(f"\n[*] Scan complete in {elapsed}s")
        return self.results
    
    def export(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Results saved: {filename}")

# Run
if __name__ == '__main__':
    # Scan subnet
    network = ipaddress.ip_network('192.168.1.0/24', strict=False)
    targets = list(network.hosts())
    
    scanner = SecurityScanner(targets[:20])  # limit for demo
    results = scanner.run()
    scanner.export('/tmp/scan_results.json')
```

### 2.2 Automated Vulnerability Checker

```python
#!/usr/bin/env python3
# vuln_checker.py - ตรวจสอบช่องโหว่อัตโนมัติ

import requests
import json
import subprocess
from datetime import datetime

class VulnerabilityChecker:
    def __init__(self, target):
        self.target = target
        self.findings = []
    
    def check_http_security_headers(self, url):
        """Check for missing security headers"""
        print(f"[*] Checking security headers: {url}")
        required_headers = {
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'Strict-Transport-Security': 'Forces HTTPS',
            'Content-Security-Policy': 'Prevents XSS',
            'X-XSS-Protection': 'XSS protection',
            'Referrer-Policy': 'Controls referrer info'
        }
        
        try:
            resp = requests.get(url, timeout=10, verify=False, 
                              allow_redirects=True)
            
            for header, desc in required_headers.items():
                if header not in resp.headers:
                    self.findings.append({
                        'severity': 'Low',
                        'title': f'Missing {header}',
                        'description': f'{desc}',
                        'url': url
                    })
                    print(f"  [-] Missing: {header}")
                else:
                    print(f"  [+] Found: {header}")
        except Exception as e:
            print(f"  [!] Error: {e}")
    
    def check_ssl_tls(self, host, port=443):
        """Check SSL/TLS configuration"""
        print(f"[*] Checking SSL/TLS: {host}:{port}")
        
        try:
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{host}:{port}',
                 '-tls1', '/dev/null'],  # test TLS 1.0
                capture_output=True, text=True, timeout=10
            )
            if 'CONNECTED' in result.stderr:
                self.findings.append({
                    'severity': 'High',
                    'title': 'TLS 1.0 Supported',
                    'description': 'TLS 1.0 is deprecated and vulnerable',
                    'host': f'{host}:{port}'
                })
                print(f"  [!] TLS 1.0 is supported (insecure)")
        except:
            pass
        
        # Check certificate expiry
        try:
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{host}:{port}'],
                capture_output=True, text=True, timeout=10,
                input=''
            )
            if 'notAfter' in result.stdout or 'notAfter' in result.stderr:
                output = result.stdout + result.stderr
                for line in output.split('\n'):
                    if 'notAfter' in line:
                        print(f"  [+] Cert expiry: {line.strip()}")
        except:
            pass
    
    def check_default_credentials(self, url, service):
        """Test default credentials"""
        print(f"[*] Checking default creds: {service}")
        
        defaults = {
            'admin': ['admin', 'password', '123456', 'admin123', 'root'],
            'root': ['root', 'toor', 'password', ''],
            'administrator': ['administrator', 'password', 'Password1'],
        }
        
        found = []
        for username, passwords in defaults.items():
            for password in passwords:
                try:
                    resp = requests.post(
                        url,
                        data={'username': username, 'password': password},
                        timeout=5, verify=False, allow_redirects=False
                    )
                    # ตรวจสอบ redirect หรือ success response
                    if resp.status_code in [200, 302] and 'logout' in resp.text.lower():
                        found.append((username, password))
                        self.findings.append({
                            'severity': 'Critical',
                            'title': f'Default Credentials Work: {username}/{password}',
                            'url': url
                        })
                        print(f"  [!!!] Default creds work: {username}:{password}")
                except:
                    pass
        
        return found
    
    def generate_report(self):
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'severity_summary': {
                'Critical': sum(1 for f in self.findings if f.get('severity') == 'Critical'),
                'High': sum(1 for f in self.findings if f.get('severity') == 'High'),
                'Medium': sum(1 for f in self.findings if f.get('severity') == 'Medium'),
                'Low': sum(1 for f in self.findings if f.get('severity') == 'Low'),
            },
            'findings': self.findings
        }
        
        with open(f'/tmp/vuln_report_{self.target}.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n=== Vulnerability Report ===")
        print(f"Target: {self.target}")
        print(f"Total: {len(self.findings)} findings")
        for sev, count in report['severity_summary'].items():
            if count > 0:
                print(f"  {sev}: {count}")

# Run
if __name__ == '__main__':
    checker = VulnerabilityChecker('192.168.1.1')
    checker.check_http_security_headers('http://192.168.1.1/')
    checker.check_ssl_tls('192.168.1.1')
    checker.generate_report()
```

---

## 3. Ansible Security Automation

### 3.1 Ansible สำหรับ Security Hardening

```yaml
# security_hardening.yml - Ansible playbook
---
- name: Linux Security Hardening
  hosts: all
  become: yes
  
  tasks:
    - name: Update all packages
      apt:
        upgrade: dist
        update_cache: yes
      when: ansible_os_family == 'Debian'
    
    - name: Disable root SSH login
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
        state: present
      notify: Restart SSH
    
    - name: Disable password authentication
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PasswordAuthentication'
        line: 'PasswordAuthentication no'
      notify: Restart SSH
    
    - name: Set SSH MaxAuthTries
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^MaxAuthTries'
        line: 'MaxAuthTries 3'
      notify: Restart SSH
    
    - name: Configure firewall (UFW)
      ufw:
        rule: allow
        port: '22'
        proto: tcp
    
    - name: Enable UFW
      ufw:
        state: enabled
        policy: deny
    
    - name: Set password policy
      lineinfile:
        path: /etc/login.defs
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      with_items:
        - { regexp: '^PASS_MAX_DAYS', line: 'PASS_MAX_DAYS 90' }
        - { regexp: '^PASS_MIN_DAYS', line: 'PASS_MIN_DAYS 1' }
        - { regexp: '^PASS_MIN_LEN',  line: 'PASS_MIN_LEN 12' }
    
    - name: Install fail2ban
      apt:
        name: fail2ban
        state: present
    
    - name: Configure fail2ban
      template:
        src: jail.local.j2
        dest: /etc/fail2ban/jail.local
      notify: Restart fail2ban
    
    - name: Disable unused services
      service:
        name: "{{ item }}"
        enabled: no
        state: stopped
      with_items:
        - telnet
        - rsh
        - rlogin
      ignore_errors: yes
    
    - name: Set kernel security parameters (sysctl)
      sysctl:
        name: "{{ item.name }}"
        value: "{{ item.value }}"
        state: present
        sysctl_set: yes
      with_items:
        - { name: 'net.ipv4.conf.all.rp_filter', value: '1' }
        - { name: 'net.ipv4.conf.default.rp_filter', value: '1' }
        - { name: 'net.ipv4.icmp_echo_ignore_broadcasts', value: '1' }
        - { name: 'net.ipv4.conf.all.accept_redirects', value: '0' }
        - { name: 'kernel.randomize_va_space', value: '2' }
        - { name: 'fs.suid_dumpable', value: '0' }
    
    - name: Remove SUID bit from dangerous commands
      file:
        path: "{{ item }}"
        mode: '0755'
      with_items:
        - /usr/bin/at
        - /bin/mount
        - /bin/umount
      ignore_errors: yes
  
  handlers:
    - name: Restart SSH
      service:
        name: sshd
        state: restarted
    
    - name: Restart fail2ban
      service:
        name: fail2ban
        state: restarted
```

```bash
# รัน playbook
ansible-playbook -i inventory.ini security_hardening.yml --check  # dry run
ansible-playbook -i inventory.ini security_hardening.yml

# inventory.ini
cat > /tmp/inventory.ini << 'EOF'
[servers]
192.168.1.10 ansible_user=admin ansible_ssh_private_key_file=~/.ssh/id_rsa
192.168.1.11 ansible_user=admin

[web_servers]
192.168.1.20
192.168.1.21

[all:vars]
ansible_python_interpreter=/usr/bin/python3
EOF
```

---

## 4. SOAR Platforms

### 4.1 TheHive + Cortex

```bash
# TheHive - Security Incident Response Platform
# Cortex - Observable Analysis

docker-compose up -d  # run with docker

# TheHive Python API
pip3 install thehive4py

python3 << 'EOF'
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseObservable

api = TheHiveApi('http://localhost:9000', 'YOUR_API_KEY')

# สร้าง case ใหม่
 case = Case(
    title='Ransomware Incident 2024-01-15',
    description='Detected ransomware activity on WS01',
    severity=3,  # High
    tags=['ransomware', 'incident', 'windows']
)

response = api.create_case(case)
if response.status_code == 201:
    case_id = response.json()['id']
    print(f"Case created: {case_id}")
    
    # เพิ่ม observables
    observables = [
        CaseObservable(
            dataType='ip',
            data=['185.220.101.45'],
            tags=['c2', 'malicious']
        ),
        CaseObservable(
            dataType='hash',
            data=['5f4dcc3b5aa765d61d8327deb882cf99'],
            tags=['malware', 'ransomware']
        )
    ]
    
    for obs in observables:
        api.create_case_observable(case_id, obs)
    
    print(f"Added {len(observables)} observables")
EOF
```

### 4.2 Shuffle SOAR

```python
#!/usr/bin/env python3
# shuffle_automation.py - Shuffle SOAR API

import requests
import json

SHUFFLE_URL = 'http://localhost:3001'
API_KEY = 'your_api_key'

def trigger_workflow(workflow_id, execution_argument=''):
    """Trigger Shuffle workflow"""
    url = f'{SHUFFLE_URL}/api/v1/workflows/{workflow_id}/execute'
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'execution_argument': execution_argument
    }
    
    resp = requests.post(url, json=payload, headers=headers)
    return resp.json()

# Auto-response workflow เมื่อพบ malware
def respond_to_malware_alert(alert_data):
    steps = [
        'isolate_host',    # Network isolation
        'take_memory_dump', # Memory forensics
        'block_c2_ip',     # Block C2 at firewall
        'notify_team',     # Alert security team
        'create_ticket'    # Create incident ticket
    ]
    
    print(f"[*] Auto-responding to: {alert_data.get('title', 'Unknown Alert')}")
    
    for step in steps:
        print(f"  [>] Executing: {step}...")
        result = trigger_workflow(
            workflow_id=f'workflow_{step}',
            execution_argument=json.dumps(alert_data)
        )
        print(f"  [+] {step}: {result.get('status', 'completed')}")

# Test
respond_to_malware_alert({
    'title': 'Ransomware Detected',
    'host': 'WS01',
    'severity': 'Critical',
    'iocs': {
        'ips': ['185.220.101.45'],
        'hashes': ['abc123...'],
        'domains': ['malware.evil.com']
    }
})
```

---

## 5. CI/CD Security (DevSecOps)

### 5.1 GitHub Actions Security Pipeline

```yaml
# .github/workflows/security.yml
name: Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  sast:
    name: Static Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Bandit (Python SAST)
        run: |
          pip install bandit
          bandit -r . -f json -o bandit_results.json || true
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: auto
      
      - name: Upload SAST results
        uses: actions/upload-artifact@v3
        with:
          name: sast-results
          path: bandit_results.json
  
  sca:
    name: Dependency Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Safety Check (Python deps)
        run: |
          pip install safety
          safety check --json --output safety_results.json || true
      
      - name: npm audit
        run: |
          npm audit --json > npm_audit.json || true
        continue-on-error: true
  
  container_scan:
    name: Container Security
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker image
        run: docker build -t app:test .
      
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'app:test'
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL,HIGH'
  
  secret_scan:
    name: Secret Detection
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: GitLeaks scan
        uses: gitleaks/gitleaks-action@v2
```

### 5.2 SAST Tools

```bash
# Bandit - Python SAST
pip3 install bandit
bandit -r /path/to/code/ -f json -o results.json
bandit -r /path/to/code/ -l  # show low severity too

# Semgrep - multi-language SAST
pip3 install semgrep
semgrep --config auto /path/to/code/
semgrep --config p/owasp-top-ten /path/to/code/

# Flake8 + security plugins (Python)
pip3 install flake8 flake8-bandit flake8-bugbear
flake8 /path/to/code/

# SpotBugs - Java SAST
# mvn spotbugs:check

# Brakeman - Ruby on Rails
gem install brakeman
brakeman /rails/app/

# npm audit - Node.js dependencies
npm audit
npm audit --audit-level critical
npm audit fix

# Trivy - container/filesystem scanning
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
sudo apt install trivy -y
trivy image nginx:latest
trivy fs /path/to/code/
trivy repo https://github.com/org/repo

# OWASP Dependency-Check
docker run --rm \
  -v $(pwd):/src \
  owasp/dependency-check \
  --scan /src \
  --format HTML \
  --out /src/dependency-check-report
```

---

## 6. Security APIs

### 6.1 VirusTotal API

```python
#!/usr/bin/env python3
# virustotal_api.py

import requests
import hashlib
import json
import time

VT_API_KEY = 'YOUR_API_KEY'
VT_BASE_URL = 'https://www.virustotal.com/api/v3'

headers = {'x-apikey': VT_API_KEY}

def get_file_report(file_hash):
    """Get VT report for file hash"""
    resp = requests.get(f'{VT_BASE_URL}/files/{file_hash}', headers=headers)
    if resp.status_code == 200:
        data = resp.json()['data']['attributes']
        return {
            'hash': file_hash,
            'name': data.get('meaningful_name', 'Unknown'),
            'type': data.get('type_description', ''),
            'size': data.get('size', 0),
            'malicious': data['last_analysis_stats']['malicious'],
            'suspicious': data['last_analysis_stats']['suspicious'],
            'total_engines': sum(data['last_analysis_stats'].values()),
            'tags': data.get('tags', []),
            'family': data.get('popular_threat_classification', {}).get('suggested_threat_label', ''),
        }
    elif resp.status_code == 404:
        return None
    else:
        raise Exception(f"VT API error: {resp.status_code}")

def scan_file(filepath):
    """Upload and scan file"""
    with open(filepath, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Check if already in VT
    result = get_file_report(file_hash)
    if result:
        return result
    
    # Upload new file
    with open(filepath, 'rb') as f:
        resp = requests.post(
            f'{VT_BASE_URL}/files',
            headers=headers,
            files={'file': f}
        )
    
    if resp.status_code == 200:
        analysis_id = resp.json()['data']['id']
        print(f"[*] File queued for analysis: {analysis_id}")
        
        # Wait for results
        for i in range(12):  # wait up to 60 seconds
            time.sleep(5)
            analysis_resp = requests.get(
                f'{VT_BASE_URL}/analyses/{analysis_id}',
                headers=headers
            )
            status = analysis_resp.json()['data']['attributes']['status']
            if status == 'completed':
                return get_file_report(file_hash)
            print(f"[*] Status: {status} (attempt {i+1}/12)")
    
    return None

def get_ip_report(ip):
    """Get VT report for IP"""
    resp = requests.get(f'{VT_BASE_URL}/ip_addresses/{ip}', headers=headers)
    if resp.status_code == 200:
        data = resp.json()['data']['attributes']
        return {
            'ip': ip,
            'country': data.get('country', ''),
            'asn': data.get('asn', 0),
            'malicious': data['last_analysis_stats']['malicious'],
            'total': sum(data['last_analysis_stats'].values()),
        }
    return None

# Demo
hash_to_check = '5f4dcc3b5aa765d61d8327deb882cf99'  # example
result = get_file_report(hash_to_check)
if result:
    print(json.dumps(result, indent=2))
else:
    print("Not in VirusTotal database")
```

### 6.2 Shodan API

```python
#!/usr/bin/env python3
# shodan_recon.py

import shodan
import json

SHODAN_API_KEY = 'YOUR_SHODAN_API_KEY'
api = shodan.Shodan(SHODAN_API_KEY)

def search_vulnerabilities(query, limit=50):
    """Search Shodan for vulnerable services"""
    try:
        results = api.search(query, limit=limit)
        print(f"Found: {results['total']} results")
        
        for match in results['matches']:
            print(f"\n[+] {match['ip_str']}:{match.get('port', 0)}")
            print(f"    Country: {match.get('location', {}).get('country_name', 'Unknown')}")
            print(f"    Org: {match.get('org', 'Unknown')}")
            print(f"    OS: {match.get('os', 'Unknown')}")
            print(f"    Banner: {match.get('data', '')[:100]}")
            
            if match.get('vulns'):
                print(f"    Vulnerabilities:")
                for vuln in match['vulns'][:5]:
                    print(f"      {vuln}")
    
    except shodan.APIError as e:
        print(f"Error: {e}")

def lookup_host(ip):
    """Lookup specific IP"""
    try:
        host = api.host(ip)
        print(f"IP: {host['ip_str']}")
        print(f"Organization: {host.get('org', 'N/A')}")
        print(f"OS: {host.get('os', 'N/A')}")
        print(f"Country: {host.get('country_name', 'N/A')}")
        print(f"Open Ports: {host.get('ports', [])}")
        
        if host.get('vulns'):
            print(f"\nVulnerabilities:")
            for vuln, info in host['vulns'].items():
                print(f"  {vuln}: CVSS {info.get('cvss', 'N/A')}")
    
    except shodan.APIError as e:
        print(f"Error: {e}")

# Searches:
# search_vulnerabilities('vuln:CVE-2021-44228')  # Log4Shell
# search_vulnerabilities('product:"Apache" port:443 country:TH')
# lookup_host('8.8.8.8')
```

---

## 7. Automated Scanning Pipeline

### 7.1 Full Pipeline

```python
#!/usr/bin/env python3
# security_pipeline.py - automated security assessment

import subprocess
import json
import os
from datetime import datetime
from pathlib import Path

class SecurityPipeline:
    def __init__(self, target, output_dir='/tmp/security_scan'):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {}
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def run_nmap(self):
        """Port scan with nmap"""
        print("[1] Running Nmap scan...")
        output_file = self.output_dir / 'nmap_scan.xml'
        
        cmd = ['nmap', '-sV', '-sC', '-O', '--open', '-oX', 
               str(output_file), self.target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        self.results['nmap'] = {
            'status': 'completed' if result.returncode == 0 else 'failed',
            'output_file': str(output_file)
        }
        print(f"   Done. Output: {output_file}")
    
    def run_nikto(self):
        """Web vulnerability scan"""
        print("[2] Running Nikto scan...")
        output_file = self.output_dir / 'nikto_scan.txt'
        
        cmd = ['nikto', '-h', f'http://{self.target}', '-o', 
               str(output_file), '-Format', 'txt']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        self.results['nikto'] = {
            'status': 'completed',
            'output_file': str(output_file)
        }
        print(f"   Done. Output: {output_file}")
    
    def run_gobuster(self, wordlist='/usr/share/wordlists/dirb/common.txt'):
        """Directory enumeration"""
        print("[3] Running GoBuster...")
        output_file = self.output_dir / 'gobuster.txt'
        
        cmd = ['gobuster', 'dir', '-u', f'http://{self.target}',
               '-w', wordlist, '-o', str(output_file), '-q']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        self.results['gobuster'] = {
            'status': 'completed',
            'output_file': str(output_file)
        }
        print(f"   Done. Output: {output_file}")
    
    def run_ssl_check(self):
        """SSL/TLS check"""
        print("[4] Running SSL check...")
        output_file = self.output_dir / 'ssl_check.txt'
        
        cmd = ['sslscan', self.target]
        with open(output_file, 'w') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=60)
        
        self.results['ssl'] = {
            'status': 'completed',
            'output_file': str(output_file)
        }
        print(f"   Done. Output: {output_file}")
    
    def generate_summary(self):
        """Generate final report"""
        summary = {
            'target': self.target,
            'scan_time': self.timestamp,
            'tools_run': list(self.results.keys()),
            'results': self.results
        }
        
        summary_file = self.output_dir / f'summary_{self.timestamp}.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n=== Scan Complete ===")
        print(f"Target: {self.target}")
        print(f"Output directory: {self.output_dir}")
        print(f"Summary: {summary_file}")
        
        return str(summary_file)
    
    def run_all(self):
        """Run full pipeline"""
        print(f"[*] Starting security assessment: {self.target}")
        print(f"[*] Output: {self.output_dir}")
        
        self.run_nmap()
        self.run_nikto()
        self.run_gobuster()
        # self.run_ssl_check()  # requires sslscan
        
        return self.generate_summary()

# Run
if __name__ == '__main__':
    # แจ้ง: ใช้กับ authorized targets เท่านั้น
    pipeline = SecurityPipeline('192.168.1.1')
    # pipeline.run_all()
    print("[*] Pipeline ready - uncomment run_all() to execute")
```

---

## 8. แบบฝึกหัด Lab

### Lab: สร้าง Security Dashboard

```python
#!/usr/bin/env python3
# security_dashboard.py - real-time security monitoring

import json
import time
import random
from datetime import datetime
from collections import Counter

class SecurityDashboard:
    def __init__(self):
        self.alerts = []
        self.metrics = {
            'failed_logins': 0,
            'blocked_ips': set(),
            'malware_detected': 0,
            'vulnerabilities': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }
    
    def ingest_log(self, log_line):
        """Process single log line"""
        # Parse JSON log
        try:
            event = json.loads(log_line)
        except:
            return
        
        event_type = event.get('type', '')
        
        if event_type == 'failed_login':
            self.metrics['failed_logins'] += 1
            ip = event.get('source_ip', '')
            
            # Auto-block after 5 failures
            if self.metrics['failed_logins'] % 5 == 0 and ip:
                self.metrics['blocked_ips'].add(ip)
                self.create_alert('HIGH', f'IP {ip} blocked - 5 failed logins')
        
        elif event_type == 'malware_detected':
            self.metrics['malware_detected'] += 1
            self.create_alert('CRITICAL', 
                f"Malware detected: {event.get('malware_name', 'Unknown')} on {event.get('host', '?')}")
        
        elif event_type == 'vulnerability_found':
            sev = event.get('severity', 'low').lower()
            if sev in self.metrics['vulnerabilities']:
                self.metrics['vulnerabilities'][sev] += 1
    
    def create_alert(self, severity, message):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'message': message
        }
        self.alerts.append(alert)
        print(f"[ALERT-{severity}] {message}")
        return alert
    
    def display_dashboard(self):
        print("\n" + "="*60)
        print(f"SECURITY DASHBOARD - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        print(f"Failed Logins:      {self.metrics['failed_logins']}")
        print(f"Blocked IPs:        {len(self.metrics['blocked_ips'])}")
        print(f"Malware Detected:   {self.metrics['malware_detected']}")
        print(f"\nVulnerabilities:")
        for sev, count in self.metrics['vulnerabilities'].items():
            bar = '#' * count
            print(f"  {sev.upper():10} {count:4} {bar}")
        print(f"\nRecent Alerts:")
        for alert in self.alerts[-5:]:
            print(f"  [{alert['severity']}] {alert['message']}")

# Simulate
dashboard = SecurityDashboard()

test_events = [
    '{"type":"failed_login","source_ip":"192.168.1.50","user":"admin"}',
    '{"type":"failed_login","source_ip":"192.168.1.50","user":"root"}',
    '{"type":"failed_login","source_ip":"192.168.1.50"}',
    '{"type":"failed_login","source_ip":"192.168.1.50"}',
    '{"type":"failed_login","source_ip":"192.168.1.50"}',
    '{"type":"malware_detected","malware_name":"Ransomware.WannaCry","host":"WS01"}',
    '{"type":"vulnerability_found","severity":"critical","vuln":"CVE-2021-44228"}',
    '{"type":"vulnerability_found","severity":"high","vuln":"CVE-2023-1234"}',
]

for event in test_events:
    dashboard.ingest_log(event)

dashboard.display_dashboard()
```

### สรุป Security Automation

```
เครื่องมือ Security Automation:

┌────────────────────────────────────────────────────────────┐
│  Area           Tool                   Language      │
├────────────────────────────────────────────────────────────┤
│  Scanner        Nmap, Nessus           Python        │
│  SAST            Bandit, Semgrep        CI/CD         │
│  Container       Trivy, Grype           Docker        │
│  Hardening       Ansible                YAML          │
│  SOAR            TheHive, Shuffle       REST API      │
│  Threat Intel    MISP, VT API           Python        │
│  Log Analysis    ELK, Splunk            KQL/SPL       │
│  Network         Zeek, Suricata         Custom rules  │
└────────────────────────────────────────────────────────────┘
```

---

**[← Part 51: Threat Hunting](Part-51-Threat-Hunting.md)** | **[→ Part 53: Exploit Development](Part-53-Exploit-Development.md)**
