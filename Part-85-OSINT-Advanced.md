# Part 85: OSINT Advanced

> **หลักสูตร Kali Linux จากระดับพื้นฐานถึงระดับโลก**  
> ← [Part 84: Digital Forensics](Part-84-Digital-Forensics.md) | [Part 86: Red Team Operations](Part-86-Red-Team-Operations.md) →

---

## สารบัญ

1. [OSINT Framework และเครื่องมือ](#1-osint-framework-และเครื่องมือ)
2. [People OSINT](#2-people-osint)
3. [Domain และ Infrastructure OSINT](#3-domain-และ-infrastructure-osint)
4. [Social Media Intelligence](#4-social-media-intelligence)
5. [Dark Web OSINT](#5-dark-web-osint)
6. [Geolocation และ Image OSINT](#6-geolocation-และ-image-osint)
7. [Corporate OSINT](#7-corporate-osint)
8. [Automated OSINT Pipelines](#8-automated-osint-pipelines)
9. [OSINT สำหรับ Threat Intelligence](#9-osint-สำหรับ-threat-intelligence)
10. [OPSEC ในการทำ OSINT](#10-opsec-ในการทำ-osint)

---

## 1. OSINT Framework และเครื่องมือ

### 1.1 เครื่องมือ OSINT สำคัญ

```bash
# ติดตั้งเครื่องมือ OSINT บน Kali
sudo apt install -y \
    maltego \
    recon-ng \
    theharvester \
    spiderfoot \
    amass \
    sherlock

pip3 install \
    shodan \
    censys \
    tweepy \
    instaloader \
    linkedin-api

# Recon-ng — frameworkสำหรับ OSINT
recon-ng
# ใน recon-ng:
workspaces create target_corp
modules search
modules load recon/domains-hosts/hackertarget
options set SOURCE example.com
run
```

### 1.2 TheHarvester

```bash
# เก็บ email, subdomain, IP จากแหล่งประจำที่สาธารณะ
theharvester -d example.com -b all -f results.html

# เลือกแหล่งข้อมูล
theharvester -d example.com -b google -l 500
theharvester -d example.com -b bing,google,yahoo
theharvester -d example.com -b linkedin
theharvester -d example.com -b shodan

# ผลลัพธ์ ได้แก่:
# [*] Emails:
# hr@example.com
# admin@example.com
# [*] Hosts:
# mail.example.com: 192.168.1.10
# vpn.example.com: 192.168.1.11
```

### 1.3 Maltego

```
Maltego — เครื่องมือ OSINT แบบ visual graph

การใช้งาน:
1. เปิด Maltego
2. สร้าง New Graph
3. ลากจุดเริ่มต้น (Domain, Person, Email)
4. Run Transforms:
   - To DNS Name     — หา subdomains
   - To Email        — หา email addresses
   - To IP Address   — resolve DNS
   - To MX Record    — หา mail servers
   - To Website      — เชื่อมโยง websites
   - Person to Accounts — หา social accounts

Transforms ที่มีประโยชน์:
- Shodan transforms — vulnerable devices
- VirusTotal transforms — malicious domains
- Have I Been Pwned transforms — leaked credentials
- Censys transforms — certificate info
```

---

## 2. People OSINT

### 2.1 Username Enumeration

```bash
# Sherlock — หา username บน social media
sherlock username123
sherlock username123 --timeout 10 --output results.txt

# ตรวจสอบหลาย usernames
sherlock alice bob charlie --output /tmp/results/

# WhatsMyName — comprehensive username search
git clone https://github.com/WebBreacher/WhatsMyName
cd WhatsMyName
python3 whatsmyname.py -u username123 -f csv -o results.csv
```

```python
#!/usr/bin/env python3
# people_osint.py — เก็บข้อมูลบุคคล

import requests
import re
import json
from concurrent.futures import ThreadPoolExecutor

class PeopleOSINT:
    SOCIAL_PLATFORMS = {
        'twitter': 'https://twitter.com/{}',
        'instagram': 'https://www.instagram.com/{}/',
        'github': 'https://github.com/{}',
        'reddit': 'https://www.reddit.com/user/{}',
        'linkedin': 'https://www.linkedin.com/in/{}',
        'facebook': 'https://www.facebook.com/{}',
        'tiktok': 'https://www.tiktok.com/@{}',
        'youtube': 'https://www.youtube.com/@{}',
        'twitch': 'https://www.twitch.tv/{}',
        'pinterest': 'https://www.pinterest.com/{}/',
        'medium': 'https://medium.com/@{}',
        'dev.to': 'https://dev.to/{}',
        'keybase': 'https://keybase.io/{}',
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; OSINT Research)'
        })
    
    def check_username(self, platform, url):
        try:
            r = self.session.get(url, timeout=10, allow_redirects=True)
            if r.status_code == 200:
                return True, url
        except:
            pass
        return False, url
    
    def search_username(self, username):
        print(f"[*] Searching for username: {username}")
        results = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.check_username, platform, url.format(username)): platform
                for platform, url in self.SOCIAL_PLATFORMS.items()
            }
            
            for future, platform in futures.items():
                found, url = future.result()
                if found:
                    results.append({'platform': platform, 'url': url})
                    print(f"  [+] Found on {platform}: {url}")
        
        return results
    
    def search_email(self, email):
        """ค้นหาข้อมูลจาก email"""
        results = {}
        
        # Gravatar
        import hashlib
        email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/{email_hash}.json"
        r = requests.get(gravatar_url, timeout=10)
        if r.status_code == 200:
            results['gravatar'] = r.json()
        
        # Hunter.io API (email verification)
        hunter_url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key=YOUR_API_KEY"
        # results['hunter'] = requests.get(hunter_url).json()
        
        return results
    
    def extract_person_info(self, github_username):
        """ดึงข้อมูลจาก GitHub profile"""
        api_url = f"https://api.github.com/users/{github_username}"
        r = requests.get(api_url, timeout=10)
        
        if r.status_code == 200:
            data = r.json()
            return {
                'name': data.get('name'),
                'email': data.get('email'),
                'bio': data.get('bio'),
                'location': data.get('location'),
                'company': data.get('company'),
                'public_repos': data.get('public_repos'),
                'followers': data.get('followers'),
                'created_at': data.get('created_at'),
                'blog': data.get('blog'),
            }
        return None
    
    def find_email_from_github(self, github_username):
        """ค้นหา email จาก Git commits"""
        emails = set()
        
        # ดึง repos
        repos_url = f"https://api.github.com/users/{github_username}/repos"
        r = requests.get(repos_url, timeout=10)
        
        if r.status_code != 200:
            return emails
        
        repos = r.json()[:5]  # ตรวจสอบ 5 repos แรก
        
        for repo in repos:
            commits_url = f"https://api.github.com/repos/{github_username}/{repo['name']}/commits"
            r = requests.get(commits_url, timeout=10)
            
            if r.status_code != 200:
                continue
            
            for commit in r.json()[:10]:  # 10 commitsแรก
                author = commit.get('commit', {}).get('author', {})
                email = author.get('email', '')
                if email and not email.endswith('@users.noreply.github.com'):
                    emails.add(email)
        
        return emails

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <username>")
        sys.exit(1)
    
    osint = PeopleOSINT()
    results = osint.search_username(sys.argv[1])
    print(f"\n[*] Found on {len(results)} platforms")
    
    github_info = osint.extract_person_info(sys.argv[1])
    if github_info:
        print(f"\n[*] GitHub profile:")
        for k, v in github_info.items():
            if v:
                print(f"  {k}: {v}")
        
        emails = osint.find_email_from_github(sys.argv[1])
        if emails:
            print(f"\n[!] Emails from commits: {emails}")
```

---

## 3. Domain และ Infrastructure OSINT

### 3.1 DNS และ Certificate Intelligence

```bash
# Amass — subdomain enumeration
amass enum -d example.com
amass enum -d example.com -passive  # passive only
amass enum -d example.com -brute -w /usr/share/wordlists/amass/all.txt

# Certificate Transparency Logs
curl https://crt.sh/?q=%.example.com&output=json | jq '.[].name_value'

# Subfinder
subfinder -d example.com -all -o subdomains.txt

# DNSRecon
dnsrecon -d example.com -t axfr    # zone transfer
dnsrecon -d example.com -t std     # standard
dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsmap.txt  # brute

# ดู historical DNS ผ่าน SecurityTrails API
curl -s "https://api.securitytrails.com/v1/domain/example.com" \
    -H "apikey: YOUR_API_KEY" | jq '.current_dns'
```

```python
#!/usr/bin/env python3
# domain_osint.py — เก็บข้อมูล domain

import dns.resolver
import requests
import json
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class DomainOSINT:
    def __init__(self, domain):
        self.domain = domain
        self.results = {}
    
    def dns_records(self):
        """เก็บ DNS records"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV']
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
        
        self.results['dns'] = records
        return records
    
    def whois_lookup(self):
        """ดึงข้อมูล WHOIS"""
        import subprocess
        result = subprocess.run(['whois', self.domain],
                               capture_output=True, text=True)
        
        # Parse key fields
        info = {}
        patterns = {
            'registrar': re.compile(r'Registrar:\s*(.+)', re.I),
            'created': re.compile(r'Creation Date:\s*(.+)', re.I),
            'expires': re.compile(r'Registry Expiry Date:\s*(.+)', re.I),
            'registrant': re.compile(r'Registrant Organization:\s*(.+)', re.I),
            'name_servers': re.compile(r'Name Server:\s*(.+)', re.I),
        }
        
        import re
        for field, pattern in patterns.items():
            matches = pattern.findall(result.stdout)
            if matches:
                info[field] = matches[0].strip() if len(matches) == 1 else [m.strip() for m in matches]
        
        self.results['whois'] = info
        return info
    
    def certificate_search(self):
        """Certificate Transparency search"""
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            r = requests.get(url, timeout=30)
            certs = r.json()
            
            # ดึงชื่อ uniqu่
            subdomains = set()
            for cert in certs:
                names = cert.get('name_value', '')
                for name in names.split('\n'):
                    name = name.strip().lstrip('*.')
                    if name.endswith(self.domain):
                        subdomains.add(name)
            
            self.results['subdomains_from_certs'] = list(subdomains)
            return list(subdomains)
        except Exception as e:
            print(f"[!] Certificate search failed: {e}")
            return []
    
    def shodan_lookup(self, api_key):
        """Shodan lookup"""
        import shodan
        api = shodan.Shodan(api_key)
        
        try:
            # ค้นหาด้วย hostname
            results = api.search(f'hostname:{self.domain}')
            
            hosts = []
            for result in results['matches']:
                hosts.append({
                    'ip': result['ip_str'],
                    'port': result['port'],
                    'banner': result.get('data', '')[:200],
                    'os': result.get('os'),
                    'product': result.get('product'),
                    'version': result.get('version'),
                    'vulns': list(result.get('vulns', {}).keys()),
                })
            
            self.results['shodan'] = hosts
            return hosts
        except Exception as e:
            print(f"[!] Shodan error: {e}")
            return []
    
    def google_dorks(self):
        """Generate useful Google dorks"""
        dorks = [
            f'site:{self.domain}',
            f'site:{self.domain} filetype:pdf',
            f'site:{self.domain} filetype:xlsx OR filetype:docx',
            f'site:{self.domain} inurl:login OR inurl:admin',
            f'site:{self.domain} ext:conf OR ext:config OR ext:env',
            f'site:{self.domain} intitle:"index of"',
            f'site:{self.domain} intext:password',
            f'"@{self.domain}"',  # email addresses
            f'site:linkedin.com "{self.domain}"',  # employees
        ]
        return dorks
    
    def full_recon(self, shodan_key=None):
        print(f"\n=== Domain OSINT: {self.domain} ===")
        
        print("\n[*] DNS Records...")
        dns = self.dns_records()
        for rtype, records in dns.items():
            print(f"  {rtype}: {records[:3]}")
        
        print("\n[*] WHOIS...")
        whois = self.whois_lookup()
        for k, v in whois.items():
            print(f"  {k}: {v}")
        
        print("\n[*] Certificate Transparency...")
        subdomains = self.certificate_search()
        print(f"  Found {len(subdomains)} subdomains")
        for sub in subdomains[:10]:
            print(f"  - {sub}")
        
        print("\n[*] Useful Google Dorks:")
        for dork in self.google_dorks():
            print(f"  {dork}")
        
        return self.results

import re
if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else 'example.com'
    osint = DomainOSINT(domain)
    osint.full_recon()
```

### 3.2 Shodan Advanced Search

```python
#!/usr/bin/env python3
# shodan_advanced.py — Shodan OSINT

import shodan
import json

class ShodanOSINT:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
    
    def search_organization(self, org_name):
        """ค้นหา infrastructure ขององค์กร"""
        results = self.api.search(f'org:"{org_name}"')
        return results
    
    def find_vulnerable_hosts(self, query):
        """ค้นหา hosts ที่มีช่องโหว่"""
        vuln_queries = {
            'eternal_blue': 'vuln:ms17-010',
            'heartbleed': 'vuln:CVE-2014-0160',
            'log4shell': 'vuln:CVE-2021-44228',
            'default_creds': 'default password',
            'open_rdp': 'port:3389 os:Windows',
            'open_elasticsearch': 'port:9200 product:Elasticsearch',
            'open_mongodb': 'port:27017 product:MongoDB',
            'open_redis': 'port:6379 product:Redis',
        }
        
        if query in vuln_queries:
            query = vuln_queries[query]
        
        return self.api.search(query)
    
    def ip_info(self, ip_address):
        """ได้รับข้อมูล IP address"""
        return self.api.host(ip_address)
    
    def monitor_network(self, network_cidr):
        """ติดตาม IP range"""
        results = self.api.search(f'net:{network_cidr}')
        hosts = []
        
        for match in results['matches']:
            hosts.append({
                'ip': match['ip_str'],
                'ports': [match['port']],
                'hostnames': match.get('hostnames', []),
                'os': match.get('os'),
                'product': match.get('product'),
                'version': match.get('version'),
                'vulns': list(match.get('vulns', {}).keys()),
            })
        
        return hosts
    
    def generate_report(self, results):
        print(f"Total results: {results['total']}")
        print(f"\nTop countries:")
        if 'facets' in results and 'country' in results.get('facets', {}):
            for country in results['facets']['country'][:5]:
                print(f"  {country['value']}: {country['count']}")
        
        print(f"\nHosts with vulnerabilities:")
        for match in results['matches'][:10]:
            vulns = list(match.get('vulns', {}).keys())
            if vulns:
                print(f"  {match['ip_str']}: {vulns}")

if __name__ == "__main__":
    SHODAN_API_KEY = "your_api_key_here"
    osint = ShodanOSINT(SHODAN_API_KEY)
    
    # ตัวอย่าง: ค้นหา EternalBlue vuln
    # results = osint.find_vulnerable_hosts('eternal_blue')
    # osint.generate_report(results)
```

---

## 4. Social Media Intelligence

### 4.1 Twitter/X OSINT

```python
#!/usr/bin/env python3
# twitter_osint.py — Twitter/X intelligence gathering

import tweepy
import json
from datetime import datetime, timedelta

class TwitterOSINT:
    def __init__(self, bearer_token):
        self.client = tweepy.Client(bearer_token=bearer_token)
    
    def get_user_info(self, username):
        """Get user profile information"""
        user = self.client.get_user(
            username=username,
            user_fields=['created_at', 'description', 'entities',
                        'location', 'public_metrics', 'url']
        )
        return user.data if user.data else None
    
    def get_user_tweets(self, user_id, max_results=100):
        """ดึง tweets ล่าสุด"""
        tweets = self.client.get_users_tweets(
            id=user_id,
            max_results=max_results,
            tweet_fields=['created_at', 'geo', 'entities', 'public_metrics']
        )
        return tweets.data or []
    
    def search_mentions(self, query, days=7):
        """Search for mentions/keywords"""
        start_time = datetime.now() - timedelta(days=days)
        
        tweets = self.client.search_recent_tweets(
            query=query,
            start_time=start_time.isoformat() + 'Z',
            max_results=100,
            tweet_fields=['created_at', 'author_id', 'geo']
        )
        return tweets.data or []
    
    def analyze_tweet_patterns(self, tweets):
        """วิเคราะห์ pattern การ tweet"""
        from collections import Counter
        
        hours = Counter()
        hashtags = Counter()
        mentions = Counter()
        urls = []
        
        for tweet in tweets:
            if hasattr(tweet, 'created_at') and tweet.created_at:
                hours[tweet.created_at.hour] += 1
            
            if hasattr(tweet, 'entities') and tweet.entities:
                for tag in tweet.entities.get('hashtags', []):
                    hashtags[tag['tag'].lower()] += 1
                for mention in tweet.entities.get('mentions', []):
                    mentions[mention['username']] += 1
                for url in tweet.entities.get('urls', []):
                    urls.append(url.get('expanded_url'))
        
        return {
            'active_hours': hours.most_common(5),
            'top_hashtags': hashtags.most_common(10),
            'frequent_mentions': mentions.most_common(10),
            'urls': urls[:20],
        }

if __name__ == "__main__":
    BEARER_TOKEN = "your_bearer_token"
    
    osint = TwitterOSINT(BEARER_TOKEN)
    user = osint.get_user_info('target_username')
    if user:
        print(f"User: {user.name}")
        print(f"Location: {user.location}")
        print(f"Followers: {user.public_metrics['followers_count']}")
```

### 4.2 LinkedIn OSINT

```python
#!/usr/bin/env python3
# linkedin_osint.py — LinkedIn intelligence

import requests
from bs4 import BeautifulSoup
import re
import json

class LinkedInOSINT:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def google_search_employees(self, company_name, domain=None, limit=50):
        """ใช้ Google dork หาพนักงาน"""
        dorks = [
            f'site:linkedin.com/in "{company_name}"',
            f'site:linkedin.com "{company_name}" engineer',
            f'site:linkedin.com "{company_name}" manager',
            f'site:linkedin.com "{company_name}" security',
        ]
        
        if domain:
            dorks.append(f'site:linkedin.com "{company_name}" @{domain}')
        
        return dorks
    
    def build_email_format(self, first_name, last_name, domain, formats=None):
        """สร้าง email รูปแบบต่างๆ"""
        f = first_name.lower()
        l = last_name.lower()
        fi = f[0]
        li = l[0]
        
        return [
            f"{f}@{domain}",
            f"{l}@{domain}",
            f"{f}.{l}@{domain}",
            f"{fi}{l}@{domain}",
            f"{f}{li}@{domain}",
            f"{fi}.{l}@{domain}",
            f"{l}.{f}@{domain}",
        ]
    
    def validate_email(self, email, smtp_check=False):
        """ตรวจสอปว่า email ใช้งานอยู่"""
        # Syntax check
        if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email):
            return False, 'invalid_syntax'
        
        if smtp_check:
            # SMTP verification (may be blocked)
            import smtplib
            domain = email.split('@')[1]
            try:
                import dns.resolver
                mx = dns.resolver.resolve(domain, 'MX')
                mx_host = str(mx[0].exchange)
                
                smtp = smtplib.SMTP(timeout=10)
                smtp.connect(mx_host)
                smtp.helo('research.local')
                smtp.mail('test@test.com')
                code, msg = smtp.rcpt(email)
                smtp.quit()
                
                return code == 250, 'smtp_verified'
            except Exception as e:
                return False, f'error: {e}'
        
        return True, 'syntax_valid'

if __name__ == "__main__":
    osint = LinkedInOSINT()
    dorks = osint.google_search_employees('Target Company Inc', 'example.com')
    print("[*] Google dorks:")
    for d in dorks:
        print(f"  {d}")
    
    emails = osint.build_email_format('John', 'Doe', 'example.com')
    print("\n[*] Possible email formats:")
    for e in emails:
        valid, reason = osint.validate_email(e)
        print(f"  {e} ({'valid' if valid else 'invalid'}: {reason})")
```

---

## 5. Dark Web OSINT

### 5.1 การสืบค้นบน Dark Web

```bash
# ตั้งค่า Tor proxy
sudo apt install tor
sudo service tor start

# ใช้งานผ่าน proxychains
proxychains4 curl http://example.onion

# torsocks
torsocks wget http://example.onion
```

```python
#!/usr/bin/env python3
# darkweb_monitor.py — Dark web monitoring สำหรับการตรวจสอป

import requests
import json
from pathlib import Path

class DarkWebMonitor:
    """
    หมายเหตุ: ใช้เพื่อการตรวจสอบหา leaked data ขององค์กรตัวเองเท่านั้น
    ไม่เหมาะสำหรับการเข้าถึงเนื้อหาผิดกฎหมาย
    """
    
    HIBP_API = "https://haveibeenpwned.com/api/v3"
    
    def __init__(self, hibp_api_key=None):
        self.hibp_key = hibp_api_key
        self.session = requests.Session()
    
    def check_email_breaches(self, email):
        """Have I Been Pwned — ตรวจสอบ email leaks"""
        headers = {
            'hibp-api-key': self.hibp_key,
            'User-Agent': 'OSINT-Research'
        }
        url = f"{self.HIBP_API}/breachedaccount/{email}?truncateResponse=false"
        
        r = requests.get(url, headers=headers, timeout=10)
        
        if r.status_code == 200:
            breaches = r.json()
            print(f"[!] {email} found in {len(breaches)} breaches:")
            for breach in breaches:
                print(f"  - {breach['Name']} ({breach['BreachDate']}): "
                      f"{', '.join(breach.get('DataClasses', [])[:5])}")
            return breaches
        elif r.status_code == 404:
            print(f"[*] {email} not found in any breaches")
            return []
        else:
            print(f"[!] API error: {r.status_code}")
            return []
    
    def check_password_pwned(self, password):
        """k-Anonymity password check — ไม่ส่ง full hash"""
        import hashlib
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        r = requests.get(url, timeout=10)
        
        for line in r.text.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                print(f"[!] Password found in {count} breaches!")
                return int(count)
        
        print("[*] Password not found in breached databases")
        return 0
    
    def search_leaked_credentials(self, domain):
        """ค้นหา leaked credentials สำหรับ domain"""
        url = f"{self.HIBP_API}/breaches?domain={domain}"
        headers = {'hibp-api-key': self.hibp_key}
        
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        return []
    
    def tor_search(self, query, proxy='socks5h://127.0.0.1:9050'):
        """ค้นหาผ่าน Tor (ต้องเปิด Tor service ก่อน)"""
        proxies = {'http': proxy, 'https': proxy}
        # Ahmia.fi — dark web search engine
        url = f"https://ahmia.fi/search/?q={query}"
        
        try:
            r = requests.get(url, proxies=proxies, timeout=30)
            return r.text
        except Exception as e:
            print(f"[!] Tor search failed: {e}")
            return None

if __name__ == "__main__":
    monitor = DarkWebMonitor(hibp_api_key="your_api_key")
    
    # ตรวจสอป email
    monitor.check_email_breaches("test@example.com")
    
    # ตรวจสอป password
    monitor.check_password_pwned("password123")
```

---

## 6. Geolocation และ Image OSINT

### 6.1 EXIF Data Analysis

```python
#!/usr/bin/env python3
# image_osint.py — วิเคราะห์รูปภาพเชิง OSINT

import exifread
import json
from pathlib import Path
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

class ImageOSINT:
    def extract_exif(self, image_path):
        """ดึง EXIF metadata"""
        with open(image_path, 'rb') as f:
            tags = exifread.process_file(f)
        
        metadata = {}
        for tag, value in tags.items():
            metadata[str(tag)] = str(value)
        
        return metadata
    
    def extract_gps(self, image_path):
        """Extract GPS coordinates"""
        img = Image.open(image_path)
        exif_data = img._getexif()
        
        if not exif_data:
            return None
        
        gps_data = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == 'GPSInfo':
                for key, val in value.items():
                    gps_data[GPSTAGS.get(key, key)] = val
        
        if not gps_data:
            return None
        
        # Convert to decimal degrees
        lat = self._convert_to_degrees(gps_data.get('GPSLatitude', (0,0,0)))
        lon = self._convert_to_degrees(gps_data.get('GPSLongitude', (0,0,0)))
        
        if gps_data.get('GPSLatitudeRef') == 'S':
            lat = -lat
        if gps_data.get('GPSLongitudeRef') == 'W':
            lon = -lon
        
        return {
            'latitude': lat,
            'longitude': lon,
            'altitude': float(gps_data.get('GPSAltitude', 0)),
            'google_maps': f"https://maps.google.com/?q={lat},{lon}",
        }
    
    def _convert_to_degrees(self, value):
        if not value or len(value) < 3:
            return 0.0
        d, m, s = value
        return float(d) + float(m)/60 + float(s)/3600
    
    def analyze(self, image_path):
        print(f"\n=== Image OSINT: {image_path} ===")
        
        metadata = self.extract_exif(image_path)
        
        interesting_fields = [
            'Image Make', 'Image Model', 'Image Software',
            'EXIF DateTimeOriginal', 'EXIF LensModel',
            'Image Artist', 'Image Copyright',
        ]
        
        print("\n[*] Device info:")
        for field in interesting_fields:
            if field in metadata:
                print(f"  {field}: {metadata[field]}")
        
        gps = self.extract_gps(image_path)
        if gps:
            print(f"\n[!] GPS Location found:")
            print(f"  Lat: {gps['latitude']:.6f}")
            print(f"  Lon: {gps['longitude']:.6f}")
            print(f"  Google Maps: {gps['google_maps']}")
        else:
            print("\n[*] No GPS data found")
        
        return metadata, gps

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <image>")
        sys.exit(1)
    analyzer = ImageOSINT()
    analyzer.analyze(sys.argv[1])
```

---

## 7. Corporate OSINT

### 7.1 เก็บข้อมูลองค์กร

```python
#!/usr/bin/env python3
# corporate_osint.py — OSINT สำหรับองค์กร

import requests
import json
from bs4 import BeautifulSoup
import re

class CorporateOSINT:
    def __init__(self, target_company, target_domain):
        self.company = target_company
        self.domain = target_domain
        self.findings = {}
    
    def check_security_headers(self, url):
        """ตรวจสอป security headers"""
        try:
            r = requests.get(url, timeout=10, verify=False)
            headers = r.headers
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'X-XSS-Protection': 'XSS protection',
                'Referrer-Policy': 'Referrer policy',
                'Permissions-Policy': 'Permissions policy',
            }
            
            missing = []
            present = []
            
            for header, desc in security_headers.items():
                if header in headers:
                    present.append(f"{header}: {headers[header][:50]}")
                else:
                    missing.append(f"{header} ({desc})")
            
            return {'present': present, 'missing': missing}
        except Exception as e:
            return {'error': str(e)}
    
    def enumerate_emails(self, use_hunter=False, hunter_api_key=None):
        """เก็บ email addresses"""
        emails = set()
        
        if use_hunter and hunter_api_key:
            # Hunter.io API
            url = f"https://api.hunter.io/v2/domain-search?domain={self.domain}&api_key={hunter_api_key}"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                for email_data in r.json().get('data', {}).get('emails', []):
                    emails.add(email_data['value'])
        
        return list(emails)
    
    def find_technology_stack(self, url):
        """Technology fingerprinting"""
        try:
            r = requests.get(url, timeout=10)
            headers = r.headers
            content = r.text
            
            tech = []
            
            # Server
            server = headers.get('Server', '')
            if server:
                tech.append(f"Server: {server}")
            
            # X-Powered-By
            powered = headers.get('X-Powered-By', '')
            if powered:
                tech.append(f"X-Powered-By: {powered}")
            
            # CMS detection
            cms_indicators = {
                'WordPress': ['/wp-content/', '/wp-login.php', 'wp-includes'],
                'Drupal': ['X-Generator: Drupal', 'drupal.js', 'sites/default'],
                'Joomla': ['index.php?option=', '/components/', '/modules/'],
                'Shopify': ['cdn.shopify.com', 'shopify.com'],
                'Magento': ['Mage.Cookies', '/skin/frontend/'],
                'Laravel': ['laravel_session', 'Laravel'],
                'Django': ['csrfmiddlewaretoken', 'Django'],
            }
            
            for cms, indicators in cms_indicators.items():
                if any(ind in content for ind in indicators):
                    tech.append(f"CMS: {cms}")
            
            return tech
        except Exception as e:
            return [f'Error: {e}']
    
    def check_subdomains(self, subdomains_file=None):
        """Active subdomain enumeration"""
        if not subdomains_file:
            common_subdomains = [
                'www', 'mail', 'remote', 'blog', 'webmail', 'server',
                'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
                'staging', 'test', 'portal', 'admin', 'git', 'jira',
                'confluence', 'jenkins', 'gitlab', 'hr', 'intranet'
            ]
        else:
            with open(subdomains_file) as f:
                common_subdomains = [line.strip() for line in f]
        
        found = []
        import socket
        from concurrent.futures import ThreadPoolExecutor
        
        def check_subdomain(sub):
            hostname = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(hostname)
                return hostname, ip
            except:
                return None, None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(check_subdomain, common_subdomains)
        
        for hostname, ip in results:
            if hostname:
                found.append({'hostname': hostname, 'ip': ip})
                print(f"  [+] {hostname}: {ip}")
        
        return found
    
    def full_recon(self):
        print(f"\n=== Corporate OSINT: {self.company} ({self.domain}) ===")
        
        print("\n[*] Security headers...")
        url = f"https://{self.domain}"
        headers_result = self.check_security_headers(url)
        if 'missing' in headers_result:
            print(f"  Missing headers: {', '.join(headers_result['missing'][:3])}")
        
        print("\n[*] Technology stack...")
        tech = self.find_technology_stack(url)
        for t in tech:
            print(f"  - {t}")
        
        print("\n[*] Subdomain enumeration...")
        subdomains = self.check_subdomains()
        print(f"  Found {len(subdomains)} subdomains")

if __name__ == "__main__":
    import sys
    company = sys.argv[1] if len(sys.argv) > 1 else 'Target Corp'
    domain = sys.argv[2] if len(sys.argv) > 2 else 'example.com'
    osint = CorporateOSINT(company, domain)
    osint.full_recon()
```

---

## 8. Automated OSINT Pipelines

### 8.1 SpiderFoot Integration

```bash
# ติดตั้ง SpiderFoot
pip3 install spiderfoot

# เริ่ม SpiderFoot web UI
spiderfoot -l 127.0.0.1:5001

# SpiderFoot CLI
spiderfoot -s example.com -m all -o csv -F results.csv

# สั่ง SpiderFoot API
curl -X POST http://127.0.0.1:5001/api/v1/scan/new \
  -d 'scanname=MyTarget&scantarget=example.com&usecase=all'
```

```python
#!/usr/bin/env python3
# osint_pipeline.py — Automated OSINT pipeline

import subprocess
import json
import requests
from pathlib import Path
from datetime import datetime

class OSINTPipeline:
    def __init__(self, target, output_dir):
        self.target = target
        self.output = Path(output_dir)
        self.output.mkdir(parents=True, exist_ok=True)
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'findings': {}
        }
    
    def run_amass(self):
        """Subdomain enumeration"""
        print("[*] Running Amass...")
        output_file = self.output / 'amass_results.txt'
        
        cmd = ['amass', 'enum', '-d', self.target, '-passive',
               '-o', str(output_file)]
        subprocess.run(cmd, timeout=300)
        
        if output_file.exists():
            subdomains = output_file.read_text().splitlines()
            self.results['findings']['subdomains'] = subdomains
            print(f"  Found {len(subdomains)} subdomains")
            return subdomains
        return []
    
    def run_theharvester(self):
        """Email harvesting"""
        print("[*] Running TheHarvester...")
        output_file = str(self.output / 'harvester')
        
        cmd = ['theHarvester', '-d', self.target, '-b', 'google,bing',
               '-f', output_file]
        subprocess.run(cmd, timeout=120)
        
        json_file = Path(output_file + '.json')
        if json_file.exists():
            data = json.loads(json_file.read_text())
            self.results['findings']['emails'] = data.get('emails', [])
            print(f"  Found {len(data.get('emails', []))} emails")
            return data
        return {}
    
    def run_shodan(self, api_key):
        """Shodan scan"""
        print("[*] Querying Shodan...")
        url = f"https://api.shodan.io/dns/resolve?hostnames={self.target}&key={api_key}"
        r = requests.get(url, timeout=30)
        
        if r.status_code == 200:
            ip_data = r.json()
            self.results['findings']['ips'] = ip_data
            
            # ได้รับข้อมูล host
            for domain, ip in ip_data.items():
                host_url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
                host_r = requests.get(host_url, timeout=30)
                if host_r.status_code == 200:
                    self.results['findings'][f'shodan_{ip}'] = host_r.json()
    
    def check_hibp(self, emails, api_key):
        """Check Have I Been Pwned"""
        print(f"[*] Checking {len(emails)} emails on HIBP...")
        breaches_found = {}
        
        for email in emails[:10]:  # จำกัด 10 อันดับแรก
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {'hibp-api-key': api_key, 'User-Agent': 'OSINT'}
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                breaches_found[email] = r.json()
        
        self.results['findings']['breaches'] = breaches_found
        return breaches_found
    
    def generate_report(self):
        report_file = self.output / 'osint_report.json'
        report_file.write_text(json.dumps(self.results, indent=2))
        print(f"\n[*] Report saved to {report_file}")
        
        print("\n=== OSINT Summary ===")
        for category, data in self.results['findings'].items():
            count = len(data) if isinstance(data, (list, dict)) else 1
            print(f"  {category}: {count} items")
    
    def run_all(self, shodan_key=None, hibp_key=None):
        print(f"[*] Starting OSINT pipeline for: {self.target}")
        
        subdomains = self.run_amass()
        harvester_data = self.run_theharvester()
        
        if shodan_key:
            self.run_shodan(shodan_key)
        
        emails = self.results['findings'].get('emails', [])
        if hibp_key and emails:
            self.check_hibp(emails, hibp_key)
        
        self.generate_report()

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else 'example.com'
    pipeline = OSINTPipeline(target, f'/tmp/osint_{target}')
    pipeline.run_all()
```

---

## 9. OSINT สำหรับ Threat Intelligence

### 9.1 Threat Actor Tracking

```python
#!/usr/bin/env python3
# threat_intel_osint.py — OSINT สำหรับ Threat Intelligence

import requests
import json
from datetime import datetime

class ThreatIntelOSINT:
    def __init__(self):
        self.session = requests.Session()
    
    def check_ip_reputation(self, ip_address):
        """ตรวจสอป IP reputation ผ่านหลายแหล่ง"""
        reputation = {}
        
        # AbuseIPDB
        url = "https://api.abuseipdb.com/api/v2/check"
        # headers = {'Key': 'YOUR_API_KEY', 'Accept': 'application/json'}
        # params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
        # r = requests.get(url, headers=headers, params=params)
        
        # ipinfo.io (ไม่ต้องใช้ API key)
        r = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=10)
        if r.status_code == 200:
            reputation['ipinfo'] = r.json()
        
        # ตรวจสอปบน ThreatCrowd
        url = f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip_address}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            reputation['threatcrowd'] = r.json()
        
        return reputation
    
    def check_domain_reputation(self, domain):
        """ตรวจสอป domain reputation"""
        results = {}
        
        # VirusTotal
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        # params = {'apikey': 'YOUR_KEY', 'domain': domain}
        # r = requests.get(url, params=params)
        
        # ThreatCrowd
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            results['threatcrowd'] = r.json()
        
        return results
    
    def search_malware_samples(self, hash_or_keyword):
        """ค้นหา malware samples"""
        # MalwareBazaar
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {'query': 'get_info', 'hash': hash_or_keyword}
        r = requests.post(url, data=data, timeout=30)
        if r.status_code == 200:
            return r.json()
        return {}
    
    def build_threat_profile(self, iocs):
        """สร้าง threat profile จาก IOCs"""
        profile = {
            'analyzed_at': datetime.now().isoformat(),
            'iocs': iocs,
            'reputation': {}
        }
        
        for ioc in iocs:
            if ioc['type'] == 'ip':
                rep = self.check_ip_reputation(ioc['value'])
                profile['reputation'][ioc['value']] = rep
            elif ioc['type'] == 'domain':
                rep = self.check_domain_reputation(ioc['value'])
                profile['reputation'][ioc['value']] = rep
        
        return profile

if __name__ == "__main__":
    ti = ThreatIntelOSINT()
    
    # ตัวอย่าง: ตรวจสอป IP
    result = ti.check_ip_reputation('8.8.8.8')
    print(json.dumps(result.get('ipinfo', {}), indent=2))
```

---

## 10. OPSEC ในการทำ OSINT

### 10.1 การป้องกันตัวเอง

```bash
# 1. ใช้ VPN หรือ Tor
command -v protonvpn-cli && protonvpn-cli connect --fastest

# 2. ปลอม User-Agent
curl -H "User-Agent: Mozilla/5.0 (compatible; Research)" https://target.com

# 3. ใช้ Disposable browser profile
mkdir /tmp/research_profile
google-chrome --user-data-dir=/tmp/research_profile \
    --no-sandbox --disable-gpu --incognito

# 4. ไม่รักษาประวัติความเคลื่อนไหว (ใน Bash history)
export HISTFILE=/dev/null

# 5. ใช้ separate VM สำหรับ OSINT activities
# ไม่ใช้เครื่องหลักเพื่อป้องกันการรั่วไหล data
```

```python
#!/usr/bin/env python3
# opsec_wrapper.py — OPSEC-aware requests wrapper

import requests
import random
import time
from itertools import cycle

class OPSECSession:
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/604.1',
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    ]
    
    def __init__(self, use_tor=False, delay_range=(1, 5)):
        self.session = requests.Session()
        self.delay_range = delay_range
        self.request_count = 0
        
        if use_tor:
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050',
            }
    
    def get(self, url, **kwargs):
        """Rate-limited GET พร้อม random User-Agent"""
        self.request_count += 1
        
        # Random delay
        time.sleep(random.uniform(*self.delay_range))
        
        # Random User-Agent
        headers = kwargs.pop('headers', {})
        headers['User-Agent'] = random.choice(self.USER_AGENTS)
        
        return self.session.get(url, headers=headers, **kwargs)
    
    def rotate_identity(self):
        """Reset session (new cookies, etc.)"""
        self.session.cookies.clear()
        self.request_count = 0
        print("[*] Identity rotated")

if __name__ == "__main__":
    opsec = OPSECSession(delay_range=(2, 8))
    r = opsec.get('https://httpbin.org/headers')
    print(r.json())
```

---

## สรุป

| ประเภท | เครื่องมือ | เทคนิค |
|--------|--------|--------|
| People OSINT | Sherlock, Google | Username enumeration |
| Domain OSINT | Amass, DNSRecon, crt.sh | Subdomain, certificate |
| Infrastructure | Shodan, Censys | Attack surface mapping |
| Social Media | Tweepy, Instaloader | Social intelligence |
| Dark Web | HIBP, Tor | Credential leak detection |
| Corporate | TheHarvester, SpiderFoot | Email, employee info |
| Image | ExifRead, Pillow | GPS, device metadata |
| Threat Intel | MalwareBazaar, VT | IOC enrichment |

---

← [Part 84: Digital Forensics](Part-84-Digital-Forensics.md) | [Part 86: Red Team Operations](Part-86-Red-Team-Operations.md) →
