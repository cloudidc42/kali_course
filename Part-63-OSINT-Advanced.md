# Part 63: OSINT Advanced

## สารบัญ
1. [OSINT Framework Overview](#overview)
2. [People Intelligence (HUMINT)](#humint)
3. [Company Intelligence](#company-intel)
4. [Technical OSINT](#technical-osint)
5. [Social Media Intelligence (SOCMINT)](#socmint)
6. [Geolocation Intelligence (GEOINT)](#geoint)
7. [Dark Web OSINT](#dark-web)
8. [Automated OSINT Tools](#automated)
9. [OSINT for Red Team](#red-team)
10. [OPSEC และ Counter-OSINT](#opsec)

---

## 1. OSINT Framework Overview {#overview}

```
OSINT Sources:

┌──────────────────────────────────────────────────┐
│                 OSINT SOURCES                          │
├─────────┬─────────┬─────────┬─────────┬─────────┤
│ Internet │ Social  │ Technical│ Public  │ Dark    │
│ Sources  │ Media   │ Sources  │ Records │ Web     │
├─────────┼─────────┼─────────┼─────────┼─────────┤
│ Google   │ LinkedIn│ Shodan   │ Whois   │ .onion  │
│ News     │ Twitter │ Censys   │ Corp    │ Forums  │
│ Archives │ Facebook│ DNS      │ Court   │ Markets │
│ Pastebin │ Instagram│ SSL Certs│ Leaks   │ Chats   │
└─────────┴─────────┴─────────┴─────────┴─────────┘
```

### Google Dorking Advanced

```bash
# Google Dorking operators

# ค้นหาไฟล์ sensitive
site:target.com filetype:pdf
site:target.com filetype:xls OR filetype:xlsx
site:target.com filetype:sql
site:target.com filetype:log

# ค้นหา exposed directories
site:target.com intitle:"Index of"
site:target.com inurl:admin
site:target.com inurl:backup
site:target.com inurl:config

# ค้นหา login pages
site:target.com inurl:login
site:target.com intitle:"Sign In" OR intitle:"Login"

# ค้นหา leaked credentials
site:pastebin.com "target.com" password
site:github.com "target.com" "password"

# ค้นหา employee emails
site:target.com filetype:pdf author:"@target.com"
"@target.com" site:linkedin.com

# ค้นหา camera/device
site:target.com inurl:"view/view.shtml"
site:target.com inurl:"/control/userimage.html"

# Cache และ Archive
cache:target.com
site:web.archive.org/web/ target.com

# GitHub leaks
site:github.com "target.com" API_KEY
site:github.com "target.com" "secret"
site:github.com "target.com" "db_password"
```

---

## 2. People Intelligence (HUMINT) {#humint}

### Email Investigation

```bash
# ค้นหา email format ขององค์กร

# Hunter.io API
curl -s 'https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY' | \
    python3 -m json.tool

# ค้นหาเอเมลแบบ pattern
# john.smith@company.com
# jsmith@company.com
# john@company.com

# Verify email ด้วย SMTP
python3 << 'EOF'
import smtplib
import dns.resolver

def verify_email(email):
    domain = email.split('@')[1]
    
    # Get MX record
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx = sorted(mx_records, key=lambda r: r.preference)[0].exchange.to_text()
    except:
        return False, "No MX record"
    
    # VRFY command
    try:
        server = smtplib.SMTP(mx, 25, timeout=10)
        server.helo('test.com')
        code, msg = server.verify(email)
        server.quit()
        return code == 250, msg.decode()
    except Exception as e:
        return False, str(e)

result, msg = verify_email('john@target.com')
print(f"Valid: {result}, Message: {msg}")
EOF

# Holehe - ซื้อหา accounts จาก email
pip3 install holehe
holehe john.smith@gmail.com
# แสดง accounts ที่ใช้ email นี้
```

### Phone Number OSINT

```python
#!/usr/bin/env python3
# phone_osint.py

import phonenumbers
from phonenumbers import geocoder, carrier, timezone

def analyze_phone(phone_str):
    try:
        phone = phonenumbers.parse(phone_str)
        
        print(f"Number: {phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
        print(f"Valid: {phonenumbers.is_valid_number(phone)}")
        print(f"Country: {geocoder.description_for_number(phone, 'en')}")
        print(f"Carrier: {carrier.name_for_number(phone, 'en')}")
        print(f"Timezone: {timezone.time_zones_for_number(phone)}")
        print(f"Number Type: {phonenumbers.number_type(phone)}")
        
    except Exception as e:
        print(f"Error: {e}")

# ตัวอย่าง
analyze_phone("+66812345678")  # Thailand number

# OSINT sources สำหรับ phone numbers:
# - TrueCaller (directory)
# - Sync.me
# - Facebook messenger search
# - WhatsApp profile check
# - Telegram @username search

# Twilio Lookup API
import requests

def twilio_lookup(phone, account_sid, auth_token):
    url = f'https://lookups.twilio.com/v1/PhoneNumbers/{phone}?Type=carrier'
    r = requests.get(url, auth=(account_sid, auth_token))
    return r.json()
```

### Social Media Profiling

```python
#!/usr/bin/env python3
# social_profile.py - สร้าง profile จากข้อมูลหลายแหล่ง

class PersonProfile:
    def __init__(self, name):
        self.name = name
        self.emails = []
        self.phones = []
        self.usernames = []
        self.social_media = {}
        self.employers = []
        self.locations = []
        self.photos = []
    
    def add_social(self, platform, url, data=None):
        self.social_media[platform] = {
            'url': url,
            'data': data or {}
        }
    
    def generate_username_variants(self):
        """สร้าง username variants จากชื่อ"""
        parts = self.name.lower().split()
        if len(parts) < 2:
            return [parts[0]]
        
        first, last = parts[0], parts[-1]
        variants = [
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{last}{first}",
            f"{first}",
            f"{last}",
        ]
        return variants
    
    def check_username_sites(self, username):
        """ตรวจสอบ username บน social platforms"""
        import requests
        
        sites = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Medium': f'https://medium.com/@{username}',
        }
        
        found = {}
        for site, url in sites.items():
            try:
                r = requests.get(url, timeout=5, 
                                headers={'User-Agent': 'Mozilla/5.0'},
                                allow_redirects=True)
                if r.status_code == 200:
                    found[site] = url
                    print(f"[+] Found on {site}: {url}")
            except:
                pass
        
        return found
    
    def to_report(self):
        return {
            'name': self.name,
            'emails': self.emails,
            'phones': self.phones,
            'usernames': self.usernames,
            'social_media': self.social_media,
            'employers': self.employers,
            'locations': self.locations,
        }

# Sherlock - username search across 400+ platforms
# git clone https://github.com/sherlock-project/sherlock
# python3 sherlock.py <username>
```

---

## 3. Company Intelligence {#company-intel}

### Corporate Recon

```bash
# ข้อมูลเกี่ยวกับบริษัท

# Business registration ใน Thailand
# เจ้าหน้าที่พาณิชย์: https://www.dbd.go.th/
# ค้นหาจากทะเบียน: company name, registered address, directors

# EDGAR (US SEC)
curl 'https://efts.sec.gov/LATEST/search-index?q="target company"&dateRange=custom'

# Companies House (UK)
curl 'https://api.companieshouse.gov.uk/search/companies?q=target' \
     -H 'Authorization: api_key'

# LinkedIn company research
# - Employees count + growth
# - Job postings (tech stack)
# - Key personnel
# - Recent changes

# theHarvester - email/subdomain harvest
theHarvester -d target.com -l 500 -b all
theHarvester -d target.com -b google,linkedin,hunter,shodan

# ค้นหา subdomains
amass enum -d target.com
subfinder -d target.com
assetfinder target.com

# ค้นหา IP ranges
whois target.com | grep -E 'inetnum|CIDR|NetRange'
nmap --script whois-ip 203.150.1.1

# BGP data
curl 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=ASN'
```

### Technology Stack Discovery

```python
#!/usr/bin/env python3
# tech_fingerprinter.py

import requests
from bs4 import BeautifulSoup
import re

class TechStackFingerprinter:
    def __init__(self, url):
        self.url = url
        self.tech = {}
    
    def analyze(self):
        try:
            r = requests.get(self.url, timeout=10, 
                           headers={'User-Agent': 'Mozilla/5.0'},
                           verify=False)
            
            self._check_headers(r.headers)
            self._check_html(r.text)
            self._check_cookies(r.cookies)
            
        except Exception as e:
            print(f"Error: {e}")
        
        return self.tech
    
    def _check_headers(self, headers):
        # Server header
        server = headers.get('Server', '')
        if server:
            self.tech['server'] = server
        
        # Framework headers
        if 'X-Powered-By' in headers:
            self.tech['backend'] = headers['X-Powered-By']
        
        # CDN
        if 'X-Cache' in headers or 'CF-RAY' in headers:
            self.tech['cdn'] = 'Cloudflare'
        elif 'X-Amz-Cf-Id' in headers:
            self.tech['cdn'] = 'AWS CloudFront'
        
        # Load balancer
        if 'X-Azure-Ref' in headers:
            self.tech['cloud'] = 'Azure'
    
    def _check_html(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        
        # JavaScript frameworks
        scripts = [s.get('src', '') for s in soup.find_all('script')]
        
        if any('react' in s.lower() for s in scripts):
            self.tech['frontend'] = 'React'
        elif any('angular' in s.lower() for s in scripts):
            self.tech['frontend'] = 'Angular'
        elif any('vue' in s.lower() for s in scripts):
            self.tech['frontend'] = 'Vue.js'
        
        # jQuery
        if any('jquery' in s.lower() for s in scripts):
            self.tech['jquery'] = True
        
        # WordPress
        if 'wp-content' in html or 'wp-includes' in html:
            self.tech['cms'] = 'WordPress'
        elif 'Drupal' in html:
            self.tech['cms'] = 'Drupal'
        elif 'Joomla' in html:
            self.tech['cms'] = 'Joomla'
        
        # Meta generator
        meta_gen = soup.find('meta', {'name': 'generator'})
        if meta_gen:
            self.tech['generator'] = meta_gen.get('content', '')
    
    def _check_cookies(self, cookies):
        cookie_names = [c.lower() for c in cookies.keys()]
        
        if 'phpsessid' in cookie_names:
            self.tech['language'] = 'PHP'
        elif 'jsessionid' in cookie_names:
            self.tech['language'] = 'Java'
        elif 'aspsessionid' in cookie_names:
            self.tech['language'] = 'ASP.NET'

f = TechStackFingerprinter('https://target.com')
tech = f.analyze()
print("Technology stack:")
for k, v in tech.items():
    print(f"  {k}: {v}")
```

---

## 4. Technical OSINT {#technical-osint}

### Shodan Advanced

```python
#!/usr/bin/env python3
# shodan_recon.py

import shodan
import json

API_KEY = 'YOUR_SHODAN_API_KEY'

def shodan_company_scan(company_name, country='TH'):
    api = shodan.Shodan(API_KEY)
    
    # Search สำหรับ company
    results = api.search(f'org:"{company_name}" country:{country}')
    
    print(f"[+] Found {results['total']} hosts for {company_name}")
    
    for host in results['matches']:
        print(f"\nIP: {host['ip_str']}")
        print(f"  Ports: {host.get('port', 'N/A')}")
        print(f"  Product: {host.get('product', 'N/A')}")
        print(f"  Version: {host.get('version', 'N/A')}")
        print(f"  Org: {host.get('org', 'N/A')}")
        print(f"  OS: {host.get('os', 'N/A')}")
        
        if 'http' in host:
            print(f"  Title: {host['http'].get('title', 'N/A')}")
    
    return results

def shodan_host_detail(ip):
    api = shodan.Shodan(API_KEY)
    host = api.host(ip)
    
    print(f"\nHost: {ip}")
    print(f"Country: {host.get('country_name')}")
    print(f"ISP: {host.get('isp')}")
    print(f"OS: {host.get('os', 'Unknown')}")
    print(f"Hostnames: {', '.join(host.get('hostnames', []))}")
    print("\nOpen Ports:")
    for item in host['data']:
        print(f"  {item['port']}/{item['transport']} - {item.get('product', '')} {item.get('version', '')}")
        if 'banner' in item:
            print(f"    Banner: {item['banner'][:100]}")
    
    print("\nVulnerabilities:")
    for vuln in host.get('vulns', []):
        print(f"  {vuln}")
    
    return host

def shodan_find_cameras(city):
    api = shodan.Shodan(API_KEY)
    query = f'webcam city:"{city}" has_screenshot:true'
    results = api.search(query)
    
    print(f"[+] Found {results['total']} cameras in {city}")
    for host in results['matches']:
        print(f"IP: {host['ip_str']} - {host.get('product', 'Unknown')}")

# ใช้งาน:
# shodan_company_scan('Target Company')
# shodan_host_detail('1.2.3.4')
```

### Censys และ FOFA

```bash
# Censys.io - alternative ถึง Shodan
# https://search.censys.io/

# Censys API
pip3 install censys

python3 << 'EOF'
from censys.search import CensysHosts

h = CensysHosts()  # ต้อง set API_ID และ API_SECRET

# ค้นหาหน้า
 results = h.search('services.service_name: HTTP AND (location.country_code: TH)')

for r in results:
    print(f"IP: {r['ip']}")
    for service in r.get('services', []):
        print(f"  {service['port']}/{service['transport_protocol']} {service.get('service_name', '')}")
EOF

# FOFA (Chinese OSINT platform)
curl 'https://fofa.info/api/v1/search/all?email=EMAIL&key=KEY&qbase64=BASE64_QUERY&fields=host,ip,port,protocol'

# ZoomEye - Chinese Shodan
# https://www.zoomeye.org/

# GreyNoise - threat intelligence
pip3 install greynoise
# gnql 'ip:1.2.3.4' - check if IP is benign/malicious
```

### DNS และ Certificate Analysis

```bash
# Passive DNS history
curl 'https://api.threatcrowd.org/searchDns.php?value=target.com'
curl 'https://api.hackertarget.com/hostsearch/?q=target.com'

# Certificate Transparency
curl 'https://crt.sh/?q=%.target.com&output=json' | \
    python3 -c "import json,sys; [print(c['name_value']) for c in json.load(sys.stdin)]" | \
    sort -u

# AMASS - comprehensive subdomain enumeration
amass enum -d target.com -passive -src -ip
amass enum -d target.com -active -ip -brute

# สรุป DNS records
for type in A AAAA MX NS TXT SOA CNAME; do
    echo "=== $type ===" 
    dig +short $type target.com
done

# Zone transfer เดิม
# (โดยทั่วไปปิดแล้ว แต่ควรลอง)
dig axfr @ns1.target.com target.com
dnsrecon -d target.com -t axfr

# Historical DNS (old IPs)
curl 'https://api.securitytrails.com/v1/domain/target.com/history/a' \
     -H 'APIKEY: YOUR_KEY' | python3 -m json.tool
```

---

## 5. Social Media Intelligence (SOCMINT) {#socmint}

### Twitter/X Intelligence

```python
#!/usr/bin/env python3
# twitter_osint.py - Twitter intelligence (with API v2)

import tweepy

def setup_twitter_api(bearer_token):
    client = tweepy.Client(bearer_token=bearer_token)
    return client

def search_tweets(client, query, max_results=100):
    """ค้นหา tweets"""
    tweets = client.search_recent_tweets(
        query=query,
        max_results=max_results,
        tweet_fields=['created_at', 'author_id', 'geo', 'entities'],
        expansions=['author_id', 'geo.place_id']
    )
    return tweets

def get_user_info(client, username):
    """ดู profile ผู้ใช้"""
    user = client.get_user(
        username=username,
        user_fields=['name', 'description', 'location', 'created_at',
                    'public_metrics', 'entities']
    )
    return user

def extract_location_from_tweets(tweets):
    """สกัด location จาก tweets"""
    locations = []
    
    for tweet in tweets.data or []:
        # Direct coordinates
        if tweet.geo and tweet.geo.get('coordinates'):
            coords = tweet.geo['coordinates']['coordinates']
            locations.append({'lat': coords[1], 'lon': coords[0],
                             'type': 'exact', 'tweet_id': tweet.id})
    
    return locations

# Social Mapper - correlate accounts across platforms
# https://github.com/Greenwolf/social_mapper
# python3 social_mapper.py -f /path/to/photos -i company -m fast
```

### LinkedIn Intelligence

```bash
# LinkedIn OSINT techniques

# 1. Google dork สำหรับ employees
site:linkedin.com/in "Target Company" "Security"
site:linkedin.com/in "Target Company" -intitle:"profiles" -inurl:"/dir/"

# 2. LinkedIn Sales Navigator (ถ้ามี subscription)
# ค้นหา: Company + Title + Location

# 3. CrossLinked - LinkedIn email harvester
pip3 install crosslinked
crosslinked -f '{first}.{last}@target.com' "Target Company"

# Output: john.smith@target.com, jane.doe@target.com, ...

# 4. Org chart reconstruction
# ค้นหา: CEO, CTO, CISO, IT Manager ของ target
# สร้าง hierarchy จาก LinkedIn profiles

# 5. Job posting intelligence
# ดู job requirements = tech stack
# "Experience with Splunk" = they use Splunk
# "Kubernetes experience" = container environment
# "Azure AD" = Microsoft 365
```

---

## 6. Geolocation Intelligence (GEOINT) {#geoint}

### Image GEOINT

```python
#!/usr/bin/env python3
# image_geoint.py - สกัด location จากรูปภาพ

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import requests

def extract_exif(image_path):
    """สกัด EXIF data จากรูปภาพ"""
    img = Image.open(image_path)
    exif_data = img._getexif()
    
    if not exif_data:
        return {}
    
    exif = {}
    for tag_id, value in exif_data.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == 'GPSInfo':
            gps_data = {}
            for gps_id in value:
                gps_tag = GPSTAGS.get(gps_id, gps_id)
                gps_data[gps_tag] = value[gps_id]
            exif['GPS'] = gps_data
        else:
            exif[tag] = value
    
    return exif

def get_coordinates(gps_info):
    """แปลง EXIF GPS เป็น decimal coordinates"""
    def convert_to_degrees(value):
        d, m, s = float(value[0]), float(value[1]), float(value[2])
        return d + m/60 + s/3600
    
    lat = convert_to_degrees(gps_info['GPSLatitude'])
    lon = convert_to_degrees(gps_info['GPSLongitude'])
    
    if gps_info.get('GPSLatitudeRef') == 'S':
        lat = -lat
    if gps_info.get('GPSLongitudeRef') == 'W':
        lon = -lon
    
    return lat, lon

def reverse_geocode(lat, lon):
    """แปลง coordinates เป็น address"""
    url = f'https://nominatim.openstreetmap.org/reverse'
    params = {'lat': lat, 'lon': lon, 'format': 'json'}
    r = requests.get(url, params=params, 
                    headers={'User-Agent': 'OSINT-Tool/1.0'})
    return r.json()

# ใช้งาน:
exif = extract_exif('photo.jpg')
if 'GPS' in exif:
    lat, lon = get_coordinates(exif['GPS'])
    print(f"Coordinates: {lat}, {lon}")
    location = reverse_geocode(lat, lon)
    print(f"Address: {location.get('display_name')}")
else:
    print("No GPS data in EXIF")

print("\nOther metadata:")
for key in ['Make', 'Model', 'DateTime', 'Software']:
    if key in exif:
        print(f"  {key}: {exif[key]}")
```

### Wayback Machine Analysis

```python
#!/usr/bin/env python3
# wayback_osint.py

import requests
from datetime import datetime

class WaybackAnalyzer:
    def __init__(self, domain):
        self.domain = domain
        self.api = 'http://archive.org/wayback/available'
    
    def get_snapshots(self, limit=100):
        """ดึง snapshots ทั้งหมด"""
        url = f'http://web.archive.org/cdx/search/cdx'
        params = {
            'url': self.domain,
            'output': 'json',
            'limit': limit,
            'fl': 'timestamp,original,statuscode',
            'filter': 'statuscode:200'
        }
        
        r = requests.get(url, params=params)
        return r.json()[1:]  # skip header
    
    def find_exposed_files(self):
        """ค้นหาไฟล์ที่เคย expose"""
        sensitive_patterns = [
            '*.sql', '*.bak', '*.backup', '*.log',
            '*.env', '*.config', '*/admin/*',
            '*.php.bak', 'robots.txt'
        ]
        
        found = []
        for pattern in sensitive_patterns:
            url = f'http://web.archive.org/cdx/search/cdx'
            params = {
                'url': f'{self.domain}/{pattern}',
                'output': 'json',
                'limit': 10,
                'matchType': 'prefix'
            }
            r = requests.get(url, params=params)
            results = r.json()
            if len(results) > 1:
                found.extend(results[1:])
        
        return found
    
    def get_historical_content(self, timestamp, url):
        """ดึง content จาก archived version"""
        archive_url = f'http://web.archive.org/web/{timestamp}/{url}'
        r = requests.get(archive_url)
        return r.text
    
    def find_old_credentials(self):
        """ค้นหา credentials ที่เคย expose"""
        # ค้นหา config files ใน archive
        exposed = self.find_exposed_files()
        credentials = []
        
        for snapshot in exposed:
            timestamp, original_url = snapshot[0], snapshot[1]
            content = self.get_historical_content(timestamp, original_url)
            
            # ค้นหา patterns ที่น่าสนใจ
            import re
            patterns = [
                r'password[^=]*=[^"]*"([^"]+)"',
                r'api_key[^=]*=[^"]*"([^"]+)"',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    credentials.append({
                        'url': original_url,
                        'timestamp': timestamp,
                        'matches': matches
                    })
        
        return credentials

# analyzer = WaybackAnalyzer('target.com')
# snapshots = analyzer.get_snapshots()
# exposed = analyzer.find_exposed_files()
```

---

## 7. Dark Web OSINT {#dark-web}

```bash
# Dark Web OSINT - ต้องใช้ Tor Browser

# ตั้งค่า Tor
apt install tor torsocks
service tor start

# ใช้ torsocks
torsocks curl https://check.torproject.org/

# Onion sites สำหรับ OSINT:
# Torch: Search engine
# Ahmia: Clearnet Tor search (https://ahmia.fi/)
# OnionScan: scan onion sites

# OnionSearch - search Tor indexes
pip3 install onionsearch
onionsearch --query "target company" --limit 100

# ค้นหา leaked data
# HaveIBeenPwned: https://haveibeenpwned.com/
# Dehashed: https://dehashed.com/
# LeakLookup: https://leak-lookup.com/

# ตรวจสอบ domain ใน paste sites
curl 'https://haveibeenpwned.com/api/v3/breachedaccount/email@target.com' \
     -H 'hibp-api-key: KEY'

# Paste search
curl 'https://psbdmp.ws/api/v3/search/target.com'

# PolySwarm - malware intelligence
curl -H 'Authorization: ApiKey YOUR_KEY' \
     'https://api.polyswarm.network/v3/search?query=target.com'
```

---

## 8. Automated OSINT Tools {#automated}

### Maltego

```bash
# Maltego - visual link analysis
# ดาวน์โหลด: https://www.maltego.com/

# Community Edition: ฟรี (จำกัด 12 entities)
# Transforms:
# - Person transforms: email, phone, social media
# - Domain transforms: DNS, whois, subdomains
# - IP transforms: Shodan, VirusTotal

# CLI สำหรับ Maltego (CANARI framework)
pip3 install canari

# SpiderFoot - automated OSINT
pip3 install spiderfoot
spiderfoot -s target.com -t DOMAIN_NAME -o /tmp/results.json

# web interface
spiderfoot -l 127.0.0.1:5001
# เปิด http://127.0.0.1:5001
```

### Recon-ng

```bash
# recon-ng - full-featured web reconnaissance framework
recon-ng

# ตั้งค่า workspace
workspaces create target_co
workspaces select target_co

# ดู modules
modules search domain
modules load recon/domains-hosts/hackertarget

# กำหนด options
options set SOURCE target.com
run

# ดูผลลัพธ์
show hosts
show contacts

# Export
reporting load reporting/html
options set FILENAME /tmp/report.html
run

# Modules ที่มีประโยชน์:
# recon/domains-hosts/google_site_web
# recon/domains-contacts/whois_pocs
# recon/hosts-ports/shodan_ip
# recon/credentials/credential_management
```

---

## 9. OSINT for Red Team {#red-team}

### Pre-Attack Intelligence

```python
#!/usr/bin/env python3
# redteam_osint.py - รวม OSINT สำหรับ Red Team

class RedTeamOSINT:
    def __init__(self, target_domain):
        self.domain = target_domain
        self.intelligence = {
            'employees': [],
            'emails': [],
            'technologies': [],
            'ip_ranges': [],
            'subdomains': [],
            'credentials': [],
            'physical_locations': []
        }
    
    def run_full_recon(self):
        """ทำ recon แบบครบวงจร"""
        print(f"[*] Starting recon for {self.domain}")
        
        # 1. DNS enumeration
        self._dns_recon()
        
        # 2. Email harvesting
        self._email_harvest()
        
        # 3. Technology fingerprinting
        self._tech_fingerprint()
        
        # 4. Shodan scan
        self._shodan_scan()
        
        # 5. LinkedIn recon
        self._linkedin_recon()
        
        # 6. Certificate transparency
        self._cert_transparency()
        
        # 7. Data breach check
        self._breach_check()
        
        return self.intelligence
    
    def identify_attack_vectors(self):
        """ระบุ attack vectors จาก intelligence"""
        vectors = []
        
        if self.intelligence['credentials']:
            vectors.append({
                'type': 'credential_stuffing',
                'description': 'Leaked credentials found',
                'data': self.intelligence['credentials'][:5]
            })
        
        if self.intelligence['employees']:
            vectors.append({
                'type': 'spear_phishing',
                'description': 'Employee info for targeted phishing',
                'targets': self.intelligence['employees'][:10]
            })
        
        if self.intelligence['technologies']:
            # ค้นหา CVEs สำหรับ tech stack
            for tech in self.intelligence['technologies']:
                vectors.append({
                    'type': 'vulnerability_exploit',
                    'description': f'Known tech: {tech}',
                    'cve_search': f'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={tech}'
                })
        
        return vectors
    
    def generate_phishing_targets(self):
        """สร้างรายชื่อเป้าหมาย phishing ที่มีโอกาสสำเร็จสูง"""
        # ค้นหา:
        # - Help desk / IT support (มักเป็นเป้าหมาย)
        # - Finance department
        # - HR (ได้รับ attachments บ่อย)
        # - Executives' assistants
        
        return [
            e for e in self.intelligence['employees']
            if any(role in e.get('title', '').lower()
                  for role in ['it', 'helpdesk', 'finance', 'hr', 'assistant'])
        ]
```

---

## 10. OPSEC และ Counter-OSINT {#opsec}

```bash
# OPSEC สำหรับ Tester - ซ่อน identity

# 1. VPN + Tor
curl --proxy socks5://127.0.0.1:9050 https://check.torproject.org/

# 2. บัญชี throwaway
# ใช้ Guerrilla Mail สำหรับ email
# ใช้ virtual phone number

# 3. Metadata removal
# รูปภาพ
exiftool -all= photo.jpg  # ลบ EXIF
mat2 document.pdf  # ลบ metadata PDF

# 4. Browser fingerprinting
# ใช้ Tor Browser ป้องกัน fingerprinting
# Canvas fingerprint block

# 5. ป้องกัน attribution
# ใช้ residential proxy
# Rotate IP addresses
# ใช้ cloud VMs ที่หลากหลาย providers

# Counter-OSINT: ลบ footprint ของตัวเอง
python3 << 'EOF'
# Google yourself
import requests
name = 'Your Name'
queries = [
    f'"{name}" site:linkedin.com',
    f'"{name}" email phone',
    f'"{name}" address',
]
for q in queries:
    print(f"Check: https://www.google.com/search?q={q.replace(' ', '+')}")
EOF

# Opt-out resources:
# Spokeo: https://www.spokeo.com/optout
# Whitepages: https://www.whitepages.com/suppression_requests
# Facebook: Privacy settings
```

---

## แบบฝึกหัด - OSINT Lab

```bash
# Lab: ทำ OSINT บน target organization

# 1. DNS enumeration
amass enum -d example.com -passive
subfinder -d example.com -o subdomains.txt

# 2. Email harvest
theHarvester -d example.com -b google,bing,linkedin -l 100

# 3. Shodan search
shodan search 'org:"Example Corp" country:TH'

# 4. Certificate transparency
curl 'https://crt.sh/?q=%.example.com&output=json' | \
    python3 -c "import json,sys; [print(c['name_value']) for c in json.load(sys.stdin)]" | \
    sort -u > cert_subdomains.txt

# 5. LinkedIn employee search
# Site:linkedin.com/in "Example Corp"

# 6. GitHub leak search
git clone https://github.com/trufflesecurity/trufflehog
python3 trufflehog/trufflehog.py github --org=ExampleCorp

# 7. Pastebin monitoring
python3 << 'EOF'
import requests
# ค้นหา domain ใน Pastebin
r = requests.get('https://psbdmp.ws/api/v3/search/example.com')
print(r.json())
EOF
```

---

## สรุป

| Tool | Purpose | Free |
|------|---------|------|
| theHarvester | Email/subdomain | Yes |
| Shodan | IoT/Device search | Limited |
| SpiderFoot | Automated OSINT | Yes |
| Maltego CE | Visual analysis | Limited |
| Amass | Subdomain enum | Yes |
| Recon-ng | Framework | Yes |
| Sherlock | Username search | Yes |
| OSINT Framework | Reference | Yes |

---

← [Part 62: Cryptography Attacks](Part-62-Crypto-Attacks.md) | [Part 64: Evasion Techniques](Part-64-Evasion-Techniques.md) →
