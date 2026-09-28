# Part 88: Security Automation

## สารบัญ
1. [Security Automation คืออะไร?](#1-security-automation)
2. [SOAR (Security Orchestration, Automation and Response)](#2-soar)
3. [Automated Vulnerability Management](#3-automated-vulnerability-management)
4. [CI/CD Security Pipeline](#4-cicd-security-pipeline)
5. [Automated Threat Intelligence](#5-automated-threat-intelligence)
6. [Security Chatbot และ AI Integration](#6-ai-integration)
7. [Infrastructure as Code Security](#7-iac-security)
8. [Automated Compliance Checking](#8-compliance)
9. [แบบฝึกหัด Lab](#9-lab)

---

## 1. Security Automation

Security Automation คือการใช้เทคโนโลยีทำงานด้านความปลอดภัยแทนมนุษย์ เพื่อ:
- ลดเวลาตอบสนองจากนาทีเป็นวินาที
- คุ้มครอง alert จำนวนมากโดยไม่ต้องเพิ่มคน
- Consistency — ทำเหมือนกันทุกครั้ง
- ปรับ scaling ตามปริมาณได้

```
[Alert] → [Enrich] → [Score] → [Auto-contain?] → [Notify] → [Ticket]
   ^          |           |              |                |          |
   |     Threat Intel  ML Model    Playbook          Slack/Email  JIRA
   |
[SIEM] ← [Logs] ← [Endpoints, Network, Cloud]
```

---

## 2. SOAR

### 2.1 Cortex XSOAR / Shuffle Automation
```python
#!/usr/bin/env python3
# soar_playbook.py — SOAR playbook สำหรับ phishing investigation

import requests
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
import hashlib
import re

@dataclass
class Alert:
    alert_id: str
    alert_type: str       # phishing, malware, brute_force, etc.
    severity: str         # critical, high, medium, low
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    username: Optional[str] = None
    file_hash: Optional[str] = None
    url: Optional[str] = None
    email_sender: Optional[str] = None
    email_subject: Optional[str] = None
    raw_data: Dict = field(default_factory=dict)
    enrichment: Dict = field(default_factory=dict)
    actions_taken: List[str] = field(default_factory=list)
    disposition: str = "open"  # open, true_positive, false_positive, benign


class SOARPlaybook:
    """
    SOAR Playbook Engine — automation ตอบสนองอัตโนมัติ
    """

    def __init__(self, config: dict):
        self.config = config
        self.vt_api_key = config.get("virustotal_api_key", "")
        self.slack_webhook = config.get("slack_webhook", "")
        self.ad_server = config.get("active_directory", "")

    # === ENRICHMENT ===

    def enrich_ip(self, ip: str) -> dict:
        """Enrich IP ด้วย VirusTotal + AbuseIPDB"""
        result = {"ip": ip}

        # VirusTotal
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self.vt_api_key}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()["data"]["attributes"]
                result["vt_malicious"] = data["last_analysis_stats"]["malicious"]
                result["vt_country"] = data.get("country", "unknown")
                result["vt_asn"] = data.get("asn", 0)
        except Exception as e:
            result["vt_error"] = str(e)

        # AbuseIPDB
        try:
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.config.get("abuseipdb_key", ""), "Accept": "application/json"}
            resp = requests.get(url, params={"ipAddress": ip, "maxAgeInDays": 90},
                                headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()["data"]
                result["abuse_score"] = data.get("abuseConfidenceScore", 0)
                result["abuse_reports"] = data.get("totalReports", 0)
        except Exception as e:
            result["abuseipdb_error"] = str(e)

        return result

    def enrich_hash(self, file_hash: str) -> dict:
        """Enrich file hash ด้วย VirusTotal"""
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.vt_api_key}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()["data"]["attributes"]
                stats = data["last_analysis_stats"]
                return {
                    "hash": file_hash,
                    "malicious": stats["malicious"],
                    "total": sum(stats.values()),
                    "name": data.get("meaningful_name", ""),
                    "type": data.get("type_description", "")
                }
            elif resp.status_code == 404:
                return {"hash": file_hash, "status": "not_found"}
        except Exception as e:
            return {"hash": file_hash, "error": str(e)}

    def enrich_url(self, url: str) -> dict:
        """Enrich URL ด้วย VirusTotal"""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": self.vt_api_key}
            resp = requests.get(vt_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()["data"]["attributes"]
                return {
                    "url": url,
                    "malicious": data["last_analysis_stats"]["malicious"],
                    "phishing": data.get("categories", {}).get("Forcepoint ThreatSeeker", "")
                }
        except Exception as e:
            return {"url": url, "error": str(e)}

    # === CONTAINMENT ACTIONS ===

    def block_ip_firewall(self, ip: str, reason: str) -> bool:
        """บล็อค IP ผ่าน firewall API"""
        # ตัวอย่าง: ใช้ pfSense / Palo Alto API
        firewall_url = self.config.get("firewall_api_url", "")
        if not firewall_url:
            print(f"[SIMULATION] Block IP: {ip} ({reason})")
            return True
        try:
            resp = requests.post(
                f"{firewall_url}/block",
                json={"ip": ip, "reason": reason, "duration": 3600},
                headers={"Authorization": f"Bearer {self.config.get('firewall_api_key')}"},
                timeout=10
            )
            return resp.status_code == 200
        except Exception:
            return False

    def disable_ad_account(self, username: str, reason: str) -> bool:
        """ปิดใช้งาน Active Directory account"""
        try:
            import ldap3
            conn = ldap3.Connection(
                self.ad_server,
                user=self.config.get("ad_admin_user"),
                password=self.config.get("ad_admin_pass"),
                auto_bind=True
            )
            # ค้นหา user DN
            conn.search(
                self.config.get("ad_base_dn", ""),
                f"(sAMAccountName={username})",
                attributes=["distinguishedName"]
            )
            if conn.entries:
                dn = conn.entries[0].distinguishedName.value
                # userAccountControl: 514 = Disabled
                conn.modify(dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [514])]})
                print(f"[+] AD account disabled: {username}")
                return True
        except Exception as e:
            print(f"[-] Failed to disable {username}: {e}")
        return False

    def isolate_host_edr(self, hostname: str) -> bool:
        """แยก host จากเครือข่ายผ่าน EDR API"""
        edr_url = self.config.get("edr_api_url", "")
        if not edr_url:
            print(f"[SIMULATION] Isolate host: {hostname}")
            return True
        try:
            resp = requests.post(
                f"{edr_url}/isolate/{hostname}",
                headers={"Authorization": f"Bearer {self.config.get('edr_api_key')}"},
                timeout=10
            )
            return resp.status_code == 200
        except Exception:
            return False

    # === NOTIFICATION ===

    def notify_slack(self, message: str, channel: str = "#soc-alerts") -> bool:
        """Send Slack notification"""
        if not self.slack_webhook:
            print(f"[NOTIFICATION] Slack: {message}")
            return True
        try:
            resp = requests.post(
                self.slack_webhook,
                json={"channel": channel, "text": message},
                timeout=10
            )
            return resp.status_code == 200
        except Exception:
            return False

    def create_jira_ticket(
        self, summary: str, description: str, priority: str = "High"
    ) -> Optional[str]:
        """Create JIRA incident ticket"""
        jira_url = self.config.get("jira_url", "")
        if not jira_url:
            print(f"[SIMULATION] JIRA ticket: {summary}")
            return "SIM-001"
        try:
            resp = requests.post(
                f"{jira_url}/rest/api/2/issue",
                json={
                    "fields": {
                        "project": {"key": self.config.get("jira_project", "SOC")},
                        "summary": summary,
                        "description": description,
                        "issuetype": {"name": "Incident"},
                        "priority": {"name": priority}
                    }
                },
                auth=(self.config.get("jira_user"), self.config.get("jira_token")),
                timeout=10
            )
            if resp.status_code == 201:
                return resp.json()["key"]
        except Exception as e:
            print(f"[-] JIRA failed: {e}")
        return None

    # === PLAYBOOKS ===

    def run_phishing_playbook(self, alert: Alert) -> Alert:
        """เย็นอัตโนมัติสำหรับ phishing alerts"""
        print(f"[*] Running Phishing Playbook for {alert.alert_id}")

        # Step 1: Enrich
        if alert.src_ip:
            alert.enrichment["src_ip"] = self.enrich_ip(alert.src_ip)
        if alert.url:
            alert.enrichment["url"] = self.enrich_url(alert.url)
        if alert.file_hash:
            alert.enrichment["file"] = self.enrich_hash(alert.file_hash)

        # Step 2: Score
        score = 0
        if alert.enrichment.get("src_ip", {}).get("vt_malicious", 0) > 5:
            score += 40
        if alert.enrichment.get("url", {}).get("malicious", 0) > 3:
            score += 30
        if alert.enrichment.get("file", {}).get("malicious", 0) > 10:
            score += 30

        alert.enrichment["risk_score"] = score

        # Step 3: Auto-contain ถ้า score สูง
        if score >= 70:
            if alert.src_ip:
                if self.block_ip_firewall(alert.src_ip, f"Phishing: {alert.alert_id}"):
                    alert.actions_taken.append(f"BLOCKED IP: {alert.src_ip}")
            if alert.username:
                if self.disable_ad_account(alert.username, f"Phishing suspect: {alert.alert_id}"):
                    alert.actions_taken.append(f"DISABLED ACCOUNT: {alert.username}")
            alert.disposition = "true_positive"

        elif score < 20:
            alert.disposition = "false_positive"

        # Step 4: Notify
        msg = (
            f":warning: *Phishing Alert* - {alert.alert_id}\n"
            f"Score: {score}/100 | Disposition: {alert.disposition}\n"
            f"Actions: {', '.join(alert.actions_taken) or 'none'}\n"
            f"Sender: {alert.email_sender} | Subject: {alert.email_subject}"
        )
        self.notify_slack(msg)

        # Step 5: Create ticket ถ้า true positive
        if alert.disposition == "true_positive":
            ticket = self.create_jira_ticket(
                f"Phishing Incident: {alert.alert_id}",
                f"Score: {score}\nEnrichment: {json.dumps(alert.enrichment, indent=2)}",
                priority="High" if score >= 70 else "Medium"
            )
            if ticket:
                alert.actions_taken.append(f"JIRA: {ticket}")

        print(f"[+] Playbook complete. Score: {score}, Disposition: {alert.disposition}")
        print(f"    Actions: {alert.actions_taken}")
        return alert

    def run_brute_force_playbook(self, alert: Alert) -> Alert:
        """เย็นอัตโนมัติสำหรับ brute force alerts"""
        print(f"[*] Running Brute Force Playbook for {alert.alert_id}")

        # Enrich source IP
        if alert.src_ip:
            alert.enrichment["src_ip"] = self.enrich_ip(alert.src_ip)

        # Auto-block external IPs with high abuse score
        abuse_score = alert.enrichment.get("src_ip", {}).get("abuse_score", 0)
        if abuse_score > 50:
            self.block_ip_firewall(alert.src_ip, f"Brute Force: {alert.alert_id}")
            alert.actions_taken.append(f"BLOCKED IP: {alert.src_ip}")
            alert.disposition = "true_positive"

        # ถ้ามี username ที่ถูก target: รีเซ็ต password
        if alert.username and alert.disposition == "true_positive":
            self.notify_slack(
                f":lock: Force password reset for `{alert.username}` - brute force detected",
                channel="#it-helpdesk"
            )
            alert.actions_taken.append(f"PASSWORD RESET REQUESTED: {alert.username}")

        self.notify_slack(
            f":rotating_light: *Brute Force* - {alert.alert_id}\n"
            f"Source: {alert.src_ip} (Abuse Score: {abuse_score})\n"
            f"Target: {alert.username}\n"
            f"Actions: {', '.join(alert.actions_taken) or 'review required'}"
        )
        return alert


# ตัวอย่างการใช้งาน
config = {
    "virustotal_api_key": "YOUR_VT_KEY",
    "abuseipdb_key": "YOUR_ABUSEIPDB_KEY",
    "slack_webhook": "https://hooks.slack.com/...",
    "jira_url": "https://company.atlassian.net",
    "jira_project": "SOC",
    "jira_user": "soc@company.com",
    "jira_token": "YOUR_JIRA_TOKEN"
}

soar = SOARPlaybook(config)
phishing_alert = Alert(
    alert_id="ALT-2024-0115-001",
    alert_type="phishing",
    severity="high",
    src_ip="185.220.101.45",
    username="john.smith",
    email_sender="ceo@company-inc.ru",
    email_subject="Urgent: Please review attached invoice",
    file_hash="a1b2c3d4e5f6..."
)
result = soar.run_phishing_playbook(phishing_alert)
```

---

## 3. Automated Vulnerability Management

### 3.1 Continuous Scanning Pipeline
```python
#!/usr/bin/env python3
# vuln_management.py — จัดการช่องโหว่องอัตโนมัติ

import subprocess
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime
import requests

@dataclass
class Vulnerability:
    vuln_id: str
    cve_id: str
    host: str
    port: int
    service: str
    severity: str
    cvss_score: float
    description: str
    solution: str
    first_seen: str
    last_seen: str
    status: str = "open"  # open, in_remediation, closed, accepted_risk
    ticket_id: str = ""


class VulnerabilityManager:
    """
    จัดการช่องโหว่ scan, track, remediation
    """

    def __init__(self):
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.scan_history = []

    def run_nmap_scan(
        self, targets: str, ports: str = "1-65535"
    ) -> list:
        """Run nmap และ parse ผล"""
        cmd = [
            "nmap", "-sV", "-sC", "--script", "vuln",
            "-p", ports, targets, "-oX", "/tmp/nmap_scan.xml"
        ]
        print(f"[*] Running nmap: {' '.join(cmd)}")
        subprocess.run(cmd, capture_output=True)
        return self._parse_nmap_xml("/tmp/nmap_scan.xml")

    def _parse_nmap_xml(self, xml_path: str) -> list:
        """Parse nmap XML output"""
        findings = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for host in root.findall("host"):
                addr = host.find("address")
                ip = addr.get("addr") if addr is not None else ""
                for port in host.findall(".//port"):
                    port_id = port.get("portid")
                    service = port.find("service")
                    svc_name = service.get("name", "") if service is not None else ""
                    # Parse script output for vulnerabilities
                    for script in port.findall("script"):
                        script_id = script.get("id", "")
                        output = script.get("output", "")
                        if "VULNERABLE" in output or "CVE" in output:
                            findings.append({
                                "host": ip,
                                "port": int(port_id),
                                "service": svc_name,
                                "script": script_id,
                                "output": output
                            })
        except Exception as e:
            print(f"[-] Parse error: {e}")
        return findings

    def run_nuclei_scan(
        self, targets: str, severity: str = "critical,high"
    ) -> list:
        """Run Nuclei vulnerability scanner"""
        cmd = [
            "nuclei", "-target", targets,
            "-severity", severity,
            "-json", "-o", "/tmp/nuclei_results.json"
        ]
        subprocess.run(cmd, capture_output=True)
        findings = []
        try:
            with open("/tmp/nuclei_results.json") as f:
                for line in f:
                    findings.append(json.loads(line))
        except Exception:
            pass
        return findings

    def enrich_with_nvd(self, cve_id: str) -> dict:
        """Enrich CVE ด้วย NVD API"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data["totalResults"] > 0:
                    vuln = data["vulnerabilities"][0]["cve"]
                    metrics = vuln.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0]
                    score = cvss_v3.get("cvssData", {}).get("baseScore", 0)
                    return {
                        "cve_id": cve_id,
                        "cvss_score": score,
                        "description": vuln["descriptions"][0]["value"][:200],
                        "published": vuln["published"]
                    }
        except Exception as e:
            return {"error": str(e)}
        return {}

    def prioritize_vulnerabilities(
        self, vulns: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        จัดลำดับความสำคัญของช่องโหว่
        โดยใช้ CVSS + asset criticality + exploitability
        """
        ASSET_WEIGHTS = {
            "dc01": 10, "payment-server": 9, "mail-server": 7,
            "web-server": 6, "workstation": 3
        }
        for v in vulns:
            asset_weight = max(
                (w for k, w in ASSET_WEIGHTS.items() if k in v.host.lower()),
                default=3
            )
            v.priority_score = v.cvss_score * asset_weight

        return sorted(vulns, key=lambda v: getattr(v, 'priority_score', 0), reverse=True)

    def generate_report(self, output: str = "vuln_report.html") -> str:
        """Generate vulnerability management report"""
        open_vulns = [v for v in self.vulnerabilities.values() if v.status == "open"]
        by_severity = {
            "Critical": [v for v in open_vulns if v.cvss_score >= 9.0],
            "High": [v for v in open_vulns if 7.0 <= v.cvss_score < 9.0],
            "Medium": [v for v in open_vulns if 4.0 <= v.cvss_score < 7.0],
            "Low": [v for v in open_vulns if v.cvss_score < 4.0]
        }

        html = f"""<!DOCTYPE html>
<html><head><title>Vulnerability Report</title>
<style>body{{font-family:Arial}} .critical{{color:red}} .high{{color:orange}} table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #ddd;padding:8px}}</style>
</head><body>
<h1>Vulnerability Management Report</h1>
<p>Generated: {datetime.utcnow().isoformat()}</p>
<h2>Summary</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
"""
        for sev, items in by_severity.items():
            css = sev.lower()
            html += f"<tr class='{css}'><td>{sev}</td><td>{len(items)}</td></tr>\n"
        html += "</table><h2>Top Vulnerabilities</h2><table>"
        html += "<tr><th>Host</th><th>CVE</th><th>CVSS</th><th>Description</th><th>Status</th></tr>\n"

        for v in sorted(open_vulns, key=lambda x: x.cvss_score, reverse=True)[:20]:
            html += f"<tr><td>{v.host}</td><td>{v.cve_id}</td><td>{v.cvss_score}</td><td>{v.description[:100]}</td><td>{v.status}</td></tr>\n"

        html += "</table></body></html>"
        with open(output, 'w') as f:
            f.write(html)
        return output
```

---

## 4. CI/CD Security Pipeline

### 4.1 GitHub Actions Security Workflow
```yaml
# .github/workflows/security-pipeline.yml
name: Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  sast:
    name: Static Analysis (SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Bandit (Python)
        run: |
          pip install bandit
          bandit -r . -f json -o bandit_results.json || true
          cat bandit_results.json

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/python

      - name: Upload SAST Results
        uses: actions/upload-artifact@v3
        with:
          name: sast-results
          path: bandit_results.json

  sca:
    name: Dependency Scanning (SCA)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Trivy SCA Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'CRITICAL,HIGH'
          format: 'json'
          output: 'trivy-results.json'

      - name: Safety Check (Python deps)
        run: |
          pip install safety
          safety check --json > safety_results.json || true

  secrets-scan:
    name: Secret Detection
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history สำหรับ gitleaks

      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  container-scan:
    name: Container Image Scan
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    steps:
      - uses: actions/checkout@v4

      - name: Build Image
        run: docker build -t app:${{ github.sha }} .

      - name: Trivy Container Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: app:${{ github.sha }}
          severity: 'CRITICAL,HIGH'
          exit-code: '1'  # Fail pipeline ถ้าเจอ Critical

  dast:
    name: Dynamic Analysis (DAST)
    runs-on: ubuntu-latest
    needs: [sast, sca]
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4

      - name: Start Application
        run: |
          docker-compose up -d
          sleep 10

      - name: OWASP ZAP Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'

      - name: Stop Application
        run: docker-compose down
```

### 4.2 Pre-commit Security Hooks
```python
#!/usr/bin/env python3
# pre_commit_security.py — pre-commit hook ตรวจความปลอดภัย

import re
import sys
import subprocess
from pathlib import Path

class SecurityPreCommit:
    """
    Pre-commit hook ตรวจและป้องกัน secrets/hardcoded creds ก่อน commit
    """

    SECRET_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{6,}["\']', "Hardcoded password"),
        (r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded API key"),
        (r'(?i)(secret|token)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret/token"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'(?i)aws_secret_access_key\s*=\s*[^\'"\s]{20,}', "AWS Secret Key"),
        (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private key in code"),
        (r'(?i)basic\s+[a-zA-Z0-9+/]{20,}={0,2}', "Base64-encoded Basic auth"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    ]

    DANGEROUS_PATTERNS = [
        (r'eval\(.*request\[', "eval() with user input — potential RCE"),
        (r'os\.system\(.*request', "os.system() with user input — command injection"),
        (r'subprocess.*shell=True.*request', "subprocess shell=True with user input"),
        (r'execute\(.*%.*request', "SQL format string — potential SQL injection"),
        (r'innerHTML\s*=\s*.*\+', "innerHTML concatenation — potential XSS"),
        (r'document\.write\(', "document.write() — potential XSS"),
    ]

    def check_file(self, file_path: str) -> list:
        issues = []
        try:
            content = Path(file_path).read_text(errors='replace')
        except Exception:
            return issues

        for lineno, line in enumerate(content.splitlines(), 1):
            for pattern, desc in self.SECRET_PATTERNS:
                if re.search(pattern, line):
                    issues.append({
                        "file": file_path,
                        "line": lineno,
                        "type": "SECRET",
                        "description": desc,
                        "content": line.strip()[:100]
                    })

            for pattern, desc in self.DANGEROUS_PATTERNS:
                if re.search(pattern, line):
                    issues.append({
                        "file": file_path,
                        "line": lineno,
                        "type": "VULNERABILITY",
                        "description": desc,
                        "content": line.strip()[:100]
                    })
        return issues

    def run(self) -> int:
        """ตรวจ staged files"""
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True
        )
        staged_files = result.stdout.strip().splitlines()

        all_issues = []
        for f in staged_files:
            if Path(f).exists():
                issues = self.check_file(f)
                all_issues.extend(issues)

        if all_issues:
            print("\n[!] SECURITY ISSUES FOUND — COMMIT BLOCKED")
            print("=" * 60)
            for issue in all_issues:
                print(f"  [{issue['type']}] {issue['file']}:{issue['line']}")
                print(f"    {issue['description']}")
                print(f"    >> {issue['content']}")
                print()
            print("Fix these issues before committing.")
            print("To skip (NOT recommended): git commit --no-verify")
            return 1

        print("[+] Security pre-commit check passed")
        return 0


if __name__ == "__main__":
    checker = SecurityPreCommit()
    sys.exit(checker.run())
```

---

## 5. Automated Threat Intelligence

### 5.1 MISP Integration
```python
#!/usr/bin/env python3
# threat_intel_automation.py — จัดการ threat intel อัตโนมัติ

from pymisp import PyMISP, MISPEvent, MISPAttribute
from datetime import datetime, timedelta
from typing import List, Dict
import json
import requests

class ThreatIntelAutomation:
    """
    ดึง IOCs จากแหล่งต่างๆ และแบ่ปันเข้า MISP อัตโนมัติ
    """

    def __init__(self, misp_url: str, misp_key: str):
        self.misp = PyMISP(misp_url, misp_key, ssl=False)
        self.ioc_cache = set()  # avoid duplicates

    def fetch_otx_iocs(
        self, api_key: str, days: int = 1
    ) -> List[Dict]:
        """ดึง IOCs จาก AlienVault OTX"""
        since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since={since}"
        headers = {"X-OTX-API-KEY": api_key}

        iocs = []
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            pulses = resp.json().get("results", [])
            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    iocs.append({
                        "type": indicator["type"],
                        "value": indicator["indicator"],
                        "source": f"OTX:{pulse['name']}",
                        "tlp": "white"
                    })
        except Exception as e:
            print(f"[-] OTX error: {e}")
        return iocs

    def fetch_abuse_ch_iocs(self) -> List[Dict]:
        """ดึง IOCs จาก abuse.ch (Feodo Tracker, URLhaus)"""
        iocs = []

        # Feodo Tracker (botnet C2)
        try:
            resp = requests.get(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                timeout=30
            )
            for entry in resp.json().get("blocklist", []):
                iocs.append({
                    "type": "ip-dst",
                    "value": entry["ip_address"],
                    "source": f"Feodo:{entry.get('malware', 'unknown')}",
                    "tlp": "white"
                })
        except Exception as e:
            print(f"[-] Feodo error: {e}")

        # URLhaus
        try:
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/",
                timeout=30
            )
            for entry in resp.json().get("urls", []):
                if entry["url_status"] == "online":
                    iocs.append({
                        "type": "url",
                        "value": entry["url"],
                        "source": f"URLhaus:{entry.get('threat', 'unknown')}",
                        "tlp": "white"
                    })
        except Exception as e:
            print(f"[-] URLhaus error: {e}")

        return iocs

    def push_to_misp(
        self, iocs: List[Dict], event_name: str
    ) -> str:
        """Push IOCs เข้า MISP event"""
        event = MISPEvent()
        event.info = event_name
        event.distribution = 0  # Your org only
        event.threat_level_id = 2  # Medium
        event.analysis = 2  # Completed

        # TLP tag
        event.add_tag("tlp:white")

        new_iocs = 0
        for ioc in iocs:
            ioc_key = f"{ioc['type']}:{ioc['value']}"
            if ioc_key in self.ioc_cache:
                continue
            self.ioc_cache.add(ioc_key)

            attr = event.add_attribute(ioc["type"], ioc["value"])
            attr.comment = ioc.get("source", "")
            attr.to_ids = True  # ใช้สำหรับ IDS/firewall detection
            new_iocs += 1

        if new_iocs > 0:
            result = self.misp.add_event(event)
            event_id = result["Event"]["id"]
            print(f"[+] MISP event created: {event_id} ({new_iocs} IOCs)")
            return event_id
        else:
            print("[*] No new IOCs to push")
            return ""

    def export_to_firewall(
        self, ioc_type: str = "ip-dst"
    ) -> List[str]:
        """Export IOCs สำหรับใช้ใน firewall blocklist"""
        iocs = []
        try:
            events = self.misp.search(
                type_attribute=ioc_type,
                to_ids=True,
                last="1d"
            )
            for event in events:
                for attr in event.get("Attribute", []):
                    if attr["type"] == ioc_type:
                        iocs.append(attr["value"])
        except Exception as e:
            print(f"[-] Export error: {e}")
        return list(set(iocs))

    def run_daily_intel(
        self, otx_key: str
    ):
        """Run ทุกวัน: fetch + push + export"""
        print("[*] Starting daily threat intelligence collection...")

        all_iocs = []
        all_iocs.extend(self.fetch_otx_iocs(otx_key, days=1))
        all_iocs.extend(self.fetch_abuse_ch_iocs())

        print(f"[+] Collected {len(all_iocs)} IOCs from all sources")

        if all_iocs:
            date = datetime.utcnow().strftime("%Y-%m-%d")
            self.push_to_misp(all_iocs, f"Daily Threat Intel {date}")

        # Export for firewall
        ip_blocklist = self.export_to_firewall("ip-dst")
        with open("/etc/firewall/blocklist.txt", "w") as f:
            f.write("\n".join(ip_blocklist))
        print(f"[+] Firewall blocklist updated: {len(ip_blocklist)} IPs")
```

---

## 6. AI Integration

### 6.1 Security Chatbot
```python
#!/usr/bin/env python3
# security_bot.py — AI-powered security assistant สำหรับ SOC

import json
import requests
from typing import List, Dict

class SecurityBot:
    """
    AI Security Bot สำหรับ SOC analysts
    ใช้ LLM ช่วย triage และอธิบาย alerts
    """

    def __init__(self, api_key: str, model: str = "claude-opus-5-5"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.anthropic.com/v1"

    def analyze_alert(self, alert: dict) -> str:
        """Analyze security alert ด้วย AI"""
        prompt = f"""You are a senior SOC analyst. Analyze this security alert and provide:
1. Brief description (1 sentence)
2. Severity assessment (Critical/High/Medium/Low) with reasoning
3. Is this likely a True Positive or False Positive? Why?
4. Recommended immediate actions (bullet points)
5. MITRE ATT&CK technique if applicable

Alert:
{json.dumps(alert, indent=2)}

Respond concisely in under 200 words."""

        return self._call_llm(prompt)

    def explain_sigma_rule(self, rule_yaml: str) -> str:
        """อธิบาย SIGMA rule ด้วยภาษาธรรมดา"""
        prompt = f"""Explain this SIGMA detection rule in plain language for a non-technical stakeholder. Include:
1. What attacker behavior this detects
2. Why this is suspicious
3. When this might fire as a false positive

SIGMA Rule:
{rule_yaml}"""
        return self._call_llm(prompt)

    def suggest_hunting_queries(
        self, threat_intel: str, siem_type: str = "splunk"
    ) -> str:
        """Suggest threat hunting queries จาก threat intelligence"""
        prompt = f"""Based on this threat intelligence, generate 5 {siem_type} queries for threat hunting.
Each query should detect a different aspect of the described activity.
Format: numbered list with explanation for each query.

Threat Intel:
{threat_intel}"""
        return self._call_llm(prompt)

    def triage_email(
        self, email_content: str, headers: str
    ) -> dict:
        """Triage phishing email อัตโนมัติ"""
        prompt = f"""Analyze this email for phishing indicators. Return a JSON object with:
{{
  "is_phishing": true/false,
  "confidence": 0-100,
  "indicators": [list of suspicious indicators found],
  "technique": "spearphishing/bulk/etc",
  "recommendation": "block/quarantine/allow"
}}

Email Headers:
{headers}

Email Content:
{email_content[:2000]}

Return ONLY valid JSON."""
        response = self._call_llm(prompt)
        try:
            return json.loads(response)
        except Exception:
            return {"error": "Parse failed", "raw": response}

    def _call_llm(self, prompt: str) -> str:
        """Call Claude API"""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        data = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}]
        }
        resp = requests.post(
            f"{self.base_url}/messages",
            headers=headers, json=data, timeout=30
        )
        if resp.status_code == 200:
            return resp.json()["content"][0]["text"]
        return f"Error: {resp.status_code}"


# ตัวอย่างการใช้งาน
bot = SecurityBot(api_key="YOUR_CLAUDE_API_KEY")
alert_sample = {
    "event_id": "4625",
    "src_ip": "185.220.101.45",
    "username": "administrator",
    "count": 247,
    "timeframe_minutes": 5,
    "dest_host": "DC01"
}
analysis = bot.analyze_alert(alert_sample)
print(analysis)
```

---

## 7. IaC Security

### 7.1 Terraform Security Scanning
```bash
# ติดตั้ง tfsec และ checkov
pip install checkov
brew install tfsec  # macOS

# Scan Terraform code
tfsec ./ --format json --out tfsec_results.json
checkov -d . --framework terraform --output json > checkov_results.json

# Scan Dockerfile
checkov -f Dockerfile --framework dockerfile

# Scan Kubernetes manifests
checkov -d k8s/ --framework kubernetes
```

```python
#!/usr/bin/env python3
# iac_security.py — ตรวจสอบความปลอดภัยของ Infrastructure as Code

import subprocess
import json
from pathlib import Path

class IaCSecurityScanner:
    def __init__(self):
        self.findings = []

    def scan_terraform(self, tf_dir: str) -> list:
        """Scan Terraform ด้วย tfsec"""
        result = subprocess.run(
            ["tfsec", tf_dir, "--format", "json"],
            capture_output=True, text=True
        )
        try:
            data = json.loads(result.stdout)
            findings = []
            for r in data.get("results", []):
                findings.append({
                    "tool": "tfsec",
                    "severity": r["severity"],
                    "rule": r["rule_id"],
                    "description": r["description"],
                    "file": r["location"]["filename"],
                    "line": r["location"]["start_line"],
                    "resolution": r["resolution"]
                })
            return findings
        except Exception as e:
            print(f"[-] tfsec parse error: {e}")
            return []

    def scan_dockerfile(self, dockerfile: str) -> list:
        """Scan Dockerfile ด้วย Hadolint"""
        result = subprocess.run(
            ["hadolint", dockerfile, "--format", "json"],
            capture_output=True, text=True
        )
        try:
            data = json.loads(result.stdout)
            findings = []
            for item in data:
                findings.append({
                    "tool": "hadolint",
                    "severity": item["level"],
                    "rule": item["code"],
                    "description": item["message"],
                    "file": dockerfile,
                    "line": item["line"]
                })
            return findings
        except Exception:
            return []

    def check_k8s_rbac(self, k8s_dir: str) -> list:
        """Check Kubernetes RBAC และสิทธิ์ที่มากเกินไป"""
        issues = []
        for yaml_file in Path(k8s_dir).rglob("*.yaml"):
            content = yaml_file.read_text()
            # ตรวจ ClusterAdmin ที่ให้กับทุก subject
            if "cluster-admin" in content and "subjects" in content:
                if "kind: ServiceAccount" in content:
                    issues.append({
                        "file": str(yaml_file),
                        "issue": "ServiceAccount with cluster-admin role",
                        "severity": "HIGH"
                    })
            # ตรวจ privileged: true
            if "privileged: true" in content:
                issues.append({
                    "file": str(yaml_file),
                    "issue": "Privileged container",
                    "severity": "CRITICAL"
                })
            # ตรวจ runAsRoot
            if "runAsUser: 0" in content:
                issues.append({
                    "file": str(yaml_file),
                    "issue": "Container running as root (UID 0)",
                    "severity": "HIGH"
                })
        return issues

    def generate_report(self) -> str:
        critical = [f for f in self.findings if f.get("severity") in ["CRITICAL", "critical", "ERROR", "error"]]
        high = [f for f in self.findings if f.get("severity") in ["HIGH", "high", "WARNING", "warning"]]
        report = f"IaC Security Report\n"
        report += f"Critical: {len(critical)} | High: {len(high)} | Total: {len(self.findings)}\n\n"
        for f in critical + high:
            report += f"[{f.get('severity', 'UNKNOWN')}] {f.get('file')}:{f.get('line', '?')}\n"
            report += f"  {f.get('rule', '')} — {f.get('description', f.get('issue', ''))}\n\n"
        return report
```

---

## 8. Compliance

### 8.1 Automated CIS Benchmark Checking
```python
#!/usr/bin/env python3
# cis_checker.py — ตรวจสอบ CIS Benchmark อัตโนมัติ

import subprocess
import os
import stat
from pathlib import Path
from dataclasses import dataclass, field
from typing import List

@dataclass
class CheckResult:
    check_id: str
    description: str
    status: str         # PASS, FAIL, MANUAL
    severity: str       # Level 1, Level 2
    remediation: str = ""
    actual_value: str = ""


class CISLinuxChecker:
    """
    ตรวจ CIS Benchmark สำหรับ Linux (Ubuntu/RHEL)
    """

    def __init__(self):
        self.results: List[CheckResult] = []

    def _run(self, cmd: str) -> str:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()

    def check_filesystem_permissions(self) -> List[CheckResult]:
        results = []

        # CIS 1.1.1: /tmp noexec
        fstab = self._run("cat /etc/fstab")
        has_tmp_noexec = "noexec" in fstab and "/tmp" in fstab
        results.append(CheckResult(
            check_id="CIS-1.1.1",
            description="/tmp partition has noexec option",
            status="PASS" if has_tmp_noexec else "FAIL",
            severity="Level 1",
            remediation="Add noexec to /tmp mount options in /etc/fstab"
        ))

        # CIS 1.4: GRUB bootloader password
        grub = self._run("grep -r 'password' /boot/grub/grub.cfg 2>/dev/null")
        results.append(CheckResult(
            check_id="CIS-1.4.2",
            description="GRUB bootloader password set",
            status="PASS" if grub else "FAIL",
            severity="Level 1",
            remediation="Set GRUB password with grub-mkpasswd-pbkdf2"
        ))

        return results

    def check_user_accounts(self) -> List[CheckResult]:
        results = []

        # ตรวจ accounts ที่มี empty password
        shadow = self._run("sudo awk -F: '($2 == \"\" ) {print}' /etc/shadow")
        results.append(CheckResult(
            check_id="CIS-6.2.2",
            description="No accounts with empty passwords",
            status="PASS" if not shadow else "FAIL",
            severity="Level 1",
            actual_value=shadow,
            remediation="Lock or set passwords for all accounts"
        ))

        # ตรวจ UID 0 accounts นอกจาก root
        uid0 = self._run("awk -F: '($3 == 0) {print}' /etc/passwd")
        uid0_accounts = [a for a in uid0.splitlines() if not a.startswith("root")]
        results.append(CheckResult(
            check_id="CIS-6.2.5",
            description="Only root has UID 0",
            status="PASS" if not uid0_accounts else "FAIL",
            severity="Level 1",
            actual_value=", ".join(uid0_accounts),
            remediation="Remove UID 0 from non-root accounts"
        ))

        return results

    def check_network_config(self) -> List[CheckResult]:
        results = []

        # ตรวจ IP forwarding
        ip_forward = self._run("sysctl net.ipv4.ip_forward")
        status = "PASS" if "= 0" in ip_forward else "FAIL"
        results.append(CheckResult(
            check_id="CIS-3.1.1",
            description="IP forwarding disabled",
            status=status,
            severity="Level 1",
            actual_value=ip_forward,
            remediation="Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf"
        ))

        # ตรวจ ICMP redirects
        icmp = self._run("sysctl net.ipv4.conf.all.accept_redirects")
        status = "PASS" if "= 0" in icmp else "FAIL"
        results.append(CheckResult(
            check_id="CIS-3.2.2",
            description="ICMP redirects not accepted",
            status=status,
            severity="Level 1",
            actual_value=icmp,
            remediation="Set net.ipv4.conf.all.accept_redirects = 0"
        ))

        return results

    def check_ssh_config(self) -> List[CheckResult]:
        results = []
        sshd = Path("/etc/ssh/sshd_config")
        if not sshd.exists():
            return results

        content = sshd.read_text()
        checks = [
            ("PermitRootLogin no", "CIS-5.2.6", "SSH root login disabled"),
            ("PermitEmptyPasswords no", "CIS-5.2.10", "SSH empty passwords disabled"),
            ("Protocol 2", "CIS-5.2.1", "SSH Protocol 2 enforced"),
            ("MaxAuthTries 4", "CIS-5.2.8", "SSH MaxAuthTries <= 4"),
            ("X11Forwarding no", "CIS-5.2.5", "SSH X11 forwarding disabled"),
        ]
        for config, check_id, desc in checks:
            key = config.split()[0]
            value = config.split()[1]
            actual = self._run(f"grep -i '{key}' /etc/ssh/sshd_config | grep -v '#'")
            status = "PASS" if actual and value in actual else "FAIL"
            results.append(CheckResult(
                check_id=check_id,
                description=desc,
                status=status,
                severity="Level 1",
                actual_value=actual,
                remediation=f"Set '{config}' in /etc/ssh/sshd_config"
            ))
        return results

    def run_all_checks(self) -> None:
        self.results.extend(self.check_filesystem_permissions())
        self.results.extend(self.check_user_accounts())
        self.results.extend(self.check_network_config())
        self.results.extend(self.check_ssh_config())

    def generate_report(self) -> str:
        passed = [r for r in self.results if r.status == "PASS"]
        failed = [r for r in self.results if r.status == "FAIL"]
        score = len(passed) / len(self.results) * 100 if self.results else 0

        report = f"CIS Benchmark Report\n"
        report += f"Score: {score:.1f}% ({len(passed)}/{len(self.results)})\n\n"
        report += "FAILURES:\n"
        for r in failed:
            report += f"  [{r.severity}] {r.check_id}: {r.description}\n"
            if r.actual_value:
                report += f"    Actual: {r.actual_value}\n"
            report += f"    Fix: {r.remediation}\n\n"
        return report


checker = CISLinuxChecker()
checker.run_all_checks()
print(checker.generate_report())
```

---

## 9. Lab

### แบบฝึกหัด: SOAR Integration Exercise

```bash
# Step 1: ติดตั้ง Shuffle SOAR (open-source)
git clone https://github.com/frikky/Shuffle
cd Shuffle
docker-compose up -d
# เข้าถึง: http://localhost:3001

# Step 2: ติดตั้ง OpenCTI สำหรับ threat intelligence
docker pull opencti/platform:latest
# สร้าง docker-compose.yml สำหรับ OpenCTI

# Step 3: ติดตั้ง TheHive + Cortex (IR platform)
wget -q -O /etc/apt/trusted.gpg.d/strangebee.gpg https://repo.strangebee.com/key.gpg
apt install thehive cortex

# Step 4: ติดตั้ง security scanning tools
pip install bandit safety pymisp
npm install -g retire.js
go install github.com/trufflesecurity/trufflehog/v3@latest

# Step 5: ทดสอบ pre-commit hooks
pip install pre-commit
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
EOF
pre-commit install
pre-commit run --all-files

# Step 6: ทดสอบ SOAR playbook ด้วย simulated alert
python3 soar_playbook.py
```

---

## สรุป Security Automation

| หมวดหมู่ | เครื่องมือ | ประโยชน์ |
|---|---|---|
| SOAR | Shuffle, XSOAR, Splunk SOAR | Automated response, playbooks |
| Vuln Mgmt | Nuclei, nmap, OpenVAS | Continuous scanning |
| CI/CD Security | GitHub Actions, Semgrep, Trivy | Shift-left security |
| Threat Intel | MISP, OTX, abuse.ch | Automated IOC management |
| AI/LLM | Claude API | Alert triage, threat analysis |
| IaC Security | tfsec, checkov, hadolint | Cloud misconfig detection |
| Compliance | OpenSCAP, Lynis, CIS-CAT | Automated benchmark checking |
| Secret Detection | Gitleaks, TruffleHog, detect-secrets | Pre-commit, CI scanning |

---

← [Part 87: Blue Team & Defensive Security](Part-87-Blue-Team-Defensive.md) | [Part 89: Cloud Security](Part-89-Cloud-Security.md) →
