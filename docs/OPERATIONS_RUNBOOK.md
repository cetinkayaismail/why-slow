# Enterprise Operations & Production SRE Runbook

This runbook outlines deployment topologies, 24/7 continuous sentinel monitoring, incident response Standard Operating Procedures (SOP), and Failure Modes and Effects Analysis (FMEA) for operating `why-slow` in mission-critical banking and enterprise environments.

---

## 🏛️ Enterprise Deployment Topologies

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SUPPORTED DEPLOYMENT TOPOLOGIES                        │
├───────────────────────┬─────────────────────────────────────────────────────┤
│ Infrastructure Type   │ Recommended Deployment Model                        │
├───────────────────────┼─────────────────────────────────────────────────────┤
│ Bare-Metal Clusters   │ Standalone binary deployed via Ansible/Chef/Puppet   │
│ Enterprise VMs        │ Systemd Sentinel Service unit (`--watch`)           │
│ Kubernetes / OpenShift│ Node DaemonSet with hostPID and read-only host /proc│
│ Air-Gapped Enclaves   │ Offline pre-compiled pure Go static binary          │
└───────────────────────┴─────────────────────────────────────────────────────┘
```

---

## ☸️ Kubernetes Node DaemonSet Deployment

Deploying `why-slow` as an unprivileged Kubernetes `DaemonSet` provides continuous node-level performance diagnostic telemetry across all cluster worker nodes.

### Production DaemonSet Manifest (`why-slow-daemonset.yaml`)

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: why-slow-sentinel
  namespace: kube-system
  labels:
    app.kubernetes.io/name: why-slow
    app.kubernetes.io/part-of: infrastructure-diagnostics
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: why-slow
  template:
    metadata:
      labels:
        app.kubernetes.io/name: why-slow
    spec:
      hostPID: true
      hostNetwork: false
      tolerations:
        - operator: Exists
          effect: NoSchedule
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: sentinel
          image: internal-registry.bank.corp/infrastructure/why-slow:v0.4.0
          args:
            - "--watch"
            - "--interval"
            - "3s"
            - "--alert-threshold"
            - "high"
            - "--json"
            - "--compact"
          resources:
            requests:
              cpu: "10m"
              memory: "16Mi"
            limits:
              cpu: "100m"
              memory: "32Mi"
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: host-proc
              mountPath: /proc
              readOnly: true
            - name: host-sys
              mountPath: /sys
              readOnly: true
      volumes:
        - name: host-proc
          hostPath:
            path: /proc
        - name: host-sys
          hostPath:
            path: /sys
```

---

## 🖥️ Systemd Sentinel Service (Bare-Metal & Virtual Machines)

For dedicated Linux servers (e.g. Oracle, PostgreSQL, Kafka, or trading gateway nodes), deploy `why-slow` as a supervised systemd sentinel service.

### Service Unit File (`/etc/systemd/system/why-slow-sentinel.service`)

```ini
[Unit]
Description=why-slow — Linux Diagnostic Sentinel Engine
After=network.target
Documentation=https://github.com/cetinkayaismail/why-slow

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/why-slow --watch --interval 3s --alert-threshold high --json --compact
Restart=always
RestartSec=5s

# Security Hardening Directives (CIS Compliant)
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
RestrictSUIDSGID=true
MemoryMax=32M
CPUQuota=2%

# Standard logging to journald for SIEM forwarder ingestion
StandardOutput=journal
StandardError=journal
SyslogIdentifier=why-slow

[Install]
WantedBy=multi-user.target
```

### Activation Commands
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now why-slow-sentinel.service
sudo systemctl status why-slow-sentinel.service
```

---

## 🚨 Incident Response Standard Operating Procedures (SOP)

When a server experiences performance degradation, high latency, or alert storms, follow this three-phase triage procedure:

```
                      INCIDENT TRIAGE WORKFLOW
                                 │
     Phase 1: Instant Root Cause Isolation
     Execute: why-slow (or sudo why-slow)
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       Tier 1 Hard Limit               Tier 2/3 Contention
       (CPU/RAM/Disk/Thermal)         (Locks, Queues, Throttling)
                 │                               │
     Phase 2: Culprit Verification   Phase 2: Corroboration Check
     Check Culprit PID & Delta       Check Wait Channel (wchan)
                 │                               │
                 └───────────────┬───────────────┘
                                 ▼
     Phase 3: Controlled Remediation
     Apply Rule Recommended Action (ionice, renice, cgroup, etc.)
```

### Phase 1: Root Cause Isolation (Execute Diagnostic Snapshot)
```bash
# 1. Standard instant check (1s window)
why-slow

# 2. If running on multi-tenant / multi-user node, run with sudo for wide PID visibility:
sudo why-slow

# 3. For fluctuating or noisy workloads, take a 3-sample median:
why-slow --samples 3 --interval 1s
```

### Phase 2: Corroboration & Blast Radius Verification
- Inspect the **Primary Blocker**:
  - If **Tier 1** (e.g. `BASE_DISK_HARDWARE_SATURATION`), focus remediation exclusively on storage I/O and culprit PID before addressing secondary alerts.
  - If **Tier 2** (e.g. `CONT_DSTATE_PILEUP`), inspect the kernel wait channel (`wchan`) listed in the card (e.g. `ext4_writepages`, `nfs_wait_bit_killable`).
- Check the **Culprit Process**: Note the PID, command name, and delta metric.

### Phase 3: Controlled Remediation
Apply the remediation command provided directly in the `why-slow` diagnostic card:
- For I/O hogs: `ionice -c3 -p <PID>`
- For CPU hogs: `renice -n 19 -p <PID>` or constrain container CPU quota.
- For lock contention: Investigate backing storage or application worker deadlock.

---

## 📊 Failure Modes and Effects Analysis (FMEA)

`why-slow` is engineered to degrade gracefully without crashing under hostile kernel conditions:

| Failure Mode / Edge Case | Kernel Behavior | `why-slow` Mitigation & Degradation | System Impact |
|---|---|---|---|
| **Legacy Kernel (< 4.20 / 5.4)** | `/proc/pressure/*` (PSI) files do not exist | Silently skips PSI parsing; falls back to traditional delta metrics (`/proc/stat`, `/proc/vmstat`). | Zero impact; returns partial report. |
| **Procfs Hardening (`hidepid=2`)** | `/proc/[pid]/*` of other users returns `EACCES` | Silently ignores permission denied errors; evaluates invoking user's processes and global stats. Confidence score scales to 80%. | Zero impact; no crashes. |
| **Rapid PID Recycling / Fork Bomb** | PIDs terminate between directory read and stat parse | Handled as `os.ErrNotExist`; worker silently skips dead PID and continues pool processing. | Zero impact; no race conditions. |
| **Filesystem Read-Only Remount** | Storage volume remounts `ro` due to hardware fault | `why-slow` only reads, so execution succeeds completely and flags `BASE_FS_READONLY_REMOUNT`. | Diagnoses fault without writes. |
| **Cgroup v1 vs Cgroup v2** | System runs legacy cgroup v1 hierarchy | Automatically detects v1 vs v2 directory structures; parses available controllers. | Gracefully degrades if stats missing. |
| **Host System 100% CPU Freeze** | Heavy host CPU starvation | Worker pool bounded to `runtime.NumCPU()`; execution yields cooperatively via Go scheduler. | Consumes `< 1%` CPU overhead. |

---

## 🔒 Disaster Recovery & Rollback

Since `why-slow` performs zero write operations and makes zero system modifications:
- **Immediate Rollback**: Simply terminate the binary (`kill -SIGINT <pid>` or `systemctl stop why-slow-sentinel`).
- **Zero Cleanup Required**: No temp files, shared memory segments, or kernel state changes are left behind.
- **Air-Gapped Binary Distribution**: Keep a single pre-compiled binary (`bin/why-slow`) on disaster recovery jump-hosts or USB keys for immediate offline triage during major outage events.
