# why-slow — Diagnostic Disambiguation & Symptom Overlap Report

## Executive Summary

Traditional monitoring tools (e.g. `top`, `htop`, basic Prometheus node exporters) frequently misdiagnose complex system bottlenecks because **distinct underlying kernel failure modes often manifest with identical high-level symptoms**.

For example:
- A slow application might look like "100% CPU usage" when it is actually **vCPU Steal Time**, **Cgroup Throttling**, or **Single-Core CPU Pinning**.
- An application freezing on memory allocations might look like "Running out of RAM" when it is actually **Low-Memory DMA32 Zone Depletion**, **Hypervisor Ballooning**, or **THP Compaction Stalls**.
- A disk write stall might look like "Disk Saturation" when it is actually **Inode Exhaustion**, **SAN I/O Latency**, or **Cgroup Dirty Throttling**.

This report documents the **5 symptom ambiguity clusters across all 160 diagnostic rules** and details how `why-slow` eliminates false positives using multi-signal kernel telemetry.

---

## 1. Cluster 1: CPU Starvation & Slowness Ambiguities

### Overlapping High-Level Symptom:
> *"My application is running slowly and compute threads are starving for CPU cycles."*

```
                                  APPARENT CPU SLOWNESS
                                             │
      ┌──────────────────┬───────────────────┼───────────────────┬──────────────────┐
      ▼                  ▼                   ▼                   ▼                  ▼
BASE_CPU_SATURATION  CONT_VCPU_STEAL  CONT_CGROUP_THROTTLED  EDGE_CPU_AFFINITY   BASE_THERMAL
 (All cores 100%     (Hypervisor steals   (Container quota      (Thread pinned     (CPU frequency
  host compute)       cycles for VM)       limit enforced)       to single core)    dropped by heat)
```

### Diagnostic Differentiation Matrix:

| Diagnostic Rule | Total Host CPU Idle | Guest Runqueue (`procs_running`) | Kernel Telemetry Source | Unique Differentiating Signal |
|---|---|---|---|---|
| **`BASE_CPU_SATURATION`** | `< 2.0%` | `> 2× Cores` | `/proc/stat` | All physical CPU cores are busy doing actual guest/process work. Runqueue is backed up. |
| **`CONT_VCPU_STEAL_TIME`** | Appears busy | Normal | `/proc/stat` (`steal` field) | `StealPercent >= 15%`. The hypervisor scheduler preempted the vCPU to run noisy neighbors. |
| **`CONT_CGROUP_THROTTLED`** | High idle (e.g. 80%) | Normal | `/sys/fs/cgroup/**/cpu.stat` | Whole system is idle, but the specific container exceeded its `cpu.max` quota (`throttled_usec > 100ms`). |
| **`EDGE_CPU_AFFINITY_PIN`** | High idle (≥ 75%) | Normal | `/proc/[pid]/status` (`Cpus_allowed`) | 1 core is 95%+ busy while other 11 cores are completely idle because process has affinity bitmask `0x1`. |
| **`BASE_THERMAL_THROTTLING`** | Any | Any | `/sys/devices/system/cpu/cpu*/cpufreq` + `/sys/class/thermal` | CPU hardware throttled clock frequency (`cur_freq < 40% max`) due to core temperature exceeding 85°C. |

---

## 2. Cluster 2: Memory Starvation & Allocation Latency

### Overlapping High-Level Symptom:
> *"The application freezes during memory allocation, memory latency spikes, or processes are killed."*

```
                                  APPARENT MEMORY PRESSURE
                                             │
      ┌──────────────────┬───────────────────┼───────────────────┬──────────────────┐
      ▼                  ▼                   ▼                   ▼                  ▼
 BASE_OOM_DANGER     CONT_SWAP_THRASH     CONT_BALLOON_OVER    EDGE_CGROUP_OOM   EDGE_ZONE_DMA32
(Host RAM + Swap    (Active page scanning (Hypervisor inflates (Container memory  (Low <4GB zone 0 free,
 100% exhausted)     + direct reclaim)     virtio_balloon)      limit killed PID)  High RAM 100GB free)
```

### Diagnostic Differentiation Matrix:

| Diagnostic Rule | Whole Host `MemAvailable` | PSI Memory Stall | Kernel Telemetry Source | Unique Differentiating Signal |
|---|---|---|---|---|
| **`BASE_OOM_DANGER`** | `< 3%` | High | `/proc/meminfo` | Both physical RAM and swap are completely exhausted across the entire machine. System-wide OOM killer imminent. |
| **`CONT_SWAP_THRASHING`** | Low | `some > 30%` | `/proc/vmstat` + PSI | `pgscan_direct > 0` AND `allocstall_direct > 0`. Kernel is desperately scanning and evicting pages. |
| **`CONT_BALLOON_OVERCOMMIT`** | Appears available | Moderate | `/proc/meminfo` + Virtio sysfs | `BalloonBytes >= 20%` of RAM. Hypervisor inflated balloon driver inside guest to reclaim RAM for host. |
| **`EDGE_CGROUP_OOM_KILL_EVENT`** | Ample (e.g. 50GB free) | Low / Zero | `memory.events` (`oom_kill`) | Host memory is healthy, but the container exceeded its private memory quota (`docker --memory=20m`). |
| **`EDGE_ZONE_DMA32_EXHAUSTION`** | Ample (> 10GB free) | Local | `/proc/buddyinfo` | Normal zone has 100GB free, but DMA32 zone (< 4GB address space) has 0 free pages. 32-bit hardware drivers stall. |
| **`EDGE_THP_COMPACTION_STALL`** | Ample | Zero | `/proc/vmstat` (`compact_stall`) | Kernel freezes thread to defragment memory pages into contiguous 2MB Transparent Huge Pages (`wchan=compact_zone`). |

---

## 3. Cluster 3: Storage & I/O Latency Stalls

### Overlapping High-Level Symptom:
> *"File read/write operations are hanging, database queries are slow, or processes are stuck in I/O wait."*

```
                                    APPARENT STORAGE SLOWNESS
                                                │
      ┌──────────────────┬──────────────────────┼──────────────────────┬─────────────────┐
      ▼                  ▼                      ▼                      ▼                 ▼
BASE_DISK_HW_SAT    BASE_IO_SERVICE_LAT    BASE_INODE_EXHAUSTION  BASE_DISK_SPACE_FULL  CONT_DSTATE_PILEUP
(Disk 100% time     (SAN/EBS high latency  (0 free inodes, free   (0 bytes free on      (3+ tasks stuck in
 busy with I/O)      despite low IOPS)      space available)       filesystem)           ext4/nfs wait)
```

### Diagnostic Differentiation Matrix:

| Diagnostic Rule | Block Device `io_ticks` | Disk Free Bytes | Inodes Free | Unique Differentiating Signal |
|---|---|---|---|---|
| **`BASE_DISK_HARDWARE_SATURATION`** | `≥ 95%` | Any | Any | Physical disk throughput is pegged at 100% hardware capability. |
| **`BASE_IO_SERVICE_LATENCY`** | Can be low (e.g. 20%) | Any | Any | Disk is not 100% busy, but `AvgReadLatencyMS` or `AvgWriteLatencyMS >= 50ms` due to SAN queue congestion or Cloud EBS burst credit depletion. |
| **`BASE_DISK_SPACE_FULL`** | Any | `< 1%` | Any | Filesystem is completely out of disk capacity blocks (`statfs.Bfree == 0`). |
| **`BASE_INODE_EXHAUSTION`** | Any | Ample (e.g. 50GB free) | `0 free` (≥ 99% used) | Free disk bytes exist, but the filesystem inode metadata table is full. New file creation fails with `ENOSPC`. |
| **`CONT_DSTATE_PILEUP`** | Any | Any | Any | ≥ 3 processes are frozen in uninterruptible sleep `D` waiting on kernel filesystem locks (`ext4_writepages`, `nfs_wait_on_request`). |
| **`EDGE_CGROUP_DIRTY_THROTTLE`**| Low | Any | Any | Process `wchan` is `balance_dirty_pages_ratelimited` because container exceeded its dirty memory writeback limit. |

---

## 4. Cluster 4: Network & Connection Failures

### Overlapping High-Level Symptom:
> *"TCP handshakes are timing out, packets are getting dropped, or client connections are failing."*

```
                                 APPARENT NETWORK DROPS / TIMEOUTS
                                                │
      ┌──────────────────┬──────────────────────┼──────────────────────┬─────────────────┐
      ▼                  ▼                      ▼                      ▼                 ▼
CONT_TCP_LISTEN_DROPS CONT_TIMEWAIT_EXHAUST  CONT_CONNTRACK_EXHAUST  CONT_SOFTIRQ_UNBAL  EDGE_IRQ_CORE_STORM
(Inbound accept queue (Outbound ephemeral    (Netfilter firewall     (Network software   (Hardware PCI-MSI
 full on server socket) port table flood)     table capacity full)    interrupt on 1 CPU) interrupt storm)
```

### Diagnostic Differentiation Matrix:

| Diagnostic Rule | Direction | Error Code in User Space | Kernel Telemetry Source | Unique Differentiating Signal |
|---|---|---|---|---|
| **`CONT_TCP_LISTEN_DROPS`** | Inbound | `ETIMEDOUT` (Client side) | `/proc/net/netstat` | Server application accept backlog queue is full. Incoming TCP SYN/ACKs dropped (`ListenDrops > 0`). |
| **`CONT_TIMEWAIT_PORT_EXHAUSTION`**| Outbound | `EADDRNOTAVAIL` (Client side) | `/proc/net/sockstat` | Outbound short-lived connections consumed > 85% of ephemeral ports (`ip_local_port_range`). |
| **`CONT_CONNTRACK_EXHAUSTION`** | Both | Silent Drop (Zero error logs) | `/proc/sys/net/netfilter/nf_conntrack_*` | Netfilter state table full (`count >= 90% max`). Packets dropped at raw IP layer before socket layer. |
| **`CONT_SOFTIRQ_UNBALANCE`** | Both | Throughput Cap | `/proc/stat` | 1 CPU core is pegged at > 80% `softirq` handling network packet RX/TX while overall CPU is idle (no RPS/RSS). |
| **`EDGE_IRQ_CORE_STORM`** | Hardware | Latency Spikes | `/proc/interrupts` | A single core is overwhelmed with > 50,000 hardware PCI-MSI interrupts while other cores receive < 1,000. |

---

## 5. Cluster 5: Process Freezes & Table Exhaustion

### Overlapping High-Level Symptom:
> *"A process stopped responding, hangs indefinitely, or new process spawning fails."*

```
                                  APPARENT PROCESS STALLS
                                             │
      ┌──────────────────┬───────────────────┼───────────────────┬──────────────────┐
      ▼                  ▼                   ▼                   ▼                  ▼
EDGE_PTY_STDOUT_LOCK  EDGE_FUTEX_CONTENTION  CONT_PID_EXHAUSTION EDGE_ZOMBIE_LEAK   CONT_FD_EXHAUSTION
(Stdout pipe buffer   (50+ threads fighting  (Process table at   (Unreaped dead     (Open files at 90%
 full, reader hung)    over single mutex)     pid_max ceiling)    children leak)     of ulimit ceiling)
```

### Diagnostic Differentiation Matrix:

| Diagnostic Rule | Process State | Wchan / Subsystem | Failure Mechanism |
|---|---|---|---|
| **`EDGE_PTY_STDOUT_LOCK`** | `S` (Sleeping) | `n_tty_write` / `pty_write` | Process is blocked waiting for terminal/SSH buffer to be drained. Not a deadlock; pure stdout backpressure. |
| **`EDGE_FUTEX_CONTENTION`** | `S` (Sleeping) | `futex_wait_queue_me` | 50+ threads are serialized waiting on the same userspace mutex lock. |
| **`CONT_PID_EXHAUSTION`** | Any | Kernel `fork()` / `clone()` | Total active processes reach ≥ 95% of `/proc/sys/kernel/pid_max`. New forks fail with `EAGAIN`. |
| **`EDGE_ZOMBIE_DEFUNCT_LEAK`** | `Z` (Zombie) | Process Table | Parent process fails to call `waitpid()`, leaving ≥ 50 defunct entries polluting the PID table. |
| **`CONT_FD_EXHAUSTION`** | Any | `open()` / `socket()` / `accept()` | Open file descriptor count exceeds 90% of soft limit in `/proc/[pid]/limits`. |

---

## 6. How `why-slow` Prevents False Positives

1. **Multi-Signal Corroboration**:
   No single metric can trigger a critical diagnosis in isolation. For example, high CPU alone is ignored unless the scheduler runqueue (`procs_running`) confirms thread starvation.
2. **Tier-Ranked Root Cause Isolation**:
   When a Tier 1 Hard Limit fires (e.g. `BASE_DISK_HARDWARE_SATURATION`), correlated Tier 2 and Tier 3 symptoms (e.g. `CONT_DSTATE_PILEUP`) are automatically **demoted to secondary contributing factors** so the engineer immediately sees the true root cause.
3. **Opportunistic Privilege Confidence Scaling**:
   When running without root privileges, rules that depend on full `/proc/[pid]/io` visibility have their confidence scaled by `0.80×`, and an informative warning footer is displayed.
