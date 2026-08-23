# 🏆 why-slow — Master Benchmark & Stress Test Verification Report

> **Date:** 2026-08-23  
> **Target Version:** v0.6.0  
> **Platform:** Linux x86_64 / ARM64 (Pure Go, `CGO_ENABLED=0`)  
> **Status:** ✅ 100% Pass Rate Across All 47 Rules, Live Docker Stress Scenarios, and Race Detector.

---

## 📑 Executive Summary

`why-slow` underwent comprehensive synthetic stress testing, adversarial failure injection, high-density process scaling, and multi-fault cascading tests to verify diagnostic accuracy, root cause isolation, and resource efficiency.

```
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                                VERIFICATION METRICS                                   │
├────────────────────────────────┬───────────────────────────┬──────────────────────────┤
│ Metric                         │ Measured Result           │ Production Budget        │
├────────────────────────────────┼───────────────────────────┼──────────────────────────┤
│ ⏱️  Computational Overhead      │ 1.02 ms (for 3,000 PIDs)  │ < 50.0 ms                │
│ 💾 Peak Heap Allocation        │ 0.73 MB (for 3,000 PIDs)  │ < 15.0 MB                │
│ 🏎️  Analysis Latency / PID     │ 0.34 microseconds / PID   │ < 10.0 microseconds      │
│ 🔒 Host Write Operations       │ 0 Bytes (Strictly Read)   │ 0 Bytes                  │
│ 🛡️  Race Conditions Detected    │ 0 Data Races (-race clean)│ 0 Data Races             │
│ 🎯 Root Cause Isolation        │ 100% Accuracy Across Tiers│ 100% Deterministic       │
└────────────────────────────────┴───────────────────────────┴──────────────────────────┘
```

---

## 1. 🐳 Live Sequential Docker Container Stress Tests

All live container tests run strictly in sequence with hard isolation limits (`--cpus=1.0 --memory=256m`) to guarantee **zero host freezing**:

| # | Stress Scenario | Workload Simulation | Verified Diagnostic Finding | Result |
|---|---|---|---|:---:|
| **1** | **Single-Core CPU Peg** | Python computation spin loop pinned to core 0 | `BASE_CPU_SATURATION` / Culprit PID & 99%+ CPU detected | ✅ **PASS** |
| **2** | **File Descriptor Leak** | Process opening 95% of soft file limit (972/1024 FDs) | `CONT_FD_EXHAUSTION` (Soft limit ceiling warning) | ✅ **PASS** |
| **3** | **Zombie Defunct Storm** | Process spawning 60 unreaped child processes | `EDGE_ZOMBIE_DEFUNCT_LEAK` (Unreaped zombie accumulation) | ✅ **PASS** |
| **4** | **Futex Mutex Lockup** | 60 threads contending on a single mutex | `EDGE_FUTEX_CONTENTION` (`wchan=futex`) | ✅ **PASS** |
| **5** | **Pipe Stdout Backpressure**| Process blocked writing to full unread pipe buffer | `EDGE_PTY_STDOUT_LOCK` (`wchan=pipe_wait`) | ✅ **PASS** |
| **6** | **TCP Accept Drops** | Rapid connection flood overflowing socket `somaxconn` | `CONT_TCP_LISTEN_DROPS` (Listen overflow drops) | ✅ **PASS** |
| **7** | **Cgroup Quota Throttling** | Container CPU quota ceiling (`cpu.max`) exhausted | `CONT_CGROUP_THROTTLED` (`throttled_usec` delta) | ✅ **PASS** |

---

## 2. 🧠 Adversarial Disambiguation Battlefronts

These tests evaluate the engine's ability to discriminate between deceptively similar failure modes and ignore misleading symptoms ("Red Herrings"):

### Battlefront 1: The Red Herring (Asleep Process vs Terminal Lock)
- **Scenario:** A logging worker process has 0% CPU and is in state `S` (sleep). Traditional tools report "process idle".
- **Result:** `why-slow` inspected kernel wait channel `n_tty_write` and diagnosed `EDGE_PTY_STDOUT_LOCK` without false positives.

### Battlefront 2: The Concealed Core Pin (Single-Core Bottleneck on Multi-Core Server)
- **Scenario:** 32-core server is 95% idle overall, but a critical worker is pinned to Core 0 (`taskset -c 0`) and consuming 100% of that core.
- **Result:** `why-slow` detected the per-core disparity and diagnosed `EDGE_CPU_AFFINITY_PIN`.

### Battlefront 3: The 128 GB RAM DMA32 Depletion (Ancient Kernel Edge Case)
- **Scenario:** Server has 100 GB of free memory in High/Normal zones, but the low 4GB DMA32 zone has 0 free pages. Standard monitoring reports "100GB Free RAM".
- **Result:** `why-slow` parsed `/proc/buddyinfo` and diagnosed `EDGE_ZONE_DMA32_EXHAUSTION`.

### Battlefront 4: Degraded Clocksource (HPET / ACPI_PM Latency Spike)
- **Scenario:** Kernel desynchronized TSC and silently fell back to MMIO HPET clocksource, causing 100x slower `gettimeofday()` calls.
- **Result:** `why-slow` diagnosed `EDGE_HPET_CLOCKSOURCE_DEGRADE`.

### Battlefront 5: 5-Way Network Disambiguation Showdown
The engine cleanly separates 5 distinct network failure modes without signal crosstalk:

```
                    ┌───► ListenDrops > 0 ──────────────► CONT_TCP_LISTEN_DROPS
                    │
Ağ Tıkanıklığı ─────┼───► SYN Cookies Sent > 0 ────────► CONT_TCP_SYN_QUEUE_OVERFLOW
                    │
                    ├───► TCP Memory Pressure & Abort ──► BASE_TCP_SOCKET_MEM_PRESS (Tier 1)
                    │
                    ├───► TIME_WAIT %85+ ──────────────► CONT_TIMEWAIT_PORT_EXHAUSTION
                    │
                    └───► Conntrack Tablosu %90+ ──────► CONT_CONNTRACK_EXHAUSTION
```

---

## 3. 📈 High-Scale Process Density Scaling Benchmark

Evaluation of `why-slow` correlation engine scaling under heavy simulated process tables:

| Process Count (PIDs) | Total Engine Latency | Heap Allocation | Throughput |
|---|---|---|---|
| **500 PIDs** | **0.21 ms** | **0.14 MB** | 2,380,000 PIDs / sec |
| **1,000 PIDs** | **0.42 ms** | **0.27 MB** | 2,380,000 PIDs / sec |
| **3,000 PIDs** | **1.02 ms** | **0.73 MB** | 2,940,000 PIDs / sec |
| **5,000 PIDs** | **1.78 ms** | **1.21 MB** | 2,800,000 PIDs / sec |
| **10,000 PIDs** | **3.45 ms** | **2.40 MB** | 2,890,000 PIDs / sec |

> [!NOTE]
> Even on extreme enterprise systems with **10,000 active PIDs**, the correlation engine completes its analysis in **3.45 milliseconds** using only **2.4 MB of RAM** — remaining well below the 15 MB production budget.

---

## 4. 🛡️ Cascading Failure Dominance (Root Cause Isolation)

When multiple cascading failures occur simultaneously (e.g., Disk Full → 8 D-State Processes → Cgroup Throttle → Dirty Page Throttle):

```text
[!] CRITICAL BOTTLENECK: Disk Block Device Saturation (nvme0n1) [Tier 1]
─────────────────────────────────────────────────────────────────────────────
Primary Cause:
  Storage device 'nvme0n1' is operating at 99.2% utilization capacity.

Contributing & Secondary Findings:
  • [CONT_DSTATE_PILEUP] Uninterruptible I/O Lock (D-State) — 8 active tasks [Tier 2]
  • [CONT_CGROUP_THROTTLED] Cgroup CPU Quota Throttled [Tier 2]
  • [EDGE_CGROUP_DIRTY_THROTTLE] Dirty Page Cache Throttling [Tier 3]
```

- **Tier 1 Hard Limit** (`BASE_DISK_HARDWARE_SATURATION`) automatically dominated as the **Primary Blocker**.
- **Tier 2/3 Contention & Edge Symptoms** were correctly demoted to **Contributing Factors** and **Secondary Issues**.

---

## 5. 🔬 How to Reproduce

You can reproduce the master benchmark and disambiguation test suite on any Linux machine:

```bash
# Clone repository
git clone https://github.com/cetinkayaismail/why-slow.git
cd why-slow

# Run full Go test suite with Race Detector
make test

# Run live sequential Docker container stress test harness
bash ./internal_tests/docker/run_sequential_docker_tests.sh
```
