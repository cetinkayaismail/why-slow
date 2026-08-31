# why-slow ⚡

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(stdlib%20only)-success)](https://pkg.go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64%20%7C%20ARM64-lightgrey)](https://kernel.org)
[![CGO](https://img.shields.io/badge/CGO-Disabled%20(Pure%20Go)-blue)](https://golang.org)

**Instant Linux Performance & Bottleneck Diagnostic Engine**

`why-slow` answers the age-old question *"Why is my Linux server suddenly slow?"* in **under 1 second**. Instead of juggling `top`, `vmstat`, `iostat`, `dmesg`, `perf`, and `sar`, `why-slow` captures two high-resolution snapshots of the Linux kernel virtual filesystems (`/proc` and `/sys`), computes differentials, and correlates **47 diagnostic rules** through a prioritized multi-tier Intelligence Engine to isolate the exact root cause.

---

## 📺 Instant Terminal Output

```text
[!] CRITICAL BOTTLENECK: Disk Block Device Saturation (nvme0n1)
─────────────────────────────────────────────────────────────────────────────
Primary Cause:
  Storage device 'nvme0n1' is operating at 99.8% utilization capacity over the sampling window.

Kernel Evidence:
  • Device 'nvme0n1' I/O Utilization: 99.8%
  • Read Throughput: 0.12 MB/s, Write Throughput: 620.50 MB/s
  • I/O Operations in Flight: 48

Culprit Process:
  • PID 14208 [mysqld] (Issued 580.4 MB write delta during sampling window)

Recommended Remediation:
  • Lower I/O priority for culprit: ionice -c3 -p 14208
─────────────────────────────────────────────────────────────────────────────
Contributing & Secondary Findings:
  • [CONT_DSTATE_PILEUP] Uninterruptible I/O Lock (D-State Pileup) — 4 active processes blocked
  • [EDGE_CGROUP_DIRTY_THROTTLE] Dirty Page Cache Throttling — PID 14208 throttled in writeback
```

---

## 🚀 Key Highlights

- **⚡ Instant 1-Second Root Cause Isolation**: Captures a 1-second baseline delta and pinpoints the exact culprit PID and kernel wait channel (`wchan`).
- **🔒 Zero Dependencies & Zero CGo**: Built strictly with Go Standard Library (`CGO_ENABLED=0`). No external CLI wrappers (`ps`, `lsof`, `iostat`).
- **🛡️ Opportunistic Elevation**: Works 100% as an unprivileged regular user with graceful degradation. Elevation (`sudo why-slow`) simply widens process visibility.
- **🚫 Zero Writes & Zero Footprint**: Strictly read-only (`/proc`, `/sys`, `statfs`). Never writes a single byte or temporary file to target systems.
- **🧠 47 Deep Diagnostic Rules**: Prioritized into **Tier 1** (Hard Limits), **Tier 2** (Contention & Queuing), and **Tier 3** (Kernel Edge Cases).
- **🤖 Structured JSON Output**: First-class `--json` support for seamless integration into SIEM, APM, Datadog, Prometheus, or CI/CD pipelines.

---

## 📦 Installation

### Go Install (Go 1.22+)
```bash
go install github.com/cetinkayaismail/why-slow/cmd/why-slow@latest
```

### Build from Source
```bash
git clone https://github.com/cetinkayaismail/why-slow.git
cd why-slow
make build
sudo make install
```

---

## 💻 CLI Usage

```bash
# Standard interactive diagnostic run (1.00s sampling window)
why-slow

# Full system-wide visibility across all PIDs and container cgroups
sudo why-slow

# Extended sampling window for capturing periodic or sustained spikes
why-slow --interval 3s

# Multi-sample statistical noise reduction (captures 3 samples and takes the median)
why-slow --samples 3 --interval 1s

# Continuous 24/7 background sentinel daemon (only alerts on HIGH & CRITICAL issues)
why-slow --watch --interval 3s --alert-threshold high

# Machine-readable JSON output for automated diagnostics / monitoring
why-slow --json

# Compact single-line JSON output for log shippers
why-slow --json --compact

# Disable ANSI terminal colors (or set NO_COLOR=1)
why-slow --no-color
```

### Available CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--interval <dur>` | `1s` | Sampling window between Snapshot A and Snapshot B (e.g. `1s`, `2s`, `5s`) |
| `--samples <n>` | `1` | Number of sampling windows to collect (uses median for noise reduction) |
| `--watch` | `false` | Run continuously as a background sentinel reporting issues |
| `--alert-threshold <lvl>` | `info` | Minimum severity to report in watch mode (`critical`, `high`, `medium`, `info`) |
| `--json` | `false` | Output diagnostic report formatted as structured JSON |
| `--compact` | `false` | Output compact single-line JSON (used with `--json`) |
| `--no-color` | `false` | Disable ANSI color coding in terminal output |
| `--version` | `false` | Print `why-slow` version and exit |

---

## 🧠 Diagnostic Rules Overview

`why-slow` correlates signals across **159 prioritized kernel diagnostic rules**:

```
┌────────────────────────────────────────────────────────────────────────┐
│  Tier 1: Base Hard Limits (P0 Priority — 13 Rules)                     │
│  CPU Saturation • OOM Imminent • Disk Full • Thermal Throttling        │
│  HW Disk Saturation • Inode Depletion • SAN Latency • Swap Saturation  │
│  Conntrack 100% Full • Host Kernel OOM Kill • System File Table Full   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Causal Suppression & Demotion)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Tier 2: Contention & Queues (P1 Priority — 83 Rules)                  │
│  D-State Pileup • Swap Thrashing • Cgroup Quota Throttled • FD Limit   │
│  SoftIRQ Storm • TCP Listen Drops • SYN Backlog • blk-mq Starvation    │
│  vCPU Steal • Conntrack Full • ARP Cache Overflow • Page Table Locks   │
│  CLOSE_WAIT Socket Leaks • Sustained Load Overload • PSI Stalls        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Demotes)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Tier 3: Subtle Kernel Edge Cases (P2 Priority — 63 Rules)             │
│  THP Compaction Stall • PTY / Pipe Lock • Degraded Clocksource (HPET)  │
│  Futex Contention • NUMA Remote Overhead • CPU Pinning • Zombie Leaks  │
│  DMA32 Low-Memory • KSM Deduplication • FUSE Daemon Wait Stalls        │
└────────────────────────────────────────────────────────────────────────┘
```

👉 **View the complete [Diagnostic Rules Catalog](docs/RULES_CATALOG.md) for full descriptions, trigger conditions, and remediations.**

---

## 🗺️ Future Plans & Autonomous Agent Roadmap

We are actively evolving `why-slow` from a standalone CLI diagnostic engine into an **Autonomous Diagnostic Agent** that plugs natively into enterprise observability infrastructure:

### 1. 📡 Autonomous Push Agent (`--push-url`)
- **Outbound-Only Push Architecture**: Transmits structured JSON diagnostic events over HTTPS with mTLS authentication (`POST https://collector:8443/v1/diagnostics`).
- **Zero Inbound Port Attack Surface**: No listening TCP ports, eliminating remote attack vectors while operating safely within private VPCs.

### 2. 🔌 Enterprise APM & Monitoring Forwarders
- **Zabbix Native Integration**: Official `UserParameter` templates and active agent streaming checks.
- **Prometheus / OpenMetrics Exporter (`--prometheus :9101`)**: Optional read-only scrape endpoint publishing synthesized rule health and PSI metrics.
- **Log Shipper Sidecars**: Native pipelines for Vector, FluentBit, Fluentd, and Promtail.

### 3. ☸️ Kubernetes-Native DaemonSet & Operator
- **Cluster-Wide Deployment**: Single-command Helm chart deployment as an unprivileged node `DaemonSet`.
- **Container Metadata Enrichment**: Automatic mapping of culprit PIDs to Kubernetes Pods, Namespaces, and Containers via downward API and cgroup v2 paths.

### 4. 🚨 Instant Incident Dispatchers
- Native webhook dispatchers directly routing actionable root-cause cards to **Slack, PagerDuty, OpsGenie, and Microsoft Teams**.

---

## 📚 Documentation

- 📖 **[System Architecture](docs/ARCHITECTURE.md)**: Deep dive into the Collector, Intelligence Engine, and Presenter pipeline.
- 📋 **[Rules Catalog](docs/RULES_CATALOG.md)**: Exhaustive reference for all 159 diagnostic rules across Tier 1, 2, and 3.
- 🏆 **[Master Benchmark & Stress Report](docs/MASTER_BENCHMARK.md)**: Live Docker stress test results, 5,000 PID performance scaling, and memory benchmarks.
- 🎯 **[Diagnostic Disambiguation](docs/DIAGNOSTIC_DISAMBIGUATION.md)**: Explanation of multi-signal correlation and root cause isolation.
- 📜 **[Changelog](docs/CHANGELOG.md)**: Version history, releases, and changelog.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

