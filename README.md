# why-slow ⚡

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(stdlib%20only)-success)](https://pkg.go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64%20%7C%20ARM64-lightgrey)](https://kernel.org)
[![CGO](https://img.shields.io/badge/CGO-Disabled%20(Pure%20Go)-blue)](https://golang.org)
[![Security](https://img.shields.io/badge/Security-Zero%20Writes%20%7C%20Read--Only-green)](docs/ARCHITECTURE.md)
[![Compliance](https://img.shields.io/badge/Compliance-PCI--DSS%20%7C%20SOC%202%20Ready-blueviolet)](docs/ARCHITECTURE.md)

**Enterprise-Grade Linux Kernel Diagnostic & Root-Cause Analysis Engine**

`why-slow` isolates the true root cause of system slowness and latency spikes in **under 1 second**. Instead of manually correlating `top`, `vmstat`, `iostat`, `dmesg`, `perf`, and `sar`, `why-slow` captures two high-resolution snapshots of Linux kernel virtual interfaces (`/proc` and `/sys`), calculates differentials, and evaluates **160 prioritized diagnostic rules** through a deterministic multi-tier Intelligence Engine.

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

## 🏛️ Enterprise & Banking Security Highlights

- **⚡ Sub-Second Deterministic Analysis**: Wall-clock execution `< 1.05s` with an in-memory compute latency `< 50ms`.
- **🔒 Zero Dependencies & Zero CGo**: Built 100% with the Go standard library (`CGO_ENABLED=0`). Zero third-party packages in `go.mod`.
- **🛡️ Opportunistic Elevation**: Works 100% unprivileged. Elevation (`sudo why-slow`) simply widens process visibility without altering code paths.
- **🚫 Strict Zero-Write Guarantee**: Opens all virtual files with `O_RDONLY`. Zero disk writes, zero temp files in `/tmp` or `/dev/shm`, and zero `ioctl` state mutations.
- **💼 Banking Compliance Ready**: Meets strict requirements for **PCI-DSS v4.0** (Req 2 & 10), **SOC 2 Type II**, and **CIS Linux Benchmarks** (runs under `hidepid=2`).
- **🧠 160 Deep Diagnostic Rules**: Prioritized into **Tier 1** (Base Hard Limits), **Tier 2** (Contention & Queuing), and **Tier 3** (Kernel Edge Cases).
- **🤖 SIEM / SOC Telemetry**: Deterministic Draft 2020-12 JSON Schema output (`--json`) for seamless ingestion into Splunk, Elastic, Datadog, and Vector.

---

## 📦 Installation

### Pre-Compiled Pure Go Binary
Download the self-contained static binary from GitHub Releases (no runtime dependencies):
```bash
curl -fsSL https://github.com/cetinkayaismail/why-slow/releases/latest/download/why-slow-linux-amd64 -o why-slow
chmod +x why-slow
sudo mv why-slow /usr/local/bin/
```

### Go Install (Go 1.22+)
```bash
go install github.com/cetinkayaismail/why-slow/cmd/why-slow@latest
```

### Build from Source (Bit-for-Bit Reproducible Build)
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

# Elevated wide-spectrum diagnostic run across all host PIDs and cgroups
sudo why-slow

# Extended sampling window for capturing intermittent or sustained spikes
why-slow --interval 3s

# Multi-sample statistical noise reduction (captures 3 samples and takes the median)
why-slow --samples 3 --interval 1s

# Continuous 24/7 background sentinel daemon (only alerts on HIGH & CRITICAL issues)
why-slow --watch --interval 3s --alert-threshold high

# Machine-readable JSON output for automated diagnostics / SIEM log forwarders
why-slow --json

# Compact single-line NDJSON output for log shippers
why-slow --json --compact

# Launch interactive raw terminal drilldown UI
why-slow --tui

# Disable ANSI color coding (or set NO_COLOR=1)
why-slow --no-color
```

### Available CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--interval <dur>` | `1s` | Sampling window between Snapshot A and Snapshot B (e.g. `1s`, `2s`, `5s`) |
| `--samples <n>` | `1` | Number of sampling windows to collect (evaluates median for noise reduction) |
| `--watch` | `false` | Run continuously as a background sentinel reporting new bottlenecks |
| `--alert-threshold <lvl>` | `info` | Minimum severity to report in watch mode (`critical`, `high`, `medium`, `info`) |
| `--json` | `false` | Output diagnostic report formatted as structured JSON |
| `--compact` | `false` | Output compact single-line JSON (used in combination with `--json`) |
| `--tui` | `false` | Launch interactive terminal user interface for interactive inspection |
| `--no-color` | `false` | Disable ANSI color formatting in terminal output |
| `--version` | `false` | Print `why-slow` version and build metadata |

---

## 🧠 Diagnostic Rules Overview

`why-slow` evaluates telemetry across **160 prioritized diagnostic rules**:

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
│  Tier 2: Contention & Queues (P1 Priority — 84 Rules)                  │
│  D-State Pileup • Swap Thrashing • Cgroup Quota Throttled • FD Limit   │
│  SoftIRQ Storm • TCP Listen Drops • SYN Backlog • blk-mq Starvation    │
│  vCPU Steal • Conntrack Full • ARP Cache Overflow • Page Table Locks   │
│  CLOSE_WAIT Socket Leaks • Sustained Load Overload • Runaway CPU Hog   │
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

👉 **View the complete [Diagnostic Rules Catalog](docs/RULES_CATALOG.md) for full trigger conditions and remediations.**

---

## 📚 Bank-Grade Enterprise Documentation Hub

| Document | Purpose & Scope |
|---|---|
| 🏛️ **[System Architecture](docs/ARCHITECTURE.md)** | Technical specification, pipeline design, STRIDE threat model, and zero-write proof. |
| 📋 **[Rules Catalog](docs/RULES_CATALOG.md)** | Complete reference for all 160 diagnostic rules across Tier 1, 2, and 3. |
| 📖 **[Operations Runbook](docs/OPERATIONS_RUNBOOK.md)** | Bare-metal, systemd sentinel service, Kubernetes DaemonSet manifest, and incident triage SOP. |
| 📡 **[SIEM & APM Integration](docs/INTEGRATION_GUIDE.md)** | JSON Schema (Draft 2020-12), Splunk, Elastic SIEM, Datadog, and Vector pipeline configs. |
| 🎯 **[Diagnostic Disambiguation](docs/DIAGNOSTIC_DISAMBIGUATION.md)** | Root cause isolation theory, causal suppression, and multi-signal disambiguation matrices. |
| 🏆 **[Master Benchmark & Stress Report](docs/MASTER_BENCHMARK.md)** | Live stress test verification, 5,000 PID density benchmarks, and resource ceiling proofs. |
| 📜 **[Release Changelog](docs/CHANGELOG.md)** | Version history, releases, and architectural change records. |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
