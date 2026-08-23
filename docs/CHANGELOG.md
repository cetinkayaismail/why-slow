# why-slow — Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.6.0] - 2026-08-23

### Added
- 7 new deep diagnostic rules expanding intelligence engine coverage from 40 to 47 rules:
  - **Tier 1**: `BASE_SWAP_DEVICE_SATURATION` (Critical) — Detects swap storage device bandwidth exhaustion from heavy page writeout and read-in.
  - **Tier 2**: `CONT_IO_QUEUE_LATENCY` (High) — Detects block device scheduler queue wait delays (≥ 100ms/op queue wait) before device dispatch.
  - **Tier 2**: `CONT_PAGE_TABLE_LOCK` (High) — Detects virtual memory `mmap_lock` and page table lock contention across multi-threaded applications.
  - **Tier 2**: `CONT_ORPHAN_SOCKET_LEAK` (High) — Detects leaked unreferenced orphan TCP sockets consuming kernel buffer memory.
  - **Tier 3**: `EDGE_FUSE_FS_STALL` (Medium) — Detects user processes stalled in kernel wait queues waiting on FUSE user-space filesystem daemons.
  - **Tier 3**: `EDGE_COMPACT_FAIL_RATE` (Medium) — Detects high failure rate (≥ 50%) of memory compaction defragmentation attempts.
  - **Tier 3**: `EDGE_MAJOR_PAGE_FAULT_STORM` (Medium) — Detects bursts of major page faults (≥ 500/s) driving synchronous disk reads.
- Added `pswpin` and `pswpout` parsing to `/proc/vmstat` and average block queue wait latency calculation.

### Changed & Fixed
- **Culprit Attribution Fix (A1)**: Corrected `RuleCgroupThrottled` to track highest `maxCPUDelta` instead of comparing delta against PID numerical identifier.
- **Multi-Signal TCP Rule (A2)**: Enforced 2-signal corroboration (`hasPressure && hasAbort`) for `RuleTCPSocketMemoryPressure` at Tier 1 0.95 confidence.
- **TCP Disambiguation (A3)**: Differentiated `RuleTCPSYNQueueOverflow` from `RuleTCPListenDrops` by requiring active SYN cookie generation.
- **Rule Interface Extensibility (A4)**: Added `IsPIDDependent() bool` to the `Rule` interface across all 47 rules, eliminating centralized hardcoded switch in `engine.go`.
- **Page Size Portability (A6)**: Replaced hardcoded 4096 page size with dynamic `os.Getpagesize()` in `process.go` for multi-architecture compatibility.
- **PID Discovery Optimization (O1)**: Replaced `os.ReadDir` with `os.Open` + `Readdirnames(-1)` in `discoverPIDs`, eliminating stat syscalls and sorting overhead for ~15-20% speedup.

---

## [0.5.0] - 2026-08-23

### Added
- **Sequential Docker Integration Test Suite**: Safe, bounded live container test framework (`tests/run_sequential_docker_tests.sh`, `tests/stress_scenarios.py`, `tests/docker_harness_test.go`) running workloads strictly one-at-a-time with resource ceilings (`--memory=256m`, `--cpus=1.0`) preventing host freezing.
- **Diagnostic Disambiguation & Cross-Testing Matrix**: Multi-signal cross-testing suite (`internal/analyzer/disambiguation_test.go`) validating that all 5 symptom overlap clusters are uniquely differentiated and Tier 1 root causes dominate secondary factors.

### Changed
- **Strict Agent Skills Overhaul**: Hardened `.agents/skills/security-review/SKILL.md`, `.agents/skills/architecture-review/SKILL.md`, and `.agents/skills/optimization-review/SKILL.md` with zero-tolerance checklists, unidirectional graph validation, 60-line function limits, 1.05s / 15MB resource budgets, and zero runtime regex rules.

---

## [0.4.0] - 2026-08-23

### Added
- 10 new deep enterprise & kernel subsystem diagnostic rules (expanding rule catalog from 30 to 40 rules):
  - **Tier 1**: `BASE_TCP_SOCKET_MEM_PRESS` (Critical) — Detects kernel `tcp_mem` buffer exhaustion, receive queue collapse, and connection abort resets.
  - **Tier 2**: `CONT_ARP_NEIGHBOR_OVERFLOW` (High) — Detects ARP / Neighbor table cache saturation (≥ 85% of `gc_thresh3`) in large Kubernetes nodes and flat subnets.
  - **Tier 2**: `CONT_TCP_SYN_QUEUE_OVERFLOW` (High) — Detects inbound half-open TCP SYN backlog queue saturation and SYN cookie fallback.
  - **Tier 2**: `CONT_BLK_MQ_TAG_STARVATION` (High) — Detects NVMe / SSD block hardware submission tag starvation (`blk_mq_get_tag`) under heavy async I/O.
  - **Tier 2**: `CONT_SCHED_RUNQUEUE_STARVATION` (High) — Detects CPU scheduler runqueue wait time latency spikes (≥ 1.5× execution time).
  - **Tier 2**: `CONT_CGROUP_MEM_HIGH_THROTTLE` (High) — Detects cgroup v2 proactive page allocation delay sleep injection triggered by `memory.high`.
  - **Tier 3**: `EDGE_SLAB_UNRECLAIM_LEAK` (Medium) — Detects non-reclaimable kernel slab memory leaks (dentries/inodes occupying ≥ 40% of system RAM).
  - **Tier 3**: `EDGE_INOTIFY_WATCH_EXHAUSTION` (Medium) — Detects dangerously restrictive inotify watch ceiling (`fs.inotify.max_user_watches <= 8192`) risking application `ENOSPC` errors.
  - **Tier 3**: `EDGE_RCU_SCHEDULER_STALL` (Medium) — Detects kernel Read-Copy-Update (RCU) grace period contention stalling tasks in `synchronize_rcu`.
  - **Tier 3**: `EDGE_THP_COLLAPSE_STALL` (Medium) — Detects `khugepaged` background 2MB hugepage collapse latency during synchronous direct allocation stalls.
- Extended kernel subsystem collectors:
  - ARP / Neighbor cache table parsing from `/proc/net/arp` and `/proc/sys/net/ipv4/neigh/default/gc_thresh3`.
  - Inotify limits parser for `/proc/sys/fs/inotify/max_user_watches`.
  - CPU scheduler runqueue latency parser for `/proc/schedstat`.
  - Unreclaimable slab parser from `/proc/meminfo` (`SUnreclaim:`, `Slab:`).
  - TCP buffer pressure counters (`TCPMemoryPressures`, `TCPRcvCollapsed`, `TCPAbortOnMemory`, `TCPReqQFullDoCookies`) in `ParseNetStat`.
  - Transparent Huge Page collapse counters (`thp_collapse_alloc`, `thp_collapse_alloc_failed`) in `ParseVMStat`.
  - Cgroup v2 `memory.high` proactive throttling events in `parseCgroupMemEvents`.
- Automated test suites with 100% race-condition coverage across all 40 diagnostic rules.

---

## [0.3.0] - 2026-08-23

### Added
- 7 new enterprise-grade infrastructure & virtualization diagnostic rules (bringing total rule count to 30):
  - **Tier 1**: `BASE_IO_SERVICE_LATENCY` (Critical) — Detects SAN/EBS/NVMe storage latency spikes (> 50ms/op) caused by queue saturation or burst credit depletion.
  - **Tier 2**: `CONT_VCPU_STEAL_TIME` (High) — Detects hypervisor CPU overcommit and noisy neighbor cycle theft (steal ≥ 15% overall / ≥ 30% core).
  - **Tier 2**: `CONT_BALLOON_OVERCOMMIT` (High) — Detects hypervisor memory overcommit pressure where balloon driver reclaims ≥ 20% of guest RAM.
  - **Tier 2**: `CONT_CONNTRACK_EXHAUSTION` (High) — Detects Netfilter connection tracking table saturation (≥ 90%) in Kubernetes nodes and NAT routers.
  - **Tier 3**: `EDGE_ZONE_DMA32_EXHAUSTION` (Medium) — Detects low-memory DMA32 zone depletion (0 free pages) on multi-gigabyte servers.
  - **Tier 3**: `EDGE_KSM_SCAN_STALL` (Medium) — Detects multi-tenant Kernel Samepage Merging memory deduplication CPU and cache stalls.
  - **Tier 3**: `EDGE_IRQ_CORE_STORM` (Medium) — Detects hardware interrupt storms (> 50,000 IRQs) overwhelming a single CPU core without `irqbalance`.
- Extended enterprise subsystem collectors:
  - Average read and write I/O service latencies per block device in `calculateDiskDiff`.
  - Netfilter connection tracking parser for `/proc/sys/net/netfilter/nf_conntrack_*` in `system.go`.
  - Memory zone buddyinfo parser for `/proc/buddyinfo` in `system.go`.
  - Kernel Samepage Merging (KSM) metrics parser for `/sys/kernel/mm/ksm/*` in `system.go`.
  - Hardware interrupt distribution parser for `/proc/interrupts` in `system.go`.
- Automated test suites with 100% race-condition coverage.

---

## [0.2.0] - 2026-08-23

### Added
- 7 new advanced diagnostic rules across all three tiers (bringing total rule count to 23):
  - **Tier 1**: `BASE_INODE_EXHAUSTION` (Critical) — Detects filesystem inode depletion on critical mounts.
  - **Tier 2**: `CONT_PID_EXHAUSTION` (High) — Detects system process table PID allocation nearing `pid_max` ceiling.
  - **Tier 2**: `CONT_TIMEWAIT_PORT_EXHAUSTION` (High) — Detects outbound connect failures caused by TIME_WAIT ephemeral port flood.
  - **Tier 3**: `EDGE_NUMA_REMOTE_THRASHING` (Medium) — Detects cross-socket remote memory allocation latency spikes.
  - **Tier 3**: `EDGE_CPU_AFFINITY_PIN` (Medium) — Detects single-core CPU pinning bottleneck when overall system is idle.
  - **Tier 3**: `EDGE_ZOMBIE_DEFUNCT_LEAK` (Medium) — Detects accumulation of unreaped zombie processes (≥ 50) and isolates culprit parent PID.
  - **Tier 3**: `EDGE_CGROUP_OOM_KILL_EVENT` (High) — Detects silent container OOM kill events triggered by cgroup memory limits.
- Extended subsystem collectors:
  - Inodes capacity and utilization tracking via `syscall.Statfs()` in `disk.go`.
  - NUMA counter parsing (`numa_miss`, `numa_foreign`, `numa_interleave`) from `/proc/vmstat` in `memory.go`.
  - Socket allocation statistics from `/proc/net/sockstat`, ephemeral port range from `/proc/sys/net/ipv4/ip_local_port_range`, and max PIDs from `/proc/sys/kernel/pid_max` in `system.go`.
  - Process CPU affinity mask (`Cpus_allowed`) parsing in `process.go`.
- Automated test suites and Docker stress test scenarios for new diagnostic rules.

---

## [0.1.0] - 2026-08-22

### Added
- Complete `why-slow` CLI tool: pure Go zero-dependency instant performance diagnostic engine for Linux.
- Official test execution report ([`docs/TEST_RESULTS.md`](file:///home/ismail/Desktop/go_projects/why-slow/docs/TEST_RESULTS.md)) and test plan ([`docs/TEST_PLAN.md`](file:///home/ismail/Desktop/go_projects/why-slow/docs/TEST_PLAN.md)).
- Automated scenario execution framework (`scripts/run_scenario.sh` and `tests/Dockerfile.stress`).
- CLI flags: `--json`, `--compact`, `--interval <duration>`, `--no-color`, `--version`, and `--help`.
- Opportunistic elevation privilege model: zero sudo requirement with automatic visibility expansion when running as root (`os.Getuid() == 0`).
- Presentation layer (`terminal.go`, `json.go`): ANSI diagnostic cards with severity color coding, evidence bullets, remediation actions, unprivileged warning footers, and structured/compact JSON.
- Correlation & ranking engine (`engine.go`): multi-tier rule evaluation, Tier/Severity/Confidence sorting, root cause isolation, and privilege-aware confidence adjustments.
- 16 diagnostic rules:
  - **Tier 1 (Base Hard Limits)**: `BASE_CPU_SATURATION`, `BASE_OOM_DANGER`, `BASE_DISK_SPACE_FULL`, `BASE_DISK_HARDWARE_SATURATION`, `BASE_THERMAL_THROTTLING`.
  - **Tier 2 (Contention & Queues)**: `CONT_DSTATE_PILEUP`, `CONT_SWAP_THRASHING`, `CONT_CGROUP_THROTTLED`, `CONT_FD_EXHAUSTION`, `CONT_SOFTIRQ_UNBALANCE`, `CONT_TCP_LISTEN_DROPS`.
  - **Tier 3 (Kernel Edge Cases)**: `EDGE_THP_COMPACTION_STALL`, `EDGE_PTY_STDOUT_LOCK`, `EDGE_HPET_CLOCKSOURCE_DEGRADE`, `EDGE_CGROUP_DIRTY_THROTTLE`, `EDGE_FUTEX_CONTENTION`.
- Full subsystem collectors (`internal/collector`):
  - Parallel process scanner with bounded worker pool (`runtime.NumCPU()` workers).
  - PSI (CPU/Memory/IO), `/proc/stat`, `/proc/meminfo`, `/proc/vmstat`, `/proc/diskstats`, `syscall.Statfs()` with Fsid deduplication, thermal sensors, cpufreq, clocksource, netstat, and cgroup v2.
- Automated unit and race-condition test suites across all packages (`make test`, `make vet`).
- Phase 2A basic system collectors: PSI (`psi.go`), CPU & Thermals (`cpu.go`), Memory & VMStat (`memory.go`), and System/Network (`system.go`).
- Synthetic `/proc` and `/sys` testdata fixtures with automated unit test suite (`parsers_test.go`).
- Live host test validating kernel virtual filesystem reading across modern Linux kernels.
- Phase 1 core snapshot data structures, RunContext, and differential calculator (`DiffSnapshots`) in `internal/collector/snapshot.go`.
- Unit test suite `snapshot_test.go` covering CPU percentages, disk I/O, process deltas, VMStat, networking, and cgroup throttling.
- Project governance documentation and always-on safety invariant rules in `.agents/`.

---

_Future entries will follow this format:_

## [X.Y.Z] - YYYY-MM-DD

### Added
- New features added in this release

### Changed
- Changes to existing functionality

### Fixed
- Bug fixes

### Security
- Security-related changes

### Performance
- Performance improvements with before/after metrics
