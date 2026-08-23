# why-slow — Complete Diagnostic Rules Catalog

This document details all **47 diagnostic rules** implemented in `why-slow`, organized by priority tier.

---

## 🔴 Tier 1: Base Hard Limits (P0 Priority)

Tier 1 rules represent absolute, unrecoverable system capacity limits. When any Tier 1 rule triggers, it automatically becomes the **Primary Blocker** and demotes lower-tier findings to secondary/contributing factors.

| Rule ID | Severity | Description | Trigger Conditions | Remediation |
|---|---|---|---|---|
| `BASE_CPU_SATURATION` | Critical | 100% CPU starvation with overloaded runqueue | `IdlePercent < 2.0%` AND `ProcsRunning >= 2× Cores` | Renice or throttle runaway compute processes (`renice -n 19 -p <PID>`) |
| `BASE_OOM_DANGER` | Critical | Imminent kernel OOM killer execution | `MemAvailable < 3%` AND `SwapFree < 5%` | Free memory, terminate memory hogs (`kill -TERM <PID>`), configure cgroups |
| `BASE_DISK_SPACE_FULL` | Critical | Filesystem mount capacity full | Storage used `≥ 99.0%` on `/`, `/tmp`, or `/var` | Clean up logs, expand volume, or clear temp files |
| `BASE_DISK_HARDWARE_SATURATION` | Critical | Storage block device 100% busy | Device I/O utilization `≥ 95.0%` | Lower process I/O class (`ionice -c3 -p <PID>`) or throttle writes |
| `BASE_THERMAL_THROTTLING` | Critical | Hardware CPU throttling from overheating | Max temp `≥ 85°C` AND core freq `< 40%` max | Inspect cooling fans, clear chassis dust, check heatsinks |
| `BASE_INODE_EXHAUSTION` | Critical | Filesystem inode table exhausted | Inodes used `≥ 99.0%` or 0 free inodes | Delete unneeded small files: `find <mount> -xdev -type f -delete` |
| `BASE_IO_SERVICE_LATENCY` | Critical | SAN / EBS / NVMe storage service delay | Avg read/write latency `≥ 50.0 ms/op` | Inspect storage burst credits, queue depths, or upgrade storage tier |
| `BASE_TCP_SOCKET_MEM_PRESS` | Critical | Kernel TCP socket buffer exhaustion | `TCPMemoryPressures > 0` AND `TCPAbortOnMemory > 0` | Increase `sysctl net.ipv4.tcp_mem` or tune socket read buffers |
| `BASE_SWAP_DEVICE_SATURATION` | Critical | Swap storage device bandwidth saturation | `pswpout_delta ≥ 25k` OR (`pswpout ≥ 10k` AND `pswpin ≥ 2k`) | Lower `vm.swappiness=10`, add RAM, or configure zram / fast NVMe swap |

---

## 🟡 Tier 2: Contention & Queues (P1 Priority)

Tier 2 rules detect resource serialization, locking, queue saturation, and capacity contention bottlenecks.

| Rule ID | Severity | Description | Trigger Conditions | Remediation |
|---|---|---|---|---|
| `CONT_DSTATE_PILEUP` | High | Uninterruptible sleep lock pileup | `≥ 3` processes stuck in uninterruptible sleep ('D' state) | Investigate slow storage/NFS, reduce writeback pressure |
| `CONT_SWAP_THRASHING` | High | Kernel direct page scan & alloc stalls | `PgScanDirectDelta > 0` AND `AllocStallDirectDelta > 0` | Reduce memory footprint, tune `vm.swappiness` |
| `CONT_CGROUP_THROTTLED` | High | Container / service cgroup CPU quota hit | `ThrottledUsecDelta ≥ 100ms` across sampling window | Increase container CPU limit (`cpu.max` in cgroup definition) |
| `CONT_FD_EXHAUSTION` | High | Process file descriptor limit saturation | `OpenFDs / MaxFDs ≥ 90.0%` | Increase process soft limit: `prlimit --nofile=<N> -p <PID>` |
| `CONT_SOFTIRQ_UNBALANCE` | High | Single-core network softirq storm | Single core `SoftIRQ ≥ 80%` while system idle `≥ 50%` | Enable Receive Packet Steering (RPS/RFS) or configure `irqbalance` |
| `CONT_TCP_LISTEN_DROPS` | High | Saturated server application listen queue | `ListenDropsDelta > 0` OR `ListenOverflowsDelta > 0` | Raise socket backlog: `sysctl -w net.core.somaxconn=4096` |
| `CONT_PID_EXHAUSTION` | High | Kernel process table PID ceiling reached | Active PIDs `≥ 95%` of `kernel.pid_max` | Raise PID ceiling: `sysctl -w kernel.pid_max=4194304` |
| `CONT_TIMEWAIT_PORT_EXHAUSTION` | High | Outbound port exhaustion from TIME_WAIT | `TCPTimeWait ≥ 85%` of ephemeral port range | Enable `sysctl -w net.ipv4.tcp_tw_reuse=1`, enable HTTP Keep-Alive |
| `CONT_VCPU_STEAL_TIME` | High | Hypervisor host CPU overcommit | Steal time `≥ 15%` aggregate or `≥ 30%` per core | Migrate VM, configure dedicated vCPU pinning, upgrade instance |
| `CONT_BALLOON_OVERCOMMIT` | High | Hypervisor memory balloon reclamation | Balloon driver inflated `≥ 20%` of guest physical RAM | Configure hypervisor memory reservations to prevent overcommit |
| `CONT_CONNTRACK_EXHAUSTION` | High | Netfilter connection tracking table full | `nf_conntrack_count / max ≥ 90.0%` | Increase table size: `sysctl -w net.netfilter.nf_conntrack_max=1048576` |
| `CONT_ARP_NEIGHBOR_OVERFLOW` | High | ARP / Neighbor cache table saturation | Active ARP entries `≥ 85%` of `gc_thresh3` | Increase cache limit: `sysctl -w net.ipv4.neigh.default.gc_thresh3=4096` |
| `CONT_TCP_SYN_QUEUE_OVERFLOW` | High | Inbound SYN backlog queue overflow | `TCPReqQFullDoCookiesDelta > 0` (SYN cookies generated) | Increase SYN backlog: `sysctl -w net.ipv4.tcp_max_syn_backlog=65535` |
| `CONT_BLK_MQ_TAG_STARVATION` | High | Block layer NVMe/SSD submission tag stall | `≥ 2` processes waiting in `blk_mq_get_tag` wchan | Increase queue depth: `echo 1024 > /sys/block/<dev>/queue/nr_requests` |
| `CONT_SCHED_RUNQUEUE_STARVATION`| High | High CPU scheduler runqueue wait delay | Runqueue wait-to-execution ratio `≥ 1.5×` | Reduce concurrency / thread pool size or tune `sched_migration_cost_ns` |
| `CONT_CGROUP_MEM_HIGH_THROTTLE` | High | Cgroup v2 proactive page delay sleep | `MemoryHighEventsDelta > 0` in cgroup `memory.events` | Raise container soft memory limit (`memory.high`) |
| `CONT_IO_QUEUE_LATENCY` | High | Disk scheduler queue delay spike | Avg scheduler queue wait `≥ 100.0 ms/op` | Switch scheduler: `echo none > /sys/block/<dev>/queue/scheduler` |
| `CONT_PAGE_TABLE_LOCK` | High | Virtual memory page table lock contention | `≥ 2` processes stalled in `mmap_lock` / `page_table_lock` | Reduce memory-intensive thread concurrency or use jemalloc arena pools |
| `CONT_ORPHAN_SOCKET_LEAK` | High | Leaked unreferenced orphan TCP sockets | `TCPOrphan ≥ 1000` AND (`≥ 50%` inuse or `≥ 5000` total) | Fix application socket leak or tune `sysctl net.ipv4.tcp_max_orphans` |

---

## 🔵 Tier 3: Subtle Kernel Edge Cases (P2 Priority)

Tier 3 rules detect subtle driver, memory subsystem, and timekeeping edge cases that degrade latency without appearing in standard user-space monitoring.

| Rule ID | Severity | Description | Trigger Conditions | Remediation |
|---|---|---|---|---|
| `EDGE_THP_COMPACTION_STALL` | Medium | THP 2MB page defragmentation stalls | `CompactStallDelta > 0` or process in `compact_zone` | Change defrag mode: `echo madvise > /sys/kernel/mm/transparent_hugepage/defrag` |
| `EDGE_PTY_STDOUT_LOCK` | Medium | Process stalled on unread stdout / pipe | Process in `n_tty_write`, `pty_write`, or `pipe_wait` | Redirect verbose output to file or discard (`> /dev/null`) |
| `EDGE_HPET_CLOCKSOURCE_DEGRADE` | High | Degraded slow MMIO clocksource | Clocksource is `hpet` or `acpi_pm` instead of `tsc` | Check dmesg for TSC desync, add kernel boot param `clocksource=tsc` |
| `EDGE_CGROUP_DIRTY_THROTTLE` | Medium | Process sleeping in dirty page flush | Process blocked in `balance_dirty_pages` wchan | Tune `sysctl vm.dirty_ratio` / `vm.dirty_background_ratio` |
| `EDGE_FUTEX_CONTENTION` | Medium | Multi-threaded user mutex contention | Process with `≥ 50` threads blocked in `futex` | Profile mutex contention (perf / pprof) or reduce thread pool size |
| `EDGE_NUMA_REMOTE_THRASHING` | Medium | Remote NUMA cross-socket memory latency | `NumaMissDelta ≥ 5000` or `NumaForeignDelta ≥ 5000` | Bind application to local NUMA node: `numactl --cpunodebind=0 --membind=0` |
| `EDGE_CPU_AFFINITY_PIN` | Medium | Single-core CPU pinning bottleneck | Single-core pinned process at `≥ 90%` CPU while system idle `≥ 75%` | Expand CPU mask: `taskset -p 0xffffffff <PID>` |
| `EDGE_ZOMBIE_DEFUNCT_LEAK` | Medium | Unreaped defunct zombie child process leak | `≥ 50` zombie processes in process table | Signal parent process to reap children: `kill -HUP <PPID>` |
| `EDGE_CGROUP_OOM_KILL_EVENT` | High | Container OOM kill event occurred | `OOMKillsDelta > 0` in cgroup `memory.events` | Increase container RAM limit (`docker update --memory <size>`) |
| `EDGE_ZONE_DMA32_EXHAUSTION` | Medium | Low-memory DMA32 zone depletion (< 4GB) | DMA32 zone has 0 free pages while Normal zone has ample free RAM | Tune `sysctl vm.zone_reclaim_mode=0` or upgrade legacy 32-bit drivers |
| `EDGE_KSM_SCAN_STALL` | Medium | KSM memory deduplication cache thrashing | KSM active with `pages_to_scan ≥ 10k` AND `ksmd` CPU `≥ 50%` | Disable KSM (`echo 0 > /sys/kernel/mm/ksm/run`) or raise sleep interval |
| `EDGE_IRQ_CORE_STORM` | Medium | Hardware interrupt storm on single core | Core handles `≥ 50k` IRQs and `≥ 5×` average of other cores | Start `irqbalance` service or adjust SMP IRQ affinity routing |
| `EDGE_SLAB_UNRECLAIM_LEAK` | Medium | Unreclaimable dentry/inode slab leak | `SUnreclaim` occupies `≥ 40%` of physical system RAM | Drop clean slab caches: `echo 2 > /proc/sys/vm/drop_caches` |
| `EDGE_INOTIFY_WATCH_EXHAUSTION` | Medium | Restrictive inotify user watch limit | `max_user_watches <= 8192` | Raise watch limit: `sysctl -w fs.inotify.max_user_watches=524288` |
| `EDGE_RCU_SCHEDULER_STALL` | Medium | Kernel RCU grace period sync stall | `≥ 2` tasks blocked in `synchronize_rcu` / `rcu_gp_kthread` | Inspect non-preemptible kernel routines, pin RT tasks away from CPU 0 |
| `EDGE_THP_COLLAPSE_STALL` | Medium | Background hugepage collapse latency | `THPCollapseAllocDelta > 0` during direct allocation stalls | Disable background defrag: `echo 0 > /sys/kernel/mm/transparent_hugepage/khugepaged/defrag` |
| `EDGE_FUSE_FS_STALL` | Medium | Process stalled on user-space FUSE daemon | `≥ 1` process blocked in `fuse_request_wait` wchan | Inspect FUSE mount daemon (sshfs/s3fs), or move data to ext4/xfs |
| `EDGE_COMPACT_FAIL_RATE` | Medium | High memory compaction failure rate | `CompactStallDelta ≥ 50` AND `CompactFail / Stall ≥ 50%` | Trigger proactive compaction: `echo 1 > /proc/sys/vm/compact_memory` |
| `EDGE_MAJOR_PAGE_FAULT_STORM` | Medium | Major page fault synchronous disk reads | `PgMajFaultDelta ≥ 500` in sampling window | Preload working set into memory page cache (`vmtouch`) |
