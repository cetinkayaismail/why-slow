# why-slow — Complete Diagnostic Rules Catalog

This document details all **160 diagnostic rules** implemented in `why-slow`, organized by priority tier.

---

## 🔴 Tier 1: Base Hard Limits (P0 Priority — 13 Rules)

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
| `BASE_SWAP_DEVICE_SATURATION` | Critical | Dedicated Swap Partition/File I/O Thrashing | `PswpoutDelta ≥ 5000` OR `PswpinDelta ≥ 5000` with high swap usage | Reduce memory consumption or add RAM |
| `BASE_FS_READONLY_REMOUNT` | Critical | Critical Filesystem Remounted Read-Only | Mount on `/`, `/var`, `/tmp`, `/home`, `/data` is `ro` | Check dmesg for I/O errors and run `fsck` |
| `BASE_SYSTEM_FILE_TABLE_FULL` | Critical | Global Operating System Open File Table Full (ENFILE) | `/proc/sys/fs/file-nr` allocated $\ge 99\%$ of `fs.file-max` | `sysctl -w fs.file-max=2097152` |
| `BASE_GLOBAL_OOM_KILL_ACTIVE` | Critical | Host Linux Kernel Out-Of-Memory (OOM) Killer Invoked | `/proc/vmstat` `oom_kill` delta $> 0$ | Identify and constrain memory-hungry processes via cgroups |
| `BASE_CONNTRACK_TABLE_HARD_DROP` | Critical | Netfilter Conntrack Table 100% Full (Packet Drop Blackhole) | `nf_conntrack_count == nf_conntrack_max` (100.0% full) | `sysctl -w net.netfilter.nf_conntrack_max=1048576` |

---

## 🟡 Tier 2: Contention & Queues (P1 Priority — 84 Rules)

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
| `CONT_CONTEXT_SWITCH_STORM` | High | Scheduler context switch rate thrashing | `ContextSwitchesDelta / sec ≥ 100k` AND System CPU `≥ 20%` | Reduce worker concurrency, increase I/O batch size, eliminate spinloops |
| `CONT_CPU_GOVERNOR_POWERSAVE_LAG`| High | CPU frequency clamped by powersave governor | CPU Busy `≥ 75%` AND core freq `≤ 50%` max in `powersave` | Change governor: `echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor` |
| `CONT_KSOFTIRQD_SATURATION` | High | Deferred softirq daemon CPU saturation | `ksoftirqd/*` CPU `≥ 40%` AND SoftIRQ time `≥ 20%` | Enable RPS/RFS packet steering, tune multiqueue NIC, raise `netdev_budget` |
| `CONT_WORKINGSET_REFAULT_THRASHING`| High| Page cache churn & refault thrashing | `WorkingsetRefaultFileDelta ≥ 5000` under memory pressure | Add RAM, downsize buffer pools, or pin hot data using `vmtouch` |
| `CONT_DIRTY_PAGE_FLUSH_SATURATION` | High | Dirty writeback buffer saturation | Dirty `≥ 15%` RAM with process in `balance_dirty_pages` | Lower `vm.dirty_background_ratio=5`, increase disk throughput |
| `CONT_FSYNC_JOURNAL_STALL` | High | Filesystem journal transaction serialization | `≥ 2` processes in `jbd2_log_wait_commit` / `vfs_fsync` | Group commits, tune commit intervals, isolate WAL on dedicated NVMe |
| `CONT_PAGECACHE_POLLUTION_STREAM` | High | Bulk streaming I/O evicting working set | Single PID I/O `≥ 50MB/s` AND file refaults `≥ 1000` | Use `posix_fadvise(POSIX_FADV_DONTNEED)` or `nocache` for backups |
| `CONT_NET_SOFTNET_BACKLOG_DROPS` | High | Host NIC driver backlog queue drops | `SoftnetDroppedDelta > 0` OR `TimeSqueezeDelta ≥ 50` | Raise `sysctl -w net.core.netdev_max_backlog=10000` & `netdev_budget=600` |
| `CONT_TCP_RETRANSMIT_STORM` | High | High TCP segment retransmission rate | `RetransSegs / OutSegs ≥ 5.0%` with OutSegs `≥ 500` | Check network MTU, inspect switch drops, switch congestion control to BBR |
| `CONT_TCP_ZEROWINDOW_STALL` | High | TCP receiver buffer ZeroWindow stall | `TCPWinProbeDelta ≥ 5` OR `sk_stream_wait_memory` wchan | Increase consumer read concurrency, expand `net.ipv4.tcp_rmem` |
| `CONT_COREDUMP_BURST_STORM` | High | Crashlooping processes core dumper burn | Core dumper active with fork rate `≥ 10` processes/sec | Stop crashlooping containers, disable dumps (`ulimit -c 0`), fix crashes |
| `CONT_UNIX_SOCKET_LOG_BLOCK` | High | Saturated Unix domain logging socket | `≥ 2` processes waiting in `unix_wait_for_peer` / `unix_stream_sendmsg` | Lower log verbosity, use async logging, raise `RateLimitBurst` in journald |
| `CONT_UDP_BUFFER_OVERRUN` | High | Saturated UDP socket receive/send queue | `UDPRcvbufErrorsDelta > 0` OR `UDPSndbufErrorsDelta > 0` | Raise `sysctl -w net.core.rmem_max=16777216` and application `SO_RCVBUF` |
| `CONT_TCP_LISTEN_OVERFLOW_STALL` | High | Saturated TCP listen backlog connection drops | `ListenOverflowsDelta > 0` AND `TCPAbortOnDataDelta > 0` | Raise `sysctl -w net.core.somaxconn=8192` and increase worker concurrency |
| `CONT_HUGETLB_POOL_EXHAUSTION` | High | Explicit HugePages pool 100% exhausted | `HugePages_Total > 0` AND `HugePages_Free == 0` AND `Rsvd > 0` | Increase pool: `sysctl -w vm.nr_hugepages=<N>` or downsize database buffers |
| `CONT_PTRACE_TRACER_ATTACH` | High | Process degraded by attached debugger/tracer | Process CPU `≥ 20%` with `TracerPid > 0` (ptrace) | Detach interactive debugger (strace/gdb), use sampling profilers (`perf`/eBPF) |
| `CONT_SYSV_SEMAPHORE_LIMIT` | High | SysV IPC semaphore table capacity saturation | Active semaphores `≥ 90%` of `SEMMNS` or sets `≥ 90%` `SEMMNI` | Increase limits: `sysctl -w kernel.sem="50100 64128000 50100 1280"` |
| `CONT_TCP_TIMEWAIT_BUCKET_OVERFLOW` | High | TCP TIME_WAIT bucket table drops | `TCPTimeWaitOverflowDelta > 0` OR `TCPTimeWait ≥ 85%` buckets | Raise limit: `sysctl -w net.ipv4.tcp_max_tw_buckets=2000000` |
| `CONT_CGROUP_IO_THROTTLE_STALL` | High | Container Cgroup v2 I/O bandwidth throttle | Process in `io_schedule`/`D-state` under PSI Full IO `≥ 10%` | Increase container I/O bandwidth: `docker update --io-max-bandwidth` |
| `CONT_AUDITD_BACKLOG_WAIT_STALL` | High | Linux Audit Subsystem Backlog Sync Stall | `≥ 2` processes in `kauditd_wait`/`audit_log_start` AND `ProcsBlocked ≥ 2` or D-state | `auditctl -b 8192 -f 0` or disable auditing (`auditctl -e 0`) |
| `CONT_TCP_SNDBUF_EXHAUSTION` | High | Outbound TCP Socket Send Buffer Starvation | Process in `sk_stream_wait_memory`/`tcp_sendmsg_locked` AND retrans/mem press | `sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"` & `tcp_window_scaling=1` |
| `CONT_XFS_AIL_PUSH_STALL` | High | XFS Journal Active Item List (AIL) Log Lock Stall | `≥ 2` processes in `xfs_log_reserve`/`xfsaild` AND PSI IO Some `≥ 15%` or `ProcsBlocked ≥ 2` | `mount -o remount,logbufs=8,logbsize=256k <mount>` or expand log size |
| `CONT_DM_QUEUE_CONGESTION` | High | Device-Mapper / LVM / LUKS Virtual Queue Saturation | `dm-*` device `UtilPercent ≥ 80%` & `WriteLatency ≥ 50ms` AND in-flight I/O $\ge 5$ | `echo 1024 > /sys/block/<dev>/queue/nr_requests` & `echo none > .../scheduler` |
| `CONT_TCP_SYN_COOKIE_FLOOD_STALL` | High | TCP Inbound SYN Cookie Burst & Handshake Degradation | `SyncookiesSentDelta ≥ 50` AND (`SyncookiesFailed > 0` OR `OutSegs ≥ 500`) | `sysctl -w net.ipv4.tcp_max_syn_backlog=65535` & `net.core.somaxconn=65535` |
| `CONT_EPOLL_WAKEUP_CONTENTION` | High | Multi-Worker Epoll Thundering Herd Wakeup Contention | $\ge 8$ processes in `epoll_wait` AND `ContextSwitches ≥ 50k/s` & `SystemCPU ≥ 15%` | Use `SO_REUSEPORT` listeners or `EPOLLEXCLUSIVE` in epoll event loops |
| `CONT_AIO_EVENT_LIMIT_SATURATION` | High | Kernel Asynchronous I/O Event Ceiling Saturation | `AIONR / AIOMaxNR ≥ 90.0%` AND process in `io_submit`/`D-state` | Increase AIO limit: `sysctl -w fs.aio-max-nr=1048576` |
| `CONT_KSWAPD_CPU_SPIN` | High | Background Memory Reclaim Daemon kswapd CPU Saturation | `kswapd*` CPU `≥ 40%` AND page scan / alloc stall / refault churn | `sysctl -w vm.watermark_scale_factor=200 && sysctl -w vm.vfs_cache_pressure=50` |
| `CONT_MD_RAID_RESYNC_STALL` | High | Software RAID Array Resync & Rebuild I/O Saturation | Active `resync`/`recovery` on `/dev/md*` with disk latency $\ge 50\text{ms}$ | `sysctl -w dev.raid.speed_limit_max=20000 && sysctl -w dev.raid.speed_limit_min=1000` |
| `CONT_NET_OUT_OF_ORDER_STALL` | High | TCP Out-of-Order Queue Overflow & SACK Recovery Stall | `TCPOFOQueueDelta ≥ 500` AND buffer collapse or dropped OFO | `sysctl -w net.ipv4.tcp_reordering=6 && sysctl -w net.ipv4.tcp_rmem="4096 131072 16777216"` |
| `CONT_POSIX_RTSIG_QUEUE_SATURATION` | High | POSIX Real-Time Signal Queue Capacity Saturation | `SigQ` queued `≥ 85%` of limit with $\ge 16$ threads or D-state | Increase signal queue: `sysctl -w kernel.rtsig-max=65536` |
| `CONT_UDP_SNDBUF_EXHAUSTION` | High | UDP Socket Transmit Buffer Exhaustion | `UDPSndbufErrorsDelta ≥ 25` with OutSegs $\ge 200$ | `sysctl -w net.core.wmem_max=16777216 && sysctl -w net.core.wmem_default=262144` |
| `CONT_CGROUP_V1_CPU_SHARES_STARVATION` | High | Cgroup Container CPU Shares Starvation | `CPUShares <= 64` under host CPU Busy $\ge 70\%$ | `docker update --cpu-shares=1024 <container>` |
| `CONT_HUGEPAGE_LEAK_NO_REUSE` | High | Reserved Explicit HugePages Memory Lock Leak | HugePages reserved $\ge 25\%$ RAM with `MemAvailable < 20%` | `sysctl -w vm.nr_hugepages=0` or restart database service |
| `CONT_NET_TCP_ABORT_ON_CLOSE` | High | TCP Socket Reset on Close with Unread Buffer Data | `TCPAbortOnCloseDelta ≥ 20` with OutSegs $\ge 200$ | Drain socket receive buffer before closing |
| `CONT_SCHED_YIELD_SPIN_CHURN` | High | Scheduler Yield Tight Spinloop Churn | Voluntary context switches $\ge 15\text{k/s}$ with process CPU $\ge 35\%$ | Replace busy-spin `sched_yield` with futex/eventfd parking |
| `CONT_NET_TCP_COLLAPSE_PRUNE` | High | TCP Receive Buffer Pruning and Memory Collapse | `TCPRcvCollapsedDelta ≥ 20` AND abort on memory or retransmits | `sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216" && sysctl -w net.ipv4.tcp_adv_win_scale=2` |
| `CONT_NET_TCP_MEMORY_ALLOC_FAIL` | High | TCP Socket Page Allocation Memory Failure | `TCPAbortOnMemoryDelta ≥ 5` AND zero window drops or memory pressures | `sysctl -w net.ipv4.tcp_mem="786432 1048576 1572864"` |
| `CONT_NET_TCP_ZERO_WINDOW_DROP` | High | TCP Receiver Zero-Window Stall & Drop | `TCPZeroWindowDropDelta ≥ 10` OR window probe with outbound segments | Ensure receiver drains socket buffers quickly or tune TCP window scale |
| `CONT_FUTEX_PI_DEADLOCK_STALL` | High | Priority-Inheritance Futex Mutex Lock Stall | Process in `futex_lock_pi` / `rt_mutex_slowlock` with 0 CPU | Inspect process mutex stacks with gdb/pprof or restart service |
| `CONT_NET_ARP_TABLE_TRASH` | High | ARP / Neighbor Table Capacity Saturation | Active ARP entries $\ge 85\%$ of `gc_thresh3` | `sysctl -w net.ipv4.neigh.default.gc_thresh3=8192 && sysctl -w net.ipv4.neigh.default.gc_thresh2=4096` |
| `CONT_DIRTY_PAGES_DIRECT_SYNC_STALL` | High | Dirty Page Cache Direct Sync Flusher Stall | Process in `sync_inodes` / `wait_on_page_writeback` or `NRDirtyDelta ≥ 2000` | `sysctl -w vm.dirty_background_ratio=5 && sysctl -w vm.dirty_ratio=15` |
| `CONT_NFS_RPC_SLOT_TABLE_SATURATION` | High | NFS Client RPC Slot Table Saturation | Process in `nfs_wait_client` / `rpc_wait_bit_killable` in D-state | `sysctl -w sunrpc.tcp_slot_table_entries=128` or inspect NFS mount |
| `CONT_UNIX_SOCKET_BACKLOG_OVERFLOW` | High | UNIX Domain Socket Queue Backlog Overflow | Process in `unix_stream_sendmsg` / `unix_wait_for_peer` with 0 CPU | Ensure receiving daemon drains socket queues or restart service |
| `CONT_VFS_INODE_LOCK_CONTENTION` | High | VFS Inode Mutex Serialization Contention | Process in `inode_lock_shared` / `ext4_file_write_iter` in D-state | Shard file writes across distinct directories or use direct/async I/O |
| `CONT_KERNEL_LOCKD_BLOCKED` | High | POSIX Advisory File Lock Contention (fcntl/flock) | Process in `fcntl_setlk` / `locks_lock_inode_wait` with 0 CPU | Inspect locks via `/proc/locks` or `lslocks` to identify blocker |
| `CONT_SCHED_AUTOGROUP_STARVATION` | High | CFS Session Autogroup CPU Bandwidth Starvation | Process with $\ge 16$ threads at low CPU under saturated runqueue | `sysctl -w kernel.sched_autogroup_enabled=0` or isolate service |
| `CONT_FTRACE_RING_BUFFER_STALL` | High | Kernel Ftrace / Tracepoint Ring Buffer Saturation | Process in `ring_buffer_wait` / `tracing_wait_pipe` in D-state | Disable tracing: `echo 0 > /sys/kernel/debug/tracing/tracing_on` |
| `CONT_NET_DEV_GRO_CELL_DROP` | High | Network GRO / Softnet Receive Processing Queue Drops | `SoftnetDroppedDelta ≥ 20` AND `SoftnetTimeSqueezeDelta ≥ 20` | `sysctl -w net.core.netdev_budget=600 && sysctl -w net.core.netdev_budget_usecs=4000` |
| `CONT_MEM_COMPACT_MIGRATION_FAIL_RATE` | High | Memory Compaction Page Migration Failure Storm | `CompactStallDelta ≥ 50` AND `CompactFailDelta ≥ 25` ($\ge 50\%$ fail) | `echo 1 > /proc/sys/vm/compact_memory` |
| `CONT_NET_TCP_FASTOPEN_FAIL` | High | TCP Fast Open Active/Passive Cookie Rejection Drop | `TCPFastOpenActiveFailDelta + TCPFastOpenPassiveFailDelta ≥ 5` | `sysctl -w net.ipv4.tcp_fastopen=3` |
| `CONT_NET_TCP_SYN_ACK_RETRANS_STALL` | High | TCP Connection Establishment SYN/SYN-ACK Retransmission Stall | `TCPSynRetransDelta ≥ 20` | Check network routing, MTU, or remote firewall drops |
| `CONT_NET_SOCKET_RECV_STALL` | High | Process Stalled on Socket Ingress Buffer Wait (D-state) | Process in `sk_wait_data` / `tcp_recvmsg` in D-state | Check network throughput or sender throttling |
| `CONT_STORAGE_BLK_THROTTLE_STALL` | High | Process Blocked in Cgroup Block I/O Throttling Queue | Process in `blk_throtl_dispatch_work_fn` / `throtl_pending_timer_fn` | Increase container I/O rate limits: `docker update --device-read-bps` |
| `CONT_NET_TCP_DEFER_ACCEPT_TIMEOUT` | High | TCP Defer Accept Listener Timeout Aborts | `TCPDeferAcceptDropDelta ≥ 10` | Tune application defer accept timeout or inspect client keep-alive |
| `CONT_MEMCG_RECLAIM_DIRECT_STALL` | High | Process Stalled in Cgroup Direct Memory Reclaim | Process in `try_to_free_mem_cgroup_pages` / `mem_cgroup_reclaim` in D-state | Increase container memory limit: `docker update --memory <size>` |
| `CONT_XFS_ALLOC_BTREE_CONTENTION` | High | XFS Allocation Btree Serialization Contention | Process in `xfs_alloc_fixup_trees` / `xfs_btree_lookup` in D-state | Mount XFS with `allocsize=64m` or distribute concurrent file writes |
| `CONT_SCHED_MIGRATION_COST_OVERHEAD` | High | Hyperactive Scheduler Task Migration (Cache Thrashing) | `sched_migration_cost_ns == 0` AND context switches $\ge 50\text{k/s}$ | `sysctl -w kernel.sched_migration_cost_ns=500000` |
| `CONT_NET_TCP_ZERO_WINDOW_ADVERT` | High | TCP Zero-Window Receive Buffer Advertisement Stall | `TCPWinProbeDelta ≥ 20` OR `TCPZeroWindowDropDelta ≥ 10` | `sysctl -w net.ipv4.tcp_adv_win_scale=2` & enlarge application buffers |
| `CONT_PSI_SOME_IO_PRESSURE_SPIKE` | High | Elevated Linux I/O Pressure Stall Spike (PSI io.some) | PSI I/O `some` avg10 $\ge 25.0\%$ | Check disk I/O queue depths, writeback buffers, or migrate to NVMe |
| `CONT_PSI_SOME_CPU_PRESSURE_SPIKE` | High | Elevated Linux CPU Pressure Stall Spike (PSI cpu.some) | PSI CPU `some` avg10 $\ge 30.0\%$ | Renice background batch tasks, pin latency workloads, or scale CPU |
| `CONT_PSI_FULL_MEMORY_PRESSURE_SPIKE` | High | Critical Memory Pressure Stall Spike (PSI memory.full) | PSI Memory `full` avg10 $\ge 15.0\%$ | Provision additional physical RAM, tune zram/zswap, or restrict memory |
| `CONT_PIPE_READ_BURST_BLOCK` | High | Process Blocked on Pipe Read Wait | Process in `pipe_read` / `fifo_read` in D-state | Enlarge pipe buffer via `fcntl(F_SETPIPE_SZ)` or diagnose producer stall |
| `CONT_RUNAWAY_CPU_PROCESS` | High | Runaway Compute CPU Hog | Process CPU $\ge 80.0\%$ on single core with standard policy | `renice -n 19 -p <PID>` or configure cgroup `cpu.max` |
| `CONT_SUSTAINED_LOAD_SATURATION` | High | Sustained Multi-Minute CPU Runqueue Overload | Load1 $\ge 2\times\text{Cores}$ AND Load5 $\ge 1.5\times\text{Cores}$ | Scale out compute instances or audit thread pool concurrency |
| `CONT_TCP_CLOSE_WAIT_LEAK` | High | Application TCP Socket Leak (CLOSE_WAIT Pileup) | CLOSE_WAIT sockets $\ge 100$ and ratio $\ge 10\%$ of established | Inspect application connection pool and HTTP client `body.Close()` |

---

## 🔵 Tier 3: Subtle Kernel Edge Cases (P2 Priority — 63 Rules)

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
| `EDGE_THP_SPLIT_STORM` | Medium | THP 2MB hugepage splitting lock storm | `THPSplitDelta ≥ 500` under allocation stalls | Disable THP: `echo never > /sys/kernel/mm/transparent_hugepage/enabled` |
| `EDGE_KHUGEPAGED_CPU_BURN` | Medium | Daemon khugepaged burning CPU on failed merges | `khugepaged` CPU `≥ 40%` AND failed collapses `> 0` | Disable khugepaged defrag: `echo 0 > /sys/kernel/mm/transparent_hugepage/khugepaged/defrag` |
| `EDGE_DISK_DEVICE_IOERR_HANG` | High | Disk block device command timeout / hang | In-flight IOs `≥ 3` with 0 completed reads/writes & `≥ 85%` util | Inspect kernel dmesg for SCSI/NVMe timeouts, check SMART diagnostics |
| `EDGE_KCOMPACTD_CPU_SPIN` | Medium | Proactive memory compaction daemon CPU spin | `kcompactd*` CPU `≥ 40%` with compaction failures `> 0` | Lower `vm.compaction_proactiveness=20` or trigger manual compaction |
| `EDGE_MIN_FREE_KBYTES_STALL` | Medium | Undersized watermark direct reclaim stalls | `min_free_kbytes < 0.25% RAM` AND `AllocStallDirectDelta ≥ 10` | Raise watermark: `sysctl -w vm.min_free_kbytes=<1-2% RAM>` |
| `EDGE_CORE_PATTERN_PIPE_STALL` | Medium | Processes hung piping core dumps to helper | `≥ 2` processes blocked in `do_coredump` / `pipe_wait` | Restart coredump handler daemon or reset: `sysctl -w kernel.core_pattern=core` |
| `EDGE_TCP_PAWS_DROP` | Medium | TCP PAWS timestamp collision drops behind NAT | `PAWSEstabDelta ≥ 10` OR `PAWSPassiveDelta ≥ 10` | Disable timestamps on NAT endpoints: `sysctl -w net.ipv4.tcp_timestamps=0` |
| `EDGE_CMA_ZONE_EXHAUSTION` | Medium | Contiguous Memory Allocator (CMA) pool depletion | `CmaTotal > 0` AND `CmaFree / CmaTotal ≤ 5%` | Add `cma=512M` or `cma=1G` in kernel boot parameters |
| `EDGE_LOOP_DEVICE_SERIALIZATION`| Medium | Loopback block device worker bottleneck | Loop device `UtilPercent ≥ 80%` | Migrate loopback images to native ext4/XFS or raw NVMe partitions |
| `EDGE_RT_SCHED_THROTTLING` | Medium | Real-Time priority tasks throttled by safety limiter | Process in `SCHED_FIFO/RR` at `≥ 90%` CPU with RT limiter active | Add sleep/yield in real-time loops or isolate cores with `isolcpus` |
| `EDGE_NUMA_AUTO_BALANCING_SCAN_STALL` | Medium | Kernel automatic NUMA balancing scanning overhead | `NumaPteUpdatesDelta ≥ 20k` AND System CPU `≥ 10%` | Disable automatic NUMA scanning: `sysctl -w kernel.numa_balancing=0` |
| `EDGE_INOTIFY_QUEUE_OVERFLOW` | Medium | Inotify File Watch Event Queue Overflow | `max_queued_events ≤ 16384` AND watches `≥ 65536` AND context switches `≥ 25k/s` | `sysctl -w fs.inotify.max_queued_events=1048576` |
| `EDGE_CGROUP_CFS_BURST_STARVATION` | Medium | Cgroup v2 CFS CPU Burst Depletion & Throttling | `NrBurstsDelta > 0` AND `NrThrottledDelta > 0` AND throttled `≥ 50ms` | `echo 'max 200000' > /sys/fs/cgroup/<path>/cpu.max.burst` |
| `EDGE_ZSWAP_COMPRESSOR_CONTENTION` | Medium | Zswap Compression Pool Saturation & Reclaim Spin | `ZswpoutDelta ≥ 500` or rejects `> 0` AND alloc stalls `> 0` or System CPU `≥ 20%` | `echo 30 > /sys/module/zswap/parameters/max_pool_percent` & use lz4 |
| `EDGE_NET_IFACE_CARRIER_FLAP` | Medium | Network Interface Carrier Flapping & Link Errors | `CarrierChangesDelta ≥ 3` AND (`RxCRCErrors > 0` OR `TxCarrierErrors > 0` OR `!up`) | `ip link set <iface> down && ip link set <iface> up` or check SFP cable |
| `EDGE_THP_ALLOC_FALLBACK_STALL` | Medium | Transparent HugePage Allocation Direct Reclaim Fallback | `THPFaultFallback ≥ 500` AND (`CompactStall > 0` OR `AllocStallDirect > 0`) | `echo madvise > /sys/kernel/mm/transparent_hugepage/enabled` & compact |
| `EDGE_SCHED_MIGRATION_BOUNCE` | Medium | Aggressive CPU Scheduler NUMA Task Migration Churn | `sched_migration_cost_ns ≤ 25000` AND (`NumaMiss ≥ 2500` OR `ContextSwitches ≥ 35k`) | `sysctl -w kernel.sched_migration_cost_ns=500000` |
| `EDGE_IP_FRAG_REASM_DROPS` | Medium | IP Packet Fragment Reassembly Queue Drops | `ReasmFailsDelta ≥ 10` or `Timeout ≥ 5` with `ReasmReqds ≥ 20` | `sysctl -w net.ipv4.ipfrag_high_thresh=4194304 && sysctl -w net.ipv4.ipfrag_time=60` |
| `EDGE_CGROUP_V2_FREEZE_HANG` | Medium | Cgroup v2 Container Subtree Frozen State Stall | Cgroup `Frozen == true` or process in `cgroup_freeze_task` | Unfreeze cgroup: `echo 0 > /sys/fs/cgroup/<path>/cgroup.freeze` |
| `EDGE_SYSV_SHM_SEGMENT_LIMIT` | Medium | System V Shared Memory Segment Table Exhaustion | `AllocatedSegments / ShmMNI ≥ 90%` or `Pages / ShmAll ≥ 90%` | `sysctl -w kernel.shmmni=8192 && sysctl -w kernel.shmall=4294967296` |
| `EDGE_NET_DEV_RX_NO_BUFFERS` | Medium | NIC Driver RX Ring Buffer Exhaustion Drops | `RxMissedErrorsDelta ≥ 20` or `RxFIFOErrorsDelta ≥ 20` | `ethtool -G <iface> rx 4096 && sysctl -w net.core.netdev_max_backlog=10000` |
| `EDGE_TRANSPARENT_HUGEPAGE_DEFRAG_ALWAYS` | Medium | Aggressive Synchronous THP Defragmentation Stall | THP defrag is `always` with direct compaction stalls | `echo madvise > /sys/kernel/mm/transparent_hugepage/defrag` |
| `EDGE_CGROUP_MEMORY_MAX_OOM_STALL` | Medium | Cgroup v2 Container Memory Max Limit Reclaim Stall | `MemEventsMaxDelta ≥ 5` in cgroup `memory.events` | `docker update --memory=<limit> <container>` |
| `EDGE_THP_SCAN_EXHAUSTION_STALL` | Medium | Transparent HugePages Daemon Scan Rate Exhaustion | `THPScanExceedDelta ≥ 50` under memory fragmentation | `echo 512 > /sys/kernel/mm/transparent_hugepage/khugepaged/pages_to_scan` |
| `EDGE_NET_DEV_TX_QUEUE_TIMEOUT` | Medium | NIC Driver Transmit Queue Timeout & Drop | `TxErrorsDelta ≥ 20` or `TxCarrierErrorsDelta ≥ 5` | `ip link set <iface> down && ip link set <iface> up` or upgrade driver |
| `EDGE_CGROUP_CPU_CORE_PIN_STARVATION` | Medium | Container Cgroup Single CPU Core Pin Starvation | Container process pinned to 1 core at $\ge 85\%$ CPU with host idle $\ge 50\%$ | `echo 0-$(nproc -1) > /sys/fs/cgroup/<path>/cpuset.cpus` |
| `EDGE_HUGETLB_VMA_MISALIGN_FAULT` | Medium | HugePage VMA Fault Misalignment & Allocation Fallback | `THPFaultFallbackDelta ≥ 50` without successful 2MB allocations | Ensure mmap/madvise allocations are 2MB-aligned (`posix_memalign`) |
| `EDGE_TCP_CHRONIC_RTO_COLLAPSE` | Medium | Chronic TCP Retransmission Timeout (RTO) Window Collapse | `TCPTimeoutsDelta ≥ 15` with segment retransmissions | Inspect path jitter/loss with mtr or tune `sysctl -w net.ipv4.tcp_min_rto_ms=50` |
| `EDGE_MEMCG_SOCK_MEMORY_THROTTLE` | Medium | Memory Cgroup Socket Buffer Charge Throttle | Cgroup `MemoryHighEventsDelta > 0` with open sockets | Increase container memory limit or exclude socket buffers |
| `EDGE_TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_SPIN` | Medium | Transparent HugePage Zero-Page Lock Contention & CPU Spin | `THPZeroPageAllocDelta ≥ 100` AND `SystemCPU ≥ 15%` | `echo 0 > /sys/kernel/mm/transparent_hugepage/use_zero_page` |
| `EDGE_SYSFS_CPU_HOTPLUG_LOCK_CONTENTION` | Medium | Kernel CPU Hotplug / Governor Policy Lock Contention | Process in `cpu_hotplug_lock` / `cpuset_mutex` in D-state | Lock CPU governor: `cpupower frequency-set -g performance` |
| `EDGE_NET_IP_MULTICAST_IGMP_REPORT_STALL` | Medium | IP Multicast / UDP Broadcast Socket Buffer Queue Drop | `UDPInErrorsDelta ≥ 50` or `UDPRcvbufErrorsDelta ≥ 10` | `sysctl -w net.ipv4.igmp_max_memberships=1024` & enlarge UDP buffers |
| `EDGE_PROC_PID_TASK_PTHREAD_LIMIT` | Medium | Process POSIX Pthread Count Limit Saturation | Process `NumThreads ≥ 500` | Reduce worker thread pool size or raise `sysctl -w kernel.threads-max` |
| `EDGE_ZONE_NORMAL_FRAGMENTATION` | Medium | Normal Memory Zone High-Order Allocation Fragmentation | `NormalHighOrderPages == 0` AND `NormalOrder0Pages ≥ 500` | Trigger compaction: `echo 1 > /proc/sys/vm/compact_memory` |
| `EDGE_NET_DEV_CARRIER_DOWN_DROP` | Medium | Socket Transmission on Inactive/Down Network Interface | Interface `OperState == "down"` with `TxErrorsDelta > 0` | Bring interface up: `ip link set <iface> up` or verify link carrier |
| `EDGE_PROC_PTRACED_STOPPED_STALL` | Medium | Process Halted in Traced / Stopped State | Process in state 'T'/'t' with `TracerPID != 0` | Resume process execution: `kill -CONT <PID>` or detach debugger |
| `EDGE_MEM_SLAB_DENTRY_PRESSURE` | Medium | Unreclaimable Slab / Dentry Cache Memory Bloat | `SUnreclaim` $\ge 30\%$ RAM with direct page scans $\ge 100$ | `sysctl -w vm.vfs_cache_pressure=150 && echo 2 > /proc/sys/vm/drop_caches` |
| `EDGE_NET_IP_REASM_TIMEOUT_STALL` | Medium | IP Packet Fragment Reassembly Timeout Stalls | `IPReasmTimeoutDelta ≥ 5` OR `IPReasmFailsDelta ≥ 20` | `sysctl -w net.ipv4.ipfrag_high_thresh=8388608 && sysctl -w net.ipv4.ipfrag_time=60` |
| `EDGE_MEM_MIN_WATERMARK_BOUNCE` | Medium | Kernel Memory Low Watermark Oscillation | `PgScanDirectDelta ≥ 50` AND `AllocStallDirectDelta == 0` with low RAM | `sysctl -w vm.min_free_kbytes=131072 && sysctl -w vm.watermark_scale_factor=200` |
| `EDGE_PROC_COMM_SWITCH_TRUNCATION` | Medium | Process Comm Renaming / Prctl Churn | Process with $\ge 150$ threads in `do_prctl` | Avoid dynamic `pthread_setname_np` in high-frequency worker loops |
| `EDGE_EPOLL_POLL_TIMEOUT_BURST` | Medium | Epoll Event Loop Starvation / Timeout Churn | Process in `epoll_pwait` with $\ge 50$ threads, 0% CPU, $\ge 100$ FDs | Tune epoll_wait timeouts and check upstream load balancer |
| `EDGE_NET_TCP_SYN_FLOOD_DROP` | Medium | TCP SYN Flood SYN-Cookie Validation Drops | `SyncookiesFailedDelta ≥ 10` | `sysctl -w net.ipv4.tcp_syncookies=1 && sysctl -w net.ipv4.tcp_max_syn_backlog=32768` |
| `EDGE_SYSFS_POWER_THROTTLE_EVENT` | Medium | Hardware RAPL / Package Power Cap Throttling | Package temp $\ge 75^\circ\text{C}$ with frequency constrained | Inspect cooling fans or disable power capping policies in IPMI/BIOS |
| `EDGE_PROC_ZOMBIE_PARENT_DEADLOCK` | Medium | Parent Supervisor Stalled Reaping Zombie Children | Parent sleeping in `wait4` with $\ge 10$ zombie child processes | Send SIGCHLD to parent: `kill -SIGCHLD <PID>` or restart supervisor |
