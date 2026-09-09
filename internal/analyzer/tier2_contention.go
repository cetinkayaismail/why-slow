// Package analyzer — tier2_contention.go contains Tier 2 (P1 Priority)
// diagnostic rules for contention and queuing bottlenecks:
//
//   - CONT_DSTATE_PILEUP:             ≥ 3 PIDs in uninterruptible sleep (D state)
//   - CONT_SWAP_THRASHING:            Direct reclaim + allocation stalls + PSI > 30%
//   - CONT_CGROUP_THROTTLED:          Cgroup CPU quota exhausted (throttled_usec delta)
//   - CONT_FD_EXHAUSTION:             FD count > 90% of soft limit
//   - CONT_SOFTIRQ_UNBALANCE:         One core at 80%+ softirq, system idle
//   - CONT_TCP_LISTEN_DROPS:          ListenDrops delta > 0
//   - CONT_PID_EXHAUSTION:            Scanned PIDs ≥ 95% of pid_max
//   - CONT_TIMEWAIT_PORT_EXHAUSTION:  TCP TIME_WAIT ≥ 85% of ephemeral ports
package analyzer

import (
	"fmt"
	"strings"
	"why-slow/internal/collector"
)

// GetTier2Rules returns all registered Tier 2 diagnostic rules.
func GetTier2Rules() []Rule {
	return []Rule{
		&RuleDStatePileup{},
		&RuleSwapThrashing{},
		&RuleCgroupThrottled{},
		&RuleFDExhaustion{},
		&RuleSoftIRQUnbalance{},
		&RuleTCPListenDrops{},
		&RulePIDExhaustion{},
		&RuleTimeWaitPortExhaustion{},
		&RuleVCPUStealTime{},
		&RuleBalloonMemoryOvercommit{},
		&RuleConntrackExhaustion{},
		&RuleARPNeighborTableOverflow{},
		&RuleTCPSYNQueueOverflow{},
		&RuleBlockHardwareTagStarvation{},
		&RuleSchedRunqueueStarvation{},
		&RuleCgroupMemoryHighThrottle{},
		&RuleIOSchedulerQueueLatency{},
		&RulePageTableLockContention{},
		&RuleOrphanSocketLeak{},
		&RuleContextSwitchStorm{},
		&RuleCPUGovernorPowersaveLag{},
		&RuleKsoftirqdSaturation{},
		&RuleWorkingsetRefaultThrashing{},
		&RuleDirtyPageFlushSaturation{},
		&RuleFsyncJournalStall{},
		&RulePageCachePollutionStream{},
		&RuleSoftnetBacklogDrops{},
		&RuleTCPRetransmitStorm{},
		&RuleTCPZeroWindowStall{},
		&RuleCoredumpBurstStorm{},
		&RuleUnixSocketLogBlock{},
		&RuleUDPBufferOverrun{},
		&RuleTCPListenOverflowStall{},
		&RuleHugeTLBPoolExhaustion{},
		&RulePtraceTracerAttach{},
		&RuleSysVSemaphoreLimit{},
		&RuleTCPTimeWaitBucketOverflow{},
		&RuleCgroupIOThrottleStall{},
		&RuleAuditdBacklogWaitStall{},
		&RuleTCPSndbufExhaustion{},
		&RuleXFSAILPushStall{},
		&RuleDMQueueCongestion{},
		&RuleTCPSYNCookieFloodStall{},
		&RuleEpollWakeupContention{},
		&RuleAIOEventLimitSaturation{},
		&RuleKswapdCPUSpin{},
		&RuleMDRAIDResyncStall{},
		&RuleNetOutOfOrderStall{},
		&RulePOSIXRTSigQueueSaturation{},
		&RuleUDPSndbufExhaustion{},
		&RuleCgroupV1CPUSharesStarvation{},
		&RuleHugepageLeakNoReuse{},
		&RuleNetTCPAbortOnClose{},
		&RuleSchedYieldSpinChurn{},
		&RuleNetTCPCollapsePrune{},
		&RuleNetTCPMemoryAllocFail{},
		&RuleNetTCPZeroWindowDrop{},
		&RuleFutexPIDeadlockStall{},
		&RuleNetARPTableTrash{},
		&RuleDirtyPagesDirectSyncStall{},
		&RuleNFSRPCClientSaturation{},
		&RuleUnixSocketBacklogOverflow{},
		&RuleVFSInodeLockContention{},
		&RuleKernelLockdBlocked{},
		&RuleSchedAutogroupStarvation{},
		&RuleFtraceRingBufferStall{},
		&RuleNetDevGROCellDrop{},
		&RuleMemCompactMigrationFailRate{},
		&RuleNetTCPFastOpenFail{},
		&RuleNetTCPSynAckRetransStall{},
		&RuleNetSocketRecvStall{},
		&RuleStorageBlkThrottleStall{},
		&RuleNetTCPDeferAcceptTimeout{},
		&RuleMemcgReclaimDirectStall{},
		&RuleXFSAllocBtreeContention{},
		&RuleSchedMigrationCostOverhead{},
		&RuleNetTCPZeroWindowAdvert{},
		&RulePSISomeIOPressureSpike{},
		&RulePSISomeCPUPressureSpike{},
		&RulePSIFullMemoryPressureSpike{},
		&RulePipeReadBurstBlock{},
		&RuleTCPCloseWaitLeak{},
		&RuleSustainedLoadSaturation{},
		&RuleRunawayCPUProcess{},
		&RuleProcessSwapPinned{},
		&RuleDentryCacheExplosion{},
	}
}

var tier2Explanations = map[string]RuleExplanation{
	"CONT_DSTATE_PILEUP": {
		Description: "Processes are frozen in uninterruptible sleep waiting for I/O.",
		Thresholds: []string{
			"≥ 3 PIDs with state `D` in `/proc/[pid]/status`.",
		},
		KernelSources: []string{
			"/proc/[pid]/status",
			"/proc/[pid]/stat",
		},
		Remediation: "Investigate slow storage devices, unresponsive NFS mounts, or lower process I/O class using ionice.",
	},
	"CONT_SWAP_THRASHING": {
		Description: "Kernel is spending CPU time scanning and swapping pages instead of running applications.",
		Thresholds: []string{
			"`pgscan_direct` delta > 0 AND `allocstall_direct` delta > 0 AND PSI memory `some` > 30%.",
		},
		KernelSources: []string{
			"/proc/meminfo",
			"/proc/vmstat",
		},
		Remediation: "Reduce memory pressure, lower sysctl vm.swappiness, or add swap on fast storage.",
	},
	"CONT_CGROUP_THROTTLED": {
		Description: "A container or systemd service hit its CPU quota and is being slowed by the kernel.",
		Thresholds: []string{
			"`throttled_usec` delta > 100,000 (100ms) AND `nr_throttled` delta > 0.",
		},
		KernelSources: []string{
			"/sys/fs/cgroup/",
		},
		Remediation: "Increase CPU quota in container or service slice definition ('cpu.max' for %s).",
	},
	"CONT_FD_EXHAUSTION": {
		Description: "A process is about to run out of file descriptors, causing `accept()` / `open()` failures.",
		Thresholds: []string{
			"FD count (entries in `/proc/[pid]/fd/`) > 90% of soft limit from `/proc/[pid]/limits`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Increase file descriptor soft limit: prlimit --nofile=%d:%d -p %d",
	},
	"CONT_SOFTIRQ_UNBALANCE": {
		Description: "Network interrupt processing is bottlenecked on a single CPU core.",
		Thresholds: []string{
			"Any single core's softirq% > 80% while aggregate system idle > 50%.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Enable network Receive Packet Steering (RPS/RFS) or configure irqbalance.",
	},
	"CONT_TCP_LISTEN_DROPS": {
		Description: "Incoming TCP connections are being silently dropped because the accept queue is full.",
		Thresholds: []string{
			"`ListenDrops` delta > 0 from `/proc/net/netstat`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Increase system socket backlog: sysctl -w net.core.somaxconn=4096 and raise application backlog setting.",
	},
	"CONT_PID_EXHAUSTION": {
		Description: "System PID table allocation is nearing the kernel ceiling, risking `fork()` / `pthread_create()` `EAGAIN` failures.",
		Thresholds: []string{
			"Scanned process count ≥ 95% of `/proc/sys/kernel/pid_max`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`sysctl -w kernel.pid_max=4194304`.",
	},
	"CONT_TIMEWAIT_PORT_EXHAUSTION": {
		Description: "Heavy short-lived TCP connection churn has filled ephemeral outbound ports with TIME_WAIT sockets, causing `connect()` `EADDRNOTAVAIL` errors.",
		Thresholds: []string{
			"`TCPTimeWait` from `/proc/net/sockstat` ≥ 85% of available ephemeral port capacity (`ip_local_port_range`).",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`sysctl -w net.ipv4.tcp_tw_reuse=1` and enable HTTP keep-alive.",
	},
	"CONT_VCPU_STEAL_TIME": {
		Description: "Hypervisor host is overcommitted and stealing execution cycles for noisy neighbor VMs.",
		Thresholds: []string{
			"`StealPercent >= 15%` aggregate or `StealPercent >= 30%` on any individual core.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "Configure hypervisor vCPU reservations or pin vCPUs to physical cores.",
	},
	"CONT_BALLOON_OVERCOMMIT": {
		Description: "Hypervisor is forcefully reclaiming memory via ballooning or overcommit pressure.",
		Thresholds: []string{
			"Balloon driver inflating `≥ 20%` of guest physical RAM or available RAM < 15%.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Configure fixed hypervisor memory reservations (`virsh setmem` / VMware Memory Reservation).",
	},
	"CONT_CONNTRACK_EXHAUSTION": {
		Description: "Netfilter connection tracking table is saturated in Kubernetes/NAT gateway, causing silent packet drops.",
		Thresholds: []string{
			"`nf_conntrack_count >= 90%` of `nf_conntrack_max`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`sysctl -w net.netfilter.nf_conntrack_max=1048576`.",
	},
	"CONT_ARP_NEIGHBOR_OVERFLOW": {
		Description: "ARP / Neighbor table cache is saturated in large flat subnets or Kubernetes nodes, dropping new outbound packets.",
		Thresholds: []string{
			"Active entries in `/proc/net/arp` ≥ 85% of `/proc/sys/net/ipv4/neigh/default/gc_thresh3`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.ipv4.neigh.default.gc_thresh3=4096`.",
	},
	"CONT_TCP_SYN_QUEUE_OVERFLOW": {
		Description: "Inbound TCP half-open connection requests exceed the kernel SYN backlog queue before handshakes complete.",
		Thresholds: []string{
			"Delta in `ListenOverflows > 0` or `TCPReqQFullDoCookies > 0` in `/proc/net/netstat`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.ipv4.tcp_max_syn_backlog=65535` and `sysctl -w net.core.somaxconn=65535`.",
	},
	"CONT_BLK_MQ_TAG_STARVATION": {
		Description: "High-throughput I/O processes are blocked waiting for NVMe/SSD hardware queue submission tags (`blk_mq_get_tag`).",
		Thresholds: []string{
			"Multiple processes with `wchan` matching `blk_mq_get_tag` or `io_schedule` with active I/O deltas.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`echo 1024 > /sys/block/<device>/queue/nr_requests` or tune async I/O / io_uring queue depths.",
	},
	"CONT_SCHED_RUNQUEUE_STARVATION": {
		Description: "Threads spend excessive time waiting in scheduler runqueues before being dispatched to CPU cores.",
		Thresholds: []string{
			"Ratio of `RunqueueWaitTimeMS` to `RunningTimeMS` ≥ 1.5 in `/proc/schedstat` with running time > 100ms.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "Reduce thread concurrency / worker pool size or tune `kernel.sched_migration_cost_ns`.",
	},
	"CONT_CGROUP_MEM_HIGH_THROTTLE": {
		Description: "Cgroup v2 `memory.high` soft limit exceeded, causing the kernel to inject proactive allocation delay sleeps into processes.",
		Thresholds: []string{
			"Delta in cgroup v2 `memory.events` `high > 0`.",
		},
		KernelSources: []string{
			"/proc/meminfo",
			"/proc/vmstat",
		},
		Remediation: "Increase container memory soft limit: `echo <bytes> > /sys/fs/cgroup<path>/memory.high`.",
	},
	"CONT_IO_QUEUE_LATENCY": {
		Description: "I/O requests on a block device are spending excessive time waiting in scheduler queues before dispatch.",
		Thresholds: []string{
			"Metric delta exceeded operational thresholds during sampling window",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Change I/O scheduler to none (or mq-deadline for HDD) or raise nr_requests queue depth.",
	},
	"CONT_PAGE_TABLE_LOCK": {
		Description: "Multiple threads are stalled contending for mmap_lock / page table locks during concurrent memory mapping, page faulting, or thread allocation.",
		Thresholds: []string{
			"Metric delta exceeded operational thresholds during sampling window",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Reduce thread concurrency in memory-intensive workers or switch to jemalloc / tcmalloc arena allocator.",
	},
	"CONT_ORPHAN_SOCKET_LEAK": {
		Description: "System has an excessive number of orphan TCP sockets detached from user applications, consuming kernel network buffer memory.",
		Thresholds: []string{
			"Metric delta exceeded operational thresholds during sampling window",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Inspect applications for abrupt TCP connection termination without orderly close, or raise sysctl net.ipv4.tcp_max_orphans.",
	},
	"CONT_CONTEXT_SWITCH_STORM": {
		Description: "The kernel CPU scheduler is thrashing under extreme context switch volume, burning system CPU cycles in dispatch rather than compute.",
		Thresholds: []string{
			"`ContextSwitchesDelta / sec >= 100,000` AND `SystemPercent >= 20.0%` with `IdlePercent < 25.0%`.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "Reduce concurrency / thread pool size, batch I/O operations, or eliminate busy-wait polling loops.",
	},
	"CONT_CPU_GOVERNOR_POWERSAVE_LAG": {
		Description: "CPU frequency scaling governor is set to `powersave`, clamping active compute cores to low base frequencies under heavy load.",
		Thresholds: []string{
			"`TotalCPUUtil.BusyPercent >= 75.0%` AND any core in `powersave` with `cur_freq <= 0.5 * max_freq`.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "`echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`.",
	},
	"CONT_KSOFTIRQD_SATURATION": {
		Description: "Software interrupt handler daemon (`ksoftirqd/X`) is pegged at high CPU processing unbatched softirqs (network RX/TX, timers).",
		Thresholds: []string{
			"Process `ksoftirqd/*` CPU% $\\ge 40.0\\%$ AND `SoftIRQPercent >= 20.0%`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Enable Receive Packet Steering (RPS/RFS), configure NIC multiqueue, or raise `sysctl net.core.netdev_budget=600`.",
	},
	"CONT_WORKINGSET_REFAULT_THRASHING": {
		Description: "Evicted page cache files are immediately being read back from disk under memory pressure, causing disk latency spikes.",
		Thresholds: []string{
			"`WorkingsetRefaultFileDelta >= 5000` AND (`AllocStallDirectDelta > 0` OR `PgScanDirectDelta > 0` OR PSI memory $\\ge 15\\%$).",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Add physical RAM, downsize active application caches, or pin hot data with `vmtouch`.",
	},
	"CONT_DIRTY_PAGE_FLUSH_SATURATION": {
		Description: "Saturated dirty/writeback memory buffers force applications into synchronous `balance_dirty_pages` throttle sleeps.",
		Thresholds: []string{
			"`Dirty >= 15% MemTotal` OR `Writeback >= 10% MemTotal` with process in `balance_dirty_pages` wchan.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Lower `sysctl -w vm.dirty_background_ratio=5` or upgrade storage write bandwidth.",
	},
	"CONT_FSYNC_JOURNAL_STALL": {
		Description: "Multiple processes serialized waiting on filesystem journal transaction commit (e.g. ext4 `jbd2` or `xfsaild`).",
		Thresholds: []string{
			"$\\ge 2$ processes sleeping in `jbd2_log_wait_commit`, `vfs_fsync`, `xfs_log_reserve`, or `sync_buffer`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Group commits, adjust commit intervals, or place WAL / journal files on dedicated NVMe storage.",
	},
	"CONT_PAGECACHE_POLLUTION_STREAM": {
		Description: "A bulk sequential I/O process streams data through buffered I/O, evicting the host's active application working set.",
		Thresholds: []string{
			"Single process with $\\ge 50\\text{MB/s}$ I/O AND `WorkingsetRefaultFileDelta >= 1000`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Run large streaming tasks (rsync, tar, backups) with `nocache` or `posix_fadvise(POSIX_FADV_DONTNEED)`.",
	},
	"CONT_NET_SOFTNET_BACKLOG_DROPS": {
		Description: "Incoming packet bursts overflow the per-CPU NIC driver backlog queue before reaching the network stack.",
		Thresholds: []string{
			"`SoftnetDroppedDelta > 0` OR `SoftnetTimeSqueezeDelta >= 50` in `/proc/net/softnet_stat`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Raise `sysctl -w net.core.netdev_max_backlog=10000` and `sysctl -w net.core.netdev_budget=600`.",
	},
	"CONT_TCP_RETRANSMIT_STORM": {
		Description: "High network packet loss is triggering TCP congestion window collapse and exponential retransmission delays.",
		Thresholds: []string{
			"`RetransSegsDelta / OutSegsDelta >= 0.05` (5% loss rate) with $\\ge 500$ outbound segments in `/proc/net/snmp`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Inspect network switch drops, check MTU consistency, or enable BBR congestion control.",
	},
	"CONT_TCP_ZEROWINDOW_STALL": {
		Description: "TCP senders are stalled because downstream consumer processes have filled their socket receive buffers.",
		Thresholds: []string{
			"`TCPWinProbeDelta >= 5` OR `TCPZeroWindowDropDelta > 0` OR process in `sk_stream_wait_memory` wchan.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Increase consumer read concurrency, enlarge `net.ipv4.tcp_rmem`, or profile slow downstream services.",
	},
	"CONT_COREDUMP_BURST_STORM": {
		Description: "Crashlooping processes continuously spawn core dump helpers (`systemd-coredump`, `apport`), burning CPU and disk.",
		Thresholds: []string{
			"Core dumper process active with $\\ge 10$ process fork creation events in `/proc/stat`.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Stop crashlooping containers, temporarily disable dumps (`ulimit -c 0`), or fix the crashing binary.",
	},
	"CONT_UNIX_SOCKET_LOG_BLOCK": {
		Description: "Applications are blocked in synchronous `sendto()` waiting for saturated Unix domain socket log buffers to drain.",
		Thresholds: []string{
			"$\\ge 2$ processes sleeping in `unix_wait_for_peer`, `unix_stream_sendmsg`, or `unix_dgram_sendmsg`.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Reduce application logging verbosity, use async log buffers, or raise `RateLimitBurst` in `/etc/systemd/journald.conf`.",
	},
	"CONT_UDP_BUFFER_OVERRUN": {
		Description: "UDP socket receive or send buffers are overflowing, causing silent packet drops for UDP services (DNS/VoIP/StatsD).",
		Thresholds: []string{
			"`UDPRcvbufErrorsDelta > 0` OR `UDPSndbufErrorsDelta > 0` in `/proc/net/snmp`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.core.rmem_max=16777216` and raise application `SO_RCVBUF` socket buffers.",
	},
	"CONT_TCP_LISTEN_OVERFLOW_STALL": {
		Description: "Application listen backlog queue is saturated, causing incoming connection drops and connection resets (`TCPAbortOnData`).",
		Thresholds: []string{
			"`ListenOverflowsDelta > 0` AND `TCPAbortOnDataDelta > 0` in `/proc/net/netstat`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.core.somaxconn=8192` and scale up server worker thread pool concurrency.",
	},
	"CONT_HUGETLB_POOL_EXHAUSTION": {
		Description: "Dedicated explicit HugePages pool (used by PostgreSQL, DPDK, Oracle) is 100% exhausted with 0 free pages.",
		Thresholds: []string{
			"`HugePages_Total > 0` AND `HugePages_Free == 0` AND `HugePages_Rsvd > 0` in `/proc/meminfo`.",
		},
		KernelSources: []string{
			"/proc/meminfo",
			"/proc/vmstat",
		},
		Remediation: "`sysctl -w vm.nr_hugepages=<N>` or downsize database shared buffer allocations.",
	},
	"CONT_PTRACE_TRACER_ATTACH": {
		Description: "An interactive debugger or profiler (`strace`, `gdb`, `lldb`) attached via `ptrace()` is intercepting every syscall and causing 10x-50x latency slowdown.",
		Thresholds: []string{
			"Process with `CPUPercent >= 20.0%` has `TracerPid > 0` in `/proc/[pid]/status`.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Detach interactive debugger or use non-blocking sampling profilers (`perf` / eBPF).",
	},
	"CONT_SYSV_SEMAPHORE_LIMIT": {
		Description: "System V IPC semaphore table capacity (`SEMMNS` / `SEMMNI`) is saturated, blocking database connection pooling and process spawning.",
		Thresholds: []string{
			"`AllocatedSemaphores >= 90%` of `SEMMNS` or `AllocatedSemSets >= 90%` of `SEMMNI` in `/proc/sysvipc/sem` and `/proc/sys/kernel/sem`.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "`sysctl -w kernel.sem=\"50100 64128000 50100 1280\"` or clean stale semaphore sets with `ipcrm -s <semid>`.",
	},
	"CONT_TCP_TIMEWAIT_BUCKET_OVERFLOW": {
		Description: "Kernel TCP TIME_WAIT bucket table is saturated, causing new incoming connections to be dropped.",
		Thresholds: []string{
			"`TCPTimeWaitOverflowDelta > 0` in `/proc/net/netstat` OR `TCPTimeWait >= 85%` of `tcp_max_tw_buckets`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.ipv4.tcp_max_tw_buckets=2000000` and enable TIME_WAIT reuse: `sysctl -w net.ipv4.tcp_tw_reuse=1`.",
	},
	"CONT_CGROUP_IO_THROTTLE_STALL": {
		Description: "Containerized processes are heavily throttled by Cgroup v2 `io.max` IOPS/bandwidth limits under high PSI I/O pressure.",
		Thresholds: []string{
			"Process with non-root `CgroupPath` blocked in `io_schedule` or `bdi_writeback_workfn` while `PSI.IO.Full.Avg10 >= 10.0%`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`docker update --io-max-bandwidth /dev/sda:500M` or relax container cgroup `io.max` limits.",
	},
	"CONT_AUDITD_BACKLOG_WAIT_STALL": {
		Description: "Linux kernel audit subsystem queue is saturated, forcing processes into synchronous kernel sleep during syscalls.",
		Thresholds: []string{
			"$\\ge 2$ processes with `wchan` in `kauditd_wait`, `audit_log_start`, or `audit_receive` AND `ProcsBlocked >= 2` or D-state.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "`auditctl -b 8192 -f 0` or disable auditing (`auditctl -e 0`).",
	},
	"CONT_TCP_SNDBUF_EXHAUSTION": {
		Description: "Outbound TCP socket send buffer is exhausted, blocking network send syscalls and stalling event loops.",
		Thresholds: []string{
			"Process in `sk_stream_wait_memory` or `tcp_sendmsg_locked` with `TCPSlowStartRetransDelta > 0` or `TCPMemoryPressuresDelta > 0`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`sysctl -w net.ipv4.tcp_wmem=\"4096 65536 16777216\"` and enable TCP window scaling: `sysctl -w net.ipv4.tcp_window_scaling=1`.",
	},
	"CONT_XFS_AIL_PUSH_STALL": {
		Description: "High metadata churn on XFS fills the journal log, forcing transactions to stall while `xfsaild` pushes dirty items.",
		Thresholds: []string{
			"$\\ge 2$ processes in `xfs_log_reserve`, `xfs_trans_reserve`, or `xfsaild` with PSI IO Some $\\ge 15.0\\%$ or `ProcsBlocked >= 2`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`mount -o remount,logbufs=8,logbsize=256k <mount>` or expand log size.",
	},
	"CONT_DM_QUEUE_CONGESTION": {
		Description: "Virtual device-mapper queue (LVM / LUKS / dm-thin) is congested with high write latency and in-flight I/O requests.",
		Thresholds: []string{
			"`dm-*` block device with `UtilPercent >= 80.0%` AND `AvgWriteLatencyMS >= 50.0` with `IOsInProgress >= 5` or active crypto workers.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`echo 1024 > /sys/block/<dev>/queue/nr_requests && echo none > /sys/block/<dev>/queue/scheduler`.",
	},
	"CONT_TCP_SYN_COOKIE_FLOOD_STALL": {
		Description: "Saturated half-open SYN connection queue forcing the kernel to generate cryptographic SYN cookies and disable TCP window scaling.",
		Thresholds: []string{
			"`SyncookiesSentDelta >= 50` OR `TCPReqQFullDoCookiesDelta >= 50` with `SyncookiesFailedDelta > 0` or `OutSegsDelta >= 500`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.ipv4.tcp_max_syn_backlog=65535 && sysctl -w net.core.somaxconn=65535`.",
	},
	"CONT_EPOLL_WAKEUP_CONTENTION": {
		Description: "Multi-worker processes sharing listening sockets or event loops suffering thundering herd wakeup storms in `epoll_wait`.",
		Thresholds: []string{
			"$\\ge 8$ processes in `do_epoll_wait` / `ep_poll` with `ContextSwitchesDelta >= 50000` and `SystemPercent >= 15.0%`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Configure listeners with `SO_REUSEPORT` or use `EPOLLEXCLUSIVE` in epoll event loops.",
	},
	"CONT_AIO_EVENT_LIMIT_SATURATION": {
		Description: "Kernel asynchronous I/O event table is nearing capacity (`aio-nr / aio-max-nr >= 90%`), risking `io_setup`/`io_submit` `EAGAIN` stalls.",
		Thresholds: []string{
			"`AIONR / AIOMaxNR >= 0.90` and process in `io_submit`/`io_getevents`/`wait_on_page_bit` or D-state or `ProcsBlocked >= 2`.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`sysctl -w fs.aio-max-nr=1048576`.",
	},
	"CONT_KSWAPD_CPU_SPIN": {
		Description: "Background memory reclamation daemon `kswapd` is pegged at high CPU failing to restore memory watermarks, causing direct reclaim stalls.",
		Thresholds: []string{
			"Process `kswapd*` CPU $\\ge 40.0\\%$ with direct reclaim scans or direct allocation stalls.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "`sysctl -w vm.watermark_scale_factor=200 && sysctl -w vm.vfs_cache_pressure=50`.",
	},
	"CONT_MD_RAID_RESYNC_STALL": {
		Description: "Linux Software RAID (`mdadm` / `/dev/md*`) background resync or rebuild is saturating disk channels.",
		Thresholds: []string{
			"`/proc/mdstat` has active `resync`, `recovery`, `check`, or `repair` with disk latency $\\ge 50\\text{ms}$ or high in-flight I/O.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`sysctl -w dev.raid.speed_limit_max=20000 && sysctl -w dev.raid.speed_limit_min=1000`.",
	},
	"CONT_NET_OUT_OF_ORDER_STALL": {
		Description: "Out-of-order TCP packets flood socket reassembly queues, triggering receive buffer collapses and throughput degradation.",
		Thresholds: []string{
			"`TCPOFOQueueDelta >= 500` and `TCPRcvCollapsedDelta > 0` or `TCPOFODropDelta > 0` or retransmit ratio $\\ge 3\\%$.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.ipv4.tcp_reordering=6 && sysctl -w net.ipv4.tcp_rmem=\"4096 131072 16777216\"`.",
	},
	"CONT_POSIX_RTSIG_QUEUE_SATURATION": {
		Description: "Process real-time signal queue (`SigQ`) is nearing capacity ($\\ge 85\\%$), risking signal drop or notification failures.",
		Thresholds: []string{
			"`SigQ` queued $\\ge 85\\%$ of limit with $\\ge 16$ threads or CPU $\\ge 20\\%$ or D-state.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`sysctl -w kernel.rtsig-max=65536`.",
	},
	"CONT_UDP_SNDBUF_EXHAUSTION": {
		Description: "Outbound UDP transmit buffers overflowed (`Udp: SndbufErrors`), causing syslog, StatsD, DNS, or streaming packet loss.",
		Thresholds: []string{
			"`UDPSndbufErrorsDelta >= 25` with OutSegs $\\ge 200$ or receive buffer errors.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`sysctl -w net.core.wmem_max=16777216 && sysctl -w net.core.wmem_default=262144`.",
	},
	"CONT_CGROUP_V1_CPU_SHARES_STARVATION": {
		Description: "Container cgroup has relative weight (`cpu.shares`) configured disproportionately low ($\\le 64$ vs 1024), causing severe CPU starvation under host CPU contention.",
		Thresholds: []string{
			"Cgroup `CPUShares <= 64` with host CPU Busy $\\ge 70\\%$ and process inside container.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "`docker update --cpu-shares=1024 <container>` or `echo 1024 > /sys/fs/cgroup/cpu<path>/cpu.shares`.",
	},
	"CONT_HUGEPAGE_LEAK_NO_REUSE": {
		Description: "Explicit HugePages (`vm.nr_hugepages`) allocated and reserved occupy significant RAM without being actively used after process crash.",
		Thresholds: []string{
			"`HugePages_Total > 0`, `HugePages_Rsvd > 0` locking $\\ge 25\\%$ of physical RAM while host `MemAvailable < 20%`.",
		},
		KernelSources: []string{
			"/proc/meminfo",
			"/proc/vmstat",
		},
		Remediation: "Remove unattached IPC segments: `ipcrm -m <shmid>` or release HugePages: `sysctl -w vm.nr_hugepages=0`.",
	},
	"CONT_NET_TCP_ABORT_ON_CLOSE": {
		Description: "Application closed TCP sockets while unread data remained in receive buffers, triggering kernel TCP RST packet generation (`TCPAbortOnClose`).",
		Thresholds: []string{
			"`TCPAbortOnCloseDelta >= 20` with OutSegs $\\ge 200$.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Drain socket receive buffers before closing or adjust request framing and HTTP keep-alive timeouts.",
	},
	"CONT_SCHED_YIELD_SPIN_CHURN": {
		Description: "Process worker threads repeatedly execute `sched_yield()` syscall in a tight loop instead of parking on futexes, generating massive voluntary context switches and CPU load.",
		Thresholds: []string{
			"Process voluntary context switches $\\ge 15\\text{k/s}$ with CPU $\\ge 35\\%$.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "Replace busy-spin yielding with proper futex/eventfd mutex parking.",
	},
	"CONT_NET_TCP_COLLAPSE_PRUNE": {
		Description: "Kernel TCP receive queues collapsed to reclaim socket memory, causing packet pruning and retransmissions.",
		Thresholds: []string{
			"`TCPRcvCollapsedDelta >= 20` with `TCPAbortOnMemoryDelta > 0` or `RetransSegsDelta >= 50`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.ipv4.tcp_rmem=\"4096 87380 16777216\" && sysctl -w net.ipv4.tcp_adv_win_scale=2`.",
	},
	"CONT_NET_TCP_MEMORY_ALLOC_FAIL": {
		Description: "Kernel aborted TCP connections or rejected packet allocations due to global `tcp_mem` socket page exhaustion.",
		Thresholds: []string{
			"`TCPAbortOnMemoryDelta >= 5` with zero window drops or TCP memory pressure.",
		},
		KernelSources: []string{
			"/proc/meminfo",
			"/proc/vmstat",
		},
		Remediation: "`sysctl -w net.ipv4.tcp_mem=\"786432 1048576 1572864\"`.",
	},
	"CONT_NET_TCP_ZERO_WINDOW_DROP": {
		Description: "Receiving endpoint or local host advertised a zero TCP receive window, stalling outbound transmission.",
		Thresholds: []string{
			"`TCPZeroWindowDropDelta >= 10` or window probe with outbound segments.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Ensure receiving application drains socket buffers quickly or enable TCP window scaling: `sysctl -w net.ipv4.tcp_window_scaling=1`.",
	},
	"CONT_FUTEX_PI_DEADLOCK_STALL": {
		Description: "Thread blocked in Priority-Inheritance / robust futex lock (`futex_lock_pi` / `rt_mutex_slowlock`) due to lock owner death or priority inversion.",
		Thresholds: []string{
			"Process in `futex_lock_pi` or `rt_mutex_slowlock` wchan with 0 CPU.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Inspect process mutex stacks with gdb/pprof or restart stalled service.",
	},
	"CONT_NET_ARP_TABLE_TRASH": {
		Description: "ARP/NDISC neighbor table is near capacity, risking neighbor discovery failures and dropped outbound packets.",
		Thresholds: []string{
			"Active ARP entries $\\ge 85\\%$ of `gc_thresh3`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.ipv4.neigh.default.gc_thresh3=8192 && sysctl -w net.ipv4.neigh.default.gc_thresh2=4096`.",
	},
	"CONT_DIRTY_PAGES_DIRECT_SYNC_STALL": {
		Description: "Unwritten dirty page cache accumulation forced processes into synchronous blocking page writeback (`sync_inodes` / `wait_on_page_writeback`).",
		Thresholds: []string{
			"Process in `sync_inodes` / `wait_on_page_writeback` in D-state or `NRDirtyDelta >= 2000`.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "`sysctl -w vm.dirty_background_ratio=5 && sysctl -w vm.dirty_ratio=15`.",
	},
	"CONT_NFS_RPC_SLOT_TABLE_SATURATION": {
		Description: "NFS client RPC transport slots exhausted (`sunrpc.tcp_slot_table_entries`) or remote NFS server unresponsive, blocking I/O calls.",
		Thresholds: []string{
			"Process in `nfs_wait_client` or `rpc_wait_bit_killable` in D-state.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "`sysctl -w sunrpc.tcp_slot_table_entries=128` or inspect remote NFS server health.",
	},
	"CONT_UNIX_SOCKET_BACKLOG_OVERFLOW": {
		Description: "Local UNIX domain socket buffer queues filled to capacity (`unix_stream_sendmsg`), blocking client threads.",
		Thresholds: []string{
			"Process in `unix_stream_sendmsg` or `unix_wait_for_peer` in D/S state with 0 CPU.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Ensure receiving daemon (syslog, systemd-journald, database IPC) drains socket queues.",
	},
	"CONT_VFS_INODE_LOCK_CONTENTION": {
		Description: "Multiple processes serializing on directory/file inode mutex locks during parallel file writeback.",
		Thresholds: []string{
			"Process in `inode_lock_shared`, `inode_lock`, or `ext4_file_write_iter` in D-state.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Shard file writes across multiple files/directories or use O_DIRECT.",
	},
	"CONT_KERNEL_LOCKD_BLOCKED": {
		Description: "Process blocked waiting for POSIX file lock acquisition (fcntl / flock) held by another process.",
		Thresholds: []string{
			"Process in `fcntl_setlk`, `locks_lock_inode_wait`, or `flock_lock_inode` with 0 CPU.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Inspect locks via `/proc/locks` or `lslocks` to identify blocker process.",
	},
	"CONT_SCHED_AUTOGROUP_STARVATION": {
		Description: "Kernel CFS autogroup scheduler grouped session tasks into a single autogroup, starving multi-threaded server tasks launched in that session.",
		Thresholds: []string{
			"Process with $\\ge 16$ threads at low CPU under busy runqueue.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "`sysctl -w kernel.sched_autogroup_enabled=0` or move tasks to a systemd service unit.",
	},
	"CONT_FTRACE_RING_BUFFER_STALL": {
		Description: "Active ftrace / tracepoint event recording saturated trace ring buffers, stalling traced syscalls on buffer locks.",
		Thresholds: []string{
			"Process blocked in `tracing_wait_pipe` or `ring_buffer_wait` wchan with high system CPU.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Disable active tracing: `echo 0 > /sys/kernel/debug/tracing/tracing_on` or enlarge ring buffer.",
	},
	"CONT_NET_DEV_GRO_CELL_DROP": {
		Description: "Generic Receive Offload cell buffer overflow in kernel softnet layer, dropping incoming packets.",
		Thresholds: []string{
			"`SoftnetDroppedDelta >= 20` AND `SoftnetTimeSqueezeDelta >= 20`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.core.netdev_budget=600 && sysctl -w net.core.netdev_budget_usecs=4000`.",
	},
	"CONT_MEM_COMPACT_MIGRATION_FAIL_RATE": {
		Description: "High rate of page migration failures during memory compaction, wasting CPU without creating contiguous 2MB blocks.",
		Thresholds: []string{
			"`CompactStallDelta >= 50` AND `CompactFailDelta >= 25` ($\\ge 50\\%$ failure rate).",
		},
		KernelSources: []string{
			"/proc/meminfo",
			"/proc/vmstat",
		},
		Remediation: "`echo 1 > /proc/sys/vm/compact_memory` or `sysctl -w vm.compact_unevictable_allowed=0`.",
	},
	"CONT_NET_TCP_FASTOPEN_FAIL": {
		Description: "TCP Fast Open (TFO) active/passive handshake attempts are rejected or dropping cookies.",
		Thresholds: []string{
			"`TCPFastOpenActiveFailDelta + TCPFastOpenPassiveFailDelta >= 5`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "`sysctl -w net.ipv4.tcp_fastopen=3` or verify middlebox compatibility.",
	},
	"CONT_NET_TCP_SYN_ACK_RETRANS_STALL": {
		Description: "High SYN or SYN-ACK retransmissions during connection establishment.",
		Thresholds: []string{
			"`TCPSynRetransDelta >= 20`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Check network routing, path MTU, or remote firewall drops.",
	},
	"CONT_NET_SOCKET_RECV_STALL": {
		Description: "Process is stalled in uninterruptible sleep ('D' state) waiting on socket ingress buffers.",
		Thresholds: []string{
			"Process in `sk_wait_data` / `tcp_recvmsg` in D-state.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Inspect network bandwidth, packet loss, or sender throughput.",
	},
	"CONT_STORAGE_BLK_THROTTLE_STALL": {
		Description: "Process is queued in cgroup block I/O throttling limits (`blk_throtl`).",
		Thresholds: []string{
			"Process in `blk_throtl_dispatch_work_fn` / `throtl_pending_timer_fn` in D-state.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/vmstat",
		},
		Remediation: "Increase container block I/O throttle limits: `docker update --device-read-bps`.",
	},
	"CONT_NET_TCP_DEFER_ACCEPT_TIMEOUT": {
		Description: "TCP listener connections configured with TCP_DEFER_ACCEPT aborted before client sent data.",
		Thresholds: []string{
			"`TCPDeferAcceptDropDelta >= 10`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Tune application defer accept timeout or inspect client connection keep-alive behavior.",
	},
	"CONT_MEMCG_RECLAIM_DIRECT_STALL": {
		Description: "Process stalled performing synchronous memory direct reclaim to satisfy cgroup limits.",
		Thresholds: []string{
			"Process in `try_to_free_mem_cgroup_pages` / `mem_cgroup_reclaim` in D-state.",
		},
		KernelSources: []string{
			"/proc/meminfo",
			"/proc/vmstat",
		},
		Remediation: "Increase container memory limit: `docker update --memory <size>` or raise cgroup memory.high.",
	},
	"CONT_XFS_ALLOC_BTREE_CONTENTION": {
		Description: "Heavy allocation group btree lock contention on high-concurrency XFS filesystems.",
		Thresholds: []string{
			"Process in `xfs_alloc_fixup_trees` / `xfs_btree_lookup` in D-state.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Mount XFS with `allocsize=64m` or distribute concurrent file creations across separate directories.",
	},
	"CONT_SCHED_MIGRATION_COST_OVERHEAD": {
		Description: "Scheduler task migration penalty is set to 0 ns, causing tasks to bounce across CPU cores and thrash caches.",
		Thresholds: []string{
			"`sched_migration_cost_ns == 0` AND context switches $\\ge 50\\text{k/s}$.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "Increase scheduler migration cost: `sysctl -w kernel.sched_migration_cost_ns=500000`.",
	},
	"CONT_NET_TCP_ZERO_WINDOW_ADVERT": {
		Description: "Host advertised zero receive window to remote peers, freezing incoming data streams.",
		Thresholds: []string{
			"`TCPWinProbeDelta >= 20` OR `TCPZeroWindowDropDelta >= 10`.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Increase TCP window scaling: `sysctl -w net.ipv4.tcp_adv_win_scale=2` and enlarge application read buffers.",
	},
	"CONT_PSI_SOME_IO_PRESSURE_SPIKE": {
		Description: "Linux Pressure Stall Information (PSI) recorded elevated task stalls waiting on storage I/O.",
		Thresholds: []string{
			"PSI I/O `some` avg10 $\\ge 25.0\\%$.",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Check disk I/O queue depths, balance disk writeback buffers, or migrate I/O to NVMe.",
	},
	"CONT_PSI_SOME_CPU_PRESSURE_SPIKE": {
		Description: "Linux PSI recorded elevated runnable task delays stalled on CPU runqueues.",
		Thresholds: []string{
			"PSI CPU `some` avg10 $\\ge 30.0\\%$.",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "Renice background batch tasks, pin critical latency workloads, or scale CPU allocation.",
	},
	"CONT_PSI_FULL_MEMORY_PRESSURE_SPIKE": {
		Description: "Linux PSI recorded critical system-wide lockup during direct memory paging and allocation.",
		Thresholds: []string{
			"PSI Memory `full` avg10 $\\ge 15.0\\%$.",
		},
		KernelSources: []string{
			"/proc/meminfo",
			"/proc/vmstat",
		},
		Remediation: "Provision additional physical RAM, tune zram/zswap, or restrict memory limits on hungry containers.",
	},
	"CONT_PIPE_READ_BURST_BLOCK": {
		Description: "Process is blocked in uninterruptible sleep on pipe read operations waiting for upstream producers.",
		Thresholds: []string{
			"Process in `pipe_read` / `fifo_read` in D-state.",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Enlarge pipe buffer capacity via `fcntl(F_SETPIPE_SZ)` or diagnose upstream pipe producer stalls.",
	},
	"CONT_TCP_CLOSE_WAIT_LEAK": {
		Description: "Kernel socket table contains excessive sockets stuck in CLOSE_WAIT state. The application process failed to close socket file descriptors, leaking kernel memory and handles.",
		Thresholds: []string{
			"Metric delta exceeded operational thresholds during sampling window",
		},
		KernelSources: []string{
			"/proc/net/netstat",
			"/proc/net/snmp",
			"/proc/net/sockstat",
		},
		Remediation: "Inspect application connection pool and HTTP client response body cleanup (ensure body.Close() is invoked). Check lsof or /proc/[pid]/fd to isolate the leaking PID.",
	},
	"CONT_SUSTAINED_LOAD_SATURATION": {
		Description: "System load averages (1m and 5m) are sustained significantly higher than available CPU core capacity.",
		Thresholds: []string{
			"Metric delta exceeded operational thresholds during sampling window",
		},
		KernelSources: []string{
			"/proc/diskstats",
			"/sys/block/*/queue/",
		},
		Remediation: "Scale out compute instances, increase CPU allocations, or audit long-running thread pools for excessive concurrency.",
	},
	"CONT_RUNAWAY_CPU_PROCESS": {
		Description: "A runaway process is consuming excessive CPU on a core, starving other workloads of compute cycles.",
		Thresholds: []string{
			"Metric delta exceeded operational thresholds during sampling window",
		},
		KernelSources: []string{
			"/proc/stat",
			"/proc/schedstat",
		},
		Remediation: "Lower CPU scheduling priority with renice or send graceful stop signal: kill -TERM <PID>.",
	},
	"CONT_PROCESS_SWAP_PINNED": {
		Description: "Process has excessive memory swapped out to disk backing store under active system memory pressure.",
		Thresholds: []string{
			"Process SmapsRollup.Swap > 500MB (512,000 KB)",
			"System MemAvailable < 20% MemTotal OR pswpin delta > 0",
		},
		KernelSources: []string{
			"/proc/[pid]/smaps_rollup",
			"/proc/meminfo",
			"/proc/vmstat",
		},
		Remediation: "Reduce memory usage of the affected process or increase physical system RAM.",
	},
	"CONT_DENTRY_CACHE_EXPLOSION": {
		Description: "Kernel dentry cache has grown excessively (> 2,000,000 objects) consuming kernel slab memory under system memory pressure.",
		Thresholds: []string{
			"DentryCacheActive > 2,000,000 objects",
			"MemAvailable < 20.0% of MemTotal",
		},
		KernelSources: []string{
			"/proc/slabinfo",
			"/proc/meminfo",
		},
		Remediation: "echo 2 > /proc/sys/vm/drop_caches (requires root) to release dentry/inode caches",
	},
}

// RuleDStatePileup detects tasks stuck in uninterruptible sleep waiting on block/NFS I/O.
type RuleDStatePileup struct{ noSuppression }

func (r *RuleDStatePileup) ID() string { return "CONT_DSTATE_PILEUP" }
func (r *RuleDStatePileup) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleDStatePileup) Tier() int            { return 2 }
func (r *RuleDStatePileup) IsPIDDependent() bool { return true }

func (r *RuleDStatePileup) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var dProcs []collector.ProcessDiff
	for i := range diff.Processes {
		if diff.Processes[i].State == 'D' {
			dProcs = append(dProcs, diff.Processes[i])
		}
	}

	if len(dProcs) < 3 {
		return nil, false
	}

	evidence := make([]string, 0, len(dProcs)+1)
	evidence = append(evidence, fmt.Sprintf("%d active processes stuck in uninterruptible sleep (State D)", len(dProcs)))

	var culprit *collector.ProcessDiff
	for i := range dProcs {
		p := &dProcs[i]
		wchanStr := p.Wchan
		if wchanStr == "" {
			wchanStr = "unknown_wait"
		}
		evidence = append(evidence, fmt.Sprintf("PID %d [%s]: wchan=%s, read=%.1f MB, write=%.1f MB",
			p.PID, p.Comm, wchanStr, float64(p.ReadBytesDelta)/(1024*1024), float64(p.WriteBytesDelta)/(1024*1024)))

		if culprit == nil || p.WriteBytesDelta+p.ReadBytesDelta > culprit.WriteBytesDelta+culprit.ReadBytesDelta {
			culprit = p
		}
	}

	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.88,
		Title:       "Uninterruptible I/O Lock (D-State Pileup)",
		Explanation: "Multiple processes are blocked in kernel uninterruptible sleep waiting on disk I/O, NFS, or page writeback.",
		Evidence:    evidence,
		Remediation: "Investigate slow storage devices, unresponsive NFS mounts, or lower process I/O class using ionice.",
	}

	if culprit != nil {
		diag.CulpritPID = culprit.PID
		diag.CulpritName = culprit.Comm
		diag.CulpritDetails = fmt.Sprintf("Stalled in kernel function '%s' with %.1f MB I/O activity", culprit.Wchan, float64(culprit.WriteBytesDelta+culprit.ReadBytesDelta)/(1024*1024))
		diag.Remediation = fmt.Sprintf("Lower I/O priority class: ionice -c3 -p %d", culprit.PID)
	}

	return diag, true
}

// RuleSwapThrashing detects kernel direct page scanning and allocation stalls.
type RuleSwapThrashing struct{ noSuppression }

func (r *RuleSwapThrashing) ID() string { return "CONT_SWAP_THRASHING" }
func (r *RuleSwapThrashing) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleSwapThrashing) Tier() int            { return 2 }
func (r *RuleSwapThrashing) IsPIDDependent() bool { return false }

func (r *RuleSwapThrashing) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	vm := &diff.VMStat
	hasDirectReclaim := vm.PgScanDirectDelta > 0
	hasAllocStall := vm.AllocStallDirectDelta > 0

	if !hasDirectReclaim || !hasAllocStall {
		return nil, false
	}

	// Corroborate with PSI memory pressure if available
	psiMemStall := 0.0
	if diff.LatestSnapshot != nil && diff.LatestSnapshot.PSI.Available {
		psiMemStall = diff.LatestSnapshot.PSI.Memory.Some.Avg10
	}

	evidence := []string{
		fmt.Sprintf("Direct Page Scans: %d pages scanned synchronously during sampling window", vm.PgScanDirectDelta),
		fmt.Sprintf("Direct Allocation Stalls: %d processes stalled waiting for memory reclaim", vm.AllocStallDirectDelta),
	}
	if psiMemStall > 0 {
		evidence = append(evidence, fmt.Sprintf("PSI Memory Stall: %.1f%% of tasks delayed on memory", psiMemStall))
	}

	confidence := 0.85
	if psiMemStall >= 30.0 {
		confidence = 0.95
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  confidence,
		Title:       "Memory Thrashing & Direct Reclamation Stall",
		Explanation: "The kernel is synchronously scanning pages and stalling processes to reclaim memory, degrading response times.",
		Evidence:    evidence,
		Remediation: "Reduce memory pressure, lower sysctl vm.swappiness, or add swap on fast storage.",
	}, true
}

// RuleCgroupThrottled detects CPU quota wall throttling inside containers or systemd slices.
type RuleCgroupThrottled struct{ noSuppression }

func (r *RuleCgroupThrottled) ID() string { return "CONT_CGROUP_THROTTLED" }
func (r *RuleCgroupThrottled) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleCgroupThrottled) Tier() int            { return 2 }
func (r *RuleCgroupThrottled) IsPIDDependent() bool { return true }

func (r *RuleCgroupThrottled) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var topThrottled *collector.CgroupDiff
	for i := range diff.Cgroups {
		cg := &diff.Cgroups[i]
		// Throttled for > 100ms (100,000 usec) within the sampling window
		if cg.ThrottledUsecDelta >= 100000 && cg.NrThrottledDelta > 0 {
			if topThrottled == nil || cg.ThrottledUsecDelta > topThrottled.ThrottledUsecDelta {
				topThrottled = cg
			}
		}
	}

	if topThrottled == nil {
		return nil, false
	}

	throttledMS := float64(topThrottled.ThrottledUsecDelta) / 1000.0
	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       fmt.Sprintf("Cgroup CPU Quota Throttled (%s)", topThrottled.Path),
		Explanation: fmt.Sprintf("Tasks inside cgroup '%s' were throttled for %.1f ms because they exhausted their allocated CPU quota.", topThrottled.Path, throttledMS),
		Evidence: []string{
			fmt.Sprintf("Cgroup Path: %s", topThrottled.Path),
			fmt.Sprintf("Throttled Duration Delta: %.1f ms across %d periods", throttledMS, topThrottled.NrThrottledDelta),
		},
		Remediation: fmt.Sprintf("Increase CPU quota in container or service slice definition ('cpu.max' for %s).", topThrottled.Path),
	}

	// Try to attribute top PID in this cgroup
	var maxCPUDelta uint64
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.CgroupPath == topThrottled.Path && p.CPUTimeDelta > 0 {
			if diag.CulpritPID == 0 || p.CPUTimeDelta > maxCPUDelta {
				maxCPUDelta = p.CPUTimeDelta
				diag.CulpritPID = p.PID
				diag.CulpritName = p.Comm
				diag.CulpritDetails = fmt.Sprintf("Active process in throttled cgroup (CPU delta: %.1f%%)", p.CPUPercent)
			}
		}
	}

	return diag, true
}

// RuleFDExhaustion detects processes approaching their file descriptor limits.
type RuleFDExhaustion struct{ noSuppression }

func (r *RuleFDExhaustion) ID() string { return "CONT_FD_EXHAUSTION" }
func (r *RuleFDExhaustion) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleFDExhaustion) Tier() int            { return 2 }
func (r *RuleFDExhaustion) IsPIDDependent() bool { return true }

func (r *RuleFDExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var topExhausted *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.MaxFDs > 0 && p.OpenFDs > 0 {
			if p.FDRatio >= 0.90 {
				if topExhausted == nil || p.FDRatio > topExhausted.FDRatio {
					topExhausted = p
				}
			}
		}
	}

	if topExhausted == nil {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.95,
		Title:       fmt.Sprintf("File Descriptor Exhaustion (PID %d [%s])", topExhausted.PID, topExhausted.Comm),
		Explanation: fmt.Sprintf("Process '%s' (PID %d) is using %d of %d allowed file descriptors (%.1f%% of limit).", topExhausted.Comm, topExhausted.PID, topExhausted.OpenFDs, topExhausted.MaxFDs, topExhausted.FDRatio*100.0),
		Evidence: []string{
			fmt.Sprintf("Open File Descriptors: %d", topExhausted.OpenFDs),
			fmt.Sprintf("Process Soft Limit: %d (%.1f%% utilized)", topExhausted.MaxFDs, topExhausted.FDRatio*100.0),
		},
		CulpritPID:     topExhausted.PID,
		CulpritName:    topExhausted.Comm,
		CulpritDetails: fmt.Sprintf("Approaching ulimit -n limit with %d open handles", topExhausted.OpenFDs),
		Remediation:    fmt.Sprintf("Increase file descriptor soft limit: prlimit --nofile=%d:%d -p %d", topExhausted.MaxFDs*2, topExhausted.MaxFDs*2, topExhausted.PID),
	}, true
}

// RuleSoftIRQUnbalance detects a single core saturated by network softirqs while other cores are idle.
type RuleSoftIRQUnbalance struct{ noSuppression }

func (r *RuleSoftIRQUnbalance) ID() string { return "CONT_SOFTIRQ_UNBALANCE" }
func (r *RuleSoftIRQUnbalance) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleSoftIRQUnbalance) Tier() int            { return 2 }
func (r *RuleSoftIRQUnbalance) IsPIDDependent() bool { return false }

func (r *RuleSoftIRQUnbalance) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.PerCoreCPUUtil) < 2 {
		return nil, false
	}

	// Overall system idle should be relatively high (> 50%)
	if diff.TotalCPUUtil.IdlePercent < 50.0 {
		return nil, false
	}

	bottleneckCore := -1
	var maxSoftIRQ float64

	for coreID, util := range diff.PerCoreCPUUtil {
		if util.SoftIRQPercent >= 80.0 {
			if util.SoftIRQPercent > maxSoftIRQ {
				maxSoftIRQ = util.SoftIRQPercent
				bottleneckCore = coreID
			}
		}
	}

	if bottleneckCore == -1 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.88,
		Title:       fmt.Sprintf("Single-Core SoftIRQ Network Storm (Core %d)", bottleneckCore),
		Explanation: fmt.Sprintf("CPU core %d is pinned at %.1f%% softirq processing while total system is %.1f%% idle, indicating network interrupt imbalance.", bottleneckCore, maxSoftIRQ, diff.TotalCPUUtil.IdlePercent),
		Evidence: []string{
			fmt.Sprintf("CPU Core %d SoftIRQ Utilization: %.1f%%", bottleneckCore, maxSoftIRQ),
			fmt.Sprintf("Overall System Idle: %.1f%%", diff.TotalCPUUtil.IdlePercent),
		},
		Remediation: "Enable network Receive Packet Steering (RPS/RFS) or configure irqbalance.",
	}, true
}

// RuleTCPListenDrops detects dropped or overflowing TCP incoming connection queues.
type RuleTCPListenDrops struct{}

func (r *RuleTCPListenDrops) ID() string { return "CONT_TCP_LISTEN_DROPS" }
func (r *RuleTCPListenDrops) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleTCPListenDrops) Tier() int            { return 2 }
func (r *RuleTCPListenDrops) IsPIDDependent() bool { return false }
func (r *RuleTCPListenDrops) Suppresses() []string {
	return []string{"CONT_TCP_LISTEN_OVERFLOW_STALL", "CONT_TCP_SYN_QUEUE_OVERFLOW"}
}

func (r *RuleTCPListenDrops) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	netDiff := &diff.NetStat
	if netDiff.ListenDropsDelta == 0 && netDiff.ListenOverflowsDelta == 0 {
		return nil, false
	}

	evidence := make([]string, 0, 2)
	if netDiff.ListenDropsDelta > 0 {
		evidence = append(evidence, fmt.Sprintf("ListenDrops: %d incoming connection attempts dropped in sampling window", netDiff.ListenDropsDelta))
	}
	if netDiff.ListenOverflowsDelta > 0 {
		evidence = append(evidence, fmt.Sprintf("ListenOverflows: %d sockets overflowed somaxconn listen queue", netDiff.ListenOverflowsDelta))
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       "TCP Socket Listen Backlog Drops",
		Explanation: "Incoming TCP connections were silently dropped because server application listen queues (somaxconn) were saturated.",
		Evidence:    evidence,
		Remediation: "Increase system socket backlog: sysctl -w net.core.somaxconn=4096 and raise application backlog setting.",
	}, true
}

// RulePIDExhaustion detects PID ceiling saturation risking fork/thread creation failures.
type RulePIDExhaustion struct{ noSuppression }

func (r *RulePIDExhaustion) ID() string { return "CONT_PID_EXHAUSTION" }
func (r *RulePIDExhaustion) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RulePIDExhaustion) Tier() int            { return 2 }
func (r *RulePIDExhaustion) IsPIDDependent() bool { return true }

func (r *RulePIDExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	pidMax := diff.LatestSnapshot.SystemConfig.PIDMax
	if pidMax == 0 {
		return nil, false
	}

	totalProcs := uint64(len(diff.Processes))
	if totalProcs == 0 {
		totalProcs = uint64(len(diff.LatestSnapshot.Processes))
	}

	ratio := float64(totalProcs) / float64(pidMax)
	if ratio < 0.95 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       "Process Table PID Allocation Exhaustion",
		Explanation: "Active process count is approaching the kernel PID limit (pid_max), risking fork() and pthread_create() EAGAIN failures.",
		Evidence: []string{
			fmt.Sprintf("Active Process Count: %d / %d pid_max ceiling (%.1f%% allocated)", totalProcs, pidMax, ratio*100.0),
		},
		Remediation: "Increase system PID ceiling: sysctl -w kernel.pid_max=4194304 or terminate redundant worker processes.",
	}, true
}

// RuleTimeWaitPortExhaustion detects outbound connect failures due to TIME_WAIT ephemeral port flood.
type RuleTimeWaitPortExhaustion struct{ noSuppression }

func (r *RuleTimeWaitPortExhaustion) ID() string { return "CONT_TIMEWAIT_PORT_EXHAUSTION" }
func (r *RuleTimeWaitPortExhaustion) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleTimeWaitPortExhaustion) Tier() int            { return 2 }
func (r *RuleTimeWaitPortExhaustion) IsPIDDependent() bool { return false }

func (r *RuleTimeWaitPortExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	sockStat := &diff.LatestSnapshot.SystemConfig.SockStat
	portRange := &diff.LatestSnapshot.SystemConfig.PortRange

	if portRange.High <= portRange.Low {
		return nil, false
	}

	capacity := portRange.High - portRange.Low + 1
	if capacity == 0 {
		return nil, false
	}

	ratio := float64(sockStat.TCPTimeWait) / float64(capacity)
	if ratio < 0.85 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.90,
		Title:       "Ephemeral Port Exhaustion (TIME_WAIT Flood)",
		Explanation: "Excessive TCP connections in TIME_WAIT state are consuming over 85% of available outbound ephemeral ports, causing connect() EADDRNOTAVAIL errors.",
		Evidence: []string{
			fmt.Sprintf("TCP TIME_WAIT Sockets: %d", sockStat.TCPTimeWait),
			fmt.Sprintf("Ephemeral Port Range: %d-%d (Capacity: %d, %.1f%% consumed)",
				portRange.Low, portRange.High, capacity, ratio*100.0),
		},
		Remediation: "Enable TCP TIME_WAIT socket reuse: sysctl -w net.ipv4.tcp_tw_reuse=1 and enable HTTP Keep-Alive in clients.",
	}, true
}

// RuleVCPUStealTime detects hypervisor CPU oversubscription and noisy neighbor cycle theft.
type RuleVCPUStealTime struct{ noSuppression }

func (r *RuleVCPUStealTime) ID() string { return "CONT_VCPU_STEAL_TIME" }
func (r *RuleVCPUStealTime) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleVCPUStealTime) Tier() int            { return 2 }
func (r *RuleVCPUStealTime) IsPIDDependent() bool { return false }

func (r *RuleVCPUStealTime) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	totalSteal := diff.TotalCPUUtil.StealPercent
	var maxCoreSteal float64
	var maxCoreID int
	for i, core := range diff.PerCoreCPUUtil {
		if core.StealPercent > maxCoreSteal {
			maxCoreSteal = core.StealPercent
			maxCoreID = i
		}
	}

	if totalSteal < 15.0 && maxCoreSteal < 30.0 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Hypervisor Steal Time: %.1f%% of overall vCPU cycles stolen by host", totalSteal),
		fmt.Sprintf("Guest CPU Busy: %.1f%%, Idle: %.1f%%", diff.TotalCPUUtil.BusyPercent, diff.TotalCPUUtil.IdlePercent),
	}
	if maxCoreSteal >= 30.0 {
		evidence = append(evidence, fmt.Sprintf("Most Impacted Core: vCPU %d (%.1f%% steal time)", maxCoreID, maxCoreSteal))
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.95,
		Title:       "Hypervisor vCPU Steal Time Saturation (Noisy Neighbor)",
		Explanation: "The virtual machine is starving for CPU execution cycles because the underlying hypervisor host is overcommitted and stealing vCPU slices for other noisy tenants.",
		Evidence:    evidence,
		Remediation: "Migrate VM to dedicated hypervisor host, configure vCPU pinning/reservations, or upgrade to dedicated cloud compute instances.",
	}, true
}

// RuleBalloonMemoryOvercommit detects hypervisor memory reclamation and balloon driver inflation.
type RuleBalloonMemoryOvercommit struct{ noSuppression }

func (r *RuleBalloonMemoryOvercommit) ID() string { return "CONT_BALLOON_OVERCOMMIT" }
func (r *RuleBalloonMemoryOvercommit) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleBalloonMemoryOvercommit) Tier() int            { return 2 }
func (r *RuleBalloonMemoryOvercommit) IsPIDDependent() bool { return false }

func (r *RuleBalloonMemoryOvercommit) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	mem := &diff.LatestSnapshot.Memory
	virt := &diff.LatestSnapshot.SystemConfig.Virt
	if mem.MemTotal == 0 {
		return nil, false
	}

	totalRAMBytes := mem.MemTotal * 1024
	availRAMBytes := mem.MemAvailable * 1024

	// If virtio balloon is holding memory or guest is low on available memory under hypervisor pressure
	balloonBytes := virt.BalloonBytes
	balloonRatio := float64(balloonBytes) / float64(totalRAMBytes)
	availRatio := float64(availRAMBytes) / float64(totalRAMBytes)

	// Trigger if balloon driver has inflated >= 20% of RAM, or balloon is active while available memory is low
	if balloonRatio < 0.20 && (balloonBytes == 0 || availRatio >= 0.15) {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.90,
		Title:       "Hypervisor Memory Ballooning Overcommit Pressure",
		Explanation: "The underlying hypervisor is actively reclaiming RAM from this virtual machine via memory ballooning, inducing memory pressure and swapping despite apparent free capacity.",
		Evidence: []string{
			fmt.Sprintf("Hypervisor Balloon Inflated: %d MB (%.1f%% of guest physical RAM)", balloonBytes/(1024*1024), balloonRatio*100.0),
			fmt.Sprintf("Guest MemTotal: %d MB, MemAvailable: %d MB (%.1f%% usable)", mem.MemTotal/1024, mem.MemAvailable/1024, availRatio*100.0),
		},
		Remediation: "Set fixed hypervisor memory reservations (e.g. virsh setmem / VMware Memory Reservation) to prevent host overcommit reclaiming guest RAM.",
	}, true
}

// RuleConntrackExhaustion detects Netfilter connection tracking table saturation.
type RuleConntrackExhaustion struct{ noSuppression }

func (r *RuleConntrackExhaustion) ID() string { return "CONT_CONNTRACK_EXHAUSTION" }
func (r *RuleConntrackExhaustion) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleConntrackExhaustion) Tier() int            { return 2 }
func (r *RuleConntrackExhaustion) IsPIDDependent() bool { return false }

func (r *RuleConntrackExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	ct := &diff.LatestSnapshot.SystemConfig.Conntrack
	if !ct.Available || ct.Max == 0 {
		return nil, false
	}

	if ct.Ratio < 0.90 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.95,
		Title:       "Netfilter Conntrack Table Saturation",
		Explanation: "The kernel Netfilter connection tracking table is nearing capacity (≥ 90%), causing silent packet drops on incoming/outgoing connections before reaching applications.",
		Evidence: []string{
			fmt.Sprintf("Active Conntrack Sessions: %d / %d max table size (%.1f%% utilized)", ct.Count, ct.Max, ct.Ratio*100.0),
			"New TCP handshakes and UDP flows are being dropped at raw IP layer without application logs",
		},
		Remediation: "Increase connection tracking capacity: sysctl -w net.netfilter.nf_conntrack_max=1048576 or reduce nf_conntrack_tcp_timeout_established.",
	}, true
}

// RuleARPNeighborTableOverflow detects ARP / Neighbor cache table saturation in large subnets or Kubernetes nodes.
type RuleARPNeighborTableOverflow struct{ noSuppression }

func (r *RuleARPNeighborTableOverflow) ID() string { return "CONT_ARP_NEIGHBOR_OVERFLOW" }
func (r *RuleARPNeighborTableOverflow) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleARPNeighborTableOverflow) Tier() int            { return 2 }
func (r *RuleARPNeighborTableOverflow) IsPIDDependent() bool { return false }

func (r *RuleARPNeighborTableOverflow) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	neigh := &diff.LatestSnapshot.SystemConfig.Neighbor
	if !neigh.Available || neigh.GCThresh3 == 0 {
		return nil, false
	}

	if neigh.Ratio >= 0.85 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.90,
			Title:       "ARP / Neighbor Cache Table Saturation",
			Explanation: "The kernel ARP / Neighbor cache has reached critical capacity (≥ 85% of gc_thresh3), causing silent packet drops and 'No route to host' errors when communicating with new IP addresses.",
			Evidence: []string{
				fmt.Sprintf("Active Neighbor/ARP Entries: %d / %d max (gc_thresh3)", neigh.ActiveEntries, neigh.GCThresh3),
				fmt.Sprintf("Table Saturation: %.1f%% of kernel ceiling", neigh.Ratio*100.0),
			},
			Remediation: fmt.Sprintf("Increase neighbor table thresholds: sysctl -w net.ipv4.neigh.default.gc_thresh3=%d", neigh.GCThresh3*4),
		}, true
	}

	return nil, false
}

// RuleTCPSYNQueueOverflow detects half-open connection SYN backlog queue floods.
type RuleTCPSYNQueueOverflow struct{ noSuppression }

func (r *RuleTCPSYNQueueOverflow) ID() string { return "CONT_TCP_SYN_QUEUE_OVERFLOW" }
func (r *RuleTCPSYNQueueOverflow) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleTCPSYNQueueOverflow) Tier() int            { return 2 }
func (r *RuleTCPSYNQueueOverflow) IsPIDDependent() bool { return false }

func (r *RuleTCPSYNQueueOverflow) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	synCookies := diff.NetStat.TCPReqQFullDoCookiesDelta
	overflows := diff.NetStat.ListenOverflowsDelta

	// Require SYN cookies as primary signal to differentiate from CONT_TCP_LISTEN_DROPS
	if synCookies > 0 {
		evidence := []string{
			fmt.Sprintf("TCP SYN Queue Full (SYN Cookies Sent): %d handshakes", synCookies),
		}
		if overflows > 0 {
			evidence = append(evidence, fmt.Sprintf("Listen Queue Overflows Delta: %d connections", overflows))
		}

		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.90,
			Title:       "TCP Inbound SYN Queue Overflow",
			Explanation: "Incoming TCP connection requests exceeded the kernel SYN backlog queue before handshakes completed, forcing fallback to SYN cookies.",
			Evidence:    evidence,
			Remediation: "Increase SYN backlog and listen queue limits: sysctl -w net.ipv4.tcp_max_syn_backlog=65535 and sysctl -w net.core.somaxconn=65535.",
		}, true
	}

	return nil, false
}

// RuleBlockHardwareTagStarvation detects storage controller blk-mq submission tag queue exhaustion.
type RuleBlockHardwareTagStarvation struct{ noSuppression }

func (r *RuleBlockHardwareTagStarvation) ID() string { return "CONT_BLK_MQ_TAG_STARVATION" }
func (r *RuleBlockHardwareTagStarvation) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleBlockHardwareTagStarvation) Tier() int            { return 2 }
func (r *RuleBlockHardwareTagStarvation) IsPIDDependent() bool { return true }

func (r *RuleBlockHardwareTagStarvation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Processes) == 0 {
		return nil, false
	}

	var tagWaitingProcs []collector.ProcessDiff
	for _, p := range diff.Processes {
		if strings.Contains(p.Wchan, "blk_mq_get_tag") || strings.Contains(p.Wchan, "io_schedule") {
			if p.ReadBytesDelta > 0 || p.WriteBytesDelta > 0 {
				tagWaitingProcs = append(tagWaitingProcs, p)
			}
		}
	}

	if len(tagWaitingProcs) >= 2 {
		topProc := tagWaitingProcs[0]
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.88,
			Title:       "Block Layer Hardware Tag Queue Starvation (blk-mq)",
			Explanation: "Multiple high-throughput I/O processes are blocked waiting for NVMe/SSD hardware submission tags, indicating block layer queue depth saturation.",
			Evidence: []string{
				fmt.Sprintf("Processes Blocked on blk-mq Tags: %d active tasks", len(tagWaitingProcs)),
				fmt.Sprintf("Representative Process: PID %d [%s] (wchan=%s)", topProc.PID, topProc.Comm, topProc.Wchan),
			},
			CulpritPID:  topProc.PID,
			CulpritName: topProc.Comm,
			Remediation: "Increase block device queue depth: echo 1024 > /sys/block/<device>/queue/nr_requests or tune io_uring queue depth.",
		}, true
	}

	return nil, false
}

// RuleSchedRunqueueStarvation detects high CPU scheduler runqueue dispatch latencies.
type RuleSchedRunqueueStarvation struct{ noSuppression }

func (r *RuleSchedRunqueueStarvation) ID() string { return "CONT_SCHED_RUNQUEUE_STARVATION" }
func (r *RuleSchedRunqueueStarvation) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleSchedRunqueueStarvation) Tier() int            { return 2 }
func (r *RuleSchedRunqueueStarvation) IsPIDDependent() bool { return false }

func (r *RuleSchedRunqueueStarvation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	sched := &diff.LatestSnapshot.SystemConfig.SchedStat
	if !sched.Available || sched.RunningTimeMS < 100 {
		return nil, false
	}

	if sched.Ratio >= 1.5 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.85,
			Title:       "CPU Scheduler Runqueue Latency Starvation",
			Explanation: "Threads are spending excessive time waiting in scheduler runqueues before being dispatched to CPU cores, causing application latency despite available compute capacity.",
			Evidence: []string{
				fmt.Sprintf("Runqueue Wait Time: %d ms vs Running Time: %d ms", sched.RunqueueWaitTimeMS, sched.RunningTimeMS),
				fmt.Sprintf("Runqueue Contention Ratio: %.2fx wait-to-execution ratio", sched.Ratio),
			},
			Remediation: "Reduce thread concurrency / pool size or tune scheduler migration cost (sysctl -w kernel.sched_migration_cost_ns=500000).",
		}, true
	}

	return nil, false
}

// RuleCgroupMemoryHighThrottle detects proactive page allocation delay injection in cgroup v2.
type RuleCgroupMemoryHighThrottle struct{ noSuppression }

func (r *RuleCgroupMemoryHighThrottle) ID() string { return "CONT_CGROUP_MEM_HIGH_THROTTLE" }
func (r *RuleCgroupMemoryHighThrottle) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleCgroupMemoryHighThrottle) Tier() int            { return 2 }
func (r *RuleCgroupMemoryHighThrottle) IsPIDDependent() bool { return false }

func (r *RuleCgroupMemoryHighThrottle) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Cgroups) == 0 {
		return nil, false
	}

	for _, cg := range diff.Cgroups {
		if cg.MemoryHighEventsDelta > 0 {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        2,
				Severity:    SeverityHigh,
				Confidence:  0.92,
				Title:       fmt.Sprintf("Cgroup v2 Proactive Page Delay Throttling (%s)", cg.Path),
				Explanation: fmt.Sprintf("Cgroup '%s' exceeded its soft memory limit ('memory.high'), causing the kernel to inject artificial sleep delays into memory allocations.", cg.Path),
				Evidence: []string{
					fmt.Sprintf("Cgroup Path: %s", cg.Path),
					fmt.Sprintf("Memory High Events Delta: %d throttled allocation cycles", cg.MemoryHighEventsDelta),
					"Kernel is actively slowing memory allocation threads instead of killing them",
				},
				Remediation: fmt.Sprintf("Raise container memory soft limit: echo <bytes> > /sys/fs/cgroup%s/memory.high or increase Pod memory request.", cg.Path),
			}, true
		}
	}

	return nil, false
}

// RuleIOSchedulerQueueLatency detects I/O scheduler queueing delays before requests reach storage controllers.
type RuleIOSchedulerQueueLatency struct{ noSuppression }

func (r *RuleIOSchedulerQueueLatency) ID() string { return "CONT_IO_QUEUE_LATENCY" }
func (r *RuleIOSchedulerQueueLatency) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleIOSchedulerQueueLatency) Tier() int            { return 2 }
func (r *RuleIOSchedulerQueueLatency) IsPIDDependent() bool { return false }

func (r *RuleIOSchedulerQueueLatency) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Disks) == 0 {
		return nil, false
	}

	for _, d := range diff.Disks {
		totalOps := d.ReadsCompletedDelta + d.WritesCompletedDelta
		if totalOps >= 20 && d.AvgQueueLatencyMS >= 100.0 {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        2,
				Severity:    SeverityHigh,
				Confidence:  0.88,
				Title:       fmt.Sprintf("Disk Scheduler Queue Latency Spike (%s)", d.DeviceName),
				Explanation: fmt.Sprintf("I/O requests on block device '%s' are spending an average of %.1f ms waiting in scheduler queues before dispatch.", d.DeviceName, d.AvgQueueLatencyMS),
				Evidence: []string{
					fmt.Sprintf("Block Device: %s (Total Completed Operations: %d)", d.DeviceName, totalOps),
					fmt.Sprintf("Average Scheduler Queue Wait: %.1f ms/op", d.AvgQueueLatencyMS),
					fmt.Sprintf("I/O in Progress: %d", d.IOsInProgress),
				},
				Remediation: fmt.Sprintf("Change I/O scheduler: echo none > /sys/block/%s/queue/scheduler or raise nr_requests queue depth.", d.DeviceName),
			}, true
		}
	}

	return nil, false
}

// RulePageTableLockContention detects mmap_lock / page table lock contention on multi-threaded runtimes.
type RulePageTableLockContention struct{ noSuppression }

func (r *RulePageTableLockContention) ID() string { return "CONT_PAGE_TABLE_LOCK" }
func (r *RulePageTableLockContention) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RulePageTableLockContention) Tier() int            { return 2 }
func (r *RulePageTableLockContention) IsPIDDependent() bool { return true }

func (r *RulePageTableLockContention) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Processes) == 0 {
		return nil, false
	}

	var ptProcs []collector.ProcessDiff
	for _, p := range diff.Processes {
		wchan := p.Wchan
		if strings.Contains(wchan, "mmap_lock") || strings.Contains(wchan, "mmap_read_lock") ||
			strings.Contains(wchan, "page_table_lock") || strings.Contains(wchan, "down_read_killable") {
			ptProcs = append(ptProcs, p)
		}
	}

	if len(ptProcs) >= 2 {
		topProc := ptProcs[0]
		evidence := []string{
			fmt.Sprintf("Processes Blocked on Page Table Locks: %d active tasks", len(ptProcs)),
			fmt.Sprintf("Representative Process: PID %d [%s] (wchan=%s, threads=%d)", topProc.PID, topProc.Comm, topProc.Wchan, topProc.NumThreads),
		}

		return &Diagnosis{
			RuleID:         r.ID(),
			Tier:           2,
			Severity:       SeverityHigh,
			Confidence:     0.85,
			Title:          "Virtual Memory Page Table Lock Contention",
			Explanation:    "Multiple threads are stalled contending for mmap_lock / page table locks during concurrent memory mapping, page faulting, or thread allocation.",
			Evidence:       evidence,
			CulpritPID:     topProc.PID,
			CulpritName:    topProc.Comm,
			CulpritDetails: fmt.Sprintf("Stalled in wchan '%s' with %d threads", topProc.Wchan, topProc.NumThreads),
			Remediation:    "Reduce thread concurrency in memory-intensive workers or switch to jemalloc / tcmalloc arena allocator.",
		}, true
	}

	return nil, false
}

// RuleOrphanSocketLeak detects accumulation of unassociated orphan TCP sockets.
type RuleOrphanSocketLeak struct{ noSuppression }

func (r *RuleOrphanSocketLeak) ID() string { return "CONT_ORPHAN_SOCKET_LEAK" }
func (r *RuleOrphanSocketLeak) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleOrphanSocketLeak) Tier() int            { return 2 }
func (r *RuleOrphanSocketLeak) IsPIDDependent() bool { return false }

func (r *RuleOrphanSocketLeak) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	sockStat := &diff.LatestSnapshot.SystemConfig.SockStat
	if sockStat.TCPOrphan < 1000 {
		return nil, false
	}

	// Trigger if orphans are significant relative to active sockets or large in absolute count
	if sockStat.TCPOrphan >= 5000 || (sockStat.TCPInUse > 0 && sockStat.TCPOrphan >= sockStat.TCPInUse/2) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.88,
			Title:       "TCP Orphan Socket Accumulation Leak",
			Explanation: fmt.Sprintf("System has %d orphan TCP sockets detached from user applications, consuming kernel network buffer memory.", sockStat.TCPOrphan),
			Evidence: []string{
				fmt.Sprintf("TCP Orphan Sockets: %d unreferenced sockets", sockStat.TCPOrphan),
				fmt.Sprintf("TCP Sockets in Use: %d active sockets", sockStat.TCPInUse),
			},
			Remediation: "Inspect applications for abrupt TCP connection termination without orderly close, or raise sysctl net.ipv4.tcp_max_orphans.",
		}, true
	}

	return nil, false
}

// RuleContextSwitchStorm detects extreme rates of CPU scheduler context switching causing kernel thrashing.
type RuleContextSwitchStorm struct{ noSuppression }

func (r *RuleContextSwitchStorm) ID() string { return "CONT_CONTEXT_SWITCH_STORM" }
func (r *RuleContextSwitchStorm) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleContextSwitchStorm) Tier() int            { return 2 }
func (r *RuleContextSwitchStorm) IsPIDDependent() bool { return false }

func (r *RuleContextSwitchStorm) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	durSec := diff.Duration.Seconds()
	if durSec <= 0 {
		durSec = 1.0
	}
	rate := float64(diff.ContextSwitchesDelta) / durSec

	if rate >= 100000 && diff.TotalCPUUtil.SystemPercent >= 20.0 && diff.TotalCPUUtil.IdlePercent < 25.0 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.88,
			Title:       "CPU Scheduler Context Switch Storm",
			Explanation: fmt.Sprintf("System is undergoing %.0f context switches/sec with %.1f%% system CPU time, spending excessive cycles in kernel scheduling dispatch.", rate, diff.TotalCPUUtil.SystemPercent),
			Evidence: []string{
				fmt.Sprintf("Context Switch Rate: %.0f switches/sec (delta: %d)", rate, diff.ContextSwitchesDelta),
				fmt.Sprintf("System CPU Overhead: %.1f%% (Idle: %.1f%%)", diff.TotalCPUUtil.SystemPercent, diff.TotalCPUUtil.IdlePercent),
			},
			Remediation: "Reduce concurrency and thread pool sizes, batch network/disk I/O operations, or eliminate tight polling/sched_yield spinloops.",
		}, true
	}
	return nil, false
}

// RuleCPUGovernorPowersaveLag detects high CPU load while frequency is throttled by powersave governor.
type RuleCPUGovernorPowersaveLag struct{ noSuppression }

func (r *RuleCPUGovernorPowersaveLag) ID() string { return "CONT_CPU_GOVERNOR_POWERSAVE_LAG" }
func (r *RuleCPUGovernorPowersaveLag) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleCPUGovernorPowersaveLag) Tier() int            { return 2 }
func (r *RuleCPUGovernorPowersaveLag) IsPIDDependent() bool { return false }

func (r *RuleCPUGovernorPowersaveLag) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil || !diff.LatestSnapshot.CPUFreq.Available {
		return nil, false
	}

	if diff.TotalCPUUtil.BusyPercent < 75.0 {
		return nil, false
	}

	var throttledCores int
	for _, core := range diff.LatestSnapshot.CPUFreq.Cores {
		if core.Governor == "powersave" && core.MaxFreq > 0 && core.CurFreq <= core.MaxFreq/2 {
			throttledCores++
		}
	}

	if throttledCores > 0 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.86,
			Title:       "CPU Frequency Scaler Clamped by Powersave Governor",
			Explanation: fmt.Sprintf("%d CPU cores are running at <= 50%% max frequency under powersave governor despite %.1f%% compute utilization.", throttledCores, diff.TotalCPUUtil.BusyPercent),
			Evidence: []string{
				fmt.Sprintf("Throttled Powersave Cores: %d cores", throttledCores),
				fmt.Sprintf("Aggregate CPU Utilization: %.1f%% busy", diff.TotalCPUUtil.BusyPercent),
			},
			Remediation: "Set CPU governor to performance: echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor or tune tuned-adm profile.",
		}, true
	}
	return nil, false
}

// RuleKsoftirqdSaturation detects CPU saturation of ksoftirqd threads handling deferred softirqs.
type RuleKsoftirqdSaturation struct{ noSuppression }

func (r *RuleKsoftirqdSaturation) ID() string { return "CONT_KSOFTIRQD_SATURATION" }
func (r *RuleKsoftirqdSaturation) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleKsoftirqdSaturation) Tier() int            { return 2 }
func (r *RuleKsoftirqdSaturation) IsPIDDependent() bool { return true }

func (r *RuleKsoftirqdSaturation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var saturatedDaemon *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if strings.HasPrefix(p.Comm, "ksoftirqd/") && p.CPUPercent >= 40.0 {
			saturatedDaemon = p
			break
		}
	}

	if saturatedDaemon != nil && (diff.TotalCPUUtil.SoftIRQPercent >= 20.0 || diff.TotalCPUUtil.BusyPercent >= 50.0) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.89,
			Title:       "Software Interrupt (ksoftirqd) Daemon Saturation",
			Explanation: fmt.Sprintf("Kernel thread '%s' is consuming %.1f%% CPU processing unbatched softirqs (network RX/TX, timers, RCU).", saturatedDaemon.Comm, saturatedDaemon.CPUPercent),
			Evidence: []string{
				fmt.Sprintf("PID %d [%s]: %.1f%% CPU utilization", saturatedDaemon.PID, saturatedDaemon.Comm, saturatedDaemon.CPUPercent),
				fmt.Sprintf("Host SoftIRQ Time: %.1f%%", diff.TotalCPUUtil.SoftIRQPercent),
			},
			CulpritPID:     saturatedDaemon.PID,
			CulpritName:    saturatedDaemon.Comm,
			CulpritDetails: fmt.Sprintf("Softirq daemon at %.1f%% CPU", saturatedDaemon.CPUPercent),
			Remediation:    "Distribute network packet handling with Receive Packet Steering (RPS), tune NIC multiqueue, or raise sysctl net.core.netdev_budget.",
		}, true
	}
	return nil, false
}

// RuleWorkingsetRefaultThrashing detects continuous page cache eviction and synchronous re-reading.
type RuleWorkingsetRefaultThrashing struct{ noSuppression }

func (r *RuleWorkingsetRefaultThrashing) ID() string { return "CONT_WORKINGSET_REFAULT_THRASHING" }
func (r *RuleWorkingsetRefaultThrashing) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleWorkingsetRefaultThrashing) Tier() int            { return 2 }
func (r *RuleWorkingsetRefaultThrashing) IsPIDDependent() bool { return false }

func (r *RuleWorkingsetRefaultThrashing) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	refaults := diff.VMStat.WorkingsetRefaultFileDelta
	if refaults < 5000 {
		return nil, false
	}

	hasMemPress := diff.VMStat.AllocStallDirectDelta > 0 || diff.VMStat.PgScanDirectDelta > 0
	if diff.LatestSnapshot != nil && diff.LatestSnapshot.PSI.Available && diff.LatestSnapshot.PSI.Memory.Some.Avg10 >= 15.0 {
		hasMemPress = true
	}

	if hasMemPress {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.87,
			Title:       "Working Set Page Cache Thrashing & Refault Storm",
			Explanation: fmt.Sprintf("Detected %d file page refaults under memory pressure; recently evicted page cache pages are immediately being read back from disk.", refaults),
			Evidence: []string{
				fmt.Sprintf("Workingset File Refaults: %d pages", refaults),
				fmt.Sprintf("Direct Memory Reclaim Stalls: %d alloc stalls", diff.VMStat.AllocStallDirectDelta),
			},
			Remediation: "Increase physical RAM, downsize active application caches to fit memory, or pin critical databases using vmtouch.",
		}, true
	}
	return nil, false
}

// RuleDirtyPageFlushSaturation detects applications blocked in synchronous dirty page flush.
type RuleDirtyPageFlushSaturation struct{ noSuppression }

func (r *RuleDirtyPageFlushSaturation) ID() string { return "CONT_DIRTY_PAGE_FLUSH_SATURATION" }
func (r *RuleDirtyPageFlushSaturation) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleDirtyPageFlushSaturation) Tier() int            { return 2 }
func (r *RuleDirtyPageFlushSaturation) IsPIDDependent() bool { return true }

func (r *RuleDirtyPageFlushSaturation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	mem := &diff.LatestSnapshot.Memory
	if mem.MemTotal == 0 {
		return nil, false
	}

	dirtyRatio := float64(mem.Dirty) / float64(mem.MemTotal)
	writebackRatio := float64(mem.Writeback) / float64(mem.MemTotal)

	var blockedProc *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if strings.HasPrefix(p.Wchan, "balance_dirty_pages") {
			blockedProc = p
			break
		}
	}

	if (dirtyRatio >= 0.15 || writebackRatio >= 0.10) && blockedProc != nil {
		diag := &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.90,
			Title:       "Kernel Dirty Memory Writeback Saturation",
			Explanation: fmt.Sprintf("Dirty memory (%.1f MB) has saturated writeback buffers, forcing processes into balance_dirty_pages sleep.", float64(mem.Dirty)/1024),
			Evidence: []string{
				fmt.Sprintf("Dirty Memory: %.1f MB (%.1f%% of RAM)", float64(mem.Dirty)/1024, dirtyRatio*100),
				fmt.Sprintf("Writeback Memory: %.1f MB (%.1f%% of RAM)", float64(mem.Writeback)/1024, writebackRatio*100),
				fmt.Sprintf("Blocked Process: PID %d [%s] (wchan=%s)", blockedProc.PID, blockedProc.Comm, blockedProc.Wchan),
			},
			CulpritPID:     blockedProc.PID,
			CulpritName:    blockedProc.Comm,
			CulpritDetails: fmt.Sprintf("Forced to sleep in '%s'", blockedProc.Wchan),
			Remediation:    "Lower sysctl vm.dirty_background_ratio=5 to trigger earlier async flush, or upgrade storage write bandwidth.",
		}
		return diag, true
	}
	return nil, false
}

// RuleFsyncJournalStall detects multiple processes serialized waiting on filesystem journal commits.
type RuleFsyncJournalStall struct{ noSuppression }

func (r *RuleFsyncJournalStall) ID() string { return "CONT_FSYNC_JOURNAL_STALL" }
func (r *RuleFsyncJournalStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleFsyncJournalStall) Tier() int            { return 2 }
func (r *RuleFsyncJournalStall) IsPIDDependent() bool { return true }

func (r *RuleFsyncJournalStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var syncProcs []collector.ProcessDiff
	for i := range diff.Processes {
		w := diff.Processes[i].Wchan
		if w == "jbd2_log_wait_commit" || w == "vfs_fsync" || w == "xfs_log_reserve" || w == "sync_buffer" || strings.HasPrefix(w, "jbd2_") {
			syncProcs = append(syncProcs, diff.Processes[i])
		}
	}

	if len(syncProcs) < 2 {
		return nil, false
	}

	evidence := make([]string, 0, len(syncProcs)+1)
	evidence = append(evidence, fmt.Sprintf("%d processes serialized on filesystem journal / fsync wait", len(syncProcs)))
	for _, p := range syncProcs {
		evidence = append(evidence, fmt.Sprintf("PID %d [%s] sleeping in wchan '%s'", p.PID, p.Comm, p.Wchan))
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.88,
		Title:          "Filesystem Journal & Synchronous Fsync Lockup",
		Explanation:    fmt.Sprintf("%d processes are stalled waiting on synchronous journal commit transactions (e.g. ext4 jbd2 / xfsaild).", len(syncProcs)),
		Evidence:       evidence,
		CulpritPID:     syncProcs[0].PID,
		CulpritName:    syncProcs[0].Comm,
		CulpritDetails: fmt.Sprintf("Waiting on journal commit in '%s'", syncProcs[0].Wchan),
		Remediation:    "Group database write transactions, adjust journal commit intervals, or place WAL / journal on low-latency NVMe / battery-backed storage.",
	}, true
}

// RulePageCachePollutionStream detects a bulk streaming I/O process evicting active working set cache.
type RulePageCachePollutionStream struct{ noSuppression }

func (r *RulePageCachePollutionStream) ID() string { return "CONT_PAGECACHE_POLLUTION_STREAM" }
func (r *RulePageCachePollutionStream) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RulePageCachePollutionStream) Tier() int            { return 2 }
func (r *RulePageCachePollutionStream) IsPIDDependent() bool { return true }

func (r *RulePageCachePollutionStream) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var streamProc *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		totalIO := p.ReadBytesDelta + p.WriteBytesDelta
		if totalIO >= 50*1024*1024 { // 50MB/s
			if streamProc == nil || totalIO > streamProc.ReadBytesDelta+streamProc.WriteBytesDelta {
				streamProc = p
			}
		}
	}

	if streamProc != nil && (diff.VMStat.WorkingsetRefaultFileDelta >= 1000 || diff.VMStat.PgScanDirectDelta > 0) {
		ioMB := float64(streamProc.ReadBytesDelta+streamProc.WriteBytesDelta) / (1024 * 1024)
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.86,
			Title:       "Sequential I/O Page Cache Eviction Pollution",
			Explanation: fmt.Sprintf("Process '%s' is streaming %.1f MB/s through buffered I/O, evicting active database/application working sets.", streamProc.Comm, ioMB),
			Evidence: []string{
				fmt.Sprintf("PID %d [%s]: %.1f MB/s I/O throughput", streamProc.PID, streamProc.Comm, ioMB),
				fmt.Sprintf("Workingset Refaults Caused: %d pages", diff.VMStat.WorkingsetRefaultFileDelta),
			},
			CulpritPID:     streamProc.PID,
			CulpritName:    streamProc.Comm,
			CulpritDetails: fmt.Sprintf("Streaming %.1f MB I/O in window", ioMB),
			Remediation:    "Run large sequential file readers (rsync, tar, backups) with nocache or posix_fadvise(POSIX_FADV_DONTNEED) to avoid cache pollution.",
		}, true
	}
	return nil, false
}

// RuleSoftnetBacklogDrops detects NIC driver backlog drops or NAPI processing budget depletion.
type RuleSoftnetBacklogDrops struct{ noSuppression }

func (r *RuleSoftnetBacklogDrops) ID() string { return "CONT_NET_SOFTNET_BACKLOG_DROPS" }
func (r *RuleSoftnetBacklogDrops) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleSoftnetBacklogDrops) Tier() int            { return 2 }
func (r *RuleSoftnetBacklogDrops) IsPIDDependent() bool { return false }

func (r *RuleSoftnetBacklogDrops) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	dropped := diff.NetStat.SoftnetDroppedDelta
	squeeze := diff.NetStat.SoftnetTimeSqueezeDelta

	if dropped > 0 || squeeze >= 50 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.89,
			Title:       "Network Stack Backlog Queue Drops (Softnet Overrun)",
			Explanation: fmt.Sprintf("Kernel network layer dropped %d packets and experienced %d NAPI time-squeeze budget overruns in /proc/net/softnet_stat.", dropped, squeeze),
			Evidence: []string{
				fmt.Sprintf("Softnet Backlog Dropped Packets: %d packets", dropped),
				fmt.Sprintf("Softnet Time Squeeze Events: %d budget overruns", squeeze),
			},
			Remediation: "Increase sysctl net.core.netdev_max_backlog=10000 and sysctl net.core.netdev_budget=600 to prevent NIC driver backlog drops.",
		}, true
	}
	return nil, false
}

// RuleTCPRetransmitStorm detects high TCP segment retransmission ratios indicating network loss.
type RuleTCPRetransmitStorm struct{ noSuppression }

func (r *RuleTCPRetransmitStorm) ID() string { return "CONT_TCP_RETRANSMIT_STORM" }
func (r *RuleTCPRetransmitStorm) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleTCPRetransmitStorm) Tier() int            { return 2 }
func (r *RuleTCPRetransmitStorm) IsPIDDependent() bool { return false }

func (r *RuleTCPRetransmitStorm) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	outSegs := diff.NetStat.OutSegsDelta
	retransSegs := diff.NetStat.RetransSegsDelta

	if outSegs >= 500 && retransSegs > 0 {
		ratio := float64(retransSegs) / float64(outSegs)
		if ratio >= 0.05 { // >= 5% retransmissions
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        2,
				Severity:    SeverityHigh,
				Confidence:  0.88,
				Title:       "Severe TCP Packet Retransmission & Loss Rate",
				Explanation: fmt.Sprintf("TCP stack retransmitted %d out of %d segments (%.1f%% loss/retransmit rate), triggering TCP window collapse.", retransSegs, outSegs, ratio*100),
				Evidence: []string{
					fmt.Sprintf("Retransmitted Segments: %d segments", retransSegs),
					fmt.Sprintf("Outbound Segments: %d segments", outSegs),
					fmt.Sprintf("Retransmission Ratio: %.1f%%", ratio*100),
				},
				Remediation: "Check network switch drops, verify MTU consistency across interfaces, or enable BBR congestion control (sysctl net.ipv4.tcp_congestion_control=bbr).",
			}, true
		}
	}
	return nil, false
}

// RuleTCPZeroWindowStall detects sender processes blocked because remote consumers have full socket buffers.
type RuleTCPZeroWindowStall struct{ noSuppression }

func (r *RuleTCPZeroWindowStall) ID() string { return "CONT_TCP_ZEROWINDOW_STALL" }
func (r *RuleTCPZeroWindowStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleTCPZeroWindowStall) Tier() int            { return 2 }
func (r *RuleTCPZeroWindowStall) IsPIDDependent() bool { return true }

func (r *RuleTCPZeroWindowStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var blockedProc *collector.ProcessDiff
	for i := range diff.Processes {
		if diff.Processes[i].Wchan == "sk_stream_wait_memory" {
			blockedProc = &diff.Processes[i]
			break
		}
	}

	winProbes := diff.NetStat.TCPWinProbeDelta
	winDrops := diff.NetStat.TCPZeroWindowDropDelta

	if winProbes >= 5 || winDrops > 0 || (blockedProc != nil && winProbes > 0) {
		diag := &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.87,
			Title:       "TCP Zero-Window Consumer Receive Buffer Stall",
			Explanation: "TCP senders are paused by remote receivers advertising ZeroWindow, indicating slow downstream data consumers.",
			Evidence: []string{
				fmt.Sprintf("TCP Window Probes: %d probes", winProbes),
				fmt.Sprintf("TCP ZeroWindow Drops: %d drops", winDrops),
			},
			Remediation: "Increase application consumer read concurrency, raise TCP socket receive buffers (net.ipv4.tcp_rmem), or profile slow downstream services.",
		}
		if blockedProc != nil {
			diag.CulpritPID = blockedProc.PID
			diag.CulpritName = blockedProc.Comm
			diag.CulpritDetails = "Blocked in kernel socket memory wait (sk_stream_wait_memory)"
		}
		return diag, true
	}
	return nil, false
}

// RuleCoredumpBurstStorm detects intense CPU/disk load generated by crashlooping processes dumping core.
type RuleCoredumpBurstStorm struct{ noSuppression }

func (r *RuleCoredumpBurstStorm) ID() string { return "CONT_COREDUMP_BURST_STORM" }
func (r *RuleCoredumpBurstStorm) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleCoredumpBurstStorm) Tier() int            { return 2 }
func (r *RuleCoredumpBurstStorm) IsPIDDependent() bool { return true }

func (r *RuleCoredumpBurstStorm) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var coredumpProc *collector.ProcessDiff
	for i := range diff.Processes {
		comm := diff.Processes[i].Comm
		if comm == "systemd-coredum" || comm == "apport" || comm == "abrt-hook-ccpp" {
			coredumpProc = &diff.Processes[i]
			break
		}
	}

	if coredumpProc != nil && diff.ProcessesCreatedDelta >= 10 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.91,
			Title:       "Crashlooping Process Coredump Saturation",
			Explanation: fmt.Sprintf("Crash dumper daemon '%s' is consuming system resources capturing core dumps from %d newly forked/crashed processes.", coredumpProc.Comm, diff.ProcessesCreatedDelta),
			Evidence: []string{
				fmt.Sprintf("Core Dumper Daemon: PID %d [%s] (CPU: %.1f%%)", coredumpProc.PID, coredumpProc.Comm, coredumpProc.CPUPercent),
				fmt.Sprintf("Fork / Crash Events: %d process creation events in sampling window", diff.ProcessesCreatedDelta),
			},
			CulpritPID:     coredumpProc.PID,
			CulpritName:    coredumpProc.Comm,
			CulpritDetails: fmt.Sprintf("Active coredump generator at %.1f%% CPU", coredumpProc.CPUPercent),
			Remediation:    "Identify and stop crashlooping containers/services, temporarily disable core dumps (ulimit -c 0), or fix the crashing binary.",
		}, true
	}
	return nil, false
}

// RuleUnixSocketLogBlock detects multiple processes blocked writing to full Unix domain sockets.
type RuleUnixSocketLogBlock struct{ noSuppression }

func (r *RuleUnixSocketLogBlock) ID() string { return "CONT_UNIX_SOCKET_LOG_BLOCK" }
func (r *RuleUnixSocketLogBlock) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleUnixSocketLogBlock) Tier() int            { return 2 }
func (r *RuleUnixSocketLogBlock) IsPIDDependent() bool { return true }

func (r *RuleUnixSocketLogBlock) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var blockedProcs []collector.ProcessDiff
	for i := range diff.Processes {
		w := diff.Processes[i].Wchan
		if w == "unix_wait_for_peer" || w == "unix_stream_sendmsg" || w == "unix_dgram_sendmsg" {
			blockedProcs = append(blockedProcs, diff.Processes[i])
		}
	}

	if len(blockedProcs) >= 2 {
		evidence := make([]string, 0, len(blockedProcs)+1)
		evidence = append(evidence, fmt.Sprintf("%d processes blocked in Unix socket write wait", len(blockedProcs)))
		for _, p := range blockedProcs {
			evidence = append(evidence, fmt.Sprintf("PID %d [%s] waiting in wchan '%s'", p.PID, p.Comm, p.Wchan))
		}

		return &Diagnosis{
			RuleID:         r.ID(),
			Tier:           2,
			Severity:       SeverityHigh,
			Confidence:     0.88,
			Title:          "Unix Domain Socket Logging & IPC Buffer Saturation",
			Explanation:    fmt.Sprintf("%d processes are frozen waiting for Unix domain socket buffers (e.g. /dev/log or journald) to drain.", len(blockedProcs)),
			Evidence:       evidence,
			CulpritPID:     blockedProcs[0].PID,
			CulpritName:    blockedProcs[0].Comm,
			CulpritDetails: fmt.Sprintf("Blocked on Unix socket in '%s'", blockedProcs[0].Wchan),
			Remediation:    "Reduce application log verbosity, switch to asynchronous logging buffers, or increase RateLimitBurst in /etc/systemd/journald.conf.",
		}, true
	}
	return nil, false
}

// RuleUDPBufferOverrun detects packet loss on UDP services from socket receive/send queue overflows.
type RuleUDPBufferOverrun struct{ noSuppression }

func (r *RuleUDPBufferOverrun) ID() string { return "CONT_UDP_BUFFER_OVERRUN" }
func (r *RuleUDPBufferOverrun) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleUDPBufferOverrun) Tier() int            { return 2 }
func (r *RuleUDPBufferOverrun) IsPIDDependent() bool { return false }

func (r *RuleUDPBufferOverrun) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	rcvErrors := diff.NetStat.UDPRcvbufErrorsDelta
	sndErrors := diff.NetStat.UDPSndbufErrorsDelta
	inErrors := diff.NetStat.UDPInErrorsDelta

	if rcvErrors > 0 || sndErrors > 0 || (inErrors >= 10 && diff.NetStat.OutSegsDelta > 0) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.89,
			Title:       "UDP Socket Buffer Overrun & Packet Drop",
			Explanation: fmt.Sprintf("Kernel is dropping UDP datagrams (%d receive buffer drops, %d send buffer drops) due to saturated UDP socket buffers.", rcvErrors, sndErrors),
			Evidence: []string{
				fmt.Sprintf("UDP Receive Buffer Errors Delta: %d drops", rcvErrors),
				fmt.Sprintf("UDP Send Buffer Errors Delta: %d drops", sndErrors),
				fmt.Sprintf("UDP Inbound Errors Delta: %d errors", inErrors),
			},
			Remediation: "Increase system UDP buffer limits: sysctl -w net.core.rmem_max=16777216 net.core.rmem_default=262144, or enlarge application SO_RCVBUF socket buffers (DNS/VoIP/StatsD).",
		}, true
	}
	return nil, false
}

// RuleTCPListenOverflowStall detects TCP listen queue overflow drop bursts resetting incoming connections.
type RuleTCPListenOverflowStall struct{ noSuppression }

func (r *RuleTCPListenOverflowStall) ID() string { return "CONT_TCP_LISTEN_OVERFLOW_STALL" }
func (r *RuleTCPListenOverflowStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleTCPListenOverflowStall) Tier() int            { return 2 }
func (r *RuleTCPListenOverflowStall) IsPIDDependent() bool { return false }

func (r *RuleTCPListenOverflowStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	overflows := diff.NetStat.ListenOverflowsDelta
	aborts := diff.NetStat.TCPAbortOnDataDelta

	if overflows > 0 && (aborts > 0 || diff.NetStat.ListenDropsDelta > 0) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.91,
			Title:       "TCP Server Listen Backlog Overflow & Connection Abort",
			Explanation: fmt.Sprintf("Server application listen backlog has overflowed (%d overflows, %d aborted connections in sampling window), causing clients to receive connection resets.", overflows, aborts),
			Evidence: []string{
				fmt.Sprintf("TCP Listen Queue Overflows Delta: %d overflow events", overflows),
				fmt.Sprintf("TCP Abort On Data Delta: %d aborted connections", aborts),
			},
			Remediation: "Increase server socket listen backlog (sysctl -w net.core.somaxconn=8192) and increase application worker thread pool concurrency.",
		}, true
	}
	return nil, false
}

// RuleHugeTLBPoolExhaustion detects when configured explicit HugeTLB pool is 100% exhausted.
type RuleHugeTLBPoolExhaustion struct{ noSuppression }

func (r *RuleHugeTLBPoolExhaustion) ID() string { return "CONT_HUGETLB_POOL_EXHAUSTION" }
func (r *RuleHugeTLBPoolExhaustion) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleHugeTLBPoolExhaustion) Tier() int            { return 2 }
func (r *RuleHugeTLBPoolExhaustion) IsPIDDependent() bool { return false }

func (r *RuleHugeTLBPoolExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	mem := diff.LatestSnapshot.Memory
	if mem.HugePagesTotal > 0 && mem.HugePagesFree == 0 && mem.HugePagesRsvd > 0 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.93,
			Title:       "Dedicated HugeTLB (HugePages) Pool Exhaustion",
			Explanation: fmt.Sprintf("System explicit HugePages pool is 100%% exhausted (%d total, 0 free, %d reserved), causing database or high-performance runtime allocations to fail or degrade.", mem.HugePagesTotal, mem.HugePagesRsvd),
			Evidence: []string{
				fmt.Sprintf("HugePages Total: %d pages", mem.HugePagesTotal),
				fmt.Sprintf("HugePages Free: %d pages", mem.HugePagesFree),
				fmt.Sprintf("HugePages Reserved: %d pages", mem.HugePagesRsvd),
			},
			Remediation: "Increase allocated HugePages pool: sysctl -w vm.nr_hugepages=<N> or reduce application shared memory segment requirements.",
		}, true
	}
	return nil, false
}

// RulePtraceTracerAttach detects active processes running with attached debuggers/tracers injecting syscall latency.
type RulePtraceTracerAttach struct{ noSuppression }

func (r *RulePtraceTracerAttach) ID() string { return "CONT_PTRACE_TRACER_ATTACH" }
func (r *RulePtraceTracerAttach) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RulePtraceTracerAttach) Tier() int            { return 2 }
func (r *RulePtraceTracerAttach) IsPIDDependent() bool { return true }

func (r *RulePtraceTracerAttach) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.TracerPID > 0 && (p.CPUPercent >= 20.0 || p.CPUTimeDelta > 0) {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        2,
				Severity:    SeverityHigh,
				Confidence:  0.94,
				Title:       "Process Degraded by Active Debugger / Tracer (ptrace)",
				Explanation: fmt.Sprintf("Process '%s' (PID %d) is being traced by debugger/profiler (Tracer PID %d), introducing severe syscall interception latency.", p.Comm, p.PID, p.TracerPID),
				Evidence: []string{
					fmt.Sprintf("Target PID %d [%s]: %.1f%% CPU utilization", p.PID, p.Comm, p.CPUPercent),
					fmt.Sprintf("Tracer PID: %d attached via ptrace()", p.TracerPID),
				},
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("Target PID %d traced by Tracer PID %d", p.PID, p.TracerPID),
				Remediation:    fmt.Sprintf("Detach interactive tracer/debugger (PID %d - strace/gdb) or replace with low-overhead non-blocking sampling profiler (perf / eBPF).", p.TracerPID),
			}, true
		}
	}
	return nil, false
}

// RuleSysVSemaphoreLimit detects system-wide SysV IPC semaphore exhaustion blocking database connections.
type RuleSysVSemaphoreLimit struct{ noSuppression }

func (r *RuleSysVSemaphoreLimit) ID() string { return "CONT_SYSV_SEMAPHORE_LIMIT" }
func (r *RuleSysVSemaphoreLimit) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleSysVSemaphoreLimit) Tier() int            { return 2 }
func (r *RuleSysVSemaphoreLimit) IsPIDDependent() bool { return false }

func (r *RuleSysVSemaphoreLimit) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	sem := diff.LatestSnapshot.SystemConfig.SysVSem
	if !sem.Available {
		return nil, false
	}

	semNearLimit := sem.SemMNS > 0 && sem.AllocatedSemaphores >= (sem.SemMNS*90)/100
	setNearLimit := sem.SemMNI > 0 && sem.AllocatedSemSets >= (sem.SemMNI*90)/100

	if semNearLimit || setNearLimit {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.92,
			Title:       "System V IPC Semaphore Table Exhaustion",
			Explanation: fmt.Sprintf("System V IPC semaphores (%d allocated / %d max SEMMNS) or semaphore sets (%d / %d max SEMMNI) are saturated, blocking database/middleware process creation.", sem.AllocatedSemaphores, sem.SemMNS, sem.AllocatedSemSets, sem.SemMNI),
			Evidence: []string{
				fmt.Sprintf("Allocated Semaphores: %d / %d SEMMNS (%.1f%%)", sem.AllocatedSemaphores, sem.SemMNS, (float64(sem.AllocatedSemaphores)/float64(sem.SemMNS))*100),
				fmt.Sprintf("Allocated Semaphore Sets: %d / %d SEMMNI (%.1f%%)", sem.AllocatedSemSets, sem.SemMNI, (float64(sem.AllocatedSemSets)/float64(sem.SemMNI))*100),
			},
			Remediation: "Increase SysV IPC semaphore limits: sysctl -w kernel.sem=\"50100 64128000 50100 1280\" or clean stale semaphore sets (ipcrm -s <semid>).",
		}, true
	}
	return nil, false
}

// RuleTCPTimeWaitBucketOverflow detects TCP TIME_WAIT bucket saturation dropping new connections.
type RuleTCPTimeWaitBucketOverflow struct{ noSuppression }

func (r *RuleTCPTimeWaitBucketOverflow) ID() string { return "CONT_TCP_TIMEWAIT_BUCKET_OVERFLOW" }
func (r *RuleTCPTimeWaitBucketOverflow) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleTCPTimeWaitBucketOverflow) Tier() int            { return 2 }
func (r *RuleTCPTimeWaitBucketOverflow) IsPIDDependent() bool { return false }

func (r *RuleTCPTimeWaitBucketOverflow) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	overflows := diff.NetStat.TCPTimeWaitOverflowDelta
	twBucketsMax := diff.LatestSnapshot.SystemConfig.TCPMaxTWBuckets
	twCount := diff.LatestSnapshot.SystemConfig.SockStat.TCPTimeWait

	isNearMax := twBucketsMax > 0 && twCount >= (twBucketsMax*85)/100

	if overflows > 0 || (isNearMax && diff.NetStat.OutSegsDelta > 0) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.94,
			Title:       "TCP TIME_WAIT Bucket Table Overflow",
			Explanation: fmt.Sprintf("Kernel tcp_max_tw_buckets limit (%d active / %d max) is overflowing (%d overflow events), causing incoming TCP connections to be dropped.", twCount, twBucketsMax, overflows),
			Evidence: []string{
				fmt.Sprintf("TCP TIME_WAIT Sockets: %d / %d max_tw_buckets", twCount, twBucketsMax),
				fmt.Sprintf("TCP TimeWait Overflow Delta: %d overflow events", overflows),
			},
			Remediation: "Raise bucket limit: sysctl -w net.ipv4.tcp_max_tw_buckets=2000000 and enable TIME_WAIT socket recycling: sysctl -w net.ipv4.tcp_tw_reuse=1.",
		}, true
	}
	return nil, false
}

// RuleCgroupIOThrottleStall detects container I/O operations throttled by Cgroup v2 io.max controllers.
type RuleCgroupIOThrottleStall struct{ noSuppression }

func (r *RuleCgroupIOThrottleStall) ID() string { return "CONT_CGROUP_IO_THROTTLE_STALL" }
func (r *RuleCgroupIOThrottleStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleCgroupIOThrottleStall) Tier() int            { return 2 }
func (r *RuleCgroupIOThrottleStall) IsPIDDependent() bool { return true }

func (r *RuleCgroupIOThrottleStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	ioFullPressure := diff.LatestSnapshot.PSI.IO.Full.Avg10
	if ioFullPressure < 10.0 {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.CgroupPath != "" && p.CgroupPath != "/" && (p.Wchan == "io_schedule" || p.Wchan == "bdi_writeback_workfn" || p.State == 'D') {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        2,
				Severity:    SeverityHigh,
				Confidence:  0.91,
				Title:       "Container Cgroup I/O Max Bandwidth / IOPS Throttle",
				Explanation: fmt.Sprintf("Process '%s' (PID %d) in cgroup '%s' is heavily throttled by cgroup io.max bandwidth/IOPS limits under %.1f%% PSI I/O pressure.", p.Comm, p.PID, p.CgroupPath, ioFullPressure),
				Evidence: []string{
					fmt.Sprintf("Cgroup Path: %s", p.CgroupPath),
					fmt.Sprintf("PSI I/O Pressure (Full): %.2f%%", ioFullPressure),
					fmt.Sprintf("PID %d [%s] blocked in wchan '%s'", p.PID, p.Comm, p.Wchan),
				},
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("Throttled in cgroup '%s' (%s)", p.CgroupPath, p.Wchan),
				Remediation:    fmt.Sprintf("Increase container cgroup I/O limits: docker update --io-max-bandwidth /dev/sda:500M (or relax io.max in %s).", p.CgroupPath),
			}, true
		}
	}
	return nil, false
}

// RuleAuditdBacklogWaitStall detects processes blocked in kernel space due to audit subsystem backlog saturation.
type RuleAuditdBacklogWaitStall struct{ noSuppression }

func (r *RuleAuditdBacklogWaitStall) ID() string { return "CONT_AUDITD_BACKLOG_WAIT_STALL" }
func (r *RuleAuditdBacklogWaitStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleAuditdBacklogWaitStall) Tier() int            { return 2 }
func (r *RuleAuditdBacklogWaitStall) IsPIDDependent() bool { return true }

func (r *RuleAuditdBacklogWaitStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var stalledProcs []collector.ProcessDiff
	hasDState := false
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.Wchan == "kauditd_wait" || p.Wchan == "audit_log_start" || p.Wchan == "audit_receive" || strings.Contains(p.Wchan, "audit_log") {
			stalledProcs = append(stalledProcs, *p)
			if p.State == 'D' {
				hasDState = true
			}
		}
	}

	if len(stalledProcs) < 2 {
		return nil, false
	}

	if diff.ProcsBlocked < 2 && !hasDState {
		return nil, false
	}

	evidence := make([]string, 0, len(stalledProcs)+2)
	evidence = append(evidence, fmt.Sprintf("%d processes blocked in audit logging kernel wait", len(stalledProcs)))
	evidence = append(evidence, fmt.Sprintf("ProcsBlocked: %d", diff.ProcsBlocked))
	for i := 0; i < len(stalledProcs) && i < 5; i++ {
		evidence = append(evidence, fmt.Sprintf("PID %d [%s]: wchan=%s, state=%c", stalledProcs[i].PID, stalledProcs[i].Comm, stalledProcs[i].Wchan, stalledProcs[i].State))
	}

	culprit := &stalledProcs[0]

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.90,
		Title:          "Linux Audit Subsystem Backlog Sync Stall",
		Explanation:    fmt.Sprintf("%d processes are stalled synchronously waiting on kernel kauditd backlog queues, serializing syscall dispatch.", len(stalledProcs)),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Blocked in %s (state %c)", culprit.Wchan, culprit.State),
		Remediation:    "Increase audit backlog limit and set failure mode to silent drop: auditctl -b 8192 -f 0 (or disable auditing: auditctl -e 0).",
	}, true
}

// RuleTCPSndbufExhaustion detects outbound TCP throughput stalls caused by saturated socket send buffers.
type RuleTCPSndbufExhaustion struct{ noSuppression }

func (r *RuleTCPSndbufExhaustion) ID() string { return "CONT_TCP_SNDBUF_EXHAUSTION" }
func (r *RuleTCPSndbufExhaustion) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleTCPSndbufExhaustion) Tier() int            { return 2 }
func (r *RuleTCPSndbufExhaustion) IsPIDDependent() bool { return true }

func (r *RuleTCPSndbufExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var stalledProcs []collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.Wchan == "sk_stream_wait_memory" || p.Wchan == "tcp_sendmsg_locked" {
			stalledProcs = append(stalledProcs, *p)
		}
	}

	if len(stalledProcs) == 0 {
		return nil, false
	}

	hasCorroboration := diff.NetStat.TCPSlowStartRetransDelta > 0 ||
		diff.NetStat.TCPMemoryPressuresDelta > 0 ||
		diff.NetStat.TCPWinProbeDelta > 0 ||
		diff.NetStat.RetransSegsDelta >= 10

	if !hasCorroboration {
		return nil, false
	}

	evidence := make([]string, 0, len(stalledProcs)+3)
	evidence = append(evidence, fmt.Sprintf("%d processes blocked waiting for socket write memory", len(stalledProcs)))
	if diff.NetStat.TCPSlowStartRetransDelta > 0 {
		evidence = append(evidence, fmt.Sprintf("TCPSlowStartRetrans Delta: %d", diff.NetStat.TCPSlowStartRetransDelta))
	}
	if diff.NetStat.TCPMemoryPressuresDelta > 0 {
		evidence = append(evidence, fmt.Sprintf("TCPMemoryPressures Delta: %d", diff.NetStat.TCPMemoryPressuresDelta))
	}
	if diff.NetStat.TCPWinProbeDelta > 0 {
		evidence = append(evidence, fmt.Sprintf("TCPWinProbe Delta: %d", diff.NetStat.TCPWinProbeDelta))
	}
	for i := 0; i < len(stalledProcs) && i < 5; i++ {
		evidence = append(evidence, fmt.Sprintf("PID %d [%s]: wchan=%s", stalledProcs[i].PID, stalledProcs[i].Comm, stalledProcs[i].Wchan))
	}

	culprit := &stalledProcs[0]

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.88,
		Title:          "Outbound TCP Socket Send Buffer Starvation",
		Explanation:    fmt.Sprintf("Process '%s' (PID %d) is blocked in socket send syscalls waiting for TCP send buffer memory to drain.", culprit.Comm, culprit.PID),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Stalled in %s", culprit.Wchan),
		Remediation:    "Enlarge TCP send buffer limits: sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216' and enable TCP window scaling: sysctl -w net.ipv4.tcp_window_scaling=1.",
	}, true
}

// RuleXFSAILPushStall detects XFS filesystem journal metadata log locks and Active Item List pushes.
type RuleXFSAILPushStall struct{ noSuppression }

func (r *RuleXFSAILPushStall) ID() string { return "CONT_XFS_AIL_PUSH_STALL" }
func (r *RuleXFSAILPushStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleXFSAILPushStall) Tier() int            { return 2 }
func (r *RuleXFSAILPushStall) IsPIDDependent() bool { return true }

func (r *RuleXFSAILPushStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var stalledProcs []collector.ProcessDiff
	dCount := 0
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.State == 'D' {
			dCount++
		}
		if p.Wchan == "xfs_log_reserve" || p.Wchan == "xfs_trans_reserve" || p.Wchan == "xfs_iomap_write_allocate" || p.Wchan == "xfsaild" || p.Wchan == "xfslogd" {
			stalledProcs = append(stalledProcs, *p)
		}
	}

	if len(stalledProcs) < 2 {
		return nil, false
	}

	psiIOHigh := diff.LatestSnapshot != nil && diff.LatestSnapshot.PSI.IO.Some.Avg10 >= 15.0
	if !psiIOHigh && diff.ProcsBlocked < 2 && dCount < 2 {
		return nil, false
	}

	evidence := make([]string, 0, len(stalledProcs)+2)
	evidence = append(evidence, fmt.Sprintf("%d processes blocked in XFS transaction/log reserve", len(stalledProcs)))
	if diff.LatestSnapshot != nil && diff.LatestSnapshot.PSI.Available {
		evidence = append(evidence, fmt.Sprintf("PSI IO Pressure (Some): %.2f%%", diff.LatestSnapshot.PSI.IO.Some.Avg10))
	}
	for i := 0; i < len(stalledProcs) && i < 5; i++ {
		evidence = append(evidence, fmt.Sprintf("PID %d [%s]: wchan=%s, state=%c", stalledProcs[i].PID, stalledProcs[i].Comm, stalledProcs[i].Wchan, stalledProcs[i].State))
	}

	culprit := &stalledProcs[0]

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.89,
		Title:          "XFS Journal Active Item List (AIL) Log Lock Stall",
		Explanation:    fmt.Sprintf("%d processes are stalled waiting for XFS log reservations while the xfsaild thread pushes dirty metadata.", len(stalledProcs)),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Blocked in %s", culprit.Wchan),
		Remediation:    "Mount XFS with increased log buffers: mount -o remount,logbufs=8,logbsize=256k <mount_point> or expand XFS on-disk log size.",
	}, true
}

// RuleDMQueueCongestion detects Device Mapper (LVM / LUKS / dm-thin) virtual queue saturation.
type RuleDMQueueCongestion struct{ noSuppression }

func (r *RuleDMQueueCongestion) ID() string { return "CONT_DM_QUEUE_CONGESTION" }
func (r *RuleDMQueueCongestion) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleDMQueueCongestion) Tier() int            { return 2 }
func (r *RuleDMQueueCongestion) IsPIDDependent() bool { return true }

func (r *RuleDMQueueCongestion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var congestedDM *collector.DiskDeviceDiff
	for i := range diff.Disks {
		d := &diff.Disks[i]
		if strings.HasPrefix(d.DeviceName, "dm-") && d.UtilPercent >= 80.0 && d.AvgWriteLatencyMS >= 50.0 {
			if congestedDM == nil || d.UtilPercent > congestedDM.UtilPercent {
				congestedDM = d
			}
		}
	}

	if congestedDM == nil {
		return nil, false
	}

	var dmWorker *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.Wchan == "kcryptd" || p.Wchan == "dm_bufio_prefetch" || p.Wchan == "dm_request_fn" || strings.Contains(p.Comm, "kcryptd") || strings.Contains(p.Comm, "dm-") {
			dmWorker = p
			break
		}
	}

	if congestedDM.IOsInProgress < 5 && dmWorker == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Device '%s' I/O Utilization: %.1f%%", congestedDM.DeviceName, congestedDM.UtilPercent),
		fmt.Sprintf("Average Write Latency: %.2f ms/op", congestedDM.AvgWriteLatencyMS),
		fmt.Sprintf("I/O Operations in Progress: %d", congestedDM.IOsInProgress),
	}

	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.89,
		Title:       fmt.Sprintf("Device-Mapper / LVM / LUKS Queue Congestion (%s)", congestedDM.DeviceName),
		Explanation: fmt.Sprintf("Virtual device-mapper block device '%s' is operating at %.1f%% utilization with high write latency (%.1f ms/op), bottlenecking encrypted or thin-provisioned storage.", congestedDM.DeviceName, congestedDM.UtilPercent, congestedDM.AvgWriteLatencyMS),
		Evidence:    evidence,
		Remediation: fmt.Sprintf("Increase device-mapper request queue depth: echo 1024 > /sys/block/%s/queue/nr_requests && echo none > /sys/block/%s/queue/scheduler.", congestedDM.DeviceName, congestedDM.DeviceName),
	}

	if dmWorker != nil {
		diag.CulpritPID = dmWorker.PID
		diag.CulpritName = dmWorker.Comm
		diag.CulpritDetails = fmt.Sprintf("DM worker wchan '%s' (State %c)", dmWorker.Wchan, dmWorker.State)
	}

	return diag, true
}

// RuleTCPSYNCookieFloodStall detects inbound SYN queue exhaustion forcing degraded SYN cookie handshakes.
type RuleTCPSYNCookieFloodStall struct{ noSuppression }

func (r *RuleTCPSYNCookieFloodStall) ID() string { return "CONT_TCP_SYN_COOKIE_FLOOD_STALL" }
func (r *RuleTCPSYNCookieFloodStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleTCPSYNCookieFloodStall) Tier() int            { return 2 }
func (r *RuleTCPSYNCookieFloodStall) IsPIDDependent() bool { return false }

func (r *RuleTCPSYNCookieFloodStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	syncookiesSent := diff.NetStat.SyncookiesSentDelta
	reqQFull := diff.NetStat.TCPReqQFullDoCookiesDelta
	syncookiesFailed := diff.NetStat.SyncookiesFailedDelta
	outSegs := diff.NetStat.OutSegsDelta

	if (syncookiesSent >= 50 || reqQFull >= 50) && (syncookiesFailed > 0 || outSegs >= 500) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.91,
			Title:       "TCP Inbound SYN Cookie Burst & Handshake Degradation",
			Explanation: fmt.Sprintf("Kernel half-open TCP connection backlog is full (%d SYN cookies sent, %d failed), forcing connections into cryptographic SYN cookie verification and disabling advanced TCP options (Window Scaling, SACK).", syncookiesSent, syncookiesFailed),
			Evidence: []string{
				fmt.Sprintf("SyncookiesSent Delta: %d cookies generated", syncookiesSent),
				fmt.Sprintf("TCPReqQFullDoCookies Delta: %d cookies triggered", reqQFull),
				fmt.Sprintf("SyncookiesFailed Delta: %d failed validations", syncookiesFailed),
				fmt.Sprintf("Outbound Segments Delta: %d segs", outSegs),
			},
			Remediation: "Increase SYN backlog ceiling and listen backlog: sysctl -w net.ipv4.tcp_max_syn_backlog=65535 && sysctl -w net.core.somaxconn=65535.",
		}, true
	}

	return nil, false
}

// RuleEpollWakeupContention detects multi-worker thundering herd wake-up contention in epoll event loops.
type RuleEpollWakeupContention struct{ noSuppression }

func (r *RuleEpollWakeupContention) ID() string { return "CONT_EPOLL_WAKEUP_CONTENTION" }
func (r *RuleEpollWakeupContention) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleEpollWakeupContention) Tier() int            { return 2 }
func (r *RuleEpollWakeupContention) IsPIDDependent() bool { return true }

func (r *RuleEpollWakeupContention) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var epollProcs []collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.Wchan == "do_epoll_wait" || p.Wchan == "ep_poll" || p.Wchan == "ep_poll_callback" {
			epollProcs = append(epollProcs, *p)
		}
	}

	if len(epollProcs) >= 8 && diff.ContextSwitchesDelta >= 50000 && diff.TotalCPUUtil.SystemPercent >= 15.0 {
		culprit := &epollProcs[0]
		evidence := []string{
			fmt.Sprintf("%d threads/processes sleeping in epoll_wait", len(epollProcs)),
			fmt.Sprintf("Context Switches Delta: %d / sec", diff.ContextSwitchesDelta),
			fmt.Sprintf("Kernel System CPU: %.1f%%", diff.TotalCPUUtil.SystemPercent),
			fmt.Sprintf("Sample Process: PID %d [%s] in wchan '%s'", culprit.PID, culprit.Comm, culprit.Wchan),
		}

		return &Diagnosis{
			RuleID:         r.ID(),
			Tier:           2,
			Severity:       SeverityHigh,
			Confidence:     0.87,
			Title:          "Multi-Worker Epoll Thundering Herd Wakeup Contention",
			Explanation:    fmt.Sprintf("%d worker threads sharing event loops are suffering from thundering herd wakeups, causing %d context switches/sec and %.1f%% kernel CPU overhead.", len(epollProcs), diff.ContextSwitchesDelta, diff.TotalCPUUtil.SystemPercent),
			Evidence:       evidence,
			CulpritPID:     culprit.PID,
			CulpritName:    culprit.Comm,
			CulpritDetails: fmt.Sprintf("Worker in wchan '%s'", culprit.Wchan),
			Remediation:    "Configure socket listener with SO_REUSEPORT or use EPOLLEXCLUSIVE flag in epoll_ctl to prevent multi-worker wakeup storm.",
		}, true
	}

	return nil, false
}

// RuleAIOEventLimitSaturation detects exhaustion of Linux kernel asynchronous I/O event limits.
type RuleAIOEventLimitSaturation struct{ noSuppression }

func (r *RuleAIOEventLimitSaturation) ID() string { return "CONT_AIO_EVENT_LIMIT_SATURATION" }
func (r *RuleAIOEventLimitSaturation) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleAIOEventLimitSaturation) Tier() int            { return 2 }
func (r *RuleAIOEventLimitSaturation) IsPIDDependent() bool { return true }

func (r *RuleAIOEventLimitSaturation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	aioNR := diff.LatestSnapshot.SystemConfig.AIONR
	aioMax := diff.LatestSnapshot.SystemConfig.AIOMaxNR
	if aioMax == 0 {
		return nil, false
	}

	ratio := float64(aioNR) / float64(aioMax)
	if ratio < 0.90 {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.Wchan == "io_submit" || p.Wchan == "io_getevents" || p.Wchan == "wait_on_page_bit" || p.State == 'D' {
			culprit = p
			break
		}
	}

	if culprit == nil && diff.ProcsBlocked < 2 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Allocated AIO Events: %d / %d (%.1f%% of fs.aio-max-nr)", aioNR, aioMax, ratio*100),
		fmt.Sprintf("Blocked Processes: %d", diff.ProcsBlocked),
	}
	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.95,
		Title:       "Kernel Asynchronous I/O Event Ceiling Saturation",
		Explanation: fmt.Sprintf("Kernel asynchronous I/O event requests (%d/%d, %.1f%%) are saturating fs.aio-max-nr, risking io_setup/io_submit EAGAIN failures and blocking database I/O.", aioNR, aioMax, ratio*100),
		Evidence:    evidence,
		Remediation: "Increase kernel asynchronous I/O event ceiling: sysctl -w fs.aio-max-nr=1048576.",
	}
	if culprit != nil {
		diag.CulpritPID = culprit.PID
		diag.CulpritName = culprit.Comm
		diag.CulpritDetails = fmt.Sprintf("Process in wchan '%s' (State: %c)", culprit.Wchan, culprit.State)
		diag.Evidence = append(diag.Evidence, fmt.Sprintf("Culprit PID: %d [%s] in wchan '%s'", culprit.PID, culprit.Comm, culprit.Wchan))
	}
	return diag, true
}

// RuleKswapdCPUSpin detects background page reclamation daemon kswapd burning CPU failing to restore watermarks.
type RuleKswapdCPUSpin struct{ noSuppression }

func (r *RuleKswapdCPUSpin) ID() string { return "CONT_KSWAPD_CPU_SPIN" }
func (r *RuleKswapdCPUSpin) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleKswapdCPUSpin) Tier() int            { return 2 }
func (r *RuleKswapdCPUSpin) IsPIDDependent() bool { return true }

func (r *RuleKswapdCPUSpin) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var kswapdProc *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if strings.HasPrefix(p.Comm, "kswapd") && p.CPUPercent >= 40.0 {
			kswapdProc = p
			break
		}
	}

	if kswapdProc == nil {
		return nil, false
	}

	hasCorroboration := diff.VMStat.PgScanDirectDelta > 0 ||
		diff.VMStat.AllocStallDirectDelta > 0 ||
		diff.VMStat.WorkingsetRefaultFileDelta >= 1000 ||
		(diff.LatestSnapshot != nil && diff.LatestSnapshot.PSI.Available && diff.LatestSnapshot.PSI.Memory.Some.Avg10 >= 15.0)

	if !hasCorroboration {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Daemon PID %d [%s] CPU: %.1f%%", kswapdProc.PID, kswapdProc.Comm, kswapdProc.CPUPercent),
		fmt.Sprintf("Direct Reclaim Page Scans Delta: %d", diff.VMStat.PgScanDirectDelta),
		fmt.Sprintf("Direct Allocation Stalls Delta: %d", diff.VMStat.AllocStallDirectDelta),
		fmt.Sprintf("File WorkingSet Refaults Delta: %d", diff.VMStat.WorkingsetRefaultFileDelta),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.92,
		Title:          "Background Memory Reclaim Daemon kswapd CPU Saturation",
		Explanation:    fmt.Sprintf("Kernel asynchronous page reclaim daemon %s is consuming %.1f%% CPU scanning memory without restoring watermarks, stalling applications in memory allocation.", kswapdProc.Comm, kswapdProc.CPUPercent),
		Evidence:       evidence,
		CulpritPID:     kswapdProc.PID,
		CulpritName:    kswapdProc.Comm,
		CulpritDetails: fmt.Sprintf("kswapd consuming %.1f%% CPU in page reclamation", kswapdProc.CPUPercent),
		Remediation:    "Tune watermark scale factor or reduce memory pressure: sysctl -w vm.watermark_scale_factor=200 && sysctl -w vm.vfs_cache_pressure=50.",
	}, true
}

// RuleMDRAIDResyncStall detects background Software RAID rebuild/scrubbing operations saturating storage.
type RuleMDRAIDResyncStall struct{ noSuppression }

func (r *RuleMDRAIDResyncStall) ID() string { return "CONT_MD_RAID_RESYNC_STALL" }
func (r *RuleMDRAIDResyncStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleMDRAIDResyncStall) Tier() int            { return 2 }
func (r *RuleMDRAIDResyncStall) IsPIDDependent() bool { return false }

func (r *RuleMDRAIDResyncStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	mdStat := diff.LatestSnapshot.SystemConfig.MDStat
	if !mdStat.Available || !mdStat.ActiveResync {
		return nil, false
	}

	var congestedDisk *collector.DiskDeviceDiff
	for i := range diff.Disks {
		d := &diff.Disks[i]
		if d.IOsInProgress >= 4 || d.AvgWriteLatencyMS >= 50.0 || d.UtilPercent >= 80.0 {
			congestedDisk = d
			break
		}
	}

	psiStall := diff.LatestSnapshot.PSI.Available && diff.LatestSnapshot.PSI.IO.Some.Avg10 >= 15.0
	if congestedDisk == nil && !psiStall {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Active Software RAID Operation: '%s' on %s", mdStat.Operation, mdStat.ArrayName),
	}
	if congestedDisk != nil {
		evidence = append(evidence,
			fmt.Sprintf("Underlying Device: %s (Util: %.1f%%, Latency: %.1fms, InFlight: %d)",
				congestedDisk.DeviceName, congestedDisk.UtilPercent, congestedDisk.AvgWriteLatencyMS, congestedDisk.IOsInProgress),
		)
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.94,
		Title:       "Software RAID Array Resync & Rebuild I/O Saturation",
		Explanation: fmt.Sprintf("Linux Software RAID (/dev/%s) is actively executing background '%s', generating continuous sequential I/O and spiking storage service latency for foreground applications.", mdStat.ArrayName, mdStat.Operation),
		Evidence:    evidence,
		Remediation: "Throttle background RAID rebuild bandwidth: sysctl -w dev.raid.speed_limit_max=20000 && sysctl -w dev.raid.speed_limit_min=1000.",
	}, true
}

// RuleNetOutOfOrderStall detects heavy out-of-order TCP segment queuing and socket buffer collapse.
type RuleNetOutOfOrderStall struct{ noSuppression }

func (r *RuleNetOutOfOrderStall) ID() string { return "CONT_NET_OUT_OF_ORDER_STALL" }
func (r *RuleNetOutOfOrderStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetOutOfOrderStall) Tier() int            { return 2 }
func (r *RuleNetOutOfOrderStall) IsPIDDependent() bool { return false }

func (r *RuleNetOutOfOrderStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	ofoQueue := diff.NetStat.TCPOFOQueueDelta
	if ofoQueue < 500 {
		return nil, false
	}

	collapsed := diff.NetStat.TCPRcvCollapsedDelta
	ofoDrop := diff.NetStat.TCPOFODropDelta
	retransRatio := 0.0
	if diff.NetStat.OutSegsDelta >= 300 {
		retransRatio = float64(diff.NetStat.RetransSegsDelta) / float64(diff.NetStat.OutSegsDelta)
	}

	if collapsed == 0 && ofoDrop == 0 && retransRatio < 0.03 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCPOFOQueue Delta: %d out-of-order segments queued", ofoQueue),
		fmt.Sprintf("TCPRcvCollapsed Delta: %d pruned buffer collapses", collapsed),
		fmt.Sprintf("TCPOFODrop Delta: %d dropped segments", ofoDrop),
		fmt.Sprintf("TCP Retransmit Ratio: %.1f%% (%d/%d segs)", retransRatio*100, diff.NetStat.RetransSegsDelta, diff.NetStat.OutSegsDelta),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.88,
		Title:       "TCP Out-of-Order Queue Overflow & SACK Recovery Stall",
		Explanation: fmt.Sprintf("High volume of out-of-order TCP segments (%d queued, %d collapsed) is saturating socket reassembly queues, triggering receive window collapse and throughput degradation.", ofoQueue, collapsed),
		Evidence:    evidence,
		Remediation: "Increase TCP reordering tolerance and read buffer headroom: sysctl -w net.ipv4.tcp_reordering=6 && sysctl -w net.ipv4.tcp_rmem=\"4096 131072 16777216\".",
	}, true
}

// RulePOSIXRTSigQueueSaturation detects POSIX real-time signal queue capacity exhaustion.
type RulePOSIXRTSigQueueSaturation struct{ noSuppression }

func (r *RulePOSIXRTSigQueueSaturation) ID() string { return "CONT_POSIX_RTSIG_QUEUE_SATURATION" }
func (r *RulePOSIXRTSigQueueSaturation) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RulePOSIXRTSigQueueSaturation) Tier() int            { return 2 }
func (r *RulePOSIXRTSigQueueSaturation) IsPIDDependent() bool { return true }

func (r *RulePOSIXRTSigQueueSaturation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.SigQMax > 0 && p.SigQRatio >= 0.85 {
			if p.NumThreads >= 16 || p.CPUPercent >= 20.0 || p.State == 'D' {
				culprit = p
				break
			}
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] Queued Real-Time Signals: %d / %d (%.1f%%)",
			culprit.PID, culprit.Comm, culprit.SigQQueued, culprit.SigQMax, culprit.SigQRatio*100),
		fmt.Sprintf("Threads: %d, CPU: %.1f%%, State: %c", culprit.NumThreads, culprit.CPUPercent, culprit.State),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.90,
		Title:          "POSIX Real-Time Signal Queue Capacity Saturation",
		Explanation:    fmt.Sprintf("Process %s (PID %d) has queued %d/%d real-time signals (%.1f%% of limit), risking signal drop or EAGAIN delivery failures.", culprit.Comm, culprit.PID, culprit.SigQQueued, culprit.SigQMax, culprit.SigQRatio*100),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("SigQ %d/%d (%.1f%%)", culprit.SigQQueued, culprit.SigQMax, culprit.SigQRatio*100),
		Remediation:    "Increase system-wide real-time signal queue limit: sysctl -w kernel.rtsig-max=65536.",
	}, true
}

// RuleUDPSndbufExhaustion detects outbound UDP socket send buffer exhaustion.
type RuleUDPSndbufExhaustion struct{ noSuppression }

func (r *RuleUDPSndbufExhaustion) ID() string { return "CONT_UDP_SNDBUF_EXHAUSTION" }
func (r *RuleUDPSndbufExhaustion) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleUDPSndbufExhaustion) Tier() int            { return 2 }
func (r *RuleUDPSndbufExhaustion) IsPIDDependent() bool { return false }

func (r *RuleUDPSndbufExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	sndErr := diff.NetStat.UDPSndbufErrorsDelta
	if sndErr < 25 {
		return nil, false
	}

	outSegs := diff.NetStat.OutSegsDelta
	rcvErr := diff.NetStat.UDPRcvbufErrorsDelta
	if outSegs < 200 && rcvErr == 0 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("UDP Send Buffer Errors Delta: %d packets dropped", sndErr),
		fmt.Sprintf("Outbound Segments Delta: %d", outSegs),
		fmt.Sprintf("UDP Receive Buffer Errors Delta: %d", rcvErr),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.88,
		Title:       "UDP Socket Transmit Buffer Exhaustion",
		Explanation: fmt.Sprintf("Outbound UDP transmit buffers overflowed (%d dropped datagrams), causing syslog, StatsD, DNS, or streaming packet loss.", sndErr),
		Evidence:    evidence,
		Remediation: "Increase socket write memory limits: sysctl -w net.core.wmem_max=16777216 && sysctl -w net.core.wmem_default=262144.",
	}, true
}

// RuleCgroupV1CPUSharesStarvation detects containers starved due to low CPU shares.
type RuleCgroupV1CPUSharesStarvation struct{ noSuppression }

func (r *RuleCgroupV1CPUSharesStarvation) ID() string { return "CONT_CGROUP_V1_CPU_SHARES_STARVATION" }
func (r *RuleCgroupV1CPUSharesStarvation) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleCgroupV1CPUSharesStarvation) Tier() int            { return 2 }
func (r *RuleCgroupV1CPUSharesStarvation) IsPIDDependent() bool { return true }

func (r *RuleCgroupV1CPUSharesStarvation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	busyCPU := diff.TotalCPUUtil.BusyPercent
	if busyCPU < 70.0 {
		return nil, false
	}

	var starvedCgroup string
	var shares uint64
	for _, g := range diff.LatestSnapshot.Cgroups.Groups {
		if g.CPUShares > 0 && g.CPUShares <= 64 && g.Path != "/" {
			starvedCgroup = g.Path
			shares = g.CPUShares
			break
		}
	}

	if starvedCgroup == "" {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.CgroupPath == starvedCgroup {
			culprit = p
			break
		}
	}

	evidence := []string{
		fmt.Sprintf("Host CPU Busy: %.1f%%", busyCPU),
		fmt.Sprintf("Cgroup '%s' cpu.shares: %d (standard baseline: 1024)", starvedCgroup, shares),
	}
	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.86,
		Title:       "Cgroup Container CPU Shares Starvation",
		Explanation: fmt.Sprintf("Cgroup '%s' has cpu.shares configured disproportionately low (%d vs 1024), causing starvation under %.1f%% host CPU contention.", starvedCgroup, shares, busyCPU),
		Evidence:    evidence,
		Remediation: fmt.Sprintf("Increase container CPU relative shares: docker update --cpu-shares=1024 <container> or echo 1024 > /sys/fs/cgroup/cpu%s/cpu.shares.", starvedCgroup),
	}
	if culprit != nil {
		diag.CulpritPID = culprit.PID
		diag.CulpritName = culprit.Comm
		diag.CulpritDetails = fmt.Sprintf("Process in starved cgroup '%s'", starvedCgroup)
	}
	return diag, true
}

// RuleHugepageLeakNoReuse detects reserved explicit HugePages abandoned without active mappings.
type RuleHugepageLeakNoReuse struct{ noSuppression }

func (r *RuleHugepageLeakNoReuse) ID() string { return "CONT_HUGEPAGE_LEAK_NO_REUSE" }
func (r *RuleHugepageLeakNoReuse) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleHugepageLeakNoReuse) Tier() int            { return 2 }
func (r *RuleHugepageLeakNoReuse) IsPIDDependent() bool { return false }

func (r *RuleHugepageLeakNoReuse) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	mem := diff.LatestSnapshot.Memory
	if mem.HugePagesTotal == 0 || mem.HugePagesRsvd == 0 || mem.MemTotal == 0 {
		return nil, false
	}

	hugepageBytes := mem.HugePagesTotal * 2048 * 1024
	ramRatio := float64(hugepageBytes) / float64(mem.MemTotal*1024)
	if ramRatio < 0.25 {
		return nil, false
	}

	availRatio := float64(mem.MemAvailable) / float64(mem.MemTotal)
	if availRatio >= 0.20 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("HugePages Total: %d, Reserved: %d (%.1f%% of RAM locked)", mem.HugePagesTotal, mem.HugePagesRsvd, ramRatio*100),
		fmt.Sprintf("Available Host Memory: %d kB (%.1f%% of RAM)", mem.MemAvailable, availRatio*100),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.89,
		Title:       "Reserved Explicit HugePages Memory Lock Leak",
		Explanation: fmt.Sprintf("Explicit HugePages lock %.1f%% of physical RAM (%d pages reserved) while host available RAM is low (%.1f%%), indicating abandoned shared memory segments.", ramRatio*100, mem.HugePagesRsvd, availRatio*100),
		Evidence:    evidence,
		Remediation: "Inspect IPC segments: ipcs -m, remove unattached segments: ipcrm -m <shmid>, or release HugePages: sysctl -w vm.nr_hugepages=0.",
	}, true
}

// RuleNetTCPAbortOnClose detects TCP connections reset due to unread receive buffer data on close.
type RuleNetTCPAbortOnClose struct{ noSuppression }

func (r *RuleNetTCPAbortOnClose) ID() string { return "CONT_NET_TCP_ABORT_ON_CLOSE" }
func (r *RuleNetTCPAbortOnClose) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetTCPAbortOnClose) Tier() int            { return 2 }
func (r *RuleNetTCPAbortOnClose) IsPIDDependent() bool { return false }

func (r *RuleNetTCPAbortOnClose) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	aborts := diff.NetStat.TCPAbortOnCloseDelta
	if aborts < 20 {
		return nil, false
	}

	outSegs := diff.NetStat.OutSegsDelta
	if outSegs < 200 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCP Abort On Close Delta: %d RST resets", aborts),
		fmt.Sprintf("Total Outbound Segments Delta: %d", outSegs),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.87,
		Title:       "TCP Socket Reset on Close with Unread Buffer Data",
		Explanation: fmt.Sprintf("Kernel sent %d TCP RST resets (TCPAbortOnClose) because application closed sockets with unread data in receive queue, terminating client connections.", aborts),
		Evidence:    evidence,
		Remediation: "Drain socket receive buffers before closing or adjust application request framing and HTTP keep-alive timeouts.",
	}, true
}

// RuleSchedYieldSpinChurn detects application threads burning CPU executing sched_yield in tight spinloops.
type RuleSchedYieldSpinChurn struct{ noSuppression }

func (r *RuleSchedYieldSpinChurn) ID() string { return "CONT_SCHED_YIELD_SPIN_CHURN" }
func (r *RuleSchedYieldSpinChurn) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleSchedYieldSpinChurn) Tier() int            { return 2 }
func (r *RuleSchedYieldSpinChurn) IsPIDDependent() bool { return true }

func (r *RuleSchedYieldSpinChurn) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.VoluntaryCtxtSwitchesDelta >= 15000 && p.CPUPercent >= 35.0 {
			culprit = p
			break
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] Voluntary Context Switches Delta: %d / sec", culprit.PID, culprit.Comm, culprit.VoluntaryCtxtSwitchesDelta),
		fmt.Sprintf("Process CPU Utilization: %.1f%%", culprit.CPUPercent),
		fmt.Sprintf("State: %c, Threads: %d, Wchan: '%s'", culprit.State, culprit.NumThreads, culprit.Wchan),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.92,
		Title:          "Scheduler Yield Tight Spinloop Churn",
		Explanation:    fmt.Sprintf("Process %s (PID %d) is consuming %.1f%% CPU while generating %d voluntary context switches/sec in sched_yield() tight spinloop.", culprit.Comm, culprit.PID, culprit.CPUPercent, culprit.VoluntaryCtxtSwitchesDelta),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("%d vol ctx switches/s, %.1f%% CPU", culprit.VoluntaryCtxtSwitchesDelta, culprit.CPUPercent),
		Remediation:    "Replace busy-spin sched_yield() loops with proper futex/eventfd mutex parking or reduce spin wait iterations.",
	}, true
}

// RuleNetTCPCollapsePrune detects TCP receive buffer collapses and packet pruning.
type RuleNetTCPCollapsePrune struct{ noSuppression }

func (r *RuleNetTCPCollapsePrune) ID() string { return "CONT_NET_TCP_COLLAPSE_PRUNE" }
func (r *RuleNetTCPCollapsePrune) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetTCPCollapsePrune) Tier() int            { return 2 }
func (r *RuleNetTCPCollapsePrune) IsPIDDependent() bool { return false }

func (r *RuleNetTCPCollapsePrune) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	collapsed := diff.NetStat.TCPRcvCollapsedDelta
	if collapsed < 20 {
		return nil, false
	}

	retrans := diff.NetStat.RetransSegsDelta
	abortMem := diff.NetStat.TCPAbortOnMemoryDelta
	zeroDrop := diff.NetStat.TCPZeroWindowDropDelta
	if retrans < 50 && abortMem == 0 && zeroDrop == 0 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCP Receive Buffer Collapses Delta: %d events", collapsed),
		fmt.Sprintf("TCP Retransmissions Delta: %d, Memory Aborts: %d", retrans, abortMem),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.89,
		Title:       "TCP Receive Buffer Pruning and Memory Collapse",
		Explanation: fmt.Sprintf("Kernel collapsed TCP receive queues %d times to reclaim socket memory, causing out-of-order drops and throughput collapse.", collapsed),
		Evidence:    evidence,
		Remediation: "Increase TCP receive memory buffers: sysctl -w net.ipv4.tcp_rmem=\"4096 87380 16777216\" && sysctl -w net.ipv4.tcp_adv_win_scale=2.",
	}, true
}

// RuleNetTCPMemoryAllocFail detects kernel TCP socket page allocation failures.
type RuleNetTCPMemoryAllocFail struct{ noSuppression }

func (r *RuleNetTCPMemoryAllocFail) ID() string { return "CONT_NET_TCP_MEMORY_ALLOC_FAIL" }
func (r *RuleNetTCPMemoryAllocFail) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetTCPMemoryAllocFail) Tier() int            { return 2 }
func (r *RuleNetTCPMemoryAllocFail) IsPIDDependent() bool { return false }

func (r *RuleNetTCPMemoryAllocFail) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	abortMem := diff.NetStat.TCPAbortOnMemoryDelta
	if abortMem < 5 {
		return nil, false
	}

	memPress := diff.NetStat.TCPMemoryPressuresDelta
	zeroDrop := diff.NetStat.TCPZeroWindowDropDelta
	reqFull := diff.NetStat.TCPReqQFullDoCookiesDelta
	if memPress == 0 && zeroDrop == 0 && reqFull == 0 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCP Aborts on Memory Limit Delta: %d connections", abortMem),
		fmt.Sprintf("TCP Memory Pressure Events Delta: %d", memPress),
		fmt.Sprintf("TCP Zero Window Drops Delta: %d", zeroDrop),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.91,
		Title:       "TCP Socket Page Allocation Memory Failure",
		Explanation: fmt.Sprintf("Kernel aborted %d TCP connections due to global tcp_mem socket page exhaustion.", abortMem),
		Evidence:    evidence,
		Remediation: "Increase system-wide TCP socket memory pages: sysctl -w net.ipv4.tcp_mem=\"786432 1048576 1572864\".",
	}, true
}

// RuleNetTCPZeroWindowDrop detects TCP zero window advertising and stalled socket transmission.
type RuleNetTCPZeroWindowDrop struct{ noSuppression }

func (r *RuleNetTCPZeroWindowDrop) ID() string { return "CONT_NET_TCP_ZERO_WINDOW_DROP" }
func (r *RuleNetTCPZeroWindowDrop) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetTCPZeroWindowDrop) Tier() int            { return 2 }
func (r *RuleNetTCPZeroWindowDrop) IsPIDDependent() bool { return false }

func (r *RuleNetTCPZeroWindowDrop) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	zeroDrop := diff.NetStat.TCPZeroWindowDropDelta
	winProbe := diff.NetStat.TCPWinProbeDelta
	outSegs := diff.NetStat.OutSegsDelta

	if zeroDrop < 10 && !(winProbe >= 10 && outSegs >= 200) {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCP Zero Window Drops Delta: %d packets dropped", zeroDrop),
		fmt.Sprintf("TCP Window Probe Delta: %d probes sent", winProbe),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.89,
		Title:       "TCP Receiver Zero-Window Stall & Drop",
		Explanation: fmt.Sprintf("TCP receiver advertised zero receive window %d times, freezing transmission and dropping incoming payloads.", zeroDrop),
		Evidence:    evidence,
		Remediation: "Ensure receiving application drains socket buffers quickly or enable TCP window scaling: sysctl -w net.ipv4.tcp_window_scaling=1.",
	}, true
}

// RuleFutexPIDeadlockStall detects processes blocked on Priority-Inheritance futexes or mutex deadlocks.
type RuleFutexPIDeadlockStall struct{ noSuppression }

func (r *RuleFutexPIDeadlockStall) ID() string { return "CONT_FUTEX_PI_DEADLOCK_STALL" }
func (r *RuleFutexPIDeadlockStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleFutexPIDeadlockStall) Tier() int            { return 2 }
func (r *RuleFutexPIDeadlockStall) IsPIDDependent() bool { return true }

func (r *RuleFutexPIDeadlockStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "futex_lock_pi" || p.Wchan == "rt_mutex_slowlock" || p.Wchan == "futex_wait_requeue_pi") && p.CPUPercent < 1.0 {
			if p.State == 'D' || p.NumThreads >= 4 {
				culprit = p
				break
			}
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] blocked in wchan: '%s'", culprit.PID, culprit.Comm, culprit.Wchan),
		fmt.Sprintf("State: %c, Threads: %d, CPU Utilization: %.2f%%", culprit.State, culprit.NumThreads, culprit.CPUPercent),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.90,
		Title:          "Priority-Inheritance Futex Mutex Lock Stall",
		Explanation:    fmt.Sprintf("Process %s (PID %d) is blocked in PI-futex kernel lock (%s), indicating lock owner thread death or priority inversion.", culprit.Comm, culprit.PID, culprit.Wchan),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Blocked in %s", culprit.Wchan),
		Remediation:    "Inspect process mutex stacks with gdb/pprof or restart the stalled worker service.",
	}, true
}

// RuleNetARPTableTrash detects ARP and IPv6 neighbor table capacity saturation and GC thrashing.
type RuleNetARPTableTrash struct{ noSuppression }

func (r *RuleNetARPTableTrash) ID() string { return "CONT_NET_ARP_TABLE_TRASH" }
func (r *RuleNetARPTableTrash) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetARPTableTrash) Tier() int            { return 2 }
func (r *RuleNetARPTableTrash) IsPIDDependent() bool { return false }

func (r *RuleNetARPTableTrash) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	arp := diff.LatestSnapshot.SystemConfig.Neighbor
	if !arp.Available || arp.GCThresh3 == 0 {
		return nil, false
	}

	if arp.Ratio < 0.85 && arp.ActiveEntries < arp.GCThresh3*85/100 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Active ARP Entries: %d / %d (%.1f%% of gc_thresh3)", arp.ActiveEntries, arp.GCThresh3, arp.Ratio*100),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       "ARP / Neighbor Table Capacity Saturation",
		Explanation: fmt.Sprintf("ARP/neighbor table is near capacity (%d/%d entries, %.1f%%), risking neighbor discovery failures and dropped outbound packets.", arp.ActiveEntries, arp.GCThresh3, arp.Ratio*100),
		Evidence:    evidence,
		Remediation: "Increase neighbor table limits: sysctl -w net.ipv4.neigh.default.gc_thresh3=8192 && sysctl -w net.ipv4.neigh.default.gc_thresh2=4096.",
	}, true
}

// RuleDirtyPagesDirectSyncStall detects direct writeback synchronous flushing stalls when dirty threshold is exceeded.
type RuleDirtyPagesDirectSyncStall struct{ noSuppression }

func (r *RuleDirtyPagesDirectSyncStall) ID() string { return "CONT_DIRTY_PAGES_DIRECT_SYNC_STALL" }
func (r *RuleDirtyPagesDirectSyncStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleDirtyPagesDirectSyncStall) Tier() int            { return 2 }
func (r *RuleDirtyPagesDirectSyncStall) IsPIDDependent() bool { return true }

func (r *RuleDirtyPagesDirectSyncStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "sync_inodes" || p.Wchan == "wait_on_page_writeback" || p.Wchan == "write_cache_pages") && (p.State == 'D' || p.CPUPercent < 5.0) {
			culprit = p
			break
		}
	}

	if culprit == nil && diff.VMStat.NRDirtyDelta < 2000 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("VMStat nr_dirty Delta: %d pages", diff.VMStat.NRDirtyDelta),
	}
	if culprit != nil {
		evidence = append(evidence, fmt.Sprintf("Process PID %d [%s] blocked in wchan '%s'", culprit.PID, culprit.Comm, culprit.Wchan))
	}

	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.91,
		Title:       "Dirty Page Cache Direct Sync Flusher Stall",
		Explanation: "Unwritten dirty page cache accumulation forced processes into synchronous blocking page writeback.",
		Evidence:    evidence,
		Remediation: "Tune dirty writeback sysctls: sysctl -w vm.dirty_background_ratio=5 && sysctl -w vm.dirty_ratio=15.",
	}
	if culprit != nil {
		diag.CulpritPID = culprit.PID
		diag.CulpritName = culprit.Comm
		diag.CulpritDetails = fmt.Sprintf("Blocked in writeback sync '%s'", culprit.Wchan)
	}
	return diag, true
}

// RuleNFSRPCClientSaturation detects NFS client RPC slot table saturation and stalled remote procedure calls.
type RuleNFSRPCClientSaturation struct{ noSuppression }

func (r *RuleNFSRPCClientSaturation) ID() string { return "CONT_NFS_RPC_SLOT_TABLE_SATURATION" }
func (r *RuleNFSRPCClientSaturation) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNFSRPCClientSaturation) Tier() int            { return 2 }
func (r *RuleNFSRPCClientSaturation) IsPIDDependent() bool { return true }

func (r *RuleNFSRPCClientSaturation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "nfs_wait_client" || p.Wchan == "rpc_wait_bit_killable" || p.Wchan == "xprt_reserve_xprt") && p.State == 'D' {
			culprit = p
			break
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] blocked in RPC wchan: '%s'", culprit.PID, culprit.Comm, culprit.Wchan),
		fmt.Sprintf("Process State: %c, Threads: %d", culprit.State, culprit.NumThreads),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.93,
		Title:          "NFS Client RPC Slot Table Saturation",
		Explanation:    fmt.Sprintf("Process %s (PID %d) is blocked in NFS RPC transport queue (%s), indicating NFS slot table exhaustion or hung remote NFS server.", culprit.Comm, culprit.PID, culprit.Wchan),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Blocked in NFS RPC queue '%s'", culprit.Wchan),
		Remediation:    "Increase sunrpc tcp slot table: sysctl -w sunrpc.tcp_slot_table_entries=128 or check NFS mount health.",
	}, true
}

// RuleUnixSocketBacklogOverflow detects UNIX domain socket send queue congestion and blocked peers.
type RuleUnixSocketBacklogOverflow struct{ noSuppression }

func (r *RuleUnixSocketBacklogOverflow) ID() string { return "CONT_UNIX_SOCKET_BACKLOG_OVERFLOW" }
func (r *RuleUnixSocketBacklogOverflow) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleUnixSocketBacklogOverflow) Tier() int            { return 2 }
func (r *RuleUnixSocketBacklogOverflow) IsPIDDependent() bool { return true }

func (r *RuleUnixSocketBacklogOverflow) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "unix_stream_sendmsg" || p.Wchan == "unix_wait_for_peer" || p.Wchan == "unix_dgram_sendmsg") && (p.State == 'D' || p.CPUPercent < 1.0) {
			culprit = p
			break
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] blocked in socket wchan: '%s'", culprit.PID, culprit.Comm, culprit.Wchan),
		fmt.Sprintf("State: %c, Threads: %d, CPU: %.2f%%", culprit.State, culprit.NumThreads, culprit.CPUPercent),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.90,
		Title:          "UNIX Domain Socket Queue Backlog Overflow",
		Explanation:    fmt.Sprintf("Process %s (PID %d) is blocked writing to full UNIX domain socket queue (%s) because reader daemon is not consuming data.", culprit.Comm, culprit.PID, culprit.Wchan),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Blocked on full UNIX socket in %s", culprit.Wchan),
		Remediation:    "Ensure receiving socket service (systemd-journald, syslog, database IPC) is responsive and drains socket queues.",
	}, true
}

// RuleVFSInodeLockContention detects serialization bottlenecks on VFS directory/file write mutexes.
type RuleVFSInodeLockContention struct{ noSuppression }

func (r *RuleVFSInodeLockContention) ID() string { return "CONT_VFS_INODE_LOCK_CONTENTION" }
func (r *RuleVFSInodeLockContention) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleVFSInodeLockContention) Tier() int            { return 2 }
func (r *RuleVFSInodeLockContention) IsPIDDependent() bool { return true }

func (r *RuleVFSInodeLockContention) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	count := 0
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "inode_lock_shared" || p.Wchan == "inode_lock" || p.Wchan == "ext4_file_write_iter" || p.Wchan == "xfs_file_write_iter") && p.State == 'D' {
			if culprit == nil {
				culprit = p
			}
			count++
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("%d process(es) blocked on VFS inode lock", count),
		fmt.Sprintf("Primary process PID %d [%s] blocked in wchan: '%s'", culprit.PID, culprit.Comm, culprit.Wchan),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.91,
		Title:          "VFS Inode Mutex Serialization Contention",
		Explanation:    fmt.Sprintf("Process %s (PID %d) and related writers are serializing on file/directory inode mutex locks (%s), causing multi-threaded I/O write starvation.", culprit.Comm, culprit.PID, culprit.Wchan),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Serialized on VFS inode lock '%s'", culprit.Wchan),
		Remediation:    "Shard file writes across distinct files/directories or use O_DIRECT / asynchronous append logging.",
	}, true
}

// RuleKernelLockdBlocked detects processes stalled on POSIX advisory file locks (fcntl/flock).
type RuleKernelLockdBlocked struct{ noSuppression }

func (r *RuleKernelLockdBlocked) ID() string { return "CONT_KERNEL_LOCKD_BLOCKED" }
func (r *RuleKernelLockdBlocked) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleKernelLockdBlocked) Tier() int            { return 2 }
func (r *RuleKernelLockdBlocked) IsPIDDependent() bool { return true }

func (r *RuleKernelLockdBlocked) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "fcntl_setlk" || p.Wchan == "locks_lock_inode_wait" || p.Wchan == "flock_lock_inode") && (p.State == 'D' || p.State == 'S') && p.CPUPercent < 1.0 {
			culprit = p
			break
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] blocked in file lock wchan: '%s'", culprit.PID, culprit.Comm, culprit.Wchan),
		fmt.Sprintf("State: %c, Threads: %d, CPU Utilization: %.2f%%", culprit.State, culprit.NumThreads, culprit.CPUPercent),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.89,
		Title:          "POSIX Advisory File Lock Contention (fcntl/flock)",
		Explanation:    fmt.Sprintf("Process %s (PID %d) is blocked waiting for POSIX file lock acquisition (%s) held by another process.", culprit.Comm, culprit.PID, culprit.Wchan),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Blocked on POSIX file lock in %s", culprit.Wchan),
		Remediation:    "Inspect file locks via /proc/locks or lslocks to identify holding process and avoid long-running locks.",
	}, true
}

// RuleSchedAutogroupStarvation detects scheduler autogroup CPU fairness starvation on multi-threaded session processes.
type RuleSchedAutogroupStarvation struct{ noSuppression }

func (r *RuleSchedAutogroupStarvation) ID() string { return "CONT_SCHED_AUTOGROUP_STARVATION" }
func (r *RuleSchedAutogroupStarvation) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleSchedAutogroupStarvation) Tier() int            { return 2 }
func (r *RuleSchedAutogroupStarvation) IsPIDDependent() bool { return true }

func (r *RuleSchedAutogroupStarvation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	if diff.TotalCPUUtil.IdlePercent > 40.0 || diff.ProcsRunning < 4 {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.NumThreads >= 16 && p.CPUPercent < 15.0 && p.State == 'R' {
			culprit = p
			break
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] Threads: %d, CPU: %.1f%% in State 'R'", culprit.PID, culprit.Comm, culprit.NumThreads, culprit.CPUPercent),
		fmt.Sprintf("Global Runnable Procs: %d, System Idle: %.1f%%", diff.ProcsRunning, diff.TotalCPUUtil.IdlePercent),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.88,
		Title:          "CFS Session Autogroup CPU Bandwidth Starvation",
		Explanation:    fmt.Sprintf("Multi-threaded process %s (PID %d with %d threads) is starved in a single session autogroup while runnable queue is saturated.", culprit.Comm, culprit.PID, culprit.NumThreads),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Starved in session autogroup with %d threads", culprit.NumThreads),
		Remediation:    "Disable session autogrouping: sysctl -w kernel.sched_autogroup_enabled=0 or move server tasks to a dedicated systemd service unit.",
	}, true
}

// RuleFtraceRingBufferStall detects kernel ftrace/tracepoint ring buffer saturation and tracing lock stalls.
type RuleFtraceRingBufferStall struct{ noSuppression }

func (r *RuleFtraceRingBufferStall) ID() string { return "CONT_FTRACE_RING_BUFFER_STALL" }
func (r *RuleFtraceRingBufferStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleFtraceRingBufferStall) Tier() int            { return 2 }
func (r *RuleFtraceRingBufferStall) IsPIDDependent() bool { return true }

func (r *RuleFtraceRingBufferStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "ring_buffer_wait" || p.Wchan == "tracing_wait_pipe" || p.Wchan == "trace_event_raw_event") && (p.State == 'D' || p.CPUPercent < 1.0) {
			culprit = p
			break
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] blocked in tracing wchan: '%s'", culprit.PID, culprit.Comm, culprit.Wchan),
		fmt.Sprintf("System CPU Utilization: %.1f%%", diff.TotalCPUUtil.SystemPercent),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.90,
		Title:          "Kernel Ftrace / Tracepoint Ring Buffer Saturation",
		Explanation:    fmt.Sprintf("Process %s (PID %d) is stalled on kernel trace event ring buffers (%s), causing tracing event drops and high lock contention.", culprit.Comm, culprit.PID, culprit.Wchan),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Blocked on tracing ring buffer in %s", culprit.Wchan),
		Remediation:    "Disable active tracing: echo 0 > /sys/kernel/debug/tracing/tracing_on or enlarge buffer: echo 16384 > /sys/kernel/debug/tracing/buffer_size_kb.",
	}, true
}

// RuleNetDevGROCellDrop detects Generic Receive Offload cell drops and softnet processing overruns.
type RuleNetDevGROCellDrop struct{ noSuppression }

func (r *RuleNetDevGROCellDrop) ID() string { return "CONT_NET_DEV_GRO_CELL_DROP" }
func (r *RuleNetDevGROCellDrop) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetDevGROCellDrop) Tier() int            { return 2 }
func (r *RuleNetDevGROCellDrop) IsPIDDependent() bool { return false }

func (r *RuleNetDevGROCellDrop) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	softnetDrop := diff.NetStat.SoftnetDroppedDelta
	squeeze := diff.NetStat.SoftnetTimeSqueezeDelta

	if softnetDrop < 20 || squeeze < 20 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Softnet Dropped Packets Delta: %d packets", softnetDrop),
		fmt.Sprintf("Softnet Time Squeeze (Budget Exhaustion) Delta: %d events", squeeze),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       "Network GRO / Softnet Receive Processing Queue Drops",
		Explanation: fmt.Sprintf("Kernel network softnet layer dropped %d packets and exhausted processing time budget %d times, indicating NAPI poll budget starvation.", softnetDrop, squeeze),
		Evidence:    evidence,
		Remediation: "Increase NAPI polling budget: sysctl -w net.core.netdev_budget=600 && sysctl -w net.core.netdev_budget_usecs=4000.",
	}, true
}

// RuleMemCompactMigrationFailRate detects high rates of page migration failures during memory compaction.
type RuleMemCompactMigrationFailRate struct{ noSuppression }

func (r *RuleMemCompactMigrationFailRate) ID() string { return "CONT_MEM_COMPACT_MIGRATION_FAIL_RATE" }
func (r *RuleMemCompactMigrationFailRate) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleMemCompactMigrationFailRate) Tier() int            { return 2 }
func (r *RuleMemCompactMigrationFailRate) IsPIDDependent() bool { return false }

func (r *RuleMemCompactMigrationFailRate) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	stalls := diff.VMStat.CompactStallDelta
	fails := diff.VMStat.CompactFailDelta

	if stalls < 50 || fails < 25 || fails*2 < stalls {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Direct Memory Compaction Stalls Delta: %d stalls", stalls),
		fmt.Sprintf("Compaction Page Migration Failures Delta: %d failures (%.1f%% fail rate)", fails, float64(fails)/float64(stalls)*100),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.91,
		Title:       "Memory Compaction Page Migration Failure Storm",
		Explanation: fmt.Sprintf("Kernel compaction attempted %d direct 2MB page reorganizations with %d failures (%.1f%% failure rate), burning CPU without resolving fragmentation.", stalls, fails, float64(fails)/float64(stalls)*100),
		Evidence:    evidence,
		Remediation: "Trigger proactive memory compaction: echo 1 > /proc/sys/vm/compact_memory or disable unevictable compaction: sysctl -w vm.compact_unevictable_allowed=0.",
	}, true
}

// RuleNetTCPFastOpenFail detects TCP Fast Open (TFO) connection failures due to middlebox cookie drops.
type RuleNetTCPFastOpenFail struct{ noSuppression }

func (r *RuleNetTCPFastOpenFail) ID() string { return "CONT_NET_TCP_FASTOPEN_FAIL" }
func (r *RuleNetTCPFastOpenFail) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetTCPFastOpenFail) Tier() int            { return 2 }
func (r *RuleNetTCPFastOpenFail) IsPIDDependent() bool { return false }

func (r *RuleNetTCPFastOpenFail) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	activeFails := diff.NetStat.TCPFastOpenActiveFailDelta
	passiveFails := diff.NetStat.TCPFastOpenPassiveFailDelta
	totalFails := activeFails + passiveFails

	if totalFails < 5 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCP Fast Open Failures Delta: %d total (%d active, %d passive)", totalFails, activeFails, passiveFails),
		"SYN+Data packets or TFO cookies rejected/dropped by network path or middlebox",
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.90,
		Title:       "TCP Fast Open (TFO) Connection Handshake Drops",
		Explanation: fmt.Sprintf("Detected %d TCP Fast Open failures (%d active / %d passive drops), forcing connections to fall back to standard 3-way handshakes with latency penalties.", totalFails, activeFails, passiveFails),
		Evidence:    evidence,
		Remediation: "Enable client-only TFO: sysctl -w net.ipv4.tcp_fastopen=1 or disable TFO if traversing incompatible firewalls: sysctl -w net.ipv4.tcp_fastopen=0.",
	}, true
}

// RuleNetTCPSynAckRetransStall detects repeated SYN+ACK segment retransmissions during connection establishment.
type RuleNetTCPSynAckRetransStall struct{ noSuppression }

func (r *RuleNetTCPSynAckRetransStall) ID() string { return "CONT_NET_TCP_SYN_ACK_RETRANS_STALL" }
func (r *RuleNetTCPSynAckRetransStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetTCPSynAckRetransStall) Tier() int            { return 2 }
func (r *RuleNetTCPSynAckRetransStall) IsPIDDependent() bool { return false }

func (r *RuleNetTCPSynAckRetransStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	synRetrans := diff.NetStat.TCPSynRetransDelta
	if synRetrans < 20 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCP SYN/SYN-ACK Retransmissions Delta: %d segments", synRetrans),
		"Client connections experiencing initial handshake timeout stalls",
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       "TCP Handshake SYN/SYN-ACK Retransmission Contention",
		Explanation: fmt.Sprintf("Kernel recorded %d TCP SYN / SYN-ACK retransmissions during the sampling window, indicating dropped connection handshakes or asymmetric routing loss.", synRetrans),
		Evidence:    evidence,
		Remediation: "Tune SYN retry timeouts: sysctl -w net.ipv4.tcp_synack_retries=3 and check for firewall SYN rate limiting.",
	}, true
}

// RuleNetSocketRecvStall detects processes blocked in socket receive sleep while experiencing network stalls.
type RuleNetSocketRecvStall struct{ noSuppression }

func (r *RuleNetSocketRecvStall) ID() string { return "CONT_NET_SOCKET_RECV_STALL" }
func (r *RuleNetSocketRecvStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetSocketRecvStall) Tier() int            { return 2 }
func (r *RuleNetSocketRecvStall) IsPIDDependent() bool { return true }

func (r *RuleNetSocketRecvStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "sk_wait_data" || p.Wchan == "tcp_recvmsg" || p.Wchan == "inet_csk_accept") && p.State == 'D' {
			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           2,
				Severity:       SeverityHigh,
				Confidence:     0.90,
				Title:          fmt.Sprintf("Process Blocked in Socket Receive Wait (%s)", p.Comm),
				Explanation:    fmt.Sprintf("Process '%s' (PID %d) is stalled in uninterruptible kernel wait '%s' waiting for ingress network buffer data.", p.Comm, p.PID, p.Wchan),
				Evidence:       []string{fmt.Sprintf("Process: %s (PID %d)", p.Comm, p.PID), fmt.Sprintf("Kernel Wchan: %s (State: %c)", p.Wchan, p.State)},
				Remediation:    "Increase socket receive buffer limits: sysctl -w net.core.rmem_max=16777216 and check peer transmission latency.",
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("Stalled in %s", p.Wchan),
			}, true
		}
	}

	return nil, false
}

// RuleStorageBlkThrottleStall detects processes blocked on cgroup block I/O throttle queues.
type RuleStorageBlkThrottleStall struct{ noSuppression }

func (r *RuleStorageBlkThrottleStall) ID() string { return "CONT_STORAGE_BLK_THROTTLE_STALL" }
func (r *RuleStorageBlkThrottleStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleStorageBlkThrottleStall) Tier() int            { return 2 }
func (r *RuleStorageBlkThrottleStall) IsPIDDependent() bool { return true }

func (r *RuleStorageBlkThrottleStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (strings.Contains(p.Wchan, "throtl") || p.Wchan == "blk_throtl_dispatch_work_fn" || p.Wchan == "throtl_pending_timer_fn") && p.State == 'D' {
			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           2,
				Severity:       SeverityHigh,
				Confidence:     0.94,
				Title:          fmt.Sprintf("Process Blocked on Cgroup Block I/O Throttle (%s)", p.Comm),
				Explanation:    fmt.Sprintf("Process '%s' (PID %d) is throttled by kernel block layer cgroup I/O limits in '%s'.", p.Comm, p.PID, p.Wchan),
				Evidence:       []string{fmt.Sprintf("Process: %s (PID %d)", p.Comm, p.PID), fmt.Sprintf("Kernel Wchan: %s", p.Wchan)},
				Remediation:    "Increase cgroup I/O limits (io.max / io.weight) or mount with asynchronous write buffering.",
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("Throttled in %s", p.Wchan),
			}, true
		}
	}

	return nil, false
}

// RuleNetTCPDeferAcceptTimeout detects listener connection drops caused by TCP_DEFER_ACCEPT timeouts.
type RuleNetTCPDeferAcceptTimeout struct{ noSuppression }

func (r *RuleNetTCPDeferAcceptTimeout) ID() string { return "CONT_NET_TCP_DEFER_ACCEPT_TIMEOUT" }
func (r *RuleNetTCPDeferAcceptTimeout) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetTCPDeferAcceptTimeout) Tier() int            { return 2 }
func (r *RuleNetTCPDeferAcceptTimeout) IsPIDDependent() bool { return false }

func (r *RuleNetTCPDeferAcceptTimeout) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	drops := diff.NetStat.TCPDeferAcceptDropDelta
	if drops < 10 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCP Defer Accept Drops Delta: %d aborted connections", drops),
		"Clients completed TCP 3-way handshake but timed out before sending HTTP/application payload",
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.88,
		Title:       "TCP Defer Accept Listener Timeout Aborts",
		Explanation: fmt.Sprintf("Kernel dropped %d connections configured with TCP_DEFER_ACCEPT because clients stalled before sending request payloads.", drops),
		Evidence:    evidence,
		Remediation: "Tune application defer accept timeout or inspect client connection keep-alive behavior.",
	}, true
}

// RuleMemcgReclaimDirectStall detects processes stalled in synchronous cgroup memory direct reclaim.
type RuleMemcgReclaimDirectStall struct{ noSuppression }

func (r *RuleMemcgReclaimDirectStall) ID() string { return "CONT_MEMCG_RECLAIM_DIRECT_STALL" }
func (r *RuleMemcgReclaimDirectStall) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleMemcgReclaimDirectStall) Tier() int            { return 2 }
func (r *RuleMemcgReclaimDirectStall) IsPIDDependent() bool { return true }

func (r *RuleMemcgReclaimDirectStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "try_to_free_mem_cgroup_pages" || p.Wchan == "mem_cgroup_reclaim" || p.Wchan == "mem_cgroup_handle_over_high") && p.State == 'D' {
			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           2,
				Severity:       SeverityHigh,
				Confidence:     0.94,
				Title:          fmt.Sprintf("Process Stalled in Cgroup Direct Memory Reclaim (%s)", p.Comm),
				Explanation:    fmt.Sprintf("Process '%s' (PID %d) is stalled in '%s' performing synchronous memory reclaim to satisfy cgroup memory limits.", p.Comm, p.PID, p.Wchan),
				Evidence:       []string{fmt.Sprintf("Process: %s (PID %d)", p.Comm, p.PID), fmt.Sprintf("Kernel Wchan: %s", p.Wchan)},
				Remediation:    "Increase container memory limit: docker update --memory <size> or raise cgroup memory.high threshold.",
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("Direct reclaim in %s", p.Wchan),
			}, true
		}
	}

	return nil, false
}

// RuleXFSAllocBtreeContention detects allocation btree lock contention on high-concurrency XFS filesystems.
type RuleXFSAllocBtreeContention struct{ noSuppression }

func (r *RuleXFSAllocBtreeContention) ID() string { return "CONT_XFS_ALLOC_BTREE_CONTENTION" }
func (r *RuleXFSAllocBtreeContention) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleXFSAllocBtreeContention) Tier() int            { return 2 }
func (r *RuleXFSAllocBtreeContention) IsPIDDependent() bool { return true }

func (r *RuleXFSAllocBtreeContention) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (strings.Contains(p.Wchan, "xfs_alloc") || strings.Contains(p.Wchan, "xfs_btree") || p.Wchan == "xfs_alloc_ag_vextent" || p.Wchan == "xfs_alloc_fixup_trees") && p.State == 'D' {
			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           2,
				Severity:       SeverityHigh,
				Confidence:     0.92,
				Title:          fmt.Sprintf("XFS Allocation Btree Serialization Contention (%s)", p.Comm),
				Explanation:    fmt.Sprintf("Process '%s' (PID %d) is stalled in '%s' waiting for XFS allocation group btree locks.", p.Comm, p.PID, p.Wchan),
				Evidence:       []string{fmt.Sprintf("Process: %s (PID %d)", p.Comm, p.PID), fmt.Sprintf("Kernel Wchan: %s", p.Wchan)},
				Remediation:    "Mount XFS with allocsize=64m or distribute concurrent file creations across separate directories/AGs.",
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("XFS btree lock in %s", p.Wchan),
			}, true
		}
	}

	return nil, false
}

// RuleSchedMigrationCostOverhead detects hyperactive scheduler task migration trashing CPU caches.
type RuleSchedMigrationCostOverhead struct{ noSuppression }

func (r *RuleSchedMigrationCostOverhead) ID() string { return "CONT_SCHED_MIGRATION_COST_OVERHEAD" }
func (r *RuleSchedMigrationCostOverhead) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleSchedMigrationCostOverhead) Tier() int            { return 2 }
func (r *RuleSchedMigrationCostOverhead) IsPIDDependent() bool { return false }

func (r *RuleSchedMigrationCostOverhead) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	costNS := diff.LatestSnapshot.SystemConfig.SchedMigrationCostNS
	if costNS == 0 && diff.ContextSwitchesDelta >= 50000 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.89,
			Title:       "Hyperactive Scheduler Task Migration (Cache Thrashing)",
			Explanation: fmt.Sprintf("Scheduler migration cost is set to 0 ns with %d context switches/sec, causing tasks to bounce across CPU cores and thrash L1/L2 caches.", diff.ContextSwitchesDelta),
			Evidence: []string{
				fmt.Sprintf("Context Switches Delta: %d / sec", diff.ContextSwitchesDelta),
				"Kernel sched_migration_cost_ns: 0 ns (zero migration penalty)",
			},
			Remediation: "Increase scheduler migration cost: sysctl -w kernel.sched_migration_cost_ns=500000.",
		}, true
	}

	return nil, false
}

// RuleNetTCPZeroWindowAdvert detects zero window receive advertisements freezing ingress streams.
type RuleNetTCPZeroWindowAdvert struct{ noSuppression }

func (r *RuleNetTCPZeroWindowAdvert) ID() string { return "CONT_NET_TCP_ZERO_WINDOW_ADVERT" }
func (r *RuleNetTCPZeroWindowAdvert) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleNetTCPZeroWindowAdvert) Tier() int            { return 2 }
func (r *RuleNetTCPZeroWindowAdvert) IsPIDDependent() bool { return false }

func (r *RuleNetTCPZeroWindowAdvert) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	winProbes := diff.NetStat.TCPWinProbeDelta
	winDrops := diff.NetStat.TCPZeroWindowDropDelta

	if winProbes < 20 && winDrops < 10 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCP Zero Window Probes Delta: %d probes", winProbes),
		fmt.Sprintf("TCP Zero Window Packet Drops Delta: %d drops", winDrops),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.91,
		Title:       "TCP Zero-Window Receive Buffer Advertisement Stall",
		Explanation: fmt.Sprintf("Host advertised zero receive window %d times (%d dropped packets), forcing remote peers into zero-window probe loops.", winProbes, winDrops),
		Evidence:    evidence,
		Remediation: "Increase TCP window scaling: sysctl -w net.ipv4.tcp_adv_win_scale=2 and enlarge application read buffers.",
	}, true
}

// RulePSISomeIOPressureSpike detects storage I/O delay spikes from Pressure Stall Information (PSI).
type RulePSISomeIOPressureSpike struct{ noSuppression }

func (r *RulePSISomeIOPressureSpike) ID() string { return "CONT_PSI_SOME_IO_PRESSURE_SPIKE" }
func (r *RulePSISomeIOPressureSpike) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RulePSISomeIOPressureSpike) Tier() int            { return 2 }
func (r *RulePSISomeIOPressureSpike) IsPIDDependent() bool { return false }

func (r *RulePSISomeIOPressureSpike) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	psi := &diff.LatestSnapshot.PSI
	if !psi.Available || psi.IO.Some.Avg10 < 25.0 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.93,
		Title:       "Elevated Linux I/O Pressure Stall Spike (PSI io.some)",
		Explanation: fmt.Sprintf("Linux Pressure Stall Information recorded %.1f%% of tasks stalled waiting on disk I/O over the last 10 seconds.", psi.IO.Some.Avg10),
		Evidence: []string{
			fmt.Sprintf("PSI I/O 'some' avg10: %.1f%% (Threshold: ≥ 25.0%%)", psi.IO.Some.Avg10),
			fmt.Sprintf("PSI I/O 'some' avg60: %.1f%%", psi.IO.Some.Avg60),
		},
		Remediation: "Check disk I/O queue depths, balance disk writeback buffers, or migrate I/O-intensive workloads to NVMe.",
	}, true
}

// RulePSISomeCPUPressureSpike detects CPU runqueue delay spikes from Pressure Stall Information (PSI).
type RulePSISomeCPUPressureSpike struct{ noSuppression }

func (r *RulePSISomeCPUPressureSpike) ID() string { return "CONT_PSI_SOME_CPU_PRESSURE_SPIKE" }
func (r *RulePSISomeCPUPressureSpike) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RulePSISomeCPUPressureSpike) Tier() int            { return 2 }
func (r *RulePSISomeCPUPressureSpike) IsPIDDependent() bool { return false }

func (r *RulePSISomeCPUPressureSpike) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	psi := &diff.LatestSnapshot.PSI
	if !psi.Available || psi.CPU.Some.Avg10 < 30.0 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       "Elevated Linux CPU Pressure Stall Spike (PSI cpu.some)",
		Explanation: fmt.Sprintf("Linux Pressure Stall Information recorded %.1f%% of runnable tasks stalled waiting on CPU runqueues over the last 10 seconds.", psi.CPU.Some.Avg10),
		Evidence: []string{
			fmt.Sprintf("PSI CPU 'some' avg10: %.1f%% (Threshold: ≥ 30.0%%)", psi.CPU.Some.Avg10),
			fmt.Sprintf("PSI CPU 'some' avg60: %.1f%%", psi.CPU.Some.Avg60),
		},
		Remediation: "Renice background batch tasks, pin critical latency workloads, or scale CPU allocation.",
	}, true
}

// RulePSIFullMemoryPressureSpike detects total system lock during paging from Pressure Stall Information (PSI).
type RulePSIFullMemoryPressureSpike struct{ noSuppression }

func (r *RulePSIFullMemoryPressureSpike) ID() string { return "CONT_PSI_FULL_MEMORY_PRESSURE_SPIKE" }
func (r *RulePSIFullMemoryPressureSpike) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RulePSIFullMemoryPressureSpike) Tier() int            { return 2 }
func (r *RulePSIFullMemoryPressureSpike) IsPIDDependent() bool { return false }

func (r *RulePSIFullMemoryPressureSpike) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	psi := &diff.LatestSnapshot.PSI
	if !psi.Available || psi.Memory.Full.Avg10 < 15.0 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.95,
		Title:       "Critical Memory Pressure Stall Spike (PSI memory.full)",
		Explanation: fmt.Sprintf("Linux PSI recorded %.1f%% of all non-idle tasks completely stalled on memory paging over the last 10 seconds.", psi.Memory.Full.Avg10),
		Evidence: []string{
			fmt.Sprintf("PSI Memory 'full' avg10: %.1f%% (Threshold: ≥ 15.0%%)", psi.Memory.Full.Avg10),
			fmt.Sprintf("PSI Memory 'some' avg10: %.1f%%", psi.Memory.Some.Avg10),
		},
		Remediation: "Provision additional physical RAM, tune zram/zswap, or restrict memory limits on hungry containers.",
	}, true
}

// RulePipeReadBurstBlock detects processes blocked in uninterruptible sleep on pipe read operations.
type RulePipeReadBurstBlock struct{ noSuppression }

func (r *RulePipeReadBurstBlock) ID() string { return "CONT_PIPE_READ_BURST_BLOCK" }
func (r *RulePipeReadBurstBlock) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RulePipeReadBurstBlock) Tier() int            { return 2 }
func (r *RulePipeReadBurstBlock) IsPIDDependent() bool { return true }

func (r *RulePipeReadBurstBlock) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "pipe_read" || p.Wchan == "fifo_read") && p.State == 'D' {
			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           2,
				Severity:       SeverityHigh,
				Confidence:     0.90,
				Title:          fmt.Sprintf("Process Blocked on Pipe Read Wait (%s)", p.Comm),
				Explanation:    fmt.Sprintf("Process '%s' (PID %d) is stalled in '%s' waiting for an upstream pipe producer.", p.Comm, p.PID, p.Wchan),
				Evidence:       []string{fmt.Sprintf("Process: %s (PID %d)", p.Comm, p.PID), fmt.Sprintf("Kernel Wchan: %s (State: %c)", p.Wchan, p.State)},
				Remediation:    "Enlarge pipe buffer capacity via fcntl(F_SETPIPE_SZ) or diagnose upstream pipe producer stalls.",
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("Blocked in %s", p.Wchan),
			}, true
		}
	}

	return nil, false
}

// RuleTCPCloseWaitLeak detects accumulated CLOSE_WAIT sockets indicating application FD/socket leaks.
type RuleTCPCloseWaitLeak struct{ noSuppression }

func (r *RuleTCPCloseWaitLeak) ID() string { return "CONT_TCP_CLOSE_WAIT_LEAK" }
func (r *RuleTCPCloseWaitLeak) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleTCPCloseWaitLeak) Tier() int            { return 2 }
func (r *RuleTCPCloseWaitLeak) IsPIDDependent() bool { return true }

func (r *RuleTCPCloseWaitLeak) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil || !diff.LatestSnapshot.TCPSockets.Available {
		return nil, false
	}

	sockets := diff.LatestSnapshot.TCPSockets
	if sockets.CloseWait < 100 {
		return nil, false
	}

	ratio := float64(sockets.CloseWait) / float64(sockets.Established+1)
	if ratio < 0.10 && sockets.CloseWait < 500 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Active CLOSE_WAIT Sockets: %d (Established: %d, Ratio: %.1f%%)",
			sockets.CloseWait, sockets.Established, ratio*100.0),
		"Application received remote TCP FIN but failed to execute close() on socket file descriptors",
	}

	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.90,
		Title:       "Application TCP Socket Leak (CLOSE_WAIT Pileup)",
		Explanation: fmt.Sprintf("Kernel socket table contains %d sockets stuck in CLOSE_WAIT state. The application process received remote FIN packets but failed to invoke close() on the corresponding file descriptors, leaking kernel memory and file handles.", sockets.CloseWait),
		Evidence:    evidence,
		Remediation: "Inspect application connection pool and HTTP client response body cleanup (ensure body.Close() is invoked). Check lsof or /proc/[pid]/fd to isolate the leaking PID.",
	}

	if topProc := findTopFDProcess(diff.Processes); topProc != nil && topProc.OpenFDs > 100 {
		diag.CulpritPID = topProc.PID
		diag.CulpritName = topProc.Comm
		diag.CulpritDetails = fmt.Sprintf("Holding %d open file descriptors (Max: %d)", topProc.OpenFDs, topProc.MaxFDs)
		diag.Remediation = fmt.Sprintf("Restart or patch leaking service PID %d (%s) to release socket descriptors.", topProc.PID, topProc.Comm)
	}

	return diag, true
}

func findTopFDProcess(procs []collector.ProcessDiff) *collector.ProcessDiff {
	var top *collector.ProcessDiff
	for i := range procs {
		p := &procs[i]
		if top == nil || p.OpenFDs > top.OpenFDs {
			top = p
		}
	}
	return top
}

// RuleSustainedLoadSaturation detects multi-minute sustained load average saturation distinguishing from 1s bursts.
type RuleSustainedLoadSaturation struct{ noSuppression }

func (r *RuleSustainedLoadSaturation) ID() string { return "CONT_SUSTAINED_LOAD_SATURATION" }
func (r *RuleSustainedLoadSaturation) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleSustainedLoadSaturation) Tier() int            { return 2 }
func (r *RuleSustainedLoadSaturation) IsPIDDependent() bool { return false }

func (r *RuleSustainedLoadSaturation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil || !diff.LatestSnapshot.LoadAvg.Available {
		return nil, false
	}

	numCores := len(diff.LatestSnapshot.CPU.PerCore)
	if numCores == 0 {
		numCores = 1
	}

	load := diff.LatestSnapshot.LoadAvg
	threshold1 := float64(numCores * 2)
	threshold5 := float64(numCores) * 1.5

	if load.Load1 < threshold1 || load.Load5 < threshold5 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Load Average: 1m=%.2f, 5m=%.2f, 15m=%.2f (CPU Cores: %d)", load.Load1, load.Load5, load.Load15, numCores),
		fmt.Sprintf("Active Scheduling Entities: %d running / %d total", load.RunningEntities, load.TotalEntities),
	}

	confidence := 0.88
	if diff.LatestSnapshot.PSI.Available && diff.LatestSnapshot.PSI.CPU.Some.Avg10 > 10.0 {
		confidence = 0.95
		evidence = append(evidence, fmt.Sprintf("CPU PSI Stall: %.1f%% of tasks delayed", diff.LatestSnapshot.PSI.CPU.Some.Avg10))
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  confidence,
		Title:       "Sustained Multi-Minute CPU Runqueue Overload",
		Explanation: fmt.Sprintf("System load averages (1m: %.2f, 5m: %.2f) consistently exceed physical CPU core capacity (%d cores) across multiple time horizons, indicating persistent compute starvation rather than a transient burst.", load.Load1, load.Load5, numCores),
		Evidence:    evidence,
		Remediation: "Scale out compute instances, increase CPU allocations, or audit long-running thread pools for excessive concurrency.",
	}, true
}

// RuleRunawayCPUProcess detects single or multi-thread runaway CPU hogs on a core.
type RuleRunawayCPUProcess struct{ noSuppression }

func (r *RuleRunawayCPUProcess) ID() string { return "CONT_RUNAWAY_CPU_PROCESS" }
func (r *RuleRunawayCPUProcess) Explain() RuleExplanation {
	return tier2Explanations[r.ID()]
}
func (r *RuleRunawayCPUProcess) Tier() int            { return 2 }
func (r *RuleRunawayCPUProcess) IsPIDDependent() bool { return true }

func (r *RuleRunawayCPUProcess) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Processes) == 0 {
		return nil, false
	}

	var topProc *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.CpusAllowed != 1 && p.Policy == 0 && p.CPUPercent >= 80.0 {
			if topProc == nil || p.CPUPercent > topProc.CPUPercent {
				topProc = p
			}
		}
	}

	if topProc == nil {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       fmt.Sprintf("Runaway Compute CPU Hog (PID %d [%s])", topProc.PID, topProc.Comm),
		Explanation: fmt.Sprintf("Process '%s' (PID %d) is consuming %.1f%% CPU on a core, starving other workloads of compute cycles.", topProc.Comm, topProc.PID, topProc.CPUPercent),
		Evidence: []string{
			fmt.Sprintf("Process CPU Utilization: %.1f%% on PID %d [%s]", topProc.CPUPercent, topProc.PID, topProc.Comm),
			fmt.Sprintf("Active Threads: %d | Kernel State: %c", topProc.NumThreads, topProc.State),
		},
		CulpritPID:     topProc.PID,
		CulpritName:    topProc.Comm,
		CulpritDetails: fmt.Sprintf("%.1f%% CPU utilization", topProc.CPUPercent),
		Remediation:    fmt.Sprintf("Lower CPU scheduling priority: renice -n 19 -p %d, or send graceful stop: kill -TERM %d", topProc.PID, topProc.PID),
	}, true
}

// RuleProcessSwapPinned detects individual processes with > 500MB swapped out under system memory pressure.
type RuleProcessSwapPinned struct {
	noSuppression
}

func (r *RuleProcessSwapPinned) ID() string             { return "CONT_PROCESS_SWAP_PINNED" }
func (r *RuleProcessSwapPinned) Tier() int              { return 2 }
func (r *RuleProcessSwapPinned) IsPIDDependent() bool   { return true }
func (r *RuleProcessSwapPinned) Explain() RuleExplanation { return tier2Explanations[r.ID()] }

func (r *RuleProcessSwapPinned) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Processes) == 0 {
		return nil, false
	}

	var topProc *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.SmapsRollup.Available && p.SmapsRollup.Swap > 512000 {
			if topProc == nil || p.SmapsRollup.Swap > topProc.SmapsRollup.Swap {
				topProc = p
			}
		}
	}
	if topProc == nil {
		return nil, false
	}

	memPressure := false
	var memTotal, memAvail uint64
	if diff.LatestSnapshot != nil {
		memTotal = diff.LatestSnapshot.Memory.MemTotal
		memAvail = diff.LatestSnapshot.Memory.MemAvailable
		if memTotal > 0 && memAvail < (memTotal*20/100) {
			memPressure = true
		}
	}
	if diff.VMStat.PswpinDelta > 0 {
		memPressure = true
	}
	if !memPressure {
		return nil, false
	}

	swapMB := float64(topProc.SmapsRollup.Swap) / 1024.0
	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.85,
		Title:       fmt.Sprintf("Process Swap-Pinned (PID %d [%s])", topProc.PID, topProc.Comm),
		Explanation: fmt.Sprintf("Process '%s' (PID %d) has %.1f MB of memory swapped out while system memory pressure is elevated.", topProc.Comm, topProc.PID, swapMB),
		Evidence: []string{
			fmt.Sprintf("Process Swapped Memory: %.1f MB (PID %d [%s])", swapMB, topProc.PID, topProc.Comm),
			fmt.Sprintf("System MemAvailable: %d KB (MemTotal: %d KB) | Pswpin Delta: %d", memAvail, memTotal, diff.VMStat.PswpinDelta),
		},
		CulpritPID:     topProc.PID,
		CulpritName:    topProc.Comm,
		CulpritDetails: fmt.Sprintf("%.1f MB swapped out", swapMB),
		Remediation:    fmt.Sprintf("Reduce memory usage of process %s or increase system RAM", topProc.Comm),
	}, true
}

// RuleDentryCacheExplosion detects excessive dentry slab object allocations under system memory pressure.
type RuleDentryCacheExplosion struct {
	noSuppression
}

func (r *RuleDentryCacheExplosion) ID() string             { return "CONT_DENTRY_CACHE_EXPLOSION" }
func (r *RuleDentryCacheExplosion) Tier() int              { return 2 }
func (r *RuleDentryCacheExplosion) IsPIDDependent() bool   { return false }
func (r *RuleDentryCacheExplosion) Explain() RuleExplanation { return tier2Explanations[r.ID()] }

func (r *RuleDentryCacheExplosion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil || !diff.LatestSnapshot.SystemConfig.Slab.Available {
		return nil, false
	}

	slab := diff.LatestSnapshot.SystemConfig.Slab
	if slab.DentryCacheActive <= 2000000 {
		return nil, false
	}

	memTotal := diff.LatestSnapshot.Memory.MemTotal
	memAvail := diff.LatestSnapshot.Memory.MemAvailable
	if memTotal == 0 || memAvail >= (memTotal*20/100) {
		return nil, false
	}

	availPct := float64(memAvail) / float64(memTotal) * 100.0
	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.75,
		Title:       "Kernel Dentry Cache Slab Explosion",
		Explanation: fmt.Sprintf("Kernel dentry cache contains %d active directory entries while available memory is depleted (%.1f%% of MemTotal).", slab.DentryCacheActive, availPct),
		Evidence: []string{
			fmt.Sprintf("Active Dentry Cache Objects: %d (Total: %d)", slab.DentryCacheActive, slab.DentryCacheTotal),
			fmt.Sprintf("Available Memory: %.1f%% (Pressure threshold: < 20.0%%)", availPct),
		},
		Remediation: "echo 2 > /proc/sys/vm/drop_caches (requires root) to release dentry/inode caches",
	}, true
}
