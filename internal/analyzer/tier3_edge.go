// Package analyzer — tier3_edge.go contains Tier 3 (P2 Priority)
// diagnostic rules for subtle kernel edge cases:
//
//   - EDGE_THP_COMPACTION_STALL:       THP defragmentation stalls
//   - EDGE_PTY_STDOUT_LOCK:            Terminal buffer backpressure
//   - EDGE_HPET_CLOCKSOURCE_DEGRADE:   Non-TSC clocksource (slow timekeeping)
//   - EDGE_CGROUP_DIRTY_THROTTLE:      Dirty page flusher stall
//   - EDGE_FUTEX_CONTENTION:           Multithread mutex lock congestion
//   - EDGE_NUMA_REMOTE_THRASHING:      Cross-socket NUMA remote memory overhead
//   - EDGE_CPU_AFFINITY_PIN:           Process pinned to single core while system idle
//   - EDGE_ZOMBIE_DEFUNCT_LEAK:        Unreaped zombie process accumulation (≥ 50)
//   - EDGE_CGROUP_OOM_KILL_EVENT:      Silent container memory.events oom_kill
package analyzer

import (
	"fmt"
	"strings"
	"why-slow/internal/collector"
)

// GetTier3Rules returns all registered Tier 3 diagnostic rules.
func GetTier3Rules() []Rule {
	return []Rule{
		&RuleTHPCompactionStall{},
		&RulePTYStdoutLock{},
		&RuleHPETClocksourceDegrade{},
		&RuleCgroupDirtyThrottle{},
		&RuleFutexContention{},
		&RuleNUMARemoteThrashing{},
		&RuleCPUAffinityPin{},
		&RuleZombieDefunctLeak{},
		&RuleCgroupOOMKillEvent{},
		&RuleDMA32ZoneExhaustion{},
		&RuleKSMScanStall{},
		&RuleIRQCoreStorm{},
		&RuleSlabUnreclaimableLeak{},
		&RuleInotifyWatchExhaustion{},
		&RuleRCUSchedulerStall{},
		&RuleTHPCollapseStall{},
		&RuleFUSEFilesystemLatency{},
		&RuleCompactionFailureRate{},
		&RuleMajorPageFaultStorm{},
	}
}

// RuleTHPCompactionStall detects memory defragmentation latency spikes caused by Transparent Huge Pages.
type RuleTHPCompactionStall struct{}

func (r *RuleTHPCompactionStall) ID() string             { return "EDGE_THP_COMPACTION_STALL" }
func (r *RuleTHPCompactionStall) Tier() int              { return 3 }
func (r *RuleTHPCompactionStall) IsPIDDependent() bool   { return false }

func (r *RuleTHPCompactionStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	stalls := diff.VMStat.CompactStallDelta
	var compactProcs []collector.ProcessDiff
	for i := range diff.Processes {
		if diff.Processes[i].Wchan == "compact_zone" {
			compactProcs = append(compactProcs, diff.Processes[i])
		}
	}

	if stalls == 0 && len(compactProcs) == 0 {
		return nil, false
	}

	evidence := make([]string, 0, 2+len(compactProcs))
	if stalls > 0 {
		evidence = append(evidence, fmt.Sprintf("THP Compaction Stalls: %d kernel memory defragmentation events", stalls))
	}
	for _, p := range compactProcs {
		evidence = append(evidence, fmt.Sprintf("PID %d [%s] blocked in kernel memory compaction (wchan=compact_zone)", p.PID, p.Comm))
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.88,
		Title:       "Transparent Huge Page (THP) Compaction Stall",
		Explanation: "The kernel paused execution to defragment 4KB memory pages into contiguous 2MB Huge Pages, causing latency spikes.",
		Evidence:    evidence,
		Remediation: "Change THP defrag mode: echo madvise > /sys/kernel/mm/transparent_hugepage/defrag or disable THP.",
	}, true
}

// RulePTYStdoutLock detects processes blocked because terminal/SSH stdout buffer is unread.
type RulePTYStdoutLock struct{}

func (r *RulePTYStdoutLock) ID() string             { return "EDGE_PTY_STDOUT_LOCK" }
func (r *RulePTYStdoutLock) Tier() int              { return 3 }
func (r *RulePTYStdoutLock) IsPIDDependent() bool   { return true }

func (r *RulePTYStdoutLock) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var lockedProc *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.State == 'S' && (p.Wchan == "n_tty_write" || p.Wchan == "pty_write" || p.Wchan == "pipe_wait" || p.Wchan == "pipe_write") {
			lockedProc = p
			break
		}
	}

	if lockedProc == nil {
		return nil, false
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           3,
		Severity:       SeverityMedium,
		Confidence:     0.90,
		Title:          fmt.Sprintf("Terminal / Pipe Output Buffer Lock (PID %d [%s])", lockedProc.PID, lockedProc.Comm),
		Explanation:    fmt.Sprintf("Process '%s' (PID %d) is stalled waiting for its stdout/pipe buffer to be consumed.", lockedProc.Comm, lockedProc.PID),
		Evidence: []string{
			fmt.Sprintf("Process PID: %d [%s], State: %c", lockedProc.PID, lockedProc.Comm, lockedProc.State),
			fmt.Sprintf("Kernel Wait Channel: %s (Terminal write backpressure)", lockedProc.Wchan),
		},
		CulpritPID:     lockedProc.PID,
		CulpritName:    lockedProc.Comm,
		CulpritDetails: fmt.Sprintf("Blocked in %s buffer write", lockedProc.Wchan),
		Remediation:    "Redirect verbose command output to a file (/tmp/out.log) or discard stdout (> /dev/null).",
	}, true
}

// RuleHPETClocksourceDegrade detects fallback from fast vDSO TSC to slow MMIO clock sources.
type RuleHPETClocksourceDegrade struct{}

func (r *RuleHPETClocksourceDegrade) ID() string             { return "EDGE_HPET_CLOCKSOURCE_DEGRADE" }
func (r *RuleHPETClocksourceDegrade) Tier() int              { return 3 }
func (r *RuleHPETClocksourceDegrade) IsPIDDependent() bool   { return false }

func (r *RuleHPETClocksourceDegrade) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	cs := diff.LatestSnapshot.Clocksource.Current
	if cs == "" || cs == "unknown" || cs == "tsc" || cs == "kvm-clock" {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityHigh,
		Confidence:  0.95,
		Title:       fmt.Sprintf("Slow Kernel Clocksource Degraded (%s)", cs),
		Explanation: fmt.Sprintf("System clocksource is '%s' instead of 'tsc'. Timestamp syscalls (gettimeofday, clock_gettime) require slow MMIO calls.", cs),
		Evidence: []string{
			fmt.Sprintf("Current Clocksource: %s", cs),
			"vDSO fast path is bypassed, adding 10-100x overhead to timekeeping operations",
		},
		Remediation: "Inspect dmesg for TSC desynchronization errors and configure kernel boot parameter 'clocksource=tsc'.",
	}, true
}

// RuleCgroupDirtyThrottle detects processes throttled in dirty memory balance flushes.
type RuleCgroupDirtyThrottle struct{}

func (r *RuleCgroupDirtyThrottle) ID() string             { return "EDGE_CGROUP_DIRTY_THROTTLE" }
func (r *RuleCgroupDirtyThrottle) Tier() int              { return 3 }
func (r *RuleCgroupDirtyThrottle) IsPIDDependent() bool   { return true }

func (r *RuleCgroupDirtyThrottle) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var dirtyProc *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if strings.HasPrefix(p.Wchan, "balance_dirty_pages") {
			dirtyProc = p
			break
		}
	}

	if dirtyProc == nil {
		return nil, false
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           3,
		Severity:       SeverityMedium,
		Confidence:     0.88,
		Title:          fmt.Sprintf("Dirty Page Cache Throttling (PID %d [%s])", dirtyProc.PID, dirtyProc.Comm),
		Explanation:    fmt.Sprintf("Process '%s' (PID %d) is forced to sleep because dirty unwritten page ratio has exceeded thresholds.", dirtyProc.Comm, dirtyProc.PID),
		Evidence: []string{
			fmt.Sprintf("Process PID %d [%s] blocked in wchan '%s'", dirtyProc.PID, dirtyProc.Comm, dirtyProc.Wchan),
		},
		CulpritPID:     dirtyProc.PID,
		CulpritName:    dirtyProc.Comm,
		CulpritDetails: fmt.Sprintf("Throttled in %s writeback flusher", dirtyProc.Wchan),
		Remediation:    "Tune sysctl vm.dirty_ratio / vm.dirty_background_ratio or accelerate underlying disk flush bandwidth.",
	}, true
}

// RuleFutexContention detects hundreds of threads blocked competing for the same user-space mutex lock.
type RuleFutexContention struct{}

func (r *RuleFutexContention) ID() string             { return "EDGE_FUTEX_CONTENTION" }
func (r *RuleFutexContention) Tier() int              { return 3 }
func (r *RuleFutexContention) IsPIDDependent() bool   { return true }

func (r *RuleFutexContention) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var topContended *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.NumThreads >= 50 && strings.Contains(p.Wchan, "futex") {
			if topContended == nil || p.NumThreads > topContended.NumThreads {
				topContended = p
			}
		}
	}

	if topContended == nil {
		return nil, false
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           3,
		Severity:       SeverityMedium,
		Confidence:     0.85,
		Title:          fmt.Sprintf("Multithreaded Mutex Lock Contention (PID %d [%s])", topContended.PID, topContended.Comm),
		Explanation:    fmt.Sprintf("Process '%s' (PID %d) has %d threads heavily blocked competing for user-space futex mutex locks.", topContended.Comm, topContended.PID, topContended.NumThreads),
		Evidence: []string{
			fmt.Sprintf("Thread Count: %d threads in process", topContended.NumThreads),
			fmt.Sprintf("Kernel Wait Channel: %s", topContended.Wchan),
		},
		CulpritPID:     topContended.PID,
		CulpritName:    topContended.Comm,
		CulpritDetails: fmt.Sprintf("High thread contention (%d threads) on futex lock", topContended.NumThreads),
		Remediation:    "Profile lock contention (perf / go pprof mutex) or reduce concurrent worker thread pool size.",
	}, true
}

// RuleNUMARemoteThrashing detects remote cross-socket memory allocation latency.
type RuleNUMARemoteThrashing struct{}

func (r *RuleNUMARemoteThrashing) ID() string             { return "EDGE_NUMA_REMOTE_THRASHING" }
func (r *RuleNUMARemoteThrashing) Tier() int              { return 3 }
func (r *RuleNUMARemoteThrashing) IsPIDDependent() bool   { return false }

func (r *RuleNUMARemoteThrashing) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	misses := diff.VMStat.NumaMissDelta
	foreign := diff.VMStat.NumaForeignDelta

	if misses < 5000 && foreign < 5000 {
		return nil, false
	}

	evidence := make([]string, 0, 2)
	if misses > 0 {
		evidence = append(evidence, fmt.Sprintf("NUMA Misses Delta: %d allocations on remote node", misses))
	}
	if foreign > 0 {
		evidence = append(evidence, fmt.Sprintf("NUMA Foreign Allocations Delta: %d allocations intended for other nodes", foreign))
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.85,
		Title:       "NUMA Remote Cross-Socket Memory Thrashing",
		Explanation: "High rate of NUMA remote memory node allocations detected, introducing 30-50% memory latency overhead due to cross-socket interconnect traversal.",
		Evidence:    evidence,
		Remediation: "Bind latency-critical applications to local NUMA node: numactl --cpunodebind=0 --membind=0 <cmd> or sysctl -w vm.zone_reclaim_mode=0.",
	}, true
}

// RuleCPUAffinityPin detects single-core affinity bottleneck when aggregate system CPU is largely idle.
type RuleCPUAffinityPin struct{}

func (r *RuleCPUAffinityPin) ID() string             { return "EDGE_CPU_AFFINITY_PIN" }
func (r *RuleCPUAffinityPin) Tier() int              { return 3 }
func (r *RuleCPUAffinityPin) IsPIDDependent() bool   { return true }

func (r *RuleCPUAffinityPin) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	numCores := len(diff.LatestSnapshot.CPU.PerCore)
	if numCores < 2 {
		return nil, false
	}

	if diff.TotalCPUUtil.IdlePercent < 75.0 {
		return nil, false
	}

	var pinnedProc *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.CpusAllowed == 1 && (p.CPUPercent >= 90.0 || p.CPUTimeDelta >= 90) {
			if pinnedProc == nil || p.CPUPercent > pinnedProc.CPUPercent {
				pinnedProc = p
			}
		}
	}

	if pinnedProc == nil {
		return nil, false
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           3,
		Severity:       SeverityMedium,
		Confidence:     0.90,
		Title:          fmt.Sprintf("Single-Core CPU Affinity Pin Bottleneck (PID %d [%s])", pinnedProc.PID, pinnedProc.Comm),
		Explanation:    fmt.Sprintf("Process '%s' (PID %d) is pinned to a single CPU core and saturating it (%.1f%% CPU) while overall system is %.1f%% idle.", pinnedProc.Comm, pinnedProc.PID, pinnedProc.CPUPercent, diff.TotalCPUUtil.IdlePercent),
		Evidence: []string{
			fmt.Sprintf("Process CPU Utilization: %.1f%% (Pinned to 1 CPU core)", pinnedProc.CPUPercent),
			fmt.Sprintf("Overall System Idle: %.1f%% across %d cores", diff.TotalCPUUtil.IdlePercent, numCores),
		},
		CulpritPID:     pinnedProc.PID,
		CulpritName:    pinnedProc.Comm,
		CulpritDetails: fmt.Sprintf("Pinned to single core with %.1f%% CPU delta", pinnedProc.CPUPercent),
		Remediation:    fmt.Sprintf("Expand CPU affinity mask across available cores: taskset -p 0xffffffff %d", pinnedProc.PID),
	}, true
}

// RuleZombieDefunctLeak detects zombie / defunct process accumulation from unreaped children.
type RuleZombieDefunctLeak struct{}

func (r *RuleZombieDefunctLeak) ID() string             { return "EDGE_ZOMBIE_DEFUNCT_LEAK" }
func (r *RuleZombieDefunctLeak) Tier() int              { return 3 }
func (r *RuleZombieDefunctLeak) IsPIDDependent() bool   { return true }

func (r *RuleZombieDefunctLeak) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	procs := diff.Processes
	zombieCount := 0
	parentZombies := make(map[int]int, 16)

	for i := range procs {
		p := &procs[i]
		if p.State == 'Z' {
			zombieCount++
			if p.PPID > 0 {
				parentZombies[p.PPID]++
			}
		}
	}

	if zombieCount < 50 {
		return nil, false
	}

	topPPID := 0
	maxChildZombies := 0
	for ppid, count := range parentZombies {
		if count > maxChildZombies {
			maxChildZombies = count
			topPPID = ppid
		}
	}

	topParentComm := "unknown"
	for i := range procs {
		if procs[i].PID == topPPID {
			topParentComm = procs[i].Comm
			break
		}
	}

	evidence := []string{
		fmt.Sprintf("Total Zombie Processes: %d defunct processes in process table", zombieCount),
	}
	if topPPID > 0 {
		evidence = append(evidence, fmt.Sprintf("Top Culprit Parent: PID %d [%s] with %d unreaped zombie children", topPPID, topParentComm, maxChildZombies))
	}

	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.90,
		Title:       "Zombie Process Leak (Unreaped Defunct Children)",
		Explanation: "Accumulation of zombie processes indicates parent process is failing to call waitpid(), polluting the kernel PID table.",
		Evidence:    evidence,
		Remediation: "Signal parent process to reap children or restart parent daemon.",
	}

	if topPPID > 0 {
		diag.CulpritPID = topPPID
		diag.CulpritName = topParentComm
		diag.CulpritDetails = fmt.Sprintf("%d unreaped zombie children", maxChildZombies)
		diag.Remediation = fmt.Sprintf("Signal parent process to reap children: kill -HUP %d", topPPID)
	}

	return diag, true
}

// RuleCgroupOOMKillEvent detects silent container OOM kill events triggered by cgroup memory limits.
type RuleCgroupOOMKillEvent struct{}

func (r *RuleCgroupOOMKillEvent) ID() string             { return "EDGE_CGROUP_OOM_KILL_EVENT" }
func (r *RuleCgroupOOMKillEvent) Tier() int              { return 3 }
func (r *RuleCgroupOOMKillEvent) IsPIDDependent() bool   { return true }

func (r *RuleCgroupOOMKillEvent) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var topOOM *collector.CgroupDiff
	for i := range diff.Cgroups {
		cg := &diff.Cgroups[i]
		if cg.OOMKillsDelta > 0 {
			if topOOM == nil || cg.OOMKillsDelta > topOOM.OOMKillsDelta {
				topOOM = cg
			}
		}
	}

	if topOOM == nil {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityHigh,
		Confidence:  0.95,
		Title:       fmt.Sprintf("Container Cgroup OOM Kill Event (%s)", topOOM.Path),
		Explanation: fmt.Sprintf("Container or cgroup '%s' triggered %d OOM kill events during the sampling window due to memory limit enforcement.", topOOM.Path, topOOM.OOMKillsDelta),
		Evidence: []string{
			fmt.Sprintf("Cgroup Path: %s", topOOM.Path),
			fmt.Sprintf("OOM Kills Delta: %d processes killed by cgroup memory controller", topOOM.OOMKillsDelta),
		},
		Remediation: fmt.Sprintf("Increase container memory allocation (e.g. docker update --memory <size> %s) or diagnose memory leak.", topOOM.Path),
	}, true
}

// RuleDMA32ZoneExhaustion detects low-memory DMA32 zone depletion on multi-gigabyte servers.
type RuleDMA32ZoneExhaustion struct{}

func (r *RuleDMA32ZoneExhaustion) ID() string             { return "EDGE_ZONE_DMA32_EXHAUSTION" }
func (r *RuleDMA32ZoneExhaustion) Tier() int              { return 3 }
func (r *RuleDMA32ZoneExhaustion) IsPIDDependent() bool   { return false }

func (r *RuleDMA32ZoneExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	buddy := &diff.LatestSnapshot.SystemConfig.BuddyInfo
	if !buddy.Available {
		return nil, false
	}

	// Trigger if DMA32 is exhausted (0 pages) while Normal zone has ample memory (> 250,000 pages / ~1GB+)
	if buddy.DMA32FreePages == 0 && buddy.NormalFreePages >= 250000 {
		normalFreeMB := (buddy.NormalFreePages * 4096) / (1024 * 1024)
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.88,
			Title:       "Low-Memory DMA32 Zone Depletion (Driver Allocation Stall)",
			Explanation: "The low-memory DMA32 physical address zone (< 4GB) is completely exhausted of free pages, triggering synchronous page reclamation for 32-bit hardware drivers despite large amounts of free memory in high zones.",
			Evidence: []string{
				"DMA32 Zone (< 4GB RAM): 0 free pages (zone exhausted)",
				fmt.Sprintf("Normal Zone (High RAM): %d MB free memory (%d pages)", normalFreeMB, buddy.NormalFreePages),
			},
			Remediation: "Configure sysctl -w vm.zone_reclaim_mode=0 or upgrade legacy 32-bit DMA hardware drivers to 64-bit DMA mode.",
		}, true
	}

	return nil, false
}

// RuleKSMScanStall detects Kernel Samepage Merging CPU thrashing and cache eviction.
type RuleKSMScanStall struct{}

func (r *RuleKSMScanStall) ID() string             { return "EDGE_KSM_SCAN_STALL" }
func (r *RuleKSMScanStall) Tier() int              { return 3 }
func (r *RuleKSMScanStall) IsPIDDependent() bool   { return true }

func (r *RuleKSMScanStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	ksm := &diff.LatestSnapshot.SystemConfig.KSM
	if !ksm.Available || !ksm.Running {
		return nil, false
	}

	// Check if ksmd process is consuming significant CPU or scanning large page batches
	var ksmdCPU float64
	var ksmdPID int
	for _, p := range diff.Processes {
		if p.Comm == "ksmd" {
			ksmdCPU = p.CPUPercent
			ksmdPID = p.PID
			break
		}
	}

	if ksm.PagesToScan >= 10000 && (ksmdCPU >= 50.0 || ksm.PagesSharing > 50000) {
		diag := &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.85,
			Title:       "Kernel Samepage Merging (KSM) Deduplication Stall",
			Explanation: "Active KSM memory deduplication is scanning thousands of pages across VMs/containers, thrashing CPU L1/L2 caches and consuming significant compute time.",
			Evidence: []string{
				fmt.Sprintf("KSM Configuration: pages_to_scan = %d, pages_sharing = %d, pages_shared = %d",
					ksm.PagesToScan, ksm.PagesSharing, ksm.PagesShared),
			},
			Remediation: "Disable KSM memory deduplication (echo 0 > /sys/kernel/mm/ksm/run) or raise scan sleep interval (/sys/kernel/mm/ksm/sleep_millisecs).",
		}
		if ksmdPID > 0 {
			diag.CulpritPID = ksmdPID
			diag.CulpritName = "ksmd"
			diag.CulpritDetails = fmt.Sprintf("Consuming %.1f%% CPU delta in background", ksmdCPU)
			diag.Evidence = append(diag.Evidence, fmt.Sprintf("KSM Daemon CPU Utilization: %.1f%%", ksmdCPU))
		}
		return diag, true
	}

	return nil, false
}

// RuleIRQCoreStorm detects severe hardware interrupt imbalance on a single CPU core.
type RuleIRQCoreStorm struct{}

func (r *RuleIRQCoreStorm) ID() string             { return "EDGE_IRQ_CORE_STORM" }
func (r *RuleIRQCoreStorm) Tier() int              { return 3 }
func (r *RuleIRQCoreStorm) IsPIDDependent() bool   { return false }

func (r *RuleIRQCoreStorm) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	irq := &diff.LatestSnapshot.SystemConfig.IRQStat
	if !irq.Available || irq.MaxCoreIRQs < 50000 {
		return nil, false
	}

	// Trigger if one core handles >= 50k IRQs and is >= 5x higher than average of others
	if irq.OtherCoresAvgIRQs == 0 || float64(irq.MaxCoreIRQs) >= 5.0*irq.OtherCoresAvgIRQs {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.88,
			Title:       fmt.Sprintf("Hardware Interrupt Storm on CPU Core %d", irq.MaxCoreID),
			Explanation: fmt.Sprintf("CPU core %d is handling an overwhelming majority of hardware interrupts (%d IRQs) without balanced SMP distribution.", irq.MaxCoreID, irq.MaxCoreIRQs),
			Evidence: []string{
				fmt.Sprintf("Most Loaded Core: CPU %d (%d hardware interrupts)", irq.MaxCoreID, irq.MaxCoreIRQs),
				fmt.Sprintf("Average on Other Cores: %.0f interrupts", irq.OtherCoresAvgIRQs),
				"Missing irqbalance or improper SMP IRQ affinity routing",
			},
			Remediation: fmt.Sprintf("Start/restart irqbalance service or adjust SMP affinity: echo <core_mask> > /proc/irq/<N>/smp_affinity"),
		}, true
	}

	return nil, false
}

// RuleSlabUnreclaimableLeak detects kernel dentry / inode slab memory consumption leaks.
type RuleSlabUnreclaimableLeak struct{}

func (r *RuleSlabUnreclaimableLeak) ID() string             { return "EDGE_SLAB_UNRECLAIM_LEAK" }
func (r *RuleSlabUnreclaimableLeak) Tier() int              { return 3 }
func (r *RuleSlabUnreclaimableLeak) IsPIDDependent() bool   { return false }

func (r *RuleSlabUnreclaimableLeak) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	mem := &diff.LatestSnapshot.Memory
	if mem.MemTotal == 0 || mem.SUnreclaim == 0 {
		return nil, false
	}

	ratio := float64(mem.SUnreclaim) / float64(mem.MemTotal)
	if ratio >= 0.40 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.90,
			Title:       "Unreclaimable Kernel Slab Memory Leak (Dentries/Inodes)",
			Explanation: "Non-reclaimable kernel slab memory (SUnreclaim) occupies ≥ 40% of system RAM, indicating dentry/inode cache bloat that is invisible in user-space process tables.",
			Evidence: []string{
				fmt.Sprintf("SUnreclaim Memory: %d MB (%.1f%% of physical RAM)", mem.SUnreclaim/1024, ratio*100.0),
				fmt.Sprintf("Total Slab Memory: %d MB", mem.Slab/1024),
			},
			Remediation: "Drop clean dentry/inode caches: echo 2 > /proc/sys/vm/drop_caches or increase vm.vfs_cache_pressure (sysctl -w vm.vfs_cache_pressure=200).",
		}, true
	}

	return nil, false
}

// RuleInotifyWatchExhaustion detects inotify watch table saturation or restrictive user limits.
type RuleInotifyWatchExhaustion struct{}

func (r *RuleInotifyWatchExhaustion) ID() string             { return "EDGE_INOTIFY_WATCH_EXHAUSTION" }
func (r *RuleInotifyWatchExhaustion) Tier() int              { return 3 }
func (r *RuleInotifyWatchExhaustion) IsPIDDependent() bool   { return false }

func (r *RuleInotifyWatchExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	inotify := &diff.LatestSnapshot.SystemConfig.Inotify
	if !inotify.Available || inotify.MaxUserWatches == 0 {
		return nil, false
	}

	// Trigger if max_user_watches is set to an dangerously low legacy limit (<= 8192)
	// which frequently causes modern file watchers, IDEs, and container daemons to fail with ENOSPC
	if inotify.MaxUserWatches <= 8192 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.80,
			Title:       "Restrictive Inotify Watch Table Limit (max_user_watches)",
			Explanation: "The system inotify watch ceiling ('fs.inotify.max_user_watches') is set to a restrictive limit (≤ 8192), risking spurious 'ENOSPC: No space left on device' failures in file watchers and dev servers.",
			Evidence: []string{
				fmt.Sprintf("Max Inotify User Watches: %d ceiling", inotify.MaxUserWatches),
				"Modern build tools, file sync daemons, and IDEs require ≥ 524,288 watches",
			},
			Remediation: "Raise inotify watch table ceiling: sysctl -w fs.inotify.max_user_watches=524288",
		}, true
	}

	return nil, false
}

// RuleRCUSchedulerStall detects kernel Read-Copy-Update (RCU) grace period contention.
type RuleRCUSchedulerStall struct{}

func (r *RuleRCUSchedulerStall) ID() string             { return "EDGE_RCU_SCHEDULER_STALL" }
func (r *RuleRCUSchedulerStall) Tier() int              { return 3 }
func (r *RuleRCUSchedulerStall) IsPIDDependent() bool   { return true }

func (r *RuleRCUSchedulerStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Processes) == 0 {
		return nil, false
	}

	var rcuWaitingProcs []collector.ProcessDiff
	for _, p := range diff.Processes {
		if strings.Contains(p.Wchan, "rcu_gp_kthread") || strings.Contains(p.Wchan, "synchronize_rcu") || strings.Contains(p.Wchan, "rcu_sched") {
			rcuWaitingProcs = append(rcuWaitingProcs, p)
		}
	}

	if len(rcuWaitingProcs) >= 2 {
		topProc := rcuWaitingProcs[0]
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.85,
			Title:       "Kernel RCU Grace Period Contention Stall",
			Explanation: "Multiple kernel or user tasks are blocked waiting for Read-Copy-Update (RCU) grace periods to advance, stalling memory deallocation and network table syncs.",
			Evidence: []string{
				fmt.Sprintf("Tasks Blocked on RCU: %d tasks", len(rcuWaitingProcs)),
				fmt.Sprintf("Representative Task: PID %d [%s] (wchan=%s)", topProc.PID, topProc.Comm, topProc.Wchan),
			},
			CulpritPID:  topProc.PID,
			CulpritName: topProc.Comm,
			Remediation: "Inspect CPU-bound non-preemptible kernel routines or pin real-time tasks away from CPU 0.",
		}, true
	}

	return nil, false
}

// RuleTHPCollapseStall detects Transparent Huge Page background defragmentation and collapse latency.
type RuleTHPCollapseStall struct{}

func (r *RuleTHPCollapseStall) ID() string             { return "EDGE_THP_COLLAPSE_STALL" }
func (r *RuleTHPCollapseStall) Tier() int              { return 3 }
func (r *RuleTHPCollapseStall) IsPIDDependent() bool   { return false }

func (r *RuleTHPCollapseStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	collapseDelta := diff.VMStat.THPCollapseAllocDelta
	allocStallDelta := diff.VMStat.AllocStallDirectDelta

	if collapseDelta > 0 && allocStallDelta > 0 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.88,
			Title:       "Transparent Hugepage Background Collapse Stall",
			Explanation: "Background 'khugepaged' is actively collapsing 4KB memory pages into 2MB hugepages during synchronous allocation stalls, locking page tables and inducing latency spikes.",
			Evidence: []string{
				fmt.Sprintf("THP Collapse Allocations Delta: %d hugepages coalesced", collapseDelta),
				fmt.Sprintf("Direct Allocation Stalls Delta: %d stalls", allocStallDelta),
			},
			Remediation: "Set THP to madvise mode: echo madvise > /sys/kernel/mm/transparent_hugepage/enabled or disable background defrag (echo 0 > /sys/kernel/mm/transparent_hugepage/khugepaged/defrag).",
		}, true
	}

	return nil, false
}

// RuleFUSEFilesystemLatency detects user processes stalled on unresponsive FUSE daemon wait queues.
type RuleFUSEFilesystemLatency struct{}

func (r *RuleFUSEFilesystemLatency) ID() string             { return "EDGE_FUSE_FS_STALL" }
func (r *RuleFUSEFilesystemLatency) Tier() int              { return 3 }
func (r *RuleFUSEFilesystemLatency) IsPIDDependent() bool   { return true }

func (r *RuleFUSEFilesystemLatency) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Processes) == 0 {
		return nil, false
	}

	var fuseProcs []collector.ProcessDiff
	for _, p := range diff.Processes {
		wchan := p.Wchan
		if strings.Contains(wchan, "fuse_request_wait") || strings.Contains(wchan, "request_wait_answer") ||
			strings.Contains(wchan, "fuse_wait_aborted") {
			fuseProcs = append(fuseProcs, p)
		}
	}

	if len(fuseProcs) >= 1 {
		topProc := fuseProcs[0]
		return &Diagnosis{
			RuleID:         r.ID(),
			Tier:           3,
			Severity:       SeverityMedium,
			Confidence:     0.88,
			Title:          "FUSE Filesystem User-Space Daemon Stall",
			Explanation:    "Processes are blocked waiting for a FUSE (Filesystem in Userspace) daemon to respond to file I/O requests.",
			Evidence:       []string{
				fmt.Sprintf("Processes Blocked in FUSE Wait: %d tasks", len(fuseProcs)),
				fmt.Sprintf("Representative Task: PID %d [%s] (wchan=%s)", topProc.PID, topProc.Comm, topProc.Wchan),
			},
			CulpritPID:     topProc.PID,
			CulpritName:    topProc.Comm,
			CulpritDetails: fmt.Sprintf("Stalled in wchan '%s'", topProc.Wchan),
			Remediation:    "Inspect FUSE mount daemon performance (e.g. sshfs, s3fs, glusterfs), or move latency-sensitive data to native filesystems (ext4/xfs).",
		}, true
	}

	return nil, false
}

// RuleCompactionFailureRate detects high failure rate of memory compaction attempts causing fragmentation.
type RuleCompactionFailureRate struct{}

func (r *RuleCompactionFailureRate) ID() string             { return "EDGE_COMPACT_FAIL_RATE" }
func (r *RuleCompactionFailureRate) Tier() int              { return 3 }
func (r *RuleCompactionFailureRate) IsPIDDependent() bool   { return false }

func (r *RuleCompactionFailureRate) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	stalls := diff.VMStat.CompactStallDelta
	fails := diff.VMStat.CompactFailDelta

	if stalls >= 50 && fails >= 25 {
		failRatio := float64(fails) / float64(stalls)
		if failRatio >= 0.50 {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        3,
				Severity:    SeverityMedium,
				Confidence:  0.86,
				Title:       "Severe Memory Compaction Failure Rate",
				Explanation: fmt.Sprintf("Over %.1f%% of kernel memory compaction attempts failed during the sampling window due to severe physical page fragmentation.", failRatio*100.0),
				Evidence: []string{
					fmt.Sprintf("Compaction Failures Delta: %d failed attempts", fails),
					fmt.Sprintf("Total Compaction Stalls Delta: %d total attempts", stalls),
					fmt.Sprintf("Failure Rate: %.1f%%", failRatio*100.0),
				},
				Remediation: "Trigger global proactive memory compaction: echo 1 > /proc/sys/vm/compact_memory or lower vm.extfrag_threshold.",
			}, true
		}
	}

	return nil, false
}

// RuleMajorPageFaultStorm detects bursts of major page faults driving synchronous disk reads.
type RuleMajorPageFaultStorm struct{}

func (r *RuleMajorPageFaultStorm) ID() string             { return "EDGE_MAJOR_PAGE_FAULT_STORM" }
func (r *RuleMajorPageFaultStorm) Tier() int              { return 3 }
func (r *RuleMajorPageFaultStorm) IsPIDDependent() bool   { return false }

func (r *RuleMajorPageFaultStorm) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	majFaults := diff.VMStat.PgMajFaultDelta
	if majFaults >= 500 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.82,
			Title:       "Major Page Fault Disk I/O Storm",
			Explanation: fmt.Sprintf("High rate of major page faults (%d major faults in sampling window) is forcing synchronous storage reads to load file-backed memory and code pages.", majFaults),
			Evidence: []string{
				fmt.Sprintf("Major Page Faults Delta: %d page fault reads", majFaults),
			},
			Remediation: "Preload executable binaries and critical working sets into page cache (e.g. vmtouch) or prevent memory cache pressure.",
		}, true
	}

	return nil, false
}
