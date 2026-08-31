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
		&RuleTHPSplitStorm{},
		&RuleKHugepagedCPUBurn{},
		&RuleDiskDeviceIOErrHang{},
		&RuleKcompactdCPUSpin{},
		&RuleMinFreeKbytesStall{},
		&RuleCorePatternPipeStall{},
		&RuleTCPPAWSDrop{},
		&RuleCMAZoneExhaustion{},
		&RuleLoopDeviceSerialization{},
		&RuleRTSchedThrottling{},
		&RuleNumaAutoBalancingScanStall{},
		&RuleInotifyQueueOverflow{},
		&RuleCgroupCFSBurstStarvation{},
		&RuleZswapCompressorContention{},
		&RuleNetIfaceCarrierFlap{},
		&RuleTHPAllocFallbackStall{},
		&RuleSchedMigrationBounce{},
		&RuleIPFragReasmDrops{},
		&RuleCgroupV2FreezeHang{},
		&RuleSysVShmSegmentLimit{},
		&RuleNetDevRxNoBuffers{},
		&RuleTHPDefragAlways{},
		&RuleCgroupMemoryMaxOOMStall{},
		&RuleTHPScanExhaustionStall{},
		&RuleNetDevTxQueueTimeout{},
		&RuleCgroupCPUCorePinStarvation{},
		&RuleHugeTLBVMAFaultMisalign{},
		&RuleTCPChronicRTOCollapse{},
		&RuleMemcgSockMemoryThrottle{},
		&RuleTHPUseZeroPageSpin{},
		&RuleSysfsCPUHotplugLockContention{},
		&RuleNetIPMulticastIGMPReportStall{},
		&RuleProcPIDTaskPthreadLimit{},
		&RuleZoneNormalFragmentation{},
		&RuleNetDevCarrierDownDrop{},
		&RuleProcPtracedStoppedStall{},
		&RuleMemSlabDentryPressure{},
		&RuleNetIPReasmTimeoutStall{},
		&RuleMemMinWatermarkBounce{},
		&RuleProcCommSwitchTruncation{},
		&RuleEpollPollTimeoutBurst{},
		&RuleNetTCPSynFloodDrop{},
		&RuleSysfsPowerThrottleEvent{},
		&RuleProcZombieParentDeadlock{},
	}
}

// RuleTHPCompactionStall detects memory defragmentation latency spikes caused by Transparent Huge Pages.
type RuleTHPCompactionStall struct{ noSuppression }

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
type RulePTYStdoutLock struct{ noSuppression }

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
type RuleHPETClocksourceDegrade struct{ noSuppression }

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
type RuleCgroupDirtyThrottle struct{ noSuppression }

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
type RuleFutexContention struct{ noSuppression }

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
type RuleNUMARemoteThrashing struct{ noSuppression }

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
type RuleCPUAffinityPin struct{ noSuppression }

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
type RuleZombieDefunctLeak struct{ noSuppression }

func (r *RuleZombieDefunctLeak) ID() string             { return "EDGE_ZOMBIE_DEFUNCT_LEAK" }
func (r *RuleZombieDefunctLeak) Tier() int              { return 3 }
func (r *RuleZombieDefunctLeak) IsPIDDependent() bool   { return true }

func (r *RuleZombieDefunctLeak) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	zombieCount, parentZombies := countZombies(diff.Processes)
	if zombieCount < 50 {
		return nil, false
	}

	topPPID, maxZombies, topParentComm := identifyTopZombieParent(diff.Processes, parentZombies)
	evidence := []string{
		fmt.Sprintf("Total Zombie Processes: %d defunct processes in process table", zombieCount),
	}
	if topPPID > 0 {
		evidence = append(evidence, fmt.Sprintf("Top Culprit Parent: PID %d [%s] with %d unreaped zombie children", topPPID, topParentComm, maxZombies))
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
		diag.CulpritDetails = fmt.Sprintf("%d unreaped zombie children", maxZombies)
		diag.Remediation = fmt.Sprintf("Signal parent process to reap children: kill -HUP %d", topPPID)
	}

	return diag, true
}

func countZombies(procs []collector.ProcessDiff) (int, map[int]int) {
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
	return zombieCount, parentZombies
}

func identifyTopZombieParent(procs []collector.ProcessDiff, parentZombies map[int]int) (int, int, string) {
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
	return topPPID, maxChildZombies, topParentComm
}

// RuleCgroupOOMKillEvent detects silent container OOM kill events triggered by cgroup memory limits.
type RuleCgroupOOMKillEvent struct{ noSuppression }

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
type RuleDMA32ZoneExhaustion struct{ noSuppression }

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
type RuleKSMScanStall struct{ noSuppression }

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
type RuleIRQCoreStorm struct{ noSuppression }

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
type RuleSlabUnreclaimableLeak struct{ noSuppression }

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
type RuleInotifyWatchExhaustion struct{ noSuppression }

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
type RuleRCUSchedulerStall struct{ noSuppression }

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
type RuleTHPCollapseStall struct{ noSuppression }

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
type RuleFUSEFilesystemLatency struct{ noSuppression }

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
type RuleCompactionFailureRate struct{ noSuppression }

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
type RuleMajorPageFaultStorm struct{ noSuppression }

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

// RuleTHPSplitStorm detects high frequency of 2MB Transparent Huge Pages being split into 4KB pages.
type RuleTHPSplitStorm struct{ noSuppression }

func (r *RuleTHPSplitStorm) ID() string           { return "EDGE_THP_SPLIT_STORM" }
func (r *RuleTHPSplitStorm) Tier() int            { return 3 }
func (r *RuleTHPSplitStorm) IsPIDDependent() bool { return false }

func (r *RuleTHPSplitStorm) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	splitDelta := diff.VMStat.THPSplitDelta
	if splitDelta >= 500 && (diff.VMStat.AllocStallDirectDelta > 0 || diff.VMStat.CompactStallDelta > 0 || diff.VMStat.PgScanDirectDelta > 0) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.86,
			Title:       "THP 2MB Page Split Storm & Allocation Penalty",
			Explanation: fmt.Sprintf("Kernel is continuously splitting 2MB Huge Pages into 4KB pages (%d THP splits in window) under memory pressure, locking page tables.", splitDelta),
			Evidence: []string{
				fmt.Sprintf("THP Splits Delta: %d hugepages split", splitDelta),
				fmt.Sprintf("Direct Reclaim / Allocation Stalls: %d alloc stalls", diff.VMStat.AllocStallDirectDelta),
			},
			Remediation: "Disable Transparent Huge Pages: echo never > /sys/kernel/mm/transparent_hugepage/enabled or avoid copy-on-write fork() in large memory processes.",
		}, true
	}
	return nil, false
}

// RuleKHugepagedCPUBurn detects CPU thrashing by background hugepage defragmentation daemon khugepaged.
type RuleKHugepagedCPUBurn struct{ noSuppression }

func (r *RuleKHugepagedCPUBurn) ID() string           { return "EDGE_KHUGEPAGED_CPU_BURN" }
func (r *RuleKHugepagedCPUBurn) Tier() int            { return 3 }
func (r *RuleKHugepagedCPUBurn) IsPIDDependent() bool { return true }

func (r *RuleKHugepagedCPUBurn) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var khugepagedProc *collector.ProcessDiff
	for i := range diff.Processes {
		if diff.Processes[i].Comm == "khugepaged" && diff.Processes[i].CPUPercent >= 40.0 {
			khugepagedProc = &diff.Processes[i]
			break
		}
	}

	if khugepagedProc != nil && (diff.VMStat.THPCollapseAllocFailedDelta > 0 || diff.VMStat.CompactFailDelta > 0 || diff.VMStat.CompactStallDelta > 0) {
		return &Diagnosis{
			RuleID:         r.ID(),
			Tier:           3,
			Severity:       SeverityMedium,
			Confidence:     0.88,
			Title:          "Transparent Hugepage Daemon (khugepaged) CPU Thrash",
			Explanation:    fmt.Sprintf("Background daemon 'khugepaged' is burning %.1f%% CPU scanning and attempting to collapse fragmented memory pages.", khugepagedProc.CPUPercent),
			Evidence: []string{
				fmt.Sprintf("PID %d [khugepaged]: %.1f%% CPU utilization", khugepagedProc.PID, khugepagedProc.CPUPercent),
				fmt.Sprintf("THP Failed Collapses Delta: %d failed allocations", diff.VMStat.THPCollapseAllocFailedDelta),
			},
			CulpritPID:     khugepagedProc.PID,
			CulpritName:    khugepagedProc.Comm,
			CulpritDetails: fmt.Sprintf("khugepaged consuming %.1f%% CPU", khugepagedProc.CPUPercent),
			Remediation:    "Disable khugepaged background defragmentation: echo 0 > /sys/kernel/mm/transparent_hugepage/khugepaged/defrag or raise scan sleep time.",
		}, true
	}
	return nil, false
}

// RuleDiskDeviceIOErrHang detects disk block devices stalled with inflight requests and zero throughput.
type RuleDiskDeviceIOErrHang struct{ noSuppression }

func (r *RuleDiskDeviceIOErrHang) ID() string           { return "EDGE_DISK_DEVICE_IOERR_HANG" }
func (r *RuleDiskDeviceIOErrHang) Tier() int            { return 3 }
func (r *RuleDiskDeviceIOErrHang) IsPIDDependent() bool { return false }

func (r *RuleDiskDeviceIOErrHang) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for _, d := range diff.Disks {
		if d.IOsInProgress >= 3 && d.ReadsCompletedDelta == 0 && d.WritesCompletedDelta == 0 && d.UtilPercent >= 85.0 {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        3,
				Severity:    SeverityHigh,
				Confidence:  0.89,
				Title:       "Block Device Command Timeout or Hardware Hang",
				Explanation: fmt.Sprintf("Block device '%s' has %d in-flight I/O requests stalled at %.1f%% utilization with 0 completed reads or writes.", d.DeviceName, d.IOsInProgress, d.UtilPercent),
				Evidence: []string{
					fmt.Sprintf("Device: %s (%.1f%% utilized)", d.DeviceName, d.UtilPercent),
					fmt.Sprintf("In-Flight I/O Requests: %d stalled requests (0 completed)", d.IOsInProgress),
				},
				Remediation: "Inspect kernel dmesg for storage driver SCSI/NVMe command timeouts or bus resets, check SMART health (smartctl), or failover multipath storage route.",
			}, true
		}
	}
	return nil, false
}

// RuleKcompactdCPUSpin detects background proactive memory compaction daemon kcompactd spinning on fragmented memory.
type RuleKcompactdCPUSpin struct{ noSuppression }

func (r *RuleKcompactdCPUSpin) ID() string           { return "EDGE_KCOMPACTD_CPU_SPIN" }
func (r *RuleKcompactdCPUSpin) Tier() int            { return 3 }
func (r *RuleKcompactdCPUSpin) IsPIDDependent() bool { return true }

func (r *RuleKcompactdCPUSpin) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var kcompactdProc *collector.ProcessDiff
	for i := range diff.Processes {
		if strings.HasPrefix(diff.Processes[i].Comm, "kcompactd") && diff.Processes[i].CPUPercent >= 40.0 {
			kcompactdProc = &diff.Processes[i]
			break
		}
	}

	if kcompactdProc != nil && (diff.VMStat.CompactFailDelta > 0 || diff.VMStat.CompactStallDelta > 0 || diff.VMStat.AllocStallDirectDelta > 0) {
		return &Diagnosis{
			RuleID:         r.ID(),
			Tier:           3,
			Severity:       SeverityMedium,
			Confidence:     0.88,
			Title:          "Background Compaction Daemon (kcompactd) CPU Spin",
			Explanation:    fmt.Sprintf("Kernel memory compaction daemon '%s' is consuming %.1f%% CPU attempting to defragment memory zones under high compaction failure rates.", kcompactdProc.Comm, kcompactdProc.CPUPercent),
			Evidence: []string{
				fmt.Sprintf("PID %d [%s]: %.1f%% CPU utilization", kcompactdProc.PID, kcompactdProc.Comm, kcompactdProc.CPUPercent),
				fmt.Sprintf("Compaction Failures Delta: %d failed attempts", diff.VMStat.CompactFailDelta),
			},
			CulpritPID:     kcompactdProc.PID,
			CulpritName:    kcompactdProc.Comm,
			CulpritDetails: fmt.Sprintf("%s spinning at %.1f%% CPU", kcompactdProc.Comm, kcompactdProc.CPUPercent),
			Remediation:    "Lower proactive compaction aggressiveness: sysctl -w vm.compaction_proactiveness=20 or trigger manual compaction (echo 1 > /proc/sys/vm/compact_memory).",
		}, true
	}
	return nil, false
}

// RuleMinFreeKbytesStall detects undersized min_free_kbytes causing sudden allocation bursts to hit direct reclaim stalls.
type RuleMinFreeKbytesStall struct{ noSuppression }

func (r *RuleMinFreeKbytesStall) ID() string           { return "EDGE_MIN_FREE_KBYTES_STALL" }
func (r *RuleMinFreeKbytesStall) Tier() int            { return 3 }
func (r *RuleMinFreeKbytesStall) IsPIDDependent() bool { return false }

func (r *RuleMinFreeKbytesStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	minFreeKB := diff.LatestSnapshot.SystemConfig.MinFreeKbytes
	memTotalKB := diff.LatestSnapshot.Memory.MemTotal

	// If min_free_kbytes is set and total RAM > 2GB
	if minFreeKB > 0 && memTotalKB > 2*1024*1024 {
		// If min_free_kbytes < 0.25% of total RAM and direct allocation stalls occur
		isUndersized := minFreeKB < (memTotalKB / 400)
		if isUndersized && diff.VMStat.AllocStallDirectDelta >= 10 {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        3,
				Severity:    SeverityMedium,
				Confidence:  0.86,
				Title:       "Undersized vm.min_free_kbytes Direct Allocation Stalls",
				Explanation: fmt.Sprintf("Kernel watermark vm.min_free_kbytes (%d kB / %.2f%% RAM) is too low for fast allocation bursts, forcing processes directly into synchronous allocation stalls.", minFreeKB, (float64(minFreeKB)/float64(memTotalKB))*100.0),
				Evidence: []string{
					fmt.Sprintf("vm.min_free_kbytes: %d kB (Total RAM: %d kB)", minFreeKB, memTotalKB),
					fmt.Sprintf("Direct Reclaim / Allocation Stalls Delta: %d stalls", diff.VMStat.AllocStallDirectDelta),
				},
				Remediation: fmt.Sprintf("Raise kernel watermark to 1%%-2%% of RAM: sysctl -w vm.min_free_kbytes=%d to give kswapd headroom to reclaim asynchronously.", memTotalKB/100),
			}, true
		}
	}
	return nil, false
}

// RuleCorePatternPipeStall detects processes stuck in coredump waiting on dead or hung user-space core dumper helper.
type RuleCorePatternPipeStall struct{ noSuppression }

func (r *RuleCorePatternPipeStall) ID() string           { return "EDGE_CORE_PATTERN_PIPE_STALL" }
func (r *RuleCorePatternPipeStall) Tier() int            { return 3 }
func (r *RuleCorePatternPipeStall) IsPIDDependent() bool { return true }

func (r *RuleCorePatternPipeStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var coredumpProcs []collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.Wchan == "do_coredump" || p.Wchan == "pipe_wait" || strings.Contains(p.Wchan, "coredump") {
			if p.State == 'D' || p.State == 'S' {
				coredumpProcs = append(coredumpProcs, *p)
			}
		}
	}

	if len(coredumpProcs) >= 2 {
		return &Diagnosis{
			RuleID:         r.ID(),
			Tier:           3,
			Severity:       SeverityMedium,
			Confidence:     0.89,
			Title:          "Core Dump Handler Pipe Serialization Stall",
			Explanation:    fmt.Sprintf("%d crashing processes are hung in kernel 'do_coredump' waiting to pipe memory to a user-space core dumper helper.", len(coredumpProcs)),
			Evidence: []string{
				fmt.Sprintf("%d processes blocked in coredump wchan", len(coredumpProcs)),
				fmt.Sprintf("PID %d [%s] blocked in wchan '%s'", coredumpProcs[0].PID, coredumpProcs[0].Comm, coredumpProcs[0].Wchan),
			},
			CulpritPID:     coredumpProcs[0].PID,
			CulpritName:    coredumpProcs[0].Comm,
			CulpritDetails: fmt.Sprintf("Blocked in coredump handler '%s'", coredumpProcs[0].Wchan),
			Remediation:    "Restart systemd-coredump / apport service or reset core pattern: sysctl -w kernel.core_pattern=core, or disable core dumps (ulimit -c 0).",
		}, true
	}
	return nil, false
}

// RuleTCPPAWSDrop detects valid TCP packets dropped due to PAWS timestamp collisions behind NAT.
type RuleTCPPAWSDrop struct{ noSuppression }

func (r *RuleTCPPAWSDrop) ID() string           { return "EDGE_TCP_PAWS_DROP" }
func (r *RuleTCPPAWSDrop) Tier() int            { return 3 }
func (r *RuleTCPPAWSDrop) IsPIDDependent() bool { return false }

func (r *RuleTCPPAWSDrop) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	pawsEstab := diff.NetStat.PAWSEstabDelta
	pawsPassive := diff.NetStat.PAWSPassiveDelta

	if pawsEstab >= 10 || pawsPassive >= 10 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.88,
			Title:       "TCP PAWS Timestamp Collision Drops behind NAT",
			Explanation: fmt.Sprintf("Kernel is rejecting inbound TCP segments (%d established, %d passive drops) due to Protection Against Wrapped Sequences (PAWS) timestamp collisions through NAT gateways.", pawsEstab, pawsPassive),
			Evidence: []string{
				fmt.Sprintf("PAWSEstab Delta: %d packet drops", pawsEstab),
				fmt.Sprintf("PAWSPassive Delta: %d packet drops", pawsPassive),
			},
			Remediation: "Disable TCP timestamp verification on NAT endpoints: sysctl -w net.ipv4.tcp_timestamps=0 or ensure upstream NAT preserves client timestamps.",
		}, true
	}
	return nil, false
}

// RuleCMAZoneExhaustion detects Contiguous Memory Allocator (CMA) pool depletion.
type RuleCMAZoneExhaustion struct{ noSuppression }

func (r *RuleCMAZoneExhaustion) ID() string           { return "EDGE_CMA_ZONE_EXHAUSTION" }
func (r *RuleCMAZoneExhaustion) Tier() int            { return 3 }
func (r *RuleCMAZoneExhaustion) IsPIDDependent() bool { return false }

func (r *RuleCMAZoneExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	mem := diff.LatestSnapshot.Memory
	if mem.CmaTotal > 0 && mem.CmaFree <= (mem.CmaTotal*5)/100 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.90,
			Title:       "Contiguous Memory Allocator (CMA) Pool Exhaustion",
			Explanation: fmt.Sprintf("Kernel CMA pool (%d kB free / %d kB total) is depleted, blocking device driver DMA allocations (GPU/RDMA/camera/crypto).", mem.CmaFree, mem.CmaTotal),
			Evidence: []string{
				fmt.Sprintf("CmaTotal: %d kB", mem.CmaTotal),
				fmt.Sprintf("CmaFree: %d kB (%.1f%% remaining)", mem.CmaFree, (float64(mem.CmaFree)/float64(mem.CmaTotal))*100),
			},
			Remediation: "Increase kernel boot CMA parameter (e.g. cma=512M or cma=1G in /etc/default/grub).",
		}, true
	}
	return nil, false
}

// RuleLoopDeviceSerialization detects I/O bottlenecks on loopback block devices.
type RuleLoopDeviceSerialization struct{ noSuppression }

func (r *RuleLoopDeviceSerialization) ID() string           { return "EDGE_LOOP_DEVICE_SERIALIZATION" }
func (r *RuleLoopDeviceSerialization) Tier() int            { return 3 }
func (r *RuleLoopDeviceSerialization) IsPIDDependent() bool { return false }

func (r *RuleLoopDeviceSerialization) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for _, d := range diff.Disks {
		if strings.HasPrefix(d.DeviceName, "loop") && d.UtilPercent >= 80.0 {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        3,
				Severity:    SeverityMedium,
				Confidence:  0.87,
				Title:       "Loopback Block Device Serialization Bottleneck",
				Explanation: fmt.Sprintf("Loopback storage device '%s' is %.1f%% utilized, bottlenecking container or squashfs image I/O through single-threaded kernel workers.", d.DeviceName, d.UtilPercent),
				Evidence: []string{
					fmt.Sprintf("Loop Device: %s (%.1f%% utilized)", d.DeviceName, d.UtilPercent),
					fmt.Sprintf("Read Bytes Delta: %d B, Write Bytes Delta: %d B", d.ReadBytesDelta, d.WriteBytesDelta),
				},
				Remediation: "Migrate loopback disk images (Docker/Snap/Flatpak) to direct native ext4/XFS filesystems or raw NVMe partitions.",
			}, true
		}
	}
	return nil, false
}

// RuleRTSchedThrottling detects real-time priority tasks throttled by kernel sched_rt_runtime_us limit.
type RuleRTSchedThrottling struct{ noSuppression }

func (r *RuleRTSchedThrottling) ID() string           { return "EDGE_RT_SCHED_THROTTLING" }
func (r *RuleRTSchedThrottling) Tier() int            { return 3 }
func (r *RuleRTSchedThrottling) IsPIDDependent() bool { return true }

func (r *RuleRTSchedThrottling) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	rtLimit := diff.LatestSnapshot.SystemConfig.SchedRTRuntimeUS
	if rtLimit <= 0 {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		// Policy 1 = SCHED_FIFO, 2 = SCHED_RR
		if (p.Policy == 1 || p.Policy == 2) && p.CPUPercent >= 90.0 {
			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           3,
				Severity:       SeverityMedium,
				Confidence:     0.89,
				Title:          "Real-Time Scheduler (SCHED_FIFO/RR) Task Throttling",
				Explanation:    fmt.Sprintf("Real-time process '%s' (PID %d) is consuming %.1f%% CPU and hitting kernel sched_rt_runtime_us throttling limit (%d μs).", p.Comm, p.PID, p.CPUPercent, rtLimit),
				Evidence: []string{
					fmt.Sprintf("PID %d [%s]: Policy=%d (SCHED_FIFO/RR), CPU=%.1f%%", p.PID, p.Comm, p.Policy, p.CPUPercent),
					fmt.Sprintf("Kernel sched_rt_runtime_us: %d μs limit", rtLimit),
				},
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("Real-time process spinning at %.1f%% CPU", p.CPUPercent),
				Remediation:    "Add explicit sleep/yield calls in real-time execution loop or isolate dedicated execution cores via isolcpus.",
			}, true
		}
	}
	return nil, false
}

// RuleNumaAutoBalancingScanStall detects excessive CPU overhead from automatic NUMA page table scanning.
type RuleNumaAutoBalancingScanStall struct{ noSuppression }

func (r *RuleNumaAutoBalancingScanStall) ID() string           { return "EDGE_NUMA_AUTO_BALANCING_SCAN_STALL" }
func (r *RuleNumaAutoBalancingScanStall) Tier() int            { return 3 }
func (r *RuleNumaAutoBalancingScanStall) IsPIDDependent() bool { return false }

func (r *RuleNumaAutoBalancingScanStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	numaBalancing := diff.LatestSnapshot.SystemConfig.NumaBalancing
	pteUpdates := diff.VMStat.NumaPteUpdatesDelta

	if numaBalancing > 0 && pteUpdates >= 20000 && diff.TotalCPUUtil.SystemPercent >= 10.0 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.86,
			Title:       "Automatic NUMA Page Table Scanning CPU Overhead",
			Explanation: fmt.Sprintf("Kernel automatic NUMA balancing is consuming high system CPU (%.1f%% System CPU, %d PTE page updates) constantly scanning virtual memory mappings.", diff.TotalCPUUtil.SystemPercent, pteUpdates),
			Evidence: []string{
				fmt.Sprintf("NUMA PTE Updates Delta: %d scans", pteUpdates),
				fmt.Sprintf("System CPU: %.1f%% (Kernel NUMA Balancing Enabled)", diff.TotalCPUUtil.SystemPercent),
			},
			Remediation: "Disable automatic NUMA scanning for statically pinned workloads: sysctl -w kernel.numa_balancing=0.",
		}, true
	}
	return nil, false
}

// RuleInotifyQueueOverflow detects when inotify event queues are undersized for high-concurrency file watchers.
type RuleInotifyQueueOverflow struct{ noSuppression }

func (r *RuleInotifyQueueOverflow) ID() string           { return "EDGE_INOTIFY_QUEUE_OVERFLOW" }
func (r *RuleInotifyQueueOverflow) Tier() int            { return 3 }
func (r *RuleInotifyQueueOverflow) IsPIDDependent() bool { return false }

func (r *RuleInotifyQueueOverflow) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	inotify := diff.LatestSnapshot.SystemConfig.Inotify
	if !inotify.Available {
		return nil, false
	}

	maxQueued := inotify.MaxQueuedEvents
	if maxQueued == 0 {
		maxQueued = 16384
	}

	if maxQueued <= 16384 && inotify.MaxUserWatches >= 65536 && (diff.ContextSwitchesDelta >= 40000 || diff.ProcessesCreatedDelta >= 100) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.85,
			Title:       "Inotify File Watch Event Queue Overflow",
			Explanation: fmt.Sprintf("Kernel inotify max_queued_events limit (%d) is undersized relative to active watch tables (%d watches) during high event churn (%d context switches/sec), risking silent event drops.", maxQueued, inotify.MaxUserWatches, diff.ContextSwitchesDelta),
			Evidence: []string{
				fmt.Sprintf("Inotify max_queued_events: %d limit", maxQueued),
				fmt.Sprintf("Inotify max_user_watches: %d watches", inotify.MaxUserWatches),
				fmt.Sprintf("Context Switches Delta: %d / sec", diff.ContextSwitchesDelta),
			},
			Remediation: "Increase inotify event queue capacity: sysctl -w fs.inotify.max_queued_events=1048576.",
		}, true
	}
	return nil, false
}

// RuleCgroupCFSBurstStarvation detects latency degradation when container CPU burst credit is exhausted.
type RuleCgroupCFSBurstStarvation struct{ noSuppression }

func (r *RuleCgroupCFSBurstStarvation) ID() string           { return "EDGE_CGROUP_CFS_BURST_STARVATION" }
func (r *RuleCgroupCFSBurstStarvation) Tier() int            { return 3 }
func (r *RuleCgroupCFSBurstStarvation) IsPIDDependent() bool { return true }

func (r *RuleCgroupCFSBurstStarvation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for i := range diff.Cgroups {
		cg := &diff.Cgroups[i]
		if cg.NrBurstsDelta > 0 && cg.NrThrottledDelta > 0 && cg.ThrottledUsecDelta >= 50000 {
			throttledMS := float64(cg.ThrottledUsecDelta) / 1000.0
			burstMS := float64(cg.BurstUsecDelta) / 1000.0

			var culprit *collector.ProcessDiff
			for j := range diff.Processes {
				p := &diff.Processes[j]
				if p.CgroupPath == cg.Path {
					if culprit == nil || p.CPUPercent > culprit.CPUPercent {
						culprit = p
					}
				}
			}

			culpritPID := 0
			culpritName := ""
			culpritDetails := fmt.Sprintf("Cgroup '%s' exhausted CPU burst", cg.Path)
			if culprit != nil {
				culpritPID = culprit.PID
				culpritName = culprit.Comm
				culpritDetails = fmt.Sprintf("Process %s (PID %d) throttled after exhausting burst in %s", culprit.Comm, culprit.PID, cg.Path)
			}

			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           3,
				Severity:       SeverityMedium,
				Confidence:     0.92,
				Title:          "Cgroup v2 CFS CPU Burst Depletion & Throttling",
				Explanation:    fmt.Sprintf("Cgroup '%s' used %.1fms of CPU burst allowance (%d bursts) but subsequently suffered %.1fms of throttling (%d periods throttled).", cg.Path, burstMS, cg.NrBurstsDelta, throttledMS, cg.NrThrottledDelta),
				Evidence: []string{
					fmt.Sprintf("Cgroup Path: %s", cg.Path),
					fmt.Sprintf("CPU Burst Usage: %.1fms (%d burst events)", burstMS, cg.NrBurstsDelta),
					fmt.Sprintf("CPU Throttled: %.1fms (%d throttled periods)", throttledMS, cg.NrThrottledDelta),
				},
				CulpritPID:     culpritPID,
				CulpritName:    culpritName,
				CulpritDetails: culpritDetails,
				Remediation:    fmt.Sprintf("Increase CFS CPU burst allowance: echo 'max 200000' > /sys/fs/cgroup%s/cpu.max.burst (or configure CPU burst in container runtime).", cg.Path),
			}, true
		}
	}
	return nil, false
}

// RuleZswapCompressorContention detects CPU and memory stalls in Linux Zswap compression pools.
type RuleZswapCompressorContention struct{ noSuppression }

func (r *RuleZswapCompressorContention) ID() string           { return "EDGE_ZSWAP_COMPRESSOR_CONTENTION" }
func (r *RuleZswapCompressorContention) Tier() int            { return 3 }
func (r *RuleZswapCompressorContention) IsPIDDependent() bool { return false }

func (r *RuleZswapCompressorContention) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	zswpout := diff.VMStat.ZswpoutDelta
	rejects := diff.VMStat.ZswapRejectReclaimFailDelta
	allocStalls := diff.VMStat.AllocStallDirectDelta
	sysPercent := diff.TotalCPUUtil.SystemPercent

	if (zswpout >= 500 || rejects > 0) && (allocStalls > 0 || sysPercent >= 20.0) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.86,
			Title:       "Zswap Compression Pool Saturation & Reclaim Spin",
			Explanation: fmt.Sprintf("Linux Zswap compression pool is under heavy churn (%d compressed page stores, %d pool reject failures) causing memory direct reclaim stalls and high kernel CPU overhead (%.1f%% System CPU).", zswpout, rejects, sysPercent),
			Evidence: []string{
				fmt.Sprintf("Zswap Page Out Delta: %d pages", zswpout),
				fmt.Sprintf("Zswap Reject/Fail Delta: %d rejects", rejects),
				fmt.Sprintf("Direct Memory Reclaim Stalls: %d stalls", allocStalls),
				fmt.Sprintf("System CPU: %.1f%%", sysPercent),
			},
			Remediation: "Increase Zswap memory pool ceiling and tune fast compression: echo 30 > /sys/module/zswap/parameters/max_pool_percent && echo lz4 > /sys/module/zswap/parameters/compressor.",
		}, true
	}
	return nil, false
}

// RuleNetIfaceCarrierFlap detects physical network interface link flapping and transmission errors.
type RuleNetIfaceCarrierFlap struct{ noSuppression }

func (r *RuleNetIfaceCarrierFlap) ID() string           { return "EDGE_NET_IFACE_CARRIER_FLAP" }
func (r *RuleNetIfaceCarrierFlap) Tier() int            { return 3 }
func (r *RuleNetIfaceCarrierFlap) IsPIDDependent() bool { return false }

func (r *RuleNetIfaceCarrierFlap) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var flappingIface *collector.NetIfaceDiff
	for i := range diff.NetIfaces {
		iface := &diff.NetIfaces[i]
		if iface.CarrierChangesDelta >= 3 && (iface.RxCRCErrorsDelta > 0 || iface.TxCarrierErrorsDelta > 0 || iface.OperState != "up") {
			flappingIface = iface
			break
		}
	}

	if flappingIface == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Interface '%s' Carrier Changes Delta: %d state transitions", flappingIface.Name, flappingIface.CarrierChangesDelta),
		fmt.Sprintf("Operational State: '%s'", flappingIface.OperState),
		fmt.Sprintf("RX CRC / Alignment Errors Delta: %d", flappingIface.RxCRCErrorsDelta),
		fmt.Sprintf("TX Carrier / Link Errors Delta: %d", flappingIface.TxCarrierErrorsDelta),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.90,
		Title:       fmt.Sprintf("Network Interface Carrier Flapping & Link Errors (%s)", flappingIface.Name),
		Explanation: fmt.Sprintf("Network interface '%s' is rapidly flapping link state (%d carrier state changes) with hardware/CRC errors, dropping packets and disrupting network routing.", flappingIface.Name, flappingIface.CarrierChangesDelta),
		Evidence:    evidence,
		Remediation: fmt.Sprintf("Reset network link: ip link set %s down && ip link set %s up or inspect physical cabling / SFP optics and switch port auto-negotiation.", flappingIface.Name, flappingIface.Name),
	}, true
}

// RuleTHPAllocFallbackStall detects Transparent HugePage direct allocation failures splitting to 4KB pages.
type RuleTHPAllocFallbackStall struct{ noSuppression }

func (r *RuleTHPAllocFallbackStall) ID() string           { return "EDGE_THP_ALLOC_FALLBACK_STALL" }
func (r *RuleTHPAllocFallbackStall) Tier() int            { return 3 }
func (r *RuleTHPAllocFallbackStall) IsPIDDependent() bool { return false }

func (r *RuleTHPAllocFallbackStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	thpFallback := diff.VMStat.THPFaultFallbackDelta
	collapseFail := diff.VMStat.THPCollapseAllocFailedDelta
	compactStalls := diff.VMStat.CompactStallDelta
	allocStalls := diff.VMStat.AllocStallDirectDelta

	if (thpFallback >= 500 || collapseFail >= 20) && (compactStalls > 0 || allocStalls > 0) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.88,
			Title:       "Transparent HugePage Allocation Direct Reclaim Fallback",
			Explanation: fmt.Sprintf("Kernel aborted %d hugepage allocations due to physical memory fragmentation, synchronously falling back to 512x 4KB split allocations and direct reclaim stalls.", thpFallback),
			Evidence: []string{
				fmt.Sprintf("THP Fault Fallback Delta: %d allocations", thpFallback),
				fmt.Sprintf("THP Collapse Alloc Failed Delta: %d", collapseFail),
				fmt.Sprintf("Direct Reclaim / Allocation Stalls: %d stalls", allocStalls),
				fmt.Sprintf("Memory Compaction Stalls: %d stalls", compactStalls),
			},
			Remediation: "Switch THP to madvise mode and trigger defragmentation: echo madvise > /sys/kernel/mm/transparent_hugepage/enabled && echo 1 > /proc/sys/vm/compact_memory.",
		}, true
	}

	return nil, false
}

// RuleSchedMigrationBounce detects aggressive CPU scheduler cross-NUMA task bouncing.
type RuleSchedMigrationBounce struct{ noSuppression }

func (r *RuleSchedMigrationBounce) ID() string           { return "EDGE_SCHED_MIGRATION_BOUNCE" }
func (r *RuleSchedMigrationBounce) Tier() int            { return 3 }
func (r *RuleSchedMigrationBounce) IsPIDDependent() bool { return false }

func (r *RuleSchedMigrationBounce) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	costNS := diff.LatestSnapshot.SystemConfig.SchedMigrationCostNS
	if costNS > 0 && costNS <= 25000 {
		numaMiss := diff.VMStat.NumaMissDelta
		cswitches := diff.ContextSwitchesDelta
		busyCPU := diff.TotalCPUUtil.BusyPercent

		if numaMiss >= 2500 || (cswitches >= 35000 && busyCPU >= 50.0) {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        3,
				Severity:    SeverityMedium,
				Confidence:  0.85,
				Title:       "Aggressive CPU Scheduler NUMA Task Migration Churn",
				Explanation: fmt.Sprintf("Kernel parameter sched_migration_cost_ns is configured too aggressively low (%d ns / %.1f μs), causing scheduler to rapidly migrate cache-hot tasks across NUMA nodes.", costNS, float64(costNS)/1000.0),
				Evidence: []string{
					fmt.Sprintf("kernel.sched_migration_cost_ns: %d ns (recommended: >= 500000 ns)", costNS),
					fmt.Sprintf("NUMA Node Miss Delta: %d remote accesses", numaMiss),
					fmt.Sprintf("Context Switches Delta: %d / sec", cswitches),
					fmt.Sprintf("Total CPU Busy: %.1f%%", busyCPU),
				},
				Remediation: "Restore standard scheduler migration cost: sysctl -w kernel.sched_migration_cost_ns=500000 to maintain CPU cache affinity.",
			}, true
		}
	}

	return nil, false
}

// RuleIPFragReasmDrops detects network IP fragment reassembly failures and timeouts.
type RuleIPFragReasmDrops struct{ noSuppression }

func (r *RuleIPFragReasmDrops) ID() string           { return "EDGE_IP_FRAG_REASM_DROPS" }
func (r *RuleIPFragReasmDrops) Tier() int            { return 3 }
func (r *RuleIPFragReasmDrops) IsPIDDependent() bool { return false }

func (r *RuleIPFragReasmDrops) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	fails := diff.NetStat.IPReasmFailsDelta
	timeout := diff.NetStat.IPReasmTimeoutDelta
	if fails < 10 && timeout < 5 {
		return nil, false
	}

	reqds := diff.NetStat.IPReasmReqdsDelta
	udpErr := diff.NetStat.UDPRcvbufErrorsDelta
	if reqds < 20 && udpErr == 0 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("IP Reassembly Failures Delta: %d", fails),
		fmt.Sprintf("IP Reassembly Timeouts Delta: %d", timeout),
		fmt.Sprintf("IP Reassembly Requests Delta: %d", reqds),
		fmt.Sprintf("UDP Receive Buffer Errors Delta: %d", udpErr),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.85,
		Title:       "IP Packet Fragment Reassembly Queue Drops",
		Explanation: fmt.Sprintf("Kernel IP stack is failing to reassemble fragmented packets (%d failures, %d timeouts across %d requests), causing network timeouts for UDP/DNS/overlay traffic.", fails, timeout, reqds),
		Evidence:    evidence,
		Remediation: "Increase IP fragment reassembly memory limits: sysctl -w net.ipv4.ipfrag_high_thresh=4194304 && sysctl -w net.ipv4.ipfrag_time=60.",
	}, true
}

// RuleCgroupV2FreezeHang detects containers or cgroups stalled in frozen state.
type RuleCgroupV2FreezeHang struct{ noSuppression }

func (r *RuleCgroupV2FreezeHang) ID() string           { return "EDGE_CGROUP_V2_FREEZE_HANG" }
func (r *RuleCgroupV2FreezeHang) Tier() int            { return 3 }
func (r *RuleCgroupV2FreezeHang) IsPIDDependent() bool { return true }

func (r *RuleCgroupV2FreezeHang) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	isFrozen := diff.LatestSnapshot.Cgroups.Frozen
	var frozenProc *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.Wchan == "cgroup_freeze_task" || p.Wchan == "cgroup_do_freeze" || isFrozen {
			if p.State == 'D' || p.State == 'T' || p.State == 'S' {
				frozenProc = p
				break
			}
		}
	}

	if frozenProc == nil && !isFrozen {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Cgroup Subtree Frozen: %t", isFrozen),
	}
	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.96,
		Title:       "Cgroup v2 Container Subtree Frozen State Stall",
		Explanation: "A container or cgroup subtree is currently in a frozen state via cgroup.freeze, suspending all process execution in kernel space and failing health checks.",
		Evidence:    evidence,
		Remediation: "Unfreeze the container cgroup: echo 0 > /sys/fs/cgroup/<path>/cgroup.freeze.",
	}
	if frozenProc != nil {
		diag.CulpritPID = frozenProc.PID
		diag.CulpritName = frozenProc.Comm
		diag.CulpritDetails = fmt.Sprintf("Process in cgroup '%s' (State: %c, Wchan: '%s')", frozenProc.CgroupPath, frozenProc.State, frozenProc.Wchan)
		diag.Evidence = append(diag.Evidence, fmt.Sprintf("Frozen PID: %d [%s] (wchan: '%s', cgroup: '%s')", frozenProc.PID, frozenProc.Comm, frozenProc.Wchan, frozenProc.CgroupPath))
	}
	return diag, true
}

// RuleSysVShmSegmentLimit detects System V shared memory segment table capacity saturation.
type RuleSysVShmSegmentLimit struct{ noSuppression }

func (r *RuleSysVShmSegmentLimit) ID() string           { return "EDGE_SYSV_SHM_SEGMENT_LIMIT" }
func (r *RuleSysVShmSegmentLimit) Tier() int            { return 3 }
func (r *RuleSysVShmSegmentLimit) IsPIDDependent() bool { return false }

func (r *RuleSysVShmSegmentLimit) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	shm := diff.LatestSnapshot.SystemConfig.SysVShm
	if !shm.Available {
		return nil, false
	}

	segRatio := 0.0
	if shm.ShmMNI > 0 {
		segRatio = float64(shm.AllocatedSegments) / float64(shm.ShmMNI)
	}

	pageRatio := 0.0
	if shm.ShmAll > 0 {
		pageRatio = float64(shm.AllocatedPages) / float64(shm.ShmAll)
	}

	if segRatio < 0.90 && pageRatio < 0.90 {
		return nil, false
	}

	mem := diff.LatestSnapshot.Memory
	hasCorroboration := (mem.MemTotal > 0 && mem.Shmem >= mem.MemTotal/5) || shm.AllocatedSegments >= 3000
	if !hasCorroboration {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Allocated Segments: %d / %d (%.1f%% of kernel.shmmni)", shm.AllocatedSegments, shm.ShmMNI, segRatio*100),
		fmt.Sprintf("Allocated Pages: %d / %d (%.1f%% of kernel.shmall)", shm.AllocatedPages, shm.ShmAll, pageRatio*100),
		fmt.Sprintf("Total Shared Memory: %d kB (%.1f%% of RAM)", mem.Shmem, float64(mem.Shmem)/float64(mem.MemTotal)*100),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.91,
		Title:       "System V Shared Memory Segment Table Exhaustion",
		Explanation: fmt.Sprintf("Active System V shared memory segments (%d/%d, %.1f%%) or pages are nearing kernel limits, risking shmget() ENOSPC/ENOMEM failures for databases.", shm.AllocatedSegments, shm.ShmMNI, segRatio*100),
		Evidence:    evidence,
		Remediation: "Increase SysV shared memory segment and page ceilings: sysctl -w kernel.shmmni=8192 && sysctl -w kernel.shmall=4294967296.",
	}, true
}

// RuleNetDevRxNoBuffers detects network interface driver RX ring buffer depletion and missed frames.
type RuleNetDevRxNoBuffers struct{ noSuppression }

func (r *RuleNetDevRxNoBuffers) ID() string           { return "EDGE_NET_DEV_RX_NO_BUFFERS" }
func (r *RuleNetDevRxNoBuffers) Tier() int            { return 3 }
func (r *RuleNetDevRxNoBuffers) IsPIDDependent() bool { return false }

func (r *RuleNetDevRxNoBuffers) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culpritIface string
	var missed, fifo uint64
	for _, iface := range diff.NetIfaces {
		if iface.OperState == "up" && (iface.RxMissedErrorsDelta >= 20 || iface.RxFIFOErrorsDelta >= 20) {
			culpritIface = iface.Name
			missed = iface.RxMissedErrorsDelta
			fifo = iface.RxFIFOErrorsDelta
			break
		}
	}

	if culpritIface == "" {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Interface '%s' RX Missed Errors Delta: %d frames", culpritIface, missed),
		fmt.Sprintf("Interface '%s' RX FIFO Errors Delta: %d frames", culpritIface, fifo),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.89,
		Title:       "NIC Driver RX Ring Buffer Exhaustion Drops",
		Explanation: fmt.Sprintf("Network interface '%s' dropped %d frames at the hardware DMA/ring buffer layer due to descriptor exhaustion.", culpritIface, missed+fifo),
		Evidence:    evidence,
		Remediation: fmt.Sprintf("Increase NIC receive ring buffer size: ethtool -G %s rx 4096 and raise netdev backlog: sysctl -w net.core.netdev_max_backlog=10000.", culpritIface),
	}, true
}

// RuleTHPDefragAlways detects aggressive synchronous THP defragmentation mode.
type RuleTHPDefragAlways struct{ noSuppression }

func (r *RuleTHPDefragAlways) ID() string           { return "EDGE_TRANSPARENT_HUGEPAGE_DEFRAG_ALWAYS" }
func (r *RuleTHPDefragAlways) Tier() int            { return 3 }
func (r *RuleTHPDefragAlways) IsPIDDependent() bool { return false }

func (r *RuleTHPDefragAlways) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	mode := diff.LatestSnapshot.SystemConfig.THPDefragMode
	if mode != "always" {
		return nil, false
	}

	compactStalls := diff.VMStat.CompactStallDelta
	allocStalls := diff.VMStat.AllocStallDirectDelta
	if compactStalls < 15 && allocStalls < 5 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Kernel THP defrag setting: '%s' (recommended: 'madvise')", mode),
		fmt.Sprintf("Memory Compaction Stalls Delta: %d", compactStalls),
		fmt.Sprintf("Direct Allocation Stalls Delta: %d", allocStalls),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.86,
		Title:       "Aggressive Synchronous THP Defragmentation Stall",
		Explanation: "Transparent HugePage defragmentation is configured to 'always', forcing synchronous 2MB page compaction on regular allocations under fragmentation.",
		Evidence:    evidence,
		Remediation: "Switch THP defragmentation to asynchronous madvise: echo madvise > /sys/kernel/mm/transparent_hugepage/defrag.",
	}, true
}

// RuleCgroupMemoryMaxOOMStall detects container memory.max hard limit reclaim stalls.
type RuleCgroupMemoryMaxOOMStall struct{ noSuppression }

func (r *RuleCgroupMemoryMaxOOMStall) ID() string           { return "EDGE_CGROUP_MEMORY_MAX_OOM_STALL" }
func (r *RuleCgroupMemoryMaxOOMStall) Tier() int            { return 3 }
func (r *RuleCgroupMemoryMaxOOMStall) IsPIDDependent() bool { return true }

func (r *RuleCgroupMemoryMaxOOMStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var maxPath string
	var maxDelta uint64
	for _, cg := range diff.Cgroups {
		if cg.MemEventsMaxDelta >= 5 {
			maxPath = cg.Path
			maxDelta = cg.MemEventsMaxDelta
			break
		}
	}

	if maxPath == "" {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.CgroupPath == maxPath {
			culprit = p
			break
		}
	}

	evidence := []string{
		fmt.Sprintf("Cgroup '%s' memory.max hits: %d events", maxPath, maxDelta),
	}
	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.90,
		Title:       "Cgroup v2 Container Memory Max Limit Reclaim Stall",
		Explanation: fmt.Sprintf("Cgroup '%s' hit its memory.max ceiling %d times, forcing synchronous container direct reclamation before OOM killer execution.", maxPath, maxDelta),
		Evidence:    evidence,
		Remediation: fmt.Sprintf("Increase container hard memory ceiling: docker update --memory=<limit> <container> or echo <bytes> > /sys/fs/cgroup%s/memory.max.", maxPath),
	}
	if culprit != nil {
		diag.CulpritPID = culprit.PID
		diag.CulpritName = culprit.Comm
		diag.CulpritDetails = fmt.Sprintf("Process in maxed cgroup '%s'", maxPath)
	}
	return diag, true
}

// RuleTHPScanExhaustionStall detects background khugepaged scanning exhaustion under memory fragmentation.
type RuleTHPScanExhaustionStall struct{ noSuppression }

func (r *RuleTHPScanExhaustionStall) ID() string           { return "EDGE_THP_SCAN_EXHAUSTION_STALL" }
func (r *RuleTHPScanExhaustionStall) Tier() int            { return 3 }
func (r *RuleTHPScanExhaustionStall) IsPIDDependent() bool { return false }

func (r *RuleTHPScanExhaustionStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	scansExceeded := diff.VMStat.THPScanExceedDelta
	if scansExceeded < 50 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Transparent HugePages Scan Exceeded Delta: %d events", scansExceeded),
		fmt.Sprintf("Direct Compaction Stalls Delta: %d", diff.VMStat.CompactStallDelta),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.86,
		Title:       "Transparent HugePages Daemon Scan Rate Exhaustion",
		Explanation: fmt.Sprintf("Kernel khugepaged daemon exceeded max scan limits %d times without completing 2MB collapses, burning CPU scanning fragmented pages.", scansExceeded),
		Evidence:    evidence,
		Remediation: "Tune khugepaged scan batching: echo 512 > /sys/kernel/mm/transparent_hugepage/khugepaged/pages_to_scan.",
	}, true
}

// RuleNetDevTxQueueTimeout detects network interface transmit queue watchdog timeouts and driver drops.
type RuleNetDevTxQueueTimeout struct{ noSuppression }

func (r *RuleNetDevTxQueueTimeout) ID() string           { return "EDGE_NET_DEV_TX_QUEUE_TIMEOUT" }
func (r *RuleNetDevTxQueueTimeout) Tier() int            { return 3 }
func (r *RuleNetDevTxQueueTimeout) IsPIDDependent() bool { return false }

func (r *RuleNetDevTxQueueTimeout) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culpritIface string
	var txErr, txCarrier uint64
	for _, iface := range diff.NetIfaces {
		if iface.OperState == "up" && (iface.TxErrorsDelta >= 20 || iface.TxCarrierErrorsDelta >= 5) {
			culpritIface = iface.Name
			txErr = iface.TxErrorsDelta
			txCarrier = iface.TxCarrierErrorsDelta
			break
		}
	}

	if culpritIface == "" {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Interface '%s' Transmit Errors Delta: %d packets", culpritIface, txErr),
		fmt.Sprintf("Interface '%s' Transmit Carrier Errors Delta: %d", culpritIface, txCarrier),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.88,
		Title:       "NIC Driver Transmit Queue Timeout & Drop",
		Explanation: fmt.Sprintf("Network interface '%s' encountered %d transmit queue errors / watchdog timeouts, stalling outbound network traffic.", culpritIface, txErr+txCarrier),
		Evidence:    evidence,
		Remediation: fmt.Sprintf("Reset link: ip link set %s down && ip link set %s up or check NIC driver/firmware.", culpritIface, culpritIface),
	}, true
}

// RuleCgroupCPUCorePinStarvation detects container processes pinned to a single overloaded CPU while host is idle.
type RuleCgroupCPUCorePinStarvation struct{ noSuppression }

func (r *RuleCgroupCPUCorePinStarvation) ID() string           { return "EDGE_CGROUP_CPU_CORE_PIN_STARVATION" }
func (r *RuleCgroupCPUCorePinStarvation) Tier() int            { return 3 }
func (r *RuleCgroupCPUCorePinStarvation) IsPIDDependent() bool { return true }

func (r *RuleCgroupCPUCorePinStarvation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	if diff.TotalCPUUtil.IdlePercent < 50.0 {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.CgroupPath != "" && p.CgroupPath != "/" && p.CpusAllowed == 1 && p.CPUPercent >= 85.0 {
			culprit = p
			break
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] Cgroup: '%s'", culprit.PID, culprit.Comm, culprit.CgroupPath),
		fmt.Sprintf("Cpus Allowed: %d mask, Process CPU: %.1f%%", culprit.CpusAllowed, culprit.CPUPercent),
		fmt.Sprintf("Overall Host CPU Idle: %.1f%%", diff.TotalCPUUtil.IdlePercent),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           3,
		Severity:       SeverityMedium,
		Confidence:     0.90,
		Title:          "Container Cgroup Single CPU Core Pin Starvation",
		Explanation:    fmt.Sprintf("Container process %s (PID %d in '%s') is pinned to 1 CPU core at %.1f%% CPU while host is %.1f%% idle.", culprit.Comm, culprit.PID, culprit.CgroupPath, culprit.CPUPercent, diff.TotalCPUUtil.IdlePercent),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Pinned to 1 core in %s", culprit.CgroupPath),
		Remediation:    fmt.Sprintf("Expand container cpuset: echo 0-$(nproc -1) > /sys/fs/cgroup%s/cpuset.cpus or docker update --cpuset-cpus.", culprit.CgroupPath),
	}, true
}

// RuleHugeTLBVMAFaultMisalign detects virtual memory area unaligned HugeTLB faults and allocation fallbacks.
type RuleHugeTLBVMAFaultMisalign struct{ noSuppression }

func (r *RuleHugeTLBVMAFaultMisalign) ID() string           { return "EDGE_HUGETLB_VMA_MISALIGN_FAULT" }
func (r *RuleHugeTLBVMAFaultMisalign) Tier() int            { return 3 }
func (r *RuleHugeTLBVMAFaultMisalign) IsPIDDependent() bool { return false }

func (r *RuleHugeTLBVMAFaultMisalign) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	fallback := diff.VMStat.THPFaultFallbackDelta
	alloc := diff.VMStat.THPFaultAllocDelta
	if fallback < 50 || (alloc > 0 && fallback < alloc*2) {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Transparent HugePage Fault Fallbacks Delta: %d events", fallback),
		fmt.Sprintf("Successful HugePage Fault Allocations Delta: %d", alloc),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.86,
		Title:       "HugePage VMA Fault Misalignment & Allocation Fallback",
		Explanation: fmt.Sprintf("Application generated %d hugepage page-fault fallbacks without successful 2MB allocations due to unaligned virtual memory mappings or memory fragmentation.", fallback),
		Evidence:    evidence,
		Remediation: "Ensure mmap/madvise allocations are 2MB-aligned: posix_memalign(&ptr, 2*1024*1024, size) or check transparent_hugepage settings.",
	}, true
}

// RuleTCPChronicRTOCollapse detects chronic TCP Retransmission Timeouts and congestion window collapse.
type RuleTCPChronicRTOCollapse struct{ noSuppression }

func (r *RuleTCPChronicRTOCollapse) ID() string           { return "EDGE_TCP_CHRONIC_RTO_COLLAPSE" }
func (r *RuleTCPChronicRTOCollapse) Tier() int            { return 3 }
func (r *RuleTCPChronicRTOCollapse) IsPIDDependent() bool { return false }

func (r *RuleTCPChronicRTOCollapse) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	timeouts := diff.NetStat.TCPTimeoutsDelta
	retrans := diff.NetStat.RetransSegsDelta
	spurious := diff.NetStat.TCPSpuriousRtxHostDelta

	if timeouts < 15 && !(timeouts >= 5 && retrans >= 50) {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCP Retransmit Timeouts (RTO) Delta: %d timer expirations", timeouts),
		fmt.Sprintf("TCP Retransmitted Segments Delta: %d", retrans),
	}
	if spurious > 0 {
		evidence = append(evidence, fmt.Sprintf("Spurious Retransmit Host Delta: %d", spurious))
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.88,
		Title:       "Chronic TCP Retransmission Timeout (RTO) Window Collapse",
		Explanation: fmt.Sprintf("TCP connections encountered %d Retransmission Timeout (RTO) events, resetting congestion window (cwnd) to 1 MSS and stalling transmission.", timeouts),
		Evidence:    evidence,
		Remediation: "Inspect network path loss / jitter with mtr/ping or tune TCP RTO limits: sysctl -w net.ipv4.tcp_min_rto_ms=50.",
	}, true
}

// RuleMemcgSockMemoryThrottle detects container memory cgroup socket buffer charge throttling.
type RuleMemcgSockMemoryThrottle struct{ noSuppression }

func (r *RuleMemcgSockMemoryThrottle) ID() string           { return "EDGE_MEMCG_SOCK_MEMORY_THROTTLE" }
func (r *RuleMemcgSockMemoryThrottle) Tier() int            { return 3 }
func (r *RuleMemcgSockMemoryThrottle) IsPIDDependent() bool { return true }

func (r *RuleMemcgSockMemoryThrottle) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culpritCgroup string
	for _, cg := range diff.Cgroups {
		if cg.MemoryHighEventsDelta > 0 && cg.Path != "/" {
			culpritCgroup = cg.Path
			break
		}
	}

	if culpritCgroup == "" {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.CgroupPath == culpritCgroup && (p.ReadBytesDelta > 0 || p.WriteBytesDelta > 0 || p.OpenFDs >= 10) {
			culprit = p
			break
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Cgroup: '%s'", culpritCgroup),
		fmt.Sprintf("Process PID %d [%s] Open FDs: %d", culprit.PID, culprit.Comm, culprit.OpenFDs),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           3,
		Severity:       SeverityMedium,
		Confidence:     0.85,
		Title:          "Memory Cgroup Socket Buffer Charge Throttle",
		Explanation:    fmt.Sprintf("Process %s (PID %d in '%s') is incurring socket memory charge pressure against cgroup limits.", culprit.Comm, culprit.PID, culpritCgroup),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Throttled in cgroup %s", culpritCgroup),
		Remediation:    "Increase container memory limit or exclude socket buffers from cgroup accounting.",
	}, true
}

// RuleTHPUseZeroPageSpin detects Transparent HugePage zero-page read-fault lock contention and CPU spin.
type RuleTHPUseZeroPageSpin struct{ noSuppression }

func (r *RuleTHPUseZeroPageSpin) ID() string           { return "EDGE_TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_SPIN" }
func (r *RuleTHPUseZeroPageSpin) Tier() int            { return 3 }
func (r *RuleTHPUseZeroPageSpin) IsPIDDependent() bool { return false }

func (r *RuleTHPUseZeroPageSpin) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	zeroAllocs := diff.VMStat.THPZeroPageAllocDelta
	sysCPU := diff.TotalCPUUtil.SystemPercent

	if zeroAllocs < 100 || sysCPU < 15.0 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("THP Zero Page Allocations Delta: %d events", zeroAllocs),
		fmt.Sprintf("Kernel System CPU Utilization: %.1f%%", sysCPU),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.87,
		Title:       "Transparent HugePage Zero-Page Lock Contention & CPU Spin",
		Explanation: fmt.Sprintf("Aggressive THP zero-page collapsing (%d zero page allocations) is causing kernel page-table lock contention under %.1f%% system CPU.", zeroAllocs, sysCPU),
		Evidence:    evidence,
		Remediation: "Disable THP zero page sharing: echo 0 > /sys/kernel/mm/transparent_hugepage/use_zero_page.",
	}, true
}

// RuleSysfsCPUHotplugLockContention detects serialization on kernel CPU hotplug or governor policy locks.
type RuleSysfsCPUHotplugLockContention struct{ noSuppression }

func (r *RuleSysfsCPUHotplugLockContention) ID() string           { return "EDGE_SYSFS_CPU_HOTPLUG_LOCK_CONTENTION" }
func (r *RuleSysfsCPUHotplugLockContention) Tier() int            { return 3 }
func (r *RuleSysfsCPUHotplugLockContention) IsPIDDependent() bool { return true }

func (r *RuleSysfsCPUHotplugLockContention) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "cpu_hotplug_lock" || p.Wchan == "cpuset_mutex" || p.Wchan == "cpufreq_policy_rwsem") && (p.State == 'D' || p.CPUPercent < 1.0) {
			culprit = p
			break
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] blocked in CPU hotplug wchan: '%s'", culprit.PID, culprit.Comm, culprit.Wchan),
		fmt.Sprintf("State: %c, Threads: %d", culprit.State, culprit.NumThreads),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           3,
		Severity:       SeverityMedium,
		Confidence:     0.89,
		Title:          "Kernel CPU Hotplug / Governor Policy Lock Contention",
		Explanation:    fmt.Sprintf("Process %s (PID %d) is blocked on CPU subsystem topology locks (%s), stalling thread dispatch and affinity binding.", culprit.Comm, culprit.PID, culprit.Wchan),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("Blocked on CPU hotplug lock '%s'", culprit.Wchan),
		Remediation:    "Lock CPU scaling governors to 'performance' mode: cpupower frequency-set -g performance.",
	}, true
}

// RuleNetIPMulticastIGMPReportStall detects IP multicast group report queue saturation and packet drops.
type RuleNetIPMulticastIGMPReportStall struct{ noSuppression }

func (r *RuleNetIPMulticastIGMPReportStall) ID() string           { return "EDGE_NET_IP_MULTICAST_IGMP_REPORT_STALL" }
func (r *RuleNetIPMulticastIGMPReportStall) Tier() int            { return 3 }
func (r *RuleNetIPMulticastIGMPReportStall) IsPIDDependent() bool { return false }

func (r *RuleNetIPMulticastIGMPReportStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	udpInErr := diff.NetStat.UDPInErrorsDelta
	rcvErr := diff.NetStat.UDPRcvbufErrorsDelta

	if udpInErr < 50 && (udpInErr < 20 || rcvErr < 10) {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("UDP Inbound Errors Delta: %d drops", udpInErr),
		fmt.Sprintf("UDP Receive Buffer Errors Delta: %d drops", rcvErr),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.86,
		Title:       "IP Multicast / UDP Broadcast Socket Buffer Queue Drop",
		Explanation: fmt.Sprintf("Multicast / UDP socket queues encountered %d inbound packet drops, degrading cluster discovery and broadcast replication.", udpInErr+rcvErr),
		Evidence:    evidence,
		Remediation: "Increase multicast membership limits: sysctl -w net.ipv4.igmp_max_memberships=1024 and enlarge UDP buffer sizes.",
	}, true
}

// RuleProcPIDTaskPthreadLimit detects processes approaching thread limits or exhaustion of thread resources.
type RuleProcPIDTaskPthreadLimit struct{ noSuppression }

func (r *RuleProcPIDTaskPthreadLimit) ID() string           { return "EDGE_PROC_PID_TASK_PTHREAD_LIMIT" }
func (r *RuleProcPIDTaskPthreadLimit) Tier() int            { return 3 }
func (r *RuleProcPIDTaskPthreadLimit) IsPIDDependent() bool { return true }

func (r *RuleProcPIDTaskPthreadLimit) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var culprit *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.NumThreads >= 500 {
			culprit = p
			break
		}
	}

	if culprit == nil {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Process PID %d [%s] Active Threads: %d", culprit.PID, culprit.Comm, culprit.NumThreads),
		fmt.Sprintf("Process State: %c, CPU: %.1f%%", culprit.State, culprit.CPUPercent),
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           3,
		Severity:       SeverityMedium,
		Confidence:     0.88,
		Title:          "Process POSIX Pthread Count Limit Saturation",
		Explanation:    fmt.Sprintf("Process %s (PID %d) has spawned %d active threads, risking pthread_create memory allocation failures (EAGAIN) and high context switch overhead.", culprit.Comm, culprit.PID, culprit.NumThreads),
		Evidence:       evidence,
		CulpritPID:     culprit.PID,
		CulpritName:    culprit.Comm,
		CulpritDetails: fmt.Sprintf("High thread count (%d threads)", culprit.NumThreads),
		Remediation:    "Reduce worker thread pool size or raise thread and memory map ceilings: sysctl -w vm.max_map_count=262144 && sysctl -w kernel.threads-max=2097152.",
	}, true
}

// RuleZoneNormalFragmentation detects severe order-0 fragmentation in the Normal memory zone.
type RuleZoneNormalFragmentation struct{ noSuppression }

func (r *RuleZoneNormalFragmentation) ID() string           { return "EDGE_ZONE_NORMAL_FRAGMENTATION" }
func (r *RuleZoneNormalFragmentation) Tier() int            { return 3 }
func (r *RuleZoneNormalFragmentation) IsPIDDependent() bool { return false }

func (r *RuleZoneNormalFragmentation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	buddy := &diff.LatestSnapshot.SystemConfig.BuddyInfo
	if !buddy.Available || buddy.NormalFreePages == 0 {
		return nil, false
	}

	if buddy.NormalOrder0Pages >= 500 && buddy.NormalHighOrderPages == 0 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.88,
			Title:       "Normal Memory Zone High-Order Allocation Fragmentation",
			Explanation: fmt.Sprintf("Normal memory zone has %d free 4KB pages but 0 free contiguous high-order chunks (order >= 3), causing latency in kernel socket buffers and DMA allocations.", buddy.NormalOrder0Pages),
			Evidence: []string{
				fmt.Sprintf("Normal Zone Order-0 Free Pages: %d pages", buddy.NormalOrder0Pages),
				"Normal Zone High-Order (>= 32KB) Free Chunks: 0 chunks",
			},
			Remediation: "Trigger immediate kernel memory compaction: echo 1 > /proc/sys/vm/compact_memory.",
		}, true
	}

	return nil, false
}

// RuleNetDevCarrierDownDrop detects packet transmission attempts over down or dormant network interfaces.
type RuleNetDevCarrierDownDrop struct{ noSuppression }

func (r *RuleNetDevCarrierDownDrop) ID() string           { return "EDGE_NET_DEV_CARRIER_DOWN_DROP" }
func (r *RuleNetDevCarrierDownDrop) Tier() int            { return 3 }
func (r *RuleNetDevCarrierDownDrop) IsPIDDependent() bool { return false }

func (r *RuleNetDevCarrierDownDrop) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for _, iface := range diff.NetIfaces {
		if (iface.OperState == "down" || iface.OperState == "dormant") && (iface.TxErrorsDelta > 0 || iface.TxCarrierErrorsDelta > 0) {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        3,
				Severity:    SeverityMedium,
				Confidence:  0.92,
				Title:       fmt.Sprintf("Packet Transmission on Down Interface (%s)", iface.Name),
				Explanation: fmt.Sprintf("Network interface '%s' is in '%s' state with %d transmission errors during the sampling window.", iface.Name, iface.OperState, iface.TxErrorsDelta+iface.TxCarrierErrorsDelta),
				Evidence: []string{
					fmt.Sprintf("Interface: %s (State: %s)", iface.Name, iface.OperState),
					fmt.Sprintf("Tx Errors Delta: %d, Tx Carrier Errors Delta: %d", iface.TxErrorsDelta, iface.TxCarrierErrorsDelta),
				},
				Remediation: fmt.Sprintf("Bring network interface up: ip link set %s up and verify physical/virtual cable connection.", iface.Name),
			}, true
		}
	}

	return nil, false
}

// RuleProcPtracedStoppedStall detects processes stopped in 'T' / 't' state by debuggers or signals.
type RuleProcPtracedStoppedStall struct{ noSuppression }

func (r *RuleProcPtracedStoppedStall) ID() string           { return "EDGE_PROC_PTRACED_STOPPED_STALL" }
func (r *RuleProcPtracedStoppedStall) Tier() int            { return 3 }
func (r *RuleProcPtracedStoppedStall) IsPIDDependent() bool { return true }

func (r *RuleProcPtracedStoppedStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.State == 'T' || p.State == 't' || (p.TracerPID != 0 && p.CPUPercent == 0)) && p.NumThreads > 0 {
			stateDesc := "stopped by signal (SIGSTOP/SIGTSTP)"
			if p.State == 't' || p.TracerPID != 0 {
				stateDesc = fmt.Sprintf("traced by debugger (TracerPid: %d)", p.TracerPID)
			}
			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           3,
				Severity:       SeverityMedium,
				Confidence:     0.94,
				Title:          fmt.Sprintf("Process Halted in Traced / Stopped State (%s)", p.Comm),
				Explanation:    fmt.Sprintf("Process '%s' (PID %d) is in state '%c' (%s), completely suspended from thread scheduling.", p.Comm, p.PID, p.State, stateDesc),
				Evidence:       []string{fmt.Sprintf("Process: %s (PID %d)", p.Comm, p.PID), fmt.Sprintf("State: %c (%s)", p.State, stateDesc)},
				Remediation:    fmt.Sprintf("Resume process execution: kill -CONT %d or detach debugger.", p.PID),
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("State %c (%s)", p.State, stateDesc),
			}, true
		}
	}

	return nil, false
}

// RuleMemSlabDentryPressure detects unevictable or bloated slab dentry/inode caches causing memory scan pressure.
type RuleMemSlabDentryPressure struct{ noSuppression }

func (r *RuleMemSlabDentryPressure) ID() string           { return "EDGE_MEM_SLAB_DENTRY_PRESSURE" }
func (r *RuleMemSlabDentryPressure) Tier() int            { return 3 }
func (r *RuleMemSlabDentryPressure) IsPIDDependent() bool { return false }

func (r *RuleMemSlabDentryPressure) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	slab := diff.LatestSnapshot.Memory.SUnreclaim
	total := diff.LatestSnapshot.Memory.MemTotal
	directScan := diff.VMStat.PgScanDirectDelta

	if total > 0 && slab > 0 && float64(slab)/float64(total) >= 0.30 && directScan >= 100 {
		slabMB := slab / (1024 * 1024)
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.89,
			Title:       "Unreclaimable Slab / Dentry Cache Memory Bloat",
			Explanation: fmt.Sprintf("Unreclaimable kernel slab memory is consuming %d MB (%.1f%% of total RAM) with %d direct page scans, causing allocator stall latency.", slabMB, float64(slab)/float64(total)*100, directScan),
			Evidence: []string{
				fmt.Sprintf("Slab Unreclaimable: %d MB (%.1f%% of total RAM)", slabMB, float64(slab)/float64(total)*100),
				fmt.Sprintf("Direct Page Scans Delta: %d scans", directScan),
			},
			Remediation: "Tune VFS cache pressure: sysctl -w vm.vfs_cache_pressure=150 and prune cached dentries: echo 2 > /proc/sys/vm/drop_caches.",
		}, true
	}

	return nil, false
}

// RuleNetIPReasmTimeoutStall detects fragmented IP packet reassembly timer expirations.
type RuleNetIPReasmTimeoutStall struct{ noSuppression }

func (r *RuleNetIPReasmTimeoutStall) ID() string           { return "EDGE_NET_IP_REASM_TIMEOUT_STALL" }
func (r *RuleNetIPReasmTimeoutStall) Tier() int            { return 3 }
func (r *RuleNetIPReasmTimeoutStall) IsPIDDependent() bool { return false }

func (r *RuleNetIPReasmTimeoutStall) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	timeouts := diff.NetStat.IPReasmTimeoutDelta
	fails := diff.NetStat.IPReasmFailsDelta

	if timeouts < 5 && fails < 20 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("IP Fragment Reassembly Timeouts Delta: %d packets", timeouts),
		fmt.Sprintf("IP Fragment Reassembly Failures Delta: %d packets", fails),
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.90,
		Title:       "IP Packet Fragment Reassembly Timeout Stalls",
		Explanation: fmt.Sprintf("Kernel timed out assembling %d fragmented IP packets (%d reassembly failures), dropping truncated packets under high UDP/tunnel traffic.", timeouts, fails),
		Evidence:    evidence,
		Remediation: "Enlarge IP fragment memory limit: sysctl -w net.ipv4.ipfrag_high_thresh=8388608 and extend reassembly timeout: sysctl -w net.ipv4.ipfrag_time=60.",
	}, true
}

// RuleMemMinWatermarkBounce detects kernel page allocator bouncing on low watermarks without triggering direct stalls.
type RuleMemMinWatermarkBounce struct{ noSuppression }

func (r *RuleMemMinWatermarkBounce) ID() string           { return "EDGE_MEM_MIN_WATERMARK_BOUNCE" }
func (r *RuleMemMinWatermarkBounce) Tier() int            { return 3 }
func (r *RuleMemMinWatermarkBounce) IsPIDDependent() bool { return false }

func (r *RuleMemMinWatermarkBounce) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	avail := diff.LatestSnapshot.Memory.MemAvailable
	total := diff.LatestSnapshot.Memory.MemTotal
	directScans := diff.VMStat.PgScanDirectDelta
	allocStalls := diff.VMStat.AllocStallDirectDelta

	if total > 0 && avail < total/10 && directScans >= 50 && allocStalls == 0 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        3,
			Severity:    SeverityMedium,
			Confidence:  0.88,
			Title:       "Kernel Memory Low Watermark Oscillation",
			Explanation: fmt.Sprintf("Kernel memory allocator experienced %d direct page scans while MemAvailable was low (%.1f%% of RAM), fluctuating near watermark boundaries.", directScans, float64(avail)/float64(total)*100),
			Evidence: []string{
				fmt.Sprintf("Direct Page Scans Delta: %d scans", directScans),
				fmt.Sprintf("Memory Available: %.1f%% of total", float64(avail)/float64(total)*100),
			},
			Remediation: "Increase minimum free memory headroom: sysctl -w vm.min_free_kbytes=131072 or increase vm.watermark_scale_factor=200.",
		}, true
	}

	return nil, false
}

// RuleProcCommSwitchTruncation detects high thread churn with process command renaming and truncation.
type RuleProcCommSwitchTruncation struct{ noSuppression }

func (r *RuleProcCommSwitchTruncation) ID() string           { return "EDGE_PROC_COMM_SWITCH_TRUNCATION" }
func (r *RuleProcCommSwitchTruncation) Tier() int            { return 3 }
func (r *RuleProcCommSwitchTruncation) IsPIDDependent() bool { return true }

func (r *RuleProcCommSwitchTruncation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.NumThreads >= 150 && (p.Wchan == "do_prctl" || p.Wchan == "prctl_set_mm") {
			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           3,
				Severity:       SeverityMedium,
				Confidence:     0.87,
				Title:          fmt.Sprintf("Process Comm Renaming / Prctl Churn (%s)", p.Comm),
				Explanation:    fmt.Sprintf("Process '%s' (PID %d with %d threads) is blocked in '%s', causing mmap_lock/creds serialization across thread workers.", p.Comm, p.PID, p.NumThreads, p.Wchan),
				Evidence:       []string{fmt.Sprintf("Process: %s (PID %d)", p.Comm, p.PID), fmt.Sprintf("Active Threads: %d, Wchan: %s", p.NumThreads, p.Wchan)},
				Remediation:    "Avoid dynamic pthread_setname_np or prctl(PR_SET_NAME) loops inside high-frequency worker loops.",
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("Prctl lock in %s", p.Wchan),
			}, true
		}
	}

	return nil, false
}

// RuleEpollPollTimeoutBurst detects worker threads repeatedly timing out in epoll without handling requests.
type RuleEpollPollTimeoutBurst struct{ noSuppression }

func (r *RuleEpollPollTimeoutBurst) ID() string           { return "EDGE_EPOLL_POLL_TIMEOUT_BURST" }
func (r *RuleEpollPollTimeoutBurst) Tier() int            { return 3 }
func (r *RuleEpollPollTimeoutBurst) IsPIDDependent() bool { return true }

func (r *RuleEpollPollTimeoutBurst) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "epoll_pwait" || p.Wchan == "do_epoll_wait" || p.Wchan == "ep_poll") && p.NumThreads >= 50 && p.CPUPercent < 0.2 && p.OpenFDs >= 100 {
			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           3,
				Severity:       SeverityMedium,
				Confidence:     0.88,
				Title:          fmt.Sprintf("Epoll Event Loop Starvation / Timeout Churn (%s)", p.Comm),
				Explanation:    fmt.Sprintf("Process '%s' (PID %d with %d threads) is idling in epoll with %d open FDs, indicating event loop underutilization or stalled inbound dispatcher.", p.Comm, p.PID, p.NumThreads, p.OpenFDs),
				Evidence:       []string{fmt.Sprintf("Process: %s (PID %d)", p.Comm, p.PID), fmt.Sprintf("Threads: %d, Open FDs: %d, CPU: %.1f%%", p.NumThreads, p.OpenFDs, p.CPUPercent)},
				Remediation:    "Tune epoll_wait timeout parameters and verify upstream connection load balancer health checks.",
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("Epoll idle with %d FDs", p.OpenFDs),
			}, true
		}
	}

	return nil, false
}

// RuleNetTCPSynFloodDrop detects TCP SYN cookie drops and failures during network flood attacks.
type RuleNetTCPSynFloodDrop struct{ noSuppression }

func (r *RuleNetTCPSynFloodDrop) ID() string           { return "EDGE_NET_TCP_SYN_FLOOD_DROP" }
func (r *RuleNetTCPSynFloodDrop) Tier() int            { return 3 }
func (r *RuleNetTCPSynFloodDrop) IsPIDDependent() bool { return false }

func (r *RuleNetTCPSynFloodDrop) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	failed := diff.NetStat.SyncookiesFailedDelta
	if failed < 10 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("TCP SYN Cookie Validation Failures Delta: %d drops", failed),
		"Kernel SYN cookies received with invalid cryptographic timestamps or sequence hashes",
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        3,
		Severity:    SeverityMedium,
		Confidence:  0.91,
		Title:       "TCP SYN Flood SYN-Cookie Validation Drops",
		Explanation: fmt.Sprintf("Kernel rejected %d incoming SYN cookie handshakes due to validation hash mismatches or spoofed sequence numbers.", failed),
		Evidence:    evidence,
		Remediation: "Enable hardware DDoS protection: sysctl -w net.ipv4.tcp_syncookies=1 and enlarge sysctl -w net.ipv4.tcp_max_syn_backlog=32768.",
	}, true
}

// RuleSysfsPowerThrottleEvent detects power capping or RAPL thermal throttle events on CPU packages.
type RuleSysfsPowerThrottleEvent struct{ noSuppression }

func (r *RuleSysfsPowerThrottleEvent) ID() string           { return "EDGE_SYSFS_POWER_THROTTLE_EVENT" }
func (r *RuleSysfsPowerThrottleEvent) Tier() int            { return 3 }
func (r *RuleSysfsPowerThrottleEvent) IsPIDDependent() bool { return false }

func (r *RuleSysfsPowerThrottleEvent) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	thermal := &diff.LatestSnapshot.Thermal
	freq := &diff.LatestSnapshot.CPUFreq

	if !thermal.Available || thermal.MaxTemp < 75.0 || thermal.MaxTemp >= 85.0 {
		return nil, false
	}

	if freq.Available && len(freq.Cores) > 0 {
		for _, c := range freq.Cores {
			if c.MaxFreq > 0 && float64(c.CurFreq) < 0.75*float64(c.MaxFreq) {
				return &Diagnosis{
					RuleID:      r.ID(),
					Tier:        3,
					Severity:    SeverityMedium,
					Confidence:  0.89,
					Title:       "Hardware RAPL / Package Power Cap Throttling",
					Explanation: fmt.Sprintf("CPU package thermal sensor is at %.1f°C with clock frequencies constrained below turbo boost (%.1f GHz vs %.1f GHz).", thermal.MaxTemp, float64(c.CurFreq)/1e6, float64(c.MaxFreq)/1e6),
					Evidence: []string{
						fmt.Sprintf("Package Temperature: %.1f°C", thermal.MaxTemp),
						fmt.Sprintf("Core Frequency: %d kHz / %d kHz max", c.CurFreq, c.MaxFreq),
					},
					Remediation: "Inspect chassis cooling fans, power distribution units (PDUs), or disable server power capping policies in IPMI/BIOS.",
				}, true
			}
		}
	}

	return nil, false
}

// RuleProcZombieParentDeadlock detects supervisor/parent processes stuck in wait4 failing to reap zombie children.
type RuleProcZombieParentDeadlock struct{ noSuppression }

func (r *RuleProcZombieParentDeadlock) ID() string           { return "EDGE_PROC_ZOMBIE_PARENT_DEADLOCK" }
func (r *RuleProcZombieParentDeadlock) Tier() int            { return 3 }
func (r *RuleProcZombieParentDeadlock) IsPIDDependent() bool { return true }

func (r *RuleProcZombieParentDeadlock) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	zombieCount := 0
	for i := range diff.Processes {
		if diff.Processes[i].State == 'Z' {
			zombieCount++
		}
	}

	if zombieCount < 10 {
		return nil, false
	}

	for i := range diff.Processes {
		p := &diff.Processes[i]
		if (p.Wchan == "do_wait" || p.Wchan == "wait4" || p.Wchan == "sys_wait4") && p.State == 'S' {
			return &Diagnosis{
				RuleID:         r.ID(),
				Tier:           3,
				Severity:       SeverityMedium,
				Confidence:     0.92,
				Title:          fmt.Sprintf("Parent Supervisor Stalled Reaping Zombie Children (%s)", p.Comm),
				Explanation:    fmt.Sprintf("Parent process '%s' (PID %d) is sleeping in '%s' while %d defunct zombie processes accumulate in the process table.", p.Comm, p.PID, p.Wchan, zombieCount),
				Evidence:       []string{fmt.Sprintf("Parent Process: %s (PID %d)", p.Comm, p.PID), fmt.Sprintf("Accumulated Zombie Count: %d PIDs", zombieCount)},
				Remediation:    fmt.Sprintf("Send SIGCHLD to parent: kill -SIGCHLD %d or restart buggy supervisor service.", p.PID),
				CulpritPID:     p.PID,
				CulpritName:    p.Comm,
				CulpritDetails: fmt.Sprintf("Stalled parent with %d zombies", zombieCount),
			}, true
		}
	}

	return nil, false
}










