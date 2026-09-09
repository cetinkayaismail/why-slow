package analyzer

import (
	"testing"
	"why-slow/internal/collector"
)

func TestRuleTHPCompactionStall(t *testing.T) {
	rule := &RuleTHPCompactionStall{}

	// Negative case: 0 compact stalls
	diffNormal := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{CompactStallDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected THPCompactionStall not to trigger")
	}

	// Positive case: 8 compaction stalls
	diffStall := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{CompactStallDelta: 8},
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "db_worker", Wchan: "compact_zone"},
		},
	}
	diag, triggered := rule.Evaluate(diffStall)
	if !triggered {
		t.Fatalf("expected THPCompactionStall to trigger")
	}
	if diag.Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium, got %s", diag.Severity)
	}
}

func TestRulePTYStdoutLock(t *testing.T) {
	rule := &RulePTYStdoutLock{}

	// Negative case: normal sleep in epoll
	diffNormal := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 200, Comm: "nginx", State: 'S', Wchan: "do_epoll_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected PTYStdoutLock not to trigger on epoll")
	}

	// Positive case: blocked in n_tty_write
	diffLocked := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 300, Comm: "cargo", State: 'S', Wchan: "n_tty_write"},
		},
	}
	diag, triggered := rule.Evaluate(diffLocked)
	if !triggered {
		t.Fatalf("expected PTYStdoutLock to trigger")
	}
	if diag.CulpritPID != 300 || diag.CulpritName != "cargo" {
		t.Errorf("expected culprit PID 300 cargo, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleHPETClocksourceDegrade(t *testing.T) {
	rule := &RuleHPETClocksourceDegrade{}

	// Negative case: tsc clocksource
	diffTSC := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Clocksource: collector.ClocksourceInfo{Current: "tsc"},
		},
	}
	if _, triggered := rule.Evaluate(diffTSC); triggered {
		t.Fatalf("expected HPETClocksourceDegrade not to trigger on tsc")
	}

	// Positive case: degraded to hpet
	diffHPET := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Clocksource: collector.ClocksourceInfo{Current: "hpet"},
		},
	}
	diag, triggered := rule.Evaluate(diffHPET)
	if !triggered {
		t.Fatalf("expected HPETClocksourceDegrade to trigger on hpet")
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh")
	}
}

func TestRuleCgroupDirtyThrottle(t *testing.T) {
	rule := &RuleCgroupDirtyThrottle{}

	// Negative case: normal write
	diffNormal := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 400, Comm: "sync_app", Wchan: "do_sys_poll"},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected CgroupDirtyThrottle not to trigger")
	}

	// Positive case: balance_dirty_pages
	diffDirty := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 500, Comm: "heavy_flusher", Wchan: "balance_dirty_pages_ratelimited"},
		},
	}
	diag, triggered := rule.Evaluate(diffDirty)
	if !triggered {
		t.Fatalf("expected CgroupDirtyThrottle to trigger")
	}
	if diag.CulpritPID != 500 || diag.CulpritName != "heavy_flusher" {
		t.Errorf("expected culprit PID 500 heavy_flusher, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleFutexContention(t *testing.T) {
	rule := &RuleFutexContention{}

	// Negative case: 4 threads on futex
	diffFew := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 600, Comm: "go_service", NumThreads: 4, Wchan: "futex_wait_queue_me"},
		},
	}
	if _, triggered := rule.Evaluate(diffFew); triggered {
		t.Fatalf("expected FutexContention not to trigger on 4 threads")
	}

	// Positive case: 120 threads on futex
	diffContended := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 700, Comm: "java_app", NumThreads: 120, Wchan: "futex_wait_queue_me"},
		},
	}
	diag, triggered := rule.Evaluate(diffContended)
	if !triggered {
		t.Fatalf("expected FutexContention to trigger")
	}
	if diag.CulpritPID != 700 || diag.CulpritName != "java_app" {
		t.Errorf("expected culprit PID 700 java_app, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleNUMARemoteThrashing(t *testing.T) {
	rule := &RuleNUMARemoteThrashing{}

	// Negative case: low NUMA miss delta
	diffNormal := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			NumaMissDelta:    50,
			NumaForeignDelta: 20,
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected NUMARemoteThrashing not to trigger on low deltas")
	}

	// Positive case: high NUMA miss / foreign deltas
	diffThrashing := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			NumaMissDelta:    7500,
			NumaForeignDelta: 6800,
		},
	}
	diag, triggered := rule.Evaluate(diffThrashing)
	if !triggered {
		t.Fatalf("expected NUMARemoteThrashing to trigger on high deltas")
	}
	if diag.RuleID != "EDGE_NUMA_REMOTE_THRASHING" {
		t.Errorf("expected rule ID EDGE_NUMA_REMOTE_THRASHING, got %s", diag.RuleID)
	}
	if diag.Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium, got %s", diag.Severity)
	}
}

func TestRuleCPUAffinityPin(t *testing.T) {
	rule := &RuleCPUAffinityPin{}

	// Negative case: Process pinned to 1 core but low CPU utilization (15%)
	diffLowCPU := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 90.0},
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"}},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "worker", CpusAllowed: 1, CPUPercent: 15.0},
		},
	}
	if _, triggered := rule.Evaluate(diffLowCPU); triggered {
		t.Fatalf("expected CPUAffinityPin not to trigger when process CPU is low")
	}

	// Negative case: Process high CPU but system overall is busy (idle 10%)
	diffSystemBusy := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 10.0},
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"}},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "worker", CpusAllowed: 1, CPUPercent: 99.0},
		},
	}
	if _, triggered := rule.Evaluate(diffSystemBusy); triggered {
		t.Fatalf("expected CPUAffinityPin not to trigger when entire system is busy")
	}

	// Positive case: Process 98% CPU, pinned to 1 core (CpusAllowed: 1), system overall is 80% idle (4 cores)
	diffPinned := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 80.0},
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"}},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 4500, Comm: "pinned_encoder", CpusAllowed: 1, CPUPercent: 98.5, CPUTimeDelta: 98},
		},
	}
	diag, triggered := rule.Evaluate(diffPinned)
	if !triggered {
		t.Fatalf("expected CPUAffinityPin to trigger")
	}
	if diag.CulpritPID != 4500 || diag.CulpritName != "pinned_encoder" {
		t.Errorf("expected culprit PID 4500 pinned_encoder, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.RuleID != "EDGE_CPU_AFFINITY_PIN" {
		t.Errorf("expected rule ID EDGE_CPU_AFFINITY_PIN, got %s", diag.RuleID)
	}
}

func TestRuleZombieDefunctLeak(t *testing.T) {
	rule := &RuleZombieDefunctLeak{}

	// Negative case: only 5 zombie processes (< 50)
	diffFewZombies := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 101, State: 'Z', PPID: 100},
			{PID: 102, State: 'Z', PPID: 100},
			{PID: 103, State: 'S', PPID: 1},
		},
	}
	if _, triggered := rule.Evaluate(diffFewZombies); triggered {
		t.Fatalf("expected ZombieDefunctLeak not to trigger with < 50 zombies")
	}

	// Positive case: 55 zombie processes with culprit parent PID 1200
	procs := make([]collector.ProcessDiff, 0, 60)
	procs = append(procs, collector.ProcessDiff{PID: 1200, Comm: "bad_master", State: 'S'})
	for i := 0; i < 55; i++ {
		procs = append(procs, collector.ProcessDiff{
			PID:   2000 + i,
			Comm:  "defunct_child",
			State: 'Z',
			PPID:  1200,
		})
	}
	diffZombies := &collector.SnapshotDiff{Processes: procs}
	diag, triggered := rule.Evaluate(diffZombies)
	if !triggered {
		t.Fatalf("expected ZombieDefunctLeak to trigger on 55 zombies")
	}
	if diag.CulpritPID != 1200 || diag.CulpritName != "bad_master" {
		t.Errorf("expected culprit PID 1200 bad_master, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.RuleID != "EDGE_ZOMBIE_DEFUNCT_LEAK" {
		t.Errorf("expected rule ID EDGE_ZOMBIE_DEFUNCT_LEAK, got %s", diag.RuleID)
	}
}

func TestRuleCgroupOOMKillEvent(t *testing.T) {
	rule := &RuleCgroupOOMKillEvent{}

	// Negative case: 0 OOM kills
	diffNormal := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/web", OOMKillsDelta: 0},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected CgroupOOMKillEvent not to trigger on 0 OOM kills")
	}

	// Positive case: 3 OOM kills in /docker/leaky-service
	diffOOM := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/leaky-service", OOMKillsDelta: 3},
		},
	}
	diag, triggered := rule.Evaluate(diffOOM)
	if !triggered {
		t.Fatalf("expected CgroupOOMKillEvent to trigger on OOM kills")
	}
	if diag.RuleID != "EDGE_CGROUP_OOM_KILL_EVENT" {
		t.Errorf("expected rule ID EDGE_CGROUP_OOM_KILL_EVENT, got %s", diag.RuleID)
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", diag.Severity)
	}
}

func TestRuleDMA32ZoneExhaustion(t *testing.T) {
	rule := &RuleDMA32ZoneExhaustion{}

	// Negative case: DMA32 has free pages
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				BuddyInfo: collector.ZoneBuddyInfo{
					Available:       true,
					DMA32FreePages:  5000,
					NormalFreePages: 1000000,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected DMA32ZoneExhaustion not to trigger on healthy zone")
	}

	// Positive case: DMA32 has 0 free pages while Normal has 500,000 pages (~2GB)
	diffExhausted := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				BuddyInfo: collector.ZoneBuddyInfo{
					Available:       true,
					DMA32FreePages:  0,
					NormalFreePages: 500000,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffExhausted)
	if !triggered {
		t.Fatalf("expected DMA32ZoneExhaustion to trigger on 0 DMA32 pages")
	}
	if diag.RuleID != "EDGE_ZONE_DMA32_EXHAUSTION" {
		t.Errorf("expected rule ID EDGE_ZONE_DMA32_EXHAUSTION, got %s", diag.RuleID)
	}
	if diag.Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium, got %s", diag.Severity)
	}
}

func TestRuleKSMScanStall(t *testing.T) {
	rule := &RuleKSMScanStall{}

	// Negative case: KSM not running
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				KSM: collector.KSMInfo{
					Available: true,
					Running:   false,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected KSMScanStall not to trigger when KSM is stopped")
	}

	// Positive case: KSM active, scanning 20k pages, ksmd process at 85% CPU
	diffKSM := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				KSM: collector.KSMInfo{
					Available:    true,
					Running:      true,
					PagesToScan:  20000,
					PagesShared:  15000,
					PagesSharing: 60000,
				},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 45, Comm: "ksmd", CPUPercent: 85.0},
		},
	}
	diag, triggered := rule.Evaluate(diffKSM)
	if !triggered {
		t.Fatalf("expected KSMScanStall to trigger on active ksmd load")
	}
	if diag.RuleID != "EDGE_KSM_SCAN_STALL" {
		t.Errorf("expected rule ID EDGE_KSM_SCAN_STALL, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 45 || diag.CulpritName != "ksmd" {
		t.Errorf("expected culprit PID 45 ksmd, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleIRQCoreStorm(t *testing.T) {
	rule := &RuleIRQCoreStorm{}

	// Negative case: Balanced IRQs (10,000 on core 0, 9,000 avg on others)
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				IRQStat: collector.IRQStatInfo{
					Available:         true,
					MaxCoreID:         0,
					MaxCoreIRQs:       10000,
					OtherCoresAvgIRQs: 9000,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected IRQCoreStorm not to trigger on balanced IRQs")
	}

	// Positive case: Core 3 receiving 150,000 IRQs while other cores average 2,000
	diffStorm := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				IRQStat: collector.IRQStatInfo{
					Available:         true,
					MaxCoreID:         3,
					MaxCoreIRQs:       150000,
					OtherCoresAvgIRQs: 2000,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffStorm)
	if !triggered {
		t.Fatalf("expected IRQCoreStorm to trigger on 150k IRQs")
	}
	if diag.RuleID != "EDGE_IRQ_CORE_STORM" {
		t.Errorf("expected rule ID EDGE_IRQ_CORE_STORM, got %s", diag.RuleID)
	}
	if diag.Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium, got %s", diag.Severity)
	}
}

func TestRuleSlabUnreclaimableLeak(t *testing.T) {
	rule := &RuleSlabUnreclaimableLeak{}

	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:   64 * 1024 * 1024,
				SUnreclaim: 2 * 1024 * 1024,
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected SlabUnreclaimableLeak not to trigger")
	}

	diffLeaked := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:   64 * 1024 * 1024,
				SUnreclaim: 32 * 1024 * 1024, // 50% of RAM
				Slab:       36 * 1024 * 1024,
			},
		},
	}
	diag, triggered := rule.Evaluate(diffLeaked)
	if !triggered {
		t.Fatalf("expected SlabUnreclaimableLeak to trigger")
	}
	if diag.RuleID != "EDGE_SLAB_UNRECLAIM_LEAK" {
		t.Errorf("expected EDGE_SLAB_UNRECLAIM_LEAK, got %s", diag.RuleID)
	}
}

func TestRuleInotifyWatchExhaustion(t *testing.T) {
	rule := &RuleInotifyWatchExhaustion{}

	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Inotify: collector.InotifyInfo{
					Available:      true,
					MaxUserWatches: 524288,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected InotifyWatchExhaustion not to trigger")
	}

	diffLowCeiling := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Inotify: collector.InotifyInfo{
					Available:      true,
					MaxUserWatches: 8192,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffLowCeiling)
	if !triggered {
		t.Fatalf("expected InotifyWatchExhaustion to trigger on 8192 max_user_watches")
	}
	if diag.RuleID != "EDGE_INOTIFY_WATCH_EXHAUSTION" {
		t.Errorf("expected EDGE_INOTIFY_WATCH_EXHAUSTION, got %s", diag.RuleID)
	}
}

func TestRuleRCUSchedulerStall(t *testing.T) {
	rule := &RuleRCUSchedulerStall{}

	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 200, Comm: "worker", Wchan: "epoll_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected RCUSchedulerStall not to trigger")
	}

	diffRCUStall := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 201, Comm: "sync_task", Wchan: "synchronize_rcu"},
			{PID: 202, Comm: "rcu_task", Wchan: "rcu_gp_kthread"},
		},
	}
	diag, triggered := rule.Evaluate(diffRCUStall)
	if !triggered {
		t.Fatalf("expected RCUSchedulerStall to trigger")
	}
	if diag.RuleID != "EDGE_RCU_SCHEDULER_STALL" {
		t.Errorf("expected EDGE_RCU_SCHEDULER_STALL, got %s", diag.RuleID)
	}
}

func TestRuleTHPCollapseStall(t *testing.T) {
	rule := &RuleTHPCollapseStall{}

	diffClean := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPCollapseAllocDelta: 0,
			AllocStallDirectDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected THPCollapseStall not to trigger")
	}

	diffStall := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPCollapseAllocDelta: 50,
			AllocStallDirectDelta: 20,
		},
	}
	diag, triggered := rule.Evaluate(diffStall)
	if !triggered {
		t.Fatalf("expected THPCollapseStall to trigger")
	}
	if diag.RuleID != "EDGE_THP_COLLAPSE_STALL" {
		t.Errorf("expected EDGE_THP_COLLAPSE_STALL, got %s", diag.RuleID)
	}
}

func TestRuleFUSEFilesystemLatency(t *testing.T) {
	rule := &RuleFUSEFilesystemLatency{}

	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 10, Comm: "worker", Wchan: "epoll_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected FUSEFilesystemLatency not to trigger on clean wchan")
	}

	diffFUSE := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 4001, Comm: "s3_writer", Wchan: "fuse_request_wait"},
		},
	}
	diag, triggered := rule.Evaluate(diffFUSE)
	if !triggered {
		t.Fatalf("expected FUSEFilesystemLatency to trigger on fuse_request_wait")
	}
	if diag.RuleID != "EDGE_FUSE_FS_STALL" {
		t.Errorf("expected EDGE_FUSE_FS_STALL, got %s", diag.RuleID)
	}
}

func TestRuleCompactionFailureRate(t *testing.T) {
	rule := &RuleCompactionFailureRate{}

	diffClean := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			CompactStallDelta: 100,
			CompactFailDelta:  10, // 10% failure rate
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected CompactionFailureRate not to trigger on 10%% failure rate")
	}

	diffHighFail := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			CompactStallDelta: 100,
			CompactFailDelta:  75, // 75% failure rate
		},
	}
	diag, triggered := rule.Evaluate(diffHighFail)
	if !triggered {
		t.Fatalf("expected CompactionFailureRate to trigger on 75%% failure rate")
	}
	if diag.RuleID != "EDGE_COMPACT_FAIL_RATE" {
		t.Errorf("expected EDGE_COMPACT_FAIL_RATE, got %s", diag.RuleID)
	}
}

func TestRuleMajorPageFaultStorm(t *testing.T) {
	rule := &RuleMajorPageFaultStorm{}

	diffClean := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			PgMajFaultDelta: 10,
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected MajorPageFaultStorm not to trigger on 10 faults")
	}

	diffStorm := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			PgMajFaultDelta: 1500,
		},
	}
	diag, triggered := rule.Evaluate(diffStorm)
	if !triggered {
		t.Fatalf("expected MajorPageFaultStorm to trigger on 1500 major faults")
	}
	if diag.RuleID != "EDGE_MAJOR_PAGE_FAULT_STORM" {
		t.Errorf("expected EDGE_MAJOR_PAGE_FAULT_STORM, got %s", diag.RuleID)
	}
}

func TestRuleTHPSplitStorm(t *testing.T) {
	rule := &RuleTHPSplitStorm{}

	diffClean := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPSplitDelta: 50,
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected THPSplitStorm not to trigger on 50 splits")
	}

	diffStorm := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPSplitDelta:         1200,
			AllocStallDirectDelta: 5,
		},
	}
	diag, triggered := rule.Evaluate(diffStorm)
	if !triggered {
		t.Fatalf("expected THPSplitStorm to trigger on 1200 splits")
	}
	if diag.RuleID != "EDGE_THP_SPLIT_STORM" {
		t.Errorf("expected EDGE_THP_SPLIT_STORM, got %s", diag.RuleID)
	}
}

func TestRuleKHugepagedCPUBurn(t *testing.T) {
	rule := &RuleKHugepagedCPUBurn{}

	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 40, Comm: "khugepaged", CPUPercent: 2.0},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected KHugepagedCPUBurn not to trigger on low CPU")
	}

	diffBurn := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 40, Comm: "khugepaged", CPUPercent: 75.0},
		},
		VMStat: collector.VMStatDiff{
			THPCollapseAllocFailedDelta: 200,
		},
	}
	diag, triggered := rule.Evaluate(diffBurn)
	if !triggered {
		t.Fatalf("expected KHugepagedCPUBurn to trigger")
	}
	if diag.CulpritPID != 40 || diag.CulpritName != "khugepaged" {
		t.Errorf("expected culprit PID 40 khugepaged, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleDiskDeviceIOErrHang(t *testing.T) {
	rule := &RuleDiskDeviceIOErrHang{}

	diffClean := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{
				DeviceName:          "nvme0n1",
				IOsInProgress:       0,
				ReadsCompletedDelta: 100,
				UtilPercent:         50.0,
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected DiskDeviceIOErrHang not to trigger on normal disk")
	}

	diffHang := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{
				DeviceName:           "sda",
				IOsInProgress:        8,
				ReadsCompletedDelta:  0,
				WritesCompletedDelta: 0,
				UtilPercent:          99.0,
			},
		},
	}
	diag, triggered := rule.Evaluate(diffHang)
	if !triggered {
		t.Fatalf("expected DiskDeviceIOErrHang to trigger on hung disk")
	}
	if diag.RuleID != "EDGE_DISK_DEVICE_IOERR_HANG" {
		t.Errorf("expected EDGE_DISK_DEVICE_IOERR_HANG, got %s", diag.RuleID)
	}
}

func TestRuleKcompactdCPUSpin(t *testing.T) {
	rule := &RuleKcompactdCPUSpin{}

	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 55, Comm: "kcompactd0", CPUPercent: 2.0},
		},
		VMStat: collector.VMStatDiff{CompactFailDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected KcompactdCPUSpin not to trigger on idle kcompactd")
	}

	diffSpin := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 55, Comm: "kcompactd0", CPUPercent: 65.0},
		},
		VMStat: collector.VMStatDiff{CompactFailDelta: 120},
	}
	diag, triggered := rule.Evaluate(diffSpin)
	if !triggered {
		t.Fatalf("expected KcompactdCPUSpin to trigger on spinning kcompactd")
	}
	if diag.CulpritPID != 55 || diag.CulpritName != "kcompactd0" {
		t.Errorf("expected culprit PID 55 kcompactd0, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.RuleID != "EDGE_KCOMPACTD_CPU_SPIN" {
		t.Errorf("expected EDGE_KCOMPACTD_CPU_SPIN, got %s", diag.RuleID)
	}
}

func TestRuleMinFreeKbytesStall(t *testing.T) {
	rule := &RuleMinFreeKbytesStall{}

	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{MemTotal: 16 * 1024 * 1024}, // 16GB
			SystemConfig: collector.SystemConfigInfo{
				MinFreeKbytes: 262144, // 256MB (~1.6% of RAM)
			},
		},
		VMStat: collector.VMStatDiff{AllocStallDirectDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected MinFreeKbytesStall not to trigger on properly sized watermark")
	}

	diffUndersized := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{MemTotal: 16 * 1024 * 1024}, // 16GB
			SystemConfig: collector.SystemConfigInfo{
				MinFreeKbytes: 8192, // 8MB (< 0.05% of RAM)
			},
		},
		VMStat: collector.VMStatDiff{AllocStallDirectDelta: 45},
	}
	diag, triggered := rule.Evaluate(diffUndersized)
	if !triggered {
		t.Fatalf("expected MinFreeKbytesStall to trigger on undersized watermark with allocstalls")
	}
	if diag.RuleID != "EDGE_MIN_FREE_KBYTES_STALL" {
		t.Errorf("expected EDGE_MIN_FREE_KBYTES_STALL, got %s", diag.RuleID)
	}
}

func TestRuleCorePatternPipeStall(t *testing.T) {
	rule := &RuleCorePatternPipeStall{}

	diffOne := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "crashed_worker", Wchan: "do_coredump", State: 'D'},
		},
	}
	if _, triggered := rule.Evaluate(diffOne); triggered {
		t.Fatalf("expected CorePatternPipeStall not to trigger with < 2 processes")
	}

	diffBlocked := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "crashed_worker", Wchan: "do_coredump", State: 'D'},
			{PID: 102, Comm: "crashed_worker2", Wchan: "pipe_wait", State: 'D'},
		},
	}
	diag, triggered := rule.Evaluate(diffBlocked)
	if !triggered {
		t.Fatalf("expected CorePatternPipeStall to trigger with multiple blocked processes")
	}
	if diag.CulpritPID != 101 || diag.CulpritName != "crashed_worker" {
		t.Errorf("expected culprit PID 101 crashed_worker, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.RuleID != "EDGE_CORE_PATTERN_PIPE_STALL" {
		t.Errorf("expected EDGE_CORE_PATTERN_PIPE_STALL, got %s", diag.RuleID)
	}
}

func TestRuleTCPPAWSDrop(t *testing.T) {
	rule := &RuleTCPPAWSDrop{}

	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{PAWSEstabDelta: 0, PAWSPassiveDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected TCPPAWSDrop not to trigger on 0 drops")
	}

	diffDrops := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{PAWSEstabDelta: 25, PAWSPassiveDelta: 15},
	}
	diag, triggered := rule.Evaluate(diffDrops)
	if !triggered {
		t.Fatalf("expected TCPPAWSDrop to trigger on PAWS drops")
	}
	if diag.RuleID != "EDGE_TCP_PAWS_DROP" {
		t.Errorf("expected EDGE_TCP_PAWS_DROP, got %s", diag.RuleID)
	}
}

func TestRuleCMAZoneExhaustion(t *testing.T) {
	rule := &RuleCMAZoneExhaustion{}

	diffAmple := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{CmaTotal: 524288, CmaFree: 262144},
		},
	}
	if _, triggered := rule.Evaluate(diffAmple); triggered {
		t.Fatalf("expected CMAZoneExhaustion not to trigger on ample CMA free")
	}

	diffExhausted := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{CmaTotal: 524288, CmaFree: 1024}, // < 1%
		},
	}
	diag, triggered := rule.Evaluate(diffExhausted)
	if !triggered {
		t.Fatalf("expected CMAZoneExhaustion to trigger on low CMA free")
	}
	if diag.RuleID != "EDGE_CMA_ZONE_EXHAUSTION" {
		t.Errorf("expected EDGE_CMA_ZONE_EXHAUSTION, got %s", diag.RuleID)
	}
}

func TestRuleLoopDeviceSerialization(t *testing.T) {
	rule := &RuleLoopDeviceSerialization{}

	diffNormal := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "loop0", UtilPercent: 10.0},
			{DeviceName: "nvme0n1", UtilPercent: 40.0},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected LoopDeviceSerialization not to trigger on low loop util")
	}

	diffSaturated := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "loop0", UtilPercent: 88.0, ReadBytesDelta: 50000000},
		},
	}
	diag, triggered := rule.Evaluate(diffSaturated)
	if !triggered {
		t.Fatalf("expected LoopDeviceSerialization to trigger on saturated loop device")
	}
	if diag.RuleID != "EDGE_LOOP_DEVICE_SERIALIZATION" {
		t.Errorf("expected EDGE_LOOP_DEVICE_SERIALIZATION, got %s", diag.RuleID)
	}
}

func TestRuleRTSchedThrottling(t *testing.T) {
	rule := &RuleRTSchedThrottling{}

	diffOther := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{SchedRTRuntimeUS: 950000},
		},
		Processes: []collector.ProcessDiff{
			{PID: 200, Comm: "worker", Policy: 0, CPUPercent: 95.0}, // SCHED_OTHER
		},
	}
	if _, triggered := rule.Evaluate(diffOther); triggered {
		t.Fatalf("expected RTSchedThrottling not to trigger for SCHED_OTHER")
	}

	diffRT := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{SchedRTRuntimeUS: 950000},
		},
		Processes: []collector.ProcessDiff{
			{PID: 200, Comm: "rt_audio", Policy: 1, CPUPercent: 96.0}, // SCHED_FIFO
		},
	}
	diag, triggered := rule.Evaluate(diffRT)
	if !triggered {
		t.Fatalf("expected RTSchedThrottling to trigger for spinning SCHED_FIFO process")
	}
	if diag.CulpritPID != 200 || diag.CulpritName != "rt_audio" {
		t.Errorf("expected culprit PID 200 rt_audio, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.RuleID != "EDGE_RT_SCHED_THROTTLING" {
		t.Errorf("expected EDGE_RT_SCHED_THROTTLING, got %s", diag.RuleID)
	}
}

func TestRuleNumaAutoBalancingScanStall(t *testing.T) {
	rule := &RuleNumaAutoBalancingScanStall{}

	diffClean := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{SystemPercent: 5.0},
		VMStat:       collector.VMStatDiff{NumaPteUpdatesDelta: 100},
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{NumaBalancing: 1},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected NumaAutoBalancingScanStall not to trigger on low scan rate")
	}

	diffHeavyScan := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{SystemPercent: 18.0},
		VMStat:       collector.VMStatDiff{NumaPteUpdatesDelta: 45000},
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{NumaBalancing: 1},
		},
	}
	diag, triggered := rule.Evaluate(diffHeavyScan)
	if !triggered {
		t.Fatalf("expected NumaAutoBalancingScanStall to trigger on high scan rate and system CPU")
	}
	if diag.RuleID != "EDGE_NUMA_AUTO_BALANCING_SCAN_STALL" {
		t.Errorf("expected EDGE_NUMA_AUTO_BALANCING_SCAN_STALL, got %s", diag.RuleID)
	}
}

func TestRuleInotifyQueueOverflow(t *testing.T) {
	rule := &RuleInotifyQueueOverflow{}

	// Negative case: low watch count and context switches
	diffNormal := &collector.SnapshotDiff{
		ContextSwitchesDelta: 500,
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Inotify: collector.InotifyInfo{
					Available:       true,
					MaxUserWatches:  8192,
					MaxQueuedEvents: 16384,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected InotifyQueueOverflow not to trigger with low watch count")
	}

	// Positive case: high watch count + high context switch rate + max_queued_events <= 16384
	diffOverflow := &collector.SnapshotDiff{
		ContextSwitchesDelta: 45000,
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Inotify: collector.InotifyInfo{
					Available:       true,
					MaxUserWatches:  1048576,
					MaxQueuedEvents: 16384,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffOverflow)
	if !triggered {
		t.Fatalf("expected InotifyQueueOverflow to trigger")
	}
	if diag.RuleID != "EDGE_INOTIFY_QUEUE_OVERFLOW" {
		t.Errorf("expected EDGE_INOTIFY_QUEUE_OVERFLOW, got %s", diag.RuleID)
	}
}

func TestRuleCgroupCFSBurstStarvation(t *testing.T) {
	rule := &RuleCgroupCFSBurstStarvation{}

	// Negative case: burst used but no throttling
	diffNoThrottle := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test", NrBurstsDelta: 5, BurstUsecDelta: 20000, NrThrottledDelta: 0},
		},
	}
	if _, triggered := rule.Evaluate(diffNoThrottle); triggered {
		t.Fatalf("expected CgroupCFSBurstStarvation not to trigger without throttling")
	}

	// Positive case: burst tokens used AND throttled >= 50ms
	diffBurstStall := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{
				Path:               "/docker/api-gateway",
				NrBurstsDelta:      15,
				BurstUsecDelta:     120000,
				NrThrottledDelta:   8,
				ThrottledUsecDelta: 85000,
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 501, Comm: "envoy", CgroupPath: "/docker/api-gateway", CPUPercent: 88.0},
		},
	}
	diag, triggered := rule.Evaluate(diffBurstStall)
	if !triggered {
		t.Fatalf("expected CgroupCFSBurstStarvation to trigger")
	}
	if diag.RuleID != "EDGE_CGROUP_CFS_BURST_STARVATION" {
		t.Errorf("expected EDGE_CGROUP_CFS_BURST_STARVATION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 501 || diag.CulpritName != "envoy" {
		t.Errorf("expected culprit PID 501 envoy, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleZswapCompressorContention(t *testing.T) {
	rule := &RuleZswapCompressorContention{}

	// Negative case: low zswpout and no alloc stalls
	diffNormal := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{SystemPercent: 5.0},
		VMStat: collector.VMStatDiff{
			ZswpoutDelta:          10,
			AllocStallDirectDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected ZswapCompressorContention not to trigger on low zswpout")
	}

	// Positive case: high zswpout + direct reclaim alloc stalls
	diffStall := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{SystemPercent: 25.0},
		VMStat: collector.VMStatDiff{
			ZswpoutDelta:                1500,
			ZswapRejectReclaimFailDelta: 50,
			AllocStallDirectDelta:       20,
		},
	}
	diag, triggered := rule.Evaluate(diffStall)
	if !triggered {
		t.Fatalf("expected ZswapCompressorContention to trigger")
	}
	if diag.RuleID != "EDGE_ZSWAP_COMPRESSOR_CONTENTION" {
		t.Errorf("expected EDGE_ZSWAP_COMPRESSOR_CONTENTION, got %s", diag.RuleID)
	}
}

func TestRuleNetIfaceCarrierFlap(t *testing.T) {
	rule := &RuleNetIfaceCarrierFlap{}

	// Negative case: no carrier changes
	diffNeg := &collector.SnapshotDiff{
		NetIfaces: []collector.NetIfaceDiff{
			{Name: "eth0", CarrierChangesDelta: 0, OperState: "up"},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetIfaceCarrierFlap not to trigger on stable interface")
	}

	// Positive case: 5 carrier changes with CRC errors
	diffPos := &collector.SnapshotDiff{
		NetIfaces: []collector.NetIfaceDiff{
			{Name: "eth0", CarrierChangesDelta: 5, OperState: "up", RxCRCErrorsDelta: 42},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetIfaceCarrierFlap to trigger on flapping interface")
	}
	if diag.RuleID != "EDGE_NET_IFACE_CARRIER_FLAP" {
		t.Errorf("expected EDGE_NET_IFACE_CARRIER_FLAP, got %s", diag.RuleID)
	}
}

func TestRuleTHPAllocFallbackStall(t *testing.T) {
	rule := &RuleTHPAllocFallbackStall{}

	// Negative case: no fallback
	diffNeg := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPFaultFallbackDelta: 0,
			AllocStallDirectDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected THPAllocFallbackStall not to trigger with 0 fallback")
	}

	// Positive case: 600 THP fallbacks + 15 direct alloc stalls
	diffPos := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPFaultFallbackDelta: 600,
			AllocStallDirectDelta: 15,
			CompactStallDelta:     5,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected THPAllocFallbackStall to trigger")
	}
	if diag.RuleID != "EDGE_THP_ALLOC_FALLBACK_STALL" {
		t.Errorf("expected EDGE_THP_ALLOC_FALLBACK_STALL, got %s", diag.RuleID)
	}
}

func TestRuleSchedMigrationBounce(t *testing.T) {
	rule := &RuleSchedMigrationBounce{}

	// Negative case: default 500,000 ns cost
	diffNeg := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{SchedMigrationCostNS: 500000},
		},
		VMStat: collector.VMStatDiff{NumaMissDelta: 3000},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected SchedMigrationBounce not to trigger with default cost")
	}

	// Positive case: low 10,000 ns cost + high NUMA misses
	diffPos := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{SchedMigrationCostNS: 10000},
		},
		VMStat: collector.VMStatDiff{NumaMissDelta: 3500},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected SchedMigrationBounce to trigger on low cost with NUMA misses")
	}
	if diag.RuleID != "EDGE_SCHED_MIGRATION_BOUNCE" {
		t.Errorf("expected EDGE_SCHED_MIGRATION_BOUNCE, got %s", diag.RuleID)
	}
}

func TestRuleIPFragReasmDrops(t *testing.T) {
	rule := &RuleIPFragReasmDrops{}

	// Negative case: 0 drops
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			IPReasmFailsDelta:   0,
			IPReasmTimeoutDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected IPFragReasmDrops not to trigger on 0 drops")
	}

	// Positive case: 25 failures + 50 requests
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			IPReasmFailsDelta:   25,
			IPReasmTimeoutDelta: 12,
			IPReasmReqdsDelta:   100,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected IPFragReasmDrops to trigger")
	}
	if diag.RuleID != "EDGE_IP_FRAG_REASM_DROPS" {
		t.Errorf("expected EDGE_IP_FRAG_REASM_DROPS, got %s", diag.RuleID)
	}
}

func TestRuleCgroupV2FreezeHang(t *testing.T) {
	rule := &RuleCgroupV2FreezeHang{}

	// Negative case: cgroup not frozen
	diffNeg := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Cgroups: collector.CgroupInfo{Available: true, Frozen: false},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected CgroupV2FreezeHang not to trigger when unfrozen")
	}

	// Positive case: cgroup frozen with process in cgroup_freeze_task
	diffPos := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Cgroups: collector.CgroupInfo{Available: true, Frozen: true},
		},
		Processes: []collector.ProcessDiff{
			{PID: 400, Comm: "worker", State: 'D', Wchan: "cgroup_freeze_task", CgroupPath: "/docker.slice/container1"},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected CgroupV2FreezeHang to trigger")
	}
	if diag.RuleID != "EDGE_CGROUP_V2_FREEZE_HANG" {
		t.Errorf("expected EDGE_CGROUP_V2_FREEZE_HANG, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 400 {
		t.Errorf("expected CulpritPID 400, got %d", diag.CulpritPID)
	}
}

func TestRuleSysVShmSegmentLimit(t *testing.T) {
	rule := &RuleSysVShmSegmentLimit{}

	// Negative case: low segment usage
	diffNeg := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				SysVShm: collector.SysVShmInfo{
					Available:         true,
					AllocatedSegments: 10,
					ShmMNI:            4096,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected SysVShmSegmentLimit not to trigger on low segments")
	}

	// Positive case: 3900 / 4096 segments (95%) with high shmem
	diffPos := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal: 16000000,
				Shmem:    5000000,
			},
			SystemConfig: collector.SystemConfigInfo{
				SysVShm: collector.SysVShmInfo{
					Available:         true,
					AllocatedSegments: 3900,
					ShmMNI:            4096,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected SysVShmSegmentLimit to trigger")
	}
	if diag.RuleID != "EDGE_SYSV_SHM_SEGMENT_LIMIT" {
		t.Errorf("expected EDGE_SYSV_SHM_SEGMENT_LIMIT, got %s", diag.RuleID)
	}
}

func TestRuleNetDevRxNoBuffers(t *testing.T) {
	rule := &RuleNetDevRxNoBuffers{}

	// Negative case: 0 missed errors
	diffNeg := &collector.SnapshotDiff{
		NetIfaces: []collector.NetIfaceDiff{
			{Name: "eth0", OperState: "up", RxMissedErrorsDelta: 0, RxFIFOErrorsDelta: 0},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetDevRxNoBuffers not to trigger on 0 drops")
	}

	// Positive case: 50 missed errors on active iface
	diffPos := &collector.SnapshotDiff{
		NetIfaces: []collector.NetIfaceDiff{
			{Name: "eth0", OperState: "up", RxMissedErrorsDelta: 50, RxFIFOErrorsDelta: 10},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetDevRxNoBuffers to trigger")
	}
	if diag.RuleID != "EDGE_NET_DEV_RX_NO_BUFFERS" {
		t.Errorf("expected EDGE_NET_DEV_RX_NO_BUFFERS, got %s", diag.RuleID)
	}
}

func TestRuleTHPDefragAlways(t *testing.T) {
	rule := &RuleTHPDefragAlways{}

	// Negative case: defrag mode is madvise
	diffNeg := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				THPDefragMode: "madvise",
			},
		},
		VMStat: collector.VMStatDiff{
			CompactStallDelta: 50,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected THPDefragAlways not to trigger with madvise")
	}

	// Positive case: defrag mode is always with compaction stalls
	diffPos := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				THPDefragMode: "always",
			},
		},
		VMStat: collector.VMStatDiff{
			CompactStallDelta:     25,
			AllocStallDirectDelta: 10,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected THPDefragAlways to trigger")
	}
	if diag.RuleID != "EDGE_TRANSPARENT_HUGEPAGE_DEFRAG_ALWAYS" {
		t.Errorf("expected EDGE_TRANSPARENT_HUGEPAGE_DEFRAG_ALWAYS, got %s", diag.RuleID)
	}
}

func TestRuleCgroupMemoryMaxOOMStall(t *testing.T) {
	rule := &RuleCgroupMemoryMaxOOMStall{}

	// Negative case: 0 max events
	diffNeg := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test", MemEventsMaxDelta: 0},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected CgroupMemoryMaxOOMStall not to trigger on 0 events")
	}

	// Positive case: 12 max events with process in cgroup
	diffPos := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test", MemEventsMaxDelta: 12},
		},
		Processes: []collector.ProcessDiff{
			{PID: 900, Comm: "container_worker", CgroupPath: "/docker/test"},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected CgroupMemoryMaxOOMStall to trigger")
	}
	if diag.RuleID != "EDGE_CGROUP_MEMORY_MAX_OOM_STALL" {
		t.Errorf("expected EDGE_CGROUP_MEMORY_MAX_OOM_STALL, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 900 {
		t.Errorf("expected CulpritPID 900, got %d", diag.CulpritPID)
	}
}

func TestRuleTHPScanExhaustionStall(t *testing.T) {
	rule := &RuleTHPScanExhaustionStall{}

	// Negative case: low scan exceeded
	diffNeg := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPScanExceedDelta: 10,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected THPScanExhaustionStall not to trigger on 10 events")
	}

	// Positive case: 75 scan exceeded events
	diffPos := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPScanExceedDelta: 75,
			CompactStallDelta:  20,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected THPScanExhaustionStall to trigger")
	}
	if diag.RuleID != "EDGE_THP_SCAN_EXHAUSTION_STALL" {
		t.Errorf("expected EDGE_THP_SCAN_EXHAUSTION_STALL, got %s", diag.RuleID)
	}
}

func TestRuleNetDevTxQueueTimeout(t *testing.T) {
	rule := &RuleNetDevTxQueueTimeout{}

	// Negative case: 0 tx errors
	diffNeg := &collector.SnapshotDiff{
		NetIfaces: []collector.NetIfaceDiff{
			{Name: "eth0", OperState: "up", TxErrorsDelta: 0},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetDevTxQueueTimeout not to trigger on 0 errors")
	}

	// Positive case: 30 tx errors on active link
	diffPos := &collector.SnapshotDiff{
		NetIfaces: []collector.NetIfaceDiff{
			{Name: "eth0", OperState: "up", TxErrorsDelta: 30, TxCarrierErrorsDelta: 2},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetDevTxQueueTimeout to trigger")
	}
	if diag.RuleID != "EDGE_NET_DEV_TX_QUEUE_TIMEOUT" {
		t.Errorf("expected EDGE_NET_DEV_TX_QUEUE_TIMEOUT, got %s", diag.RuleID)
	}
}

func TestRuleCgroupCPUCorePinStarvation(t *testing.T) {
	rule := &RuleCgroupCPUCorePinStarvation{}

	// Negative case: system CPU is busy (< 50% idle)
	diffNeg := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 20.0},
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "pinned", CgroupPath: "/docker/test", CpusAllowed: 1, CPUPercent: 95.0},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected CgroupCPUCorePinStarvation not to trigger when host is busy")
	}

	// Positive case: system CPU 80% idle, process pinned to 1 core at 95% CPU
	diffPos := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 80.0},
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "pinned", CgroupPath: "/docker/test", CpusAllowed: 1, CPUPercent: 95.0},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected CgroupCPUCorePinStarvation to trigger")
	}
	if diag.RuleID != "EDGE_CGROUP_CPU_CORE_PIN_STARVATION" {
		t.Errorf("expected EDGE_CGROUP_CPU_CORE_PIN_STARVATION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 100 {
		t.Errorf("expected CulpritPID 100, got %d", diag.CulpritPID)
	}
}

func TestRuleHugeTLBVMAFaultMisalign(t *testing.T) {
	rule := &RuleHugeTLBVMAFaultMisalign{}

	// Negative case: 0 fallbacks
	diffNeg := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPFaultFallbackDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected HugeTLBVMAFaultMisalign not to trigger on 0 fallbacks")
	}

	// Positive case: 75 fallbacks with 0 successful allocations
	diffPos := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPFaultFallbackDelta: 75,
			THPFaultAllocDelta:    0,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected HugeTLBVMAFaultMisalign to trigger")
	}
	if diag.RuleID != "EDGE_HUGETLB_VMA_MISALIGN_FAULT" {
		t.Errorf("expected EDGE_HUGETLB_VMA_MISALIGN_FAULT, got %s", diag.RuleID)
	}
}

func TestRuleTCPChronicRTOCollapse(t *testing.T) {
	rule := &RuleTCPChronicRTOCollapse{}

	// Negative case: 0 timeouts
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPTimeoutsDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected TCPChronicRTOCollapse not to trigger on 0 timeouts")
	}

	// Positive case: 20 RTO timeouts with retransmissions
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPTimeoutsDelta: 20,
			RetransSegsDelta: 100,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected TCPChronicRTOCollapse to trigger")
	}
	if diag.RuleID != "EDGE_TCP_CHRONIC_RTO_COLLAPSE" {
		t.Errorf("expected EDGE_TCP_CHRONIC_RTO_COLLAPSE, got %s", diag.RuleID)
	}
}

func TestRuleMemcgSockMemoryThrottle(t *testing.T) {
	rule := &RuleMemcgSockMemoryThrottle{}

	// Negative case: 0 high events
	diffNeg := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test", MemoryHighEventsDelta: 0},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected MemcgSockMemoryThrottle not to trigger on 0 events")
	}

	// Positive case: cgroup with memory high events and process with open sockets
	diffPos := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test", MemoryHighEventsDelta: 15},
		},
		Processes: []collector.ProcessDiff{
			{PID: 500, Comm: "net_worker", CgroupPath: "/docker/test", OpenFDs: 25},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected MemcgSockMemoryThrottle to trigger")
	}
	if diag.RuleID != "EDGE_MEMCG_SOCK_MEMORY_THROTTLE" {
		t.Errorf("expected EDGE_MEMCG_SOCK_MEMORY_THROTTLE, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 500 {
		t.Errorf("expected CulpritPID 500, got %d", diag.CulpritPID)
	}
}

func TestRuleTHPUseZeroPageSpin(t *testing.T) {
	rule := &RuleTHPUseZeroPageSpin{}

	// Negative case: low zero page allocs
	diffNeg := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPZeroPageAllocDelta: 10,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected THPUseZeroPageSpin not to trigger on 10 allocs")
	}

	// Positive case: 200 zero page allocs with high system CPU
	diffPos := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{SystemPercent: 20.0},
		VMStat: collector.VMStatDiff{
			THPZeroPageAllocDelta: 200,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected THPUseZeroPageSpin to trigger")
	}
	if diag.RuleID != "EDGE_TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_SPIN" {
		t.Errorf("expected EDGE_TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_SPIN, got %s", diag.RuleID)
	}
}

func TestRuleSysfsCPUHotplugLockContention(t *testing.T) {
	rule := &RuleSysfsCPUHotplugLockContention{}

	// Negative case: running process
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "worker", Wchan: "epoll_wait", State: 'S'},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected SysfsCPUHotplugLockContention not to trigger on epoll_wait")
	}

	// Positive case: blocked in cpu_hotplug_lock
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 777, Comm: "gov_daemon", Wchan: "cpu_hotplug_lock", State: 'D', CPUPercent: 0.0},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected SysfsCPUHotplugLockContention to trigger")
	}
	if diag.RuleID != "EDGE_SYSFS_CPU_HOTPLUG_LOCK_CONTENTION" {
		t.Errorf("expected EDGE_SYSFS_CPU_HOTPLUG_LOCK_CONTENTION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 777 {
		t.Errorf("expected CulpritPID 777, got %d", diag.CulpritPID)
	}
}

func TestRuleNetIPMulticastIGMPReportStall(t *testing.T) {
	rule := &RuleNetIPMulticastIGMPReportStall{}

	// Negative case: 0 inbound UDP errors
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			UDPInErrorsDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetIPMulticastIGMPReportStall not to trigger on 0 errors")
	}

	// Positive case: 100 inbound UDP errors
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			UDPInErrorsDelta:     100,
			UDPRcvbufErrorsDelta: 20,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetIPMulticastIGMPReportStall to trigger")
	}
	if diag.RuleID != "EDGE_NET_IP_MULTICAST_IGMP_REPORT_STALL" {
		t.Errorf("expected EDGE_NET_IP_MULTICAST_IGMP_REPORT_STALL, got %s", diag.RuleID)
	}
}

func TestRuleProcPIDTaskPthreadLimit(t *testing.T) {
	rule := &RuleProcPIDTaskPthreadLimit{}

	// Negative case: low thread count
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "light_proc", NumThreads: 10},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected ProcPIDTaskPthreadLimit not to trigger on 10 threads")
	}

	// Positive case: 600 threads
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 888, Comm: "heavy_threads", NumThreads: 600, State: 'S', CPUPercent: 5.0},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected ProcPIDTaskPthreadLimit to trigger")
	}
	if diag.RuleID != "EDGE_PROC_PID_TASK_PTHREAD_LIMIT" {
		t.Errorf("expected EDGE_PROC_PID_TASK_PTHREAD_LIMIT, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 888 {
		t.Errorf("expected CulpritPID 888, got %d", diag.CulpritPID)
	}
}

func TestRuleZoneNormalFragmentation(t *testing.T) {
	rule := &RuleZoneNormalFragmentation{}

	// Negative case: High-order chunks available
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				BuddyInfo: collector.ZoneBuddyInfo{
					Available:            true,
					NormalFreePages:      50000,
					NormalOrder0Pages:    100,
					NormalHighOrderPages: 40000,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected ZoneNormalFragmentation not to trigger on healthy high order pages")
	}

	// Positive case: 800 order-0 pages, 0 high-order pages
	diffFrag := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				BuddyInfo: collector.ZoneBuddyInfo{
					Available:            true,
					NormalFreePages:      800,
					NormalOrder0Pages:    800,
					NormalHighOrderPages: 0,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffFrag)
	if !triggered {
		t.Fatalf("expected ZoneNormalFragmentation to trigger")
	}
	if diag.RuleID != "EDGE_ZONE_NORMAL_FRAGMENTATION" {
		t.Errorf("expected EDGE_ZONE_NORMAL_FRAGMENTATION, got %s", diag.RuleID)
	}
}

func TestRuleNetDevCarrierDownDrop(t *testing.T) {
	rule := &RuleNetDevCarrierDownDrop{}

	// Negative case: interface is up
	diffClean := &collector.SnapshotDiff{
		NetIfaces: []collector.NetIfaceDiff{
			{Name: "eth0", OperState: "up", TxErrorsDelta: 0},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected NetDevCarrierDownDrop not to trigger on up interface")
	}

	// Positive case: interface down with Tx errors
	diffDown := &collector.SnapshotDiff{
		NetIfaces: []collector.NetIfaceDiff{
			{Name: "eth1", OperState: "down", TxErrorsDelta: 12},
		},
	}
	diag, triggered := rule.Evaluate(diffDown)
	if !triggered {
		t.Fatalf("expected NetDevCarrierDownDrop to trigger on down interface with errors")
	}
	if diag.RuleID != "EDGE_NET_DEV_CARRIER_DOWN_DROP" {
		t.Errorf("expected EDGE_NET_DEV_CARRIER_DOWN_DROP, got %s", diag.RuleID)
	}
}

func TestRuleProcPtracedStoppedStall(t *testing.T) {
	rule := &RuleProcPtracedStoppedStall{}

	// Negative case: running process
	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "worker", State: 'R', NumThreads: 4},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected ProcPtracedStoppedStall not to trigger on running process")
	}

	// Positive case: stopped process in state 'T'
	diffStopped := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 555, Comm: "debugged_app", State: 'T', NumThreads: 8, TracerPID: 1234},
		},
	}
	diag, triggered := rule.Evaluate(diffStopped)
	if !triggered {
		t.Fatalf("expected ProcPtracedStoppedStall to trigger on state T")
	}
	if diag.RuleID != "EDGE_PROC_PTRACED_STOPPED_STALL" {
		t.Errorf("expected EDGE_PROC_PTRACED_STOPPED_STALL, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 555 {
		t.Errorf("expected CulpritPID 555, got %d", diag.CulpritPID)
	}
}

func TestRuleMemSlabDentryPressure(t *testing.T) {
	rule := &RuleMemSlabDentryPressure{}

	// Negative case: low slab
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{MemTotal: 16 * 1024 * 1024 * 1024, SUnreclaim: 500 * 1024 * 1024},
		},
		VMStat: collector.VMStatDiff{PgScanDirectDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected MemSlabDentryPressure not to trigger on low slab")
	}

	// Positive case: 6GB slab unreclaimable on 16GB RAM with 200 direct scans
	diffBloated := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{MemTotal: 16 * 1024 * 1024 * 1024, SUnreclaim: 6 * 1024 * 1024 * 1024},
		},
		VMStat: collector.VMStatDiff{PgScanDirectDelta: 200},
	}
	diag, triggered := rule.Evaluate(diffBloated)
	if !triggered {
		t.Fatalf("expected MemSlabDentryPressure to trigger on bloated slab")
	}
	if diag.RuleID != "EDGE_MEM_SLAB_DENTRY_PRESSURE" {
		t.Errorf("expected EDGE_MEM_SLAB_DENTRY_PRESSURE, got %s", diag.RuleID)
	}
}

func TestRuleNetIPReasmTimeoutStall(t *testing.T) {
	rule := &RuleNetIPReasmTimeoutStall{}

	// Negative case: 0 timeouts
	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{IPReasmTimeoutDelta: 0, IPReasmFailsDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected NetIPReasmTimeoutStall not to trigger on 0 timeouts")
	}

	// Positive case: 10 timeouts
	diffTimeouts := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{IPReasmTimeoutDelta: 10, IPReasmFailsDelta: 25},
	}
	diag, triggered := rule.Evaluate(diffTimeouts)
	if !triggered {
		t.Fatalf("expected NetIPReasmTimeoutStall to trigger on 10 timeouts")
	}
	if diag.RuleID != "EDGE_NET_IP_REASM_TIMEOUT_STALL" {
		t.Errorf("expected EDGE_NET_IP_REASM_TIMEOUT_STALL, got %s", diag.RuleID)
	}
}

func TestRuleMemMinWatermarkBounce(t *testing.T) {
	rule := &RuleMemMinWatermarkBounce{}

	// Negative case: 0 direct scans
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{MemTotal: 16 * 1024 * 1024 * 1024, MemAvailable: 10 * 1024 * 1024 * 1024},
		},
		VMStat: collector.VMStatDiff{PgScanDirectDelta: 0, AllocStallDirectDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected MemMinWatermarkBounce not to trigger on healthy available RAM")
	}

	// Positive case: MemAvailable is 1GB (< 10% of 16GB) with 100 direct scans and 0 direct stalls
	diffBouncing := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{MemTotal: 16 * 1024 * 1024 * 1024, MemAvailable: 1 * 1024 * 1024 * 1024},
		},
		VMStat: collector.VMStatDiff{PgScanDirectDelta: 100, AllocStallDirectDelta: 0},
	}
	diag, triggered := rule.Evaluate(diffBouncing)
	if !triggered {
		t.Fatalf("expected MemMinWatermarkBounce to trigger on watermark bounce")
	}
	if diag.RuleID != "EDGE_MEM_MIN_WATERMARK_BOUNCE" {
		t.Errorf("expected EDGE_MEM_MIN_WATERMARK_BOUNCE, got %s", diag.RuleID)
	}
}

func TestRuleProcCommSwitchTruncation(t *testing.T) {
	rule := &RuleProcCommSwitchTruncation{}

	// Negative case: normal thread
	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "normal_proc", NumThreads: 20, Wchan: "epoll_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected ProcCommSwitchTruncation not to trigger on normal threads")
	}

	// Positive case: 200 threads in do_prctl
	diffChurn := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 777, Comm: "churn_proc", NumThreads: 200, Wchan: "do_prctl"},
		},
	}
	diag, triggered := rule.Evaluate(diffChurn)
	if !triggered {
		t.Fatalf("expected ProcCommSwitchTruncation to trigger on do_prctl")
	}
	if diag.RuleID != "EDGE_PROC_COMM_SWITCH_TRUNCATION" {
		t.Errorf("expected EDGE_PROC_COMM_SWITCH_TRUNCATION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 777 {
		t.Errorf("expected CulpritPID 777, got %d", diag.CulpritPID)
	}
}

func TestRuleEpollPollTimeoutBurst(t *testing.T) {
	rule := &RuleEpollPollTimeoutBurst{}

	// Negative case: active worker
	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "active_epoll", NumThreads: 10, Wchan: "epoll_wait", CPUPercent: 5.0},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected EpollPollTimeoutBurst not to trigger on active worker")
	}

	// Positive case: 60 threads in epoll_pwait with 0.0% CPU and 120 FDs
	diffStalled := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 900, Comm: "idle_server", NumThreads: 60, Wchan: "epoll_pwait", CPUPercent: 0.05, OpenFDs: 120},
		},
	}
	diag, triggered := rule.Evaluate(diffStalled)
	if !triggered {
		t.Fatalf("expected EpollPollTimeoutBurst to trigger on epoll idle churn")
	}
	if diag.RuleID != "EDGE_EPOLL_POLL_TIMEOUT_BURST" {
		t.Errorf("expected EDGE_EPOLL_POLL_TIMEOUT_BURST, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 900 {
		t.Errorf("expected CulpritPID 900, got %d", diag.CulpritPID)
	}
}

func TestRuleNetTCPSynFloodDrop(t *testing.T) {
	rule := &RuleNetTCPSynFloodDrop{}

	// Negative case: 0 failed syncookies
	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{SyncookiesFailedDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected NetTCPSynFloodDrop not to trigger on 0 failed cookies")
	}

	// Positive case: 15 failed syncookies
	diffFlood := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{SyncookiesFailedDelta: 15},
	}
	diag, triggered := rule.Evaluate(diffFlood)
	if !triggered {
		t.Fatalf("expected NetTCPSynFloodDrop to trigger on 15 failed cookies")
	}
	if diag.RuleID != "EDGE_NET_TCP_SYN_FLOOD_DROP" {
		t.Errorf("expected EDGE_NET_TCP_SYN_FLOOD_DROP, got %s", diag.RuleID)
	}
}

func TestRuleSysfsPowerThrottleEvent(t *testing.T) {
	rule := &RuleSysfsPowerThrottleEvent{}

	// Negative case: normal thermal state
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 55.0},
			CPUFreq: collector.CPUFreqInfo{
				Available: true,
				Cores:     []collector.CoreFreq{{CurFreq: 3000000, MaxFreq: 3000000}},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected SysfsPowerThrottleEvent not to trigger on clean thermal")
	}

	// Positive case: 78°C with core frequency at 2.0GHz vs 3.2GHz max (< 0.75x)
	diffThrottled := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 78.0},
			CPUFreq: collector.CPUFreqInfo{
				Available: true,
				Cores:     []collector.CoreFreq{{CurFreq: 2000000, MaxFreq: 3200000}},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffThrottled)
	if !triggered {
		t.Fatalf("expected SysfsPowerThrottleEvent to trigger on power/thermal event")
	}
	if diag.RuleID != "EDGE_SYSFS_POWER_THROTTLE_EVENT" {
		t.Errorf("expected EDGE_SYSFS_POWER_THROTTLE_EVENT, got %s", diag.RuleID)
	}
}

func TestRuleProcZombieParentDeadlock(t *testing.T) {
	rule := &RuleProcZombieParentDeadlock{}

	// Negative case: 0 zombies
	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 1, Comm: "systemd", State: 'S', Wchan: "do_epoll_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected ProcZombieParentDeadlock not to trigger on 0 zombies")
	}

	// Positive case: parent in wait4 with 12 zombies
	procs := make([]collector.ProcessDiff, 0, 15)
	procs = append(procs, collector.ProcessDiff{PID: 10, Comm: "supervisor", State: 'S', Wchan: "wait4"})
	for i := 11; i <= 23; i++ {
		procs = append(procs, collector.ProcessDiff{PID: i, Comm: "zombie_worker", State: 'Z', PPID: 10})
	}
	diffZombies := &collector.SnapshotDiff{Processes: procs}

	diag, triggered := rule.Evaluate(diffZombies)
	if !triggered {
		t.Fatalf("expected ProcZombieParentDeadlock to trigger on wait4 with 12 zombies")
	}
	if diag.RuleID != "EDGE_PROC_ZOMBIE_PARENT_DEADLOCK" {
		t.Errorf("expected EDGE_PROC_ZOMBIE_PARENT_DEADLOCK, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 10 {
		t.Errorf("expected CulpritPID 10, got %d", diag.CulpritPID)
	}
}

func TestRuleIOSchedulerMismatch(t *testing.T) {
	rule := &RuleIOSchedulerMismatch{}

	tests := []struct {
		name       string
		disks      []collector.DiskDeviceDiff
		shouldFire bool
	}{
		{
			name: "SSD with bfq and high latency fires",
			disks: []collector.DiskDeviceDiff{
				{DeviceName: "nvme0n1", Rotational: false, Scheduler: "bfq", AvgQueueLatencyMS: 25.0},
			},
			shouldFire: true,
		},
		{
			name: "HDD with none and high latency fires",
			disks: []collector.DiskDeviceDiff{
				{DeviceName: "sda", Rotational: true, Scheduler: "none", AvgQueueLatencyMS: 30.0},
			},
			shouldFire: true,
		},
		{
			name: "SSD with none is optimal",
			disks: []collector.DiskDeviceDiff{
				{DeviceName: "nvme0n1", Rotational: false, Scheduler: "none", AvgQueueLatencyMS: 25.0},
			},
			shouldFire: false,
		},
		{
			name: "HDD with mq-deadline is optimal",
			disks: []collector.DiskDeviceDiff{
				{DeviceName: "sda", Rotational: true, Scheduler: "mq-deadline", AvgQueueLatencyMS: 25.0},
			},
			shouldFire: false,
		},
		{
			name: "SSD with bfq but low latency does not fire",
			disks: []collector.DiskDeviceDiff{
				{DeviceName: "nvme0n1", Rotational: false, Scheduler: "bfq", AvgQueueLatencyMS: 15.0},
			},
			shouldFire: false,
		},
		{
			name: "Missing scheduler does not fire",
			disks: []collector.DiskDeviceDiff{
				{DeviceName: "nvme0n1", Rotational: false, Scheduler: "", AvgQueueLatencyMS: 35.0},
			},
			shouldFire: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			diff := &collector.SnapshotDiff{Disks: tc.disks}
			diag, fired := rule.Evaluate(diff)
			if fired != tc.shouldFire {
				t.Fatalf("expected fired=%v, got %v", tc.shouldFire, fired)
			}
			if fired && diag.Severity != SeverityMedium {
				t.Errorf("expected SeverityMedium, got %v", diag.Severity)
			}
		})
	}
}

func TestRuleOOMImmuneMemoryHog(t *testing.T) {
	rule := &RuleOOMImmuneMemoryHog{}
	const totalKB uint64 = 1000 * 1024

	tests := []struct {
		name       string
		availKB    uint64
		procs      []collector.ProcessDiff
		shouldFire bool
	}{
		{
			name:    "Immune hog consuming 40% RAM under pressure fires",
			availKB: 100 * 1024,
			procs: []collector.ProcessDiff{
				{PID: 4000, Comm: "bad_hog", OOMScoreAdj: -1000, RSSBytes: 400 * 1024 * 1024},
			},
			shouldFire: true,
		},
		{
			name:    "Whitelisted systemd is ignored",
			availKB: 100 * 1024,
			procs: []collector.ProcessDiff{
				{PID: 1, Comm: "systemd", OOMScoreAdj: -1000, RSSBytes: 400 * 1024 * 1024},
			},
			shouldFire: false,
		},
		{
			name:    "Non-immune process with normal oom_score_adj does not fire",
			availKB: 100 * 1024,
			procs: []collector.ProcessDiff{
				{PID: 4001, Comm: "normal_proc", OOMScoreAdj: 0, RSSBytes: 400 * 1024 * 1024},
			},
			shouldFire: false,
		},
		{
			name:    "Immune proc below 30% threshold does not fire",
			availKB: 100 * 1024,
			procs: []collector.ProcessDiff{
				{PID: 4002, Comm: "small_proc", OOMScoreAdj: -1000, RSSBytes: 200 * 1024 * 1024},
			},
			shouldFire: false,
		},
		{
			name:    "Immune hog without memory pressure does not fire",
			availKB: 300 * 1024,
			procs: []collector.ProcessDiff{
				{PID: 4003, Comm: "bad_hog", OOMScoreAdj: -1000, RSSBytes: 400 * 1024 * 1024},
			},
			shouldFire: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			diff := &collector.SnapshotDiff{
				LatestSnapshot: &collector.SystemSnapshot{
					Memory: collector.MemInfo{MemTotal: totalKB, MemAvailable: tc.availKB},
				},
				Processes: tc.procs,
			}
			diag, fired := rule.Evaluate(diff)
			if fired != tc.shouldFire {
				t.Fatalf("expected fired=%v, got %v", tc.shouldFire, fired)
			}
			if fired && diag.Severity != SeverityHigh {
				t.Errorf("expected SeverityHigh, got %v", diag.Severity)
			}
		})
	}
}
