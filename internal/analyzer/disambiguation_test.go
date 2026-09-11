// Package analyzer_test validates that the intelligence engine
// reliably discriminates between overlapping failure modes across all 5 symptom clusters
// and guarantees that Tier 1 root causes dominate secondary contributing factors.
package analyzer_test

import (
	"fmt"
	"testing"
	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
)

// Helper to run engine analysis in tests
func analyzeSnapshotDiff(diff *collector.SnapshotDiff, isRoot bool) *analyzer.DiagnosticReport {
	eng := analyzer.NewEngine()
	eng.DisableEarlyExit = true
	return eng.Analyze(diff, collector.RunContext{IsRoot: isRoot, EffectiveUID: 0})
}

// ============================================================================
// CLUSTER 1: CPU Starvation & Slowness Ambiguities
// ============================================================================

func TestDisambiguation_Cluster1_CPUSaturation_vs_Others(t *testing.T) {
	// Scenario: Real host CPU saturation (all cores busy, heavy runqueue)
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.8, BusyPercent: 99.2},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{IdlePercent: 0.5}, {IdlePercent: 1.0}, {IdlePercent: 0.8}, {IdlePercent: 0.9},
		},
		ProcsRunning: 16,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{
					{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"},
				},
			},
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 60.0},
			CPUFreq: collector.CPUFreqInfo{
				Available: true,
				Cores: []collector.CoreFreq{
					{CoreID: 0, CurFreq: 3400000, MaxFreq: 3400000},
				},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "heavy_calc", CPUPercent: 390.0, CPUTimeDelta: 390},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for CPU saturation, got nil")
	}
	if report.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected BASE_CPU_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_Cluster1_VCPUSteal_vs_Saturation(t *testing.T) {
	// Scenario: Steal time on hypervisor guest (aggregate steal > 15%, but guest CPU idle is moderate)
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 20.0, StealPercent: 45.0, BusyPercent: 35.0},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{StealPercent: 50.0}, {StealPercent: 40.0},
		},
		ProcsRunning: 2,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{
					{ID: "cpu0"}, {ID: "cpu1"},
				},
			},
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 50.0},
			CPUFreq: collector.CPUFreqInfo{
				Available: true,
				Cores:     []collector.CoreFreq{{CoreID: 0, CurFreq: 2400000, MaxFreq: 2400000}},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for VCPU Steal, got nil")
	}
	if report.PrimaryBlocker.RuleID != "CONT_VCPU_STEAL_TIME" {
		t.Errorf("expected CONT_VCPU_STEAL_TIME, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_Cluster1_CgroupThrottle_vs_HostSaturation(t *testing.T) {
	// Scenario: Host CPU is 85% idle, but container cgroup is throttled (throttled_usec > 100ms)
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 85.0, BusyPercent: 15.0},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{IdlePercent: 85.0},
		},
		ProcsRunning: 2,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}},
			},
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 45.0},
		},
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test_container", ThrottledUsecDelta: 350000, NrThrottledDelta: 25},
		},
		Processes: []collector.ProcessDiff{
			{PID: 202, Comm: "worker", CgroupPath: "/docker/test_container", CPUPercent: 95.0},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for Cgroup Throttled, got nil")
	}
	if report.PrimaryBlocker.RuleID != "CONT_CGROUP_THROTTLED" {
		t.Errorf("expected CONT_CGROUP_THROTTLED, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_Cluster1_CPUAffinityPin_vs_HostSaturation(t *testing.T) {
	// Scenario: 1 process pinned to CPU 0 pinned at 98%, host aggregate idle is 80%
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 80.0, BusyPercent: 20.0},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{IdlePercent: 0.0}, {IdlePercent: 100.0}, {IdlePercent: 100.0}, {IdlePercent: 100.0},
		},
		ProcsRunning: 2,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{
					{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"},
				},
			},
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 50.0},
		},
		Processes: []collector.ProcessDiff{
			{PID: 303, Comm: "pinned_app", CPUPercent: 98.0, CpusAllowed: 1},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for CPU Affinity Pin, got nil")
	}
	if report.PrimaryBlocker.RuleID != "EDGE_CPU_AFFINITY_PIN" {
		t.Errorf("expected EDGE_CPU_AFFINITY_PIN, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_Cluster1_ThermalThrottling_vs_CPUSaturation(t *testing.T) {
	// Scenario: CPU frequency severely degraded (< 40% max) due to high heat (92°C)
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 50.0, BusyPercent: 50.0},
		ProcsRunning: 2,
		LatestSnapshot: &collector.SystemSnapshot{
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 94.5},
			CPUFreq: collector.CPUFreqInfo{
				Available: true,
				Cores: []collector.CoreFreq{
					{CoreID: 0, CurFreq: 800000, MaxFreq: 3800000},
				},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for Thermal Throttling, got nil")
	}
	if report.PrimaryBlocker.RuleID != "BASE_THERMAL_THROTTLING" {
		t.Errorf("expected BASE_THERMAL_THROTTLING, got %s", report.PrimaryBlocker.RuleID)
	}
}

// ============================================================================
// CLUSTER 2: Memory Starvation & Allocation Latency
// ============================================================================

func TestDisambiguation_Cluster2_OOMDanger_vs_CgroupOOM(t *testing.T) {
	// Scenario A: Whole host OOM danger (RAM < 3% and swap empty)
	diffHostOOM := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     32000000,
				MemAvailable: 400000, // 1.25%
				SwapTotal:    8000000,
				SwapFree:     100000, // 1.25%
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 501, Comm: "big_app", RSSBytes: 30000000 * 1024, OOMScore: 900},
		},
	}
	reportHost := analyzeSnapshotDiff(diffHostOOM, true)
	if reportHost.PrimaryBlocker == nil || reportHost.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Fatalf("expected BASE_OOM_DANGER, got %+v", reportHost.PrimaryBlocker)
	}

	// Scenario B: Host memory is completely fine (20GB free), but a single container hit its memory quota and had OOM kill
	diffCgroupOOM := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     32000000,
				MemAvailable: 20000000, // ~62% free
				SwapTotal:    8000000,
				SwapFree:     8000000,
			},
		},
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/mem_leaker", OOMKillsDelta: 1},
		},
		Processes: []collector.ProcessDiff{
			{PID: 502, Comm: "container_app", CgroupPath: "/docker/mem_leaker"},
		},
	}
	reportCgroup := analyzeSnapshotDiff(diffCgroupOOM, true)
	if reportCgroup.PrimaryBlocker == nil || reportCgroup.PrimaryBlocker.RuleID != "EDGE_CGROUP_OOM_KILL_EVENT" {
		t.Fatalf("expected EDGE_CGROUP_OOM_KILL_EVENT, got %+v", reportCgroup.PrimaryBlocker)
	}
}

func TestDisambiguation_Cluster2_DMA32Zone_vs_HostOOM(t *testing.T) {
	// Scenario: Host has 100GB free in Normal zone, but DMA32 zone has 0 free pages
	diffDMA := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     64000000,
				MemAvailable: 45000000,
				SwapTotal:    8000000,
				SwapFree:     8000000,
			},
			SystemConfig: collector.SystemConfigInfo{
				BuddyInfo: collector.ZoneBuddyInfo{
					Available:       true,
					DMA32FreePages:  0,
					NormalFreePages: 500000,
				},
			},
		},
	}

	report := analyzeSnapshotDiff(diffDMA, true)
	if report.PrimaryBlocker == nil || report.PrimaryBlocker.RuleID != "EDGE_ZONE_DMA32_EXHAUSTION" {
		t.Fatalf("expected EDGE_ZONE_DMA32_EXHAUSTION, got %+v", report.PrimaryBlocker)
	}
}

func TestDisambiguation_Cluster2_SwapThrashing_vs_BalloonOvercommit(t *testing.T) {
	// Scenario A: Swap thrashing with direct reclaim & PSI memory stall
	diffSwap := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     16000000,
				MemAvailable: 1500000,
				SwapTotal:    4000000,
				SwapFree:     500000,
			},
			VMStat: collector.VMStatInfo{
				PgScanDirect:     10000,
				AllocStallDirect: 500,
			},
			PSI: collector.PSIInfo{
				Available: true,
				Memory: collector.PSIResource{
					Some: collector.PSIMetrics{Avg10: 45.0},
				},
			},
		},
		VMStat: collector.VMStatDiff{
			PgScanDirectDelta:     5000,
			AllocStallDirectDelta: 100,
		},
	}
	reportSwap := analyzeSnapshotDiff(diffSwap, true)
	if reportSwap.PrimaryBlocker == nil || reportSwap.PrimaryBlocker.RuleID != "CONT_SWAP_THRASHING" {
		t.Fatalf("expected CONT_SWAP_THRASHING, got %+v", reportSwap.PrimaryBlocker)
	}

	// Scenario B: Balloon driver inflation > 20% total RAM
	diffBalloon := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     16000000,
				MemAvailable: 1800000, // < 15%
				SwapTotal:    4000000,
				SwapFree:     4000000,
			},
			SystemConfig: collector.SystemConfigInfo{
				Virt: collector.VirtInfo{
					BalloonBytes: 4000000 * 1024, // 25% of RAM
				},
			},
		},
	}
	reportBalloon := analyzeSnapshotDiff(diffBalloon, true)
	if reportBalloon.PrimaryBlocker == nil || reportBalloon.PrimaryBlocker.RuleID != "CONT_BALLOON_OVERCOMMIT" {
		t.Fatalf("expected CONT_BALLOON_OVERCOMMIT, got %+v", reportBalloon.PrimaryBlocker)
	}
}

// ============================================================================
// CLUSTER 3: Storage & I/O Latency Stalls
// ============================================================================

func TestDisambiguation_Cluster3_DiskSpace_vs_InodeExhaustion(t *testing.T) {
	// Scenario A: Disk bytes full (100% used, 0 bytes free, but inodes plenty)
	diffSpace := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			DiskSpace: collector.DiskSpaceInfo{
				Mounts: []collector.MountSpaceInfo{
					{Path: "/", UsedPercent: 99.8, AvailBytes: 0, InodesUsedPercent: 15.0, InodesFree: 5000000},
				},
			},
		},
	}
	reportSpace := analyzeSnapshotDiff(diffSpace, true)
	if reportSpace.PrimaryBlocker == nil || reportSpace.PrimaryBlocker.RuleID != "BASE_DISK_SPACE_FULL" {
		t.Fatalf("expected BASE_DISK_SPACE_FULL, got %+v", reportSpace.PrimaryBlocker)
	}

	// Scenario B: Inodes exhausted (0 free inodes, but 100GB disk bytes free)
	diffInode := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			DiskSpace: collector.DiskSpaceInfo{
				Mounts: []collector.MountSpaceInfo{
					{Path: "/var/spool", UsedPercent: 30.0, AvailBytes: 100 * 1024 * 1024 * 1024, InodesTotal: 1000000, InodesUsedPercent: 100.0, InodesFree: 0},
				},
			},
		},
	}
	reportInode := analyzeSnapshotDiff(diffInode, true)
	if reportInode.PrimaryBlocker == nil || reportInode.PrimaryBlocker.RuleID != "BASE_INODE_EXHAUSTION" {
		t.Fatalf("expected BASE_INODE_EXHAUSTION, got %+v", reportInode.PrimaryBlocker)
	}
}

func TestDisambiguation_Cluster3_HardwareSaturation_vs_IOServiceLatency(t *testing.T) {
	// Scenario A: Disk hardware busy 99% of time
	diffHWSat := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 99.0, ReadBytesDelta: 500000000, WriteBytesDelta: 100000000},
		},
	}
	reportHWSat := analyzeSnapshotDiff(diffHWSat, true)
	if reportHWSat.PrimaryBlocker == nil || reportHWSat.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Fatalf("expected BASE_DISK_HARDWARE_SATURATION, got %+v", reportHWSat.PrimaryBlocker)
	}

	// Scenario B: Disk utilization low (20%), but SAN/EBS service latency is 95ms
	diffLatency := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "sdb", UtilPercent: 20.0, ReadsCompletedDelta: 100, WritesCompletedDelta: 100, AvgReadLatencyMS: 95.0, AvgWriteLatencyMS: 110.0},
		},
	}
	reportLatency := analyzeSnapshotDiff(diffLatency, true)
	if reportLatency.PrimaryBlocker == nil || reportLatency.PrimaryBlocker.RuleID != "BASE_IO_SERVICE_LATENCY" {
		t.Fatalf("expected BASE_IO_SERVICE_LATENCY, got %+v", reportLatency.PrimaryBlocker)
	}
}

// ============================================================================
// CLUSTER 4: Network & Connection Failures
// ============================================================================

func TestDisambiguation_Cluster4_ListenDrops_vs_TimeWait_vs_Conntrack(t *testing.T) {
	// Scenario A: Server listen drops on inbound accept backlog
	diffListen := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{ListenDropsDelta: 45},
	}
	reportListen := analyzeSnapshotDiff(diffListen, true)
	if reportListen.PrimaryBlocker == nil || reportListen.PrimaryBlocker.RuleID != "CONT_TCP_LISTEN_DROPS" {
		t.Fatalf("expected CONT_TCP_LISTEN_DROPS, got %+v", reportListen.PrimaryBlocker)
	}

	// Scenario B: Outbound ephemeral port exhaustion (TIME_WAIT >= 85% range)
	diffTimeWait := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				SockStat: collector.SockStatInfo{
					TCPTimeWait: 27000,
				},
				PortRange: collector.PortRangeInfo{
					Low:  32768,
					High: 60999, // Capacity = 28232; 27000 is ~95.6%
				},
			},
		},
	}
	reportTimeWait := analyzeSnapshotDiff(diffTimeWait, true)
	if reportTimeWait.PrimaryBlocker == nil || reportTimeWait.PrimaryBlocker.RuleID != "CONT_TIMEWAIT_PORT_EXHAUSTION" {
		t.Fatalf("expected CONT_TIMEWAIT_PORT_EXHAUSTION, got %+v", reportTimeWait.PrimaryBlocker)
	}

	// Scenario C: Netfilter conntrack table saturation (95% full)
	diffConntrack := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Conntrack: collector.ConntrackInfo{
					Available: true,
					Count:     250000,
					Max:       262144, // 95.3%
					Ratio:     0.953,
				},
			},
		},
	}
	reportConntrack := analyzeSnapshotDiff(diffConntrack, true)
	if reportConntrack.PrimaryBlocker == nil || reportConntrack.PrimaryBlocker.RuleID != "CONT_CONNTRACK_EXHAUSTION" {
		t.Fatalf("expected CONT_CONNTRACK_EXHAUSTION, got %+v", reportConntrack.PrimaryBlocker)
	}
}

func TestDisambiguation_Cluster4_SoftIRQUnbalance_vs_IRQStorm(t *testing.T) {
	// Scenario A: SoftIRQ unbalance (1 core softirq 85%, system idle 70%)
	diffSoftIRQ := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 70.0},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{SoftIRQPercent: 88.0},
			{SoftIRQPercent: 1.0},
			{SoftIRQPercent: 0.5},
			{SoftIRQPercent: 0.5},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{
					{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"},
				},
			},
		},
	}
	reportSoftIRQ := analyzeSnapshotDiff(diffSoftIRQ, true)
	if reportSoftIRQ.PrimaryBlocker == nil || reportSoftIRQ.PrimaryBlocker.RuleID != "CONT_SOFTIRQ_UNBALANCE" {
		t.Fatalf("expected CONT_SOFTIRQ_UNBALANCE, got %+v", reportSoftIRQ.PrimaryBlocker)
	}

	// Scenario B: Hardware IRQ Storm on 1 core (> 50,000 IRQs and 10x others)
	diffIRQ := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				IRQStat: collector.IRQStatInfo{
					Available:         true,
					MaxCoreIRQs:       75000,
					MaxCoreID:         0,
					OtherCoresAvgIRQs: 1200,
				},
			},
		},
	}
	reportIRQ := analyzeSnapshotDiff(diffIRQ, true)
	if reportIRQ.PrimaryBlocker == nil || reportIRQ.PrimaryBlocker.RuleID != "EDGE_IRQ_CORE_STORM" {
		t.Fatalf("expected EDGE_IRQ_CORE_STORM, got %+v", reportIRQ.PrimaryBlocker)
	}
}

// ============================================================================
// CLUSTER 5: Process Freezes & Table Exhaustion
// ============================================================================

func TestDisambiguation_Cluster5_PTYLock_vs_Futex_vs_ZombieLeak(t *testing.T) {
	// Scenario A: PTY stdout buffer lock (wchan = n_tty_write, State = 'S')
	diffPTY := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 701, Comm: "noisy_logger", State: 'S', Wchan: "n_tty_write"},
		},
	}
	reportPTY := analyzeSnapshotDiff(diffPTY, true)
	if reportPTY.PrimaryBlocker == nil || reportPTY.PrimaryBlocker.RuleID != "EDGE_PTY_STDOUT_LOCK" {
		t.Fatalf("expected EDGE_PTY_STDOUT_LOCK, got %+v", reportPTY.PrimaryBlocker)
	}

	// Scenario B: Futex lock contention (50+ threads on futex_wait_queue_me)
	diffFutex := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 702, Comm: "locked_server", NumThreads: 64, Wchan: "futex_wait_queue_me"},
		},
	}
	reportFutex := analyzeSnapshotDiff(diffFutex, true)
	if reportFutex.PrimaryBlocker == nil || reportFutex.PrimaryBlocker.RuleID != "EDGE_FUTEX_CONTENTION" {
		t.Fatalf("expected EDGE_FUTEX_CONTENTION, got %+v", reportFutex.PrimaryBlocker)
	}

	// Scenario C: Zombie process leak (60 zombie processes unreaped)
	zombieProcs := make([]collector.ProcessDiff, 0, 65)
	for i := 1000; i < 1060; i++ {
		zombieProcs = append(zombieProcs, collector.ProcessDiff{
			PID:   i,
			PPID:  999,
			Comm:  "child_task",
			State: 'Z',
		})
	}
	diffZombie := &collector.SnapshotDiff{Processes: zombieProcs}
	reportZombie := analyzeSnapshotDiff(diffZombie, true)
	if reportZombie.PrimaryBlocker == nil || reportZombie.PrimaryBlocker.RuleID != "EDGE_ZOMBIE_DEFUNCT_LEAK" {
		t.Fatalf("expected EDGE_ZOMBIE_DEFUNCT_LEAK, got %+v", reportZombie.PrimaryBlocker)
	}
}

// ============================================================================
// TIER 1 ROOT CAUSE ISOLATION & DEMOTION VERIFICATION
// ============================================================================

func TestDisambiguation_Tier1_RootCauseDemotion(t *testing.T) {
	// Scenario: Tier 1 Hardware Saturation occurs alongside Tier 2 D-State processes
	// and Tier 3 Dirty Page Throttle.
	// Engine MUST elect Tier 1 as PrimaryBlocker and demote Tier 2/3.
	diff := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "sda", UtilPercent: 98.5, WriteBytesDelta: 400 * 1024 * 1024},
		},
		Processes: []collector.ProcessDiff{
			{PID: 801, Comm: "flush1", State: 'D', Wchan: "ext4_writepages"},
			{PID: 802, Comm: "flush2", State: 'D', Wchan: "ext4_writepages"},
			{PID: 803, Comm: "flush3", State: 'D', Wchan: "ext4_writepages"},
			{PID: 804, Comm: "writer", State: 'D', Wchan: "balance_dirty_pages_ratelimited"},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker, got nil")
	}

	// Primary MUST be Tier 1 Hardware Saturation
	if report.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_DISK_HARDWARE_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}
	if report.PrimaryBlocker.Tier != 1 {
		t.Errorf("expected Tier 1 primary, got Tier %d", report.PrimaryBlocker.Tier)
	}

	// CONT_DSTATE_PILEUP should be SUPPRESSED by BASE_DISK_HARDWARE_SATURATION (causal chain)
	// EDGE_CGROUP_DIRTY_THROTTLE should still appear (not suppressed)
	foundDirtyThrottle := false

	allSecondary := append(report.ContributingFactors, report.SecondaryIssues...)
	for _, diag := range allSecondary {
		if diag.RuleID == "CONT_DSTATE_PILEUP" {
			t.Errorf("expected CONT_DSTATE_PILEUP to be suppressed, but found in output")
		}
		if diag.RuleID == "EDGE_CGROUP_DIRTY_THROTTLE" {
			foundDirtyThrottle = true
		}
	}

	if !foundDirtyThrottle {
		t.Errorf("expected EDGE_CGROUP_DIRTY_THROTTLE demoted into contributing/secondary")
	}
}

func TestDisambiguation_SwapDeviceSaturation_vs_Thrashing(t *testing.T) {
	// Scenario: Massive swap writeout saturates storage (Tier 1) alongside direct reclamation stalls (Tier 2).
	// Tier 1 Swap Device Saturation MUST be PrimaryBlocker and Swap Thrashing demoted.
	diff := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			PswpinDelta:           8000,
			PswpoutDelta:          30000,
			PgScanDirectDelta:     500,
			AllocStallDirectDelta: 200,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for swap saturation, got nil")
	}
	if report.PrimaryBlocker.RuleID != "BASE_SWAP_DEVICE_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_SWAP_DEVICE_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	foundThrashing := false
	for _, diag := range append(report.ContributingFactors, report.SecondaryIssues...) {
		if diag.RuleID == "CONT_SWAP_THRASHING" {
			foundThrashing = true
			break
		}
	}
	if !foundThrashing {
		t.Errorf("expected CONT_SWAP_THRASHING in contributing/secondary issues")
	}
}

func TestDisambiguation_PageTableLock_vs_Futex(t *testing.T) {
	// Scenario: Multi-threaded app blocked on mmap_read_lock should trigger CONT_PAGE_TABLE_LOCK, not FUTEX
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "db_worker", Wchan: "mmap_read_lock", NumThreads: 64},
			{PID: 102, Comm: "db_worker", Wchan: "page_table_lock", NumThreads: 64},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for page table lock, got nil")
	}
	if report.PrimaryBlocker.RuleID != "CONT_PAGE_TABLE_LOCK" {
		t.Errorf("expected CONT_PAGE_TABLE_LOCK, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_ContextSwitchStorm_vs_CPUSaturation(t *testing.T) {
	// When Tier 1 CPU Saturation is present (Idle < 2%, ProcsRunning >= 2x cores),
	// it dominates over Tier 2 Context Switch Storm.
	diff := &collector.SnapshotDiff{
		TotalCPUUtil:         collector.CPUUtilization{IdlePercent: 1.0, SystemPercent: 30.0, BusyPercent: 99.0},
		PerCoreCPUUtil:       []collector.CPUUtilization{{IdlePercent: 1.0}, {IdlePercent: 1.0}},
		ProcsRunning:         10,
		ContextSwitchesDelta: 180000,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for CPU saturation")
	}
	if report.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_CPU_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	// CONT_CONTEXT_SWITCH_STORM should be SUPPRESSED by BASE_CPU_SATURATION (causal chain)
	for _, diag := range append(report.ContributingFactors, report.SecondaryIssues...) {
		if diag.RuleID == "CONT_CONTEXT_SWITCH_STORM" {
			t.Errorf("expected CONT_CONTEXT_SWITCH_STORM to be suppressed by BASE_CPU_SATURATION, but found in output")
		}
	}
}

func TestDisambiguation_FsyncJournalStall_vs_DiskHWSaturation(t *testing.T) {
	// When Tier 1 Disk Hardware Saturation is active (Util >= 95%),
	// it dominates over Tier 2 Fsync Journal Stall.
	diff := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 98.0, AvgWriteLatencyMS: 25.0},
		},
		Processes: []collector.ProcessDiff{
			{PID: 201, Comm: "postgres", Wchan: "jbd2_log_wait_commit"},
			{PID: 202, Comm: "postgres", Wchan: "vfs_fsync"},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_DISK_HARDWARE_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_THPSplitStorm_vs_CompactionStall(t *testing.T) {
	// When THP split storm occurs without Tier 1/2 blocker, EDGE_THP_SPLIT_STORM triggers cleanly.
	diff := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPSplitDelta:         2500,
			AllocStallDirectDelta: 10,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "EDGE_THP_SPLIT_STORM" {
		t.Errorf("expected EDGE_THP_SPLIT_STORM, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_CoredumpBurst_vs_ZombieLeak(t *testing.T) {
	// When crash dumper process is actively dumping cores with high fork rate,
	// CONT_COREDUMP_BURST_STORM takes precedence as Tier 2 over Tier 3 Zombie Defunct Leak.
	diff := &collector.SnapshotDiff{
		ProcessesCreatedDelta: 40,
		Processes: []collector.ProcessDiff{
			{PID: 900, Comm: "systemd-coredum", CPUPercent: 65.0},
			{PID: 901, Comm: "dead_worker", State: 'Z', PPID: 800},
			{PID: 902, Comm: "dead_worker", State: 'Z', PPID: 800},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "CONT_COREDUMP_BURST_STORM" {
		t.Errorf("expected PrimaryBlocker CONT_COREDUMP_BURST_STORM, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_TCPRetransmit_vs_ListenDrops(t *testing.T) {
	// Multiple network layer issues: listen queue drop vs TCP retransmission storm
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			ListenDropsDelta: 10,
			OutSegsDelta:     5000,
			RetransSegsDelta: 600, // 12% loss
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	// Both are Tier 2 High, verify both are diagnosed (one as Primary, other as Contributing)
	allRules := make(map[string]bool)
	allRules[report.PrimaryBlocker.RuleID] = true
	for _, f := range report.ContributingFactors {
		allRules[f.RuleID] = true
	}
	for _, s := range report.SecondaryIssues {
		allRules[s.RuleID] = true
	}

	if !allRules["CONT_TCP_LISTEN_DROPS"] || !allRules["CONT_TCP_RETRANSMIT_STORM"] {
		t.Errorf("expected both CONT_TCP_LISTEN_DROPS and CONT_TCP_RETRANSMIT_STORM in report, got %+v", allRules)
	}
}

func TestDisambiguation_FSReadOnlyRemount_vs_DiskSpace(t *testing.T) {
	// When filesystem is remounted read-only (Tier 1 Critical), it triggers cleanly as PrimaryBlocker.
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			DiskSpace: collector.DiskSpaceInfo{
				Mounts: []collector.MountSpaceInfo{
					{Path: "/", ReadOnly: true, UsedPercent: 60.0},
				},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for Read-Only filesystem")
	}
	if report.PrimaryBlocker.RuleID != "BASE_FS_READONLY_REMOUNT" {
		t.Errorf("expected BASE_FS_READONLY_REMOUNT, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_UDPBufferOverrun_vs_ListenDrops(t *testing.T) {
	// When UDP buffer drops and TCP listen drops occur simultaneously, both are captured across Primary and Contributing.
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			UDPRcvbufErrorsDelta: 200,
			ListenDropsDelta:     50,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}

	allRules := make(map[string]bool)
	allRules[report.PrimaryBlocker.RuleID] = true
	for _, f := range report.ContributingFactors {
		allRules[f.RuleID] = true
	}
	for _, s := range report.SecondaryIssues {
		allRules[s.RuleID] = true
	}

	if !allRules["CONT_UDP_BUFFER_OVERRUN"] || !allRules["CONT_TCP_LISTEN_DROPS"] {
		t.Errorf("expected both CONT_UDP_BUFFER_OVERRUN and CONT_TCP_LISTEN_DROPS, got %+v", allRules)
	}
}

func TestDisambiguation_HugeTLBExhaustion_vs_OOMDanger(t *testing.T) {
	// When Tier 1 OOM danger exists alongside Tier 2 HugeTLB exhaustion, Tier 1 OOM dominates as PrimaryBlocker.
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:       32 * 1024 * 1024,
				MemAvailable:   100 * 1024, // < 1% (OOM)
				SwapTotal:      8 * 1024 * 1024,
				SwapFree:       50 * 1024, // < 1%
				HugePagesTotal: 2048,
				HugePagesFree:  0,
				HugePagesRsvd:  2048,
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for OOM")
	}
	if report.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Errorf("expected PrimaryBlocker BASE_OOM_DANGER, got %s", report.PrimaryBlocker.RuleID)
	}

	foundHugeTLB := false
	for _, f := range append(report.ContributingFactors, report.SecondaryIssues...) {
		if f.RuleID == "CONT_HUGETLB_POOL_EXHAUSTION" {
			foundHugeTLB = true
			break
		}
	}
	if !foundHugeTLB {
		t.Errorf("expected CONT_HUGETLB_POOL_EXHAUSTION demoted to contributing/secondary")
	}
}

func TestDisambiguation_PtraceAttach_vs_CPUSaturation(t *testing.T) {
	// When a single traced process consumes CPU without host-wide starvation, CONT_PTRACE_TRACER_ATTACH triggers.
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 40.0, BusyPercent: 60.0},
		Processes: []collector.ProcessDiff{
			{PID: 1234, Comm: "api_server", TracerPID: 5678, CPUPercent: 55.0, CPUTimeDelta: 55},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for ptrace attach")
	}
	if report.PrimaryBlocker.RuleID != "CONT_PTRACE_TRACER_ATTACH" {
		t.Errorf("expected CONT_PTRACE_TRACER_ATTACH, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_CorePatternPipe_vs_DStatePileup(t *testing.T) {
	// When processes are stuck in do_coredump, EDGE_CORE_PATTERN_PIPE_STALL identifies the specific coredump pipe stall.
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 501, Comm: "worker_a", Wchan: "do_coredump", State: 'D'},
			{PID: 502, Comm: "worker_b", Wchan: "pipe_wait", State: 'D'},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for coredump pipe stall")
	}
	if report.PrimaryBlocker.RuleID != "EDGE_CORE_PATTERN_PIPE_STALL" {
		t.Errorf("expected EDGE_CORE_PATTERN_PIPE_STALL, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_SysVSemaphore_vs_FDExhaustion(t *testing.T) {
	// SysV Semaphore table exhaustion triggers cleanly as Tier 2 blocker
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				SysVSem: collector.SysVSemInfo{
					Available:           true,
					SemMSL:              250,
					SemMNS:              32000,
					SemOPM:              32,
					SemMNI:              128,
					AllocatedSemaphores: 31000,
					AllocatedSemSets:    125,
				},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for SysV sem limit")
	}
	if report.PrimaryBlocker.RuleID != "CONT_SYSV_SEMAPHORE_LIMIT" {
		t.Errorf("expected CONT_SYSV_SEMAPHORE_LIMIT, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_TimeWaitBucketOverflow_vs_PortRange(t *testing.T) {
	// When TIME_WAIT bucket overflows occur, CONT_TCP_TIMEWAIT_BUCKET_OVERFLOW triggers
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPTimeWaitOverflowDelta: 50},
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				TCPMaxTWBuckets: 262144,
				SockStat:        collector.SockStatInfo{TCPTimeWait: 262000},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for TIME_WAIT bucket overflow")
	}
	if report.PrimaryBlocker.RuleID != "CONT_TCP_TIMEWAIT_BUCKET_OVERFLOW" {
		t.Errorf("expected CONT_TCP_TIMEWAIT_BUCKET_OVERFLOW, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_CgroupIOThrottle_vs_DiskHWSaturation(t *testing.T) {
	// When container hit cgroup io.max under high PSI I/O pressure, CONT_CGROUP_IO_THROTTLE_STALL isolates the container
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				IO: collector.PSIResource{
					Full: collector.PSIMetrics{Avg10: 22.0},
				},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 400, Comm: "postgres", CgroupPath: "/docker/db1", Wchan: "io_schedule", State: 'D'},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for cgroup I/O throttle")
	}
	if report.PrimaryBlocker.RuleID != "CONT_CGROUP_IO_THROTTLE_STALL" {
		t.Errorf("expected CONT_CGROUP_IO_THROTTLE_STALL, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_RTSchedThrottling_vs_CPUSaturation(t *testing.T) {
	// A single spinning real-time FIFO task triggers EDGE_RT_SCHED_THROTTLING
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 60.0, BusyPercent: 40.0},
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{SchedRTRuntimeUS: 950000},
		},
		Processes: []collector.ProcessDiff{
			{PID: 88, Comm: "rt_dsp", Policy: 1, CPUPercent: 98.0},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for RT sched throttling")
	}
	if report.PrimaryBlocker.RuleID != "EDGE_RT_SCHED_THROTTLING" {
		t.Errorf("expected EDGE_RT_SCHED_THROTTLING, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_CMAZone_vs_OOMDanger(t *testing.T) {
	// When Tier 1 OOM danger exists alongside CMA exhaustion, Tier 1 dominates
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     32 * 1024 * 1024,
				MemAvailable: 100 * 1024, // < 1% (OOM)
				SwapTotal:    8 * 1024 * 1024,
				SwapFree:     50 * 1024,
				CmaTotal:     524288,
				CmaFree:      1024,
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker for OOM")
	}
	if report.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Errorf("expected BASE_OOM_DANGER, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_AuditdBacklog_vs_CPUSaturation(t *testing.T) {
	// Compound scenario: Host CPU is saturated (Tier 1), but processes also wait on audit backlog (Tier 2).
	// Tier 1 BASE_CPU_SATURATION MUST dominate as PrimaryBlocker.
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.5, BusyPercent: 99.5},
		ProcsRunning: 16,
		ProcsBlocked: 4,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
			Memory:      collector.MemInfo{MemTotal: 16000000, MemAvailable: 8000000},
			Clocksource: collector.ClocksourceInfo{Current: "tsc"},
		},
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "node_app", Wchan: "audit_log_start", State: 'D', CPUPercent: 50.0},
			{PID: 102, Comm: "db_app", Wchan: "kauditd_wait", State: 'D', CPUPercent: 45.0},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_CPU_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	foundAudit := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_AUDITD_BACKLOG_WAIT_STALL" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Errorf("expected CONT_AUDITD_BACKLOG_WAIT_STALL in ContributingFactors")
	}
}

func TestDisambiguation_TCPSndbuf_vs_TCPMemPress(t *testing.T) {
	// Compound scenario: Kernel global TCP socket memory pressure (Tier 1) vs process send buffer stall (Tier 2).
	// Tier 1 BASE_TCP_SOCKET_MEM_PRESS MUST dominate as PrimaryBlocker.
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPMemoryPressuresDelta:  50,
			TCPAbortOnMemoryDelta:    5,
			TCPSlowStartRetransDelta: 10,
		},
		Processes: []collector.ProcessDiff{
			{PID: 201, Comm: "gateway", Wchan: "sk_stream_wait_memory"},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_TCP_SOCKET_MEM_PRESS" {
		t.Errorf("expected PrimaryBlocker BASE_TCP_SOCKET_MEM_PRESS, got %s", report.PrimaryBlocker.RuleID)
	}

	foundSndbuf := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_TCP_SNDBUF_EXHAUSTION" {
			foundSndbuf = true
			break
		}
	}
	if !foundSndbuf {
		t.Errorf("expected CONT_TCP_SNDBUF_EXHAUSTION in ContributingFactors")
	}
}

func TestDisambiguation_XFSAILPush_vs_DiskHWSaturation(t *testing.T) {
	// Compound scenario: Physical disk saturated at 98% (Tier 1) and XFS transactions blocked in log reserve (Tier 2).
	// Tier 1 BASE_DISK_HARDWARE_SATURATION MUST dominate as PrimaryBlocker.
	diff := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 98.5, ReadsCompletedDelta: 1000},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				IO: collector.PSIResource{
					Some: collector.PSIMetrics{Avg10: 25.0},
				},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 301, Comm: "xfs_writer", Wchan: "xfs_log_reserve", State: 'D'},
			{PID: 302, Comm: "xfs_syncer", Wchan: "xfs_trans_reserve", State: 'D'},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_DISK_HARDWARE_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	foundXFS := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_XFS_AIL_PUSH_STALL" {
			foundXFS = true
			break
		}
	}
	if !foundXFS {
		t.Errorf("expected CONT_XFS_AIL_PUSH_STALL in ContributingFactors")
	}
}

func TestDisambiguation_ZswapContention_vs_SwapThrashing(t *testing.T) {
	// Compound scenario: Direct reclaim swap thrashing (Tier 2) and Zswap compression contention (Tier 3).
	// Tier 2 CONT_SWAP_THRASHING MUST dominate over Tier 3 EDGE_ZSWAP_COMPRESSOR_CONTENTION.
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{SystemPercent: 22.0},
		VMStat: collector.VMStatDiff{
			PgScanDirectDelta:           2000,
			AllocStallDirectDelta:       50,
			ZswpoutDelta:                1200,
			ZswapRejectReclaimFailDelta: 30,
		},
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				Memory: collector.PSIResource{
					Some: collector.PSIMetrics{Avg10: 45.0},
				},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "CONT_SWAP_THRASHING" {
		t.Errorf("expected PrimaryBlocker CONT_SWAP_THRASHING, got %s", report.PrimaryBlocker.RuleID)
	}

	foundZswap := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_ZSWAP_COMPRESSOR_CONTENTION" {
			foundZswap = true
			break
		}
	}
	if !foundZswap {
		t.Errorf("expected EDGE_ZSWAP_COMPRESSOR_CONTENTION in SecondaryIssues")
	}
}

func TestDisambiguation_DMQueueCongestion_vs_DiskHWSaturation(t *testing.T) {
	// Physical drive nvme0n1 is 99% utilized (Tier 1), while dm-0 is congested (Tier 2).
	// Tier 1 BASE_DISK_HARDWARE_SATURATION MUST dominate as PrimaryBlocker.
	diff := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 99.0, ReadsCompletedDelta: 1000},
			{DeviceName: "dm-0", UtilPercent: 85.0, AvgWriteLatencyMS: 60.0, IOsInProgress: 8},
		},
		Processes: []collector.ProcessDiff{
			{PID: 400, Comm: "kcryptd", Wchan: "kcryptd", State: 'D'},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_DISK_HARDWARE_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	foundDM := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_DM_QUEUE_CONGESTION" {
			foundDM = true
			break
		}
	}
	if !foundDM {
		t.Errorf("expected CONT_DM_QUEUE_CONGESTION in ContributingFactors")
	}
}

func TestDisambiguation_EpollWakeup_vs_CPUSaturation(t *testing.T) {
	// CPU is 100% saturated (Tier 1) and workers have epoll wakeup contention (Tier 2).
	// Tier 1 BASE_CPU_SATURATION MUST dominate as PrimaryBlocker.
	procs := make([]collector.ProcessDiff, 10)
	for i := 0; i < 10; i++ {
		procs[i] = collector.ProcessDiff{
			PID:   100 + i,
			Comm:  fmt.Sprintf("nginx_%d", i),
			Wchan: "ep_poll",
		}
	}
	diff := &collector.SnapshotDiff{
		TotalCPUUtil:         collector.CPUUtilization{IdlePercent: 0.5, BusyPercent: 99.5, SystemPercent: 20.0},
		ProcsRunning:         16,
		ContextSwitchesDelta: 75000,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
			Memory:      collector.MemInfo{MemTotal: 16000000, MemAvailable: 8000000},
			Clocksource: collector.ClocksourceInfo{Current: "tsc"},
		},
		Processes: procs,
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_CPU_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	foundEpoll := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_EPOLL_WAKEUP_CONTENTION" {
			foundEpoll = true
			break
		}
	}
	if !foundEpoll {
		t.Errorf("expected CONT_EPOLL_WAKEUP_CONTENTION in ContributingFactors")
	}
}

func TestDisambiguation_THPAllocFallback_vs_OOMDanger(t *testing.T) {
	// Imminent OOM (Tier 1) and THP fallback (Tier 3).
	// Tier 1 BASE_OOM_DANGER MUST dominate as PrimaryBlocker.
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     32 * 1024 * 1024,
				MemAvailable: 50 * 1024, // < 1%
				SwapTotal:    8 * 1024 * 1024,
				SwapFree:     20 * 1024,
			},
		},
		VMStat: collector.VMStatDiff{
			THPFaultFallbackDelta: 1000,
			AllocStallDirectDelta: 50,
			CompactStallDelta:     10,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Errorf("expected PrimaryBlocker BASE_OOM_DANGER, got %s", report.PrimaryBlocker.RuleID)
	}

	foundTHP := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_THP_ALLOC_FALLBACK_STALL" {
			foundTHP = true
			break
		}
	}
	if !foundTHP {
		t.Errorf("expected EDGE_THP_ALLOC_FALLBACK_STALL in SecondaryIssues")
	}
}

func TestDisambiguation_DiskHardwareSaturation_vs_MDResync_and_AIO(t *testing.T) {
	// Compound scenario: Disk 100% busy (Tier 1), Software RAID resync active (Tier 2), AIO ceiling saturated (Tier 2)
	diff := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "sda", UtilPercent: 99.0, AvgWriteLatencyMS: 85.0, IOsInProgress: 12},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				MDStat: collector.MDStatInfo{
					Available:    true,
					ActiveResync: true,
					ArrayName:    "md0",
					Operation:    "resync",
				},
				AIONR:    62000,
				AIOMaxNR: 65536,
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 500, Comm: "db_writer", Wchan: "io_submit", State: 'D'},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_DISK_HARDWARE_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	cfMap := make(map[string]bool)
	for _, cf := range report.ContributingFactors {
		cfMap[cf.RuleID] = true
	}
	if !cfMap["CONT_MD_RAID_RESYNC_STALL"] {
		t.Errorf("expected CONT_MD_RAID_RESYNC_STALL in ContributingFactors")
	}
	if !cfMap["CONT_AIO_EVENT_LIMIT_SATURATION"] {
		t.Errorf("expected CONT_AIO_EVENT_LIMIT_SATURATION in ContributingFactors")
	}
}

func TestDisambiguation_OOMDanger_vs_KswapdSpin_and_SysVShm(t *testing.T) {
	// Compound scenario: Imminent OOM (Tier 1), kswapd CPU spin (Tier 2), SysV SHM table saturation (Tier 3)
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     16 * 1024 * 1024,
				MemAvailable: 100 * 1024, // < 1%
				SwapTotal:    4 * 1024 * 1024,
				SwapFree:     50 * 1024,
				Shmem:        4 * 1024 * 1024,
			},
			SystemConfig: collector.SystemConfigInfo{
				SysVShm: collector.SysVShmInfo{
					Available:         true,
					AllocatedSegments: 3800,
					ShmMNI:            4096,
				},
			},
		},
		VMStat: collector.VMStatDiff{
			PgScanDirectDelta:     2000,
			AllocStallDirectDelta: 40,
		},
		Processes: []collector.ProcessDiff{
			{PID: 30, Comm: "kswapd0", CPUPercent: 80.0},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Errorf("expected PrimaryBlocker BASE_OOM_DANGER, got %s", report.PrimaryBlocker.RuleID)
	}

	// CONT_KSWAPD_CPU_SPIN should be SUPPRESSED by BASE_OOM_DANGER (causal chain)
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_KSWAPD_CPU_SPIN" {
			t.Errorf("expected CONT_KSWAPD_CPU_SPIN to be suppressed by BASE_OOM_DANGER, but found in ContributingFactors")
		}
	}

	foundSHM := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_SYSV_SHM_SEGMENT_LIMIT" {
			foundSHM = true
			break
		}
	}
	if !foundSHM {
		t.Errorf("expected EDGE_SYSV_SHM_SEGMENT_LIMIT in SecondaryIssues")
	}
}

func TestDisambiguation_TCPRetransmitStorm_vs_NetOutOfOrder_and_IPFrag(t *testing.T) {
	// Compound network scenario: High TCP retransmissions (Tier 2), OFO queue overflow (Tier 2), IP fragment drops (Tier 3)
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			RetransSegsDelta:     150,
			OutSegsDelta:         1000, // 15% retransmits
			TCPOFOQueueDelta:     1500,
			TCPRcvCollapsedDelta: 20,
			IPReasmFailsDelta:    30,
			IPReasmTimeoutDelta:  15,
			IPReasmReqdsDelta:    100,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	// Either CONT_TCP_RETRANSMIT_STORM or CONT_NET_OUT_OF_ORDER_STALL will be primary (both Tier 2)
	if report.PrimaryBlocker.Tier != 2 {
		t.Errorf("expected Tier 2 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundIPFrag := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_IP_FRAG_REASM_DROPS" {
			foundIPFrag = true
			break
		}
	}
	if !foundIPFrag {
		t.Errorf("expected EDGE_IP_FRAG_REASM_DROPS in SecondaryIssues")
	}
}

func TestDisambiguation_DStatePileup_vs_CgroupV2Freeze(t *testing.T) {
	// D-state pileup (Tier 2) and Cgroup v2 frozen (Tier 3)
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "p1", State: 'D', Wchan: "sync_file_range"},
			{PID: 102, Comm: "p2", State: 'D', Wchan: "ext4_writepages"},
			{PID: 103, Comm: "p3", State: 'D', Wchan: "io_schedule"},
			{PID: 104, Comm: "p4", State: 'D', Wchan: "cgroup_freeze_task", CgroupPath: "/docker.slice/c1"},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			Cgroups: collector.CgroupInfo{Available: true, Frozen: true},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "CONT_DSTATE_PILEUP" {
		t.Errorf("expected PrimaryBlocker CONT_DSTATE_PILEUP, got %s", report.PrimaryBlocker.RuleID)
	}

	foundFreeze := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_CGROUP_V2_FREEZE_HANG" {
			foundFreeze = true
			break
		}
	}
	if !foundFreeze {
		t.Errorf("expected EDGE_CGROUP_V2_FREEZE_HANG in SecondaryIssues")
	}
}

func TestDisambiguation_CPUSaturation_vs_SchedYieldSpinChurn(t *testing.T) {
	// Compound scenario: Host CPU 100% busy (Tier 1), sched_yield tight spinloop (Tier 2), starved cgroup shares (Tier 2)
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.5, BusyPercent: 99.5},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{IdlePercent: 0.5}, {IdlePercent: 0.5},
		},
		ProcsRunning: 10,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 55.0},
			CPUFreq: collector.CPUFreqInfo{Available: true, Cores: []collector.CoreFreq{{CoreID: 0, CurFreq: 3400000, MaxFreq: 3400000}}},
			Cgroups: collector.CgroupInfo{
				Groups: []collector.CgroupEntry{
					{Path: "/docker/starved", CPUShares: 32},
				},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "spinner", VoluntaryCtxtSwitchesDelta: 30000, CPUPercent: 95.0, State: 'R', CgroupPath: "/docker/starved"},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_CPU_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	cfMap := make(map[string]bool)
	for _, cf := range report.ContributingFactors {
		cfMap[cf.RuleID] = true
	}
	if !cfMap["CONT_SCHED_YIELD_SPIN_CHURN"] {
		t.Errorf("expected CONT_SCHED_YIELD_SPIN_CHURN in ContributingFactors")
	}
	if !cfMap["CONT_CGROUP_V1_CPU_SHARES_STARVATION"] {
		t.Errorf("expected CONT_CGROUP_V1_CPU_SHARES_STARVATION in ContributingFactors")
	}
}

func TestDisambiguation_OOMDanger_vs_HugepageLeak_and_CgroupMemoryMax(t *testing.T) {
	// Compound scenario: Imminent OOM (Tier 1), HugePages locked/abandoned (Tier 2), Cgroup memory.max hit (Tier 3)
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:       16 * 1024 * 1024,
				MemAvailable:   100 * 1024, // < 1%
				SwapTotal:      4 * 1024 * 1024,
				SwapFree:       50 * 1024,
				HugePagesTotal: 2500, // ~31% RAM
				HugePagesRsvd:  2500,
			},
		},
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/container1", MemEventsMaxDelta: 20},
		},
		Processes: []collector.ProcessDiff{
			{PID: 50, Comm: "worker", CgroupPath: "/docker/container1"},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Errorf("expected PrimaryBlocker BASE_OOM_DANGER, got %s", report.PrimaryBlocker.RuleID)
	}

	foundHuge := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_HUGEPAGE_LEAK_NO_REUSE" {
			foundHuge = true
			break
		}
	}
	if !foundHuge {
		t.Errorf("expected CONT_HUGEPAGE_LEAK_NO_REUSE in ContributingFactors")
	}

	foundCgMax := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_CGROUP_MEMORY_MAX_OOM_STALL" {
			foundCgMax = true
			break
		}
	}
	if !foundCgMax {
		t.Errorf("expected EDGE_CGROUP_MEMORY_MAX_OOM_STALL in SecondaryIssues")
	}
}

func TestDisambiguation_UDPBufferOverrun_vs_UDPSndbufExhaustion(t *testing.T) {
	// Compound UDP scenario: Receive buffer overrun and Send buffer exhaustion
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			UDPRcvbufErrorsDelta: 200,
			UDPSndbufErrorsDelta: 150,
			OutSegsDelta:         1000,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 2 {
		t.Errorf("expected Tier 2 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundSnd := report.PrimaryBlocker.RuleID == "CONT_UDP_SNDBUF_EXHAUSTION"
	foundRcv := report.PrimaryBlocker.RuleID == "CONT_UDP_BUFFER_OVERRUN"
	for _, d := range report.ContributingFactors {
		if d.RuleID == "CONT_UDP_SNDBUF_EXHAUSTION" {
			foundSnd = true
		}
		if d.RuleID == "CONT_UDP_BUFFER_OVERRUN" {
			foundRcv = true
		}
	}
	if !foundSnd || !foundRcv {
		t.Errorf("expected both UDP send and receive issues reported, got snd=%v rcv=%v", foundSnd, foundRcv)
	}
}

func TestDisambiguation_TCPRetransmitStorm_vs_NetDevRxNoBuffers_and_TCPAbortOnClose(t *testing.T) {
	// Compound TCP network scenario: High TCP retransmissions (Tier 2), TCP abort on close (Tier 2), NIC ring buffer drops (Tier 3)
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			RetransSegsDelta:     120,
			OutSegsDelta:         1000, // 12% retransmits
			TCPAbortOnCloseDelta: 40,
		},
		NetIfaces: []collector.NetIfaceDiff{
			{Name: "eth0", OperState: "up", RxMissedErrorsDelta: 80},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 2 {
		t.Errorf("expected Tier 2 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundAbort := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_NET_TCP_ABORT_ON_CLOSE" {
			foundAbort = true
			break
		}
	}
	if !foundAbort {
		t.Errorf("expected CONT_NET_TCP_ABORT_ON_CLOSE in ContributingFactors")
	}

	foundNIC := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_NET_DEV_RX_NO_BUFFERS" {
			foundNIC = true
			break
		}
	}
	if !foundNIC {
		t.Errorf("expected EDGE_NET_DEV_RX_NO_BUFFERS in SecondaryIssues")
	}
}

func TestDisambiguation_TCPSocketMemPress_vs_TCPCollapsePrune_and_TCPMemoryAllocFail(t *testing.T) {
	// Compound scenario: Global TCP Memory Pressure (Tier 1), TCP Receive Collapse (Tier 2), TCP Socket Alloc Fail (Tier 2)
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPMemoryPressuresDelta: 100,
			TCPRcvCollapsedDelta:    80,
			TCPAbortOnMemoryDelta:   15,
			RetransSegsDelta:        300,
			OutSegsDelta:            2000,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_TCP_SOCKET_MEM_PRESS" {
		t.Errorf("expected PrimaryBlocker BASE_TCP_SOCKET_MEM_PRESS, got %s", report.PrimaryBlocker.RuleID)
	}

	foundCollapse := false
	foundAllocFail := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_NET_TCP_COLLAPSE_PRUNE" {
			foundCollapse = true
		}
		if cf.RuleID == "CONT_NET_TCP_MEMORY_ALLOC_FAIL" {
			foundAllocFail = true
		}
	}
	if !foundCollapse || !foundAllocFail {
		t.Errorf("expected CONT_NET_TCP_COLLAPSE_PRUNE and CONT_NET_TCP_MEMORY_ALLOC_FAIL in ContributingFactors")
	}
}

func TestDisambiguation_FutexContention_vs_FutexPIDeadlockStall(t *testing.T) {
	// Compound scenario: Multi-thread futex contention (Tier 3) vs Priority-Inheritance futex deadlock stall (Tier 2)
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "deadlocked_worker", Wchan: "futex_lock_pi", State: 'D', CPUPercent: 0.0, NumThreads: 8},
			{PID: 102, Comm: "contended_worker", Wchan: "futex_wait", State: 'S', CPUPercent: 5.0, NumThreads: 60},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "CONT_FUTEX_PI_DEADLOCK_STALL" {
		t.Errorf("expected PrimaryBlocker CONT_FUTEX_PI_DEADLOCK_STALL, got %s", report.PrimaryBlocker.RuleID)
	}

	foundContention := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_FUTEX_CONTENTION" {
			foundContention = true
			break
		}
	}
	if !foundContention {
		t.Errorf("expected EDGE_FUTEX_CONTENTION in SecondaryIssues")
	}
}

func TestDisambiguation_CgroupMemoryHigh_vs_CgroupMemoryMaxOOM(t *testing.T) {
	// Compound scenario: Cgroup memory.high delays (Tier 2) and Cgroup memory.max reclaim stalls (Tier 3)
	diff := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test_cont", MemoryHighEventsDelta: 40, MemEventsMaxDelta: 10},
		},
		Processes: []collector.ProcessDiff{
			{PID: 202, Comm: "worker", CgroupPath: "/docker/test_cont", CPUPercent: 15.0},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "CONT_CGROUP_MEM_HIGH_THROTTLE" {
		t.Errorf("expected PrimaryBlocker CONT_CGROUP_MEM_HIGH_THROTTLE, got %s", report.PrimaryBlocker.RuleID)
	}

	foundMax := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_CGROUP_MEMORY_MAX_OOM_STALL" {
			foundMax = true
			break
		}
	}
	if !foundMax {
		t.Errorf("expected EDGE_CGROUP_MEMORY_MAX_OOM_STALL in SecondaryIssues")
	}
}

func TestDisambiguation_CPUAffinityPin_vs_CgroupCPUCorePinStarvation(t *testing.T) {
	// Both Tier 3 rules active on different processes
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 85.0},
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{
					{ID: "cpu0"}, {ID: "cpu1"},
				},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 10, Comm: "host_pinned", CgroupPath: "/", CpusAllowed: 1, CPUPercent: 95.0},
			{PID: 20, Comm: "cont_pinned", CgroupPath: "/docker/c1", CpusAllowed: 1, CPUPercent: 95.0},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 3 {
		t.Errorf("expected Tier 3 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundHostPin := report.PrimaryBlocker.RuleID == "EDGE_CPU_AFFINITY_PIN"
	foundContPin := report.PrimaryBlocker.RuleID == "EDGE_CGROUP_CPU_CORE_PIN_STARVATION"
	all := append(report.ContributingFactors, report.SecondaryIssues...)
	for _, d := range all {
		if d.RuleID == "EDGE_CPU_AFFINITY_PIN" {
			foundHostPin = true
		}
		if d.RuleID == "EDGE_CGROUP_CPU_CORE_PIN_STARVATION" {
			foundContPin = true
		}
	}
	if !foundHostPin || !foundContPin {
		t.Errorf("expected both CPU pin diagnoses, got hostPin=%v contPin=%v", foundHostPin, foundContPin)
	}
}

func TestDisambiguation_DiskHardwareSaturation_vs_DirtyPagesDirectSync_and_VFSInodeLock(t *testing.T) {
	// Compound scenario: Hardware disk 100% busy (Tier 1), Direct page dirty sync (Tier 2), VFS Inode write lock (Tier 2)
	diff := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 99.5, IOsInProgress: 32, AvgReadLatencyMS: 85.0},
		},
		VMStat: collector.VMStatDiff{
			NRDirtyDelta: 4000,
		},
		Processes: []collector.ProcessDiff{
			{PID: 301, Comm: "db_syncer", Wchan: "sync_inodes", State: 'D'},
			{PID: 302, Comm: "db_writer", Wchan: "inode_lock", State: 'D'},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_DISK_HARDWARE_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	foundDirty := false
	foundInode := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_DIRTY_PAGES_DIRECT_SYNC_STALL" {
			foundDirty = true
		}
		if cf.RuleID == "CONT_VFS_INODE_LOCK_CONTENTION" {
			foundInode = true
		}
	}
	if !foundDirty || !foundInode {
		t.Errorf("expected CONT_DIRTY_PAGES_DIRECT_SYNC_STALL and CONT_VFS_INODE_LOCK_CONTENTION in ContributingFactors")
	}
}

func TestDisambiguation_TCPRetransmitStorm_vs_TCPChronicRTOCollapse(t *testing.T) {
	// Compound scenario: High TCP Retransmit Storm (Tier 2) vs Chronic RTO (Tier 3)
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			RetransSegsDelta:        800,
			OutSegsDelta:            1000,
			TCPTimeoutsDelta:        35,
			TCPSpuriousRtxHostDelta: 5,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "CONT_TCP_RETRANSMIT_STORM" {
		t.Errorf("expected PrimaryBlocker CONT_TCP_RETRANSMIT_STORM, got %s", report.PrimaryBlocker.RuleID)
	}

	foundRTO := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_TCP_CHRONIC_RTO_COLLAPSE" {
			foundRTO = true
			break
		}
	}
	if !foundRTO {
		t.Errorf("expected EDGE_TCP_CHRONIC_RTO_COLLAPSE in SecondaryIssues")
	}
}

func TestDisambiguation_NFSRPCClientSaturation_vs_KernelLockdBlocked(t *testing.T) {
	// Scenario: NFS RPC slot table saturation (Tier 2) vs POSIX file lock contention (Tier 2)
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 401, Comm: "nfs_worker", Wchan: "nfs_wait_client", State: 'D', NumThreads: 8},
			{PID: 402, Comm: "db_locker", Wchan: "fcntl_setlk", State: 'D', CPUPercent: 0.0, NumThreads: 8},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 2 {
		t.Errorf("expected Tier 2 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundNFS := report.PrimaryBlocker.RuleID == "CONT_NFS_RPC_SLOT_TABLE_SATURATION"
	foundLock := report.PrimaryBlocker.RuleID == "CONT_KERNEL_LOCKD_BLOCKED"
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_NFS_RPC_SLOT_TABLE_SATURATION" {
			foundNFS = true
		}
		if cf.RuleID == "CONT_KERNEL_LOCKD_BLOCKED" {
			foundLock = true
		}
	}
	if !foundNFS || !foundLock {
		t.Errorf("expected both NFS and POSIX lock diagnoses, got NFS=%v lock=%v", foundNFS, foundLock)
	}
}

func TestDisambiguation_HugeTLBExhaustion_vs_HugeTLBVMAFaultMisalign(t *testing.T) {
	// Scenario: HugeTLB memory exhaustion (Tier 2) vs HugeTLB VMA fault misalignment (Tier 3)
	diff := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			THPFaultFallbackDelta: 100,
			THPFaultAllocDelta:    0,
		},
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				HugePagesTotal: 100,
				HugePagesFree:  0,
				HugePagesRsvd:  100,
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "CONT_HUGETLB_POOL_EXHAUSTION" {
		t.Errorf("expected PrimaryBlocker CONT_HUGETLB_POOL_EXHAUSTION, got %s", report.PrimaryBlocker.RuleID)
	}

	foundMisalign := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_HUGETLB_VMA_MISALIGN_FAULT" {
			foundMisalign = true
			break
		}
	}
	if !foundMisalign {
		t.Errorf("expected EDGE_HUGETLB_VMA_MISALIGN_FAULT in SecondaryIssues")
	}
}

func TestDisambiguation_CPUSaturation_vs_SchedAutogroupStarvation(t *testing.T) {
	// Compound scenario: System CPU Saturation (Tier 1) vs Sched Autogroup Starvation (Tier 2)
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{UserPercent: 85.0, SystemPercent: 14.0, IdlePercent: 1.0},
		ProcsRunning: 32,
		Processes: []collector.ProcessDiff{
			{PID: 200, Comm: "session_worker", NumThreads: 32, CPUPercent: 5.0, State: 'R'},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{}, {}, {}, {}},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_CPU_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	foundAutogroup := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_SCHED_AUTOGROUP_STARVATION" {
			foundAutogroup = true
			break
		}
	}
	if !foundAutogroup {
		t.Errorf("expected CONT_SCHED_AUTOGROUP_STARVATION in ContributingFactors")
	}
}

func TestDisambiguation_SoftIRQUnbalance_vs_NetDevGROCellDrop(t *testing.T) {
	// Scenario: SoftIRQ Core Unbalance (Tier 2) vs GRO Cell Drops (Tier 2)
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 60.0},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{SoftIRQPercent: 85.0},
			{SoftIRQPercent: 2.0},
		},
		NetStat: collector.NetStatDiff{
			SoftnetDroppedDelta:     60,
			SoftnetTimeSqueezeDelta: 60,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 2 {
		t.Errorf("expected Tier 2 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundSoftIRQ := report.PrimaryBlocker.RuleID == "CONT_SOFTIRQ_UNBALANCE"
	foundGRO := report.PrimaryBlocker.RuleID == "CONT_NET_DEV_GRO_CELL_DROP"
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_SOFTIRQ_UNBALANCE" {
			foundSoftIRQ = true
		}
		if cf.RuleID == "CONT_NET_DEV_GRO_CELL_DROP" {
			foundGRO = true
		}
	}
	if !foundSoftIRQ || !foundGRO {
		t.Errorf("expected both SoftIRQ and GRO diagnoses, got softirq=%v gro=%v", foundSoftIRQ, foundGRO)
	}
}

func TestDisambiguation_THPCompactionStall_vs_MemCompactMigrationFailRate(t *testing.T) {
	// Scenario: Compaction migration failures (Tier 2) vs THP Compaction Stall (Tier 3)
	diff := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			CompactStallDelta: 90,
			CompactFailDelta:  60,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "CONT_MEM_COMPACT_MIGRATION_FAIL_RATE" {
		t.Errorf("expected PrimaryBlocker CONT_MEM_COMPACT_MIGRATION_FAIL_RATE, got %s", report.PrimaryBlocker.RuleID)
	}

	foundTHP := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_THP_COMPACTION_STALL" {
			foundTHP = true
			break
		}
	}
	if !foundTHP {
		t.Errorf("expected EDGE_THP_COMPACTION_STALL in SecondaryIssues")
	}
}

func TestDisambiguation_FutexContention_vs_ProcPIDTaskPthreadLimit(t *testing.T) {
	// Scenario: Futex Contention (Tier 3) vs Thread Count limit (Tier 3)
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 501, Comm: "heavy_lock", NumThreads: 60, Wchan: "futex_wait", State: 'S'},
			{PID: 502, Comm: "thread_pool", NumThreads: 800, Wchan: "do_epoll_wait", State: 'S'},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 3 {
		t.Errorf("expected Tier 3 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundFutex := report.PrimaryBlocker.RuleID == "EDGE_FUTEX_CONTENTION"
	foundPthread := report.PrimaryBlocker.RuleID == "EDGE_PROC_PID_TASK_PTHREAD_LIMIT"
	all := append(report.ContributingFactors, report.SecondaryIssues...)
	for _, d := range all {
		if d.RuleID == "EDGE_FUTEX_CONTENTION" {
			foundFutex = true
		}
		if d.RuleID == "EDGE_PROC_PID_TASK_PTHREAD_LIMIT" {
			foundPthread = true
		}
	}
	if !foundFutex || !foundPthread {
		t.Errorf("expected both Futex and Pthread diagnoses, got futex=%v pthread=%v", foundFutex, foundPthread)
	}
}

func TestDisambiguation_SystemFileTableFull_vs_ProcessFDExhaustion(t *testing.T) {
	// Scenario: Global OS file table is 100% full (Tier 1) vs process near its individual FD limit (Tier 2)
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				FileNR: collector.FileNRInfo{Available: true, Allocated: 1048576, Max: 1048576},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "db_proc", OpenFDs: 950, MaxFDs: 1024, FDRatio: 0.95},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_SYSTEM_FILE_TABLE_FULL" {
		t.Errorf("expected PrimaryBlocker BASE_SYSTEM_FILE_TABLE_FULL, got %s", report.PrimaryBlocker.RuleID)
	}

	// CONT_FD_EXHAUSTION should be SUPPRESSED by BASE_SYSTEM_FILE_TABLE_FULL (causal chain)
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_FD_EXHAUSTION" {
			t.Errorf("expected CONT_FD_EXHAUSTION to be suppressed by BASE_SYSTEM_FILE_TABLE_FULL, but found in ContributingFactors")
		}
	}
}

func TestDisambiguation_GlobalOOMKillActive_vs_CgroupOOMKillEvent(t *testing.T) {
	// Scenario: Host kernel OOM killer active (Tier 1) vs Cgroup OOM kill event (Tier 3)
	diff := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			OOMKillDelta: 3,
		},
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test", OOMKillsDelta: 1},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_GLOBAL_OOM_KILL_ACTIVE" {
		t.Errorf("expected PrimaryBlocker BASE_GLOBAL_OOM_KILL_ACTIVE, got %s", report.PrimaryBlocker.RuleID)
	}

	foundCgroupOOM := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "EDGE_CGROUP_OOM_KILL_EVENT" {
			foundCgroupOOM = true
			break
		}
	}
	if !foundCgroupOOM {
		t.Errorf("expected EDGE_CGROUP_OOM_KILL_EVENT in ContributingFactors")
	}
}

func TestDisambiguation_ConntrackHardDrop_vs_ConntrackExhaustion(t *testing.T) {
	// Scenario: Netfilter conntrack table 100% full (Tier 1)
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Conntrack: collector.ConntrackInfo{Available: true, Count: 262144, Max: 262144, Ratio: 1.0},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_CONNTRACK_TABLE_HARD_DROP" {
		t.Errorf("expected PrimaryBlocker BASE_CONNTRACK_TABLE_HARD_DROP, got %s", report.PrimaryBlocker.RuleID)
	}

	// CONT_CONNTRACK_EXHAUSTION should be SUPPRESSED by BASE_CONNTRACK_TABLE_HARD_DROP (causal chain)
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_CONNTRACK_EXHAUSTION" {
			t.Errorf("expected CONT_CONNTRACK_EXHAUSTION to be suppressed by BASE_CONNTRACK_TABLE_HARD_DROP, but found in ContributingFactors")
		}
	}
}

func TestDisambiguation_TCPSynRetrans_vs_TCPFastOpenFail(t *testing.T) {
	// Scenario: SYN+ACK Retransmissions (Tier 2 High) vs TFO Failures (Tier 2 High)
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPSynRetransDelta:          35,
			TCPFastOpenActiveFailDelta:  10,
			TCPFastOpenPassiveFailDelta: 5,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 2 {
		t.Errorf("expected Tier 2 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundSynRetrans := false
	foundTFO := false
	all := append([]analyzer.Diagnosis{*report.PrimaryBlocker}, append(report.ContributingFactors, report.SecondaryIssues...)...)
	for _, d := range all {
		if d.RuleID == "CONT_NET_TCP_SYN_ACK_RETRANS_STALL" {
			foundSynRetrans = true
		}
		if d.RuleID == "CONT_NET_TCP_FASTOPEN_FAIL" {
			foundTFO = true
		}
	}
	if !foundSynRetrans || !foundTFO {
		t.Errorf("expected both SynRetrans and TFO diagnoses, got syn=%v tfo=%v", foundSynRetrans, foundTFO)
	}
}

func TestDisambiguation_DiskHardwareSaturation_vs_StorageBlkThrottleStall(t *testing.T) {
	// Scenario: Disk Hardware Saturation (Tier 1) vs Cgroup Block Throttle (Tier 2)
	diff := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 99.0, IOsInProgress: 64},
		},
		Processes: []collector.ProcessDiff{
			{PID: 401, Comm: "throttled_writer", Wchan: "blk_throtl_dispatch_work_fn", State: 'D'},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_DISK_HARDWARE_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	foundThrotl := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_STORAGE_BLK_THROTTLE_STALL" {
			foundThrotl = true
			break
		}
	}
	if !foundThrotl {
		t.Errorf("expected CONT_STORAGE_BLK_THROTTLE_STALL in ContributingFactors")
	}
}

func TestDisambiguation_ZoneDMA32_vs_ZoneNormalFragmentation(t *testing.T) {
	// Scenario: DMA32 Zone Exhaustion (Tier 3) vs Normal Zone Fragmentation (Tier 3)
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{MemTotal: 64 * 1024 * 1024 * 1024, MemAvailable: 30 * 1024 * 1024 * 1024},
			SystemConfig: collector.SystemConfigInfo{
				BuddyInfo: collector.ZoneBuddyInfo{
					Available:            true,
					DMA32FreePages:       0,
					NormalFreePages:      300000,
					NormalOrder0Pages:    300000,
					NormalHighOrderPages: 0,
				},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 3 {
		t.Errorf("expected Tier 3 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundDMA32 := false
	foundNormalFrag := false
	all := append([]analyzer.Diagnosis{*report.PrimaryBlocker}, append(report.ContributingFactors, report.SecondaryIssues...)...)
	for _, d := range all {
		if d.RuleID == "EDGE_ZONE_DMA32_EXHAUSTION" {
			foundDMA32 = true
		}
		if d.RuleID == "EDGE_ZONE_NORMAL_FRAGMENTATION" {
			foundNormalFrag = true
		}
	}
	if !foundDMA32 || !foundNormalFrag {
		t.Errorf("expected both DMA32 and NormalFrag diagnoses, got dma=%v frag=%v", foundDMA32, foundNormalFrag)
	}
}

func TestDisambiguation_DStatePileup_vs_ProcPtracedStoppedStall(t *testing.T) {
	// Scenario: D-State Pileup (Tier 2 High) vs Ptraced Stopped Process (Tier 3 Medium)
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "io_wait1", State: 'D', Wchan: "wait_on_page_bit"},
			{PID: 102, Comm: "io_wait2", State: 'D', Wchan: "blk_mq_get_request"},
			{PID: 103, Comm: "io_wait3", State: 'D', Wchan: "io_schedule"},
			{PID: 104, Comm: "io_wait4", State: 'D', Wchan: "get_request"},
			{PID: 501, Comm: "debugged", State: 'T', NumThreads: 4, TracerPID: 9999},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "CONT_DSTATE_PILEUP" {
		t.Errorf("expected PrimaryBlocker CONT_DSTATE_PILEUP, got %s", report.PrimaryBlocker.RuleID)
	}

	foundPtraced := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_PROC_PTRACED_STOPPED_STALL" {
			foundPtraced = true
			break
		}
	}
	if !foundPtraced {
		t.Errorf("expected EDGE_PROC_PTRACED_STOPPED_STALL in SecondaryIssues")
	}
}

func TestDisambiguation_OOMDanger_vs_MemcgReclaimDirectStall(t *testing.T) {
	// Scenario: Host OOM Danger (Tier 1) vs Container Direct Reclaim (Tier 2)
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     16 * 1024 * 1024 * 1024,
				MemAvailable: 200 * 1024 * 1024, // < 3% RAM
				SwapTotal:    0,
				SwapFree:     0,
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 401, Comm: "java_mem", State: 'D', Wchan: "try_to_free_mem_cgroup_pages"},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Errorf("expected PrimaryBlocker BASE_OOM_DANGER, got %s", report.PrimaryBlocker.RuleID)
	}

	// CONT_MEMCG_RECLAIM_DIRECT_STALL should be SUPPRESSED by BASE_OOM_DANGER (causal chain)
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_MEMCG_RECLAIM_DIRECT_STALL" {
			t.Errorf("expected CONT_MEMCG_RECLAIM_DIRECT_STALL to be suppressed by BASE_OOM_DANGER, but found in ContributingFactors")
		}
	}
}

func TestDisambiguation_XFSAllocBtree_vs_VFSInodeLock(t *testing.T) {
	// Scenario: XFS Btree allocation contention vs VFS Inode Lock Contention (Tier 2)
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 201, Comm: "xfs_writer", State: 'D', Wchan: "xfs_alloc_fixup_trees"},
			{PID: 202, Comm: "vfs_lock", State: 'D', Wchan: "inode_lock"},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 2 {
		t.Errorf("expected Tier 2 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundXFS := false
	foundVFS := false
	all := append([]analyzer.Diagnosis{*report.PrimaryBlocker}, append(report.ContributingFactors, report.SecondaryIssues...)...)
	for _, d := range all {
		if d.RuleID == "CONT_XFS_ALLOC_BTREE_CONTENTION" {
			foundXFS = true
		}
		if d.RuleID == "CONT_VFS_INODE_LOCK_CONTENTION" {
			foundVFS = true
		}
	}
	if !foundXFS || !foundVFS {
		t.Errorf("expected both XFS and VFS diagnoses, got xfs=%v vfs=%v", foundXFS, foundVFS)
	}
}

func TestDisambiguation_MemMinWatermarkBounce_vs_MemSlabDentryPressure(t *testing.T) {
	// Scenario: Memory Min Watermark Bounce (Tier 3) vs Slab Dentry Pressure (Tier 3)
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     16 * 1024 * 1024 * 1024,
				MemAvailable: 1 * 1024 * 1024 * 1024, // < 10%
				SUnreclaim:   6 * 1024 * 1024 * 1024, // > 30%
			},
		},
		VMStat: collector.VMStatDiff{
			PgScanDirectDelta:     120,
			AllocStallDirectDelta: 0,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 3 {
		t.Errorf("expected Tier 3 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundBounce := false
	foundSlab := false
	all := append([]analyzer.Diagnosis{*report.PrimaryBlocker}, append(report.ContributingFactors, report.SecondaryIssues...)...)
	for _, d := range all {
		if d.RuleID == "EDGE_MEM_MIN_WATERMARK_BOUNCE" {
			foundBounce = true
		}
		if d.RuleID == "EDGE_MEM_SLAB_DENTRY_PRESSURE" {
			foundSlab = true
		}
	}
	if !foundBounce || !foundSlab {
		t.Errorf("expected both WatermarkBounce and SlabPressure diagnoses, got bounce=%v slab=%v", foundBounce, foundSlab)
	}
}

func TestDisambiguation_TCPZeroWindowAdvert_vs_TCPZeroWindowDrop(t *testing.T) {
	// Scenario: TCP Zero Window Advert (Tier 2) vs Zero Window Drop (Tier 2)
	diff := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPWinProbeDelta:       40,
			TCPZeroWindowDropDelta: 25,
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 2 {
		t.Errorf("expected Tier 2 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundAdvert := false
	foundDrop := false
	all := append([]analyzer.Diagnosis{*report.PrimaryBlocker}, append(report.ContributingFactors, report.SecondaryIssues...)...)
	for _, d := range all {
		if d.RuleID == "CONT_NET_TCP_ZERO_WINDOW_ADVERT" {
			foundAdvert = true
		}
		if d.RuleID == "CONT_NET_TCP_ZERO_WINDOW_DROP" {
			foundDrop = true
		}
	}
	if !foundAdvert || !foundDrop {
		t.Errorf("expected both ZeroWindowAdvert and ZeroWindowDrop, got advert=%v drop=%v", foundAdvert, foundDrop)
	}
}

func TestDisambiguation_CPUSaturation_vs_PSISomeCPU(t *testing.T) {
	// Scenario: 100% CPU Saturation (Tier 1) vs PSI CPU Some Pressure (Tier 2)
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{UserPercent: 95.0, SystemPercent: 5.0, IdlePercent: 0.0},
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				CPU:       collector.PSIResource{Some: collector.PSIMetrics{Avg10: 45.0}},
			},
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{
					{ID: "cpu0", Idle: 0, User: 100},
					{ID: "cpu1", Idle: 0, User: 100},
				},
			},
		},
		ProcsRunning: 6,
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "heavy_calc", CPUPercent: 195.0},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected PrimaryBlocker BASE_CPU_SATURATION, got %s", report.PrimaryBlocker.RuleID)
	}

	foundPSI := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_PSI_SOME_CPU_PRESSURE_SPIKE" {
			foundPSI = true
			break
		}
	}
	if !foundPSI {
		t.Errorf("expected CONT_PSI_SOME_CPU_PRESSURE_SPIKE in ContributingFactors")
	}
}

func TestDisambiguation_PSISomeIO_vs_PipeReadBurst(t *testing.T) {
	// Scenario: PSI IO Pressure (Tier 2 High) vs Pipe Read Block (Tier 2 High)
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				IO:        collector.PSIResource{Some: collector.PSIMetrics{Avg10: 35.0}},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 301, Comm: "pipe_waiter", State: 'D', Wchan: "pipe_read"},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 2 {
		t.Errorf("expected Tier 2 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundPSI := false
	foundPipe := false
	all := append([]analyzer.Diagnosis{*report.PrimaryBlocker}, append(report.ContributingFactors, report.SecondaryIssues...)...)
	for _, d := range all {
		if d.RuleID == "CONT_PSI_SOME_IO_PRESSURE_SPIKE" {
			foundPSI = true
		}
		if d.RuleID == "CONT_PIPE_READ_BURST_BLOCK" {
			foundPipe = true
		}
	}
	if !foundPSI || !foundPipe {
		t.Errorf("expected both PSI and Pipe diagnoses, got psi=%v pipe=%v", foundPSI, foundPipe)
	}
}

func TestDisambiguation_EpollPollTimeout_vs_ZombieParentDeadlock(t *testing.T) {
	// Scenario: Epoll Event Loop Starvation (Tier 3) vs Zombie Parent Deadlock (Tier 3)
	procs := make([]collector.ProcessDiff, 0, 20)
	procs = append(procs, collector.ProcessDiff{PID: 10, Comm: "supervisor", State: 'S', Wchan: "wait4"})
	for i := 11; i <= 22; i++ {
		procs = append(procs, collector.ProcessDiff{PID: i, Comm: "zombie_worker", State: 'Z', PPID: 10})
	}
	procs = append(procs, collector.ProcessDiff{PID: 901, Comm: "epoll_idle", State: 'S', Wchan: "epoll_pwait", NumThreads: 60, CPUPercent: 0.05, OpenFDs: 150})
	diff := &collector.SnapshotDiff{Processes: procs}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 3 {
		t.Errorf("expected Tier 3 PrimaryBlocker, got tier %d", report.PrimaryBlocker.Tier)
	}

	foundEpoll := false
	foundZombie := false
	all := append([]analyzer.Diagnosis{*report.PrimaryBlocker}, append(report.ContributingFactors, report.SecondaryIssues...)...)
	for _, d := range all {
		if d.RuleID == "EDGE_EPOLL_POLL_TIMEOUT_BURST" {
			foundEpoll = true
		}
		if d.RuleID == "EDGE_PROC_ZOMBIE_PARENT_DEADLOCK" {
			foundZombie = true
		}
	}
	if !foundEpoll || !foundZombie {
		t.Errorf("expected both Epoll and Zombie diagnoses, got epoll=%v zombie=%v", foundEpoll, foundZombie)
	}
}

func TestDisambiguation_ThermalThrottling_vs_SysfsPowerThrottle(t *testing.T) {
	// Scenario: Base Thermal Throttling (Tier 1) vs Sysfs Power/Thermal Governor (Tier 3)
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 92.0},
			CPUFreq: collector.CPUFreqInfo{
				Available: true,
				Cores: []collector.CoreFreq{
					{CurFreq: 800000, MaxFreq: 4000000},
				},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_THERMAL_THROTTLING" {
		t.Errorf("expected PrimaryBlocker BASE_THERMAL_THROTTLING, got %s", report.PrimaryBlocker.RuleID)
	}
}

func TestDisambiguation_SustainedLoad_vs_CPUSaturation(t *testing.T) {
	// Scenario: Tier 1 CPU saturation active alongside Tier 2 Sustained Load Saturation
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.5, BusyPercent: 99.5},
		ProcsRunning: 16,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{
					{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"},
				},
			},
			LoadAvg: collector.LoadAvgInfo{
				Available:       true,
				Load1:           14.0,
				Load5:           10.0,
				Load15:          8.0,
				RunningEntities: 16,
				TotalEntities:   400,
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "compute", CPUPercent: 390.0, CPUTimeDelta: 390},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	// Tier 1 Base CPU Saturation MUST dominate over Tier 2 Sustained Load
	if report.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected BASE_CPU_SATURATION as primary, got %s", report.PrimaryBlocker.RuleID)
	}

	foundSustained := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_SUSTAINED_LOAD_SATURATION" {
			foundSustained = true
			break
		}
	}
	if !foundSustained {
		t.Errorf("expected CONT_SUSTAINED_LOAD_SATURATION in ContributingFactors")
	}
}

func TestDisambiguation_TCPCloseWaitLeak_vs_FDExhaustion(t *testing.T) {
	// Scenario: 300 CLOSE_WAIT sockets causing 95% FD exhaustion on leaking server
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			TCPSockets: collector.TCPSocketsInfo{
				Available:   true,
				Established: 400,
				CloseWait:   300,
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 2001, Comm: "web_api", OpenFDs: 980, MaxFDs: 1024, FDRatio: 0.957},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.Tier != 2 {
		t.Errorf("expected Tier 2 primary blocker, got tier %d", report.PrimaryBlocker.Tier)
	}
}

func TestDisambiguation_OOMImmuneMemoryHog_vs_BaseOOMDanger(t *testing.T) {
	const totalKB uint64 = 1000 * 1024
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     totalKB,
				MemAvailable: 20 * 1024,
				SwapTotal:    0,
				SwapFree:     0,
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 9999, Comm: "rogue_hog", OOMScoreAdj: -1000, RSSBytes: 450 * 1024 * 1024},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Errorf("expected BASE_OOM_DANGER as primary, got %s", report.PrimaryBlocker.RuleID)
	}

	foundHog := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "EDGE_OOM_IMMUNE_MEMORY_HOG" {
			foundHog = true
			break
		}
	}
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_OOM_IMMUNE_MEMORY_HOG" {
			foundHog = true
			break
		}
	}
	if !foundHog {
		t.Errorf("expected EDGE_OOM_IMMUNE_MEMORY_HOG in secondary or contributing factors")
	}
}

func TestDisambiguation_IOSchedulerMismatch_vs_BaseDiskSaturation(t *testing.T) {
	diff := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{
				DeviceName:        "nvme0n1",
				UtilPercent:       98.0,
				Scheduler:         "bfq",
				Rotational:        false,
				AvgQueueLatencyMS: 30.0,
				WriteBytesDelta:   200 * 1024 * 1024,
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Errorf("expected BASE_DISK_HARDWARE_SATURATION as primary, got %s", report.PrimaryBlocker.RuleID)
	}

	foundSched := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "EDGE_IO_SCHEDULER_MISMATCH" {
			foundSched = true
			break
		}
	}
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_IO_SCHEDULER_MISMATCH" {
			foundSched = true
			break
		}
	}
	if !foundSched {
		t.Errorf("expected EDGE_IO_SCHEDULER_MISMATCH in secondary or contributing factors")
	}
}

func TestDisambiguation_ProcessSwapPinned_vs_BaseOOMDanger(t *testing.T) {
	// Scenario: Tier 1 OOM danger (< 3% available RAM) while a process is swap pinned (>500MB swap)
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:  901,
				Comm: "swap_hog",
				SmapsRollup: collector.SmapsRollupInfo{
					Available: true,
					Swap:      750000, // 750 MB
				},
			},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     10000000,
				MemAvailable: 200000, // 2% < 3% -> triggers BASE_OOM_DANGER
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Errorf("expected BASE_OOM_DANGER to dominate as primary blocker, got %s", report.PrimaryBlocker.RuleID)
	}

	foundSwapPinned := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_PROCESS_SWAP_PINNED" {
			foundSwapPinned = true
			break
		}
	}
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "CONT_PROCESS_SWAP_PINNED" {
			foundSwapPinned = true
			break
		}
	}
	if !foundSwapPinned {
		t.Errorf("expected CONT_PROCESS_SWAP_PINNED in contributing factors or secondary issues")
	}
}

func TestDisambiguation_DentryCacheExplosion_vs_BaseOOMDanger(t *testing.T) {
	// Scenario: Tier 1 OOM danger with massive dentry slab explosion (> 2M dentries)
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Slab: collector.SlabInfo{
					Available:         true,
					DentryCacheActive: 2800000,
					DentryCacheTotal:  2900000,
				},
			},
			Memory: collector.MemInfo{
				MemTotal:     16000000,
				MemAvailable: 300000, // 1.87% < 3% -> triggers BASE_OOM_DANGER
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Errorf("expected BASE_OOM_DANGER to dominate as primary blocker, got %s", report.PrimaryBlocker.RuleID)
	}

	foundDentry := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_DENTRY_CACHE_EXPLOSION" {
			foundDentry = true
			break
		}
	}
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "CONT_DENTRY_CACHE_EXPLOSION" {
			foundDentry = true
			break
		}
	}
	if !foundDentry {
		t.Errorf("expected CONT_DENTRY_CACHE_EXPLOSION in contributing factors or secondary issues")
	}
}

func TestDisambiguation_SecurityFanotify_vs_BaseCPUSaturation(t *testing.T) {
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.1, BusyPercent: 99.9},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{IdlePercent: 0.1}, {IdlePercent: 0.1},
		},
		ProcsRunning: 16,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 50.0},
			CPUFreq: collector.CPUFreqInfo{Available: true, Cores: []collector.CoreFreq{{CoreID: 0, CurFreq: 3000000, MaxFreq: 3000000}}},
		},
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "cpu_burner", CPUPercent: 198.0, CPUTimeDelta: 200},
			{PID: 102, Comm: "stalled_app", State: 'S', Wchan: "fanotify_get_response", CPUPercent: 0.1, NumThreads: 2},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected BASE_CPU_SATURATION to dominate, got %s", report.PrimaryBlocker.RuleID)
	}

	foundFanotify := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_SECURITY_FANOTIFY_STALL" {
			foundFanotify = true
			break
		}
	}
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "CONT_SECURITY_FANOTIFY_STALL" {
			foundFanotify = true
			break
		}
	}
	if !foundFanotify {
		t.Errorf("expected CONT_SECURITY_FANOTIFY_STALL in contributing factors or secondary issues")
	}
}

func TestDisambiguation_FileLockGraph_vs_BaseDiskHWSaturation(t *testing.T) {
	diff := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 99.8, IOsInProgress: 120, AvgReadLatencyMS: 85.0},
		},
		FileLocks: collector.FileLocksInfo{
			Available:  true,
			TotalLocks: 5,
			BlockedLocks: []collector.BlockedFileLock{
				{BlockedPID: 202, HolderPID: 201, LockType: "POSIX", DeviceInode: "08:01:9999"},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 201, Comm: "db_holder", ReadBytesDelta: 500000000},
			{PID: 202, Comm: "db_waiter", State: 'D', CPUPercent: 0.0},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Errorf("expected BASE_DISK_HARDWARE_SATURATION to dominate, got %s", report.PrimaryBlocker.RuleID)
	}

	foundLock := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_FILE_LOCK_GRAPH_BLOCKED" {
			foundLock = true
			break
		}
	}
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "CONT_FILE_LOCK_GRAPH_BLOCKED" {
			foundLock = true
			break
		}
	}
	if !foundLock {
		t.Errorf("expected CONT_FILE_LOCK_GRAPH_BLOCKED in contributing factors or secondary issues")
	}
}

func TestDisambiguation_SharedCacheIllusion_vs_BaseOOMDanger(t *testing.T) {
	diff := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     16000000,
				MemAvailable: 200000, // 1.25% < 3% -> triggers BASE_OOM_DANGER
			},
		},
		Processes: []collector.ProcessDiff{
			{
				PID:      301,
				Comm:     "cache_hog",
				RSSBytes: 2048 * 1024 * 1024,
				SmapsRollup: collector.SmapsRollupInfo{
					Available:    true,
					RSS:          2048 * 1024,
					SharedClean:  1800 * 1024,
					PrivateDirty: 100 * 1024,
					PSS:          600 * 1024,
				},
			},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Errorf("expected BASE_OOM_DANGER to dominate, got %s", report.PrimaryBlocker.RuleID)
	}

	foundSharedCache := false
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "EDGE_SHARED_CACHE_RSS_ILLUSION" {
			foundSharedCache = true
			break
		}
	}
	if !foundSharedCache {
		t.Errorf("expected EDGE_SHARED_CACHE_RSS_ILLUSION in secondary issues")
	}
}

func TestDisambiguation_IPCUnixPeer_vs_BaseCPUSaturation(t *testing.T) {
	diff := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.1, BusyPercent: 99.9},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{IdlePercent: 0.1}, {IdlePercent: 0.1},
		},
		ProcsRunning: 16,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 50.0},
			CPUFreq: collector.CPUFreqInfo{Available: true, Cores: []collector.CoreFreq{{CoreID: 0, CurFreq: 3000000, MaxFreq: 3000000}}},
		},
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "cpu_burner", CPUPercent: 198.0, CPUTimeDelta: 200},
			{PID: 102, Comm: "syslog_client", State: 'S', Wchan: "unix_stream_sendmsg", CPUPercent: 0.0, NumThreads: 2},
		},
	}

	report := analyzeSnapshotDiff(diff, true)
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if report.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected BASE_CPU_SATURATION to dominate, got %s", report.PrimaryBlocker.RuleID)
	}

	foundIPC := false
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_IPC_UNIX_PEER_CONGESTION" {
			foundIPC = true
			break
		}
	}
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "CONT_IPC_UNIX_PEER_CONGESTION" {
			foundIPC = true
			break
		}
	}
	if !foundIPC {
		t.Errorf("expected CONT_IPC_UNIX_PEER_CONGESTION in contributing factors or secondary issues")
	}
}
