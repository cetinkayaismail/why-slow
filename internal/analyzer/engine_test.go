package analyzer

import (
	"testing"
	"time"
	"why-slow/internal/collector"
)

func TestEngineCleanSystem(t *testing.T) {
	engine := NewEngine()
	diff := &collector.SnapshotDiff{
		Duration:     1 * time.Second,
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 85.0},
		LatestSnapshot: &collector.SystemSnapshot{
			Memory:      collector.MemInfo{MemTotal: 16000000, MemAvailable: 10000000},
			Clocksource: collector.ClocksourceInfo{Current: "tsc"},
		},
	}

	report := engine.Analyze(diff, collector.RunContext{IsRoot: false})
	if report == nil {
		t.Fatalf("expected non-nil report")
	}
	if report.PrimaryBlocker != nil {
		t.Errorf("expected no PrimaryBlocker on clean system, got %+v", report.PrimaryBlocker)
	}
	if report.PrivilegeLevel != "unprivileged" {
		t.Errorf("expected PrivilegeLevel 'unprivileged', got '%s'", report.PrivilegeLevel)
	}
}

func TestEngineRootCauseIsolation(t *testing.T) {
	engine := NewEngine()

	// Multi-fault scenario:
	// Tier 1: Disk HW saturation (nvme0n1 at 99%)
	// Tier 2: D-state pileup (3 processes waiting on ext4_writepages)
	// Tier 3: THP compaction stall (5 stalls)
	diff := &collector.SnapshotDiff{
		Duration:     1 * time.Second,
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 80.0},
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 99.0, WriteBytesDelta: 500 * 1024 * 1024},
		},
		VMStat: collector.VMStatDiff{
			CompactStallDelta: 5,
		},
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "db1", State: 'D', Wchan: "ext4_writepages", WriteBytesDelta: 200 * 1024 * 1024},
			{PID: 102, Comm: "db2", State: 'D', Wchan: "ext4_writepages", WriteBytesDelta: 200 * 1024 * 1024},
			{PID: 103, Comm: "db3", State: 'D', Wchan: "sync_file_range", WriteBytesDelta: 100 * 1024 * 1024},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			Memory:      collector.MemInfo{MemTotal: 16000000, MemAvailable: 8000000},
			Clocksource: collector.ClocksourceInfo{Current: "tsc"},
		},
	}

	report := engine.Analyze(diff, collector.RunContext{IsRoot: true})
	if report == nil || report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker to be diagnosed")
	}

	// Primary blocker MUST be the Tier 1 issue: BASE_DISK_HARDWARE_SATURATION
	if report.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Errorf("expected PrimaryBlocker 'BASE_DISK_HARDWARE_SATURATION', got '%s'", report.PrimaryBlocker.RuleID)
	}

	// CONT_DSTATE_PILEUP should be SUPPRESSED by BASE_DISK_HARDWARE_SATURATION (causal chain)
	for _, cf := range report.ContributingFactors {
		if cf.RuleID == "CONT_DSTATE_PILEUP" {
			t.Errorf("expected CONT_DSTATE_PILEUP to be suppressed by BASE_DISK_HARDWARE_SATURATION, but found in ContributingFactors")
		}
	}
	for _, si := range report.SecondaryIssues {
		if si.RuleID == "CONT_DSTATE_PILEUP" {
			t.Errorf("expected CONT_DSTATE_PILEUP to be suppressed by BASE_DISK_HARDWARE_SATURATION, but found in SecondaryIssues")
		}
	}

	// Secondary issues should contain EDGE_THP_COMPACTION_STALL
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

func TestEnginePrivilegeConfidencePenalty(t *testing.T) {
	engine := NewEngine()

	diff := &collector.SnapshotDiff{
		Duration:     1 * time.Second,
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.5, BusyPercent: 99.5},
		ProcsRunning: 8,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
			Memory:      collector.MemInfo{MemTotal: 16000000, MemAvailable: 8000000},
			Clocksource: collector.ClocksourceInfo{Current: "tsc"},
		},
		Processes: []collector.ProcessDiff{
			{PID: 500, Comm: "heavy", CPUTimeDelta: 100},
		},
	}

	// When unprivileged: confidence is penalized by 0.6x for PID-dependent rules
	reportUnpriv := engine.Analyze(diff, collector.RunContext{IsRoot: false})
	if reportUnpriv.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	expectedUnprivConf := 0.95 * 0.60
	if reportUnpriv.PrimaryBlocker.Confidence != expectedUnprivConf {
		t.Errorf("expected unprivileged confidence %f, got %f", expectedUnprivConf, reportUnpriv.PrimaryBlocker.Confidence)
	}

	// When root: full confidence
	reportRoot := engine.Analyze(diff, collector.RunContext{IsRoot: true})
	if reportRoot.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker")
	}
	if reportRoot.PrimaryBlocker.Confidence != 0.95 {
		t.Errorf("expected root confidence 0.95, got %f", reportRoot.PrimaryBlocker.Confidence)
	}
}

func TestEngineEnterpriseCompoundScenario(t *testing.T) {
	engine := NewEngine()

	diff := &collector.SnapshotDiff{
		Duration: 1 * time.Second,
		TotalCPUUtil: collector.CPUUtilization{
			StealPercent: 24.5,
			BusyPercent:  60.0,
			IdlePercent:  15.5,
		},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{StealPercent: 35.0},
			{StealPercent: 14.0},
		},
		Disks: []collector.DiskDeviceDiff{
			{
				DeviceName:           "sdb",
				ReadsCompletedDelta:  50,
				WritesCompletedDelta: 100,
				AvgReadLatencyMS:     82.5,
				AvgWriteLatencyMS:    120.0,
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 45, Comm: "ksmd", CPUPercent: 85.0},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     100 * 1024 * 1024,
				MemAvailable: 10 * 1024 * 1024,
			},
			Clocksource: collector.ClocksourceInfo{Current: "tsc"},
			SystemConfig: collector.SystemConfigInfo{
				Virt: collector.VirtInfo{
					BalloonBytes: 40 * 1024 * 1024 * 1024,
				},
				Conntrack: collector.ConntrackInfo{
					Available: true,
					Count:     245760,
					Max:       262144,
					Ratio:     float64(245760) / 262144.0,
				},
				BuddyInfo: collector.ZoneBuddyInfo{
					Available:       true,
					DMA32FreePages:  0,
					NormalFreePages: 500000,
				},
				KSM: collector.KSMInfo{
					Available:    true,
					Running:      true,
					PagesToScan:  20000,
					PagesShared:  15000,
					PagesSharing: 60000,
				},
				IRQStat: collector.IRQStatInfo{
					Available:         true,
					MaxCoreID:         3,
					MaxCoreIRQs:       150000,
					OtherCoresAvgIRQs: 2000,
				},
			},
		},
	}

	report := engine.Analyze(diff, collector.RunContext{IsRoot: true})
	if report == nil || report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker to be diagnosed in compound scenario")
	}

	// Primary blocker MUST be the Tier 1 issue: BASE_IO_SERVICE_LATENCY
	if report.PrimaryBlocker.RuleID != "BASE_IO_SERVICE_LATENCY" {
		t.Errorf("expected PrimaryBlocker 'BASE_IO_SERVICE_LATENCY', got '%s'", report.PrimaryBlocker.RuleID)
	}

	// Contributing factors should contain Tier 2 rules: VCPU_STEAL_TIME, BALLOON_OVERCOMMIT, CONNTRACK_EXHAUSTION
	tier2Map := make(map[string]bool)
	for _, cf := range report.ContributingFactors {
		tier2Map[cf.RuleID] = true
	}
	if !tier2Map["CONT_VCPU_STEAL_TIME"] {
		t.Errorf("expected CONT_VCPU_STEAL_TIME in ContributingFactors")
	}
	if !tier2Map["CONT_BALLOON_OVERCOMMIT"] {
		t.Errorf("expected CONT_BALLOON_OVERCOMMIT in ContributingFactors")
	}
	if !tier2Map["CONT_CONNTRACK_EXHAUSTION"] {
		t.Errorf("expected CONT_CONNTRACK_EXHAUSTION in ContributingFactors")
	}

	// Secondary issues should contain Tier 3 rules: ZONE_DMA32_EXHAUSTION, KSM_SCAN_STALL, IRQ_CORE_STORM
	tier3Map := make(map[string]bool)
	for _, si := range report.SecondaryIssues {
		tier3Map[si.RuleID] = true
	}
	if !tier3Map["EDGE_ZONE_DMA32_EXHAUSTION"] {
		t.Errorf("expected EDGE_ZONE_DMA32_EXHAUSTION in SecondaryIssues")
	}
	if !tier3Map["EDGE_KSM_SCAN_STALL"] {
		t.Errorf("expected EDGE_KSM_SCAN_STALL in SecondaryIssues")
	}
	if !tier3Map["EDGE_IRQ_CORE_STORM"] {
		t.Errorf("expected EDGE_IRQ_CORE_STORM in SecondaryIssues")
	}
}
