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
	engine.DisableEarlyExit = true

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

	engine.DisableEarlyExit = true
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

func TestEngineEarlyExit(t *testing.T) {
	engine := NewEngine()

	// 1. High confidence Tier 1 scenario: CPU saturation (Confidence >= 0.90)
	diffHighConf := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.1, BusyPercent: 99.9},
		ProcsRunning: 32,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
		},
	}
	report := engine.Analyze(diffHighConf, collector.RunContext{IsRoot: true})
	if report.PrimaryBlocker == nil {
		t.Fatalf("expected PrimaryBlocker to fire")
	}
	if report.PrimaryBlocker.Confidence < 0.90 {
		t.Fatalf("expected Tier 1 confidence >= 0.90, got %f", report.PrimaryBlocker.Confidence)
	}
	if report.Tier3Evaluated {
		t.Errorf("expected Tier3Evaluated to be false when Tier 1 confidence >= 0.90")
	}

	// 2. Clean system: Tier 1 does not fire, Tier 3 must be evaluated
	diffClean := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 95.0, BusyPercent: 5.0},
		LatestSnapshot: &collector.SystemSnapshot{
			Memory:      collector.MemInfo{MemTotal: 16000000, MemAvailable: 12000000},
			Clocksource: collector.ClocksourceInfo{Current: "tsc"},
		},
	}
	reportClean := engine.Analyze(diffClean, collector.RunContext{IsRoot: true})
	if !reportClean.Tier3Evaluated {
		t.Errorf("expected Tier3Evaluated to be true on clean system")
	}
}

func TestEngineDisableRules(t *testing.T) {
	engine := NewEngine()

	err := engine.SetDisabledRules([]string{"NON_EXISTENT_RULE_XYZ"})
	if err == nil {
		t.Fatalf("expected error when disabling unknown rule, got nil")
	}

	ruleID := "BASE_DISK_HARDWARE_SATURATION"
	if err := engine.SetDisabledRules([]string{ruleID}); err != nil {
		t.Fatalf("failed to disable rule %s: %v", ruleID, err)
	}

	diff := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "sda", UtilPercent: 99.0, WriteBytesDelta: 500 * 1024 * 1024},
		},
	}
	report := engine.Analyze(diff, collector.RunContext{IsRoot: true})
	if report.PrimaryBlocker != nil && report.PrimaryBlocker.RuleID == ruleID {
		t.Fatalf("rule %s was disabled but still triggered as primary blocker", ruleID)
	}

	if len(report.DisabledRules) != 1 || report.DisabledRules[0] != ruleID {
		t.Errorf("expected report.DisabledRules to contain %s, got %v", ruleID, report.DisabledRules)
	}
}

func TestRuleExplainAllRules(t *testing.T) {
	engine := NewEngine()
	rules := engine.Rules()
	if len(rules) == 0 {
		t.Fatalf("expected registered rules in engine, got 0")
	}

	for _, rule := range rules {
		expl := rule.Explain()
		if expl.Description == "" {
			t.Errorf("rule %s has empty Description in Explain()", rule.ID())
		}
		if len(expl.KernelSources) == 0 {
			t.Errorf("rule %s has no KernelSources in Explain()", rule.ID())
		}
	}
}

func TestEngineConfidenceCalibration(t *testing.T) {
	engine := NewEngine()

	// 1. Memory rule with High PSI (>20%) -> boosted by 1.10 (0.95 * 1.10 = 1.045 -> clamped to 1.0)
	diffMemHigh := &collector.SnapshotDiff{
		Duration: 1 * time.Second,
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{MemTotal: 10000000, MemAvailable: 200000}, // triggers BASE_OOM_DANGER (base conf 0.95)
			PSI: collector.PSIInfo{
				Available: true,
				Memory:    collector.PSIResource{Some: collector.PSIMetrics{Avg10: 25.0}},
			},
		},
	}
	reportMemHigh := engine.Analyze(diffMemHigh, collector.RunContext{IsRoot: true})
	if !reportMemHigh.Calibrated {
		t.Errorf("expected report.Calibrated=true")
	}
	if reportMemHigh.PrimaryBlocker == nil || reportMemHigh.PrimaryBlocker.RuleID != "BASE_OOM_DANGER" {
		t.Fatalf("expected BASE_OOM_DANGER primary blocker")
	}
	if reportMemHigh.PrimaryBlocker.Confidence != 1.0 {
		t.Errorf("expected clamped confidence 1.0, got %f", reportMemHigh.PrimaryBlocker.Confidence)
	}

	// 2. Memory rule with Low PSI (<1%) -> demoted by 0.70 (0.95 * 0.70 = 0.665)
	diffMemLow := &collector.SnapshotDiff{
		Duration: 1 * time.Second,
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{MemTotal: 10000000, MemAvailable: 200000},
			PSI: collector.PSIInfo{
				Available: true,
				Memory:    collector.PSIResource{Some: collector.PSIMetrics{Avg10: 0.2}},
			},
		},
	}
	reportMemLow := engine.Analyze(diffMemLow, collector.RunContext{IsRoot: true})
	if reportMemLow.PrimaryBlocker.Confidence < 0.66 || reportMemLow.PrimaryBlocker.Confidence > 0.67 {
		t.Errorf("expected demoted confidence ~0.665, got %f", reportMemLow.PrimaryBlocker.Confidence)
	}

	// 3. IO rule with High PSI (>20%) -> boosted by 1.10 (0.95 * 1.10 = 1.045 -> clamped to 1.0)
	diffIOHigh := &collector.SnapshotDiff{
		Duration: 1 * time.Second,
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "sda", UtilPercent: 99.0},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				IO:        collector.PSIResource{Some: collector.PSIMetrics{Avg10: 30.0}},
			},
		},
	}
	reportIOHigh := engine.Analyze(diffIOHigh, collector.RunContext{IsRoot: true})
	if reportIOHigh.PrimaryBlocker == nil || reportIOHigh.PrimaryBlocker.RuleID != "BASE_DISK_HARDWARE_SATURATION" {
		t.Fatalf("expected BASE_DISK_HARDWARE_SATURATION primary blocker")
	}
	if reportIOHigh.PrimaryBlocker.Confidence != 1.0 {
		t.Errorf("expected clamped confidence 1.0, got %f", reportIOHigh.PrimaryBlocker.Confidence)
	}

	// 4. CPU rule with Low PSI (<1%) -> demoted by 0.70 (0.95 * 0.70 = 0.665)
	diffCPULow := &collector.SnapshotDiff{
		Duration:     1 * time.Second,
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.5, BusyPercent: 99.5},
		ProcsRunning: 10,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
			PSI: collector.PSIInfo{
				Available: true,
				CPU:       collector.PSIResource{Some: collector.PSIMetrics{Avg10: 0.5}},
			},
		},
	}
	reportCPULow := engine.Analyze(diffCPULow, collector.RunContext{IsRoot: true})
	if reportCPULow.PrimaryBlocker == nil || reportCPULow.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Fatalf("expected BASE_CPU_SATURATION primary blocker")
	}
	if reportCPULow.PrimaryBlocker.Confidence < 0.66 || reportCPULow.PrimaryBlocker.Confidence > 0.67 {
		t.Errorf("expected demoted confidence ~0.665, got %f", reportCPULow.PrimaryBlocker.Confidence)
	}

	// 5. PSI unavailable -> no-op (confidence remains 0.95)
	diffNoPSI := &collector.SnapshotDiff{
		Duration: 1 * time.Second,
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "sda", UtilPercent: 99.0},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{Available: false},
		},
	}
	reportNoPSI := engine.Analyze(diffNoPSI, collector.RunContext{IsRoot: true})
	if reportNoPSI.Calibrated {
		t.Errorf("expected report.Calibrated=false when PSI is not available")
	}
	if reportNoPSI.PrimaryBlocker.Confidence != 0.95 {
		t.Errorf("expected original uncalibrated confidence 0.95, got %f", reportNoPSI.PrimaryBlocker.Confidence)
	}
}

