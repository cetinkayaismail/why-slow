// Package analyzer — audit_test.go conducts comprehensive static and dynamic
// audits of all diagnostic rules, causal suppressions, calibration categories,
// and edge-case execution safety.
package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	"why-slow/internal/collector"
)

func TestExhaustiveRuleAudit(t *testing.T) {
	engine := NewEngine()
	rules := engine.Rules()

	ruleMap := make(map[string]Rule)
	structToID := make(map[string]string)

	tierCounts := map[int]int{1: 0, 2: 0, 3: 0}
	var duplicates []string

	for _, r := range rules {
		id := r.ID()
		if id == "" {
			t.Errorf("Rule %T has empty ID", r)
		}
		if _, exists := ruleMap[id]; exists {
			duplicates = append(duplicates, id)
		}
		ruleMap[id] = r
		structName := fmt.Sprintf("%T", r)
		structToID[structName] = id

		tier := r.Tier()
		if tier < 1 || tier > 3 {
			t.Errorf("Rule %s has invalid tier: %d", id, tier)
		}
		tierCounts[tier]++

		expl := r.Explain()
		if expl.Description == "" {
			t.Errorf("Rule %s has empty Explain().Description", id)
		}
		if len(expl.KernelSources) == 0 {
			t.Errorf("Rule %s has empty Explain().KernelSources", id)
		}
		if len(expl.Thresholds) == 0 {
			t.Errorf("Rule %s has empty Explain().Thresholds", id)
		}
		if expl.Remediation == "" {
			t.Errorf("Rule %s has empty Explain().Remediation", id)
		}
	}

	if len(duplicates) > 0 {
		t.Fatalf("Duplicate Rule IDs found: %v", duplicates)
	}

	t.Logf("Audit passed: %d total rules registered (Tier 1: %d, Tier 2: %d, Tier 3: %d)",
		len(rules), tierCounts[1], tierCounts[2], tierCounts[3])

	// Check Suppresses(): verify all suppressed rule IDs exist
	for _, r := range rules {
		for _, sup := range r.Suppresses() {
			if _, exists := ruleMap[sup]; !exists {
				t.Errorf("Rule %s suppresses non-existent rule ID: %q", r.ID(), sup)
			}
		}
	}

	// Verify that every defined Rule struct in source files is registered
	files := []string{
		"tier1_base.go",
		"tier2_contention.go",
		"tier3_edge.go",
	}

	structRegex := regexp.MustCompile(`type Rule([A-Za-z0-9]+)\s+struct`)

	for _, filename := range files {
		f, err := os.Open(filename)
		if err != nil {
			t.Fatalf("Could not open %s: %v", filename, err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if m := structRegex.FindStringSubmatch(line); len(m) == 2 {
				fullStruct := "*analyzer.Rule" + m[1]
				if _, ok := structToID[fullStruct]; !ok {
					t.Errorf("Defined struct %s in %s is NOT registered in Engine!", m[1], filename)
				}
			}
		}
		f.Close()
	}
}

func hasToken(id, token string) bool {
	for _, part := range strings.Split(id, "_") {
		if part == token {
			return true
		}
	}
	return false
}

func TestCalibrationCategorizationAudit(t *testing.T) {
	engine := NewEngine()
	rules := engine.Rules()

	for _, r := range rules {
		id := r.ID()
		isMem := isMemoryRule(id)
		isIO := isIORule(id)
		isCPU := isCPURule(id)

		_ = isMem
		var matched []string
		if isMem {
			matched = append(matched, "MEM")
		}
		if isIO {
			matched = append(matched, "IO")
		}
		if isCPU {
			matched = append(matched, "CPU")
		}

		if len(matched) > 1 {
			t.Errorf("Rule %s matched multiple categories: %v", id, matched)
		}
	}
}

func TestExhaustiveRuleEvaluationSafety(t *testing.T) {
	engine := NewEngine()
	rules := engine.Rules()

	t.Run("nil diff", func(t *testing.T) {
		for _, r := range rules {
			diag, ok := r.Evaluate(nil)
			if ok && diag != nil {
				t.Errorf("Rule %s reported bottleneck on nil diff", r.ID())
			}
		}
	})

	t.Run("nil LatestSnapshot", func(t *testing.T) {
		diff := &collector.SnapshotDiff{
			LatestSnapshot: nil,
		}
		for _, r := range rules {
			diag, ok := r.Evaluate(diff)
			if ok && diag != nil {
				t.Errorf("Rule %s reported bottleneck on nil LatestSnapshot", r.ID())
			}
		}
	})

	t.Run("all zero snapshot", func(t *testing.T) {
		diff := &collector.SnapshotDiff{
			LatestSnapshot: &collector.SystemSnapshot{},
		}
		for _, r := range rules {
			// Must not panic with division by zero or nil dereference
			_, _ = r.Evaluate(diff)
		}
	})

	t.Run("zero MemTotal and zero duration", func(t *testing.T) {
		diff := &collector.SnapshotDiff{
			Duration: 0,
			LatestSnapshot: &collector.SystemSnapshot{
				Memory: collector.MemInfo{MemTotal: 0},
			},
		}
		for _, r := range rules {
			// Must not panic on division by zero
			_, _ = r.Evaluate(diff)
		}
	})

	t.Run("negative or huge deltas", func(t *testing.T) {
		diff := &collector.SnapshotDiff{
			Duration: 1,
			TotalCPUUtil: collector.CPUUtilization{
				UserPercent: 0, SystemPercent: 0, IdlePercent: 0, IOWaitPercent: 0, StealPercent: 0,
			},
			LatestSnapshot: &collector.SystemSnapshot{
				Memory: collector.MemInfo{
					MemTotal:     1000,
					MemAvailable: 2000, // available > total
					SwapTotal:    500,
					SwapFree:     1000, // free > total
				},
			},
		}
		for _, r := range rules {
			// Must not panic on underflow
			_, _ = r.Evaluate(diff)
		}
	})
}

func TestExhaustiveNoFalsePositivesOnHealthyBaseline(t *testing.T) {
	engine := NewEngine()
	rules := engine.Rules()

	healthySnapshot := &collector.SystemSnapshot{
		Timestamp: time.Now(),
		Memory: collector.MemInfo{
			MemTotal:     16 * 1024 * 1024 * 1024, // 16 GB
			MemFree:      8 * 1024 * 1024 * 1024,
			MemAvailable: 12 * 1024 * 1024 * 1024,
			Buffers:      512 * 1024 * 1024,
			Cached:       4 * 1024 * 1024 * 1024,
			SwapTotal:    8 * 1024 * 1024 * 1024,
			SwapFree:     8 * 1024 * 1024 * 1024, // 0 swap used
			Dirty:        10 * 1024 * 1024,       // 10 MB
			Writeback:    0,
			AnonPages:    2 * 1024 * 1024 * 1024,
			Slab:         512 * 1024 * 1024,
			SReclaimable: 400 * 1024 * 1024,
			SUnreclaim:   112 * 1024 * 1024,
		},
		PSI: collector.PSIInfo{
			Available: true,
			CPU: collector.PSIResource{
				Some: collector.PSIMetrics{Avg10: 0.0, Avg60: 0.0, Avg300: 0.0, Total: 0},
			},
			Memory: collector.PSIResource{
				Some: collector.PSIMetrics{Avg10: 0.0, Avg60: 0.0, Avg300: 0.0, Total: 0},
				Full: collector.PSIMetrics{Avg10: 0.0, Avg60: 0.0, Avg300: 0.0, Total: 0},
			},
			IO: collector.PSIResource{
				Some: collector.PSIMetrics{Avg10: 0.0, Avg60: 0.0, Avg300: 0.0, Total: 0},
				Full: collector.PSIMetrics{Avg10: 0.0, Avg60: 0.0, Avg300: 0.0, Total: 0},
			},
		},
		Processes: []collector.ProcessInfo{
			{
				PID:         1,
				Comm:        "systemd",
				State:       'S',
				PPID:        0,
				NumThreads:  1,
				RSSBytes:    10 * 1024 * 1024,
				UTime:       100,
				STime:       50,
				OOMScore:    0,
				OOMScoreAdj: 0,
			},
			{
				PID:         100,
				Comm:        "mysqld",
				State:       'S',
				PPID:        1,
				NumThreads:  16,
				RSSBytes:    500 * 1024 * 1024,
				UTime:       500,
				STime:       200,
				OOMScore:    100,
				OOMScoreAdj: 0,
			},
		},
		DiskSpace: collector.DiskSpaceInfo{
			Mounts: []collector.MountSpaceInfo{
				{
					Path:              "/",
					TotalBytes:        100 * 1024 * 1024 * 1024,
					FreeBytes:         80 * 1024 * 1024 * 1024,
					AvailBytes:        75 * 1024 * 1024 * 1024,
					UsedPercent:       25.0,
					InodesTotal:       1000000,
					InodesFree:        950000,
					InodesUsedPercent: 5.0,
				},
			},
		},
		DiskStats: collector.DiskStatsInfo{
			Devices: []collector.DiskDeviceStat{
				{
					DeviceName:      "nvme0n1",
					ReadsCompleted:  1000,
					WritesCompleted: 2000,
				},
			},
		},
		TCPSockets: collector.TCPSocketsInfo{
			Established: 50,
			TimeWait:    5,
		},
	}

	healthyDiff := &collector.SnapshotDiff{
		Duration:          1 * time.Second,
		Timestamp:         time.Now(),
		ClockJumpDetected: false,
		TotalCPUUtil: collector.CPUUtilization{
			UserPercent:    5.0,
			SystemPercent:  2.0,
			IdlePercent:    93.0,
			IOWaitPercent:  0.0,
			SoftIRQPercent: 0.0,
			StealPercent:   0.0,
			BusyPercent:    7.0,
		},
		ProcsRunning:          1,
		ProcsBlocked:          0,
		ContextSwitchesDelta:  1000,
		ProcessesCreatedDelta: 5,
		Disks: []collector.DiskDeviceDiff{
			{
				DeviceName:        "nvme0n1",
				UtilPercent:       2.0,
				AvgReadLatencyMS:  0.5,
				AvgWriteLatencyMS: 0.5,
			},
		},
		Processes: []collector.ProcessDiff{
			{
				PID:      1,
				Comm:     "systemd",
				State:    'S',
				RSSBytes: 10 * 1024 * 1024,
			},
			{
				PID:      100,
				Comm:     "mysqld",
				State:    'S',
				RSSBytes: 500 * 1024 * 1024,
			},
		},
		LatestSnapshot: healthySnapshot,
	}

	var falsePositives []string
	for _, r := range rules {
		diag, ok := r.Evaluate(healthyDiff)
		if ok && diag != nil {
			falsePositives = append(falsePositives, fmt.Sprintf("%s (Tier %d, Severity %s, Conf %.2f: %s)",
				r.ID(), diag.Tier, diag.Severity, diag.Confidence, diag.Title))
		}
	}

	if len(falsePositives) > 0 {
		for _, fp := range falsePositives {
			t.Errorf("FALSE POSITIVE ON HEALTHY BASELINE: %s", fp)
		}
		t.Fatalf("Total %d False Positives detected on healthy baseline!", len(falsePositives))
	}
}
