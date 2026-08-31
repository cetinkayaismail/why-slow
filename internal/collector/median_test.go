package collector

import (
	"testing"
	"time"
)

func TestMedianDiff(t *testing.T) {
	// Test empty slice
	if res := MedianDiff(nil); res != nil {
		t.Errorf("expected nil for empty diffs")
	}

	// 3 samples with transient spike on sample 2
	d1 := &SnapshotDiff{
		Duration:             1 * time.Second,
		TotalCPUUtil:         CPUUtilization{IdlePercent: 80.0, BusyPercent: 20.0},
		ProcsRunning:         2,
		ContextSwitchesDelta: 1000,
		VMStat:               VMStatDiff{PgScanDirectDelta: 0},
	}
	d2 := &SnapshotDiff{
		Duration:             1 * time.Second,
		TotalCPUUtil:         CPUUtilization{IdlePercent: 10.0, BusyPercent: 90.0}, // spike!
		ProcsRunning:         16,                                                   // spike!
		ContextSwitchesDelta: 50000,                                                // spike!
		VMStat:               VMStatDiff{PgScanDirectDelta: 500},
	}
	d3 := &SnapshotDiff{
		Duration:             1 * time.Second,
		TotalCPUUtil:         CPUUtilization{IdlePercent: 75.0, BusyPercent: 25.0},
		ProcsRunning:         3,
		ContextSwitchesDelta: 1200,
		VMStat:               VMStatDiff{PgScanDirectDelta: 0},
	}

	median := MedianDiff([]*SnapshotDiff{d1, d2, d3})
	if median == nil {
		t.Fatalf("expected non-nil median diff")
	}

	if median.ProcsRunning != 3 {
		t.Errorf("expected median ProcsRunning=3, got %d", median.ProcsRunning)
	}
	if median.ContextSwitchesDelta != 1200 {
		t.Errorf("expected median ContextSwitchesDelta=1200, got %d", median.ContextSwitchesDelta)
	}
	if median.TotalCPUUtil.BusyPercent != 25.0 {
		t.Errorf("expected median BusyPercent=25.0, got %f", median.TotalCPUUtil.BusyPercent)
	}
	if median.VMStat.PgScanDirectDelta != 0 {
		t.Errorf("expected median PgScanDirectDelta=0, got %d", median.VMStat.PgScanDirectDelta)
	}
}
