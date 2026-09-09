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

func TestMedianDiff_PerCoreAndDisksAndCgroups(t *testing.T) {
	d1 := &SnapshotDiff{
		PerCoreCPUUtil: []CPUUtilization{
			{BusyPercent: 10.0},
			{BusyPercent: 30.0},
		},
		Disks: []DiskDeviceDiff{
			{DeviceName: "sda", UtilPercent: 10.0, AvgReadLatencyMS: 5.0},
			{DeviceName: "sdb", UtilPercent: 10.0},
		},
		Cgroups: []CgroupDiff{
			{Path: "/docker/c1", ThrottledUsecDelta: 100, NrThrottledDelta: 1},
			{Path: "/docker/c2", ThrottledUsecDelta: 50},
		},
	}
	d2 := &SnapshotDiff{
		PerCoreCPUUtil: []CPUUtilization{
			{BusyPercent: 90.0},
			{BusyPercent: 80.0},
		},
		Disks: []DiskDeviceDiff{
			{DeviceName: "sda", UtilPercent: 95.0, AvgReadLatencyMS: 50.0},
			{DeviceName: "sdb", UtilPercent: 90.0},
		},
		Cgroups: []CgroupDiff{
			{Path: "/docker/c1", ThrottledUsecDelta: 5000, NrThrottledDelta: 50},
		},
	}
	d3 := &SnapshotDiff{
		PerCoreCPUUtil: []CPUUtilization{
			{BusyPercent: 15.0},
			{BusyPercent: 35.0},
		},
		Disks: []DiskDeviceDiff{
			{DeviceName: "sda", UtilPercent: 12.0, AvgReadLatencyMS: 6.0},
		},
		Cgroups: []CgroupDiff{
			{Path: "/docker/c1", ThrottledUsecDelta: 200, NrThrottledDelta: 2},
			{Path: "/docker/c2", ThrottledUsecDelta: 60},
		},
	}

	median := MedianDiff([]*SnapshotDiff{d1, d2, d3})
	if median == nil {
		t.Fatalf("expected non-nil median diff")
	}

	if len(median.PerCoreCPUUtil) != 2 {
		t.Fatalf("expected 2 cores, got %d", len(median.PerCoreCPUUtil))
	}
	if median.PerCoreCPUUtil[0].BusyPercent != 15.0 {
		t.Errorf("expected core 0 median BusyPercent=15.0, got %f", median.PerCoreCPUUtil[0].BusyPercent)
	}
	if median.PerCoreCPUUtil[1].BusyPercent != 35.0 {
		t.Errorf("expected core 1 median BusyPercent=35.0, got %f", median.PerCoreCPUUtil[1].BusyPercent)
	}

	if len(median.Disks) != 1 || median.Disks[0].DeviceName != "sda" {
		t.Fatalf("expected 1 disk (sda) in intersection, got %+v", median.Disks)
	}
	if median.Disks[0].UtilPercent != 12.0 {
		t.Errorf("expected sda median UtilPercent=12.0, got %f", median.Disks[0].UtilPercent)
	}
	if median.Disks[0].AvgReadLatencyMS != 6.0 {
		t.Errorf("expected sda median AvgReadLatencyMS=6.0, got %f", median.Disks[0].AvgReadLatencyMS)
	}

	if len(median.Cgroups) != 1 || median.Cgroups[0].Path != "/docker/c1" {
		t.Fatalf("expected 1 cgroup (/docker/c1) in intersection, got %+v", median.Cgroups)
	}
	if median.Cgroups[0].ThrottledUsecDelta != 200 {
		t.Errorf("expected median ThrottledUsecDelta=200, got %d", median.Cgroups[0].ThrottledUsecDelta)
	}
	if median.Cgroups[0].NrThrottledDelta != 2 {
		t.Errorf("expected median NrThrottledDelta=2, got %d", median.Cgroups[0].NrThrottledDelta)
	}
}
