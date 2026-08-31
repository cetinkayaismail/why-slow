package collector

import (
	"path/filepath"
	"testing"
)

func TestParseDiskStats(t *testing.T) {
	diskstatsPath := filepath.Join("testdata", "proc_diskstats")
	info, err := ParseDiskStats(diskstatsPath)
	if err != nil {
		t.Fatalf("unexpected error parsing diskstats: %v", err)
	}

	// Should include "loop0", "sda", "nvme0n1", and "dm-0" (skipping partitions sda1 and nvme0n1p1)
	if len(info.Devices) != 4 {
		t.Fatalf("expected exactly 4 monitored devices, got %d", len(info.Devices))
	}

	dev0 := info.Devices[0]
	if dev0.DeviceName != "loop0" {
		t.Errorf("expected device name 'loop0', got '%s'", dev0.DeviceName)
	}

	dev1 := info.Devices[1]
	if dev1.DeviceName != "sda" {
		t.Errorf("expected device name 'sda', got '%s'", dev1.DeviceName)
	}
	if dev1.ReadsCompleted != 15000 {
		t.Errorf("expected ReadsCompleted 15000, got %d", dev1.ReadsCompleted)
	}
	if dev1.SectorsRead != 1200000 {
		t.Errorf("expected SectorsRead 1200000, got %d", dev1.SectorsRead)
	}
	if dev1.WritesCompleted != 25000 {
		t.Errorf("expected WritesCompleted 25000, got %d", dev1.WritesCompleted)
	}
	if dev1.IOTicks != 54000 {
		t.Errorf("expected IOTicks 54000, got %d", dev1.IOTicks)
	}

	dev2 := info.Devices[2]
	if dev2.DeviceName != "nvme0n1" {
		t.Errorf("expected device name 'nvme0n1', got '%s'", dev2.DeviceName)
	}
	if dev2.IOsInProgress != 2 {
		t.Errorf("expected IOsInProgress 2, got %d", dev2.IOsInProgress)
	}
	if dev2.IOTicks != 150000 {
		t.Errorf("expected IOTicks 150000, got %d", dev2.IOTicks)
	}

	dev3 := info.Devices[3]
	if dev3.DeviceName != "dm-0" {
		t.Errorf("expected device name 'dm-0', got '%s'", dev3.DeviceName)
	}
	if dev3.ReadsCompleted != 12000 {
		t.Errorf("expected ReadsCompleted 12000, got %d", dev3.ReadsCompleted)
	}
}

func TestCheckMountsSpace(t *testing.T) {
	// Test on standard root path
	info, err := CheckMountsSpace([]string{"/"})
	if err != nil {
		t.Fatalf("unexpected error checking mount space: %v", err)
	}

	if len(info.Mounts) == 0 {
		t.Fatalf("expected at least 1 mount report for '/'")
	}

	rootMount := info.Mounts[0]
	if rootMount.Path != "/" {
		t.Errorf("expected path '/', got '%s'", rootMount.Path)
	}
	if rootMount.TotalBytes == 0 {
		t.Errorf("expected non-zero TotalBytes")
	}
	if rootMount.UsedPercent < 0 || rootMount.UsedPercent > 100 {
		t.Errorf("invalid UsedPercent: %f", rootMount.UsedPercent)
	}
	if rootMount.InodesTotal == 0 {
		t.Errorf("expected non-zero InodesTotal on root mount")
	}
	if rootMount.InodesUsedPercent < 0 || rootMount.InodesUsedPercent > 100 {
		t.Errorf("invalid InodesUsedPercent: %f", rootMount.InodesUsedPercent)
	}

	// Test deduplication with duplicate paths
	dedupInfo, err := CheckMountsSpace([]string{"/", "/", "/tmp"})
	if err != nil {
		t.Fatalf("unexpected error on duplicate check: %v", err)
	}
	if len(dedupInfo.Mounts) > 2 {
		t.Errorf("expected deduplication to limit mounts, got %d", len(dedupInfo.Mounts))
	}
}

func TestLiveHostDiskCollectors(t *testing.T) {
	diskStats, err := CollectDiskStats()
	if err != nil {
		t.Fatalf("CollectDiskStats failed on host: %v", err)
	}
	t.Logf("Found %d real block devices on host", len(diskStats.Devices))
	for _, dev := range diskStats.Devices {
		t.Logf("Device: %s (IOTicks: %d, SectorsRead: %d, SectorsWritten: %d)",
			dev.DeviceName, dev.IOTicks, dev.SectorsRead, dev.SectorsWritten)
	}

	diskSpace, err := CollectDiskSpace()
	if err != nil {
		t.Fatalf("CollectDiskSpace failed on host: %v", err)
	}
	t.Logf("Inspected %d mounts on host", len(diskSpace.Mounts))
	for _, m := range diskSpace.Mounts {
		t.Logf("Mount %s: %.1f%% used (Total: %d GB, Avail: %d GB)",
			m.Path, m.UsedPercent, m.TotalBytes/(1024*1024*1024), m.AvailBytes/(1024*1024*1024))
	}
}
