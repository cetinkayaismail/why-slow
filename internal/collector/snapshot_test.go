package collector

import (
	"context"
	"testing"
	"time"
)

func TestDiffSnapshots(t *testing.T) {
	t0 := time.Now()
	t1 := t0.Add(1 * time.Second)

	snapA := &SystemSnapshot{
		Timestamp: t0,
		CPU: CPUStatInfo{
			TotalCPU: CoreCPUStat{
				User:    100,
				Nice:    0,
				System:  50,
				Idle:    800,
				IOWait:  50,
				IRQ:     0,
				SoftIRQ: 0,
				Steal:   0,
			},
			PerCore: []CoreCPUStat{
				{ID: "cpu0", User: 50, System: 25, Idle: 400, IOWait: 25},
				{ID: "cpu1", User: 50, System: 25, Idle: 400, IOWait: 25},
			},
			ProcsRunning: 2,
			ProcsBlocked: 0,
		},
		DiskStats: DiskStatsInfo{
			Devices: []DiskDeviceStat{
				{
					DeviceName:     "nvme0n1",
					SectorsRead:    1000,
					SectorsWritten: 2000,
					IOTicks:        100,
				},
			},
		},
		VMStat: VMStatInfo{
			PgScanDirect:     10,
			AllocStallDirect: 5,
			CompactStall:     2,
			CompactFail:      1,
			PgMajFault:       100,
		},
		NetStat: NetStatInfo{
			ListenOverflows: 0,
			ListenDrops:     0,
		},
		Cgroups: CgroupInfo{
			Groups: []CgroupEntry{
				{Path: "slice/test", ThrottledUsec: 1000, NrThrottled: 2, OOMKills: 0},
			},
		},
		Processes: []ProcessInfo{
			{
				PID:        1001,
				Comm:       "worker",
				State:      'R',
				UTime:      10,
				STime:      5,
				ReadBytes:  1024,
				WriteBytes: 2048,
				OpenFDs:    50,
				MaxFDs:     100,
			},
		},
	}

	snapB := &SystemSnapshot{
		Timestamp: t1,
		CPU: CPUStatInfo{
			TotalCPU: CoreCPUStat{
				User:    150, // +50
				Nice:    0,
				System:  75,  // +25
				Idle:    850, // +50
				IOWait:  125, // +75
				IRQ:     0,
				SoftIRQ: 0,
				Steal:   0,
			}, // Delta total = 200 jiffies
			PerCore: []CoreCPUStat{
				{ID: "cpu0", User: 75, System: 37, Idle: 425, IOWait: 63},
				{ID: "cpu1", User: 75, System: 38, Idle: 425, IOWait: 62},
			},
			ProcsRunning: 4,
			ProcsBlocked: 1,
		},
		DiskStats: DiskStatsInfo{
			Devices: []DiskDeviceStat{
				{
					DeviceName:     "nvme0n1",
					SectorsRead:    1100, // +100 sectors = 51200 bytes
					SectorsWritten: 2500, // +500 sectors = 256000 bytes
					IOTicks:        900,  // +800 ms delta out of 1000 ms = 80% util
					IOsInProgress:  3,
				},
			},
		},
		VMStat: VMStatInfo{
			PgScanDirect:     30,  // +20
			AllocStallDirect: 10,  // +5
			CompactStall:     6,   // +4
			CompactFail:      2,   // +1
			PgMajFault:       120, // +20
		},
		NetStat: NetStatInfo{
			ListenOverflows: 2, // +2
			ListenDrops:     5, // +5
		},
		Cgroups: CgroupInfo{
			Groups: []CgroupEntry{
				{Path: "slice/test", ThrottledUsec: 6000, NrThrottled: 5, OOMKills: 1}, // +5000 usec, +3 nr, +1 oom
			},
		},
		Processes: []ProcessInfo{
			{
				PID:        1001,
				Comm:       "worker",
				State:      'D',
				UTime:      50, // +40
				STime:      15, // +10 (total +50 jiffies)
				ReadBytes:  2048,
				WriteBytes: 4096,
				OpenFDs:    95,
				MaxFDs:     100,
			},
		},
	}

	diff := DiffSnapshots(snapA, snapB)

	// Verify CPU metrics
	// Total delta = 200. User delta = 50 (25%), Sys delta = 25 (12.5%), IOWait delta = 75 (37.5%), Idle delta = 50 (25%)
	if diff.TotalCPUUtil.UserPercent != 25.0 {
		t.Errorf("expected UserPercent 25.0, got %f", diff.TotalCPUUtil.UserPercent)
	}
	if diff.TotalCPUUtil.SystemPercent != 12.5 {
		t.Errorf("expected SystemPercent 12.5, got %f", diff.TotalCPUUtil.SystemPercent)
	}
	if diff.TotalCPUUtil.IOWaitPercent != 37.5 {
		t.Errorf("expected IOWaitPercent 37.5, got %f", diff.TotalCPUUtil.IOWaitPercent)
	}
	if diff.TotalCPUUtil.IdlePercent != 25.0 {
		t.Errorf("expected IdlePercent 25.0, got %f", diff.TotalCPUUtil.IdlePercent)
	}

	// Verify Disk metrics
	if len(diff.Disks) != 1 {
		t.Fatalf("expected 1 disk diff, got %d", len(diff.Disks))
	}
	if diff.Disks[0].UtilPercent != 80.0 {
		t.Errorf("expected Disk UtilPercent 80.0, got %f", diff.Disks[0].UtilPercent)
	}
	if diff.Disks[0].ReadBytesDelta != 51200 {
		t.Errorf("expected ReadBytesDelta 51200, got %d", diff.Disks[0].ReadBytesDelta)
	}
	if diff.Disks[0].WriteBytesDelta != 256000 {
		t.Errorf("expected WriteBytesDelta 256000, got %d", diff.Disks[0].WriteBytesDelta)
	}

	// Verify VMStat deltas
	if diff.VMStat.PgScanDirectDelta != 20 {
		t.Errorf("expected PgScanDirectDelta 20, got %d", diff.VMStat.PgScanDirectDelta)
	}
	if diff.VMStat.AllocStallDirectDelta != 5 {
		t.Errorf("expected AllocStallDirectDelta 5, got %d", diff.VMStat.AllocStallDirectDelta)
	}
	if diff.VMStat.CompactStallDelta != 4 {
		t.Errorf("expected CompactStallDelta 4, got %d", diff.VMStat.CompactStallDelta)
	}

	// Verify NetStat deltas
	if diff.NetStat.ListenDropsDelta != 5 {
		t.Errorf("expected ListenDropsDelta 5, got %d", diff.NetStat.ListenDropsDelta)
	}
	if diff.NetStat.ListenOverflowsDelta != 2 {
		t.Errorf("expected ListenOverflowsDelta 2, got %d", diff.NetStat.ListenOverflowsDelta)
	}

	// Verify Cgroup deltas
	if len(diff.Cgroups) != 1 {
		t.Fatalf("expected 1 cgroup diff, got %d", len(diff.Cgroups))
	}
	if diff.Cgroups[0].ThrottledUsecDelta != 5000 {
		t.Errorf("expected ThrottledUsecDelta 5000, got %d", diff.Cgroups[0].ThrottledUsecDelta)
	}
	if diff.Cgroups[0].NrThrottledDelta != 3 {
		t.Errorf("expected NrThrottledDelta 3, got %d", diff.Cgroups[0].NrThrottledDelta)
	}
	if diff.Cgroups[0].OOMKillsDelta != 1 {
		t.Errorf("expected OOMKillsDelta 1, got %d", diff.Cgroups[0].OOMKillsDelta)
	}

	// Verify Process deltas
	if len(diff.Processes) != 1 {
		t.Fatalf("expected 1 process diff, got %d", len(diff.Processes))
	}
	p := diff.Processes[0]
	if p.CPUTimeDelta != 50 {
		t.Errorf("expected CPUTimeDelta 50, got %d", p.CPUTimeDelta)
	}
	if p.State != 'D' {
		t.Errorf("expected State 'D', got %c", p.State)
	}
	if p.FDRatio != 0.95 {
		t.Errorf("expected FDRatio 0.95, got %f", p.FDRatio)
	}
}

func TestLiveHostFullSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	snapA, err := CollectSnapshot(ctx)
	if err != nil {
		t.Fatalf("CollectSnapshot A failed on host: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	snapB, err := CollectSnapshot(ctx)
	if err != nil {
		t.Fatalf("CollectSnapshot B failed on host: %v", err)
	}

	diff := DiffSnapshots(snapA, snapB)
	if diff.LatestSnapshot == nil {
		t.Fatalf("expected non-nil LatestSnapshot in diff")
	}

	t.Logf("Host Snapshot Diff: Duration=%v, CPU Busy=%.2f%%, Procs Scanned=%d, Disks=%d",
		diff.Duration, diff.TotalCPUUtil.BusyPercent, len(diff.Processes), len(diff.Disks))
}

