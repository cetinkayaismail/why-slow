package analyzer

import (
	"testing"
	"why-slow/internal/collector"
)

func TestRuleCPUSaturation(t *testing.T) {
	rule := &RuleCPUSaturation{}

	// Test negative case (high idle)
	diffOK := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 40.0},
		ProcsRunning: 2,
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
		},
	}
	if diag, triggered := rule.Evaluate(diffOK); triggered {
		t.Fatalf("expected rule not to trigger, got %+v", diag)
	}

	// Test positive case
	diffSat := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.5, BusyPercent: 99.5},
		ProcsRunning: 8, // 4x cores
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 1234, Comm: "stress-ng", CPUPercent: 195.0, CPUTimeDelta: 195},
			{PID: 5678, Comm: "bash", CPUPercent: 2.0, CPUTimeDelta: 2},
		},
	}

	diag, triggered := rule.Evaluate(diffSat)
	if !triggered {
		t.Fatalf("expected rule to trigger")
	}
	if diag.CulpritPID != 1234 || diag.CulpritName != "stress-ng" {
		t.Errorf("expected culprit PID 1234 stress-ng, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", diag.Severity)
	}
}

func TestRuleOOMDanger(t *testing.T) {
	rule := &RuleOOMDanger{}

	// Negative case: Plenty of RAM
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     16000000,
				MemAvailable: 8000000,
				SwapTotal:    4000000,
				SwapFree:     4000000,
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected OOM rule not to trigger")
	}

	// Positive case: RAM depleted + swap depleted
	diffOOM := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     16000000,
				MemAvailable: 200000, // ~1.25% available (< 3%)
				SwapTotal:    4000000,
				SwapFree:     100000, // 2.5% free (< 5%)
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 9001, Comm: "leaky_app", OOMScore: 850, RSSBytes: 14000000 * 1024},
		},
	}

	diag, triggered := rule.Evaluate(diffOOM)
	if !triggered {
		t.Fatalf("expected OOM rule to trigger")
	}
	if diag.CulpritPID != 9001 || diag.CulpritName != "leaky_app" {
		t.Errorf("expected culprit PID 9001 leaky_app, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleDiskSpaceFull(t *testing.T) {
	rule := &RuleDiskSpaceFull{}

	// Negative case: Normal disk usage
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			DiskSpace: collector.DiskSpaceInfo{
				Mounts: []collector.MountSpaceInfo{
					{Path: "/", UsedPercent: 65.0},
					{Path: "/tmp", UsedPercent: 20.0},
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected DiskSpaceFull not to trigger")
	}

	// Positive case: Root partition at 99.5%
	diffFull := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			DiskSpace: collector.DiskSpaceInfo{
				Mounts: []collector.MountSpaceInfo{
					{Path: "/", UsedPercent: 99.5, AvailBytes: 100 * 1024 * 1024, TotalBytes: 500 * 1024 * 1024 * 1024},
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffFull)
	if !triggered {
		t.Fatalf("expected DiskSpaceFull to trigger")
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected Critical severity")
	}
}

func TestRuleDiskHWSaturation(t *testing.T) {
	rule := &RuleDiskHWSaturation{}

	// Negative case: Disk util 30%
	diffNormal := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 30.0},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected DiskHWSaturation not to trigger")
	}

	// Positive case: nvme0n1 at 98%
	diffSat := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 98.2, ReadBytesDelta: 5000000, WriteBytesDelta: 450000000, IOsInProgress: 12},
		},
		Processes: []collector.ProcessDiff{
			{PID: 4812, Comm: "heavy_writer", WriteBytesDelta: 420 * 1024 * 1024},
		},
	}
	diag, triggered := rule.Evaluate(diffSat)
	if !triggered {
		t.Fatalf("expected DiskHWSaturation to trigger")
	}
	if diag.CulpritPID != 4812 || diag.CulpritName != "heavy_writer" {
		t.Errorf("expected culprit PID 4812 heavy_writer, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleThermalThrottling(t *testing.T) {
	rule := &RuleThermalThrottling{}

	// Negative case: Normal temp & full frequency
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 55.0},
			CPUFreq: collector.CPUFreqInfo{
				Available: true,
				Cores: []collector.CoreFreq{
					{CoreID: 0, CurFreq: 3600000, MaxFreq: 3600000},
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected ThermalThrottling not to trigger")
	}

	// Positive case: 92°C and throttled frequency (800 MHz vs 3600 MHz max = 22% of max)
	diffThrottled := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Thermal: collector.ThermalInfo{Available: true, MaxTemp: 92.0},
			CPUFreq: collector.CPUFreqInfo{
				Available: true,
				Cores: []collector.CoreFreq{
					{CoreID: 0, CurFreq: 800000, MaxFreq: 3600000},
					{CoreID: 1, CurFreq: 800000, MaxFreq: 3600000},
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffThrottled)
	if !triggered {
		t.Fatalf("expected ThermalThrottling to trigger")
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected Critical severity")
	}
}

func TestRuleInodeExhaustion(t *testing.T) {
	rule := &RuleInodeExhaustion{}

	// Negative case: Plenty of inodes free
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			DiskSpace: collector.DiskSpaceInfo{
				Mounts: []collector.MountSpaceInfo{
					{Path: "/", InodesTotal: 1000000, InodesFree: 800000, InodesUsedPercent: 20.0},
					{Path: "/tmp", InodesTotal: 500000, InodesFree: 490000, InodesUsedPercent: 2.0},
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected InodeExhaustion not to trigger on healthy filesystem")
	}

	// Positive case: Inodes depleted (99.5% used, only 500 free of 100,000)
	diffDepleted := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			DiskSpace: collector.DiskSpaceInfo{
				Mounts: []collector.MountSpaceInfo{
					{Path: "/var/spool", InodesTotal: 100000, InodesFree: 500, InodesUsedPercent: 99.5},
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffDepleted)
	if !triggered {
		t.Fatalf("expected InodeExhaustion to trigger on 99.5%% inode usage")
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", diag.Severity)
	}
	if diag.RuleID != "BASE_INODE_EXHAUSTION" {
		t.Errorf("expected rule ID BASE_INODE_EXHAUSTION, got %s", diag.RuleID)
	}

	// Positive case: InodesFree == 0
	diffZeroFree := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			DiskSpace: collector.DiskSpaceInfo{
				Mounts: []collector.MountSpaceInfo{
					{Path: "/", InodesTotal: 5000000, InodesFree: 0, InodesUsedPercent: 100.0},
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffZeroFree); !triggered {
		t.Fatalf("expected InodeExhaustion to trigger when InodesFree == 0")
	}
}

func TestRuleIOServiceLatency(t *testing.T) {
	rule := &RuleIOServiceLatency{}

	// Negative case: Normal NVMe latencies (< 1.5ms)
	diffNormal := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{
				DeviceName:           "nvme0n1",
				ReadsCompletedDelta:  500,
				WritesCompletedDelta: 300,
				AvgReadLatencyMS:     0.8,
				AvgWriteLatencyMS:    1.2,
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected IOServiceLatency not to trigger on fast nvme")
	}

	// Positive case: SAN / Cloud EBS storage latency explosion (> 80ms)
	diffSlowSAN := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{
				DeviceName:           "sdb",
				ReadsCompletedDelta:  50,
				WritesCompletedDelta: 100,
				AvgReadLatencyMS:     82.5,
				AvgWriteLatencyMS:    120.0,
			},
		},
	}
	diag, triggered := rule.Evaluate(diffSlowSAN)
	if !triggered {
		t.Fatalf("expected IOServiceLatency to trigger on 82.5ms latency")
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", diag.Severity)
	}
	if diag.RuleID != "BASE_IO_SERVICE_LATENCY" {
		t.Errorf("expected rule ID BASE_IO_SERVICE_LATENCY, got %s", diag.RuleID)
	}
}

func TestRuleTCPSocketMemoryPressure(t *testing.T) {
	rule := &RuleTCPSocketMemoryPressure{}

	// Negative case: Clean TCP stats
	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPMemoryPressuresDelta: 0,
			TCPAbortOnMemoryDelta:   0,
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected TCPSocketMemoryPressure not to trigger on clean netstat")
	}

	// Positive case: Memory pressure and connection aborts
	diffPressured := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPMemoryPressuresDelta: 15,
			TCPAbortOnMemoryDelta:   3,
			TCPRcvCollapsedDelta:    40,
		},
	}
	diag, triggered := rule.Evaluate(diffPressured)
	if !triggered {
		t.Fatalf("expected TCPSocketMemoryPressure to trigger")
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", diag.Severity)
	}
	if diag.RuleID != "BASE_TCP_SOCKET_MEM_PRESS" {
		t.Errorf("expected BASE_TCP_SOCKET_MEM_PRESS, got %s", diag.RuleID)
	}
}

func TestRuleSwapDeviceSaturation(t *testing.T) {
	rule := &RuleSwapDeviceSaturation{}

	// Negative case: Low/no swap traffic
	diffNormal := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			PswpinDelta:  10,
			PswpoutDelta: 20,
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected SwapDeviceSaturation not to trigger on low swap")
	}

	// Positive case: Heavy swap out traffic
	diffHeavy := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			PswpinDelta:  5000,
			PswpoutDelta: 15000,
		},
	}
	diag, triggered := rule.Evaluate(diffHeavy)
	if !triggered {
		t.Fatalf("expected SwapDeviceSaturation to trigger on heavy swap delta")
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", diag.Severity)
	}
	if diag.RuleID != "BASE_SWAP_DEVICE_SATURATION" {
		t.Errorf("expected BASE_SWAP_DEVICE_SATURATION, got %s", diag.RuleID)
	}
}

func TestRuleFSReadOnlyRemount(t *testing.T) {
	rule := &RuleFSReadOnlyRemount{}

	// Negative case: Clean read-write filesystem
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			DiskSpace: collector.DiskSpaceInfo{
				Mounts: []collector.MountSpaceInfo{
					{Path: "/", ReadOnly: false},
					{Path: "/var", ReadOnly: false},
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected FSReadOnlyRemount not to trigger on clean rw mounts")
	}

	// Positive case: Root filesystem remounted read-only
	diffReadOnly := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			DiskSpace: collector.DiskSpaceInfo{
				Mounts: []collector.MountSpaceInfo{
					{Path: "/", ReadOnly: true},
					{Path: "/tmp", ReadOnly: false},
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffReadOnly)
	if !triggered {
		t.Fatalf("expected FSReadOnlyRemount to trigger on ro rootfs")
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", diag.Severity)
	}
	if diag.RuleID != "BASE_FS_READONLY_REMOUNT" {
		t.Errorf("expected BASE_FS_READONLY_REMOUNT, got %s", diag.RuleID)
	}
}

func TestRuleSystemFileTableFull(t *testing.T) {
	rule := &RuleSystemFileTableFull{}

	// Negative case: Plenty of file table headroom
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				FileNR: collector.FileNRInfo{Available: true, Allocated: 5000, Max: 1048576},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected SystemFileTableFull not to trigger on 5k/1M files")
	}

	// Positive case: 100% full file table
	diffFull := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				FileNR: collector.FileNRInfo{Available: true, Allocated: 1048570, Max: 1048576},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffFull)
	if !triggered {
		t.Fatalf("expected SystemFileTableFull to trigger on full file table")
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", diag.Severity)
	}
	if diag.RuleID != "BASE_SYSTEM_FILE_TABLE_FULL" {
		t.Errorf("expected BASE_SYSTEM_FILE_TABLE_FULL, got %s", diag.RuleID)
	}
}

func TestRuleGlobalOOMKillActive(t *testing.T) {
	rule := &RuleGlobalOOMKillActive{}

	// Negative case: 0 OOM kills
	diffClean := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			OOMKillDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected GlobalOOMKillActive not to trigger on 0 kills")
	}

	// Positive case: 2 processes OOM killed in sampling window
	diffKilled := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			OOMKillDelta: 2,
		},
	}
	diag, triggered := rule.Evaluate(diffKilled)
	if !triggered {
		t.Fatalf("expected GlobalOOMKillActive to trigger on OOMKillDelta > 0")
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", diag.Severity)
	}
	if diag.RuleID != "BASE_GLOBAL_OOM_KILL_ACTIVE" {
		t.Errorf("expected BASE_GLOBAL_OOM_KILL_ACTIVE, got %s", diag.RuleID)
	}
}

func TestRuleConntrackTableHardDrop(t *testing.T) {
	rule := &RuleConntrackTableHardDrop{}

	// Negative case: 90% conntrack (handled by Tier 2 warning)
	diffWarning := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Conntrack: collector.ConntrackInfo{Available: true, Count: 235000, Max: 262144, Ratio: 0.896},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffWarning); triggered {
		t.Fatalf("expected ConntrackTableHardDrop not to trigger at 89.6%%")
	}

	// Positive case: 100% full conntrack table
	diffMaxed := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Conntrack: collector.ConntrackInfo{Available: true, Count: 262144, Max: 262144, Ratio: 1.00},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffMaxed)
	if !triggered {
		t.Fatalf("expected ConntrackTableHardDrop to trigger at 100%%")
	}
	if diag.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", diag.Severity)
	}
	if diag.RuleID != "BASE_CONNTRACK_TABLE_HARD_DROP" {
		t.Errorf("expected BASE_CONNTRACK_TABLE_HARD_DROP, got %s", diag.RuleID)
	}
}


