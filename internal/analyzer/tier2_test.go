package analyzer

import (
	"fmt"
	"testing"
	"why-slow/internal/collector"
)

func TestRuleDStatePileup(t *testing.T) {
	rule := &RuleDStatePileup{}

	// Negative case: only 1 D state process
	diffFew := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "worker1", State: 'D', Wchan: "ext4_writepages"},
			{PID: 101, Comm: "worker2", State: 'S', Wchan: "futex_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffFew); triggered {
		t.Fatalf("expected DStatePileup not to trigger with < 3 D-state processes")
	}

	// Positive case: 3 D state processes
	diffPileup := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "worker1", State: 'D', Wchan: "sync_file_range", WriteBytesDelta: 50 * 1024 * 1024},
			{PID: 101, Comm: "worker2", State: 'D', Wchan: "ext4_writepages", WriteBytesDelta: 100 * 1024 * 1024},
			{PID: 102, Comm: "worker3", State: 'D', Wchan: "nfs_wait_on_request", WriteBytesDelta: 10 * 1024 * 1024},
		},
	}
	diag, triggered := rule.Evaluate(diffPileup)
	if !triggered {
		t.Fatalf("expected DStatePileup to trigger")
	}
	if diag.CulpritPID != 101 || diag.CulpritName != "worker2" {
		t.Errorf("expected culprit PID 101 worker2, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", diag.Severity)
	}
}

func TestRuleSwapThrashing(t *testing.T) {
	rule := &RuleSwapThrashing{}

	// Negative case: no alloc stalls
	diffNormal := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			PgScanDirectDelta:     10,
			AllocStallDirectDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected SwapThrashing not to trigger when allocstall=0")
	}

	// Positive case
	diffThrashing := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			PgScanDirectDelta:     500,
			AllocStallDirectDelta: 45,
		},
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				Memory: collector.PSIResource{
					Some: collector.PSIMetrics{Avg10: 42.0},
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffThrashing)
	if !triggered {
		t.Fatalf("expected SwapThrashing to trigger")
	}
	if diag.Confidence != 0.95 {
		t.Errorf("expected 0.95 confidence with high PSI, got %f", diag.Confidence)
	}
}

func TestRuleCgroupThrottled(t *testing.T) {
	rule := &RuleCgroupThrottled{}

	// Negative case: low throttling
	diffLow := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test", ThrottledUsecDelta: 5000, NrThrottledDelta: 1},
		},
	}
	if _, triggered := rule.Evaluate(diffLow); triggered {
		t.Fatalf("expected CgroupThrottled not to trigger on < 100ms throttle")
	}

	// Positive case: 250ms throttled
	diffThrottled := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/heavy-job", ThrottledUsecDelta: 250000, NrThrottledDelta: 12},
		},
		Processes: []collector.ProcessDiff{
			{PID: 4001, Comm: "heavy-node", CgroupPath: "/docker/heavy-job", CPUTimeDelta: 80, CPUPercent: 80.0},
		},
	}
	diag, triggered := rule.Evaluate(diffThrottled)
	if !triggered {
		t.Fatalf("expected CgroupThrottled to trigger")
	}
	if diag.CulpritPID != 4001 || diag.CulpritName != "heavy-node" {
		t.Errorf("expected culprit PID 4001 heavy-node, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleFDExhaustion(t *testing.T) {
	rule := &RuleFDExhaustion{}

	// Negative case: 50% FD usage
	diffNormal := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "app", OpenFDs: 500, MaxFDs: 1000, FDRatio: 0.50},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected FDExhaustion not to trigger on 50%%")
	}

	// Positive case: 94% FD usage
	diffExhausted := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 200, Comm: "leaky-srv", OpenFDs: 940, MaxFDs: 1000, FDRatio: 0.94},
		},
	}
	diag, triggered := rule.Evaluate(diffExhausted)
	if !triggered {
		t.Fatalf("expected FDExhaustion to trigger")
	}
	if diag.CulpritPID != 200 || diag.CulpritName != "leaky-srv" {
		t.Errorf("expected culprit PID 200 leaky-srv, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleSoftIRQUnbalance(t *testing.T) {
	rule := &RuleSoftIRQUnbalance{}

	// Negative case: overall system is busy (idle < 50%)
	diffBusy := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 20.0},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{SoftIRQPercent: 85.0},
			{SoftIRQPercent: 5.0},
		},
	}
	if _, triggered := rule.Evaluate(diffBusy); triggered {
		t.Fatalf("expected SoftIRQUnbalance not to trigger when total idle < 50%%")
	}

	// Positive case: Core 1 at 85% softirq while system is 70% idle
	diffStorm := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 70.0},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{SoftIRQPercent: 5.0},
			{SoftIRQPercent: 85.0},
		},
	}
	diag, triggered := rule.Evaluate(diffStorm)
	if !triggered {
		t.Fatalf("expected SoftIRQUnbalance to trigger")
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh")
	}
}

func TestRuleTCPListenDrops(t *testing.T) {
	rule := &RuleTCPListenDrops{}

	// Negative case: no drops
	diffOK := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{ListenDropsDelta: 0, ListenOverflowsDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffOK); triggered {
		t.Fatalf("expected TCPListenDrops not to trigger")
	}

	// Positive case: 15 drops
	diffDrops := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{ListenDropsDelta: 15, ListenOverflowsDelta: 5},
	}
	diag, triggered := rule.Evaluate(diffDrops)
	if !triggered {
		t.Fatalf("expected TCPListenDrops to trigger")
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh")
	}
}

func TestRulePIDExhaustion(t *testing.T) {
	rule := &RulePIDExhaustion{}

	// Negative case: 100 processes with 4194304 pid_max (0.002% utilized)
	diffNormal := &collector.SnapshotDiff{
		Processes: make([]collector.ProcessDiff, 100),
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				PIDMax: 4194304,
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected PIDExhaustion not to trigger with normal process count")
	}

	// Positive case: 3950 processes with 4096 pid_max (96.4% allocated >= 95%)
	diffExhausted := &collector.SnapshotDiff{
		Processes: make([]collector.ProcessDiff, 3950),
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				PIDMax: 4096,
			},
		},
	}
	diag, triggered := rule.Evaluate(diffExhausted)
	if !triggered {
		t.Fatalf("expected PIDExhaustion to trigger on 96.4%% allocation")
	}
	if diag.RuleID != "CONT_PID_EXHAUSTION" {
		t.Errorf("expected rule ID CONT_PID_EXHAUSTION, got %s", diag.RuleID)
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", diag.Severity)
	}
}

func TestRuleTimeWaitPortExhaustion(t *testing.T) {
	rule := &RuleTimeWaitPortExhaustion{}

	// Negative case: 200 TIME_WAIT sockets with 28232 range (0.7% utilized)
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				PortRange: collector.PortRangeInfo{Low: 32768, High: 60999}, // capacity: 28232
				SockStat:  collector.SockStatInfo{TCPTimeWait: 200},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected TimeWaitPortExhaustion not to trigger on 200 sockets")
	}

	// Positive case: 25000 TIME_WAIT sockets with 28232 range (88.5% >= 85%)
	diffExhausted := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				PortRange: collector.PortRangeInfo{Low: 32768, High: 60999},
				SockStat:  collector.SockStatInfo{TCPTimeWait: 25000},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffExhausted)
	if !triggered {
		t.Fatalf("expected TimeWaitPortExhaustion to trigger on 88.5%% utilization")
	}
	if diag.RuleID != "CONT_TIMEWAIT_PORT_EXHAUSTION" {
		t.Errorf("expected rule ID CONT_TIMEWAIT_PORT_EXHAUSTION, got %s", diag.RuleID)
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", diag.Severity)
	}
}

func TestRuleVCPUStealTime(t *testing.T) {
	rule := &RuleVCPUStealTime{}

	// Negative case: Clean system with 0.1% steal
	diffNormal := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{
			StealPercent: 0.1,
			BusyPercent:  45.0,
			IdlePercent:  54.9,
		},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{StealPercent: 0.1},
			{StealPercent: 0.2},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected VCPUStealTime not to trigger on 0.1%% steal")
	}

	// Positive case: 24.5% aggregate steal time on noisy neighbor hypervisor
	diffSteal := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{
			StealPercent: 24.5,
			BusyPercent:  60.0,
			IdlePercent:  15.5,
		},
		PerCoreCPUUtil: []collector.CPUUtilization{
			{StealPercent: 35.0},
			{StealPercent: 14.0},
		},
	}
	diag, triggered := rule.Evaluate(diffSteal)
	if !triggered {
		t.Fatalf("expected VCPUStealTime to trigger on 24.5%% steal")
	}
	if diag.RuleID != "CONT_VCPU_STEAL_TIME" {
		t.Errorf("expected rule ID CONT_VCPU_STEAL_TIME, got %s", diag.RuleID)
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", diag.Severity)
	}
}

func TestRuleBalloonMemoryOvercommit(t *testing.T) {
	rule := &RuleBalloonMemoryOvercommit{}

	// Negative case: No balloon driver active, healthy memory
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     16384 * 1024, // 16GB
				MemAvailable: 12000 * 1024,
			},
			SystemConfig: collector.SystemConfigInfo{
				Virt: collector.VirtInfo{BalloonBytes: 0},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected BalloonMemoryOvercommit not to trigger on clean system")
	}

	// Positive case: Hypervisor inflates 40GB balloon in 100GB VM (40% >= 20%)
	diffBalloon := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     100 * 1024 * 1024, // 100GB in KB
				MemAvailable: 10 * 1024 * 1024,  // 10GB left
			},
			SystemConfig: collector.SystemConfigInfo{
				Virt: collector.VirtInfo{
					BalloonBytes: 40 * 1024 * 1024 * 1024, // 40GB in bytes
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffBalloon)
	if !triggered {
		t.Fatalf("expected BalloonMemoryOvercommit to trigger on 40GB balloon")
	}
	if diag.RuleID != "CONT_BALLOON_OVERCOMMIT" {
		t.Errorf("expected rule ID CONT_BALLOON_OVERCOMMIT, got %s", diag.RuleID)
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", diag.Severity)
	}
}

func TestRuleConntrackExhaustion(t *testing.T) {
	rule := &RuleConntrackExhaustion{}

	// Negative case: 1,000 / 262,144 (0.4% utilized)
	diffNormal := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Conntrack: collector.ConntrackInfo{
					Available: true,
					Count:     1000,
					Max:       262144,
					Ratio:     float64(1000) / 262144.0,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected ConntrackExhaustion not to trigger on 0.4%% table usage")
	}

	// Positive case: 245,760 / 262,144 (93.75% >= 90%)
	diffExhausted := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Conntrack: collector.ConntrackInfo{
					Available: true,
					Count:     245760,
					Max:       262144,
					Ratio:     float64(245760) / 262144.0,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffExhausted)
	if !triggered {
		t.Fatalf("expected ConntrackExhaustion to trigger on 93.75%% usage")
	}
	if diag.RuleID != "CONT_CONNTRACK_EXHAUSTION" {
		t.Errorf("expected rule ID CONT_CONNTRACK_EXHAUSTION, got %s", diag.RuleID)
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", diag.Severity)
	}
}

func TestRuleARPNeighborTableOverflow(t *testing.T) {
	rule := &RuleARPNeighborTableOverflow{}

	// Negative case: Low neighbor usage
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Neighbor: collector.ARPNeighborInfo{
					Available:     true,
					ActiveEntries: 50,
					GCThresh3:     1024,
					Ratio:         50.0 / 1024.0,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected ARPNeighborTableOverflow not to trigger on clean ARP table")
	}

	// Positive case: Saturated neighbor cache (920 / 1024 = 89.8% >= 85%)
	diffSaturated := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Neighbor: collector.ARPNeighborInfo{
					Available:     true,
					ActiveEntries: 920,
					GCThresh3:     1024,
					Ratio:         920.0 / 1024.0,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffSaturated)
	if !triggered {
		t.Fatalf("expected ARPNeighborTableOverflow to trigger")
	}
	if diag.RuleID != "CONT_ARP_NEIGHBOR_OVERFLOW" {
		t.Errorf("expected CONT_ARP_NEIGHBOR_OVERFLOW, got %s", diag.RuleID)
	}
}

func TestRuleTCPSYNQueueOverflow(t *testing.T) {
	rule := &RuleTCPSYNQueueOverflow{}

	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			ListenOverflowsDelta:      0,
			TCPReqQFullDoCookiesDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected TCPSYNQueueOverflow not to trigger")
	}

	diffOverflow := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			ListenOverflowsDelta:      25,
			TCPReqQFullDoCookiesDelta: 50,
		},
	}
	diag, triggered := rule.Evaluate(diffOverflow)
	if !triggered {
		t.Fatalf("expected TCPSYNQueueOverflow to trigger")
	}
	if diag.RuleID != "CONT_TCP_SYN_QUEUE_OVERFLOW" {
		t.Errorf("expected CONT_TCP_SYN_QUEUE_OVERFLOW, got %s", diag.RuleID)
	}
}

func TestRuleBlockHardwareTagStarvation(t *testing.T) {
	rule := &RuleBlockHardwareTagStarvation{}

	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "app", Wchan: "epoll_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected BlockHardwareTagStarvation not to trigger")
	}

	diffStarved := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "db_writer", Wchan: "blk_mq_get_tag", WriteBytesDelta: 50000},
			{PID: 102, Comm: "db_flusher", Wchan: "io_schedule", WriteBytesDelta: 60000},
		},
	}
	diag, triggered := rule.Evaluate(diffStarved)
	if !triggered {
		t.Fatalf("expected BlockHardwareTagStarvation to trigger")
	}
	if diag.RuleID != "CONT_BLK_MQ_TAG_STARVATION" {
		t.Errorf("expected CONT_BLK_MQ_TAG_STARVATION, got %s", diag.RuleID)
	}
}

func TestRuleSchedRunqueueStarvation(t *testing.T) {
	rule := &RuleSchedRunqueueStarvation{}

	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				SchedStat: collector.SchedStatInfo{
					Available:          true,
					RunqueueWaitTimeMS: 50,
					RunningTimeMS:      1000,
					Ratio:              0.05,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected SchedRunqueueStarvation not to trigger")
	}

	diffStarved := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				SchedStat: collector.SchedStatInfo{
					Available:          true,
					RunqueueWaitTimeMS: 2500,
					RunningTimeMS:      1000,
					Ratio:              2.5,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffStarved)
	if !triggered {
		t.Fatalf("expected SchedRunqueueStarvation to trigger")
	}
	if diag.RuleID != "CONT_SCHED_RUNQUEUE_STARVATION" {
		t.Errorf("expected CONT_SCHED_RUNQUEUE_STARVATION, got %s", diag.RuleID)
	}
}

func TestRuleCgroupMemoryHighThrottle(t *testing.T) {
	rule := &RuleCgroupMemoryHighThrottle{}

	diffClean := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test", MemoryHighEventsDelta: 0},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected CgroupMemoryHighThrottle not to trigger")
	}

	diffThrottled := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{Path: "/docker/test", MemoryHighEventsDelta: 120},
		},
	}
	diag, triggered := rule.Evaluate(diffThrottled)
	if !triggered {
		t.Fatalf("expected CgroupMemoryHighThrottle to trigger")
	}
	if diag.RuleID != "CONT_CGROUP_MEM_HIGH_THROTTLE" {
		t.Errorf("expected CONT_CGROUP_MEM_HIGH_THROTTLE, got %s", diag.RuleID)
	}
}

func TestRuleIOSchedulerQueueLatency(t *testing.T) {
	rule := &RuleIOSchedulerQueueLatency{}

	diffClean := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", ReadsCompletedDelta: 100, AvgQueueLatencyMS: 5.0},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected IOSchedulerQueueLatency not to trigger on low latency")
	}

	diffLaggy := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{
				DeviceName:           "sda",
				ReadsCompletedDelta:  50,
				WritesCompletedDelta: 50,
				AvgQueueLatencyMS:    185.0,
			},
		},
	}
	diag, triggered := rule.Evaluate(diffLaggy)
	if !triggered {
		t.Fatalf("expected IOSchedulerQueueLatency to trigger on 185ms queue delay")
	}
	if diag.RuleID != "CONT_IO_QUEUE_LATENCY" {
		t.Errorf("expected CONT_IO_QUEUE_LATENCY, got %s", diag.RuleID)
	}
}

func TestRulePageTableLockContention(t *testing.T) {
	rule := &RulePageTableLockContention{}

	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 1, Comm: "init", Wchan: "epoll_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected PageTableLockContention not to trigger on clean wchan")
	}

	diffContended := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 1001, Comm: "java", Wchan: "mmap_read_lock", NumThreads: 200},
			{PID: 1002, Comm: "java", Wchan: "page_table_lock", NumThreads: 200},
		},
	}
	diag, triggered := rule.Evaluate(diffContended)
	if !triggered {
		t.Fatalf("expected PageTableLockContention to trigger on multiple page table lock waiters")
	}
	if diag.RuleID != "CONT_PAGE_TABLE_LOCK" {
		t.Errorf("expected CONT_PAGE_TABLE_LOCK, got %s", diag.RuleID)
	}
}

func TestRuleOrphanSocketLeak(t *testing.T) {
	rule := &RuleOrphanSocketLeak{}

	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				SockStat: collector.SockStatInfo{
					TCPInUse:  1000,
					TCPOrphan: 20,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected OrphanSocketLeak not to trigger on low orphans")
	}

	diffLeaked := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				SockStat: collector.SockStatInfo{
					TCPInUse:  3000,
					TCPOrphan: 2000,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffLeaked)
	if !triggered {
		t.Fatalf("expected OrphanSocketLeak to trigger on high orphan ratio")
	}
	if diag.RuleID != "CONT_ORPHAN_SOCKET_LEAK" {
		t.Errorf("expected CONT_ORPHAN_SOCKET_LEAK, got %s", diag.RuleID)
	}
}

func TestRuleContextSwitchStorm(t *testing.T) {
	rule := &RuleContextSwitchStorm{}

	diffLow := &collector.SnapshotDiff{
		ContextSwitchesDelta: 5000,
		TotalCPUUtil: collector.CPUUtilization{
			SystemPercent: 5.0,
			IdlePercent:   80.0,
		},
	}
	if _, triggered := rule.Evaluate(diffLow); triggered {
		t.Fatalf("expected ContextSwitchStorm not to trigger on low switches")
	}

	diffStorm := &collector.SnapshotDiff{
		ContextSwitchesDelta: 150000,
		TotalCPUUtil: collector.CPUUtilization{
			SystemPercent: 28.0,
			IdlePercent:   10.0,
		},
	}
	diag, triggered := rule.Evaluate(diffStorm)
	if !triggered {
		t.Fatalf("expected ContextSwitchStorm to trigger")
	}
	if diag.RuleID != "CONT_CONTEXT_SWITCH_STORM" || diag.Severity != SeverityHigh {
		t.Errorf("unexpected diagnosis: %+v", diag)
	}
}

func TestRuleCPUGovernorPowersaveLag(t *testing.T) {
	rule := &RuleCPUGovernorPowersaveLag{}

	diffNormal := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{BusyPercent: 85.0},
		LatestSnapshot: &collector.SystemSnapshot{
			CPUFreq: collector.CPUFreqInfo{
				Available: true,
				Cores: []collector.CoreFreq{
					{CoreID: 0, CurFreq: 3600000, MaxFreq: 3600000, Governor: "performance"},
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected CPUGovernorPowersaveLag not to trigger on performance governor")
	}

	diffLag := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{BusyPercent: 88.0},
		LatestSnapshot: &collector.SystemSnapshot{
			CPUFreq: collector.CPUFreqInfo{
				Available: true,
				Cores: []collector.CoreFreq{
					{CoreID: 0, CurFreq: 800000, MaxFreq: 3600000, Governor: "powersave"},
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffLag)
	if !triggered {
		t.Fatalf("expected CPUGovernorPowersaveLag to trigger on clamped powersave core")
	}
	if diag.RuleID != "CONT_CPU_GOVERNOR_POWERSAVE_LAG" {
		t.Errorf("expected CONT_CPU_GOVERNOR_POWERSAVE_LAG, got %s", diag.RuleID)
	}
}

func TestRuleKsoftirqdSaturation(t *testing.T) {
	rule := &RuleKsoftirqdSaturation{}

	diffLow := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{SoftIRQPercent: 2.0, BusyPercent: 10.0},
		Processes: []collector.ProcessDiff{
			{PID: 12, Comm: "ksoftirqd/0", CPUPercent: 1.0},
		},
	}
	if _, triggered := rule.Evaluate(diffLow); triggered {
		t.Fatalf("expected KsoftirqdSaturation not to trigger on low load")
	}

	diffSat := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{SoftIRQPercent: 25.0, BusyPercent: 70.0},
		Processes: []collector.ProcessDiff{
			{PID: 12, Comm: "ksoftirqd/0", CPUPercent: 55.0},
		},
	}
	diag, triggered := rule.Evaluate(diffSat)
	if !triggered {
		t.Fatalf("expected KsoftirqdSaturation to trigger on high ksoftirqd CPU")
	}
	if diag.CulpritPID != 12 || diag.CulpritName != "ksoftirqd/0" {
		t.Errorf("expected culprit PID 12 ksoftirqd/0, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleWorkingsetRefaultThrashing(t *testing.T) {
	rule := &RuleWorkingsetRefaultThrashing{}

	diffLow := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			WorkingsetRefaultFileDelta: 100,
		},
	}
	if _, triggered := rule.Evaluate(diffLow); triggered {
		t.Fatalf("expected WorkingsetRefaultThrashing not to trigger on low refaults")
	}

	diffThrash := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			WorkingsetRefaultFileDelta: 8000,
			AllocStallDirectDelta:      15,
		},
	}
	diag, triggered := rule.Evaluate(diffThrash)
	if !triggered {
		t.Fatalf("expected WorkingsetRefaultThrashing to trigger")
	}
	if diag.RuleID != "CONT_WORKINGSET_REFAULT_THRASHING" {
		t.Errorf("expected CONT_WORKINGSET_REFAULT_THRASHING, got %s", diag.RuleID)
	}
}

func TestRuleDirtyPageFlushSaturation(t *testing.T) {
	rule := &RuleDirtyPageFlushSaturation{}

	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal: 16000000,
				Dirty:    50000,
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected DirtyPageFlushSaturation not to trigger on low dirty memory")
	}

	diffDirty := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal: 16000000,
				Dirty:    3500000, // > 20% of RAM
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 400, Comm: "db_writer", Wchan: "balance_dirty_pages_ratelimited"},
		},
	}
	diag, triggered := rule.Evaluate(diffDirty)
	if !triggered {
		t.Fatalf("expected DirtyPageFlushSaturation to trigger")
	}
	if diag.CulpritPID != 400 || diag.CulpritName != "db_writer" {
		t.Errorf("expected culprit PID 400 db_writer, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleFsyncJournalStall(t *testing.T) {
	rule := &RuleFsyncJournalStall{}

	diffOne := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "pg_wal", Wchan: "jbd2_log_wait_commit"},
		},
	}
	if _, triggered := rule.Evaluate(diffOne); triggered {
		t.Fatalf("expected FsyncJournalStall not to trigger with < 2 processes")
	}

	diffMultiple := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "pg_wal", Wchan: "jbd2_log_wait_commit"},
			{PID: 101, Comm: "mysql_commit", Wchan: "vfs_fsync"},
		},
	}
	diag, triggered := rule.Evaluate(diffMultiple)
	if !triggered {
		t.Fatalf("expected FsyncJournalStall to trigger with multiple blocked processes")
	}
	if diag.RuleID != "CONT_FSYNC_JOURNAL_STALL" {
		t.Errorf("expected CONT_FSYNC_JOURNAL_STALL, got %s", diag.RuleID)
	}
}

func TestRulePageCachePollutionStream(t *testing.T) {
	rule := &RulePageCachePollutionStream{}

	diffLow := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 50, Comm: "small_app", ReadBytesDelta: 1024},
		},
	}
	if _, triggered := rule.Evaluate(diffLow); triggered {
		t.Fatalf("expected PageCachePollutionStream not to trigger on low IO")
	}

	diffPollution := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 888, Comm: "rsync_backup", ReadBytesDelta: 80 * 1024 * 1024},
		},
		VMStat: collector.VMStatDiff{
			WorkingsetRefaultFileDelta: 2500,
		},
	}
	diag, triggered := rule.Evaluate(diffPollution)
	if !triggered {
		t.Fatalf("expected PageCachePollutionStream to trigger")
	}
	if diag.CulpritPID != 888 || diag.CulpritName != "rsync_backup" {
		t.Errorf("expected culprit PID 888 rsync_backup, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleSoftnetBacklogDrops(t *testing.T) {
	rule := &RuleSoftnetBacklogDrops{}

	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			SoftnetDroppedDelta:     0,
			SoftnetTimeSqueezeDelta: 5,
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected SoftnetBacklogDrops not to trigger on 0 drops and low squeeze")
	}

	diffDrops := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			SoftnetDroppedDelta:     120,
			SoftnetTimeSqueezeDelta: 80,
		},
	}
	diag, triggered := rule.Evaluate(diffDrops)
	if !triggered {
		t.Fatalf("expected SoftnetBacklogDrops to trigger")
	}
	if diag.RuleID != "CONT_NET_SOFTNET_BACKLOG_DROPS" {
		t.Errorf("expected CONT_NET_SOFTNET_BACKLOG_DROPS, got %s", diag.RuleID)
	}
}

func TestRuleTCPRetransmitStorm(t *testing.T) {
	rule := &RuleTCPRetransmitStorm{}

	diffLow := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			OutSegsDelta:     1000,
			RetransSegsDelta: 5, // 0.5%
		},
	}
	if _, triggered := rule.Evaluate(diffLow); triggered {
		t.Fatalf("expected TCPRetransmitStorm not to trigger on 0.5%% loss")
	}

	diffStorm := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			OutSegsDelta:     2000,
			RetransSegsDelta: 250, // 12.5%
		},
	}
	diag, triggered := rule.Evaluate(diffStorm)
	if !triggered {
		t.Fatalf("expected TCPRetransmitStorm to trigger on 12.5%% loss")
	}
	if diag.RuleID != "CONT_TCP_RETRANSMIT_STORM" {
		t.Errorf("expected CONT_TCP_RETRANSMIT_STORM, got %s", diag.RuleID)
	}
}

func TestRuleTCPZeroWindowStall(t *testing.T) {
	rule := &RuleTCPZeroWindowStall{}

	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPWinProbeDelta:       0,
			TCPZeroWindowDropDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected TCPZeroWindowStall not to trigger on clean network")
	}

	diffStall := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPWinProbeDelta: 12,
		},
		Processes: []collector.ProcessDiff{
			{PID: 600, Comm: "slow_receiver", Wchan: "sk_stream_wait_memory"},
		},
	}
	diag, triggered := rule.Evaluate(diffStall)
	if !triggered {
		t.Fatalf("expected TCPZeroWindowStall to trigger")
	}
	if diag.CulpritPID != 600 || diag.CulpritName != "slow_receiver" {
		t.Errorf("expected culprit PID 600 slow_receiver, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleCoredumpBurstStorm(t *testing.T) {
	rule := &RuleCoredumpBurstStorm{}

	diffClean := &collector.SnapshotDiff{
		ProcessesCreatedDelta: 2,
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected CoredumpBurstStorm not to trigger without dumper process")
	}

	diffDumping := &collector.SnapshotDiff{
		ProcessesCreatedDelta: 35,
		Processes: []collector.ProcessDiff{
			{PID: 1234, Comm: "systemd-coredum", CPUPercent: 45.0},
		},
	}
	diag, triggered := rule.Evaluate(diffDumping)
	if !triggered {
		t.Fatalf("expected CoredumpBurstStorm to trigger")
	}
	if diag.CulpritPID != 1234 || diag.CulpritName != "systemd-coredum" {
		t.Errorf("expected culprit PID 1234 systemd-coredum, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
}

func TestRuleUnixSocketLogBlock(t *testing.T) {
	rule := &RuleUnixSocketLogBlock{}

	diffOne := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 10, Comm: "app1", Wchan: "unix_wait_for_peer"},
		},
	}
	if _, triggered := rule.Evaluate(diffOne); triggered {
		t.Fatalf("expected UnixSocketLogBlock not to trigger with < 2 processes")
	}

	diffBlocked := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 10, Comm: "app1", Wchan: "unix_wait_for_peer"},
			{PID: 11, Comm: "app2", Wchan: "unix_stream_sendmsg"},
		},
	}
	diag, triggered := rule.Evaluate(diffBlocked)
	if !triggered {
		t.Fatalf("expected UnixSocketLogBlock to trigger with multiple blocked processes")
	}
	if diag.RuleID != "CONT_UNIX_SOCKET_LOG_BLOCK" {
		t.Errorf("expected CONT_UNIX_SOCKET_LOG_BLOCK, got %s", diag.RuleID)
	}
}

func TestRuleUDPBufferOverrun(t *testing.T) {
	rule := &RuleUDPBufferOverrun{}

	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			UDPRcvbufErrorsDelta: 0,
			UDPSndbufErrorsDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected UDPBufferOverrun not to trigger on 0 drops")
	}

	diffDrops := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			UDPRcvbufErrorsDelta: 150,
			UDPSndbufErrorsDelta: 20,
		},
	}
	diag, triggered := rule.Evaluate(diffDrops)
	if !triggered {
		t.Fatalf("expected UDPBufferOverrun to trigger on UDP drops")
	}
	if diag.RuleID != "CONT_UDP_BUFFER_OVERRUN" {
		t.Errorf("expected CONT_UDP_BUFFER_OVERRUN, got %s", diag.RuleID)
	}
}

func TestRuleTCPListenOverflowStall(t *testing.T) {
	rule := &RuleTCPListenOverflowStall{}

	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			ListenOverflowsDelta: 0,
			TCPAbortOnDataDelta:  0,
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected TCPListenOverflowStall not to trigger on clean netstat")
	}

	diffOverflow := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			ListenOverflowsDelta: 50,
			TCPAbortOnDataDelta:  20,
		},
	}
	diag, triggered := rule.Evaluate(diffOverflow)
	if !triggered {
		t.Fatalf("expected TCPListenOverflowStall to trigger")
	}
	if diag.RuleID != "CONT_TCP_LISTEN_OVERFLOW_STALL" {
		t.Errorf("expected CONT_TCP_LISTEN_OVERFLOW_STALL, got %s", diag.RuleID)
	}
}

func TestRuleHugeTLBPoolExhaustion(t *testing.T) {
	rule := &RuleHugeTLBPoolExhaustion{}

	diffAmple := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				HugePagesTotal: 2048,
				HugePagesFree:  1024,
				HugePagesRsvd:  512,
			},
		},
	}
	if _, triggered := rule.Evaluate(diffAmple); triggered {
		t.Fatalf("expected HugeTLBPoolExhaustion not to trigger on ample free hugepages")
	}

	diffExhausted := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				HugePagesTotal: 2048,
				HugePagesFree:  0,
				HugePagesRsvd:  2048,
			},
		},
	}
	diag, triggered := rule.Evaluate(diffExhausted)
	if !triggered {
		t.Fatalf("expected HugeTLBPoolExhaustion to trigger on 0 free hugepages")
	}
	if diag.RuleID != "CONT_HUGETLB_POOL_EXHAUSTION" {
		t.Errorf("expected CONT_HUGETLB_POOL_EXHAUSTION, got %s", diag.RuleID)
	}
}

func TestRulePtraceTracerAttach(t *testing.T) {
	rule := &RulePtraceTracerAttach{}

	diffNormal := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "node", TracerPID: 0, CPUPercent: 50.0},
		},
	}
	if _, triggered := rule.Evaluate(diffNormal); triggered {
		t.Fatalf("expected PtraceTracerAttach not to trigger with TracerPID=0")
	}

	diffTraced := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "node", TracerPID: 9999, CPUPercent: 65.0, CPUTimeDelta: 100},
		},
	}
	diag, triggered := rule.Evaluate(diffTraced)
	if !triggered {
		t.Fatalf("expected PtraceTracerAttach to trigger on traced process")
	}
	if diag.CulpritPID != 100 || diag.CulpritName != "node" {
		t.Errorf("expected culprit PID 100 node, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.RuleID != "CONT_PTRACE_TRACER_ATTACH" {
		t.Errorf("expected CONT_PTRACE_TRACER_ATTACH, got %s", diag.RuleID)
	}
}

func TestRuleSysVSemaphoreLimit(t *testing.T) {
	rule := &RuleSysVSemaphoreLimit{}

	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				SysVSem: collector.SysVSemInfo{
					Available:           true,
					SemMSL:              250,
					SemMNS:              32000,
					SemOPM:              32,
					SemMNI:              128,
					AllocatedSemaphores: 500,
					AllocatedSemSets:    5,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected SysVSemaphoreLimit not to trigger on low usage")
	}

	diffExhausted := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				SysVSem: collector.SysVSemInfo{
					Available:           true,
					SemMSL:              250,
					SemMNS:              32000,
					SemOPM:              32,
					SemMNI:              128,
					AllocatedSemaphores: 30000, // > 90%
					AllocatedSemSets:    120,   // > 90%
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffExhausted)
	if !triggered {
		t.Fatalf("expected SysVSemaphoreLimit to trigger on semaphore exhaustion")
	}
	if diag.RuleID != "CONT_SYSV_SEMAPHORE_LIMIT" {
		t.Errorf("expected CONT_SYSV_SEMAPHORE_LIMIT, got %s", diag.RuleID)
	}
}

func TestRuleTCPTimeWaitBucketOverflow(t *testing.T) {
	rule := &RuleTCPTimeWaitBucketOverflow{}

	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPTimeWaitOverflowDelta: 0},
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				TCPMaxTWBuckets: 262144,
				SockStat:        collector.SockStatInfo{TCPTimeWait: 5000},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected TCPTimeWaitBucketOverflow not to trigger on clean state")
	}

	diffOverflow := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPTimeWaitOverflowDelta: 15},
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				TCPMaxTWBuckets: 262144,
				SockStat:        collector.SockStatInfo{TCPTimeWait: 260000},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffOverflow)
	if !triggered {
		t.Fatalf("expected TCPTimeWaitBucketOverflow to trigger on bucket overflows")
	}
	if diag.RuleID != "CONT_TCP_TIMEWAIT_BUCKET_OVERFLOW" {
		t.Errorf("expected CONT_TCP_TIMEWAIT_BUCKET_OVERFLOW, got %s", diag.RuleID)
	}
}

func TestRuleCgroupIOThrottleStall(t *testing.T) {
	rule := &RuleCgroupIOThrottleStall{}

	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				IO: collector.PSIResource{
					Full: collector.PSIMetrics{Avg10: 1.0},
				},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 10, Comm: "db_worker", CgroupPath: "/docker/123", Wchan: "do_epoll_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected CgroupIOThrottleStall not to trigger on low I/O pressure")
	}

	diffThrottled := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				IO: collector.PSIResource{
					Full: collector.PSIMetrics{Avg10: 25.0},
				},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 10, Comm: "db_worker", CgroupPath: "/docker/123", Wchan: "io_schedule", State: 'D'},
		},
	}
	diag, triggered := rule.Evaluate(diffThrottled)
	if !triggered {
		t.Fatalf("expected CgroupIOThrottleStall to trigger under high I/O pressure in io_schedule")
	}
	if diag.CulpritPID != 10 || diag.CulpritName != "db_worker" {
		t.Errorf("expected culprit PID 10 db_worker, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.RuleID != "CONT_CGROUP_IO_THROTTLE_STALL" {
		t.Errorf("expected CONT_CGROUP_IO_THROTTLE_STALL, got %s", diag.RuleID)
	}
}

func TestRuleAuditdBacklogWaitStall(t *testing.T) {
	rule := &RuleAuditdBacklogWaitStall{}

	// Negative case: only 1 stalled process
	diffSingle := &collector.SnapshotDiff{
		ProcsBlocked: 2,
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "worker1", Wchan: "kauditd_wait", State: 'D'},
			{PID: 102, Comm: "worker2", Wchan: "epoll_wait", State: 'S'},
		},
	}
	if _, triggered := rule.Evaluate(diffSingle); triggered {
		t.Fatalf("expected AuditdBacklogWaitStall not to trigger with single process")
	}

	// Positive case: 2 stalled processes in audit_log_start with ProcsBlocked >= 2
	diffStalled := &collector.SnapshotDiff{
		ProcsBlocked: 3,
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "node_svc", Wchan: "audit_log_start", State: 'D'},
			{PID: 102, Comm: "db_client", Wchan: "kauditd_wait", State: 'D'},
		},
	}
	diag, triggered := rule.Evaluate(diffStalled)
	if !triggered {
		t.Fatalf("expected AuditdBacklogWaitStall to trigger on kauditd wait")
	}
	if diag.RuleID != "CONT_AUDITD_BACKLOG_WAIT_STALL" {
		t.Errorf("expected CONT_AUDITD_BACKLOG_WAIT_STALL, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 101 {
		t.Errorf("expected CulpritPID 101, got %d", diag.CulpritPID)
	}
}

func TestRuleTCPSndbufExhaustion(t *testing.T) {
	rule := &RuleTCPSndbufExhaustion{}

	// Negative case: process in sk_stream_wait_memory but 0 corroboration
	diffNoCorrob := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 201, Comm: "streamer", Wchan: "sk_stream_wait_memory"},
		},
	}
	if _, triggered := rule.Evaluate(diffNoCorrob); triggered {
		t.Fatalf("expected TCPSndbufExhaustion not to trigger without corroborating netstat metrics")
	}

	// Positive case: process in tcp_sendmsg_locked + TCPSlowStartRetransDelta > 0
	diffStall := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPSlowStartRetransDelta: 5,
		},
		Processes: []collector.ProcessDiff{
			{PID: 201, Comm: "streamer", Wchan: "tcp_sendmsg_locked"},
		},
	}
	diag, triggered := rule.Evaluate(diffStall)
	if !triggered {
		t.Fatalf("expected TCPSndbufExhaustion to trigger")
	}
	if diag.RuleID != "CONT_TCP_SNDBUF_EXHAUSTION" {
		t.Errorf("expected CONT_TCP_SNDBUF_EXHAUSTION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 201 {
		t.Errorf("expected CulpritPID 201, got %d", diag.CulpritPID)
	}
}

func TestRuleXFSAILPushStall(t *testing.T) {
	rule := &RuleXFSAILPushStall{}

	// Negative case: only 1 process
	diffSingle := &collector.SnapshotDiff{
		ProcsBlocked: 2,
		Processes: []collector.ProcessDiff{
			{PID: 301, Comm: "postgres", Wchan: "xfs_log_reserve"},
		},
	}
	if _, triggered := rule.Evaluate(diffSingle); triggered {
		t.Fatalf("expected XFSAILPushStall not to trigger with 1 process")
	}

	// Positive case: 2 processes in xfs_log_reserve with PSI IO Some >= 15%
	diffStall := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				IO: collector.PSIResource{
					Some: collector.PSIMetrics{Avg10: 22.5},
				},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 301, Comm: "postgres_wal", Wchan: "xfs_log_reserve", State: 'D'},
			{PID: 302, Comm: "postgres_writer", Wchan: "xfs_trans_reserve", State: 'D'},
		},
	}
	diag, triggered := rule.Evaluate(diffStall)
	if !triggered {
		t.Fatalf("expected XFSAILPushStall to trigger on XFS log reserve stalls")
	}
	if diag.RuleID != "CONT_XFS_AIL_PUSH_STALL" {
		t.Errorf("expected CONT_XFS_AIL_PUSH_STALL, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 301 {
		t.Errorf("expected CulpritPID 301, got %d", diag.CulpritPID)
	}
}

func TestRuleDMQueueCongestion(t *testing.T) {
	rule := &RuleDMQueueCongestion{}

	// Negative case: physical disk (not dm-) or low latency
	diffNeg := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "sda", UtilPercent: 90.0, AvgWriteLatencyMS: 60.0},
			{DeviceName: "dm-0", UtilPercent: 40.0, AvgWriteLatencyMS: 10.0},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected DMQueueCongestion not to trigger on low util dm device")
	}

	// Positive case: dm-0 with high util, high write latency, and crypto worker active
	diffPos := &collector.SnapshotDiff{
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "dm-0", UtilPercent: 88.5, AvgWriteLatencyMS: 75.0, IOsInProgress: 8},
		},
		Processes: []collector.ProcessDiff{
			{PID: 400, Comm: "kcryptd/253:0", Wchan: "kcryptd", State: 'D'},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected DMQueueCongestion to trigger")
	}
	if diag.RuleID != "CONT_DM_QUEUE_CONGESTION" {
		t.Errorf("expected CONT_DM_QUEUE_CONGESTION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 400 {
		t.Errorf("expected CulpritPID 400, got %d", diag.CulpritPID)
	}
}

func TestRuleTCPSYNCookieFloodStall(t *testing.T) {
	rule := &RuleTCPSYNCookieFloodStall{}

	// Negative case: no syncookies generated
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			SyncookiesSentDelta: 0,
			OutSegsDelta:        1000,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected TCPSYNCookieFloodStall not to trigger with 0 syncookies")
	}

	// Positive case: 120 syncookies sent, 5 failed validations
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			SyncookiesSentDelta:   120,
			SyncookiesFailedDelta: 5,
			OutSegsDelta:          2500,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected TCPSYNCookieFloodStall to trigger on SYN cookie flood")
	}
	if diag.RuleID != "CONT_TCP_SYN_COOKIE_FLOOD_STALL" {
		t.Errorf("expected CONT_TCP_SYN_COOKIE_FLOOD_STALL, got %s", diag.RuleID)
	}
}

func TestRuleEpollWakeupContention(t *testing.T) {
	rule := &RuleEpollWakeupContention{}

	// Negative case: only 3 epoll workers
	diffNeg := &collector.SnapshotDiff{
		ContextSwitchesDelta: 60000,
		TotalCPUUtil:         collector.CPUUtilization{SystemPercent: 20.0},
		Processes: []collector.ProcessDiff{
			{PID: 1, Comm: "worker1", Wchan: "ep_poll"},
			{PID: 2, Comm: "worker2", Wchan: "ep_poll"},
			{PID: 3, Comm: "worker3", Wchan: "ep_poll"},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected EpollWakeupContention not to trigger with 3 workers")
	}

	// Positive case: 10 epoll workers with high context switches and high system CPU
	procs := make([]collector.ProcessDiff, 10)
	for i := 0; i < 10; i++ {
		procs[i] = collector.ProcessDiff{
			PID:   100 + i,
			Comm:  fmt.Sprintf("nginx_worker_%d", i),
			Wchan: "ep_poll",
		}
	}
	diffPos := &collector.SnapshotDiff{
		ContextSwitchesDelta: 85000,
		TotalCPUUtil:         collector.CPUUtilization{SystemPercent: 25.0},
		Processes:            procs,
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected EpollWakeupContention to trigger")
	}
	if diag.RuleID != "CONT_EPOLL_WAKEUP_CONTENTION" {
		t.Errorf("expected CONT_EPOLL_WAKEUP_CONTENTION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 100 {
		t.Errorf("expected CulpritPID 100, got %d", diag.CulpritPID)
	}
}

func TestRuleAIOEventLimitSaturation(t *testing.T) {
	rule := &RuleAIOEventLimitSaturation{}

	// Negative case: AIO NR is low (50%)
	diffNeg := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				AIONR:    32000,
				AIOMaxNR: 65536,
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 10, Comm: "mysqld", Wchan: "io_submit"},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected AIOEventLimitSaturation not to trigger at 50%%")
	}

	// Positive case: AIO NR is 95% with process in io_submit
	diffPos := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				AIONR:    63000,
				AIOMaxNR: 65536,
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 1234, Comm: "mysqld", Wchan: "io_submit"},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected AIOEventLimitSaturation to trigger")
	}
	if diag.RuleID != "CONT_AIO_EVENT_LIMIT_SATURATION" {
		t.Errorf("expected CONT_AIO_EVENT_LIMIT_SATURATION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 1234 {
		t.Errorf("expected CulpritPID 1234, got %d", diag.CulpritPID)
	}
}

func TestRuleKswapdCPUSpin(t *testing.T) {
	rule := &RuleKswapdCPUSpin{}

	// Negative case: kswapd low CPU
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 50, Comm: "kswapd0", CPUPercent: 5.0},
		},
		VMStat: collector.VMStatDiff{
			PgScanDirectDelta: 10,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected KswapdCPUSpin not to trigger on low CPU")
	}

	// Positive case: kswapd 75% CPU with direct reclaim page scans
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 50, Comm: "kswapd0", CPUPercent: 75.0},
		},
		VMStat: collector.VMStatDiff{
			PgScanDirectDelta:     1500,
			AllocStallDirectDelta: 25,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected KswapdCPUSpin to trigger")
	}
	if diag.RuleID != "CONT_KSWAPD_CPU_SPIN" {
		t.Errorf("expected CONT_KSWAPD_CPU_SPIN, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 50 {
		t.Errorf("expected CulpritPID 50, got %d", diag.CulpritPID)
	}
}

func TestRuleMDRAIDResyncStall(t *testing.T) {
	rule := &RuleMDRAIDResyncStall{}

	// Negative case: no active resync
	diffNeg := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				MDStat: collector.MDStatInfo{
					Available:    true,
					ActiveResync: false,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected MDRAIDResyncStall not to trigger when inactive")
	}

	// Positive case: active resync with underlying disk latency
	diffPos := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				MDStat: collector.MDStatInfo{
					Available:    true,
					ActiveResync: true,
					ArrayName:    "md0",
					Operation:    "resync",
				},
			},
		},
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "sda", UtilPercent: 85.0, AvgWriteLatencyMS: 65.0, IOsInProgress: 6},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected MDRAIDResyncStall to trigger")
	}
	if diag.RuleID != "CONT_MD_RAID_RESYNC_STALL" {
		t.Errorf("expected CONT_MD_RAID_RESYNC_STALL, got %s", diag.RuleID)
	}
}

func TestRuleNetOutOfOrderStall(t *testing.T) {
	rule := &RuleNetOutOfOrderStall{}

	// Negative case: low OFO queue
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPOFOQueueDelta: 50,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetOutOfOrderStall not to trigger on low OFO")
	}

	// Positive case: OFO queue 1200 with buffer collapse
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPOFOQueueDelta:     1200,
			TCPRcvCollapsedDelta: 15,
			OutSegsDelta:         1000,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetOutOfOrderStall to trigger")
	}
	if diag.RuleID != "CONT_NET_OUT_OF_ORDER_STALL" {
		t.Errorf("expected CONT_NET_OUT_OF_ORDER_STALL, got %s", diag.RuleID)
	}
}

func TestRulePOSIXRTSigQueueSaturation(t *testing.T) {
	rule := &RulePOSIXRTSigQueueSaturation{}

	// Negative case: low SigQ ratio
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "app", SigQQueued: 100, SigQMax: 60000, SigQRatio: 0.0016},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected POSIXRTSigQueueSaturation not to trigger on low ratio")
	}

	// Positive case: SigQ 90% with 32 threads
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 888, Comm: "realtime_srv", SigQQueued: 54000, SigQMax: 60000, SigQRatio: 0.90, NumThreads: 32},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected POSIXRTSigQueueSaturation to trigger")
	}
	if diag.RuleID != "CONT_POSIX_RTSIG_QUEUE_SATURATION" {
		t.Errorf("expected CONT_POSIX_RTSIG_QUEUE_SATURATION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 888 {
		t.Errorf("expected CulpritPID 888, got %d", diag.CulpritPID)
	}
}

func TestRuleUDPSndbufExhaustion(t *testing.T) {
	rule := &RuleUDPSndbufExhaustion{}

	// Negative case: low sndbuf errors
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			UDPSndbufErrorsDelta: 5,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected UDPSndbufExhaustion not to trigger on 5 errors")
	}

	// Positive case: 120 sndbuf errors with outbound segments
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			UDPSndbufErrorsDelta: 120,
			OutSegsDelta:         600,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected UDPSndbufExhaustion to trigger")
	}
	if diag.RuleID != "CONT_UDP_SNDBUF_EXHAUSTION" {
		t.Errorf("expected CONT_UDP_SNDBUF_EXHAUSTION, got %s", diag.RuleID)
	}
}

func TestRuleCgroupV1CPUSharesStarvation(t *testing.T) {
	rule := &RuleCgroupV1CPUSharesStarvation{}

	// Negative case: low host CPU
	diffNeg := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{BusyPercent: 30.0},
		LatestSnapshot: &collector.SystemSnapshot{
			Cgroups: collector.CgroupInfo{
				Groups: []collector.CgroupEntry{
					{Path: "/docker/starved", CPUShares: 32},
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected CgroupV1CPUSharesStarvation not to trigger on low CPU")
	}

	// Positive case: host CPU 85% with starved cgroup shares 32
	diffPos := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{BusyPercent: 85.0},
		LatestSnapshot: &collector.SystemSnapshot{
			Cgroups: collector.CgroupInfo{
				Groups: []collector.CgroupEntry{
					{Path: "/docker/starved", CPUShares: 32},
				},
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 450, Comm: "worker", CgroupPath: "/docker/starved"},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected CgroupV1CPUSharesStarvation to trigger")
	}
	if diag.RuleID != "CONT_CGROUP_V1_CPU_SHARES_STARVATION" {
		t.Errorf("expected CONT_CGROUP_V1_CPU_SHARES_STARVATION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 450 {
		t.Errorf("expected CulpritPID 450, got %d", diag.CulpritPID)
	}
}

func TestRuleHugepageLeakNoReuse(t *testing.T) {
	rule := &RuleHugepageLeakNoReuse{}

	// Negative case: ample available memory
	diffNeg := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:       16 * 1024 * 1024,
				MemAvailable:   12 * 1024 * 1024,
				HugePagesTotal: 2048,
				HugePagesRsvd:  2048,
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected HugepageLeakNoReuse not to trigger with ample memory")
	}

	// Positive case: HugePages locking 30% of RAM with low available RAM (10%)
	diffPos := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:       16 * 1024 * 1024,
				MemAvailable:   1 * 1024 * 1024, // < 10%
				HugePagesTotal: 2500,            // 5GB = ~31% of 16GB
				HugePagesRsvd:  2500,
			},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected HugepageLeakNoReuse to trigger")
	}
	if diag.RuleID != "CONT_HUGEPAGE_LEAK_NO_REUSE" {
		t.Errorf("expected CONT_HUGEPAGE_LEAK_NO_REUSE, got %s", diag.RuleID)
	}
}

func TestRuleNetTCPAbortOnClose(t *testing.T) {
	rule := &RuleNetTCPAbortOnClose{}

	// Negative case: low aborts
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPAbortOnCloseDelta: 5,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetTCPAbortOnClose not to trigger on 5 aborts")
	}

	// Positive case: 50 aborts on close with 1000 outbound segments
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPAbortOnCloseDelta: 50,
			OutSegsDelta:         1000,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetTCPAbortOnClose to trigger")
	}
	if diag.RuleID != "CONT_NET_TCP_ABORT_ON_CLOSE" {
		t.Errorf("expected CONT_NET_TCP_ABORT_ON_CLOSE, got %s", diag.RuleID)
	}
}

func TestRuleSchedYieldSpinChurn(t *testing.T) {
	rule := &RuleSchedYieldSpinChurn{}

	// Negative case: low voluntary context switches
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "normal", VoluntaryCtxtSwitchesDelta: 500, CPUPercent: 50.0},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected SchedYieldSpinChurn not to trigger on low switches")
	}

	// Positive case: 25k voluntary context switches/s with 60% CPU
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 777, Comm: "busy_spinner", VoluntaryCtxtSwitchesDelta: 25000, CPUPercent: 60.0, State: 'R', Wchan: "do_sched_yield"},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected SchedYieldSpinChurn to trigger")
	}
	if diag.RuleID != "CONT_SCHED_YIELD_SPIN_CHURN" {
		t.Errorf("expected CONT_SCHED_YIELD_SPIN_CHURN, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 777 {
		t.Errorf("expected CulpritPID 777, got %d", diag.CulpritPID)
	}
}

func TestRuleNetTCPCollapsePrune(t *testing.T) {
	rule := &RuleNetTCPCollapsePrune{}

	// Negative case: low collapses
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPRcvCollapsedDelta: 5,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetTCPCollapsePrune not to trigger on 5 collapses")
	}

	// Positive case: 50 collapses with 100 retransmits
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPRcvCollapsedDelta: 50,
			RetransSegsDelta:     100,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetTCPCollapsePrune to trigger")
	}
	if diag.RuleID != "CONT_NET_TCP_COLLAPSE_PRUNE" {
		t.Errorf("expected CONT_NET_TCP_COLLAPSE_PRUNE, got %s", diag.RuleID)
	}
}

func TestRuleNetTCPMemoryAllocFail(t *testing.T) {
	rule := &RuleNetTCPMemoryAllocFail{}

	// Negative case: 0 memory aborts
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPAbortOnMemoryDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetTCPMemoryAllocFail not to trigger on 0 aborts")
	}

	// Positive case: 10 memory aborts with memory pressure
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPAbortOnMemoryDelta:   10,
			TCPMemoryPressuresDelta: 15,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetTCPMemoryAllocFail to trigger")
	}
	if diag.RuleID != "CONT_NET_TCP_MEMORY_ALLOC_FAIL" {
		t.Errorf("expected CONT_NET_TCP_MEMORY_ALLOC_FAIL, got %s", diag.RuleID)
	}
}

func TestRuleNetTCPZeroWindowDrop(t *testing.T) {
	rule := &RuleNetTCPZeroWindowDrop{}

	// Negative case: 0 zero window drops
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPZeroWindowDropDelta: 0,
			TCPWinProbeDelta:       0,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetTCPZeroWindowDrop not to trigger on 0 drops")
	}

	// Positive case: 25 zero window drops
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			TCPZeroWindowDropDelta: 25,
			TCPWinProbeDelta:       15,
			OutSegsDelta:           500,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetTCPZeroWindowDrop to trigger")
	}
	if diag.RuleID != "CONT_NET_TCP_ZERO_WINDOW_DROP" {
		t.Errorf("expected CONT_NET_TCP_ZERO_WINDOW_DROP, got %s", diag.RuleID)
	}
}

func TestRuleFutexPIDeadlockStall(t *testing.T) {
	rule := &RuleFutexPIDeadlockStall{}

	// Negative case: active CPU progress
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "active", Wchan: "futex_lock_pi", CPUPercent: 50.0},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected FutexPIDeadlockStall not to trigger on active CPU")
	}

	// Positive case: blocked in futex_lock_pi with 0 CPU
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 555, Comm: "deadlocked_svc", Wchan: "futex_lock_pi", State: 'D', CPUPercent: 0.0, NumThreads: 8},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected FutexPIDeadlockStall to trigger")
	}
	if diag.RuleID != "CONT_FUTEX_PI_DEADLOCK_STALL" {
		t.Errorf("expected CONT_FUTEX_PI_DEADLOCK_STALL, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 555 {
		t.Errorf("expected CulpritPID 555, got %d", diag.CulpritPID)
	}
}

func TestRuleNetARPTableTrash(t *testing.T) {
	rule := &RuleNetARPTableTrash{}

	// Negative case: 10% ARP table capacity
	diffNeg := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Neighbor: collector.ARPNeighborInfo{
					Available:     true,
					ActiveEntries: 100,
					GCThresh3:     4096,
					Ratio:         0.024,
				},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetARPTableTrash not to trigger on 2.4%% capacity")
	}

	// Positive case: 95% ARP table capacity
	diffPos := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Neighbor: collector.ARPNeighborInfo{
					Available:     true,
					ActiveEntries: 3900,
					GCThresh3:     4096,
					Ratio:         0.952,
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetARPTableTrash to trigger")
	}
	if diag.RuleID != "CONT_NET_ARP_TABLE_TRASH" {
		t.Errorf("expected CONT_NET_ARP_TABLE_TRASH, got %s", diag.RuleID)
	}
}

func TestRuleDirtyPagesDirectSyncStall(t *testing.T) {
	rule := &RuleDirtyPagesDirectSyncStall{}

	// Negative case: low dirty pages delta and no blocked processes
	diffNeg := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			NRDirtyDelta: 100,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected DirtyPagesDirectSyncStall not to trigger on 100 pages delta")
	}

	// Positive case: process in sync_inodes in D-state
	diffPos := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			NRDirtyDelta: 5000,
		},
		Processes: []collector.ProcessDiff{
			{PID: 400, Comm: "db_flusher", Wchan: "sync_inodes", State: 'D', CPUPercent: 0.0},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected DirtyPagesDirectSyncStall to trigger")
	}
	if diag.RuleID != "CONT_DIRTY_PAGES_DIRECT_SYNC_STALL" {
		t.Errorf("expected CONT_DIRTY_PAGES_DIRECT_SYNC_STALL, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 400 {
		t.Errorf("expected CulpritPID 400, got %d", diag.CulpritPID)
	}
}

func TestRuleNFSRPCClientSaturation(t *testing.T) {
	rule := &RuleNFSRPCClientSaturation{}

	// Negative case: normal process
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "app", Wchan: "epoll_wait", State: 'S'},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NFSRPCClientSaturation not to trigger on epoll_wait")
	}

	// Positive case: process blocked in nfs_wait_client in D-state
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 601, Comm: "nfs_writer", Wchan: "nfs_wait_client", State: 'D', NumThreads: 16},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NFSRPCClientSaturation to trigger")
	}
	if diag.RuleID != "CONT_NFS_RPC_SLOT_TABLE_SATURATION" {
		t.Errorf("expected CONT_NFS_RPC_SLOT_TABLE_SATURATION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 601 {
		t.Errorf("expected CulpritPID 601, got %d", diag.CulpritPID)
	}
}

func TestRuleUnixSocketBacklogOverflow(t *testing.T) {
	rule := &RuleUnixSocketBacklogOverflow{}

	// Negative case: 0 blocked processes
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "daemon", Wchan: "poll_schedule_timeout", State: 'S'},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected UnixSocketBacklogOverflow not to trigger on normal poll")
	}

	// Positive case: process blocked in unix_stream_sendmsg
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 705, Comm: "logger_client", Wchan: "unix_stream_sendmsg", State: 'S', CPUPercent: 0.0, NumThreads: 4},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected UnixSocketBacklogOverflow to trigger")
	}
	if diag.RuleID != "CONT_UNIX_SOCKET_BACKLOG_OVERFLOW" {
		t.Errorf("expected CONT_UNIX_SOCKET_BACKLOG_OVERFLOW, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 705 {
		t.Errorf("expected CulpritPID 705, got %d", diag.CulpritPID)
	}
}

func TestRuleVFSInodeLockContention(t *testing.T) {
	rule := &RuleVFSInodeLockContention{}

	// Negative case: 0 inode lock processes
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "worker", Wchan: "futex_wait", State: 'S'},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected VFSInodeLockContention not to trigger on futex_wait")
	}

	// Positive case: process blocked in inode_lock_shared in D-state
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 880, Comm: "log_writer", Wchan: "inode_lock_shared", State: 'D'},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected VFSInodeLockContention to trigger")
	}
	if diag.RuleID != "CONT_VFS_INODE_LOCK_CONTENTION" {
		t.Errorf("expected CONT_VFS_INODE_LOCK_CONTENTION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 880 {
		t.Errorf("expected CulpritPID 880, got %d", diag.CulpritPID)
	}
}

func TestRuleKernelLockdBlocked(t *testing.T) {
	rule := &RuleKernelLockdBlocked{}

	// Negative case: process active on CPU
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "locker", Wchan: "fcntl_setlk", State: 'R', CPUPercent: 40.0},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected KernelLockdBlocked not to trigger on running CPU")
	}

	// Positive case: process blocked in fcntl_setlk with 0 CPU
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 920, Comm: "db_file_lock", Wchan: "fcntl_setlk", State: 'D', CPUPercent: 0.0, NumThreads: 8},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected KernelLockdBlocked to trigger")
	}
	if diag.RuleID != "CONT_KERNEL_LOCKD_BLOCKED" {
		t.Errorf("expected CONT_KERNEL_LOCKD_BLOCKED, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 920 {
		t.Errorf("expected CulpritPID 920, got %d", diag.CulpritPID)
	}
}

func TestRuleSchedAutogroupStarvation(t *testing.T) {
	rule := &RuleSchedAutogroupStarvation{}

	// Negative case: low procs running
	diffNeg := &collector.SnapshotDiff{
		ProcsRunning: 1,
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "worker", NumThreads: 32, CPUPercent: 10.0, State: 'R'},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected SchedAutogroupStarvation not to trigger on 1 running proc")
	}

	// Positive case: 32 threads with low CPU under busy runqueue
	diffPos := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 10.0},
		ProcsRunning: 12,
		Processes: []collector.ProcessDiff{
			{PID: 333, Comm: "session_server", NumThreads: 32, CPUPercent: 8.0, State: 'R'},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected SchedAutogroupStarvation to trigger")
	}
	if diag.RuleID != "CONT_SCHED_AUTOGROUP_STARVATION" {
		t.Errorf("expected CONT_SCHED_AUTOGROUP_STARVATION, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 333 {
		t.Errorf("expected CulpritPID 333, got %d", diag.CulpritPID)
	}
}

func TestRuleFtraceRingBufferStall(t *testing.T) {
	rule := &RuleFtraceRingBufferStall{}

	// Negative case: normal process
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "worker", Wchan: "epoll_wait", State: 'S'},
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected FtraceRingBufferStall not to trigger on epoll_wait")
	}

	// Positive case: blocked in tracing_wait_pipe
	diffPos := &collector.SnapshotDiff{
		TotalCPUUtil: collector.CPUUtilization{SystemPercent: 25.0},
		Processes: []collector.ProcessDiff{
			{PID: 444, Comm: "trace_agent", Wchan: "tracing_wait_pipe", State: 'D', CPUPercent: 0.0},
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected FtraceRingBufferStall to trigger")
	}
	if diag.RuleID != "CONT_FTRACE_RING_BUFFER_STALL" {
		t.Errorf("expected CONT_FTRACE_RING_BUFFER_STALL, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 444 {
		t.Errorf("expected CulpritPID 444, got %d", diag.CulpritPID)
	}
}

func TestRuleNetDevGROCellDrop(t *testing.T) {
	rule := &RuleNetDevGROCellDrop{}

	// Negative case: 0 softnet drops
	diffNeg := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			SoftnetDroppedDelta:     0,
			SoftnetTimeSqueezeDelta: 0,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected NetDevGROCellDrop not to trigger on 0 drops")
	}

	// Positive case: 50 drops and 50 time squeezes
	diffPos := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{
			SoftnetDroppedDelta:     50,
			SoftnetTimeSqueezeDelta: 50,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected NetDevGROCellDrop to trigger")
	}
	if diag.RuleID != "CONT_NET_DEV_GRO_CELL_DROP" {
		t.Errorf("expected CONT_NET_DEV_GRO_CELL_DROP, got %s", diag.RuleID)
	}
}

func TestRuleMemCompactMigrationFailRate(t *testing.T) {
	rule := &RuleMemCompactMigrationFailRate{}

	// Negative case: low fails
	diffNeg := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			CompactStallDelta: 60,
			CompactFailDelta:  5,
		},
	}
	if _, triggered := rule.Evaluate(diffNeg); triggered {
		t.Fatalf("expected MemCompactMigrationFailRate not to trigger on 5 fails")
	}

	// Positive case: 80 stalls with 50 failures (> 50% fail rate)
	diffPos := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			CompactStallDelta: 80,
			CompactFailDelta:  50,
		},
	}
	diag, triggered := rule.Evaluate(diffPos)
	if !triggered {
		t.Fatalf("expected MemCompactMigrationFailRate to trigger")
	}
	if diag.RuleID != "CONT_MEM_COMPACT_MIGRATION_FAIL_RATE" {
		t.Errorf("expected CONT_MEM_COMPACT_MIGRATION_FAIL_RATE, got %s", diag.RuleID)
	}
}

func TestRuleNetTCPFastOpenFail(t *testing.T) {
	rule := &RuleNetTCPFastOpenFail{}

	// Negative case: 0 TFO failures
	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPFastOpenActiveFailDelta: 0, TCPFastOpenPassiveFailDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected NetTCPFastOpenFail not to trigger on 0 fails")
	}

	// Positive case: 6 TFO fails
	diffFail := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPFastOpenActiveFailDelta: 4, TCPFastOpenPassiveFailDelta: 2},
	}
	diag, triggered := rule.Evaluate(diffFail)
	if !triggered {
		t.Fatalf("expected NetTCPFastOpenFail to trigger on 6 fails")
	}
	if diag.RuleID != "CONT_NET_TCP_FASTOPEN_FAIL" {
		t.Errorf("expected CONT_NET_TCP_FASTOPEN_FAIL, got %s", diag.RuleID)
	}
}

func TestRuleNetTCPSynAckRetransStall(t *testing.T) {
	rule := &RuleNetTCPSynAckRetransStall{}

	// Negative case: 2 SYN retransmissions
	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPSynRetransDelta: 2},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected NetTCPSynAckRetransStall not to trigger on 2 retrans")
	}

	// Positive case: 25 SYN retransmissions
	diffRetrans := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPSynRetransDelta: 25},
	}
	diag, triggered := rule.Evaluate(diffRetrans)
	if !triggered {
		t.Fatalf("expected NetTCPSynAckRetransStall to trigger on 25 retrans")
	}
	if diag.RuleID != "CONT_NET_TCP_SYN_ACK_RETRANS_STALL" {
		t.Errorf("expected CONT_NET_TCP_SYN_ACK_RETRANS_STALL, got %s", diag.RuleID)
	}
}

func TestRuleNetSocketRecvStall(t *testing.T) {
	rule := &RuleNetSocketRecvStall{}

	// Negative case: process in normal epoll_wait
	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "nginx", Wchan: "epoll_wait", State: 'S'},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected NetSocketRecvStall not to trigger on epoll_wait")
	}

	// Positive case: process stalled in sk_wait_data in D-state
	diffStalled := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 200, Comm: "api_worker", Wchan: "sk_wait_data", State: 'D'},
		},
	}
	diag, triggered := rule.Evaluate(diffStalled)
	if !triggered {
		t.Fatalf("expected NetSocketRecvStall to trigger on sk_wait_data")
	}
	if diag.RuleID != "CONT_NET_SOCKET_RECV_STALL" {
		t.Errorf("expected CONT_NET_SOCKET_RECV_STALL, got %s", diag.RuleID)
	}
}

func TestRuleStorageBlkThrottleStall(t *testing.T) {
	rule := &RuleStorageBlkThrottleStall{}

	// Negative case: process in normal sleep
	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "db_proc", Wchan: "futex_wait", State: 'S'},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected StorageBlkThrottleStall not to trigger on clean wchan")
	}

	// Positive case: process in blk_throtl_dispatch_work_fn in D-state
	diffThrottled := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 300, Comm: "heavy_writer", Wchan: "blk_throtl_dispatch_work_fn", State: 'D'},
		},
	}
	diag, triggered := rule.Evaluate(diffThrottled)
	if !triggered {
		t.Fatalf("expected StorageBlkThrottleStall to trigger on blk_throtl")
	}
	if diag.RuleID != "CONT_STORAGE_BLK_THROTTLE_STALL" {
		t.Errorf("expected CONT_STORAGE_BLK_THROTTLE_STALL, got %s", diag.RuleID)
	}
}

func TestRuleNetTCPDeferAcceptTimeout(t *testing.T) {
	rule := &RuleNetTCPDeferAcceptTimeout{}

	// Negative case: 0 drops
	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPDeferAcceptDropDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected NetTCPDeferAcceptTimeout not to trigger on 0 drops")
	}

	// Positive case: 15 drops
	diffDropped := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPDeferAcceptDropDelta: 15},
	}
	diag, triggered := rule.Evaluate(diffDropped)
	if !triggered {
		t.Fatalf("expected NetTCPDeferAcceptTimeout to trigger on 15 drops")
	}
	if diag.RuleID != "CONT_NET_TCP_DEFER_ACCEPT_TIMEOUT" {
		t.Errorf("expected CONT_NET_TCP_DEFER_ACCEPT_TIMEOUT, got %s", diag.RuleID)
	}
}

func TestRuleMemcgReclaimDirectStall(t *testing.T) {
	rule := &RuleMemcgReclaimDirectStall{}

	// Negative case: running process
	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "node", State: 'R', Wchan: ""},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected MemcgReclaimDirectStall not to trigger on running process")
	}

	// Positive case: direct reclaim stall in D-state
	diffStalled := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 400, Comm: "java_app", State: 'D', Wchan: "try_to_free_mem_cgroup_pages"},
		},
	}
	diag, triggered := rule.Evaluate(diffStalled)
	if !triggered {
		t.Fatalf("expected MemcgReclaimDirectStall to trigger on try_to_free_mem_cgroup_pages")
	}
	if diag.RuleID != "CONT_MEMCG_RECLAIM_DIRECT_STALL" {
		t.Errorf("expected CONT_MEMCG_RECLAIM_DIRECT_STALL, got %s", diag.RuleID)
	}
}

func TestRuleXFSAllocBtreeContention(t *testing.T) {
	rule := &RuleXFSAllocBtreeContention{}

	// Negative case: clean process
	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "db", State: 'S', Wchan: "epoll_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected XFSAllocBtreeContention not to trigger on epoll_wait")
	}

	// Positive case: xfs btree lock in D-state
	diffContended := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 450, Comm: "xfs_writer", State: 'D', Wchan: "xfs_alloc_fixup_trees"},
		},
	}
	diag, triggered := rule.Evaluate(diffContended)
	if !triggered {
		t.Fatalf("expected XFSAllocBtreeContention to trigger on xfs_alloc_fixup_trees")
	}
	if diag.RuleID != "CONT_XFS_ALLOC_BTREE_CONTENTION" {
		t.Errorf("expected CONT_XFS_ALLOC_BTREE_CONTENTION, got %s", diag.RuleID)
	}
}

func TestRuleSchedMigrationCostOverhead(t *testing.T) {
	rule := &RuleSchedMigrationCostOverhead{}

	// Negative case: cost is 500us
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{SchedMigrationCostNS: 500000},
		},
		ContextSwitchesDelta: 10000,
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected SchedMigrationCostOverhead not to trigger on 500us cost")
	}

	// Positive case: cost is 0 with 60k ctx switches
	diffOverhead := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{SchedMigrationCostNS: 0},
		},
		ContextSwitchesDelta: 60000,
	}
	diag, triggered := rule.Evaluate(diffOverhead)
	if !triggered {
		t.Fatalf("expected SchedMigrationCostOverhead to trigger on 0 cost with 60k ctx switches")
	}
	if diag.RuleID != "CONT_SCHED_MIGRATION_COST_OVERHEAD" {
		t.Errorf("expected CONT_SCHED_MIGRATION_COST_OVERHEAD, got %s", diag.RuleID)
	}
}

func TestRuleNetTCPZeroWindowAdvert(t *testing.T) {
	rule := &RuleNetTCPZeroWindowAdvert{}

	// Negative case: 0 zero window drops
	diffClean := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPWinProbeDelta: 0, TCPZeroWindowDropDelta: 0},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected NetTCPZeroWindowAdvert not to trigger on 0 drops")
	}

	// Positive case: 30 win probes and 12 drops
	diffDrops := &collector.SnapshotDiff{
		NetStat: collector.NetStatDiff{TCPWinProbeDelta: 30, TCPZeroWindowDropDelta: 12},
	}
	diag, triggered := rule.Evaluate(diffDrops)
	if !triggered {
		t.Fatalf("expected NetTCPZeroWindowAdvert to trigger on zero window drops")
	}
	if diag.RuleID != "CONT_NET_TCP_ZERO_WINDOW_ADVERT" {
		t.Errorf("expected CONT_NET_TCP_ZERO_WINDOW_ADVERT, got %s", diag.RuleID)
	}
}

func TestRulePSISomeIOPressureSpike(t *testing.T) {
	rule := &RulePSISomeIOPressureSpike{}

	// Negative case: low PSI I/O
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				IO:        collector.PSIResource{Some: collector.PSIMetrics{Avg10: 5.0}},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected PSISomeIOPressureSpike not to trigger on 5%%")
	}

	// Positive case: 32% PSI I/O some
	diffSpike := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				IO:        collector.PSIResource{Some: collector.PSIMetrics{Avg10: 32.0, Avg60: 28.0}},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffSpike)
	if !triggered {
		t.Fatalf("expected PSISomeIOPressureSpike to trigger on 32%%")
	}
	if diag.RuleID != "CONT_PSI_SOME_IO_PRESSURE_SPIKE" {
		t.Errorf("expected CONT_PSI_SOME_IO_PRESSURE_SPIKE, got %s", diag.RuleID)
	}
}

func TestRulePSISomeCPUPressureSpike(t *testing.T) {
	rule := &RulePSISomeCPUPressureSpike{}

	// Negative case: low PSI CPU
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				CPU:       collector.PSIResource{Some: collector.PSIMetrics{Avg10: 10.0}},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected PSISomeCPUPressureSpike not to trigger on 10%%")
	}

	// Positive case: 45% PSI CPU some
	diffSpike := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				CPU:       collector.PSIResource{Some: collector.PSIMetrics{Avg10: 45.0}},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffSpike)
	if !triggered {
		t.Fatalf("expected PSISomeCPUPressureSpike to trigger on 45%%")
	}
	if diag.RuleID != "CONT_PSI_SOME_CPU_PRESSURE_SPIKE" {
		t.Errorf("expected CONT_PSI_SOME_CPU_PRESSURE_SPIKE, got %s", diag.RuleID)
	}
}

func TestRulePSIFullMemoryPressureSpike(t *testing.T) {
	rule := &RulePSIFullMemoryPressureSpike{}

	// Negative case: low PSI memory full
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				Memory:    collector.PSIResource{Full: collector.PSIMetrics{Avg10: 2.0}},
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected PSIFullMemoryPressureSpike not to trigger on 2%%")
	}

	// Positive case: 22% PSI memory full
	diffSpike := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			PSI: collector.PSIInfo{
				Available: true,
				Memory:    collector.PSIResource{Full: collector.PSIMetrics{Avg10: 22.0}},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffSpike)
	if !triggered {
		t.Fatalf("expected PSIFullMemoryPressureSpike to trigger on 22%%")
	}
	if diag.RuleID != "CONT_PSI_FULL_MEMORY_PRESSURE_SPIKE" {
		t.Errorf("expected CONT_PSI_FULL_MEMORY_PRESSURE_SPIKE, got %s", diag.RuleID)
	}
}

func TestRulePipeReadBurstBlock(t *testing.T) {
	rule := &RulePipeReadBurstBlock{}

	// Negative case: normal process
	diffClean := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 100, Comm: "worker", State: 'S', Wchan: "epoll_wait"},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected PipeReadBurstBlock not to trigger on epoll_wait")
	}

	// Positive case: pipe read block in D-state
	diffBlocked := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 500, Comm: "log_sink", State: 'D', Wchan: "pipe_read"},
		},
	}
	diag, triggered := rule.Evaluate(diffBlocked)
	if !triggered {
		t.Fatalf("expected PipeReadBurstBlock to trigger on pipe_read")
	}
	if diag.RuleID != "CONT_PIPE_READ_BURST_BLOCK" {
		t.Errorf("expected CONT_PIPE_READ_BURST_BLOCK, got %s", diag.RuleID)
	}
}

func TestRuleTCPCloseWaitLeak(t *testing.T) {
	rule := &RuleTCPCloseWaitLeak{}

	// Negative case: low CLOSE_WAIT
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			TCPSockets: collector.TCPSocketsInfo{
				Available:   true,
				Established: 200,
				CloseWait:   5,
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected RuleTCPCloseWaitLeak not to trigger on 5 close_wait sockets")
	}

	// Positive case: 250 CLOSE_WAIT out of 500 established
	diffLeaking := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			TCPSockets: collector.TCPSocketsInfo{
				Available:   true,
				Established: 500,
				CloseWait:   250,
			},
		},
		Processes: []collector.ProcessDiff{
			{PID: 1001, Comm: "leaky_server", OpenFDs: 400, MaxFDs: 1024},
		},
	}
	diag, triggered := rule.Evaluate(diffLeaking)
	if !triggered {
		t.Fatalf("expected RuleTCPCloseWaitLeak to trigger on 250 close_wait sockets")
	}
	if diag.RuleID != "CONT_TCP_CLOSE_WAIT_LEAK" {
		t.Errorf("expected CONT_TCP_CLOSE_WAIT_LEAK, got %s", diag.RuleID)
	}
	if diag.CulpritPID != 1001 {
		t.Errorf("expected culprit PID 1001, got %d", diag.CulpritPID)
	}
}

func TestRuleSustainedLoadSaturation(t *testing.T) {
	rule := &RuleSustainedLoadSaturation{}

	// Negative case: normal load
	diffClean := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{
					{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"},
				},
			},
			LoadAvg: collector.LoadAvgInfo{
				Available: true,
				Load1:     2.0,
				Load5:     1.5,
				Load15:    1.0,
			},
		},
	}
	if _, triggered := rule.Evaluate(diffClean); triggered {
		t.Fatalf("expected RuleSustainedLoadSaturation not to trigger on normal load")
	}

	// Positive case: 4 cores, 1m load = 12.5, 5m load = 9.0
	diffOverloaded := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{
					{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"},
				},
			},
			LoadAvg: collector.LoadAvgInfo{
				Available:       true,
				Load1:           12.5,
				Load5:           9.0,
				Load15:          6.5,
				RunningEntities: 16,
				TotalEntities:   400,
			},
			PSI: collector.PSIInfo{
				Available: true,
				CPU: collector.PSIResource{
					Some: collector.PSIMetrics{Avg10: 25.0},
				},
			},
		},
	}
	diag, triggered := rule.Evaluate(diffOverloaded)
	if !triggered {
		t.Fatalf("expected RuleSustainedLoadSaturation to trigger on load 12.5")
	}
	if diag.RuleID != "CONT_SUSTAINED_LOAD_SATURATION" {
		t.Errorf("expected CONT_SUSTAINED_LOAD_SATURATION, got %s", diag.RuleID)
	}
	if diag.Confidence != 0.95 {
		t.Errorf("expected 0.95 confidence with PSI, got %f", diag.Confidence)
	}
}

func TestRuleRunawayCPUProcess(t *testing.T) {
	rule := &RuleRunawayCPUProcess{}

	// Positive test: single process consuming 98% CPU
	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 1234, Comm: "python3", CPUPercent: 98.5, State: 'R', NumThreads: 1, CpusAllowed: 4, Policy: 0},
			{PID: 1, Comm: "systemd", CPUPercent: 0.1, State: 'S', NumThreads: 1, CpusAllowed: 4, Policy: 0},
		},
	}
	diag, ok := rule.Evaluate(diffPos)
	if !ok || diag == nil {
		t.Fatalf("expected RuleRunawayCPUProcess to trigger on 98.5%% CPU process")
	}
	if diag.CulpritPID != 1234 {
		t.Errorf("expected CulpritPID 1234, got %d", diag.CulpritPID)
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", diag.Severity)
	}

	// Negative test: all processes below 80% CPU
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 1234, Comm: "python3", CPUPercent: 45.0, State: 'R', NumThreads: 1, CpusAllowed: 4, Policy: 0},
			{PID: 1, Comm: "systemd", CPUPercent: 0.1, State: 'S', NumThreads: 1, CpusAllowed: 4, Policy: 0},
		},
	}
	diagNeg, okNeg := rule.Evaluate(diffNeg)
	if okNeg || diagNeg != nil {
		t.Fatalf("expected RuleRunawayCPUProcess not to trigger on 45%% CPU")
	}
}

func TestRuleProcessSwapPinned(t *testing.T) {
	rule := &RuleProcessSwapPinned{}

	// Positive test: swap > 500MB and MemAvailable < 20%
	diffMemPressure := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:  501,
				Comm: "python_hog",
				SmapsRollup: collector.SmapsRollupInfo{
					Available: true,
					Swap:      600000, // 600,000 KB > 512,000 KB
				},
			},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     10000000,
				MemAvailable: 1500000, // 15% < 20%
			},
		},
	}
	diag, ok := rule.Evaluate(diffMemPressure)
	if !ok || diag == nil {
		t.Fatalf("expected RuleProcessSwapPinned to trigger on 600MB swap + 15%% MemAvailable")
	}
	if diag.CulpritPID != 501 || diag.CulpritName != "python_hog" {
		t.Errorf("expected culprit PID 501 python_hog, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %f", diag.Confidence)
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", diag.Severity)
	}

	// Positive test 2: swap > 500MB and PswpinDelta > 0
	diffSwapIn := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:  502,
				Comm: "java_app",
				SmapsRollup: collector.SmapsRollupInfo{
					Available: true,
					Swap:      550000,
				},
			},
		},
		VMStat: collector.VMStatDiff{
			PswpinDelta: 120,
		},
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     10000000,
				MemAvailable: 5000000, // 50%
			},
		},
	}
	if _, ok := rule.Evaluate(diffSwapIn); !ok {
		t.Fatalf("expected RuleProcessSwapPinned to trigger when PswpinDelta > 0")
	}

	// Negative test 1: swap <= 500MB
	diffLowSwap := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:  503,
				Comm: "small_app",
				SmapsRollup: collector.SmapsRollupInfo{
					Available: true,
					Swap:      100000, // 100MB
				},
			},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     10000000,
				MemAvailable: 1000000,
			},
		},
	}
	if _, ok := rule.Evaluate(diffLowSwap); ok {
		t.Fatalf("expected RuleProcessSwapPinned not to trigger on 100MB swap")
	}

	// Negative test 2: swap > 500MB but no memory pressure and pswpin == 0
	diffNoPressure := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:  504,
				Comm: "idle_daemon",
				SmapsRollup: collector.SmapsRollupInfo{
					Available: true,
					Swap:      700000,
				},
			},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			Memory: collector.MemInfo{
				MemTotal:     10000000,
				MemAvailable: 6000000, // 60% available
			},
		},
	}
	if _, ok := rule.Evaluate(diffNoPressure); ok {
		t.Fatalf("expected RuleProcessSwapPinned not to trigger when memory is healthy and pswpin is 0")
	}
}

func TestRuleDentryCacheExplosion(t *testing.T) {
	rule := &RuleDentryCacheExplosion{}

	// Positive test: DentryCacheActive > 2,000,000 and MemAvailable < 20%
	diffPos := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Slab: collector.SlabInfo{
					Available:         true,
					DentryCacheActive: 2500000,
					DentryCacheTotal:  2600000,
				},
			},
			Memory: collector.MemInfo{
				MemTotal:     16000000,
				MemAvailable: 2000000, // 12.5% < 20%
			},
		},
	}
	diag, ok := rule.Evaluate(diffPos)
	if !ok || diag == nil {
		t.Fatalf("expected RuleDentryCacheExplosion to trigger")
	}
	if diag.Confidence != 0.75 {
		t.Errorf("expected confidence 0.75, got %f", diag.Confidence)
	}
	if diag.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", diag.Severity)
	}

	// Negative test 1: DentryCacheActive <= 2,000,000
	diffLowDentry := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Slab: collector.SlabInfo{
					Available:         true,
					DentryCacheActive: 1500000,
					DentryCacheTotal:  1600000,
				},
			},
			Memory: collector.MemInfo{
				MemTotal:     16000000,
				MemAvailable: 2000000,
			},
		},
	}
	if _, ok := rule.Evaluate(diffLowDentry); ok {
		t.Fatalf("expected RuleDentryCacheExplosion not to trigger on 1.5M dentries")
	}

	// Negative test 2: DentryCacheActive > 2M but MemAvailable >= 20%
	diffPlentyMem := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Slab: collector.SlabInfo{
					Available:         true,
					DentryCacheActive: 3000000,
					DentryCacheTotal:  3100000,
				},
			},
			Memory: collector.MemInfo{
				MemTotal:     16000000,
				MemAvailable: 8000000, // 50%
			},
		},
	}
	if _, ok := rule.Evaluate(diffPlentyMem); ok {
		t.Fatalf("expected RuleDentryCacheExplosion not to trigger with 50%% MemAvailable")
	}

	// Negative test 3: Slab unavailable
	diffNoSlab := &collector.SnapshotDiff{
		LatestSnapshot: &collector.SystemSnapshot{
			SystemConfig: collector.SystemConfigInfo{
				Slab: collector.SlabInfo{Available: false},
			},
			Memory: collector.MemInfo{
				MemTotal:     16000000,
				MemAvailable: 2000000,
			},
		},
	}
	if _, ok := rule.Evaluate(diffNoSlab); ok {
		t.Fatalf("expected RuleDentryCacheExplosion not to trigger when slab is unavailable")
	}
}

func TestRuleSecurityFanotifyStall(t *testing.T) {
	t.Parallel()
	rule := &RuleSecurityFanotifyStall{}

	if rule.ID() != "CONT_SECURITY_FANOTIFY_STALL" || rule.Tier() != 2 || !rule.IsPIDDependent() {
		t.Fatalf("unexpected rule metadata: ID=%s, Tier=%d, IsPIDDependent=%v", rule.ID(), rule.Tier(), rule.IsPIDDependent())
	}

	diffPositive := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:        1001,
				Comm:       "data_app",
				State:      'S',
				Wchan:      "fanotify_get_response",
				CPUPercent: 0.1,
				NumThreads: 4,
			},
		},
	}

	diag, ok := rule.Evaluate(diffPositive)
	if !ok || diag == nil {
		t.Fatalf("expected RuleSecurityFanotifyStall to trigger on fanotify_get_response wchan")
	}
	if diag.CulpritPID != 1001 || diag.CulpritName != "data_app" {
		t.Errorf("expected Culprit 1001 data_app, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.Confidence != 0.95 || diag.Severity != SeverityHigh {
		t.Errorf("unexpected confidence/severity: %f / %s", diag.Confidence, diag.Severity)
	}

	diffNormal := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:        1002,
				Comm:       "worker",
				State:      'S',
				Wchan:      "ep_poll",
				CPUPercent: 0.1,
			},
		},
	}
	if _, ok := rule.Evaluate(diffNormal); ok {
		t.Fatalf("expected RuleSecurityFanotifyStall not to trigger on normal ep_poll wchan")
	}
}

func TestRuleFileLockGraphBlocked(t *testing.T) {
	t.Parallel()
	rule := &RuleFileLockGraphBlocked{}

	if rule.ID() != "CONT_FILE_LOCK_GRAPH_BLOCKED" || rule.Tier() != 2 || !rule.IsPIDDependent() {
		t.Fatalf("unexpected rule metadata: ID=%s, Tier=%d, IsPIDDependent=%v", rule.ID(), rule.Tier(), rule.IsPIDDependent())
	}

	diffPositive := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 2001, Comm: "db_writer"},
			{PID: 2002, Comm: "db_reader"},
		},
		FileLocks: collector.FileLocksInfo{
			Available:  true,
			TotalLocks: 10,
			BlockedLocks: []collector.BlockedFileLock{
				{
					BlockedPID:  2002,
					HolderPID:   2001,
					LockType:    "POSIX",
					DeviceInode: "08:01:123456",
				},
			},
		},
	}

	diag, ok := rule.Evaluate(diffPositive)
	if !ok || diag == nil {
		t.Fatalf("expected RuleFileLockGraphBlocked to trigger on blocked file lock")
	}
	if diag.CulpritPID != 2001 || diag.CulpritName != "db_writer" {
		t.Errorf("expected lock holder PID 2001 db_writer as culprit, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.Confidence != 0.95 || diag.Severity != SeverityHigh {
		t.Errorf("unexpected confidence/severity: %f / %s", diag.Confidence, diag.Severity)
	}

	diffEmpty := &collector.SnapshotDiff{
		FileLocks: collector.FileLocksInfo{
			Available:    true,
			BlockedLocks: []collector.BlockedFileLock{},
		},
	}
	if _, ok := rule.Evaluate(diffEmpty); ok {
		t.Fatalf("expected RuleFileLockGraphBlocked not to trigger when no locks are blocked")
	}
}

func TestRuleIPCUnixPeerCongestion(t *testing.T) {
	t.Parallel()
	rule := &RuleIPCUnixPeerCongestion{}

	if rule.ID() != "CONT_IPC_UNIX_PEER_CONGESTION" || rule.Tier() != 2 || !rule.IsPIDDependent() {
		t.Fatalf("unexpected rule metadata: ID=%s, Tier=%d, IsPIDDependent=%v", rule.ID(), rule.Tier(), rule.IsPIDDependent())
	}

	diffPositive := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:        3001,
				Comm:       "syslog_sender",
				State:      'S',
				Wchan:      "unix_stream_sendmsg",
				CPUPercent: 0.0,
				NumThreads: 2,
			},
		},
	}

	diag, ok := rule.Evaluate(diffPositive)
	if !ok || diag == nil {
		t.Fatalf("expected RuleIPCUnixPeerCongestion to trigger on unix_stream_sendmsg wchan")
	}
	if diag.CulpritPID != 3001 || diag.CulpritName != "syslog_sender" {
		t.Errorf("expected Culprit 3001 syslog_sender, got %d %s", diag.CulpritPID, diag.CulpritName)
	}
	if diag.Confidence != 0.90 || diag.Severity != SeverityHigh {
		t.Errorf("unexpected confidence/severity: %f / %s", diag.Confidence, diag.Severity)
	}

	diffNormal := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:        3002,
				Comm:       "idle_proc",
				State:      'S',
				Wchan:      "poll_schedule_timeout",
				CPUPercent: 0.0,
			},
		},
	}
	if _, ok := rule.Evaluate(diffNormal); ok {
		t.Fatalf("expected RuleIPCUnixPeerCongestion not to trigger on poll_schedule_timeout wchan")
	}
}

func TestRuleMemDirectReclaimStall(t *testing.T) {
	t.Parallel()
	rule := &RuleMemDirectReclaimStall{}

	if rule.ID() != "CONT_MEM_DIRECT_RECLAIM_STALL" || rule.Tier() != 2 || !rule.IsPIDDependent() {
		t.Fatalf("unexpected metadata: %s %d %v", rule.ID(), rule.Tier(), rule.IsPIDDependent())
	}

	diffPos := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			AllocStallDirectDelta: 150,
			PgScanDirectDelta:     2500,
		},
		Processes: []collector.ProcessDiff{
			{
				PID:      4001,
				Comm:     "allocator",
				Wchan:    "alloc_pages_slowpath",
				RSSBytes: 256 * 1024 * 1024,
			},
		},
	}

	diag, ok := rule.Evaluate(diffPos)
	if !ok || diag == nil {
		t.Fatalf("expected RuleMemDirectReclaimStall to trigger on slowpath culprit")
	}
	if diag.CulpritPID != 4001 || diag.Confidence != 0.95 {
		t.Errorf("unexpected culprit or confidence: %d / %f", diag.CulpritPID, diag.Confidence)
	}

	// Negative: zero allocstall
	diffNeg := &collector.SnapshotDiff{
		VMStat: collector.VMStatDiff{
			AllocStallDirectDelta: 0,
			PgScanDirectDelta:     5000,
		},
	}
	if _, ok := rule.Evaluate(diffNeg); ok {
		t.Fatalf("expected RuleMemDirectReclaimStall not to trigger on zero allocstall")
	}
}

func TestRuleRemoteStorageRPCHang(t *testing.T) {
	t.Parallel()
	rule := &RuleRemoteStorageRPCHang{}

	if rule.ID() != "CONT_REMOTE_STORAGE_RPC_HANG" || rule.Tier() != 2 || !rule.IsPIDDependent() {
		t.Fatalf("unexpected metadata: %s %d %v", rule.ID(), rule.Tier(), rule.IsPIDDependent())
	}

	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:          5001,
				Comm:         "nfs_worker",
				State:        'D',
				Wchan:        "nfs_wait_bit_killable",
				CPUPercent:   0.0,
				CPUTimeDelta: 0,
			},
		},
	}

	diag, ok := rule.Evaluate(diffPos)
	if !ok || diag == nil {
		t.Fatalf("expected RuleRemoteStorageRPCHang to trigger on nfs_wait_bit_killable")
	}
	if diag.CulpritPID != 5001 || diag.Confidence != 0.98 {
		t.Errorf("unexpected culprit or confidence: %d / %f", diag.CulpritPID, diag.Confidence)
	}

	// Negative: local disk D state
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:          5002,
				Comm:         "disk_worker",
				State:        'D',
				Wchan:        "io_schedule",
				CPUPercent:   0.0,
				CPUTimeDelta: 0,
			},
		},
	}
	if _, ok := rule.Evaluate(diffNeg); ok {
		t.Fatalf("expected RuleRemoteStorageRPCHang not to trigger on local io_schedule")
	}
}

func TestRuleCPUKernelSpinlockBurn(t *testing.T) {
	t.Parallel()
	rule := &RuleCPUKernelSpinlockBurn{}

	if rule.ID() != "CONT_CPU_KERNEL_SPINLOCK_BURN" || rule.Tier() != 2 || !rule.IsPIDDependent() {
		t.Fatalf("unexpected metadata: %s %d %v", rule.ID(), rule.Tier(), rule.IsPIDDependent())
	}

	diffPos := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:                           6001,
				Comm:                          "spinlock_app",
				CPUPercent:                    96.0,
				CPUTimeDelta:                  100,
				STimeDelta:                    88,
				UTimeDelta:                    12,
				NonvoluntaryCtxtSwitchesDelta: 6500,
			},
		},
	}

	diag, ok := rule.Evaluate(diffPos)
	if !ok || diag == nil {
		t.Fatalf("expected RuleCPUKernelSpinlockBurn to trigger on 88%% system time")
	}
	if diag.CulpritPID != 6001 || diag.Confidence != 0.94 {
		t.Errorf("unexpected culprit or confidence: %d / %f", diag.CulpritPID, diag.Confidence)
	}

	// Negative: user-space compute
	diffNeg := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:          6002,
				Comm:         "compute_app",
				CPUPercent:   96.0,
				CPUTimeDelta: 100,
				STimeDelta:   10,
				UTimeDelta:   90,
			},
		},
	}
	if _, ok := rule.Evaluate(diffNeg); ok {
		t.Fatalf("expected RuleCPUKernelSpinlockBurn not to trigger on user compute")
	}
}

func TestRuleCgroupCFSBurstThrottle(t *testing.T) {
	t.Parallel()
	rule := &RuleCgroupCFSBurstThrottle{}

	if rule.ID() != "CONT_CGROUP_CFS_BURST_THROTTLE" || rule.Tier() != 2 || !rule.IsPIDDependent() {
		t.Fatalf("unexpected metadata: %s %d %v", rule.ID(), rule.Tier(), rule.IsPIDDependent())
	}

	diffPos := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{
				Path:               "/docker/web",
				NrPeriodsDelta:     100,
				NrThrottledDelta:   35,
				ThrottledUsecDelta: 250000,
			},
		},
		Processes: []collector.ProcessDiff{
			{
				PID:        7001,
				Comm:       "web_srv",
				CgroupPath: "/docker/web",
				CPUPercent: 18.0,
			},
		},
	}

	diag, ok := rule.Evaluate(diffPos)
	if !ok || diag == nil {
		t.Fatalf("expected RuleCgroupCFSBurstThrottle to trigger on 35%% throttled periods")
	}
	if diag.CulpritPID != 7001 || diag.Confidence != 0.96 {
		t.Errorf("unexpected culprit or confidence: %d / %f", diag.CulpritPID, diag.Confidence)
	}

	// Negative: low period count jitter (< 10 periods)
	diffNeg := &collector.SnapshotDiff{
		Cgroups: []collector.CgroupDiff{
			{
				Path:               "/docker/web",
				NrPeriodsDelta:     5,
				NrThrottledDelta:   2,
				ThrottledUsecDelta: 250000,
			},
		},
	}
	if _, ok := rule.Evaluate(diffNeg); ok {
		t.Fatalf("expected RuleCgroupCFSBurstThrottle not to trigger on < 10 periods")
	}
}
