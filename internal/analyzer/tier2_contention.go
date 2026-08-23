// Package analyzer — tier2_contention.go contains Tier 2 (P1 Priority)
// diagnostic rules for contention and queuing bottlenecks:
//
//   - CONT_DSTATE_PILEUP:             ≥ 3 PIDs in uninterruptible sleep (D state)
//   - CONT_SWAP_THRASHING:            Direct reclaim + allocation stalls + PSI > 30%
//   - CONT_CGROUP_THROTTLED:          Cgroup CPU quota exhausted (throttled_usec delta)
//   - CONT_FD_EXHAUSTION:             FD count > 90% of soft limit
//   - CONT_SOFTIRQ_UNBALANCE:         One core at 80%+ softirq, system idle
//   - CONT_TCP_LISTEN_DROPS:          ListenDrops delta > 0
//   - CONT_PID_EXHAUSTION:            Scanned PIDs ≥ 95% of pid_max
//   - CONT_TIMEWAIT_PORT_EXHAUSTION:  TCP TIME_WAIT ≥ 85% of ephemeral ports
package analyzer

import (
	"fmt"
	"strings"
	"why-slow/internal/collector"
)

// GetTier2Rules returns all registered Tier 2 diagnostic rules.
func GetTier2Rules() []Rule {
	return []Rule{
		&RuleDStatePileup{},
		&RuleSwapThrashing{},
		&RuleCgroupThrottled{},
		&RuleFDExhaustion{},
		&RuleSoftIRQUnbalance{},
		&RuleTCPListenDrops{},
		&RulePIDExhaustion{},
		&RuleTimeWaitPortExhaustion{},
		&RuleVCPUStealTime{},
		&RuleBalloonMemoryOvercommit{},
		&RuleConntrackExhaustion{},
		&RuleARPNeighborTableOverflow{},
		&RuleTCPSYNQueueOverflow{},
		&RuleBlockHardwareTagStarvation{},
		&RuleSchedRunqueueStarvation{},
		&RuleCgroupMemoryHighThrottle{},
		&RuleIOSchedulerQueueLatency{},
		&RulePageTableLockContention{},
		&RuleOrphanSocketLeak{},
	}
}

// RuleDStatePileup detects tasks stuck in uninterruptible sleep waiting on block/NFS I/O.
type RuleDStatePileup struct{}

func (r *RuleDStatePileup) ID() string             { return "CONT_DSTATE_PILEUP" }
func (r *RuleDStatePileup) Tier() int              { return 2 }
func (r *RuleDStatePileup) IsPIDDependent() bool   { return true }

func (r *RuleDStatePileup) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var dProcs []collector.ProcessDiff
	for i := range diff.Processes {
		if diff.Processes[i].State == 'D' {
			dProcs = append(dProcs, diff.Processes[i])
		}
	}

	if len(dProcs) < 3 {
		return nil, false
	}

	evidence := make([]string, 0, len(dProcs)+1)
	evidence = append(evidence, fmt.Sprintf("%d active processes stuck in uninterruptible sleep (State D)", len(dProcs)))

	var culprit *collector.ProcessDiff
	for i := range dProcs {
		p := &dProcs[i]
		wchanStr := p.Wchan
		if wchanStr == "" {
			wchanStr = "unknown_wait"
		}
		evidence = append(evidence, fmt.Sprintf("PID %d [%s]: wchan=%s, read=%.1f MB, write=%.1f MB",
			p.PID, p.Comm, wchanStr, float64(p.ReadBytesDelta)/(1024*1024), float64(p.WriteBytesDelta)/(1024*1024)))

		if culprit == nil || p.WriteBytesDelta+p.ReadBytesDelta > culprit.WriteBytesDelta+culprit.ReadBytesDelta {
			culprit = p
		}
	}

	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.88,
		Title:       "Uninterruptible I/O Lock (D-State Pileup)",
		Explanation: "Multiple processes are blocked in kernel uninterruptible sleep waiting on disk I/O, NFS, or page writeback.",
		Evidence:    evidence,
		Remediation: "Investigate slow storage devices, unresponsive NFS mounts, or lower process I/O class using ionice.",
	}

	if culprit != nil {
		diag.CulpritPID = culprit.PID
		diag.CulpritName = culprit.Comm
		diag.CulpritDetails = fmt.Sprintf("Stalled in kernel function '%s' with %.1f MB I/O activity", culprit.Wchan, float64(culprit.WriteBytesDelta+culprit.ReadBytesDelta)/(1024*1024))
		diag.Remediation = fmt.Sprintf("Lower I/O priority class: ionice -c3 -p %d", culprit.PID)
	}

	return diag, true
}

// RuleSwapThrashing detects kernel direct page scanning and allocation stalls.
type RuleSwapThrashing struct{}

func (r *RuleSwapThrashing) ID() string             { return "CONT_SWAP_THRASHING" }
func (r *RuleSwapThrashing) Tier() int              { return 2 }
func (r *RuleSwapThrashing) IsPIDDependent() bool   { return false }

func (r *RuleSwapThrashing) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	vm := &diff.VMStat
	hasDirectReclaim := vm.PgScanDirectDelta > 0
	hasAllocStall := vm.AllocStallDirectDelta > 0

	if !hasDirectReclaim || !hasAllocStall {
		return nil, false
	}

	// Corroborate with PSI memory pressure if available
	psiMemStall := 0.0
	if diff.LatestSnapshot != nil && diff.LatestSnapshot.PSI.Available {
		psiMemStall = diff.LatestSnapshot.PSI.Memory.Some.Avg10
	}

	evidence := []string{
		fmt.Sprintf("Direct Page Scans: %d pages scanned synchronously during sampling window", vm.PgScanDirectDelta),
		fmt.Sprintf("Direct Allocation Stalls: %d processes stalled waiting for memory reclaim", vm.AllocStallDirectDelta),
	}
	if psiMemStall > 0 {
		evidence = append(evidence, fmt.Sprintf("PSI Memory Stall: %.1f%% of tasks delayed on memory", psiMemStall))
	}

	confidence := 0.85
	if psiMemStall >= 30.0 {
		confidence = 0.95
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  confidence,
		Title:       "Memory Thrashing & Direct Reclamation Stall",
		Explanation: "The kernel is synchronously scanning pages and stalling processes to reclaim memory, degrading response times.",
		Evidence:    evidence,
		Remediation: "Reduce memory pressure, lower sysctl vm.swappiness, or add swap on fast storage.",
	}, true
}

// RuleCgroupThrottled detects CPU quota wall throttling inside containers or systemd slices.
type RuleCgroupThrottled struct{}

func (r *RuleCgroupThrottled) ID() string             { return "CONT_CGROUP_THROTTLED" }
func (r *RuleCgroupThrottled) Tier() int              { return 2 }
func (r *RuleCgroupThrottled) IsPIDDependent() bool   { return true }

func (r *RuleCgroupThrottled) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var topThrottled *collector.CgroupDiff
	for i := range diff.Cgroups {
		cg := &diff.Cgroups[i]
		// Throttled for > 100ms (100,000 usec) within the sampling window
		if cg.ThrottledUsecDelta >= 100000 && cg.NrThrottledDelta > 0 {
			if topThrottled == nil || cg.ThrottledUsecDelta > topThrottled.ThrottledUsecDelta {
				topThrottled = cg
			}
		}
	}

	if topThrottled == nil {
		return nil, false
	}

	throttledMS := float64(topThrottled.ThrottledUsecDelta) / 1000.0
	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       fmt.Sprintf("Cgroup CPU Quota Throttled (%s)", topThrottled.Path),
		Explanation: fmt.Sprintf("Tasks inside cgroup '%s' were throttled for %.1f ms because they exhausted their allocated CPU quota.", topThrottled.Path, throttledMS),
		Evidence: []string{
			fmt.Sprintf("Cgroup Path: %s", topThrottled.Path),
			fmt.Sprintf("Throttled Duration Delta: %.1f ms across %d periods", throttledMS, topThrottled.NrThrottledDelta),
		},
		Remediation: fmt.Sprintf("Increase CPU quota in container or service slice definition ('cpu.max' for %s).", topThrottled.Path),
	}

	// Try to attribute top PID in this cgroup
	var maxCPUDelta uint64
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.CgroupPath == topThrottled.Path && p.CPUTimeDelta > 0 {
			if diag.CulpritPID == 0 || p.CPUTimeDelta > maxCPUDelta {
				maxCPUDelta = p.CPUTimeDelta
				diag.CulpritPID = p.PID
				diag.CulpritName = p.Comm
				diag.CulpritDetails = fmt.Sprintf("Active process in throttled cgroup (CPU delta: %.1f%%)", p.CPUPercent)
			}
		}
	}

	return diag, true
}

// RuleFDExhaustion detects processes approaching their file descriptor limits.
type RuleFDExhaustion struct{}

func (r *RuleFDExhaustion) ID() string             { return "CONT_FD_EXHAUSTION" }
func (r *RuleFDExhaustion) Tier() int              { return 2 }
func (r *RuleFDExhaustion) IsPIDDependent() bool   { return true }

func (r *RuleFDExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var topExhausted *collector.ProcessDiff
	for i := range diff.Processes {
		p := &diff.Processes[i]
		if p.MaxFDs > 0 && p.OpenFDs > 0 {
			if p.FDRatio >= 0.90 {
				if topExhausted == nil || p.FDRatio > topExhausted.FDRatio {
					topExhausted = p
				}
			}
		}
	}

	if topExhausted == nil {
		return nil, false
	}

	return &Diagnosis{
		RuleID:         r.ID(),
		Tier:           2,
		Severity:       SeverityHigh,
		Confidence:     0.95,
		Title:          fmt.Sprintf("File Descriptor Exhaustion (PID %d [%s])", topExhausted.PID, topExhausted.Comm),
		Explanation:    fmt.Sprintf("Process '%s' (PID %d) is using %d of %d allowed file descriptors (%.1f%% of limit).", topExhausted.Comm, topExhausted.PID, topExhausted.OpenFDs, topExhausted.MaxFDs, topExhausted.FDRatio*100.0),
		Evidence: []string{
			fmt.Sprintf("Open File Descriptors: %d", topExhausted.OpenFDs),
			fmt.Sprintf("Process Soft Limit: %d (%.1f%% utilized)", topExhausted.MaxFDs, topExhausted.FDRatio*100.0),
		},
		CulpritPID:     topExhausted.PID,
		CulpritName:    topExhausted.Comm,
		CulpritDetails: fmt.Sprintf("Approaching ulimit -n limit with %d open handles", topExhausted.OpenFDs),
		Remediation:    fmt.Sprintf("Increase file descriptor soft limit: prlimit --nofile=%d:%d -p %d", topExhausted.MaxFDs*2, topExhausted.MaxFDs*2, topExhausted.PID),
	}, true
}

// RuleSoftIRQUnbalance detects a single core saturated by network softirqs while other cores are idle.
type RuleSoftIRQUnbalance struct{}

func (r *RuleSoftIRQUnbalance) ID() string             { return "CONT_SOFTIRQ_UNBALANCE" }
func (r *RuleSoftIRQUnbalance) Tier() int              { return 2 }
func (r *RuleSoftIRQUnbalance) IsPIDDependent() bool   { return false }

func (r *RuleSoftIRQUnbalance) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.PerCoreCPUUtil) < 2 {
		return nil, false
	}

	// Overall system idle should be relatively high (> 50%)
	if diff.TotalCPUUtil.IdlePercent < 50.0 {
		return nil, false
	}

	bottleneckCore := -1
	var maxSoftIRQ float64

	for coreID, util := range diff.PerCoreCPUUtil {
		if util.SoftIRQPercent >= 80.0 {
			if util.SoftIRQPercent > maxSoftIRQ {
				maxSoftIRQ = util.SoftIRQPercent
				bottleneckCore = coreID
			}
		}
	}

	if bottleneckCore == -1 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.88,
		Title:       fmt.Sprintf("Single-Core SoftIRQ Network Storm (Core %d)", bottleneckCore),
		Explanation: fmt.Sprintf("CPU core %d is pinned at %.1f%% softirq processing while total system is %.1f%% idle, indicating network interrupt imbalance.", bottleneckCore, maxSoftIRQ, diff.TotalCPUUtil.IdlePercent),
		Evidence: []string{
			fmt.Sprintf("CPU Core %d SoftIRQ Utilization: %.1f%%", bottleneckCore, maxSoftIRQ),
			fmt.Sprintf("Overall System Idle: %.1f%%", diff.TotalCPUUtil.IdlePercent),
		},
		Remediation: "Enable network Receive Packet Steering (RPS/RFS) or configure irqbalance.",
	}, true
}

// RuleTCPListenDrops detects dropped or overflowing TCP incoming connection queues.
type RuleTCPListenDrops struct{}

func (r *RuleTCPListenDrops) ID() string             { return "CONT_TCP_LISTEN_DROPS" }
func (r *RuleTCPListenDrops) Tier() int              { return 2 }
func (r *RuleTCPListenDrops) IsPIDDependent() bool   { return false }

func (r *RuleTCPListenDrops) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	netDiff := &diff.NetStat
	if netDiff.ListenDropsDelta == 0 && netDiff.ListenOverflowsDelta == 0 {
		return nil, false
	}

	evidence := make([]string, 0, 2)
	if netDiff.ListenDropsDelta > 0 {
		evidence = append(evidence, fmt.Sprintf("ListenDrops: %d incoming connection attempts dropped in sampling window", netDiff.ListenDropsDelta))
	}
	if netDiff.ListenOverflowsDelta > 0 {
		evidence = append(evidence, fmt.Sprintf("ListenOverflows: %d sockets overflowed somaxconn listen queue", netDiff.ListenOverflowsDelta))
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       "TCP Socket Listen Backlog Drops",
		Explanation: "Incoming TCP connections were silently dropped because server application listen queues (somaxconn) were saturated.",
		Evidence:    evidence,
		Remediation: "Increase system socket backlog: sysctl -w net.core.somaxconn=4096 and raise application backlog setting.",
	}, true
}

// RulePIDExhaustion detects PID ceiling saturation risking fork/thread creation failures.
type RulePIDExhaustion struct{}

func (r *RulePIDExhaustion) ID() string             { return "CONT_PID_EXHAUSTION" }
func (r *RulePIDExhaustion) Tier() int              { return 2 }
func (r *RulePIDExhaustion) IsPIDDependent() bool   { return true }

func (r *RulePIDExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	pidMax := diff.LatestSnapshot.SystemConfig.PIDMax
	if pidMax == 0 {
		return nil, false
	}

	totalProcs := uint64(len(diff.Processes))
	if totalProcs == 0 {
		totalProcs = uint64(len(diff.LatestSnapshot.Processes))
	}

	ratio := float64(totalProcs) / float64(pidMax)
	if ratio < 0.95 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.92,
		Title:       "Process Table PID Allocation Exhaustion",
		Explanation: "Active process count is approaching the kernel PID limit (pid_max), risking fork() and pthread_create() EAGAIN failures.",
		Evidence: []string{
			fmt.Sprintf("Active Process Count: %d / %d pid_max ceiling (%.1f%% allocated)", totalProcs, pidMax, ratio*100.0),
		},
		Remediation: "Increase system PID ceiling: sysctl -w kernel.pid_max=4194304 or terminate redundant worker processes.",
	}, true
}

// RuleTimeWaitPortExhaustion detects outbound connect failures due to TIME_WAIT ephemeral port flood.
type RuleTimeWaitPortExhaustion struct{}

func (r *RuleTimeWaitPortExhaustion) ID() string             { return "CONT_TIMEWAIT_PORT_EXHAUSTION" }
func (r *RuleTimeWaitPortExhaustion) Tier() int              { return 2 }
func (r *RuleTimeWaitPortExhaustion) IsPIDDependent() bool   { return false }

func (r *RuleTimeWaitPortExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	sockStat := &diff.LatestSnapshot.SystemConfig.SockStat
	portRange := &diff.LatestSnapshot.SystemConfig.PortRange

	if portRange.High <= portRange.Low {
		return nil, false
	}

	capacity := portRange.High - portRange.Low + 1
	if capacity == 0 {
		return nil, false
	}

	ratio := float64(sockStat.TCPTimeWait) / float64(capacity)
	if ratio < 0.85 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.90,
		Title:       "Ephemeral Port Exhaustion (TIME_WAIT Flood)",
		Explanation: "Excessive TCP connections in TIME_WAIT state are consuming over 85% of available outbound ephemeral ports, causing connect() EADDRNOTAVAIL errors.",
		Evidence: []string{
			fmt.Sprintf("TCP TIME_WAIT Sockets: %d", sockStat.TCPTimeWait),
			fmt.Sprintf("Ephemeral Port Range: %d-%d (Capacity: %d, %.1f%% consumed)",
				portRange.Low, portRange.High, capacity, ratio*100.0),
		},
		Remediation: "Enable TCP TIME_WAIT socket reuse: sysctl -w net.ipv4.tcp_tw_reuse=1 and enable HTTP Keep-Alive in clients.",
	}, true
}

// RuleVCPUStealTime detects hypervisor CPU oversubscription and noisy neighbor cycle theft.
type RuleVCPUStealTime struct{}

func (r *RuleVCPUStealTime) ID() string             { return "CONT_VCPU_STEAL_TIME" }
func (r *RuleVCPUStealTime) Tier() int              { return 2 }
func (r *RuleVCPUStealTime) IsPIDDependent() bool   { return false }

func (r *RuleVCPUStealTime) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	totalSteal := diff.TotalCPUUtil.StealPercent
	var maxCoreSteal float64
	var maxCoreID int
	for i, core := range diff.PerCoreCPUUtil {
		if core.StealPercent > maxCoreSteal {
			maxCoreSteal = core.StealPercent
			maxCoreID = i
		}
	}

	if totalSteal < 15.0 && maxCoreSteal < 30.0 {
		return nil, false
	}

	evidence := []string{
		fmt.Sprintf("Hypervisor Steal Time: %.1f%% of overall vCPU cycles stolen by host", totalSteal),
		fmt.Sprintf("Guest CPU Busy: %.1f%%, Idle: %.1f%%", diff.TotalCPUUtil.BusyPercent, diff.TotalCPUUtil.IdlePercent),
	}
	if maxCoreSteal >= 30.0 {
		evidence = append(evidence, fmt.Sprintf("Most Impacted Core: vCPU %d (%.1f%% steal time)", maxCoreID, maxCoreSteal))
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.95,
		Title:       "Hypervisor vCPU Steal Time Saturation (Noisy Neighbor)",
		Explanation: "The virtual machine is starving for CPU execution cycles because the underlying hypervisor host is overcommitted and stealing vCPU slices for other noisy tenants.",
		Evidence:    evidence,
		Remediation: "Migrate VM to dedicated hypervisor host, configure vCPU pinning/reservations, or upgrade to dedicated cloud compute instances.",
	}, true
}

// RuleBalloonMemoryOvercommit detects hypervisor memory reclamation and balloon driver inflation.
type RuleBalloonMemoryOvercommit struct{}

func (r *RuleBalloonMemoryOvercommit) ID() string             { return "CONT_BALLOON_OVERCOMMIT" }
func (r *RuleBalloonMemoryOvercommit) Tier() int              { return 2 }
func (r *RuleBalloonMemoryOvercommit) IsPIDDependent() bool   { return false }

func (r *RuleBalloonMemoryOvercommit) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	mem := &diff.LatestSnapshot.Memory
	virt := &diff.LatestSnapshot.SystemConfig.Virt
	if mem.MemTotal == 0 {
		return nil, false
	}

	totalRAMBytes := mem.MemTotal * 1024
	availRAMBytes := mem.MemAvailable * 1024

	// If virtio balloon is holding memory or guest is low on available memory under hypervisor pressure
	balloonBytes := virt.BalloonBytes
	balloonRatio := float64(balloonBytes) / float64(totalRAMBytes)
	availRatio := float64(availRAMBytes) / float64(totalRAMBytes)

	// Trigger if balloon driver has inflated >= 20% of RAM, or balloon is active while available memory is low
	if balloonRatio < 0.20 && (balloonBytes == 0 || availRatio >= 0.15) {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.90,
		Title:       "Hypervisor Memory Ballooning Overcommit Pressure",
		Explanation: "The underlying hypervisor is actively reclaiming RAM from this virtual machine via memory ballooning, inducing memory pressure and swapping despite apparent free capacity.",
		Evidence: []string{
			fmt.Sprintf("Hypervisor Balloon Inflated: %d MB (%.1f%% of guest physical RAM)", balloonBytes/(1024*1024), balloonRatio*100.0),
			fmt.Sprintf("Guest MemTotal: %d MB, MemAvailable: %d MB (%.1f%% usable)", mem.MemTotal/1024, mem.MemAvailable/1024, availRatio*100.0),
		},
		Remediation: "Set fixed hypervisor memory reservations (e.g. virsh setmem / VMware Memory Reservation) to prevent host overcommit reclaiming guest RAM.",
	}, true
}

// RuleConntrackExhaustion detects Netfilter connection tracking table saturation.
type RuleConntrackExhaustion struct{}

func (r *RuleConntrackExhaustion) ID() string             { return "CONT_CONNTRACK_EXHAUSTION" }
func (r *RuleConntrackExhaustion) Tier() int              { return 2 }
func (r *RuleConntrackExhaustion) IsPIDDependent() bool   { return false }

func (r *RuleConntrackExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	ct := &diff.LatestSnapshot.SystemConfig.Conntrack
	if !ct.Available || ct.Max == 0 {
		return nil, false
	}

	if ct.Ratio < 0.90 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        2,
		Severity:    SeverityHigh,
		Confidence:  0.95,
		Title:       "Netfilter Conntrack Table Saturation",
		Explanation: "The kernel Netfilter connection tracking table is nearing capacity (≥ 90%), causing silent packet drops on incoming/outgoing connections before reaching applications.",
		Evidence: []string{
			fmt.Sprintf("Active Conntrack Sessions: %d / %d max table size (%.1f%% utilized)", ct.Count, ct.Max, ct.Ratio*100.0),
			"New TCP handshakes and UDP flows are being dropped at raw IP layer without application logs",
		},
		Remediation: "Increase connection tracking capacity: sysctl -w net.netfilter.nf_conntrack_max=1048576 or reduce nf_conntrack_tcp_timeout_established.",
	}, true
}

// RuleARPNeighborTableOverflow detects ARP / Neighbor cache table saturation in large subnets or Kubernetes nodes.
type RuleARPNeighborTableOverflow struct{}

func (r *RuleARPNeighborTableOverflow) ID() string             { return "CONT_ARP_NEIGHBOR_OVERFLOW" }
func (r *RuleARPNeighborTableOverflow) Tier() int              { return 2 }
func (r *RuleARPNeighborTableOverflow) IsPIDDependent() bool   { return false }

func (r *RuleARPNeighborTableOverflow) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	neigh := &diff.LatestSnapshot.SystemConfig.Neighbor
	if !neigh.Available || neigh.GCThresh3 == 0 {
		return nil, false
	}

	if neigh.Ratio >= 0.85 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.90,
			Title:       "ARP / Neighbor Cache Table Saturation",
			Explanation: "The kernel ARP / Neighbor cache has reached critical capacity (≥ 85% of gc_thresh3), causing silent packet drops and 'No route to host' errors when communicating with new IP addresses.",
			Evidence: []string{
				fmt.Sprintf("Active Neighbor/ARP Entries: %d / %d max (gc_thresh3)", neigh.ActiveEntries, neigh.GCThresh3),
				fmt.Sprintf("Table Saturation: %.1f%% of kernel ceiling", neigh.Ratio*100.0),
			},
			Remediation: fmt.Sprintf("Increase neighbor table thresholds: sysctl -w net.ipv4.neigh.default.gc_thresh3=%d", neigh.GCThresh3*4),
		}, true
	}

	return nil, false
}

// RuleTCPSYNQueueOverflow detects half-open connection SYN backlog queue floods.
type RuleTCPSYNQueueOverflow struct{}

func (r *RuleTCPSYNQueueOverflow) ID() string             { return "CONT_TCP_SYN_QUEUE_OVERFLOW" }
func (r *RuleTCPSYNQueueOverflow) Tier() int              { return 2 }
func (r *RuleTCPSYNQueueOverflow) IsPIDDependent() bool   { return false }

func (r *RuleTCPSYNQueueOverflow) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	synCookies := diff.NetStat.TCPReqQFullDoCookiesDelta
	overflows := diff.NetStat.ListenOverflowsDelta

	// Require SYN cookies as primary signal to differentiate from CONT_TCP_LISTEN_DROPS
	if synCookies > 0 {
		evidence := []string{
			fmt.Sprintf("TCP SYN Queue Full (SYN Cookies Sent): %d handshakes", synCookies),
		}
		if overflows > 0 {
			evidence = append(evidence, fmt.Sprintf("Listen Queue Overflows Delta: %d connections", overflows))
		}

		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.90,
			Title:       "TCP Inbound SYN Queue Overflow",
			Explanation: "Incoming TCP connection requests exceeded the kernel SYN backlog queue before handshakes completed, forcing fallback to SYN cookies.",
			Evidence:    evidence,
			Remediation: "Increase SYN backlog and listen queue limits: sysctl -w net.ipv4.tcp_max_syn_backlog=65535 and sysctl -w net.core.somaxconn=65535.",
		}, true
	}

	return nil, false
}

// RuleBlockHardwareTagStarvation detects storage controller blk-mq submission tag queue exhaustion.
type RuleBlockHardwareTagStarvation struct{}

func (r *RuleBlockHardwareTagStarvation) ID() string             { return "CONT_BLK_MQ_TAG_STARVATION" }
func (r *RuleBlockHardwareTagStarvation) Tier() int              { return 2 }
func (r *RuleBlockHardwareTagStarvation) IsPIDDependent() bool   { return true }

func (r *RuleBlockHardwareTagStarvation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Processes) == 0 {
		return nil, false
	}

	var tagWaitingProcs []collector.ProcessDiff
	for _, p := range diff.Processes {
		if strings.Contains(p.Wchan, "blk_mq_get_tag") || strings.Contains(p.Wchan, "io_schedule") {
			if p.ReadBytesDelta > 0 || p.WriteBytesDelta > 0 {
				tagWaitingProcs = append(tagWaitingProcs, p)
			}
		}
	}

	if len(tagWaitingProcs) >= 2 {
		topProc := tagWaitingProcs[0]
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.88,
			Title:       "Block Layer Hardware Tag Queue Starvation (blk-mq)",
			Explanation: "Multiple high-throughput I/O processes are blocked waiting for NVMe/SSD hardware submission tags, indicating block layer queue depth saturation.",
			Evidence: []string{
				fmt.Sprintf("Processes Blocked on blk-mq Tags: %d active tasks", len(tagWaitingProcs)),
				fmt.Sprintf("Representative Process: PID %d [%s] (wchan=%s)", topProc.PID, topProc.Comm, topProc.Wchan),
			},
			CulpritPID:  topProc.PID,
			CulpritName: topProc.Comm,
			Remediation: "Increase block device queue depth: echo 1024 > /sys/block/<device>/queue/nr_requests or tune io_uring queue depth.",
		}, true
	}

	return nil, false
}

// RuleSchedRunqueueStarvation detects high CPU scheduler runqueue dispatch latencies.
type RuleSchedRunqueueStarvation struct{}

func (r *RuleSchedRunqueueStarvation) ID() string             { return "CONT_SCHED_RUNQUEUE_STARVATION" }
func (r *RuleSchedRunqueueStarvation) Tier() int              { return 2 }
func (r *RuleSchedRunqueueStarvation) IsPIDDependent() bool   { return false }

func (r *RuleSchedRunqueueStarvation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	sched := &diff.LatestSnapshot.SystemConfig.SchedStat
	if !sched.Available || sched.RunningTimeMS < 100 {
		return nil, false
	}

	if sched.Ratio >= 1.5 {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.85,
			Title:       "CPU Scheduler Runqueue Latency Starvation",
			Explanation: "Threads are spending excessive time waiting in scheduler runqueues before being dispatched to CPU cores, causing application latency despite available compute capacity.",
			Evidence: []string{
				fmt.Sprintf("Runqueue Wait Time: %d ms vs Running Time: %d ms", sched.RunqueueWaitTimeMS, sched.RunningTimeMS),
				fmt.Sprintf("Runqueue Contention Ratio: %.2fx wait-to-execution ratio", sched.Ratio),
			},
			Remediation: "Reduce thread concurrency / pool size or tune scheduler migration cost (sysctl -w kernel.sched_migration_cost_ns=500000).",
		}, true
	}

	return nil, false
}

// RuleCgroupMemoryHighThrottle detects proactive page allocation delay injection in cgroup v2.
type RuleCgroupMemoryHighThrottle struct{}

func (r *RuleCgroupMemoryHighThrottle) ID() string             { return "CONT_CGROUP_MEM_HIGH_THROTTLE" }
func (r *RuleCgroupMemoryHighThrottle) Tier() int              { return 2 }
func (r *RuleCgroupMemoryHighThrottle) IsPIDDependent() bool   { return false }

func (r *RuleCgroupMemoryHighThrottle) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Cgroups) == 0 {
		return nil, false
	}

	for _, cg := range diff.Cgroups {
		if cg.MemoryHighEventsDelta > 0 {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        2,
				Severity:    SeverityHigh,
				Confidence:  0.92,
				Title:       fmt.Sprintf("Cgroup v2 Proactive Page Delay Throttling (%s)", cg.Path),
				Explanation: fmt.Sprintf("Cgroup '%s' exceeded its soft memory limit ('memory.high'), causing the kernel to inject artificial sleep delays into memory allocations.", cg.Path),
				Evidence: []string{
					fmt.Sprintf("Cgroup Path: %s", cg.Path),
					fmt.Sprintf("Memory High Events Delta: %d throttled allocation cycles", cg.MemoryHighEventsDelta),
					"Kernel is actively slowing memory allocation threads instead of killing them",
				},
				Remediation: fmt.Sprintf("Raise container memory soft limit: echo <bytes> > /sys/fs/cgroup%s/memory.high or increase Pod memory request.", cg.Path),
			}, true
		}
	}

	return nil, false
}

// RuleIOSchedulerQueueLatency detects I/O scheduler queueing delays before requests reach storage controllers.
type RuleIOSchedulerQueueLatency struct{}

func (r *RuleIOSchedulerQueueLatency) ID() string             { return "CONT_IO_QUEUE_LATENCY" }
func (r *RuleIOSchedulerQueueLatency) Tier() int              { return 2 }
func (r *RuleIOSchedulerQueueLatency) IsPIDDependent() bool   { return false }

func (r *RuleIOSchedulerQueueLatency) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Disks) == 0 {
		return nil, false
	}

	for _, d := range diff.Disks {
		totalOps := d.ReadsCompletedDelta + d.WritesCompletedDelta
		if totalOps >= 20 && d.AvgQueueLatencyMS >= 100.0 {
			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        2,
				Severity:    SeverityHigh,
				Confidence:  0.88,
				Title:       fmt.Sprintf("Disk Scheduler Queue Latency Spike (%s)", d.DeviceName),
				Explanation: fmt.Sprintf("I/O requests on block device '%s' are spending an average of %.1f ms waiting in scheduler queues before dispatch.", d.DeviceName, d.AvgQueueLatencyMS),
				Evidence: []string{
					fmt.Sprintf("Block Device: %s (Total Completed Operations: %d)", d.DeviceName, totalOps),
					fmt.Sprintf("Average Scheduler Queue Wait: %.1f ms/op", d.AvgQueueLatencyMS),
					fmt.Sprintf("I/O in Progress: %d", d.IOsInProgress),
				},
				Remediation: fmt.Sprintf("Change I/O scheduler: echo none > /sys/block/%s/queue/scheduler or raise nr_requests queue depth.", d.DeviceName),
			}, true
		}
	}

	return nil, false
}

// RulePageTableLockContention detects mmap_lock / page table lock contention on multi-threaded runtimes.
type RulePageTableLockContention struct{}

func (r *RulePageTableLockContention) ID() string             { return "CONT_PAGE_TABLE_LOCK" }
func (r *RulePageTableLockContention) Tier() int              { return 2 }
func (r *RulePageTableLockContention) IsPIDDependent() bool   { return true }

func (r *RulePageTableLockContention) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Processes) == 0 {
		return nil, false
	}

	var ptProcs []collector.ProcessDiff
	for _, p := range diff.Processes {
		wchan := p.Wchan
		if strings.Contains(wchan, "mmap_lock") || strings.Contains(wchan, "mmap_read_lock") ||
			strings.Contains(wchan, "page_table_lock") || strings.Contains(wchan, "down_read_killable") {
			ptProcs = append(ptProcs, p)
		}
	}

	if len(ptProcs) >= 2 {
		topProc := ptProcs[0]
		evidence := []string{
			fmt.Sprintf("Processes Blocked on Page Table Locks: %d active tasks", len(ptProcs)),
			fmt.Sprintf("Representative Process: PID %d [%s] (wchan=%s, threads=%d)", topProc.PID, topProc.Comm, topProc.Wchan, topProc.NumThreads),
		}

		return &Diagnosis{
			RuleID:         r.ID(),
			Tier:           2,
			Severity:       SeverityHigh,
			Confidence:     0.85,
			Title:          "Virtual Memory Page Table Lock Contention",
			Explanation:    "Multiple threads are stalled contending for mmap_lock / page table locks during concurrent memory mapping, page faulting, or thread allocation.",
			Evidence:       evidence,
			CulpritPID:     topProc.PID,
			CulpritName:    topProc.Comm,
			CulpritDetails: fmt.Sprintf("Stalled in wchan '%s' with %d threads", topProc.Wchan, topProc.NumThreads),
			Remediation:    "Reduce thread concurrency in memory-intensive workers or switch to jemalloc / tcmalloc arena allocator.",
		}, true
	}

	return nil, false
}

// RuleOrphanSocketLeak detects accumulation of unassociated orphan TCP sockets.
type RuleOrphanSocketLeak struct{}

func (r *RuleOrphanSocketLeak) ID() string             { return "CONT_ORPHAN_SOCKET_LEAK" }
func (r *RuleOrphanSocketLeak) Tier() int              { return 2 }
func (r *RuleOrphanSocketLeak) IsPIDDependent() bool   { return false }

func (r *RuleOrphanSocketLeak) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	sockStat := &diff.LatestSnapshot.SystemConfig.SockStat
	if sockStat.TCPOrphan < 1000 {
		return nil, false
	}

	// Trigger if orphans are significant relative to active sockets or large in absolute count
	if sockStat.TCPOrphan >= 5000 || (sockStat.TCPInUse > 0 && sockStat.TCPOrphan >= sockStat.TCPInUse/2) {
		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        2,
			Severity:    SeverityHigh,
			Confidence:  0.88,
			Title:       "TCP Orphan Socket Accumulation Leak",
			Explanation: fmt.Sprintf("System has %d orphan TCP sockets detached from user applications, consuming kernel network buffer memory.", sockStat.TCPOrphan),
			Evidence: []string{
				fmt.Sprintf("TCP Orphan Sockets: %d unreferenced sockets", sockStat.TCPOrphan),
				fmt.Sprintf("TCP Sockets in Use: %d active sockets", sockStat.TCPInUse),
			},
			Remediation: "Inspect applications for abrupt TCP connection termination without orderly close, or raise sysctl net.ipv4.tcp_max_orphans.",
		}, true
	}

	return nil, false
}
