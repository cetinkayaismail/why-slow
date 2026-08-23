// Package analyzer — tier1_base.go contains Tier 1 (P0 Priority) diagnostic
// rules for base hard bottlenecks:
//
//   - BASE_CPU_SATURATION:        All CPUs pegged, run queue > 2× core count
//   - BASE_OOM_DANGER:            MemAvailable < 3%, swap exhausted
//   - BASE_DISK_SPACE_FULL:       / or /tmp or /var at ≥ 99%
//   - BASE_DISK_HARDWARE_SATURATION: io_ticks delta ≥ 95%
//   - BASE_THERMAL_THROTTLING:    CPU freq < 40% max + temp > 85°C
//   - BASE_INODE_EXHAUSTION:      Inodes on critical mount ≥ 99% or 0 free
package analyzer

import (
	"fmt"
	"why-slow/internal/collector"
)

// GetTier1Rules returns all registered Tier 1 diagnostic rules.
func GetTier1Rules() []Rule {
	return []Rule{
		&RuleCPUSaturation{},
		&RuleOOMDanger{},
		&RuleDiskSpaceFull{},
		&RuleDiskHWSaturation{},
		&RuleThermalThrottling{},
		&RuleInodeExhaustion{},
		&RuleIOServiceLatency{},
		&RuleTCPSocketMemoryPressure{},
		&RuleSwapDeviceSaturation{},
	}
}

// RuleCPUSaturation detects 100% CPU starvation with an overloaded runqueue.
type RuleCPUSaturation struct{}

func (r *RuleCPUSaturation) ID() string             { return "BASE_CPU_SATURATION" }
func (r *RuleCPUSaturation) Tier() int              { return 1 }
func (r *RuleCPUSaturation) IsPIDDependent() bool   { return true }

func (r *RuleCPUSaturation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	numCores := len(diff.LatestSnapshot.CPU.PerCore)
	if numCores == 0 {
		numCores = 1
	}

	// Multi-signal: CPU is busy (idle < 2.0%) AND runqueue has waiting tasks (> 2x cores)
	isIdleLow := diff.TotalCPUUtil.IdlePercent < 2.0
	isQueueSaturated := diff.ProcsRunning >= uint64(numCores*2) && diff.ProcsRunning >= 4

	if !isIdleLow || !isQueueSaturated {
		return nil, false
	}

	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        1,
		Severity:    SeverityCritical,
		Confidence:  0.95,
		Title:       "100% CPU Runqueue Starvation",
		Explanation: "All CPU cores are fully saturated and the scheduler runqueue is overloaded with waiting threads.",
		Evidence: []string{
			fmt.Sprintf("CPU Idle: %.1f%% (Busy: %.1f%%, System: %.1f%%, IOWait: %.1f%%)",
				diff.TotalCPUUtil.IdlePercent, diff.TotalCPUUtil.BusyPercent, diff.TotalCPUUtil.SystemPercent, diff.TotalCPUUtil.IOWaitPercent),
			fmt.Sprintf("Procs Running in Runqueue: %d (CPU Cores: %d)", diff.ProcsRunning, numCores),
		},
		Remediation: "Identify and throttle or renice runaway compute processes.",
	}

	// Attribute culprit PID with highest CPU usage
	if topProc := findTopCPUProcess(diff.Processes); topProc != nil {
		diag.CulpritPID = topProc.PID
		diag.CulpritName = topProc.Comm
		diag.CulpritDetails = fmt.Sprintf("Consuming %.1f%% CPU delta with %d active threads", topProc.CPUPercent, topProc.NumThreads)
		diag.Remediation = fmt.Sprintf("Lower process scheduling priority: renice -n 19 -p %d", topProc.PID)
	}

	return diag, true
}

func findTopCPUProcess(procs []collector.ProcessDiff) *collector.ProcessDiff {
	var top *collector.ProcessDiff
	for i := range procs {
		p := &procs[i]
		if top == nil || p.CPUTimeDelta > top.CPUTimeDelta {
			top = p
		}
	}
	return top
}

// RuleOOMDanger detects immediate risk of out-of-memory kernel termination.
type RuleOOMDanger struct{}

func (r *RuleOOMDanger) ID() string             { return "BASE_OOM_DANGER" }
func (r *RuleOOMDanger) Tier() int              { return 1 }
func (r *RuleOOMDanger) IsPIDDependent() bool   { return true }

func (r *RuleOOMDanger) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	mem := &diff.LatestSnapshot.Memory
	if mem.MemTotal == 0 {
		return nil, false
	}

	availRatio := float64(mem.MemAvailable) / float64(mem.MemTotal)
	isRAMDepleted := availRatio < 0.03 // < 3% available

	isSwapDepleted := false
	if mem.SwapTotal == 0 {
		isSwapDepleted = true
	} else {
		swapFreeRatio := float64(mem.SwapFree) / float64(mem.SwapTotal)
		isSwapDepleted = swapFreeRatio < 0.05 // < 5% swap free
	}

	if !isRAMDepleted || !isSwapDepleted {
		return nil, false
	}

	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        1,
		Severity:    SeverityCritical,
		Confidence:  0.95,
		Title:       "Severe Memory Starvation (OOM Killer Imminent)",
		Explanation: "Available physical memory is below 3% and swap is depleted. The kernel OOM killer will soon terminate processes.",
		Evidence: []string{
			fmt.Sprintf("MemAvailable: %d MB out of %d MB total (%.1f%% available)",
				mem.MemAvailable/1024, mem.MemTotal/1024, availRatio*100.0),
			fmt.Sprintf("Swap: %d MB free out of %d MB total",
				mem.SwapFree/1024, mem.SwapTotal/1024),
		},
		Remediation: "Free memory immediately or configure cgroup memory limits to protect critical services.",
	}

	if topOOM := findTopOOMScoreProcess(diff.Processes); topOOM != nil {
		diag.CulpritPID = topOOM.PID
		diag.CulpritName = topOOM.Comm
		diag.CulpritDetails = fmt.Sprintf("Kernel OOM Score: %d (RSS: %d MB)", topOOM.OOMScore, topOOM.RSSBytes/(1024*1024))
		diag.Remediation = fmt.Sprintf("Restart or terminate high-memory process: kill -TERM %d", topOOM.PID)
	}

	return diag, true
}

func findTopOOMScoreProcess(procs []collector.ProcessDiff) *collector.ProcessDiff {
	var top *collector.ProcessDiff
	for i := range procs {
		p := &procs[i]
		if top == nil || p.OOMScore > top.OOMScore || (p.OOMScore == top.OOMScore && p.RSSBytes > top.RSSBytes) {
			top = p
		}
	}
	return top
}

// RuleDiskSpaceFull detects critical storage capacity exhaustion.
type RuleDiskSpaceFull struct{}

func (r *RuleDiskSpaceFull) ID() string             { return "BASE_DISK_SPACE_FULL" }
func (r *RuleDiskSpaceFull) Tier() int              { return 1 }
func (r *RuleDiskSpaceFull) IsPIDDependent() bool   { return false }

func (r *RuleDiskSpaceFull) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	var fullMounts []collector.MountSpaceInfo
	for _, m := range diff.LatestSnapshot.DiskSpace.Mounts {
		if m.UsedPercent >= 99.0 {
			fullMounts = append(fullMounts, m)
		}
	}

	if len(fullMounts) == 0 {
		return nil, false
	}

	evidence := make([]string, 0, len(fullMounts))
	for _, m := range fullMounts {
		evidence = append(evidence, fmt.Sprintf("Mount '%s': %.1f%% used (%d MB available of %d MB total)",
			m.Path, m.UsedPercent, m.AvailBytes/(1024*1024), m.TotalBytes/(1024*1024)))
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        1,
		Severity:    SeverityCritical,
		Confidence:  1.0,
		Title:       "Filesystem Storage Capacity Full",
		Explanation: "One or more critical filesystems have reached 99-100% capacity, blocking write syscalls and causing system freezes.",
		Evidence:    evidence,
		Remediation: fmt.Sprintf("Clean up disk space, rotate logs, or expand storage for '%s'.", fullMounts[0].Path),
	}, true
}

// RuleDiskHWSaturation detects 100% hardware disk saturation.
type RuleDiskHWSaturation struct{}

func (r *RuleDiskHWSaturation) ID() string             { return "BASE_DISK_HARDWARE_SATURATION" }
func (r *RuleDiskHWSaturation) Tier() int              { return 1 }
func (r *RuleDiskHWSaturation) IsPIDDependent() bool   { return true }

func (r *RuleDiskHWSaturation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	var satDevice *collector.DiskDeviceDiff
	for i := range diff.Disks {
		d := &diff.Disks[i]
		if d.UtilPercent >= 95.0 {
			if satDevice == nil || d.UtilPercent > satDevice.UtilPercent {
				satDevice = d
			}
		}
	}

	if satDevice == nil {
		return nil, false
	}

	diag := &Diagnosis{
		RuleID:      r.ID(),
		Tier:        1,
		Severity:    SeverityCritical,
		Confidence:  0.95,
		Title:       fmt.Sprintf("Disk Block Device Saturation (%s)", satDevice.DeviceName),
		Explanation: fmt.Sprintf("Storage device '%s' is operating at %.1f%% utilization capacity over the sampling window.", satDevice.DeviceName, satDevice.UtilPercent),
		Evidence: []string{
			fmt.Sprintf("Device '%s' I/O Utilization: %.1f%%", satDevice.DeviceName, satDevice.UtilPercent),
			fmt.Sprintf("Read Throughput: %.2f MB/s, Write Throughput: %.2f MB/s",
				float64(satDevice.ReadBytesDelta)/(1024*1024), float64(satDevice.WriteBytesDelta)/(1024*1024)),
			fmt.Sprintf("I/O Operations in Flight: %d", satDevice.IOsInProgress),
		},
		Remediation: "Throttle synchronous write calls or reduce I/O queue congestion.",
	}

	if topWriter := findTopWriterProcess(diff.Processes); topWriter != nil && topWriter.WriteBytesDelta > 10*1024*1024 {
		diag.CulpritPID = topWriter.PID
		diag.CulpritName = topWriter.Comm
		diag.CulpritDetails = fmt.Sprintf("Issued %.1f MB write delta during sampling window", float64(topWriter.WriteBytesDelta)/(1024*1024))
		diag.Remediation = fmt.Sprintf("Lower I/O priority for culprit: ionice -c3 -p %d", topWriter.PID)
	}

	return diag, true
}

func findTopWriterProcess(procs []collector.ProcessDiff) *collector.ProcessDiff {
	var top *collector.ProcessDiff
	for i := range procs {
		p := &procs[i]
		if top == nil || p.WriteBytesDelta > top.WriteBytesDelta {
			top = p
		}
	}
	return top
}

// RuleThermalThrottling detects hardware CPU throttling due to thermal overheating.
type RuleThermalThrottling struct{}

func (r *RuleThermalThrottling) ID() string             { return "BASE_THERMAL_THROTTLING" }
func (r *RuleThermalThrottling) Tier() int              { return 1 }
func (r *RuleThermalThrottling) IsPIDDependent() bool   { return false }

func (r *RuleThermalThrottling) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	freqInfo := &diff.LatestSnapshot.CPUFreq
	thermalInfo := &diff.LatestSnapshot.Thermal

	if !freqInfo.Available || !thermalInfo.Available {
		return nil, false
	}

	if thermalInfo.MaxTemp < 85.0 {
		return nil, false
	}

	throttledCores := 0
	for _, c := range freqInfo.Cores {
		if c.MaxFreq > 0 && float64(c.CurFreq) < 0.40*float64(c.MaxFreq) {
			throttledCores++
		}
	}

	if throttledCores == 0 {
		return nil, false
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        1,
		Severity:    SeverityCritical,
		Confidence:  0.90,
		Title:       "Hardware CPU Thermal Throttling",
		Explanation: "CPU temperature exceeded 85°C and clock frequencies have been drastically cut by hardware throttling.",
		Evidence: []string{
			fmt.Sprintf("Maximum Thermal Zone Temperature: %.1f°C", thermalInfo.MaxTemp),
			fmt.Sprintf("%d cores throttled below 40%% of maximum frequency", throttledCores),
		},
		Remediation: "Inspect cooling fans, clear chassis dust blockages, and ensure adequate airflow.",
	}, true
}

// RuleInodeExhaustion detects filesystem inode table exhaustion.
type RuleInodeExhaustion struct{}

func (r *RuleInodeExhaustion) ID() string             { return "BASE_INODE_EXHAUSTION" }
func (r *RuleInodeExhaustion) Tier() int              { return 1 }
func (r *RuleInodeExhaustion) IsPIDDependent() bool   { return false }

func (r *RuleInodeExhaustion) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || diff.LatestSnapshot == nil {
		return nil, false
	}

	var fullMounts []collector.MountSpaceInfo
	for _, m := range diff.LatestSnapshot.DiskSpace.Mounts {
		if m.InodesTotal > 0 && (m.InodesUsedPercent >= 99.0 || m.InodesFree == 0) {
			fullMounts = append(fullMounts, m)
		}
	}

	if len(fullMounts) == 0 {
		return nil, false
	}

	evidence := make([]string, 0, len(fullMounts))
	for _, m := range fullMounts {
		evidence = append(evidence, fmt.Sprintf("Mount '%s': %.1f%% inodes used (%d free of %d total inodes)",
			m.Path, m.InodesUsedPercent, m.InodesFree, m.InodesTotal))
	}

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        1,
		Severity:    SeverityCritical,
		Confidence:  1.0,
		Title:       "Filesystem Inode Depletion",
		Explanation: "One or more critical filesystems have exhausted their inode table, preventing new file creation even if disk space is available.",
		Evidence:    evidence,
		Remediation: fmt.Sprintf("Delete unused small files or clear spool/cache directories on '%s': find %s -xdev -type f -delete", fullMounts[0].Path, fullMounts[0].Path),
	}, true
}

// RuleIOServiceLatency detects excessive block I/O service latencies on SAN/EBS/NVMe volumes.
type RuleIOServiceLatency struct{}

func (r *RuleIOServiceLatency) ID() string             { return "BASE_IO_SERVICE_LATENCY" }
func (r *RuleIOServiceLatency) Tier() int              { return 1 }
func (r *RuleIOServiceLatency) IsPIDDependent() bool   { return false }

func (r *RuleIOServiceLatency) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil || len(diff.Disks) == 0 {
		return nil, false
	}

	for _, d := range diff.Disks {
		totalOps := d.ReadsCompletedDelta + d.WritesCompletedDelta
		if totalOps < 10 {
			continue
		}

		isReadSlow := d.ReadsCompletedDelta > 0 && d.AvgReadLatencyMS >= 50.0
		isWriteSlow := d.WritesCompletedDelta > 0 && d.AvgWriteLatencyMS >= 50.0

		if isReadSlow || isWriteSlow {
			evidence := []string{
				fmt.Sprintf("Block Device: %s (Total I/O Operations: %d in sampling window)", d.DeviceName, totalOps),
			}
			if isReadSlow {
				evidence = append(evidence, fmt.Sprintf("Average Read Latency: %.1f ms/op (Reads: %d ops, Data: %d KB)",
					d.AvgReadLatencyMS, d.ReadsCompletedDelta, d.ReadBytesDelta/1024))
			}
			if isWriteSlow {
				evidence = append(evidence, fmt.Sprintf("Average Write Latency: %.1f ms/op (Writes: %d ops, Data: %d KB)",
					d.AvgWriteLatencyMS, d.WritesCompletedDelta, d.WriteBytesDelta/1024))
			}

			return &Diagnosis{
				RuleID:      r.ID(),
				Tier:        1,
				Severity:    SeverityCritical,
				Confidence:  0.92,
				Title:       fmt.Sprintf("Storage I/O Service Latency Spike (%s)", d.DeviceName),
				Explanation: fmt.Sprintf("Block device '%s' is suffering severe I/O service delays exceeding 50ms per operation, indicating SAN/EBS congestion, storage queue saturation, or burst credit depletion.", d.DeviceName),
				Evidence:    evidence,
				Remediation: fmt.Sprintf("Inspect SAN/Cloud EBS volume burst credits, examine storage controller queue depths, or upgrade storage tier for %s.", d.DeviceName),
			}, true
		}
	}

	return nil, false
}

// RuleTCPSocketMemoryPressure detects kernel TCP socket buffer exhaustion and connection aborts.
type RuleTCPSocketMemoryPressure struct{}

func (r *RuleTCPSocketMemoryPressure) ID() string             { return "BASE_TCP_SOCKET_MEM_PRESS" }
func (r *RuleTCPSocketMemoryPressure) Tier() int              { return 1 }
func (r *RuleTCPSocketMemoryPressure) IsPIDDependent() bool   { return false }

func (r *RuleTCPSocketMemoryPressure) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	hasPressure := diff.NetStat.TCPMemoryPressuresDelta > 0
	hasAbort := diff.NetStat.TCPAbortOnMemoryDelta > 0
	hasCollapsed := diff.NetStat.TCPRcvCollapsedDelta > 0

	if hasPressure && hasAbort {
		evidence := []string{
			fmt.Sprintf("TCP Memory Pressures Delta: %d events", diff.NetStat.TCPMemoryPressuresDelta),
			fmt.Sprintf("TCP Connections Aborted On Memory: %d resets", diff.NetStat.TCPAbortOnMemoryDelta),
		}
		if hasCollapsed {
			evidence = append(evidence, fmt.Sprintf("TCP Receive Queues Collapsed: %d buffers", diff.NetStat.TCPRcvCollapsedDelta))
		}

		return &Diagnosis{
			RuleID:      r.ID(),
			Tier:        1,
			Severity:    SeverityCritical,
			Confidence:  0.95,
			Title:       "TCP Socket Buffer Memory Exhaustion",
			Explanation: "The kernel TCP stack has exceeded its 'tcp_mem' allocation limits, forcing receive queue buffer collapse and actively terminating connections with RST packets.",
			Evidence:    evidence,
			Remediation: "Increase system TCP buffer limits (sysctl -w net.ipv4.tcp_mem='<min> <pressure> <max>') or tune application socket read buffers (net.ipv4.tcp_rmem).",
		}, true
	}

	return nil, false
}

// RuleSwapDeviceSaturation detects swap storage subsystem saturation from massive page in/out traffic.
type RuleSwapDeviceSaturation struct{}

func (r *RuleSwapDeviceSaturation) ID() string             { return "BASE_SWAP_DEVICE_SATURATION" }
func (r *RuleSwapDeviceSaturation) Tier() int              { return 1 }
func (r *RuleSwapDeviceSaturation) IsPIDDependent() bool   { return false }

func (r *RuleSwapDeviceSaturation) Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool) {
	if diff == nil {
		return nil, false
	}

	swpin := diff.VMStat.PswpinDelta
	swpout := diff.VMStat.PswpoutDelta

	// Multi-signal: active swap writeout (> 10k pages / ~40MB) along with read-in (> 2k pages) or heavy writeout (> 25k pages)
	isHeavySwap := swpout >= 25000 || (swpout >= 10000 && swpin >= 2000)
	if !isHeavySwap {
		return nil, false
	}

	pageSizeKB := uint64(4) // 4KB per page
	swpinMB := (swpin * pageSizeKB) / 1024
	swpoutMB := (swpout * pageSizeKB) / 1024

	return &Diagnosis{
		RuleID:      r.ID(),
		Tier:        1,
		Severity:    SeverityCritical,
		Confidence:  0.92,
		Title:       "Swap Storage Device I/O Saturation",
		Explanation: "High-volume page swapping is saturating the swap storage device bandwidth, stalling kernel memory management and user processes.",
		Evidence: []string{
			fmt.Sprintf("Swap Pages Out Delta: %d pages (~%d MB)", swpout, swpoutMB),
			fmt.Sprintf("Swap Pages In Delta: %d pages (~%d MB)", swpin, swpinMB),
		},
		Remediation: "Reduce system memory footprint, tune vm.swappiness (sysctl -w vm.swappiness=10), or configure zram / fast NVMe swap storage.",
	}, true
}
