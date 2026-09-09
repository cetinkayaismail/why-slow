// Package collector — median.go computes median metrics across multiple
// SnapshotDiff windows to filter out transient microsecond noise.
package collector

import (
	"sort"
)

// MedianDiff aggregates a series of SnapshotDiff samples and produces a single
// representative SnapshotDiff containing median values for all rate and counter metrics.
func MedianDiff(diffs []*SnapshotDiff) *SnapshotDiff {
	valid := filterValidDiffs(diffs)
	if len(valid) == 0 {
		return nil
	}
	if len(valid) == 1 {
		return valid[0]
	}

	latest := valid[len(valid)-1]

	result := &SnapshotDiff{
		Duration:              latest.Duration,
		Timestamp:             latest.Timestamp,
		ClockJumpDetected:     anyClockJump(valid),
		ProcsRunning:          medianUint64(extractFieldUint64(valid, func(d *SnapshotDiff) uint64 { return d.ProcsRunning })),
		ProcsBlocked:          medianUint64(extractFieldUint64(valid, func(d *SnapshotDiff) uint64 { return d.ProcsBlocked })),
		ContextSwitchesDelta:  medianUint64(extractFieldUint64(valid, func(d *SnapshotDiff) uint64 { return d.ContextSwitchesDelta })),
		ProcessesCreatedDelta: medianUint64(extractFieldUint64(valid, func(d *SnapshotDiff) uint64 { return d.ProcessesCreatedDelta })),
		TotalCPUUtil:          medianCPUUtil(valid),
		PerCoreCPUUtil:        medianPerCoreCPUUtil(valid),
		LatestSnapshot:        latest.LatestSnapshot,
		VMStat:                medianVMStat(valid),
		NetStat:               medianNetStat(valid),
		Disks:                 medianDiskDiffs(valid),
		Cgroups:               medianCgroupDiffs(valid),
		NetIfaces:             latest.NetIfaces,
		Processes:             latest.Processes,
	}

	return result
}

func filterValidDiffs(diffs []*SnapshotDiff) []*SnapshotDiff {
	valid := make([]*SnapshotDiff, 0, len(diffs))
	for _, d := range diffs {
		if d != nil {
			valid = append(valid, d)
		}
	}
	return valid
}

func anyClockJump(diffs []*SnapshotDiff) bool {
	for _, d := range diffs {
		if d.ClockJumpDetected {
			return true
		}
	}
	return false
}

func extractFieldUint64(diffs []*SnapshotDiff, fn func(*SnapshotDiff) uint64) []uint64 {
	vals := make([]uint64, len(diffs))
	for i, d := range diffs {
		vals[i] = fn(d)
	}
	return vals
}

func medianUint64(vals []uint64) uint64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]uint64, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func medianFloat64(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)
	return sorted[len(sorted)/2]
}

func medianCPUUtil(diffs []*SnapshotDiff) CPUUtilization {
	users := make([]float64, len(diffs))
	syss := make([]float64, len(diffs))
	iowaits := make([]float64, len(diffs))
	idles := make([]float64, len(diffs))
	busys := make([]float64, len(diffs))
	softirqs := make([]float64, len(diffs))
	steals := make([]float64, len(diffs))

	for i, d := range diffs {
		users[i] = d.TotalCPUUtil.UserPercent
		syss[i] = d.TotalCPUUtil.SystemPercent
		iowaits[i] = d.TotalCPUUtil.IOWaitPercent
		idles[i] = d.TotalCPUUtil.IdlePercent
		busys[i] = d.TotalCPUUtil.BusyPercent
		softirqs[i] = d.TotalCPUUtil.SoftIRQPercent
		steals[i] = d.TotalCPUUtil.StealPercent
	}

	return CPUUtilization{
		UserPercent:    medianFloat64(users),
		SystemPercent:  medianFloat64(syss),
		IOWaitPercent:  medianFloat64(iowaits),
		IdlePercent:    medianFloat64(idles),
		BusyPercent:    medianFloat64(busys),
		SoftIRQPercent: medianFloat64(softirqs),
		StealPercent:   medianFloat64(steals),
	}
}

func medianVMStat(diffs []*SnapshotDiff) VMStatDiff {
	latest := diffs[len(diffs)-1].VMStat
	latest.PgScanDirectDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.VMStat.PgScanDirectDelta }))
	latest.AllocStallDirectDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.VMStat.AllocStallDirectDelta }))
	latest.CompactStallDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.VMStat.CompactStallDelta }))
	latest.PgMajFaultDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.VMStat.PgMajFaultDelta }))
	latest.PswpinDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.VMStat.PswpinDelta }))
	latest.PswpoutDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.VMStat.PswpoutDelta }))
	latest.OOMKillDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.VMStat.OOMKillDelta }))
	return latest
}

func medianNetStat(diffs []*SnapshotDiff) NetStatDiff {
	latest := diffs[len(diffs)-1].NetStat
	latest.ListenOverflowsDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.NetStat.ListenOverflowsDelta }))
	latest.ListenDropsDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.NetStat.ListenDropsDelta }))
	latest.TCPMemoryPressuresDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.NetStat.TCPMemoryPressuresDelta }))
	latest.RetransSegsDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.NetStat.RetransSegsDelta }))
	latest.SoftnetDroppedDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.NetStat.SoftnetDroppedDelta }))
	latest.SoftnetTimeSqueezeDelta = medianUint64(extractFieldUint64(diffs, func(d *SnapshotDiff) uint64 { return d.NetStat.SoftnetTimeSqueezeDelta }))
	return latest
}

func medianPerCoreCPUUtil(diffs []*SnapshotDiff) []CPUUtilization {
	if len(diffs) == 0 || len(diffs[0].PerCoreCPUUtil) == 0 {
		return nil
	}
	minCores := len(diffs[0].PerCoreCPUUtil)
	for _, d := range diffs[1:] {
		if len(d.PerCoreCPUUtil) < minCores {
			minCores = len(d.PerCoreCPUUtil)
		}
	}
	if minCores == 0 {
		return nil
	}

	result := make([]CPUUtilization, minCores)
	for c := 0; c < minCores; c++ {
		users := make([]float64, len(diffs))
		syss := make([]float64, len(diffs))
		iowaits := make([]float64, len(diffs))
		idles := make([]float64, len(diffs))
		busys := make([]float64, len(diffs))
		softirqs := make([]float64, len(diffs))
		steals := make([]float64, len(diffs))

		for i, d := range diffs {
			core := d.PerCoreCPUUtil[c]
			users[i] = core.UserPercent
			syss[i] = core.SystemPercent
			iowaits[i] = core.IOWaitPercent
			idles[i] = core.IdlePercent
			busys[i] = core.BusyPercent
			softirqs[i] = core.SoftIRQPercent
			steals[i] = core.StealPercent
		}

		result[c] = CPUUtilization{
			UserPercent:    medianFloat64(users),
			SystemPercent:  medianFloat64(syss),
			IOWaitPercent:  medianFloat64(iowaits),
			IdlePercent:    medianFloat64(idles),
			BusyPercent:    medianFloat64(busys),
			SoftIRQPercent: medianFloat64(softirqs),
			StealPercent:   medianFloat64(steals),
		}
	}
	return result
}

func medianDiskDiffs(diffs []*SnapshotDiff) []DiskDeviceDiff {
	if len(diffs) == 0 {
		return nil
	}
	latest := diffs[len(diffs)-1]
	counts := make(map[string]int)
	for _, d := range diffs {
		for _, dev := range d.Disks {
			counts[dev.DeviceName]++
		}
	}

	result := make([]DiskDeviceDiff, 0, len(latest.Disks))
	for _, base := range latest.Disks {
		if counts[base.DeviceName] != len(diffs) {
			continue // intersection: only devices present in ALL samples
		}

		utils := make([]float64, len(diffs))
		readLats := make([]float64, len(diffs))
		writeLats := make([]float64, len(diffs))
		queueLats := make([]float64, len(diffs))
		readBytes := make([]uint64, len(diffs))
		writeBytes := make([]uint64, len(diffs))

		for i, d := range diffs {
			for _, dev := range d.Disks {
				if dev.DeviceName == base.DeviceName {
					utils[i] = dev.UtilPercent
					readLats[i] = dev.AvgReadLatencyMS
					writeLats[i] = dev.AvgWriteLatencyMS
					queueLats[i] = dev.AvgQueueLatencyMS
					readBytes[i] = dev.ReadBytesDelta
					writeBytes[i] = dev.WriteBytesDelta
					break
				}
			}
		}

		merged := base
		merged.UtilPercent = medianFloat64(utils)
		merged.AvgReadLatencyMS = medianFloat64(readLats)
		merged.AvgWriteLatencyMS = medianFloat64(writeLats)
		merged.AvgQueueLatencyMS = medianFloat64(queueLats)
		merged.ReadBytesDelta = medianUint64(readBytes)
		merged.WriteBytesDelta = medianUint64(writeBytes)
		result = append(result, merged)
	}
	return result
}

func medianCgroupDiffs(diffs []*SnapshotDiff) []CgroupDiff {
	if len(diffs) == 0 {
		return nil
	}
	latest := diffs[len(diffs)-1]
	counts := make(map[string]int)
	for _, d := range diffs {
		for _, cg := range d.Cgroups {
			counts[cg.Path]++
		}
	}

	result := make([]CgroupDiff, 0, len(latest.Cgroups))
	for _, base := range latest.Cgroups {
		if counts[base.Path] != len(diffs) {
			continue // intersection: only cgroups present in ALL samples
		}

		throttledUsecs := make([]uint64, len(diffs))
		nrThrottleds := make([]uint64, len(diffs))
		oomKills := make([]uint64, len(diffs))
		memHighs := make([]uint64, len(diffs))

		for i, d := range diffs {
			for _, cg := range d.Cgroups {
				if cg.Path == base.Path {
					throttledUsecs[i] = cg.ThrottledUsecDelta
					nrThrottleds[i] = cg.NrThrottledDelta
					oomKills[i] = cg.OOMKillsDelta
					memHighs[i] = cg.MemoryHighEventsDelta
					break
				}
			}
		}

		merged := base
		merged.ThrottledUsecDelta = medianUint64(throttledUsecs)
		merged.NrThrottledDelta = medianUint64(nrThrottleds)
		merged.OOMKillsDelta = medianUint64(oomKills)
		merged.MemoryHighEventsDelta = medianUint64(memHighs)
		result = append(result, merged)
	}
	return result
}
