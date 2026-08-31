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
		LatestSnapshot:        latest.LatestSnapshot,
		VMStat:                medianVMStat(valid),
		NetStat:               medianNetStat(valid),
		Disks:                 latest.Disks,
		Cgroups:               latest.Cgroups,
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
