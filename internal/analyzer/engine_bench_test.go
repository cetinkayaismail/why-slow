package analyzer_test

import (
	"testing"
	"time"
	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
)

func BenchmarkEngine_Analyze159Rules_CleanSystem(b *testing.B) {
	eng := analyzer.NewEngine()
	diff := &collector.SnapshotDiff{
		Duration:     1 * time.Second,
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 95.0, BusyPercent: 5.0},
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"}},
			},
			Memory:      collector.MemInfo{MemTotal: 16000000, MemAvailable: 12000000},
			Clocksource: collector.ClocksourceInfo{Current: "tsc"},
		},
	}
	runCtx := collector.RunContext{IsRoot: true}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = eng.Analyze(diff, runCtx)
	}
}

func BenchmarkEngine_Analyze159Rules_CompoundFailure(b *testing.B) {
	eng := analyzer.NewEngine()
	diff := &collector.SnapshotDiff{
		Duration:     1 * time.Second,
		TotalCPUUtil: collector.CPUUtilization{IdlePercent: 0.5, BusyPercent: 99.5},
		ProcsRunning: 16,
		Disks: []collector.DiskDeviceDiff{
			{DeviceName: "nvme0n1", UtilPercent: 99.0, AvgWriteLatencyMS: 25.0},
		},
		VMStat: collector.VMStatDiff{
			PgScanDirectDelta:     5000,
			AllocStallDirectDelta: 50,
			OOMKillDelta:          2,
		},
		Processes: []collector.ProcessDiff{
			{PID: 101, Comm: "db_writer", State: 'D', Wchan: "sync_file_range", WriteBytesDelta: 500 * 1024 * 1024},
			{PID: 102, Comm: "heavy_calc", CPUPercent: 390.0, CPUTimeDelta: 390},
			{PID: 103, Comm: "leaky_server", OpenFDs: 900, MaxFDs: 1024},
		},
		LatestSnapshot: &collector.SystemSnapshot{
			CPU: collector.CPUStatInfo{
				PerCore: []collector.CoreCPUStat{{ID: "cpu0"}, {ID: "cpu1"}, {ID: "cpu2"}, {ID: "cpu3"}},
			},
			Memory:      collector.MemInfo{MemTotal: 16000000, MemAvailable: 200000, MemFree: 100000, SwapTotal: 2000000, SwapFree: 50000},
			Clocksource: collector.ClocksourceInfo{Current: "tsc"},
			SystemConfig: collector.SystemConfigInfo{
				Conntrack: collector.ConntrackInfo{Available: true, Count: 65535, Max: 65536, Ratio: 0.999},
			},
			TCPSockets: collector.TCPSocketsInfo{Available: true, Established: 500, CloseWait: 300},
			LoadAvg:    collector.LoadAvgInfo{Available: true, Load1: 16.0, Load5: 12.0, Load15: 8.0, RunningEntities: 16, TotalEntities: 500},
		},
	}
	runCtx := collector.RunContext{IsRoot: true}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = eng.Analyze(diff, runCtx)
	}
}
