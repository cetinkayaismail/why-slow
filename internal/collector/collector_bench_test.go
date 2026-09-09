package collector_test

import (
	"context"
	"testing"
	"time"
	"why-slow/internal/collector"
)

func BenchmarkCollector_ParseAllStaticFiles(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = collector.ParseCPUStat("testdata/proc_stat")
		_, _ = collector.ParseMemInfo("testdata/proc_meminfo")
		_, _ = collector.ParseLoadAvg("testdata/proc_loadavg")
		_, _ = collector.ParseTCPSockets("testdata/proc_net_tcp", "testdata/proc_net_tcp")
	}
}

func BenchmarkCollector_DiffSnapshots(b *testing.B) {
	snapA := &collector.SystemSnapshot{
		Timestamp: time.Now(),
		CPU: collector.CPUStatInfo{
			TotalCPU: collector.CoreCPUStat{User: 1000, System: 500, Idle: 8500},
			PerCore: []collector.CoreCPUStat{
				{ID: "cpu0", User: 250, System: 125, Idle: 2125},
				{ID: "cpu1", User: 250, System: 125, Idle: 2125},
				{ID: "cpu2", User: 250, System: 125, Idle: 2125},
				{ID: "cpu3", User: 250, System: 125, Idle: 2125},
			},
		},
		VMStat: collector.VMStatInfo{PgScanDirect: 1000},
	}
	snapB := &collector.SystemSnapshot{
		Timestamp: snapA.Timestamp.Add(1 * time.Second),
		CPU: collector.CPUStatInfo{
			TotalCPU: collector.CoreCPUStat{User: 1200, System: 600, Idle: 8600},
			PerCore: []collector.CoreCPUStat{
				{ID: "cpu0", User: 300, System: 150, Idle: 2150},
				{ID: "cpu1", User: 300, System: 150, Idle: 2150},
				{ID: "cpu2", User: 300, System: 150, Idle: 2150},
				{ID: "cpu3", User: 300, System: 150, Idle: 2150},
			},
		},
		VMStat: collector.VMStatInfo{PgScanDirect: 1500},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = collector.DiffSnapshots(snapA, snapB)
	}
}

func BenchmarkCollectSnapshot(b *testing.B) {
	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = collector.CollectSnapshot(ctx)
	}
}
