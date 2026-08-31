package tui

import (
	"bytes"
	"testing"
	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
)

func TestAssessBlastRadius(t *testing.T) {
	// Protected PID 1
	impact1 := AssessBlastRadius(1, "systemd", nil, nil)
	if !impact1.IsBlocked {
		t.Errorf("expected PID 1 to be blocked by safety gate")
	}

	// Normal worker with children
	procs := []collector.ProcessDiff{
		{PID: 100, Comm: "master", PPID: 1},
		{PID: 101, Comm: "worker1", PPID: 100},
		{PID: 102, Comm: "worker2", PPID: 100},
	}
	diag := &analyzer.Diagnosis{Remediation: "renice -n 19 -p 100"}
	impact100 := AssessBlastRadius(100, "master", procs, diag)
	if impact100.IsBlocked {
		t.Errorf("expected PID 100 not to be blocked")
	}
	if impact100.ChildCount != 2 {
		t.Errorf("expected 2 child workers, got %d", impact100.ChildCount)
	}
}

func TestSortProcesses(t *testing.T) {
	procs := []collector.ProcessDiff{
		{PID: 1, Comm: "p1", CPUPercent: 10.0, RSSBytes: 1000, ReadBytesDelta: 500},
		{PID: 2, Comm: "p2", CPUPercent: 80.0, RSSBytes: 500, ReadBytesDelta: 100},
		{PID: 3, Comm: "p3", CPUPercent: 5.0, RSSBytes: 5000, ReadBytesDelta: 5000},
	}

	// Sort by CPU
	byCPU := sortProcesses(procs, SortByCPU)
	if byCPU[0].PID != 2 {
		t.Errorf("expected top CPU PID=2, got %d", byCPU[0].PID)
	}

	// Sort by Memory
	byMem := sortProcesses(procs, SortByMemory)
	if byMem[0].PID != 3 {
		t.Errorf("expected top Memory PID=3, got %d", byMem[0].PID)
	}

	// Sort by IO
	byIO := sortProcesses(procs, SortByIO)
	if byIO[0].PID != 3 {
		t.Errorf("expected top IO PID=3, got %d", byIO[0].PID)
	}
}

func TestRenderHeaderAndModals(t *testing.T) {
	theme := NewTheme(true)
	screen := NewScreen(100, 30, theme)

	report := &analyzer.DiagnosticReport{
		Duration: "1.0s",
		SystemPressure: analyzer.PSISummary{
			Available:         true,
			CPUStallPercent:   15.5,
			MemoryStallPercent: 0.0,
			IOStallPercent:    45.2,
		},
		PrimaryBlocker: &analyzer.Diagnosis{
			RuleID:      "BASE_CPU_SATURATION",
			Tier:        1,
			Severity:    analyzer.SeverityCritical,
			Confidence:  0.95,
			Title:       "CPU Starvation",
			Explanation: "Runaway threads consuming all CPU cores.",
			CulpritPID:  5001,
			CulpritName: "heavy_job",
			Remediation: "renice -n 19 -p 5001",
		},
	}

	RenderHeader(screen, theme, report, nil, 100)
	RenderPrimaryBlocker(screen, theme, report, 6, 100, 8)
	RenderRuleMatrix(screen, theme, report, 26, 100)

	var buf bytes.Buffer
	if err := screen.Flush(&buf); err != nil {
		t.Fatalf("unexpected flush error: %v", err)
	}

	out := buf.String()
	if len(out) == 0 {
		t.Errorf("expected rendered output in buffer")
	}
}
