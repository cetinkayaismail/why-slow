// Package tui — view_header.go renders the top host metadata and PSI pressure gauges.
package tui

import (
	"fmt"
	"os"
	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
)

// RenderHeader draws the top status header including PSI stall gauges.
func RenderHeader(s *Screen, theme *Theme, report *analyzer.DiagnosticReport, diff *collector.SnapshotDiff, width int) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "localhost"
	}

	durStr := "1.0s"
	if report != nil && report.Duration != "" {
		durStr = report.Duration
	}

	headerTitle := fmt.Sprintf("why-slow v0.20.0 — [Host: %s] — [Window: %s] — [Live]", hostname, durStr)
	s.DrawBox(1, 1, width, 5, headerTitle)

	// Render PSI pressure gauges
	cpuStall := 0.0
	memStall := 0.0
	ioStall := 0.0

	if report != nil && report.SystemPressure.Available {
		cpuStall = report.SystemPressure.CPUStallPercent
		memStall = report.SystemPressure.MemoryStallPercent
		ioStall = report.SystemPressure.IOStallPercent
	}

	gaugeW := 16
	if width > 100 {
		gaugeW = 24
	}

	cpuGauge := fmt.Sprintf("CPU %s", theme.ProgressBar(cpuStall, gaugeW))
	memGauge := fmt.Sprintf("MEM %s", theme.ProgressBar(memStall, gaugeW))
	ioGauge := fmt.Sprintf("I/O %s", theme.ProgressBar(ioStall, gaugeW))

	line := fmt.Sprintf("  PRESSURE (PSI):  %s   %s   %s", cpuGauge, memGauge, ioGauge)
	s.PrintAt(3, 2, line)
}
