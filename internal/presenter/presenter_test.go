package presenter

import (
	"bytes"
	"strings"
	"testing"
	"why-slow/internal/analyzer"
)

func TestRenderTerminalBlocker(t *testing.T) {
	report := &analyzer.DiagnosticReport{
		Timestamp:      "2026-08-22T12:00:00Z",
		PrivilegeLevel: "unprivileged",
		Duration:       "1.00s",
		PrimaryBlocker: &analyzer.Diagnosis{
			RuleID:         "BASE_CPU_SATURATION",
			Tier:           1,
			Severity:       analyzer.SeverityCritical,
			Confidence:     0.95,
			Title:          "100% CPU Runqueue Starvation",
			Explanation:    "All CPU cores are saturated.",
			Evidence:       []string{"CPU Idle: 0.2%", "procs_running: 16"},
			CulpritPID:     1234,
			CulpritName:    "ffmpeg",
			CulpritDetails: "Generating 800% CPU load",
			Remediation:    "renice -n 19 -p 1234",
		},
		ContributingFactors: []analyzer.Diagnosis{
			{
				RuleID:      "CONT_DSTATE_PILEUP",
				Title:       "D-State Pileup",
				Severity:    analyzer.SeverityHigh,
				Explanation: "Tasks waiting on disk",
			},
		},
		SystemPressure: analyzer.PSISummary{
			Available:       true,
			CPUStallPercent: 45.0,
		},
	}

	var buf bytes.Buffer
	err := RenderTerminal(&buf, report, true) // noColor = true for plain text assertions
	if err != nil {
		t.Fatalf("unexpected error rendering terminal: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CRITICAL BOTTLENECK: 100% CPU Runqueue Starvation") {
		t.Errorf("missing header in output: %s", out)
	}
	if !strings.Contains(out, "PID 1234 [ffmpeg]") {
		t.Errorf("missing culprit in output: %s", out)
	}
	if !strings.Contains(out, "renice -n 19 -p 1234") {
		t.Errorf("missing remediation in output: %s", out)
	}
	if !strings.Contains(out, "Running as unprivileged user") {
		t.Errorf("missing unprivileged footer in output: %s", out)
	}

	// Also test that color mode outputs ANSI escape codes
	var bufColor bytes.Buffer
	_ = RenderTerminal(&bufColor, report, false)
	if !strings.Contains(bufColor.String(), "\033[1;31m") {
		t.Errorf("expected ANSI red escape code in color output")
	}
}

func TestRenderTerminalHealthy(t *testing.T) {
	report := &analyzer.DiagnosticReport{
		Timestamp:      "2026-08-22T12:00:00Z",
		PrivilegeLevel: "root",
		Duration:       "1.00s",
		SystemPressure: analyzer.PSISummary{
			Available:          true,
			CPUStallPercent:    0.0,
			MemoryStallPercent: 0.0,
			IOStallPercent:     0.0,
		},
	}

	var buf bytes.Buffer
	err := RenderTerminal(&buf, report, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "SYSTEM HEALTHY: No critical bottlenecks detected") {
		t.Errorf("missing healthy header: %s", out)
	}
	// As root, should NOT show unprivileged warning
	if strings.Contains(out, "Running as unprivileged user") {
		t.Errorf("unexpected unprivileged warning for root user: %s", out)
	}
}

func TestRenderJSON(t *testing.T) {
	report := &analyzer.DiagnosticReport{
		Timestamp:      "2026-08-22T12:00:00Z",
		PrivilegeLevel: "unprivileged",
		Duration:       "1.00s",
		PrimaryBlocker: &analyzer.Diagnosis{
			RuleID:   "BASE_DISK_SPACE_FULL",
			Severity: analyzer.SeverityCritical,
			Title:    "Disk Full",
		},
	}

	var bufPretty bytes.Buffer
	if err := RenderJSON(&bufPretty, report, true); err != nil {
		t.Fatalf("failed to render pretty JSON: %v", err)
	}
	if !strings.Contains(bufPretty.String(), "  \"rule_id\": \"BASE_DISK_SPACE_FULL\"") {
		t.Errorf("expected indented JSON, got: %s", bufPretty.String())
	}

	var bufCompact bytes.Buffer
	if err := RenderJSON(&bufCompact, report, false); err != nil {
		t.Fatalf("failed to render compact JSON: %v", err)
	}
	if strings.Contains(bufCompact.String(), "\n ") {
		t.Errorf("expected single-line compact JSON, got: %s", bufCompact.String())
	}
}
