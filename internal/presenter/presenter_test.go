package presenter

import (
	"bytes"
	"strings"
	"testing"
	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
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
	err := RenderTerminal(&buf, report, TerminalOptions{NoColor: true, ShowRemedy: false})
	if err != nil {
		t.Fatalf("unexpected error rendering terminal: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CRITICAL BOTTLENECK: 100% CPU Runqueue Starvation") {
		t.Errorf("missing header in output: %s", out)
	}
	if !strings.Contains(out, "Rule ID: BASE_CPU_SATURATION") {
		t.Errorf("missing rule id in output: %s", out)
	}
	if !strings.Contains(out, "Diagnostic Finding:") {
		t.Errorf("missing diagnostic finding in output: %s", out)
	}
	if !strings.Contains(out, "Diagnostic Proof:") {
		t.Errorf("missing diagnostic proof in output: %s", out)
	}
	if !strings.Contains(out, "PID 1234 [ffmpeg]") {
		t.Errorf("missing culprit in output: %s", out)
	}
	if strings.Contains(out, "Recommended Remediation:") {
		t.Errorf("remediation should NOT be displayed when ShowRemedy is false: %s", out)
	}
	if !strings.Contains(out, "(Tip: Run with --remedy to view system remediation advice)") {
		t.Errorf("missing remedy tip in output: %s", out)
	}
	if !strings.Contains(out, "Running as unprivileged user") {
		t.Errorf("missing unprivileged footer in output: %s", out)
	}

	// Test with ShowRemedy = true
	var bufRemedy bytes.Buffer
	err = RenderTerminal(&bufRemedy, report, TerminalOptions{NoColor: true, ShowRemedy: true})
	if err != nil {
		t.Fatalf("unexpected error rendering terminal with remedy: %v", err)
	}
	outRemedy := bufRemedy.String()
	if !strings.Contains(outRemedy, "Recommended Remediation:") {
		t.Errorf("missing Recommended Remediation when ShowRemedy is true: %s", outRemedy)
	}
	if !strings.Contains(outRemedy, "renice -n 19 -p 1234") {
		t.Errorf("missing remediation advice in output: %s", outRemedy)
	}

	// Also test that color mode outputs ANSI escape codes
	var bufColor bytes.Buffer
	_ = RenderTerminal(&bufColor, report, TerminalOptions{NoColor: false})
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
	err := RenderTerminal(&buf, report, TerminalOptions{NoColor: true})
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

func TestRenderRuleList(t *testing.T) {
	engine := analyzer.NewEngine()
	rules := engine.Rules()

	var buf bytes.Buffer
	RenderRuleList(&buf, rules, "", true)
	out := buf.String()

	if !strings.Contains(out, "why-slow Diagnostic Rules Catalog") {
		t.Errorf("expected catalog header, got:\n%s", out)
	}
	if !strings.Contains(out, "BASE_CPU_SATURATION") {
		t.Errorf("expected BASE_CPU_SATURATION in output, got:\n%s", out)
	}
	if !strings.Contains(out, "[CPU]") {
		t.Errorf("expected [CPU] tag, got:\n%s", out)
	}
	if !strings.Contains(out, "CONT_DIRTY_PAGE_FLUSH_SATURATION") {
		t.Errorf("expected CONT_DIRTY_PAGE_FLUSH_SATURATION in output, got:\n%s", out)
	}
	if !strings.Contains(out, "[Memory]") {
		t.Errorf("expected [Memory] tag, got:\n%s", out)
	}
}

func TestRenderRuleList_Filter(t *testing.T) {
	engine := analyzer.NewEngine()
	rules := engine.Rules()

	var buf bytes.Buffer
	RenderRuleList(&buf, rules, "disk", true)
	out := buf.String()

	if !strings.Contains(out, `Filter: "disk"`) {
		t.Errorf("expected filter header, got:\n%s", out)
	}
	if strings.Contains(out, "BASE_CPU_SATURATION") {
		t.Errorf("expected BASE_CPU_SATURATION to be filtered out, got:\n%s", out)
	}
	if !strings.Contains(out, "BASE_DISK_SPACE_FULL") {
		t.Errorf("expected BASE_DISK_SPACE_FULL to be included, got:\n%s", out)
	}
}

func TestRuleCategory(t *testing.T) {
	tests := []struct {
		id       string
		expected string
	}{
		{"BASE_CPU_SATURATION", "CPU"},
		{"BASE_OOM_DANGER", "Memory"},
		{"BASE_DISK_SPACE_FULL", "Storage"},
		{"BASE_TCP_SOCKET_MEM_PRESS", "Network"},
		{"CONT_CGROUP_THROTTLED", "Cgroup"},
		{"CONT_DSTATE_PILEUP", "Process"},
		{"EDGE_HPET_CLOCKSOURCE_DEGRADE", "Kernel"},
	}

	for _, tt := range tests {
		got := RuleCategory(tt.id)
		if got != tt.expected {
			t.Errorf("RuleCategory(%q) = %q; want %q", tt.id, got, tt.expected)
		}
	}
}

func TestRenderRuleExplanation(t *testing.T) {
	engine := analyzer.NewEngine()
	rule := engine.GetRule("BASE_CPU_SATURATION")
	if rule == nil {
		t.Fatalf("expected to find rule BASE_CPU_SATURATION")
	}

	var buf bytes.Buffer
	RenderRuleExplanation(&buf, rule, true)
	out := buf.String()

	if !strings.Contains(out, "Rule ID:      BASE_CPU_SATURATION") {
		t.Errorf("missing Rule ID, got:\n%s", out)
	}
	if !strings.Contains(out, "Subsystem:    CPU") {
		t.Errorf("missing Subsystem, got:\n%s", out)
	}
	if !strings.Contains(out, "Description:") {
		t.Errorf("missing Description, got:\n%s", out)
	}
}

func TestRenderTerminalPIDFocus(t *testing.T) {
	report := &analyzer.DiagnosticReport{
		Timestamp:      "2026-08-22T12:00:00Z",
		PrivilegeLevel: "root",
		Duration:       "1.00s",
		PIDFocus: &analyzer.PIDFocusReport{
			PID:        12345,
			Comm:       "nginx",
			State:      "S",
			PPID:       1,
			NumThreads: 4,
			CPUPercent: 12.5,
			RSSMB:      256.0,
			SwapMB:     32.0,
			ReadKB:     100.0,
			WriteKB:    50.0,
			OpenFDs:    20,
			MaxFDs:     1024,
			FDRatio:    0.0195,
			SmapsRollup: collector.SmapsRollupInfo{
				Available:    true,
				PSS:          200000,
				SharedDirty:  50000,
				PrivateDirty: 150000,
			},
			FDTypes: collector.ProcessFDTypeCounts{
				Total:      20,
				Files:      10,
				Sockets:    8,
				Pipes:      2,
				AnonInodes: 0,
				Other:      0,
			},
			RelatedIssues: []analyzer.Diagnosis{
				{
					RuleID:      "CONT_PROCESS_SWAP_PINNED",
					Severity:    analyzer.SeverityHigh,
					Title:       "Process Swap-Pinned",
					Explanation: "Process has swapped memory",
				},
			},
		},
	}

	var buf bytes.Buffer
	err := RenderTerminal(&buf, report, TerminalOptions{NoColor: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Process Deep Dive: PID 12345 (nginx)") {
		t.Errorf("missing deep dive header in output:\n%s", out)
	}
	if !strings.Contains(out, "FD Breakdown: Files: 10 | Sockets: 8 | Pipes: 2") {
		t.Errorf("missing FD breakdown in output:\n%s", out)
	}
	if !strings.Contains(out, "Related Diagnostic Findings (1):") {
		t.Errorf("missing related findings in output:\n%s", out)
	}
	if !strings.Contains(out, "CONT_PROCESS_SWAP_PINNED") {
		t.Errorf("missing related rule ID in output:\n%s", out)
	}
}

