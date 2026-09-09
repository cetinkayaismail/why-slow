package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
	"why-slow/internal/presenter"
)

func TestExtractTopProcesses(t *testing.T) {
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{PID: 10, Comm: "proc_a", CPUPercent: 10.0, RSSBytes: 50 * 1024 * 1024, State: 'S'},
			{PID: 20, Comm: "proc_b", CPUPercent: 50.0, RSSBytes: 100 * 1024 * 1024, State: 'R'},
			{PID: 30, Comm: "proc_c", CPUPercent: 50.0, RSSBytes: 200 * 1024 * 1024, State: 'D'},
			{PID: 40, Comm: "proc_d", CPUPercent: 5.0, RSSBytes: 10 * 1024 * 1024, State: 'S'},
		},
	}

	// Request top 2: should be PID 30 (50% CPU, 200MB RSS) then PID 20 (50% CPU, 100MB RSS)
	top := extractTopProcesses(diff, 2)
	if len(top) != 2 {
		t.Fatalf("expected 2 processes, got %d", len(top))
	}
	if top[0].PID != 30 {
		t.Errorf("expected top[0].PID == 30, got %d", top[0].PID)
	}
	if top[1].PID != 20 {
		t.Errorf("expected top[1].PID == 20, got %d", top[1].PID)
	}

	// Check fields
	if top[0].Comm != "proc_c" || top[0].State != "D" {
		t.Errorf("unexpected proc_c fields: %+v", top[0])
	}
	if top[0].RSSMB != 200.0 {
		t.Errorf("expected RSSMB == 200.0, got %f", top[0].RSSMB)
	}

	// Edge cases
	if extractTopProcesses(nil, 5) != nil {
		t.Errorf("expected nil for nil diff")
	}
	if extractTopProcesses(diff, 0) != nil {
		t.Errorf("expected nil for n <= 0")
	}
}

func TestValidateConfig(t *testing.T) {
	engine := analyzer.NewEngine()

	// 1. Negative interval
	cfg := &cliConfig{interval: -1 * time.Second, samples: 1}
	if err := validateConfig(cfg, false, engine); err == nil {
		t.Errorf("expected error on negative interval")
	}

	// 2. Negative samples
	cfg = &cliConfig{interval: 1 * time.Second, samples: 0}
	if err := validateConfig(cfg, false, engine); err == nil {
		t.Errorf("expected error on samples <= 0")
	}

	// 3. Negative top when passed
	cfg = &cliConfig{interval: 1 * time.Second, samples: 1, top: 0}
	if err := validateConfig(cfg, true, engine); err == nil {
		t.Errorf("expected error on top <= 0 when topPassed=true")
	}

	// 4. Top 0 when not passed should succeed
	cfg = &cliConfig{interval: 1 * time.Second, samples: 1, top: 0}
	if err := validateConfig(cfg, false, engine); err != nil {
		t.Errorf("unexpected error on top 0 when topPassed=false: %v", err)
	}

	// 5. Valid disable rules
	cfg = &cliConfig{interval: 1 * time.Second, samples: 1, disableRules: "BASE_CPU_SATURATION"}
	if err := validateConfig(cfg, false, engine); err != nil {
		t.Errorf("unexpected error on valid disable-rules: %v", err)
	}
}

func TestHandleRuleCommands(t *testing.T) {
	engine := analyzer.NewEngine()

	// 1. Neither flag set
	cfg := &cliConfig{}
	if handleRuleCommands(cfg, engine) {
		t.Errorf("expected false when neither listRules nor explain is set")
	}

	// 2. List rules
	cfg = &cliConfig{listRules: true, noColor: true}
	var buf bytes.Buffer
	presenter.RenderRuleList(&buf, engine.Rules(), "", true)
	if buf.Len() == 0 {
		t.Errorf("expected RenderRuleList output")
	}
	buf.Reset()
	presenter.RenderRuleList(&buf, engine.Rules(), "cpu", true)
	if !strings.Contains(buf.String(), "BASE_CPU_SATURATION") {
		t.Errorf("expected filtered RenderRuleList output to contain BASE_CPU_SATURATION")
	}

	// 3. Explain valid rule
	cfg = &cliConfig{explain: "BASE_CPU_SATURATION", noColor: true}
	rule := engine.GetRule(cfg.explain)
	if rule == nil {
		t.Fatalf("expected to find rule BASE_CPU_SATURATION")
	}
	buf.Reset()
	presenter.RenderRuleExplanation(&buf, rule, true)
	if buf.Len() == 0 {
		t.Errorf("expected RenderRuleExplanation output")
	}
}

func TestValidateConfig_PID(t *testing.T) {
	engine := analyzer.NewEngine()

	// Negative PID -> error
	cfgNeg := &cliConfig{interval: 1 * time.Second, samples: 1, pid: -5}
	if err := validateConfig(cfgNeg, false, engine); err == nil {
		t.Errorf("expected error for negative pid")
	}

	// Nonexistent PID -> error
	cfgNonexistent := &cliConfig{interval: 1 * time.Second, samples: 1, pid: 99999999}
	if err := validateConfig(cfgNonexistent, false, engine); err == nil {
		t.Errorf("expected error for nonexistent pid")
	}

	// Valid PID (current process) -> success
	cfgValid := &cliConfig{interval: 1 * time.Second, samples: 1, pid: 1} // PID 1 is init/systemd, always present
	if err := validateConfig(cfgValid, false, engine); err != nil {
		t.Errorf("unexpected error for PID 1: %v", err)
	}
}

func TestExtractPIDFocus(t *testing.T) {
	diff := &collector.SnapshotDiff{
		Processes: []collector.ProcessDiff{
			{
				PID:             1234,
				Comm:            "target_app",
				State:           'S',
				PPID:            1,
				NumThreads:      4,
				CPUPercent:      25.5,
				RSSBytes:        100 * 1024 * 1024,
				ReadBytesDelta:  10240,
				WriteBytesDelta: 20480,
				OpenFDs:         15,
				MaxFDs:          1024,
				FDRatio:         0.015,
				SmapsRollup: collector.SmapsRollupInfo{
					Available: true,
					Swap:      51200,
					PSS:       90000,
				},
			},
		},
	}

	diag := analyzer.Diagnosis{
		RuleID:      "CONT_PROCESS_SWAP_PINNED",
		Severity:    analyzer.SeverityHigh,
		Confidence:  0.85,
		Title:       "Process Swap Pinned",
		CulpritPID:  1234,
		CulpritName: "target_app",
	}

	report := &analyzer.DiagnosticReport{
		PrimaryBlocker: &diag,
	}

	pf := extractPIDFocus(diff, 1234, report)
	if pf == nil {
		t.Fatalf("expected non-nil PIDFocusReport")
	}
	if pf.PID != 1234 || pf.Comm != "target_app" {
		t.Errorf("expected PID 1234 target_app, got %d %s", pf.PID, pf.Comm)
	}
	if pf.CPUPercent != 25.5 {
		t.Errorf("expected CPUPercent 25.5, got %f", pf.CPUPercent)
	}
	if pf.RSSMB != 100.0 {
		t.Errorf("expected RSSMB 100.0, got %f", pf.RSSMB)
	}
	if pf.SwapMB != 50.0 {
		t.Errorf("expected SwapMB 50.0, got %f", pf.SwapMB)
	}
	if len(pf.RelatedIssues) != 1 || pf.RelatedIssues[0].RuleID != "CONT_PROCESS_SWAP_PINNED" {
		t.Errorf("expected 1 related issue with CONT_PROCESS_SWAP_PINNED, got %+v", pf.RelatedIssues)
	}

	// Test PID not in diff (e.g. process died)
	pfMissing := extractPIDFocus(diff, 9999, report)
	if pfMissing == nil {
		t.Fatalf("expected non-nil report for PID not in diff")
	}
	if pfMissing.PID != 9999 {
		t.Errorf("expected PID 9999, got %d", pfMissing.PID)
	}
}

