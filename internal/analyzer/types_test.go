package analyzer

import (
	"encoding/json"
	"testing"
	"why-slow/internal/collector"
)

func TestExtractPSISummary(t *testing.T) {
	snapNil := ExtractPSISummary(nil)
	if snapNil.Available {
		t.Errorf("expected Available=false for nil snapshot")
	}

	snapUnavail := &collector.SystemSnapshot{
		PSI: collector.PSIInfo{Available: false},
	}
	summaryUnavail := ExtractPSISummary(snapUnavail)
	if summaryUnavail.Available {
		t.Errorf("expected Available=false when PSI not available")
	}

	snap := &collector.SystemSnapshot{
		PSI: collector.PSIInfo{
			Available: true,
			CPU: collector.PSIResource{
				Some: collector.PSIMetrics{Avg10: 12.5},
			},
			Memory: collector.PSIResource{
				Some: collector.PSIMetrics{Avg10: 45.0},
			},
			IO: collector.PSIResource{
				Some: collector.PSIMetrics{Avg10: 88.2},
			},
		},
	}

	summary := ExtractPSISummary(snap)
	if !summary.Available {
		t.Fatalf("expected Available=true")
	}
	if summary.CPUStallPercent != 12.5 {
		t.Errorf("expected CPU 12.5, got %f", summary.CPUStallPercent)
	}
	if summary.MemoryStallPercent != 45.0 {
		t.Errorf("expected Memory 45.0, got %f", summary.MemoryStallPercent)
	}
	if summary.IOStallPercent != 88.2 {
		t.Errorf("expected IO 88.2, got %f", summary.IOStallPercent)
	}
}

func TestDiagnosticReportJSON(t *testing.T) {
	report := DiagnosticReport{
		Timestamp:      "2026-08-22T12:00:00Z",
		PrivilegeLevel: "unprivileged",
		Duration:       "1.00s",
		PrimaryBlocker: &Diagnosis{
			RuleID:         "BASE_CPU_SATURATION",
			Tier:           1,
			Severity:       SeverityCritical,
			Confidence:     0.95,
			Title:          "100% CPU Runqueue Starvation",
			Explanation:    "All CPU cores are fully saturated and runqueue is backlogged.",
			Evidence:       []string{"CPU idle: 0.5%", "procs_running: 16 (cores: 8)"},
			CulpritPID:     1234,
			CulpritName:    "ffmpeg",
			CulpritDetails: "Generating 780% CPU utilization across threads",
			Remediation:    "Lower process CPU priority: nice -n 19 -p 1234",
		},
		ContributingFactors: []Diagnosis{
			{
				RuleID:      "CONT_DSTATE_PILEUP",
				Tier:        2,
				Severity:    SeverityHigh,
				Confidence:  0.85,
				Title:       "Uninterruptible I/O Lock",
				Explanation: "Tasks are stalled waiting on block writeback.",
				Evidence:    []string{"3 threads blocked in ext4_writepages"},
				Remediation: "Check disk health or lower process I/O priority with ionice",
			},
		},
		SystemPressure: PSISummary{
			Available:       true,
			CPUStallPercent: 65.0,
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal DiagnosticReport: %v", err)
	}

	var decoded DiagnosticReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal DiagnosticReport: %v", err)
	}

	if decoded.PrivilegeLevel != "unprivileged" {
		t.Errorf("expected PrivilegeLevel 'unprivileged', got '%s'", decoded.PrivilegeLevel)
	}
	if decoded.PrimaryBlocker == nil || decoded.PrimaryBlocker.RuleID != "BASE_CPU_SATURATION" {
		t.Errorf("expected PrimaryBlocker 'BASE_CPU_SATURATION'")
	}
	if len(decoded.ContributingFactors) != 1 {
		t.Errorf("expected 1 contributing factor, got %d", len(decoded.ContributingFactors))
	}
	if decoded.SystemPressure.CPUStallPercent != 65.0 {
		t.Errorf("expected CPUStallPercent 65.0, got %f", decoded.SystemPressure.CPUStallPercent)
	}
}
