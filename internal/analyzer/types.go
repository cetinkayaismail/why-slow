// Package analyzer defines the diagnostic types, severity levels,
// Rule interface, and DiagnosticReport structure used by the
// correlation engine and diagnostic rules.
package analyzer

import (
	"why-slow/internal/collector"
)

// Severity represents the urgency and impact level of a diagnosed performance bottleneck.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityInfo     Severity = "INFO"
)

// Diagnosis represents a concrete identified bottleneck or performance issue.
type Diagnosis struct {
	RuleID         string   `json:"rule_id"`
	Tier           int      `json:"tier"` // 1 = Base Hard Limits, 2 = Contention & Queues, 3 = Kernel Edge Cases
	Severity       Severity `json:"severity"`
	Confidence     float64  `json:"confidence"` // 0.0 to 1.0 confidence score
	Title          string   `json:"title"`
	Explanation    string   `json:"explanation"`
	Evidence       []string `json:"evidence"`
	CulpritPID     int      `json:"culprit_pid,omitempty"`
	CulpritName    string   `json:"culprit_name,omitempty"`
	CulpritDetails string   `json:"culprit_details,omitempty"`
	Remediation    string   `json:"remediation"`
}

// PSISummary captures top-level Pressure Stall Information across CPU, Memory, and I/O.
type PSISummary struct {
	Available          bool    `json:"available"`
	CPUStallPercent    float64 `json:"cpu_stall_percent"`
	MemoryStallPercent float64 `json:"memory_stall_percent"`
	IOStallPercent     float64 `json:"io_stall_percent"`
}

// DiagnosticReport represents the finalized, prioritized root cause analysis for the system.
type DiagnosticReport struct {
	Timestamp           string      `json:"timestamp"`
	PrivilegeLevel      string      `json:"privilege_level"` // "root" or "unprivileged"
	Duration            string      `json:"duration"`
	PrimaryBlocker      *Diagnosis  `json:"primary_blocker,omitempty"`
	ContributingFactors []Diagnosis `json:"contributing_factors,omitempty"`
	SecondaryIssues     []Diagnosis `json:"secondary_issues,omitempty"`
	SystemPressure      PSISummary  `json:"system_pressure"`
}

// Rule defines the interface that all diagnostic analyzers across Tier 1, 2, and 3 must implement.
type Rule interface {
	ID() string
	Tier() int
	IsPIDDependent() bool
	Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool)
}

// ExtractPSISummary extracts top-level pressure percentages from a snapshot.
func ExtractPSISummary(snap *collector.SystemSnapshot) PSISummary {
	if snap == nil || !snap.PSI.Available {
		return PSISummary{Available: false}
	}

	return PSISummary{
		Available:          true,
		CPUStallPercent:    snap.PSI.CPU.Some.Avg10,
		MemoryStallPercent: snap.PSI.Memory.Some.Avg10,
		IOStallPercent:     snap.PSI.IO.Some.Avg10,
	}
}
