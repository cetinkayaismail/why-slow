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

// RuleExplanation provides structured human-readable documentation for a diagnostic rule.
type RuleExplanation struct {
	Description   string   `json:"description"`
	Thresholds    []string `json:"thresholds"`
	KernelSources []string `json:"kernel_sources"`
	Remediation   string   `json:"remediation"`
}

// TopProcessReport represents a process summary for the --top N report.
type TopProcessReport struct {
	PID             int     `json:"pid"`
	Comm            string  `json:"comm"`
	CPUPercent      float64 `json:"cpu_percent"`
	RSSMB           float64 `json:"rss_mb"`
	ReadKB          float64 `json:"read_kb"`
	WriteKB         float64 `json:"write_kb"`
	RSSBytes        uint64  `json:"rss_bytes,omitempty"`
	ReadBytesDelta  uint64  `json:"read_bytes_delta,omitempty"`
	WriteBytesDelta uint64  `json:"write_bytes_delta,omitempty"`
	OpenFDs         int     `json:"open_fds"`
	State           string  `json:"state"`
}

// PIDFocusReport captures targeted deep-dive telemetry and related diagnostic findings for a specific PID.
type PIDFocusReport struct {
	PID           int                           `json:"pid"`
	Comm          string                        `json:"comm"`
	State         string                        `json:"state"`
	PPID          int                           `json:"ppid"`
	NumThreads    int                           `json:"num_threads"`
	CPUPercent    float64                       `json:"cpu_percent"`
	RSSMB         float64                       `json:"rss_mb"`
	SwapMB        float64                       `json:"swap_mb"`
	ReadKB        float64                       `json:"read_kb"`
	WriteKB       float64                       `json:"write_kb"`
	OpenFDs       int                           `json:"open_fds"`
	MaxFDs        uint64                        `json:"max_fds"`
	FDRatio       float64                       `json:"fd_ratio"`
	Wchan         string                        `json:"wchan,omitempty"`
	CgroupPath    string                        `json:"cgroup_path,omitempty"`
	OOMScore      int                           `json:"oom_score"`
	OOMScoreAdj   int                           `json:"oom_score_adj"`
	SmapsRollup   collector.SmapsRollupInfo     `json:"smaps_rollup"`
	FDTypes       collector.ProcessFDTypeCounts `json:"fd_types"`
	RelatedIssues []Diagnosis                   `json:"related_issues,omitempty"`
}

// DiagnosticReport represents the finalized, prioritized root cause analysis for the system.
type DiagnosticReport struct {
	Timestamp           string             `json:"timestamp"`
	PrivilegeLevel      string             `json:"privilege_level"` // "root" or "unprivileged"
	Duration            string             `json:"duration"`
	PrimaryBlocker      *Diagnosis         `json:"primary_blocker,omitempty"`
	ContributingFactors []Diagnosis        `json:"contributing_factors,omitempty"`
	SecondaryIssues     []Diagnosis        `json:"secondary_issues,omitempty"`
	SystemPressure      PSISummary         `json:"system_pressure"`
	TopProcesses        []TopProcessReport `json:"top_processes,omitempty"`
	PIDFocus            *PIDFocusReport    `json:"pid_focus,omitempty"`
	DisabledRules       []string           `json:"disabled_rules,omitempty"`
	Tier3Evaluated      bool               `json:"tier3_evaluated"`
	Calibrated          bool               `json:"calibrated"`
}

// Rule defines the interface that all diagnostic analyzers across Tier 1, 2, and 3 must implement.
type Rule interface {
	ID() string
	Tier() int
	IsPIDDependent() bool
	Evaluate(diff *collector.SnapshotDiff) (*Diagnosis, bool)
	// Suppresses returns rule IDs that this rule makes redundant when it fires.
	// This enables causal chain suppression: when a root cause fires, its
	// downstream symptoms are removed from contributing factors.
	Suppresses() []string
	// Explain returns human-readable documentation, thresholds, kernel sources, and remediation steps.
	Explain() RuleExplanation
}

// noSuppression is an embeddable base struct that provides a default nil
// Suppresses() implementation. Embed this in any rule that does not suppress other rules.
type noSuppression struct{}

// Suppresses implements Rule.Suppresses with a nil return (no suppressions).
func (noSuppression) Suppresses() []string { return nil }

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
