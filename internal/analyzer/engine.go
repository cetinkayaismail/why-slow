// Package analyzer — engine.go is the correlation engine that runs all
// registered diagnostic rules against a SnapshotDiff, sorts findings by
// Tier → Severity → Confidence, performs root cause isolation (Tier 1
// demotes Tier 2/3 to secondary), and builds the final DiagnosticReport.
package analyzer

import (
	"fmt"
	"sort"
	"time"
	"why-slow/internal/collector"
)

// Engine orchestrates multi-tier rule evaluation, prioritization, and correlation.
type Engine struct {
	rules []Rule
}

// NewEngine creates an Engine pre-loaded with all Tier 1, Tier 2, and Tier 3 rules.
func NewEngine() *Engine {
	e := &Engine{
		rules: make([]Rule, 0, 16),
	}
	e.RegisterRules(GetTier1Rules())
	e.RegisterRules(GetTier2Rules())
	e.RegisterRules(GetTier3Rules())
	return e
}

// RegisterRules adds diagnostic rules to the engine.
func (e *Engine) RegisterRules(rules []Rule) {
	e.rules = append(e.rules, rules...)
}

// Analyze runs all registered rules against the snapshot differential and builds a DiagnosticReport.
func (e *Engine) Analyze(diff *collector.SnapshotDiff, runCtx collector.RunContext) *DiagnosticReport {
	report := &DiagnosticReport{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		PrivilegeLevel: "unprivileged",
		Duration:       "1.00s",
	}

	if runCtx.IsRoot {
		report.PrivilegeLevel = "root"
	}
	if diff != nil && diff.Duration > 0 {
		report.Duration = fmt.Sprintf("%.2fs", diff.Duration.Seconds())
	}
	if diff != nil && diff.LatestSnapshot != nil {
		report.SystemPressure = ExtractPSISummary(diff.LatestSnapshot)
	}

	if diff == nil {
		return report
	}

	// 1. Evaluate all rules
	var triggered []Diagnosis
	for _, rule := range e.rules {
		diag, ok := rule.Evaluate(diff)
		if ok && diag != nil {
			// Clock jump makes all rate-based metrics unreliable
			if diff.ClockJumpDetected {
				diag.Confidence *= 0.50
			}
			// Apply unprivileged confidence penalty for PID-dependent rules
			if !runCtx.IsRoot && rule.IsPIDDependent() {
				diag.Confidence *= 0.60
			}
			triggered = append(triggered, *diag)
		}
	}

	if len(triggered) == 0 {
		return report
	}

	// 2. Sort by Tier ASC -> Severity Rank DESC -> Confidence DESC
	sortDiagnoses(triggered)

	// 3. Root Cause Isolation & Demotion (with causal suppression)
	categorizeDiagnoses(triggered, report, e.rules)

	return report
}

func sortDiagnoses(items []Diagnosis) {
	sort.SliceStable(items, func(i, j int) bool {
		// 1. Tier ASC (Tier 1 > Tier 2 > Tier 3)
		if items[i].Tier != items[j].Tier {
			return items[i].Tier < items[j].Tier
		}
		// 2. Severity Rank DESC
		rankI := severityRank(items[i].Severity)
		rankJ := severityRank(items[j].Severity)
		if rankI != rankJ {
			return rankI > rankJ
		}
		// 3. Confidence DESC
		return items[i].Confidence > items[j].Confidence
	})
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func categorizeDiagnoses(sorted []Diagnosis, report *DiagnosticReport, rules []Rule) {
	if len(sorted) == 0 {
		return
	}

	// Top finding is the PrimaryBlocker
	primary := sorted[0]
	report.PrimaryBlocker = &primary

	remaining := sorted[1:]
	if len(remaining) == 0 {
		return
	}

	// Build suppression set from primary blocker and all contributing rules
	suppressedIDs := buildSuppressionSet(primary.RuleID, rules)

	report.ContributingFactors = make([]Diagnosis, 0, len(remaining))
	report.SecondaryIssues = make([]Diagnosis, 0, len(remaining))

	for _, d := range remaining {
		// Skip rules that are suppressed by the primary blocker
		if suppressedIDs[d.RuleID] {
			continue
		}

		if primary.Tier == 1 {
			// If Tier 1 hard blocker exists, Tier 2/3 findings are contributing or secondary
			if d.Severity == SeverityCritical || d.Severity == SeverityHigh {
				report.ContributingFactors = append(report.ContributingFactors, d)
			} else {
				report.SecondaryIssues = append(report.SecondaryIssues, d)
			}
		} else {
			if d.Tier == primary.Tier || severityRank(d.Severity) >= severityRank(SeverityHigh) {
				report.ContributingFactors = append(report.ContributingFactors, d)
			} else {
				report.SecondaryIssues = append(report.SecondaryIssues, d)
			}
		}
	}
}

// buildSuppressionSet returns a set of rule IDs that should be suppressed
// based on the primary blocker's causal chain.
func buildSuppressionSet(primaryRuleID string, rules []Rule) map[string]bool {
	suppressed := make(map[string]bool)
	for _, rule := range rules {
		if rule.ID() == primaryRuleID {
			for _, sid := range rule.Suppresses() {
				suppressed[sid] = true
			}
			break
		}
	}
	return suppressed
}
