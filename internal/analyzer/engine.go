// Package analyzer — engine.go is the correlation engine that runs all
// registered diagnostic rules against a SnapshotDiff, sorts findings by
// Tier → Severity → Confidence, performs root cause isolation (Tier 1
// demotes Tier 2/3 to secondary), and builds the final DiagnosticReport.
package analyzer

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"why-slow/internal/collector"
)

const skipTier3Threshold = 0.90

// Engine orchestrates multi-tier rule evaluation, prioritization, and correlation.
type Engine struct {
	rules            []Rule
	tier1Rules       []Rule
	tier2Rules       []Rule
	tier3Rules       []Rule
	disabledRules    map[string]bool
	disabledList     []string
	DisableEarlyExit bool
}

// NewEngine creates an Engine pre-loaded with all Tier 1, Tier 2, and Tier 3 rules.
func NewEngine() *Engine {
	e := &Engine{
		rules:         make([]Rule, 0, 16),
		tier1Rules:    make([]Rule, 0, 16),
		tier2Rules:    make([]Rule, 0, 16),
		tier3Rules:    make([]Rule, 0, 16),
		disabledRules: make(map[string]bool),
		disabledList:  make([]string, 0),
	}
	e.RegisterRules(GetTier1Rules())
	e.RegisterRules(GetTier2Rules())
	e.RegisterRules(GetTier3Rules())
	return e
}

// RegisterRules adds diagnostic rules to the engine.
func (e *Engine) RegisterRules(rules []Rule) {
	e.rules = append(e.rules, rules...)
	for _, r := range rules {
		switch r.Tier() {
		case 1:
			e.tier1Rules = append(e.tier1Rules, r)
		case 2:
			e.tier2Rules = append(e.tier2Rules, r)
		case 3:
			e.tier3Rules = append(e.tier3Rules, r)
		}
	}
}

// SetDisabledRules validates and records rule IDs to be suppressed during evaluation.
// Returns an error if any rule ID is not registered in the engine.
func (e *Engine) SetDisabledRules(ids []string) error {
	registered := make(map[string]Rule, len(e.rules))
	for _, r := range e.rules {
		registered[r.ID()] = r
	}

	e.disabledRules = make(map[string]bool, len(ids))
	e.disabledList = make([]string, 0, len(ids))

	for _, rawID := range ids {
		id := strings.TrimSpace(rawID)
		if id == "" {
			continue
		}
		rule, exists := registered[id]
		if !exists {
			return fmt.Errorf("analyzer: unknown rule ID in --disable-rules: %q (use --list-rules to view valid IDs)", id)
		}

		if rule.Tier() == 1 {
			fmt.Fprintf(os.Stderr, "WARNING: disabling Tier 1 rule %s (base hard limit)\n", id)
		}

		e.disabledRules[id] = true
		e.disabledList = append(e.disabledList, id)
	}

	return nil
}

// DisabledRules returns the list of active disabled rule IDs.
func (e *Engine) DisabledRules() []string {
	return e.disabledList
}

// GetRule returns a registered rule by its ID, or nil if not found.
func (e *Engine) GetRule(id string) Rule {
	for _, r := range e.rules {
		if r.ID() == id {
			return r
		}
	}
	return nil
}

// Rules returns all registered rules in the engine.
func (e *Engine) Rules() []Rule {
	return e.rules
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
		if diff.LatestSnapshot.PSI.Available {
			report.Calibrated = true
		}
	}
	if len(e.disabledList) > 0 {
		report.DisabledRules = e.disabledList
	}

	if diff == nil {
		return report
	}

	// 1. Evaluate Tier 1 rules
	var triggered []Diagnosis
	hasHighConfTier1 := false
	for _, rule := range e.tier1Rules {
		if e.disabledRules[rule.ID()] {
			continue
		}
		if diag := e.evaluateRule(rule, diff, runCtx); diag != nil {
			triggered = append(triggered, *diag)
			if diag.Confidence >= skipTier3Threshold {
				hasHighConfTier1 = true
			}
		}
	}

	// 2. Evaluate Tier 2 rules
	for _, rule := range e.tier2Rules {
		if e.disabledRules[rule.ID()] {
			continue
		}
		if diag := e.evaluateRule(rule, diff, runCtx); diag != nil {
			triggered = append(triggered, *diag)
		}
	}

	// 3. Evaluate Tier 3 rules (skip if Tier 1 fired with Confidence >= 0.90 unless DisableEarlyExit)
	if !e.DisableEarlyExit && hasHighConfTier1 {
		report.Tier3Evaluated = false
	} else {
		report.Tier3Evaluated = true
		for _, rule := range e.tier3Rules {
			if e.disabledRules[rule.ID()] {
				continue
			}
			if diag := e.evaluateRule(rule, diff, runCtx); diag != nil {
				triggered = append(triggered, *diag)
			}
		}
	}

	if len(triggered) == 0 {
		return report
	}

	// 4. Apply PSI-based confidence calibration before sorting
	if report.Calibrated && diff.LatestSnapshot != nil {
		calibrateDiagnoses(triggered, diff.LatestSnapshot.PSI)
	}

	// 5. Sort by Tier ASC -> Severity Rank DESC -> Confidence DESC
	sortDiagnoses(triggered)

	// 6. Root Cause Isolation & Demotion (with causal suppression)
	categorizeDiagnoses(triggered, report, e.rules)

	return report
}

func (e *Engine) evaluateRule(rule Rule, diff *collector.SnapshotDiff, runCtx collector.RunContext) *Diagnosis {
	diag, ok := rule.Evaluate(diff)
	if !ok || diag == nil {
		return nil
	}
	// Clock jump makes all rate-based metrics unreliable
	if diff.ClockJumpDetected {
		diag.Confidence *= 0.50
	}
	// Apply unprivileged confidence penalty for PID-dependent rules
	if !runCtx.IsRoot && rule.IsPIDDependent() {
		diag.Confidence *= 0.60
	}
	return diag
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

func hasRuleToken(id, token string) bool {
	for _, part := range strings.Split(id, "_") {
		if part == token {
			return true
		}
	}
	return false
}

func isMemoryRule(id string) bool {
	return strings.Contains(id, "OOM") || strings.Contains(id, "SWAP") ||
		strings.Contains(id, "MEM") || strings.Contains(id, "CGROUP_MEM") ||
		strings.Contains(id, "THP") || strings.Contains(id, "SLAB") ||
		strings.Contains(id, "PAGECACHE") || strings.Contains(id, "HUGETLB") ||
		strings.Contains(id, "ZSWAP") || strings.Contains(id, "REFAULT") ||
		strings.Contains(id, "DMA32") || strings.Contains(id, "CMA")
}

func isIORule(id string) bool {
	return strings.Contains(id, "DISK") || hasRuleToken(id, "IO") ||
		hasRuleToken(id, "AIO") || strings.Contains(id, "DSTATE") ||
		strings.Contains(id, "BLK") || hasRuleToken(id, "DM") ||
		strings.Contains(id, "STORAGE") || strings.Contains(id, "WRITEBACK")
}

func isCPURule(id string) bool {
	return (strings.Contains(id, "CPU") || strings.Contains(id, "SCHED") ||
		strings.Contains(id, "RUNQUEUE") || strings.Contains(id, "KSOFTIRQD")) &&
		!hasRuleToken(id, "IO") && !strings.Contains(id, "KSWAPD")
}

func calibrateDiagnoses(items []Diagnosis, psi collector.PSIInfo) {
	for i := range items {
		id := items[i].RuleID
		conf := items[i].Confidence

		switch {
		case isMemoryRule(id):
			if psi.Memory.Some.Avg10 > 20.0 {
				conf *= 1.10
			} else if psi.Memory.Some.Avg10 < 1.0 {
				conf *= 0.70
			}
		case isIORule(id):
			if psi.IO.Some.Avg10 > 20.0 {
				conf *= 1.10
			} else if psi.IO.Some.Avg10 < 1.0 {
				conf *= 0.70
			}
		case isCPURule(id):
			if psi.CPU.Some.Avg10 > 20.0 {
				conf *= 1.10
			} else if psi.CPU.Some.Avg10 < 1.0 {
				conf *= 0.70
			}
		}

		items[i].Confidence = clampConfidence(conf)
	}
}

func clampConfidence(conf float64) float64 {
	if conf > 1.0 {
		return 1.0
	}
	if conf < 0.0 {
		return 0.0
	}
	return conf
}
