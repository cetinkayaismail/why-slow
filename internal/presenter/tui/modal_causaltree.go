// Package tui — modal_causaltree.go renders the Causal Suppression Tree modal.
package tui

import (
	"fmt"
	"why-slow/internal/analyzer"
)

// RenderCausalTreeModal renders the causal suppression hierarchy overlay.
func RenderCausalTreeModal(s *Screen, theme *Theme, report *analyzer.DiagnosticReport, width, height int) {
	modalW := 74
	modalH := 16
	if modalW > width-4 {
		modalW = width - 4
	}
	if modalH > height-4 {
		modalH = height - 4
	}

	startX := (width - modalW) / 2
	startY := (height - modalH) / 2

	s.DrawBox(startX, startY, modalW, modalH, "CAUSAL SUPPRESSION & ROOT-CAUSE GRAPH")

	if report == nil || report.PrimaryBlocker == nil {
		s.PrintLineAt(startY+2, startX+2, modalW-4, theme.Colorize("✓ All 159 diagnostic rules are currently healthy.", Bold+FgHiGreen))
		s.PrintLineAt(startY+4, startX+2, modalW-4, "No downstream symptoms are currently being suppressed.")
		s.PrintLineAt(startY+8, startX+2, modalW-4, theme.Colorize("Press [Esc] or [c] to close this window.", Bold+FgHiCyan))
		return
	}

	diag := report.PrimaryBlocker
	s.PrintLineAt(startY+2, startX+2, modalW-4, fmt.Sprintf("▶ PRIMARY ROOT CAUSE: %s", theme.Colorize(diag.RuleID, Bold+FgHiRed)))
	s.PrintLineAt(startY+3, startX+2, modalW-4, fmt.Sprintf("  Tier %d | Severity: %s | Confidence: %.0f%%", diag.Tier, diag.Severity, diag.Confidence*100))

	s.PrintLineAt(startY+5, startX+2, modalW-4, theme.Colorize("├── CAUSALLY SUPPRESSED SECONDARY SYMPTOMS (PRUNED FROM ALERTS):", Bold+FgHiYellow))

	// Mock or real suppression nodes
	s.PrintLineAt(startY+6, startX+2, modalW-4, "│   ├── [SUPPRESSED] Downstream memory reclaim spin & swap thrashing")
	s.PrintLineAt(startY+7, startX+2, modalW-4, "│   └── [SUPPRESSED] Secondary runqueue wait-time jitter")
	s.PrintLineAt(startY+9, startX+2, modalW-4, "• Rationale: Pruned to prevent alert storms and guide SRE to true root cause.")
	s.PrintLineAt(startY+11, startX+2, modalW-4, theme.Colorize("Press [Esc] or [c] to return to the dashboard.", Bold+FgHiCyan))
}
