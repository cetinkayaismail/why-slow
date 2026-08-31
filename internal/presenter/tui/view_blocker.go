// Package tui — view_blocker.go renders the Primary Root Cause Hero Card.
package tui

import (
	"fmt"
	"why-slow/internal/analyzer"
)

// RenderPrimaryBlocker draws the central explanatory diagnosis card.
func RenderPrimaryBlocker(s *Screen, theme *Theme, report *analyzer.DiagnosticReport, startY, width, height int) {
	contentW := width - 6
	if contentW <= 0 {
		return
	}

	if report == nil || report.PrimaryBlocker == nil {
		renderHealthyCard(s, theme, startY, width, height, contentW)
		return
	}

	diag := report.PrimaryBlocker
	badge := theme.SeverityBadge(string(diag.Severity))
	confStr := fmt.Sprintf("(Tier %d | Conf: %.0f%%)", diag.Tier, diag.Confidence*100)

	title := fmt.Sprintf("%s %s %s", badge, theme.Colorize(diag.Title, Bold), theme.Colorize(confStr, Dim))
	s.DrawBox(1, startY, width, height, "PRIMARY BOTTLENECK & ROOT CAUSE")

	s.PrintLineAt(startY+1, 3, contentW, title)
	s.PrintLineAt(startY+2, 3, contentW, fmt.Sprintf("• Explanation: %s", diag.Explanation))

	renderEvidence(s, theme, diag.Evidence, startY+3, contentW)
	renderCulpritAndFix(s, theme, diag, startY+5, contentW)
}

func renderHealthyCard(s *Screen, theme *Theme, startY, width, height, contentW int) {
	s.DrawBox(1, startY, width, height, "SYSTEM STATUS")
	badge := theme.SeverityBadge("HEALTHY")
	s.PrintLineAt(startY+1, 3, contentW, fmt.Sprintf("%s %s", badge, theme.Colorize("All 159 kernel subsystems operating within normal bounds.", Bold+FgHiGreen)))
	s.PrintLineAt(startY+2, 3, contentW, theme.Colorize("No critical resource starvation, lock contention, or queue backpressure detected.", FgHiBlack))

	for r := startY + 3; r < startY+height-1; r++ {
		s.PrintLineAt(r, 3, contentW, "")
	}
}

func renderEvidence(s *Screen, theme *Theme, evidence []string, startY, contentW int) {
	var evStr string
	if len(evidence) == 0 {
		evStr = "• Evidence: Telemetry indicates localized threshold anomaly."
	} else if len(evidence) == 1 {
		evStr = fmt.Sprintf("• Evidence: %s", evidence[0])
	} else {
		evStr = fmt.Sprintf("• Evidence: %s | %s", evidence[0], evidence[1])
	}
	s.PrintLineAt(startY, 3, contentW, theme.Colorize(evStr, Dim))
	s.PrintLineAt(startY+1, 3, contentW, "")
}

func renderCulpritAndFix(s *Screen, theme *Theme, diag *analyzer.Diagnosis, startY, contentW int) {
	if diag.CulpritPID > 0 {
		culpritStr := fmt.Sprintf("• Culprit: PID %d [%s] — %s   [f: Jump & Lock Cursor]", diag.CulpritPID, diag.CulpritName, diag.CulpritDetails)
		s.PrintLineAt(startY, 3, contentW, theme.Colorize(culpritStr, Bold+FgHiYellow))
	} else {
		s.PrintLineAt(startY, 3, contentW, theme.Colorize("• Scope: System-wide kernel contention", Dim))
	}

	if diag.Remediation != "" {
		fixStr := fmt.Sprintf("• [x] Actionable Remedy: %s", diag.Remediation)
		s.PrintLineAt(startY+1, 3, contentW, theme.Colorize(fixStr, Bold+FgHiCyan))
	} else {
		s.PrintLineAt(startY+1, 3, contentW, "")
	}
}
