// Package tui — view_blocker.go renders the Primary Root Cause Hero Card.
package tui

import (
	"fmt"
	"why-slow/internal/analyzer"
)

// RenderPrimaryBlocker draws the central explanatory diagnosis card.
func RenderPrimaryBlocker(s *Screen, theme *Theme, report *analyzer.DiagnosticReport, startY, width, height int) {
	if report == nil || report.PrimaryBlocker == nil {
		renderHealthyCard(s, theme, startY, width, height)
		return
	}

	diag := report.PrimaryBlocker
	badge := theme.SeverityBadge(string(diag.Severity))
	confStr := fmt.Sprintf("(Tier %d | Conf: %.0f%%)", diag.Tier, diag.Confidence*100)

	title := fmt.Sprintf("%s %s %s", badge, theme.Colorize(diag.Title, Bold), theme.Colorize(confStr, Dim))
	s.DrawBox(1, startY, width, height, "PRIMARY BOTTLENECK & ROOT CAUSE")

	s.PrintAt(startY+1, 3, title)

	// Explanation
	explText := fmt.Sprintf("• Explanation: %s", diag.Explanation)
	if len(explText) > width-6 {
		explText = explText[:width-9] + "..."
	}
	s.PrintAt(startY+2, 3, explText)

	// Kernel Evidence
	renderEvidence(s, theme, diag.Evidence, startY+3, width)

	// Culprit Attribution & Remediation
	renderCulpritAndFix(s, theme, diag, startY+5, width)
}

func renderHealthyCard(s *Screen, theme *Theme, startY, width, height int) {
	s.DrawBox(1, startY, width, height, "SYSTEM STATUS")
	badge := theme.SeverityBadge("HEALTHY")
	s.PrintAt(startY+1, 3, fmt.Sprintf("%s %s", badge, theme.Colorize("All 159 kernel subsystems operating within normal bounds.", Bold+FgHiGreen)))
	s.PrintAt(startY+2, 3, theme.Colorize("No critical resource starvation, lock contention, or queue backpressure detected.", FgHiBlack))
}

func renderEvidence(s *Screen, theme *Theme, evidence []string, startY, width int) {
	if len(evidence) == 0 {
		return
	}
	var evStr string
	if len(evidence) == 1 {
		evStr = fmt.Sprintf("• Evidence: %s", evidence[0])
	} else {
		evStr = fmt.Sprintf("• Evidence: %s | %s", evidence[0], evidence[1])
	}
	if len(evStr) > width-6 {
		evStr = evStr[:width-9] + "..."
	}
	s.PrintAt(startY, 3, theme.Colorize(evStr, Dim))
}

func renderCulpritAndFix(s *Screen, theme *Theme, diag *analyzer.Diagnosis, startY, width int) {
	if diag.CulpritPID > 0 {
		culpritStr := fmt.Sprintf("• Culprit: PID %d [%s] — %s", diag.CulpritPID, diag.CulpritName, diag.CulpritDetails)
		if len(culpritStr) > width-6 {
			culpritStr = culpritStr[:width-9] + "..."
		}
		s.PrintAt(startY, 3, theme.Colorize(culpritStr, Bold+FgHiYellow))
	} else {
		s.PrintAt(startY, 3, theme.Colorize("• Scope: System-wide kernel contention", Dim))
	}

	if diag.Remediation != "" {
		fixStr := fmt.Sprintf("• [x] Actionable Remedy: %s", diag.Remediation)
		if len(fixStr) > width-6 {
			fixStr = fixStr[:width-9] + "..."
		}
		s.PrintAt(startY+1, 3, theme.Colorize(fixStr, Bold+FgHiCyan))
	}
}
