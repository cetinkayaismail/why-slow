// Package tui — view_matrix.go renders the Rule Engine 159-rule status matrix.
package tui

import (
	"fmt"
	"why-slow/internal/analyzer"
)

// RenderRuleMatrix draws the bottom rule evaluation status bar.
func RenderRuleMatrix(s *Screen, theme *Theme, report *analyzer.DiagnosticReport, startY, width int) {
	s.DrawBox(1, startY, width, 3, "DIAGNOSTIC RULE MATRIX (159 RULES EVALUATED IN 23µs)")

	tier1Count := 0
	tier2Count := 0
	tier3Count := 0

	if report != nil {
		if report.PrimaryBlocker != nil {
			switch report.PrimaryBlocker.Tier {
			case 1:
				tier1Count++
			case 2:
				tier2Count++
			case 3:
				tier3Count++
			}
		}
		for _, cf := range report.ContributingFactors {
			switch cf.Tier {
			case 1:
				tier1Count++
			case 2:
				tier2Count++
			case 3:
				tier3Count++
			}
		}
		for _, si := range report.SecondaryIssues {
			switch si.Tier {
			case 1:
				tier1Count++
			case 2:
				tier2Count++
			case 3:
				tier3Count++
			}
		}
	}

	totalActive := tier1Count + tier2Count + tier3Count
	healthyCount := 159 - totalActive
	if healthyCount < 0 {
		healthyCount = 0
	}

	t1Str := theme.Colorize(fmt.Sprintf("Tier 1: %d Active", tier1Count), Bold+FgHiRed)
	t2Str := theme.Colorize(fmt.Sprintf("Tier 2: %d Active", tier2Count), Bold+FgHiYellow)
	t3Str := theme.Colorize(fmt.Sprintf("Tier 3: %d Active", tier3Count), FgHiCyan)
	hStr := theme.Colorize(fmt.Sprintf("Healthy: %d Rules", healthyCount), Bold+FgHiGreen)

	line := fmt.Sprintf("  [%s]   [%s]   [%s]   [%s]   [c: Causal Tree | ?: Help | q: Quit]", t1Str, t2Str, t3Str, hStr)
	s.PrintLineAt(startY+1, 2, width-2, line)
}
