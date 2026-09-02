// Package tui — modal_all_remedies.go renders the full-screen recovery workbook
// displaying all detected bottlenecks, root causes, and complete remediation commands.
package tui

import (
	"fmt"
	"why-slow/internal/analyzer"
)

// RenderAllRemediesModal renders all active bottlenecks and their remedies.
func RenderAllRemediesModal(s *Screen, theme *Theme, report *analyzer.DiagnosticReport, width, height int) {
	modalW := width - 6
	modalH := height - 4
	if modalW < 60 {
		modalW = 60
	}
	if modalH < 14 {
		modalH = 14
	}

	startX := (width - modalW) / 2
	startY := (height - modalH) / 2
	contentW := modalW - 4

	s.DrawBox(startX, startY, modalW, modalH, "SYSTEM BOTTLENECK REMEDIES & RECOVERY PLAYBOOK")

	allIssues := GetAllActiveIssues(report)
	if len(allIssues) == 0 {
		s.PrintLineAt(startY+2, startX+2, contentW, theme.Colorize("✓ No active bottlenecks detected. System is running healthy!", Bold+FgHiGreen))
		s.PrintLineAt(startY+modalH-2, startX+2, contentW, theme.Colorize("Press [Esc] or [r] to return to dashboard.", Bold+FgHiCyan))
		return
	}

	curY := startY + 2
	maxY := startY + modalH - 3

	for i, diag := range allIssues {
		if curY > maxY {
			break
		}
		curY = renderRemedySection(s, theme, diag, i+1, startX+2, curY, contentW, maxY)
	}

	footer := "Press [Esc] or [r] to return  •  Press [x] on dashboard to execute process remedy"
	s.DrawDivider(startX, startY+modalH-2, modalW)
	s.PrintLineAt(startY+modalH-1, startX+2, contentW, theme.Colorize(footer, Bold+FgHiCyan))
}

func renderRemedySection(s *Screen, theme *Theme, diag *analyzer.Diagnosis, idx, startX, curY, contentW, maxY int) int {
	if curY > maxY {
		return curY
	}

	badge := theme.SeverityBadge(string(diag.Severity))
	header := fmt.Sprintf("[%d] %s %s (Tier %d | Conf: %.0f%%)", idx, badge, diag.Title, diag.Tier, diag.Confidence*100)
	s.PrintLineAt(curY, startX, contentW, theme.Colorize(header, Bold))
	curY++

	if curY <= maxY {
		if diag.CulpritPID > 0 {
			target := fmt.Sprintf("• Culprit: PID %d [%s] — %s", diag.CulpritPID, diag.CulpritName, diag.CulpritDetails)
			s.PrintLineAt(curY, startX, contentW, theme.Colorize(target, Bold+FgHiYellow))
		} else {
			s.PrintLineAt(curY, startX, contentW, theme.Colorize("• Scope: System-wide hardware / kernel contention", Dim))
		}
		curY++
	}

	if curY <= maxY && diag.Remediation != "" {
		remLines := WrapText("• Actionable Remedy: "+diag.Remediation, contentW)
		for _, line := range remLines {
			if curY > maxY {
				break
			}
			s.PrintLineAt(curY, startX, contentW, theme.Colorize(line, Bold+FgHiCyan))
			curY++
		}
	}

	curY++ // separator space
	return curY
}
