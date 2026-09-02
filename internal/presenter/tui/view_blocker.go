// Package tui — view_blocker.go renders the Primary Root Cause Hero Card.
package tui

import (
	"fmt"
	"why-slow/internal/analyzer"
)

// RenderPrimaryBlocker draws the central explanatory diagnosis card with multi-issue display and word wrapping.
func RenderPrimaryBlocker(s *Screen, theme *Theme, report *analyzer.DiagnosticReport, activeIssueIdx, startY, width, height int) {
	contentW := width - 6
	if contentW <= 0 {
		return
	}

	allIssues := GetAllActiveIssues(report)
	if len(allIssues) == 0 {
		renderHealthyCard(s, theme, startY, width, height, contentW)
		return
	}

	if activeIssueIdx >= len(allIssues) || activeIssueIdx < 0 {
		activeIssueIdx = 0
	}
	diag := allIssues[activeIssueIdx]

	boxTitle := "PRIMARY BOTTLENECK & ROOT CAUSE"
	if len(allIssues) > 1 {
		boxTitle = fmt.Sprintf("ACTIVE ISSUES [%d of %d] — Press [1]..[%d] Select | 'n'/'m' Cycle | 'r' All Remedies",
			activeIssueIdx+1, len(allIssues), len(allIssues))
	}
	s.DrawBox(1, startY, width, height, boxTitle)

	maxY := startY + height - 2
	curY := startY + 1

	// Render Active Issue in detail
	curY = renderDetailedIssue(s, theme, diag, activeIssueIdx+1, curY, contentW, maxY)

	// Render summary of other active issues and their remedies
	if len(allIssues) > 1 && curY <= maxY {
		curY = renderOtherIssuesSummary(s, theme, allIssues, activeIssueIdx, curY, contentW, maxY)
	}

	// Blank any remaining rows inside box
	for r := curY; r <= maxY; r++ {
		s.PrintLineAt(r, 3, contentW, "")
	}
}

func renderDetailedIssue(s *Screen, theme *Theme, diag *analyzer.Diagnosis, num, curY, contentW, maxY int) int {
	if curY > maxY {
		return curY
	}
	badge := theme.SeverityBadge(string(diag.Severity))
	confStr := fmt.Sprintf("(Tier %d | Conf: %.0f%%)", diag.Tier, diag.Confidence*100)
	title := fmt.Sprintf("[%d] %s %s %s", num, badge, theme.Colorize(diag.Title, Bold), theme.Colorize(confStr, Dim))
	s.PrintLineAt(curY, 3, contentW, title)
	curY++

	if curY <= maxY {
		if diag.CulpritPID > 0 {
			culpritStr := fmt.Sprintf("• Culprit: PID %d [%s] — %s  [Press 'x' to Remedy]", diag.CulpritPID, diag.CulpritName, diag.CulpritDetails)
			s.PrintLineAt(curY, 3, contentW, theme.Colorize(culpritStr, Bold+FgHiYellow))
		} else {
			s.PrintLineAt(curY, 3, contentW, theme.Colorize("• Scope: System-wide hardware / kernel contention  [Press 'r' for Playbook]", Dim))
		}
		curY++
	}

	if curY <= maxY-1 {
		expLines := WrapText("• Explanation: "+diag.Explanation, contentW)
		for _, l := range expLines {
			if curY > maxY-1 {
				break
			}
			s.PrintLineAt(curY, 3, contentW, l)
			curY++
		}
	}

	if curY <= maxY && diag.Remediation != "" {
		remLines := WrapText("• Actionable Remedy: "+diag.Remediation, contentW)
		for _, l := range remLines {
			if curY > maxY {
				break
			}
			s.PrintLineAt(curY, 3, contentW, theme.Colorize(l, Bold+FgHiCyan))
			curY++
		}
	}
	return curY
}

func renderOtherIssuesSummary(s *Screen, theme *Theme, allIssues []*analyzer.Diagnosis, activeIdx, curY, contentW, maxY int) int {
	for i, other := range allIssues {
		if i == activeIdx || curY > maxY {
			continue
		}
		badgeOther := theme.SeverityBadge(string(other.Severity))
		rem := other.Remediation
		if rem == "" {
			rem = "See details"
		}
		otherLine := fmt.Sprintf("• [%d] %s %s ➔ %s [Press '%d']", i+1, badgeOther, other.Title, rem, i+1)
		s.PrintLineAt(curY, 3, contentW, theme.Colorize(otherLine, FgHiWhite))
		curY++
	}
	return curY
}

// GetAllActiveIssues aggregates primary blocker and contributing/secondary issues.
func GetAllActiveIssues(report *analyzer.DiagnosticReport) []*analyzer.Diagnosis {
	if report == nil {
		return nil
	}
	var issues []*analyzer.Diagnosis
	if report.PrimaryBlocker != nil {
		issues = append(issues, report.PrimaryBlocker)
	}
	for i := range report.ContributingFactors {
		issues = append(issues, &report.ContributingFactors[i])
	}
	for i := range report.SecondaryIssues {
		issues = append(issues, &report.SecondaryIssues[i])
	}
	return issues
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
