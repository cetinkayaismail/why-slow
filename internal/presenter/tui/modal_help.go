// Package tui — modal_help.go renders the interactive keybindings cheat sheet.
package tui

// RenderHelpModal renders the keybinding reference overlay.
func RenderHelpModal(s *Screen, theme *Theme, width, height int) {
	modalW := 68
	modalH := 16
	if modalW > width-4 {
		modalW = width - 4
	}
	if modalH > height-4 {
		modalH = height - 4
	}

	startX := (width - modalW) / 2
	startY := (height - modalH) / 2

	s.DrawBox(startX, startY, modalW, modalH, "KEYBOARD SHORTCUTS & NAVIGATION")

	shortcuts := []string{
		"• ↑ / ↓ or k / j    Navigate process table rows",
		"• f                 Focus & Lock onto Root Cause Culprit PID directly",
		"• l / p             Lock / Pin selected PID (follow across dynamic re-sorts)",
		"• Enter             Open process telemetry drill-down modal",
		"• Space             Freeze / Pause live differential snapshot",
		"• s                 Save currently frozen snapshot to JSON report",
		"• 1 / 2 / 3 / 4     Filter processes by CPU / Memory / IO / D-State",
		"• n / m             Cycle through multiple active issues / root causes",
		"• x                 Open Pre-Flight Blast Radius Remedy modal",
		"• c                 Toggle causal suppression tree indicators",
		"• ?                 Toggle this help reference overlay",
		"• q or Ctrl+C       Quit why-slow TUI and restore terminal",
		"",
		theme.Colorize("Press [Esc] or [?] to close this help window.", Bold+FgHiCyan),
	}

	for i, sc := range shortcuts {
		if startY+2+i >= startY+modalH-1 {
			break
		}
		s.PrintLineAt(startY+2+i, startX+2, modalW-4, sc)
	}
}
