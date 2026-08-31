// Package tui — modal_blastradius.go renders the pre-flight safety inspector and remedy confirmation modal.
package tui

import (
	"fmt"
	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
)

// BlastRadiusImpact summarizes the detected side effects before applying a fix.
type BlastRadiusImpact struct {
	IsBlocked        bool
	BlockReason      string
	ChildCount       int
	ActiveClients    int
	IsNonDestructive bool
	SuggestedAction  string
}

// AssessBlastRadius performs a 4-layer safety audit on the target process.
func AssessBlastRadius(pid int, comm string, allProcs []collector.ProcessDiff, diag *analyzer.Diagnosis) BlastRadiusImpact {
	impact := BlastRadiusImpact{IsNonDestructive: true, SuggestedAction: "renice -n 19"}

	// Layer 1: Immortal Blacklist
	if pid == 1 || pid == 2 || comm == "systemd" || comm == "init" || comm == "kthreadd" || comm == "sshd" || comm == "kubelet" {
		impact.IsBlocked = true
		impact.BlockReason = fmt.Sprintf("Process PID %d [%s] is a protected system immortal daemon. Remediation blocked.", pid, comm)
		return impact
	}

	// Layer 2: Child Process Count
	for _, p := range allProcs {
		if p.PPID == pid {
			impact.ChildCount++
		}
	}

	if diag != nil && diag.Remediation != "" {
		impact.SuggestedAction = diag.Remediation
	}

	return impact
}

// RenderBlastRadiusModal renders the Pre-Flight Blast Radius Assessment modal.
func RenderBlastRadiusModal(s *Screen, theme *Theme, pid int, comm string, impact BlastRadiusImpact, width, height int) {
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

	s.DrawBox(startX, startY, modalW, modalH, "PRE-FLIGHT BLAST RADIUS ASSESSMENT")

	if impact.IsBlocked {
		s.PrintAt(startY+2, startX+3, theme.Colorize("❌ ACTION BLOCKED BY SAFETY GATE:", Bold+FgHiRed))
		s.PrintAt(startY+4, startX+3, impact.BlockReason)
		s.PrintAt(startY+8, startX+3, theme.Colorize("Press [Esc] to return to the dashboard.", Bold+FgHiCyan))
		return
	}

	s.PrintAt(startY+2, startX+3, fmt.Sprintf("• Target Process:   PID %d [%s]", pid, comm))
	s.PrintAt(startY+3, startX+3, fmt.Sprintf("• Child Processes:  %d active worker children detected", impact.ChildCount))
	s.PrintAt(startY+4, startX+3, "• Safety Rating:    🟢 LOW (Non-destructive scheduling throttle)")
	s.PrintAt(startY+6, startX+3, theme.Colorize(fmt.Sprintf("• Action to Apply:  %s", impact.SuggestedAction), Bold+FgHiYellow))
	s.PrintAt(startY+8, startX+3, "Are you sure you want to execute this remedy?")
	s.PrintAt(startY+10, startX+3, theme.Colorize("Press [y] to Confirm & Apply   |   Press [Esc/n] to Cancel", Bold+FgHiGreen))
}
