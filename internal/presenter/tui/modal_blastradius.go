// Package tui — modal_blastradius.go renders the pre-flight safety inspector and remedy confirmation modal.
package tui

import (
	"fmt"
	"strings"
	"syscall"
	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
)

// RemedyActionType defines the execution strategy for a process remedy.
type RemedyActionType int

const (
	ActionThrottleNice19 RemedyActionType = iota
	ActionGracefulSigterm
	ActionForceSigkill
)

// BlastRadiusImpact summarizes the detected side effects before applying a fix.
type BlastRadiusImpact struct {
	IsBlocked        bool
	BlockReason      string
	ChildCount       int
	ChildNames       []string
	IsSSHSession     bool
	IsSystemDaemon   bool
	SafetyRating     string
	SelectedAction   RemedyActionType
	ActionName       string
	SyscallName      string
	SideEffectDesc   string
	SuggestedCommand string
}

// AssessBlastRadius performs a 4-layer safety audit on the target process.
func AssessBlastRadius(pid int, comm string, allProcs []collector.ProcessDiff, diag *analyzer.Diagnosis, actionType RemedyActionType) BlastRadiusImpact {
	impact := BlastRadiusImpact{
		SelectedAction: actionType,
	}

	// Layer 1: Immortal & System Core Daemon Blacklist
	isImmortal := pid <= 2 || comm == "systemd" || comm == "init" || comm == "kthreadd" ||
		comm == "dbus-daemon" || comm == "udevd" || comm == "kubelet" || strings.HasPrefix(comm, "kworker/") ||
		strings.HasPrefix(comm, "migration/") || strings.HasPrefix(comm, "rcu_") || strings.HasPrefix(comm, "ksoftirqd/")

	if isImmortal {
		impact.IsBlocked = true
		impact.IsSystemDaemon = true
		impact.BlockReason = fmt.Sprintf("Process PID %d [%s] is a core kernel/system immortal daemon. Automated modifications are blocked to prevent OS kernel panic.", pid, comm)
		return impact
	}

	// Layer 2: Child Worker & Process Tree Analysis
	for _, p := range allProcs {
		if p.PPID == pid {
			impact.ChildCount++
			if len(impact.ChildNames) < 3 {
				impact.ChildNames = append(impact.ChildNames, fmt.Sprintf("%s (PID %d)", p.Comm, p.PID))
			}
		}
	}

	// Layer 3: SSH & Remote Terminal Connection Association
	if comm == "sshd" || comm == "ssh" {
		impact.IsSSHSession = true
	} else {
		// Check parent chain for SSH
		for _, p := range allProcs {
			if p.PID == pid && (strings.Contains(p.CgroupPath, "sshd") || strings.Contains(p.CgroupPath, "session-")) {
				impact.IsSSHSession = true
				break
			}
		}
	}

	// Layer 4: Action Strategy & Risk Rating
	switch actionType {
	case ActionThrottleNice19:
		impact.SafetyRating = "🟢 LOW RISK (Non-destructive priority throttle)"
		impact.ActionName = "Throttle CPU Scheduling to Idle (Nice +19)"
		impact.SyscallName = fmt.Sprintf("syscall.Setpriority(PRIO_PROCESS, %d, 19)", pid)
		impact.SideEffectDesc = "Process continues running; data is preserved; CPU starvation of host is instantly eliminated."
		impact.SuggestedCommand = fmt.Sprintf("renice -n 19 -p %d", pid)
	case ActionGracefulSigterm:
		impact.SafetyRating = "🟡 MEDIUM RISK (Graceful service termination)"
		impact.ActionName = "Send Graceful Stop Signal (SIGTERM)"
		impact.SyscallName = fmt.Sprintf("syscall.Kill(%d, syscall.SIGTERM)", pid)
		if impact.ChildCount > 0 {
			impact.SideEffectDesc = fmt.Sprintf("Process will exit cleanly. %d child worker processes will be terminated or orphaned.", impact.ChildCount)
		} else {
			impact.SideEffectDesc = "Process will exit cleanly, flushing active buffers and releasing open sockets."
		}
		impact.SuggestedCommand = fmt.Sprintf("kill -TERM %d", pid)
	case ActionForceSigkill:
		impact.SafetyRating = "🔴 HIGH RISK (Forceful ungraceful kill)"
		impact.ActionName = "Force Kill Immediately (SIGKILL)"
		impact.SyscallName = fmt.Sprintf("syscall.Kill(%d, syscall.SIGKILL)", pid)
		impact.SideEffectDesc = "Process is killed immediately with zero cleanup. In-flight data and shared memory locks may be lost."
		impact.SuggestedCommand = fmt.Sprintf("kill -9 %d", pid)
	}

	return impact
}

// ExecuteRemedy applies the chosen pure Go syscall for the given remedy action.
func ExecuteRemedy(pid int, actionType RemedyActionType) error {
	switch actionType {
	case ActionThrottleNice19:
		return syscall.Setpriority(syscall.PRIO_PROCESS, pid, 19)
	case ActionGracefulSigterm:
		return syscall.Kill(pid, syscall.SIGTERM)
	case ActionForceSigkill:
		return syscall.Kill(pid, syscall.SIGKILL)
	default:
		return syscall.Setpriority(syscall.PRIO_PROCESS, pid, 19)
	}
}

// RenderBlastRadiusModal renders the Pre-Flight Blast Radius Assessment modal.
func RenderBlastRadiusModal(s *Screen, theme *Theme, p *collector.ProcessDiff, impact BlastRadiusImpact, width, height int) {
	if p == nil {
		return
	}

	modalW := 76
	modalH := 18
	if modalW > width-2 {
		modalW = width - 2
	}
	if modalH > height-2 {
		modalH = height - 2
	}

	startX := (width - modalW) / 2
	startY := (height - modalH) / 2

	s.DrawBox(startX, startY, modalW, modalH, "PRE-FLIGHT BLAST RADIUS & REMEDY ASSESSMENT")

	contentW := modalW - 4
	if contentW <= 0 {
		return
	}

	if impact.IsBlocked {
		s.PrintLineAt(startY+2, startX+2, contentW, theme.Colorize("❌ SAFETY GUARD: ACTION BLOCKED FOR THIS PROCESS", Bold+FgHiRed))
		s.PrintLineAt(startY+4, startX+2, contentW, TruncateVisible(impact.BlockReason, contentW))
		s.PrintLineAt(startY+6, startX+2, contentW, "This process is essential for kernel scheduling, systemd, or hardware I/O.")
		s.PrintLineAt(startY+7, startX+2, contentW, "Modifying or terminating it would cause immediate system crash or disconnect.")
		s.DrawDivider(startX, startY+modalH-3, modalW)
		s.PrintLineAt(startY+modalH-2, startX+2, contentW, theme.Colorize("Press [Esc] or [n] to return to the dashboard safely.", Bold+FgHiCyan))
		return
	}

	// Target Info
	targetLine := fmt.Sprintf("• Target:    PID %d [%s]  │  PPID: %d  │  Threads: %d", p.PID, p.Comm, p.PPID, p.NumThreads)
	s.PrintLineAt(startY+2, startX+2, contentW, theme.Colorize(targetLine, Bold))

	// Dependency & Process Tree Audit
	childStr := "0 child workers (Isolated process)"
	if impact.ChildCount > 0 {
		childStr = fmt.Sprintf("⚠ %d child worker processes (%s...)", impact.ChildCount, strings.Join(impact.ChildNames, ", "))
	}
	s.PrintLineAt(startY+3, startX+2, contentW, fmt.Sprintf("• Hierarchy: %s", childStr))

	// SSH & Network warning
	if impact.IsSSHSession {
		s.PrintLineAt(startY+4, startX+2, contentW, theme.Colorize("• Network:   ⚠ SSH / Remote terminal session association detected!", Bold+FgHiYellow))
	} else {
		s.PrintLineAt(startY+4, startX+2, contentW, "• Network:   Standard user-space process (No direct SSH daemon link)")
	}

	s.DrawDivider(startX, startY+5, modalW)

	// Proposed Remedy Action
	s.PrintLineAt(startY+6, startX+2, contentW, fmt.Sprintf("• Proposed Remedy: %s", theme.Colorize(impact.ActionName, Bold+FgHiYellow)))
	s.PrintLineAt(startY+7, startX+2, contentW, fmt.Sprintf("• Pure Go Syscall: %s", theme.Colorize(impact.SyscallName, FgHiCyan)))
	s.PrintLineAt(startY+8, startX+2, contentW, fmt.Sprintf("• Risk Assessment: %s", impact.SafetyRating))
	s.PrintLineAt(startY+9, startX+2, contentW, fmt.Sprintf("• Side Effects:    %s", TruncateVisible(impact.SideEffectDesc, contentW-18)))

	s.DrawDivider(startX, startY+11, modalW)

	// Strategy Selection & Confirmation Footer
	var strat1, strat2, strat3 string
	switch impact.SelectedAction {
	case ActionThrottleNice19:
		strat1 = theme.Colorize("[● 1] Throttle (Nice 19) [ACTIVE]", Bold+FgHiGreen)
		strat2 = theme.Colorize("[○ 2] SIGTERM", Dim)
		strat3 = theme.Colorize("[○ 3] SIGKILL", Dim)
	case ActionGracefulSigterm:
		strat1 = theme.Colorize("[○ 1] Throttle (Nice 19)", Dim)
		strat2 = theme.Colorize("[● 2] Graceful SIGTERM [ACTIVE]", Bold+FgHiYellow)
		strat3 = theme.Colorize("[○ 3] SIGKILL", Dim)
	case ActionForceSigkill:
		strat1 = theme.Colorize("[○ 1] Throttle (Nice 19)", Dim)
		strat2 = theme.Colorize("[○ 2] SIGTERM", Dim)
		strat3 = theme.Colorize("[● 3] Force SIGKILL [ACTIVE]", Bold+FgHiRed)
	}

	optionsLine := fmt.Sprintf("Select Strategy: %s  %s  %s", strat1, strat2, strat3)
	s.PrintLineAt(startY+12, startX+2, contentW, optionsLine)

	confirmLine := fmt.Sprintf("Press [y] to Execute Remedy (%s)  |  [Esc/n] Cancel", theme.Colorize(impact.SuggestedCommand, Bold+FgHiWhite))
	s.PrintLineAt(startY+14, startX+2, contentW, theme.Colorize(confirmLine, Bold+FgHiGreen))
}
