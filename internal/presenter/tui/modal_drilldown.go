// Package tui — modal_drilldown.go renders the process inspection modal.
package tui

import (
	"fmt"
	"why-slow/internal/collector"
)

// RenderDrilldownModal renders a centered modal box with detailed process telemetry.
func RenderDrilldownModal(s *Screen, theme *Theme, p *collector.ProcessDiff, width, height int) {
	if p == nil {
		return
	}

	modalW := 74
	modalH := 16
	if modalW > width-2 {
		modalW = width - 2
	}
	if modalH > height-2 {
		modalH = height - 2
	}

	startX := (width - modalW) / 2
	startY := (height - modalH) / 2

	title := fmt.Sprintf("PROCESS INSPECTOR — PID: %d [%s]", p.PID, p.Comm)
	s.DrawBox(startX, startY, modalW, modalH, title)

	contentW := modalW - 4
	if contentW <= 0 {
		return
	}

	rssMB := float64(p.RSSBytes) / (1024 * 1024)
	readMB := float64(p.ReadBytesDelta) / (1024 * 1024)
	writeMB := float64(p.WriteBytesDelta) / (1024 * 1024)

	wchan := p.Wchan
	if wchan == "" {
		wchan = "None (Running)"
	}
	if len(wchan) > 20 {
		wchan = wchan[:20]
	}

	cgroup := p.CgroupPath
	if cgroup == "" || cgroup == "/" {
		cgroup = "root"
	}
	if len(cgroup) > 20 {
		cgroup = cgroup[:20]
	}

	// 2-Column Grid Rows
	r1 := fmt.Sprintf("  %-16s %-16s │ %-16s %s", "Process Name:", p.Comm, "Process State:", string(p.State))
	r2 := fmt.Sprintf("  %-16s %-16d │ %-16s %d", "Process ID:", p.PID, "Parent PID:", p.PPID)
	r3 := fmt.Sprintf("  %-16s %-15.1f%% │ %-16s %d threads", "CPU Usage:", p.CPUPercent, "Active Threads:", p.NumThreads)
	r4 := fmt.Sprintf("  %-16s %-13.1f MB │ %-16s %d", "Resident Memory:", rssMB, "OOM Score:", p.OOMScore)
	r5 := fmt.Sprintf("  %-16s %-16d │ %-16s %d", "Open FDs:", p.OpenFDs, "Max Soft FDs:", p.MaxFDs)
	r6 := fmt.Sprintf("  %-16s %-13.1f MB │ %-16s %.1f MB", "Read Delta:", readMB, "Write Delta:", writeMB)
	r7 := fmt.Sprintf("  %-16s %-16s │ %-16s %s", "Kernel Wchan:", wchan, "Cgroup Scope:", cgroup)

	s.PrintLineAt(startY+2, startX+2, contentW, theme.Colorize(r1, Bold))
	s.PrintLineAt(startY+3, startX+2, contentW, r2)
	s.PrintLineAt(startY+4, startX+2, contentW, r3)
	s.PrintLineAt(startY+5, startX+2, contentW, r4)
	s.PrintLineAt(startY+6, startX+2, contentW, r5)
	s.PrintLineAt(startY+7, startX+2, contentW, r6)
	s.PrintLineAt(startY+8, startX+2, contentW, r7)

	s.DrawDivider(startX, startY+10, modalW)

	footer := "Actions: [Esc/Enter] Close  •  [l] Pin/Lock PID  •  [x] Blast Radius Remedy"
	s.PrintLineAt(startY+12, startX+2, contentW, theme.Colorize(footer, Bold+FgHiCyan))
}
