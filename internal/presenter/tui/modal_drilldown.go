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

	title := fmt.Sprintf("PROCESS INSPECTOR: PID %d [%s]", p.PID, p.Comm)
	s.DrawBox(startX, startY, modalW, modalH, title)

	rssMB := float64(p.RSSBytes) / (1024 * 1024)
	readMB := float64(p.ReadBytesDelta) / (1024 * 1024)
	writeMB := float64(p.WriteBytesDelta) / (1024 * 1024)

	wchan := p.Wchan
	if wchan == "" {
		wchan = "None (Running / Interruptible)"
	}
	cgroup := p.CgroupPath
	if cgroup == "" {
		cgroup = "/"
	}

	lines := []string{
		fmt.Sprintf("• Process Name:   %-20s   • State: %c", p.Comm, p.State),
		fmt.Sprintf("• Process ID:     %-20d   • Parent PID (PPID): %d", p.PID, p.PPID),
		fmt.Sprintf("• CPU Utilization:%-19.1f%%   • Active Threads:    %d", p.CPUPercent, p.NumThreads),
		fmt.Sprintf("• Resident Memory:%-19.1f MB  • OOM Score:         %d", rssMB, p.OOMScore),
		fmt.Sprintf("• Open File Descr:%-19d   • Max File Descr:    %d", p.OpenFDs, p.MaxFDs),
		fmt.Sprintf("• Read I/O Delta: %-19.1f MB  • Write I/O Delta:   %.1f MB", readMB, writeMB),
		fmt.Sprintf("• Kernel Wchan:   %s", wchan),
		fmt.Sprintf("• Cgroup Path:    %s", cgroup),
		"",
		theme.Colorize("Press [Esc] or [Enter] to close this inspector modal.", Bold+FgHiCyan),
	}

	for i, line := range lines {
		if startY+2+i >= startY+modalH-1 {
			break
		}
		s.PrintLineAt(startY+2+i, startX+2, modalW-4, line)
	}
}
