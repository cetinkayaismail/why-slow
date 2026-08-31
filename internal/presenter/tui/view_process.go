// Package tui — view_process.go renders the interactive process table with kernel wait-channels.
package tui

import (
	"fmt"
	"sort"
	"why-slow/internal/collector"
)

// ProcessSortMode specifies the sort order of the process table.
type ProcessSortMode int

const (
	SortByAuto ProcessSortMode = iota
	SortByCPU
	SortByIO
	SortByMemory
	SortByDState
)

// TableState tracks cursor position, scroll offset, and sort mode for the process table.
type TableState struct {
	CursorIdx int
	ScrollIdx int
	SortMode  ProcessSortMode
}

// RenderProcessTable draws the interactive process list with wait-channel columns.
func RenderProcessTable(s *Screen, theme *Theme, procs []collector.ProcessDiff, state *TableState, startY, width, height int) {
	s.DrawBox(1, startY, width, height, "ACTIVE PROCESSES & KERNEL WAIT-CHANNELS")

	header := fmt.Sprintf("   %-7s %-16s %-5s %-7s %-10s %-10s %-20s %s",
		"PID", "COMM", "STATE", "CPU%", "READ/s", "WRITE/s", "WCHAN", "CGROUP")
	if len(header) > width-4 {
		header = header[:width-4]
	}
	s.PrintAt(startY+1, 2, theme.Colorize(header, Bold+Underline))

	sorted := sortProcesses(procs, state.SortMode)
	maxVisibleRows := height - 3
	if maxVisibleRows <= 0 {
		return
	}

	clampScroll(state, len(sorted), maxVisibleRows)

	for i := 0; i < maxVisibleRows; i++ {
		rowIdx := state.ScrollIdx + i
		if rowIdx >= len(sorted) {
			break
		}

		p := sorted[rowIdx]
		isSelected := rowIdx == state.CursorIdx
		renderProcessRow(s, theme, p, isSelected, startY+2+i, width)
	}
}

func sortProcesses(procs []collector.ProcessDiff, mode ProcessSortMode) []collector.ProcessDiff {
	copied := make([]collector.ProcessDiff, len(procs))
	copy(copied, procs)

	switch mode {
	case SortByCPU:
		sort.Slice(copied, func(i, j int) bool { return copied[i].CPUPercent > copied[j].CPUPercent })
	case SortByMemory:
		sort.Slice(copied, func(i, j int) bool { return copied[i].RSSBytes > copied[j].RSSBytes })
	case SortByDState:
		sort.Slice(copied, func(i, j int) bool {
			if copied[i].State == 'D' && copied[j].State != 'D' {
				return true
			}
			return copied[i].CPUPercent > copied[j].CPUPercent
		})
	default: // Auto / IO
		sort.Slice(copied, func(i, j int) bool {
			return (copied[i].ReadBytesDelta + copied[i].WriteBytesDelta) > (copied[j].ReadBytesDelta + copied[j].WriteBytesDelta)
		})
	}
	return copied
}

func clampScroll(state *TableState, totalRows, maxVisible int) {
	if state.CursorIdx >= totalRows {
		state.CursorIdx = totalRows - 1
	}
	if state.CursorIdx < 0 {
		state.CursorIdx = 0
	}
	if state.CursorIdx < state.ScrollIdx {
		state.ScrollIdx = state.CursorIdx
	}
	if state.CursorIdx >= state.ScrollIdx+maxVisible {
		state.ScrollIdx = state.CursorIdx - maxVisible + 1
	}
}

func renderProcessRow(s *Screen, theme *Theme, p collector.ProcessDiff, isSelected bool, row, width int) {
	prefix := "  "
	if isSelected {
		prefix = "▶ "
	}

	comm := p.Comm
	if len(comm) > 15 {
		comm = comm[:15]
	}

	wchan := p.Wchan
	if wchan == "" {
		wchan = "-"
	}
	if len(wchan) > 19 {
		wchan = wchan[:19]
	}

	cgroup := p.CgroupPath
	if cgroup == "" || cgroup == "/" {
		cgroup = "-"
	}
	if len(cgroup) > 20 {
		cgroup = cgroup[:20]
	}

	readMB := float64(p.ReadBytesDelta) / (1024 * 1024)
	writeMB := float64(p.WriteBytesDelta) / (1024 * 1024)

	line := fmt.Sprintf("%s%-7d %-16s %-5c %-6.1f%% %-9.1fM %-9.1fM %-20s %s",
		prefix, p.PID, comm, p.State, p.CPUPercent, readMB, writeMB, wchan, cgroup)

	if len(line) > width-4 {
		line = line[:width-4]
	}

	if isSelected {
		s.PrintAt(row, 2, theme.Colorize(line, Bold+FgHiWhite+BgBlue))
	} else if p.State == 'D' {
		s.PrintAt(row, 2, theme.Colorize(line, Bold+FgHiRed))
	} else {
		s.PrintAt(row, 2, line)
	}
}
