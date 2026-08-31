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
	CursorIdx   int
	ScrollIdx   int
	SortMode    ProcessSortMode
	SelectedPID int
	LockedPID   int
}

// RenderProcessTable draws the interactive process list with wait-channel columns.
func RenderProcessTable(s *Screen, theme *Theme, procs []collector.ProcessDiff, state *TableState, startY, width, height int) {
	title := "ACTIVE PROCESSES & KERNEL WAIT-CHANNELS"
	if state.LockedPID > 0 {
		title = fmt.Sprintf("ACTIVE PROCESSES [🔒 LOCKED ON PID: %d — Press 'l' to Unlock]", state.LockedPID)
	}
	s.DrawBox(1, startY, width, height, title)

	tableW := width - 2
	if tableW <= 0 {
		return
	}

	header := fmt.Sprintf("   %-7s %-16s %-5s %-7s %-10s %-10s %-20s %s",
		"PID", "COMM", "STATE", "CPU%", "READ/s", "WRITE/s", "WCHAN", "CGROUP")
	s.PrintLineAt(startY+1, 2, tableW, theme.Colorize(header, Bold+Underline))

	sorted := sortProcesses(procs, state.SortMode)
	maxVisibleRows := height - 3
	if maxVisibleRows <= 0 {
		return
	}

	// Follow tracked/locked PID across dynamic re-sorts
	trackPID(state, sorted)
	clampScroll(state, len(sorted), maxVisibleRows)

	for i := 0; i < maxVisibleRows; i++ {
		rowIdx := state.ScrollIdx + i
		if rowIdx >= len(sorted) {
			s.PrintLineAt(startY+2+i, 2, tableW, "")
			continue
		}

		p := sorted[rowIdx]
		isSelected := rowIdx == state.CursorIdx
		isLocked := p.PID == state.LockedPID
		renderProcessRow(s, theme, p, isSelected, isLocked, startY+2+i, tableW)
	}
}

func trackPID(state *TableState, sorted []collector.ProcessDiff) {
	targetPID := state.SelectedPID
	if state.LockedPID > 0 {
		targetPID = state.LockedPID
	}

	if targetPID > 0 {
		for idx, p := range sorted {
			if p.PID == targetPID {
				state.CursorIdx = idx
				return
			}
		}
	} else if len(sorted) > 0 && state.CursorIdx < len(sorted) {
		state.SelectedPID = sorted[state.CursorIdx].PID
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

func renderProcessRow(s *Screen, theme *Theme, p collector.ProcessDiff, isSelected, isLocked bool, row, tableW int) {
	prefix := "  "
	if isLocked && isSelected {
		prefix = "🔒▶"
	} else if isLocked {
		prefix = "🔒 "
	} else if isSelected {
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

	if isSelected {
		s.PrintLineAt(row, 2, tableW, theme.Colorize(line, Bold+FgHiWhite+BgBlue))
	} else if isLocked {
		s.PrintLineAt(row, 2, tableW, theme.Colorize(line, Bold+FgHiYellow))
	} else if p.State == 'D' {
		s.PrintLineAt(row, 2, tableW, theme.Colorize(line, Bold+FgHiRed))
	} else {
		s.PrintLineAt(row, 2, tableW, line)
	}
}
