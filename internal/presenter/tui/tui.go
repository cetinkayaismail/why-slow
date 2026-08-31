// Package tui — tui.go coordinates the live interactive event loop and UI state.
package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
)

// ActiveModal represents which overlay modal is currently active.
type ActiveModal int

const (
	ModalNone ActiveModal = iota
	ModalDrilldown
	ModalBlastRadius
	ModalHelp
	ModalCausalTree
)

// UIState encapsulates the real-time state of the interactive console.
type UIState struct {
	IsFrozen      bool
	ActiveModal   ActiveModal
	TableState    TableState
	LastReport    *analyzer.DiagnosticReport
	LastDiff      *collector.SnapshotDiff
	StatusMessage string
	Theme         *Theme
}

// RunTUI launches the full-screen interactive diagnostic dashboard.
func RunTUI(ctx context.Context, interval time.Duration, runCtx collector.RunContext, noColor bool) error {
	fd := int(os.Stdin.Fd())
	if !IsTerminal(fd) {
		return fmt.Errorf("tui: standard input is not a terminal TTY")
	}

	termState, err := EnableRawMode(fd)
	if err != nil {
		return fmt.Errorf("tui: enable raw mode: %w", err)
	}
	defer Restore(fd, termState)

	theme := NewTheme(noColor)
	w, h, _ := GetTerminalSize(fd)
	screen := NewScreen(w, h, theme)
	screen.EnterAltScreen()
	defer screen.ExitAltScreen()

	state := &UIState{
		Theme: theme,
	}

	engine := analyzer.NewEngine()
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGWINCH)

	return eventLoop(ctx, fd, interval, runCtx, engine, state, screen, sigChan)
}

func eventLoop(ctx context.Context, fd int, interval time.Duration, runCtx collector.RunContext,
	engine *analyzer.Engine, state *UIState, screen *Screen, sigChan chan os.Signal) error {

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial collection pass
	refreshSnapshot(ctx, engine, runCtx, state, interval)
	renderFrame(screen, state, fd)

	for {
		select {
		case <-ctx.Done():
			return nil
		case sig := <-sigChan:
			if sig == syscall.SIGWINCH {
				w, h, _ := GetTerminalSize(fd)
				screen.Width, screen.Height = w, h
				renderFrame(screen, state, fd)
			} else {
				return nil
			}
		case <-ticker.C:
			if !state.IsFrozen {
				refreshSnapshot(ctx, engine, runCtx, state, interval)
				renderFrame(screen, state, fd)
			}
		default:
			key, _ := ReadKey(os.Stdin)
			if key != "" {
				if shouldQuit := handleKeyPress(key, state, screen); shouldQuit {
					return nil
				}
				renderFrame(screen, state, fd)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func refreshSnapshot(ctx context.Context, engine *analyzer.Engine, runCtx collector.RunContext, state *UIState, interval time.Duration) {
	snapA, errA := collector.CollectSnapshot(ctx)
	if errA != nil {
		return
	}
	time.Sleep(200 * time.Millisecond)
	snapB, errB := collector.CollectSnapshot(ctx)
	if errB != nil {
		return
	}
	diff := collector.DiffSnapshots(snapA, snapB)
	report := engine.Analyze(diff, runCtx)
	state.LastDiff = diff
	state.LastReport = report
}

func handleKeyPress(key string, state *UIState, screen *Screen) bool {
	switch key {
	case "q", "\x03": // q or Ctrl+C
		return true
	case "\x1b[A", "\x1bOA", "k": // Up
		if state.TableState.CursorIdx > 0 {
			state.TableState.CursorIdx--
			updateSelectedPID(state)
		}
	case "\x1b[B", "\x1bOB", "j": // Down
		state.TableState.CursorIdx++
		updateSelectedPID(state)
	case "l", "p": // Lock / Pin selected PID
		toggleLockPID(state)
	case " ": // Space (Pause / Freeze)
		state.IsFrozen = !state.IsFrozen
	case "s": // Save report
		saveReport(state)
	case "1":
		state.TableState.SortMode = SortByCPU
	case "2":
		state.TableState.SortMode = SortByMemory
	case "3":
		state.TableState.SortMode = SortByIO
	case "4":
		state.TableState.SortMode = SortByDState
	case "?":
		toggleModal(state, ModalHelp)
	case "c":
		toggleModal(state, ModalCausalTree)
	case "\t":
		cycleModal(state)
	case "\r", "\n":
		toggleModal(state, ModalDrilldown)
	case "x":
		toggleModal(state, ModalBlastRadius)
	case "\x1b", "n": // Esc or Cancel
		state.ActiveModal = ModalNone
	case "y":
		if state.ActiveModal == ModalBlastRadius {
			applyRemedyAction(state)
		}
	}
	return false
}

func updateSelectedPID(state *UIState) {
	if state.LastDiff == nil || len(state.LastDiff.Processes) == 0 {
		return
	}
	culpritPID := getCulpritPID(state)
	sorted := sortProcesses(state.LastDiff.Processes, state.TableState.SortMode, culpritPID)
	if state.TableState.CursorIdx < len(sorted) {
		state.TableState.SelectedPID = sorted[state.TableState.CursorIdx].PID
	}
}

func getCulpritPID(state *UIState) int {
	if state.LastReport != nil && state.LastReport.PrimaryBlocker != nil {
		return state.LastReport.PrimaryBlocker.CulpritPID
	}
	return 0
}

func toggleLockPID(state *UIState) {
	if state.TableState.LockedPID > 0 {
		state.TableState.LockedPID = 0
		return
	}
	if state.TableState.SelectedPID > 0 {
		state.TableState.LockedPID = state.TableState.SelectedPID
	}
}

func cycleModal(state *UIState) {
	switch state.ActiveModal {
	case ModalNone:
		state.ActiveModal = ModalDrilldown
	case ModalDrilldown:
		state.ActiveModal = ModalCausalTree
	case ModalCausalTree:
		state.ActiveModal = ModalHelp
	default:
		state.ActiveModal = ModalNone
	}
}

func toggleModal(state *UIState, target ActiveModal) {
	if state.ActiveModal == target {
		state.ActiveModal = ModalNone
	} else {
		state.ActiveModal = target
	}
}

func saveReport(state *UIState) {
	if state.LastReport == nil {
		return
	}
	filename := fmt.Sprintf("why-slow-report-%d.json", time.Now().Unix())
	data, err := json.MarshalIndent(state.LastReport, "", "  ")
	if err == nil {
		_ = os.WriteFile(filename, data, 0644)
	}
}

func applyRemedyAction(state *UIState) {
	if state.LastDiff == nil || len(state.LastDiff.Processes) == 0 {
		return
	}
	idx := state.TableState.CursorIdx
	if idx >= len(state.LastDiff.Processes) {
		return
	}
	p := state.LastDiff.Processes[idx]
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, p.PID, 19)
	state.ActiveModal = ModalNone
}

func renderFrame(s *Screen, state *UIState, fd int) {
	if curW, curH, err := GetTerminalSize(fd); err == nil && curW > 0 && curH > 0 {
		s.Width, s.Height = curW, curH
	}

	s.Clear()
	w, h := s.Width, s.Height

	RenderHeader(s, state.Theme, state.LastReport, state.LastDiff, w)

	blockerH := 8
	RenderPrimaryBlocker(s, state.Theme, state.LastReport, 6, w, blockerH)

	tableY := 6 + blockerH
	tableH := h - tableY - 4
	culpritPID := getCulpritPID(state)
	if tableH > 5 && state.LastDiff != nil {
		RenderProcessTable(s, state.Theme, state.LastDiff.Processes, &state.TableState, culpritPID, tableY, w, tableH)
	}

	matrixY := h - 3
	RenderRuleMatrix(s, state.Theme, state.LastReport, matrixY, w)

	renderActiveModal(s, state, culpritPID, w, h)
	_ = s.Flush(os.Stdout)
}

func renderActiveModal(s *Screen, state *UIState, culpritPID, w, h int) {
	switch state.ActiveModal {
	case ModalHelp:
		RenderHelpModal(s, state.Theme, w, h)
	case ModalCausalTree:
		RenderCausalTreeModal(s, state.Theme, state.LastReport, w, h)
	case ModalDrilldown:
		if state.LastDiff != nil && len(state.LastDiff.Processes) > 0 {
			sorted := sortProcesses(state.LastDiff.Processes, state.TableState.SortMode, culpritPID)
			if state.TableState.CursorIdx < len(sorted) {
				p := sorted[state.TableState.CursorIdx]
				RenderDrilldownModal(s, state.Theme, &p, w, h)
			}
		}
	case ModalBlastRadius:
		if state.LastDiff != nil && len(state.LastDiff.Processes) > 0 {
			sorted := sortProcesses(state.LastDiff.Processes, state.TableState.SortMode, culpritPID)
			if state.TableState.CursorIdx < len(sorted) {
				p := sorted[state.TableState.CursorIdx]
				impact := AssessBlastRadius(p.PID, p.Comm, state.LastDiff.Processes, state.LastReport.PrimaryBlocker)
				RenderBlastRadiusModal(s, state.Theme, p.PID, p.Comm, impact, w, h)
			}
		}
	}
}
