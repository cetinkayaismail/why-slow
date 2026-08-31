// Package tui provides an interactive, double-buffered Terminal User Interface
// for real-time Linux kernel bottleneck diagnostics and root-cause visualization.
package tui

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// TermState preserves original terminal termios state to guarantee clean restoration.
type TermState struct {
	termios syscall.Termios
}

// winsize matches the Linux kernel struct winsize for TIOCGWINSZ ioctl.
type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// EnableRawMode puts the terminal into raw mode (non-canonical, no echo, non-blocking input).
func EnableRawMode(fd int) (*TermState, error) {
	var oldTermios syscall.Termios
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS, uintptr(unsafe.Pointer(&oldTermios))); err != 0 {
		return nil, fmt.Errorf("tui: tcgets failed: %w", err)
	}

	raw := oldTermios
	// Disable echo, canonical mode, extended input processing, and interrupt signals
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.IEXTEN | syscall.ISIG
	// Disable software flow control and carriage return translation
	raw.Iflag &^= syscall.IXON | syscall.ICRNL | syscall.BRKINT | syscall.INPCK | syscall.ISTRIP
	// Set 8-bit characters
	raw.Cflag |= syscall.CS8
	// Disable output post-processing
	raw.Oflag &^= syscall.OPOST

	// Non-blocking read with 100ms timeout
	raw.Cc[syscall.VMIN] = 0
	raw.Cc[syscall.VTIME] = 1

	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS, uintptr(unsafe.Pointer(&raw))); err != 0 {
		return nil, fmt.Errorf("tui: tcsets raw mode failed: %w", err)
	}

	return &TermState{termios: oldTermios}, nil
}

// Restore canonical mode using the preserved TermState.
func Restore(fd int, state *TermState) error {
	if state == nil {
		return nil
	}
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS, uintptr(unsafe.Pointer(&state.termios))); err != 0 {
		return fmt.Errorf("tui: restore terminal state failed: %w", err)
	}
	return nil
}

// GetTerminalSize returns the current columns and rows of the terminal window.
func GetTerminalSize(fd int) (width, height int, err error) {
	var ws winsize
	if _, _, errSys := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws))); errSys != 0 {
		return 80, 24, fmt.Errorf("tui: tiocgwinsz failed: %w", errSys)
	}
	if ws.Col == 0 || ws.Row == 0 {
		return 80, 24, nil
	}
	return int(ws.Col), int(ws.Row), nil
}

// IsTerminal returns true if the given file descriptor is connected to a live TTY.
func IsTerminal(fd int) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS, uintptr(unsafe.Pointer(&termios)))
	return err == 0
}

// ReadKey reads a single keypress or ANSI escape sequence from stdin.
func ReadKey(f *os.File) (string, error) {
	buf := make([]byte, 16)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return "", err
	}
	return string(buf[:n]), nil
}
