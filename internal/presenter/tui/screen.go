// Package tui — screen.go provides double-buffered virtual terminal screen
// rendering to eliminate screen flicker over SSH sessions.
package tui

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// Screen encapsulates a double-buffered virtual terminal viewport.
type Screen struct {
	Width  int
	Height int
	buf    bytes.Buffer
	theme  *Theme
}

// NewScreen initializes a new virtual screen with target dimensions.
func NewScreen(width, height int, theme *Theme) *Screen {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	s := &Screen{
		Width:  width,
		Height: height,
		theme:  theme,
	}
	s.buf.Grow(width * height * 4)
	return s
}

// EnterAltScreen switches the terminal to the alternate screen buffer.
func (s *Screen) EnterAltScreen() {
	s.buf.WriteString("\033[?1049h\033[2J\033[H\033[?25l")
}

// ExitAltScreen exits the alternate screen buffer and restores cursor.
func (s *Screen) ExitAltScreen() {
	s.buf.WriteString("\033[?25h\033[2J\033[?1049l")
}

// Clear resets cursor to top-left and clears buffer.
func (s *Screen) Clear() {
	s.buf.Reset()
	s.buf.WriteString("\033[2J\033[H")
}

// MoveTo sets cursor position (1-indexed).
func (s *Screen) MoveTo(row, col int) {
	fmt.Fprintf(&s.buf, "\033[%d;%dH", row, col)
}

// PrintAt writes formatted text at specific (row, col) coordinates.
func (s *Screen) PrintAt(row, col int, text string) {
	s.MoveTo(row, col)
	s.buf.WriteString(text)
}

// PrintLineAt prints a line at (row, col) fitted and padded precisely to target width.
func (s *Screen) PrintLineAt(row, col, width int, text string) {
	if width <= 0 {
		return
	}
	fitted := TruncateVisible(text, width)
	padded := PadRightVisible(fitted, width)
	s.MoveTo(row, col)
	s.buf.WriteString(padded)
	s.buf.WriteString("\033[K")
}

// DrawBox renders a framed box with an optional title.
func (s *Screen) DrawBox(x, y, w, h int, title string) {
	if w < 4 || h < 2 {
		return
	}

	// Top border
	s.MoveTo(y, x)
	s.buf.WriteString(BoxTopLeft)
	if title != "" {
		titleText := fmt.Sprintf(" %s ", title)
		titleLen := VisibleLen(titleText)
		if titleLen < w-2 {
			s.buf.WriteString(s.theme.Colorize(titleText, Bold+FgHiCyan))
			s.buf.WriteString(strings.Repeat(BoxHorizontal, w-2-titleLen))
		} else {
			s.buf.WriteString(strings.Repeat(BoxHorizontal, w-2))
		}
	} else {
		s.buf.WriteString(strings.Repeat(BoxHorizontal, w-2))
	}
	s.buf.WriteString(BoxTopRight)

	// Side borders and interior line blanks
	for row := 1; row < h-1; row++ {
		s.MoveTo(y+row, x)
		s.buf.WriteString(BoxVertical)
		s.buf.WriteString(strings.Repeat(" ", w-2))
		s.buf.WriteString(BoxVertical)
	}

	// Bottom border
	s.MoveTo(y+h-1, x)
	s.buf.WriteString(BoxBottomLeft)
	s.buf.WriteString(strings.Repeat(BoxHorizontal, w-2))
	s.buf.WriteString(BoxBottomRight)
}

// DrawDivider renders a horizontal divider line across the box.
func (s *Screen) DrawDivider(x, y, w int) {
	s.MoveTo(y, x)
	s.buf.WriteString(BoxTeeRight)
	s.buf.WriteString(strings.Repeat(BoxHorizontal, w-2))
	s.buf.WriteString(BoxTeeLeft)
}

// Flush writes the double-buffered frame to the terminal output in a single write.
func (s *Screen) Flush(w io.Writer) error {
	_, err := s.buf.WriteTo(w)
	return err
}
