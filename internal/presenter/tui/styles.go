// Package tui — styles.go provides color palettes, box-drawing characters,
// and progress gauge builders for terminal visualization.
package tui

import (
	"fmt"
	"os"
	"strings"
)

// ANSI Color & Formatting Constants.
const (
	Reset       = "\033[0m"
	Bold        = "\033[1m"
	Dim         = "\033[2m"
	Italic      = "\033[3m"
	Underline   = "\033[4m"
	Reverse     = "\033[7m"
	FgBlack     = "\033[30m"
	FgRed       = "\033[31m"
	FgGreen     = "\033[32m"
	FgYellow    = "\033[33m"
	FgBlue      = "\033[34m"
	FgMagenta   = "\033[35m"
	FgCyan      = "\033[36m"
	FgWhite     = "\033[37m"
	FgHiBlack   = "\033[90m"
	FgHiRed     = "\033[91m"
	FgHiGreen   = "\033[92m"
	FgHiYellow  = "\033[93m"
	FgHiBlue    = "\033[94m"
	FgHiMagenta = "\033[95m"
	FgHiCyan    = "\033[96m"
	FgHiWhite   = "\033[97m"
	BgRed       = "\033[41m"
	BgGreen     = "\033[42m"
	BgYellow    = "\033[43m"
	BgBlue      = "\033[44m"
	BgHiBlack   = "\033[100m"
)

// Box-Drawing Unicode Characters.
const (
	BoxTopLeft     = "┌"
	BoxTopRight    = "┐"
	BoxBottomLeft  = "└"
	BoxBottomRight = "┘"
	BoxHorizontal  = "─"
	BoxVertical    = "│"
	BoxTeeDown     = "┬"
	BoxTeeUp       = "┴"
	BoxTeeRight    = "├"
	BoxTeeLeft     = "┤"
	BoxCross       = "┼"
)

// Theme encapsulates styling methods with NO_COLOR awareness.
type Theme struct {
	NoColor bool
}

// NewTheme creates a new theme respecting NO_COLOR environment variable.
func NewTheme(noColor bool) *Theme {
	if _, exists := os.LookupEnv("NO_COLOR"); exists {
		noColor = true
	}
	return &Theme{NoColor: noColor}
}

// Colorize wraps text in ANSI sequence if color is enabled.
func (t *Theme) Colorize(text, colorSeq string) string {
	if t.NoColor {
		return text
	}
	return colorSeq + text + Reset
}

// SeverityBadge returns a stylized, color-coded severity tag.
func (t *Theme) SeverityBadge(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return t.Colorize(" [! CRITICAL] ", BgRed+FgHiWhite+Bold)
	case "HIGH":
		return t.Colorize(" [▲ HIGH] ", BgYellow+FgBlack+Bold)
	case "MEDIUM":
		return t.Colorize(" [• MEDIUM] ", FgHiYellow+Bold)
	case "INFO":
		return t.Colorize(" [i INFO] ", FgHiCyan)
	default:
		return t.Colorize(" [✓ HEALTHY] ", FgHiGreen+Bold)
	}
}

// ProgressBar renders a visual progress gauge (e.g. "[||||||||      ] 54.0%").
func (t *Theme) ProgressBar(percent float64, width int) string {
	if width < 5 {
		width = 10
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	filled := int((percent / 100.0) * float64(width))
	if filled > width {
		filled = width
	}
	empty := width - filled

	barChars := strings.Repeat("|", filled) + strings.Repeat(" ", empty)

	var color string
	if percent >= 80.0 {
		color = FgHiRed + Bold
	} else if percent >= 40.0 {
		color = FgHiYellow
	} else {
		color = FgHiGreen
	}

	return fmt.Sprintf("[%s] %5.1f%%", t.Colorize(barChars, color), percent)
}
