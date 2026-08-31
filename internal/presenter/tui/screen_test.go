package tui

import (
	"bytes"
	"strings"
	"testing"
)

func TestScreenDrawBox(t *testing.T) {
	theme := NewTheme(true)
	screen := NewScreen(80, 24, theme)

	screen.DrawBox(1, 1, 40, 10, "TEST PANEL")
	var buf bytes.Buffer
	if err := screen.Flush(&buf); err != nil {
		t.Fatalf("unexpected error flushing screen: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "TEST PANEL") {
		t.Errorf("expected screen to contain title 'TEST PANEL'")
	}
	if !strings.Contains(out, BoxTopLeft) || !strings.Contains(out, BoxBottomRight) {
		t.Errorf("expected screen to contain box border characters")
	}
}

func TestThemeProgressBar(t *testing.T) {
	theme := NewTheme(true)
	bar := theme.ProgressBar(50.0, 10)
	if !strings.Contains(bar, "50.0%") {
		t.Errorf("expected bar to contain '50.0%%', got %s", bar)
	}
	if !strings.Contains(bar, "|||||     ") {
		t.Errorf("expected 5 filled bars and 5 spaces, got %s", bar)
	}
}

func TestThemeSeverityBadge(t *testing.T) {
	theme := NewTheme(true)
	badgeCrit := theme.SeverityBadge("CRITICAL")
	if !strings.Contains(badgeCrit, "CRITICAL") {
		t.Errorf("expected badge to contain CRITICAL, got %s", badgeCrit)
	}
	badgeHealthy := theme.SeverityBadge("HEALTHY")
	if !strings.Contains(badgeHealthy, "HEALTHY") {
		t.Errorf("expected badge to contain HEALTHY, got %s", badgeHealthy)
	}
}
