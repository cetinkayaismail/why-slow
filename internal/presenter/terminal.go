// Package presenter provides terminal and JSON output formatters
// for why-slow diagnostic reports.
package presenter

import (
	"fmt"
	"io"
	"os"
	"why-slow/internal/analyzer"
)

// TerminalColors holds ANSI escape codes for stylized terminal rendering.
type TerminalColors struct {
	Reset  string
	Bold   string
	Dim    string
	Red    string
	Yellow string
	Cyan   string
	Green  string
	White  string
}

// NewTerminalColors returns ANSI color codes or empty strings if disabled.
func NewTerminalColors(noColor bool) TerminalColors {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return TerminalColors{}
	}
	return TerminalColors{
		Reset:  "\033[0m",
		Bold:   "\033[1m",
		Dim:    "\033[2m",
		Red:    "\033[1;31m",
		Yellow: "\033[1;33m",
		Cyan:   "\033[1;36m",
		Green:  "\033[1;32m",
		White:  "\033[1;37m",
	}
}

// RenderTerminal writes the diagnostic report formatted as an ANSI diagnostic card to w.
func RenderTerminal(w io.Writer, report *analyzer.DiagnosticReport, noColor bool) error {
	if report == nil {
		return fmt.Errorf("presenter: report is nil")
	}

	c := NewTerminalColors(noColor)
	divider := "─────────────────────────────────────────────────────────────────────────────"

	if report.PrimaryBlocker == nil {
		renderHealthyCard(w, report, c, divider)
	} else {
		renderBlockerCard(w, report, c, divider)
	}

	renderContributing(w, report, c)
	renderPrivilegeFooter(w, report, c, divider)

	return nil
}

func renderHealthyCard(w io.Writer, report *analyzer.DiagnosticReport, c TerminalColors, divider string) {
	fmt.Fprintf(w, "\n%s[✓] SYSTEM HEALTHY: No critical bottlenecks detected%s\n", c.Green, c.Reset)
	fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)
	fmt.Fprintf(w, "%sSampling Window:%s %s\n", c.Bold, c.Reset, report.Duration)

	if report.SystemPressure.Available {
		fmt.Fprintf(w, "\n%sSystem Pressure (PSI):%s\n", c.Bold, c.Reset)
		fmt.Fprintf(w, "  • CPU Stall:    %.2f%%\n", report.SystemPressure.CPUStallPercent)
		fmt.Fprintf(w, "  • Memory Stall: %.2f%%\n", report.SystemPressure.MemoryStallPercent)
		fmt.Fprintf(w, "  • I/O Stall:    %.2f%%\n", report.SystemPressure.IOStallPercent)
	}
	fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)
}

func renderBlockerCard(w io.Writer, report *analyzer.DiagnosticReport, c TerminalColors, divider string) {
	p := report.PrimaryBlocker
	color := severityColor(p.Severity, c)

	fmt.Fprintf(w, "\n%s[!] %s BOTTLENECK: %s%s\n", color, p.Severity, p.Title, c.Reset)
	fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)

	fmt.Fprintf(w, "%sPrimary Cause:%s\n  %s\n\n", c.Bold, c.Reset, p.Explanation)

	if len(p.Evidence) > 0 {
		fmt.Fprintf(w, "%sKernel Evidence:%s\n", c.Bold, c.Reset)
		for _, ev := range p.Evidence {
			fmt.Fprintf(w, "  • %s\n", ev)
		}
		fmt.Fprintln(w)
	}

	if p.CulpritPID > 0 || p.CulpritName != "" {
		fmt.Fprintf(w, "%sCulprit Process:%s\n", c.Bold, c.Reset)
		fmt.Fprintf(w, "  • PID %d [%s%s%s]", p.CulpritPID, c.Cyan, p.CulpritName, c.Reset)
		if p.CulpritDetails != "" {
			fmt.Fprintf(w, " (%s)", p.CulpritDetails)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w)
	}

	if p.Remediation != "" {
		fmt.Fprintf(w, "%sRecommended Remediation:%s\n  • %s%s%s\n", c.Bold, c.Reset, c.Green, p.Remediation, c.Reset)
	}
	fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)
}

func renderContributing(w io.Writer, report *analyzer.DiagnosticReport, c TerminalColors) {
	if len(report.ContributingFactors) == 0 && len(report.SecondaryIssues) == 0 {
		return
	}

	fmt.Fprintf(w, "%sContributing & Secondary Findings:%s\n", c.Bold, c.Reset)
	for _, f := range report.ContributingFactors {
		color := severityColor(f.Severity, c)
		fmt.Fprintf(w, "  • %s[%s]%s %s — %s\n", color, f.RuleID, c.Reset, f.Title, f.Explanation)
	}
	for _, s := range report.SecondaryIssues {
		fmt.Fprintf(w, "  • %s[%s]%s %s — %s\n", c.Dim, s.RuleID, c.Reset, s.Title, s.Explanation)
	}
	fmt.Fprintln(w)
}

func renderPrivilegeFooter(w io.Writer, report *analyzer.DiagnosticReport, c TerminalColors, divider string) {
	if report.PrivilegeLevel != "unprivileged" {
		return
	}

	fmt.Fprintf(w, "%s%s⚠ Running as unprivileged user. Some process data and /proc/[pid]/io may be hidden.%s\n", c.Yellow, c.Dim, c.Reset)
	fmt.Fprintf(w, "%s  Run with 'sudo why-slow' for complete system-wide process visibility.%s\n\n", c.Dim, c.Reset)
}

func severityColor(s analyzer.Severity, c TerminalColors) string {
	switch s {
	case analyzer.SeverityCritical:
		return c.Red
	case analyzer.SeverityHigh:
		return c.Yellow
	case analyzer.SeverityMedium:
		return c.Cyan
	default:
		return c.White
	}
}
