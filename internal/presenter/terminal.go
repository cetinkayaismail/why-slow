// Package presenter provides terminal and JSON output formatters
// for why-slow diagnostic reports.
package presenter

import (
	"fmt"
	"io"
	"os"
	"strings"
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

// TerminalOptions specifies configuration options for terminal rendering.
type TerminalOptions struct {
	NoColor    bool
	ShowRemedy bool
}

// RenderTerminal writes the diagnostic report formatted as an ANSI diagnostic card to w.
func RenderTerminal(w io.Writer, report *analyzer.DiagnosticReport, opts TerminalOptions) error {
	if report == nil {
		return fmt.Errorf("presenter: report is nil")
	}

	c := NewTerminalColors(opts.NoColor)
	divider := "─────────────────────────────────────────────────────────────────────────────"

	if report.PrimaryBlocker == nil {
		renderHealthyCard(w, report, c, divider)
	} else {
		renderBlockerCard(w, report, c, divider, opts)
	}

	renderContributing(w, report, c)
	if report.PIDFocus != nil {
		renderPIDFocus(w, report.PIDFocus, c, divider)
	}
	if len(report.TopProcesses) > 0 {
		renderTopProcesses(w, report, c, divider)
	}
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

func tierName(tier int) string {
	switch tier {
	case 1:
		return "Tier 1 (Base Hard Limits)"
	case 2:
		return "Tier 2 (Resource Contention)"
	case 3:
		return "Tier 3 (Kernel Edge Cases)"
	default:
		return fmt.Sprintf("Tier %d", tier)
	}
}

func renderBlockerCard(w io.Writer, report *analyzer.DiagnosticReport, c TerminalColors, divider string, opts TerminalOptions) {
	p := report.PrimaryBlocker
	color := severityColor(p.Severity, c)

	fmt.Fprintf(w, "\n%s[!] %s BOTTLENECK: %s%s\n", color, p.Severity, p.Title, c.Reset)
	fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)
	if p.RuleID != "" {
		fmt.Fprintf(w, "%sRule ID:%s %s | %s%s%s | %sConfidence:%s %.1f%%\n",
			c.Bold, c.Reset, p.RuleID,
			c.Dim, tierName(p.Tier), c.Reset,
			c.Bold, c.Reset, p.Confidence*100.0)
		fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)
	}

	fmt.Fprintf(w, "%sDiagnostic Finding:%s\n  %s\n\n", c.Bold, c.Reset, p.Explanation)

	if len(p.Evidence) > 0 {
		fmt.Fprintf(w, "%sDiagnostic Proof:%s\n", c.Bold, c.Reset)
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

	if opts.ShowRemedy && p.Remediation != "" {
		fmt.Fprintf(w, "%sRecommended Remediation:%s\n  • %s%s%s\n", c.Bold, c.Reset, c.Green, p.Remediation, c.Reset)
	} else if !opts.ShowRemedy && p.Remediation != "" {
		fmt.Fprintf(w, "%s(Tip: Run with --remedy to view system remediation advice)%s\n", c.Dim, c.Reset)
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

func renderPIDFocus(w io.Writer, pf *analyzer.PIDFocusReport, c TerminalColors, divider string) {
	fmt.Fprintf(w, "%sProcess Deep Dive: PID %d (%s)%s\n", c.Bold, pf.PID, pf.Comm, c.Reset)
	fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)

	fmt.Fprintf(w, "  • %sState:%s %s | %sPPID:%s %d | %sThreads:%s %d\n",
		c.Bold, c.Reset, pf.State, c.Bold, c.Reset, pf.PPID, c.Bold, c.Reset, pf.NumThreads)

	fmt.Fprintf(w, "  • %sCPU:%s %.1f%% | %sRSS:%s %.1f MB | %sSwap:%s %.1f MB\n",
		c.Bold, c.Reset, pf.CPUPercent, c.Bold, c.Reset, pf.RSSMB, c.Bold, c.Reset, pf.SwapMB)

	fmt.Fprintf(w, "  • %sI/O Delta:%s Read %.1f KB | Write %.1f KB\n",
		c.Bold, c.Reset, pf.ReadKB, pf.WriteKB)

	fmt.Fprintf(w, "  • %sFDs:%s %d / %d (%.1f%% of limit)\n",
		c.Bold, c.Reset, pf.OpenFDs, pf.MaxFDs, pf.FDRatio*100)

	fmt.Fprintf(w, "    %sFD Breakdown:%s Files: %d | Sockets: %d | Pipes: %d | Anon: %d | Other: %d\n",
		c.Dim, c.Reset, pf.FDTypes.Files, pf.FDTypes.Sockets, pf.FDTypes.Pipes, pf.FDTypes.AnonInodes, pf.FDTypes.Other)

	if pf.SmapsRollup.Available {
		fmt.Fprintf(w, "  • %sMemory PSS:%s %.1f MB | %sShared Dirty:%s %.1f MB | %sPrivate Dirty:%s %.1f MB\n",
			c.Bold, c.Reset, float64(pf.SmapsRollup.PSS)/1024,
			c.Bold, c.Reset, float64(pf.SmapsRollup.SharedDirty)/1024,
			c.Bold, c.Reset, float64(pf.SmapsRollup.PrivateDirty)/1024)
	}

	if pf.CgroupPath != "" || pf.Wchan != "" || pf.OOMScore != 0 || pf.OOMScoreAdj != 0 {
		fmt.Fprintf(w, "  • %sOOM Score:%s %d (adj: %d)", c.Bold, c.Reset, pf.OOMScore, pf.OOMScoreAdj)
		if pf.Wchan != "" {
			fmt.Fprintf(w, " | %sWchan:%s %s", c.Bold, c.Reset, pf.Wchan)
		}
		if pf.CgroupPath != "" {
			fmt.Fprintf(w, " | %sCgroup:%s %s", c.Bold, c.Reset, pf.CgroupPath)
		}
		fmt.Fprintln(w)
	}

	renderPIDRelatedIssues(w, pf.RelatedIssues, c)

	fmt.Fprintf(w, "%s%s%s\n\n", c.Dim, divider, c.Reset)
}

func renderPIDRelatedIssues(w io.Writer, issues []analyzer.Diagnosis, c TerminalColors) {
	if len(issues) > 0 {
		fmt.Fprintf(w, "\n  %sRelated Diagnostic Findings (%d):%s\n", c.Bold, len(issues), c.Reset)
		for _, issue := range issues {
			color := severityColor(issue.Severity, c)
			fmt.Fprintf(w, "  • %s[%s]%s %s — %s\n", color, issue.RuleID, c.Reset, issue.Title, issue.Explanation)
		}
	} else {
		fmt.Fprintf(w, "\n  %sRelated Diagnostic Findings:%s %sNone detected (process operating within normal thresholds)%s\n",
			c.Bold, c.Reset, c.Dim, c.Reset)
	}
}

func renderTopProcesses(w io.Writer, report *analyzer.DiagnosticReport, c TerminalColors, divider string) {
	fmt.Fprintf(w, "%sTop %d Processes (by CPU / Memory):%s\n", c.Bold, len(report.TopProcesses), c.Reset)
	fmt.Fprintf(w, "  %-7s  %-18s  %7s  %9s  %11s  %11s  %6s  %5s\n",
		"PID", "COMM", "CPU%", "RSS(MB)", "READΔ(KB)", "WRITEΔ(KB)", "FDS", "STATE")
	fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)

	for _, p := range report.TopProcesses {
		rssMB := p.RSSMB
		if rssMB == 0 && p.RSSBytes > 0 {
			rssMB = float64(p.RSSBytes) / (1024 * 1024)
		}
		readKB := p.ReadKB
		if readKB == 0 && p.ReadBytesDelta > 0 {
			readKB = float64(p.ReadBytesDelta) / 1024
		}
		writeKB := p.WriteKB
		if writeKB == 0 && p.WriteBytesDelta > 0 {
			writeKB = float64(p.WriteBytesDelta) / 1024
		}

		comm := p.Comm
		if len(comm) > 18 {
			comm = comm[:15] + "..."
		}

		fmt.Fprintf(w, "  %-7d  %-18s  %6.1f%%  %9.1f  %11.1f  %11.1f  %6d  %5s\n",
			p.PID, comm, p.CPUPercent, rssMB, readKB, writeKB, p.OpenFDs, p.State)
	}
	fmt.Fprintf(w, "%s%s%s\n\n", c.Dim, divider, c.Reset)
}

// RenderRuleExplanation writes a formatted diagnostic rule explanation to w.
func RenderRuleExplanation(w io.Writer, rule analyzer.Rule, noColor bool) {
	c := NewTerminalColors(noColor)
	expl := rule.Explain()

	fmt.Fprintf(w, "\n%sRule ID:%s      %s%s%s\n", c.Bold, c.Reset, c.Cyan, rule.ID(), c.Reset)
	fmt.Fprintf(w, "%sTier:%s         Tier %d\n", c.Bold, c.Reset, rule.Tier())
	fmt.Fprintf(w, "%sSubsystem:%s    %s%s%s\n", c.Bold, c.Reset, c.Cyan, RuleCategory(rule.ID()), c.Reset)
	fmt.Fprintf(w, "%sDescription:%s  %s\n\n", c.Bold, c.Reset, expl.Description)

	if len(expl.Thresholds) > 0 {
		fmt.Fprintf(w, "%sTrigger Thresholds:%s\n", c.Bold, c.Reset)
		for _, th := range expl.Thresholds {
			fmt.Fprintf(w, "  • %s\n", th)
		}
		fmt.Fprintln(w)
	}

	if len(expl.KernelSources) > 0 {
		fmt.Fprintf(w, "%sKernel Telemetry Sources:%s\n", c.Bold, c.Reset)
		for _, src := range expl.KernelSources {
			fmt.Fprintf(w, "  • %s\n", src)
		}
		fmt.Fprintln(w)
	}

	if expl.Remediation != "" {
		fmt.Fprintf(w, "%sRecommended Remediation:%s\n  • %s%s%s\n\n", c.Bold, c.Reset, c.Green, expl.Remediation, c.Reset)
	}
}

// RenderRuleList writes registered rule IDs grouped by Tier to w with clean styling and optional filtering.
func RenderRuleList(w io.Writer, rules []analyzer.Rule, filter string, noColor bool) {
	c := NewTerminalColors(noColor)
	divider := "─────────────────────────────────────────────────────────────────────────────"

	filtered := make([]analyzer.Rule, 0, len(rules))
	for _, r := range rules {
		if ruleMatchesFilter(r, filter) {
			filtered = append(filtered, r)
		}
	}

	renderCatalogHeader(w, rules, filtered, filter, c, divider)

	tierNames := map[int]string{
		1: "Tier 1 — Base Hard Limits (Primary Blockers)",
		2: "Tier 2 — Contention & Queuing (Contributing Factors)",
		3: "Tier 3 — Subtle Kernel Edge Cases",
	}

	for tier := 1; tier <= 3; tier++ {
		var tierRules []analyzer.Rule
		for _, r := range filtered {
			if r.Tier() == tier {
				tierRules = append(tierRules, r)
			}
		}
		if len(tierRules) == 0 {
			continue
		}

		fmt.Fprintf(w, "\n%s%s [%d Rules]%s\n", c.Bold, tierNames[tier], len(tierRules), c.Reset)
		fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)

		for _, r := range tierRules {
			cat := RuleCategory(r.ID())
			fmt.Fprintf(w, "  • %sRule ID:%s %s%s%s  %s[%s]%s\n", c.Cyan, c.Reset, c.Bold, r.ID(), c.Reset, c.Cyan, cat, c.Reset)
			desc := wrapText(r.Explain().Description, 85, "    ")
			fmt.Fprintf(w, "%s\n\n", desc)
		}
	}
}

func renderCatalogHeader(w io.Writer, all, filtered []analyzer.Rule, filter string, c TerminalColors, divider string) {
	if filter != "" {
		fmt.Fprintf(w, "\n%swhy-slow Diagnostic Rules — Filter: %q (%d matching of %d rules)%s\n", c.Bold, filter, len(filtered), len(all), c.Reset)
		fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)
		return
	}

	var t1, t2, t3 int
	for _, r := range all {
		switch r.Tier() {
		case 1:
			t1++
		case 2:
			t2++
		case 3:
			t3++
		}
	}

	fmt.Fprintf(w, "\n%swhy-slow Diagnostic Rules Catalog (%d Rules Registered)%s\n", c.Bold, len(all), c.Reset)
	fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)
	fmt.Fprintf(w, "  • %sTier 1%s (Base Hard Limits):     %2d rules  (Crash hazards, OOM, storage exhaustion)\n", c.Bold, c.Reset, t1)
	fmt.Fprintf(w, "  • %sTier 2%s (Resource Contention):  %2d rules  (Starvation, queuing, lock & memory churn)\n", c.Bold, c.Reset, t2)
	fmt.Fprintf(w, "  • %sTier 3%s (Kernel Edge Cases):   %3d rules  (Subsystem stalls, sysfs & driver edge cases)\n\n", c.Bold, c.Reset, t3)
	fmt.Fprintf(w, "  %sTip:%s Filter rules by subsystem:  %swhy-slow --list-rules [cpu|mem|storage|net|cgroup|proc]%s\n", c.Yellow, c.Reset, c.Bold, c.Reset)
	exampleID := "BASE_CPU_SATURATION"
	if len(all) > 0 {
		exampleID = all[0].ID()
	}
	fmt.Fprintf(w, "  %sTip:%s Inspect rule thresholds:    %swhy-slow --explain <RULE_ID>%s (e.g. %swhy-slow --explain %s%s)\n", c.Yellow, c.Reset, c.Bold, c.Reset, c.Cyan, exampleID, c.Reset)
	fmt.Fprintf(w, "%s%s%s\n", c.Dim, divider, c.Reset)
}

func ruleMatchesFilter(r analyzer.Rule, filter string) bool {
	if filter == "" {
		return true
	}
	f := strings.ToLower(filter)
	id := strings.ToLower(r.ID())
	desc := strings.ToLower(r.Explain().Description)
	cat := strings.ToLower(RuleCategory(r.ID()))
	tierStr := fmt.Sprintf("tier%d", r.Tier())

	return strings.Contains(id, f) ||
		strings.Contains(desc, f) ||
		strings.EqualFold(cat, f) ||
		strings.Contains(tierStr, f)
}

// RuleCategory detects a human-friendly subsystem category for a rule ID.
func RuleCategory(ruleID string) string {
	r := strings.ToUpper(ruleID)
	if strings.Contains(r, "CGROUP") || strings.Contains(r, "MEMCG") {
		return "Cgroup"
	}
	if strings.Contains(r, "TCP") || strings.Contains(r, "NET") || strings.Contains(r, "CONNTRACK") ||
		strings.Contains(r, "ARP") || strings.Contains(r, "IP_") || strings.Contains(r, "UDP") ||
		strings.Contains(r, "SOCKET") || strings.Contains(r, "TIMEWAIT") {
		return "Network"
	}
	if strings.Contains(r, "DISK") || strings.Contains(r, "FS") || strings.Contains(r, "INODE") ||
		strings.Contains(r, "BLK") || strings.Contains(r, "DM_") || strings.Contains(r, "EXT4") ||
		strings.Contains(r, "LOOP") || strings.Contains(r, "FUSE") || strings.Contains(r, "AIO") ||
		strings.Contains(r, "SCHEDULER") || strings.Contains(r, "RAID") || strings.Contains(r, "STORAGE") ||
		strings.Contains(r, "IO_SERVICE") || strings.Contains(r, "IO_QUEUE") || strings.Contains(r, "IO_PRESSURE") {
		return "Storage"
	}
	if strings.Contains(r, "OOM") || strings.Contains(r, "MEM") || strings.Contains(r, "SWAP") ||
		strings.Contains(r, "THP") || strings.Contains(r, "COMPACT") || strings.Contains(r, "SLAB") ||
		strings.Contains(r, "CMA") || strings.Contains(r, "BALLOON") || strings.Contains(r, "ZSWAP") ||
		strings.Contains(r, "HUGETLB") || strings.Contains(r, "HUGEPAGE") || strings.Contains(r, "PAGE") ||
		strings.Contains(r, "ZONE") || strings.Contains(r, "NUMA") || strings.Contains(r, "KSM") ||
		strings.Contains(r, "WORKINGSET") || strings.Contains(r, "MIN_FREE") {
		return "Memory"
	}
	if strings.Contains(r, "CPU") || strings.Contains(r, "SCHED") || strings.Contains(r, "CONTEXT_SWITCH") ||
		strings.Contains(r, "THERMAL") || strings.Contains(r, "GOVERNOR") || strings.Contains(r, "POWER") ||
		strings.Contains(r, "IRQ") || strings.Contains(r, "LOAD_SATURATION") {
		return "CPU"
	}
	if strings.Contains(r, "PROC") || strings.Contains(r, "TASK") || strings.Contains(r, "DSTATE") ||
		strings.Contains(r, "MUTEX") || strings.Contains(r, "FUTEX") || strings.Contains(r, "PTY") ||
		strings.Contains(r, "COREDUMP") || strings.Contains(r, "INOTIFY") || strings.Contains(r, "EPOLL") ||
		strings.Contains(r, "ZOMBIE") || strings.Contains(r, "AUDITD") || strings.Contains(r, "FILE_TABLE") ||
		strings.Contains(r, "FD_") || strings.Contains(r, "PID_") || strings.Contains(r, "PIPE") ||
		strings.Contains(r, "PTRACE") || strings.Contains(r, "SYSV") || strings.Contains(r, "RTSIG") {
		return "Process"
	}
	return "Kernel"
}

// wrapText splits a single-line string into word-wrapped lines indented by indent.
func wrapText(text string, maxWidth int, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := len(indent)
	b.WriteString(indent)

	for i, w := range words {
		wLen := len(w)
		if i > 0 && lineLen+1+wLen > maxWidth {
			b.WriteByte('\n')
			b.WriteString(indent)
			lineLen = len(indent)
		} else if i > 0 {
			b.WriteByte(' ')
			lineLen++
		}
		b.WriteString(w)
		lineLen += wLen
	}
	return b.String()
}
