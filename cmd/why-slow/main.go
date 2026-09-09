// Package main is the CLI entry point for why-slow.
// It parses flags, detects privilege level, orchestrates the
// collect → analyze → present pipeline, and renders output.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
	"why-slow/internal/presenter"
)

var version = "dev"

type cliConfig struct {
	json           bool
	compact        bool
	noColor        bool
	interval       time.Duration
	samples        int
	watch          bool
	alertThreshold string
	top            int
	pid            int
	explain        string
	listRules      bool
	disableRules   string
	remedy         bool
}

func main() {
	cfg, topPassed := parseFlags()
	engine := analyzer.NewEngine()

	if err := validateConfig(cfg, topPassed, engine); err != nil {
		fmt.Fprintf(os.Stderr, "why-slow: %v\n", err)
		os.Exit(1)
	}

	if handleRuleCommands(cfg, engine) {
		return
	}

	runCtx := collector.RunContext{
		IsRoot:       os.Getuid() == 0,
		EffectiveUID: os.Geteuid(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setupSignalHandler(cancel)

	if cfg.watch {
		runWatchLoop(ctx, cfg, runCtx, engine)
		return
	}

	showProgress := !cfg.json && !cfg.watch && isTerminal(os.Stderr)
	diff := captureSamples(ctx, cfg.interval, cfg.samples, showProgress)
	report := engine.Analyze(diff, runCtx)
	if cfg.pid > 0 {
		report.PIDFocus = extractPIDFocus(diff, cfg.pid, report)
	}
	if cfg.top > 0 {
		report.TopProcesses = extractTopProcesses(diff, cfg.top)
	}
	renderReport(report, cfg)
}

func parseFlags() (*cliConfig, bool) {
	cfg := &cliConfig{}
	flag.BoolVar(&cfg.json, "json", false, "Output diagnostic report in machine-readable JSON format")
	flag.BoolVar(&cfg.compact, "compact", false, "Output compact single-line JSON (used with -json)")
	flag.DurationVar(&cfg.interval, "interval", 3*time.Second, "Sampling window interval between snapshots (e.g. 1s, 3s, 5s)")
	flag.BoolVar(&cfg.noColor, "no-color", false, "Disable ANSI color coding in terminal output")
	flag.IntVar(&cfg.samples, "samples", 1, "Number of sampling windows to collect (uses median for statistical noise reduction)")
	flag.BoolVar(&cfg.watch, "watch", false, "Run continuously in watch mode, reporting findings meeting alert threshold")
	flag.StringVar(&cfg.alertThreshold, "alert-threshold", "info", "Minimum severity to report in watch mode (critical, high, medium, info)")
	var versionFlag bool
	flag.BoolVar(&versionFlag, "version", false, "Print why-slow version and exit")
	flag.IntVar(&cfg.top, "top", 0, "Append Top N processes table sorted by CPU and RSS")
	flag.IntVar(&cfg.pid, "pid", 0, "Single-process deep dive analysis for target PID")
	flag.StringVar(&cfg.explain, "explain", "", "Print detailed documentation for a diagnostic rule and exit")
	flag.BoolVar(&cfg.listRules, "list-rules", false, "List all registered diagnostic rules grouped by tier and exit")
	flag.StringVar(&cfg.disableRules, "disable-rules", "", "Comma-separated list of rule IDs to disable")
	flag.BoolVar(&cfg.remedy, "remedy", false, "Display recommended remediation and tuning advice for diagnosed issues")
	var rFlag bool
	flag.BoolVar(&rFlag, "r", false, "Alias for --remedy (display remediation advice)")

	setupFlagUsage()
	flag.Parse()

	if versionFlag {
		fmt.Printf("why-slow version %s\n", version)
		os.Exit(0)
	}
	if rFlag {
		cfg.remedy = true
	}

	topPassed := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "top" {
			topPassed = true
		}
	})

	return cfg, topPassed
}

func validateConfig(cfg *cliConfig, topPassed bool, engine *analyzer.Engine) error {
	if cfg.interval <= 0 {
		return fmt.Errorf("invalid interval '%v', must be positive", cfg.interval)
	}
	if cfg.samples <= 0 {
		return fmt.Errorf("invalid samples '%d', must be >= 1", cfg.samples)
	}
	if topPassed && cfg.top <= 0 {
		return fmt.Errorf("invalid --top '%d', must be > 0", cfg.top)
	}
	if cfg.pid < 0 {
		return fmt.Errorf("invalid --pid '%d', must be positive", cfg.pid)
	}
	if cfg.pid > 0 {
		statPath := fmt.Sprintf("/proc/%d/stat", cfg.pid)
		if _, err := os.Stat(statPath); err != nil {
			return fmt.Errorf("process PID %d not found or not readable: %w", cfg.pid, err)
		}
	}
	if cfg.disableRules != "" {
		ids := strings.Split(cfg.disableRules, ",")
		if err := engine.SetDisabledRules(ids); err != nil {
			return err
		}
	}
	return nil
}

func handleRuleCommands(cfg *cliConfig, engine *analyzer.Engine) bool {
	if cfg.listRules {
		filter := ""
		if len(flag.Args()) > 0 {
			filter = flag.Args()[0]
		}
		presenter.RenderRuleList(os.Stdout, engine.Rules(), filter, cfg.noColor)
		return true
	}
	if cfg.explain != "" {
		rule := engine.GetRule(cfg.explain)
		if rule == nil {
			fmt.Fprintf(os.Stderr, "why-slow: unknown rule ID %q (use --list-rules to view valid IDs)\n", cfg.explain)
			os.Exit(1)
		}
		presenter.RenderRuleExplanation(os.Stdout, rule, cfg.noColor)
		return true
	}
	return false
}

func extractTopProcesses(diff *collector.SnapshotDiff, n int) []analyzer.TopProcessReport {
	if diff == nil || n <= 0 {
		return nil
	}
	procs := make([]collector.ProcessDiff, len(diff.Processes))
	copy(procs, diff.Processes)

	sort.Slice(procs, func(i, j int) bool {
		if procs[i].CPUPercent != procs[j].CPUPercent {
			return procs[i].CPUPercent > procs[j].CPUPercent
		}
		return procs[i].RSSBytes > procs[j].RSSBytes
	})

	if n > len(procs) {
		n = len(procs)
	}

	result := make([]analyzer.TopProcessReport, n)
	for i := 0; i < n; i++ {
		p := procs[i]
		state := string(p.State)
		if p.State == 0 {
			state = "?"
		}
		result[i] = analyzer.TopProcessReport{
			PID:             p.PID,
			Comm:            p.Comm,
			CPUPercent:      p.CPUPercent,
			RSSMB:           float64(p.RSSBytes) / (1024 * 1024),
			ReadKB:          float64(p.ReadBytesDelta) / 1024,
			WriteKB:         float64(p.WriteBytesDelta) / 1024,
			RSSBytes:        p.RSSBytes,
			ReadBytesDelta:  p.ReadBytesDelta,
			WriteBytesDelta: p.WriteBytesDelta,
			OpenFDs:         p.OpenFDs,
			State:           state,
		}
	}
	return result
}

func extractPIDFocus(diff *collector.SnapshotDiff, targetPID int, report *analyzer.DiagnosticReport) *analyzer.PIDFocusReport {
	if targetPID <= 0 {
		return nil
	}

	var p collector.ProcessDiff
	found := false
	if diff != nil {
		for _, proc := range diff.Processes {
			if proc.PID == targetPID {
				p = proc
				found = true
				break
			}
		}
	}

	if !found {
		p.PID = targetPID
		p.Comm = "unknown"
	}

	enrichTargetPIDDetails(&p, targetPID)

	state := string(p.State)
	if p.State == 0 {
		state = "?"
	}

	var swapMB float64
	if p.SmapsRollup.Available {
		swapMB = float64(p.SmapsRollup.Swap) / 1024.0
	}

	fdTypes, _ := collector.CountProcessFDTypes("/proc", targetPID)
	openFDs := p.OpenFDs
	if openFDs == 0 && fdTypes.Total > 0 {
		openFDs = fdTypes.Total
	}

	return &analyzer.PIDFocusReport{
		PID:           p.PID,
		Comm:          p.Comm,
		State:         state,
		PPID:          p.PPID,
		NumThreads:    p.NumThreads,
		CPUPercent:    p.CPUPercent,
		RSSMB:         float64(p.RSSBytes) / (1024 * 1024),
		SwapMB:        swapMB,
		ReadKB:        float64(p.ReadBytesDelta) / 1024,
		WriteKB:       float64(p.WriteBytesDelta) / 1024,
		OpenFDs:       openFDs,
		MaxFDs:        p.MaxFDs,
		FDRatio:       p.FDRatio,
		Wchan:         p.Wchan,
		CgroupPath:    p.CgroupPath,
		OOMScore:      p.OOMScore,
		OOMScoreAdj:   p.OOMScoreAdj,
		SmapsRollup:   p.SmapsRollup,
		FDTypes:       fdTypes,
		RelatedIssues: filterRelatedIssues(targetPID, report),
	}
}

func enrichTargetPIDDetails(p *collector.ProcessDiff, targetPID int) {
	if p.Comm == "unknown" || p.Comm == "" {
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", targetPID)); err == nil {
			statStr := string(data)
			start := strings.IndexByte(statStr, '(')
			end := strings.LastIndexByte(statStr, ')')
			if start != -1 && end != -1 && end > start {
				p.Comm = statStr[start+1 : end]
			}
		}
	}
	if !p.SmapsRollup.Available {
		smapsPath := fmt.Sprintf("/proc/%d/smaps_rollup", targetPID)
		if smaps, err := collector.ParseSmapsRollup(smapsPath); err == nil && smaps.Available {
			p.SmapsRollup = smaps
		}
	}
}

func filterRelatedIssues(targetPID int, report *analyzer.DiagnosticReport) []analyzer.Diagnosis {
	if report == nil {
		return nil
	}
	var related []analyzer.Diagnosis
	if report.PrimaryBlocker != nil && report.PrimaryBlocker.CulpritPID == targetPID {
		related = append(related, *report.PrimaryBlocker)
	}
	for _, d := range report.ContributingFactors {
		if d.CulpritPID == targetPID {
			related = append(related, d)
		}
	}
	for _, d := range report.SecondaryIssues {
		if d.CulpritPID == targetPID {
			related = append(related, d)
		}
	}
	return related
}

func setupSignalHandler(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()
}

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func runWatchLoop(ctx context.Context, cfg *cliConfig, runCtx collector.RunContext, engine *analyzer.Engine) {
	minRank := severityToRank(cfg.alertThreshold)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		diff := captureSamples(ctx, cfg.interval, cfg.samples, false)
		if diff == nil {
			continue
		}

		report := engine.Analyze(diff, runCtx)
		if shouldAlert(report, minRank) {
			if cfg.pid > 0 {
				report.PIDFocus = extractPIDFocus(diff, cfg.pid, report)
			}
			if cfg.top > 0 {
				report.TopProcesses = extractTopProcesses(diff, cfg.top)
			}
			renderReport(report, cfg)
		}
	}
}

func shouldAlert(report *analyzer.DiagnosticReport, minRank int) bool {
	if report == nil || report.PrimaryBlocker == nil {
		return minRank <= 0
	}
	return severityToRank(string(report.PrimaryBlocker.Severity)) >= minRank
}

func severityToRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

func captureSamples(ctx context.Context, interval time.Duration, samples int, showProgress bool) *collector.SnapshotDiff {
	if samples <= 1 {
		return captureDifferential(ctx, interval, showProgress)
	}

	diffs := make([]*collector.SnapshotDiff, 0, samples)
	for i := 0; i < samples; i++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		diff := captureDifferential(ctx, interval, showProgress)
		if diff != nil {
			diffs = append(diffs, diff)
		}
	}

	return collector.MedianDiff(diffs)
}

func captureDifferential(ctx context.Context, interval time.Duration, showProgress bool) *collector.SnapshotDiff {
	snapA, err := collector.CollectSnapshot(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why-slow: warning: partial initial snapshot: %v\n", err)
		return nil
	}

	if showProgress {
		fmt.Fprintf(os.Stderr, "Sampling system telemetry (%.1fs window)...", interval.Seconds())
	}

	select {
	case <-ctx.Done():
		if showProgress {
			fmt.Fprintf(os.Stderr, "\r\033[K")
		}
		return nil
	case <-time.After(interval):
		if showProgress {
			fmt.Fprintf(os.Stderr, "\r\033[K")
		}
	}

	snapB, err := collector.CollectSnapshot(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why-slow: warning: partial differential snapshot: %v\n", err)
		return nil
	}

	return collector.DiffSnapshots(snapA, snapB)
}

func renderReport(report *analyzer.DiagnosticReport, cfg *cliConfig) {
	if cfg.json {
		if err := presenter.RenderJSON(os.Stdout, report, !cfg.compact); err != nil {
			fmt.Fprintf(os.Stderr, "why-slow: error rendering JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		opts := presenter.TerminalOptions{
			NoColor:    cfg.noColor,
			ShowRemedy: cfg.remedy,
		}
		if err := presenter.RenderTerminal(os.Stdout, report, opts); err != nil {
			fmt.Fprintf(os.Stderr, "why-slow: error rendering terminal output: %v\n", err)
			os.Exit(1)
		}
	}
}

func setupFlagUsage() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "why-slow — Instant Linux Performance & Bottleneck Diagnostic Engine\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  why-slow [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow                           # Standard terminal diagnostic run (3s window)\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --remedy                  # Include actionable tuning & fix advice in diagnostic cards\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --interval 1s             # Quick 1-second check\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --interval 10s            # Extended 10-second deep audit\n")
		fmt.Fprintf(os.Stderr, "  $ sudo why-slow                      # Run with root for complete process visibility\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --top 10                  # Show top 10 CPU/RSS processes table\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --pid 1234                # Deep dive single process resource consumption\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --explain BASE_CPU_SATURATION # Explain a specific rule\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --list-rules              # List all registered diagnostic rules\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --disable-rules RULE_A,RULE_B # Skip evaluation of specific rules\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --samples 5               # 5-sample median statistical noise reduction\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --watch                   # Continuous background monitoring sentinel\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --watch --alert-threshold high  # Only report HIGH and CRITICAL alerts\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --json                    # JSON output for SIEM/APM pipelines\n")
	}
}
