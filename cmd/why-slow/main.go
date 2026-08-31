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
}

func main() {
	jsonFlag := flag.Bool("json", false, "Output diagnostic report in machine-readable JSON format")
	compactFlag := flag.Bool("compact", false, "Output compact single-line JSON (used with -json)")
	intervalFlag := flag.Duration("interval", 1*time.Second, "Sampling window interval between snapshots (e.g. 1s, 2s, 5s)")
	noColorFlag := flag.Bool("no-color", false, "Disable ANSI color coding in terminal output")
	versionFlag := flag.Bool("version", false, "Print why-slow version and exit")
	samplesFlag := flag.Int("samples", 1, "Number of sampling windows to collect (uses median for statistical noise reduction)")
	watchFlag := flag.Bool("watch", false, "Run continuously in watch mode, reporting findings meeting alert threshold")
	alertFlag := flag.String("alert-threshold", "info", "Minimum severity to report in watch mode (critical, high, medium, info)")

	setupFlagUsage()
	flag.Parse()

	if *versionFlag {
		fmt.Printf("why-slow version %s\n", version)
		os.Exit(0)
	}

	if *intervalFlag <= 0 {
		fmt.Fprintf(os.Stderr, "why-slow: invalid interval '%v', must be positive\n", *intervalFlag)
		os.Exit(1)
	}
	if *samplesFlag <= 0 {
		fmt.Fprintf(os.Stderr, "why-slow: invalid samples '%d', must be >= 1\n", *samplesFlag)
		os.Exit(1)
	}

	cfg := cliConfig{
		json:           *jsonFlag,
		compact:        *compactFlag,
		noColor:        *noColorFlag,
		interval:       *intervalFlag,
		samples:        *samplesFlag,
		watch:          *watchFlag,
		alertThreshold: *alertFlag,
	}

	runCtx := collector.RunContext{
		IsRoot:       os.Getuid() == 0,
		EffectiveUID: os.Geteuid(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupSignalHandler(cancel)

	if cfg.watch {
		runWatchLoop(ctx, cfg, runCtx)
		return
	}

	diff := captureSamples(ctx, cfg.interval, cfg.samples)
	engine := analyzer.NewEngine()
	report := engine.Analyze(diff, runCtx)
	renderReport(report, cfg)
}

func setupSignalHandler(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()
}

func runWatchLoop(ctx context.Context, cfg cliConfig, runCtx collector.RunContext) {
	engine := analyzer.NewEngine()
	minRank := severityToRank(cfg.alertThreshold)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		diff := captureSamples(ctx, cfg.interval, cfg.samples)
		if diff == nil {
			continue
		}

		report := engine.Analyze(diff, runCtx)
		if shouldAlert(report, minRank) {
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

func captureSamples(ctx context.Context, interval time.Duration, samples int) *collector.SnapshotDiff {
	if samples <= 1 {
		return captureDifferential(ctx, interval)
	}

	diffs := make([]*collector.SnapshotDiff, 0, samples)
	for i := 0; i < samples; i++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		diff := captureDifferential(ctx, interval)
		if diff != nil {
			diffs = append(diffs, diff)
		}
	}

	return collector.MedianDiff(diffs)
}

func captureDifferential(ctx context.Context, interval time.Duration) *collector.SnapshotDiff {
	snapA, err := collector.CollectSnapshot(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why-slow: warning: partial initial snapshot: %v\n", err)
		return nil
	}

	select {
	case <-ctx.Done():
		return nil
	case <-time.After(interval):
	}

	snapB, err := collector.CollectSnapshot(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why-slow: warning: partial differential snapshot: %v\n", err)
		return nil
	}

	return collector.DiffSnapshots(snapA, snapB)
}

func renderReport(report *analyzer.DiagnosticReport, cfg cliConfig) {
	if cfg.json {
		if err := presenter.RenderJSON(os.Stdout, report, !cfg.compact); err != nil {
			fmt.Fprintf(os.Stderr, "why-slow: error rendering JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := presenter.RenderTerminal(os.Stdout, report, cfg.noColor); err != nil {
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
		fmt.Fprintf(os.Stderr, "  $ why-slow                           # Standard terminal diagnostic run (1s window)\n")
		fmt.Fprintf(os.Stderr, "  $ sudo why-slow                      # Full visibility run across all system PIDs\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --interval 3s             # 3-second sampling window for sustained spikes\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --samples 5               # 5-sample median statistical noise reduction\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --watch                   # Continuous background monitoring sentinel\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --watch --alert-threshold high  # Only report HIGH and CRITICAL alerts\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --json                    # JSON output for SIEM/APM pipelines\n")
	}
}
