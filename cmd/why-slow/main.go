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
	"syscall"
	"time"

	"why-slow/internal/analyzer"
	"why-slow/internal/collector"
	"why-slow/internal/presenter"
)

var version = "dev"

func main() {
	jsonFlag := flag.Bool("json", false, "Output diagnostic report in machine-readable JSON format")
	compactFlag := flag.Bool("compact", false, "Output compact single-line JSON (used with -json)")
	intervalFlag := flag.Duration("interval", 1*time.Second, "Sampling window interval between snapshots (e.g. 1s, 2s, 5s)")
	noColorFlag := flag.Bool("no-color", false, "Disable ANSI color coding in terminal output")
	versionFlag := flag.Bool("version", false, "Print why-slow version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "why-slow — Instant Linux Performance & Bottleneck Diagnostic Engine\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  why-slow [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow                # Standard terminal diagnostic run (1s window)\n")
		fmt.Fprintf(os.Stderr, "  $ sudo why-slow           # Full visibility run across all system PIDs\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --interval 3s  # 3-second sampling window for sustained spikes\n")
		fmt.Fprintf(os.Stderr, "  $ why-slow --json         # JSON output for SIEM/APM pipelines\n")
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("why-slow version %s\n", version)
		os.Exit(0)
	}

	if *intervalFlag <= 0 {
		fmt.Fprintf(os.Stderr, "why-slow: invalid interval '%v', must be positive\n", *intervalFlag)
		os.Exit(1)
	}

	// Detect opportunistic privilege level (only in main.go per security invariants)
	runCtx := collector.RunContext{
		IsRoot:       os.Getuid() == 0,
		EffectiveUID: os.Geteuid(),
	}

	// Setup signal trapping for clean cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// 1. Capture Snapshot A
	snapA, err := collector.CollectSnapshot(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why-slow: error collecting initial snapshot: %v\n", err)
		os.Exit(1)
	}

	// 2. Sleep for sampling interval
	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\nwhy-slow: diagnostic cancelled by user.")
		os.Exit(130)
	case <-time.After(*intervalFlag):
	}

	// 3. Capture Snapshot B
	snapB, err := collector.CollectSnapshot(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why-slow: error collecting differential snapshot: %v\n", err)
		os.Exit(1)
	}

	// 4. Calculate Differential
	diff := collector.DiffSnapshots(snapA, snapB)

	// 5. Correlate and Analyze
	engine := analyzer.NewEngine()
	report := engine.Analyze(diff, runCtx)

	// 6. Present Output
	if *jsonFlag {
		pretty := !*compactFlag
		if err := presenter.RenderJSON(os.Stdout, report, pretty); err != nil {
			fmt.Fprintf(os.Stderr, "why-slow: error rendering JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := presenter.RenderTerminal(os.Stdout, report, *noColorFlag); err != nil {
			fmt.Fprintf(os.Stderr, "why-slow: error rendering terminal output: %v\n", err)
			os.Exit(1)
		}
	}
}
