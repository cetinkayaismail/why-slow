# Contributing to why-slow

Thank you for your interest in contributing to **`why-slow`**! ⚡

`why-slow` is an enterprise-grade Linux kernel diagnostic engine built with strict performance, security, and architectural invariants. We welcome contributions, bug reports, kernel rule proposals, and optimizations from the community.

Please take a few moments to review this guide to ensure your contributions align with our engineering standards.

---

## 🏛️ Guiding Philosophy & Invariants

All contributions must strictly uphold these core architectural principles:

> 💡 **Before writing code, please read our friendly [Design Principles & 8 Iron Laws](docs/DESIGN_PRINCIPLES.md) guide to understand the engineering mental model.**

1. **Zero Dependencies & Zero CGo**: The project is 100% Go standard library (`CGO_ENABLED=0`). No external packages may be introduced to `go.mod`.
2. **Strict Read-Only Guarantee**: `why-slow` never modifies the host system. It opens `/proc` and `/sys` virtual files strictly with `O_RDONLY`. Zero disk writes, zero `/tmp` files, and zero `exec.Command` invocations.
3. **Sub-Second Execution & Strict Budget**: Total compute latency must remain $< 50\text{ ms}$, RSS memory footprint $< 15\text{ MB}$, and CPU usage negligible.
4. **Opportunistic Elevation**: The tool must work completely as an unprivileged user with silent, graceful degradation when kernel entries are restricted.
5. **Strict English Only**: All code, comments, commit messages, tests, and documentation must be written in English.

---

## 🛠️ Development Setup & Prerequisites

### Prerequisites
- **Operating System**: Linux (x86_64 or ARM64) with kernel $\ge 4.18$
- **Go**: Version `1.22` or later installed
- **Make**: Standard GNU Make

### Quick Start
```bash
# Clone the repository
git clone https://github.com/cetinkayaismail/why-slow.git
cd why-slow

# Build the static binary
make build

# Install local Git hooks (enforces formatting, <=60 line limit, and security invariants on commit)
make setup-hooks

# Run comprehensive validation (linting, security invariant checks, unit & race tests)
make check
```


---

## 🏗️ Codebase Architecture

The project follows a unidirectional, clean-layered pipeline:

```
cmd/why-slow/           # CLI entrypoint, flag parsing, and execution lifecycle
internal/
├── collector/          # Snapshot capture from /proc and /sys (concurrent worker pool)
├── analyzer/           # 160+ Diagnostic Rules, PSI calibration, causal suppression
└── presenter/          # Terminal forensic cards and Draft 2020-12 JSON output
```

- Collectors are privilege-unaware: they read kernel virtual files and return typed telemetry snapshots.
- Analyzers compare Snapshot A and Snapshot B across a sampling window (default: 3 seconds) and evaluate deterministic rule criteria.
- Presenters format the diagnosis cleanly for terminal output (preserving scrollback) or machine-readable JSON.

---

## 🧠 How to Add a New Diagnostic Rule

Adding a new kernel diagnostic rule is the most common contribution. Follow these steps:

### 1. Identify the Subsystem & Tier
Rules are organized into three prioritized tiers:
- **Tier 1 (Base Hard Limits)**: Unrecoverable hardware or OS limits (Disk 100% full, CPU hardware saturation, OOM imminent, thermal throttling).
- **Tier 2 (Contention & Queuing)**: Resource contention (D-State pileup, SoftIRQ storm, TCP listen drops, runqueue starvation).
- **Tier 3 (Subtle Edge Cases)**: Latency anomalies (THP compaction stalls, PTY buffer deadlocks, futex contention, zombie leaks).

### 2. Add Telemetry Fields (if needed)
If the rule requires new metrics from `/proc` or `/sys`:
- Add typed fields to the relevant struct in `internal/collector/`.
- Parse line-by-line using `bufio.Scanner` and `strconv.ParseUint` (never `fmt.Sscanf` or regex).
- Handle `os.ErrPermission` and `os.ErrNotExist` gracefully with fallback baselines.

### 3. Implement the Rule in `internal/analyzer/`
- Add the rule logic to the appropriate file (`rules_tier1.go`, `rules_tier2.go`, or `rules_tier3.go`).
- Follow the multi-signal corroboration rule: every diagnostic rule should corroborate at least two distinct kernel signals before triggering.
- Supply a clear diagnostic finding, proof format, and actionable remediation advice.

### 4. Write Mandatory Unit & Disambiguation Tests
- Add positive and negative unit test cases in `internal/analyzer/rules_tier*_test.go`.
- If the rule interacts with other related rules, add cross-tier disambiguation tests in `internal/analyzer/disambiguation_test.go` to prove no unintended shadowing occurs.

### 5. Document the Rule
- Add the rule specification, trigger thresholds, and remediation advice to `docs/RULES_CATALOG.md`.

---

## 📏 Code Style Guidelines

- **Function Length**: Maximum **60 lines** per function. Extract focused helper functions beyond that.
- **Error Handling**: Wrap errors with context: `fmt.Errorf("collector: parsing stat: %w", err)`.
- **Parsing**: Zero regex on hot paths. Use `bytes.IndexByte`, `strings.Split`, and `strconv.Parse*`.
- **Allocations**: Pre-allocate slices where length is predictable (`make([]T, 0, cap)`).
- **Concurrency**: All goroutines must be bounded by a worker pool (`runtime.NumCPU()`) and accept a `context.Context` for cancellation.

---

## 🧪 Testing Checklist

Before submitting a Pull Request, verify that all tests pass locally:

```bash
# 1. Static analysis & format
make vet
make fmt

# 2. Complete test suite with data race detection
make test

# 3. Exhaustive audit and scenario verification
go test -v -race -count=1 ./internal_tests/battle_test.go

# 4. Clean static compilation
make build
```

---

## 🚀 Submitting a Pull Request

1. **Fork** the repository and create a descriptive branch:
   ```bash
   git checkout -b feat/add-bcache-congestion-rule
   ```
2. **Commit** your changes following the [Conventional Commits](https://www.conventionalcommits.org/) specification:
   - `feat: add Tier 2 Bcache congestion diagnostic rule`
   - `fix: resolve counter wrap-around in network collector`
   - `docs: update troubleshooting guide for PSI metrics`
3. **Update Changelog**: Add your change summary to `docs/CHANGELOG.md`.
4. **Push** your branch to your fork and open a Pull Request against the `main` branch.
5. Complete the provided Pull Request template checklist. Our automated CI will run checks across supported Go versions.

---

## 🤝 Community & Questions

- **Discussions & Ideas**: Open an issue or join GitHub Discussions.
- **Security Inquiries**: See [SECURITY.md](SECURITY.md) for private vulnerability disclosure instructions.
- **Code of Conduct**: All participants must abide by our [Code of Conduct](CODE_OF_CONDUCT.md).
