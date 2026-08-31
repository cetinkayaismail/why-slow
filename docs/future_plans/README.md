# why-slow — Future Plans & Architectural Roadmap

This directory contains the detailed engineering specifications for the next major evolutionary phases of `why-slow`.

---

## 🗺️ Roadmap Overview

| Module | Document | Core Focus |
| :--- | :--- | :--- |
| **01. Autonomous Agent Mode** | [01_AUTONOMOUS_AGENT_MODE.md](01_AUTONOMOUS_AGENT_MODE.md) | Outbound-only push client (`--push-url`), mTLS security, Zabbix/Prometheus sidecars, and Kubernetes DaemonSet integration. |
| **02. Interactive Terminal UI** | [02_INTERACTIVE_TERMINAL_UI.md](02_INTERACTIVE_TERMINAL_UI.md) | Pure Go VT100/ANSI interactive TUI (`-i` / `--tui`) for live SSH debugging with drill-down modals and causal trees. |
| **03. Human-in-the-Loop Remediation** | [03_HUMAN_IN_THE_LOOP_REMEDIATION.md](03_HUMAN_IN_THE_LOOP_REMEDIATION.md) | Safe interactive operator actions, pure syscall execution (zero shell injection), and tamper-evident audit logging. |
| **04. Blast Radius Pre-Flight Safety** | [04_BLAST_RADIUS_PREFLIGHT_SAFETY.md](04_BLAST_RADIUS_PREFLIGHT_SAFETY.md) | 4-layer pre-flight safety inspector: protected process blacklist, child worker cascades, socket dependencies, and throttle-first principle. |

---

## 🏛️ Guiding Architectural Invariants

Across all future milestones, the following master safety invariants remain non-negotiable:

1. **Zero Autonomous Write Operations**: Background sentinel modes (`--watch`) remain strictly read-only.
2. **Zero Shell Injection**: All remediation handlers execute strictly via typed Go Linux syscalls (`syscall.Setpriority`, `syscall.Syscall`), never via `exec.Command("sh", "-c", ...)`.
3. **Strict Resource Budgets**: All agent and TUI modules must operate within $< 15\text{ MB}$ RSS memory footprint and $< 0.05\%$ CPU usage.
4. **Zero Dependencies**: Pure Go standard library (`CGO_ENABLED=0`) across all collectors, analyzers, and terminal interfaces.
