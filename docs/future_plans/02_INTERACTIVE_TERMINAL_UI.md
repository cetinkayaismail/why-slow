# Future Plans 02: Interactive Terminal User Interface (TUI)

## 1. Vision & The Linux Philosophy

Traditional desktop tools attempt to solve diagnostics by packaging web browsers (Electron) or opening local HTTP ports. In production Linux server environments, this is an anti-pattern:
* Production servers are **headless** (no graphical server or display).
* Web listeners require opening firewall ports and create new attack vectors.
* Web servers consume 50–150 MB of memory.

A **Terminal User Interface (TUI)** (following the tradition of `htop`, `btop`, `k9s`, and `glances`):
* Operates **natively inside standard SSH terminals** over low-bandwidth connections.
* Requires **zero open network ports**.
* Consumes **$< 10\text{ MB}$ of memory** using pure ANSI escape sequences.
* Allows an SRE to SSH into a node, run `why-slow -i`, inspect live kernel wait-channels, and exit cleanly.

---

## 2. Mock Terminal Layout Design

```text
┌── why-slow v0.20.0 ── [Host: prod-db-02] ── [Sampling: 1.0s] ─────────────── [q: Quit | ?: Help] ──┐
│ PSI Pressures:   CPU [|||||||||||||||||||| 62.4%]   MEM [| 1.2%]   I/O [|||||||||||||||||||| 98.1%]  │
├────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ [!] PRIMARY ROOT CAUSE: BASE_DISK_HARDWARE_SATURATION (Tier 1 | Severity: CRITICAL | Conf: 95%)   │
│ • Device 'nvme0n1' IO utilization at 99.8% capacity (Queue latency: 45.2ms, In-Flight IOs: 48)   │
│ • Culprit: PID 14208 [postgres] (Issuing 580.4 MB/s write throughput in 'ext4_writepages')        │
│ • Remediation: Lower IO priority class: ionice -c3 -p 14208                                        │
├────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ ACTIVE PROCESSES & KERNEL WAIT-CHANNELS (Sorted by IO Delta) ─────────────────────────────────────│
│   PID   COMM          STATE  CPU%    READ/s     WRITE/s    WCHAN                  CGROUP / SLICE   │
│ ▶ 14208 postgres        D    34.2%   0.1 MB     580.4 MB   ext4_writepages        system.slice     │
│   14210 postgres        D     2.1%   0.0 MB      45.0 MB   jbd2_log_wait_commit   system.slice     │
│    8192 clickhouse      S   140.0%  12.0 MB       1.2 MB   epoll_wait             docker/analytics │
│    3001 redis-server    S    12.0%   0.0 MB       0.0 MB   epoll_wait             docker/cache     │
├────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ RULE ENGINE MATRIX (159 Rules Evaluated in 23µs) ──────────────────────────────────────────────────┤
│ [Tier 1: 1 Triggered]  [Tier 2: 2 Suppressed by Root Cause]  [Tier 3: 0 Triggered]  [Healthy: 156] │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Interactive Keybindings & Controls

| Key | Action | Description |
| :--- | :--- | :--- |
| `q` / `Ctrl+C` | **Quit** | Restores terminal cursor and exits cleanly. |
| `Space` | **Pause / Freeze** | Freezes the live snapshot to inspect a transient spike. |
| `s` | **Save Report** | Dumps the currently frozen report to a timestamped JSON file. |
| `Tab` | **Cycle Panes** | Switches focus between Primary Blocker, Process Table, and Rule Matrix. |
| `1` / `2` / `3` / `4` | **Subsystem Filter** | Filters view to CPU (`1`), Memory (`2`), Disk/IO (`3`), or Network (`4`). |
| `c` | **Causal Suppression Tree** | Toggles tree view showing which secondary symptoms were pruned by the root cause. |
| `Enter` | **Process Drill-Down** | Opens detail modal for highlighted PID (open FDs, threads, memory maps). |
| `x` | **Execute Safe Remedy** | Opens the Pre-Flight Blast Radius Assessment modal for the selected issue. |

---

## 4. Pure Go Implementation Architecture (Zero CGo / Zero ncurses)

Many TUI libraries depend on CGo bindings to `ncurses`. To strictly preserve our **Zero Dependencies / `CGO_ENABLED=0` invariant**, the TUI will be implemented using:

1. **VT100 & ANSI Control Codes**:
   * Cursor positioning: `\033[<row>;<col>H`
   * Clear screen: `\033[2J`
   * Hide/Show cursor: `\033[?25l` / `\033[?25h`
   * Double-buffering: Render complete screen in an in-memory `bytes.Buffer` before writing to `os.Stdout` to eliminate screen flicker.
2. **Raw Terminal Input (Pure Go Syscalls)**:
   * Linux `syscall.SYS_IOCTL` with `TCGETS` and `TCSETS` to capture single keystrokes without requiring `Enter`.
   * Non-blocking keyboard polling with `context.Context` cancellation.
