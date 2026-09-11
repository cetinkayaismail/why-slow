# why-slow — Design Principles & Architectural Guide

Welcome to the engineering design principles guide for **`why-slow`**! ⚡

This document explains the foundational architectural decisions, invariants, and mental models of this project in **simple, friendly, and crystal-clear English**.

If you are a developer, contributor, or curious engineer looking at this codebase for the first time, this guide explains *why* the code is built the way it is.

---

## 🏥 The Golden Principle: The Doctor's Rule

Before writing a single line of code in `why-slow`, always remember this metaphor:

> **"Imagine an ambulance rushing into an emergency room with a patient having a severe heart attack. A good doctor does not jump on the patient's chest with heavy boots. The doctor uses a quiet, precise stethoscope."**

When someone runs `why-slow`:
- Their computer or server is **already freezing, lagging, or dying**.
- The CPU might be at 100%. The RAM might be almost empty. The disk might be stuck.
- Therefore, **`why-slow` must be as light as a feather**. It must never make the computer slower.

Everything in our architecture flows from this single principle.

---

## 🏛️ The 8 Iron Architectural Laws

Here are the 8 fundamental rules that govern the entire codebase:

---

### Law 1: ZERO WRITE OPERATIONS (Strict Read-Only)

* **The Rule:** The program must **never write a single byte** to the disk.
  - No `os.Create()`, no `os.WriteFile()`, no `os.Remove()`.
  - No temporary files in `/tmp` or `/dev/shm`.
  - No writing to log files.
  - Virtual files in `/proc` and `/sys` are opened strictly with `O_RDONLY`.
* **The Reason:** 
  - If a system is freezing because the **hard drive is 100% full**, what happens if your diagnostic tool tries to create a log file in `/tmp`? **The tool crashes with `No space left on device`!**
  - If a disk has hardware errors or bad sectors, writing to it can destroy user data.
  - By being 100% read-only, `why-slow` is safe to run on any computer, anywhere, at any time.

---

### Law 2: ZERO EXTERNAL DEPENDENCIES (Pure Go Standard Library)

* **The Rule:** Look inside `go.mod`. You will see **zero third-party packages**.
  - No external GitHub libraries.
  - No CGo (`CGO_ENABLED=0` — pure Go only).
  - No calling external terminal commands like `exec.Command("ps")`, `exec.Command("lsof")`, or `exec.Command("iostat")`.
* **The Reason:**
  - **Speed:** Running `exec.Command("ps")` creates a whole new operating system process (`fork/exec`), which burns massive CPU power on an overloaded machine.
  - **Portability:** You can download the single static binary on *any* Linux machine (Ubuntu, Debian, RedHat, Alpine, Arch) and it will immediately run without installing anything.
  - **Security:** Zero risk of supply-chain attacks or compromised dependencies.

---

### Law 3: ZERO SUDO REQUIREMENT (Opportunistic Elevation)

* **The Rule:** `why-slow` must work perfectly for a normal, everyday unprivileged user. It must never say *"Error: You must run as root"*.
* **The Reason:**
  - In real-world enterprise servers, junior developers and engineers do not have root (`sudo`) access.
  - **How it works:** When run as a normal user, it inspects everything it is allowed to see. If you run it with `sudo why-slow`, it automatically widens its vision to see all system processes, but the code paths and behavior stay completely identical.

---

### Law 4: NO REGEX & REUSABLE BUFFERS (Zero-Trash Memory)

* **The Rule:** Never use the `regexp` package in the codebase. Always use `bufio.Scanner`, `bytes.IndexByte`, and `strconv.ParseUint`.
* **The Reason:**
  - Regular expressions (Regex) are slow and create thousands of temporary string objects in RAM.
  - Go's Garbage Collector (the background cleanup crew) would have to pause the program to clean up that memory trash.
  - Instead, we use a single **reusable buffer** (like a whiteboard). We read a line onto the board, point to the number directly, save it, wipe the board, and repeat.
  - Result: **Zero memory trash**, $< 15\text{ MB}$ RAM footprint, and 100x faster parsing.

---

### Law 5: THE 3-TIER HIERARCHY (Causal Suppression)

`why-slow` checks **164 different kernel rules**, but it never confuses the user with a messy list of 20 warnings. It organizes problems into 3 strict tiers:

```text
┌────────────────────────────────────────────────────────────┐
│  Tier 1: Base Hard Limits (P0 Priority)                    │
│  The Physical Walls: Disk 100% Full, OOM, CPU Saturation   │
└─────────────────────────────┬──────────────────────────────┘
                              │ (Suppresses secondary symptoms)
                              ▼
┌────────────────────────────────────────────────────────────┐
│  Tier 2: Contention & Queuing (P1 Priority)                 │
│  The Traffic Jams: D-State Pileup, SoftIRQ, Socket Drops   │
└─────────────────────────────┬──────────────────────────────┘
                              │ (Demotes lower-priority noise)
                              ▼
┌────────────────────────────────────────────────────────────┐
│  Tier 3: Subtle Kernel Edge Cases (P2 Priority)            │
│  The Glitches: Futex Locks, Compaction Stalls, Zombies     │
└────────────────────────────────────────────────────────────┘
```

* **The Reason (Causal Suppression):**
  - If a delivery truck crashes on the highway (Tier 1: Root Cause), 50 cars behind it will get stuck in traffic (Tier 2: Secondary Symptoms).
  - A bad tool reports 51 separate errors.
  - **`why-slow` reports the truck crash as the primary blocker**, and quietly groups the traffic jam underneath as contributing evidence.

---

### Law 6: MULTI-SIGNAL CORROBORATION (Never Cry Wolf)

* **The Rule:** A single high metric is never enough to declare a critical bottleneck. Every rule must require at least **two independent kernel signals** to agree.
* **The Reason:**
  - Just because CPU usage is 95% does not mean the computer is broken—maybe the user is compiling code or rendering a 3D video very efficiently!
  - But if **CPU usage is 99%** AND **Pressure Stall Information (PSI) shows CPU stalls > 30%** AND **runqueue latency is spiking**: now we have proof of real starvation.
  - This prevents false alarms and builds trust with users.

---

### Law 7: BOUNDED CONCURRENCY (The Worker Pool)

* **The Rule:** Never launch unbounded goroutines (`go func()`) in a loop over thousands of processes. Always use a worker pool bounded by `runtime.NumCPU()`.
* **The Reason:**
  - If a server has 5,000 running processes, launching 5,000 simultaneous goroutines would flood the Go runtime scheduler and eat memory.
  - If the machine has 4 CPU cores, we create 4 worker workers. Each worker grabs a PID from a queue, inspects it, and grabs the next. Fast, orderly, and calm.

---

### Law 8: GRACEFUL DEGRADATION (Never Panic, Never Crash)

* **The Rule:** Never use `panic()` or `log.Fatal()` during data collection. Silently handle `os.ErrPermission` and `os.ErrNotExist`.
* **The Reason:**
  - In Linux, short-lived processes start and exit in milliseconds.
  - If `why-slow` sees PID `1234` in `/proc`, but by the time it opens `/proc/1234/stat` the process has already finished, Linux returns `os.ErrNotExist`.
  - A fragile program crashes. `why-slow` simply ignores the dead process and moves to the next one without a single hiccup.

---

## ⚙️ The 3-Step Pipeline Architecture

The entire codebase is structured like a clean, one-way factory assembly line:

```
Step 1: COLLECTOR          Step 2: ANALYZER          Step 3: PRESENTER
(/proc and /sys)     ───>  (164 Rules & Tiers) ───>  (Terminal Card / JSON)
```

1. **`internal/collector/`**:
   - The eyes and ears.
   - It only reads raw numbers from the kernel virtual filesystem.
   - It knows *nothing* about rules, alarms, or presentation.
2. **`internal/analyzer/`**:
   - The brain.
   - Compares Snapshot A (at $t=0$) and Snapshot B (at $t=3\text{s}$).
   - Evaluates the differentials across all 164 rules, applies causal suppression, and determines the primary root cause.
3. **`internal/presenter/`**:
   - The voice.
   - Formats the diagnostic verdict into an ANSI terminal forensic card or machine-readable JSON.

---

## 📋 Quick Summary Table

| Law | What We Do | What We NEVER Do |
|---|---|---|
| **Writes** | Strict `O_RDONLY` | No `os.WriteFile`, no `/tmp` files |
| **Dependencies** | Pure Go stdlib | No external packages, no CGo |
| **Parsing** | `bufio.Scanner` + byte indexing | No `regexp`, no `fmt.Sscanf` |
| **Privileges** | Opportunistic elevation | Never demand `sudo` |
| **Hierarchy** | Tier 1 > Tier 2 > Tier 3 | Never show symptoms before causes |
| **Alarms** | Multi-signal corroboration | Never alert on a single metric |
| **Concurrency** | `runtime.NumCPU()` worker pool | No unbounded `go func()` |
| **Errors** | Graceful degradation | No `panic`, no `log.Fatal` |

Keep these rules in mind whenever you touch any part of this codebase!
