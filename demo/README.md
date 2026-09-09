# why-slow Scenario Demo & Simulation Suite

This directory contains standalone, non-destructive simulation scripts designed to test and demonstrate `why-slow` diagnostic capabilities on any Linux machine—even a fast, healthy workstation without preexisting bottlenecks.

---

## Quick Start

### 1. Interactive Menu
Launch the interactive selection menu by running `run.sh` with no arguments:
```bash
./demo/run.sh
```

### 2. Flag-Based Execution
Run any specific bottleneck scenario directly:

```bash
# 1. Zombie / Defunct Process Accumulation (Triggers EDGE_ZOMBIE_DEFUNCT_LEAK)
./demo/run.sh --zombie

# 2. File Descriptor Leak Deep Dive (Shows --pid PID FD breakdown card)
./demo/run.sh --fd

# 3. Single-Core CPU Affinity Pinning (Triggers EDGE_CPU_AFFINITY_PIN & 99% CPU card)
./demo/run.sh --cpu

# 4. Memory Allocation & Top RSS Inspection (Shows --top 5 and --pid PID memory card)
./demo/run.sh --mem

# 5. Direct I/O Sync Burst (Monitors I/O wait and disk write throughput)
./demo/run.sh --dstate

# 6. Run all scenarios sequentially
./demo/run.sh --all
```

---

## Safety Guarantees

All demo workloads adhere to strict safety invariants to ensure your machine is never harmed, locked up, or destabilized:

1. **Auto-Expiry Self-Destruct**: Every background workload process has a hardcoded internal `time.sleep(15)` auto-termination timer. Even if killed or detached, workloads exit automatically after 15 seconds.
2. **Signal Trapping (`EXIT`, `SIGINT`, `SIGTERM`)**: The script intercepts Ctrl+C or early script exit, immediately issuing `kill -9` to all spawned PIDs and unlinking any temporary files created in `/tmp`.
3. **Strict Resource Bounding**:
   - CPU loops are pinned to a single core using `taskset -c 0` (never saturates all cores or freezes your desktop).
   - Memory workloads allocate a fixed, bounded chunk (~250MB) and never provoke a real OS Out-Of-Memory condition.
   - File descriptor leaks open temporary handles under `/tmp/why_slow_demo_fd_*` and delete them upon completion.
4. **Zero Impact on Production Code**: Kept completely isolated in `demo/`. The `why-slow` production binary remains 100% pure and dependency-free.
