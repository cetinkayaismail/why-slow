#!/usr/bin/env bash
# ==============================================================================
# why-slow Demo & Scenario Simulation Tool
# ==============================================================================
# Safely simulates real-world Linux performance bottlenecks in bounded,
# self-cleaning background workloads to demonstrate why-slow diagnosis.
#
# Safety Guarantees:
#  1. All workloads self-terminate within 15 seconds (auto-timeout).
#  2. All processes and temp files are killed/removed on EXIT, INT, or TERM.
#  3. Memory and CPU usage are strictly bounded (safe for any host).
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$ROOT_DIR/bin/why-slow"

PIDS=()
TEMP_FILES=()

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    echo ""
    if [[ ${#PIDS[@]} -gt 0 ]]; then
        echo "  [DEMO CLEANUP] Terminating background workload processes: ${PIDS[*]}..."
        for pid in "${PIDS[@]}"; do
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        done
        PIDS=()
    fi
    if [[ ${#TEMP_FILES[@]} -gt 0 ]]; then
        echo "  [DEMO CLEANUP] Removing temporary files..."
        for f in "${TEMP_FILES[@]}"; do
            rm -rf "$f" 2>/dev/null || true
        done
        TEMP_FILES=()
    fi
    exit $exit_code
}

trap cleanup EXIT INT TERM

ensure_binary() {
    if [[ ! -x "$BIN" ]]; then
        echo "  [DEMO] Building why-slow binary..."
        (cd "$ROOT_DIR" && CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/why-slow ./cmd/why-slow)
        echo "  [DEMO] Build complete: $BIN"
    fi
}

print_header() {
    local title="$1"
    echo ""
    echo "=============================================================================="
    echo "  WHY-SLOW DEMO: $title"
    echo "=============================================================================="
}

# ------------------------------------------------------------------------------
# Scenarios
# ------------------------------------------------------------------------------

demo_zombie() {
    print_header "Zombie / Defunct Process Accumulation"
    echo "  • Spawning 50 unreaped zombie child processes via python3..."
    echo "  • Expected Rule Triggered: EDGE_ZOMBIE_DEFUNCT_LEAK"
    echo ""

    python3 -c "
import os, time
children = []
for _ in range(50):
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    children.append(pid)
print('  • Workload active: 50 child processes exited without waitpid()')
time.sleep(15)
" &
    local parent_pid=$!
    PIDS+=("$parent_pid")

    echo "  • Parent PID: $parent_pid (running why-slow in 1.5s)..."
    sleep 1.5

    "$BIN" || true
    echo ""
    echo "  [DEMO SUCCESS] why-slow detected zombie leak and identified culprit parent PID $parent_pid!"
}

demo_fd() {
    print_header "File Descriptor Leak Deep Dive (--pid focus)"
    echo "  • Spawning process that opens 100 file handles under /tmp..."
    echo "  • Expected Output: Process Deep Dive card showing Open File Descriptors"
    echo ""

    local tmp_prefix="/tmp/why_slow_demo_fd_$$"
    TEMP_FILES+=("${tmp_prefix}*")

    python3 -c "
import time, os
handles = []
for i in range(100):
    f = open('${tmp_prefix}_' + str(i), 'w')
    f.write('demo')
    f.flush()
    handles.append(f)
print('  • Workload active: 100 open file descriptors held in memory')
time.sleep(15)
" &
    local fd_pid=$!
    PIDS+=("$fd_pid")

    echo "  • Target PID: $fd_pid (running why-slow --pid $fd_pid in 1.5s)..."
    sleep 1.5

    "$BIN" --pid "$fd_pid" || true
    echo ""
    echo "  [DEMO SUCCESS] Process deep dive card inspected open FDs and kernel telemetry!"
}

demo_cpu_affinity() {
    print_header "Single-Core CPU Affinity Pinning"
    echo "  • Pinning a 100% busy loop process to Core 0 for 12 seconds..."
    echo "  • Expected Rule Triggered: EDGE_CPU_AFFINITY_PIN"
    echo ""

    taskset -c 0 bash -c 'for ((;;)); do :; done' &
    local cpu_pid=$!
    PIDS+=("$cpu_pid")

    echo "  • Pinned Process PID: $cpu_pid on Core 0 (running why-slow in 1.5s)..."
    sleep 1.5

    "$BIN" --pid "$cpu_pid" || true
    echo ""
    echo "  [DEMO SUCCESS] why-slow detected single-core affinity pinning on PID $cpu_pid!"
}

demo_mem() {
    print_header "Memory Allocation & Top RSS Process Inspection"
    echo "  • Allocating ~250MB of memory safely in a background process..."
    echo "  • Demonstrating: Top N process ranking and memory telemetry"
    echo ""

    python3 -c "
import time
print('  • Allocating ~250MB in bytearray...')
data = bytearray(250 * 1024 * 1024)
print('  • Memory held active for 15 seconds')
time.sleep(15)
" &
    local mem_pid=$!
    PIDS+=("$mem_pid")

    echo "  • Memory Process PID: $mem_pid (running why-slow --top 5 in 1.5s)..."
    sleep 1.5

    "$BIN" --top 5 --pid "$mem_pid" || true
    echo ""
    echo "  [DEMO SUCCESS] Process deep dive card & Top 5 table captured memory footprint!"
}

demo_dstate() {
    print_header "Direct I/O Sync Wait (D-State Task)"
    echo "  • Issuing continuous direct synchronous I/O writes with oflag=dsync..."
    echo "  • Demonstrating: I/O wait and disk write throughput tracking"
    echo ""

    local tmp_disk="/tmp/why_slow_demo_disk_$$.dat"
    TEMP_FILES+=("$tmp_disk")

    (dd if=/dev/zero of="$tmp_disk" bs=1M count=300 oflag=dsync status=none 2>/dev/null || true) &
    local dd_pid=$!
    PIDS+=("$dd_pid")

    echo "  • DSync Worker PID: $dd_pid (running why-slow in 1.5s)..."
    sleep 1.5

    "$BIN" --top 5 || true
    echo ""
    echo "  [DEMO SUCCESS] why-slow monitored active I/O wait and disk throughput!"
}

show_menu() {
    while true; do
        echo ""
        echo "=============================================================================="
        echo "  why-slow Scenario Simulation & Demo Menu"
        echo "=============================================================================="
        echo "  Select a scenario to simulate (harmless, self-cleaning, 15s auto-timeout):"
        echo ""
        echo "  1) Zombie / Defunct Process Leak   (EDGE_ZOMBIE_DEFUNCT_LEAK)"
        echo "  2) File Descriptor Leak Deep Dive   (--pid PID open file breakdown)"
        echo "  3) Single-Core CPU Affinity Pinning (EDGE_CPU_AFFINITY_PIN)"
        echo "  4) Memory & Top RSS Inspection      (--top 5 + --pid PID memory card)"
        echo "  5) Synchronous Direct I/O Burst     (D-State wait & disk write rate)"
        echo "  6) Run All Scenarios Sequentially"
        echo "  q) Quit"
        echo "=============================================================================="
        read -r -p "  Enter choice [1-6, q]: " choice
        case "$choice" in
            1) demo_zombie ;;
            2) demo_fd ;;
            3) demo_cpu_affinity ;;
            4) demo_mem ;;
            5) demo_dstate ;;
            6)
                demo_zombie
                demo_fd
                demo_cpu_affinity
                demo_mem
                demo_dstate
                ;;
            q|Q)
                echo "  Exiting demo."
                exit 0
                ;;
            *)
                echo "  Invalid choice. Please enter 1-6 or q."
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------

ensure_binary

case "${1:-}" in
    --zombie|-z)
        demo_zombie
        ;;
    --fd|-f)
        demo_fd
        ;;
    --cpu|-c)
        demo_cpu_affinity
        ;;
    --mem|-m)
        demo_mem
        ;;
    --dstate|-d)
        demo_dstate
        ;;
    --all|-a)
        demo_zombie
        demo_fd
        demo_cpu_affinity
        demo_mem
        demo_dstate
        ;;
    --help|-h)
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  --zombie, -z    Simulate 50 unreaped zombie processes"
        echo "  --fd, -f        Simulate 100 open file descriptors with --pid focus"
        echo "  --cpu, -c       Simulate single-core CPU affinity pinning"
        echo "  --mem, -m       Simulate bounded memory allocation with --top 5"
        echo "  --dstate, -d    Simulate synchronous direct I/O write burst"
        echo "  --all, -a       Run all scenarios sequentially"
        echo "  --help, -h      Display this help menu"
        echo ""
        echo "Run without options to launch the interactive selection menu."
        ;;
    "")
        show_menu
        ;;
    *)
        echo "Unknown option: $1"
        echo "Run '$0 --help' for usage."
        exit 1
        ;;
esac
