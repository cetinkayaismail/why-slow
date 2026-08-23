// Package collector — memory.go parses /proc/meminfo for memory metrics
// (MemTotal, MemAvailable, SwapTotal, SwapFree, Dirty, Writeback) and
// /proc/vmstat for page reclaim counters (pgscan_direct, allocstall_direct,
// compact_stall, compact_fail, pgmajfault).
package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Default paths for memory statistics.
const (
	DefaultMemInfoPath = "/proc/meminfo"
	DefaultVMStatPath  = "/proc/vmstat"
)

// CollectMemInfo parses memory and swap metrics from /proc/meminfo.
func CollectMemInfo() (MemInfo, error) {
	return ParseMemInfo(DefaultMemInfoPath)
}

// ParseMemInfo parses memory and swap metrics from a custom meminfo file path.
func ParseMemInfo(path string) (MemInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return MemInfo{}, fmt.Errorf("collector: open meminfo: %w", err)
	}
	defer file.Close()

	var info MemInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		key, valStr, found := strings.Cut(line, ":")
		if !found {
			continue
		}

		// Fields in /proc/meminfo are formatted as "Key:     123456 kB"
		valFields := strings.Fields(valStr)
		if len(valFields) == 0 {
			continue
		}

		val, err := strconv.ParseUint(valFields[0], 10, 64)
		if err != nil {
			continue
		}

		switch key {
		case "MemTotal":
			info.MemTotal = val
		case "MemFree":
			info.MemFree = val
		case "MemAvailable":
			info.MemAvailable = val
		case "Buffers":
			info.Buffers = val
		case "Cached":
			info.Cached = val
		case "SwapTotal":
			info.SwapTotal = val
		case "SwapFree":
			info.SwapFree = val
		case "Dirty":
			info.Dirty = val
		case "Writeback":
			info.Writeback = val
		case "AnonPages":
			info.AnonPages = val
		case "Mapped":
			info.Mapped = val
		case "Shmem":
			info.Shmem = val
		case "Slab":
			info.Slab = val
		case "SReclaimable":
			info.SReclaimable = val
		case "SUnreclaim":
			info.SUnreclaim = val
		}
	}

	if err := scanner.Err(); err != nil {
		return MemInfo{}, fmt.Errorf("collector: scan meminfo: %w", err)
	}

	return info, nil
}

// CollectVMStat parses memory management event counters from /proc/vmstat.
func CollectVMStat() (VMStatInfo, error) {
	return ParseVMStat(DefaultVMStatPath)
}

// ParseVMStat parses event counters from a custom vmstat file path.
func ParseVMStat(path string) (VMStatInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return VMStatInfo{}, fmt.Errorf("collector: open vmstat: %w", err)
	}
	defer file.Close()

	var info VMStatInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		switch fields[0] {
		case "pgscan_direct", "pgscan_direct_throttle":
			info.PgScanDirect += val
		case "allocstall_direct":
			info.AllocStallDirect = val
		case "compact_stall":
			info.CompactStall = val
		case "compact_fail":
			info.CompactFail = val
		case "pgmajfault":
			info.PgMajFault = val
		case "pswpin":
			info.Pswpin = val
		case "pswpout":
			info.Pswpout = val
		case "numa_miss":
			info.NumaMiss = val
		case "numa_foreign":
			info.NumaForeign = val
		case "numa_interleave":
			info.NumaInterleave = val
		case "thp_collapse_alloc":
			info.THPCollapseAlloc = val
		case "thp_collapse_alloc_failed":
			info.THPCollapseAllocFailed = val
		}
	}

	if err := scanner.Err(); err != nil {
		return VMStatInfo{}, fmt.Errorf("collector: scan vmstat: %w", err)
	}

	return info, nil
}
