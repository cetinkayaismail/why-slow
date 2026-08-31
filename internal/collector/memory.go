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

		valFields := strings.Fields(valStr)
		if len(valFields) == 0 {
			continue
		}

		val, err := strconv.ParseUint(valFields[0], 10, 64)
		if err != nil {
			continue
		}

		populateMemInfoKey(key, val, &info)
	}

	if err := scanner.Err(); err != nil {
		return MemInfo{}, fmt.Errorf("collector: scan meminfo: %w", err)
	}

	return info, nil
}

func populateMemInfoKey(key string, val uint64, info *MemInfo) {
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
	case "HugePages_Total":
		info.HugePagesTotal = val
	case "HugePages_Free":
		info.HugePagesFree = val
	case "HugePages_Rsvd":
		info.HugePagesRsvd = val
	case "CmaTotal":
		info.CmaTotal = val
	case "CmaFree":
		info.CmaFree = val
	case "Zswap":
		info.Zswap = val
	case "Zswapped":
		info.Zswapped = val
	}
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

		populateVMStatKey(fields[0], val, &info)
	}

	if err := scanner.Err(); err != nil {
		return VMStatInfo{}, fmt.Errorf("collector: scan vmstat: %w", err)
	}

	return info, nil
}

func populateVMStatKey(key string, val uint64, info *VMStatInfo) {
	switch key {
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
	case "workingset_refault_file", "workingset_refault":
		info.WorkingsetRefaultFile += val
	case "workingset_refault_anon":
		info.WorkingsetRefaultAnon = val
	case "thp_split":
		info.THPSplit = val
	case "numa_pte_updates":
		info.NumaPteUpdates = val
	case "numa_hint_faults":
		info.NumaHintFaults = val
	case "zswpin":
		info.Zswpin = val
	case "zswpout":
		info.Zswpout = val
	case "zswap_reject_reclaim_fail":
		info.ZswapRejectReclaimFail = val
	case "thp_fault_fallback":
		info.THPFaultFallback = val
	case "thp_fault_alloc":
		info.THPFaultAlloc = val
	case "thp_scan_exceed", "thp_split_page_failed":
		info.THPScanExceed += val
	case "nr_dirty":
		info.NRDirty = val
	case "thp_zero_page_alloc":
		info.THPZeroPageAlloc = val
	case "oom_kill":
		info.OOMKill = val
	}
}
