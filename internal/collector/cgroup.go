// Package collector — cgroup.go discovers cgroup paths and reads
// cpu.stat (throttled_usec, nr_throttled) and memory.events (oom_kill)
// from /sys/fs/cgroup. Supports cgroup v2.
package collector

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Default cgroup mount path for Linux cgroup v2.
const (
	DefaultCgroupV2Dir = "/sys/fs/cgroup"
)

// CollectCgroups reads metrics for unique cgroups found across inspected processes.
func CollectCgroups(procs []ProcessInfo) (CgroupInfo, error) {
	return ParseCgroups(DefaultCgroupV2Dir, procs)
}

// ParseCgroups inspects cgroup metrics for the given base directory and process list.
func ParseCgroups(baseDir string, procs []ProcessInfo) (CgroupInfo, error) {
	if _, err := os.Stat(baseDir); err != nil {
		return CgroupInfo{Available: false}, nil
	}

	uniquePaths := make(map[string]struct{}, len(procs)+1)
	uniquePaths["/"] = struct{}{}

	for _, p := range procs {
		if p.CgroupPath != "" {
			uniquePaths[p.CgroupPath] = struct{}{}
		}
	}

	info := CgroupInfo{
		Available: true,
		Groups:    make([]CgroupEntry, 0, len(uniquePaths)),
	}

	for cgPath := range uniquePaths {
		relPath := strings.TrimPrefix(cgPath, "/")
		fullDir := filepath.Join(baseDir, relPath)

		entry := CgroupEntry{Path: cgPath}
		hasData := false

		// Parse cpu.stat
		cpuStatPath := filepath.Join(fullDir, "cpu.stat")
		if parseCgroupCPUStat(cpuStatPath, &entry) {
			hasData = true
		}

		// Parse cpu.shares
		cpuSharesPath := filepath.Join(fullDir, "cpu.shares")
		if parseCPUShares(cpuSharesPath, &entry) {
			hasData = true
		}

		// Parse memory.events
		memEventsPath := filepath.Join(fullDir, "memory.events")
		if parseCgroupMemEvents(memEventsPath, &entry) {
			hasData = true
		}

		// Parse cgroup.events
		eventsPath := filepath.Join(fullDir, "cgroup.events")
		if parseCgroupEvents(eventsPath, &entry) {
			hasData = true
		}

		// Parse cgroup.freeze
		freezePath := filepath.Join(fullDir, "cgroup.freeze")
		if parseCgroupFreeze(freezePath, &entry) {
			hasData = true
		}

		if entry.Frozen {
			info.Frozen = true
		}

		if hasData {
			info.Groups = append(info.Groups, entry)
		}
	}

	if len(info.Groups) == 0 {
		info.Available = false
	}
	return info, nil
}

func parseCgroupEvents(path string, entry *CgroupEntry) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	found := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "frozen" && fields[1] == "1" {
			entry.Frozen = true
			found = true
		}
	}
	return found
}

func parseCgroupFreeze(path string, entry *CgroupEntry) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if strings.TrimSpace(string(data)) == "1" {
		entry.Frozen = true
		return true
	}
	return false
}

func parseCgroupCPUStat(path string, entry *CgroupEntry) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	found := false
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
		case "nr_periods":
			entry.NrPeriods = val
			found = true
		case "throttled_usec":
			entry.ThrottledUsec = val
			found = true
		case "nr_throttled":
			entry.NrThrottled = val
			found = true
		case "nr_bursts":
			entry.NrBursts = val
			found = true
		case "burst_usec":
			entry.BurstUsec = val
			found = true
		}
	}
	return found
}

func parseCgroupMemEvents(path string, entry *CgroupEntry) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	found := false
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
		case "oom_kill":
			entry.OOMKills = val
			found = true
		case "high":
			entry.MemoryHighEvents = val
			found = true
		case "max":
			entry.MemEventsMax = val
			found = true
		}
	}
	return found
}

func parseCPUShares(path string, entry *CgroupEntry) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return false
	}
	entry.CPUShares = val
	return true
}
