// Package collector — process.go scans /proc/[pid]/ for per-process metrics.
//
// Per-PID reads: stat (comm, state, utime, stime, threads, rss),
// oom_score, wchan, io (read_bytes, write_bytes), limits (Max open files),
// fd/ (entry count), and cgroup membership.
//
// Uses a bounded worker pool (runtime.NumCPU goroutines) for parallel collection.
// All per-PID sub-file reads are performed sequentially within a single worker's scope
// to minimize PID recycling races and lock contention.
package collector

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// Default paths for process inspection.
const (
	DefaultProcDir = "/proc"
)

// CollectProcesses scans all visible PIDs under /proc using a bounded worker pool.
func CollectProcesses(ctx context.Context) ([]ProcessInfo, error) {
	return ScanProcesses(ctx, DefaultProcDir)
}

// ScanProcesses scans processes from a given proc root directory using a bounded worker pool.
func ScanProcesses(ctx context.Context, procDir string) ([]ProcessInfo, error) {
	pids, err := discoverPIDs(procDir)
	if err != nil {
		return nil, err
	}

	if len(pids) == 0 {
		return []ProcessInfo{}, nil
	}

	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}
	if numWorkers > len(pids) {
		numWorkers = len(pids)
	}

	jobs := make(chan int, len(pids))
	results := make(chan ProcessInfo, len(pids))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pid := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					info, ok := readProcessInfo(procDir, pid)
					if ok {
						results <- info
					}
				}
			}
		}()
	}

	for _, pid := range pids {
		jobs <- pid
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	collected := make([]ProcessInfo, 0, len(pids))
	for info := range results {
		collected = append(collected, info)
	}

	return collected, nil
}

func discoverPIDs(procDir string) ([]int, error) {
	dir, err := os.Open(procDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	pids := make([]int, 0, len(names)/2)
	for _, name := range names {
		if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
			if pid, err := strconv.Atoi(name); err == nil {
				pids = append(pids, pid)
			}
		}
	}
	return pids, nil
}

func readProcessInfo(procDir string, pid int) (ProcessInfo, bool) {
	pidDir := filepath.Join(procDir, strconv.Itoa(pid))

	statPath := filepath.Join(pidDir, "stat")
	statBytes, err := os.ReadFile(statPath)
	if err != nil {
		return ProcessInfo{}, false
	}

	info, ok := parseProcStatLine(string(statBytes), pid)
	if !ok {
		return ProcessInfo{}, false
	}

	// Read wchan
	if wchanBytes, err := os.ReadFile(filepath.Join(pidDir, "wchan")); err == nil {
		wchan := strings.TrimSpace(string(wchanBytes))
		if wchan != "0" {
			info.Wchan = wchan
		}
	}

	// Read oom_score
	if oomBytes, err := os.ReadFile(filepath.Join(pidDir, "oom_score")); err == nil {
		if val, err := strconv.Atoi(strings.TrimSpace(string(oomBytes))); err == nil {
			info.OOMScore = val
		}
	}

	// Read io (may return EACCES if unprivileged)
	readProcessIO(pidDir, &info)

	// Read limits for Max open files
	readProcessLimits(pidDir, &info)

	// Read status for CPU affinity (Cpus_allowed)
	readProcessStatus(pidDir, &info)

	// Count open FDs
	if fdEntries, err := os.ReadDir(filepath.Join(pidDir, "fd")); err == nil {
		info.OpenFDs = len(fdEntries)
	}

	// Read cgroup path
	readProcessCgroup(pidDir, &info)

	return info, true
}

// parseProcStatLine parses a /proc/[pid]/stat line.
// Field 2 (comm) is in parens: "(comm)" and can contain spaces and parens.
// We locate the first '(' and the LAST ')' to safely isolate comm.
func parseProcStatLine(line string, expectedPID int) (ProcessInfo, bool) {
	line = strings.TrimSpace(line)
	firstParen := strings.IndexByte(line, '(')
	lastParen := strings.LastIndexByte(line, ')')

	if firstParen == -1 || lastParen == -1 || lastParen <= firstParen {
		return ProcessInfo{}, false
	}

	pidStr := strings.TrimSpace(line[:firstParen])
	pid, err := strconv.Atoi(pidStr)
	if err != nil || (expectedPID > 0 && pid != expectedPID) {
		return ProcessInfo{}, false
	}

	comm := line[firstParen+1 : lastParen]
	afterComm := strings.Fields(line[lastParen+1:])
	if len(afterComm) < 22 {
		return ProcessInfo{}, false
	}

	// afterComm indices (0-indexed after comm):
	// 0: state (char)
	// 1: ppid (int)
	// 11: utime (clock ticks)
	// 12: stime (clock ticks)
	// 17: num_threads (long)
	// 21: rss (pages)
	var state byte = '?'
	if len(afterComm[0]) > 0 {
		state = afterComm[0][0]
	}

	ppid, _ := strconv.Atoi(afterComm[1])
	utime, _ := strconv.ParseUint(afterComm[11], 10, 64)
	stime, _ := strconv.ParseUint(afterComm[12], 10, 64)
	numThreads, _ := strconv.Atoi(afterComm[17])
	rssPages, _ := strconv.ParseUint(afterComm[21], 10, 64)

	var policy int
	if len(afterComm) > 38 {
		policy, _ = strconv.Atoi(afterComm[38])
	}

	// Standard Linux page size is 4KB (4096 bytes)
	rssBytes := rssPages * uint64(os.Getpagesize())

	return ProcessInfo{
		PID:        pid,
		Comm:       comm,
		State:      state,
		PPID:       ppid,
		UTime:      utime,
		STime:      stime,
		NumThreads: numThreads,
		RSSBytes:   rssBytes,
		Policy:     policy,
	}, true
}

func readProcessIO(pidDir string, info *ProcessInfo) {
	ioPath := filepath.Join(pidDir, "io")
	file, err := os.Open(ioPath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) {
			info.IOAvailable = false
		}
		return
	}
	defer file.Close()

	info.IOAvailable = true
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		key, valStr, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		val, err := strconv.ParseUint(strings.TrimSpace(valStr), 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "read_bytes":
			info.ReadBytes = val
		case "write_bytes":
			info.WriteBytes = val
		}
	}
}

func readProcessLimits(pidDir string, info *ProcessInfo) {
	limitsPath := filepath.Join(pidDir, "limits")
	file, err := os.Open(limitsPath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Max open files") {
			fields := strings.Fields(line)
			// Format: "Max open files  1024  1048576  files"
			// fields[3] is soft limit, fields[4] is hard limit
			if len(fields) >= 4 {
				if val, err := strconv.ParseUint(fields[3], 10, 64); err == nil {
					info.MaxFDs = val
				}
			}
			break
		}
	}
}

func readProcessCgroup(pidDir string, info *ProcessInfo) {
	cgroupPath := filepath.Join(pidDir, "cgroup")
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// cgroup v2 format: "0::/user.slice/user-1000.slice/session-1.scope"
		if strings.HasPrefix(line, "0::") {
			info.CgroupPath = strings.TrimPrefix(line, "0::")
			return
		}
	}
}

var hexNibbleBits = [256]int{
	'1': 1, '2': 1, '4': 1, '8': 1,
	'3': 2, '5': 2, '6': 2, '9': 2, 'a': 2, 'c': 2, 'A': 2, 'C': 2,
	'7': 3, 'b': 3, 'd': 3, 'e': 3, 'B': 3, 'D': 3, 'E': 3,
	'f': 4, 'F': 4,
}

func countBitsInHexMask(mask string) int {
	count := 0
	for i := 0; i < len(mask); i++ {
		count += hexNibbleBits[mask[i]]
	}
	return count
}

func readProcessStatus(pidDir string, info *ProcessInfo) {
	statusPath := filepath.Join(pidDir, "status")
	file, err := os.Open(statusPath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Cpus_allowed:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.CpusAllowed = countBitsInHexMask(fields[1])
			}
		} else if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				tracerPID, _ := strconv.Atoi(fields[1])
				info.TracerPID = tracerPID
			}
		} else if strings.HasPrefix(line, "SigQ:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if qStr, maxStr, ok := strings.Cut(fields[1], "/"); ok {
					q, _ := strconv.ParseUint(qStr, 10, 64)
					m, _ := strconv.ParseUint(maxStr, 10, 64)
					info.SigQQueued = q
					info.SigQMax = m
				}
			}
		} else if strings.HasPrefix(line, "voluntary_ctxt_switches:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.VoluntaryCtxtSwitches, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "nonvoluntary_ctxt_switches:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.NonvoluntaryCtxtSwitches, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}
}
