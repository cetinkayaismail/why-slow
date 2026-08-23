// Package collector — system.go reads system-wide miscellaneous metrics:
// clocksource from /sys/devices/system/clocksource/clocksource0/current_clocksource
// and TCP listen drops/overflows from /proc/net/netstat.
package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Default paths for system and network stats.
const (
	DefaultClocksourcePath    = "/sys/devices/system/clocksource/clocksource0/current_clocksource"
	DefaultNetStatPath        = "/proc/net/netstat"
	DefaultProcSockStatPath   = "/proc/net/sockstat"
	DefaultPortRangePath      = "/proc/sys/net/ipv4/ip_local_port_range"
	DefaultPIDMaxPath         = "/proc/sys/kernel/pid_max"
	DefaultConntrackCountPath = "/proc/sys/net/netfilter/nf_conntrack_count"
	DefaultConntrackMaxPath   = "/proc/sys/net/netfilter/nf_conntrack_max"
	DefaultBuddyInfoPath      = "/proc/buddyinfo"
	DefaultKSMDir             = "/sys/kernel/mm/ksm"
	DefaultInterruptsPath     = "/proc/interrupts"
	DefaultARPPath            = "/proc/net/arp"
	DefaultGCThresh3Path      = "/proc/sys/net/ipv4/neigh/default/gc_thresh3"
	DefaultInotifyMaxPath     = "/proc/sys/fs/inotify/max_user_watches"
	DefaultSchedStatPath      = "/proc/schedstat"
)

// CollectSystemConfig collects kernel configuration parameters, sysctls, and enterprise topologies.
func CollectSystemConfig() (SystemConfigInfo, error) {
	return ParseSystemConfig(
		DefaultProcSockStatPath,
		DefaultPortRangePath,
		DefaultPIDMaxPath,
		DefaultConntrackCountPath,
		DefaultConntrackMaxPath,
		DefaultBuddyInfoPath,
		DefaultKSMDir,
		DefaultInterruptsPath,
		DefaultARPPath,
		DefaultGCThresh3Path,
		DefaultInotifyMaxPath,
		DefaultSchedStatPath,
	)
}

// ParseSystemConfig parses all global system configuration metrics.
func ParseSystemConfig(sockStatPath, portRangePath, pidMaxPath, ctCountPath, ctMaxPath, buddyPath, ksmDir, irqPath, arpPath, gcThreshPath, inotifyMaxPath, schedStatPath string) (SystemConfigInfo, error) {
	var info SystemConfigInfo
	info.SockStat, _ = ParseSockStat(sockStatPath)
	info.PortRange, _ = ParsePortRange(portRangePath)
	info.PIDMax, _ = ParsePIDMax(pidMaxPath)
	info.Conntrack, _ = ParseConntrack(ctCountPath, ctMaxPath)
	info.BuddyInfo, _ = ParseBuddyInfo(buddyPath)
	info.KSM, _ = ParseKSM(ksmDir)
	info.IRQStat, _ = ParseInterrupts(irqPath)
	info.Neighbor, _ = ParseNeighborTable(arpPath, gcThreshPath)
	info.Inotify, _ = ParseInotifyWatches(inotifyMaxPath)
	info.SchedStat, _ = ParseSchedStat(schedStatPath)
	return info, nil
}

// ParseSockStat parses TCP socket statistics from /proc/net/sockstat.
func ParseSockStat(path string) (SockStatInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return SockStatInfo{}, err
	}
	defer file.Close()

	var info SockStatInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "TCP:") {
			fields := strings.Fields(line)
			for i := 1; i < len(fields)-1; i += 2 {
				val, err := strconv.ParseUint(fields[i+1], 10, 64)
				if err != nil {
					continue
				}
				switch fields[i] {
				case "inuse":
					info.TCPInUse = val
				case "orphan":
					info.TCPOrphan = val
				case "tw":
					info.TCPTimeWait = val
				}
			}
			break
		}
	}
	return info, scanner.Err()
}

// ParsePortRange parses ephemeral port range from /proc/sys/net/ipv4/ip_local_port_range.
func ParsePortRange(path string) (PortRangeInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PortRangeInfo{Low: 32768, High: 60999}, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return PortRangeInfo{Low: 32768, High: 60999}, nil
	}

	low, _ := strconv.ParseUint(fields[0], 10, 64)
	high, _ := strconv.ParseUint(fields[1], 10, 64)
	if low == 0 || high == 0 || high <= low {
		return PortRangeInfo{Low: 32768, High: 60999}, nil
	}

	return PortRangeInfo{Low: low, High: high}, nil
}

// ParsePIDMax parses max PID limit from /proc/sys/kernel/pid_max.
func ParsePIDMax(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 32768, err
	}

	val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || val == 0 {
		return 32768, nil
	}
	return val, nil
}

// CollectClocksource reads the currently active kernel clocksource.
func CollectClocksource() (ClocksourceInfo, error) {
	return ParseClocksource(DefaultClocksourcePath)
}

// ParseClocksource reads the clocksource name from a given path.
func ParseClocksource(path string) (ClocksourceInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ClocksourceInfo{Current: "unknown"}, nil
	}
	return ClocksourceInfo{Current: strings.TrimSpace(string(data))}, nil
}

// CollectNetStat parses ListenOverflows and ListenDrops from /proc/net/netstat.
func CollectNetStat() (NetStatInfo, error) {
	return ParseNetStat(DefaultNetStatPath)
}

// ParseNetStat parses network metrics from a custom netstat path.
func ParseNetStat(path string) (NetStatInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return NetStatInfo{}, fmt.Errorf("collector: open netstat: %w", err)
	}
	defer file.Close()

	var info NetStatInfo
	scanner := bufio.NewScanner(file)

	// /proc/net/netstat uses paired lines:
	// Header: TcpExt: SyncookiesSent ... ListenOverflows ListenDrops ...
	// Values: TcpExt: 0 ... 5 12 ...
	var pendingHeaderPrefix string
	var headerFields []string

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		prefix := fields[0]
		if pendingHeaderPrefix == "" {
			// This is a header row
			pendingHeaderPrefix = prefix
			headerFields = fields[1:]
		} else if pendingHeaderPrefix == prefix {
			// This is the matching value row
			valFields := fields[1:]
			if prefix == "TcpExt:" {
				parseTcpExtFields(headerFields, valFields, &info)
			}
			pendingHeaderPrefix = ""
			headerFields = nil
		} else {
			// Mismatched or new header
			pendingHeaderPrefix = prefix
			headerFields = fields[1:]
		}
	}

	if err := scanner.Err(); err != nil {
		return NetStatInfo{}, fmt.Errorf("collector: scan netstat: %w", err)
	}

	return info, nil
}

func parseTcpExtFields(headers, values []string, info *NetStatInfo) {
	count := len(headers)
	if len(values) < count {
		count = len(values)
	}

	for i := 0; i < count; i++ {
		val, err := strconv.ParseUint(values[i], 10, 64)
		if err != nil {
			continue
		}

		switch headers[i] {
		case "ListenOverflows":
			info.ListenOverflows = val
		case "ListenDrops":
			info.ListenDrops = val
		case "TCPMemoryPressures":
			info.TCPMemoryPressures = val
		case "TCPRcvCollapsed":
			info.TCPRcvCollapsed = val
		case "TCPAbortOnMemory":
			info.TCPAbortOnMemory = val
		case "TCPReqQFullDoCookies":
			info.TCPReqQFullDoCookies = val
		}
	}
}

// ParseConntrack parses netfilter connection tracking tables count and max capacity.
func ParseConntrack(countPath, maxPath string) (ConntrackInfo, error) {
	countData, err := os.ReadFile(countPath)
	if err != nil {
		// Fallback to legacy ipv4 path if exists
		countData, err = os.ReadFile("/proc/sys/net/ipv4/netfilter/ip_conntrack_count")
		if err != nil {
			return ConntrackInfo{}, err
		}
	}

	maxData, err := os.ReadFile(maxPath)
	if err != nil {
		maxData, err = os.ReadFile("/proc/sys/net/ipv4/netfilter/ip_conntrack_max")
		if err != nil {
			return ConntrackInfo{}, err
		}
	}

	count, err1 := strconv.ParseUint(strings.TrimSpace(string(countData)), 10, 64)
	max, err2 := strconv.ParseUint(strings.TrimSpace(string(maxData)), 10, 64)
	if err1 != nil || err2 != nil || max == 0 {
		return ConntrackInfo{}, fmt.Errorf("collector: invalid conntrack numbers")
	}

	return ConntrackInfo{
		Available: true,
		Count:     count,
		Max:       max,
		Ratio:     float64(count) / float64(max),
	}, nil
}

// ParseBuddyInfo parses /proc/buddyinfo to calculate page fragmentation across zones.
func ParseBuddyInfo(path string) (ZoneBuddyInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return ZoneBuddyInfo{}, err
	}
	defer file.Close()

	var info ZoneBuddyInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		// Format: Node 0, zone DMA32 10 20 30 ...
		if len(fields) < 4 {
			continue
		}

		var zoneName string
		var chunkStart int
		for i, f := range fields {
			if f == "zone" && i+1 < len(fields) {
				zoneName = fields[i+1]
				chunkStart = i + 2
				break
			}
		}

		if chunkStart == 0 || chunkStart >= len(fields) {
			continue
		}

		var totalPages uint64
		for order := 0; order+chunkStart < len(fields); order++ {
			chunks, err := strconv.ParseUint(fields[order+chunkStart], 10, 64)
			if err != nil {
				continue
			}
			totalPages += chunks * (1 << uint(order))
		}

		switch zoneName {
		case "DMA32":
			info.DMA32FreePages += totalPages
			info.Available = true
		case "Normal":
			info.NormalFreePages += totalPages
			info.Available = true
		}
	}

	return info, scanner.Err()
}

// ParseKSM parses Kernel Samepage Merging memory deduplication statistics.
func ParseKSM(ksmDir string) (KSMInfo, error) {
	runData, err := os.ReadFile(ksmDir + "/run")
	if err != nil {
		return KSMInfo{}, err
	}

	running := strings.TrimSpace(string(runData)) == "1"
	sharedData, _ := os.ReadFile(ksmDir + "/pages_shared")
	sharingData, _ := os.ReadFile(ksmDir + "/pages_sharing")
	toScanData, _ := os.ReadFile(ksmDir + "/pages_to_scan")

	shared, _ := strconv.ParseUint(strings.TrimSpace(string(sharedData)), 10, 64)
	sharing, _ := strconv.ParseUint(strings.TrimSpace(string(sharingData)), 10, 64)
	toScan, _ := strconv.ParseUint(strings.TrimSpace(string(toScanData)), 10, 64)

	return KSMInfo{
		Available:    true,
		Running:      running,
		PagesShared:  shared,
		PagesSharing: sharing,
		PagesToScan:  toScan,
	}, nil
}

// ParseInterrupts parses /proc/interrupts to detect hardware IRQ imbalance.
func ParseInterrupts(path string) (IRQStatInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return IRQStatInfo{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return IRQStatInfo{}, fmt.Errorf("collector: empty interrupts file")
	}

	headerLine := scanner.Text()
	cpuHeaders := strings.Fields(headerLine)
	numCPUs := len(cpuHeaders)
	if numCPUs == 0 {
		return IRQStatInfo{}, fmt.Errorf("collector: no cpu headers in interrupts")
	}

	cpuTotals := make([]uint64, numCPUs)
	for scanner.Scan() {
		line := scanner.Text()
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}

		fields := strings.Fields(line[colonIdx+1:])
		for i := 0; i < numCPUs && i < len(fields); i++ {
			count, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				break
			}
			cpuTotals[i] += count
		}
	}

	var maxIRQs uint64
	var maxID int
	var totalSum uint64
	for i, count := range cpuTotals {
		totalSum += count
		if count > maxIRQs {
			maxIRQs = count
			maxID = i
		}
	}

	var otherAvg float64
	if numCPUs > 1 {
		otherAvg = float64(totalSum-maxIRQs) / float64(numCPUs-1)
	}

	return IRQStatInfo{
		Available:         true,
		MaxCoreID:         maxID,
		MaxCoreIRQs:       maxIRQs,
		OtherCoresAvgIRQs: otherAvg,
	}, nil
}

// ParseNeighborTable parses /proc/net/arp and /proc/sys/net/ipv4/neigh/default/gc_thresh3.
func ParseNeighborTable(arpPath, gcThreshPath string) (ARPNeighborInfo, error) {
	file, err := os.Open(arpPath)
	if err != nil {
		return ARPNeighborInfo{}, err
	}
	defer file.Close()

	activeCount := 0
	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false // Skip header line
			continue
		}
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			activeCount++
		}
	}

	gcData, err := os.ReadFile(gcThreshPath)
	gcThresh3 := 1024 // Default fallback
	if err == nil {
		if val, err2 := strconv.Atoi(strings.TrimSpace(string(gcData))); err2 == nil && val > 0 {
			gcThresh3 = val
		}
	}

	ratio := float64(activeCount) / float64(gcThresh3)
	return ARPNeighborInfo{
		Available:     true,
		ActiveEntries: activeCount,
		GCThresh3:     gcThresh3,
		Ratio:         ratio,
	}, nil
}

// ParseInotifyWatches parses inotify max user watches limit.
func ParseInotifyWatches(maxPath string) (InotifyInfo, error) {
	data, err := os.ReadFile(maxPath)
	if err != nil {
		return InotifyInfo{}, err
	}

	maxWatches, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || maxWatches == 0 {
		return InotifyInfo{}, fmt.Errorf("collector: invalid inotify max")
	}

	return InotifyInfo{
		Available:      true,
		MaxUserWatches: maxWatches,
	}, nil
}

// ParseSchedStat parses /proc/schedstat for CPU runqueue wait time vs running time.
func ParseSchedStat(path string) (SchedStatInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return SchedStatInfo{}, err
	}
	defer file.Close()

	var totalWaitTime uint64
	var totalRunTime uint64
	hasData := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu") {
			fields := strings.Fields(line)
			// Format: cpuX <count1> ... <count7> <run_time_ns> <wait_time_ns> <timeslices>
			// In standard Linux /proc/schedstat:
			// field[8] is running time in ns, field[9] is wait time on runqueue in ns
			if len(fields) >= 10 {
				runTime, err1 := strconv.ParseUint(fields[8], 10, 64)
				waitTime, err2 := strconv.ParseUint(fields[9], 10, 64)
				if err1 == nil && err2 == nil {
					totalRunTime += runTime / 1_000_000   // convert ns to ms
					totalWaitTime += waitTime / 1_000_000 // convert ns to ms
					hasData = true
				}
			}
		}
	}

	var ratio float64
	if totalRunTime > 0 {
		ratio = float64(totalWaitTime) / float64(totalRunTime)
	}

	return SchedStatInfo{
		Available:          hasData,
		RunqueueWaitTimeMS: totalWaitTime,
		RunningTimeMS:      totalRunTime,
		Ratio:              ratio,
	}, nil
}
