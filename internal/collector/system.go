// Package collector — system.go reads system-wide miscellaneous metrics:
// clocksource from /sys/devices/system/clocksource/clocksource0/current_clocksource
// and TCP listen drops/overflows from /proc/net/netstat.
package collector

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Default paths for system and network stats.
const (
	DefaultClocksourcePath          = "/sys/devices/system/clocksource/clocksource0/current_clocksource"
	DefaultNetStatPath              = "/proc/net/netstat"
	DefaultProcSockStatPath         = "/proc/net/sockstat"
	DefaultPortRangePath            = "/proc/sys/net/ipv4/ip_local_port_range"
	DefaultPIDMaxPath               = "/proc/sys/kernel/pid_max"
	DefaultConntrackCountPath       = "/proc/sys/net/netfilter/nf_conntrack_count"
	DefaultConntrackMaxPath         = "/proc/sys/net/netfilter/nf_conntrack_max"
	DefaultBuddyInfoPath            = "/proc/buddyinfo"
	DefaultKSMDir                   = "/sys/kernel/mm/ksm"
	DefaultInterruptsPath           = "/proc/interrupts"
	DefaultARPPath                  = "/proc/net/arp"
	DefaultGCThresh3Path            = "/proc/sys/net/ipv4/neigh/default/gc_thresh3"
	DefaultInotifyMaxPath           = "/proc/sys/fs/inotify/max_user_watches"
	DefaultInotifyMaxQueuedPath     = "/proc/sys/fs/inotify/max_queued_events"
	DefaultSchedStatPath            = "/proc/schedstat"
	DefaultSNMPPath                 = "/proc/net/snmp"
	DefaultSoftnetPath              = "/proc/net/softnet_stat"
	DefaultMinFreeKbytesPath        = "/proc/sys/vm/min_free_kbytes"
	DefaultCorePatternPath          = "/proc/sys/kernel/core_pattern"
	DefaultKernelSemPath            = "/proc/sys/kernel/sem"
	DefaultSysVIPCSemPath           = "/proc/sysvipc/sem"
	DefaultTCPMaxTWBucketsPath      = "/proc/sys/net/ipv4/tcp_max_tw_buckets"
	DefaultNumaBalancingPath        = "/proc/sys/kernel/numa_balancing"
	DefaultSchedRTRuntimeUSPath     = "/proc/sys/kernel/sched_rt_runtime_us"
	DefaultSchedMigrationCostNSPath = "/proc/sys/kernel/sched_migration_cost_ns"
	DefaultAIONRPath                = "/proc/sys/fs/aio-nr"
	DefaultAIOMaxNRPath             = "/proc/sys/fs/aio-max-nr"
	DefaultSysVIPCShmPath           = "/proc/sysvipc/shm"
	DefaultKernelShmMNIPath         = "/proc/sys/kernel/shmmni"
	DefaultKernelShmAllPath         = "/proc/sys/kernel/shmall"
	DefaultThreadsMaxPath           = "/proc/sys/kernel/threads-max"
	DefaultFileNRPath               = "/proc/sys/fs/file-nr"
	DefaultMDStatPath               = "/proc/mdstat"
	DefaultTHPDefragPath            = "/sys/kernel/mm/transparent_hugepage/defrag"
	DefaultSysNetDir                = "/sys/class/net"
)

// CollectSystemConfig collects kernel configuration parameters, sysctls, and enterprise topologies.
func CollectSystemConfig() (SystemConfigInfo, error) {
	info, err := ParseSystemConfig(
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
	info.MinFreeKbytes, _ = ParseMinFreeKbytes(DefaultMinFreeKbytesPath)
	info.CorePattern, _ = ParseCorePattern(DefaultCorePatternPath)
	info.SysVSem, _ = ParseSysVSem(DefaultKernelSemPath, DefaultSysVIPCSemPath)
	info.TCPMaxTWBuckets, _ = ParseTCPMaxTWBuckets(DefaultTCPMaxTWBucketsPath)
	info.NumaBalancing, _ = ParseNumaBalancing(DefaultNumaBalancingPath)
	info.SchedRTRuntimeUS, _ = ParseSchedRTRuntimeUS(DefaultSchedRTRuntimeUSPath)
	info.SchedMigrationCostNS, _ = ParseSchedMigrationCostNS(DefaultSchedMigrationCostNSPath)
	info.Inotify.MaxQueuedEvents, _ = ParseInotifyMaxQueuedEvents(DefaultInotifyMaxQueuedPath)
	info.AIONR, info.AIOMaxNR, _ = ParseAIO(DefaultAIONRPath, DefaultAIOMaxNRPath)
	info.SysVShm, _ = ParseSysVShm(DefaultSysVIPCShmPath, DefaultKernelShmMNIPath, DefaultKernelShmAllPath)
	info.MDStat, _ = ParseMDStat(DefaultMDStatPath)
	info.THPDefragMode, _ = ParseTHPDefrag(DefaultTHPDefragPath)
	info.ThreadsMax, _ = ParseThreadsMax(DefaultThreadsMaxPath)
	info.FileNR, _ = ParseFileNR(DefaultFileNRPath)
	return info, err
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

// ParseMinFreeKbytes reads vm.min_free_kbytes from /proc/sys/vm/min_free_kbytes.
func ParseMinFreeKbytes(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// ParseCorePattern reads kernel.core_pattern from /proc/sys/kernel/core_pattern.
func ParseCorePattern(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ParseSysVSem parses SysV semaphore limits from /proc/sys/kernel/sem and allocations from /proc/sysvipc/sem.
func ParseSysVSem(limitsPath, ipcPath string) (SysVSemInfo, error) {
	var info SysVSemInfo

	// 1. Read limits from /proc/sys/kernel/sem
	data, err := os.ReadFile(limitsPath)
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 4 {
			info.SemMSL, _ = strconv.ParseUint(fields[0], 10, 64)
			info.SemMNS, _ = strconv.ParseUint(fields[1], 10, 64)
			info.SemOPM, _ = strconv.ParseUint(fields[2], 10, 64)
			info.SemMNI, _ = strconv.ParseUint(fields[3], 10, 64)
			info.Available = true
		}
	}

	// 2. Read allocations from /proc/sysvipc/sem
	file, err := os.Open(ipcPath)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		isHeader := true
		for scanner.Scan() {
			if isHeader {
				isHeader = false
				continue
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 {
				info.AllocatedSemSets++
				nsems, _ := strconv.ParseUint(fields[3], 10, 64)
				info.AllocatedSemaphores += nsems
			}
		}
	}

	return info, nil
}

// ParseTCPMaxTWBuckets reads tcp_max_tw_buckets from /proc/sys/net/ipv4/tcp_max_tw_buckets.
func ParseTCPMaxTWBuckets(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// ParseNumaBalancing reads numa_balancing from /proc/sys/kernel/numa_balancing.
func ParseNumaBalancing(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// ParseSchedRTRuntimeUS reads sched_rt_runtime_us from /proc/sys/kernel/sched_rt_runtime_us.
func ParseSchedRTRuntimeUS(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
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

// CollectNetStat parses ListenOverflows, drops, memory pressures, SNMP retransmissions, and softnet backlog drops.
func CollectNetStat() (NetStatInfo, error) {
	info, _ := ParseNetStat(DefaultNetStatPath)
	retrans, outSegs, udpRcv, udpSnd, udpIn, _ := ParseSNMP(DefaultSNMPPath)
	info.RetransSegs = retrans
	info.OutSegs = outSegs
	info.UDPRcvbufErrors = udpRcv
	info.UDPSndbufErrors = udpSnd
	info.UDPInErrors = udpIn

	ipReqds, ipFails, ipTimeout, ipOKs, _ := ParseIPSNMP(DefaultSNMPPath)
	info.IPReasmReqds = ipReqds
	info.IPReasmFails = ipFails
	info.IPReasmTimeout = ipTimeout
	info.IPReasmOKs = ipOKs

	dropped, squeeze, _ := ParseSoftnet(DefaultSoftnetPath)
	info.SoftnetDropped = dropped
	info.SoftnetTimeSqueeze = squeeze

	return info, nil
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
		case "TCPWinProbe":
			info.TCPWinProbe = val
		case "TCPZeroWindowDrop":
			info.TCPZeroWindowDrop = val
		case "TCPAbortOnData":
			info.TCPAbortOnData = val
		case "TCPAbortOnClose":
			info.TCPAbortOnClose = val
		case "TCPTimeouts":
			info.TCPTimeouts = val
		case "TCPSpuriousRtxHost":
			info.TCPSpuriousRtxHost = val
		case "TCPTimeWaitOverflow":
			info.TCPTimeWaitOverflow = val
		case "PAWSEstab":
			info.PAWSEstab = val
		case "PAWSPassive":
			info.PAWSPassive = val
		case "TCPSlowStartRetrans":
			info.TCPSlowStartRetrans = val
		case "SyncookiesSent":
			info.SyncookiesSent = val
		case "SyncookiesRecv":
			info.SyncookiesRecv = val
		case "SyncookiesFailed":
			info.SyncookiesFailed = val
		case "TCPOFOQueue":
			info.TCPOFOQueue = val
		case "TCPFastOpenActiveFail":
			info.TCPFastOpenActiveFail = val
		case "TCPFastOpenPassiveFail":
			info.TCPFastOpenPassiveFail = val
		case "TCPSynRetrans":
			info.TCPSynRetrans = val
		case "TCPDeferAcceptDrop":
			info.TCPDeferAcceptDrop = val
		}
	}
}

// ParseSNMP parses TCP OutSegs, RetransSegs, and UDP buffer errors from /proc/net/snmp.
func ParseSNMP(path string) (uint64, uint64, uint64, uint64, uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("collector: open snmp: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var pendingHeaderPrefix string
	var headerFields []string
	var retransSegs, outSegs, udpRcv, udpSnd, udpIn uint64

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		prefix := fields[0]
		if pendingHeaderPrefix == "" {
			pendingHeaderPrefix = prefix
			headerFields = fields[1:]
		} else if pendingHeaderPrefix == prefix {
			valFields := fields[1:]
			count := len(headerFields)
			if len(valFields) < count {
				count = len(valFields)
			}
			if prefix == "Tcp:" {
				for i := 0; i < count; i++ {
					if headerFields[i] == "RetransSegs" {
						retransSegs, _ = strconv.ParseUint(valFields[i], 10, 64)
					} else if headerFields[i] == "OutSegs" {
						outSegs, _ = strconv.ParseUint(valFields[i], 10, 64)
					}
				}
			} else if prefix == "Udp:" {
				for i := 0; i < count; i++ {
					switch headerFields[i] {
					case "RcvbufErrors":
						udpRcv, _ = strconv.ParseUint(valFields[i], 10, 64)
					case "SndbufErrors":
						udpSnd, _ = strconv.ParseUint(valFields[i], 10, 64)
					case "InErrors":
						udpIn, _ = strconv.ParseUint(valFields[i], 10, 64)
					}
				}
			}
			pendingHeaderPrefix = ""
			headerFields = nil
		} else {
			pendingHeaderPrefix = prefix
			headerFields = fields[1:]
		}
	}

	return retransSegs, outSegs, udpRcv, udpSnd, udpIn, scanner.Err()
}

// ParseSoftnet parses dropped packets and time squeeze counts from /proc/net/softnet_stat.
func ParseSoftnet(path string) (uint64, uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, fmt.Errorf("collector: open softnet_stat: %w", err)
	}
	defer file.Close()

	var totalDropped, totalTimeSqueeze uint64
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		// Column 2 (0-indexed 1) is dropped, Column 3 (0-indexed 2) is time_squeeze (hex format)
		dropped, err1 := strconv.ParseUint(fields[1], 16, 64)
		timeSqueeze, err2 := strconv.ParseUint(fields[2], 16, 64)
		if err1 == nil {
			totalDropped += dropped
		}
		if err2 == nil {
			totalTimeSqueeze += timeSqueeze
		}
	}

	return totalDropped, totalTimeSqueeze, scanner.Err()
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

		var totalPages, order0Pages, highOrderPages uint64
		for order := 0; order+chunkStart < len(fields); order++ {
			chunks, err := strconv.ParseUint(fields[order+chunkStart], 10, 64)
			if err != nil {
				continue
			}
			pgs := chunks * (1 << uint(order))
			totalPages += pgs
			if order == 0 {
				order0Pages += pgs
			} else if order >= 3 {
				highOrderPages += pgs
			}
		}

		switch zoneName {
		case "DMA32":
			info.DMA32FreePages += totalPages
			info.Available = true
		case "Normal":
			info.NormalFreePages += totalPages
			info.NormalOrder0Pages += order0Pages
			info.NormalHighOrderPages += highOrderPages
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

// ParseInotifyMaxQueuedEvents parses inotify max queued events limit.
func ParseInotifyMaxQueuedEvents(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("collector: parse inotify max_queued_events: %w", err)
	}

	return val, nil
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

// ParseSchedMigrationCostNS parses kernel.sched_migration_cost_ns from /proc/sys/kernel/sched_migration_cost_ns.
func ParseSchedMigrationCostNS(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, err
	}
	return val, nil
}

// CollectNetIfaces collects network interface carrier status and statistics from /sys/class/net.
func CollectNetIfaces() ([]NetIfaceStat, error) {
	return ParseNetIfaces(DefaultSysNetDir)
}

// ParseNetIfaces parses network interfaces in the specified sysfs net directory.
func ParseNetIfaces(sysNetDir string) ([]NetIfaceStat, error) {
	entries, err := os.ReadDir(sysNetDir)
	if err != nil {
		return nil, err
	}

	ifaces := make([]NetIfaceStat, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}

		ifaceDir := sysNetDir + "/" + name
		stat := NetIfaceStat{Name: name}

		// Read carrier_changes
		if data, err := os.ReadFile(ifaceDir + "/carrier_changes"); err == nil {
			stat.CarrierChanges, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}

		// Read operstate
		if data, err := os.ReadFile(ifaceDir + "/operstate"); err == nil {
			stat.OperState = strings.TrimSpace(string(data))
		}

		// Read rx_crc_errors
		if data, err := os.ReadFile(ifaceDir + "/statistics/rx_crc_errors"); err == nil {
			stat.RxCRCErrors, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}

		// Read tx_carrier_errors
		if data, err := os.ReadFile(ifaceDir + "/statistics/tx_carrier_errors"); err == nil {
			stat.TxCarrierErrors, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}

		// Read rx_errors
		if data, err := os.ReadFile(ifaceDir + "/statistics/rx_errors"); err == nil {
			stat.RxErrors, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}

		// Read tx_errors
		if data, err := os.ReadFile(ifaceDir + "/statistics/tx_errors"); err == nil {
			stat.TxErrors, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}

		// Read rx_missed_errors
		if data, err := os.ReadFile(ifaceDir + "/statistics/rx_missed_errors"); err == nil {
			stat.RxMissedErrors, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}

		// Read rx_fifo_errors
		if data, err := os.ReadFile(ifaceDir + "/statistics/rx_fifo_errors"); err == nil {
			stat.RxFIFOErrors, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}

		ifaces = append(ifaces, stat)
	}

	return ifaces, nil
}

// ParseTHPDefrag parses the transparent hugepage defrag setting from sysfs.
func ParseTHPDefrag(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	content := strings.TrimSpace(string(data))
	// Look for bracketed option, e.g. "always defer defer+madvise [madvise] never"
	start := strings.IndexByte(content, '[')
	end := strings.IndexByte(content, ']')
	if start != -1 && end != -1 && end > start {
		return content[start+1 : end], nil
	}
	return content, nil
}

// ParseIPSNMP parses IP reassembly counters from /proc/net/snmp.
func ParseIPSNMP(path string) (uint64, uint64, uint64, uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("collector: open snmp: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var pendingHeaderPrefix string
	var headerFields []string
	var reqds, fails, timeout, oks uint64

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		prefix := fields[0]
		if pendingHeaderPrefix == "" {
			pendingHeaderPrefix = prefix
			headerFields = fields[1:]
		} else if pendingHeaderPrefix == prefix {
			valFields := fields[1:]
			count := len(headerFields)
			if len(valFields) < count {
				count = len(valFields)
			}
			if prefix == "Ip:" {
				for i := 0; i < count; i++ {
					switch headerFields[i] {
					case "ReasmReqds":
						reqds, _ = strconv.ParseUint(valFields[i], 10, 64)
					case "ReasmFails":
						fails, _ = strconv.ParseUint(valFields[i], 10, 64)
					case "ReasmTimeout":
						timeout, _ = strconv.ParseUint(valFields[i], 10, 64)
					case "ReasmOKs":
						oks, _ = strconv.ParseUint(valFields[i], 10, 64)
					}
				}
			}
			pendingHeaderPrefix = ""
			headerFields = nil
		} else {
			pendingHeaderPrefix = prefix
			headerFields = fields[1:]
		}
	}
	return reqds, fails, timeout, oks, scanner.Err()
}

// ParseAIO parses current and maximum asynchronous I/O event limits from /proc/sys/fs/aio-nr and /proc/sys/fs/aio-max-nr.
func ParseAIO(nrPath, maxPath string) (uint64, uint64, error) {
	var nr, max uint64
	if data, err := os.ReadFile(nrPath); err == nil {
		nr, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}
	if data, err := os.ReadFile(maxPath); err == nil {
		max, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}
	return nr, max, nil
}

// ParseSysVShm parses active SysV shared memory segments and kernel limits.
func ParseSysVShm(shmPath, mniPath, allPath string) (SysVShmInfo, error) {
	var info SysVShmInfo
	if data, err := os.ReadFile(mniPath); err == nil {
		info.ShmMNI, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}
	if data, err := os.ReadFile(allPath); err == nil {
		info.ShmAll, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}

	file, err := os.Open(shmPath)
	if err != nil {
		return info, err
	}
	defer file.Close()

	info.Available = true
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] == "key" {
			continue
		}
		info.AllocatedSegments++
		if sizeBytes, err := strconv.ParseUint(fields[3], 10, 64); err == nil {
			info.AllocatedPages += (sizeBytes + 4095) / 4096
		}
	}
	return info, scanner.Err()
}

// ParseMDStat parses /proc/mdstat to detect active RAID resync, rebuild, or check operations.
func ParseMDStat(path string) (MDStatInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return MDStatInfo{Available: false}, err
	}
	defer file.Close()

	info := MDStatInfo{Available: true}
	scanner := bufio.NewScanner(file)
	currentMD := ""

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "md") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				currentMD = fields[0]
			}
		}

		if strings.Contains(trimmed, "resync =") {
			info.ActiveResync = true
			info.ArrayName = currentMD
			info.Operation = "resync"
		} else if strings.Contains(trimmed, "recovery =") {
			info.ActiveResync = true
			info.ArrayName = currentMD
			info.Operation = "recovery"
		} else if strings.Contains(trimmed, "check =") {
			info.ActiveResync = true
			info.ArrayName = currentMD
			info.Operation = "check"
		} else if strings.Contains(trimmed, "repair =") {
			info.ActiveResync = true
			info.ArrayName = currentMD
			info.Operation = "repair"
		}
	}
	return info, scanner.Err()
}

// ParseThreadsMax reads threads-max from /proc/sys/kernel/threads-max.
func ParseThreadsMax(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// ParseFileNR parses system-wide allocated and max file handles from /proc/sys/fs/file-nr.
func ParseFileNR(path string) (FileNRInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileNRInfo{Available: false}, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return FileNRInfo{Available: false}, fmt.Errorf("collector: invalid file-nr format: %s", string(data))
	}

	alloc, err1 := strconv.ParseUint(fields[0], 10, 64)
	unused, err2 := strconv.ParseUint(fields[1], 10, 64)
	maxF, err3 := strconv.ParseUint(fields[2], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return FileNRInfo{Available: false}, fmt.Errorf("collector: parse file-nr numbers: %w", errors.Join(err1, err2, err3))
	}

	return FileNRInfo{
		Available: true,
		Allocated: alloc,
		Unused:    unused,
		Max:       maxF,
	}, nil
}
