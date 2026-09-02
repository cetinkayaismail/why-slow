// Package collector provides parsers for Linux /proc and /sys virtual
// filesystems. It defines the SystemSnapshot and SnapshotDiff types,
// the master CollectSnapshot function, and the differential calculator.
//
// All collectors are privilege-unaware: they read files and silently
// handle ErrPermission/ErrNotExist. When running as root, the kernel
// returns more data through the same code paths.
package collector

import (
	"context"
	"fmt"
	"time"
)

// RunContext holds process-level execution context and privilege metadata.
type RunContext struct {
	IsRoot       bool
	EffectiveUID int
}

// PSIMetrics contains Pressure Stall Information metrics for a single level (some or full).
type PSIMetrics struct {
	Avg10  float64
	Avg60  float64
	Avg300 float64
	Total  uint64 // total stall time in microseconds
}

// PSIResource holds 'some' and 'full' pressure stall metrics for a resource.
type PSIResource struct {
	Some PSIMetrics
	Full PSIMetrics
}

// PSIInfo encapsulates Linux Pressure Stall Information for CPU, Memory, and I/O.
type PSIInfo struct {
	Available bool
	CPU       PSIResource
	Memory    PSIResource
	IO        PSIResource
}

// CoreCPUStat holds raw jiffies for an individual CPU core or aggregate.
type CoreCPUStat struct {
	ID        string // "cpu", "cpu0", "cpu1", etc.
	User      uint64
	Nice      uint64
	System    uint64
	Idle      uint64
	IOWait    uint64
	IRQ       uint64
	SoftIRQ   uint64
	Steal     uint64
	Guest     uint64
	GuestNice uint64
}

// Total returns the sum of all CPU jiffies.
// Note: Linux kernel includes Guest in User and GuestNice in Nice,
// so we do NOT add Guest/GuestNice separately to avoid double-counting.
func (c *CoreCPUStat) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// Busy returns the sum of all non-idle CPU jiffies.
func (c *CoreCPUStat) Busy() uint64 {
	return c.User + c.Nice + c.System + c.IRQ + c.SoftIRQ + c.Steal
}

// CPUStatInfo holds aggregate CPU counters, per-core metrics, and process states.
type CPUStatInfo struct {
	TotalCPU         CoreCPUStat
	PerCore          []CoreCPUStat
	ProcsRunning     uint64
	ProcsBlocked     uint64
	ContextSwitches  uint64
	ProcessesCreated uint64
}

// MemInfo holds key memory and swap metrics in kilobytes (kB) from /proc/meminfo.
type MemInfo struct {
	MemTotal       uint64
	MemFree        uint64
	MemAvailable   uint64
	Buffers        uint64
	Cached         uint64
	SwapTotal      uint64
	SwapFree       uint64
	Dirty          uint64
	Writeback      uint64
	AnonPages      uint64
	Mapped         uint64
	Shmem          uint64
	Slab           uint64
	SReclaimable   uint64
	SUnreclaim     uint64
	HugePagesTotal uint64
	HugePagesFree  uint64
	HugePagesRsvd  uint64
	CmaTotal       uint64
	CmaFree        uint64
	Zswap          uint64
	Zswapped       uint64
}

// VMStatInfo holds page reclamation, memory compaction, THP, and NUMA event counters from /proc/vmstat.
type VMStatInfo struct {
	PgScanDirect           uint64
	AllocStallDirect       uint64
	CompactStall           uint64
	CompactFail            uint64
	PgMajFault             uint64
	Pswpin                 uint64
	Pswpout                uint64
	NumaMiss               uint64
	NumaForeign            uint64
	NumaInterleave         uint64
	THPCollapseAlloc       uint64
	THPCollapseAllocFailed uint64
	WorkingsetRefaultFile  uint64
	WorkingsetRefaultAnon  uint64
	THPSplit               uint64
	NumaPteUpdates         uint64
	NumaHintFaults         uint64
	Zswpin                 uint64
	Zswpout                uint64
	ZswapRejectReclaimFail uint64
	THPFaultFallback       uint64
	THPFaultAlloc          uint64
	THPScanExceed          uint64
	NRDirty                uint64
	THPZeroPageAlloc       uint64
	OOMKill                uint64
}

// DiskDeviceStat holds raw I/O statistics for a block device from /proc/diskstats.
type DiskDeviceStat struct {
	DeviceName      string
	ReadsCompleted  uint64
	ReadsMerged     uint64
	SectorsRead     uint64
	TimeReadingMS   uint64
	WritesCompleted uint64
	WritesMerged    uint64
	SectorsWritten  uint64
	TimeWritingMS   uint64
	IOsInProgress   uint64
	IOTicks         uint64 // Milliseconds spent doing I/O
	WeightedIOTicks uint64
	QueueNrRequests uint64
}

// DiskStatsInfo holds per-device disk statistics.
type DiskStatsInfo struct {
	Devices []DiskDeviceStat
}

// MountSpaceInfo holds filesystem capacity and inode data from statfs.
type MountSpaceInfo struct {
	Path              string
	Fsid              uint64
	TotalBytes        uint64
	FreeBytes         uint64
	AvailBytes        uint64
	UsedPercent       float64
	InodesTotal       uint64
	InodesFree        uint64
	InodesUsedPercent float64
	ReadOnly          bool
}

// DiskSpaceInfo holds space usage across critical mounts (/, /tmp, /var).
type DiskSpaceInfo struct {
	Mounts []MountSpaceInfo
}

// CoreFreq holds cpufreq frequency limits and current frequency for a core in kHz.
type CoreFreq struct {
	CoreID   int
	CurFreq  uint64
	MaxFreq  uint64
	Governor string
}

// CPUFreqInfo holds cpufreq scaling information across all cores.
type CPUFreqInfo struct {
	Available bool
	Cores     []CoreFreq
}

// ThermalZone holds temperature readings in degrees Celsius.
type ThermalZone struct {
	Type    string
	TempDeg float64
}

// ThermalInfo holds thermal zone sensor readings.
type ThermalInfo struct {
	Available bool
	Zones     []ThermalZone
	MaxTemp   float64
}

// ClocksourceInfo holds the currently active kernel clocksource.
type ClocksourceInfo struct {
	Current string // e.g. "tsc", "hpet", "acpi_pm"
}

// NetStatInfo holds TCP drop, overflow, and socket memory pressure metrics from /proc/net/netstat, /proc/net/snmp, and /proc/net/softnet_stat.
type NetStatInfo struct {
	ListenOverflows        uint64
	ListenDrops            uint64
	TCPMemoryPressures     uint64
	TCPRcvCollapsed        uint64
	TCPAbortOnMemory       uint64
	TCPReqQFullDoCookies   uint64
	TCPWinProbe            uint64
	TCPZeroWindowDrop      uint64
	RetransSegs            uint64
	OutSegs                uint64
	SoftnetDropped         uint64
	SoftnetTimeSqueeze     uint64
	UDPRcvbufErrors        uint64
	UDPSndbufErrors        uint64
	UDPInErrors            uint64
	TCPAbortOnData         uint64
	TCPTimeWaitOverflow    uint64
	PAWSEstab              uint64
	PAWSPassive            uint64
	TCPSlowStartRetrans    uint64
	SyncookiesSent         uint64
	SyncookiesRecv         uint64
	SyncookiesFailed       uint64
	TCPOFOQueue            uint64
	TCPOFODrop             uint64
	TCPOFOMerge            uint64
	IPReasmReqds           uint64
	IPReasmFails           uint64
	IPReasmTimeout         uint64
	IPReasmOKs             uint64
	TCPAbortOnClose        uint64
	TCPTimeouts            uint64
	TCPSpuriousRtxHost     uint64
	TCPFastOpenActiveFail  uint64
	TCPFastOpenPassiveFail uint64
	TCPSynRetrans          uint64
	TCPDeferAcceptDrop     uint64
}

// SysVShmInfo holds SysV IPC shared memory limits and segment allocation counts from /proc/sys/kernel/shm* and /proc/sysvipc/shm.
type SysVShmInfo struct {
	Available         bool
	AllocatedSegments uint64
	AllocatedPages    uint64
	ShmMNI            uint64
	ShmAll            uint64
}

// MDStatInfo holds Linux software RAID (mdadm) resync and rebuild operational status from /proc/mdstat.
type MDStatInfo struct {
	Available    bool
	ActiveResync bool
	ArrayName    string
	Operation    string
}

// SysVSemInfo holds SysV IPC semaphore limits and allocation counts from /proc/sys/kernel/sem and /proc/sysvipc/sem.
type SysVSemInfo struct {
	Available           bool
	SemMSL              uint64
	SemMNS              uint64
	SemOPM              uint64
	SemMNI              uint64
	AllocatedSemaphores uint64
	AllocatedSemSets    uint64
}

// SockStatInfo holds socket allocation counters from /proc/net/sockstat.
type SockStatInfo struct {
	TCPInUse    uint64
	TCPOrphan   uint64
	TCPTimeWait uint64
}

// PortRangeInfo holds ephemeral port range from /proc/sys/net/ipv4/ip_local_port_range.
type PortRangeInfo struct {
	Low  uint64
	High uint64
}

// ConntrackInfo holds netfilter connection tracking limits and counts.
type ConntrackInfo struct {
	Available bool
	Count     uint64
	Max       uint64
	Ratio     float64
}

// ZoneBuddyInfo holds page allocation state across memory zones from /proc/buddyinfo.
type ZoneBuddyInfo struct {
	Available            bool
	DMA32FreePages       uint64
	NormalFreePages      uint64
	NormalOrder0Pages    uint64
	NormalHighOrderPages uint64
}

// KSMInfo holds Kernel Samepage Merging memory deduplication counters.
type KSMInfo struct {
	Available    bool
	Running      bool
	PagesShared  uint64
	PagesSharing uint64
	PagesToScan  uint64
}

// IRQStatInfo holds hardware interrupt distribution metrics from /proc/interrupts.
type IRQStatInfo struct {
	Available         bool
	MaxCoreID         int
	MaxCoreIRQs       uint64
	OtherCoresAvgIRQs float64
}

// VirtInfo holds virtualization and hypervisor overcommit indicators.
type VirtInfo struct {
	BalloonBytes uint64 // bytes inflated by virtio_balloon
}

// ARPNeighborInfo holds ARP/Neighbor cache capacity and count metrics.
type ARPNeighborInfo struct {
	Available     bool
	ActiveEntries int
	GCThresh3     int
	Ratio         float64
}

// InotifyInfo holds inotify watch table metrics.
type InotifyInfo struct {
	Available       bool
	MaxUserWatches  uint64
	CurrentWatches  uint64
	MaxQueuedEvents uint64
	Ratio           float64
}

// SchedStatInfo holds scheduler runqueue latency and run time metrics.
type SchedStatInfo struct {
	Available          bool
	RunqueueWaitTimeMS uint64
	RunningTimeMS      uint64
	Ratio              float64
}

// SystemConfigInfo holds global kernel configuration limits, enterprise sysctls, and socket counts.
type SystemConfigInfo struct {
	PIDMax               uint64
	PortRange            PortRangeInfo
	SockStat             SockStatInfo
	Conntrack            ConntrackInfo
	BuddyInfo            ZoneBuddyInfo
	KSM                  KSMInfo
	IRQStat              IRQStatInfo
	Virt                 VirtInfo
	Neighbor             ARPNeighborInfo
	Inotify              InotifyInfo
	SchedStat            SchedStatInfo
	MinFreeKbytes        uint64
	CorePattern          string
	SysVSem              SysVSemInfo
	TCPMaxTWBuckets      uint64
	NumaBalancing        uint64
	SchedRTRuntimeUS     int64
	SchedMigrationCostNS uint64
	AIONR                uint64
	AIOMaxNR             uint64
	SysVShm              SysVShmInfo
	MDStat               MDStatInfo
	THPDefragMode        string
	ThreadsMax           uint64
	FileNR               FileNRInfo
}

// FileNRInfo holds system-wide open file table allocation counters from /proc/sys/fs/file-nr.
type FileNRInfo struct {
	Available bool
	Allocated uint64
	Unused    uint64
	Max       uint64
}

// LoadAvgInfo holds 1, 5, and 15-minute system load averages and scheduling entity counts from /proc/loadavg.
type LoadAvgInfo struct {
	Available       bool
	Load1           float64
	Load5           float64
	Load15          float64
	RunningEntities int
	TotalEntities   int
}

// TCPSocketsInfo holds breakdown of TCP socket states from /proc/net/tcp and /proc/net/tcp6.
type TCPSocketsInfo struct {
	Available   bool
	Established int
	SynSent     int
	SynRecv     int
	FinWait1    int
	FinWait2    int
	TimeWait    int
	Close       int
	CloseWait   int
	LastAck     int
	Listen      int
	Closing     int
}

// VMConfigInfo holds memory management sysctl tunables from /proc/sys/vm/.
type VMConfigInfo struct {
	Available        bool
	OvercommitMemory int // 0=heuristic, 1=always, 2=never
	Swappiness       int // 0-200
}

// NetIfaceStat holds link state and error counters for a network interface from /sys/class/net/<iface>.
type NetIfaceStat struct {
	Name            string
	CarrierChanges  uint64
	OperState       string
	RxErrors        uint64
	TxErrors        uint64
	TxCarrierErrors uint64
	RxCRCErrors     uint64
	RxMissedErrors  uint64
	RxFIFOErrors    uint64
}

// ProcessInfo holds snapshot metrics for a single PID.
type ProcessInfo struct {
	PID                      int
	Comm                     string
	State                    byte // 'R', 'S', 'D', 'Z', 'T', etc.
	PPID                     int
	UTime                    uint64
	STime                    uint64
	NumThreads               int
	RSSBytes                 uint64
	OOMScore                 int
	Wchan                    string
	ReadBytes                uint64
	WriteBytes               uint64
	IOAvailable              bool
	OpenFDs                  int
	MaxFDs                   uint64 // Soft limit
	CgroupPath               string
	CpusAllowed              int
	TracerPID                int
	Policy                   int
	SigQQueued               uint64
	SigQMax                  uint64
	VoluntaryCtxtSwitches    uint64
	NonvoluntaryCtxtSwitches uint64
	Partial                  bool
}

// CgroupEntry holds throttling, memory.events, and resource statistics for a cgroup.
type CgroupEntry struct {
	Path             string
	ThrottledUsec    uint64
	NrThrottled      uint64
	OOMKills         uint64
	MemoryHighEvents uint64
	NrBursts         uint64
	BurstUsec        uint64
	Frozen           bool
	CPUShares        uint64
	MemEventsMax     uint64
}

// CgroupInfo holds cgroup v2 controller metrics.
type CgroupInfo struct {
	Available bool
	Frozen    bool
	Groups    []CgroupEntry
}

// SystemSnapshot represents a complete point-in-time capture of Linux kernel states.
type SystemSnapshot struct {
	Timestamp    time.Time
	PSI          PSIInfo
	CPU          CPUStatInfo
	Memory       MemInfo
	VMStat       VMStatInfo
	DiskStats    DiskStatsInfo
	DiskSpace    DiskSpaceInfo
	CPUFreq      CPUFreqInfo
	Thermal      ThermalInfo
	Clocksource  ClocksourceInfo
	NetStat      NetStatInfo
	SystemConfig SystemConfigInfo
	Processes    []ProcessInfo
	Cgroups      CgroupInfo
	NetIfaces    []NetIfaceStat
	LoadAvg      LoadAvgInfo
	TCPSockets   TCPSocketsInfo
	VMConfig     VMConfigInfo
}

// CPUUtilization holds computed CPU percentage deltas over the sampling window.
type CPUUtilization struct {
	UserPercent    float64
	SystemPercent  float64
	IOWaitPercent  float64
	IdlePercent    float64
	SoftIRQPercent float64
	StealPercent   float64
	BusyPercent    float64
}

// ProcessDiff represents computed CPU, I/O, and resource deltas for a process.
type ProcessDiff struct {
	PID                           int
	Comm                          string
	State                         byte
	PPID                          int
	NumThreads                    int
	RSSBytes                      uint64
	OOMScore                      int
	Wchan                         string
	CPUTimeDelta                  uint64 // (utime + stime) delta in jiffies
	CPUPercent                    float64
	ReadBytesDelta                uint64
	WriteBytesDelta               uint64
	OpenFDs                       int
	MaxFDs                        uint64
	FDRatio                       float64
	CgroupPath                    string
	CpusAllowed                   int
	TracerPID                     int
	Policy                        int
	SigQQueued                    uint64
	SigQMax                       uint64
	SigQRatio                     float64
	VoluntaryCtxtSwitchesDelta    uint64
	NonvoluntaryCtxtSwitchesDelta uint64
}

// DiskDeviceDiff represents computed I/O utilization, throughput, and service latency deltas for a block device.
type DiskDeviceDiff struct {
	DeviceName           string
	UtilPercent          float64
	ReadBytesDelta       uint64
	WriteBytesDelta      uint64
	IOsInProgress        uint64
	ReadsCompletedDelta  uint64
	WritesCompletedDelta uint64
	AvgReadLatencyMS     float64
	AvgWriteLatencyMS    float64
	WeightedIOTicksDelta uint64
	AvgQueueLatencyMS    float64
	QueueNrRequests      uint64
}

// VMStatDiff represents delta counters for memory events over the sampling window.
type VMStatDiff struct {
	PgScanDirectDelta           uint64
	AllocStallDirectDelta       uint64
	CompactStallDelta           uint64
	CompactFailDelta            uint64
	PgMajFaultDelta             uint64
	PswpinDelta                 uint64
	PswpoutDelta                uint64
	NumaMissDelta               uint64
	NumaForeignDelta            uint64
	NumaInterleaveDelta         uint64
	THPCollapseAllocDelta       uint64
	THPCollapseAllocFailedDelta uint64
	WorkingsetRefaultFileDelta  uint64
	WorkingsetRefaultAnonDelta  uint64
	THPSplitDelta               uint64
	NumaPteUpdatesDelta         uint64
	NumaHintFaultsDelta         uint64
	ZswpinDelta                 uint64
	ZswpoutDelta                uint64
	ZswapRejectReclaimFailDelta uint64
	THPFaultFallbackDelta       uint64
	THPFaultAllocDelta          uint64
	THPScanExceedDelta          uint64
	NRDirtyDelta                uint64
	THPZeroPageAllocDelta       uint64
	OOMKillDelta                uint64
}

// NetStatDiff represents delta counters for networking drops and overflows.
type NetStatDiff struct {
	ListenOverflowsDelta        uint64
	ListenDropsDelta            uint64
	TCPMemoryPressuresDelta     uint64
	TCPRcvCollapsedDelta        uint64
	TCPAbortOnMemoryDelta       uint64
	TCPReqQFullDoCookiesDelta   uint64
	TCPWinProbeDelta            uint64
	TCPZeroWindowDropDelta      uint64
	RetransSegsDelta            uint64
	OutSegsDelta                uint64
	SoftnetDroppedDelta         uint64
	SoftnetTimeSqueezeDelta     uint64
	UDPRcvbufErrorsDelta        uint64
	UDPSndbufErrorsDelta        uint64
	UDPInErrorsDelta            uint64
	TCPAbortOnDataDelta         uint64
	TCPTimeWaitOverflowDelta    uint64
	PAWSEstabDelta              uint64
	PAWSPassiveDelta            uint64
	TCPSlowStartRetransDelta    uint64
	SyncookiesSentDelta         uint64
	SyncookiesRecvDelta         uint64
	SyncookiesFailedDelta       uint64
	TCPOFOQueueDelta            uint64
	TCPOFODropDelta             uint64
	TCPOFOMergeDelta            uint64
	IPReasmReqdsDelta           uint64
	IPReasmFailsDelta           uint64
	IPReasmTimeoutDelta         uint64
	IPReasmOKsDelta             uint64
	TCPAbortOnCloseDelta        uint64
	TCPTimeoutsDelta            uint64
	TCPSpuriousRtxHostDelta     uint64
	TCPFastOpenActiveFailDelta  uint64
	TCPFastOpenPassiveFailDelta uint64
	TCPSynRetransDelta          uint64
	TCPDeferAcceptDropDelta     uint64
}

// NetIfaceDiff represents rate and counter differentials for a network interface.
type NetIfaceDiff struct {
	Name                 string
	CarrierChangesDelta  uint64
	OperState            string
	RxErrorsDelta        uint64
	TxErrorsDelta        uint64
	TxCarrierErrorsDelta uint64
	RxCRCErrorsDelta     uint64
	RxMissedErrorsDelta  uint64
	RxFIFOErrorsDelta    uint64
}

// CgroupDiff represents delta counters for cgroup throttling, memory.events, and OOM events.
type CgroupDiff struct {
	Path                  string
	ThrottledUsecDelta    uint64
	NrThrottledDelta      uint64
	OOMKillsDelta         uint64
	MemoryHighEventsDelta uint64
	NrBurstsDelta         uint64
	BurstUsecDelta        uint64
	MemEventsMaxDelta     uint64
}

// SnapshotDiff represents computed deltas and aggregated states between Snapshot A and Snapshot B.
type SnapshotDiff struct {
	Duration              time.Duration
	Timestamp             time.Time
	ClockJumpDetected     bool // True when system clock jumped backward between snapshots
	TotalCPUUtil          CPUUtilization
	PerCoreCPUUtil        []CPUUtilization
	ProcsRunning          uint64
	ProcsBlocked          uint64
	ContextSwitchesDelta  uint64
	ProcessesCreatedDelta uint64
	Processes             []ProcessDiff
	Disks                 []DiskDeviceDiff
	VMStat                VMStatDiff
	NetStat               NetStatDiff
	Cgroups               []CgroupDiff
	NetIfaces             []NetIfaceDiff
	LatestSnapshot        *SystemSnapshot
}

// CollectSnapshot captures a complete point-in-time snapshot of the Linux system.
func CollectSnapshot(ctx context.Context) (*SystemSnapshot, error) {
	snap := &SystemSnapshot{
		Timestamp: time.Now(),
	}

	var err error
	snap.PSI, _ = CollectPSI()
	snap.CPU, err = CollectCPUStat()
	if err != nil {
		return nil, fmt.Errorf("collector: snapshot cpu: %w", err)
	}

	snap.Memory, err = CollectMemInfo()
	if err != nil {
		return nil, fmt.Errorf("collector: snapshot memory: %w", err)
	}

	snap.VMStat, _ = CollectVMStat()
	snap.DiskStats, _ = CollectDiskStats()
	snap.DiskSpace, _ = CollectDiskSpace()
	snap.CPUFreq, _ = CollectCPUFreq()
	snap.Thermal, _ = CollectThermal()
	snap.Clocksource, _ = CollectClocksource()
	snap.NetStat, _ = CollectNetStat()
	snap.NetIfaces, _ = CollectNetIfaces()
	snap.SystemConfig, _ = CollectSystemConfig()
	snap.LoadAvg, _ = CollectLoadAvg()
	snap.TCPSockets, _ = CollectTCPSockets()
	snap.VMConfig, _ = CollectVMConfig()

	// Parallel process collection via worker pool
	snap.Processes, _ = CollectProcesses(ctx)

	// Cgroups parsed using the discovered process cgroup memberships
	snap.Cgroups, _ = CollectCgroups(snap.Processes)

	return snap, nil
}

// DiffSnapshots calculates rate and counter differentials between two snapshots.
func DiffSnapshots(a, b *SystemSnapshot) *SnapshotDiff {
	duration := b.Timestamp.Sub(a.Timestamp)
	clockJump := false
	if duration <= 0 {
		duration = time.Second
		clockJump = true
	}

	diff := &SnapshotDiff{
		Duration:              duration,
		Timestamp:             b.Timestamp,
		ClockJumpDetected:     clockJump,
		ProcsRunning:          b.CPU.ProcsRunning,
		ProcsBlocked:          b.CPU.ProcsBlocked,
		ContextSwitchesDelta:  diffUint64(b.CPU.ContextSwitches, a.CPU.ContextSwitches),
		ProcessesCreatedDelta: diffUint64(b.CPU.ProcessesCreated, a.CPU.ProcessesCreated),
		TotalCPUUtil:          calculateCoreUtil(&a.CPU.TotalCPU, &b.CPU.TotalCPU),
		PerCoreCPUUtil:        calculatePerCoreUtil(a.CPU.PerCore, b.CPU.PerCore),
		Disks:                 calculateDiskDiff(a.DiskStats.Devices, b.DiskStats.Devices, duration),
		VMStat:                calculateVMStatDiff(&a.VMStat, &b.VMStat),
		NetStat:               calculateNetStatDiff(&a.NetStat, &b.NetStat),
		Cgroups:               calculateCgroupDiff(a.Cgroups.Groups, b.Cgroups.Groups),
		NetIfaces:             calculateNetIfacesDiff(a.NetIfaces, b.NetIfaces),
		Processes:             calculateProcessDiff(a.Processes, b.Processes, duration),
		LatestSnapshot:        b,
	}

	return diff
}

func calculateCoreUtil(a, b *CoreCPUStat) CPUUtilization {
	totalA := a.Total()
	totalB := b.Total()

	if totalB <= totalA {
		return CPUUtilization{}
	}

	deltaTotal := float64(totalB - totalA)
	deltaUser := float64(diffUint64(b.User+b.Nice, a.User+a.Nice))
	deltaSys := float64(diffUint64(b.System+b.IRQ, a.System+a.IRQ))
	deltaIOWait := float64(diffUint64(b.IOWait, a.IOWait))
	deltaIdle := float64(diffUint64(b.Idle, a.Idle))
	deltaSoftIRQ := float64(diffUint64(b.SoftIRQ, a.SoftIRQ))
	deltaSteal := float64(diffUint64(b.Steal, a.Steal))
	deltaBusy := float64(diffUint64(b.Busy(), a.Busy()))

	return CPUUtilization{
		UserPercent:    clampPercent((deltaUser / deltaTotal) * 100.0),
		SystemPercent:  clampPercent((deltaSys / deltaTotal) * 100.0),
		IOWaitPercent:  clampPercent((deltaIOWait / deltaTotal) * 100.0),
		IdlePercent:    clampPercent((deltaIdle / deltaTotal) * 100.0),
		SoftIRQPercent: clampPercent((deltaSoftIRQ / deltaTotal) * 100.0),
		StealPercent:   clampPercent((deltaSteal / deltaTotal) * 100.0),
		BusyPercent:    clampPercent((deltaBusy / deltaTotal) * 100.0),
	}
}

func calculatePerCoreUtil(aCores, bCores []CoreCPUStat) []CPUUtilization {
	minLen := len(aCores)
	if len(bCores) < minLen {
		minLen = len(bCores)
	}

	result := make([]CPUUtilization, minLen)
	for i := 0; i < minLen; i++ {
		result[i] = calculateCoreUtil(&aCores[i], &bCores[i])
	}
	return result
}

func calculateDiskDiff(aDevs, bDevs []DiskDeviceStat, duration time.Duration) []DiskDeviceDiff {
	aMap := make(map[string]*DiskDeviceStat, len(aDevs))
	for i := range aDevs {
		aMap[aDevs[i].DeviceName] = &aDevs[i]
	}

	result := make([]DiskDeviceDiff, 0, len(bDevs))
	durMS := float64(duration.Milliseconds())
	if durMS <= 0 {
		durMS = 1000.0
	}

	for i := range bDevs {
		b := &bDevs[i]
		a, found := aMap[b.DeviceName]
		if !found {
			continue
		}

		deltaTicks := float64(diffUint64(b.IOTicks, a.IOTicks))
		utilPercent := clampPercent((deltaTicks / durMS) * 100.0)

		// 1 sector = 512 bytes on Linux block layer
		readBytes := diffUint64(b.SectorsRead, a.SectorsRead) * 512
		writeBytes := diffUint64(b.SectorsWritten, a.SectorsWritten) * 512
		deltaReads := diffUint64(b.ReadsCompleted, a.ReadsCompleted)
		deltaWrites := diffUint64(b.WritesCompleted, a.WritesCompleted)
		deltaReadTime := diffUint64(b.TimeReadingMS, a.TimeReadingMS)
		deltaWriteTime := diffUint64(b.TimeWritingMS, a.TimeWritingMS)

		var avgReadLatencyMS, avgWriteLatencyMS float64
		if deltaReads > 0 {
			avgReadLatencyMS = float64(deltaReadTime) / float64(deltaReads)
		}
		if deltaWrites > 0 {
			avgWriteLatencyMS = float64(deltaWriteTime) / float64(deltaWrites)
		}

		deltaWeightedTicks := diffUint64(b.WeightedIOTicks, a.WeightedIOTicks)
		var avgQueueLatencyMS float64
		if (deltaReads + deltaWrites) > 0 {
			avgQueueLatencyMS = float64(deltaWeightedTicks) / float64(deltaReads+deltaWrites)
		}

		result = append(result, DiskDeviceDiff{
			DeviceName:           b.DeviceName,
			UtilPercent:          utilPercent,
			ReadBytesDelta:       readBytes,
			WriteBytesDelta:      writeBytes,
			IOsInProgress:        b.IOsInProgress,
			ReadsCompletedDelta:  deltaReads,
			WritesCompletedDelta: deltaWrites,
			AvgReadLatencyMS:     avgReadLatencyMS,
			AvgWriteLatencyMS:    avgWriteLatencyMS,
			WeightedIOTicksDelta: deltaWeightedTicks,
			AvgQueueLatencyMS:    avgQueueLatencyMS,
			QueueNrRequests:      b.QueueNrRequests,
		})
	}
	return result
}

func calculateVMStatDiff(a, b *VMStatInfo) VMStatDiff {
	return VMStatDiff{
		PgScanDirectDelta:           diffUint64(b.PgScanDirect, a.PgScanDirect),
		AllocStallDirectDelta:       diffUint64(b.AllocStallDirect, a.AllocStallDirect),
		CompactStallDelta:           diffUint64(b.CompactStall, a.CompactStall),
		CompactFailDelta:            diffUint64(b.CompactFail, a.CompactFail),
		PgMajFaultDelta:             diffUint64(b.PgMajFault, a.PgMajFault),
		PswpinDelta:                 diffUint64(b.Pswpin, a.Pswpin),
		PswpoutDelta:                diffUint64(b.Pswpout, a.Pswpout),
		NumaMissDelta:               diffUint64(b.NumaMiss, a.NumaMiss),
		NumaForeignDelta:            diffUint64(b.NumaForeign, a.NumaForeign),
		NumaInterleaveDelta:         diffUint64(b.NumaInterleave, a.NumaInterleave),
		THPCollapseAllocDelta:       diffUint64(b.THPCollapseAlloc, a.THPCollapseAlloc),
		THPCollapseAllocFailedDelta: diffUint64(b.THPCollapseAllocFailed, a.THPCollapseAllocFailed),
		WorkingsetRefaultFileDelta:  diffUint64(b.WorkingsetRefaultFile, a.WorkingsetRefaultFile),
		WorkingsetRefaultAnonDelta:  diffUint64(b.WorkingsetRefaultAnon, a.WorkingsetRefaultAnon),
		THPSplitDelta:               diffUint64(b.THPSplit, a.THPSplit),
		NumaPteUpdatesDelta:         diffUint64(b.NumaPteUpdates, a.NumaPteUpdates),
		NumaHintFaultsDelta:         diffUint64(b.NumaHintFaults, a.NumaHintFaults),
		ZswpinDelta:                 diffUint64(b.Zswpin, a.Zswpin),
		ZswpoutDelta:                diffUint64(b.Zswpout, a.Zswpout),
		ZswapRejectReclaimFailDelta: diffUint64(b.ZswapRejectReclaimFail, a.ZswapRejectReclaimFail),
		THPFaultFallbackDelta:       diffUint64(b.THPFaultFallback, a.THPFaultFallback),
		THPFaultAllocDelta:          diffUint64(b.THPFaultAlloc, a.THPFaultAlloc),
		THPScanExceedDelta:          diffUint64(b.THPScanExceed, a.THPScanExceed),
		NRDirtyDelta:                diffUint64(b.NRDirty, a.NRDirty),
		THPZeroPageAllocDelta:       diffUint64(b.THPZeroPageAlloc, a.THPZeroPageAlloc),
		OOMKillDelta:                diffUint64(b.OOMKill, a.OOMKill),
	}
}

func calculateNetStatDiff(a, b *NetStatInfo) NetStatDiff {
	return NetStatDiff{
		ListenOverflowsDelta:        diffUint64(b.ListenOverflows, a.ListenOverflows),
		ListenDropsDelta:            diffUint64(b.ListenDrops, a.ListenDrops),
		TCPMemoryPressuresDelta:     diffUint64(b.TCPMemoryPressures, a.TCPMemoryPressures),
		TCPRcvCollapsedDelta:        diffUint64(b.TCPRcvCollapsed, a.TCPRcvCollapsed),
		TCPAbortOnMemoryDelta:       diffUint64(b.TCPAbortOnMemory, a.TCPAbortOnMemory),
		TCPReqQFullDoCookiesDelta:   diffUint64(b.TCPReqQFullDoCookies, a.TCPReqQFullDoCookies),
		TCPWinProbeDelta:            diffUint64(b.TCPWinProbe, a.TCPWinProbe),
		TCPZeroWindowDropDelta:      diffUint64(b.TCPZeroWindowDrop, a.TCPZeroWindowDrop),
		RetransSegsDelta:            diffUint64(b.RetransSegs, a.RetransSegs),
		OutSegsDelta:                diffUint64(b.OutSegs, a.OutSegs),
		SoftnetDroppedDelta:         diffUint64(b.SoftnetDropped, a.SoftnetDropped),
		SoftnetTimeSqueezeDelta:     diffUint64(b.SoftnetTimeSqueeze, a.SoftnetTimeSqueeze),
		UDPRcvbufErrorsDelta:        diffUint64(b.UDPRcvbufErrors, a.UDPRcvbufErrors),
		UDPSndbufErrorsDelta:        diffUint64(b.UDPSndbufErrors, a.UDPSndbufErrors),
		UDPInErrorsDelta:            diffUint64(b.UDPInErrors, a.UDPInErrors),
		TCPAbortOnDataDelta:         diffUint64(b.TCPAbortOnData, a.TCPAbortOnData),
		TCPTimeWaitOverflowDelta:    diffUint64(b.TCPTimeWaitOverflow, a.TCPTimeWaitOverflow),
		PAWSEstabDelta:              diffUint64(b.PAWSEstab, a.PAWSEstab),
		PAWSPassiveDelta:            diffUint64(b.PAWSPassive, a.PAWSPassive),
		TCPSlowStartRetransDelta:    diffUint64(b.TCPSlowStartRetrans, a.TCPSlowStartRetrans),
		SyncookiesSentDelta:         diffUint64(b.SyncookiesSent, a.SyncookiesSent),
		SyncookiesRecvDelta:         diffUint64(b.SyncookiesRecv, a.SyncookiesRecv),
		SyncookiesFailedDelta:       diffUint64(b.SyncookiesFailed, a.SyncookiesFailed),
		TCPOFOQueueDelta:            diffUint64(b.TCPOFOQueue, a.TCPOFOQueue),
		TCPOFODropDelta:             diffUint64(b.TCPOFODrop, a.TCPOFODrop),
		TCPOFOMergeDelta:            diffUint64(b.TCPOFOMerge, a.TCPOFOMerge),
		IPReasmReqdsDelta:           diffUint64(b.IPReasmReqds, a.IPReasmReqds),
		IPReasmFailsDelta:           diffUint64(b.IPReasmFails, a.IPReasmFails),
		IPReasmTimeoutDelta:         diffUint64(b.IPReasmTimeout, a.IPReasmTimeout),
		IPReasmOKsDelta:             diffUint64(b.IPReasmOKs, a.IPReasmOKs),
		TCPAbortOnCloseDelta:        diffUint64(b.TCPAbortOnClose, a.TCPAbortOnClose),
		TCPTimeoutsDelta:            diffUint64(b.TCPTimeouts, a.TCPTimeouts),
		TCPSpuriousRtxHostDelta:     diffUint64(b.TCPSpuriousRtxHost, a.TCPSpuriousRtxHost),
		TCPFastOpenActiveFailDelta:  diffUint64(b.TCPFastOpenActiveFail, a.TCPFastOpenActiveFail),
		TCPFastOpenPassiveFailDelta: diffUint64(b.TCPFastOpenPassiveFail, a.TCPFastOpenPassiveFail),
		TCPSynRetransDelta:          diffUint64(b.TCPSynRetrans, a.TCPSynRetrans),
		TCPDeferAcceptDropDelta:     diffUint64(b.TCPDeferAcceptDrop, a.TCPDeferAcceptDrop),
	}
}

func calculateNetIfacesDiff(aIfaces, bIfaces []NetIfaceStat) []NetIfaceDiff {
	aMap := make(map[string]*NetIfaceStat, len(aIfaces))
	for i := range aIfaces {
		aMap[aIfaces[i].Name] = &aIfaces[i]
	}

	result := make([]NetIfaceDiff, 0, len(bIfaces))
	for i := range bIfaces {
		b := &bIfaces[i]
		a, found := aMap[b.Name]
		var carrierDelta, rxErrDelta, txErrDelta, txCarrierErrDelta, rxCRCDelta, rxMissedDelta, rxFIFODelta uint64
		if found {
			carrierDelta = diffUint64(b.CarrierChanges, a.CarrierChanges)
			rxErrDelta = diffUint64(b.RxErrors, a.RxErrors)
			txErrDelta = diffUint64(b.TxErrors, a.TxErrors)
			txCarrierErrDelta = diffUint64(b.TxCarrierErrors, a.TxCarrierErrors)
			rxCRCDelta = diffUint64(b.RxCRCErrors, a.RxCRCErrors)
			rxMissedDelta = diffUint64(b.RxMissedErrors, a.RxMissedErrors)
			rxFIFODelta = diffUint64(b.RxFIFOErrors, a.RxFIFOErrors)
		}
		result = append(result, NetIfaceDiff{
			Name:                 b.Name,
			CarrierChangesDelta:  carrierDelta,
			OperState:            b.OperState,
			RxErrorsDelta:        rxErrDelta,
			TxErrorsDelta:        txErrDelta,
			TxCarrierErrorsDelta: txCarrierErrDelta,
			RxCRCErrorsDelta:     rxCRCDelta,
			RxMissedErrorsDelta:  rxMissedDelta,
			RxFIFOErrorsDelta:    rxFIFODelta,
		})
	}
	return result
}

func calculateCgroupDiff(aGroups, bGroups []CgroupEntry) []CgroupDiff {
	aMap := make(map[string]*CgroupEntry, len(aGroups))
	for i := range aGroups {
		aMap[aGroups[i].Path] = &aGroups[i]
	}

	result := make([]CgroupDiff, 0, len(bGroups))
	for i := range bGroups {
		b := &bGroups[i]
		a, found := aMap[b.Path]
		if !found {
			continue
		}

		result = append(result, CgroupDiff{
			Path:                  b.Path,
			ThrottledUsecDelta:    diffUint64(b.ThrottledUsec, a.ThrottledUsec),
			NrThrottledDelta:      diffUint64(b.NrThrottled, a.NrThrottled),
			OOMKillsDelta:         diffUint64(b.OOMKills, a.OOMKills),
			MemoryHighEventsDelta: diffUint64(b.MemoryHighEvents, a.MemoryHighEvents),
			NrBurstsDelta:         diffUint64(b.NrBursts, a.NrBursts),
			BurstUsecDelta:        diffUint64(b.BurstUsec, a.BurstUsec),
			MemEventsMaxDelta:     diffUint64(b.MemEventsMax, a.MemEventsMax),
		})
	}
	return result
}

func calculateProcessDiff(aProcs, bProcs []ProcessInfo, duration time.Duration) []ProcessDiff {
	aMap := make(map[int]*ProcessInfo, len(aProcs))
	for i := range aProcs {
		aMap[aProcs[i].PID] = &aProcs[i]
	}

	result := make([]ProcessDiff, 0, len(bProcs))
	durSec := duration.Seconds()
	if durSec <= 0 {
		durSec = 1.0
	}

	for i := range bProcs {
		b := &bProcs[i]
		var cpuDelta uint64
		var readBytesDelta, writeBytesDelta uint64
		var volCtxDelta, nonVolCtxDelta uint64

		if a, found := aMap[b.PID]; found {
			aTime := a.UTime + a.STime
			bTime := b.UTime + b.STime
			cpuDelta = diffUint64(bTime, aTime)
			readBytesDelta = diffUint64(b.ReadBytes, a.ReadBytes)
			writeBytesDelta = diffUint64(b.WriteBytes, a.WriteBytes)
			volCtxDelta = diffUint64(b.VoluntaryCtxtSwitches, a.VoluntaryCtxtSwitches)
			nonVolCtxDelta = diffUint64(b.NonvoluntaryCtxtSwitches, a.NonvoluntaryCtxtSwitches)
		}

		var fdRatio float64
		if b.MaxFDs > 0 {
			fdRatio = float64(b.OpenFDs) / float64(b.MaxFDs)
		}

		var sigQRatio float64
		if b.SigQMax > 0 {
			sigQRatio = float64(b.SigQQueued) / float64(b.SigQMax)
		}

		// CPU percentage is approximately jiffies (100 Hz = 100 jiffies/sec/core)
		// normalized across duration. 1 jiffy per second = 1% of a single core.
		cpuPercent := (float64(cpuDelta) / durSec)

		result = append(result, ProcessDiff{
			PID:                           b.PID,
			Comm:                          b.Comm,
			State:                         b.State,
			PPID:                          b.PPID,
			NumThreads:                    b.NumThreads,
			RSSBytes:                      b.RSSBytes,
			OOMScore:                      b.OOMScore,
			Wchan:                         b.Wchan,
			CPUTimeDelta:                  cpuDelta,
			CPUPercent:                    cpuPercent,
			ReadBytesDelta:                readBytesDelta,
			WriteBytesDelta:               writeBytesDelta,
			OpenFDs:                       b.OpenFDs,
			MaxFDs:                        b.MaxFDs,
			FDRatio:                       fdRatio,
			CgroupPath:                    b.CgroupPath,
			CpusAllowed:                   b.CpusAllowed,
			TracerPID:                     b.TracerPID,
			Policy:                        b.Policy,
			SigQQueued:                    b.SigQQueued,
			SigQMax:                       b.SigQMax,
			SigQRatio:                     sigQRatio,
			VoluntaryCtxtSwitchesDelta:    volCtxDelta,
			NonvoluntaryCtxtSwitchesDelta: nonVolCtxDelta,
		})
	}
	return result
}

func diffUint64(newVal, oldVal uint64) uint64 {
	if newVal > oldVal {
		return newVal - oldVal
	}
	return 0
}

func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
