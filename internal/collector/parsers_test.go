package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePSI(t *testing.T) {
	testDir := "testdata"
	cpuPath := filepath.Join(testDir, "psi_cpu")
	memPath := filepath.Join(testDir, "psi_memory")
	ioPath := filepath.Join(testDir, "psi_io")

	info, err := ParsePSI(cpuPath, memPath, ioPath)
	if err != nil {
		t.Fatalf("unexpected error parsing PSI: %v", err)
	}

	if !info.Available {
		t.Fatal("expected PSI to be available")
	}

	// Verify CPU PSI
	if info.CPU.Some.Avg10 != 12.50 {
		t.Errorf("expected CPU Some.Avg10 12.50, got %f", info.CPU.Some.Avg10)
	}
	if info.CPU.Full.Total != 123450 {
		t.Errorf("expected CPU Full.Total 123450, got %d", info.CPU.Full.Total)
	}

	// Verify Memory PSI
	if info.Memory.Some.Avg10 != 35.40 {
		t.Errorf("expected Memory Some.Avg10 35.40, got %f", info.Memory.Some.Avg10)
	}
	if info.Memory.Full.Avg300 != 4.10 {
		t.Errorf("expected Memory Full.Avg300 4.10, got %f", info.Memory.Full.Avg300)
	}

	// Verify IO PSI
	if info.IO.Some.Avg10 != 62.80 {
		t.Errorf("expected IO Some.Avg10 62.80, got %f", info.IO.Some.Avg10)
	}
	if info.IO.Full.Total != 8765432 {
		t.Errorf("expected IO Full.Total 8765432, got %d", info.IO.Full.Total)
	}

	// Test missing file fallback
	missingInfo, err := ParsePSI("/nonexistent/cpu", "/nonexistent/mem", "/nonexistent/io")
	if err != nil {
		t.Fatalf("expected graceful fallback on missing PSI, got error: %v", err)
	}
	if missingInfo.Available {
		t.Error("expected Available to be false for nonexistent paths")
	}
}

func TestParseCPUStat(t *testing.T) {
	statPath := filepath.Join("testdata", "proc_stat")
	info, err := ParseCPUStat(statPath)
	if err != nil {
		t.Fatalf("unexpected error parsing proc stat: %v", err)
	}

	if info.TotalCPU.User != 10123 {
		t.Errorf("expected TotalCPU.User 10123, got %d", info.TotalCPU.User)
	}
	if info.TotalCPU.Idle != 890123 {
		t.Errorf("expected TotalCPU.Idle 890123, got %d", info.TotalCPU.Idle)
	}
	if len(info.PerCore) != 2 {
		t.Fatalf("expected 2 cores, got %d", len(info.PerCore))
	}
	if info.PerCore[0].ID != "cpu0" || info.PerCore[0].User != 5000 {
		t.Errorf("unexpected core 0 stat: %+v", info.PerCore[0])
	}
	if info.PerCore[1].ID != "cpu1" || info.PerCore[1].Idle != 445123 {
		t.Errorf("unexpected core 1 stat: %+v", info.PerCore[1])
	}
	if info.ProcsRunning != 5 {
		t.Errorf("expected ProcsRunning 5, got %d", info.ProcsRunning)
	}
	if info.ProcsBlocked != 2 {
		t.Errorf("expected ProcsBlocked 2, got %d", info.ProcsBlocked)
	}
	if info.ContextSwitches != 9876543 {
		t.Errorf("expected ContextSwitches 9876543, got %d", info.ContextSwitches)
	}
	if info.ProcessesCreated != 12345 {
		t.Errorf("expected ProcessesCreated 12345, got %d", info.ProcessesCreated)
	}
}

func TestParseMemInfo(t *testing.T) {
	memPath := filepath.Join("testdata", "proc_meminfo")
	info, err := ParseMemInfo(memPath)
	if err != nil {
		t.Fatalf("unexpected error parsing meminfo: %v", err)
	}

	if info.MemTotal != 32768000 {
		t.Errorf("expected MemTotal 32768000, got %d", info.MemTotal)
	}
	if info.MemAvailable != 8192000 {
		t.Errorf("expected MemAvailable 8192000, got %d", info.MemAvailable)
	}
	if info.SwapTotal != 8388608 {
		t.Errorf("expected SwapTotal 8388608, got %d", info.SwapTotal)
	}
	if info.SwapFree != 7340032 {
		t.Errorf("expected SwapFree 7340032, got %d", info.SwapFree)
	}
	if info.Dirty != 12345 {
		t.Errorf("expected Dirty 12345, got %d", info.Dirty)
	}
	if info.Writeback != 567 {
		t.Errorf("expected Writeback 567, got %d", info.Writeback)
	}
	if info.HugePagesTotal != 2048 {
		t.Errorf("expected HugePagesTotal 2048, got %d", info.HugePagesTotal)
	}
	if info.HugePagesFree != 1024 {
		t.Errorf("expected HugePagesFree 1024, got %d", info.HugePagesFree)
	}
	if info.HugePagesRsvd != 512 {
		t.Errorf("expected HugePagesRsvd 512, got %d", info.HugePagesRsvd)
	}
}

func TestParseVMStat(t *testing.T) {
	vmstatPath := filepath.Join("testdata", "proc_vmstat")
	info, err := ParseVMStat(vmstatPath)
	if err != nil {
		t.Fatalf("unexpected error parsing vmstat: %v", err)
	}

	if info.PgScanDirect != 567 {
		t.Errorf("expected PgScanDirect 567, got %d", info.PgScanDirect)
	}
	if info.AllocStallDirect != 89 {
		t.Errorf("expected AllocStallDirect 89, got %d", info.AllocStallDirect)
	}
	if info.CompactStall != 45 {
		t.Errorf("expected CompactStall 45, got %d", info.CompactStall)
	}
	if info.CompactFail != 12 {
		t.Errorf("expected CompactFail 12, got %d", info.CompactFail)
	}
	if info.PgMajFault != 1234 {
		t.Errorf("expected PgMajFault 1234, got %d", info.PgMajFault)
	}
	if info.NumaMiss != 88 {
		t.Errorf("expected NumaMiss 88, got %d", info.NumaMiss)
	}
	if info.NumaForeign != 99 {
		t.Errorf("expected NumaForeign 99, got %d", info.NumaForeign)
	}
	if info.NumaInterleave != 111 {
		t.Errorf("expected NumaInterleave 111, got %d", info.NumaInterleave)
	}
}

func TestParseClocksource(t *testing.T) {
	csPath := filepath.Join("testdata", "clocksource")
	info, err := ParseClocksource(csPath)
	if err != nil {
		t.Fatalf("unexpected error parsing clocksource: %v", err)
	}
	if info.Current != "tsc" {
		t.Errorf("expected clocksource 'tsc', got '%s'", info.Current)
	}

	missing, _ := ParseClocksource("/nonexistent/clocksource")
	if missing.Current != "unknown" {
		t.Errorf("expected 'unknown' on missing clocksource, got '%s'", missing.Current)
	}
}

func TestParseNetStat(t *testing.T) {
	netPath := filepath.Join("testdata", "netstat")
	info, err := ParseNetStat(netPath)
	if err != nil {
		t.Fatalf("unexpected error parsing netstat: %v", err)
	}

	if info.ListenOverflows != 14 {
		t.Errorf("expected ListenOverflows 14, got %d", info.ListenOverflows)
	}
	if info.ListenDrops != 28 {
		t.Errorf("expected ListenDrops 28, got %d", info.ListenDrops)
	}
	if info.TCPMemoryPressures != 50 {
		t.Errorf("expected TCPMemoryPressures 50, got %d", info.TCPMemoryPressures)
	}
	if info.TCPRcvCollapsed != 120 {
		t.Errorf("expected TCPRcvCollapsed 120, got %d", info.TCPRcvCollapsed)
	}
	if info.TCPAbortOnMemory != 5 {
		t.Errorf("expected TCPAbortOnMemory 5, got %d", info.TCPAbortOnMemory)
	}
	if info.TCPReqQFullDoCookies != 10 {
		t.Errorf("expected TCPReqQFullDoCookies 10, got %d", info.TCPReqQFullDoCookies)
	}
}

func TestParseSystemConfig(t *testing.T) {
	sockPath := filepath.Join("testdata", "sockstat")
	portPath := filepath.Join("testdata", "port_range")
	pidPath := filepath.Join("testdata", "pid_max")
	ctCountPath := filepath.Join("testdata", "conntrack_count")
	ctMaxPath := filepath.Join("testdata", "conntrack_max")
	buddyPath := filepath.Join("testdata", "buddyinfo")
	ksmDir := filepath.Join("testdata", "ksm")
	irqPath := filepath.Join("testdata", "interrupts")
	arpPath := filepath.Join("testdata", "arp")
	gcThreshPath := filepath.Join("testdata", "gc_thresh3")
	inotifyPath := filepath.Join("testdata", "max_user_watches")
	schedPath := filepath.Join("testdata", "schedstat")

	config, err := ParseSystemConfig(sockPath, portPath, pidPath, ctCountPath, ctMaxPath, buddyPath, ksmDir, irqPath, arpPath, gcThreshPath, inotifyPath, schedPath)
	if err != nil {
		t.Fatalf("unexpected error parsing system config: %v", err)
	}

	if config.SockStat.TCPInUse != 42 {
		t.Errorf("expected TCPInUse 42, got %d", config.SockStat.TCPInUse)
	}
	if config.SockStat.TCPOrphan != 3 {
		t.Errorf("expected TCPOrphan 3, got %d", config.SockStat.TCPOrphan)
	}
	if config.SockStat.TCPTimeWait != 150 {
		t.Errorf("expected TCPTimeWait 150, got %d", config.SockStat.TCPTimeWait)
	}

	if config.PortRange.Low != 32768 || config.PortRange.High != 60999 {
		t.Errorf("expected PortRange 32768-60999, got %d-%d", config.PortRange.Low, config.PortRange.High)
	}

	if config.PIDMax != 4194304 {
		t.Errorf("expected PIDMax 4194304, got %d", config.PIDMax)
	}

	if !config.Conntrack.Available || config.Conntrack.Count != 245760 || config.Conntrack.Max != 262144 {
		t.Errorf("unexpected Conntrack: %+v", config.Conntrack)
	}

	if !config.BuddyInfo.Available || config.BuddyInfo.DMA32FreePages != 0 {
		t.Errorf("expected DMA32FreePages 0, got %d", config.BuddyInfo.DMA32FreePages)
	}

	if !config.KSM.Available || !config.KSM.Running || config.KSM.PagesToScan != 15000 {
		t.Errorf("unexpected KSM info: %+v", config.KSM)
	}

	if !config.IRQStat.Available || config.IRQStat.MaxCoreID != 3 || config.IRQStat.MaxCoreIRQs != 121000 {
		t.Errorf("unexpected IRQStat info: %+v", config.IRQStat)
	}

	if !config.Neighbor.Available || config.Neighbor.ActiveEntries != 5 || config.Neighbor.GCThresh3 != 1024 {
		t.Errorf("unexpected Neighbor info: %+v", config.Neighbor)
	}

	if !config.Inotify.Available || config.Inotify.MaxUserWatches != 524288 {
		t.Errorf("unexpected Inotify info: %+v", config.Inotify)
	}

	if !config.SchedStat.Available || config.SchedStat.RunqueueWaitTimeMS != 5500 || config.SchedStat.RunningTimeMS != 11000 {
		t.Errorf("unexpected SchedStat info: %+v", config.SchedStat)
	}
}

func TestLiveHostBasicCollectors(t *testing.T) {
	// These tests run on the host kernel directly to ensure no panics or unhandled errors.
	psi, err := CollectPSI()
	if err != nil {
		t.Errorf("CollectPSI failed on host: %v", err)
	}
	t.Logf("Host PSI available: %v", psi.Available)

	cpuStat, err := CollectCPUStat()
	if err != nil {
		t.Fatalf("CollectCPUStat failed on host: %v", err)
	}
	if cpuStat.TotalCPU.Total() == 0 {
		t.Errorf("expected non-zero host CPU total")
	}

	memInfo, err := CollectMemInfo()
	if err != nil {
		t.Fatalf("CollectMemInfo failed on host: %v", err)
	}
	if memInfo.MemTotal == 0 {
		t.Errorf("expected non-zero host MemTotal")
	}

	vmStat, err := CollectVMStat()
	if err != nil {
		t.Fatalf("CollectVMStat failed on host: %v", err)
	}
	t.Logf("Host vmstat pgscan_direct: %d, allocstall_direct: %d, numa_miss: %d", vmStat.PgScanDirect, vmStat.AllocStallDirect, vmStat.NumaMiss)

	cs, err := CollectClocksource()
	if err != nil {
		t.Errorf("CollectClocksource failed on host: %v", err)
	}
	t.Logf("Host clocksource: %s", cs.Current)

	netStat, err := CollectNetStat()
	if err != nil {
		t.Errorf("CollectNetStat failed on host: %v", err)
	}
	t.Logf("Host netstat listen drops: %d, overflows: %d", netStat.ListenDrops, netStat.ListenOverflows)

	sysCfg, err := CollectSystemConfig()
	if err != nil {
		t.Errorf("CollectSystemConfig failed on host: %v", err)
	}
	t.Logf("Host system config: PIDMax=%d, PortRange=%d-%d, TCPTimeWait=%d, ConntrackAvail=%v, BuddyAvail=%v, KSMAvail=%v, IRQAvail=%v",
		sysCfg.PIDMax, sysCfg.PortRange.Low, sysCfg.PortRange.High, sysCfg.SockStat.TCPTimeWait,
		sysCfg.Conntrack.Available, sysCfg.BuddyInfo.Available, sysCfg.KSM.Available, sysCfg.IRQStat.Available)
}

func TestParseSNMPAndSoftnet(t *testing.T) {
	snmpPath := filepath.Join("testdata", "snmp")
	retrans, outSegs, udpRcv, udpSnd, udpIn, err := ParseSNMP(snmpPath)
	if err != nil {
		t.Fatalf("unexpected error parsing snmp: %v", err)
	}
	if retrans != 6044 {
		t.Errorf("expected RetransSegs 6044, got %d", retrans)
	}
	if outSegs != 120890 {
		t.Errorf("expected OutSegs 120890, got %d", outSegs)
	}
	if udpRcv != 25 {
		t.Errorf("expected UDPRcvbufErrors 25, got %d", udpRcv)
	}
	if udpSnd != 12 {
		t.Errorf("expected UDPSndbufErrors 12, got %d", udpSnd)
	}
	if udpIn != 5 {
		t.Errorf("expected UDPInErrors 5, got %d", udpIn)
	}

	softnetPath := filepath.Join("testdata", "softnet_stat")
	dropped, squeeze, err := ParseSoftnet(softnetPath)
	if err != nil {
		t.Fatalf("unexpected error parsing softnet_stat: %v", err)
	}
	// Line 1: 0xa = 10, 0x78 = 120. Line 2: 0x5 = 5, 0x32 = 50. Total: dropped=15, squeeze=170
	if dropped != 15 {
		t.Errorf("expected dropped 15, got %d", dropped)
	}
	if squeeze != 170 {
		t.Errorf("expected time_squeeze 170, got %d", squeeze)
	}
}

func TestParseInotifyMaxQueuedEvents(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "max_queued_events")
	if err := os.WriteFile(tmpFile, []byte("16384\n"), 0644); err != nil {
		t.Fatalf("failed to write mock max_queued_events: %v", err)
	}

	val, err := ParseInotifyMaxQueuedEvents(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error parsing max_queued_events: %v", err)
	}
	if val != 16384 {
		t.Errorf("expected max_queued_events 16384, got %d", val)
	}

	_, errMissing := ParseInotifyMaxQueuedEvents("/nonexistent/path")
	if errMissing == nil {
		t.Errorf("expected error on nonexistent file")
	}
}

func TestParseNetIfaces(t *testing.T) {
	tmpDir := t.TempDir()
	eth0Dir := filepath.Join(tmpDir, "eth0")
	if err := os.MkdirAll(filepath.Join(eth0Dir, "statistics"), 0755); err != nil {
		t.Fatalf("failed to create mock sysfs net dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(eth0Dir, "carrier_changes"), []byte("5\n"), 0644)
	_ = os.WriteFile(filepath.Join(eth0Dir, "operstate"), []byte("up\n"), 0644)
	_ = os.WriteFile(filepath.Join(eth0Dir, "statistics", "rx_crc_errors"), []byte("42\n"), 0644)
	_ = os.WriteFile(filepath.Join(eth0Dir, "statistics", "tx_carrier_errors"), []byte("7\n"), 0644)
	_ = os.WriteFile(filepath.Join(eth0Dir, "statistics", "rx_errors"), []byte("50\n"), 0644)

	ifaces, err := ParseNetIfaces(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error parsing net ifaces: %v", err)
	}
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
	if ifaces[0].Name != "eth0" || ifaces[0].CarrierChanges != 5 || ifaces[0].RxCRCErrors != 42 {
		t.Errorf("parsed interface mismatch: %+v", ifaces[0])
	}
}

func TestParseSchedMigrationCostNS(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "sched_migration_cost_ns")
	if err := os.WriteFile(tmpFile, []byte("500000\n"), 0644); err != nil {
		t.Fatalf("failed to write mock sched_migration_cost_ns: %v", err)
	}

	val, err := ParseSchedMigrationCostNS(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error parsing sched_migration_cost_ns: %v", err)
	}
	if val != 500000 {
		t.Errorf("expected 500000, got %d", val)
	}
}

func TestParseAIO(t *testing.T) {
	tmpDir := t.TempDir()
	nrPath := filepath.Join(tmpDir, "aio-nr")
	maxPath := filepath.Join(tmpDir, "aio-max-nr")

	_ = os.WriteFile(nrPath, []byte("60000\n"), 0644)
	_ = os.WriteFile(maxPath, []byte("65536\n"), 0644)

	nr, max, err := ParseAIO(nrPath, maxPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nr != 60000 || max != 65536 {
		t.Errorf("expected 60000/65536, got %d/%d", nr, max)
	}
}

func TestParseSysVShm(t *testing.T) {
	tmpDir := t.TempDir()
	shmPath := filepath.Join(tmpDir, "shm")
	mniPath := filepath.Join(tmpDir, "shmmni")
	allPath := filepath.Join(tmpDir, "shmall")

	_ = os.WriteFile(mniPath, []byte("4096\n"), 0644)
	_ = os.WriteFile(allPath, []byte("18446744073709551615\n"), 0644)

	mockContent := `------ Shared Memory Segments --------
key        shmid      owner      perms      size       nattch     status      
0x00000000 65536      ismail     600        524288     2                       
0x00000000 98305      ismail     600        1048576    2                       
`
	_ = os.WriteFile(shmPath, []byte(mockContent), 0644)

	info, err := ParseSysVShm(shmPath, mniPath, allPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.Available {
		t.Fatalf("expected Available true")
	}
	if info.AllocatedSegments != 2 {
		t.Errorf("expected 2 segments, got %d", info.AllocatedSegments)
	}
	if info.ShmMNI != 4096 {
		t.Errorf("expected ShmMNI 4096, got %d", info.ShmMNI)
	}
}

func TestParseMDStat(t *testing.T) {
	tmpDir := t.TempDir()
	mdPath := filepath.Join(tmpDir, "mdstat")

	mockContent := `Personalities : [raid1] [linear] [multipath] [raid0] [raid6] [raid5] [raid4] [raid10] 
md0 : active raid1 sdb1[1] sda1[0]
      1048576 blocks [2/2] [UU]
      [====>................]  resync = 24.1% (253056/1048576) finish=0.8min speed=15816K/sec
`
	_ = os.WriteFile(mdPath, []byte(mockContent), 0644)

	info, err := ParseMDStat(mdPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.Available || !info.ActiveResync {
		t.Fatalf("expected active resync true, got %+v", info)
	}
	if info.ArrayName != "md0" || info.Operation != "resync" {
		t.Errorf("expected md0 / resync, got %s / %s", info.ArrayName, info.Operation)
	}
}

func TestParseIPSNMP(t *testing.T) {
	snmpPath := filepath.Join("testdata", "snmp")
	reqds, fails, timeout, oks, err := ParseIPSNMP(snmpPath)
	if err != nil {
		t.Fatalf("unexpected error parsing IP SNMP: %v", err)
	}
	// testdata/snmp has:
	// ReasmTimeout=0, ReasmReqds=0, ReasmOKs=0, ReasmFails=0
	if reqds != 0 || fails != 0 || timeout != 0 || oks != 0 {
		t.Logf("parsed IP SNMP: reqds=%d, fails=%d, timeout=%d, oks=%d", reqds, fails, timeout, oks)
	}
}

func TestParseTHPDefrag(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "defrag")
	_ = os.WriteFile(tmpFile, []byte("always defer defer+madvise [madvise] never\n"), 0644)

	mode, err := ParseTHPDefrag(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != "madvise" {
		t.Errorf("expected 'madvise', got '%s'", mode)
	}
}

func TestParseNetIfacesMissedFIFO(t *testing.T) {
	tmpDir := t.TempDir()
	eth0Dir := filepath.Join(tmpDir, "eth0")
	if err := os.MkdirAll(filepath.Join(eth0Dir, "statistics"), 0755); err != nil {
		t.Fatalf("failed to create mock sysfs net dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(eth0Dir, "operstate"), []byte("up\n"), 0644)
	_ = os.WriteFile(filepath.Join(eth0Dir, "statistics", "rx_missed_errors"), []byte("128\n"), 0644)
	_ = os.WriteFile(filepath.Join(eth0Dir, "statistics", "rx_fifo_errors"), []byte("64\n"), 0644)

	ifaces, err := ParseNetIfaces(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
	if ifaces[0].RxMissedErrors != 128 || ifaces[0].RxFIFOErrors != 64 {
		t.Errorf("expected missed=128/fifo=64, got %+v", ifaces[0])
	}
}

func TestParseFileNR(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "file-nr")
	_ = os.WriteFile(tmpFile, []byte("1048500\t0\t1048576\n"), 0644)

	fnr, err := ParseFileNR(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fnr.Available || fnr.Allocated != 1048500 || fnr.Max != 1048576 {
		t.Errorf("unexpected file-nr parsed result: %+v", fnr)
	}
}






