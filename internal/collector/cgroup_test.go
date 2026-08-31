package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCgroupsMock(t *testing.T) {
	tmpDir := t.TempDir()

	// Mock cgroup slice dir
	sliceDir := filepath.Join(tmpDir, "system.slice", "test.service")
	if err := os.MkdirAll(sliceDir, 0755); err != nil {
		t.Fatalf("failed to create cgroup mock dir: %v", err)
	}

	cpuStatContent := "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\nnr_periods 500\nnr_throttled 25\nthrottled_usec 50000\nnr_bursts 10\nburst_usec 40000\n"
	if err := os.WriteFile(filepath.Join(sliceDir, "cpu.stat"), []byte(cpuStatContent), 0644); err != nil {
		t.Fatalf("failed to write cpu.stat: %v", err)
	}

	memEventsContent := "low 0\nhigh 0\nmax 7\noom 2\noom_kill 1\n"
	if err := os.WriteFile(filepath.Join(sliceDir, "memory.events"), []byte(memEventsContent), 0644); err != nil {
		t.Fatalf("failed to write memory.events: %v", err)
	}

	if err := os.WriteFile(filepath.Join(sliceDir, "cpu.shares"), []byte("512\n"), 0644); err != nil {
		t.Fatalf("failed to write cpu.shares: %v", err)
	}

	mockProcs := []ProcessInfo{
		{PID: 100, CgroupPath: "/system.slice/test.service"},
	}

	info, err := ParseCgroups(tmpDir, mockProcs)
	if err != nil {
		t.Fatalf("unexpected error parsing cgroups: %v", err)
	}

	if !info.Available {
		t.Fatal("expected cgroup info to be available")
	}

	var foundEntry *CgroupEntry
	for i := range info.Groups {
		if info.Groups[i].Path == "/system.slice/test.service" {
			foundEntry = &info.Groups[i]
			break
		}
	}

	if foundEntry == nil {
		t.Fatalf("expected to find entry for '/system.slice/test.service'")
	}
	if foundEntry.ThrottledUsec != 50000 {
		t.Errorf("expected ThrottledUsec 50000, got %d", foundEntry.ThrottledUsec)
	}
	if foundEntry.NrThrottled != 25 {
		t.Errorf("expected NrThrottled 25, got %d", foundEntry.NrThrottled)
	}
	if foundEntry.NrBursts != 10 {
		t.Errorf("expected NrBursts 10, got %d", foundEntry.NrBursts)
	}
	if foundEntry.BurstUsec != 40000 {
		t.Errorf("expected BurstUsec 40000, got %d", foundEntry.BurstUsec)
	}
	if foundEntry.OOMKills != 1 {
		t.Errorf("expected OOMKills 1, got %d", foundEntry.OOMKills)
	}
	if foundEntry.MemEventsMax != 7 {
		t.Errorf("expected MemEventsMax 7, got %d", foundEntry.MemEventsMax)
	}
	if foundEntry.CPUShares != 512 {
		t.Errorf("expected CPUShares 512, got %d", foundEntry.CPUShares)
	}
}

func TestLiveHostCgroups(t *testing.T) {
	procs := []ProcessInfo{
		{PID: 1, CgroupPath: "/"},
	}
	info, err := CollectCgroups(procs)
	if err != nil {
		t.Fatalf("CollectCgroups failed on host: %v", err)
	}
	t.Logf("Host cgroup available: %v (found %d groups)", info.Available, len(info.Groups))
}

func TestParseCgroupsFrozenMock(t *testing.T) {
	tmpDir := t.TempDir()
	sliceDir := filepath.Join(tmpDir, "docker.slice", "frozen.container")
	if err := os.MkdirAll(sliceDir, 0755); err != nil {
		t.Fatalf("failed to create cgroup mock dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(sliceDir, "cgroup.events"), []byte("populated 1\nfrozen 1\n"), 0644)

	mockProcs := []ProcessInfo{
		{PID: 200, CgroupPath: "/docker.slice/frozen.container"},
	}

	info, err := ParseCgroups(tmpDir, mockProcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.Available || !info.Frozen {
		t.Fatalf("expected Available and Frozen true, got info: %+v", info)
	}
	if len(info.Groups) != 1 || !info.Groups[0].Frozen {
		t.Fatalf("expected Group Frozen true, got: %+v", info.Groups)
	}
}

