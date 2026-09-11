package collector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestParseProcStatLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		expectedPID int
		wantComm    string
		wantState   byte
		wantThreads int
		wantUTime   uint64
		wantSTime   uint64
		wantRSS     uint64
		wantOK      bool
	}{
		{
			name:        "standard comm",
			line:        "1234 (systemd) S 1 1234 1234 0 -1 4194560 120 0 0 0 500 250 0 0 20 0 5 0 100 20000000 1000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0",
			expectedPID: 1234,
			wantComm:    "systemd",
			wantState:   'S',
			wantThreads: 5,
			wantUTime:   500,
			wantSTime:   250,
			wantRSS:     1000 * 4096,
			wantOK:      true,
		},
		{
			name:        "comm with spaces and nested parens",
			line:        "4567 (worker (pool 1)) R 1234 4567 4567 0 -1 4194560 50 0 0 0 1200 800 0 0 20 0 16 0 100 20000000 2500 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0",
			expectedPID: 4567,
			wantComm:    "worker (pool 1)",
			wantState:   'R',
			wantThreads: 16,
			wantUTime:   1200,
			wantSTime:   800,
			wantRSS:     2500 * 4096,
			wantOK:      true,
		},
		{
			name:        "invalid line",
			line:        "not a valid stat line",
			expectedPID: 0,
			wantOK:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, ok := parseProcStatLine(tc.line, tc.expectedPID)
			if ok != tc.wantOK {
				t.Fatalf("expected ok %v, got %v", tc.wantOK, ok)
			}
			if !tc.wantOK {
				return
			}
			if info.Comm != tc.wantComm {
				t.Errorf("expected Comm '%s', got '%s'", tc.wantComm, info.Comm)
			}
			if info.State != tc.wantState {
				t.Errorf("expected State '%c', got '%c'", tc.wantState, info.State)
			}
			if info.NumThreads != tc.wantThreads {
				t.Errorf("expected NumThreads %d, got %d", tc.wantThreads, info.NumThreads)
			}
			if info.UTime != tc.wantUTime {
				t.Errorf("expected UTime %d, got %d", tc.wantUTime, info.UTime)
			}
			if info.STime != tc.wantSTime {
				t.Errorf("expected STime %d, got %d", tc.wantSTime, info.STime)
			}
			if info.RSSBytes != tc.wantRSS {
				t.Errorf("expected RSSBytes %d, got %d", tc.wantRSS, info.RSSBytes)
			}
		})
	}
}

func TestWorkerPoolContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	procs, err := CollectProcesses(ctx)
	if err != nil {
		t.Fatalf("unexpected error on cancelled context: %v", err)
	}
	// With an already cancelled context, scan should terminate quickly without deadlock or panic
	t.Logf("Collected %d processes after immediate cancellation", len(procs))
}

func TestWorkerGoroutineCleanup(t *testing.T) {
	// Baseline goroutine count before collection
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	// Execute process scan multiple times
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := CollectProcesses(ctx)
		cancel()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Allow goroutines to finish defer cleanup
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	finalGoroutines := runtime.NumGoroutine()

	// Verify no worker goroutines are leaked (diff should be <= 1 for background testing runtime)
	if finalGoroutines > initialGoroutines+2 {
		t.Errorf("potential zombie worker goroutines detected: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}

func TestScanProcessesMock(t *testing.T) {
	tmpDir := t.TempDir()

	// Create mock PID 999
	pidDir := filepath.Join(tmpDir, "999")
	if err := os.Mkdir(pidDir, 0755); err != nil {
		t.Fatalf("failed to create mock pid dir: %v", err)
	}

	statContent := "999 (mock_proc) D 1 999 999 0 -1 0 0 0 0 0 100 50 0 0 20 0 4 0 100 1000000 500 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(statContent), 0644); err != nil {
		t.Fatalf("failed to write stat: %v", err)
	}

	if err := os.WriteFile(filepath.Join(pidDir, "wchan"), []byte("ext4_writepages\n"), 0644); err != nil {
		t.Fatalf("failed to write wchan: %v", err)
	}

	if err := os.WriteFile(filepath.Join(pidDir, "oom_score"), []byte("250\n"), 0644); err != nil {
		t.Fatalf("failed to write oom_score: %v", err)
	}

	if err := os.WriteFile(filepath.Join(pidDir, "oom_score_adj"), []byte("-1000\n"), 0644); err != nil {
		t.Fatalf("failed to write oom_score_adj: %v", err)
	}

	ioContent := "read_bytes: 1048576\nwrite_bytes: 2097152\n"
	if err := os.WriteFile(filepath.Join(pidDir, "io"), []byte(ioContent), 0644); err != nil {
		t.Fatalf("failed to write io: %v", err)
	}

	limitsContent := "Limit                     Soft Limit           Hard Limit           Units     \nMax open files            4096                 8192                 files     \n"
	if err := os.WriteFile(filepath.Join(pidDir, "limits"), []byte(limitsContent), 0644); err != nil {
		t.Fatalf("failed to write limits: %v", err)
	}

	statusContent := "Name:\tmock_proc\nState:\tD (disk sleep)\nCpus_allowed:\t00000001\nSigQ:\t50000/60000\nvoluntary_ctxt_switches:\t1500\nnonvoluntary_ctxt_switches:\t200\n"
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(statusContent), 0644); err != nil {
		t.Fatalf("failed to write status: %v", err)
	}

	fdDir := filepath.Join(pidDir, "fd")
	if err := os.Mkdir(fdDir, 0755); err != nil {
		t.Fatalf("failed to create fd dir: %v", err)
	}
	_ = os.WriteFile(filepath.Join(fdDir, "0"), []byte{}, 0644)
	_ = os.WriteFile(filepath.Join(fdDir, "1"), []byte{}, 0644)
	_ = os.WriteFile(filepath.Join(fdDir, "2"), []byte{}, 0644)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	procs, err := ScanProcesses(ctx, tmpDir)
	if err != nil {
		t.Fatalf("failed to scan mock processes: %v", err)
	}

	if len(procs) != 1 {
		t.Fatalf("expected 1 process, got %d", len(procs))
	}

	p := procs[0]
	if p.PID != 999 || p.Comm != "mock_proc" || p.State != 'D' {
		t.Errorf("unexpected process fields: %+v", p)
	}
	if p.Wchan != "ext4_writepages" {
		t.Errorf("expected wchan 'ext4_writepages', got '%s'", p.Wchan)
	}
	if p.OOMScore != 250 {
		t.Errorf("expected OOMScore 250, got %d", p.OOMScore)
	}
	if p.OOMScoreAdj != -1000 {
		t.Errorf("expected OOMScoreAdj -1000, got %d", p.OOMScoreAdj)
	}
	if p.ReadBytes != 1048576 || p.WriteBytes != 2097152 {
		t.Errorf("unexpected io stats: read=%d, write=%d", p.ReadBytes, p.WriteBytes)
	}
	if p.MaxFDs != 4096 {
		t.Errorf("expected MaxFDs 4096, got %d", p.MaxFDs)
	}
	if p.OpenFDs != 3 {
		t.Errorf("expected OpenFDs 3, got %d", p.OpenFDs)
	}
	if p.CpusAllowed != 1 {
		t.Errorf("expected CpusAllowed 1, got %d", p.CpusAllowed)
	}
	if p.SigQQueued != 50000 || p.SigQMax != 60000 {
		t.Errorf("expected SigQ 50000/60000, got %d/%d", p.SigQQueued, p.SigQMax)
	}
	if p.VoluntaryCtxtSwitches != 1500 || p.NonvoluntaryCtxtSwitches != 200 {
		t.Errorf("expected ctx switches 1500/200, got %d/%d", p.VoluntaryCtxtSwitches, p.NonvoluntaryCtxtSwitches)
	}
}

func TestCountBitsInHexMask(t *testing.T) {
	tests := []struct {
		mask string
		want int
	}{
		{"1", 1},
		{"00000001", 1},
		{"3", 2},
		{"f", 4},
		{"fff", 12},
		{"ffffffff", 32},
		{"00000000,00000001", 1},
		{"0", 0},
	}

	for _, tc := range tests {
		got := countBitsInHexMask(tc.mask)
		if got != tc.want {
			t.Errorf("countBitsInHexMask(%q) = %d, want %d", tc.mask, got, tc.want)
		}
	}
}

func TestLiveHostCollectProcesses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	procs, err := CollectProcesses(ctx)
	if err != nil {
		t.Fatalf("CollectProcesses failed on host: %v", err)
	}

	if len(procs) == 0 {
		t.Fatalf("expected to discover host processes, got 0")
	}

	t.Logf("Discovered %d processes on host", len(procs))
}

func TestReadFileWithBuf(t *testing.T) {
	tmpDir := t.TempDir()
	content := "hello world from process collector buffer test"
	filePath := filepath.Join(tmpDir, "test_file")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	buf4k := make([]byte, 4096)
	data, err := readFileWithBuf(filePath, buf4k)
	if err != nil {
		t.Fatalf("readFileWithBuf failed: %v", err)
	}
	if string(data) != content {
		t.Errorf("expected %q, got %q", content, string(data))
	}

	bufSmall := make([]byte, 10)
	dataFallback, err := readFileWithBuf(filePath, bufSmall)
	if err != nil {
		t.Fatalf("readFileWithBuf with small buffer failed: %v", err)
	}
	if string(dataFallback) != content {
		t.Errorf("expected fallback to read entire content %q, got %q", content, string(dataFallback))
	}

	if _, err := readFileWithBuf(filepath.Join(tmpDir, "does_not_exist"), buf4k); err == nil {
		t.Errorf("expected error for non-existent file")
	}
}

func TestParseSmapsRollup(t *testing.T) {
	tmpDir := t.TempDir()
	content := `Rss:                2048 kB
Pss:                1024 kB
Shared_Clean:        512 kB
Shared_Dirty:        256 kB
Private_Clean:       256 kB
Private_Dirty:      1024 kB
Swap:                640 kB
`
	filePath := filepath.Join(tmpDir, "smaps_rollup")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	info, err := ParseSmapsRollup(filePath)
	if err != nil {
		t.Fatalf("ParseSmapsRollup failed: %v", err)
	}
	if !info.Available {
		t.Fatalf("expected Available=true, got false")
	}
	if info.RSS != 2048 || info.PSS != 1024 || info.Swap != 640 {
		t.Errorf("unexpected metrics: RSS=%d, PSS=%d, Swap=%d", info.RSS, info.PSS, info.Swap)
	}
	if info.SharedClean != 512 || info.SharedDirty != 256 {
		t.Errorf("unexpected shared: clean=%d, dirty=%d", info.SharedClean, info.SharedDirty)
	}
	if info.PrivateClean != 256 || info.PrivateDirty != 1024 {
		t.Errorf("unexpected private: clean=%d, dirty=%d", info.PrivateClean, info.PrivateDirty)
	}

	// Nonexistent file test
	missing, err := ParseSmapsRollup(filepath.Join(tmpDir, "nonexistent"))
	if err != nil {
		t.Fatalf("expected nil error on missing file, got: %v", err)
	}
	if missing.Available {
		t.Errorf("expected Available=false for missing smaps_rollup")
	}
}

func TestCountProcessFDTypes(t *testing.T) {
	tmpDir := t.TempDir()
	fdDir := filepath.Join(tmpDir, "42", "fd")
	if err := os.MkdirAll(fdDir, 0755); err != nil {
		t.Fatalf("failed to create fake fd dir: %v", err)
	}

	targets := map[string]string{
		"0": "/dev/null",
		"1": "socket:[12345]",
		"2": "pipe:[67890]",
		"3": "anon_inode:[eventpoll]",
		"4": "custom_handle",
	}

	for name, target := range targets {
		if err := os.Symlink(target, filepath.Join(fdDir, name)); err != nil {
			t.Fatalf("failed to create test symlink %s: %v", name, err)
		}
	}

	counts, err := CountProcessFDTypes(tmpDir, 42)
	if err != nil {
		t.Fatalf("CountProcessFDTypes failed: %v", err)
	}

	if counts.Total != 5 {
		t.Errorf("expected Total 5, got %d", counts.Total)
	}
	if counts.Files != 1 {
		t.Errorf("expected Files 1, got %d", counts.Files)
	}
	if counts.Sockets != 1 {
		t.Errorf("expected Sockets 1, got %d", counts.Sockets)
	}
	if counts.Pipes != 1 {
		t.Errorf("expected Pipes 1, got %d", counts.Pipes)
	}
	if counts.AnonInodes != 1 {
		t.Errorf("expected AnonInodes 1, got %d", counts.AnonInodes)
	}
	if counts.Other != 1 {
		t.Errorf("expected Other 1, got %d", counts.Other)
	}

	// Test nonexistent PID
	if _, err := CountProcessFDTypes(tmpDir, 99999); err == nil {
		t.Errorf("expected error for nonexistent PID")
	}
}
