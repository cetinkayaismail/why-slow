package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFileLocks(t *testing.T) {
	t.Parallel()

	sampleData := `1: POSIX  ADVISORY  WRITE 3846 103:04:17828930 1073741826 1073742335
1: -> POSIX ADVISORY WRITE 4521 103:04:17828930 1073741826 1073742335
2: FLOCK  ADVISORY  WRITE 1231 103:02:536270 0 EOF
3: FLOCK  ADVISORY  WRITE 1231 103:02:536269 0 EOF
4: -> FLOCK ADVISORY WRITE 9876 103:02:536269 0 EOF
`

	tmpDir := t.TempDir()
	locksPath := filepath.Join(tmpDir, "locks")
	if err := os.WriteFile(locksPath, []byte(sampleData), 0644); err != nil {
		t.Fatalf("failed to write mock locks file: %v", err)
	}

	info, err := parseFileLocks(locksPath)
	if err != nil {
		t.Fatalf("unexpected error parsing locks: %v", err)
	}

	if !info.Available {
		t.Fatalf("expected Available to be true")
	}

	if info.TotalLocks != 5 {
		t.Errorf("expected 5 total locks, got %d", info.TotalLocks)
	}

	if len(info.BlockedLocks) != 2 {
		t.Fatalf("expected 2 blocked locks, got %d", len(info.BlockedLocks))
	}

	// First blocked lock: 4521 blocked behind 3846
	b0 := info.BlockedLocks[0]
	if b0.BlockedPID != 4521 || b0.HolderPID != 3846 || b0.LockType != "POSIX" {
		t.Errorf("unexpected b0: %+v", b0)
	}

	// Second blocked lock: 9876 blocked behind 1231
	b1 := info.BlockedLocks[1]
	if b1.BlockedPID != 9876 || b1.HolderPID != 1231 || b1.LockType != "FLOCK" {
		t.Errorf("unexpected b1: %+v", b1)
	}
}

func TestParseFileLocks_EmptyAndMissing(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	emptyPath := filepath.Join(tmpDir, "empty_locks")
	if err := os.WriteFile(emptyPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create empty file: %v", err)
	}

	info, err := parseFileLocks(emptyPath)
	if err != nil {
		t.Fatalf("unexpected error for empty locks file: %v", err)
	}
	if !info.Available || len(info.BlockedLocks) != 0 || info.TotalLocks != 0 {
		t.Errorf("unexpected info for empty locks: %+v", info)
	}

	// Non-existent path should return Available: false without error (graceful degradation)
	missingPath := filepath.Join(tmpDir, "non_existent")
	infoMissing, err := parseFileLocks(missingPath)
	if err != nil {
		t.Fatalf("unexpected error for missing locks file: %v", err)
	}
	if infoMissing.Available || len(infoMissing.BlockedLocks) != 0 {
		t.Errorf("expected Available: false for missing locks, got %+v", infoMissing)
	}
}
