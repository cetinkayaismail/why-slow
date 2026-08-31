package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseVMConfig(t *testing.T) {
	tmpDir := t.TempDir()
	overcommitFile := filepath.Join(tmpDir, "overcommit_memory")
	swappinessFile := filepath.Join(tmpDir, "swappiness")

	_ = os.WriteFile(overcommitFile, []byte("1\n"), 0644)
	_ = os.WriteFile(swappinessFile, []byte("60\n"), 0644)

	info, err := ParseVMConfig(overcommitFile, swappinessFile)
	if err != nil {
		t.Fatalf("unexpected error parsing vm config: %v", err)
	}

	if !info.Available {
		t.Errorf("expected Available to be true")
	}
	if info.OvercommitMemory != 1 {
		t.Errorf("expected OvercommitMemory=1, got %d", info.OvercommitMemory)
	}
	if info.Swappiness != 60 {
		t.Errorf("expected Swappiness=60, got %d", info.Swappiness)
	}
}

func TestParseVMConfigMissing(t *testing.T) {
	_, err := ParseVMConfig("/non_existent/overcommit", "/non_existent/swappiness")
	if err == nil {
		t.Errorf("expected error when files missing, got nil")
	}
}
