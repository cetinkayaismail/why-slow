package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSlabInfo_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	content := `slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
dentry             2500000 2600000    192   21    1 : tunables    0    0    0 : slabdata  123809 123809      0
inode_cache        1200000 1300000    608   13    2 : tunables    0    0    0 : slabdata  100000 100000      0
ext4_inode_cache    800000  900000   1088   15    4 : tunables    0    0    0 : slabdata   60000  60000      0
task_struct          15000   16000   5952    5    8 : tunables    0    0    0 : slabdata    3200   3200      0
kmalloc-512          50000   55000    512   16    2 : tunables    0    0    0 : slabdata    3437   3437      0
`
	filePath := filepath.Join(tmpDir, "slabinfo")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	info, err := ParseSlabInfo(filePath)
	if err != nil {
		t.Fatalf("ParseSlabInfo failed: %v", err)
	}
	if !info.Available {
		t.Fatalf("expected Available=true, got false")
	}
	if info.DentryCacheActive != 2500000 || info.DentryCacheTotal != 2600000 {
		t.Errorf("unexpected dentry: active=%d, total=%d", info.DentryCacheActive, info.DentryCacheTotal)
	}
	if info.InodeCacheActive != 2000000 || info.InodeCacheTotal != 2200000 {
		t.Errorf("unexpected inode: active=%d, total=%d", info.InodeCacheActive, info.InodeCacheTotal)
	}
	if info.TaskStructActive != 15000 || info.TaskStructTotal != 16000 {
		t.Errorf("unexpected task_struct: active=%d, total=%d", info.TaskStructActive, info.TaskStructTotal)
	}
}

func TestParseSlabInfo_UnsupportedVersion(t *testing.T) {
	tmpDir := t.TempDir()
	content := `slabinfo - version: 1.1
# name            <active_objs> <num_objs>
dentry             2500000 2600000
`
	filePath := filepath.Join(tmpDir, "slabinfo_old")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	info, err := ParseSlabInfo(filePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Available {
		t.Errorf("expected Available=false for v1.1 slabinfo")
	}
}

func TestParseSlabInfo_MissingFile(t *testing.T) {
	info, err := ParseSlabInfo("/path/to/nonexistent/slabinfo")
	if err != nil {
		t.Fatalf("expected nil error on missing file, got %v", err)
	}
	if info.Available {
		t.Errorf("expected Available=false for missing file")
	}
}
