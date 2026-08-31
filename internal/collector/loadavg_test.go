package collector

import (
	"testing"
)

func TestParseLoadAvg(t *testing.T) {
	info, err := ParseLoadAvg("testdata/proc_loadavg")
	if err != nil {
		t.Fatalf("unexpected error parsing loadavg: %v", err)
	}

	if !info.Available {
		t.Errorf("expected Available to be true")
	}
	if info.Load1 != 4.25 {
		t.Errorf("expected Load1=4.25, got %f", info.Load1)
	}
	if info.Load5 != 3.80 {
		t.Errorf("expected Load5=3.80, got %f", info.Load5)
	}
	if info.Load15 != 2.15 {
		t.Errorf("expected Load15=2.15, got %f", info.Load15)
	}
	if info.RunningEntities != 8 {
		t.Errorf("expected RunningEntities=8, got %d", info.RunningEntities)
	}
	if info.TotalEntities != 456 {
		t.Errorf("expected TotalEntities=456, got %d", info.TotalEntities)
	}
}

func TestParseLoadAvgNotFound(t *testing.T) {
	_, err := ParseLoadAvg("testdata/non_existent_file")
	if err == nil {
		t.Errorf("expected error for non existent file, got nil")
	}
}
