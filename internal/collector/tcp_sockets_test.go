package collector

import (
	"testing"
)

func TestParseTCPSockets(t *testing.T) {
	info, err := ParseTCPSockets("testdata/proc_net_tcp", "testdata/non_existent_tcp6")
	if err != nil {
		t.Fatalf("unexpected error parsing tcp sockets: %v", err)
	}

	if !info.Available {
		t.Errorf("expected Available to be true")
	}
	if info.Listen != 1 {
		t.Errorf("expected Listen=1, got %d", info.Listen)
	}
	if info.Established != 2 {
		t.Errorf("expected Established=2, got %d", info.Established)
	}
	if info.CloseWait != 2 {
		t.Errorf("expected CloseWait=2, got %d", info.CloseWait)
	}
	if info.TimeWait != 1 {
		t.Errorf("expected TimeWait=1, got %d", info.TimeWait)
	}
}

func TestParseTCPSocketsAllMissing(t *testing.T) {
	_, err := ParseTCPSockets("testdata/non_existent_1", "testdata/non_existent_2")
	if err == nil {
		t.Errorf("expected error when all files missing, got nil")
	}
}
