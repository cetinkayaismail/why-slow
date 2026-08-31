// Package collector — vm_config.go parses kernel virtual memory tunables
// from /proc/sys/vm (overcommit_memory, swappiness).
package collector

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Default sysctl paths for VM tunables.
const (
	DefaultOvercommitMemoryPath = "/proc/sys/vm/overcommit_memory"
	DefaultSwappinessPath       = "/proc/sys/vm/swappiness"
)

// CollectVMConfig collects kernel memory management tunables.
func CollectVMConfig() (VMConfigInfo, error) {
	return ParseVMConfig(DefaultOvercommitMemoryPath, DefaultSwappinessPath)
}

// ParseVMConfig parses overcommit_memory and swappiness from custom sysctl file paths.
func ParseVMConfig(overcommitPath, swappinessPath string) (VMConfigInfo, error) {
	var info VMConfigInfo

	overcommitData, err := os.ReadFile(overcommitPath)
	if err == nil {
		if val, err := strconv.Atoi(strings.TrimSpace(string(overcommitData))); err == nil {
			info.OvercommitMemory = val
			info.Available = true
		}
	}

	swappinessData, err := os.ReadFile(swappinessPath)
	if err == nil {
		if val, err := strconv.Atoi(strings.TrimSpace(string(swappinessData))); err == nil {
			info.Swappiness = val
			info.Available = true
		}
	}

	if !info.Available {
		return VMConfigInfo{}, fmt.Errorf("collector: unable to read VM sysctl tunables")
	}

	return info, nil
}
