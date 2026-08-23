// Package collector — cpu.go parses /proc/stat for per-CPU and aggregate
// CPU time counters (user, nice, system, idle, iowait, irq, softirq, steal),
// procs_running, and procs_blocked.
//
// Also reads cpufreq sysfs (scaling_cur_freq, scaling_max_freq) and
// thermal zone temperatures from /sys/class/thermal/thermal_zone*/temp.
package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Default paths for CPU and thermal information.
const (
	DefaultProcStatPath = "/proc/stat"
	DefaultCPUFreqDir   = "/sys/devices/system/cpu"
	DefaultThermalDir   = "/sys/class/thermal"
)

// CollectCPUStat parses CPU counters from /proc/stat.
func CollectCPUStat() (CPUStatInfo, error) {
	return ParseCPUStat(DefaultProcStatPath)
}

// ParseCPUStat parses CPU counters from a custom /proc/stat path.
func ParseCPUStat(path string) (CPUStatInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return CPUStatInfo{}, fmt.Errorf("collector: open proc stat: %w", err)
	}
	defer file.Close()

	var info CPUStatInfo
	info.PerCore = make([]CoreCPUStat, 0, 16)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 3 {
			continue
		}

		if strings.HasPrefix(line, "cpu") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			coreStat := parseCPUFields(fields)
			if fields[0] == "cpu" {
				info.TotalCPU = coreStat
			} else if strings.HasPrefix(fields[0], "cpu") {
				info.PerCore = append(info.PerCore, coreStat)
			}
		} else if strings.HasPrefix(line, "procs_running ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.ProcsRunning, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "procs_blocked ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.ProcsBlocked, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return CPUStatInfo{}, fmt.Errorf("collector: scan proc stat: %w", err)
	}

	return info, nil
}

func parseCPUFields(fields []string) CoreCPUStat {
	stat := CoreCPUStat{ID: fields[0]}
	if len(fields) > 1 {
		stat.User, _ = strconv.ParseUint(fields[1], 10, 64)
	}
	if len(fields) > 2 {
		stat.Nice, _ = strconv.ParseUint(fields[2], 10, 64)
	}
	if len(fields) > 3 {
		stat.System, _ = strconv.ParseUint(fields[3], 10, 64)
	}
	if len(fields) > 4 {
		stat.Idle, _ = strconv.ParseUint(fields[4], 10, 64)
	}
	if len(fields) > 5 {
		stat.IOWait, _ = strconv.ParseUint(fields[5], 10, 64)
	}
	if len(fields) > 6 {
		stat.IRQ, _ = strconv.ParseUint(fields[6], 10, 64)
	}
	if len(fields) > 7 {
		stat.SoftIRQ, _ = strconv.ParseUint(fields[7], 10, 64)
	}
	if len(fields) > 8 {
		stat.Steal, _ = strconv.ParseUint(fields[8], 10, 64)
	}
	if len(fields) > 9 {
		stat.Guest, _ = strconv.ParseUint(fields[9], 10, 64)
	}
	if len(fields) > 10 {
		stat.GuestNice, _ = strconv.ParseUint(fields[10], 10, 64)
	}
	return stat
}

// CollectCPUFreq reads scaling frequencies across CPU cores from sysfs.
func CollectCPUFreq() (CPUFreqInfo, error) {
	return ParseCPUFreq(DefaultCPUFreqDir)
}

// ParseCPUFreq parses cpufreq from a base sysfs directory.
func ParseCPUFreq(baseDir string) (CPUFreqInfo, error) {
	matches, err := filepath.Glob(filepath.Join(baseDir, "cpu[0-9]*", "cpufreq"))
	if err != nil || len(matches) == 0 {
		return CPUFreqInfo{Available: false}, nil
	}

	info := CPUFreqInfo{
		Available: true,
		Cores:     make([]CoreFreq, 0, len(matches)),
	}

	for _, dir := range matches {
		coreIDStr := filepath.Base(filepath.Dir(dir)) // e.g. "cpu0"
		coreID, err := strconv.Atoi(strings.TrimPrefix(coreIDStr, "cpu"))
		if err != nil {
			continue
		}

		curFreq := readUintFromFile(filepath.Join(dir, "scaling_cur_freq"))
		maxFreq := readUintFromFile(filepath.Join(dir, "scaling_max_freq"))

		if curFreq > 0 || maxFreq > 0 {
			info.Cores = append(info.Cores, CoreFreq{
				CoreID:  coreID,
				CurFreq: curFreq,
				MaxFreq: maxFreq,
			})
		}
	}

	if len(info.Cores) == 0 {
		info.Available = false
	}
	return info, nil
}

// CollectThermal reads thermal zones from /sys/class/thermal.
func CollectThermal() (ThermalInfo, error) {
	return ParseThermal(DefaultThermalDir)
}

// ParseThermal parses thermal zone metrics from a sysfs directory.
func ParseThermal(baseDir string) (ThermalInfo, error) {
	matches, err := filepath.Glob(filepath.Join(baseDir, "thermal_zone[0-9]*"))
	if err != nil || len(matches) == 0 {
		return ThermalInfo{Available: false}, nil
	}

	info := ThermalInfo{
		Available: true,
		Zones:     make([]ThermalZone, 0, len(matches)),
		MaxTemp:   0,
	}

	for _, dir := range matches {
		typeBytes, _ := os.ReadFile(filepath.Join(dir, "type"))
		zoneType := strings.TrimSpace(string(typeBytes))

		milliDeg := readUintFromFile(filepath.Join(dir, "temp"))
		tempDeg := float64(milliDeg) / 1000.0

		if tempDeg > 0 {
			info.Zones = append(info.Zones, ThermalZone{
				Type:    zoneType,
				TempDeg: tempDeg,
			})
			if tempDeg > info.MaxTemp {
				info.MaxTemp = tempDeg
			}
		}
	}

	if len(info.Zones) == 0 {
		info.Available = false
	}
	return info, nil
}

func readUintFromFile(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	val, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return val
}
