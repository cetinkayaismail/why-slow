// Package collector — psi.go parses /proc/pressure/{cpu,memory,io}
// for Pressure Stall Information (PSI) metrics.
//
// Returns PSIInfo with Some/Full avg10/avg60/avg300 and total for each
// resource. Gracefully returns an empty PSIInfo struct with Available=false
// if PSI is not available (kernel < 4.20 or CONFIG_PSI=n).
package collector

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Default paths for Linux PSI files.
const (
	DefaultPSICPUPath    = "/proc/pressure/cpu"
	DefaultPSIMemoryPath = "/proc/pressure/memory"
	DefaultPSIIOPath     = "/proc/pressure/io"
)

// CollectPSI reads all PSI metrics from /proc/pressure.
func CollectPSI() (PSIInfo, error) {
	return ParsePSI(DefaultPSICPUPath, DefaultPSIMemoryPath, DefaultPSIIOPath)
}

// ParsePSI reads PSI metrics from custom file paths (useful for test fixtures).
func ParsePSI(cpuPath, memPath, ioPath string) (PSIInfo, error) {
	info := PSIInfo{Available: false}

	cpuResource, err := parsePSIFile(cpuPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return info, nil
		}
		return info, fmt.Errorf("collector: parse psi cpu: %w", err)
	}

	memResource, err := parsePSIFile(memPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
		return info, fmt.Errorf("collector: parse psi memory: %w", err)
	}

	ioResource, err := parsePSIFile(ioPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
		return info, fmt.Errorf("collector: parse psi io: %w", err)
	}

	info.Available = true
	info.CPU = cpuResource
	info.Memory = memResource
	info.IO = ioResource

	return info, nil
}

func parsePSIFile(path string) (PSIResource, error) {
	file, err := os.Open(path)
	if err != nil {
		return PSIResource{}, err
	}
	defer file.Close()

	var resource PSIResource
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "some ") {
			resource.Some = parsePSILine(line[5:])
		} else if strings.HasPrefix(line, "full ") {
			resource.Full = parsePSILine(line[5:])
		}
	}

	if err := scanner.Err(); err != nil {
		return PSIResource{}, err
	}

	return resource, nil
}

// parsePSILine parses "avg10=0.00 avg60=0.00 avg300=0.00 total=123456"
func parsePSILine(content string) PSIMetrics {
	var metrics PSIMetrics
	fields := strings.Fields(content)

	for _, field := range fields {
		key, val, found := strings.Cut(field, "=")
		if !found {
			continue
		}

		switch key {
		case "avg10":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				metrics.Avg10 = v
			}
		case "avg60":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				metrics.Avg60 = v
			}
		case "avg300":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				metrics.Avg300 = v
			}
		case "total":
			if v, err := strconv.ParseUint(val, 10, 64); err == nil {
				metrics.Total = v
			}
		}
	}

	return metrics
}
