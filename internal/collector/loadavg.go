// Package collector — loadavg.go parses /proc/loadavg to extract 1, 5, and 15-minute
// system load averages and active/total scheduling entity counts.
package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultProcLoadAvgPath is the standard Linux load average file.
const DefaultProcLoadAvgPath = "/proc/loadavg"

// CollectLoadAvg reads system load averages from /proc/loadavg.
func CollectLoadAvg() (LoadAvgInfo, error) {
	return ParseLoadAvg(DefaultProcLoadAvgPath)
}

// ParseLoadAvg parses 1/5/15 minute load averages from a /proc/loadavg formatted file.
func ParseLoadAvg(path string) (LoadAvgInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return LoadAvgInfo{}, fmt.Errorf("collector: open loadavg: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return LoadAvgInfo{}, fmt.Errorf("collector: scan loadavg: %w", err)
		}
		return LoadAvgInfo{}, fmt.Errorf("collector: empty loadavg file")
	}

	fields := strings.Fields(scanner.Text())
	if len(fields) < 4 {
		return LoadAvgInfo{}, fmt.Errorf("collector: invalid loadavg format, expected >= 4 fields")
	}

	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return LoadAvgInfo{}, fmt.Errorf("collector: parse load1: %w", err)
	}
	load5, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return LoadAvgInfo{}, fmt.Errorf("collector: parse load5: %w", err)
	}
	load15, err := strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return LoadAvgInfo{}, fmt.Errorf("collector: parse load15: %w", err)
	}

	running, total := parseEntities(fields[3])

	return LoadAvgInfo{
		Available:       true,
		Load1:           load1,
		Load5:           load5,
		Load15:          load15,
		RunningEntities: running,
		TotalEntities:   total,
	}, nil
}

func parseEntities(field string) (int, int) {
	parts := strings.Split(field, "/")
	if len(parts) != 2 {
		return 0, 0
	}
	running, _ := strconv.Atoi(parts[0])
	total, _ := strconv.Atoi(parts[1])
	return running, total
}
