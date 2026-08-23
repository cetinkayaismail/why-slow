// Package collector — disk.go parses /proc/diskstats for block device
// I/O counters (reads, writes, io_ticks) filtered to real devices
// (sd*, nvme*, vd*, xvd*, mmcblk*). Also calls statfs() syscall on critical
// system mounts (/, /tmp, /var) for disk capacity and utilization.
package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Default paths for disk statistics and critical mount inspection.
const (
	DefaultProcDiskStatsPath = "/proc/diskstats"
)

// DefaultMountPaths defines standard Linux mount points inspected for disk exhaustion.
var DefaultMountPaths = []string{"/", "/tmp", "/var"}

// CollectDiskStats parses block device I/O counters from /proc/diskstats.
func CollectDiskStats() (DiskStatsInfo, error) {
	return ParseDiskStats(DefaultProcDiskStatsPath)
}

// ParseDiskStats parses block device metrics from a custom diskstats file path.
func ParseDiskStats(path string) (DiskStatsInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return DiskStatsInfo{}, fmt.Errorf("collector: open diskstats: %w", err)
	}
	defer file.Close()

	var info DiskStatsInfo
	info.Devices = make([]DiskDeviceStat, 0, 8)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}

		devName := fields[2]
		if !isRealBlockDevice(devName) {
			continue
		}

		stat := parseDiskDeviceFields(devName, fields[3:])
		info.Devices = append(info.Devices, stat)
	}

	if err := scanner.Err(); err != nil {
		return DiskStatsInfo{}, fmt.Errorf("collector: scan diskstats: %w", err)
	}

	return info, nil
}

// isRealBlockDevice filters out loop, ram, virtual partitions, and mapper devices.
func isRealBlockDevice(name string) bool {
	// Skip pseudo / RAM / CD devices
	if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") ||
		strings.HasPrefix(name, "sr") || strings.HasPrefix(name, "dm-") ||
		strings.HasPrefix(name, "zram") {
		return false
	}

	// Match common physical/virtual disk naming conventions:
	// - SCSI/SATA: sda, sdb (skip sda1, sda2 partitions)
	// - NVMe: nvme0n1, nvme1n1 (skip nvme0n1p1 partitions)
	// - VirtIO: vda, vdb (skip vda1)
	// - Xen: xvda, xvdb (skip xvda1)
	// - MMC/SD: mmcblk0 (skip mmcblk0p1)
	if strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "xvd") {
		return isAlphaOnlySuffix(name[2:])
	}

	if strings.HasPrefix(name, "nvme") {
		// Expect format nvmeXnY (e.g. nvme0n1) without 'p' partition suffix
		return strings.Contains(name, "n") && !strings.Contains(name[strings.Index(name, "n")+1:], "p")
	}

	if strings.HasPrefix(name, "mmcblk") {
		return !strings.Contains(name, "p")
	}

	return false
}

func isAlphaOnlySuffix(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

func parseDiskDeviceFields(devName string, fields []string) DiskDeviceStat {
	stat := DiskDeviceStat{DeviceName: devName}
	if len(fields) > 0 {
		stat.ReadsCompleted, _ = strconv.ParseUint(fields[0], 10, 64)
	}
	if len(fields) > 1 {
		stat.ReadsMerged, _ = strconv.ParseUint(fields[1], 10, 64)
	}
	if len(fields) > 2 {
		stat.SectorsRead, _ = strconv.ParseUint(fields[2], 10, 64)
	}
	if len(fields) > 3 {
		stat.TimeReadingMS, _ = strconv.ParseUint(fields[3], 10, 64)
	}
	if len(fields) > 4 {
		stat.WritesCompleted, _ = strconv.ParseUint(fields[4], 10, 64)
	}
	if len(fields) > 5 {
		stat.WritesMerged, _ = strconv.ParseUint(fields[5], 10, 64)
	}
	if len(fields) > 6 {
		stat.SectorsWritten, _ = strconv.ParseUint(fields[6], 10, 64)
	}
	if len(fields) > 7 {
		stat.TimeWritingMS, _ = strconv.ParseUint(fields[7], 10, 64)
	}
	if len(fields) > 8 {
		stat.IOsInProgress, _ = strconv.ParseUint(fields[8], 10, 64)
	}
	if len(fields) > 9 {
		stat.IOTicks, _ = strconv.ParseUint(fields[9], 10, 64)
	}
	if len(fields) > 10 {
		stat.WeightedIOTicks, _ = strconv.ParseUint(fields[10], 10, 64)
	}
	return stat
}

// CollectDiskSpace inspects default mount points using the statfs syscall.
func CollectDiskSpace() (DiskSpaceInfo, error) {
	return CheckMountsSpace(DefaultMountPaths)
}

// CheckMountsSpace inspects the provided mount paths and deduplicates filesystems by Fsid.
func CheckMountsSpace(paths []string) (DiskSpaceInfo, error) {
	info := DiskSpaceInfo{
		Mounts: make([]MountSpaceInfo, 0, len(paths)),
	}

	seenFsid := make(map[uint64]bool, len(paths))

	for _, mountPath := range paths {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountPath, &stat); err != nil {
			// Skip unmounted or inaccessible paths gracefully
			continue
		}

		fsid := uint64(uint32(stat.Fsid.X__val[0]))<<32 | uint64(uint32(stat.Fsid.X__val[1]))
		if fsid != 0 && seenFsid[fsid] {
			// Same underlying filesystem already inspected
			continue
		}
		if fsid != 0 {
			seenFsid[fsid] = true
		}

		blockSize := uint64(stat.Bsize)
		totalBytes := stat.Blocks * blockSize
		freeBytes := stat.Bfree * blockSize
		availBytes := stat.Bavail * blockSize

		var usedPercent float64
		if totalBytes > 0 {
			usedBytes := totalBytes - freeBytes
			usedPercent = clampPercent((float64(usedBytes) / float64(totalBytes)) * 100.0)
		}

		inodesTotal := stat.Files
		inodesFree := stat.Ffree
		var inodesUsedPercent float64
		if inodesTotal > 0 {
			usedInodes := inodesTotal - inodesFree
			inodesUsedPercent = clampPercent((float64(usedInodes) / float64(inodesTotal)) * 100.0)
		}

		info.Mounts = append(info.Mounts, MountSpaceInfo{
			Path:              mountPath,
			Fsid:              fsid,
			TotalBytes:        totalBytes,
			FreeBytes:         freeBytes,
			AvailBytes:        availBytes,
			UsedPercent:       usedPercent,
			InodesTotal:       inodesTotal,
			InodesFree:        inodesFree,
			InodesUsedPercent: inodesUsedPercent,
		})
	}

	return info, nil
}
