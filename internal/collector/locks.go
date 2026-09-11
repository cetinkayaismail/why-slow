// Package collector — locks.go parses /proc/locks to detect file locking contention
// between processes (POSIX fcntl, FLOCK, and OFD).
//
// Linux kernel outputs locks in /proc/locks with the format:
//
//	1: POSIX  ADVISORY  WRITE 3846 103:04:17828930 1073741826 1073742335
//	1: -> POSIX ADVISORY WRITE 4521 103:04:17828930 1073741826 1073742335
//
// Lines with "->" denote blocked lock requests waiting on the active lock holder.
package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultLocksPath is the default path to Linux active file locks.
const DefaultLocksPath = "/proc/locks"

// BlockedFileLock represents a blocked lock waiter and its corresponding lock holder.
type BlockedFileLock struct {
	BlockedPID  int    `json:"blocked_pid"`
	HolderPID   int    `json:"holder_pid"`
	LockType    string `json:"lock_type"`
	DeviceInode string `json:"device_inode"`
}

// FileLocksInfo contains system-wide file lock statistics and active lock contention.
type FileLocksInfo struct {
	Available    bool              `json:"available"`
	TotalLocks   int               `json:"total_locks"`
	BlockedLocks []BlockedFileLock `json:"blocked_locks"`
}

// CollectFileLocks reads and parses active file locks from the default /proc/locks.
func CollectFileLocks() (*FileLocksInfo, error) {
	return parseFileLocks(DefaultLocksPath)
}

// parseFileLocks reads and parses the given file locks path.
func parseFileLocks(path string) (*FileLocksInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return &FileLocksInfo{Available: false, BlockedLocks: []BlockedFileLock{}}, nil
		}
		return nil, fmt.Errorf("collector: open locks: %w", err)
	}
	defer file.Close()

	info := &FileLocksInfo{
		Available:    true,
		BlockedLocks: make([]BlockedFileLock, 0, 8),
	}

	holders := make(map[string]int, 32)
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 4096)
	scanner.Buffer(buf, 65536)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		info.TotalLocks++
		parseLockLine(line, holders, info)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("collector: scan locks: %w", err)
	}

	return info, nil
}

func parseLockLine(line string, holders map[string]int, info *FileLocksInfo) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return
	}

	isBlocked := false
	idToken := fields[0]
	lockID := strings.TrimSuffix(idToken, ":")

	fieldOffset := 1
	if fieldOffset < len(fields) && fields[fieldOffset] == "->" {
		isBlocked = true
		fieldOffset++
	} else if strings.Contains(idToken, "->") {
		isBlocked = true
		lockID = strings.TrimSuffix(strings.ReplaceAll(idToken, "->", ""), ":")
	}

	if len(fields) <= fieldOffset+4 {
		return
	}

	lockType := fields[fieldOffset]
	pidStr := fields[fieldOffset+3]
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return
	}

	deviceInode := fields[fieldOffset+4]

	if isBlocked {
		holderPID := holders[lockID]
		if holderPID == 0 {
			holderPID = holders[deviceInode]
		}
		info.BlockedLocks = append(info.BlockedLocks, BlockedFileLock{
			BlockedPID:  pid,
			HolderPID:   holderPID,
			LockType:    lockType,
			DeviceInode: deviceInode,
		})
	} else {
		holders[lockID] = pid
		holders[deviceInode] = pid
	}
}
