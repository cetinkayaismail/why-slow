// Package collector — tcp_sockets.go parses /proc/net/tcp and /proc/net/tcp6
// to categorize TCP connections across kernel socket states (ESTABLISHED, CLOSE_WAIT, etc.).
package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Default paths for IPv4 and IPv6 TCP sockets.
const (
	DefaultProcNetTCP  = "/proc/net/tcp"
	DefaultProcNetTCP6 = "/proc/net/tcp6"
)

// Linux TCP socket states constants from include/net/tcp_states.h.
const (
	tcpEstablished = 0x01
	tcpSynSent     = 0x02
	tcpSynRecv     = 0x03
	tcpFinWait1    = 0x04
	tcpFinWait2    = 0x05
	tcpTimeWait    = 0x06
	tcpClose       = 0x07
	tcpCloseWait   = 0x08
	tcpLastAck     = 0x09
	tcpListen      = 0x0A
	tcpClosing     = 0x0B
)

// CollectTCPSockets parses socket states from /proc/net/tcp and /proc/net/tcp6.
func CollectTCPSockets() (TCPSocketsInfo, error) {
	return ParseTCPSockets(DefaultProcNetTCP, DefaultProcNetTCP6)
}

// ParseTCPSockets aggregates socket counts from IPv4 and IPv6 /proc/net/tcp tables.
func ParseTCPSockets(tcpPath, tcp6Path string) (TCPSocketsInfo, error) {
	var info TCPSocketsInfo
	var anySuccess bool

	if err := parseSingleTCPFile(tcpPath, &info); err == nil {
		anySuccess = true
	}
	if err := parseSingleTCPFile(tcp6Path, &info); err == nil {
		anySuccess = true
	}

	if !anySuccess {
		return TCPSocketsInfo{}, fmt.Errorf("collector: unable to read TCP sockets table")
	}

	info.Available = true
	return info, nil
}

func parseSingleTCPFile(path string, info *TCPSocketsInfo) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	if !scanner.Scan() {
		return nil
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		stateVal, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}

		incrementSocketState(info, uint8(stateVal))
	}

	return scanner.Err()
}

func incrementSocketState(info *TCPSocketsInfo, state uint8) {
	switch state {
	case tcpEstablished:
		info.Established++
	case tcpSynSent:
		info.SynSent++
	case tcpSynRecv:
		info.SynRecv++
	case tcpFinWait1:
		info.FinWait1++
	case tcpFinWait2:
		info.FinWait2++
	case tcpTimeWait:
		info.TimeWait++
	case tcpClose:
		info.Close++
	case tcpCloseWait:
		info.CloseWait++
	case tcpLastAck:
		info.LastAck++
	case tcpListen:
		info.Listen++
	case tcpClosing:
		info.Closing++
	}
}
