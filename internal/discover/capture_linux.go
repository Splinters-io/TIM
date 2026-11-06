//go:build linux

package discover

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Capture reads every Ethernet frame on iface with a raw AF_PACKET socket
// (no libpcap needed) and calls fn for each one until ctx is cancelled.
func Capture(ctx context.Context, iface string, fn func([]byte)) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("raw socket (are you root?): %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		return err
	}
	tv := syscall.NsecToTimeval(int64(500 * time.Millisecond))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	buf := make([]byte, 65536)
	for ctx.Err() == nil {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			return err
		}
		// Skip frames this host sent (PACKET_OUTGOING = 4). We only care
		// about what clients send.
		if ll, ok := from.(*syscall.SockaddrLinklayer); ok && ll.Pkttype == 4 {
			continue
		}
		fn(buf[:n])
	}
	return nil
}
