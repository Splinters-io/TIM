//go:build linux

package spoof

import (
	"net"
	"strconv"
	"syscall"
)

const soOriginalDst = 80 // SO_ORIGINAL_DST from linux/netfilter_ipv4.h

// OriginalDst returns the pre-REDIRECT destination of a TCP connection,
// read with getsockopt(SO_ORIGINAL_DST). It returns "" on failure.
func OriginalDst(c net.Conn) string {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return ""
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return ""
	}
	var out string
	raw.Control(func(fd uintptr) {
		// The kernel fills a sockaddr_in. IPv6Mreq is a 20-byte struct, big
		// enough to receive it; this is the usual Go trick.
		mreq, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
		if err != nil {
			return
		}
		a := mreq.Multiaddr
		port := int(a[2])<<8 | int(a[3])
		ip := net.IPv4(a[4], a[5], a[6], a[7])
		out = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	})
	return out
}
