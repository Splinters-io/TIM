//go:build !linux

package spoof

import "net"

// OriginalDst is only supported on Linux. Elsewhere the HTTP proxy falls
// back to the Host header.
func OriginalDst(net.Conn) string { return "" }
