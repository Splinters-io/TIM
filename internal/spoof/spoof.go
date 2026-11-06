// Package spoof contains the fake time servers: NTP/SNTP, RFC 868 Time,
// RFC 867 Daytime, and an HTTP proxy that rewrites the Date header.
package spoof

import (
	"time"
)

// Clock is the source of fake time.
type Clock interface {
	Now() time.Time
}

// Logf is a printf-style logger.
type Logf func(format string, args ...any)

// Service is a running spoofer.
type Service interface {
	Name() string
	Addr() string
	Serve() error // blocks until Close
	Close() error
}

// ntpEpochOffset is the number of seconds between 1900-01-01 and 1970-01-01.
const ntpEpochOffset = 2208988800

// ntpSeconds is the 32-bit NTP/RFC 868 seconds field for t. It wraps
// naturally at the 2036 era boundary, which is what clients expect.
func ntpSeconds(t time.Time) uint32 {
	return uint32(t.Unix() + ntpEpochOffset)
}

// ntpTimestamp encodes t as a 64-bit NTP timestamp (32.32 fixed point).
func ntpTimestamp(t time.Time) uint64 {
	frac := (uint64(t.Nanosecond()) << 32) / 1e9
	return uint64(ntpSeconds(t))<<32 | frac
}

// ntpTime decodes a 64-bit NTP timestamp, choosing the era closest to pivot.
func ntpTime(ts uint64, pivot time.Time) time.Time {
	secs := int64(ts >> 32)
	nsec := int64(((ts & 0xffffffff) * 1e9) >> 32)
	base := secs - ntpEpochOffset // era 0
	const era = int64(1) << 32
	p := pivot.Unix()
	best := base
	for _, cand := range []int64{base + era, base - era} {
		if abs(cand-p) < abs(best-p) {
			best = cand
		}
	}
	return time.Unix(best, nsec).UTC()
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
