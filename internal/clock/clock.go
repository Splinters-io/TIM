// Package clock provides the fake clock that every TIM spoofer reads from.
package clock

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Clock reports a fake "now". It is either anchored to a fixed instant
// (ticking forward from when TIM started, or frozen), or a fixed offset
// from the real time.
type Clock struct {
	mu      sync.RWMutex
	anchor  time.Time
	started time.Time
	offset  time.Duration
	freeze  bool
	useOff  bool
	realNow func() time.Time
}

// Anchored returns a clock that starts at t. If freeze is true it always
// reports exactly t; otherwise it ticks forward in real time from t.
func Anchored(t time.Time, freeze bool) *Clock {
	return &Clock{anchor: t, started: time.Now(), freeze: freeze, realNow: time.Now}
}

// Offset returns a clock that is always real time + d (d is usually negative).
func Offset(d time.Duration) *Clock {
	return &Clock{offset: d, useOff: true, realNow: time.Now}
}

// Now returns the fake current time in UTC.
func (c *Clock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.realNow()
	switch {
	case c.useOff:
		return now.Add(c.offset).UTC()
	case c.freeze:
		return c.anchor.UTC()
	default:
		return c.anchor.Add(now.Sub(c.started)).UTC()
	}
}

// Describe is a one-line human description of the clock mode.
func (c *Clock) Describe() string {
	switch {
	case c.useOff:
		return fmt.Sprintf("real time %s (now %s)", fmtOffset(c.offset), c.Now().Format(time.RFC3339))
	case c.freeze:
		return fmt.Sprintf("frozen at %s", c.anchor.UTC().Format(time.RFC3339))
	default:
		return fmt.Sprintf("starting at %s and ticking", c.anchor.UTC().Format(time.RFC3339))
	}
}

func fmtOffset(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign, d = "-", -d
	}
	days := d / (24 * time.Hour)
	rest := d % (24 * time.Hour)
	if days > 0 {
		return fmt.Sprintf("%s%dd%s", sign, days, rest)
	}
	return sign + d.String()
}

// ParseTime accepts RFC 3339 ("2024-01-01T00:00:00Z") or a bare date
// ("2024-01-01", taken as midnight UTC).
func ParseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q (use 2024-01-01 or 2024-01-01T00:00:00Z)", s)
}

var offsetPart = regexp.MustCompile(`(\d+)(y|w|d|h|ms|m|s)`)

// ParseOffset accepts things like "-400d", "-1y2w", "+36h", "-90d12h".
// y = 365 days, w = 7 days, d = 24 hours.
func ParseOffset(s string) (time.Duration, error) {
	orig := s
	s = strings.TrimSpace(s)
	sign := time.Duration(1)
	if strings.HasPrefix(s, "-") {
		sign, s = -1, s[1:]
	} else {
		s = strings.TrimPrefix(s, "+")
	}
	if s == "" {
		return 0, fmt.Errorf("empty offset")
	}
	units := map[string]time.Duration{
		"y": 365 * 24 * time.Hour, "w": 7 * 24 * time.Hour, "d": 24 * time.Hour,
		"h": time.Hour, "m": time.Minute, "s": time.Second, "ms": time.Millisecond,
	}
	var total time.Duration
	consumed := 0
	for _, m := range offsetPart.FindAllStringSubmatchIndex(s, -1) {
		if m[0] != consumed {
			return 0, fmt.Errorf("cannot parse offset %q", orig)
		}
		n, err := strconv.ParseInt(s[m[2]:m[3]], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot parse offset %q: %v", orig, err)
		}
		total += time.Duration(n) * units[s[m[4]:m[5]]]
		consumed = m[1]
	}
	if consumed != len(s) {
		return 0, fmt.Errorf("cannot parse offset %q (examples: -400d, -1y2w, +36h)", orig)
	}
	return sign * total, nil
}
