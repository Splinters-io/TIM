package clock

import (
	"testing"
	"time"
)

func TestParseOffset(t *testing.T) {
	cases := map[string]time.Duration{
		"-400d":   -400 * 24 * time.Hour,
		"+36h":    36 * time.Hour,
		"1y2w":    (365 + 14) * 24 * time.Hour,
		"-90d12h": -(90*24 + 12) * time.Hour,
		"30m":     30 * time.Minute,
		"500ms":   500 * time.Millisecond,
	}
	for in, want := range cases {
		got, err := ParseOffset(in)
		if err != nil || got != want {
			t.Errorf("ParseOffset(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-", "abc", "10x", "10d foo", "d10"} {
		if _, err := ParseOffset(bad); err == nil {
			t.Errorf("ParseOffset(%q) should fail", bad)
		}
	}
}

func TestParseTime(t *testing.T) {
	want := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, in := range []string{"2024-01-01", "2024-01-01T00:00:00Z", "2024-01-01T02:00:00+02:00"} {
		got, err := ParseTime(in)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseTime(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseTime("yesterday"); err == nil {
		t.Error("expected error")
	}
}

func TestClockModes(t *testing.T) {
	anchor := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	real := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

	c := Anchored(anchor, false)
	c.started = real
	c.realNow = func() time.Time { return real.Add(90 * time.Second) }
	if got := c.Now(); !got.Equal(anchor.Add(90 * time.Second)) {
		t.Errorf("ticking clock = %v", got)
	}

	f := Anchored(anchor, true)
	f.realNow = func() time.Time { return real.Add(time.Hour) }
	if got := f.Now(); !got.Equal(anchor) {
		t.Errorf("frozen clock = %v", got)
	}

	o := Offset(-400 * 24 * time.Hour)
	o.realNow = func() time.Time { return real }
	if got := o.Now(); !got.Equal(real.Add(-400 * 24 * time.Hour)) {
		t.Errorf("offset clock = %v", got)
	}
}
