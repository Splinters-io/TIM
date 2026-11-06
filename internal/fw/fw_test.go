package fw

import (
	"reflect"
	"strings"
	"testing"
)

func TestTargetMatches(t *testing.T) {
	got, err := targetMatches([]string{"AA:BB:CC:00:11:22", "10.77.0.23", "10.77.0.0/28"})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"-m", "mac", "--mac-source", "aa:bb:cc:00:11:22"},
		{"-s", "10.77.0.23"},
		{"-s", "10.77.0.0/28"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	if all, _ := targetMatches(nil); len(all) != 1 || all[0] != nil {
		t.Errorf("empty targets should mean one match-all entry")
	}
	if _, err := targetMatches([]string{"bogus"}); err == nil {
		t.Error("expected error")
	}
}

func TestHasTag(t *testing.T) {
	ours := "-A PREROUTING -i wlan1 -p udp -m udp --dport 123 -m comment --comment TIM -j REDIRECT --to-ports 10123"
	theirs := "-A PREROUTING -i docker0 -m comment --comment TIMMY -j ACCEPT"
	quoted := `-A FORWARD -m comment --comment "TIM" -j ACCEPT`
	if !hasTag(strings.Fields(ours)) || !hasTag(strings.Fields(quoted)) {
		t.Error("should match our rules")
	}
	if hasTag(strings.Fields(theirs)) {
		t.Error("must not match other rules")
	}
}
