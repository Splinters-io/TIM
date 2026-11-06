// Package fw manages TIM's iptables rules and IP forwarding.
//
// Every rule TIM adds carries the comment "TIM". Teardown scans the rule
// list for that comment, so `tim down` can clean up after a crash without
// any saved state, and it never touches anyone else's rules.
package fw

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	Tag         = "TIM"
	forwardPath = "/proc/sys/net/ipv4/ip_forward"
)

// StateDir holds the saved ip_forward value (shared with the ap package).
var StateDir = "/run/tim"

// Redirect sends traffic from the AP side for Proto/Port to a local port.
type Redirect struct {
	Proto  string // "tcp" or "udp"
	Port   int
	ToPort int
}

type Config struct {
	AP       string     // AP-side interface, e.g. wlan1
	Uplink   string     // internet-side interface, e.g. eth0
	Targets  []string   // optional: only redirect these MACs/IPs (empty = everyone on the AP)
	Redirect []Redirect // time traffic to steal
	BlockNTS bool       // reject NTS-KE (tcp/4460) so NTS clients may fall back to plain NTP
	Logf     func(string, ...any)
}

func ipt(args ...string) error {
	cmd := exec.Command("iptables", append([]string{"-w"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func comment() []string { return []string{"-m", "comment", "--comment", Tag} }

// targetMatches returns one iptables match per target (nil entry = match all).
func targetMatches(targets []string) ([][]string, error) {
	if len(targets) == 0 {
		return [][]string{nil}, nil
	}
	var out [][]string
	for _, t := range targets {
		if mac, err := net.ParseMAC(t); err == nil {
			out = append(out, []string{"-m", "mac", "--mac-source", mac.String()})
		} else if ip := net.ParseIP(t); ip != nil && ip.To4() != nil {
			out = append(out, []string{"-s", ip.String()})
		} else if _, n, err := net.ParseCIDR(t); err == nil {
			out = append(out, []string{"-s", n.String()})
		} else {
			return nil, fmt.Errorf("target %q is not a MAC, IPv4 address or CIDR", t)
		}
	}
	return out, nil
}

// Up enables forwarding and NAT, then installs the redirect rules.
func Up(c Config) error {
	matches, err := targetMatches(c.Targets)
	if err != nil {
		return err
	}
	if err := enableForwarding(); err != nil {
		return err
	}
	rules := [][]string{
		// NAT the AP clients out through the uplink.
		append(append([]string{"-t", "nat", "-A", "POSTROUTING", "-o", c.Uplink}, comment()...), "-j", "MASQUERADE"),
		// Allow forwarding (insert at the top so a default DROP policy or
		// docker's chains don't block it).
		append(append([]string{"-I", "FORWARD", "1", "-i", c.Uplink, "-o", c.AP, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"}, comment()...), "-j", "ACCEPT"),
		append(append([]string{"-I", "FORWARD", "1", "-i", c.AP, "-o", c.Uplink}, comment()...), "-j", "ACCEPT"),
		// Allow AP clients to reach DHCP, DNS and our spoofers on this box.
		append(append([]string{"-I", "INPUT", "1", "-i", c.AP}, comment()...), "-j", "ACCEPT"),
	}
	if c.BlockNTS {
		rules = append(rules, append(append([]string{"-I", "FORWARD", "1", "-i", c.AP, "-p", "tcp", "--dport", "4460"}, comment()...), "-j", "REJECT", "--reject-with", "tcp-reset"))
	}
	for _, r := range c.Redirect {
		for _, m := range matches {
			rule := []string{"-t", "nat", "-A", "PREROUTING", "-i", c.AP, "-p", r.Proto, "--dport", strconv.Itoa(r.Port)}
			rule = append(rule, m...)
			rule = append(rule, comment()...)
			rule = append(rule, "-j", "REDIRECT", "--to-ports", strconv.Itoa(r.ToPort))
			rules = append(rules, rule)
		}
	}
	for _, r := range rules {
		if err := ipt(r...); err != nil {
			return err
		}
		if c.Logf != nil {
			c.Logf("fw: iptables %s", strings.Join(r, " "))
		}
	}
	return nil
}

// Down removes every rule tagged TIM and restores ip_forward. It is safe to
// call more than once and when nothing is installed.
func Down() error {
	var errs []string
	for _, table := range []string{"nat", "filter"} {
		out, err := exec.Command("iptables", "-w", "-t", table, "-S").Output()
		if err != nil {
			errs = append(errs, fmt.Sprintf("list %s: %v", table, err))
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "-A" || !hasTag(fields) {
				continue
			}
			fields[0] = "-D"
			if err := ipt(append([]string{"-t", table}, fields...)...); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if err := restoreForwarding(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("fw teardown: %s", strings.Join(errs, "; "))
	}
	return nil
}

func hasTag(fields []string) bool {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--comment" && strings.Trim(fields[i+1], `"`) == Tag {
			return true
		}
	}
	return false
}

func enableForwarding() error {
	prevFile := filepath.Join(StateDir, "ip_forward.prev")
	if err := os.MkdirAll(StateDir, 0o755); err != nil {
		return err
	}
	cur, err := os.ReadFile(forwardPath)
	if err != nil {
		return err
	}
	// Only save the original value once, so a crash and re-run doesn't
	// record our own "1" as the original.
	if _, err := os.Stat(prevFile); os.IsNotExist(err) {
		if err := os.WriteFile(prevFile, bytes.TrimSpace(cur), 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(forwardPath, []byte("1\n"), 0o644)
}

func restoreForwarding() error {
	prevFile := filepath.Join(StateDir, "ip_forward.prev")
	prev, err := os.ReadFile(prevFile)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := os.WriteFile(forwardPath, append(bytes.TrimSpace(prev), '\n'), 0o644); err != nil {
		return err
	}
	return os.Remove(prevFile)
}
