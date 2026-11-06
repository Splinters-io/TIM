// Package ap brings up a WiFi access point with hostapd (radio) and
// dnsmasq (DHCP + DNS) on a Kali/Linux box.
package ap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// StateDir holds generated configs, logs and pid files.
var StateDir = "/run/tim"

type Config struct {
	Iface   string // wireless interface that supports AP mode
	SSID    string
	Pass    string // empty = open network; otherwise WPA2-PSK (8-63 chars)
	Channel int
	Country string // regulatory domain, e.g. "GB", "US"; empty = leave alone
	Gateway string // AP-side IPv4 address, e.g. 10.77.0.1 (a /24 is used)
	// TimeServer is advertised as DHCP options 42 (NTP) and 4 (RFC 868
	// time server). Usually the same as Gateway.
	TimeServer string
	Verbose    bool
	Logf       func(string, ...any)
}

type AP struct {
	cfg     Config
	hostapd *exec.Cmd
	dnsmasq *exec.Cmd
}

// Start configures the interface and launches hostapd and dnsmasq. It
// returns once hostapd reports AP-ENABLED.
func Start(cfg Config) (*AP, error) {
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(StateDir, 0o755); err != nil {
		return nil, err
	}
	a := &AP{cfg: cfg}

	// Stop NetworkManager fighting us for the interface. Ignore errors
	// because NM may not be installed or running.
	_ = exec.Command("nmcli", "device", "set", cfg.Iface, "managed", "no").Run()
	_ = exec.Command("rfkill", "unblock", "wlan").Run()
	steps := [][]string{
		{"ip", "link", "set", cfg.Iface, "down"},
		{"ip", "addr", "flush", "dev", cfg.Iface},
		{"ip", "addr", "add", cfg.Gateway + "/24", "dev", cfg.Iface},
		{"ip", "link", "set", cfg.Iface, "up"},
	}
	for _, s := range steps {
		if out, err := exec.Command(s[0], s[1:]...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("%s: %v: %s", strings.Join(s, " "), err, strings.TrimSpace(string(out)))
		}
	}

	hostapdConf := filepath.Join(StateDir, "hostapd.conf")
	if err := os.WriteFile(hostapdConf, []byte(HostapdConf(cfg)), 0o600); err != nil {
		return nil, err
	}
	dnsmasqConf := filepath.Join(StateDir, "dnsmasq.conf")
	if err := os.WriteFile(dnsmasqConf, []byte(DnsmasqConf(cfg)), 0o644); err != nil {
		return nil, err
	}

	// hostapd
	a.hostapd = exec.Command("hostapd", hostapdConf)
	ready := make(chan struct{})
	failed := make(chan string, 1)
	var tail []string
	if err := a.startLogged(a.hostapd, "hostapd", func(line string) {
		tail = append(tail, line)
		if len(tail) > 15 {
			tail = tail[1:]
		}
		switch {
		case strings.Contains(line, "AP-ENABLED"):
			closeOnce(ready)
		case strings.Contains(line, "AP-STA-CONNECTED"), strings.Contains(line, "AP-STA-DISCONNECTED"):
			cfg.Logf("ap: %s", trimIface(line, cfg.Iface))
		case strings.Contains(line, "AP-DISABLED"):
			select {
			case failed <- line:
			default:
			}
		}
		if cfg.Verbose {
			cfg.Logf("hostapd: %s", line)
		}
	}); err != nil {
		return nil, fmt.Errorf("start hostapd: %w", err)
	}
	exited := make(chan struct{})
	go func() { a.hostapd.Wait(); close(exited) }()
	select {
	case <-ready:
	case <-exited:
		return nil, fmt.Errorf("hostapd exited before the AP came up:\n  %s", strings.Join(tail, "\n  "))
	case line := <-failed:
		a.Stop()
		return nil, fmt.Errorf("hostapd failed: %s\n  %s", line, strings.Join(tail, "\n  "))
	case <-time.After(20 * time.Second):
		a.Stop()
		return nil, fmt.Errorf("hostapd did not report AP-ENABLED within 20s:\n  %s", strings.Join(tail, "\n  "))
	}

	// dnsmasq
	a.dnsmasq = exec.Command("dnsmasq", "--keep-in-foreground", "--conf-file="+dnsmasqConf)
	if err := a.startLogged(a.dnsmasq, "dnsmasq", func(line string) {
		if strings.Contains(line, "DHCPACK") {
			cfg.Logf("dhcp: %s", afterColon(line))
		} else if cfg.Verbose || strings.Contains(line, "failed") || strings.Contains(line, "FAILED") || strings.Contains(line, "error") {
			cfg.Logf("dnsmasq: %s", line)
		}
	}); err != nil {
		a.Stop()
		return nil, fmt.Errorf("start dnsmasq: %w", err)
	}
	dnsExited := make(chan error, 1)
	go func() { dnsExited <- a.dnsmasq.Wait() }()
	select {
	case err := <-dnsExited:
		a.dnsmasq = nil
		a.Stop()
		return nil, fmt.Errorf("dnsmasq exited immediately (%v). Is another DNS/DHCP server bound to %s? Try: ss -lunp | grep -E ':(53|67) '", err, cfg.Iface)
	case <-time.After(1500 * time.Millisecond):
	}
	return a, nil
}

func closeOnce(c chan struct{}) {
	select {
	case <-c:
	default:
		close(c)
	}
}

func trimIface(line, iface string) string {
	return strings.TrimSpace(strings.TrimPrefix(line, iface+":"))
}

func afterColon(s string) string {
	if i := strings.Index(s, ": "); i >= 0 && i < 40 {
		return s[i+2:]
	}
	return s
}

func (a *AP) startLogged(cmd *exec.Cmd, name string, onLine func(string)) error {
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	// Own process group so Ctrl-C reaches TIM first, and TIM decides the
	// teardown order.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(StateDir, name+".pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			onLine(sc.Text())
		}
	}()
	return nil
}

// Stop kills hostapd and dnsmasq and releases the interface.
func (a *AP) Stop() {
	for _, c := range []*exec.Cmd{a.dnsmasq, a.hostapd} {
		if c != nil && c.Process != nil {
			stopProcess(c.Process.Pid)
		}
	}
	releaseIface(a.cfg.Iface, a.cfg.Gateway)
	os.Remove(filepath.Join(StateDir, "hostapd.pid"))
	os.Remove(filepath.Join(StateDir, "dnsmasq.pid"))
}

func stopProcess(pid int) {
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Signal(syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		if p.Signal(syscall.Signal(0)) != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = p.Kill()
}

func releaseIface(iface, gw string) {
	if iface == "" {
		return
	}
	if gw != "" {
		_ = exec.Command("ip", "addr", "del", gw+"/24", "dev", iface).Run()
	}
	_ = exec.Command("nmcli", "device", "set", iface, "managed", "yes").Run()
}

// Cleanup kills leftover hostapd/dnsmasq processes from a previous crashed
// run, using the pid files. A pid is only killed if it still belongs to the
// expected program.
func Cleanup(iface, gw string) {
	for _, name := range []string{"dnsmasq", "hostapd"} {
		pidFile := filepath.Join(StateDir, name+".pid")
		b, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err == nil {
			comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if strings.TrimSpace(string(comm)) == name {
				stopProcess(pid)
			}
		}
		os.Remove(pidFile)
	}
	releaseIface(iface, gw)
}

func validate(c *Config) error {
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	if c.Iface == "" {
		return fmt.Errorf("no AP interface given")
	}
	if c.SSID == "" || len(c.SSID) > 32 {
		return fmt.Errorf("SSID must be 1-32 bytes")
	}
	if c.Pass != "" && (len(c.Pass) < 8 || len(c.Pass) > 63) {
		return fmt.Errorf("WPA2 passphrase must be 8-63 characters")
	}
	if strings.ContainsAny(c.SSID+c.Pass, "\n\r") {
		return fmt.Errorf("SSID/passphrase must not contain newlines")
	}
	if c.Channel == 0 {
		c.Channel = 6
	}
	ip := net.ParseIP(c.Gateway).To4()
	if ip == nil {
		return fmt.Errorf("gateway %q is not an IPv4 address", c.Gateway)
	}
	if c.TimeServer == "" {
		c.TimeServer = c.Gateway
	}
	return nil
}

func prefix24(gw string) string {
	ip := net.ParseIP(gw).To4()
	return fmt.Sprintf("%d.%d.%d.", ip[0], ip[1], ip[2])
}

// HostapdConf renders hostapd.conf.
func HostapdConf(c Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "interface=%s\ndriver=nl80211\nssid=%s\n", c.Iface, c.SSID)
	if c.Channel > 14 {
		b.WriteString("hw_mode=a\n")
	} else {
		b.WriteString("hw_mode=g\n")
	}
	fmt.Fprintf(&b, "channel=%d\n", c.Channel)
	if c.Country != "" {
		fmt.Fprintf(&b, "country_code=%s\nieee80211d=1\n", strings.ToUpper(c.Country))
	}
	b.WriteString("ieee80211n=1\nwmm_enabled=1\nauth_algs=1\nignore_broadcast_ssid=0\nctrl_interface=/run/tim/hostapd\n")
	if c.Pass != "" {
		// WPA1+WPA2 with TKIP+CCMP, so old IoT devices can join too.
		fmt.Fprintf(&b, "wpa=3\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP CCMP\nrsn_pairwise=CCMP\nwpa_passphrase=%s\n", c.Pass)
	}
	return b.String()
}

// DnsmasqConf renders dnsmasq.conf.
func DnsmasqConf(c Config) string {
	p := prefix24(c.Gateway)
	var b strings.Builder
	fmt.Fprintf(&b, "interface=%s\nbind-interfaces\nexcept-interface=lo\n", c.Iface)
	fmt.Fprintf(&b, "dhcp-range=%s10,%s200,255.255.255.0,12h\n", p, p)
	fmt.Fprintf(&b, "dhcp-option=option:router,%s\n", c.Gateway)
	fmt.Fprintf(&b, "dhcp-option=option:dns-server,%s\n", c.Gateway)
	// Point the device's time lookups at us.
	fmt.Fprintf(&b, "dhcp-option=option:ntp-server,%s\n", c.TimeServer)
	fmt.Fprintf(&b, "dhcp-option=4,%s\n", c.TimeServer) // RFC 868 time server
	fmt.Fprintf(&b, "dhcp-authoritative\ndhcp-leasefile=%s\n", filepath.Join(StateDir, "dnsmasq.leases"))
	b.WriteString("log-dhcp\nlog-facility=-\nuser=root\n")
	// Forward DNS to the host's resolvers, plus public fallbacks, so the
	// device still reaches its real servers.
	b.WriteString("server=1.1.1.1\nserver=8.8.8.8\n")
	if c.Verbose {
		b.WriteString("log-queries\n")
	}
	return b.String()
}
