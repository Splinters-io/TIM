// Command tim (Time In the Middle) provides network time control and
// certificate diagnostics for testing, troubleshooting and compatibility work.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tim/internal/ap"
	"tim/internal/certs"
	"tim/internal/clock"
	"tim/internal/discover"
	"tim/internal/fw"
	"tim/internal/spoof"
)

const version = "0.1.0-beta.1"

const usage = `TIM - Time In the Middle

Network time control and certificate diagnostics for testing, troubleshooting
and compatibility work. Run standalone time services or a controlled WiFi AP.

Usage:
  tim version                                   print version
  tim check    --ap wlan1 --uplink eth0           preflight checks
  tim discover --ap wlan1 --uplink eth0 [...]     run the AP, watch how devices get the time
  tim up       --ap wlan1 --uplink eth0 --time 2024-01-01 [...]
                                                  run the AP and spoof the time
  tim down     [--ap wlan1]                       clean up after a crash
  tim certs    [--root ca.pem] [--hok dir] host[:port]|file ...
                                                  cert validity, device-root check, known-bad keys
  tim hok update                               refresh fingerprint-only cache
  tim serve    --listen 127.0.0.1 --time ...      spoofers only (no AP or firewall), for testing

Run "tim <command> -h" for a command's flags.
`

var logger = log.New(os.Stderr, "", log.Ltime)

func logf(format string, args ...any) { logger.Printf(format, args...) }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "version", "--version":
		fmt.Println("TIM " + version)
		return
	case "up":
		err = cmdUp(args)
	case "discover":
		err = cmdDiscover(args)
	case "down":
		err = cmdDown(args)
	case "check":
		err = cmdCheck(args)
	case "hok":
		err = cmdHoK(args)
	case "certs":
		err = cmdCerts(args)
	case "serve":
		err = cmdServe(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tim %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

// ---- shared flag groups -------------------------------------------------

type apFlags struct {
	iface, uplink, ssid, pass, country, gw string
	channel                                int
	verbose                                bool
}

func (a *apFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&a.iface, "ap", "", "wireless interface to run the AP on (must support AP mode)")
	fs.StringVar(&a.uplink, "uplink", "", "interface with internet access (e.g. eth0 or a second WiFi card)")
	fs.StringVar(&a.ssid, "ssid", "TIM", "AP network name")
	fs.StringVar(&a.pass, "pass", "", "WPA2 passphrase, 8-63 chars (empty = open network)")
	fs.IntVar(&a.channel, "channel", 6, "WiFi channel (1-14 = 2.4GHz, 36+ = 5GHz)")
	fs.StringVar(&a.country, "country", "", "regulatory country code, e.g. GB or US")
	fs.StringVar(&a.gw, "gw", "10.77.0.1", "AP-side IP address of this box (a /24 is used)")
	fs.BoolVar(&a.verbose, "v", false, "verbose: show hostapd/dnsmasq output and every DNS query")
}

func (a *apFlags) validate() error {
	if a.iface == "" || a.uplink == "" {
		return errors.New("--ap and --uplink are required")
	}
	if a.iface == a.uplink {
		return errors.New("--ap and --uplink must be different interfaces")
	}
	for _, i := range []string{a.iface, a.uplink} {
		if _, err := net.InterfaceByName(i); err != nil {
			return fmt.Errorf("interface %s: %v", i, err)
		}
	}
	return nil
}

func (a *apFlags) config() ap.Config {
	return ap.Config{Iface: a.iface, SSID: a.ssid, Pass: a.pass, Channel: a.channel, Country: a.country, Gateway: a.gw, Verbose: a.verbose, Logf: logf}
}

type clockFlags struct {
	at, offset string
	freeze     bool
}

func (c *clockFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.at, "time", "", "fake time to serve: 2024-01-01 or 2024-01-01T12:00:00Z (ticks forward from there)")
	fs.StringVar(&c.offset, "offset", "", "or: shift real time, e.g. -400d, -1y2w, -36h")
	fs.BoolVar(&c.freeze, "freeze", false, "with --time: always serve exactly that instant (don't tick)")
}

func (c *clockFlags) build() (*clock.Clock, error) {
	switch {
	case c.at != "" && c.offset != "":
		return nil, errors.New("use either --time or --offset, not both")
	case c.at != "":
		t, err := clock.ParseTime(c.at)
		if err != nil {
			return nil, err
		}
		return clock.Anchored(t, c.freeze), nil
	case c.offset != "":
		if c.freeze {
			return nil, errors.New("--freeze only works with --time")
		}
		d, err := clock.ParseOffset(c.offset)
		if err != nil {
			return nil, err
		}
		return clock.Offset(d), nil
	}
	return nil, errors.New("need --time or --offset (run `tim certs <host>` to pick one)")
}

// spoofer kinds and the iptables redirects each one needs.
var allSpoofers = []string{"ntp", "time37", "daytime", "http"}

const (
	portNTP     = 10123
	portTime37  = 10037
	portDaytime = 10013
	portHTTP    = 10080
)

func parseSpoof(s string) (map[string]bool, error) {
	out := map[string]bool{}
	if s == "" || s == "all" {
		for _, k := range allSpoofers {
			out[k] = true
		}
		return out, nil
	}
	for _, k := range strings.Split(s, ",") {
		k = strings.TrimSpace(k)
		valid := false
		for _, a := range allSpoofers {
			if k == a {
				valid = true
			}
		}
		if !valid {
			return nil, fmt.Errorf("unknown spoofer %q (choose from %s)", k, strings.Join(allSpoofers, ","))
		}
		out[k] = true
	}
	return out, nil
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("bad port %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}

// startSpoofers listens on host with TIM's high ports. It returns the
// running services and the iptables redirects to point at them.
func startSpoofers(host string, enabled map[string]bool, httpPorts []int, clk spoof.Clock, ports [4]int) ([]spoof.Service, []fw.Redirect, error) {
	var svcs []spoof.Service
	var redirs []fw.Redirect
	fail := func(err error) ([]spoof.Service, []fw.Redirect, error) {
		for _, s := range svcs {
			s.Close()
		}
		return nil, nil, err
	}
	addr := func(p int) string { return net.JoinHostPort(host, strconv.Itoa(p)) }
	if enabled["ntp"] {
		s, err := spoof.NewNTP(addr(ports[0]), clk, logf)
		if err != nil {
			return fail(fmt.Errorf("ntp: %w", err))
		}
		svcs = append(svcs, s)
		redirs = append(redirs, fw.Redirect{Proto: "udp", Port: 123, ToPort: ports[0]})
	}
	if enabled["time37"] {
		s, err := spoof.NewTime37(addr(ports[1]), clk, logf)
		if err != nil {
			return fail(fmt.Errorf("time37: %w", err))
		}
		svcs = append(svcs, s)
		redirs = append(redirs, fw.Redirect{Proto: "tcp", Port: 37, ToPort: ports[1]}, fw.Redirect{Proto: "udp", Port: 37, ToPort: ports[1]})
	}
	if enabled["daytime"] {
		s, err := spoof.NewDaytime(addr(ports[2]), clk, logf)
		if err != nil {
			return fail(fmt.Errorf("daytime: %w", err))
		}
		svcs = append(svcs, s)
		redirs = append(redirs, fw.Redirect{Proto: "tcp", Port: 13, ToPort: ports[2]}, fw.Redirect{Proto: "udp", Port: 13, ToPort: ports[2]})
	}
	if enabled["http"] {
		var originalDst spoof.OrigDstFunc
		if len(httpPorts) > 0 {
			originalDst = spoof.OriginalDst
		}
		s, err := spoof.NewHTTPDate(addr(ports[3]), clk, logf, originalDst)
		if err != nil {
			return fail(fmt.Errorf("http: %w", err))
		}
		svcs = append(svcs, s)
		for _, p := range httpPorts {
			redirs = append(redirs, fw.Redirect{Proto: "tcp", Port: p, ToPort: ports[3]})
		}
	}
	for _, s := range svcs {
		go func(s spoof.Service) {
			if err := s.Serve(); err != nil {
				logf("%s: stopped: %v", s.Name(), err)
			}
		}(s)
	}
	return svcs, redirs, nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root (sudo)")
	}
	return nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}

// ---- commands -----------------------------------------------------------

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	var af apFlags
	var cf clockFlags
	af.register(fs)
	cf.register(fs)
	spoofList := fs.String("spoof", "all", "comma-separated spoofers: "+strings.Join(allSpoofers, ","))
	targets := fs.String("target", "", "comma-separated MACs/IPs to spoof (default: every client on the AP)")
	httpPortsS := fs.String("http-ports", "80", "TCP ports to run the HTTP Date rewriter on")
	blockNTS := fs.Bool("block-nts", false, "reject NTS-KE (tcp/4460) so NTS clients may fall back to plain NTP")
	fs.Parse(args)

	if err := requireRoot(); err != nil {
		return err
	}
	if err := af.validate(); err != nil {
		return err
	}
	clk, err := cf.build()
	if err != nil {
		return err
	}
	enabled, err := parseSpoof(*spoofList)
	if err != nil {
		return err
	}
	httpPorts, err := parsePorts(*httpPortsS)
	if err != nil {
		return err
	}
	var tlist []string
	if *targets != "" {
		for _, t := range strings.Split(*targets, ",") {
			tlist = append(tlist, strings.TrimSpace(t))
		}
	}

	// Clear anything a previous crashed run left behind.
	fw.Down()
	ap.Cleanup(af.iface, af.gw)

	logf("starting AP %q on %s ...", af.ssid, af.iface)
	a, err := ap.Start(af.config())
	if err != nil {
		return err
	}
	defer func() {
		logf("tearing down ...")
		if err := fw.Down(); err != nil {
			logf("%v", err)
		}
		a.Stop()
		logf("clean.")
	}()

	svcs, redirs, err := startSpoofers(af.gw, enabled, httpPorts, clk, [4]int{portNTP, portTime37, portDaytime, portHTTP})
	if err != nil {
		return err
	}
	defer func() {
		for _, s := range svcs {
			s.Close()
		}
	}()

	if err := fw.Up(fw.Config{AP: af.iface, Uplink: af.uplink, Targets: tlist, Redirect: redirs, BlockNTS: *blockNTS, Logf: verboseLog(af.verbose)}); err != nil {
		return err
	}

	var names []string
	for _, s := range svcs {
		names = append(names, s.Name())
	}
	who := "all clients"
	if len(tlist) > 0 {
		who = strings.Join(tlist, ", ")
	}
	logf("TIM is up. SSID %q, NAT via %s", af.ssid, af.uplink)
	logf("fake time: %s", clk.Describe())
	logf("spoofing %s for %s", strings.Join(names, ", "), who)
	logf("connect the device now. Ctrl-C to stop.")

	ctx, cancel := signalContext()
	defer cancel()
	<-ctx.Done()
	return nil
}

func verboseLog(v bool) func(string, ...any) {
	if v {
		return logf
	}
	return nil
}

func cmdDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	var af apFlags
	af.register(fs)
	dur := fs.Duration("for", 0, "stop after this long (e.g. 5m); default: until Ctrl-C")
	fs.Parse(args)

	if err := requireRoot(); err != nil {
		return err
	}
	if err := af.validate(); err != nil {
		return err
	}
	fw.Down()
	ap.Cleanup(af.iface, af.gw)

	logf("starting AP %q on %s (no spoofing, just watching) ...", af.ssid, af.iface)
	a, err := ap.Start(af.config())
	if err != nil {
		return err
	}
	defer func() {
		if err := fw.Down(); err != nil {
			logf("%v", err)
		}
		a.Stop()
	}()
	if err := fw.Up(fw.Config{AP: af.iface, Uplink: af.uplink, Logf: verboseLog(af.verbose)}); err != nil {
		return err
	}

	ctx, cancel := signalContext()
	defer cancel()
	if *dur > 0 {
		var c2 context.CancelFunc
		ctx, c2 = context.WithTimeout(ctx, *dur)
		defer c2()
	}

	rec := discover.NewRecorder(af.gw)
	logf("watching %s. Join the device, then power-cycle it so it syncs time. Ctrl-C for the report.", af.iface)
	err = discover.Capture(ctx, af.iface, func(frame []byte) {
		ev, ok := discover.ParseFrame(frame)
		if !ok {
			return
		}
		if rec.Add(ev) {
			if ev.Kind == discover.KindDNS && !af.verbose && !discover.TimeishName(ev.Detail) {
				return
			}
			v6 := ""
			if ev.IPv6 {
				v6 = " (IPv6)"
			}
			logf("%s %-9s %s%s", ev.MAC, ev.Kind, ev.Detail, v6)
		}
	})
	fmt.Fprintln(os.Stdout, "\n========== TIM discover report ==========")
	rec.Report(os.Stdout)
	return err
}

func cmdDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	iface := fs.String("ap", "", "AP interface to give back to NetworkManager")
	gw := fs.String("gw", "10.77.0.1", "AP-side IP that was used")
	fs.Parse(args)
	if err := requireRoot(); err != nil {
		return err
	}
	err := fw.Down()
	ap.Cleanup(*iface, *gw)
	if err == nil {
		logf("removed TIM firewall rules, stopped hostapd/dnsmasq, restored ip_forward.")
	}
	return err
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	iface := fs.String("ap", "", "AP interface to check")
	uplink := fs.String("uplink", "", "uplink interface to check")
	fs.Parse(args)

	bad := 0
	report := func(ok bool, msg string, fix string) {
		mark := "ok  "
		if !ok {
			mark = "FAIL"
			bad++
		}
		fmt.Printf("[%s] %s\n", mark, msg)
		if !ok && fix != "" {
			fmt.Printf("       -> %s\n", fix)
		}
	}
	report(os.Geteuid() == 0, "running as root", "re-run with sudo")
	for _, bin := range []string{"hostapd", "dnsmasq", "iptables", "ip", "iw"} {
		_, err := exec.LookPath(bin)
		report(err == nil, "found "+bin, "sudo apt install hostapd dnsmasq iptables iproute2 iw")
	}
	if *iface != "" {
		_, err := net.InterfaceByName(*iface)
		report(err == nil, "AP interface "+*iface+" exists", "check `iw dev`")
		if err == nil {
			ok, detail := supportsAP(*iface)
			report(ok, "AP interface "+*iface+" supports AP mode "+detail, "use a card/driver that lists 'AP' in `iw list` under 'Supported interface modes'")
		}
		if out, err := exec.Command("nmcli", "-t", "-f", "DEVICE,STATE", "device").Output(); err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(l, *iface+":") && strings.Contains(l, ":connected") {
					report(false, *iface+" is connected to a network by NetworkManager", "TIM will take it over; make sure that's not your uplink")
				}
			}
		}
	}
	if *uplink != "" {
		out, _ := exec.Command("ip", "route", "show", "default").Output()
		report(strings.Contains(string(out), "dev "+*uplink), "default route goes via "+*uplink, "connect the uplink to the internet first")
	}
	for _, p := range []string{"udp:67", "udp:53"} {
		proto, port, _ := strings.Cut(p, ":")
		out, _ := exec.Command("ss", "-lnp", "-"+proto[:1]).Output()
		busy := ""
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) >= 5 && (strings.HasSuffix(f[4], ":"+port) && (strings.HasPrefix(f[4], "0.0.0.0") || strings.HasPrefix(f[4], "*"))) {
				busy = l
			}
		}
		report(busy == "", fmt.Sprintf("%s/%s not bound to all interfaces by another program", proto, port), "stop it (often dnsmasq or systemd-resolved): "+strings.TrimSpace(busy))
	}
	if bad > 0 {
		return fmt.Errorf("%d check(s) failed", bad)
	}
	fmt.Println("all good.")
	return nil
}

// supportsAP parses `iw phy<N> info` for the phy behind iface.
func supportsAP(iface string) (bool, string) {
	b, err := os.ReadFile("/sys/class/net/" + iface + "/phy80211/name")
	if err != nil {
		return false, "(not a wireless interface?)"
	}
	phy := strings.TrimSpace(string(b))
	out, err := exec.Command("iw", "phy", phy, "info").Output()
	if err != nil {
		return false, "(iw failed)"
	}
	in := false
	for _, l := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "Supported interface modes") {
			in = true
			continue
		}
		if in {
			if !strings.HasPrefix(t, "*") {
				break
			}
			if t == "* AP" {
				return true, "(" + phy + ")"
			}
		}
	}
	return false, "(" + phy + ")"
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdCerts(args []string) error {
	fs := flag.NewFlagSet("certs", flag.ExitOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "connect timeout")
	var rootFiles multiFlag
	fs.Var(&rootFiles, "root", "device's trusted root cert or CA bundle (PEM/DER); repeatable")
	hokDir := fs.String("hok", os.Getenv("TIM_HOK"), "dataset directory, fingerprint cache file, or off (default: local cache; TIM_HOK supported)")
	exportFile := fs.String("export", "", "export one target's observed chain to a new PEM file (not automatically trusted)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: tim certs [flags] host[:port] | cert-file ...")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() == 0 {
		fs.Usage()
		return errors.New("no targets")
	}

	if *exportFile != "" && fs.NArg() != 1 {
		return errors.New("--export requires exactly one target")
	}
	opts := certs.Options{Now: time.Now()}
	for _, f := range rootFiles {
		rs, err := certs.LoadFile(f)
		if err != nil {
			return fmt.Errorf("--root: %w", err)
		}
		opts.Roots = append(opts.Roots, rs...)
	}
	if len(opts.Roots) > 0 {
		fmt.Printf("device roots: %d certificate(s) from %s\n", len(opts.Roots), strings.Join(rootFiles, ", "))
	}
	if *hokDir != "off" {
		var h *certs.HoK
		var err error
		if *hokDir == "" {
			var file string
			file, err = certs.HoKCachePath()
			if err == nil {
				h, err = certs.LoadHoKCache(file)
			}
			if err != nil {
				logf("House of Keys cache unavailable: %v (run tim hok update; --hok off disables)", err)
				err = nil
			}
		} else if st, statErr := os.Stat(*hokDir); statErr == nil && st.IsDir() {
			h, err = certs.LoadHoK(*hokDir)
		} else {
			h, err = certs.LoadHoKCache(*hokDir)
		}
		if err != nil {
			return fmt.Errorf("--hok: %w", err)
		}
		opts.HoK = h
		if h != nil {
			fmt.Printf("House of Keys: %d known-compromised public keys\n", h.Len())
		}
	}
	fmt.Println()

	var failed int
	for _, t := range fs.Args() {
		var chain []*x509.Certificate
		o := opts
		if st, err := os.Stat(t); err == nil && !st.IsDir() {
			chain, err = certs.LoadFile(t)
			if err != nil {
				if ders, derr := certs.LoadDERs(t); derr == nil && len(ders) > 0 {
					if *exportFile != "" {
						return fmt.Errorf("cannot export unparseable certificate: %w", err)
					}
					certs.PrintRaw(os.Stdout, t, ders, err, o)
					fmt.Println()
					continue
				}
				fmt.Printf("%s\n  error: %v\n\n", t, err)
				failed++
				continue
			}
		} else {
			var host string
			chain, host, err = certs.Fetch(t, *timeout)
			if err != nil {
				fmt.Printf("%s\n  error: %v\n", t, err)
				fmt.Printf("  (if the certificate itself is malformed, save it with\n   openssl s_client -connect %s -showcerts </dev/null > chain.pem\n   and run: tim certs chain.pem)\n\n", t)
				failed++
				continue
			}
			o.Host = host
		}
		if *exportFile != "" {
			if err := certs.Export(*exportFile, chain); err != nil {
				return fmt.Errorf("export: %w", err)
			}
			fmt.Printf("Exported observed chain to %s (not a verified trust bundle).\n", *exportFile)
		}
		certs.Print(os.Stdout, t, chain, o)
		fmt.Println()
	}
	if failed > 0 {
		return fmt.Errorf("%d target(s) failed", failed)
	}
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var cf clockFlags
	cf.register(fs)
	listen := fs.String("listen", "127.0.0.1", "address to listen on")
	spoofList := fs.String("spoof", "all", "comma-separated spoofers: "+strings.Join(allSpoofers, ","))
	std := fs.Bool("std-ports", false, "use the real ports (123/37/13/80) instead of 10123/10037/10013/10080 (needs root)")
	fs.Parse(args)

	clk, err := cf.build()
	if err != nil {
		return err
	}
	enabled, err := parseSpoof(*spoofList)
	if err != nil {
		return err
	}
	ports := [4]int{portNTP, portTime37, portDaytime, portHTTP}
	if *std {
		ports = [4]int{123, 37, 13, 80}
	}
	svcs, _, err := startSpoofers(*listen, enabled, nil, clk, ports)
	if err != nil {
		return err
	}
	defer func() {
		for _, s := range svcs {
			s.Close()
		}
	}()
	logf("fake time: %s", clk.Describe())
	for _, s := range svcs {
		logf("%-8s listening on %s", s.Name(), s.Addr())
	}
	ctx, cancel := signalContext()
	defer cancel()
	<-ctx.Done()
	return nil
}

func cmdHoK(args []string) error {
	if len(args) != 1 || args[0] != "update" {
		return errors.New("usage: tim hok update")
	}
	file, err := certs.HoKCachePath()
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	h, err := certs.UpdateHoK(ctx, file)
	if err != nil {
		return err
	}
	fmt.Printf("Cached %d public-key fingerprints from %s in %s; temporary raw dataset removed.\n", h.Len(), certs.HoKCommit, file)
	return nil
}
