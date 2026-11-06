package discover

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Recorder collects events per client and deduplicates them.
type Recorder struct {
	mu      sync.Mutex
	clients map[string]*client // by MAC
	gateway string             // our own AP IP; traffic from it is ignored
}

type client struct {
	ips   map[string]bool
	first time.Time
	seen  map[string]map[string]int // kind -> detail -> count
}

func NewRecorder(gateway string) *Recorder {
	return &Recorder{clients: map[string]*client{}, gateway: gateway}
}

// Add records an event. It returns true the first time a (MAC, kind,
// detail) combination is seen, so the caller can print it live.
func (r *Recorder) Add(ev Event) bool {
	if ev.Src == r.gateway {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.clients[ev.MAC]
	if c == nil {
		c = &client{ips: map[string]bool{}, first: time.Now(), seen: map[string]map[string]int{}}
		r.clients[ev.MAC] = c
	}
	if ev.Src != "" && ev.Src != "0.0.0.0" {
		c.ips[ev.Src] = true
	}
	k := ev.Kind
	if ev.IPv6 {
		k += "6"
	}
	if c.seen[k] == nil {
		c.seen[k] = map[string]int{}
	}
	c.seen[k][ev.Detail]++
	return c.seen[k][ev.Detail] == 1
}

func base(kind string) string { return strings.TrimSuffix(kind, "6") }

// Report writes a per-client summary and recommends a `tim up` command.
func (r *Recorder) Report(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.clients) == 0 {
		fmt.Fprintln(w, "No client traffic seen. Did the device join the AP? Try power-cycling it while discover is running, since many devices only sync time at boot.")
		return
	}
	macs := make([]string, 0, len(r.clients))
	for m := range r.clients {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	for _, mac := range macs {
		c := r.clients[mac]
		fmt.Fprintf(w, "\n== Client %s  (%s)\n", mac, strings.Join(sortedKeys(c.ips), ", "))
		kinds := sortedKeys2(c.seen)
		for _, k := range kinds {
			if base(k) == KindDNS {
				continue
			}
			fmt.Fprintf(w, "  %-10s", k)
			first := true
			for _, d := range sortedKeys3(c.seen[k]) {
				if !first {
					fmt.Fprintf(w, "  %-10s", "")
				}
				fmt.Fprintf(w, "%s  (x%d)\n", d, c.seen[k][d])
				first = false
			}
		}
		var timeish, other []string
		for _, k := range []string{KindDNS, KindDNS + "6"} {
			for name := range c.seen[k] {
				if TimeishName(name) {
					timeish = append(timeish, name)
				} else {
					other = append(other, name)
				}
			}
		}
		sort.Strings(timeish)
		sort.Strings(other)
		if len(timeish) > 0 {
			fmt.Fprintf(w, "  dns(time)  %s\n", strings.Join(timeish, ", "))
		}
		if len(other) > 0 {
			fmt.Fprintf(w, "  dns(other) %s\n", strings.Join(other, ", "))
		}
		r.recommend(w, mac, c)
	}
}

func (r *Recorder) recommend(w io.Writer, mac string, c *client) {
	has := func(kind string) bool { return len(c.seen[kind]) > 0 || len(c.seen[kind+"6"]) > 0 }
	var spoof, notes []string
	if has(KindNTP) {
		spoof = append(spoof, "ntp")
	}
	if has(KindTime37) {
		spoof = append(spoof, "time37")
	}
	if has(KindDaytime) {
		spoof = append(spoof, "daytime")
	}
	if has(KindHTTP) {
		spoof = append(spoof, "http")
		notes = append(notes, "Plain HTTP seen. Some devices read the clock from the HTTP Date header, so the http spoofer is included.")
	}
	blockNTS := false
	if has(KindNTSKE) {
		blockNTS = true
		notes = append(notes, "NTS (authenticated NTP) seen. It can't be spoofed. --block-nts rejects it, and some clients then fall back to plain NTP.")
	}
	if has(KindRoughtime) {
		notes = append(notes, "Roughtime seen. Responses are signed and can't be spoofed.")
	}
	if has(KindPTP) {
		notes = append(notes, "PTP seen. TIM does not spoof PTP.")
	}
	for _, k := range []string{KindNTP, KindTime37, KindDaytime, KindHTTP, KindDNS} {
		if len(c.seen[k+"6"]) > 0 {
			notes = append(notes, "The device also uses IPv6. The TIM AP hands out IPv4 only, so this traffic came from a link-local or cached setup and isn't intercepted.")
			break
		}
	}
	var sni []string
	for d := range c.seen[KindTLS] {
		sni = append(sni, strings.SplitN(d, " ", 2)[0])
	}
	sort.Strings(sni)
	if len(sni) > 0 {
		notes = append(notes, fmt.Sprintf("TLS hosts contacted: %s. Run `tim certs <host>` on each to see which certificate expired and pick a --time inside its validity window.", strings.Join(sni, ", ")))
	}
	if len(spoof) == 0 {
		notes = append(notes, "No spoofable time request seen. The device may get time over HTTPS (unspoofable), from a battery RTC, GPS or cellular, or only at cold boot. Power-cycle it with discover running, and leave it at least 2 minutes.")
	}

	fmt.Fprintln(w, "  --")
	for _, n := range notes {
		fmt.Fprintf(w, "  * %s\n", n)
	}
	if len(spoof) > 0 {
		cmd := fmt.Sprintf("tim up ... --target %s --spoof %s", mac, strings.Join(spoof, ","))
		if blockNTS {
			cmd += " --block-nts"
		}
		fmt.Fprintf(w, "  Suggested: %s --time <before-expiry>\n", cmd)
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys2(m map[string]map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys3(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
