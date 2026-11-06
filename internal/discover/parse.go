// Package discover watches traffic on the AP interface and works out how a
// device tries to learn the time.
package discover

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Kinds of time-relevant traffic.
const (
	KindNTP       = "ntp"
	KindTime37    = "time37"
	KindDaytime   = "daytime"
	KindNTSKE     = "nts-ke"
	KindRoughtime = "roughtime"
	KindPTP       = "ptp"
	KindDNS       = "dns"
	KindHTTP      = "http"
	KindTLS       = "tls"
)

// Event is one interesting packet from a client.
type Event struct {
	MAC    string
	Src    string
	Dst    string
	Kind   string
	Detail string
	IPv6   bool
}

// ParseFrame decodes an Ethernet frame. It returns an event if the frame is
// a client request worth reporting.
func ParseFrame(b []byte) (Event, bool) {
	if len(b) < 14 {
		return Event{}, false
	}
	mac := net.HardwareAddr(b[6:12]).String()
	etype := binary.BigEndian.Uint16(b[12:14])
	p := b[14:]
	if etype == 0x8100 && len(p) >= 4 { // 802.1Q VLAN tag
		etype = binary.BigEndian.Uint16(p[2:4])
		p = p[4:]
	}
	var ev Event
	var proto byte
	var l4 []byte
	switch etype {
	case 0x0800:
		if len(p) < 20 || p[0]>>4 != 4 {
			return Event{}, false
		}
		ihl := int(p[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(p[2:4]))
		if ihl < 20 || len(p) < ihl {
			return Event{}, false
		}
		if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 { // not the first fragment
			return Event{}, false
		}
		if total >= ihl && total < len(p) {
			p = p[:total] // drop Ethernet padding
		}
		proto = p[9]
		ev.Src, ev.Dst = net.IP(p[12:16]).String(), net.IP(p[16:20]).String()
		l4 = p[ihl:]
	case 0x86DD:
		if len(p) < 40 {
			return Event{}, false
		}
		proto = p[6] // no extension-header walking; enough for NTP/DNS/TCP
		ev.Src, ev.Dst = net.IP(p[8:24]).String(), net.IP(p[24:40]).String()
		ev.IPv6 = true
		l4 = p[40:]
	default:
		return Event{}, false
	}
	ev.MAC = mac

	switch proto {
	case 17: // UDP
		if len(l4) < 8 {
			return Event{}, false
		}
		dport := binary.BigEndian.Uint16(l4[2:4])
		return classifyUDP(ev, dport, l4[8:])
	case 6: // TCP
		if len(l4) < 20 {
			return Event{}, false
		}
		dport := binary.BigEndian.Uint16(l4[2:4])
		off := int(l4[12]>>4) * 4
		flags := l4[13]
		if off < 20 || len(l4) < off {
			return Event{}, false
		}
		return classifyTCP(ev, dport, flags, l4[off:])
	}
	return Event{}, false
}

func classifyUDP(ev Event, dport uint16, payload []byte) (Event, bool) {
	switch dport {
	case 123:
		if len(payload) < 48 {
			return Event{}, false
		}
		vn, mode := (payload[0]>>3)&7, payload[0]&7
		if mode != 3 && mode != 1 && mode != 0 { // client requests only
			return Event{}, false
		}
		ev.Kind, ev.Detail = KindNTP, fmt.Sprintf("v%d -> %s", vn, ev.Dst)
		return ev, true
	case 37:
		ev.Kind, ev.Detail = KindTime37, "udp -> "+ev.Dst
		return ev, true
	case 13:
		ev.Kind, ev.Detail = KindDaytime, "udp -> "+ev.Dst
		return ev, true
	case 2002:
		ev.Kind, ev.Detail = KindRoughtime, "-> "+ev.Dst
		return ev, true
	case 319, 320:
		ev.Kind, ev.Detail = KindPTP, "-> "+ev.Dst
		return ev, true
	case 53:
		name, ok := dnsQuestion(payload)
		if !ok {
			return Event{}, false
		}
		ev.Kind, ev.Detail = KindDNS, name
		return ev, true
	}
	return Event{}, false
}

func classifyTCP(ev Event, dport uint16, flags byte, payload []byte) (Event, bool) {
	syn := flags&0x02 != 0 && flags&0x10 == 0 // SYN without ACK = new connection
	switch dport {
	case 37:
		if syn {
			ev.Kind, ev.Detail = KindTime37, "tcp -> "+ev.Dst
			return ev, true
		}
		return Event{}, false
	case 13:
		if syn {
			ev.Kind, ev.Detail = KindDaytime, "tcp -> "+ev.Dst
			return ev, true
		}
		return Event{}, false
	case 4460:
		if syn {
			ev.Kind, ev.Detail = KindNTSKE, "-> "+ev.Dst
			return ev, true
		}
		return Event{}, false
	}
	if len(payload) == 0 {
		return Event{}, false
	}
	if host, line, ok := httpRequest(payload); ok {
		ev.Kind = KindHTTP
		if host == "" {
			host = ev.Dst
		}
		ev.Detail = fmt.Sprintf("%s %s:%d", line, host, dport)
		return ev, true
	}
	if sni, ok := tlsSNI(payload); ok {
		ev.Kind = KindTLS
		if sni == "" {
			sni = "(no SNI) " + ev.Dst
		}
		ev.Detail = fmt.Sprintf("%s:%d", sni, dport)
		return ev, true
	}
	return Event{}, false
}

func dnsQuestion(p []byte) (string, bool) {
	if len(p) < 12 || p[2]&0x80 != 0 { // too short, or a response
		return "", false
	}
	if binary.BigEndian.Uint16(p[4:6]) == 0 {
		return "", false
	}
	var labels []string
	i := 12
	for i < len(p) {
		l := int(p[i])
		if l == 0 {
			return strings.ToLower(strings.Join(labels, ".")), len(labels) > 0
		}
		if l&0xc0 != 0 || i+1+l > len(p) {
			return "", false
		}
		labels = append(labels, string(p[i+1:i+1+l]))
		i += 1 + l
	}
	return "", false
}

var httpMethods = [][]byte{[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("OPTIONS "), []byte("DELETE "), []byte("PATCH ")}

func httpRequest(p []byte) (host, line string, ok bool) {
	matched := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(p, m) {
			matched = true
			break
		}
	}
	if !matched {
		return "", "", false
	}
	lines := strings.Split(string(p), "\r\n")
	first := strings.Fields(lines[0])
	if len(first) >= 2 {
		path := first[1]
		if len(path) > 60 {
			path = path[:60] + "..."
		}
		line = first[0] + " " + path
	}
	for _, l := range lines[1:] {
		if k, v, found := strings.Cut(l, ":"); found && strings.EqualFold(strings.TrimSpace(k), "host") {
			host = strings.TrimSpace(v)
			break
		}
	}
	return host, line, true
}

// tlsSNI pulls the server name out of a TLS ClientHello. ok is true for any
// ClientHello, even one without SNI.
func tlsSNI(p []byte) (string, bool) {
	// record: type(1)=22 version(2) len(2); handshake: type(1)=1 len(3)
	if len(p) < 9 || p[0] != 0x16 || p[1] != 0x03 || p[5] != 0x01 {
		return "", false
	}
	h := p[9:]
	// client_version(2) random(32)
	if len(h) < 34 {
		return "", true
	}
	h = h[34:]
	skip := func(n int) bool {
		if len(h) < n {
			return false
		}
		h = h[n:]
		return true
	}
	vec := func(lenBytes int) bool {
		if len(h) < lenBytes {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(h[i])
		}
		return skip(lenBytes + n)
	}
	if !vec(1) || !vec(2) || !vec(1) { // session id, cipher suites, compression
		return "", true
	}
	if len(h) < 2 {
		return "", true
	}
	h = h[2:] // extensions total length
	for len(h) >= 4 {
		typ := binary.BigEndian.Uint16(h[0:2])
		l := int(binary.BigEndian.Uint16(h[2:4]))
		if len(h) < 4+l {
			return "", true
		}
		data := h[4 : 4+l]
		h = h[4+l:]
		if typ != 0 { // server_name
			continue
		}
		// list len(2), then entries: type(1) len(2) name
		if len(data) < 5 || data[2] != 0 {
			return "", true
		}
		n := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+n {
			return "", true
		}
		return strings.ToLower(string(data[5 : 5+n])), true
	}
	return "", true
}

// TimeishName reports whether a DNS name looks like a time service.
func TimeishName(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"ntp", "time.", "time-", "chrony", "clock", "roughtime", "tlsdate", "nts.", "ptp"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}
