package discover

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

var clientMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}

func frame(proto byte, src, dst string, l4 []byte) []byte {
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{1, 2, 3, 4, 5, 6})
	copy(eth[6:12], clientMAC)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())
	out := append(eth, ip...)
	out = append(out, l4...)
	return append(out, 0, 0, 0, 0) // Ethernet padding should be ignored
}

func udp(dport uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], 40000)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

func tcp(dport uint16, flags byte, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], 40000)
	binary.BigEndian.PutUint16(h[2:], dport)
	h[12] = 5 << 4
	h[13] = flags
	return append(h, payload...)
}

func dnsQuery(name string) []byte {
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p[4:], 1)
	for _, l := range strings.Split(name, ".") {
		p = append(p, byte(len(l)))
		p = append(p, l...)
	}
	return append(p, 0, 0, 1, 0, 1)
}

func clientHello(t *testing.T, sni string) []byte {
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		c.SetDeadline(time.Now().Add(time.Second))
		c.Handshake()
		a.Close()
	}()
	buf := make([]byte, 4096)
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	return buf[:n]
}

func TestParseFrame(t *testing.T) {
	ntp := make([]byte, 48)
	ntp[0] = 4<<3 | 3
	ntpResp := make([]byte, 48)
	ntpResp[0] = 4<<3 | 4

	cases := []struct {
		name   string
		frame  []byte
		kind   string
		detail string
	}{
		{"ntp", frame(17, "10.77.0.23", "162.159.200.1", udp(123, ntp)), KindNTP, "v4 -> 162.159.200.1"},
		{"time37 udp", frame(17, "10.77.0.23", "1.2.3.4", udp(37, nil)), KindTime37, "udp -> 1.2.3.4"},
		{"time37 tcp", frame(6, "10.77.0.23", "1.2.3.4", tcp(37, 0x02, nil)), KindTime37, "tcp -> 1.2.3.4"},
		{"daytime", frame(6, "10.77.0.23", "1.2.3.4", tcp(13, 0x02, nil)), KindDaytime, "tcp -> 1.2.3.4"},
		{"nts", frame(6, "10.77.0.23", "1.2.3.4", tcp(4460, 0x02, nil)), KindNTSKE, "-> 1.2.3.4"},
		{"dns", frame(17, "10.77.0.23", "10.77.0.1", udp(53, dnsQuery("Pool.NTP.org"))), KindDNS, "pool.ntp.org"},
		{"http", frame(6, "10.77.0.23", "93.184.216.34", tcp(80, 0x18, []byte("GET /time HTTP/1.1\r\nhost: example.com\r\n\r\n"))), KindHTTP, "GET /time example.com:80"},
		{"tls", frame(6, "10.77.0.23", "1.2.3.4", tcp(443, 0x18, clientHello(t, "api.vendor.example"))), KindTLS, "api.vendor.example:443"},
	}
	for _, c := range cases {
		ev, ok := ParseFrame(c.frame)
		if !ok || ev.Kind != c.kind || ev.Detail != c.detail || ev.MAC != clientMAC.String() {
			t.Errorf("%s: got %+v ok=%v", c.name, ev, ok)
		}
	}

	ignored := map[string][]byte{
		"ntp response": frame(17, "1.2.3.4", "10.77.0.23", udp(123, ntpResp)),
		"tcp ack":      frame(6, "10.77.0.23", "1.2.3.4", tcp(37, 0x10, nil)),
		"random udp":   frame(17, "10.77.0.23", "1.2.3.4", udp(9999, []byte("x"))),
		"short":        {1, 2, 3},
	}
	for name, f := range ignored {
		if ev, ok := ParseFrame(f); ok {
			t.Errorf("%s: should be ignored, got %+v", name, ev)
		}
	}
}

func TestRecorderReport(t *testing.T) {
	r := NewRecorder("10.77.0.1")
	mac := clientMAC.String()
	if !r.Add(Event{MAC: mac, Src: "10.77.0.23", Kind: KindNTP, Detail: "v4 -> 1.2.3.4"}) {
		t.Error("first event should be new")
	}
	if r.Add(Event{MAC: mac, Src: "10.77.0.23", Kind: KindNTP, Detail: "v4 -> 1.2.3.4"}) {
		t.Error("duplicate should not be new")
	}
	r.Add(Event{MAC: mac, Src: "10.77.0.23", Kind: KindNTSKE, Detail: "-> 5.6.7.8"})
	r.Add(Event{MAC: mac, Src: "10.77.0.23", Kind: KindDNS, Detail: "time.vendor.example"})
	r.Add(Event{MAC: mac, Src: "10.77.0.23", Kind: KindTLS, Detail: "api.vendor.example:443"})
	r.Add(Event{MAC: "11:11:11:11:11:11", Src: "10.77.0.1", Kind: KindDNS, Detail: "ignored.example"})

	var buf bytes.Buffer
	r.Report(&buf)
	out := buf.String()
	for _, want := range []string{"x2", "dns(time)  time.vendor.example", "--spoof ntp --block-nts", "tim certs", "api.vendor.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ignored.example") {
		t.Error("gateway traffic should be ignored")
	}
}
