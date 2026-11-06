package spoof

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

var fake = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func nolog(string, ...any) {}

func TestNTPTimestampKnownValues(t *testing.T) {
	// 2024-01-01T00:00:00Z: Unix 1704067200, NTP 3913056000.
	if got := ntpSeconds(fake); got != 3913056000 {
		t.Fatalf("ntpSeconds = %d", got)
	}
	// Era rollover: 2036-02-07T06:28:16Z is NTP seconds 0 in era 1.
	rollover := time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)
	if got := ntpSeconds(rollover); got != 0 {
		t.Fatalf("era rollover = %d", got)
	}
	// Round trip with sub-second precision, across eras.
	for _, tm := range []time.Time{fake.Add(123456789 * time.Nanosecond), rollover.Add(90 * 24 * time.Hour), time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC)} {
		got := ntpTime(ntpTimestamp(tm), tm)
		if d := got.Sub(tm); d < -time.Microsecond || d > time.Microsecond {
			t.Errorf("round trip %v -> %v", tm, got)
		}
	}
}

func clientPacket(vn, mode byte, xmit uint64) []byte {
	p := make([]byte, 48)
	p[0] = vn<<3 | mode
	p[2] = 6
	binary.BigEndian.PutUint64(p[40:], xmit)
	return p
}

func TestBuildNTPReply(t *testing.T) {
	ref := [4]byte{10, 77, 0, 1}
	for _, vn := range []byte{1, 2, 3, 4} {
		req := clientPacket(vn, 3, 0xdeadbeefcafebabe)
		resp, gotVN, ok := BuildNTPReply(req, fake, fake.Add(time.Millisecond), ref)
		if !ok || gotVN != int(vn) {
			t.Fatalf("v%d: ok=%v vn=%d", vn, ok, gotVN)
		}
		if resp[0] != vn<<3|4 {
			t.Errorf("v%d: li/vn/mode = %08b", vn, resp[0])
		}
		if resp[1] != 2 {
			t.Errorf("stratum = %d", resp[1])
		}
		if binary.BigEndian.Uint64(resp[24:]) != 0xdeadbeefcafebabe {
			t.Errorf("origin timestamp not echoed")
		}
		if got := ntpTime(binary.BigEndian.Uint64(resp[40:]), fake); got.Sub(fake)-time.Millisecond > time.Microsecond || got.Sub(fake) < time.Millisecond-time.Microsecond {
			t.Errorf("tx = %v", got)
		}
	}
	// Symmetric active (mode 1) gets symmetric passive (mode 2).
	if resp, _, ok := BuildNTPReply(clientPacket(4, 1, 1), fake, fake, ref); !ok || resp[0]&7 != 2 {
		t.Errorf("symmetric mode reply wrong")
	}
	// Ignore control mode, server mode, bad version, short packets.
	for _, req := range [][]byte{clientPacket(4, 6, 0), clientPacket(4, 4, 0), clientPacket(0, 3, 0), clientPacket(5, 3, 0), make([]byte, 20)} {
		if _, _, ok := BuildNTPReply(req, fake, fake, ref); ok {
			t.Errorf("should ignore %x", req[:1])
		}
	}
}

func TestNTPServer(t *testing.T) {
	srv, err := NewNTP("127.0.0.1:0", fixedClock{fake}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	defer srv.Close()

	c, err := net.Dial("udp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(clientPacket(4, 3, 42))
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil || n != 48 {
		t.Fatalf("read %d, %v", n, err)
	}
	if got := ntpTime(binary.BigEndian.Uint64(buf[40:]), fake); !got.Equal(fake) {
		t.Errorf("server time = %v", got)
	}
}

func TestTime37AndDaytime(t *testing.T) {
	t37, err := NewTime37("127.0.0.1:0", fixedClock{fake}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	go t37.Serve()
	defer t37.Close()

	c, err := net.Dial("tcp", t37.Addr())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(c)
	c.Close()
	if len(b) != 4 || binary.BigEndian.Uint32(b) != 3913056000 {
		t.Errorf("time37 tcp = %x", b)
	}

	u, _ := net.Dial("udp", t37.Addr())
	u.SetDeadline(time.Now().Add(2 * time.Second))
	u.Write([]byte{0})
	ub := make([]byte, 16)
	n, err := u.Read(ub)
	u.Close()
	if err != nil || n != 4 || binary.BigEndian.Uint32(ub) != 3913056000 {
		t.Errorf("time37 udp = %x %v", ub[:n], err)
	}

	dt, err := NewDaytime("127.0.0.1:0", fixedClock{fake}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	go dt.Serve()
	defer dt.Close()
	c2, _ := net.Dial("tcp", dt.Addr())
	line, _ := bufio.NewReader(c2).ReadString('\n')
	c2.Close()
	if line != "Mon Jan  1 00:00:00 2024\r\n" {
		t.Errorf("daytime = %q", line)
	}
}

func TestHTTPDateRewrite(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Path", r.URL.Path)
		w.Header().Set("X-Has-XFF", r.Header.Get("X-Forwarded-For"))
		io.WriteString(w, "hello from upstream")
	}))
	defer upstream.Close()

	p, err := NewHTTPDate("127.0.0.1:0", fixedClock{fake}, nolog, nil)
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	defer p.Close()

	// Send it the way a REDIRECTed device would: to the proxy, with Host
	// set to the real site.
	req, _ := http.NewRequest("GET", "http://"+p.Addr()+"/some/path", nil)
	req.Host = strings.TrimPrefix(upstream.URL, "http://")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if got := resp.Header.Get("Date"); got != "Mon, 01 Jan 2024 00:00:00 GMT" {
		t.Errorf("Date = %q", got)
	}
	if string(body) != "hello from upstream" || resp.Header.Get("X-Path") != "/some/path" {
		t.Errorf("proxying broken: %q %q", body, resp.Header.Get("X-Path"))
	}
	if resp.Header.Get("X-Has-XFF") != "" {
		t.Errorf("proxy should not add X-Forwarded-For")
	}
}
