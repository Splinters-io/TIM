package spoof

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// simpleServer serves a fixed-format time answer over TCP (send and close)
// and UDP (any datagram gets one reply). RFC 868 Time and RFC 867 Daytime
// both work this way.
type simpleServer struct {
	name   string
	ln     net.Listener
	pc     net.PacketConn
	clk    Clock
	logf   Logf
	encode func(time.Time) []byte
}

func newSimple(name, addr string, clk Clock, logf Logf, encode func(time.Time) []byte) (*simpleServer, error) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	// Bind UDP on the same port TCP got (matters when addr uses port 0).
	pc, err := net.ListenPacket("udp4", ln.Addr().String())
	if err != nil {
		ln.Close()
		return nil, err
	}
	return &simpleServer{name: name, ln: ln, pc: pc, clk: clk, logf: logf, encode: encode}, nil
}

// NewTime37 is an RFC 868 Time server: 32-bit big-endian seconds since 1900.
func NewTime37(addr string, clk Clock, logf Logf) (Service, error) {
	return newSimple("time37", addr, clk, logf, func(t time.Time) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, ntpSeconds(t))
		return b
	})
}

// NewDaytime is an RFC 867 Daytime server. It uses the ctime-style format
// that inetd's built-in daytime service sends.
func NewDaytime(addr string, clk Clock, logf Logf) (Service, error) {
	return newSimple("daytime", addr, clk, logf, func(t time.Time) []byte {
		return []byte(t.Format(time.ANSIC) + "\r\n")
	})
}

func (s *simpleServer) Name() string { return s.name }
func (s *simpleServer) Addr() string { return s.ln.Addr().String() }

func (s *simpleServer) Close() error {
	err1 := s.ln.Close()
	err2 := s.pc.Close()
	return errors.Join(err1, err2)
}

func (s *simpleServer) Serve() error {
	var wg sync.WaitGroup
	errc := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errc <- s.serveTCP() }()
	go func() { defer wg.Done(); errc <- s.serveUDP() }()
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *simpleServer) serveTCP() error {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			now := s.clk.Now()
			c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(s.encode(now)); err == nil {
				s.logf("%s: %s (tcp) <- %s", s.name, c.RemoteAddr(), now.Format(time.RFC3339))
			}
		}(c)
	}
}

func (s *simpleServer) serveUDP() error {
	buf := make([]byte, 512)
	for {
		_, peer, err := s.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		now := s.clk.Now()
		if _, err := s.pc.WriteTo(s.encode(now), peer); err == nil {
			s.logf("%s: %s (udp) <- %s", s.name, peer, now.Format(time.RFC3339))
		}
	}
}
