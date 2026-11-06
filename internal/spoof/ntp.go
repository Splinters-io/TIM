package spoof

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

const ntpPacketLen = 48

// NTP answers NTP/SNTP v1-v4 client requests with the fake time.
type NTP struct {
	conn  net.PacketConn
	clk   Clock
	logf  Logf
	refID [4]byte
}

// NewNTP listens on a UDP address (e.g. "10.77.0.1:10123").
func NewNTP(addr string, clk Clock, logf Logf) (*NTP, error) {
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, err
	}
	n := &NTP{conn: conn, clk: clk, logf: logf}
	// Stratum 2 servers put their upstream's IPv4 address in the reference
	// ID. Use our own listen address, which looks plausible.
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if ip4 := ua.IP.To4(); ip4 != nil && !ip4.IsUnspecified() {
			copy(n.refID[:], ip4)
		}
	}
	if n.refID == [4]byte{} {
		n.refID = [4]byte{10, 77, 0, 1}
	}
	return n, nil
}

func (n *NTP) Name() string { return "ntp" }
func (n *NTP) Addr() string { return n.conn.LocalAddr().String() }
func (n *NTP) Close() error { return n.conn.Close() }

func (n *NTP) Serve() error {
	buf := make([]byte, 1024)
	for {
		sz, peer, err := n.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		rx := n.clk.Now()
		resp, vn, ok := BuildNTPReply(buf[:sz], rx, rx, n.refID)
		if !ok {
			continue
		}
		// Stamp the transmit time as late as possible.
		binary.BigEndian.PutUint64(resp[40:], ntpTimestamp(n.clk.Now()))
		if _, err := n.conn.WriteTo(resp, peer); err != nil {
			n.logf("ntp: reply to %s failed: %v", peer, err)
			continue
		}
		n.logf("ntp: %s (v%d) <- %s", peer, vn, rx.Format(time.RFC3339))
	}
}

// BuildNTPReply builds a server response to an NTP client request. It
// returns ok=false for packets we should ignore (too short, control/private
// modes, or a bad version).
func BuildNTPReply(req []byte, rx, tx time.Time, refID [4]byte) (resp []byte, version int, ok bool) {
	if len(req) < ntpPacketLen {
		return nil, 0, false
	}
	vn := (req[0] >> 3) & 0x7
	mode := req[0] & 0x7
	if vn < 1 || vn > 4 {
		return nil, 0, false
	}
	var rmode byte
	switch mode {
	case 3, 0: // client (mode 0 = NTPv1-style client)
		rmode = 4 // server
	case 1: // symmetric active
		rmode = 2 // symmetric passive
	default: // 2,4,5 are not requests; 6,7 are control/private
		return nil, 0, false
	}

	resp = make([]byte, ntpPacketLen)
	resp[0] = 0<<6 | vn<<3 | rmode // LI=0 (no warning)
	resp[1] = 2                    // stratum 2
	poll := req[2]
	if poll < 4 || poll > 17 {
		poll = 6
	}
	resp[2] = poll
	resp[3] = 0xEC                                                               // precision 2^-20 s
	binary.BigEndian.PutUint32(resp[4:], 0x00000100)                             // root delay ~3.9 ms
	binary.BigEndian.PutUint32(resp[8:], 0x00000200)                             // root dispersion ~7.8 ms
	copy(resp[12:16], refID[:])                                                  // reference ID
	binary.BigEndian.PutUint64(resp[16:], ntpTimestamp(rx.Add(-16*time.Second))) // reference ts
	copy(resp[24:32], req[40:48])                                                // origin ts = client's transmit ts
	binary.BigEndian.PutUint64(resp[32:], ntpTimestamp(rx))
	binary.BigEndian.PutUint64(resp[40:], ntpTimestamp(tx))
	return resp, int(vn), true
}
