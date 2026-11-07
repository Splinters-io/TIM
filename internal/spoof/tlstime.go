package spoof

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// TLSTime is a standalone HTTPS time service.
type TLSTime struct{ *HTTPDate }

func (s *TLSTime) Name() string { return "https-time" }

// NewTLSTime serves a controlled HTTPS Date using an operator's PEM chain and
// matching private key. The scenario clock affects HTTP only, never TLS's
// cryptographic random source or certificate verification clocks.
func NewTLSTime(addr, certFile, keyFile string, minVersion uint16, clk Clock) (*TLSTime, error) {
	if minVersion < tls.VersionTLS10 || minVersion > tls.VersionTLS13 {
		return nil, fmt.Errorf("unsupported minimum TLS version")
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate/key: %w", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: minVersion, NextProtos: []string{"http/1.1"}}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := clk.Now().UTC()
			w.Header().Set("Date", now.Format(http.TimeFormat))
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			if r.URL.Path != "/" && r.URL.Path != "/time" {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			fmt.Fprintln(w, now.Format(time.RFC3339))
		}),
	}
	return &TLSTime{HTTPDate: &HTTPDate{ln: tls.NewListener(ln, cfg), srv: srv}}, nil
}
