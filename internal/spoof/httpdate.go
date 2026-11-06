package spoof

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

type origDstKey struct{}

// HTTPDate is a transparent HTTP proxy. iptables REDIRECTs the device's
// port-80 traffic here. We forward each request to its real destination and
// rewrite the Date response header to the fake time. Bodies pass through
// unchanged.
type HTTPDate struct {
	ln  net.Listener
	srv *http.Server
}

// OrigDstFunc returns the pre-REDIRECT destination ("ip:port") of an
// accepted connection, or "" if it is unknown.
type OrigDstFunc func(net.Conn) string

// NewHTTPDate listens on addr. origDst may be nil, in which case requests
// are forwarded to their Host header (handy for testing without iptables).
func NewHTTPDate(addr string, clk Clock, logf Logf, origDst OrigDstFunc) (*HTTPDate, error) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Dial the IP the device actually wanted. Don't re-resolve the
			// Host header: the device may have hard-coded the IP, and the
			// answer may differ from what we'd get.
			if od, _ := ctx.Value(origDstKey{}).(string); od != "" {
				addr = od
			}
			return dialer.DialContext(ctx, network, addr)
		},
		DisableCompression:    true, // don't add or strip encodings; pass through whatever the device asked for
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			host := r.In.Host
			if host == "" {
				host, _ = r.In.Context().Value(origDstKey{}).(string)
			}
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = host
			r.Out.Host = r.In.Host
			// No X-Forwarded-* headers: stay transparent.
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			now := clk.Now()
			resp.Header.Set("Date", now.UTC().Format(http.TimeFormat))
			logf("http: %s %s%s <- Date %s", resp.Request.Method, resp.Request.Host, resp.Request.URL.Path, now.Format(time.RFC3339))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logf("http: %s %s%s upstream error: %v", r.Method, r.Host, r.URL.Path, err)
			w.Header().Set("Date", clk.Now().UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	srv := &http.Server{
		Handler:           rp,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if origDst != nil {
				if od := origDst(c); od != "" {
					return context.WithValue(ctx, origDstKey{}, od)
				}
			}
			return ctx
		},
	}
	return &HTTPDate{ln: ln, srv: srv}, nil
}

func (h *HTTPDate) Name() string { return "http" }
func (h *HTTPDate) Addr() string { return h.ln.Addr().String() }

func (h *HTTPDate) Serve() error {
	err := h.srv.Serve(h.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (h *HTTPDate) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return h.srv.Shutdown(ctx)
}
