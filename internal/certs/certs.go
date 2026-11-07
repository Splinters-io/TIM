// Package certs inspects certificate chains: when they're valid, whether a
// device's own roots would accept them at some fake date, and whether keys
// are known-compromised (House of Keys, ROCA, weak sizes) or come from CAs
// with a history that matters to old devices.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Fetch connects to host[:port] (default 443) and returns the certificate
// chain the server presents.
//
// Verification is turned off on purpose: the point is to inspect
// certificates that are already expired or otherwise invalid. Nothing is
// sent over this connection besides the handshake.
func Fetch(target string, timeout time.Duration) (chain []*x509.Certificate, host string, err error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "443"
	}
	d := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{
		InsecureSkipVerify: true, // inspection only; see doc comment
		// Offer old versions too: old device servers often only speak TLS 1.0.
		MinVersion: tls.VersionTLS10,
	}
	if net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), cfg)
	if err != nil {
		return nil, host, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, host, nil
}

// LoadFile reads certificates from a PEM bundle, or from DER (one or more
// concatenated certificates).
func LoadFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(data), "-----BEGIN") {
		var out []*x509.Certificate
		rest := data
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if b.Type != "CERTIFICATE" && b.Type != "TRUSTED CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", path, err)
			}
			out = append(out, c)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%s: no certificates found", path)
		}
		return out, nil
	}
	out, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("%s: not PEM, and DER parse failed: %v", path, err)
	}
	return out, nil
}

// LoadDERs returns the raw DER of every certificate in a PEM or DER file
// without parsing it, for certificates Go's strict parser rejects.
func LoadDERs(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(data), "-----BEGIN") {
		return certDERsFromPEM(data), nil
	}
	return [][]byte{data}, nil
}

// PrintRaw reports on certificates Go can't parse. Only the key checks that
// work on raw DER (House of Keys) are possible.
func PrintRaw(w io.Writer, target string, ders [][]byte, parseErr error, o Options) {
	fmt.Fprintf(w, "%s\n", target)
	fmt.Fprintf(w, "  Go can't fully parse this certificate (%v).\n", parseErr)
	fmt.Fprintln(w, "  Firmware often produces quirky certificates like this, and old devices accept them. Only the key checks can run.")
	for i, der := range ders {
		if _, ok := CertFP(der); !ok {
			fmt.Fprintf(w, "  [%d] can't locate the public key either\n", i)
			continue
		}
		if e := o.HoK.LookupDER(der); e != nil {
			fmt.Fprintf(w, "  [%d] BAD: %s\n", i, hokMsg(e))
		} else if o.HoK != nil {
			fmt.Fprintf(w, "  [%d] key not in House of Keys\n", i)
		} else {
			fmt.Fprintf(w, "  [%d] (pass --hok to check against House of Keys)\n", i)
		}
	}
}

// Window is the time range in which every certificate in the chain is
// valid. Valid is false if the ranges don't overlap.
func Window(chain []*x509.Certificate) (from, to time.Time, valid bool) {
	for i, c := range chain {
		if i == 0 || c.NotBefore.After(from) {
			from = c.NotBefore
		}
		if i == 0 || c.NotAfter.Before(to) {
			to = c.NotAfter
		}
	}
	return from.UTC(), to.UTC(), len(chain) > 0 && from.Before(to)
}

// Suggest picks a fake time inside the window: a week before the earliest
// expiry, or the middle of the window if it's shorter than two weeks.
func Suggest(from, to time.Time) time.Time {
	t := to.Add(-7 * 24 * time.Hour)
	if !t.After(from.Add(7 * 24 * time.Hour)) {
		t = from.Add(to.Sub(from) / 2)
	}
	return t.Truncate(time.Hour).UTC()
}

// Options for Print.
type Options struct {
	Now   time.Time
	Host  string              // hostname to check (empty for files/IPs)
	Roots []*x509.Certificate // the device's trusted roots (--root)
	HoK   *HoK                // House of Keys index (--hok), optional
}

func label(cn string, n fmt.Stringer) string {
	if cn != "" {
		return cn
	}
	return n.String()
}

// Findings collects every finding for one certificate.
func Findings(c *x509.Certificate, isLeaf, isRoot bool, o Options) []Finding {
	var out []Finding
	if e := o.HoK.Lookup(c); e != nil {
		out = append(out, Finding{Bad, hokMsg(e)})
	}
	out = append(out, WeakKey(c, isRoot)...)
	out = append(out, NotableCA(c)...)
	if isLeaf && o.Host != "" && net.ParseIP(o.Host) == nil {
		if err := c.VerifyHostname(o.Host); err != nil {
			out = append(out, Finding{Warn, fmt.Sprintf("Certificate is not for %q. Many embedded TLS stacks don't check the hostname; if this device does, no date will help.", o.Host)})
		}
	}
	if isLeaf && c.Subject.String() == c.Issuer.String() {
		out = append(out, Finding{Info, "Self-signed: the device must have this exact certificate pinned or trusted."})
	}
	return dedupe(out)
}

func hokMsg(e *HoKEntry) string {
	prods := e.Products
	more := ""
	if len(prods) > 6 {
		more = fmt.Sprintf(" and %d more", len(prods)-6)
		prods = prods[:6]
	}
	where := strings.Join(prods, "; ")
	if where == "" {
		where = "unknown products"
	}
	return fmt.Sprintf("PRIVATE KEY IS PUBLIC (House of Keys %s): found in firmware of %s%s. Anyone can impersonate this endpoint.", shortHoKID(e), where, more)
}

func dedupe(fs []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range fs {
		if !seen[f.Msg] {
			seen[f.Msg] = true
			out = append(out, f)
		}
	}
	return out
}

func printCert(w io.Writer, tag string, c *x509.Certificate, isLeaf, isRoot bool, o Options) {
	fmt.Fprintf(w, "  [%s] %s\n", tag, label(c.Subject.CommonName, c.Subject))
	fmt.Fprintf(w, "      issuer: %s\n", label(c.Issuer.CommonName, c.Issuer))
	if isLeaf && len(c.DNSNames) > 0 {
		names := c.DNSNames
		if len(names) > 5 {
			names = append(names[:5:5], "...")
		}
		fmt.Fprintf(w, "      names:  %s\n", strings.Join(names, ", "))
	}
	_, st := Validity(c, o.Now)
	fmt.Fprintf(w, "      valid:  %s -> %s  [%s]\n", c.NotBefore.UTC().Format("2006-01-02"), c.NotAfter.UTC().Format("2006-01-02"), st)
	fmt.Fprintf(w, "      key:    %s, signed %s\n", KeyDesc(c), c.SignatureAlgorithm)
	for _, f := range Findings(c, isLeaf, isRoot, o) {
		fmt.Fprintf(w, "      %-4s %s\n", f.Level+":", f.Msg)
	}
}

// Print writes a full report for one target and suggests a --time.
func Print(w io.Writer, target string, chain []*x509.Certificate, o Options) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	fmt.Fprintf(w, "%s\n", target)
	for i, c := range chain {
		printCert(w, fmt.Sprint(i), c, i == 0, i == len(chain)-1 && c.Subject.String() == c.Issuer.String(), o)
	}
	for i, r := range o.Roots {
		if len(o.Roots) > 8 {
			break // a whole CA bundle; don't print every root
		}
		printCert(w, fmt.Sprintf("device root %d", i), r, false, true, o)
	}

	from, to, ok := Window(chain)
	if ok {
		fmt.Fprintf(w, "  Served chain valid: %s -> %s\n", from.Format(time.RFC3339), to.Format(time.RFC3339))
	} else {
		fmt.Fprintln(w, "  Served chain: no single date makes every certificate the server sent valid.")
	}

	if len(o.Roots) == 0 {
		if ok {
			if o.Now.After(from) && o.Now.Before(to) {
				fmt.Fprintln(w, "  The served chain is valid right now, so no fake time is needed for it. If the device still fails, its own root or client certificate is the likely culprit; check with --root.")
			} else {
				fmt.Fprintf(w, "  Suggested: --time %s\n", Suggest(from, to).Format(time.RFC3339))
			}
		}
		fmt.Fprintln(w, "  Tip: pass the device's root certificate or CA bundle with --root to check the device can actually accept this chain.")
		return
	}

	pr := FindValidPath(chain, o.Roots, o.Host)
	if !pr.OK {
		fmt.Fprintln(w, "  With the device's roots: NO fake date fixes this.")
		for _, r := range pr.Reasons {
			fmt.Fprintf(w, "    - %s\n", r)
		}
		PrintTrustRepair(w, chain, o.Host, o.Now)
		return
	}
	var names []string
	for _, c := range pr.Path {
		names = append(names, label(c.Subject.CommonName, c.Subject))
	}
	fmt.Fprintf(w, "  With the device's roots: OK via %s\n", strings.Join(names, " -> "))
	fmt.Fprintf(w, "    valid %s -> %s\n", pr.From.Format(time.RFC3339), pr.To.Format(time.RFC3339))
	if pr.HostnameMismatch {
		fmt.Fprintln(w, "    (only if the device doesn't check the hostname)")
	}
	if o.Now.After(pr.From) && o.Now.Before(pr.To) {
		fmt.Fprintln(w, "  The device should accept this chain right now; no fake time needed. Look at the device's own client certificate, or how it validates.")
		return
	}
	fmt.Fprintf(w, "  Suggested: --time %s\n", Suggest(pr.From, pr.To).Format(time.RFC3339))
}

func shortHoKID(e *HoKEntry) string {
	if len(e.Files) == 0 {
		return "unknown"
	}
	id := e.Files[0]
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}
