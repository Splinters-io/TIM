package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tim/internal/clock"
	"tim/internal/spoof"
)

// Exercise real TLS validation after obtaining time over each supported wire
// protocol. Also prove changing time cannot fix an unrelated trust store.
func TestTimeLockedDeviceRepair(t *testing.T) {
	fake := time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic root"}, NotBefore: fake.AddDate(-5, 0, 0), NotAfter: fake.AddDate(20, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"server"}, NotBefore: fake.AddDate(0, -1, 0), NotAfter: fake.AddDate(0, 1, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "account data") }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: key}}}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	check := func(now time.Time, pool *x509.CertPool) error {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "server", Time: func() time.Time { return now }}}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Get(server.URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err == nil && string(b) != "account data" {
			t.Fatalf("body changed: %q", b)
		}
		return err
	}
	if err := check(time.Now(), roots); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired certificate: %v", err)
	}
	clk := clock.Anchored(fake, true)
	quiet := func(string, ...any) {}
	ntp, err := spoof.NewNTP("127.0.0.1:0", clk, quiet)
	if err != nil {
		t.Fatal(err)
	}
	go ntp.Serve()
	defer ntp.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer upstream.Close()
	proxy, err := spoof.NewHTTPDate("127.0.0.1:0", clk, quiet, nil)
	if err != nil {
		t.Fatal(err)
	}
	go proxy.Serve()
	defer proxy.Close()
	for _, source := range []string{"ntp://" + ntp.Addr(), "http://" + proxy.Addr()} {
		t.Run(source, func(t *testing.T) {
			now, _, err := resolveTime(source, strings.TrimPrefix(upstream.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			if !now.Equal(fake) {
				t.Fatalf("time=%s", now)
			}
			if err := check(now, roots); err != nil {
				t.Fatalf("repair failed: %v", err)
			}
			if err := check(now, x509.NewCertPool()); err == nil || !strings.Contains(err.Error(), "unknown authority") {
				t.Fatalf("untrusted CA accepted: %v", err)
			}
		})
	}
}
