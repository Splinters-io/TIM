package spoof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tlsFixture(t *testing.T, expired bool) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TIM test root"}, NotBefore: now.AddDate(-10, 0, 0), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"time.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if expired {
		leaf.NotBefore = now.Add(-48 * time.Hour)
		leaf.NotAfter = now.Add(-24 * time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	if err := os.WriteFile(certFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return certFile, keyFile, roots
}

func startTLSFixture(t *testing.T, cert, key string, minimum uint16) *TLSTime {
	t.Helper()
	svc, err := NewTLSTime("127.0.0.1:0", cert, key, minimum, fixedClock{fake})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- svc.Serve() }()
	t.Cleanup(func() {
		if err := svc.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})
	return svc
}

func tlsTestClient(t *testing.T, roots *x509.CertPool, host string, version uint16) *http.Client {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: host, MinVersion: version, MaxVersion: version}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 3 * time.Second}
}

func TestTLSTime(t *testing.T) {
	cert, key, roots := tlsFixture(t, false)
	svc := startTLSFixture(t, cert, key, tls.VersionTLS12)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		client := tlsTestClient(t, roots, "time.test", version)
		for _, tc := range []struct {
			method, path string
			status       int
		}{{"GET", "/", 200}, {"HEAD", "/time", 200}, {"POST", "/time", 405}, {"GET", "/missing", 404}} {
			req, _ := http.NewRequest(tc.method, "https://"+svc.Addr()+tc.path, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status || resp.Header.Get("Date") != fake.Format(http.TimeFormat) || resp.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("response: %d %v", resp.StatusCode, resp.Header)
			}
			if tc.method == "HEAD" && len(body) != 0 {
				t.Fatal("HEAD returned body")
			}
			if tc.method == "GET" && tc.status == 200 && strings.TrimSpace(string(body)) != fake.Format(time.RFC3339) {
				t.Fatalf("body=%q", body)
			}
			if resp.TLS.Version != version {
				t.Fatal("wrong TLS version")
			}
		}
	}
	for _, tc := range []struct {
		roots   *x509.CertPool
		host    string
		version uint16
	}{{x509.NewCertPool(), "time.test", tls.VersionTLS12}, {roots, "wrong.test", tls.VersionTLS12}, {roots, "time.test", tls.VersionTLS10}, {roots, "time.test", tls.VersionTLS11}} {
		resp, err := tlsTestClient(t, tc.roots, tc.host, tc.version).Get("https://" + svc.Addr())
		if err == nil {
			resp.Body.Close()
			t.Fatal("untrusted, wrong-host or legacy client unexpectedly accepted")
		}
	}
}

func TestTLSTimeLegacyOptIn(t *testing.T) {
	cert, key, roots := tlsFixture(t, false)
	svc := startTLSFixture(t, cert, key, tls.VersionTLS10)
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		resp, err := tlsTestClient(t, roots, "time.test", version).Head("https://" + svc.Addr())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.TLS.Version != version || resp.Header.Get("Date") != fake.Format(http.TimeFormat) {
			t.Fatal("legacy response mismatch")
		}
	}
}

func TestTLSTimeExpiredAndInvalidKeys(t *testing.T) {
	cert, key, roots := tlsFixture(t, true)
	svc := startTLSFixture(t, cert, key, tls.VersionTLS12)
	resp, err := tlsTestClient(t, roots, "time.test", tls.VersionTLS12).Get("https://" + svc.Addr())
	if err == nil {
		resp.Body.Close()
		t.Fatal("expired certificate accepted")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiration failure: %v", err)
	}
	_, otherKey, _ := tlsFixture(t, false)
	for _, k := range []string{otherKey, filepath.Join(t.TempDir(), "missing.pem")} {
		s, err := NewTLSTime("127.0.0.1:0", cert, k, tls.VersionTLS12, fixedClock{fake})
		if err == nil {
			s.ln.Close()
			t.Fatal("bad key accepted")
		}
	}
}
