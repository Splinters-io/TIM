package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func d(s string) time.Time { t, _ := time.Parse("2006-01-02", s); return t }

func TestWindowAndSuggest(t *testing.T) {
	chain := []*x509.Certificate{
		{NotBefore: d("2023-06-01"), NotAfter: d("2024-06-01")}, // leaf
		{NotBefore: d("2020-01-01"), NotAfter: d("2025-01-01")}, // intermediate
	}
	from, to, ok := Window(chain)
	if !ok || !from.Equal(d("2023-06-01")) || !to.Equal(d("2024-06-01")) {
		t.Fatalf("window = %v %v %v", from, to, ok)
	}
	if got := Suggest(from, to); !got.Equal(d("2024-05-25")) {
		t.Errorf("suggest = %v", got)
	}
	if got := Suggest(d("2024-01-01"), d("2024-01-11")); !got.Equal(d("2024-01-06")) {
		t.Errorf("short suggest = %v", got)
	}
	bad := []*x509.Certificate{{NotBefore: d("2024-01-01"), NotAfter: d("2024-02-01")}, {NotBefore: d("2024-03-01"), NotAfter: d("2025-01-01")}}
	if _, _, ok := Window(bad); ok {
		t.Error("expected no window")
	}
}

// --- a tiny test PKI -------------------------------------------------------

type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64

func mkCert(t *testing.T, cn, org string, from, to time.Time, parent *issued, isCA bool, dns ...string) *issued {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:             from,
		NotAfter:              to,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		DNSNames:              dns,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &issued{c, key}
}

func TestFindValidPath(t *testing.T) {
	// The device trusts an old root that expired 2024-01-01.
	oldRoot := mkCert(t, "Old Root", "OldCA", d("2010-01-01"), d("2024-01-01"), nil, true)
	oldInt := mkCert(t, "Old Int", "OldCA", d("2015-01-01"), d("2030-01-01"), oldRoot, true)

	// 1. Leaf issued before the root expired: a fake date works.
	leaf := mkCert(t, "api.vendor.example", "Vendor", d("2023-01-01"), d("2024-06-01"), oldInt, false, "api.vendor.example")
	pr := FindValidPath([]*x509.Certificate{leaf.cert, oldInt.cert}, []*x509.Certificate{oldRoot.cert}, "api.vendor.example")
	if !pr.OK || !pr.From.Equal(d("2023-01-01")) || !pr.To.Equal(d("2024-01-01")) || len(pr.Path) != 3 {
		t.Fatalf("expected window 2023-01-01..2024-01-01, got %+v", pr)
	}

	// 2. Leaf issued after the root expired: no date works (the DST Root CA
	//    X3 situation).
	late := mkCert(t, "api.vendor.example", "Vendor", d("2025-01-01"), d("2026-01-01"), oldInt, false, "api.vendor.example")
	pr = FindValidPath([]*x509.Certificate{late.cert, oldInt.cert}, []*x509.Certificate{oldRoot.cert}, "api.vendor.example")
	if pr.OK {
		t.Fatalf("expected no valid date, got %+v", pr)
	}

	// 3. Vendor moved to a new CA: no date works, and we say why.
	newRoot := mkCert(t, "New Root", "NewCA", d("2020-01-01"), d("2040-01-01"), nil, true)
	moved := mkCert(t, "api.vendor.example", "Vendor", d("2025-01-01"), d("2026-01-01"), newRoot, false, "api.vendor.example")
	pr = FindValidPath([]*x509.Certificate{moved.cert}, []*x509.Certificate{oldRoot.cert}, "api.vendor.example")
	if pr.OK || !strings.Contains(strings.Join(pr.Reasons, " "), "switched CA") {
		t.Fatalf("expected unknown-authority reason, got %+v", pr)
	}

	// 4. Wrong hostname: valid only if the device skips hostname checks.
	pr = FindValidPath([]*x509.Certificate{leaf.cert, oldInt.cert}, []*x509.Certificate{oldRoot.cert}, "other.example")
	if !pr.OK || !pr.HostnameMismatch {
		t.Fatalf("expected hostname-mismatch OK, got %+v", pr)
	}
}

func TestNotableCA(t *testing.T) {
	root := mkCert(t, "emSign ECC Root CA - G3", "eMudhra Technologies Limited", d("2018-01-01"), d("2043-01-01"), nil, true)
	leaf := mkCert(t, "device.example", "Someone", d("2024-01-01"), d("2025-01-01"), root, false)
	for _, c := range []*x509.Certificate{root.cert, leaf.cert} {
		f := NotableCA(c)
		if len(f) != 1 || !strings.Contains(f[0].Msg, "eMudhra") {
			t.Errorf("%s: %+v", c.Subject.CommonName, f)
		}
	}
	dst := &x509.Certificate{IsCA: true, Subject: pkix.Name{CommonName: "DST Root CA X3"}, Issuer: pkix.Name{CommonName: "DST Root CA X3"}}
	if f := NotableCA(dst); len(f) != 1 || !strings.Contains(f[0].Msg, "2021-09-30") {
		t.Errorf("DST: %+v", f)
	}
	// A leaf merely *named* emsign.com, issued by someone else, is not flagged.
	other := mkCert(t, "Sectigo DV", "Sectigo", d("2018-01-01"), d("2043-01-01"), nil, true)
	named := mkCert(t, "*.emsign.com", "eMudhra Technologies Limited", d("2026-01-01"), d("2027-01-01"), other, false)
	if f := NotableCA(named.cert); len(f) != 0 {
		t.Errorf("leaf name should not trigger: %+v", f)
	}
	plain := mkCert(t, "Fine Root", "Fine CA", d("2018-01-01"), d("2043-01-01"), nil, true)
	if f := NotableCA(plain.cert); len(f) != 0 {
		t.Errorf("unexpected: %+v", f)
	}
}

func TestROCA(t *testing.T) {
	// Build a modulus with the ROCA structure: p, q = k*M + 65537^a mod M.
	M := big.NewInt(1)
	for _, p := range rocaPrimes {
		M.Mul(M, big.NewInt(p))
	}
	g := big.NewInt(65537)
	mk := func(k, a int64) *big.Int {
		r := new(big.Int).Exp(g, big.NewInt(a), M)
		return r.Add(r, new(big.Int).Mul(big.NewInt(k), M))
	}
	n := new(big.Int).Mul(mk(123456789, 1234), mk(987654321, 4321))
	if !ROCAVulnerable(n) {
		t.Error("synthetic ROCA modulus not detected")
	}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	if ROCAVulnerable(k.N) {
		t.Error("random key flagged as ROCA")
	}
}

func TestHoKIndexAndLookup(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "certificates"), 0o755)
	os.MkdirAll(filepath.Join(dir, "private_keys"), 0o755)

	// A leaked certificate, with the dataset's header text before the PEM.
	leaked := mkCert(t, "192.168.1.1", "Router Co", d("2015-01-01"), d("2035-01-01"), nil, false)
	pemData := append([]byte("SHA1: xx\nSHA256: yy\n\n"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaked.cert.Raw})...)
	os.WriteFile(filepath.Join(dir, "certificates", "aaaaaaaaaaaaaaaa.pem"), pemData, 0o644)
	os.WriteFile(filepath.Join(dir, "certificates", "aaaaaaaaaaaaaaaa.json"), []byte(`{"products":[{"vendor":"ACME","name":"R100","description":"Router"}]}`), 0o644)

	// A bare leaked private key, plus a cert someone later issued for it.
	rk, _ := rsa.GenerateKey(rand.Reader, 1024)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})
	os.WriteFile(filepath.Join(dir, "private_keys", "bbbbbbbbbbbbbbbb.key"), keyPEM, 0o644)
	os.WriteFile(filepath.Join(dir, "private_keys", "bbbbbbbbbbbbbbbb.json"), []byte(`{"products":[{"vendor":"Cam","name":"C1","description":"Camera"}]}`), 0o644)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "cam"}, NotBefore: d("2016-01-01"), NotAfter: d("2036-01-01")}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	camCert, _ := x509.ParseCertificate(der)

	h, err := LoadHoK(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h.Len() != 2 {
		t.Fatalf("indexed %d keys", h.Len())
	}
	if e := h.Lookup(leaked.cert); e == nil || e.Products[0] != "ACME R100 (Router)" {
		t.Errorf("leaked cert lookup = %+v", e)
	}
	if e := h.Lookup(camCert); e == nil || e.Products[0] != "Cam C1 (Camera)" {
		t.Errorf("cert for leaked key lookup = %+v", e)
	}
	clean := mkCert(t, "clean", "Clean", d("2020-01-01"), d("2030-01-01"), nil, false)
	if h.Lookup(clean.cert) != nil {
		t.Error("clean cert matched")
	}

	// The report flags it.
	var buf bytes.Buffer
	Print(&buf, "cam.pem", []*x509.Certificate{camCert}, Options{Now: d("2026-11-06"), HoK: h})
	if !strings.Contains(buf.String(), "PRIVATE KEY IS PUBLIC") || !strings.Contains(buf.String(), "Cam C1") || !strings.Contains(buf.String(), "RSA 1024-bit") {
		t.Errorf("report:\n%s", buf.String())
	}
}

func TestLooseSPKIMatchesStrict(t *testing.T) {
	c := mkCert(t, "x", "y", d("2020-01-01"), d("2030-01-01"), nil, false)
	spki, ok := looseSPKI(c.cert.Raw)
	if !ok || !bytes.Equal(spki, c.cert.RawSubjectPublicKeyInfo) {
		t.Error("loose SPKI differs from Go's")
	}
}
