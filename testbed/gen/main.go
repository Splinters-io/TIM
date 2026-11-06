// Command tim-gen creates a throwaway CA and a leaf certificate for the
// testbed. By default the leaf's validity window is in the past, so to a
// device with a correct clock it is EXPIRED — the fabricated fault TIM is
// meant to work around. Everything here is synthetic; no real names, keys
// or services are involved.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	out := flag.String("out", "/certs", "directory to write certificates into")
	host := flag.String("host", "server", "leaf certificate hostname (SAN + CN)")
	nb := flag.String("not-before", "2023-01-01", "leaf notBefore (YYYY-MM-DD)")
	na := flag.String("not-after", "2024-01-01", "leaf notAfter (YYYY-MM-DD)")
	caOrg := flag.String("ca-org", "TIM Testbed Root CA", "CA organization/CN")
	flag.Parse()

	notBefore, err := time.Parse("2006-01-02", *nb)
	must(err)
	notAfter, err := time.Parse("2006-01-02", *na)
	must(err)
	must(os.MkdirAll(*out, 0o755))

	// Root CA: long-lived so the ONLY problem is the leaf's dates.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: *caOrg, Organization: []string{*caOrg}},
		NotBefore:             time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	must(err)
	caCert, _ := x509.ParseCertificate(caDER)

	// Leaf: validity window is in the past by default -> expired "now".
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: *host, Organization: []string{"TIM Testbed Device Vendor"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dedupe(*host, "localhost"),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	must(err)

	writeCert(filepath.Join(*out, "ca.pem"), caDER)
	writeKey(filepath.Join(*out, "ca-key.pem"), caKey)
	writeCert(filepath.Join(*out, "server.pem"), leafDER)
	writeKey(filepath.Join(*out, "server-key.pem"), leafKey)

	fmt.Printf("wrote CA + leaf for %q to %s\n", *host, *out)
	fmt.Printf("leaf valid: %s -> %s  (now=%s)\n", notBefore.Format("2006-01-02"), notAfter.Format("2006-01-02"), time.Now().UTC().Format("2006-01-02"))
	if time.Now().After(notAfter) {
		fmt.Println("leaf is EXPIRED relative to the real clock: this is the fabricated fault.")
	}
}

func dedupe(names ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

func writeCert(path string, der []byte) {
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	must(pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writeKey(path string, key *ecdsa.PrivateKey) {
	der, err := x509.MarshalECPrivateKey(key)
	must(err)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	must(err)
	defer f.Close()
	must(pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
