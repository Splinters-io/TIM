package certs

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"
)

// Export writes the observed certificates without treating them as trusted.
// Refuse to replace an existing file (including a symlink).
func Export(file string, chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return fmt.Errorf("no certificates to export")
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(file)
		}
	}()
	for _, c := range chain {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

// PrintTrustRepair identifies a root only when a complete path verifies against
// this machine's system trust store. A served issuer name alone is not proof.
func PrintTrustRepair(w io.Writer, chain []*x509.Certificate, host string, now time.Time) {
	if len(chain) == 0 {
		return
	}
	fmt.Fprintf(w, "  Presented leaf issuer: %s\n", chain[0].Issuer.String())
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	paths, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, CurrentTime: now, Intermediates: inter})
	if err != nil {
		fmt.Fprintln(w, "  Cannot identify a currently trusted replacement root from this chain. Obtain the current root from the service/CA's official distribution and verify its fingerprint independently; servers often omit roots.")
		return
	}
	for _, p := range paths {
		root := p[len(p)-1]
		fmt.Fprintf(w, "  System-verified root candidate: %s\n    SHA-256: %X\n", root.Subject.String(), sha256.Sum256(root.Raw))
	}
	fmt.Fprintln(w, "  If the device supports trust-store updates, obtain the matching root from the CA's official distribution. An exported server chain is evidence, not a root bundle to trust automatically.")
}
