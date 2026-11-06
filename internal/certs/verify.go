package certs

import (
	"crypto/x509"
	"errors"
	"sort"
	"strings"
	"time"
)

// PathResult is the outcome of searching for a date at which the device's
// roots would accept the server's chain.
type PathResult struct {
	OK       bool
	Path     []*x509.Certificate // leaf ... root
	From, To time.Time           // when that path is valid
	// HostnameMismatch: the chain only verifies if hostname checking is
	// skipped. (Many embedded TLS stacks don't check the hostname.)
	HostnameMismatch bool
	// Reasons explains a failure (deduplicated verifier errors).
	Reasons []string
}

// FindValidPath looks for a time at which chain[0] verifies up to one of
// roots, using chain[1:] as intermediates.
//
// Each path is valid from max(NotBefore) to min(NotAfter) of its certs, and
// both ends are some cert's boundary. So trying just inside every cert's
// NotBefore and NotAfter finds a working time whenever one exists. If
// several paths work, the one valid latest (closest to now) wins.
func FindValidPath(chain, roots []*x509.Certificate, dnsName string) PathResult {
	if len(chain) == 0 || len(roots) == 0 {
		return PathResult{Reasons: []string{"need a server chain and at least one root"}}
	}
	res := search(chain, roots, dnsName)
	if !res.OK && dnsName != "" {
		if r2 := search(chain, roots, ""); r2.OK {
			r2.HostnameMismatch = true
			return r2
		}
	}
	return res
}

func search(chain, roots []*x509.Certificate, dnsName string) PathResult {
	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	var candidates []time.Time
	for _, c := range append(append([]*x509.Certificate{}, chain...), roots...) {
		candidates = append(candidates, c.NotBefore.Add(time.Minute), c.NotAfter.Add(-time.Minute))
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].After(candidates[j]) })

	var best PathResult
	reasons := map[string]bool{}
	for _, t := range candidates {
		chains, err := chain[0].Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: inter,
			CurrentTime:   t,
			DNSName:       dnsName,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			reasons[explain(err)] = true
			continue
		}
		for _, p := range chains {
			from, to, ok := Window(p)
			if ok && (!best.OK || to.After(best.To)) {
				best = PathResult{OK: true, Path: p, From: from, To: to}
			}
		}
	}
	if best.OK {
		return best
	}
	// An expiry error just means that time was wrong; it isn't a reason
	// in itself when we tried every candidate time.
	delete(reasons, "expired or not yet valid")
	for r := range reasons {
		best.Reasons = append(best.Reasons, r)
	}
	sort.Strings(best.Reasons)
	if len(best.Reasons) == 0 {
		best.Reasons = []string{"no single date is inside every certificate's validity period"}
	}
	return best
}

func explain(err error) string {
	var inv x509.CertificateInvalidError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ia x509.InsecureAlgorithmError
	switch {
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		return "expired or not yet valid"
	case errors.As(err, &ua):
		return "the server's chain does not lead to any of the device's roots (the vendor probably switched CA)"
	case errors.As(err, &hn):
		return "hostname mismatch: " + hn.Error()
	case errors.As(err, &ia):
		return "the chain uses SHA-1/MD5 signatures, which this checker can't verify. Old devices usually accept them, so fall back to the date window above"
	case errors.As(err, &inv):
		return "invalid: " + inv.Error()
	}
	return strings.TrimPrefix(err.Error(), "x509: ")
}
