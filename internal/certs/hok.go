package certs

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// HoK is an index of the public halves of the keys in SEC Consult's
// "House of Keys" dataset (https://github.com/sec-consult/houseofkeys): TLS
// certificates and private keys pulled from embedded-device firmware.
//
// Only normalised public-key fingerprints are kept. TIM uses this to warn that a key's
// private half is public. It never uses the private keys for anything else.
type HoK struct {
	byKey map[keyFP]*HoKEntry
	Stats HoKStats
}

type HoKEntry struct {
	Files    []string // dataset file IDs (sha256 names)
	Products []string // "Vendor Product (description)"
}

type HoKStats struct {
	Certs, Keys, Skipped int
}

const maxHoKFile = 1 << 20

// LoadHoK indexes a clone of the houseofkeys repository.
func LoadHoK(dir string) (*HoK, error) {
	if st, err := os.Stat(dir); err != nil {
		return nil, err
	} else if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (point --hok at a clone of github.com/sec-consult/houseofkeys)", dir)
	}
	h := &HoK{byKey: map[keyFP]*HoKEntry{}}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".pem" && ext != ".crt" && ext != ".key" {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxHoKFile {
			h.Stats.Skipped++
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			h.Stats.Skipped++
			return nil
		}
		var fps []keyFP
		if ext == ".key" {
			fps = privateKeyFPs(data)
			if len(fps) > 0 {
				h.Stats.Keys++
			}
		} else {
			for _, der := range certDERsFromPEM(data) {
				if fp, ok := CertFP(der); ok {
					fps = append(fps, fp)
				}
			}
			if len(fps) > 0 {
				h.Stats.Certs++
			}
		}
		if len(fps) == 0 {
			h.Stats.Skipped++
			return nil
		}
		id := strings.TrimSuffix(filepath.Base(path), ext)
		products := readProducts(strings.TrimSuffix(path, ext) + ".json")
		for _, k := range fps {
			e := h.byKey[k]
			if e == nil {
				e = &HoKEntry{}
				h.byKey[k] = e
			}
			e.Files = appendUnique(e.Files, id)
			for _, p := range products {
				e.Products = appendUnique(e.Products, p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(h.byKey) == 0 {
		return nil, fmt.Errorf("no keys found under %s; is it a houseofkeys clone?", dir)
	}
	for _, e := range h.byKey {
		sort.Strings(e.Products)
	}
	return h, nil
}

// Lookup returns the entry for a certificate's public key, or nil.
func (h *HoK) Lookup(c *x509.Certificate) *HoKEntry {
	return h.LookupDER(c.Raw)
}

// LookupDER is Lookup for certificate DER that Go may not fully parse.
func (h *HoK) LookupDER(der []byte) *HoKEntry {
	if h == nil {
		return nil
	}
	fp, ok := CertFP(der)
	if !ok {
		return nil
	}
	return h.byKey[fp]
}

// Len is the number of distinct public keys indexed.
func (h *HoK) Len() int { return len(h.byKey) }

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func readProducts(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > maxHoKFile {
		return nil
	}
	var doc struct {
		Products []struct {
			Vendor, Name, Description string
		} `json:"products"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []string
	for _, p := range doc.Products {
		s := strings.TrimSpace(p.Vendor + " " + p.Name)
		if p.Description != "" {
			s += " (" + p.Description + ")"
		}
		out = appendUnique(out, s)
	}
	return out
}

// certDERsFromPEM returns the DER of every CERTIFICATE block. Text before
// the first block (the dataset's fingerprint header) is ignored.
func certDERsFromPEM(data []byte) [][]byte {
	var out [][]byte
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return out
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, b.Bytes)
		}
	}
}

// certsFromPEM returns every CERTIFICATE block that Go can fully parse.
func certsFromPEM(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for _, der := range certDERsFromPEM(data) {
		if c, err := x509.ParseCertificate(der); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// Key fingerprints are normalised so that a private key and its certificate
// match even when the firmware's encoding is off. Seen in the dataset:
// RSA moduli missing their leading zero, missing NULL parameters, invalid
// version fields. RSA: sha256 of the modulus magnitude. Other: sha256 of
// algorithm OID + public key bits.
type keyFP = [32]byte

var (
	oidRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidDSA = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
)

func rsaFP(modulusContent []byte) keyFP {
	return sha256.Sum256(append([]byte("rsa:"), bytes.TrimLeft(modulusContent, "\x00")...))
}

func otherFP(oid asn1.ObjectIdentifier, keyBits []byte) keyFP {
	return sha256.Sum256(append([]byte(oid.String()+":"), keyBits...))
}

// spkiFP fingerprints a DER SubjectPublicKeyInfo.
func spkiFP(spki []byte) (keyFP, bool) {
	var s struct {
		Algo asn1.RawValue
		Key  asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &s); err != nil {
		return keyFP{}, false
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(s.Algo.Bytes, &oid); err != nil {
		return keyFP{}, false
	}
	if oid.Equal(oidRSA) {
		var pub struct{ N, E asn1.RawValue }
		if _, err := asn1.Unmarshal(s.Key.Bytes, &pub); err != nil {
			return keyFP{}, false
		}
		return rsaFP(pub.N.Bytes), true
	}
	return otherFP(oid, s.Key.Bytes), true
}

// looseSPKI pulls SubjectPublicKeyInfo out of certificate DER without
// validating anything else, so certs Go refuses to parse still work.
func looseSPKI(der []byte) ([]byte, bool) {
	var cert, tbs asn1.RawValue
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return nil, false
	}
	if _, err := asn1.Unmarshal(cert.Bytes, &tbs); err != nil {
		return nil, false
	}
	rest := tbs.Bytes
	var elems []asn1.RawValue
	for len(rest) > 0 && len(elems) < 8 {
		var rv asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &rv); err != nil {
			return nil, false
		}
		elems = append(elems, rv)
	}
	if len(elems) > 0 && elems[0].Class == asn1.ClassContextSpecific && elems[0].Tag == 0 {
		elems = elems[1:] // explicit [0] version
	}
	// serial, signature, issuer, validity, subject, subjectPublicKeyInfo
	if len(elems) < 6 {
		return nil, false
	}
	return elems[5].FullBytes, true
}

// CertFP fingerprints the key in certificate DER (tolerant of quirks).
func CertFP(der []byte) (keyFP, bool) {
	spki, ok := looseSPKI(der)
	if !ok {
		return keyFP{}, false
	}
	return spkiFP(spki)
}

// privateKeyFPs fingerprints every private key in PEM data.
func privateKeyFPs(data []byte) []keyFP {
	var out []keyFP
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return out
		}
		if fp, ok := privateKeyFP(b.Type, b.Bytes); ok {
			out = append(out, fp)
		}
	}
}

func privateKeyFP(typ string, der []byte) (keyFP, bool) {
	switch typ {
	case "RSA PRIVATE KEY":
		return rsaPrivFP(der)
	case "DSA PRIVATE KEY":
		// OpenSSL: SEQUENCE { version, p, q, g, y, x }; cert key bits = INTEGER y
		var k struct{ V, P, Q, G, Y, X asn1.RawValue }
		if _, err := asn1.Unmarshal(der, &k); err != nil {
			return keyFP{}, false
		}
		return otherFP(oidDSA, k.Y.FullBytes), true
	case "PRIVATE KEY":
		var p struct {
			Version    int
			Algo       pkix.AlgorithmIdentifier
			PrivateKey []byte
			Rest       []asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(der, &p); err == nil && p.Algo.Algorithm.Equal(oidRSA) {
			return rsaPrivFP(p.PrivateKey)
		}
		if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			return signerFP(k)
		}
	case "EC PRIVATE KEY":
		if k, err := x509.ParseECPrivateKey(der); err == nil {
			return signerFP(k)
		}
	}
	return keyFP{}, false
}

func rsaPrivFP(der []byte) (keyFP, bool) {
	// RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent, ... }
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return keyFP{}, false
	}
	var version, n asn1.RawValue
	rest, err := asn1.Unmarshal(outer.Bytes, &version)
	if err != nil {
		return keyFP{}, false
	}
	if _, err := asn1.Unmarshal(rest, &n); err != nil || n.Tag != asn1.TagInteger {
		return keyFP{}, false
	}
	return rsaFP(n.Bytes), true
}

func signerFP(k any) (keyFP, bool) {
	s, ok := k.(crypto.Signer)
	if !ok {
		return keyFP{}, false
	}
	der, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		return keyFP{}, false
	}
	return spkiFP(der)
}
