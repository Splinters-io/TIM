package certs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func archive(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestCacheInstallAndFailurePreservesOld(t *testing.T) {
	cert := mkCert(t, "test", "test", d("2023-01-01"), d("2024-01-01"), nil, true)
	data := archive(t, "dataset/test.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.cert.Raw}))
	file := filepath.Join(t.TempDir(), "cache.json")
	h, err := installHoKArchive(data, fmt.Sprintf("%x", sha256.Sum256(data)), file)
	if err != nil {
		t.Fatal(err)
	}
	if h.Len() != 1 {
		t.Fatalf("keys=%d", h.Len())
	}
	loaded, err := LoadHoKCache(file)
	if err != nil || loaded.Lookup(cert.cert) == nil {
		t.Fatalf("roundtrip: %v", err)
	}
	before, _ := os.ReadFile(file)
	if bytes.Contains(before, []byte("BEGIN")) {
		t.Fatal("cache contains PEM")
	}
	for _, bad := range []struct {
		data []byte
		sum  string
	}{
		{data, "wrong"},
		{archive(t, "../escape.pem", []byte("test")), ""},
	} {
		sum := bad.sum
		if sum == "" {
			sum = fmt.Sprintf("%x", sha256.Sum256(bad.data))
		}
		if _, err := installHoKArchive(bad.data, sum, file); err == nil {
			t.Fatal("bad archive accepted")
		}
		after, _ := os.ReadFile(file)
		if !bytes.Equal(before, after) {
			t.Fatal("old cache changed on failure")
		}
	}
}

func TestPinnedArchive(t *testing.T) {
	file := os.Getenv("TIM_HOK_ARCHIVE")
	if file == "" {
		t.Skip("set TIM_HOK_ARCHIVE to test the pinned release archive")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	h, err := installHoKArchive(data, hokSHA256, filepath.Join(t.TempDir(), "cache.json"))
	if err != nil {
		t.Fatal(err)
	}
	if h.Len() != 567 {
		t.Fatalf("got %d fingerprints, want 567", h.Len())
	}
	t.Logf("verified pinned archive: %d fingerprints", h.Len())
}

func TestExportRoundTripAndNoOverwrite(t *testing.T) {
	c := mkCert(t, "test", "test", d("2023-01-01"), d("2024-01-01"), nil, true).cert
	file := filepath.Join(t.TempDir(), "chain.pem")
	if err := Export(file, []*x509.Certificate{c}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(file)
	if err != nil || len(loaded) != 1 || !bytes.Equal(c.Raw, loaded[0].Raw) {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if err := Export(file, []*x509.Certificate{c}); err == nil {
		t.Fatal("overwrote existing file")
	}
	var b bytes.Buffer
	PrintTrustRepair(&b, []*x509.Certificate{c}, "", d("2026-01-01"))
	if !strings.Contains(b.String(), "Cannot identify") {
		t.Fatal(b.String())
	}
}

func TestHoKDownload(t *testing.T) {
	if os.Getenv("TIM_HOK_DOWNLOAD") != "1" {
		t.Skip("set TIM_HOK_DOWNLOAD=1 for the network updater test")
	}
	file := filepath.Join(t.TempDir(), "cache.json")
	h, err := UpdateHoK(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadHoKCache(file)
	if err != nil {
		t.Fatal(err)
	}
	if h.Len() != 567 || loaded.Len() != h.Len() {
		t.Fatalf("download/cache: %d/%d fingerprints", h.Len(), loaded.Len())
	}
}
