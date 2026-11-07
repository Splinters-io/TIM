package certs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const HoKCommit = "b4c8ee416f1c494b033ae930d464a37809ed61d8"
const hokURL = "https://codeload.github.com/sec-consult/houseofkeys/tar.gz/" + HoKCommit
const hokSHA256 = "847c129ce05139be2b6b2f70a795edfe452dcaccaa77417b04acd728bd0cdb64"
const maxArchive = 32 << 20

type hokCache struct {
	Version int
	Commit  string
	Stats   HoKStats
	Entries map[string]*HoKEntry
}

func HoKCachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tim", "houseofkeys.json"), nil
}

func LoadHoKCache(file string) (*HoK, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxArchive+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxArchive {
		return nil, fmt.Errorf("fingerprint cache too large")
	}
	var c hokCache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Version != 1 || c.Commit != HoKCommit || len(c.Entries) == 0 {
		return nil, fmt.Errorf("unsupported or empty fingerprint cache; run tim hok update")
	}
	h := &HoK{byKey: map[keyFP]*HoKEntry{}, Stats: c.Stats}
	for s, e := range c.Entries {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 || e == nil || len(e.Files) == 0 {
			return nil, fmt.Errorf("invalid fingerprint entry")
		}
		var fp keyFP
		copy(fp[:], b)
		h.byKey[fp] = e
	}
	return h, nil
}

// UpdateHoK downloads an immutable, checksum-pinned snapshot on explicit request.
// Only the derived public fingerprints and product descriptions survive in cache.
func UpdateHoK(ctx context.Context, file string) (*HoK, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hokURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dataset download: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxArchive {
		return nil, fmt.Errorf("dataset exceeds download limit")
	}
	return installHoKArchive(data, hokSHA256, file)
}

func installHoKArchive(data []byte, checksum, file string) (*HoK, error) {
	if fmt.Sprintf("%x", sha256.Sum256(data)) != checksum {
		return nil, fmt.Errorf("dataset checksum mismatch; cache unchanged")
	}
	dir, err := os.MkdirTemp("", "tim-hok-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := path.Clean(hdr.Name)
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") {
			return nil, fmt.Errorf("unsafe archive path %q", hdr.Name)
		}
		if hdr.Typeflag == tar.TypeDir || hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("unsupported archive entry %q", hdr.Name)
		}
		total += hdr.Size
		if hdr.Size < 0 || hdr.Size > maxHoKFile || total > 128<<20 {
			return nil, fmt.Errorf("dataset exceeds extraction limit")
		}
		ext := path.Ext(name)
		if ext != ".pem" && ext != ".crt" && ext != ".key" && ext != ".json" {
			continue
		}
		dest := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return nil, err
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(dest, b, 0600); err != nil {
			return nil, err
		}
	}
	h, err := LoadHoK(dir)
	if err != nil {
		return nil, err
	}
	c := hokCache{Version: 1, Commit: HoKCommit, Stats: h.Stats, Entries: map[string]*HoKEntry{}}
	for fp, e := range h.byKey {
		c.Entries[hex.EncodeToString(fp[:])] = e
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(file), ".hok-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(f.Name(), file); err != nil {
		return nil, err
	}
	return h, nil
}
