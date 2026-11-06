package certs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHoKDataset runs against a real houseofkeys clone when TIM_HOK is set:
//
//	TIM_HOK=/path/to/houseofkeys go test ./internal/certs -run Dataset -v
//
// Each certificates/<id>.pem has its matching private key in <id>.key, so
// the fingerprint of the .key must equal the certificate's, including for
// certificates Go's strict parser rejects.
func TestHoKDataset(t *testing.T) {
	dir := os.Getenv("TIM_HOK")
	if dir == "" {
		t.Skip("set TIM_HOK to a houseofkeys clone")
	}
	pems, _ := filepath.Glob(filepath.Join(dir, "certificates", "*.pem"))
	var pairs, match, noKey, keyUnparsed int
	for _, p := range pems {
		data, _ := os.ReadFile(p)
		ders := certDERsFromPEM(data)
		if len(ders) == 0 {
			t.Errorf("no certificate in %s", filepath.Base(p))
			continue
		}
		cfp, ok := CertFP(ders[0])
		if !ok {
			t.Errorf("could not fingerprint cert %s", filepath.Base(p))
			continue
		}
		kdata, err := os.ReadFile(p[:len(p)-4] + ".key")
		if err != nil {
			noKey++
			continue
		}
		pairs++
		fps := privateKeyFPs(kdata)
		if len(fps) == 0 {
			keyUnparsed++
			t.Logf("key unparsed: %s", filepath.Base(p))
			continue
		}
		if fps[0] == cfp {
			match++
		} else {
			t.Errorf("fingerprint mismatch for %s", filepath.Base(p))
		}
	}
	t.Logf("cert files %d, cert+key pairs %d, matched %d, key unparsed %d, no key %d", len(pems), pairs, match, keyUnparsed, noKey)

	h, err := LoadHoK(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("index: %d distinct keys, %d cert files, %d key files, %d skipped", h.Len(), h.Stats.Certs, h.Stats.Keys, h.Stats.Skipped)
	if h.Len() < 400 || match < pairs-keyUnparsed {
		t.Errorf("indexing looks wrong")
	}
}
