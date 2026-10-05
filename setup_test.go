package acmednschallenge

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetupSurvivesReload(t *testing.T) {
	input := `acmednschallenge {
		email test@example.org
		acceptedLetsEncryptToS
		skipDnsPropagationTest
		certificateStorageDisk ` + t.TempDir() + `
		acmeAccountStorageDisk ` + t.TempDir() + `
	}`

	for i := range 3 {
		c := caddy.NewTestController("dns", input)
		c.ServerBlockKeys = []string{"example.org.:0"}
		if err := setup(c); err != nil {
			t.Fatalf("reload %d: setup failed: %v", i, err)
		}
	}
}
