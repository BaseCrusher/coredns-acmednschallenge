package acmednschallenge

import (
	"testing"

	"github.com/coredns/coredns/plugin/acmednschallenge/config"
)

type fakeAccount struct {
	keys      map[string][]byte
	saveCalls int
}

func newFakeAccount() *fakeAccount { return &fakeAccount{keys: map[string][]byte{}} }

func (f *fakeAccount) SaveAccountKey(email string, keyPEM []byte) error {
	f.saveCalls++
	f.keys[email] = keyPEM
	return nil
}
func (f *fakeAccount) LoadAccountKey(email string) []byte { return f.keys[email] }

func newProviderConfig(email string) *config.ACMEChallengeConfig {
	return &config.ACMEChallengeConfig{Email: email, ManagedDomains: map[string][]string{}}
}

func TestNewCoreDnsLegoProviderGeneratesKey(t *testing.T) {
	acc := newFakeAccount()
	cfg := newProviderConfig("new@example.com")

	p, err := newCoreDnsLegoProvider(cfg, acc, &map[string][]string{}, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.acmeUser.alreadyExists {
		t.Error("alreadyExists = true, want false for a freshly generated account")
	}
	if p.acmeUser.Key == nil {
		t.Error("account key was not generated")
	}
	if acc.saveCalls != 1 {
		t.Errorf("SaveAccountKey called %d times, want 1", acc.saveCalls)
	}
}

func TestNewCoreDnsLegoProviderLoadsExistingKey(t *testing.T) {
	acc := newFakeAccount()
	if _, err := newCoreDnsLegoProvider(newProviderConfig("me@example.com"), acc, &map[string][]string{}, "test"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	acc.saveCalls = 0

	p, err := newCoreDnsLegoProvider(newProviderConfig("me@example.com"), acc, &map[string][]string{}, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.acmeUser.alreadyExists {
		t.Error("alreadyExists = false, want true when a stored key is loaded")
	}
	if acc.saveCalls != 0 {
		t.Errorf("SaveAccountKey called %d times, want 0 when reusing a stored key", acc.saveCalls)
	}
}

func TestNewCoreDnsLegoProviderBadStoredKey(t *testing.T) {
	acc := newFakeAccount()
	acc.keys["bad@example.com"] = []byte("not a valid pem key")

	if _, err := newCoreDnsLegoProvider(newProviderConfig("bad@example.com"), acc, &map[string][]string{}, "test"); err == nil {
		t.Fatal("expected an error for an unparseable stored account key, got nil")
	}
}
