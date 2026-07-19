package acmednschallenge

import (
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/acmednschallenge/config"
	"github.com/go-acme/lego/v4/certificate"
)

type fakeStorage struct{ saves int }

func (f *fakeStorage) Save(*certificate.Resource) error  { f.saves++; return nil }
func (f *fakeStorage) Load(string) *certificate.Resource { return nil }

func TestUpdateCertForDomainRetry(t *testing.T) {
	tests := []struct {
		name          string
		failCount     int
		isNew         bool
		retryInterval time.Duration
		maxRetryCount uint32
		wantAttempts  int
		wantSaves     int
	}{
		{name: "succeeds first try", failCount: 0, isNew: true, retryInterval: time.Millisecond, maxRetryCount: 3, wantAttempts: 1, wantSaves: 1},
		{name: "succeeds after retries", failCount: 2, isNew: true, retryInterval: time.Millisecond, maxRetryCount: 3, wantAttempts: 3, wantSaves: 1},
		{name: "not new skips save", failCount: 0, isNew: false, retryInterval: time.Millisecond, maxRetryCount: 3, wantAttempts: 1, wantSaves: 0},
		{name: "gives up after maxRetryCount", failCount: 99, retryInterval: time.Millisecond, maxRetryCount: 3, wantAttempts: 4, wantSaves: 0},
		{name: "zero interval disables retry", failCount: 99, retryInterval: 0, maxRetryCount: 3, wantAttempts: 1, wantSaves: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStorage{}
			attempts := 0
			ac := &acmeChallenge{
				config:  &config.ACMEChallengeConfig{RetryInterval: tc.retryInterval, MaxRetryCount: tc.maxRetryCount},
				storage: store,
			}
			ac.obtainOrRenew = func(domain string) (bool, *certificate.Resource, error) {
				attempts++
				if attempts <= tc.failCount {
					return false, nil, errors.New("boom")
				}
				return tc.isNew, &certificate.Resource{Domain: domain}, nil
			}

			ac.updateCertForDomain("example.com")

			if attempts != tc.wantAttempts {
				t.Errorf("attempts = %d, want %d", attempts, tc.wantAttempts)
			}
			if store.saves != tc.wantSaves {
				t.Errorf("saves = %d, want %d", store.saves, tc.wantSaves)
			}
		})
	}
}

func TestCheckAndUpdateCertForAllDomains(t *testing.T) {
	want := []string{"a.example.com", "b.example.com", "c.example.com"}

	var mu sync.Mutex
	var seen []string
	ac := &acmeChallenge{
		config:  &config.ACMEChallengeConfig{ManagedDomains: map[string][]string{}},
		storage: &fakeStorage{},
	}
	for _, d := range want {
		ac.config.ManagedDomains[d] = nil
	}
	ac.obtainOrRenew = func(domain string) (bool, *certificate.Resource, error) {
		mu.Lock()
		seen = append(seen, domain)
		mu.Unlock()
		return false, nil, nil
	}

	ac.checkAndUpdateCertForAllDomains()

	sort.Strings(seen)
	if len(seen) != len(want) {
		t.Fatalf("attempted %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("attempted %v, want %v", seen, want)
			break
		}
	}
}
