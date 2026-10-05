package acmednschallenge

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/acmednschallenge/config"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func newTestChallenge(next plugin.Handler, challenges map[string][]string) *acmeChallenge {
	store := newChallengeStore()
	if challenges != nil {
		store.replace(challenges)
	}
	return &acmeChallenge{
		Next:       next,
		config:     &config.ACMEChallengeConfig{DnsTTL: 120},
		challenges: store,
	}
}

func TestServeDNSNoNextRefused(t *testing.T) {
	ac := newTestChallenge(nil, nil)
	r := new(dns.Msg)
	r.SetQuestion("_acme-challenge.example.com.", dns.TypeTXT)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	code, err := ac.ServeDNS(context.Background(), rec, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != dns.RcodeRefused {
		t.Errorf("code = %d, want RcodeRefused (%d)", code, dns.RcodeRefused)
	}
}

func TestServeDNS(t *testing.T) {
	challenges := map[string][]string{
		"_acme-challenge.example.com.": {"token-a", "token-b"},
	}

	tests := []struct {
		name        string
		qname       string
		qtype       uint16
		wantHandled bool
	}{
		{name: "managed acme txt is answered", qname: "_acme-challenge.example.com.", qtype: dns.TypeTXT, wantHandled: true},
		{name: "case-insensitive match", qname: "_ACME-Challenge.EXAMPLE.com.", qtype: dns.TypeTXT, wantHandled: true},
		{name: "non-acme query delegated", qname: "example.com.", qtype: dns.TypeA, wantHandled: false},
		{name: "acme name but not txt delegated", qname: "_acme-challenge.example.com.", qtype: dns.TypeA, wantHandled: false},
		{name: "unmanaged acme txt delegated", qname: "_acme-challenge.other.com.", qtype: dns.TypeTXT, wantHandled: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac := newTestChallenge(test.NextHandler(dns.RcodeSuccess, nil), challenges)

			r := new(dns.Msg)
			r.SetQuestion(tc.qname, tc.qtype)

			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			code, err := ac.ServeDNS(context.Background(), rec, r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != dns.RcodeSuccess {
				t.Fatalf("code = %d, want RcodeSuccess", code)
			}

			if !tc.wantHandled {
				if rec.Msg != nil {
					t.Fatalf("expected delegation (no answer written), got %v", rec.Msg)
				}
				return
			}

			if rec.Msg == nil {
				t.Fatal("expected an answer to be written, got none")
			}
			if len(rec.Msg.Answer) != 2 {
				t.Fatalf("got %d answers, want 2", len(rec.Msg.Answer))
			}
			for _, a := range rec.Msg.Answer {
				txt, ok := a.(*dns.TXT)
				if !ok {
					t.Fatalf("answer is %T, want *dns.TXT", a)
				}
				if txt.Hdr.Ttl != 120 {
					t.Errorf("TTL = %d, want 120", txt.Hdr.Ttl)
				}
			}
		})
	}
}

func TestPresentCleanUp(t *testing.T) {
	store := newChallengeStore()
	p := &coreDnsLegoProvider{activeChallenges: store}

	if err := p.Present("example.com", "", "keyauth-one"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := p.Present("example.com", "", "keyauth-two"); err != nil {
		t.Fatalf("Present: %v", err)
	}

	challenges := store.snapshot()
	if len(challenges) != 1 {
		t.Fatalf("got %d fqdn keys, want 1", len(challenges))
	}
	for _, vals := range challenges {
		if len(vals) != 2 {
			t.Errorf("got %d TXT values, want 2 (one per Present call)", len(vals))
		}
	}

	if err := p.CleanUp("example.com", "", "keyauth-one"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if !store.isEmpty() {
		t.Errorf("CleanUp left %d entries, want 0", len(store.snapshot()))
	}
}

func TestStripLogPrefix(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"[INFO] hello", "hello"},
		{"[WARN] a b c", "a b c"},
		{"no prefix", "no prefix"},
		{"[unterminated", "[unterminated"},
		{"[]", "[]"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := stripLogPrefix(tc.in); got != tc.want {
			t.Errorf("stripLogPrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
