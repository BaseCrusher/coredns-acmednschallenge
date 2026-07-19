package storage

import (
	"testing"

	"github.com/go-acme/lego/v4/certificate"
)

func TestVaultCertDataRoundTrip(t *testing.T) {
	in := &certificate.Resource{
		Domain:      "example.com",
		CertURL:     "https://acme/cert/1",
		Certificate: []byte("CERTPEM"),
		PrivateKey:  []byte("KEYPEM"),
	}

	data, err := certToVaultData(in)
	if err != nil {
		t.Fatalf("certToVaultData: %v", err)
	}
	if _, ok := data["tls.crt"].(string); !ok {
		t.Fatal("tls.crt should be stored as a string")
	}

	out := vaultDataToCert(data)
	if out == nil {
		t.Fatal("vaultDataToCert returned nil")
	}
	if out.Domain != "example.com" || out.CertURL != "https://acme/cert/1" {
		t.Errorf("metadata not restored: %+v", out)
	}
	if string(out.Certificate) != "CERTPEM" || string(out.PrivateKey) != "KEYPEM" {
		t.Errorf("tls material not restored: cert=%q key=%q", out.Certificate, out.PrivateKey)
	}
}

func TestVaultDataToCertMissingMeta(t *testing.T) {
	if vaultDataToCert(map[string]interface{}{"tls.crt": "x"}) != nil {
		t.Error("expected nil when acme.json is absent")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "c"); got != "c" {
		t.Errorf("firstNonEmpty = %q, want c", got)
	}
	if got := firstNonEmpty("a", "b"); got != "a" {
		t.Errorf("firstNonEmpty = %q, want a", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("firstNonEmpty = %q, want empty", got)
	}
}

func TestKVPath(t *testing.T) {
	if got := kvPath("secret", "coredns/certs", "example.com"); got != "secret/data/coredns/certs/example.com" {
		t.Errorf("kvPath = %q", got)
	}
}
