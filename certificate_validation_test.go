package acmednschallenge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/acmednschallenge/config"
	"github.com/go-acme/lego/v4/certificate"
)

func makeCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCheckIfCertIsValid(t *testing.T) {
	ac := &acmeChallenge{config: &config.ACMEChallengeConfig{RenewBeforeDays: 10}}

	tests := []struct {
		name string
		cert []byte
		want bool
	}{
		{name: "valid with plenty of days", cert: makeCertPEM(t, time.Now().Add(30*24*time.Hour)), want: true},
		{name: "within renew window", cert: makeCertPEM(t, time.Now().Add(5*24*time.Hour)), want: false},
		{name: "expired", cert: makeCertPEM(t, time.Now().Add(-time.Hour)), want: false},
		{name: "not pem", cert: []byte("this is not a pem block"), want: false},
		{name: "wrong block type", cert: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}), want: false},
		{name: "unparseable certificate", cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certs := &certificate.Resource{Domain: "example.com", Certificate: tc.cert}
			if got := checkIfCertIsValid(ac, certs); got != tc.want {
				t.Errorf("checkIfCertIsValid = %v, want %v", got, tc.want)
			}
		})
	}
}
