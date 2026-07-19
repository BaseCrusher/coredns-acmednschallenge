package storage

import (
	"context"
	"testing"

	"github.com/go-acme/lego/v4/certificate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSecretsRoundTrip(t *testing.T) {
	s := newSecrets(fake.NewClientset(), "certs-ns")

	in := &certificate.Resource{
		Domain:      "example.com",
		CertURL:     "https://acme/cert/1",
		Certificate: []byte("CERT"),
		PrivateKey:  []byte("KEY"),
	}
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	in.Certificate = []byte("CERT2")
	if err := s.Save(in); err != nil {
		t.Fatalf("second Save (update): %v", err)
	}

	out := s.Load("example.com")
	if out == nil {
		t.Fatal("Load returned nil after Save")
	}
	if out.Domain != "example.com" || out.CertURL != "https://acme/cert/1" {
		t.Errorf("metadata not restored: %+v", out)
	}
	if string(out.Certificate) != "CERT2" || string(out.PrivateKey) != "KEY" {
		t.Errorf("tls material not restored: cert=%q key=%q", out.Certificate, out.PrivateKey)
	}

	if s.Load("missing.com") != nil {
		t.Error("Load of unknown domain should return nil")
	}
}

func TestSecretsTypeAndName(t *testing.T) {
	client := fake.NewClientset()
	s := newSecrets(client, "ns")
	if err := s.Save(&certificate.Resource{Domain: "*.example.com", Certificate: []byte("c"), PrivateKey: []byte("k")}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	sec, err := client.CoreV1().Secrets("ns").Get(context.Background(), "wildcard.example.com", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected secret named wildcard.example.com: %v", err)
	}
	if sec.Type != corev1.SecretTypeTLS {
		t.Errorf("secret type = %q, want %q", sec.Type, corev1.SecretTypeTLS)
	}
}

func TestSecretsAccountRoundTrip(t *testing.T) {
	client := fake.NewClientset()
	a := &SecretsAccount{client: client, namespace: "acme-ns"}

	if a.LoadAccountKey("test@test.com") != nil {
		t.Fatal("expected nil for absent account key")
	}

	key := []byte("-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n")
	if err := a.SaveAccountKey("test@test.com", key); err != nil {
		t.Fatalf("SaveAccountKey: %v", err)
	}
	if err := a.SaveAccountKey("test@test.com", key); err != nil {
		t.Fatalf("second SaveAccountKey (update): %v", err)
	}

	if got := a.LoadAccountKey("test@test.com"); string(got) != string(key) {
		t.Errorf("LoadAccountKey = %q, want %q", got, key)
	}

	sec, err := client.CoreV1().Secrets("acme-ns").Get(context.Background(), "acme-account-test-test.com", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected secret acme-account-test-test.com: %v", err)
	}
	if sec.Type != corev1.SecretTypeOpaque {
		t.Errorf("secret type = %q, want %q", sec.Type, corev1.SecretTypeOpaque)
	}
}
