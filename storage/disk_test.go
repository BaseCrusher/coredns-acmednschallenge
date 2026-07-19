package storage

import (
	"testing"

	"github.com/go-acme/lego/v4/certificate"
)

func TestNewUnknownType(t *testing.T) {
	if _, err := New(Options{Type: "s3"}); err == nil {
		t.Fatal("expected error for unknown storage type")
	}
}

func TestDiskRoundTrip(t *testing.T) {
	s, err := New(Options{Type: "disk", DiskPath: t.TempDir(), KeyMode: 0600})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := []byte("-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n")
	in := &certificate.Resource{Domain: "example.com", PrivateKey: key}
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	out := s.Load("example.com")
	if out == nil {
		t.Fatal("Load returned nil after Save")
	}
	if out.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", out.Domain)
	}

	if s.Load("missing.com") != nil {
		t.Error("Load of unknown domain should return nil")
	}
}

func TestNewAccountUnknownType(t *testing.T) {
	if _, err := NewAccount(Options{Type: "s3"}); err == nil {
		t.Fatal("expected error for unknown account storage type")
	}
}

func TestNewAccountDisk(t *testing.T) {
	a, err := NewAccount(Options{Type: "disk", DiskPath: t.TempDir()})
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	if _, ok := a.(*DiskAccount); !ok {
		t.Fatalf("got %T, want *DiskAccount", a)
	}
}

func TestDiskAccountRoundTrip(t *testing.T) {
	a := NewDiskAccount(t.TempDir())

	if a.LoadAccountKey("test@test.com") != nil {
		t.Fatal("expected nil for absent account key")
	}

	key := []byte("-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n")
	if err := a.SaveAccountKey("test@test.com", key); err != nil {
		t.Fatalf("SaveAccountKey: %v", err)
	}

	got := a.LoadAccountKey("test@test.com")
	if string(got) != string(key) {
		t.Errorf("LoadAccountKey = %q, want %q", got, key)
	}
}
