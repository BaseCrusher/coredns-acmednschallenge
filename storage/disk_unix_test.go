//go:build unix

package storage

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/go-acme/lego/v4/certificate"
)

func TestDiskChgrp(t *testing.T) {
	// chgrp to our own gid: always permitted, so this runs unprivileged.
	gid := os.Getgid()
	dir := t.TempDir()
	s, err := New(Options{Type: "disk", DiskPath: dir, KeyMode: 0640, Gid: gid})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	in := &certificate.Resource{Domain: "example.com", PrivateKey: []byte("k")}
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	fi, err := os.Stat(filepath.Join(dir, "certs", "example.com.key"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := int(fi.Sys().(*syscall.Stat_t).Gid); got != gid {
		t.Errorf("cert file gid = %d, want %d", got, gid)
	}
}
