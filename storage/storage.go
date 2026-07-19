package storage

import (
	"fmt"
	"io/fs"

	"github.com/go-acme/lego/v4/certificate"
)

type CertStorage interface {
	Save(certs *certificate.Resource) error
	Load(domain string) *certificate.Resource
}

type Options struct {
	Type string

	DiskPath string
	KeyMode  fs.FileMode
	Gid      int // group owner for cert files; <= 0 means leave unchanged

	Namespace string

	VaultMount  string
	VaultPrefix string
	VaultAuth   string
	VaultRole   string
}

func New(o Options) (CertStorage, error) {
	switch o.Type {
	case "disk":
		return NewDisk(o.DiskPath, o.KeyMode, o.Gid)
	case "kubernetesSecrets":
		return NewSecrets(o.Namespace)
	case "vault":
		return NewVaultCerts(o)
	default:
		return nil, fmt.Errorf("unknown storage type: %s", o.Type)
	}
}
