package storage

import "fmt"

type AccountStorage interface {
	SaveAccountKey(email string, keyPEM []byte) error
	LoadAccountKey(email string) []byte
}

func NewAccount(o Options) (AccountStorage, error) {
	switch o.Type {
	case "disk":
		return NewDiskAccount(o.DiskPath), nil
	case "kubernetesSecrets":
		return NewSecretsAccount(o.Namespace)
	case "vault":
		return NewVaultAccount(o)
	default:
		return nil, fmt.Errorf("unknown storage type: %s", o.Type)
	}
}
