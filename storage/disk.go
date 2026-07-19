package storage

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/go-acme/lego/v4/certificate"
	"golang.org/x/net/idna"
)

var log = clog.NewWithPlugin("acmednschallenge")

type Disk struct {
	certsPath string
	keyMode   fs.FileMode
}

func NewDisk(dataPath string, keyMode fs.FileMode) (*Disk, error) {
	certsPath := filepath.Join(dataPath, "certs")
	if err := os.MkdirAll(certsPath, os.ModePerm); err != nil {
		return nil, fmt.Errorf("could not create certificates directory at %s: %w", certsPath, err)
	}
	return &Disk{certsPath: certsPath, keyMode: keyMode}, nil
}

func (d *Disk) Save(certs *certificate.Resource) error {
	if err := d.writeFile(certs.Domain, ".key", certs.PrivateKey); err != nil {
		return fmt.Errorf("unable to save key file: %w", err)
	}

	if err := d.writeFile(certs.Domain, ".pem", bytes.Join([][]byte{certs.Certificate, certs.PrivateKey}, nil)); err != nil {
		return fmt.Errorf("unable to save PEM file: %w", err)
	}

	jsonBytes, err := json.MarshalIndent(certs, "", "\t")
	if err != nil {
		return fmt.Errorf("unable to marshal CertResource for domain %s: %w", certs.Domain, err)
	}

	if err := d.writeFile(certs.Domain, ".json", jsonBytes); err != nil {
		return fmt.Errorf("unable to save CertResource for domain %s: %w", certs.Domain, err)
	}

	return nil
}

func (d *Disk) Load(domain string) *certificate.Resource {
	raw, err := d.readFile(domain, ".json")
	if err != nil {
		return nil
	}
	var resource certificate.Resource
	if err = json.Unmarshal(raw, &resource); err != nil {
		return nil
	}

	content, err := d.readFile(domain, ".pem")
	if err != nil {
		return nil
	}

	var certBytes, keyBytes []byte

	block, _ := pem.Decode(content)
	if block == nil {
		return nil
	}

	switch block.Type {
	case "CERTIFICATE":
		certBytes = pem.EncodeToMemory(block)
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		keyBytes = pem.EncodeToMemory(block)
	}

	resource.Certificate = certBytes
	resource.PrivateKey = keyBytes

	return &resource
}

func (d *Disk) readFile(domain, extension string) ([]byte, error) {
	return os.ReadFile(filepath.Join(d.certsPath, getFileName(domain, extension)))
}

func (d *Disk) writeFile(domain, extension string, data []byte) error {
	return os.WriteFile(filepath.Join(d.certsPath, getFileName(domain, extension)), data, d.keyMode)
}

func getFileName(domain, extension string) string {
	return sanitizedDomain(domain) + extension
}

func sanitizedDomain(domain string) string {
	safe, err := idna.ToASCII(strings.NewReplacer(":", "-", "*", "_").Replace(domain))
	if err != nil {
		log.Fatal(err)
	}

	return safe
}

type DiskAccount struct {
	dataPath string
}

func NewDiskAccount(dataPath string) *DiskAccount {
	return &DiskAccount{dataPath: dataPath}
}

func (d *DiskAccount) keyPath(email string) string {
	return filepath.Join(d.dataPath, "users", email, "key.pem")
}

func (d *DiskAccount) SaveAccountKey(email string, keyPEM []byte) error {
	keyFile := d.keyPath(email)
	if err := os.MkdirAll(filepath.Dir(keyFile), os.ModePerm); err != nil {
		return fmt.Errorf("could not create account key directory: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("could not write account key: %w", err)
	}
	return nil
}

func (d *DiskAccount) LoadAccountKey(email string) []byte {
	keyPEM, err := os.ReadFile(d.keyPath(email))
	if err != nil {
		return nil
	}
	return keyPEM
}
