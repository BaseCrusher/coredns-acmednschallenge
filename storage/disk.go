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
	certsPath    string
	certFileMode fs.FileMode
	jsonFileMode fs.FileMode
	groupId      int
}

func NewDisk(dataPath string, certFileMode, jsonFileMode fs.FileMode, groupId int) (*Disk, error) {
	certsPath := filepath.Join(dataPath, "certs")
	if err := os.MkdirAll(certsPath, dirMode(certFileMode)); err != nil {
		return nil, fmt.Errorf("could not create certificates directory at %s: %w", certsPath, err)
	}
	if err := os.Chmod(certsPath, dirMode(certFileMode)); err != nil {
		return nil, fmt.Errorf("could not set mode on %s: %w", certsPath, err)
	}
	if groupId > 0 {
		if err := os.Chown(certsPath, -1, groupId); err != nil {
			return nil, fmt.Errorf("could not set group %d on %s: %w", groupId, certsPath, err)
		}
	}
	d := &Disk{certsPath: certsPath, certFileMode: certFileMode, jsonFileMode: jsonFileMode, groupId: groupId}
	if err := d.reconcile(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Disk) reconcile() error {
	entries, err := os.ReadDir(d.certsPath)
	if err != nil {
		return fmt.Errorf("could not read certificates directory at %s: %w", d.certsPath, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(d.certsPath, e.Name())
		if err := os.Chmod(p, d.modeFor(e.Name())); err != nil {
			return fmt.Errorf("could not set mode on %s: %w", p, err)
		}
		if d.groupId > 0 {
			if err := os.Chown(p, -1, d.groupId); err != nil {
				return fmt.Errorf("could not set group %d on %s: %w", d.groupId, p, err)
			}
		}
	}
	return nil
}

func (d *Disk) modeFor(name string) fs.FileMode {
	if filepath.Ext(name) == ".json" {
		return d.jsonFileMode
	}
	return d.certFileMode
}

func dirMode(m fs.FileMode) fs.FileMode {
	d := m
	for _, r := range []fs.FileMode{0400, 0040, 0004} {
		if m&r != 0 {
			d |= r >> 2
		}
	}
	return d
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
	name := getFileName(domain, extension)
	path := filepath.Join(d.certsPath, name)
	if err := os.WriteFile(path, data, d.modeFor(name)); err != nil {
		return err
	}
	if d.groupId > 0 {
		if err := os.Chown(path, -1, d.groupId); err != nil {
			return fmt.Errorf("could not set group %d on %s: %w", d.groupId, path, err)
		}
	}
	return nil
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
