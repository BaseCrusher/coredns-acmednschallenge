package storage

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	fileMode  fs.FileMode
	groupId   int
}

func NewDisk(dataPath string, fileMode fs.FileMode, groupId int) (*Disk, error) {
	certsPath := filepath.Join(dataPath, "certs")
	if err := os.MkdirAll(certsPath, dirMode(fileMode)); err != nil {
		return nil, fmt.Errorf("could not create certificates directory at %s: %w", certsPath, err)
	}
	if err := applyPerms(certsPath, dirMode(fileMode), groupId); err != nil {
		return nil, err
	}
	d := &Disk{certsPath: certsPath, fileMode: fileMode, groupId: groupId}
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
		if err := applyPerms(filepath.Join(d.certsPath, e.Name()), d.fileMode, d.groupId); err != nil {
			return err
		}
	}
	return nil
}

func applyPerms(path string, mode fs.FileMode, groupId int) error {
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("could not set mode on %s: %w", path, err)
	}
	if groupId > 0 {
		if err := os.Chown(path, -1, groupId); err != nil {
			return fmt.Errorf("could not set group %d on %s: %w", groupId, path, err)
		}
	}
	return nil
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
	path := filepath.Join(d.certsPath, getFileName(domain, extension))
	if err := os.WriteFile(path, data, d.fileMode); err != nil {
		return err
	}
	return applyPerms(path, d.fileMode, d.groupId)
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
	fileMode fs.FileMode
	groupId  int
}

func NewDiskAccount(dataPath string, fileMode fs.FileMode, groupId int) (*DiskAccount, error) {
	d := &DiskAccount{dataPath: dataPath, fileMode: fileMode, groupId: groupId}
	if err := d.reconcile(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *DiskAccount) reconcile() error {
	root := filepath.Join(d.dataPath, "users")
	if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := d.fileMode
		if e.IsDir() {
			mode = dirMode(d.fileMode)
		}
		return applyPerms(p, mode, d.groupId)
	})
}

func (d *DiskAccount) keyPath(email string) string {
	return filepath.Join(d.dataPath, "users", email, "key.pem")
}

func (d *DiskAccount) SaveAccountKey(email string, keyPEM []byte) error {
	keyFile := d.keyPath(email)
	emailDir := filepath.Dir(keyFile)
	if err := os.MkdirAll(emailDir, dirMode(d.fileMode)); err != nil {
		return fmt.Errorf("could not create account key directory: %w", err)
	}
	for _, dir := range []string{filepath.Dir(emailDir), emailDir} {
		if err := applyPerms(dir, dirMode(d.fileMode), d.groupId); err != nil {
			return err
		}
	}
	if err := os.WriteFile(keyFile, keyPEM, d.fileMode); err != nil {
		return fmt.Errorf("could not write account key: %w", err)
	}
	return applyPerms(keyFile, d.fileMode, d.groupId)
}

func (d *DiskAccount) LoadAccountKey(email string) []byte {
	keyPEM, err := os.ReadFile(d.keyPath(email))
	if err != nil {
		return nil
	}
	return keyPEM
}
