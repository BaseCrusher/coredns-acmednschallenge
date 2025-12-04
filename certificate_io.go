package acmednschallenge

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"golang.org/x/net/idna"
)

func saveCerts(certSavePath string, certs *certificate.Resource, privateKeyPermission fs.FileMode) {
	err := writeFile(certSavePath, certs.Domain, ".key", privateKeyPermission, certs.PrivateKey)
	if err != nil {
		log.Errorf("unable to save key file: %s", err)
		return
	}

	err = writeFile(certSavePath, certs.Domain, ".pem", privateKeyPermission, bytes.Join([][]byte{certs.Certificate, certs.PrivateKey}, nil))
	if err != nil {
		log.Errorf("unable to save PEM file: %s", err)
		return
	}

	jsonBytes, err := json.MarshalIndent(certs, "", "\t")
	if err != nil {
		log.Fatalf("Unable to marshal CertResource for domain %s\n\t%v", certs.Domain, err)
	}

	err = writeFile(certSavePath, certs.Domain, ".json", privateKeyPermission, jsonBytes)
	if err != nil {
		log.Fatalf("Unable to save CertResource for domain %s\n\t%v", certs.Domain, err)
	}
}

func readCerts(certSavePath string, domain string) *certificate.Resource {
	raw, _ := readFile(certSavePath, domain, ".json")
	var resource certificate.Resource
	json.Unmarshal(raw, &resource)

	return &resource
}

func readFile(certSavePath string, domain, extension string) ([]byte, error) {
	filePath := filepath.Join(certSavePath, getFileName(domain, extension))
	return os.ReadFile(filePath)
}

func writeFile(certSavePath string, domain, extension string, permission fs.FileMode, data []byte) error {
	filePath := filepath.Join(certSavePath, getFileName(domain, extension))
	return os.WriteFile(filePath, data, permission)
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
