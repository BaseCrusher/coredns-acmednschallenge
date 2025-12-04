package acmednschallenge

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"golang.org/x/net/idna"
)

func toCertFileName(domain string) string {
	return fmt.Sprintf("%s.crt", domain)
}

func toKeyFileName(domain string) string {
	return fmt.Sprintf("%s.key", domain)
}

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
}

func getSavedCert(certSavePath string, domain string) *certificate.Resource {
	certFile := filepath.Join(certSavePath, toCertFileName(domain))
	keyFile := filepath.Join(certSavePath, toKeyFileName(domain))

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil
	}

	return &certificate.Resource{
		Domain:      domain,
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}
}

func writeFile(certSavePath string, domain, extension string, permission fs.FileMode, data []byte) error {
	baseFileName := sanitizedDomain(domain)
	filePath := filepath.Join(certSavePath, baseFileName+extension)

	return os.WriteFile(filePath, data, permission)
}

func sanitizedDomain(domain string) string {
	safe, err := idna.ToASCII(strings.NewReplacer(":", "-", "*", "_").Replace(domain))
	if err != nil {
		log.Fatal(err)
	}

	return safe
}
