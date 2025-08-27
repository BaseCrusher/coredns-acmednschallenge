package acmednschallenge

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certificate"
)

func assertCertificateDirectoryExist(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			return fmt.Errorf("error creating directory: %s", err)
		}
		log.Infof("Created directory: %s", path)
	}
	return nil
}

func toCertFileName(domain string) string {
	return fmt.Sprintf("%s.pem", domain)
}

func toKeyFileName(domain string) string {
	return fmt.Sprintf("%s.key.pem", domain)
}

func saveCerts(certSavePath string, certs *certificate.Resource) {
	keyPath := filepath.Join(certSavePath, toKeyFileName(certs.Domain))
	writeCert(certs.PrivateKey, keyPath, 0600)

	fullCertChain := append(certs.Certificate, certs.IssuerCertificate...)
	certPath := filepath.Join(certSavePath, toCertFileName(certs.Domain))
	writeCert(fullCertChain, certPath, 0644)
}

func writeCert(content []byte, path string, permission os.FileMode) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, permission)
	if err != nil {
		log.Errorf("Error creating file: %s", err)
		return
	}
	defer func() {
		if cert := file.Close(); cert != nil {
			log.Errorf("Error closing file %s: %s", file.Name(), cert)
		}
	}()

	if _, err := file.Write(content); err != nil {
		log.Errorf("Error writing to file: %s", err)
		return
	}

	log.Infof("Successfully wrote to %s", file.Name())
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

	if info, err := os.Stat(certFile); err == nil && info.Mode().Perm() != 0o644 {
		return nil
	}
	if info, err := os.Stat(keyFile); err == nil && info.Mode().Perm() != 0o600 {
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
