package acmednschallenge

import (
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

func checkIfCertIsValid(ac *acmeChallenge, certs *certificate.Resource) bool {
	block, _ := pem.Decode(certs.Certificate)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	log.Infof("Certificate for %s expires in %d days", certs.Domain, daysLeft)

	if time.Now().After(cert.NotAfter) {
		return false
	}

	if daysLeft < int(ac.config.renewBeforeDays) {
		return false
	}

	return true
}
