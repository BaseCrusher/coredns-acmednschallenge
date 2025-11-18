package acmednschallenge

import (
	"crypto/tls"
	"net/http"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

func (p *coreDnsLegoProvider) renewCertificate(certs *certificate.Resource) (*certificate.Resource, error) {
	client, err := p.getAcmeClient()
	if err != nil {
		return nil, err
	}

	renewOptions := &certificate.RenewOptions{
		Bundle:     true,
		MustStaple: false,
	}

	renewedCerts, err := client.Certificate.RenewWithOptions(*certs, renewOptions)
	if err != nil {
		return nil, err
	}

	return renewedCerts, nil
}

func (p *coreDnsLegoProvider) obtainNewCertificate(mainDomain string) (*certificate.Resource, error) {
	client, err := p.getAcmeClient()
	if err != nil {
		return nil, err
	}

	additionalSans, ok := p.managedDomains[mainDomain]
	if !ok {
		additionalSans = []string{}
	}

	domains := []string{mainDomain}
	domains = append(domains, additionalSans...)

	r := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(r)
	if err != nil {
		return nil, err
	}

	return certificates, nil
}

func (p *coreDnsLegoProvider) getAcmeClient() (*lego.Client, error) {
	config := lego.NewConfig(p.acmeUser)
	if p.customCAD != "" {
		config.CADirURL = p.customCAD
	} else {
		config.CADirURL = lego.LEDirectoryProduction
		if p.useLetsEncryptTestServer {
			config.CADirURL = lego.LEDirectoryStaging
		}
	}

	config.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: p.allowInsecureCAD},
	}

	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	dnsTimeout := dns01.AddDNSTimeout(p.dnsTimeout)

	if len(p.customNameservers) < 1 {
		err = client.Challenge.SetDNS01Provider(p, dnsTimeout)
	} else {
		err = client.Challenge.SetDNS01Provider(p, dnsTimeout, dns01.AddRecursiveNameservers(p.customNameservers))
	}

	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: p.acceptedLetsEncryptToS})
	if err != nil {
		return nil, err
	}
	p.acmeUser.Registration = reg

	return client, nil
}
