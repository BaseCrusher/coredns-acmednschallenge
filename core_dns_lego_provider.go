package acmednschallenge

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/coredns/coredns/plugin/acmednschallenge/config"
	"github.com/coredns/coredns/plugin/acmednschallenge/storage"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge/dns01"
	acmeLog "github.com/go-acme/lego/v4/log"
	"github.com/miekg/dns"
)

type coreDnsLegoProvider struct {
	acmeUser         *AcmeUser
	activeChallenges *map[string][]string

	acceptedLetsEncryptToS   bool
	managedDomains           map[string][]string
	useLetsEncryptTestServer bool
	skipDnsPropagationTest   bool
	customCAD                string
	allowInsecureCAD         bool
	customNameservers        []string
	dnsTimeout               time.Duration
}

func newCoreDnsLegoProvider(acc *config.ACMEChallengeConfig, account storage.AccountStorage, challenges *map[string][]string, loggerName string) (*coreDnsLegoProvider, error) {
	acmeLogger := clog.NewWithPlugin(loggerName)
	acmeLog.Logger = &logger{logger: acmeLogger}

	var privateKey crypto.PrivateKey
	alreadyExists := false

	if keyPEM := account.LoadAccountKey(acc.Email); keyPEM != nil {
		pk, err := certcrypto.ParsePEMPrivateKey(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("could not parse ACME account key for %s: %w", acc.Email, err)
		}
		privateKey = pk
		alreadyExists = true
		log.Infof("loaded existing Let's Encrypt account for %s", acc.Email)
	} else {
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("could not create ACME account key: %w", err)
		}
		privateKey = pk

		keyPEM := pem.EncodeToMemory(certcrypto.PEMBlock(pk))
		if err := account.SaveAccountKey(acc.Email, keyPEM); err != nil {
			return nil, err
		}
		log.Infof("registered new Let's Encrypt account for %s", acc.Email)
	}

	user := &AcmeUser{
		Email:         acc.Email,
		Key:           privateKey,
		alreadyExists: alreadyExists,
	}

	provider := &coreDnsLegoProvider{
		acmeUser:                 user,
		activeChallenges:         challenges,
		acceptedLetsEncryptToS:   acc.AcceptedLetsEncryptToS,
		managedDomains:           acc.ManagedDomains,
		useLetsEncryptTestServer: acc.UseLetsEncryptTestServer,
		customCAD:                acc.CustomCAD,
		allowInsecureCAD:         acc.AllowInsecureCAD,
		customNameservers:        acc.CustomNameservers,
		dnsTimeout:               acc.DnsTimeout,
		skipDnsPropagationTest:   acc.SkipDnsPropagationTest,
	}

	return provider, nil
}

func (p *coreDnsLegoProvider) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fdqn := dns.Fqdn(info.EffectiveFQDN)
	if (*p.activeChallenges)[fdqn] == nil {
		(*p.activeChallenges)[fdqn] = []string{}
	}

	(*p.activeChallenges)[fdqn] = append((*p.activeChallenges)[fdqn], info.Value)

	log.Infof("added TXT '%s' record for domain '%s'", info.Value, domain)
	return nil
}

func (p *coreDnsLegoProvider) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fdqn := dns.Fqdn(info.EffectiveFQDN)
	delete(*p.activeChallenges, fdqn)
	log.Infof("removed TXT '%s' record for domain '%s'", info.Value, fdqn)
	return nil
}
