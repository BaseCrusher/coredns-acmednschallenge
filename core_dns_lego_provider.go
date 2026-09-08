package acmednschallenge

import (
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
	activeChallenges *challengeStore

	acceptedLetsEncryptToS   bool
	managedDomains           map[string][]string
	useLetsEncryptTestServer bool
	skipDnsPropagationTest   bool
	customCAD                string
	allowInsecureCAD         bool
	customNameservers        []string
	dnsTimeout               time.Duration
}

func newCoreDnsLegoProvider(acc *config.ACMEChallengeConfig, account storage.AccountStorage, challenges *challengeStore, loggerName string) (*coreDnsLegoProvider, error) {
	acmeLogger := clog.NewWithPlugin(loggerName)
	acmeLog.Logger = &logger{logger: acmeLogger}

	user := &AcmeUser{Email: acc.Email}
	if keyPEM := account.LoadAccountKey(acc.Email); keyPEM != nil {
		pk, err := certcrypto.ParsePEMPrivateKey(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("could not parse ACME account key for %s: %w", acc.Email, err)
		}
		user.Key = pk
		user.alreadyExists = true
		log.Infof("loaded existing Let's Encrypt account for %s", acc.Email)
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
	p.activeChallenges.add(fdqn, info.Value)

	log.Infof("added TXT '%s' record for domain '%s'", info.Value, domain)
	return nil
}

func (p *coreDnsLegoProvider) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fdqn := dns.Fqdn(info.EffectiveFQDN)
	p.activeChallenges.remove(fdqn)
	log.Infof("removed TXT '%s' record for domain '%s'", info.Value, fdqn)
	return nil
}
