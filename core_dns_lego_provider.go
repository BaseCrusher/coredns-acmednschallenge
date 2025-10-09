package acmednschallenge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/go-acme/lego/v4/challenge/dns01"
	acmeLog "github.com/go-acme/lego/v4/log"
)

type coreDnsLegoProvider struct {
	acmeUser         *AcmeUser
	activeChallenges *map[string][]string

	acceptedLetsEncryptToS   bool
	managedDomains           map[string][]string
	useLetsEncryptTestServer bool
	customCAD                string
	allowInsecureCAD         bool
	customNameservers        []string
}

func newCoreDnsLegoProvider(acc *ACMEChallengeConfig, challenges *map[string][]string, loggerName string) (*coreDnsLegoProvider, error) {
	// set lego logger to coredns logger
	acmeLogger := clog.NewWithPlugin(fmt.Sprintf("%s.lego", loggerName))
	acmeLog.Logger = &logger{logger: acmeLogger}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("could not create private key")
		return nil, errors.New("could not create ")
	}

	user := &AcmeUser{
		Email: acc.email,
		key:   privateKey,
	}

	provider := &coreDnsLegoProvider{
		acmeUser:                 user,
		activeChallenges:         challenges,
		acceptedLetsEncryptToS:   acc.acceptedLetsEncryptToS,
		managedDomains:           acc.managedDomains,
		useLetsEncryptTestServer: acc.useLetsEncryptTestServer,
		customCAD:                acc.customCAD,
		allowInsecureCAD:         acc.allowInsecureCAD,
		customNameservers:        acc.customNameservers,
	}

	return provider, nil
}

func (p *coreDnsLegoProvider) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	if (*p.activeChallenges)[info.EffectiveFQDN] == nil {
		(*p.activeChallenges)[info.EffectiveFQDN] = []string{}
	}
	log.Info(info.Value)
	(*p.activeChallenges)[info.EffectiveFQDN] = append((*p.activeChallenges)[info.EffectiveFQDN], info.Value)
	return nil
}

func (p *coreDnsLegoProvider) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	delete(*p.activeChallenges, info.EffectiveFQDN)
	return nil
}
