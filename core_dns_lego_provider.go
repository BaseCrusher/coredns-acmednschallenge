package acmednschallenge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	dnsTimeout               time.Duration
}

func newCoreDnsLegoProvider(acc *ACMEChallengeConfig, challenges *map[string][]string, loggerName string) (*coreDnsLegoProvider, error) {
	// set lego logger to coredns logger
	acmeLogger := clog.NewWithPlugin(fmt.Sprintf("%s.lego", loggerName))
	acmeLog.Logger = &logger{logger: acmeLogger}

	userFile := filepath.Join(acc.certSavePath, "user.json")
	var user *AcmeUser

	data, err := os.ReadFile(userFile)
	if err == nil {
		user = &AcmeUser{}
		if err := json.Unmarshal(data, user); err != nil {
			user = nil
		}
	}

	if user == nil {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal("could not create private key")
			return nil, errors.New("could not create ")
		}

		user = &AcmeUser{
			Email: acc.email,
			Key:   privateKey,
		}

		userJson, err := json.Marshal(user)
		if err != nil {
			log.Fatal("could not marshal user to JSON")
			return nil, errors.New("could not marshal user")
		}

		err = os.MkdirAll(acc.certSavePath, os.ModePerm)
		if err != nil {
			log.Fatalf("could not write user.json. err: %s", err)
			return nil, errors.New("could not write user.json")
		}

		err = os.WriteFile(userFile, userJson, 0600)
		if err != nil {
			log.Fatalf("could not write user.json. err: %s", err)
			return nil, errors.New("could not write user.json")
		}
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
		dnsTimeout:               acc.dnsTimeout,
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
