package acmednschallenge

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	customCAD                string
	allowInsecureCAD         bool
	customNameservers        []string
	dnsTimeout               time.Duration
}

func newCoreDnsLegoProvider(acc *ACMEChallengeConfig, challenges *map[string][]string, loggerName string) (*coreDnsLegoProvider, error) {
	// set lego logger to coredns logger
	acmeLogger := clog.NewWithPlugin(fmt.Sprintf("%s", loggerName))
	acmeLog.Logger = &logger{logger: acmeLogger}

	var privateKey crypto.PrivateKey

	keyFile := filepath.Join(acc.dataPath, "users", acc.email, "key.pem")

	if err := os.MkdirAll(filepath.Dir(keyFile), os.ModePerm); err != nil {
		log.Debug("could not create directory structure")
		return nil, err
	}

	keyBytes, err := os.ReadFile(keyFile)
	alreadyExists := false

	if err != nil {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Debug("could not create private key")
			return nil, err
		}

		err = os.MkdirAll(acc.dataPath, os.ModePerm)
		if err != nil {
			log.Debugf("could not write user.json. err: %s", err)
			return nil, errors.New("could not write user.json")
		}

		certOut, err := os.Create(keyFile)
		if err != nil {
			log.Debugf("could not create file at %s", keyFile)
			return nil, err
		}

		defer func(certOut *os.File) {
			err := certOut.Close()
			if err != nil {
				log.Debugf("could not write file at %s", keyFile)
			}
		}(certOut)

		pemKey := certcrypto.PEMBlock(privateKey)

		err = pem.Encode(certOut, pemKey)
		if err != nil {
			log.Debug("could not encode the certificate")
			return nil, err
		}
		log.Infof("setup new Let's Encrypt %s", keyFile)
	} else {
		privateKey, err = certcrypto.ParsePEMPrivateKey(keyBytes)
		if err != nil {
			log.Debug("could not parse private key")
			return nil, err
		}
		log.Infof("loaded existing Let's Encrypt user from %s", keyFile)
		alreadyExists = true
	}

	user := &AcmeUser{
		Email:         acc.email,
		Key:           privateKey,
		alreadyExists: alreadyExists,
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
