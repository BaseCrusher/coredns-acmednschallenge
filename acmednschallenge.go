package acmednschallenge

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin(name)

type acmeChallenge struct {
	Next            plugin.Handler
	config          *ACMEChallengeConfig
	challenges      *map[string][]string
	coreDNSProvider *coreDnsLegoProvider
}

func newAcmeChallenge(config *ACMEChallengeConfig) (*acmeChallenge, error) {
	challenges := make(map[string][]string)
	coreDNSProvider, err := newCoreDnsLegoProvider(config, &challenges, fmt.Sprintf("%s/acme", name))
	if err != nil {
		return nil, err
	}

	challenge := &acmeChallenge{
		config:          config,
		challenges:      &challenges,
		coreDNSProvider: coreDNSProvider,
	}

	return challenge, nil
}

func (ac *acmeChallenge) Name() string { return name }

func (ac *acmeChallenge) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	qName := state.QName()
	qType := state.Type()

	isAcmeChallenge := strings.HasPrefix(strings.ToLower(qName), "_acme-challenge.")
	isTxtRequest := qType == "TXT"

	txtValues, ok := (*ac.challenges)[qName]

	if isAcmeChallenge && !isTxtRequest && ok {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	if !isTxtRequest || !isAcmeChallenge {
		log.Debugf("request was not a dns challenge. Domain: %s, Type: %s", qName, qType)
		return plugin.NextOrFailure(ac.Name(), ac.Next, ctx, w, r)
	}

	if !ok {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, txtValue := range txtValues {
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(qName),
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ac.config.dnsTTL,
			},
			Txt: []string{txtValue},
		}
		m.Answer = append(m.Answer, rr)
	}

	_ = w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

func (ac *acmeChallenge) start() {

	log.Info("started certificate service")

	ac.checkAndUpdateCertForAllDomains()

	uptimeTicker := time.NewTicker(ac.config.certValidationInterval)

	for {
		select {
		case <-uptimeTicker.C:
			ac.checkAndUpdateCertForAllDomains()
		}
	}
}

func (ac *acmeChallenge) checkAndUpdateCertForAllDomains() {
	log.Info("starting cert validation!")

	if err := assertCertificateDirectoryExist(ac.config.certSavePath); err != nil {
		log.Errorf("cannot create or access certificate directory: %s", err)
		return
	}

	var wg sync.WaitGroup
	for domain := range maps.Keys(ac.config.managedDomains) {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()

			isNew, certs, err := ac.checkAndCreateOrRenewCert(d)
			if err != nil {
				log.Error(err)
				return
			}
			if isNew {
				saveCerts(ac.config.certSavePath, certs)
			} else {
				log.Infof("Certificate for domain '%s' is still valid, do nothing", d)
			}
		}(domain)
	}

	wg.Wait()
}

func (ac *acmeChallenge) checkAndCreateOrRenewCert(domain string) (bool, *certificate.Resource, error) {
	certs := getSavedCert(ac.config.certSavePath, domain)
	if certs == nil {
		log.Infof("No certificate found for %s, obtaining new one", domain)
		certs, err := ac.coreDNSProvider.obtainNewCertificate(domain)
		return true, certs, err
	} else {
		log.Infof("Loaded certificate for %s", domain)
		if !checkIfCertIsValid(ac, certs) {
			certs, err := ac.coreDNSProvider.renewCertificate(certs)
			if err != nil {
				log.Errorf("Error renewing certificate. the cert for the domain '%s' is probably to old. Trying to obtain a new one.", domain)
				certs, err := ac.coreDNSProvider.obtainNewCertificate(domain)
				return true, certs, err
			}
			return true, certs, err
		}

		return false, certs, nil
	}
}
