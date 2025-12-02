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
	isAcmeChallenge := strings.HasPrefix(strings.ToLower(qName), "_acme-challenge.")
	isTxtRequest := state.QType() == dns.TypeTXT

	txtValues, ok := (*ac.challenges)[qName]

	if !ok || !isAcmeChallenge || !isTxtRequest {
		return plugin.NextOrFailure(ac.Name(), ac.Next, ctx, w, r)
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	for _, rr := range txtValues {
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(qName),
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ac.config.dnsTTL,
			},
			Txt: []string{rr},
		})
		msg.Authoritative = true
	}

	msg.Ns = append(msg.Ns,
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:   "swarm-dev2.ms-dev.ch.", // zone apex
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    ac.config.dnsTTL,
			},
			Ns:      "ns1.dev2.ms-dev.ch.",
			Mbox:    "dns-hostmaster.swarm-dev2.ms-dev.ch.",
			Serial:  uint32(time.Now().Unix()),
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  ac.config.dnsTTL,
		},
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   "swarm-dev2.ms-dev.ch.", // zone apex
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    ac.config.dnsTTL,
			},
			Ns: "ns1.dev2.ms-dev.ch.",
		},
	)

	w.WriteMsg(msg)

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
