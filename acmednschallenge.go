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

type responseRecorder struct {
	dns.ResponseWriter
	Msg *dns.Msg
}

func (r *responseRecorder) WriteMsg(msg *dns.Msg) error {
	r.Msg = msg
	return nil // don’t write yet
}

func (ac *acmeChallenge) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if ac.Next == nil {
		log.Error("There is no further plugins configured. The ACME plugin only works if there is at least one plugin after it.")
		return dns.RcodeRefused, nil
	}

	state := request.Request{W: w, Req: r}

	qName := state.QName()
	isAcmeChallenge := strings.HasPrefix(strings.ToLower(qName), "_acme-challenge.")
	isTxtRequest := state.QType() == dns.TypeTXT

	// when this has nothing to do with ACME, delegate to the next plugin
	if !isAcmeChallenge || !isTxtRequest {
		return plugin.NextOrFailure(ac.Name(), ac.Next, ctx, w, r)
	}

	// check if this plugin manages this txt record. if not, delegate to the next plugin
	txtValues, ok := (*ac.challenges)[qName]
	if (!ok) || (len(txtValues) == 0) {
		return plugin.NextOrFailure(ac.Name(), ac.Next, ctx, w, r)
	}

	// -----------------------------
	// Capture downstream response
	// -----------------------------
	rec := &responseRecorder{ResponseWriter: w}
	rcode, err := plugin.NextOrFailure(ac.Name(), ac.Next, ctx, rec, r)
	if err != nil {
		log.Infof("Error delegating to next plugin: %v", err)
		return rcode, err
	}

	// -----------------------------
	// Merge ACME TXT answers
	// -----------------------------
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	msg.SetReply(r)
	msg.Authoritative = false
	msg.Ns = rec.Msg.Ns
	msg.Extra = rec.Msg.Extra

	for _, txt := range txtValues {
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(qName),
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ac.config.dnsTTL,
			},
			Txt: []string{txt},
		})
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Infof("Failed to write merged DNS response: %v", err)
		return dns.RcodeServerFailure, err
	}

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
