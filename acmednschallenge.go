package acmednschallenge

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/acmednschallenge/config"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/acmednschallenge/storage"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin(name)

type acmeChallenge struct {
	Next            plugin.Handler
	config          *config.ACMEChallengeConfig
	challenges      *challengeStore
	coreDNSProvider *coreDnsLegoProvider
	storage         storage.CertStorage
	obtainOrRenew   func(domain string) (bool, *certificate.Resource, error)
	cluster         *cluster
}

func newAcmeChallenge(config *config.ACMEChallengeConfig) (*acmeChallenge, error) {
	challenges := newChallengeStore()

	accountStore, err := storage.NewAccount(config.Account)
	if err != nil {
		return nil, err
	}

	coreDNSProvider, err := newCoreDnsLegoProvider(config, accountStore, challenges, fmt.Sprintf("%s/acme", name))
	if err != nil {
		return nil, err
	}

	certStorage, err := storage.New(config.Storage)
	if err != nil {
		return nil, err
	}

	challenge := &acmeChallenge{
		config:          config,
		challenges:      challenges,
		coreDNSProvider: coreDNSProvider,
		storage:         certStorage,
	}
	challenge.obtainOrRenew = challenge.checkAndCreateOrRenewCert

	if config.Cluster != nil {
		challenge.cluster = newCluster(challenge, config.Cluster)
	}

	return challenge, nil
}

func (ac *acmeChallenge) Name() string { return name }

func (ac *acmeChallenge) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if ac.Next == nil {
		log.Error("There is no further plugins configured. The ACME plugin only works if there is at least one plugin after it.")
		return dns.RcodeRefused, nil
	}

	state := request.Request{W: w, Req: r}

	qName := state.QName()
	qNameFqdn := dns.Fqdn(strings.ToLower(qName))
	isAcmeChallenge := strings.HasPrefix(qNameFqdn, "_acme-challenge.")
	isTxtRequest := state.QType() == dns.TypeTXT

	if !isAcmeChallenge || !isTxtRequest {
		return plugin.NextOrFailure(ac.Name(), ac.Next, ctx, w, r)
	}

	txtValues, ok := ac.challenges.get(qNameFqdn)
	if (!ok) || (len(txtValues) == 0) {
		return plugin.NextOrFailure(ac.Name(), ac.Next, ctx, w, r)
	}

	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	msg.SetReply(r)
	msg.Authoritative = false
	msg.CheckingDisabled = true

	for _, txt := range txtValues {
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(qName),
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ac.config.DnsTTL,
			},
			Txt: []string{txt},
		})
	}

	w.WriteMsg(msg)
	challengeResponses.WithLabelValues(metrics.WithServer(ctx)).Inc()

	return dns.RcodeSuccess, nil
}

func (ac *acmeChallenge) start(ctx context.Context) {

	log.Info("started certificate service")

	ac.checkAndUpdateCertForAllDomains(ctx)

	uptimeTicker := time.NewTicker(ac.config.CertValidationInterval)
	defer uptimeTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("stopped certificate service")
			return
		case <-uptimeTicker.C:
			ac.checkAndUpdateCertForAllDomains(ctx)
		}
	}
}

func (ac *acmeChallenge) checkAndUpdateCertForAllDomains(ctx context.Context) {
	log.Info("starting cert validation!")

	var wg sync.WaitGroup
	for domain := range maps.Keys(ac.config.ManagedDomains) {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			ac.updateCertForDomain(d)
		}(domain)
	}

	wg.Wait()
}

func (ac *acmeChallenge) updateCertForDomain(domain string) {
	for attempt := uint32(0); ; attempt++ {
		isNew, certs, err := ac.obtainOrRenew(domain)
		if err == nil {
			if isNew {
				if err := ac.storage.Save(certs); err != nil {
					log.Errorf("could not save certificate for domain '%s': %v", domain, err)
				}
			} else if certs != nil {
				log.Infof("Certificate for domain '%s' is still valid, do nothing", domain)
			} else {
				log.Infof("Skipping certificate for domain '%s' this cycle (another node is issuing)", domain)
			}
			return
		}

		log.Error(err)
		if ac.config.RetryInterval <= 0 || attempt >= ac.config.MaxRetryCount {
			return
		}
		log.Infof("retrying certificate for domain '%s' in %s (attempt %d/%d)", domain, ac.config.RetryInterval, attempt+1, ac.config.MaxRetryCount)
		time.Sleep(ac.config.RetryInterval)
	}
}

func (ac *acmeChallenge) checkAndCreateOrRenewCert(domain string) (bool, *certificate.Resource, error) {
	certs := ac.storage.Load(domain)
	if certs != nil && checkIfCertIsValid(ac, certs) {
		log.Infof("Loaded certificate for %s, still valid", domain)
		return false, certs, nil
	}

	if ac.cluster != nil {
		if !ac.cluster.canIssue() {
			return false, nil, nil
		}
		ac.cluster.beginIssue()
		defer ac.cluster.endIssue()
	}

	if certs == nil {
		log.Infof("No certificate found for %s, obtaining new one", domain)
		certs, err := ac.coreDNSProvider.obtainNewCertificate(domain)
		recordObtain(domain, "obtained", err)
		return true, certs, err
	}

	certs, err := ac.coreDNSProvider.renewCertificate(certs)
	if err != nil {
		log.Errorf("Error renewing certificate. the cert for the domain '%s' is probably to old. Trying to obtain a new one.", domain)
		certs, err := ac.coreDNSProvider.obtainNewCertificate(domain)
		recordObtain(domain, "obtained", err)
		return true, certs, err
	}
	recordObtain(domain, "renewed", nil)
	return true, certs, err
}
