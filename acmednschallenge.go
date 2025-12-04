package acmednschallenge

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cbroglie/mustache"
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
	if ac.Next == nil {
		log.Error("There is no further plugins configured. The ACME plugin only works if there is at least one plugin after it.")
		return dns.RcodeRefused, nil
	}

	state := request.Request{W: w, Req: r}

	qName := state.QName()
	qNameFqdn := dns.Fqdn(strings.ToLower(qName))
	isAcmeChallenge := strings.HasPrefix(qNameFqdn, "_acme-challenge.")
	isTxtRequest := state.QType() == dns.TypeTXT

	// when this has nothing to do with ACME, delegate to the next plugin
	if !isAcmeChallenge || !isTxtRequest {
		return plugin.NextOrFailure(ac.Name(), ac.Next, ctx, w, r)
	}

	// check if this plugin manages this txt record. if not, delegate to the next plugin
	txtValues, ok := (*ac.challenges)[qNameFqdn]
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
				Ttl:    ac.config.dnsTTL,
			},
			Txt: []string{txt},
		})
	}

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

	certsPath := filepath.Join(ac.config.dataPath, "certs")
	if err := os.MkdirAll(certsPath, os.ModePerm); err != nil {
		log.Errorf("could not create certificates directory at %s: %v", certsPath, err)
		return
	}

	var wg sync.WaitGroup
	for domain := range maps.Keys(ac.config.managedDomains) {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()

			isNew, certs, err := ac.checkAndCreateOrRenewCert(certsPath, d)
			if err != nil {
				log.Error(err)
				return
			}
			if isNew {
				saveCerts(certsPath, certs, ac.config.privateKeyFileMode)
				if ac.config.postCertificateMustacheTemplatePath != "" {
					mustacheContext := map[string]string{
						"domain": sanitizedDomain(certs.Domain),
						"dir":    certsPath,
						"key":    getFileName(certs.Domain, ".key"),
						"pem":    getFileName(certs.Domain, ".pem"),
					}

					resFile, err := mustache.RenderFile(ac.config.postCertificateMustacheTemplatePath, mustacheContext)
					if err != nil {
						log.Errorf("Error rendering postCertificateMustacheTemplatePath: %v", err)
						return
					}

					resFilePath, err := mustache.Render(ac.config.postCertificateMustacheResultPath, mustacheContext)
					if err != nil {
						log.Errorf("Error rendering postCertificateMustacheResultPath: %v", err)
						return
					}

					err = os.WriteFile(resFilePath, []byte(resFile), 0644)
					if err != nil {
						log.Errorf("Error writing postCertificateMustacheResultPath: %v", err)
						return
					}
				}
			} else {
				log.Infof("Certificate for domain '%s' is still valid, do nothing", d)
			}
		}(domain)
	}

	wg.Wait()
}

func (ac *acmeChallenge) checkAndCreateOrRenewCert(certsPath string, domain string) (bool, *certificate.Resource, error) {
	certs := readCerts(certsPath, domain)
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
