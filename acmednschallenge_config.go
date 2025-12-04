package acmednschallenge

import (
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
)

const defaultCertSavePath = "/var/lib/coredns/certs"
const defaultRenewBeforeDays = 10

//goland:noinspection GoNameStartsWithPackageName
type ACMEChallengeConfig struct {
	dataPath                            string
	managedDomains                      map[string][]string
	renewBeforeDays                     uint32
	useLetsEncryptTestServer            bool
	email                               string
	acceptedLetsEncryptToS              bool
	skipDnsPropagationTest              bool
	customCAD                           string
	allowInsecureCAD                    bool
	privateKeyFileMode                  os.FileMode
	customNameservers                   []string
	dnsTimeout                          time.Duration
	dnsTTL                              uint32
	certValidationInterval              time.Duration
	postCertificateMustacheTemplatePath string
	postCertificateMustacheResultPath   string
}

func parseConfig(c *caddy.Controller) (*ACMEChallengeConfig, error) {
	cfg := &ACMEChallengeConfig{
		dataPath:                 defaultCertSavePath,
		renewBeforeDays:          defaultRenewBeforeDays,
		dnsTTL:                   120,
		useLetsEncryptTestServer: false,
		acceptedLetsEncryptToS:   false,
		skipDnsPropagationTest:   false,
		customNameservers:        []string{},
		certValidationInterval:   24 * time.Hour,
		dnsTimeout:               60 * time.Second,
		privateKeyFileMode:       os.FileMode(0600),
	}

	// Get the zone from the server block
	zones := c.ServerBlockKeys
	if len(zones) == 0 {
		return nil, c.Errf("%s plugin can only be configured in a dns zone", name)
	}

	for i, z := range zones {
		z = strings.TrimPrefix(z, "dns://")
		z = strings.Split(z, ":")[0]

		if z == "" {
			return nil, c.Err("there was some error parsing the dns zone")
		}

		z = strings.TrimSuffix(z, ".")

		if len(strings.Split(z, ".")) < 1 {
			return nil, c.Errf("zone '%s' must be a fully-qualified domain name.", z)
		}
		zones[i] = z
	}

	cfg.managedDomains = make(map[string][]string)
	for _, z := range zones {
		cfg.managedDomains[z] = []string{}
	}

	c.Next() // skip "acmednschallenge" before the block
	for c.NextBlock() {
		switch c.Val() {
		case "dataPath":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			p := c.Val()
			if !filepath.IsAbs(p) {
				return nil, c.Errf("dataPath must be an absolut path: %v", p)
			}
			cfg.dataPath = p
			break
		case "privateKeyFileMode":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			p, err := strconv.ParseUint(c.Val(), 10, 32)
			if err != nil {
				return nil, c.Errf("invalid privateKeyFileMode it must be 600, 640 or 644 but the value is: %v", c.Val())
			}
			switch p {
			case 600:
				cfg.privateKeyFileMode = os.FileMode(0600)
			case 640:
				cfg.privateKeyFileMode = os.FileMode(0640)
			case 644:
				cfg.privateKeyFileMode = os.FileMode(0644)
			default:
				return nil, c.Errf("invalid privateKeyFileMode it must be 600, 640 or 644 but the value is: %v", p)
			}
		case "renewBeforeDays":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			renewBeforeDays, err := strconv.ParseUint(c.Val(), 10, 32)
			if err != nil {
				return nil, c.Errf("invalid renewBeforeDays it must be an integer between 1 and 30 but the value is: %v", c.Val())
			}
			if renewBeforeDays < 1 || renewBeforeDays > 30 {
				return nil, c.Errf("invalid renewBeforeDays it must be an integer between 1 and 30 but the value is: %v", renewBeforeDays)
			}
			cfg.renewBeforeDays = uint32(renewBeforeDays)
			break
		case "dnsTTL":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			ttl, err := strconv.ParseUint(c.Val(), 10, 32)
			if err != nil {
				return nil, c.Errf("invalid dnsTTL it must be an integer between 60 and 600 but the value is: %v", c.Val())
			}
			if ttl < 60 || ttl > 600 {
				return nil, c.Errf("invalid dnsTTL it must be an integer between 60 and 600 but the value is: %v", ttl)
			}
			cfg.dnsTTL = uint32(ttl)
			break
		case "additionalSans":
			var sans []string
			for c.NextArg() {
				sans = append(sans, c.Val())
			}

			if sans == nil {
				return nil, c.ArgErr()
			}

			for _, z := range zones {
				cfg.managedDomains[z] = sans
			}
		case "useLetsEncryptTestServer":
			if c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.useLetsEncryptTestServer = true
		case "skipDnsPropagationTest":
			if c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.skipDnsPropagationTest = true
		case "acceptedLetsEncryptToS":
			if c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.acceptedLetsEncryptToS = true
		case "email":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.email = c.Val()
			if _, err := mail.ParseAddress(cfg.email); err != nil {
				return nil, c.Errf("invalid email: %v", cfg.email)
			}
		case "customCAD":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.customCAD = c.Val()
		case "allowInsecureCAD":
			if c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.allowInsecureCAD = true
		case "customNameservers":
			var nameservers []string
			for c.NextArg() {
				nameservers = append(nameservers, c.Val())
			}

			if nameservers == nil {
				return nil, c.ArgErr()
			}

			hasInvalidNameserver := false
			for _, ns := range nameservers {
				if !isValidNameserver(ns) {
					log.Errorf("Invalid nameserver: %s", ns)
					hasInvalidNameserver = true
				}
			}

			if hasInvalidNameserver {
				return nil, c.Err("config contains invalid nameservers, please check the log for more details")
			}
			cfg.customNameservers = nameservers
		case "certValidationInterval":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			duration := c.Val()
			d, err := time.ParseDuration(duration)
			if err != nil {
				return nil, c.Errf("invalid certValidationInterval: %v", duration)
			}
			cfg.certValidationInterval = d
		case "dnsTimeout":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			duration := c.Val()
			d, err := time.ParseDuration(duration)
			if err != nil {
				return nil, c.Errf("invalid certValidationInterval: %v", duration)
			}
			cfg.certValidationInterval = d
		case "postCertificateMustacheRender":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			templatePath := c.Val()
			if _, err := os.Stat(templatePath); err != nil {
				return nil, c.Errf("invalid postCertificateMustacheRender. The first value must point to an existing file! Path: %v", templatePath)
			}
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			resultPath := c.Val()
			if resultPath == "" {
				return nil, c.Errf("invalid postCertificateMustacheRender. The second value must be a valid path! It may contain mustache variables, e.g. {{.Domain}}.")
			}
			cfg.postCertificateMustacheTemplatePath = templatePath
			cfg.postCertificateMustacheResultPath = resultPath
		default:
			return nil, c.Errf("unknown property '%s'", c.Val())
		}
	}

	if cfg.email == "" {
		return nil, c.Err("you must provide an email that will be used for acme")
	}

	if cfg.useLetsEncryptTestServer && cfg.customCAD != "" {
		return nil, c.Err("you can't use a custom CA with the test server")
	}

	if !cfg.acceptedLetsEncryptToS {
		return nil, c.Err("you must agree to the Let's Encrypt Terms of Service by setting 'acceptedLetsEncryptToS'")
	}

	return cfg, nil
}

func isValidNameserver(ns string) bool {
	host, port, err := net.SplitHostPort(ns)
	if err != nil {
		host = ns
		port = ""
	}

	if ip := net.ParseIP(host); ip != nil {
		if port != "" {
			if _, err := net.LookupPort("udp", port); err != nil {
				return false
			}
		}
		return true
	}

	fqdnRegex := `^(?i)[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$`
	matched, _ := regexp.MatchString(fqdnRegex, host)
	return matched
}
