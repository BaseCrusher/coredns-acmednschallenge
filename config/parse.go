package config

import (
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/acmednschallenge/storage"
)

func ParseConfig(c *caddy.Controller) (*ACMEChallengeConfig, error) {
	cfg := &ACMEChallengeConfig{
		Storage: storage.Options{
			Type:     "disk",
			DiskPath: defaultCertSavePath,
			KeyMode:  os.FileMode(0600),
		},
		Account: storage.Options{
			Type:     "disk",
			DiskPath: defaultUserDataPath,
		},
		RenewBeforeDays:          defaultRenewBeforeDays,
		DnsTTL:                   120,
		UseLetsEncryptTestServer: false,
		AcceptedLetsEncryptToS:   false,
		SkipDnsPropagationTest:   false,
		CustomNameservers:        []string{},
		CertValidationInterval:   24 * time.Hour,
		DnsTimeout:               60 * time.Second,
		MaxRetryCount:            defaultMaxRetryCount,
	}

	zones := c.ServerBlockKeys
	if len(zones) == 0 {
		return nil, c.Errf("%s plugin can only be configured in a dns zone", pluginName)
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

	cfg.ManagedDomains = make(map[string][]string)
	for _, z := range zones {
		cfg.ManagedDomains[z] = []string{}
	}

	var certificateStorageDiskSet, certificateStorageKubernetesSet, certificateStorageVaultSet bool
	var userDiskSet, userKubernetesSet, accountStorageVaultSet bool

	c.Next()
	for c.NextBlock() {
		switch c.Val() {
		case "certificateStorageDisk":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			p := c.Val()
			if !filepath.IsAbs(p) {
				return nil, c.Errf("certificateStorageDisk path must be an absolute path: %v", p)
			}
			cfg.Storage.Type = "disk"
			cfg.Storage.DiskPath = p
			certificateStorageDiskSet = true
			if c.NextArg() {
				switch c.Val() {
				case "600":
					cfg.Storage.KeyMode = os.FileMode(0600)
				case "640":
					cfg.Storage.KeyMode = os.FileMode(0640)
				case "644":
					cfg.Storage.KeyMode = os.FileMode(0644)
				default:
					return nil, c.Errf("certificateStorageDisk file mode must be 600, 640 or 644 but the value is: %v", c.Val())
				}
			}
		case "certificateStorageKubernetes":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.Storage.Type = "kubernetesSecrets"
			cfg.Storage.Namespace = c.Val()
			certificateStorageKubernetesSet = true
		case "accountStorageDisk":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			p := c.Val()
			if !filepath.IsAbs(p) {
				return nil, c.Errf("accountStorageDisk path must be an absolute path: %v", p)
			}
			cfg.Account.Type = "disk"
			cfg.Account.DiskPath = p
			userDiskSet = true
		case "accountStorageKubernetes":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.Account.Type = "kubernetesSecrets"
			cfg.Account.Namespace = c.Val()
			userKubernetesSet = true
		case "certificateStorageVault":
			if err := parseVaultOptions(c, &cfg.Storage); err != nil {
				return nil, err
			}
			certificateStorageVaultSet = true
		case "accountStorageVault":
			if err := parseVaultOptions(c, &cfg.Account); err != nil {
				return nil, err
			}
			accountStorageVaultSet = true
		case "renewBeforeDays":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			renewBeforeDays, err := strconv.ParseUint(c.Val(), 10, 32)
			if err != nil {
				return nil, c.Errf("invalid renewBeforeDays it must be an integer >= 1 but the value is: %v", c.Val())
			}
			if renewBeforeDays < 1 {
				return nil, c.Errf("invalid renewBeforeDays it must be an integer >= 1 but the value is: %v", renewBeforeDays)
			}
			cfg.RenewBeforeDays = uint32(renewBeforeDays)
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
			cfg.DnsTTL = uint32(ttl)
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
				for _, san := range sans {
					if !isSubdomainOf(san, z) {
						return nil, c.Errf("additionalSans '%s' must be a subdomain of the managed domain '%s'", san, z)
					}
				}
				cfg.ManagedDomains[z] = sans
			}
		case "useLetsEncryptTestServer":
			if c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.UseLetsEncryptTestServer = true
		case "skipDnsPropagationTest":
			if c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.SkipDnsPropagationTest = true
		case "acceptedLetsEncryptToS":
			if c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.AcceptedLetsEncryptToS = true
		case "email":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.Email = c.Val()
			if _, err := mail.ParseAddress(cfg.Email); err != nil {
				return nil, c.Errf("invalid email: %v", cfg.Email)
			}
		case "customCAD":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.CustomCAD = c.Val()
		case "allowInsecureCAD":
			if c.NextArg() {
				return nil, c.ArgErr()
			}
			cfg.AllowInsecureCAD = true
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
			cfg.CustomNameservers = nameservers
		case "certValidationInterval":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			duration := c.Val()
			d, err := time.ParseDuration(duration)
			if err != nil {
				return nil, c.Errf("invalid certValidationInterval: %v", duration)
			}
			cfg.CertValidationInterval = d
		case "dnsTimeout":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			duration := c.Val()
			d, err := time.ParseDuration(duration)
			if err != nil {
				return nil, c.Errf("invalid dnsTimeout: %v", duration)
			}
			cfg.DnsTimeout = d
		case "retryInterval":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			duration := c.Val()
			d, err := time.ParseDuration(duration)
			if err != nil {
				return nil, c.Errf("invalid retryInterval: %v", duration)
			}
			if d < 0 {
				return nil, c.Errf("retryInterval must not be negative: %v", duration)
			}
			cfg.RetryInterval = d
		case "maxRetryCount":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			n, err := strconv.ParseUint(c.Val(), 10, 32)
			if err != nil {
				return nil, c.Errf("invalid maxRetryCount, it must be a non-negative integer but the value is: %v", c.Val())
			}
			cfg.MaxRetryCount = uint32(n)
		default:
			return nil, c.Errf("unknown property '%s'", c.Val())
		}
	}

	if countTrue(certificateStorageDiskSet, certificateStorageKubernetesSet, certificateStorageVaultSet) > 1 {
		return nil, c.Err("only one certificate storage backend may be set (certificateStorageDisk, certificateStorageKubernetes, certificateStorageVault)")
	}

	if countTrue(userDiskSet, userKubernetesSet, accountStorageVaultSet) > 1 {
		return nil, c.Err("only one account storage backend may be set (accountStorageDisk, accountStorageKubernetes, accountStorageVault)")
	}

	if cfg.Email == "" {
		return nil, c.Err("you must provide an email that will be used for acme")
	}

	if cfg.UseLetsEncryptTestServer && cfg.CustomCAD != "" {
		return nil, c.Err("you can't use a custom CA with the test server")
	}

	if !cfg.AcceptedLetsEncryptToS {
		return nil, c.Err("you must agree to the Let's Encrypt Terms of Service by setting 'acceptedLetsEncryptToS'")
	}

	return cfg, nil
}
