package config

import (
	"time"

	"github.com/coredns/coredns/plugin/acmednschallenge/storage"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

const pluginName = "acmednschallenge"

var log = clog.NewWithPlugin(pluginName)

const defaultCertSavePath = "/var/lib/coredns/certs"
const defaultUserDataPath = "/var/lib/coredns/acme-user"
const defaultRenewBeforeDays = 10
const defaultMaxRetryCount = 3

type ACMEChallengeConfig struct {
	Storage                  storage.Options
	Account                  storage.Options
	ManagedDomains           map[string][]string
	RenewBeforeDays          uint32
	UseLetsEncryptTestServer bool
	Email                    string
	AcceptedLetsEncryptToS   bool
	SkipDnsPropagationTest   bool
	CustomCAD                string
	AllowInsecureCAD         bool
	CustomNameservers        []string
	DnsTimeout               time.Duration
	DnsTTL                   uint32
	CertValidationInterval   time.Duration
	RetryInterval            time.Duration
	MaxRetryCount            uint32
}
