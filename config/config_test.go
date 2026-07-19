package config

import (
	"os"
	"testing"
	"time"

	"github.com/coredns/caddy"
)

func TestParseConfigAdditionalSans(t *testing.T) {
	tests := []struct {
		name      string
		sans      string
		shouldErr bool
	}{
		{name: "wildcard of zone", sans: "*.example.com"},
		{name: "subdomain of zone", sans: "www.example.com"},
		{name: "nested subdomain", sans: "a.b.example.com"},
		{name: "zone itself", sans: "example.com"},
		{name: "mixed valid", sans: "*.example.com www.example.com"},
		{name: "unrelated domain rejected", sans: "example.org", shouldErr: true},
		{name: "suffix-not-subdomain rejected", sans: "notexample.com", shouldErr: true},
		{name: "one invalid among valid rejected", sans: "www.example.com evil.org", shouldErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nadditionalSans " + tc.sans + "\n}"
			c := caddy.NewTestController("dns", config)
			c.ServerBlockKeys = []string{"example.com"}

			_, err := ParseConfig(c)
			if tc.shouldErr && err == nil {
				t.Fatalf("expected error, got none")
			}
			if !tc.shouldErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseConfigRetryInterval(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		shouldErr bool
		want      time.Duration
		wantMax   uint32
	}{
		{
			name:    "default disables retry",
			config:  "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\n}",
			want:    0,
			wantMax: defaultMaxRetryCount,
		},
		{
			name:    "custom retry interval",
			config:  "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nretryInterval 5m\n}",
			want:    5 * time.Minute,
			wantMax: defaultMaxRetryCount,
		},
		{
			name:    "custom max retry count",
			config:  "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nretryInterval 5m\nmaxRetryCount 7\n}",
			want:    5 * time.Minute,
			wantMax: 7,
		},
		{
			name:      "invalid max retry count rejected",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nmaxRetryCount nope\n}",
			shouldErr: true,
		},
		{
			name:      "invalid duration rejected",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nretryInterval nope\n}",
			shouldErr: true,
		},
		{
			name:      "negative duration rejected",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nretryInterval -5m\n}",
			shouldErr: true,
		},
		{
			name:      "missing argument rejected",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nretryInterval\n}",
			shouldErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.config)
			c.ServerBlockKeys = []string{"example.com"}

			cfg, err := ParseConfig(c)
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.RetryInterval != tc.want {
				t.Errorf("retryInterval = %v, want %v", cfg.RetryInterval, tc.want)
			}
			if cfg.MaxRetryCount != tc.wantMax {
				t.Errorf("maxRetryCount = %v, want %v", cfg.MaxRetryCount, tc.wantMax)
			}
		})
	}
}

func TestParseConfigRenewBeforeDays(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		shouldErr bool
		want      uint32
	}{
		{
			name:   "default",
			config: "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\n}",
			want:   defaultRenewBeforeDays,
		},
		{
			name:   "within old range",
			config: "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nrenewBeforeDays 30\n}",
			want:   30,
		},
		{
			name:   "above 30 accepted",
			config: "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nrenewBeforeDays 120\n}",
			want:   120,
		},
		{
			name:      "zero rejected",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nrenewBeforeDays 0\n}",
			shouldErr: true,
		},
		{
			name:      "non-integer rejected",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\nrenewBeforeDays nope\n}",
			shouldErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.config)
			c.ServerBlockKeys = []string{"example.com"}

			cfg, err := ParseConfig(c)
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.RenewBeforeDays != tc.want {
				t.Errorf("renewBeforeDays = %v, want %v", cfg.RenewBeforeDays, tc.want)
			}
		})
	}
}

func TestParseConfigStorage(t *testing.T) {
	tests := []struct {
		name            string
		config          string
		shouldErr       bool
		wantType        string
		wantDiskPath    string
		wantKeyMode     os.FileMode
		wantGid         int
		wantNamespace   string
		wantVaultMount  string
		wantVaultPrefix string
		wantVaultAuth   string
		wantVaultRole   string
		wantAccountType string
		wantAccountPath string
		wantAccountNsp  string
	}{
		{
			name:            "defaults",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\n}",
			wantType:        "disk",
			wantDiskPath:    defaultCertSavePath,
			wantAccountType: "disk",
			wantAccountPath: defaultUserDataPath,
		},
		{
			name:            "certificateStorageDisk with path",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageDisk /srv/certs\n}",
			wantType:        "disk",
			wantDiskPath:    "/srv/certs",
			wantKeyMode:     0600,
			wantAccountType: "disk",
			wantAccountPath: defaultUserDataPath,
		},
		{
			name:            "certificateStorageDisk with file mode",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageDisk /srv/certs 640\n}",
			wantType:        "disk",
			wantDiskPath:    "/srv/certs",
			wantKeyMode:     0640,
			wantAccountType: "disk",
			wantAccountPath: defaultUserDataPath,
		},
		{
			name:      "certificateStorageDisk invalid file mode",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageDisk /srv/certs 700\n}",
			shouldErr: true,
		},
		{
			name:            "certificateStorageDisk with numeric group",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageDisk /srv/certs 640 3000\n}",
			wantType:        "disk",
			wantDiskPath:    "/srv/certs",
			wantKeyMode:     0640,
			wantGid:         3000,
			wantAccountType: "disk",
			wantAccountPath: defaultUserDataPath,
		},
		{
			name:      "certificateStorageDisk group rejected without group mode bit",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageDisk /srv/certs 600 3000\n}",
			shouldErr: true,
		},
		{
			name:            "certificateStorageKubernetes with namespace",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageKubernetes certs-ns\n}",
			wantType:        "kubernetesSecrets",
			wantDiskPath:    defaultCertSavePath,
			wantNamespace:   "certs-ns",
			wantAccountType: "disk",
			wantAccountPath: defaultUserDataPath,
		},
		{
			name:            "accountStorageDisk with path",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\naccountStorageDisk /srv/acme\n}",
			wantType:        "disk",
			wantDiskPath:    defaultCertSavePath,
			wantAccountType: "disk",
			wantAccountPath: "/srv/acme",
		},
		{
			name:            "accountStorageKubernetes with namespace",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\naccountStorageKubernetes acme-ns\n}",
			wantType:        "disk",
			wantDiskPath:    defaultCertSavePath,
			wantAccountType: "kubernetesSecrets",
			wantAccountPath: defaultUserDataPath,
			wantAccountNsp:  "acme-ns",
		},
		{
			name:            "certs and account in different backends",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageKubernetes certs-ns\naccountStorageDisk /srv/acme\n}",
			wantType:        "kubernetesSecrets",
			wantDiskPath:    defaultCertSavePath,
			wantNamespace:   "certs-ns",
			wantAccountType: "disk",
			wantAccountPath: "/srv/acme",
		},
		{
			name:            "certificateStorageVault token auth",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageVault secret coredns/certs\n}",
			wantType:        "vault",
			wantDiskPath:    defaultCertSavePath,
			wantVaultMount:  "secret",
			wantVaultPrefix: "coredns/certs",
			wantVaultAuth:   "token",
			wantAccountType: "disk",
			wantAccountPath: defaultUserDataPath,
		},
		{
			name:            "certificateStorageVault kubernetes auth",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageVault secret coredns/certs kubernetes my-role\n}",
			wantType:        "vault",
			wantDiskPath:    defaultCertSavePath,
			wantVaultMount:  "secret",
			wantVaultPrefix: "coredns/certs",
			wantVaultAuth:   "kubernetes",
			wantVaultRole:   "my-role",
			wantAccountType: "disk",
			wantAccountPath: defaultUserDataPath,
		},
		{
			name:            "accountStorageVault",
			config:          "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\naccountStorageVault secret coredns/acme\n}",
			wantType:        "disk",
			wantDiskPath:    defaultCertSavePath,
			wantAccountType: "vault",
			wantAccountPath: defaultUserDataPath,
		},
		{
			name:      "vault missing prefix",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageVault secret\n}",
			shouldErr: true,
		},
		{
			name:      "vault unknown auth method",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageVault secret p approle\n}",
			shouldErr: true,
		},
		{
			name:      "vault kubernetes auth without role",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageVault secret p kubernetes\n}",
			shouldErr: true,
		},
		{
			name:      "disk and vault backends rejected",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageDisk /srv/certs\ncertificateStorageVault secret p\n}",
			shouldErr: true,
		},
		{
			name:      "certificateStorageKubernetes without namespace",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageKubernetes\n}",
			shouldErr: true,
		},
		{
			name:      "relative certificateStorageDisk path rejected",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageDisk certs\n}",
			shouldErr: true,
		},
		{
			name:      "both storage backends rejected",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\ncertificateStorageDisk /srv/certs\ncertificateStorageKubernetes ns\n}",
			shouldErr: true,
		},
		{
			name:      "both account backends rejected",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\naccountStorageDisk /srv/acme\naccountStorageKubernetes ns\n}",
			shouldErr: true,
		},
		{
			name:      "removed mustache directive is unknown",
			config:    "acmednschallenge {\nemail a@b.com\nacceptedLetsEncryptToS\npostCertificateMustacheRender t r\n}",
			shouldErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.config)
			c.ServerBlockKeys = []string{"example.com"}

			cfg, err := ParseConfig(c)
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Storage.Type != tc.wantType {
				t.Errorf("storage.Type = %q, want %q", cfg.Storage.Type, tc.wantType)
			}
			if cfg.Storage.DiskPath != tc.wantDiskPath {
				t.Errorf("storage.DiskPath = %q, want %q", cfg.Storage.DiskPath, tc.wantDiskPath)
			}
			if tc.wantGid != 0 && cfg.Storage.Gid != tc.wantGid {
				t.Errorf("storage.Gid = %d, want %d", cfg.Storage.Gid, tc.wantGid)
			}
			if tc.wantKeyMode != 0 && cfg.Storage.KeyMode != tc.wantKeyMode {
				t.Errorf("storage.KeyMode = %o, want %o", cfg.Storage.KeyMode, tc.wantKeyMode)
			}
			if cfg.Storage.Namespace != tc.wantNamespace {
				t.Errorf("storage.Namespace = %q, want %q", cfg.Storage.Namespace, tc.wantNamespace)
			}
			if cfg.Storage.VaultMount != tc.wantVaultMount {
				t.Errorf("storage.VaultMount = %q, want %q", cfg.Storage.VaultMount, tc.wantVaultMount)
			}
			if cfg.Storage.VaultPrefix != tc.wantVaultPrefix {
				t.Errorf("storage.VaultPrefix = %q, want %q", cfg.Storage.VaultPrefix, tc.wantVaultPrefix)
			}
			if cfg.Storage.VaultAuth != tc.wantVaultAuth {
				t.Errorf("storage.VaultAuth = %q, want %q", cfg.Storage.VaultAuth, tc.wantVaultAuth)
			}
			if cfg.Storage.VaultRole != tc.wantVaultRole {
				t.Errorf("storage.VaultRole = %q, want %q", cfg.Storage.VaultRole, tc.wantVaultRole)
			}
			if cfg.Account.Type != tc.wantAccountType {
				t.Errorf("account.Type = %q, want %q", cfg.Account.Type, tc.wantAccountType)
			}
			if cfg.Account.DiskPath != tc.wantAccountPath {
				t.Errorf("account.DiskPath = %q, want %q", cfg.Account.DiskPath, tc.wantAccountPath)
			}
			if cfg.Account.Namespace != tc.wantAccountNsp {
				t.Errorf("account.Namespace = %q, want %q", cfg.Account.Namespace, tc.wantAccountNsp)
			}
		})
	}
}

func TestIsValidNameserver(t *testing.T) {
	tests := []struct {
		ns   string
		want bool
	}{
		{"1.1.1.1", true},
		{"1.1.1.1:53", true},
		{"ns.example.com", true},
		{"ns.example.com:53", true},
		{"1.1.1.1:99999", false},
		{"not_a_host", false},
		{"example", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := isValidNameserver(tc.ns); got != tc.want {
			t.Errorf("isValidNameserver(%q) = %v, want %v", tc.ns, got, tc.want)
		}
	}
}
