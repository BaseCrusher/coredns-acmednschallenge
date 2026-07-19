package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	bao "github.com/openbao/openbao/api/v2"
)

const serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

const vaultAccountKeyField = "key.pem"

func newVaultClient(o Options) (*bao.Client, error) {
	client, err := bao.NewClient(bao.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("could not create vault client: %w", err)
	}

	switch o.VaultAuth {
	case "", "token":
		if client.Token() == "" {
			client.SetToken(firstNonEmpty(os.Getenv("BAO_TOKEN"), os.Getenv("VAULT_TOKEN")))
		}
		if client.Token() == "" {
			return nil, fmt.Errorf("vault token auth selected but no token found (set BAO_TOKEN or VAULT_TOKEN)")
		}
	case "kubernetes":
		if err := vaultKubernetesLogin(client, o.VaultRole); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown vault auth method: %s", o.VaultAuth)
	}
	return client, nil
}

func vaultKubernetesLogin(client *bao.Client, role string) error {
	if role == "" {
		return fmt.Errorf("vault kubernetes auth requires a role")
	}
	jwt, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return fmt.Errorf("could not read service account token: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	secret, err := client.Logical().WriteWithContext(ctx, "auth/kubernetes/login", map[string]interface{}{
		"role": role,
		"jwt":  strings.TrimSpace(string(jwt)),
	})
	if err != nil {
		return fmt.Errorf("vault kubernetes login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return fmt.Errorf("vault kubernetes login returned no token")
	}
	client.SetToken(secret.Auth.ClientToken)
	return nil
}

func kvPath(mount, prefix, key string) string {
	return path.Join(mount, "data", prefix, key)
}

type VaultCerts struct {
	client *bao.Client
	mount  string
	prefix string
}

func NewVaultCerts(o Options) (*VaultCerts, error) {
	client, err := newVaultClient(o)
	if err != nil {
		return nil, err
	}
	return &VaultCerts{client: client, mount: o.VaultMount, prefix: o.VaultPrefix}, nil
}

func (v *VaultCerts) Save(certs *certificate.Resource) error {
	data, err := certToVaultData(certs)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	_, err = v.client.Logical().WriteWithContext(ctx,
		kvPath(v.mount, v.prefix, sanitizedDomain(certs.Domain)),
		map[string]interface{}{"data": data})
	if err != nil {
		return fmt.Errorf("unable to save certificate for domain %s to vault: %w", certs.Domain, err)
	}
	return nil
}

func (v *VaultCerts) Load(domain string) *certificate.Resource {
	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	secret, err := v.client.Logical().ReadWithContext(ctx, kvPath(v.mount, v.prefix, sanitizedDomain(domain)))
	if err != nil || secret == nil {
		return nil
	}
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil
	}
	return vaultDataToCert(data)
}

type VaultAccount struct {
	client *bao.Client
	mount  string
	prefix string
}

func NewVaultAccount(o Options) (*VaultAccount, error) {
	client, err := newVaultClient(o)
	if err != nil {
		return nil, err
	}
	return &VaultAccount{client: client, mount: o.VaultMount, prefix: o.VaultPrefix}, nil
}

func (v *VaultAccount) SaveAccountKey(email string, keyPEM []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	_, err := v.client.Logical().WriteWithContext(ctx,
		kvPath(v.mount, v.prefix, strings.ToLower(email)),
		map[string]interface{}{"data": map[string]interface{}{vaultAccountKeyField: string(keyPEM)}})
	if err != nil {
		return fmt.Errorf("unable to save account key for %s to vault: %w", email, err)
	}
	return nil
}

func (v *VaultAccount) LoadAccountKey(email string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	secret, err := v.client.Logical().ReadWithContext(ctx, kvPath(v.mount, v.prefix, strings.ToLower(email)))
	if err != nil || secret == nil {
		return nil
	}
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil
	}
	key, _ := data[vaultAccountKeyField].(string)
	if key == "" {
		return nil
	}
	return []byte(key)
}

func certToVaultData(certs *certificate.Resource) (map[string]interface{}, error) {
	meta, err := json.Marshal(certs)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal CertResource for domain %s: %w", certs.Domain, err)
	}
	return map[string]interface{}{
		"tls.crt":   string(certs.Certificate),
		"tls.key":   string(certs.PrivateKey),
		"acme.json": string(meta),
	}, nil
}

func vaultDataToCert(data map[string]interface{}) *certificate.Resource {
	meta, _ := data["acme.json"].(string)
	if meta == "" {
		return nil
	}
	var resource certificate.Resource
	if err := json.Unmarshal([]byte(meta), &resource); err != nil {
		return nil
	}
	crt, _ := data["tls.crt"].(string)
	key, _ := data["tls.key"].(string)
	resource.Certificate = []byte(crt)
	resource.PrivateKey = []byte(key)
	return &resource
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
