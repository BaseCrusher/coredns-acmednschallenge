package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	acmeResourceKey = "acme.json"
	managedByLabel  = "app.kubernetes.io/managed-by"
	managedByValue  = "coredns-acmednschallenge"
	k8sTimeout      = 30 * time.Second
)

type Secrets struct {
	client    kubernetes.Interface
	namespace string
}

func NewSecrets(namespace string) (*Secrets, error) {
	cfg, err := restConfig()
	if err != nil {
		return nil, fmt.Errorf("could not build kubernetes client config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not create kubernetes client: %w", err)
	}
	return newSecrets(client, namespace), nil
}

func newSecrets(client kubernetes.Interface, namespace string) *Secrets {
	return &Secrets{client: client, namespace: namespace}
}

func restConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
}

func (s *Secrets) Save(certs *certificate.Resource) error {
	meta, err := json.Marshal(certs)
	if err != nil {
		return fmt.Errorf("unable to marshal CertResource for domain %s: %w", certs.Domain, err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName(certs.Domain),
			Namespace:   s.namespace,
			Labels:      map[string]string{managedByLabel: managedByValue},
			Annotations: map[string]string{"acmednschallenge/domain": certs.Domain},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certs.Certificate,
			corev1.TLSPrivateKeyKey: certs.PrivateKey,
			acmeResourceKey:         meta,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	api := s.client.CoreV1().Secrets(s.namespace)
	_, err = api.Update(ctx, secret, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = api.Create(ctx, secret, metav1.CreateOptions{})
	}
	if err != nil {
		return fmt.Errorf("unable to save secret for domain %s: %w", certs.Domain, err)
	}
	return nil
}

func (s *Secrets) Load(domain string) *certificate.Resource {
	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, secretName(domain), metav1.GetOptions{})
	if err != nil {
		return nil
	}

	meta, ok := secret.Data[acmeResourceKey]
	if !ok {
		return nil
	}

	var resource certificate.Resource
	if err := json.Unmarshal(meta, &resource); err != nil {
		return nil
	}

	resource.Certificate = secret.Data[corev1.TLSCertKey]
	resource.PrivateKey = secret.Data[corev1.TLSPrivateKeyKey]
	return &resource
}

func secretName(domain string) string {
	return strings.NewReplacer("*", "wildcard", ":", "-").Replace(strings.ToLower(domain))
}

const accountKeyDataKey = "key.pem"

type SecretsAccount struct {
	client    kubernetes.Interface
	namespace string
}

func NewSecretsAccount(namespace string) (*SecretsAccount, error) {
	cfg, err := restConfig()
	if err != nil {
		return nil, fmt.Errorf("could not build kubernetes client config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not create kubernetes client: %w", err)
	}
	return &SecretsAccount{client: client, namespace: namespace}, nil
}

func (s *SecretsAccount) SaveAccountKey(email string, keyPEM []byte) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        accountSecretName(email),
			Namespace:   s.namespace,
			Labels:      map[string]string{managedByLabel: managedByValue},
			Annotations: map[string]string{"acmednschallenge/email": email},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{accountKeyDataKey: keyPEM},
	}

	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	api := s.client.CoreV1().Secrets(s.namespace)
	_, err := api.Update(ctx, secret, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = api.Create(ctx, secret, metav1.CreateOptions{})
	}
	if err != nil {
		return fmt.Errorf("unable to save account key secret for %s: %w", email, err)
	}
	return nil
}

func (s *SecretsAccount) LoadAccountKey(email string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), k8sTimeout)
	defer cancel()

	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, accountSecretName(email), metav1.GetOptions{})
	if err != nil {
		return nil
	}
	return secret.Data[accountKeyDataKey]
}

var invalidSecretNameChars = regexp.MustCompile(`[^a-z0-9.-]+`)

func accountSecretName(email string) string {
	name := invalidSecretNameChars.ReplaceAllString(strings.ToLower(email), "-")
	return "acme-account-" + strings.Trim(name, "-.")
}
