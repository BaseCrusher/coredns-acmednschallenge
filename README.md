# acmednschallenge

## Name

*acmednschallenge* - obtains and renews ACME certificates (Let's Encrypt by default) using the DNS-01 challenge.

## Description

*acmednschallenge* turns CoreDNS into the DNS-01 solver for its own zone: it answers the
`_acme-challenge` TXT queries required by the ACME protocol itself, so no external DNS provider API
is needed. It is built on [lego](https://github.com/go-acme/lego) and, for every managed name,
obtains a certificate and periodically renews it before expiry.

Issued certificates and the ACME account key are written to a configurable backend. Three backends
are supported and can be chosen independently for certificates and for the account key: local
**disk**, **Kubernetes** Secrets, and **OpenBao/Vault** (KV v2).

*acmednschallenge* only answers `_acme-challenge` TXT queries it manages; all other queries are
passed to the next plugin, so it must be configured in a zone with at least one further plugin (for
example *file* or *forward*) to serve normal traffic.

## Motivation

DNS-01 issuance normally couples every certificate to the API of whatever DNS provider hosts the
domain: each provider needs its own credentials and its own lego/certbot integration, and the
process differs from provider to provider. That does not scale when domains are spread across many
providers.

*acmednschallenge* removes that coupling. You delegate only the challenge record to CoreDNS once,
by pointing `_acme-challenge.example.org` at this plugin with a CNAME (or NS) in the provider that
hosts `example.org`. From then on the ACME server follows that delegation and CoreDNS answers the
challenge directly. The provider hosting the real records never has to change, no provider
credentials are stored, and issuance and renewal are **identical for every domain regardless of its
DNS provider** — one uniform path to manage instead of one per provider.

## Syntax

~~~ txt
acmednschallenge {
    email EMAIL
    acceptedLetsEncryptToS
    additionalSans SAN...
    renewBeforeDays DAYS
    certValidationInterval DURATION
    retryInterval DURATION
    maxRetryCount COUNT
    dnsTTL TTL
    dnsTimeout DURATION
    skipDnsPropagationTest
    useLetsEncryptTestServer
    customCAD URL
    allowInsecureCAD
    customNameservers NAMESERVER...
}
~~~

* `email` **EMAIL** **required**, the contact address registered with the ACME account.
* `acceptedLetsEncryptToS` **required**, its presence records your agreement to the Let's Encrypt
  [Terms of Service](https://letsencrypt.org/privacy/).
* `additionalSans` **SAN...** additional subject alternative names to include on the certificate,
  for example `*.example.org`. Each SAN must be the managed domain, a wildcard of it, or a subdomain
  of it.
* `renewBeforeDays` **DAYS** renew this many days before expiry, an integer `>= 1`. Default `10`.
  Values above `30` are accepted but not recommended, as they largely defeat renew-before-expiry.
* `certValidationInterval` **DURATION** how often certificates are checked for renewal, a Go
  [duration](https://pkg.go.dev/time#ParseDuration). Default `24h`.
* `retryInterval` **DURATION** when issuing or renewing a certificate fails, retry this often until it
  succeeds, a Go duration. Default `0`, which disables retrying (the domain is retried on the next
  `certValidationInterval` tick instead).
* `maxRetryCount` **COUNT** maximum number of retries per validation cycle when `retryInterval` is
  set, a non-negative integer. Default `3`. After the retries are exhausted the domain is retried on
  the next `certValidationInterval` tick.
* `dnsTTL` **TTL** TTL of the challenge TXT record, an integer in `[60, 600]`. Default `120`.
* `dnsTimeout` **DURATION** timeout for the DNS propagation check, a Go duration. Default `60s`.
* `skipDnsPropagationTest` skip lego's DNS propagation pre-check. Takes no argument.
* `useLetsEncryptTestServer` use the Let's Encrypt staging server. Takes no argument.
* `customCAD` **URL** ACME CA directory URL to use instead of Let's Encrypt.
* `allowInsecureCAD` disable TLS verification for `customCAD`. Do not use in production. Takes no
  argument.
* `customNameservers` **NAMESERVER...** nameservers to use for lego's propagation pre-check. For
  development only.

### Certificate storage

Where issued certificates are stored. Set at most one; defaults to
`certificateStorageDisk /var/lib/coredns/certs`.

* `certificateStorageDisk` **PATH** `[MODE]` write certificate files under **PATH**`/certs`. **PATH**
  must be absolute. The optional **MODE** sets the private-key file mode, one of `600`, `640`, `644`
  (default `600`).
* `certificateStorageKubernetes` **NAMESPACE** store one `kubernetes.io/tls` Secret per domain in
  **NAMESPACE** (`tls.crt`, `tls.key`, and `acme.json` renewal metadata). Uses in-cluster config,
  falling back to the default kubeconfig (`KUBECONFIG`, `~/.kube/config`) out of cluster.
* `certificateStorageVault` **MOUNT** **PREFIX** `[token|kubernetes ROLE]` store one entry per domain
  in an OpenBao/Vault KV v2 engine at **MOUNT**`/data/`**PREFIX**`/`*domain*. See
  [Vault / OpenBao](#vault--openbao).

### Account-key storage

Where the ACME account key is stored, chosen independently of certificate storage. Set at most one;
defaults to `accountStorageDisk /var/lib/coredns/acme-user`.

* `accountStorageDisk` **PATH** write the account key to **PATH**`/users/`*email*`/key.pem`. **PATH**
  must be absolute.
* `accountStorageKubernetes` **NAMESPACE** store the account key as an `Opaque` Secret
  (`acme-account-`*email*) in **NAMESPACE**.
* `accountStorageVault` **MOUNT** **PREFIX** `[token|kubernetes ROLE]` store the account key at
  **MOUNT**`/data/`**PREFIX**`/`*email*. See [Vault / OpenBao](#vault--openbao).

### Vault / OpenBao

The `*StorageVault` directives target a [KV version 2](https://openbao.org/docs/secrets/kv/kv-v2/)
engine and work with both OpenBao and Vault. The server address, namespace and TLS settings are read
from the environment (`BAO_ADDR`/`VAULT_ADDR`, `BAO_NAMESPACE`/`VAULT_NAMESPACE`,
`BAO_CACERT`/`VAULT_CACERT`, ...). Authentication is selected by the optional third argument:

* `token` (default) the token is read from `BAO_TOKEN`/`VAULT_TOKEN`, for example one injected by an
  agent sidecar.
* `kubernetes` **ROLE** log in at `auth/kubernetes/login` with the pod's ServiceAccount token and the
  given **ROLE**.

## Examples

Obtain and renew a certificate for `example.org` and `*.example.org`, storing everything on disk:

~~~ txt
example.org:53 {
    acmednschallenge {
        email admin@example.org
        acceptedLetsEncryptToS
        additionalSans *.example.org
        certificateStorageDisk /var/lib/coredns/certs
    }

    file db.example.org
}
~~~

Store certificates in Kubernetes Secrets while keeping the ACME account key in OpenBao/Vault using
Kubernetes auth:

~~~ txt
example.org:53 {
    acmednschallenge {
        email admin@example.org
        acceptedLetsEncryptToS
        certificateStorageKubernetes cert-manager
        accountStorageVault secret coredns/acme kubernetes coredns
    }

    forward . 127.0.0.1:5300
}
~~~

## Building

This plugin must be compiled into CoreDNS. Add it to
[plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg) **above `file` and `forward`**:

~~~ txt
acmednschallenge:github.com/BaseCrusher/coredns-acmednschallenge
~~~

Plugin order in `plugin.cfg` is the request-handling order (not the Corefile order). This plugin only
intercepts `_acme-challenge` TXT queries and passes everything else on, so it must run before the
plugin that serves the zone — otherwise `file`/`forward` answers the challenge query first and
issuance fails. Then rebuild with `go generate && go build`, or `make`.

## Development

1. Clone CoreDNS from [GitHub](https://github.com/coredns/coredns).
2. Clone this repository into `plugin/acmednschallenge`.
3. Add `acmednschallenge` to `plugin.cfg`, above `file` and `forward` (see [Building](#building)).
4. Run `go generate` and `go build`.
5. Create a Corefile under `_development_stuff/coredns_configs/Corefile`:

    ~~~ txt
    example.org:5354 {
        acmednschallenge {
            email admin@example.org
            acceptedLetsEncryptToS
            additionalSans *.example.org
            certificateStorageDisk /tmp/coredns-certs
            accountStorageDisk /tmp/coredns-acme
            customCAD https://localhost:14000/dir
            allowInsecureCAD
            skipDnsPropagationTest
            customNameservers 127.0.0.1:5354
        }

        file db.example.org

        log
        errors
    }
    ~~~

    Notes:
    * Port `5354` (not `53`): `53`/`5354`... `53` needs root and, together with `5353`, clashes with
      the mDNS/Bonjour resolver on macOS. Any free high port works.
    * `accountStorageDisk` keeps the ACME account key off the default `/var/lib/coredns` path, which
      needs root.
    * `skipDnsPropagationTest` disables lego's *authoritative-nameserver* propagation check — that
      check resolves the zone's `NS` and queries it on port `53`, which can't reach CoreDNS on `5354`.
      lego's recursive check still runs against `customNameservers` (i.e. CoreDNS itself), and Pebble
      still validates the challenge for real via its `-dnsserver`, so DNS answering is fully exercised.

6. Create the zone file `db.example.org` next to the Corefile so the `file` plugin can serve the zone:

    ~~~ txt
    $ORIGIN example.org.
    $TTL 3600
    @   IN  SOA ns.example.org. admin.example.org. ( 1 7200 3600 1209600 3600 )
    @   IN  NS  ns.example.org.
    ns  IN  A   127.0.0.1
    @   IN  A   127.0.0.1
    ~~~

7. Run `docker compose up` under `_development_stuff/pebble` to start the mock ACME server. Its
   `-dnsserver` already points at `host.docker.internal:5354`, so Pebble validates against your local
   CoreDNS — no `/etc/hosts` entries needed.
8. Run `coredns -conf <path_to_Corefile>`. A certificate for `example.org` should appear under
   `/tmp/coredns-certs/certs` within a few seconds.
