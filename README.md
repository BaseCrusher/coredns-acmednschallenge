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
    clusterMode SERVICE [PORT] [STARTUP_DELAY] [OWN_IP]

    # certificate storage — choose at most one (default: certificateStorageDisk /var/lib/coredns/certs)
    certificateStorageDisk PATH [MODE] [GROUP]
    certificateStorageKubernetes NAMESPACE
    certificateStorageVault MOUNT PREFIX [token|kubernetes ROLE]

    # account-key storage — choose at most one (default: acmeAccountStorageDisk /var/lib/coredns/acme-user)
    acmeAccountStorageDisk PATH [MODE] [GROUP]
    acmeAccountStorageKubernetes NAMESPACE
    acmeAccountStorageVault MOUNT PREFIX [token|kubernetes ROLE]
}
~~~

* `email` **EMAIL** **required**, the contact address registered with the ACME account.
* `acceptedLetsEncryptToS` **required**, its presence records your agreement to the Let's Encrypt
  [Terms of Service](https://letsencrypt.org/privacy/).
* `additionalSans` **SAN...** **optional**, additional subject alternative names to include on the
  certificate, for example `*.example.org`. Each SAN must be the managed domain, a wildcard of it, or a
  subdomain of it.
* `renewBeforeDays` **DAYS** **optional**, renew this many days before expiry, an integer `>= 1`.
  Default `10`. Values above `30` are accepted but not recommended, as they largely defeat
  renew-before-expiry.
* `certValidationInterval` **DURATION** **optional**, how often certificates are checked for renewal, a
  Go [duration](https://pkg.go.dev/time#ParseDuration). Default `24h`.
* `retryInterval` **DURATION** **optional**, when issuing or renewing a certificate fails, retry this
  often until it succeeds, a Go duration. Default `0`, which disables retrying (the domain is retried on
  the next `certValidationInterval` tick instead).
* `maxRetryCount` **COUNT** **optional**, maximum number of retries per validation cycle when
  `retryInterval` is set, a non-negative integer. Default `3`. After the retries are exhausted the
  domain is retried on the next `certValidationInterval` tick.
* `dnsTTL` **TTL** **optional**, TTL of the challenge TXT record, an integer in `[60, 600]`. Default
  `120`.
* `dnsTimeout` **DURATION** **optional**, timeout for the DNS propagation check, a Go duration. Default
  `60s`.
* `skipDnsPropagationTest` **optional**, skip lego's DNS propagation pre-check. Takes no argument.
* `useLetsEncryptTestServer` **optional**, use the Let's Encrypt staging server. Takes no argument.
* `customCAD` **URL** **optional**, ACME CA directory URL to use instead of Let's Encrypt.
* `allowInsecureCAD` **optional**, disable TLS verification for `customCAD`. Do not use in production.
  Takes no argument.
* `customNameservers` **NAMESERVER...** **optional**, nameservers to use for lego's propagation
  pre-check. For development only.
* `clusterMode` **SERVICE** `[PORT]` **optional**, run several CoreDNS instances as a cluster. Its
  presence enables cluster mode (default off). See [Cluster mode](#cluster-mode).
* `certificateStorage*` **optional**, where issued certificates are stored — pick at most one backend.
  See [Certificate storage](#certificate-storage).
* `acmeAccountStorage*` **optional**, where the ACME account key is stored, chosen independently — pick
  at most one backend. See [Account-key storage](#account-key-storage).

### Certificate storage

Where issued certificates are stored. Set at most one; defaults to
`certificateStorageDisk /var/lib/coredns/certs`.

* `certificateStorageDisk` **PATH** `[MODE]` `[GROUP]` write certificate files under **PATH**`/certs`.
  **PATH** must be absolute. The optional **MODE** sets the mode of the cert files (`.key`/`.pem`/`.json`)
  and the `certs` directory (which additionally gets the matching execute bits: `600`→`700`, `640`→`750`,
  `644`→`755`), one of `600`, `640`, `644` (default `600`). The optional **GROUP** (group name or numeric
  gid) sets the group owner of the cert files and directory via `chgrp`; the file owner is left
  unchanged, so a non-root CoreDNS keeps full access. **GROUP** is only accepted when **MODE** grants
  group access (`640` or `644`) — it is rejected with `600`, since the group would have no way to read
  the files. On startup the configured mode and group are re-applied to any existing files, so changing
  them in the config takes effect on restart. The account key has its own independent mode/group — see
  [`acmeAccountStorageDisk`](#account-key-storage).
* `certificateStorageKubernetes` **NAMESPACE** store one `kubernetes.io/tls` Secret per domain in
  **NAMESPACE** (`tls.crt`, `tls.key`, and `acme.json` renewal metadata). Uses in-cluster config,
  falling back to the default kubeconfig (`KUBECONFIG`, `~/.kube/config`) out of cluster.
* `certificateStorageVault` **MOUNT** **PREFIX** `[token|kubernetes ROLE]` store one entry per domain
  in an OpenBao/Vault KV v2 engine at **MOUNT**`/data/`**PREFIX**`/`*domain*. See
  [Vault / OpenBao](#vault--openbao).

### Account-key storage

Where the ACME account key is stored, chosen independently of certificate storage. Set at most one;
defaults to `acmeAccountStorageDisk /var/lib/coredns/acme-user`.

* `acmeAccountStorageDisk` **PATH** `[MODE]` `[GROUP]` write the account key to
  **PATH**`/users/`*email*`/key.pem`. **PATH** must be absolute. The optional **MODE** and **GROUP**
  work exactly as for [`certificateStorageDisk`](#certificate-storage) — **MODE** (`600`/`640`/`644`,
  default `600`) sets the mode of `key.pem` and the `users` directories (with matching execute bits),
  **GROUP** sets their group owner, and both are re-applied to existing files on startup.
* `acmeAccountStorageKubernetes` **NAMESPACE** store the account key as an `Opaque` Secret
  (`acme-account-`*email*) in **NAMESPACE**.
* `acmeAccountStorageVault` **MOUNT** **PREFIX** `[token|kubernetes ROLE]` store the account key at
  **MOUNT**`/data/`**PREFIX**`/`*email*. See [Vault / OpenBao](#vault--openbao).

### Cluster mode

By default a single CoreDNS instance drives ACME. `clusterMode` lets you run several instances behind
one zone: the instance with the **lowest IP** drives ACME issuance/renewal, while **every** instance
serves the `_acme-challenge` TXT records, so the DNS-01 challenge resolves no matter which instance the
CA queries.

* `clusterMode` **SERVICE** `[PORT]` `[STARTUP_DELAY]` `[OWN_IP]` — **SERVICE** is a DNS name that resolves
  to the addresses of all instances (a Kubernetes headless Service, a Docker Swarm `tasks.` name, etc.).
  **PORT** is the port of the small internal HTTP API each instance runs for coordination; default `8090`.
  **STARTUP_DELAY** is a duration (e.g. `10s`) each instance waits before its first certificate check, so
  peers have time to appear in **SERVICE** before the issuer is picked; default `5s`. **OWN_IP** is this
  instance's address as seen in **SERVICE**; set it when an instance cannot identify itself automatically
  (see below). All arguments after **SERVICE** are optional and may be given in any order: an integer sets
  **PORT**, a duration sets **STARTUP_DELAY**, and an IP sets **OWN_IP**.

How it works:

* There is no leader election or background reconcile loop. Each instance runs the normal cert
  loop; whenever a certificate needs obtaining or renewing, a gate decides whether *this* instance should
  do it: it resolves **SERVICE**, and issues only if it is the **lowest IP** among the resolved instances
  **and** no peer is already mid-challenge. Everyone else simply serves whatever records the issuer pushes.
* Instances discover their peers by resolving **SERVICE** and identify themselves by matching a resolved
  address against their local interfaces — no per-instance config needed in the common case. DNS often
  lags at startup, so each instance waits **STARTUP_DELAY** before its first certificate check to let the
  peer set (including its own address) appear. If an instance's address in **SERVICE** is never one of its
  local interface addresses (NAT, a routed/overlay setup, a ClusterIP rather than pod IPs), set **OWN_IP**
  to that address to fix it.
* Only ready instances are published in **SERVICE**, so a dead lowest-IP instance drops out of DNS and the
  next-lowest takes over automatically — no explicit re-election needed.
* The issuer pushes each challenge TXT record to all peers as soon as it is created. Every other instance
  also polls the issuer every 5s as a backstop: if the issuer has finished or become unreachable, it drops
  the stale records it was holding.

> [!WARNING]
> **Cluster mode requires shared storage.** It only coordinates the ACME challenge; it does **not**
> replicate issued certificates or the account key between instances. Every instance must read and write
> the **same** storage, so any node can serve certs and any node can issue when it is the lowest IP. Use a
> backend that is shared by design (`certificateStorageKubernetes`/`certificateStorageVault` and the
> matching `acmeAccountStorage*`), **or** `certificateStorageDisk`/`acmeAccountStorageDisk` pointing at a
> shared volume mounted by all instances (NFS, a multi-attach block volume, etc.). Per-instance disk
> storage that is not shared will make every issuer change re-issue from scratch and quickly hit ACME
> rate limits.

Every node must be mounted with **read and write** access to the shared certificate and account-key
storage — not just the current issuer. Which instance issues shifts as instances come and go, so any node
may issue, renew, and save certificates and the account key at any time. A node mounted read-only will
fail to persist certificates once it becomes the issuer.

The internal API is unauthenticated; it only carries challenge TXT values, which are public in DNS
anyway.

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
        acmeAccountStorageVault secret coredns/acme kubernetes coredns
    }

    forward . 127.0.0.1:5300
}
~~~

## Metrics

If the [`prometheus`](https://coredns.io/plugins/metrics/) plugin is enabled, the following metrics are
exported under the `coredns_acmednschallenge_` prefix:

* `cert_expiry_timestamp_seconds{domain}` – certificate expiry (`NotAfter`) as a unix timestamp. Alert on
  `(coredns_acmednschallenge_cert_expiry_timestamp_seconds - time()) / 86400 < <days>`.
* `obtain_total{domain, result}` – count of obtain/renew attempts; `result` is `obtained`, `renewed`, or `failed`.
* `challenge_responses_total{server}` – count of ACME DNS-01 TXT challenge responses served.

In cluster mode these are also exported:

* `cluster_peers` – number of peers resolved on the last discovery.
* `cluster_issuing` – `1` while this node is issuing/renewing, `0` otherwise.
* `cluster_push_failures_total` – count of failed challenge pushes to peers.

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
            acmeAccountStorageDisk /tmp/coredns-acme
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
    * `acmeAccountStorageDisk` keeps the ACME account key off the default `/var/lib/coredns` path, which
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
