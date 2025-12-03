# CoreDNS acme-dns challenge plugin
## Description
This plugin uses acme-dns challenge to get a certificate for specified domains. By default, it uses Let'sEncrypt.
It is build on [lego](https://github.com/go-acme/lego) and automatically creates the required records to solve the challenge.

## Usage
### Compilation
This package must be compiled as part of CoreDNS.
A simple way to consume this plugin, is by adding the following on [plugin.cfg](https://github.com/coredns/coredns/blob/master/plugin.cfg), and recompile it as [detailed on coredns.io](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/#build-with-compile-time-configuration-file).

```
acmednschallenge:github.com/BaseCrusher/coredns-acmednschallenge
```

After this you can compile coredns by:

``` sh
go generate
go build
```

Or you can instead use make:

``` sh
make
```

### Configuration
```
example.com:53 {
    acmednschallenge {
        dataPath <path_to_data_folder>
        email test@test.com
        acceptedLetsEncryptToS
        useLetsEncryptTestServer
        additionalSans *.example.com
        renewBeforeDays 20
        certValidationInterval 24h
        dnsTimeout 60s
        dnsTTL 60
        customCAD https://localhost:14000/dir
        allowInsecureCAD
        customNameservers 127.0.0.1:53
    }
}
```
- `dataPath`
  - Required. String
  - Absolute path where the plugin will save acme user data the certificates.
- `email`
    - Required. String
    - The email used for Let'sEncrypt API.
- `acceptedLetsEncryptToS`
    - Required. Boolean. Must be set.
    - If you agree to the [Let'sEncrypt Terms of Service](https://letsencrypt.org/privacy/). By settings this you're agreeing to them.
- `skipDnsPropagationTest`
    - Optional. Boolean. Default: false
    - If set lego will skip the DNS propagation test.
- `useLetsEncryptTestServer`
    - Optional. Boolean. Default: false
    - Use Let'sEncrypts test server.
- `additionalSans` 
  - Optional. String list
  - Additional SANs to add to the certificate.
- `renewBeforeDays` 
  - Optional. Int between 1 and 30. Default: 30
  - Days before the certificate expires to renew it.
- `certValidationInterval`
    - Optional. Interval in go format [Duration](https://pkg.go.dev/time#ParseDuration). Default: 24h
    - How often to check if the certificate is valid and renew if needed.
- `customCAD` 
  - Optional. String
  - Custom CA Directory.
- `allowInsecureCAD` 
  - Optional. Boolean. Default: false
  - Disable TLS verification for the CA Directory. Don't use this in production.
- `customNameservers` 
  - Optional. String list
  - Custom nameservers to use when lego makes a precheck for the records. (For development purposes only)
- `dnsTimeout`
  - Optional. Interval in go format [Duration](https://pkg.go.dev/time#ParseDuration). Default: 60s
    - Timeout for DNS Propagation.
- `dnsTTL`
    - Optional. Int between 60 and 600. Default: 60
        - TTL of the TXT record used for DNS challenge.

#### Basic example
```
example.com:53 {
    acmednschallenge {
        certSavePath /my_certs/
        email test@test.com
        acceptedLetsEncryptToS
        additionalSans *.example.com
    }
}
```
- Will create a certificate for example.com and *.example.com.
- Will save 
  - the certificate with its full chain at `/my_certs/example.com.pem`.
  - the private key at `/my_certs/example.com.key.pem`.
- Will check every 24h if the certificate is still more than 30 days valid and if not, will try to renew it.


## Development
1. Clone coredns from [GitHub](https://github.com/coredns/coredns)
2. Clone this repository into `plugin/acmednschallenge`
3. Add `acmednschallenge` to the `plugin.cfg`
4. Run `go generate`
5. Run `go build`
6. Add local entry for `example.com` in `/etc/hosts` for Linux or in `C:\Windows\System32\drivers\etc\hosts` for Windows pointing to `127.0.0.1`. There are scripts that will do that for you under `_development_stuff/scripts`.
7. Create a Corefile under `_development_stuff/coredns_configs/Corefile`.

    ```
    example.com:53 {
        acmednschallenge {
            certSavePath <path_to_cert_folder>
            email test@test.com
            additionalSans *.example.com
            acceptedLetsEncryptToS
            customCAD https://localhost:14000/dir
            customNameservers 127.0.0.1:53
            allowInsecureCAD
        }
    
        file <path_to_zone_file. should be next to the Corefile>
    
        log
        errors
    }
    ```
8. Run `docker-compose up` under `_development_stuff/pebble` to start the mock ACME server.
9. Run `coredns -conf <path_to_Corefile>` to start coredns.
