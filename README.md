# httpx-pki

[![CI](https://img.shields.io/github/actions/workflow/status/ccbest/httpx-pki/ci.yml?branch=main&label=CI)](https://github.com/ccbest/httpx-pki/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/ccbest/httpx-pki?branch=main)](https://codecov.io/gh/ccbest/httpx-pki)
[![PyPI](https://img.shields.io/pypi/v/httpx-pki)](https://pypi.org/project/httpx-pki/)
[![Python versions](https://img.shields.io/pypi/pyversions/httpx-pki)](https://pypi.org/project/httpx-pki/)
[![Docs](https://img.shields.io/readthedocs/httpx-pki)](https://httpx-pki.readthedocs.io/)
[![License: MIT](https://img.shields.io/pypi/l/httpx-pki)](https://github.com/ccbest/httpx-pki/blob/main/LICENSE)
[![Checked with mypy](https://img.shields.io/badge/mypy-checked-2a6db2)](https://mypy-lang.org/)

PKCS#12 client-certificate (mTLS) sessions for
[httpx2](https://github.com/pydantic/httpx2) and
[httpx](https://www.python-httpx.org/).

`httpx-pki` gives you an `httpx.Client` (and `httpx.AsyncClient`) subclass with a
client certificate already mounted, so mutual-TLS endpoints "just work":

```python
from httpx_pki import PKIClient

with PKIClient("client.p12", password="secret") as client:
    resp = client.get("https://mtls.example.com/")
    print(resp.status_code)
```

📖 **[Full documentation](https://httpx-pki.readthedocs.io/)**

#### Purpose

httpx deprecated its `cert=` argument in 0.28 — a design httpx2 keeps — in
favor of building an `ssl.SSLContext` yourself, which stdlib `ssl` can't do
from PKCS#12 or in-memory bytes. `httpx-pki` is that missing piece.

## Install

```bash
pip install httpx-pki
```

Requires Python 3.10+. httpx2 comes with it, along with `cryptography`,
`truststore`, and `certifi`.

Prefer the original httpx? It stays fully supported — install with `--no-deps`
so httpx2 isn't pulled in. See
[Install](https://httpx-pki.readthedocs.io/en/stable/install.html) and
[Backends](https://httpx-pki.readthedocs.io/en/stable/guide/backends.html).

## Whatever you were handed, there's a one-liner for it

Certificate files come with all sorts of extensions — `.p12`, `.pfx`, `.pem`,
`.crt`, `.tls` — but an extension is just a name. `httpx-pki` detects the
encoding from the **bytes**, so you can point it at whatever your PKI team sent
you:

```python
from httpx_pki import PKIClient

# PKCS#12 bundle — key + cert + chain in one blob
PKIClient("client.p12", password="secret")

# PEM bundle — key + cert(s) in one file, any block order
PKIClient("client.pem")

# Raw bytes you already have in hand
PKIClient(p12_bytes, password=b"secret")

# Separate certificate and key, PEM or DER
PKIClient.from_key_pair("client.crt", "client.key")

# ...with intermediates, as PEM or PKCS#7
PKIClient.from_key_pair("client.crt", "client.key", chain="chain.p7b")

# The Windows certificate store (Windows only)
PKIClient.from_windows_cert_store(name="Acme Corp")

# The macOS keychain (macOS only)
PKIClient.from_macos_keychain(name="Acme Corp")

# Configured entirely by environment variables
PKIClient.from_env()
```

→ [Loading certificates](https://httpx-pki.readthedocs.io/en/stable/guide/loading-certificates.html)

## Handed a whole folder?

A CA rarely sends one file. `inventory` reads the folder, says what each file
actually is, pairs the keys with their certificates, and prints the call each
pairing amounts to:

```console
$ python -m httpx_pki inventory ./corp-export
```

```text
INVENTORY  corp-export — 7 files, 2 identities

IDENTITY   svc-client   RSA-2048   expires 2027-01-15
             bundle        corp.p12 (password #1)
             chain         corp-issuing-ca.crt
             → PKIClient("corp.p12", password=..., chain="corp-issuing-ca.crt")

IDENTITY   svc-client   RSA-2048   expires 2027-01-15
             certificate   svc-client.pem
             private key   svc-client.key (encrypted — opened with password #2)
             chain         corp-issuing-ca.crt
             same certificate as corp.p12
             → from_key_pair(certificate="svc-client.pem", private_key="svc-client.key", password=..., chain="corp-issuing-ca.crt")

LOCKED     old-2025.pem — 1 certificate, plus 1 encrypted private key none of the given passwords open

NOTES      cert-details.txt — human-readable dump; fingerprint matches corp.p12 (not loadable)
           svc-client.csr — certificate request for the key of corp.p12 (issuance artifact, not loadable)
```

Nothing is skipped: a file no password opens is reported as locked, not
dropped. It classifies and pairs — it never builds a session for you, because a
folder like that usually holds more than one answer.

→ [Taking inventory of a folder](https://httpx-pki.readthedocs.io/en/stable/guide/taking-inventory.html)

## Async

```python
from httpx_pki import AsyncPKIClient

async with AsyncPKIClient("client.p12", password="secret") as client:
    resp = await client.get("https://mtls.example.com/")
```

## One file, several certificates

A PKCS#12 or PEM bundle can hold more than one identity — a dual key pair from
AD key archival, or a renewed certificate kept beside the one it replaces.
`cryptography` can't express that: it returns the first key and leaves the other
identity's certificate looking like a chain certificate. `httpx-pki` reads the
structure itself, so you can inspect and select:

```python
from httpx_pki import PKIClient, list_identities, for_mtls

list_identities("corp.p12", password="secret")   # see what's in there

# Usually all you need: the identity that is valid now and can do client auth
PKIClient("corp.p12", password="secret", identity=for_mtls)

# Or pick one yourself
PKIClient("corp.p12", password="secret", key_usage="digital_signature")
PKIClient("corp.p12", password="secret", identity="Signature")
```

Loading a multi-identity bundle without a selector raises rather than guessing.

→ [Choosing the right certificate](https://httpx-pki.readthedocs.io/en/stable/guide/choosing-a-certificate.html)

## Server trust

Your client certificate and the server's are independent. `verify=True` (the
default) uses the **OS trust store**, so corporate CAs distributed by group
policy or MDM work out of the box:

```python
PKIClient("client.p12", password="secret", verify="/etc/ssl/internal-ca.pem")
PKIClient("client.p12", password="secret", verify="certifi")
```

Naming a bundle *replaces* the default trust. To keep it and add your own —
the usual shape for a service that talks to internal and public endpoints
both — pass a list:

```python
PKIClient("client.p12", password="secret",
          verify=["system", "/etc/pki/internal-root.pem"])
```

→ [Server trust](https://httpx-pki.readthedocs.io/en/stable/guide/server-trust.html)

## Expiry and rotation

Certificates keep getting shorter-lived. Warn early, reload automatically, or
fail loudly:

```python
from datetime import timedelta

PKIClient(
    "/etc/certs/client.pem",
    auto_reload=True,                            # pick up cert-manager rotations
    strict_validity=True,                        # fail clearly, not at handshake
    warn_if_expires_within=timedelta(days=7),
)
```

→ [Expiry and rotation](https://httpx-pki.readthedocs.io/en/stable/guide/expiry-and-rotation.html)

## Inspecting what's mounted

```python
client.cn                 # 'corp-user'
client.not_valid_after    # datetime (UTC)
client.is_expired         # bool
client.cert_info()        # CertInfo: subject, issuer, fingerprints, usages, SANs
```

→ [Inspecting a certificate](https://httpx-pki.readthedocs.io/en/stable/guide/inspecting-a-certificate.html)

## Why won't the handshake work?

`explain()` takes the same arguments as the constructors and reports what it
*would* do instead of doing it — what the source holds, what it would present,
what it would trust, and what would stop it working:

```console
$ python -m httpx_pki explain corp.p12 --verify internal-ca.pem
```

```text
corp.p12 — PKCS#12, 1 identity, 1 chain certificate

PRESENTS   svc-client
           valid      2026-01-15 → 2027-01-15   (159 days left)
           ext usage  client_auth

CHAIN      svc-client
             └─ Corp Issuing CA   [verified]
               └─ Corp Root   [NOT SUPPLIED; trust anchor, need not be sent]

TRUSTS     internal-ca.pem — 1 anchor: Corp Root

PROBLEMS   none
```

It works when *loading* does not — several identities with no selector, or a
missing password, produce a report rather than an exception. `client.explain()`
does the same for a live session, and the CLI exits non-zero when there are
problems, so it works as a CI check.

→ [Explaining a whole configuration](https://httpx-pki.readthedocs.io/en/stable/guide/inspecting-a-certificate.html#explaining-a-whole-configuration)

## Just the SSL context

Don't want the client wrapper? `build_ssl_context()` gives you the hard part,
ready for a plain `httpx.Client` or a custom transport:

```python
import httpx
from httpx_pki import build_ssl_context

ctx = build_ssl_context("client.p12", password="secret")
client = httpx.Client(verify=ctx)
```

⚠️ Passing a custom `transport=` makes httpx ignore `verify=` — put the context
on the **inner** transport, not the client.

→ [Advanced usage](https://httpx-pki.readthedocs.io/en/stable/guide/advanced.html)

## Testing helpers

`httpx_pki.testing` mints throwaway certificates, including multi-identity
bundles that nothing else readily produces:

```python
from httpx_pki.testing import make_ca, make_client_cert

ca = make_ca()
bundle = make_client_cert("svc-client", ca=ca, dns_names=["svc.internal"])
expired = make_client_cert("old", ca=ca, expired=True)
```

→ [Testing helpers](https://httpx-pki.readthedocs.io/en/stable/guide/testing.html)

## ⚠️ Security note on pickling

To support pickling, a client stores its certificate material and rebuilds the
SSL context on unpickle. **The pickle therefore contains the decrypted private
key in cleartext** — treat it as a secret. `repr()` never reveals key material.

Passwords are not retained, with one exception: enabling `auto_reload` keeps the
password on the client so unattended reloads can decrypt the rotated source.

→ [Security notes](https://httpx-pki.readthedocs.io/en/stable/about/security.html)
· [SECURITY.md](https://github.com/ccbest/httpx-pki/blob/main/SECURITY.md)

## How it works

Stdlib `ssl` can't load PKCS#12 or in-memory key material, so `httpx-pki` uses
[`cryptography`](https://cryptography.io/) to extract the key and certificates,
stages them where OpenSSL can read them, and passes the resulting
`ssl.SSLContext` to httpx via `verify=`.

**On Linux the decrypted key never touches disk** — it's staged in an anonymous
`memfd` that OpenSSL reads through `/proc/self/fd` and that ceases to exist when
closed. Elsewhere it's a `0600` temp file, deleted immediately after loading.

→ [How it works](https://httpx-pki.readthedocs.io/en/stable/about/how-it-works.html)

## Non-goals

Scoped to credentials whose private key can be exported into memory. Not
supported: **PKCS#11 / smartcards / HSMs / TPMs** (incompatible with stdlib
`ssl`, which needs the raw key bytes), **Java keystores** (convert to PKCS#12
with `keytool`), **workload-identity protocol clients** (point `auto_reload` at
the files they write), and **OCSP / CRL revocation** (nothing in stdlib `ssl` to
build on).

→ [Non-goals](https://httpx-pki.readthedocs.io/en/stable/about/non-goals.html)

## Supply chain

Released to PyPI exclusively from GitHub Actions via
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC — no
long-lived tokens) with [PEP 740](https://peps.python.org/pep-0740/)
attestations, from a tagged commit whose version is verified against
`__version__` at build time. All Actions are pinned to full commit SHAs.

Install via a lockfile that records hashes, as with any security-sensitive
dependency.

→ [Supply chain](https://httpx-pki.readthedocs.io/en/stable/about/supply-chain.html)
· [Changelog](https://github.com/ccbest/httpx-pki/blob/main/CHANGELOG.md)

## License

MIT
