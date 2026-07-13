# httpx-pki

[![CI](https://img.shields.io/github/actions/workflow/status/ccbest/httpx-pki/ci.yml?branch=main&label=CI)](https://github.com/ccbest/httpx-pki/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/ccbest/httpx-pki?branch=main)](https://codecov.io/gh/ccbest/httpx-pki)
[![PyPI](https://img.shields.io/pypi/v/httpx-pki)](https://pypi.org/project/httpx-pki/)
[![Python versions](https://img.shields.io/pypi/pyversions/httpx-pki)](https://pypi.org/project/httpx-pki/)
[![License: MIT](https://img.shields.io/pypi/l/httpx-pki)](https://github.com/ccbest/httpx-pki/blob/main/LICENSE)
[![Checked with mypy](https://img.shields.io/badge/mypy-checked-2a6db2)](https://mypy-lang.org/)

PKCS#12 client-certificate (mTLS) sessions for [httpx](https://www.python-httpx.org/).

`httpx-pki` gives you an `httpx.Client` (and `httpx.AsyncClient`) subclass with a
client certificate already mounted, so mutual-TLS endpoints "just work":

```python
from httpx_pki import PKIClient

with PKIClient("client.p12", password="secret") as client:
    resp = client.get("https://mtls.example.com/")
    print(resp.status_code)
```

#### Purpose

httpx deprecated its `cert=` argument in 0.28 in favor of building an
`ssl.SSLContext` yourself — which stdlib `ssl` can't do from PKCS#12 or in-memory
bytes. `httpx-pki` is that missing piece.

## Install

```bash
pip install httpx-pki
```

Requires Python 3.10+, `httpx>=0.28`, and `cryptography>=44`.

## Supported formats

Certificate files come with many extensions (`.p12`, `.pfx`, `.pem`, `.crt`,
`.key`, `.tls`, `.ukey`, ...), but an extension is just a name — what matters is
the **encoding of the bytes**. `httpx-pki` detects that from the content, so the
extension never matters:

| Input | Constructor | Notes |
| --- | --- | --- |
| **PKCS#12** (`.p12`, `.pfx`, binary) | `PKIClient(...)` or `from_pkcs12(...)` | key + cert + chain in one password-protected blob |
| **PEM bundle** (key + cert(s) in one file) | `PKIClient(...)` or `from_pem(...)` | any block order; PKCS#1/PKCS#8/EC/encrypted keys |
| **Separate cert + key** (PEM *or* DER) | `from_key_pair(...)` | optional `chain=` intermediates |
| **Windows cert store** | `from_windows_cert_store(...)` | Windows only; see below |

`PKIClient(source, password=...)` auto-detects PKCS#12 vs PEM, so you can point
it at whatever you were handed. Use the explicit `from_pkcs12` / `from_pem`
constructors when you want to force one interpretation.

## Usage

### From a PKCS#12 bundle (`.p12` / `.pfx`)

A path (`str` or `pathlib.Path`) or raw `bytes` both work:

```python
from pathlib import Path
from httpx_pki import PKIClient

PKIClient("client.p12", password="secret")          # path
PKIClient(Path("client.pfx"), password="secret")     # pathlib.Path
PKIClient(p12_bytes, password=b"secret")             # bytes; password may be bytes
```

### From a PEM file (key + cert in one blob)

```python
from httpx_pki import PKIClient

PKIClient("client.pem")                       # auto-detected
PKIClient.from_pem("client.pem")              # explicit
PKIClient.from_pem(pem_bytes, password="..")  # if the key block is encrypted
```

### From a separate certificate and key

```python
from httpx_pki import PKIClient

client = PKIClient.from_key_pair(
    certificate="client.crt",
    private_key="client.key",
    key_password="secret",      # if the key is encrypted
    chain="intermediate.crt",   # optional: intermediates to present; one
                                # path/bytes (may concatenate several) or a list
)
```

### From the Windows certificate store (Windows only)

Pull an **exportable** client certificate (key included) straight out of the
user's personal store, selecting by a case-insensitive substring of the subject
common name or the Windows "friendly name":

```python
from httpx_pki import PKIClient

with PKIClient.from_windows_cert_store(name="ACME Client") as client:
    client.get("https://mtls.example.com/")
```

If several certificates match you'll get an `AmbiguousCertificateError` listing
the candidates; narrow it with an exact thumbprint or a predicate:

```python
PKIClient.from_windows_cert_store(thumbprint="A1:B2:C3:...")
PKIClient.from_windows_cert_store(predicate=lambda c: c.friendly_name == "prod")
PKIClient.from_windows_cert_store(name="ACME", location="LocalMachine")
```

To see what's in the store before selecting, `list_windows_certificates()`
returns a `WinCert` (subject CN, friendly name, thumbprint) for each certificate
— metadata only, no key is exported:

```python
from httpx_pki import list_windows_certificates

for c in list_windows_certificates():        # location="LocalMachine" for the machine store
    print(c.friendly_name, c.subject_cn, c.thumbprint)
```

Notes:

- **Windows only** — calling it elsewhere raises `UnsupportedPlatformError`.
- The certificate's private key must have been imported as **exportable** —
  otherwise the export fails with a `CertificateLoadError`.
- No password is involved: the cert is exported under a random, single-use
  password that never leaves the library.
- `AsyncPKIClient.from_windows_cert_store(...)` is the async equivalent.

### From environment variables

For containerized / 12-factor deployments, configure the certificate out of band:

```python
from httpx_pki import PKIClient

with PKIClient.from_env() as client:        # reads HTTPX_PKI_* by default
    client.get("https://mtls.example.com/")
```

| Variable | Meaning |
| --- | --- |
| `HTTPX_PKI_CERT` | path to a PKCS#12 or PEM source (**required**) |
| `HTTPX_PKI_PASSWORD` | password for the cert / key (optional) |
| `HTTPX_PKI_KEY` | path to a separate private key; switches to cert+key mode |
| `HTTPX_PKI_CA` | CA bundle for **server** trust (`verify=`) |

Pass a different `prefix=` to namespace per service (`PKIClient.from_env("MYAPP_")`).

### Async

```python
from httpx_pki import AsyncPKIClient

async with AsyncPKIClient("client.p12", password="secret") as client:
    resp = await client.get("https://mtls.example.com/")
```

### Passing httpx options

Any extra keyword arguments flow straight through to the underlying httpx client:

```python
PKIClient("client.p12", base_url="https://api.example.com",
           headers={"User-Agent": "me"}, timeout=10.0, http2=True)
```

### Server trust (`verify`)

Mounting *your* client certificate and verifying the *server's* certificate are
independent. `verify` behaves just like httpx — `True` (default, uses certifi),
`False` to disable (with a warning), a path to a CA bundle, or a ready-made
`ssl.SSLContext`:

```python
PKIClient("client.p12", verify="/etc/ssl/custom-ca.pem")
```

> **Passing your own `ssl.SSLContext`?** `httpx-pki` loads the client certificate
> into that exact object (it can't be copied), so don't reuse a shared context
> across clients — each load would overwrite the previous cert. You'll get a
> warning. Pass `verify=True` or a CA-bundle path to let `httpx-pki` build a
> dedicated context instead.

### Subclassing

```python
class MyServiceSession(PKIClient):
    def __init__(self, p12, **kwargs):
        super().__init__(p12, base_url="https://service.internal", **kwargs)

    def health(self):
        return self.get("/health").json()
```

### Inspecting the certificate

```python
info = client.cert_info()
print(info.common_name, info.not_after, info.subject_alt_names)
print(info.dns_names)  # just the dNSName SANs, for hostname checks
```

`subject_alt_names` lists every SAN entry as a string (DNS names, IP addresses,
email addresses, URIs); `dns_names` is the dNSName subset.

### Expiry awareness

An expired (or not-yet-valid) client certificate is the most common silent mTLS
failure. Loading one **warns** immediately, and the session exposes its validity
window so you can check before you depend on it:

```python
client.is_expired        # bool
client.is_not_yet_valid  # bool
client.expires_in        # timedelta (negative once expired)
client.not_valid_after   # datetime (UTC)
```

Pass `warn_if_expires_within=` to be told about a cert that's about to roll over,
and call `check_validity()` to turn "not currently usable" into a hard error:

```python
from datetime import timedelta
from httpx_pki import PKIClient, CertificateExpiredError

client = PKIClient("client.p12", password="secret",
                    warn_if_expires_within=timedelta(days=14))

client.check_validity()                       # raises if expired / not yet valid
client.check_validity(within=timedelta(days=7))  # also raises if it expires soon
```

(`check_validity` raises `CertificateExpiredError` or `CertificateNotYetValidError`.)

### Just the SSL context

Don't want the session wrapper? `build_ssl_context` gives you the hard part — a
ready `ssl.SSLContext` with the client certificate mounted — to use with a plain
`httpx.Client`, an httpx transport, or anything else that accepts a context:

```python
import httpx
from httpx_pki import build_ssl_context

ctx = build_ssl_context("client.p12", password="secret")
client = httpx.Client(verify=ctx)
```

`build_windows_ssl_context` is the same seam for the Windows store — it selects a
certificate exactly like `from_windows_cert_store` (`name` / `thumbprint` /
`predicate`) but hands back the `ssl.SSLContext` instead of a session, so you can
mount a store cert on your own transport without building a client first:

```python
from httpx_pki import build_windows_ssl_context

ctx = build_windows_ssl_context(predicate=lambda c: c.friendly_name == "prod")
```

### Custom transports (e.g. `httpx-retries`)

`httpx-pki` is fully compatible with libraries that supply a custom transport,
such as [`httpx-retries`](https://github.com/will-ockmore/httpx-retries) — but
there is one **httpx rule** to know, and it is not specific to this library:

> Whenever you pass a custom `transport=` (or `mounts=`) to an httpx client, httpx
> uses that transport **as-is** and ignores the client-level `verify=`/`cert=`.
> The TLS configuration — including your client certificate — must live on the
> transport itself.

So the client certificate has to be mounted on the **inner** transport that the
retry transport wraps. `build_ssl_context()` is exactly that seam:

```python
import httpx
from httpx_pki import build_ssl_context
from httpx_retries import RetryTransport, Retry

# ✅ WORKS — the cert lives on the inner transport the retry layer wraps
ctx = build_ssl_context("client.p12", password="secret", verify="/etc/ssl/ca.pem")
transport = RetryTransport(transport=httpx.HTTPTransport(verify=ctx),
                           retry=Retry(total=5))
client = httpx.Client(transport=transport)           # mTLS + retries
resp = client.get("https://mtls.example.com/")
```

```python
# ❌ DOES NOT mount the cert — the custom transport makes httpx ignore verify=,
#    so no client certificate is presented and the handshake fails.
from httpx_pki import PKIClient
from httpx_retries import RetryTransport

client = PKIClient("client.p12", password="secret",
                    transport=RetryTransport())       # cert silently dropped!
```

If you specifically want your `PKIClient` *subclass* (its methods, `base_url`,
`cert_info()`, ...) **and** retries, give that subclass the same inner transport.
Its own `verify=` is ignored (the transport wins), but the rest of its behavior
is preserved:

```python
ctx = build_ssl_context("client.p12", password="secret")
inner = httpx.HTTPTransport(verify=ctx)
client = PKIClient("client.p12", password="secret",
                    transport=RetryTransport(transport=inner, retry=Retry(total=5)))
```

The same rule applies to any custom-transport library and to hand-built
`mounts=` — put the TLS config on the transport, not on the client.

### Mismatched key / cert

When you build from a separate key and certificate (`from_key_pair` or a PEM
bundle), `httpx-pki` checks that the private key actually matches the certificate
and raises `CertificateLoadError` up front, instead of letting it surface later as
an opaque OpenSSL handshake error.

### Testing helpers

`httpx_pki.testing` mints throwaway certificates so your own test suites don't
have to re-derive the `cryptography` boilerplate:

```python
from httpx_pki import PKIClient
from httpx_pki.testing import make_ca, make_client_cert

ca = make_ca()
bundle = make_client_cert("svc-client", ca=ca, dns_names=["svc.internal"])

with PKIClient(bundle.pkcs12(), password=b"") as client:
  assert client.cn == "svc-client"

expired = make_client_cert("old", ca=ca, expired=True)  # for expiry tests
```

## ⚠️ Security note on pickling

To support pickling, the session stores its certificate material and
reconstructs the live SSL context on unpickle. **The pickle therefore contains
the decrypted private key in cleartext.** Treat a pickled session as a secret:
do not write it to untrusted storage or transmit it over untrusted channels. The
password itself is never retained, and `repr()` never reveals key material.

A custom `ssl.SSLContext` passed as `verify=` cannot be pickled; an unpickled
session falls back to default server verification (with a warning).

## How it works

Python's stdlib `ssl` cannot load PKCS#12 or in-memory key material — only cert
chains from file paths. So `httpx-pki` uses
[`cryptography`](https://cryptography.io/) to extract the key and certificates,
writes them to a `0600` temporary PEM file just long enough for OpenSSL to read,
deletes it, and passes the resulting `ssl.SSLContext` to httpx via `verify=` (the
recommended path since httpx 0.28).

## License

MIT
