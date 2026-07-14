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

Requires Python 3.10+, `httpx>=0.28`, and `cryptography>=44`. To verify servers
against the OS trust store (`verify="system"`, for corporate/private CAs),
install the extra: `pip install httpx-pki[system]`.

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
| **macOS keychain** | `from_macos_keychain(...)` | macOS only; see below |

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

If `certificate` is itself a bundle (leaf plus intermediates in one PEM file),
the leaf is identified by matching the private key — in any block order — and
the other certificates are presented as chain automatically.

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

### From the macOS keychain (macOS only)

The macOS sibling of the Windows store: pull an **exportable** identity
(certificate + private key) out of the default keychain search list, selecting
by a case-insensitive substring of the subject common name or the keychain
label:

```python
from httpx_pki import PKIClient

with PKIClient.from_macos_keychain(name="ACME Client") as client:
    client.get("https://mtls.example.com/")
```

Selection works exactly like the Windows store — `AmbiguousCertificateError`
lists the candidates; narrow with an exact thumbprint or a predicate:

```python
PKIClient.from_macos_keychain(thumbprint="A1:B2:C3:...")
PKIClient.from_macos_keychain(predicate=lambda c: c.label == "prod")
```

`list_macos_certificates()` returns a `MacCert` (subject CN, keychain label,
SHA-1 thumbprint) per identity — metadata only, no key is exported — and
`build_macos_ssl_context(...)` is the session-less seam, mirroring
`build_windows_ssl_context`.

Notes:

- **macOS only** — calling it elsewhere raises `UnsupportedPlatformError`.
- The private key must be exportable, and the keychain may require **user
  consent** for the export. A headless session cannot grant consent — for
  unattended use, import the certificate with access pre-granted
  (`security import client.p12 -k login.keychain -A`) or click "Always Allow"
  once in the consent dialog.
- No password is involved: the identity is exported under a random,
  single-use password that never leaves the library.
- `reload()` re-exports from the keychain with the same selector; there is no
  file to watch, so `auto_reload` is not available.
- `AsyncPKIClient.from_macos_keychain(...)` is the async equivalent.

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
| `HTTPX_PKI_CHAIN` | intermediates to present, in addition to any carried by `CERT` |
| `HTTPX_PKI_CA` | CA bundle for **server** trust (`verify=`), or the literal `system` for the OS trust store |

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
`ssl.SSLContext` — plus one httpx-pki extra: the literal `"system"` for the
operating-system trust store:

```python
PKIClient("client.p12", verify="/etc/ssl/custom-ca.pem")
```

#### Corporate / private CAs: `verify="system"`

If the server's certificate chains to a private CA distributed through your OS
(group policy, MDM, a TLS-inspecting proxy), certifi has never heard of it —
that's the classic `CERTIFICATE_VERIFY_FAILED: unable to get local issuer
certificate` right after your client certificate loaded fine. `verify="system"`
verifies the server against the **operating-system trust store** instead
(Windows CryptoAPI / macOS Security framework / OpenSSL's system CA paths on
Linux), via the same [truststore](https://truststore.readthedocs.io/) machinery
pip uses by default:

```bash
pip install httpx-pki[system]
```

```python
PKIClient("client.p12", password="secret", verify="system")
```

Works with every constructor and `build_ssl_context`; `HTTPX_PKI_CA=system`
selects it for `from_env`. Unlike a custom `ssl.SSLContext`, it survives
pickling. It is never chosen implicitly — `verify=True` always means certifi,
exactly like httpx, even when truststore is installed. (A CA-bundle *file*
literally named `system` can still be passed as `Path("system")`.)

> **Passing your own `ssl.SSLContext`?** `httpx-pki` loads the client certificate
> into that exact object (it can't be copied), so don't reuse a shared context
> across clients — each load would overwrite the previous cert. You'll get a
> warning. Pass `verify=True` or a CA-bundle path to let `httpx-pki` build a
> dedicated context instead.

Like httpx, contexts built by `httpx-pki` honor the `SSLKEYLOGFILE` environment
variable, logging TLS session keys to that file so a capture tool (e.g.
Wireshark) can decrypt the handshake — invaluable when debugging mTLS failures.
A context you pass in yourself is left untouched.

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
print(info.dns_names)             # just the dNSName SANs, for hostname checks
print(info.issuer_common_name)    # who signed it (issuer_distinguished_name for the full DN)
print(info.serial_number_hex)     # audit logging (serial_number for the raw int)
print(info.fingerprint_sha256)    # uppercase hex, no separators
```

`subject_alt_names` lists every SAN entry as a string (DNS names, IP addresses,
email addresses, URIs); `dns_names` is the dNSName subset.

`fingerprint_sha1` is also available, in the same format the platform stores
use for thumbprints — so it can be compared against
`list_windows_certificates()` / `list_macos_certificates()` output or passed
straight to a `thumbprint=` selector.

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

Pass `warn_if_expires_within=` (accepted by every constructor, `from_*`
included) to be told about a cert that's about to roll over, and call
`check_validity()` to turn "not currently usable" into a hard error:

```python
from datetime import timedelta
from httpx_pki import PKIClient, CertificateExpiredError

client = PKIClient("client.p12", password="secret",
                    warn_if_expires_within=timedelta(days=14))

client.check_validity()                       # raises if expired / not yet valid
client.check_validity(within=timedelta(days=7))  # also raises if it expires soon
```

(`check_validity` raises `CertificateExpiredError` or `CertificateNotYetValidError`.)

### Filtering warnings

Every warning `httpx-pki` emits carries a filterable category, all subclasses of
`PKIWarning` (itself a `UserWarning`): `CertificateValidityWarning` (expired /
not yet valid / expiring soon), `TLSConfigWarning` (a TLS configuration that
likely doesn't do what was intended, e.g. a custom transport that drops the
client cert, or `verify=False`), and `PicklingWarning` (configuration dropped
during pickling). Silence one concern without hiding the others:

```python
import warnings
from httpx_pki import CertificateValidityWarning

warnings.filterwarnings("ignore", category=CertificateValidityWarning)
```

### Certificate rotation (hot reload)

Client certificates keep getting shorter-lived — cert-manager renews a mounted
Secret at two-thirds of its lifetime, Vault PKI issues certs measured in hours —
but a session snapshots its certificate at construction. Without rotation
support, a long-running process presents the stale cert until handshakes start
failing, and the only fix is a restart.

`reload()` re-reads the certificate source (file, `from_env` variables, or the
Windows store) and swaps the fresh certificate into the mounted SSL context
**in place**, so new handshakes — on every transport sharing the context —
present it immediately:

```python
client = PKIClient("/etc/certs/client.pem")
# ... /etc/certs/client.pem is rotated by cert-manager ...
client.reload()
```

Or let the session watch for you — `auto_reload` stats the source files before
a request (throttled, default at most once per second) and reloads when they
change:

```python
from datetime import timedelta

client = PKIClient("/etc/certs/client.pem", auto_reload=True)
client = PKIClient("/etc/certs/client.pem", auto_reload=timedelta(seconds=30))
```

`strict_validity=True` completes the picture: every request is preceded by
`check_validity()`, so a certificate that expired anyway fails with a clear
`CertificateExpiredError` *before* the connection is attempted, instead of an
opaque OpenSSL handshake error.

Semantics worth knowing:

- The swap is atomic: if the rotated file is unreadable or garbage, `reload()`
  raises `CertificateLoadError` and the previous certificate keeps serving.
  With `auto_reload` the error surfaces on the triggering request and is
  retried on the next one.
- Connections already established keep the certificate they handshook with
  until they close (TLS has no mid-connection re-authentication); only new
  connections present the rotated cert.
- Rotation tooling should replace files atomically (write-then-rename), which
  kubelet and cert-manager already do.
- `auto_reload` requires a filesystem source to watch — construction from
  in-memory bytes or the Windows store raises `TypeError` (the store can still
  be re-exported with a manual `reload()`).
- If the source is password-protected, enabling `auto_reload` retains the
  password on the session so unattended reloads can decrypt it (see the
  security note below). Without `auto_reload` no password is retained; pass
  one explicitly to a manual reload: `client.reload(password="secret")`.

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

Minted certificates carry the extensions a real CA would issue — a
`digitalSignature`/`keyEncipherment` KeyUsage and a `clientAuth` ExtendedKeyUsage —
so servers that enforce EKU accept them.

## ⚠️ Security note on pickling

To support pickling, the session stores its certificate material and
reconstructs the live SSL context on unpickle. **The pickle therefore contains
the decrypted private key in cleartext.** Treat a pickled session as a secret:
do not write it to untrusted storage or transmit it over untrusted channels.
`repr()` never reveals key material.

The source password is never retained — with one exception: enabling
`auto_reload` keeps it on the session (and in its pickles, which already carry
the decrypted key) so unattended reloads can decrypt the rotated source.

A custom `ssl.SSLContext` passed as `verify=` cannot be pickled; an unpickled
session falls back to default server verification (with a warning). A
certificate source that cannot be pickled (e.g. a Windows-store `predicate`
lambda) is dropped with a warning — the unpickled session works but cannot
`reload()`.

## How it works

Python's stdlib `ssl` cannot load PKCS#12 or in-memory key material — only cert
chains from file paths. So `httpx-pki` uses
[`cryptography`](https://cryptography.io/) to extract the key and certificates,
stages them somewhere OpenSSL can read, and passes the resulting
`ssl.SSLContext` to httpx via `verify=` (the recommended path since httpx 0.28).

**On Linux, the decrypted key never touches disk**: the material is staged in
an anonymous in-memory file (`memfd_create`) that OpenSSL reads via
`/proc/self/fd`, and that ceases to exist the moment it's closed — nothing to
unlink, nothing for a crash to leave behind, nothing for a temp-directory
sweeper to catch. This matters most with `auto_reload`, where the key is
re-staged on every certificate rotation. On other platforms — or in a rare
Linux sandbox where memfd or procfs is unavailable — the material lands in a
`0600` temporary PEM file just long enough for OpenSSL to read it, then is
deleted.

## License

MIT
