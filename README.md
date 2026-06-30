# httpx-pki

PKCS#12 client-certificate (mTLS) sessions for [httpx](https://www.python-httpx.org/).

`httpx-pki` gives you an `httpx.Client` (and `httpx.AsyncClient`) subclass with a
client certificate already mounted, so mutual-TLS endpoints "just work":

```python
from httpx_pki import PKCSession

with PKCSession("client.p12", password="secret") as client:
    resp = client.get("https://mtls.example.com/")
    print(resp.status_code)
```

Unlike helper-function approaches, the session is a real, **subclassable** class:
it works as a context manager, and it is **picklable** so you can hand a
preconfigured session across process boundaries.

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
| **PKCS#12** (`.p12`, `.pfx`, binary) | `PKCSession(...)` or `from_pkcs12(...)` | key + cert + chain in one password-protected blob |
| **PEM bundle** (key + cert(s) in one file) | `PKCSession(...)` or `from_pem(...)` | any block order; PKCS#1/PKCS#8/EC/encrypted keys |
| **Separate cert + key** (PEM *or* DER) | `from_key_pair(...)` | optional `ca=` chain |
| **Windows cert store** | `from_windows_cert_store(...)` | Windows only; see below |

`PKCSession(source, password=...)` auto-detects PKCS#12 vs PEM, so you can point
it at whatever you were handed. Use the explicit `from_pkcs12` / `from_pem`
constructors when you want to force one interpretation.

## Usage

### From a PKCS#12 bundle (`.p12` / `.pfx`)

A path (`str` or `pathlib.Path`) or raw `bytes` both work:

```python
from pathlib import Path
from httpx_pki import PKCSession

PKCSession("client.p12", password="secret")          # path
PKCSession(Path("client.pfx"), password="secret")     # pathlib.Path
PKCSession(p12_bytes, password=b"secret")             # bytes; password may be bytes
```

### From a PEM file (key + cert in one blob)

```python
from httpx_pki import PKCSession

PKCSession("client.pem")                       # auto-detected
PKCSession.from_pem("client.pem")              # explicit
PKCSession.from_pem(pem_bytes, password="..")  # if the key block is encrypted
```

### From a separate certificate and key

```python
from httpx_pki import PKCSession

client = PKCSession.from_key_pair(
    certificate="client.crt",
    private_key="client.key",
    key_password="secret",      # if the key is encrypted
    ca="intermediate.crt",      # optional: one path/bytes or a list
)
```

### From the Windows certificate store (Windows only)

Pull an **exportable** client certificate (key included) straight out of the
user's personal store, selecting by a case-insensitive substring of the subject
common name or the Windows "friendly name":

```python
from httpx_pki import PKCSession

with PKCSession.from_windows_cert_store(name="ACME Client") as client:
    client.get("https://mtls.example.com/")
```

If several certificates match you'll get an `AmbiguousCertificateError` listing
the candidates; narrow it with an exact thumbprint or a predicate:

```python
PKCSession.from_windows_cert_store(thumbprint="A1:B2:C3:...")
PKCSession.from_windows_cert_store(predicate=lambda c: c.friendly_name == "prod")
PKCSession.from_windows_cert_store(name="ACME", location="LocalMachine")
```

Notes:

- **Windows only** — calling it elsewhere raises `UnsupportedPlatformError`. The
  implementation uses stdlib `ctypes` against `crypt32.dll`, lazily; it adds no
  dependency and no import cost on Linux/macOS.
- The certificate's private key must have been imported as **exportable** —
  otherwise the export fails with a `CertificateLoadError`.
- No password is involved: the cert is exported under a random, single-use
  password that never leaves the library.
- `AsyncPKCSession.from_windows_cert_store(...)` is the async equivalent.

### Async

```python
from httpx_pki import AsyncPKCSession

async with AsyncPKCSession("client.p12", password="secret") as client:
    resp = await client.get("https://mtls.example.com/")
```

### Passing httpx options

Any extra keyword arguments flow straight through to the underlying httpx client:

```python
PKCSession("client.p12", base_url="https://api.example.com",
           headers={"User-Agent": "me"}, timeout=10.0, http2=True)
```

### Server trust (`verify`)

Mounting *your* client certificate and verifying the *server's* certificate are
independent. `verify` behaves just like httpx — `True` (default, uses certifi),
`False` to disable (with a warning), a path to a CA bundle, or a ready-made
`ssl.SSLContext`:

```python
PKCSession("client.p12", verify="/etc/ssl/custom-ca.pem")
```

### Subclassing

```python
class MyServiceSession(PKCSession):
    def __init__(self, p12, **kwargs):
        super().__init__(p12, base_url="https://service.internal", **kwargs)

    def health(self):
        return self.get("/health").json()
```

### Inspecting the certificate

```python
info = client.cert_info()
print(info.common_name, info.not_after, info.subject_alt_names)
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
