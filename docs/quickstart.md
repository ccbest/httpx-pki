# Quickstart

Already [installed](install.md)? This page gets you from a certificate file to
an authenticated request.

## Your first request

`PKIClient` is an httpx client that presents a client certificate. Point it at
a PKCS#12 bundle and use it exactly like `httpx.Client`:

```python
from httpx_pki import PKIClient

with PKIClient("client.p12", password="secret") as client:
    resp = client.get("https://mtls.example.com/")
    print(resp.status_code)
```

There is no `ssl.SSLContext` to build and no key file left behind — the private
key is decrypted into memory and mounted on the connection, never written
anywhere that outlives the load. See [](about/how-it-works.md#staging-the-key-never-touches-disk-on-linux)
for what that means on each platform.

## Whatever you were handed, there is a one-liner for it

Client certificates arrive in a lot of shapes. httpx-pki takes all of them:

```python
from pathlib import Path
from httpx_pki import PKIClient

# PKCS#12 bundle — key + cert + chain in one blob
PKIClient("client.p12", password="secret")
PKIClient(Path("client.pfx"), password="secret")

# PEM bundle — key + cert(s) in one file, any block order
PKIClient("client.pem")

# Raw bytes you already have in hand (the password may be bytes too)
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

That last one is how you keep the source out of your code altogether — set
`HTTPX_PKI_CERT` (and friends) in the environment and the same image runs
anywhere. See [](guide/environment.md).

Note what is *not* in that list: any step where you tell httpx-pki which format
you have. Certificate files come with all sorts of extensions — `.p12`, `.pfx`,
`.pem`, `.crt`, `.tls`, `.ukey` — but an extension is just a name. httpx-pki
detects the encoding from the **bytes**, so pointing `PKIClient` at whatever
your PKI team sent you generally just works.

Use the explicit `from_pkcs12` / `from_pem` constructors when you would rather
force one interpretation than rely on detection.

:::{tip}
If a source holds more than one identity — a dual key pair, or a renewed
certificate kept alongside the one it replaced — httpx-pki refuses to guess and
raises `AmbiguousCertificateError`. See [](guide/choosing-a-certificate.md) for
how to pick one.
:::

Every form above is covered in full in [](guide/loading-certificates.md).

## Async

`AsyncPKIClient` is the `httpx.AsyncClient` equivalent, and takes every
constructor and option the synchronous class does:

```python
from httpx_pki import AsyncPKIClient

async with AsyncPKIClient("client.p12", password="secret") as client:
    resp = await client.get("https://mtls.example.com/")
```

## Passing httpx options

Any keyword argument httpx-pki does not consume flows straight through to the
underlying httpx client:

```python
PKIClient(
    "client.p12",
    password="secret",
    base_url="https://api.example.com",
    headers={"User-Agent": "me"},
    timeout=10.0,
)
```

:::{note}
`http2=True` works too, but — as with plain httpx — it needs the `h2` package:
`pip install h2`.
:::

## Verifying the server

The certificate above is what *you* present. `verify` controls how the
**server** is checked, and the two are independent.

The default, `verify=True`, is your operating system's trust store: Windows
CryptoAPI, the macOS Security framework, or OpenSSL's system CA paths on Linux.
Certificates issued by a corporate CA that is distributed through the OS
therefore verify with no extra configuration.

When the private CA is *not* in the OS store — the common case for an internal
service whose CA came to you as a file — point `verify` at it:

```python
# Any PEM CA bundle, or a certs-only PKCS#7 (.p7b)
PKIClient("client.p12", password="secret", verify="/etc/pki/internal-ca.pem")
```

To pin the certifi bundle instead:

```python
PKIClient("client.p12", password="secret", verify="certifi")
```

Custom SSL contexts and turning verification off are covered in
[](guide/server-trust.md).

## Next steps

- [](guide/loading-certificates.md) — every source format in full
- [](guide/choosing-a-certificate.md) — picking one when a source holds several
- [](guide/expiry-and-rotation.md) — hot reload and expiry warnings for
  long-lived clients
- [](guide/testing.md) — throwaway certificates for your test suite
- [](troubleshooting.md) — when the load fails, or the handshake does
