# Loading certificates

Client certificates arrive in whatever shape your PKI team, cloud provider, or
corporate CA happened to produce. This page covers every file-based form
httpx-pki accepts. The two OS certificate stores have their own pages
([Windows](windows-store.md), [macOS](macos-keychain.md)), as does
[configuration from the environment](environment.md).

:::{important}
Whatever the shape, mTLS needs **a certificate and the private key that matches
it** — the certificate states who you are, the key proves you are entitled to
it, and the handshake uses both. Some of the formats below carry only
certificates: a `.crt` or `.cer` is a single certificate, and a PKCS#7 `.p7b`
cannot hold a key at all. If yours has no key in it, see
[](../troubleshooting.md#do-you-have-both-halves).
:::

## The extension does not matter

Certificate files come with a lot of names — `.p12`, `.pfx`, `.pem`, `.crt`,
`.cer`, `.key`, `.tls`, `.ukey` — but an extension is just a label somebody
chose. What matters is the **encoding of the bytes**, and httpx-pki reads that
from the content:

```python
PKIClient("whatever-they-sent-me.tls")     # works if the bytes are PKCS#12 or PEM
```

So you can generally point `PKIClient` at the file you were handed without
first working out what it is. Use the explicit constructors below when you
would rather force one interpretation than rely on detection.

| Input | Constructor |
| --- | --- |
| **PKCS#12** — `.p12`, `.pfx`, binary | `PKIClient(...)` or `from_pkcs12(...)` |
| **PEM bundle** — key + cert(s) in one file | `PKIClient(...)` or `from_pem(...)` |
| **Separate cert + key** — PEM or DER | `from_key_pair(...)` |
| **PKCS#7** — `.p7b`, `.p7c`, certs only | `certificate=` or `chain=` on `from_key_pair(...)` |

Every source below accepts a `str` path, a {py:class}`pathlib.Path`, or raw
`bytes`.

## PKCS#12 bundles

The usual enterprise hand-off: private key, leaf certificate, and chain in one
password-protected blob.

```python
from pathlib import Path
from httpx_pki import PKIClient

PKIClient("client.p12", password="secret")
PKIClient(Path("client.pfx"), password="secret")
PKIClient(p12_bytes, password=b"secret")      # the password may be bytes too
PKIClient("client.p12")                       # no password on the bundle

PKIClient.from_pkcs12("client.p12", "secret") # explicit; password is positional
```

Any chain certificates inside the bundle are presented to the server
automatically. A bundle exported *without* them — a common shape, since
Windows only includes the chain when "include all certificates in the
certification path" is ticked — can be completed with `chain=`:

```python
PKIClient("client.p12", password="secret", chain="intermediate.crt")
```

## PEM bundles

A single file holding the private key and its certificate — and possibly
intermediates — as consecutive PEM blocks.

```python
PKIClient("client.pem")                        # auto-detected
PKIClient.from_pem("client.pem")               # explicit
PKIClient.from_pem(pem_bytes, password="pw")   # if the key block is encrypted
```

Block order does not matter, and the key may be any of the usual encodings:

- **PKCS#8** — `-----BEGIN PRIVATE KEY-----`
- **PKCS#1** — `-----BEGIN RSA PRIVATE KEY-----`
- **Encrypted PKCS#8** — `-----BEGIN ENCRYPTED PRIVATE KEY-----`, with `password=`
- **EC keys**, alongside RSA

## A separate certificate and key

Two files, the shape most non-Windows tooling produces:

```python
client = PKIClient.from_key_pair(
    certificate="client.crt",
    private_key="client.key",
    password="secret",          # only if the key is encrypted
    chain="intermediate.crt",   # optional intermediates to present
)
```

Both files may be **PEM or DER** — again detected from the bytes, so a DER
certificate with a `.crt` name and a DER key with a `.key` name work as-is.

### When the certificate file is itself a bundle

If `certificate` holds several certificates — a leaf plus intermediates — the
leaf is identified by **matching it against the private key**, in any block
order. The remaining certificates become the chain automatically:

```python
# fullchain.pem contains the CA first, then the leaf. Still correct.
PKIClient.from_key_pair("fullchain.pem", "client.key")
```

### Intermediates

`chain` takes a single source, or a list:

```python
chain="intermediates.pem"                     # one file, may concatenate several
chain=["intermediate.crt", "root.crt"]        # a list of sources
chain=b"-----BEGIN CERTIFICATE-----\n..."     # raw bytes
```

It is accepted by **every** constructor — `PKIClient(...)`, `from_pkcs12`,
`from_pem`, `from_key_pair` — and by `build_ssl_context`, so a source of any
kind that arrives without its intermediates can be completed the same way.
`auto_reload` watches the chain files alongside the certificate, and `reload()`
re-reads them.

:::{tip}
Certificates passed as `chain=` that are not actually between your certificate
and its issuer are reported at construction, rather than becoming a handshake
error the server explains badly:

```text
TLSConfigWarning: 1 of 2 presented certificates ('Unrelated Root') are not on
this certificate's chain. They are sent for nothing, and a strict server may
reject the chain. Remove them from chain=.
```
:::

## PKCS#7 bundles

`.p7b` / `.p7c` files hold certificates but **no private key**, which is the
format Windows CAs commonly export chains in. They work anywhere a certificate
source is accepted — DER or PEM — and pair with a separate key:

```python
# The .p7b holds the leaf and its intermediates; the key comes separately
PKIClient.from_key_pair("issued.p7b", "client.key")

# Or as the chain alongside a normal leaf certificate
PKIClient.from_key_pair("client.crt", "client.key", chain="chain.p7b")
```

A certs-only PKCS#7 is also valid as a `verify=` CA bundle — see
[](server-trust.md).

## When a source holds several identities

A PKCS#12 or PEM bundle can hold more than one key-and-certificate pair — a
dual key pair from AD key archival, or a renewed certificate kept alongside the
one it replaces. httpx-pki will not guess which one you meant:

```text
AmbiguousCertificateError: this PKCS#12 data holds 2 identities:
  [0] dual (dual) key_usage=digital_signature expires=...
  [1] dual (dual) key_usage=key_encipherment expires=...
```

`from_pkcs12` and `from_pem` both take `identity=`, `key_usage=`, and
`extended_key_usage=` to resolve it. That is its own topic:
[](choosing-a-certificate.md).

## When the key and certificate do not match

Pairing the wrong two files is a common and confusing mistake, so httpx-pki
checks at load time rather than letting it surface as an opaque handshake
failure:

```text
CertificateLoadError: private key does not match certificate
(their public keys differ)
```

An encrypted key with the wrong password — or none — fails the same way:

```text
CertificateLoadError: could not parse private key (wrong password?)
```

## Next steps

- [](choosing-a-certificate.md) — picking one identity out of several
- [](server-trust.md) — how the server gets verified
- [](expiry-and-rotation.md) — reloading these sources as they rotate
