# The Windows certificate store

On Windows, the certificate you need is often already in the user's personal
store — enrolled by Active Directory, pushed by group policy, or imported by
hand — with no file to point at. `from_windows_cert_store` pulls it out
directly:

```python
from httpx_pki import PKIClient

with PKIClient.from_windows_cert_store(name="ACME Client") as client:
    client.get("https://mtls.example.com/")
```

`name` is a case-insensitive substring of either the subject common name or the
Windows "friendly name", so you rarely need the exact string.

:::{important}
**Windows only.** Calling this anywhere else raises `UnsupportedPlatformError`:

```text
UnsupportedPlatformError: the Windows certificate store is only available on Windows
```

`AsyncPKIClient.from_windows_cert_store(...)` is the async equivalent.
:::

## The certificate must be exportable

httpx-pki needs the private key, so the certificate has to have been imported
with its key marked **exportable**. If it was not, the export fails with
`CertificateLoadError`.

No password is involved: the certificate is exported under a random,
single-use password that never leaves the library.

## Looking before you select

`list_windows_certificates()` returns a `WinCert` per certificate — metadata
only, with no key exported:

```python
from httpx_pki import list_windows_certificates

for c in list_windows_certificates():
    print(c.friendly_name, c.subject_cn, c.thumbprint, sorted(c.key_usage))
```

| Attribute | |
| --- | --- |
| `subject_cn` | Subject common name |
| `friendly_name` | The Windows friendly name |
| `thumbprint` | SHA-1 thumbprint, uppercase hex |
| `certificate` | The parsed `x509.Certificate` |
| `info` | Its {py:class}`~httpx_pki.CertInfo` |
| `key_usage` / `extended_key_usage` | Convenience accessors onto `info` |

Because each record carries the parsed certificate, a predicate can select on
anything a certificate holds. See [](inspecting-a-certificate.md) for what
`CertInfo` exposes.

## Selecting

If more than one certificate matches, you get an `AmbiguousCertificateError`
listing the candidates with their usages, expiry, and thumbprints:

```text
name='ACME' matched 2 certificates:
  ACME Client key_usage=digital_signature expires=2027-08-02 AA11BB
  ACME Client key_usage=key_encipherment expires=2027-08-02 CC22DD
Narrow it with a more specific name, a key usage, or an exact thumbprint.
```

Narrow it with any combination of selectors:

```python
# By exact thumbprint — colons and case are ignored
PKIClient.from_windows_cert_store(thumbprint="A1:B2:C3:...")

# By key usage — the usual discriminator for a dual key pair
PKIClient.from_windows_cert_store(name="ACME", key_usage="digital_signature")

# By extended key usage
PKIClient.from_windows_cert_store(name="ACME", extended_key_usage="client_auth")

# By any predicate over the WinCert
PKIClient.from_windows_cert_store(identity=lambda c: c.friendly_name == "prod")

# By identity — the portable spelling: a name substring, an exact
# fingerprint, or a predicate, exactly as a PKCS#12 bundle accepts
PKIClient.from_windows_cert_store(identity="ACME")
```

`identity=` is the same keyword a bundle takes, so a selector written for a
`.p12` carries over to the store unchanged. The one form it does *not* accept
here is an integer position — a store has no stable ordering, so a position
would pick a different certificate from one run to the next:

```text
TypeError: identity= cannot be an integer for a platform certificate store:
a store has no stable ordering...
```

`name=` and `thumbprint=` remain the unambiguous spellings, for when you want
to force one interpretation rather than let a bare string be either.

:::{note}
**Every selector you pass must match.** They intersect rather than falling
back, so a thumbprint from one certificate combined with a name from another
matches nothing:

```text
CertificateNotFoundError: thumbprint='AA11BB' + name='Encryption' matched no
certificate in the store, which holds: ...
```
:::

### Dual key pairs

AD key archival provisions both halves of a dual key pair into the store under
one subject, so `name=` alone will not separate them — the key usage is what
does:

```python
PKIClient.from_windows_cert_store(name="ACME", key_usage="digital_signature")
```

For mTLS you want the signing half; the background is in
[](choosing-a-certificate.md#why-one-file-holds-two-certificates).

### Skipping the expired copy

A store tends to keep the old certificate after a renewal. The ready-made
`currently_valid` selector filters those out:

```python
from httpx_pki import currently_valid

PKIClient.from_windows_cert_store(name="ACME", identity=currently_valid)
```

Where two remain valid during a renewal overlap, it resolves to the later
window.

## Choosing the store

Both arguments default to the user's personal store:

```python
PKIClient.from_windows_cert_store(name="ACME", store="MY", location="CurrentUser")
```

- `store` — `"MY"` (personal), `"CA"`, `"ROOT"`, or any store name
- `location` — `"CurrentUser"` or `"LocalMachine"`

`list_windows_certificates(store=..., location=...)` takes the same two.

## Reloading

There is no file to watch, so `auto_reload` is not offered here. `reload()`
still works and re-exports from the store on demand, which picks up a
certificate that has been renewed in place:

```python
client.reload()
```

No password is involved, so `reload()` takes none. Passing one raises rather
than being silently ignored, since the export uses an internal single-use
password:

```text
TypeError: reload(password=...) does not apply to a client built from the
Windows certificate store: the certificate is exported under an internally
generated single-use password, so there is none to supply. Drop the argument.
```

See [](expiry-and-rotation.md).

## Just the SSL context

`build_windows_ssl_context()` takes the same selectors and returns the
{py:class}`ssl.SSLContext` alone, for mounting on a transport or a routing
layer:

```python
from httpx_pki import build_windows_ssl_context

ctx = build_windows_ssl_context(name="ACME", key_usage="digital_signature")
```

See [](advanced.md).

## Next steps

- [](macos-keychain.md) — the same idea on macOS
- [](inspecting-a-certificate.md) — what the selected certificate says about
  itself
- [](server-trust.md) — verifying the server you are connecting to
