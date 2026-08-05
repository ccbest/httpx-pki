# The macOS keychain

The macOS sibling of [](windows-store.md): pull an **exportable** identity —
certificate plus private key — out of the default keychain search list, with no
file to point at.

```python
from httpx_pki import PKIClient

with PKIClient.from_macos_keychain(name="ACME Client") as client:
    client.get("https://mtls.example.com/")
```

`name` is a case-insensitive substring of either the subject common name or the
keychain label.

:::{important}
**macOS only.** Calling this anywhere else raises `UnsupportedPlatformError`:

```text
UnsupportedPlatformError: the macOS keychain is only available on macOS
```

`AsyncPKIClient.from_macos_keychain(...)` is the async equivalent.
:::

## Export requires consent

The private key must be exportable, and **the keychain may prompt for user
consent** when httpx-pki exports it. That matters most where nobody is there to
click:

:::{warning}
A headless session — CI, a launch daemon, a container — cannot grant consent,
so the export blocks or fails. For unattended use, grant access up front:

```console
$ security import client.p12 -k login.keychain -A
```

The `-A` flag allows access by any application. Alternatively, click **Always
Allow** once in the consent dialog on an interactive session, which persists
the grant for that application.
:::

No password is involved: the identity is exported under a random, single-use
password that never leaves the library.

## Looking before you select

`list_macos_certificates()` returns a `MacCert` per identity — metadata only,
with no key exported:

```python
from httpx_pki import list_macos_certificates

for c in list_macos_certificates():
    print(c.label, c.subject_cn, c.thumbprint, sorted(c.key_usage))
```

| Attribute | |
| --- | --- |
| `subject_cn` | Subject common name |
| `label` | The keychain label |
| `thumbprint` | SHA-1 thumbprint, uppercase hex |
| `certificate` | The parsed `x509.Certificate` |
| `info` | Its {py:class}`~httpx_pki.CertInfo` |
| `key_usage` / `extended_key_usage` | Convenience accessors onto `info` |

It takes no arguments — the default keychain search list is what gets searched,
which is the macOS equivalent of the Windows store/location pair.

## Selecting

Selection works exactly as it does on Windows. More than one match gives an
`AmbiguousCertificateError` naming the candidates:

```text
name='ACME' matched 2 certificates:
  ACME Client key_usage=digital_signature expires=2027-08-02 AA11BB
  ACME Client key_usage=key_encipherment expires=2027-08-02 CC22DD
Narrow it with a more specific name, a key usage, or an exact thumbprint.
```

Narrow it with any combination:

```python
# By exact thumbprint — colons and case are ignored
PKIClient.from_macos_keychain(thumbprint="A1:B2:C3:...")

# By key usage — both halves of a dual key pair in one keychain
PKIClient.from_macos_keychain(name="ACME", key_usage="digital_signature")

# By extended key usage
PKIClient.from_macos_keychain(name="ACME", extended_key_usage="email_protection")

# By any predicate over the MacCert
PKIClient.from_macos_keychain(identity=lambda c: c.label == "prod")

# By identity — the portable spelling: a name substring, an exact
# fingerprint, or a predicate, exactly as a PKCS#12 bundle accepts
PKIClient.from_macos_keychain(identity="ACME")
```

`identity=` is the same keyword a bundle and the Windows store take. As there,
an integer position is rejected — a keychain has no stable ordering — and
`name=` / `thumbprint=` remain the unambiguous spellings.

:::{note}
**Every selector you pass must match** — they intersect rather than falling
back, so a thumbprint from one identity combined with a name from another
matches nothing.
:::

:::{warning}
**A predicate does not port between the two stores unchanged.** Each record
exposes the platform's own name for its human-readable label — `WinCert` has
`friendly_name` (the Windows friendly name, also what PKCS#12 calls it),
`MacCert` has `label` (the keychain's `kSecAttrLabel`):

```python
identity=lambda c: c.friendly_name == "prod"   # Windows
identity=lambda c: c.label == "prod"           # macOS — same idea, other name
```

Everything else is shared: `subject_cn`, `thumbprint`, `info`, `key_usage`,
and `extended_key_usage` are spelled the same on both, so a predicate over any
of those *is* portable — as is `name=`, which matches against the label or the
common name on either platform.
:::

For mTLS you want the signing half of a dual key pair; the background is in
[](choosing-a-certificate.md#why-one-file-holds-two-certificates).

### Skipping the expired copy

A keychain tends to keep the old identity after a renewal. The ready-made
`currently_valid` selector filters those out:

```python
from httpx_pki import currently_valid

PKIClient.from_macos_keychain(name="ACME", identity=currently_valid)
```

## Reloading

There is no file to watch, so `auto_reload` is not offered here. `reload()`
re-exports from the keychain with the same selector:

```python
client.reload()
```

No password is involved, so `reload()` takes none. Passing one raises rather
than being silently ignored, since the export uses an internal single-use
password:

```text
TypeError: reload(password=...) does not apply to a client built from the
macOS keychain: the certificate is exported under an internally generated
single-use password, so there is none to supply. Drop the argument.
```

Note that a re-export can prompt for consent again unless access was
pre-granted — see [](#export-requires-consent). See also
[](expiry-and-rotation.md).

## Just the SSL context

`build_macos_ssl_context()` takes the same selectors and returns the
{py:class}`ssl.SSLContext` alone, mirroring `build_windows_ssl_context`:

```python
from httpx_pki import build_macos_ssl_context

ctx = build_macos_ssl_context(name="ACME", key_usage="digital_signature")
```

See [](advanced.md).

## Next steps

- [](windows-store.md) — the same idea on Windows
- [](inspecting-a-certificate.md) — what the selected certificate says about
  itself
- [](server-trust.md) — verifying the server you are connecting to
