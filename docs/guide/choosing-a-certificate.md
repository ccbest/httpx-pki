# Choosing the right certificate

A single PKCS#12 or PEM file often carries more than one private key and
certificate. httpx-pki calls each key-and-certificate pair an **identity**, and
when a source holds several it will not guess which one you meant:

```text
AmbiguousCertificateError: this PKCS#12 data holds 2 identities:
  [0] corp-user (Signature) key_usage=digital_signature expires=2027-07-30 8F78A78195…
  [1] corp-user (Encryption) key_usage=key_encipherment expires=2027-07-30 6E88063681…
Pick one with identity= (index, name, or fingerprint), key_usage=, or extended_key_usage=.
```

This page is about resolving that.

## Why one file holds two certificates

Two identities for the same subject is routine wherever a CA archives the key
that *decrypts* data — so encrypted mail and files survive a lost laptop — but
never the key that *signs*, which would defeat non-repudiation. Entrust dual
key pairs, PIV/CAC, S/MIME key archival, and national eID schemes all work this
way. The two certificates usually differ only in their key usage:

| Half | Typical key usage |
| --- | --- |
| encryption | `key_encipherment` (RSA) or `key_agreement` (ECDH) |
| signing | `digital_signature`, and/or `content_commitment` — the bit most CAs still call *nonRepudiation* |

:::{important}
**For mTLS you almost always want the signing half.** TLS 1.3, and every ECDHE
suite before it, has the client sign the handshake; an encryption-only
certificate cannot complete one.
:::

Some schemes split three ways instead of two. A PIV card carries
authentication, signature, and key-management certificates, and the first two
*both* assert `digital_signature` — there the extended key usage
(`client_auth` versus `email_protection`) is what tells them apart.

The other common case is a **renewed certificate stored beside the one it
replaces**: two certificates over one key pair, which is what renewing rather
than rekeying produces. Only the validity window separates those — see
[](#picking-the-current-one).

## Why httpx-pki parses these itself

`cryptography` cannot express a multi-identity bundle.
`pkcs12.load_key_and_certificates()` returns the **first** private key, pairs
it with its certificate, and discards every other key — leaving the other
identities' certificates lumped in with the genuine CA chain:

```python
key, cert, additional = pkcs12.load_key_and_certificates(raw, b"secret")

cert         # corp-user / digital_signature  — whichever happened to be first
additional   # [corp-user / key_encipherment,  ← another identity's LEAF
             #  Acme Issuing CA]               ← a real chain certificate
```

Nothing in that return value distinguishes the two, and the second identity's
private key is simply gone. A client built naively from it presents another
leaf certificate as though it were a chain certificate, which a strict server
can reject — and gives you no way to select the identity you actually wanted.

So httpx-pki reads the key bags itself, pairs keys to certificates by public
key, and exposes each pair as an identity you can inspect and select.
`cryptography` still does the decryption and certificate parsing. A file whose
layout it cannot read that way falls back to `cryptography`'s single-identity
view.

## Look before you choose

`list_identities` shows what a file holds. It detects PKCS#12 versus PEM from
the content, exactly like the constructors, and never returns private keys:

```python
from httpx_pki import list_identities

for identity in list_identities("corp.p12", password="secret"):
    print(
        identity.index,
        identity.friendly_name,
        sorted(identity.info.key_usage),
        identity.info.extended_key_usage
    )
```

```text
0 Signature ['digital_signature'] ['client_auth']
1 Encryption ['key_encipherment'] ['email_protection']
```

Each entry is a {py:class}`~httpx_pki.P12Identity`, whose `info` is a
{py:class}`~httpx_pki.CertInfo` carrying the subject, validity window,
fingerprints, and usage bits. `list_pkcs12_identities` is the stricter sibling
for when only PKCS#12 should be accepted — it rejects PEM rather than falling
back to it.

(for-mtls)=
## Start here: `for_mtls`

Most of the time the question is not *which of these certificates do I want* —
it is *which one can I actually connect with*. `for_mtls` answers exactly that:

```python
from httpx_pki import PKIClient, for_mtls

PKIClient("corp.p12", password="secret", identity=for_mtls)
```

It selects the identity that is **valid right now** and **usable for client
authentication**, which between them cover the two situations the rest of this
page is about:

- a **dual key pair** — the signing half qualifies, the encryption half does
  not
- a **renewal pair** — the expired certificate is out, and during an overlap
  the later one wins

If you reach for one selector, reach for this one. The rest of the page is for
when you need something it cannot express — a specific certificate by name,
fingerprint, or position, or a rule of your own.

:::{note}
`for_mtls` is a filter, so it **raises**
{class}`~httpx_pki.CertificateNotFoundError` when nothing qualifies rather than
falling back to something unusable. The message lists what was there, including
each identity's extended key usage — which is usually what explains the miss.
:::

### What qualifies

| ExtendedKeyUsage | KeyUsage | Usable? |
| --- | --- | --- |
| includes `client_auth` | anything | **yes** |
| present, no `client_auth` | anything | no — the CA said what it is for |
| absent | includes `digital_signature`, or absent | **yes** |
| absent | present, no `digital_signature` | no — the key cannot sign the handshake |

An absent extension means *unconstrained* in X.509, not *forbidden* — so a
certificate carrying neither extension is accepted. When there is no
ExtendedKeyUsage to go on, KeyUsage decides, which is what separates the halves
of a dual key pair issued without one.

## The selectors

Every bundle entry point takes the same three selectors — `PKIClient(...)`,
`from_pkcs12(...)`, `from_pem(...)`, `AsyncPKIClient`, and
`build_ssl_context`:

```python
# By key usage — the usual discriminator for a dual key pair
PKIClient("corp.p12", password="secret", key_usage="digital_signature")

# By extended key usage — when both certs share their key-usage bits
PKIClient("corp.p12", password="secret", extended_key_usage="client_auth")

# By name — case-insensitive substring of the friendly name, common name,
# or full subject
PKIClient("corp.p12", password="secret", identity="Signature")

# By exact SHA-1 or SHA-256 fingerprint (colons and case are ignored)
PKIClient("corp.p12", password="secret", identity="9F:86:D0:81…")

# By position in the file
PKIClient("corp.p12", password="secret", identity=0)

# By any predicate over the identity
PKIClient(
    "corp.p12",
    password="secret",
    identity=lambda i: i.info.serial_number == 4242
)

# Multiple kwargs are ANDed together
PKIClient(
    "corp.p12",
    password="secret",
    key_usage="digital_signature",
    extended_key_usage="client_auth"
)
```

### How usage names are spelled

Usage names are spelled as `CertInfo` reports them — `digital_signature`,
`client_auth` — but camelCase and dotted OIDs are accepted too, so you can
paste whatever your CA's documentation uses:

```python
key_usage="digital_signature"            # as CertInfo reports it
key_usage="digitalSignature"             # camelCase
key_usage="nonRepudiation"               # accepted spelling of content_commitment
extended_key_usage="1.3.6.1.5.5.7.3.2"   # dotted OID
```

(picking-the-current-one)=
## Picking the current one

:::{tip}
For the common case, [`for_mtls`](#for-mtls) already applies this
rule *and* the client-authentication one. Reach for `currently_valid` when you
want freshness alone — for example on a certificate that is deliberately not
for client authentication.
:::

When a file carries a renewed certificate next to the one it replaces, only the
validity window separates them. The ready-made `currently_valid` selector picks
on exactly that:

```python
from httpx_pki import PKIClient, currently_valid

PKIClient("corp.p12", password="secret", identity=currently_valid)
```

Expired and not-yet-valid identities never match it. During a renewal
*overlap*, when the old certificate has not expired yet, the tie resolves to
the later validity window — but only between certificates that are otherwise
interchangeable, meaning the same subject and usages.

:::{warning}
`currently_valid` never picks between the halves of a dual key pair. Freshness
cannot tell a signing certificate from an encryption one, so both remain
matched and the load is still ambiguous. Combine it with `key_usage=` there:

```python
PKIClient(
    "corp.p12",
    password="secret",
    identity=currently_valid,
    key_usage="digital_signature"
)
```
:::

## When a selector does not resolve to one identity

Matching nothing and matching several are different errors, and both name what
the file actually holds so you can correct the selector:

```text
CertificateNotFoundError: key_usage='crl_sign' matched no identity in the
PKCS#12 data, which holds: ...
```

```text
AmbiguousCertificateError: identity=httpx_pki.currently_valid matched
2 identities: ...
```

## PEM bundles work the same way

A `.pem` concatenating two key-and-certificate pairs — or one key followed by
its old and renewed certificates — holds several identities, chosen with the
same selectors:

```python
PKIClient("corp.pem", key_usage="digital_signature")
```

Keys are paired to certificates by public key, in any block order. A key
matching no certificate at all means the bundle was assembled from the wrong
pieces, and is rejected.

## What happens to the identities you did not pick

They are **not** presented as chain certificates. They are leaf certificates in
their own right, and a strict server can reject a chain carrying them — only
real chain certificates are sent.

The selection is also remembered. `reload()` and `auto_reload` re-select the
same identity after a rotation, even if the new file lists them in a different
order, and it survives pickling.

## Next steps

- [](server-trust.md) — how the server gets verified
- [](expiry-and-rotation.md) — reload, and warnings as a certificate ages
- [](windows-store.md) and [](macos-keychain.md) — the same problem in the OS
  stores, which have their own selectors
