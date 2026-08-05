# Inspecting a certificate

Once a certificate is mounted, the client exposes what it is presenting —
useful for a startup log line, a health check, a support diagnostic, or an
assertion in a test.

```python
from httpx_pki import PKIClient

client = PKIClient("client.p12", password="secret")

client.cn                 # 'corp-user'
client.not_valid_after    # datetime(2027, 8, 2, 17, 31, 31, tzinfo=utc)
client.is_expired         # False
```

## Quick properties

The common questions have direct properties, so you rarely need the full
detail:

| Property | Type | |
| --- | --- | --- |
| `cn` | `str` | Subject common name |
| `dn` | `str` | Full subject distinguished name |
| `not_valid_before` | `datetime` | Start of the validity window |
| `not_valid_after` | `datetime` | End of the validity window |
| `is_expired` | `bool` | Past `not_valid_after` |
| `is_not_yet_valid` | `bool` | Before `not_valid_before` |
| `expires_in` | `timedelta` | Time left until `not_valid_after` |
| `certificate` | `x509.Certificate` | The parsed certificate itself |
| `ssl_context` | `ssl.SSLContext` | The context the client uses |

All datetimes are timezone-aware and in UTC.

```python
if client.expires_in < datetime.timedelta(days=14):
    log.warning("client cert %s expires %s", client.cn, client.not_valid_after)
```

## The full picture: `cert_info()`

`client.cert_info()` returns a {py:class}`~httpx_pki.CertInfo` — a frozen
dataclass with everything httpx-pki reads off the certificate:

```python
info = client.cert_info()
```

| Field | Example |
| --- | --- |
| `common_name` | `'corp-user'` |
| `distinguished_name` | `'CN=corp-user'` |
| `issuer_common_name` | `'Acme Issuing CA'` |
| `issuer_distinguished_name` | `'CN=Acme Issuing CA,O=Acme'` |
| `serial_number` | `137979069391421544275421516091962167926830026919` |
| `not_valid_before` | `datetime(2026, 8, 1, 17, 31, 31, tzinfo=utc)` |
| `not_valid_after` | `datetime(2027, 8, 2, 17, 31, 31, tzinfo=utc)` |
| `fingerprint_sha256` | `'A92ABBA4A948400B6F791A49226192FD…'` |
| `fingerprint_sha1` | `'B8A2152EC0FC713231352786123249F35FC66B5A'` |
| `subject_alt_names` | `['client.example.com']` |
| `dns_names` | `['client.example.com']` |
| `key_usage` | `frozenset({'digital_signature'})` |
| `extended_key_usage` | `['client_auth']` |

Fingerprints are uppercase hex without separators — the same form
`identity=` accepts when [choosing a certificate](choosing-a-certificate.md),
which also tolerates colons and lowercase.

`key_usage` is a `frozenset` because order is meaningless; `extended_key_usage`
is a list. Both use the readable names shown here rather than raw OIDs.

:::{note}
`CertInfo` describes the **leaf certificate only** — the one being presented.
It says nothing about the chain, and nothing about server trust.
:::

## Inspecting without building a client

The module-level `cert_info()` reads a certificate straight from PEM bytes,
with no client and no private key involved:

```python
from httpx_pki import cert_info

info = cert_info(pem_bytes)
print(info.common_name, info.not_valid_after)
```

To inspect what a *file* holds — including a bundle with several identities,
and without touching the private keys — use `list_identities` instead. See
[](choosing-a-certificate.md#look-before-you-choose).

## Asserting validity

`check_validity()` raises rather than returning a boolean, so it reads well in
a startup check:

```python
client.check_validity()          # raises if expired or not yet valid
```

- `CertificateExpiredError` — past `not_valid_after`
- `CertificateNotYetValidError` — before `not_valid_before`

Pass `within=` to treat an imminent expiry as a failure too:

```python
client.check_validity(within=datetime.timedelta(days=30))
```

```text
CertificateExpiredError: client certificate expires on 2027-08-02 17:31 UTC,
within 30 days
```

Loading an already-expired certificate does **not** raise by default — it
warns, so a diagnostic tool can still inspect it:

```text
CertificateValidityWarning: client certificate expired on 2026-08-01;
mTLS handshakes will fail.
```

To make expiry a hard failure on every request instead, use
`strict_validity=True`. That and the rollover warning are covered in
[](expiry-and-rotation.md).

## Next steps

- [](choosing-a-certificate.md) — inspecting a file that holds several
  identities
- [](expiry-and-rotation.md) — acting on what you find as certificates age
- [](server-trust.md) — the other half of the connection
