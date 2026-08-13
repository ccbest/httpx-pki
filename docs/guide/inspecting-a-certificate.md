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

## Explaining a whole configuration

`cert_info()` describes one certificate. `explain()` describes the whole
setup — what a source holds, what it would present, what it would trust, and
what would stop it working:

```python
import httpx_pki

print(httpx_pki.explain("corp.p12", password="secret",
                        verify=["system", "/etc/pki/internal-root.pem"]))
```

```text
corp.p12 — PKCS#12, 1 identity, 1 chain certificate

PRESENTS   svc-client
           issued by  Corp Issuing CA
           valid      2026-01-15 → 2027-01-15   (159 days left)
           usage      digital_signature, key_encipherment
           ext usage  client_auth
           SANs       svc.internal
           SHA-256    7923E578…

CHAIN      svc-client
             └─ Corp Issuing CA   [verified]
               └─ Corp Root   [NOT SUPPLIED; trust anchor, need not be sent]

TRUSTS     the OS trust store
           /etc/pki/internal-root.pem — 1 anchor: Corp Root

PROBLEMS   none
```

It takes the same arguments as [`build_ssl_context()`](advanced.md) and reports
what it *would* do instead of doing it — a dry run.

`repr()` is the full report too, so evaluating it in a REPL or a notebook shows
the same thing as `print()`.

### It works when loading does not

This is the point. A bundle you cannot yet open is exactly the one you need to
look inside, so a source that is merely *confusing* produces a report rather
than an exception:

- **several identities and no selector** — lists them, with the usages and
  expiry that tell them apart, and says which selector to pass
- **no password, or the wrong one** — says so, and says why nothing at all can
  be shown (a PKCS#12 keeps its certificates in an encrypted section, so unlike
  PEM there is no part of it readable first)

Only a source that cannot be read at all still raises.

### The diagram accounts for everything sent

Three things can be true of a certificate, and all three are drawn:

```text
CHAIN      svc-client   [SENT TWICE]
             └─ Corp Issuing CA   [verified]
               └─ Corp Root CA   [NOT SUPPLIED]

           Unrelated Root   [UNATTACHED]
```

Indented under a connector: on the path. `NOT SUPPLIED` is on the path but was
not given — the gap the server will look for. At the left margin with no
connector: on the wire, attached to nothing.

Upper case marks a fault and lower case a neutral fact, so the severity of a
line is readable without reading the words.

### What you are trusting, anchor by anchor

`TRUSTS` breaks down every certificate a `verify=` entry contributed — its key,
its expiry, and whether it can serve as an anchor at all:

```text
TRUSTS     internal-ca.pem — 2 anchors
             Corp Root CA              RSA-4096  expires 2034-01-12
             Legacy Cross-Sign Root    RSA-2048  UNUSABLE — expired 2023-11-13
           the OS trust store
```

Four defects make OpenSSL reject an anchor outright, and all four are visible
in the bytes: it is **expired**, **not yet valid**, has a **key below the local
security level**, or asserts `CA:TRUE` while its **KeyUsage omits
`keyCertSign`**.

An anchor marked `UNUSABLE` is described, not complained about — one dead root
beside a live one is the normal shape of a bundle carrying a cross-signing root
through a transition, and verification simply uses the live one. It becomes
`trust.no_usable_anchor` only when **nothing** configured can anchor a chain,
which is a certainty rather than a guess. (A `CA:TRUE` certificate that cannot
sign is `trust.not_a_ca` on its own, since no amount of other anchors makes it
work.)

:::{note}
A root signed with SHA-1 is **not** flagged. A trust anchor is trusted by fiat
and its own signature is never verified during path validation, so a SHA-1 root
works exactly as well as a SHA-256 one — flagging it would be a false alarm on
a working setup. Key *size* is different, and is checked against the security
level your OpenSSL is actually configured with.
:::

### Describing is not accusing

A chain that stops before its root is the **normal** shape — the root is what
the server already has. The report shows the gap and, when the missing issuer
is one you trust, says so. `PROBLEMS` lists only what is actually wrong.

When the issuer is one you *don't* have, the report names where the certificate
says it is published:

```text
CHAIN      svc-client
             └─ Corp Issuing CA   [NOT SUPPLIED; published at http://pki.corp.example/CorpIssuingCA.crt]
```

httpx-pki never fetches that URL — see [](../about/non-goals.md#fetching-anything-over-the-network).

### Acting on a finding

Most remedies are things only you can do — obtain a current certificate, supply
the right intermediates, trust the root instead of an intermediate. Two are
subtractions over material httpx-pki already holds, so it can do them for you:
`chain.stray` and `chain.duplicate_leaf` both clear with
[`prune_chain=True`](loading-certificates.md#dropping-what-does-not-belong),
which is what their remedy suggests.

```console
$ python -m httpx_pki explain corp.p12 --prune-chain
```

### On a live client

`client.explain()` is the more useful of the two when there is a session,
because a client knows both halves — and most confusion lives in the pairing of
"the CAs I trust to identify the server" with "the chain I present to it":

```python
with PKIClient("corp.p12", password="secret") as client:
    print(client.explain())
```

### In a test or CI check

The report is an object, not just text. Match on `Problem.code`, never on the
message — the codes are stable, the prose is not:

```python
report = httpx_pki.explain("corp.p12", password=pw)
assert report.ok
assert not [p for p in report.problems if p.code.startswith("chain.")]
```

### From a shell

For a file you have not written any code for yet:

```console
$ python -m httpx_pki explain corp.p12
```

(For a whole *folder* you have not written any code for yet, the command is
[`inventory`](taking-inventory.md) — it names the files, and `explain` takes it
from there.)

It takes the same selectors the library does, so a bundle holding several
identities can be listed and then inspected:

```console
$ python -m httpx_pki explain corp.p12                              # lists them
$ python -m httpx_pki explain corp.p12 --key-usage digital_signature
$ python -m httpx_pki explain corp.p12 --identity 0
```

`--chain` and `--verify` are there too, both repeatable, which makes the
command a full dry run of `build_ssl_context()`:

```console
$ python -m httpx_pki explain corp.p12 --verify system --verify internal-ca.pem
```

It prompts for a password only if the source needs one, and exits non-zero when
there are problems, so it works as a CI check. There is deliberately no
`--password` flag — an argument lands in shell history and in every process
listing; use `--password-env VAR` for scripted use.

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

- [](taking-inventory.md) — the step before this one, when what you have is a
  folder rather than a file
- [](choosing-a-certificate.md) — inspecting a file that holds several
  identities
- [](expiry-and-rotation.md) — acting on what you find as certificates age
- [](server-trust.md) — the other half of the connection
