# Testing helpers

Testing mTLS code means having certificates, and checking key material into a
repository is a bad habit. `httpx_pki.testing` mints throwaway certificates so
your suite does not have to re-derive the `cryptography` boilerplate.

```python
from httpx_pki import PKIClient
from httpx_pki.testing import make_ca, make_client_cert

ca = make_ca()
bundle = make_client_cert("svc-client", ca=ca, dns_names=["svc.internal"])

with PKIClient(bundle.pkcs12(), password=b"") as client:
    assert client.cn == "svc-client"
```

The module is not imported by `httpx_pki` itself — import it explicitly. It is
for tests, and it is not a CA.

## What you get back

Both `make_ca()` and `make_client_cert()` return a `CertBundle`, which can hand
you the material in whatever shape the code under test wants:

| Accessor | |
| --- | --- |
| `.pkcs12(password=b"")` | A PKCS#12 blob |
| `.pem` | Key and certificate concatenated, ready for `PKIClient(...)` |
| `.cert_pem` | The certificate alone |
| `.key_pem` | The unencrypted private key alone |
| `.ca_pem` | The issuing CA's certificate — useful as `verify=` |
| `.common_name` | The subject common name |
| `.issuer` | The issuing `CertBundle`, or `None` |

```python
PKIClient(bundle.pkcs12(), password=b"")            # PKCS#12
PKIClient(bundle.pem)                               # PEM bundle
PKIClient.from_key_pair(bundle.cert_pem, bundle.key_pem)
```

## Realistic extensions by default

Minted certificates carry what a real CA would issue — a
`digital_signature` / `key_encipherment` KeyUsage and a `client_auth`
ExtendedKeyUsage — so servers that enforce EKU accept them:

```python
info = client.cert_info()
info.key_usage           # frozenset({'digital_signature', 'key_encipherment'})
info.extended_key_usage  # ['client_auth']
```

Override either to test your own selection logic:

```python
make_client_cert("me", ca=ca, key_usage=["digital_signature"])
make_client_cert("me", ca=ca, extended_key_usage=["email_protection"])
```

## Exercising the validity paths

```python
expired = make_client_cert("old", ca=ca, expired=True)

future = make_client_cert(
    "new",
    ca=ca,
    not_before=datetime.now(timezone.utc) + timedelta(days=5),
    not_after=datetime.now(timezone.utc) + timedelta(days=50),
)
```

```python
PKIClient(expired.pem).is_expired          # True
PKIClient(future.pem).is_not_yet_valid     # True
```

Both emit a `CertificateValidityWarning` on load, so a test that builds one
deliberately will want to filter it — see
[](../reference/exceptions.md#filtering-warnings).

## Multi-identity bundles

`make_pkcs12` writes **several identities into one bundle**, which nothing else
readily does — `cryptography` and the `openssl` command line both keep a single
key. That makes it the only convenient way to test how your code handles a dual
key pair:

```python
from httpx_pki.testing import make_ca, make_client_cert, make_pkcs12

ca = make_ca()
signing = make_client_cert("me", ca=ca, key_usage=["digital_signature"])
encryption = make_client_cert("me", ca=ca, key_usage=["key_encipherment"])

blob = make_pkcs12(
    [(signing, "Signature"), (encryption, "Encryption")],
    password="secret",
)
```

Each entry is a `CertBundle`, or a `(bundle, friendly_name)` tuple when you want
the identity labelled. The result behaves exactly like a real dual key pair:

```python
PKIClient(blob, password="secret")                              # AmbiguousCertificateError
PKIClient(blob, password="secret", key_usage="digital_signature")   # picks Signature
```

See [](choosing-a-certificate.md).

## Bundle layout

By default `make_pkcs12` lays the file out the way OpenSSL and Windows write
one: certificates in a PBES2-encrypted block, each key individually shrouded,
and an HMAC over the whole file. Three flags produce the plainer variants, for
testing a parser against the shapes it will meet in the wild:

```python
make_pkcs12([bundle], password="pw", encrypt_certs=False)
make_pkcs12([bundle], password="pw", mac=False)
make_pkcs12([bundle], password="pw", keys_in_encrypted_safe=True)
make_pkcs12([bundle])                                    # no password at all
```

## A pytest fixture

```python
import pytest
from httpx_pki import PKIClient
from httpx_pki.testing import make_ca, make_client_cert


@pytest.fixture(scope="session")
def ca():
    return make_ca()


@pytest.fixture
def client(ca):
    bundle = make_client_cert("test-client", ca=ca)
    with PKIClient(bundle.pem, verify=False) as session:
        yield session
```

For a full round trip, point a local TLS server at `ca.cert_pem` as its client
CA and pass `verify=bundle.ca_pem` to the client — the two halves of the same
CA.

## Next steps

- [](choosing-a-certificate.md) — what multi-identity bundles are for
- [](expiry-and-rotation.md) — what the expired-certificate paths do
- [](../reference/api.md#testing-helpers) — the generated API reference
