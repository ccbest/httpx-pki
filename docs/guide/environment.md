# From environment variables

Containerized and 12-factor deployments configure the client certificate
through the environment rather than in code. `from_env()` reads a set of
`HTTPX_PKI_*` variables and builds the session from them:

```python
from httpx_pki import PKIClient

client = PKIClient.from_env()
```

```console
$ export HTTPX_PKI_CERT=/etc/pki/client.p12
$ export HTTPX_PKI_PASSWORD=secret
$ python -m myapp
```

Nothing about the source is decided in code — the same image runs against a
PKCS#12 bundle in one environment and a separate cert and key in another.

## The variables

Only `CERT` is required. Every variable takes the prefix `HTTPX_PKI_` by
default; see [](#using-a-different-prefix) to change it.

| Variable | Purpose                                                                                                                                   |
| --- |-------------------------------------------------------------------------------------------------------------------------------------------|
| `HTTPX_PKI_CERT` | **Required.** Path to a PKCS#12 or PEM source. The encoding is detected from the bytes.                                                   |
| `HTTPX_PKI_PASSWORD` | Password for the certificate or key. Omit for unencrypted material.                                                                       |
| `HTTPX_PKI_KEY` | Path to a separate private key. Switches to the cert-and-key path (`PKIClient.from_key_pair( ... )`), with `HTTPX_PKI_CERT` as the certificate.     |
| `HTTPX_PKI_CHAIN` | Path to intermediate certificates to present, in addition to any `CERT` already carries.                                                  |
| `HTTPX_PKI_CA` | Server trust: a CA bundle path or directory, or the literal `system` or `certifi`. Several combine, separated by `:` (`;` on Windows). Absent means the default. |
| `HTTPX_PKI_IDENTITY` | Which identity to use when the source holds several: a position (`0`), a name substring, a fingerprint, or the literal `currently_valid`. |
| `HTTPX_PKI_KEY_USAGE` | Select an identity by key usage. Comma-separated, e.g. `digital_signature`.                                                               |
| `HTTPX_PKI_EXT_KEY_USAGE` | Select an identity by extended key usage. Comma-separated, e.g. `client_auth`.                                                            |

## Common shapes

A PKCS#12 bundle:

```console
$ export HTTPX_PKI_CERT=/etc/pki/client.p12
$ export HTTPX_PKI_PASSWORD=secret
```

A separate certificate and key — setting `HTTPX_PKI_KEY` is what switches modes:

```console
$ export HTTPX_PKI_CERT=/etc/pki/client.crt
$ export HTTPX_PKI_KEY=/etc/pki/client.key
```

A PEM bundle needing no password at all:

```console
$ export HTTPX_PKI_CERT=/etc/pki/client.pem
```

## Server trust

`HTTPX_PKI_CA` sets `verify`. It takes a path to a CA bundle or directory, or one of two
literals:

```console
$ export HTTPX_PKI_CA=/etc/pki/internal-ca.pem   # a private CA
$ export HTTPX_PKI_CA=system                     # the OS trust store (default when unset)
$ export HTTPX_PKI_CA=certifi                    # the certifi bundle
$ export HTTPX_PKI_CA=/etc/pki/ca.d              # a directory of CA certificates

# Several sources combine -- the OS trust store *and* a private root:
$ export HTTPX_PKI_CA=system:/etc/pki/internal-root.pem
```

Leaving it unset gives the default, which is the OS trust store — see
[](server-trust.md).

An explicit `verify` argument wins over `HTTPX_PKI_CA`, so code can override
the environment when it needs to:

```python
PKIClient.from_env(verify="certifi")     # ignores HTTPX_PKI_CA
```

## Selecting an identity

When `CERT` points at a bundle holding several identities, the same
discriminators available in code are available here. Without one, httpx-pki
refuses to guess and raises `AmbiguousCertificateError`:

```console
$ export HTTPX_PKI_IDENTITY=0                      # by position
$ export HTTPX_PKI_IDENTITY="Acme Corp"            # by name substring
$ export HTTPX_PKI_IDENTITY=A1:B2:C3:...           # by fingerprint
$ export HTTPX_PKI_KEY_USAGE=digital_signature     # by key usage
$ export HTTPX_PKI_EXT_KEY_USAGE=client_auth       # by extended key usage
```

`HTTPX_PKI_IDENTITY=currently_valid` is the environment spelling of the
{py:func}`~httpx_pki.currently_valid` selector.

:::{note}
`currently_valid` discards identities outside their validity window. During a
renewal *overlap*, when old and new are both valid, it resolves to the later
window — but only between certificates that are otherwise interchangeable
(same subject and usages). The halves of a dual key pair stay ambiguous, so
combine it with `HTTPX_PKI_KEY_USAGE` there.
:::

Full detail on all of these: [](choosing-a-certificate.md).

:::{important}
The identity selectors describe a position *inside a bundle*, so they cannot be
combined with `HTTPX_PKI_KEY`, which points at a separate key file. Setting
both raises `CertificateLoadError`:

```
HTTPX_PKI_IDENTITY / HTTPX_PKI_KEY_USAGE / HTTPX_PKI_EXT_KEY_USAGE select an
identity inside a PKCS#12 or PEM bundle, but HTTPX_PKI_KEY points at a
separate private key; drop one or the other
```
:::

(using-a-different-prefix)=
## Using a different prefix

Pass one to `from_env()` if `HTTPX_PKI_` collides with something, or if you
would rather namespace the variables to your own application:

```python
PKIClient.from_env("MYAPP_")
```

```console
$ export MYAPP_CERT=/etc/pki/client.p12
$ export MYAPP_PASSWORD=secret
```

The prefix applies to every variable in the table above.

## Reloading

`reload()` re-reads the environment, so a redeployed pod picks up whatever the
variables now point at. With `auto_reload`, httpx-pki watches the files the
variables named when the session was built:

```python
client = PKIClient.from_env(auto_reload=True)
```

Because the password comes from `HTTPX_PKI_PASSWORD` along with everything
else, `reload()` takes no `password=` here — passing one raises rather than
being silently ignored:

```text
TypeError: reload(password=...) does not apply to a from_env() client: the
password is read from HTTPX_PKI_PASSWORD along with the rest of the
configuration. Set that variable instead of passing one here.
```

See [](expiry-and-rotation.md).

## When something is missing

A missing `CERT` fails immediately and by name, rather than at handshake time:

```
CertificateLoadError: environment variable HTTPX_PKI_CERT is not set
```

## Other variables httpx-pki reads

Two more environment variables affect behavior, neither of them tied to
`from_env()`:

`HTTPX_PKI_BACKEND`
: Forces the HTTP backend to `httpx` or `httpx2`. Read once, at import.
  See [](backends.md).

`SSLKEYLOGFILE`
: Standard across the Python TLS ecosystem — when set, TLS session keys are
  written to that path, which decrypts your traffic by design. Honored by
  every context httpx-pki builds. See [](../about/security.md).
