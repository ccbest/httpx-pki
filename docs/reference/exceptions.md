# Exceptions and warnings

Everything httpx-pki tells you about, in one place. This page is organized by
what httpx-pki raises; if you have an error in hand and want to know what to do
about it — including the handshake failures that come from OpenSSL rather than
from here — start at [](../troubleshooting.md).

The split is deliberate. httpx-pki **raises** when it cannot do what you asked,
and **warns** when it can proceed but the result is probably not what you
intended — an expired certificate you may be deliberately inspecting, a
`verify=False` in a throwaway script.

```
Exception                      UserWarning
└── PKIError                   └── PKIWarning
    ├── CertificateLoadError       ├── CertificateValidityWarning
    ├── CertificateExpiredError    ├── TLSConfigWarning
    ├── CertificateNotYetValidError└── PicklingWarning
    ├── CertificateNotFoundError
    ├── AmbiguousCertificateError
    └── UnsupportedPlatformError
```

Both base classes exist so one `except` or one filter reaches everything.
Neither is raised directly.

## Exceptions

```{eval-rst}
.. autoexception:: httpx_pki.PKIError
   :show-inheritance:

.. autoexception:: httpx_pki.CertificateLoadError
   :show-inheritance:

.. autoexception:: httpx_pki.CertificateNotFoundError
   :show-inheritance:

.. autoexception:: httpx_pki.AmbiguousCertificateError
   :show-inheritance:

.. autoexception:: httpx_pki.CertificateExpiredError
   :show-inheritance:

.. autoexception:: httpx_pki.CertificateNotYetValidError
   :show-inheritance:

.. autoexception:: httpx_pki.UnsupportedPlatformError
   :show-inheritance:
```

### What they look like

| Message | Cause |
| --- | --- |
| `invalid PKCS#12 data or wrong password` | Wrong password, or the bytes are not PKCS#12 |
| `could not parse private key (wrong password?)` | Encrypted key with a wrong or missing `password` |
| `no private key found in PEM data` | The PEM holds certificates only — see [](../troubleshooting.md#no-private-key) |
| `PKCS#12 data contains no private key` | The bundle holds certificates only — see [](../troubleshooting.md#no-private-key) |
| `the data is a DER certificate with no private key; …` | A bare `.crt`/`.cer` passed as the single source; use `from_key_pair` |
| `the data is a certificate-only PKCS#7 bundle with no private key; …` | A `.p7b` passed as the single source; it belongs in `chain=` or `verify=` |
| `no certificate found in PEM data` | The reverse — a key with no certificate |
| `PKCS#12 data contains no certificate` | The reverse — a key with no certificate |
| `private key does not match certificate (their public keys differ)` | The cert and key are not a pair — see [](../guide/loading-certificates.md#when-the-key-and-certificate-do-not-match) |
| `private key does not match any certificate in the PEM data` | Same, within one bundle — it was assembled from the wrong pieces |
| `could not load CA bundle …: [X509: NO_CERTIFICATE_OR_CRL_FOUND]` | A `verify=` bundle that is bare DER — see [](../guide/server-trust.md#the-extension-does-not-matter-here-either) |
| `this PKCS#12 data holds 2 identities: …` | Several identities, no selector — see [](../guide/choosing-a-certificate.md) |
| `key_usage='crl_sign' matched no identity …` | A selector that matched nothing |
| `the Windows certificate store is only available on Windows` | Platform-specific constructor off-platform |
| `client certificate expired on 2026-08-01 18:02 UTC` | From `check_validity()` or `strict_validity=True` |

:::{note}
Not every failure is a `PKIError`. Asking for `auto_reload` on a source with no
file to watch is a plain `TypeError`, because it is a programming error rather
than a certificate problem:

```text
TypeError: auto_reload requires a filesystem-path certificate source to watch
```

The same goes for `reload(password=...)` on a source that supplies its own —
`from_env`, the Windows store, or the macOS keychain. The password would have
nothing to decrypt, so it is refused rather than quietly discarded. See
[](../guide/expiry-and-rotation.md#passwords-and-unattended-reloads).
:::

## Warnings

```{eval-rst}
.. autoexception:: httpx_pki.PKIWarning
   :show-inheritance:

.. autoexception:: httpx_pki.CertificateValidityWarning
   :show-inheritance:

.. autoexception:: httpx_pki.TLSConfigWarning
   :show-inheritance:

.. autoexception:: httpx_pki.PicklingWarning
   :show-inheritance:
```

### What they look like

`CertificateValidityWarning` — the certificate cannot be used, or soon will not
be. See [](../guide/expiry-and-rotation.md).

```text
client certificate expired on 2026-08-01; mTLS handshakes will fail.

client certificate is not valid until 2026-09-01; mTLS handshakes will fail
until then.

client certificate expires on 2026-08-07 (in 4 day(s)).
```

The third fires only when you asked for it with `warn_if_expires_within=`. The
first two always fire — loading an unusable certificate is never silent.

`TLSConfigWarning` — a setup that runs but does not do what it looks like it
does. These are worth reading rather than silencing.

```text
verify=False disables server certificate verification; connections are
vulnerable to man-in-the-middle attacks.

verify= was given a pre-built ssl.SSLContext; httpx-pki loads the client
certificate into it in place. Do not share this context with other clients --
use verify=True or a CA-bundle path (letting httpx-pki build a dedicated
context) if it must stay cert-free.

a custom transport=/mounts= makes httpx ignore verify=, so the client
certificate is NOT mounted on this session. Build the context with
build_ssl_context() and put it on the inner transport instead, e.g.
httpx.HTTPTransport(verify=ctx).
```

Between them: no client certificate presented, no server verified, or two
clients quietly sharing one identity. See
[](../guide/server-trust.md#passing-your-own-ssl-context) and
[](../guide/advanced.md).

The audit that runs at construction warns only on findings that predict a
**failing handshake**. Findings are grouped per source, so a bundle assembled
wrongly produces one warning rather than one per certificate.

```text
none of the 1 presented certificate ('Unrelated Root') reach the issuer
'Corp Issuing CA'. The server cannot build a path and will reject the
handshake with unknown_ca.

none of the 2 configured trust anchors can be used: Old Root (expired
2023-11-13); Older Root (expired 2021-02-01). Every server certificate will
fail verification.

the client certificate's ExtendedKeyUsage is email_protection, which omits
client_auth. It was not issued for client authentication and a server
enforcing EKU will reject it.
```

Everything else the audit finds describes a configuration that **still
works** — an intermediate CA or a leaf in `verify=` (a genuine, if narrow,
anchor under [partial-chain
verification](#intermediate-as-anchor)),
your own certificate in `verify=`, a chain certificate that connects to
nothing, the leaf sent twice. Those findings are **report-only**: they appear
under `PROBLEMS` in [`explain()`](../guide/inspecting-a-certificate.md), where
whoever is actually looking at the material reads them, rather than as
warnings a production log learns to scroll past.

A **self-signed** certificate in `verify=` is never a finding at all — that is
a root CA, and equally the self-signed server certificate a development setup
pins. Nor is a cross-signed CA in `chain=`: the chain is followed along every
path, so a second copy of an intermediate under a different root is recognized
rather than reported as a stray. See
[](../guide/server-trust.md#combining-trust-sources) and
[](../guide/loading-certificates.md#intermediates).

`PicklingWarning` — configuration that will not survive `pickle`, which matters
at process boundaries such as `multiprocessing` or a prefork task queue.
Neither is fatal; the unpickled client works with less than you configured.

```text
a custom ssl.SSLContext passed as verify= cannot be pickled; the unpickled
client falls back to default server verification.

the certificate source cannot be pickled; the unpickled client will not be
reloadable.
```

## Filtering warnings

Silence one concern without hiding the others:

```python
import warnings
from httpx_pki import CertificateValidityWarning

warnings.filterwarnings("ignore", category=CertificateValidityWarning)
```

Or reach all of them at once:

```python
from httpx_pki import PKIWarning

warnings.filterwarnings("ignore", category=PKIWarning)
```

To silence warnings only around a specific call, scope the filter:

```python
with warnings.catch_warnings():
    warnings.simplefilter("ignore", CertificateValidityWarning)
    client = PKIClient("expired.p12", password="secret")
```

### Making them fatal

Turning `PKIWarning` into an error is a cheap way to catch a misconfiguration
before it ships:

```python
warnings.filterwarnings("error", category=PKIWarning)
```

In a pytest suite, via `pyproject.toml`:

```toml
[tool.pytest.ini_options]
filterwarnings = [
    "error::httpx_pki.PKIWarning",
]
```

:::{tip}
`TLSConfigWarning` is the one most worth promoting to an error in CI — every
message under it describes a client that silently fails to do its job.
:::

### Why you may only see a warning once

Python deduplicates warnings by default: the same message from the same line is
shown once per process, so constructing ten clients with `verify=False` prints
one warning, not ten.

```console
$ python -W always myapp.py    # show every occurrence
$ python -W error myapp.py     # turn them all into errors
```

That is a property of Python's warning machinery, not of httpx-pki — worth
knowing when a warning you expected repeatedly appears only once.
