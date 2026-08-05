# httpx-pki

PKCS#12 client-certificate (mTLS) sessions for [httpx2](https://github.com/pydantic/httpx2)
and httpx.

`httpx-pki` gives you an httpx client that presents a client certificate, loaded
from wherever your certificate actually lives — a `.p12`/`.pfx` bundle, a PEM
file, a separate key and cert, the Windows certificate store, or the macOS
keychain — without hand-rolling an `ssl.SSLContext` or writing the private key
to a temporary file.

```python
from httpx_pki import PKIClient

with PKIClient("client.p12", password="secret") as client:
    r = client.get("https://mtls.example.com/")
```

:::{admonition} Backend
:class: note

Since 0.8, httpx-pki depends on **httpx2** and `PKIClient` subclasses
`httpx2.Client`. The original httpx remains fully supported as a fallback —
see [](guide/backends.md).
:::

## Where to start

:::::{grid} 1 1 2 2
:gutter: 3

::::{grid-item-card} {octicon}`rocket` Quickstart
:link: quickstart
:link-type: doc

Install, load a certificate, make a request.
::::

::::{grid-item-card} {octicon}`book` User guide
:link: guide/index
:link-type: doc

Every source format, identity selection, server trust, rotation.
::::

::::{grid-item-card} {octicon}`code` API reference
:link: reference/index
:link-type: doc

Every public class, function, exception, and warning.
::::

::::{grid-item-card} {octicon}`gear` How it works
:link: about/how-it-works
:link-type: doc

What happens between your bundle and the TLS handshake.
::::

:::::

```{toctree}
:hidden:
:caption: Getting started

install
quickstart
troubleshooting
```

```{toctree}
:hidden:
:caption: User guide

guide/index
guide/backends
guide/loading-certificates
guide/choosing-a-certificate
guide/inspecting-a-certificate
guide/windows-store
guide/macos-keychain
guide/environment
guide/server-trust
guide/expiry-and-rotation
guide/advanced
guide/testing
```

```{toctree}
:hidden:
:caption: Reference

reference/index
reference/api
reference/exceptions
```

```{toctree}
:hidden:
:caption: About

about/how-it-works
about/security
about/non-goals
about/supply-chain
about/changelog
```
