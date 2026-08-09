# API reference

Everything exported from `httpx_pki`, grouped by what it is for. Anything not
listed here is private and may change without a major version bump.

## Clients

The two session classes. Both take the same alternate constructors and
certificate behavior; they differ only in which httpx client they subclass.

```{eval-rst}
.. autoclass:: httpx_pki.PKIClient
   :members:
   :private-members: _init_state
   :inherited-members: Client, BaseClient
   :show-inheritance:

.. autoclass:: httpx_pki.AsyncPKIClient
   :members:
   :private-members: _init_state
   :inherited-members: AsyncClient, BaseClient
   :show-inheritance:
```

## SSL contexts

For callers who want the configured {py:class}`ssl.SSLContext` without the
client — see [](../guide/advanced.md).

```{eval-rst}
.. autofunction:: httpx_pki.build_ssl_context

.. autofunction:: httpx_pki.build_windows_ssl_context

.. autofunction:: httpx_pki.build_macos_ssl_context
```

## Discovery and selection

Inspect what a source holds before mounting anything — see
[](../guide/choosing-a-certificate.md).

```{eval-rst}
.. autofunction:: httpx_pki.list_identities

.. autofunction:: httpx_pki.list_pkcs12_identities

.. autofunction:: httpx_pki.list_windows_certificates

.. autofunction:: httpx_pki.select_windows_certificate

.. autofunction:: httpx_pki.list_macos_certificates

.. autofunction:: httpx_pki.select_macos_certificate

.. autofunction:: httpx_pki.currently_valid
```

## Inspection

`explain()` describes a whole configuration — what a source holds, what it
would present, what it would trust, and what would stop it working. See
[](../guide/inspecting-a-certificate.md#explaining-a-whole-configuration).

```{eval-rst}
.. autofunction:: httpx_pki.explain
```

```{eval-rst}
.. autoclass:: httpx_pki.X509Explanation
   :members:
```

```{eval-rst}
.. autoclass:: httpx_pki.Problem
```

```{eval-rst}
.. autoclass:: httpx_pki.ChainLink
```

```{eval-rst}
.. autoclass:: httpx_pki.TrustAnchor
```

## Data types

```{eval-rst}
.. autoclass:: httpx_pki.CertInfo
   :members:

.. autoclass:: httpx_pki.Material
   :members:

.. autoclass:: httpx_pki.P12Identity
   :members:

.. autoclass:: httpx_pki.WinCert
   :members:

.. autoclass:: httpx_pki.MacCert
   :members:

.. autofunction:: httpx_pki.cert_info
```

## Backend resolution

```{eval-rst}
.. autodata:: httpx_pki.HTTP_BACKEND
```

See [](../guide/backends.md).

(testing-helpers)=
## Testing helpers

Throwaway certificate generation for test suites — see
[](../guide/testing.md). This module is not imported by `httpx_pki` itself;
import it explicitly as `httpx_pki.testing`.

```{eval-rst}
.. automodule:: httpx_pki.testing
   :members:
   :member-order: bysource
```
